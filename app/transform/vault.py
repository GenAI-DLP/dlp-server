"""
가역적 토큰화 (기능 a) — token_vault 레포지토리.

PII 를 결정론적 토큰 라벨(`<PII:RRN:1>`)로 치환하고, 인가된 요청자에 한해 원본으로 복원한다.
상태는 PostgreSQL 에 있고(`token_vault` / `token_vault_access_log`), 커넥션은 `app/db.py` 풀.
스키마·수명 규칙 SSOT: docs/schemas/dlp-server/token-vault.md + postgres-schema.sql §2.

fail-closed: detokenize 와 DB 오류는 None 반환(예외 전파 안 함). tokenize 의 DB 오류는 raise.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app import db
from app.config import load_config

logger = logging.getLogger(__name__)

# token_vault.session_id (및 token_vault_access_log.session_id) 는 DB 스키마상
# UUID 타입이다(postgres-schema.sql — 이 파일에선 직접 안 보임, 실제 INSERT 시
# psycopg.errors.InvalidTextRepresentation 으로 확인됨). 반면 실제 session_id 는
# 프록시가 헤더/쿠키/원격주소에서 뽑은 임의 문자열이라(§2.3) UUID 형식이 보장
# 안 된다. 문자열을 결정론적으로 UUID 로 매핑해 스키마 제약을 만족시킨다 —
# 같은 session_id 문자열은 항상 같은 UUID 로 매핑되므로 조회/삽입 일관성은
# 유지된다(uuid5 는 순수 함수, 매 호출 재계산해도 결과 동일 — 별도 캐시 불필요).
#
# ⚠️ 이 매핑은 이 모듈(vault.py) 안에서만 유효하다. 세션 컨텍스트 테이블
# (sessions, session_entities — context/store.py 가 PostgreSQL 백엔드로 바뀔 때
# 쓸 것으로 보이는 테이블, §7.3 미정)이나 로그 테이블도 session_id 를 UUID 로
# 저장한다면 거기서도 이 함수와 동일한 네임스페이스·알고리즘을 써야 서로 대조
# (JOIN 등)할 수 있다. 근본적으로는 스키마를 session_id TEXT 로 바꾸는 게 더
# 간단한 해결책일 수 있다 — 스키마 담당자와 논의 필요, 여기서는 애플리케이션
# 레벨 우회로만 처리한다.
_SESSION_UUID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # 표준 URL 네임스페이스


def _session_uuid(session_id: str) -> str:
    """임의의 session_id 문자열 → 결정론적 UUID 문자열 (DB의 UUID 컬럼용)."""
    return str(uuid.uuid5(_SESSION_UUID_NAMESPACE, session_id))


# 정상 입력으로 인정하는 entity_type. 밖의 값은 "UNKNOWN" 으로 폴백한다.
ENTITY_TYPES = frozenset(
    {
        "RRN",
        "FOREIGN_RRN",
        "CARD",
        "ACCOUNT",
        "PASSPORT",
        "DRIVER",
        "CREDIT_INFO",
        "PHONE",
        "EMAIL",
        "BIZNO",
        "AMOUNT",
        "NAME",
    }
)

TOKEN_LABEL_FMT = "<PII:{etype}:{n}>"
TOKEN_LABEL_RE = re.compile(r"<PII:([A-Z_]+):(\d+)>")

# access_log.token_id 는 NOT NULL — 미존재 토큰 조회 시도를 기록할 때 채운다.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# 공개 API
# ---------------------------------------------------------------------------
def tokenize(
    session_id: str,
    entity_type: str,
    value: str,
    access_scope: dict | None = None,
) -> str:
    """원본 값 → 토큰 라벨. 같은 세션의 같은 값은 항상 같은 라벨.

    access_scope = {"roles": [...], "purposes": [...]} — 복원 허용 조건.
    기본값(빈 리스트)은 아무도 복원 못 하는 토큰. DB 오류는 raise 한다.
    """
    etype = _normalize_entity_type(entity_type)
    vhash = _hash(session_id, etype, value)
    scope = access_scope if access_scope is not None else {"roles": [], "purposes": []}
    ttl_sec = load_config().vault_ttl_sec
    db_session_id = _session_uuid(session_id)  # UUID 컬럼용 — advisory lock 키는 원본 문자열 유지

    with db.connection() as conn, conn.transaction():
        existing = conn.execute(
            "SELECT token_label FROM token_vault "
            "WHERE session_id = %s AND value_hash = %s AND revoked_at IS NULL",
            (db_session_id, vhash),
        ).fetchone()
        if existing is not None:
            return existing[0]

        # 카운터 증가 구간만 직렬화 (xact lock — 트랜잭션 종료 시 해제).
        # advisory lock 키는 DB 컬럼이 아니라 해시 입력일 뿐이라 원본 session_id 문자열 사용.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{session_id}|{etype}",),
        )
        # revoked 포함 count — 라벨 번호를 재사용하지 않아 옛 라벨의 오복원을 막는다.
        count = conn.execute(
            "SELECT count(*) FROM token_vault WHERE session_id = %s AND entity_type = %s",
            (db_session_id, etype),
        ).fetchone()[0]
        label = TOKEN_LABEL_FMT.format(etype=etype, n=count + 1)

        inserted = conn.execute(
            "INSERT INTO token_vault "
            "(session_id, entity_type, token_label, cipher_value, value_hash, "
            "access_scope, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(secs => %s)) "
            "ON CONFLICT (session_id, value_hash) WHERE revoked_at IS NULL "
            "DO NOTHING RETURNING token_label",
            (db_session_id, etype, label, _encrypt(value), vhash, Jsonb(scope), ttl_sec),
        ).fetchone()
        if inserted is not None:
            return inserted[0]

        # 경합: 다른 트랜잭션이 같은 값을 먼저 커밋 → 그 라벨 회수.
        existing = conn.execute(
            "SELECT token_label FROM token_vault "
            "WHERE session_id = %s AND value_hash = %s AND revoked_at IS NULL",
            (db_session_id, vhash),
        ).fetchone()
        return existing[0]


def detokenize(
    session_id: str,
    token_label: str,
    role: str | None,
    purpose: str | None,
) -> str | None:
    """토큰 라벨 → 원본. access_scope 통과 시에만. 실패·오류는 None (토큰 유지).

    성공·실패 무관하게 매 시도를 token_vault_access_log 에 기록한다.
    """
    try:
        with db.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT token_id, cipher_value, access_scope, "
                    "(expires_at <= now()) AS is_expired "
                    "FROM token_vault "
                    "WHERE session_id = %s AND token_label = %s AND revoked_at IS NULL",
                    (_session_uuid(session_id), token_label),
                )
                row = cur.fetchone()

            if row is None:
                _log_access(
                    conn,
                    _NIL_UUID,
                    session_id,
                    token_label,
                    role,
                    purpose,
                    granted=False,
                    denied_reason="unknown_or_revoked",
                )
                return None
            if row["is_expired"]:
                _log_access(
                    conn,
                    row["token_id"],
                    session_id,
                    token_label,
                    role,
                    purpose,
                    granted=False,
                    denied_reason="expired",
                )
                return None

            allowed, denied_reason = _scope_allows(_resolve_scope(row), role, purpose)
            if not allowed:
                _log_access(
                    conn,
                    row["token_id"],
                    session_id,
                    token_label,
                    role,
                    purpose,
                    granted=False,
                    denied_reason=denied_reason,
                )
                return None

            value = _decrypt(row["cipher_value"])
            _log_access(
                conn,
                row["token_id"],
                session_id,
                token_label,
                role,
                purpose,
                granted=True,
                denied_reason=None,
            )
            return value
    except Exception:
        logger.exception("detokenize 실패 — fail-closed(None)")
        return None


def detokenize_text(
    session_id: str,
    text: str,
    role: str | None,
    purpose: str | None,
) -> str:
    """text 안의 <PII:...> 라벨을 스캔해 각각 detokenize. 인가 실패한 라벨은 그대로 둔다."""

    def _replace(match: re.Match[str]) -> str:
        original = detokenize(session_id, match.group(0), role, purpose)
        return original if original is not None else match.group(0)

    return TOKEN_LABEL_RE.sub(_replace, text)


def purge_expired() -> None:
    """만료 볼트 레코드를 soft revoke → 유예 후 하드 삭제. 스케줄러/배치가 주기 호출.

    스키마 §5 plpgsql 은 세션까지 지우므로 쓰지 않고 볼트 부분만 실행한다.
    """
    try:
        with db.connection() as conn, conn.transaction():
            conn.execute(
                "UPDATE token_vault SET revoked_at = now() "
                "WHERE expires_at < now() AND revoked_at IS NULL"
            )
            conn.execute(
                "DELETE FROM token_vault "
                "WHERE revoked_at IS NOT NULL AND revoked_at < now() - interval '1 day'"
            )
    except Exception:
        logger.exception("purge_expired 실패")


def revoke_session(session_id: str) -> None:
    """특정 세션의 모든 미만료 볼트 레코드를 즉시 soft revoke 한다.

    세션(§6-e, context/store.py)과 볼트(§7.2)는 원래 수명이 분리돼 있어
    session_id 로의 FK 도 없고, vault_ttl_sec 이 지나야 자연 만료된다. 다만
    session_ttl_sec 이 vault_ttl_sec 보다 짧게 설정되면 세션은 끝났는데
    토큰은 한동안 더 살아있는 창(window)이 생긴다 — 최소 보관 원칙을 강화하려고
    세션 만료를 "조기 정리" 트리거로 추가한 것이다. purge_expired() 의 정기
    스케줄과 독립적으로 동작하며 서로 충돌하지 않는다(둘 다 revoked_at 만 세팅,
    하드 삭제는 purge_expired() 의 유예 기간 로직에서만 일어남).

    호출부(context/stage.py 의 InMemorySessionStore on_expire 훅)는 이 함수의
    실패를 예외로 전파받지 않는다 — 여기서 이미 흡수해서 로깅만 한다. vault
    정리 실패가 세션 만료 처리 자체를 막으면 안 되기 때문(최선 노력 정리).
    """
    try:
        with db.connection() as conn, conn.transaction():
            conn.execute(
                "UPDATE token_vault SET revoked_at = now() "
                "WHERE session_id = %s AND revoked_at IS NULL",
                (_session_uuid(session_id),),
            )
    except Exception:
        logger.exception("revoke_session 실패 — session=%s", session_id)


def _reset() -> None:
    """테스트 전용 — 볼트·감사 테이블을 비운다."""
    with db.connection() as conn:
        conn.execute("TRUNCATE token_vault, token_vault_access_log RESTART IDENTITY")


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------
def _hash(session_id: str, entity_type: str, value: str) -> str:
    """sha256(session_id ‖ entity_type ‖ value) 앞 32 hex. 로깅하지 않는다."""
    raw = f"{session_id}\x1f{entity_type}\x1f{value}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _scope_allows(
    scope: dict,
    role: str | None,
    purpose: str | None,
) -> tuple[bool, str | None]:
    """roles·purposes 각 축이 role/purpose 를 포함하거나 "*" 를 가져야 통과. 빈 리스트 = 거부."""
    roles = scope.get("roles") or []
    purposes = scope.get("purposes") or []
    if not ("*" in roles or (role is not None and role in roles)):
        return False, "role_not_in_scope"
    if not ("*" in purposes or (purpose is not None and purpose in purposes)):
        return False, "purpose_not_in_scope"
    return True, None


def _resolve_scope(row: dict) -> dict:
    """복원 허용 조건을 얻는 지점. 지금은 레코드 고정 — 정책 재평가로 바꾸려면 여기만 교체."""
    return row["access_scope"]


def _normalize_entity_type(entity_type: str) -> str:
    """12종 화이트리스트 대조, 밖이면 warning 후 "UNKNOWN"."""
    etype = (entity_type or "").strip().upper()
    if etype in ENTITY_TYPES:
        return etype
    logger.warning("미지의 entity_type %r → UNKNOWN 폴백", entity_type)
    return "UNKNOWN"


def _log_access(
    conn: Connection,
    token_id: str,
    session_id: str,
    token_label: str,
    role: str | None,
    purpose: str | None,
    *,
    granted: bool,
    denied_reason: str | None,
) -> None:
    """복원 시도 1건 기록. 원문·평문·value_hash 는 넣지 않는다. role 없으면 "" (NOT NULL).

    token_vault_access_log.session_id 도 token_vault 와 같은 스키마 계열(UUID 타입)
    이라고 가정하고 _session_uuid() 로 변환한다 — 실제 컬럼 타입이 다르면(예: TEXT)
    이 변환은 불필요하니 스키마 확인 후 제거해도 된다.
    """
    conn.execute(
        "INSERT INTO token_vault_access_log "
        "(token_id, session_id, token_label, requested_role, requested_purpose, "
        "granted, denied_reason) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            token_id,
            _session_uuid(session_id),
            token_label,
            role or "",
            purpose,
            granted,
            denied_reason,
        ),
    )


_NONCE_BYTES = 12


def _cipher() -> AESGCM:
    """config.vault.key(base64 32B)로 만든 AES-GCM. 키가 없거나 길이가 틀리면 raise."""
    raw = load_config().vault.key
    if not raw:
        raise RuntimeError("config.vault.key (DLP_VAULT__KEY) 미설정 — 볼트 암·복호 불가")
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(f"vault key 는 base64 인코딩된 32바이트여야 함 (현재 {len(key)}B)")
    return AESGCM(key)


def _encrypt(value: str) -> bytes:
    """원본 → cipher_value. nonce(12B) ‖ AES-GCM 암호문. 키는 저장소 밖(config)에만 있다."""
    nonce = os.urandom(_NONCE_BYTES)
    return nonce + _cipher().encrypt(nonce, value.encode("utf-8"), None)


def _decrypt(blob: bytes) -> str:
    """cipher_value → 원본. 앞 12B 를 nonce 로 분리해 복호."""
    data = bytes(blob)
    return _cipher().decrypt(data[:_NONCE_BYTES], data[_NONCE_BYTES:], None).decode("utf-8")
