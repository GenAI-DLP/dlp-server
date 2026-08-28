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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app import db
from app.config import load_config

logger = logging.getLogger(__name__)

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

    with db.connection() as conn, conn.transaction():
        existing = conn.execute(
            "SELECT token_label FROM token_vault "
            "WHERE session_id = %s AND value_hash = %s AND revoked_at IS NULL",
            (session_id, vhash),
        ).fetchone()
        if existing is not None:
            return existing[0]

        # 카운터 증가 구간만 직렬화 (xact lock — 트랜잭션 종료 시 해제).
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{session_id}|{etype}",),
        )
        # revoked 포함 count — 라벨 번호를 재사용하지 않아 옛 라벨의 오복원을 막는다.
        count = conn.execute(
            "SELECT count(*) FROM token_vault WHERE session_id = %s AND entity_type = %s",
            (session_id, etype),
        ).fetchone()[0]
        label = TOKEN_LABEL_FMT.format(etype=etype, n=count + 1)

        inserted = conn.execute(
            "INSERT INTO token_vault "
            "(session_id, entity_type, token_label, cipher_value, value_hash, "
            "access_scope, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(secs => %s)) "
            "ON CONFLICT (session_id, value_hash) WHERE revoked_at IS NULL "
            "DO NOTHING RETURNING token_label",
            (session_id, etype, label, _encrypt(value), vhash, Jsonb(scope), ttl_sec),
        ).fetchone()
        if inserted is not None:
            return inserted[0]

        # 경합: 다른 트랜잭션이 같은 값을 먼저 커밋 → 그 라벨 회수.
        existing = conn.execute(
            "SELECT token_label FROM token_vault "
            "WHERE session_id = %s AND value_hash = %s AND revoked_at IS NULL",
            (session_id, vhash),
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
                    (session_id, token_label),
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
    """복원 시도 1건 기록. 원문·평문·value_hash 는 넣지 않는다. role 없으면 "" (NOT NULL)."""
    conn.execute(
        "INSERT INTO token_vault_access_log "
        "(token_id, session_id, token_label, requested_role, requested_purpose, "
        "granted, denied_reason) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (token_id, session_id, token_label, role or "", purpose, granted, denied_reason),
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
