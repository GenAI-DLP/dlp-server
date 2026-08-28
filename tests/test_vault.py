"""
가역적 토큰화 (기능 a) — token_vault 레포지토리 테스트.

PostgreSQL + 스키마가 있을 때만 실행된다 (conftest 의 `db` fixture 가 조건 미충족 시 skip).
왕복·결정론·카운터·AES-GCM·access_scope 게이팅·만료·감사·동시성을 확인한다.
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.transform import vault

_TEST_KEY = base64.b64encode(bytes(range(32))).decode()
_S1 = "11111111-1111-1111-1111-111111111111"
_S2 = "22222222-2222-2222-2222-222222222222"
_WILDCARD = {"roles": ["*"], "purposes": ["*"]}


@pytest.fixture(autouse=True)
def _vault_setup(db, monkeypatch):
    """모든 테스트: 볼트 AES-GCM 키 주입 + 볼트/감사 테이블 초기화."""
    monkeypatch.setenv("DLP_VAULT__KEY", _TEST_KEY)
    vault._reset()


def _scalar(db, sql, *params):
    with db.connection() as conn:
        return conn.execute(sql, params).fetchone()[0]


def _rows(db, sql, *params):
    with db.connection() as conn:
        return conn.execute(sql, params).fetchall()


def _exec(db, sql, *params):
    with db.connection() as conn:
        conn.execute(sql, params)


# ---------------------------------------------------------------------------
# 왕복 · 결정론 · 카운터
# ---------------------------------------------------------------------------
def test_roundtrip(db):
    label = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    assert label == "<PII:RRN:1>"
    assert vault.detokenize(_S1, label, "agent", "cs") == "880101-1234567"


def test_deterministic_reuse(db):
    a = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    b = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    assert a == b
    assert _scalar(db, "SELECT count(*) FROM token_vault WHERE session_id = %s", _S1) == 1


def test_session_isolation(db):
    vault.tokenize(_S1, "RRN", "aaa", _WILDCARD)
    s1_only = vault.tokenize(_S1, "RRN", "bbb", _WILDCARD)  # <PII:RRN:2> — S1 에만 존재
    s2_label = vault.tokenize(_S2, "RRN", "aaa", _WILDCARD)  # 값이 같아도 세션마다 별도 행
    assert _scalar(db, "SELECT count(*) FROM token_vault") == 3
    assert vault.detokenize(_S2, s1_only, "r", "p") is None  # 다른 세션 라벨은 복원 불가
    assert vault.detokenize(_S2, s2_label, "r", "p") == "aaa"
    assert vault.detokenize(_S1, s1_only, "r", "p") == "bbb"


def test_counter_per_session_and_type(db):
    assert vault.tokenize(_S1, "RRN", "v1", _WILDCARD) == "<PII:RRN:1>"
    assert vault.tokenize(_S1, "RRN", "v2", _WILDCARD) == "<PII:RRN:2>"
    assert vault.tokenize(_S1, "CARD", "v3", _WILDCARD) == "<PII:CARD:1>"
    assert vault.tokenize(_S2, "RRN", "v1", _WILDCARD) == "<PII:RRN:1>"


def test_unknown_entity_type_falls_back(db):
    label = vault.tokenize(_S1, "WEIRD", "zzz", _WILDCARD)
    assert label == "<PII:UNKNOWN:1>"
    assert vault.detokenize(_S1, label, "r", "p") == "zzz"


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------
def test_cipher_value_is_encrypted(db):
    secret = "880101-1234567"
    label = vault.tokenize(_S1, "RRN", secret, _WILDCARD)
    cipher = bytes(
        _scalar(db, "SELECT cipher_value FROM token_vault WHERE token_label = %s", label)
    )
    assert secret.encode() not in cipher
    assert len(cipher) == 12 + len(secret.encode()) + 16  # nonce ‖ ct ‖ GCM tag
    assert vault.detokenize(_S1, label, "r", "p") == secret  # 복호는 detokenize 로만


def test_missing_key_fails_closed(db, monkeypatch):
    monkeypatch.setenv("DLP_VAULT__KEY", "")
    with pytest.raises(RuntimeError):
        vault.tokenize(_S1, "RRN", "x", _WILDCARD)  # tokenize 는 전파
    monkeypatch.setenv("DLP_VAULT__KEY", _TEST_KEY)
    label = vault.tokenize(_S1, "RRN", "x", _WILDCARD)
    monkeypatch.setenv("DLP_VAULT__KEY", "")
    assert vault.detokenize(_S1, label, "r", "p") is None  # detokenize 는 None


# ---------------------------------------------------------------------------
# access_scope 게이팅
# ---------------------------------------------------------------------------
def test_default_scope_denies_everyone(db):
    label = vault.tokenize(
        _S1, "RRN", "880101-1234567"
    )  # scope 미지정 → {"roles":[],"purposes":[]}
    assert vault.detokenize(_S1, label, "agent", "cs") is None
    row = _scalar(
        db,
        "SELECT denied_reason FROM token_vault_access_log "
        "WHERE token_label = %s AND granted = false",
        label,
    )
    assert row == "role_not_in_scope"


def test_wildcard_scope_allows_any(db):
    label = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    assert vault.detokenize(_S1, label, "anyone", "whatever") == "880101-1234567"


def test_specific_scope_matches_only_listed(db):
    scope = {"roles": ["agent_l1"], "purposes": ["customer_support"]}
    label = vault.tokenize(_S1, "RRN", "880101-1234567", scope)
    assert vault.detokenize(_S1, label, "agent_l1", "customer_support") == "880101-1234567"
    assert vault.detokenize(_S1, label, "agent_l2", "customer_support") is None
    assert vault.detokenize(_S1, label, "agent_l1", "fraud_investigation") is None
    reasons = {
        r[0]
        for r in _rows(db, "SELECT denied_reason FROM token_vault_access_log WHERE granted = false")
    }
    assert reasons == {"role_not_in_scope", "purpose_not_in_scope"}


def test_every_attempt_is_logged(db):
    label = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    vault.detokenize(_S1, label, "r", "p")  # granted
    vault.detokenize(_S1, "<PII:RRN:99>", "r", "p")  # unknown
    assert _scalar(db, "SELECT count(*) FROM token_vault_access_log") == 2
    assert (
        _scalar(db, "SELECT denied_reason FROM token_vault_access_log WHERE granted = false")
        == "unknown_or_revoked"
    )


def test_access_log_has_no_plaintext(db):
    secret = "880101-7654321"
    label = vault.tokenize(_S1, "RRN", secret, _WILDCARD)
    vault.detokenize(_S1, label, "r", "p")
    dump = repr(_rows(db, "SELECT * FROM token_vault_access_log"))
    assert secret not in dump


# ---------------------------------------------------------------------------
# 만료 · purge
# ---------------------------------------------------------------------------
def test_expired_token_denies(db):
    label = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    _exec(
        db,
        "UPDATE token_vault SET expires_at = now() - interval '1 hour' WHERE token_label = %s",
        label,
    )
    assert vault.detokenize(_S1, label, "r", "p") is None
    assert (
        _scalar(
            db, "SELECT denied_reason FROM token_vault_access_log WHERE token_label = %s", label
        )
        == "expired"
    )


def test_purge_expired_revokes_then_hard_deletes(db):
    label = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    _exec(
        db,
        "UPDATE token_vault SET expires_at = now() - interval '1 hour' WHERE token_label = %s",
        label,
    )

    vault.purge_expired()  # 1) soft revoke
    assert (
        _scalar(db, "SELECT revoked_at FROM token_vault WHERE token_label = %s", label) is not None
    )
    assert vault.detokenize(_S1, label, "r", "p") is None

    _exec(
        db,
        "UPDATE token_vault SET revoked_at = now() - interval '2 days' WHERE token_label = %s",
        label,
    )
    vault.purge_expired()  # 2) 유예 지나 하드 삭제
    assert _scalar(db, "SELECT count(*) FROM token_vault WHERE token_label = %s", label) == 0


# ---------------------------------------------------------------------------
# detokenize_text
# ---------------------------------------------------------------------------
def test_detokenize_text_restores_only_authorized(db):
    ok = vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD)
    locked = vault.tokenize(_S1, "CARD", "1234-5678-9012-3456")  # 기본 scope → 거부
    text = f"주민 {ok} 카드 {locked} 끝"
    assert (
        vault.detokenize_text(_S1, text, "agent", "cs") == f"주민 880101-1234567 카드 {locked} 끝"
    )


# ---------------------------------------------------------------------------
# 동시성
# ---------------------------------------------------------------------------
def test_concurrent_same_value_single_row(db):
    with ThreadPoolExecutor(max_workers=16) as ex:
        labels = list(
            ex.map(lambda _: vault.tokenize(_S1, "RRN", "880101-1234567", _WILDCARD), range(100))
        )
    assert set(labels) == {"<PII:RRN:1>"}
    assert _scalar(db, "SELECT count(*) FROM token_vault WHERE session_id = %s", _S1) == 1


def test_concurrent_distinct_values_unique_labels(db):
    values = [f"val-{i:02d}" for i in range(20)]
    with ThreadPoolExecutor(max_workers=16) as ex:
        labels = list(ex.map(lambda v: vault.tokenize(_S1, "RRN", v, _WILDCARD), values))
    assert len(set(labels)) == 20
    nums = sorted(int(label.split(":")[2].rstrip(">")) for label in labels)
    assert nums == list(range(1, 21))
