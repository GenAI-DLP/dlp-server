"""
DB 인프라 스모크 테스트.

PostgreSQL 이 붙어 있고 스키마가 적용됐을 때만 실행된다 (conftest 의 `db` fixture 가
조건 미충족 시 skip). 커넥션 풀 · 스키마 테이블 · TTL 함수 · 시드를 확인한다.
"""

from __future__ import annotations

_EXPECTED_TABLES = {
    "sessions",
    "session_turns",
    "session_entities",
    "token_vault",
    "token_vault_access_log",
    "policy_versions",
    "policy_rules",
    "policy_risk_overrides",
    "log_events",
    "entity_type_ref",
    "purpose_ref",
}


def test_pool_select_1(db):
    with db.connection() as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1


def test_core_tables_exist(db):
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        ).fetchall()
    have = {r[0] for r in rows}
    missing = _EXPECTED_TABLES - have
    assert not missing, f"누락 테이블: {missing}"


def test_entity_type_ref_seed(db):
    with db.connection() as conn:
        codes = {r[0] for r in conn.execute("SELECT code FROM entity_type_ref").fetchall()}
    assert "RRN" in codes
    assert "UNKNOWN" in codes  # vault 폴백용 (docs fix/db-psql)
    assert len(codes) == 13


def test_purge_expired_function_exists(db):
    with db.connection() as conn:
        row = conn.execute("SELECT proname FROM pg_proc WHERE proname = 'purge_expired'").fetchone()
    assert row is not None


def test_health_reports_db_ok(db):
    from fastapi.testclient import TestClient

    from app.api import create_app

    resp = TestClient(create_app()).get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "db": "ok"}
