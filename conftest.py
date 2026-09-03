"""공통 테스트 설정."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _audit_log_to_tmp(tmp_path, monkeypatch):
    """감사 로그를 테스트별 tmp 파일로 보내 repo 오염 방지.

    기본 sink 를 jsonl 로 고정한다 — DB 없는 테스트가 매번 PG 풀에 연결을 시도하지
    않도록. PG sink 를 검증하는 테스트는 DLP_LOG_SINK=pg 로 직접 오버라이드한다.
    """
    monkeypatch.setenv("DLP_LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("DLP_LOG_SINK", "jsonl")


# TRUNCATE 대상 — 운영/볼트/감사/정책. 조회 테이블(entity_type_ref, purpose_ref) 시드는 보존.
_TRUNCATE_TABLES = (
    "sessions, session_turns, session_entities, "
    "token_vault, token_vault_access_log, "
    "policy_versions, policy_rules, policy_risk_overrides, "
    "log_events"
)


@pytest.fixture
def db():
    """PostgreSQL 이 붙어 있고 스키마가 적용됐을 때만 도는 테스트용 fixture.

    조건 미충족 시 skip. 테스트 후 운영/볼트/감사/정책 테이블을 TRUNCATE 한다.
    """
    import psycopg

    from app import db as _db
    from app.config import load_config

    dsn = load_config().db.dsn

    # 풀(재시도·긴 timeout)을 거치지 않고 짧게 직접 찔러서 빠르게 skip 판정
    try:
        with psycopg.connect(dsn, connect_timeout=3) as probe:
            has_schema = probe.execute("SELECT to_regclass('public.token_vault')").fetchone()[0]
    except Exception as e:  # 연결 불가면 skip 이지 실패가 아님
        pytest.skip(f"PostgreSQL 없음: {e}")

    if has_schema is None:
        pytest.skip("스키마 미적용 — python scripts/apply_schema.py 먼저 실행")

    yield _db

    with _db.connection() as conn:
        conn.execute(f"TRUNCATE {_TRUNCATE_TABLES} RESTART IDENTITY CASCADE")
        conn.commit()
