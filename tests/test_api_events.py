"""읽기 API 테스트 — /events · /events/{session_id}.

PostgreSQL 이 붙어 있고 스키마가 적용됐을 때만 돈다(`db` fixture 가 조건 미충족 시 skip).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from app.api import create_app
from app.ids import coerce_session_uuid

_RAW_PII = "880101-1234567"  # 어떤 응답에도 나오면 안 되는 원문


@pytest.fixture
def client(db):
    return TestClient(create_app())


def _insert(
    db_mod,
    *,
    session_id: str = "s1",
    direction: str = "input",
    provider: str = "gateway",
    purpose: str | None = None,
    verdict: str = "allow",
    transforms: list | None = None,
    entities: list | None = None,
    guardrail: list | None = None,
    fail: bool = False,
    latency_ms: int = 10,
    reason_extra: dict | None = None,
    created_at: datetime | None = None,
) -> None:
    reason = {"session_id_raw": session_id, "verdict": verdict, **(reason_extra or {})}
    with db_mod.connection() as conn:
        conn.execute(
            "INSERT INTO log_events (session_id, direction, provider, purpose, verdict_action, "
            "transforms, entities_summary, guardrail_hits, fail_policy_applied, latency_ms, "
            "reason, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, COALESCE(%s, now()))",
            (
                str(coerce_session_uuid(session_id)),
                direction,
                provider,
                purpose,
                verdict,
                Jsonb(transforms or []),
                Jsonb(entities or []),
                Jsonb(guardrail or []),
                fail,
                latency_ms,
                Jsonb(reason),
                created_at,
            ),
        )


def test_events_returns_latest_first(client, db):
    base = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    _insert(db, session_id="a", created_at=base)
    _insert(db, session_id="b", created_at=base + timedelta(minutes=1))
    _insert(db, session_id="c", created_at=base + timedelta(minutes=2))

    rows = client.get("/events").json()

    assert [r["session_id_raw"] for r in rows] == ["c", "b", "a"]
    # 응답 created_at 은 KST(+09:00)로 통일
    assert rows[0]["created_at"] == "2026-09-01T21:02:00+09:00"


def test_events_limit_is_clamped_not_rejected(client, db):
    _insert(db)
    r = client.get("/events", params={"limit": 100_000})
    assert r.status_code == 200


def test_events_limit_applies(client, db):
    for i in range(3):
        _insert(db, session_id=f"s{i}")
    assert len(client.get("/events", params={"limit": 2}).json()) == 2


def test_events_filters(client, db):
    _insert(db, session_id="x", direction="input", verdict="allow")
    _insert(db, session_id="x", direction="output", verdict="transform")
    _insert(db, session_id="y", direction="input", verdict="block")

    assert len(client.get("/events", params={"direction": "output"}).json()) == 1
    assert len(client.get("/events", params={"verdict": "block"}).json()) == 1

    by_session = client.get("/events", params={"session_id": "x"}).json()
    assert len(by_session) == 2
    assert {r["session_id_raw"] for r in by_session} == {"x"}


def test_events_since_filter(client, db):
    base = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
    _insert(db, session_id="old", created_at=base)
    _insert(db, session_id="new", created_at=base + timedelta(hours=2))

    rows = client.get("/events", params={"since": (base + timedelta(hours=1)).isoformat()}).json()
    assert [r["session_id_raw"] for r in rows] == ["new"]


def test_events_promotes_reason_fields(client, db):
    _insert(
        db,
        session_id="s",
        verdict="block",
        reason_extra={"risk_score": 0.73, "note": "risk_hard_block"},
    )
    row = client.get("/events").json()[0]
    assert row["risk_score"] == 0.73
    assert row["note"] == "risk_hard_block"
    assert row["session_id_raw"] == "s"
    assert "reason" not in row  # 목록 응답에는 reason 원본을 접는다


def test_session_timeline_is_ascending_with_reason(client, db):
    base = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
    _insert(db, session_id="sess", direction="input", created_at=base)
    _insert(db, session_id="sess", direction="output", created_at=base + timedelta(seconds=5))
    _insert(db, session_id="other", direction="input", created_at=base)

    sid = str(coerce_session_uuid("sess"))
    rows = client.get(f"/events/{sid}").json()

    assert [r["direction"] for r in rows] == ["input", "output"]
    assert rows[0]["reason"]["session_id_raw"] == "sess"


def test_session_timeline_accepts_raw_session_id(client, db):
    _insert(db, session_id="human-readable-sess")
    rows = client.get("/events/human-readable-sess").json()
    assert len(rows) == 1


def test_no_raw_pii_in_response(client, db):
    _insert(
        db,
        session_id="s",
        verdict="transform",
        transforms=[{"entity": "RRN", "action": "tokenize", "token_label": "<PII:RRN:1>"}],
        entities=[{"type": "RRN", "masked_preview": "8801**-*******", "confidence": 0.99}],
    )
    body = client.get("/events").text + client.get(f"/events/{coerce_session_uuid('s')}").text
    assert _RAW_PII not in body


def test_events_rejects_bad_params(client, db):
    assert client.get("/events", params={"verdict": "nope"}).status_code == 422
    assert client.get("/events", params={"direction": "sideways"}).status_code == 422
    assert client.get("/events", params={"since": "not-a-date"}).status_code == 422
    assert client.get("/events", params={"limit": 0}).status_code == 422


# --- /stats ---------------------------------------------------------------


def test_stats_counts(client, db):
    _insert(db, session_id="a", verdict="allow")
    _insert(db, session_id="a", verdict="allow", direction="output")
    _insert(db, session_id="b", verdict="block", guardrail=[{"type": "injection"}])
    _insert(db, session_id="c", verdict="transform")
    _insert(db, session_id="d", verdict="block", fail=True, reason_extra={"stage": "pipeline"})

    s = client.get("/stats", params={"window": "24h"}).json()

    assert s["totals"] == {"events": 5, "sessions": 4, "input": 4, "output": 1}
    assert s["verdict"] == {"allow": 2, "block": 2, "transform": 1}
    assert s["guardrail_hits"] == 1
    assert s["fail_closed"] == 1


def test_stats_latency_p95(client, db):
    for ms in (10, 20, 30, 40, 100):
        _insert(db, session_id=f"s{ms}", latency_ms=ms)
    s = client.get("/stats", params={"window": "24h"}).json()
    # percentile_cont(0.95) over [10,20,30,40,100] → 40 + 0.8*(100-40) = 88.0
    assert s["latency_ms"]["p95"] == 88.0
    assert s["latency_ms"]["avg"] == 40.0


def test_stats_by_entity_and_action(client, db):
    _insert(
        db,
        session_id="s1",
        verdict="transform",
        transforms=[{"entity": "RRN", "action": "tokenize"}],
        entities=[{"type": "RRN", "masked_preview": "8801**", "confidence": 0.9}],
    )
    _insert(
        db,
        session_id="s2",
        verdict="transform",
        transforms=[{"entity": "RRN", "action": "tokenize"}, {"entity": "PHONE", "action": "mask"}],
        entities=[{"type": "RRN", "masked_preview": "9002**", "confidence": 0.8}],
    )
    s = client.get("/stats", params={"window": "24h"}).json()

    assert {row["type"]: row["count"] for row in s["by_entity_type"]} == {"RRN": 2}
    assert {row["action"]: row["count"] for row in s["by_action"]} == {"tokenize": 2, "mask": 1}


def test_stats_buckets_sum_matches_events(client, db):
    for i in range(4):
        _insert(db, session_id=f"s{i}", verdict="allow" if i else "block")
    s = client.get("/stats", params={"window": "24h"}).json()

    assert s["buckets"]
    total = sum(b["allow"] + b["block"] + b["transform"] for b in s["buckets"])
    assert total == s["totals"]["events"] == 4
    assert s["buckets"][0]["ts"].endswith("+09:00")


def test_stats_rejects_bad_window(client, db):
    assert client.get("/stats", params={"window": "1d"}).status_code == 422
    assert client.get("/stats", params={"window": "0h"}).status_code == 422
    assert client.get("/stats", params={"window": "abc"}).status_code == 422


# --- /vault-access ------------------------------------------------------------


def _insert_vault_access(
    db_mod,
    *,
    session_id: str,
    token_label: str = "<PII:RRN:1>",
    requested_role: str = "agent_l1",
    requested_purpose: str | None = "doc_summarize",
    granted: bool = True,
    denied_reason: str | None = None,
    accessed_at: datetime | None = None,
) -> None:
    with db_mod.connection() as conn:
        conn.execute(
            "INSERT INTO token_vault_access_log (token_id, session_id, token_label, "
            "requested_role, requested_purpose, granted, denied_reason, accessed_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s, COALESCE(%s, now()))",
            (
                str(uuid.uuid4()),
                str(coerce_session_uuid(session_id)),
                token_label,
                requested_role,
                requested_purpose,
                granted,
                denied_reason,
                accessed_at,
            ),
        )


def test_vault_access_latest_first_with_denied_flag(client, db):
    base = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
    _insert_vault_access(db, session_id="sess", granted=True, accessed_at=base)
    _insert_vault_access(
        db,
        session_id="sess",
        granted=False,
        denied_reason="purpose_mismatch",
        accessed_at=base + timedelta(minutes=1),
    )
    _insert_vault_access(db, session_id="other", granted=True, accessed_at=base)

    rows = client.get("/vault-access", params={"session_id": "sess"}).json()

    assert len(rows) == 2
    assert rows[0]["granted"] is False
    assert rows[0]["denied_reason"] == "purpose_mismatch"
    assert rows[0]["accessed_at"].endswith("+09:00")
    assert all(isinstance(r["token_id"], str) for r in rows)


def test_vault_access_requires_session_id(client, db):
    assert client.get("/vault-access").status_code == 422
