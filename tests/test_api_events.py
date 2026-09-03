"""읽기 API 테스트 — /events · /events/{session_id}.

PostgreSQL 이 붙어 있고 스키마가 적용됐을 때만 돈다(`db` fixture 가 조건 미충족 시 skip).
"""

from __future__ import annotations

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
