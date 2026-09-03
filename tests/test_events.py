"""감사 로그 sink 테스트 — JSONL / PostgreSQL log_events / 폴백 / 원문 무저장."""

from __future__ import annotations

import json

import pytest

from app import pipeline
from app.config import load_config
from app.logging.events import LogEvent, log_event

_BODY = json.dumps(
    {"messages": [{"role": "user", "content": "홍길동 880101-1234567"}]},
    ensure_ascii=False,
).encode("utf-8")


def test_log_event_appends_jsonl_line(tmp_path):
    p = tmp_path / "e.jsonl"
    log_event(LogEvent("s", "input", "gateway", "allow", 3), p)
    log_event(LogEvent("s", "output", "gateway", "allow", 1), p)
    lines = p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    row = json.loads(lines[0])
    assert row["verdict_action"] == "allow"
    assert row["created_at"]


def test_pipeline_emits_one_event(tmp_path):
    cfg = load_config()  # autouse fixture 가 DLP_LOG_SINK=jsonl + DLP_LOG_PATH → tmp
    pipeline.analyze("s1", "input", "POST", "/v1/chat/completions", {}, _BODY, config=cfg)
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["direction"] == "input"
    assert row["provider"] == "gateway"
    assert row["verdict_action"] == "allow"
    assert row["latency_ms"] >= 0


def test_log_has_no_raw_pii(tmp_path):
    cfg = load_config()
    pipeline.analyze("s1", "input", "POST", "/x", {}, _BODY, config=cfg)
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "880101-1234567" not in text
    assert "홍길동" not in text


def test_pg_sink_failure_falls_back_to_jsonl(tmp_path, monkeypatch):
    """pg sink 에서 write_pg 가 터져도 판정은 나가고 JSONL 로 폴백된다."""
    monkeypatch.setenv("DLP_LOG_SINK", "pg")

    def _boom(_event):
        raise RuntimeError("DB down")

    monkeypatch.setattr(pipeline, "write_pg", _boom)

    d = pipeline.analyze("s1", "input", "POST", "/x", {}, _BODY, config=load_config())

    assert d.action == "allow"
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


def test_pipeline_writes_log_events_row(db, monkeypatch):
    """pg sink: 판정 1건이 log_events 에 원문 없이 기록되고 원본 session_id 는 reason 에 남는다."""
    monkeypatch.setenv("DLP_LOG_SINK", "pg")

    pipeline.analyze("s1", "input", "POST", "/v1/chat/completions", {}, _BODY, config=load_config())

    with db.connection() as conn:
        rows = conn.execute(
            "SELECT direction, provider, verdict_action, latency_ms, "
            "reason ->> 'session_id_raw', log_events::text "
            "FROM log_events"
        ).fetchall()

    assert len(rows) == 1
    direction, provider, action, latency_ms, sid_raw, row_text = rows[0]
    assert (direction, provider, action) == ("input", "gateway", "allow")
    assert latency_ms >= 0
    assert sid_raw == "s1"
    assert "880101-1234567" not in row_text
    assert "홍길동" not in row_text


@pytest.mark.parametrize("sink", ["pg", "both"])
def test_sink_modes_write_to_pg(db, tmp_path, monkeypatch, sink):
    monkeypatch.setenv("DLP_LOG_SINK", sink)

    pipeline.analyze("sess_abc", "input", "POST", "/x", {}, _BODY, config=load_config())

    with db.connection() as conn:
        n = conn.execute("SELECT count(*) FROM log_events").fetchone()[0]
    assert n == 1

    jsonl = tmp_path / "events.jsonl"
    assert jsonl.exists() == (sink == "both")
