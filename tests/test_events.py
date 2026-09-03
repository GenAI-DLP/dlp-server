# """감사 로그 sink 테스트 — JSONL 기록 / 원문 무저장."""

# from __future__ import annotations

# import json

# from app import pipeline
# from app.config import load_config
# from app.logging.events import LogEvent, log_event

# _BODY = json.dumps(
#     {"messages": [{"role": "user", "content": "홍길동 880101-1234567"}]},
#     ensure_ascii=False,
# ).encode("utf-8")


# def test_log_event_appends_jsonl_line(tmp_path):
#     p = tmp_path / "e.jsonl"
#     log_event(LogEvent("s", "input", "gateway", "allow", 3), p)
#     log_event(LogEvent("s", "output", "gateway", "allow", 1), p)
#     lines = p.read_text(encoding="utf-8").splitlines()
#     assert len(lines) == 2
#     row = json.loads(lines[0])
#     assert row["verdict_action"] == "allow"
#     assert row["created_at"]


# def test_pipeline_emits_one_event(tmp_path):
#     cfg = load_config()  # autouse fixture 가 DLP_LOG_PATH → tmp_path/events.jsonl
#     pipeline.analyze("s1", "input", "POST", "/v1/chat/completions", {}, _BODY, config=cfg)
#     lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
#     assert len(lines) == 1
#     row = json.loads(lines[0])
#     assert row["direction"] == "input"
#     assert row["provider"] == "gateway"
#     assert row["verdict_action"] == "allow"
#     assert row["latency_ms"] >= 0


# def test_log_has_no_raw_pii(tmp_path):
#     cfg = load_config()
#     pipeline.analyze("s1", "input", "POST", "/x", {}, _BODY, config=cfg)
#     text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
#     assert "880101-1234567" not in text
#     assert "홍길동" not in text
