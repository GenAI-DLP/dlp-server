"""pipeline 배선 테스트 — 어댑터 연결 / 스테이지 규약 / block·transform 판정."""

from __future__ import annotations

import json

from app import pipeline
from app.config import load_config
from app.models import AnalysisContext, InjectionVerdict

_CFG = load_config()

_REQ = json.dumps(
    {"model": "x", "messages": [{"role": "user", "content": "홍길동 880101-1234567"}]},
    ensure_ascii=False,
).encode("utf-8")
_RESP = json.dumps(
    {"choices": [{"message": {"role": "assistant", "content": "네 확인했습니다"}}]}
).encode("utf-8")


def _analyze(direction: str, body: bytes):
    return pipeline.analyze("s1", direction, "POST", "/v1/chat/completions", {}, body, config=_CFG)


def test_input_no_stage_is_allow():
    d = _analyze("input", _REQ)
    assert d.action == "allow"
    assert d.transformed_body is None
    assert d.reason_obj["verdict"] == "allow"


def test_output_no_stage_is_allow():
    assert _analyze("output", _RESP).action == "allow"


def test_stage_modifying_turn_text_yields_transform(monkeypatch):
    def redact(ctx: AnalysisContext) -> AnalysisContext:
        ctx.turns[-1].text = ctx.turns[-1].text.replace("880101-1234567", "<PII:RRN:1>")
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [redact])
    d = _analyze("input", _REQ)
    assert d.action == "transform"
    assert b"<PII:RRN:1>" in d.transformed_body
    assert b"880101-1234567" not in d.transformed_body
    assert json.loads(d.transformed_body)["model"] == "x"  # 기타 키 보존


def test_injection_hit_blocks(monkeypatch):
    def guard(ctx: AnalysisContext) -> AnalysisContext:
        ctx.injection = InjectionVerdict(hit=True, score=0.9, pattern="ignore previous")
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [guard])
    d = _analyze("input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["guardrail_hits"][0]["pattern"] == "ignore previous"


def test_risk_hard_block(monkeypatch):
    def bump(ctx: AnalysisContext) -> AnalysisContext:
        ctx.risk_score = 0.95
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [bump])
    d = _analyze("input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["risk_score"] == 0.95
