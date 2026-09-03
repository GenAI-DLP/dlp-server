"""pipeline 배선 테스트 — 어댑터 연결 / 스테이지 규약 / block·transform 판정."""

from __future__ import annotations

import json

import pytest

from app import pipeline
from app.config import load_config
from app.models import AnalysisContext, InjectionVerdict

_REQ = json.dumps(
    {"model": "x", "messages": [{"role": "user", "content": "안녕하세요"}]},
    ensure_ascii=False,
).encode("utf-8")
_PII_REQ = json.dumps(
    {"model": "x", "messages": [{"role": "user", "content": "홍길동 880101-1234567"}]},
    ensure_ascii=False,
).encode("utf-8")
_RESP = json.dumps(
    {"choices": [{"message": {"role": "assistant", "content": "네 확인했습니다"}}]}
).encode("utf-8")


@pytest.fixture
def cfg():
    return load_config()


def _analyze(cfg, direction: str, body: bytes):
    return pipeline.analyze("s1", direction, "POST", "/v1/chat/completions", {}, body, config=cfg)


def test_input_no_stage_is_allow(cfg):
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "allow"
    assert d.transformed_body is None
    assert d.reason_obj["verdict"] == "allow"


def test_output_no_stage_is_allow(cfg):
    assert _analyze(cfg, "output", _RESP).action == "allow"


def test_stage_modifying_turn_text_yields_transform(cfg, monkeypatch):
    def redact(ctx: AnalysisContext) -> AnalysisContext:
        ctx.turns[-1].text = ctx.turns[-1].text.replace("880101-1234567", "<PII:RRN:1>")
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [redact])
    d = _analyze(cfg, "input", _PII_REQ)
    assert d.action == "transform"
    assert b"<PII:RRN:1>" in d.transformed_body
    assert b"880101-1234567" not in d.transformed_body
    assert json.loads(d.transformed_body)["model"] == "x"  # 기타 키 보존


def test_injection_hit_blocks(cfg, monkeypatch):
    def guard(ctx: AnalysisContext) -> AnalysisContext:
        ctx.injection = InjectionVerdict(hit=True, score=0.9, pattern="ignore previous")
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [guard])
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["guardrail_hits"][0]["pattern"] == "ignore previous"


def test_risk_hard_block(cfg, monkeypatch):
    def bump(ctx: AnalysisContext) -> AnalysisContext:
        ctx.risk_score = 0.95
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [bump])
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["risk_score"] == 0.95


def test_blocked_field_blocks_with_reason(cfg, monkeypatch):
    def guard(ctx: AnalysisContext) -> AnalysisContext:
        ctx.blocked = True
        ctx.block_reason = {"type": "data_exfil", "pattern": "send all customer data"}
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [guard])
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["guardrail_hits"][0]["type"] == "data_exfil"


def test_blocked_field_blocks_without_reason(cfg, monkeypatch):
    def guard(ctx: AnalysisContext) -> AnalysisContext:
        ctx.blocked = True
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [guard])
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "block"
    assert d.reason_obj["guardrail_hits"] == []


def test_blocked_on_output(cfg, monkeypatch):
    def guard(ctx: AnalysisContext) -> AnalysisContext:
        ctx.blocked = True
        ctx.block_reason = {"type": "output_secret_leak"}
        return ctx

    monkeypatch.setattr("app.pipeline._OUTPUT_STAGES", [guard])
    d = _analyze(cfg, "output", _RESP)
    assert d.action == "block"
    assert d.reason_obj["guardrail_hits"][0]["type"] == "output_secret_leak"


def test_purpose_policy_stage_populates_span_actions(cfg, monkeypatch):
    from app.models import Span
    from app.policy import engine

    # DB 없이: 캐시에 규칙셋 직접 주입 (CARD → block, 그 외 → tokenize)
    monkeypatch.setattr(
        engine,
        "_cache",
        engine.Ruleset(
            rules=[
                engine._Rule(None, None, "CARD", "block", 0),
                engine._Rule(None, None, None, "tokenize", -1),
            ]
        ),
    )

    def fake_detect(ctx: AnalysisContext) -> AnalysisContext:
        ctx.new_turn_spans = [
            Span("NAME", "홍길동", 0, 3, 0.6, "dict"),
            Span("CARD", "4111-1111-1111-1111", 4, 23, 0.97, "regex"),
        ]
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [fake_detect, engine.purpose_policy_stage])
    d = _analyze(cfg, "input", _REQ)

    assert d.action == "block"  # CARD span 이 block action
    assert d.reason_obj["guardrail_hits"][0]["type"] == "policy"
    assert d.reason_obj["purpose"] is not None


def test_blocked_short_circuits_later_stages(cfg, monkeypatch):
    ran = []

    def first(ctx: AnalysisContext) -> AnalysisContext:
        ran.append("first")
        ctx.blocked = True
        return ctx

    def second(ctx: AnalysisContext) -> AnalysisContext:
        ran.append("second")
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [first, second])
    d = _analyze(cfg, "input", _REQ)
    assert d.action == "block"
    assert ran == ["first"]  # second 는 실행되지 않음
