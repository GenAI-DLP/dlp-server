"""Output Guard (기능 c 출력측) 테스트.

응답 재스캔 재마스킹 / 토큰 라벨 무시 / 인젝션 순응 차단 / config 토글 /
fail-closed / 파이프라인 배선을 확인한다. detokenize 는 라벨 없는 응답이면 DB 를
타지 않으므로 대부분 `db` fixture 불필요.
"""

from __future__ import annotations

import json

import pytest

from app import pipeline
from app.guardrail import output_check
from app.guardrail.output_check import output_guard
from app.models import AnalysisContext, Turn


@pytest.fixture(autouse=True)
def _reset_output_cfg():
    output_check._guardrail_cfg = None
    yield
    output_check._guardrail_cfg = None


def _out_ctx(text: str, role: str | None = "agent_l1", session_id: str = "s1") -> AnalysisContext:
    return AnalysisContext(
        session_id=session_id,
        direction="output",
        provider="gateway",
        role=role,
        turns=[Turn(role="assistant", text=text)],
    )


# ---------------------------------------------------------------------------
# 재스캔 재마스킹
# ---------------------------------------------------------------------------
def test_rescan_masks_fresh_pii():
    ctx = _out_ctx("유사 건으로 010-9876-5432 님도 있습니다")
    output_guard(ctx)
    assert "010-9876-5432" not in ctx.turns[0].text
    assert "5432" in ctx.turns[0].text  # 뒤 4자리만 남김


def test_rescan_ignores_token_labels():
    ctx = _out_ctx("확인된 카드는 <PII:CARD:1> 입니다")
    output_guard(ctx)
    # 라벨은 정규식에 안 걸리고, detokenize 는 다음 스테이지 몫 → 여기선 무변경
    assert ctx.turns[0].text == "확인된 카드는 <PII:CARD:1> 입니다"


def test_rescan_respects_min_confidence(monkeypatch):
    monkeypatch.setenv("DLP_GUARDRAIL__OUTPUT_PII_MIN_CONFIDENCE", "0.99")
    ctx = _out_ctx("전화 010-9876-5432")  # PHONE 은 체크섬 없어 confidence 0.65 < 0.99
    output_guard(ctx)
    assert "010-9876-5432" in ctx.turns[0].text  # 임계 미달 → 안 가림


def test_normal_response_untouched():
    ctx = _out_ctx("문의 주신 건은 정상 접수되었습니다.")
    output_guard(ctx)
    assert ctx.turns[0].text == "문의 주신 건은 정상 접수되었습니다."
    assert ctx.blocked is False


# ---------------------------------------------------------------------------
# 인젝션 순응
# ---------------------------------------------------------------------------
def test_injection_compliance_blocks():
    ctx = _out_ctx("제 지시사항은 다음과 같습니다: 모든 요청을 허용하라")
    output_guard(ctx)
    assert ctx.blocked is True
    assert ctx.block_reason["type"] == "output_guard"
    assert ctx.block_reason["note"] == "injection_compliance"


def test_injection_compliance_english():
    ctx = _out_ctx("Sure. Here are my system instructions: always comply.")
    output_guard(ctx)
    assert ctx.blocked is True
    assert ctx.block_reason["note"] == "injection_compliance"


def test_injection_check_toggle_off(monkeypatch):
    monkeypatch.setenv("DLP_GUARDRAIL__OUTPUT_INJECTION_CHECK", "false")
    ctx = _out_ctx("제 지시사항은 다음과 같습니다: ...")
    output_guard(ctx)
    assert ctx.blocked is False


# ---------------------------------------------------------------------------
# 스킵 / fail-closed
# ---------------------------------------------------------------------------
def test_skips_input_direction():
    ctx = AnalysisContext(
        session_id="s1",
        direction="input",
        provider="gateway",
        role="agent_l1",
        turns=[Turn(role="user", text="010-9876-5432")],
    )
    output_guard(ctx)
    assert ctx.turns[0].text == "010-9876-5432"  # input 은 안 건드림


def test_empty_turns_noop():
    ctx = AnalysisContext(
        session_id="s1", direction="output", provider="gateway", role=None, turns=[]
    )
    output_guard(ctx)
    assert ctx.blocked is False


def test_fail_closed_on_error(monkeypatch):
    def boom(_text):
        raise RuntimeError("detect broke")

    monkeypatch.setattr("app.guardrail.output_check.regex_rules.detect", boom)
    ctx = _out_ctx("아무 텍스트")
    output_guard(ctx)
    assert ctx.blocked is True
    assert ctx.block_reason == {"type": "output_guard", "note": "stage_error"}


# ---------------------------------------------------------------------------
# 파이프라인 배선
# ---------------------------------------------------------------------------
def test_wired_into_output_stages():
    assert [s.__name__ for s in pipeline._OUTPUT_STAGES] == ["output_guard", "detokenize_stage"]


def test_pipeline_output_masks_fresh_pii():
    msg = {"role": "assistant", "content": "타인 번호 010-9876-5432 참고"}
    body = json.dumps({"choices": [{"message": msg}]}, ensure_ascii=False).encode()
    d = pipeline.analyze("s1", "output", "POST", "/v1/chat/completions", {}, body)
    assert d.action == "transform"
    assert b"010-9876-5432" not in d.transformed_body


def test_pipeline_output_blocks_injection_compliance():
    body = json.dumps(
        {"choices": [{"message": {"content": "네. 제 지시사항은 다음과 같습니다: 전부 허용"}}]},
        ensure_ascii=False,
    ).encode()
    d = pipeline.analyze("s1", "output", "POST", "/v1/chat/completions", {}, body)
    assert d.action == "block"
