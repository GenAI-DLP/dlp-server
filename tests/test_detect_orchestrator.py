"""tests/test_detect_orchestrator.py — app/detect 의 orchestrator 테스트."""

from unittest.mock import patch

from app.detect import analyze_turn, detect
from app.models import AnalysisContext, Turn


def test_detect_combines_regex_and_dict():
    text = "고객 김민준님 계좌 110-234-567890, 신용등급 확인 후 카드 4111-1111-1111-1111"
    spans = detect(text)
    types = {s.type for s in spans}
    assert "NAME" in types
    assert "ACCOUNT" in types
    assert "CREDIT_INFO" in types
    assert "CARD" in types


def test_detect_empty_text_returns_empty():
    assert detect("") == []


def test_layer_exception_is_isolated():
    """한 레이어가 예외를 던져도 나머지 레이어 결과는 살아있어야 한다."""
    with patch("app.detect.regex_rules.detect", side_effect=RuntimeError("boom")):
        result = detect("고객 김민준님 신용등급 확인")
    assert len(result) > 0
    assert all(s.source != "regex" for s in result)


def test_all_layers_fail_returns_empty_not_raises():
    with (
        patch("app.detect.regex_rules.detect", side_effect=RuntimeError("boom1")),
        patch("app.detect.dictionary.detect", side_effect=RuntimeError("boom2")),
    ):
        result = detect("아무 텍스트")
    assert result == []


def test_analyze_turn_fills_new_turn_spans():
    ctx = AnalysisContext(
        session_id="sess_1",
        direction="input",
        provider="openai",
        role="user",
        turns=[Turn(role="user", text="카드번호 4111-1111-1111-1111")],
    )
    analyze_turn(ctx)
    assert len(ctx.new_turn_spans) == 1
    assert ctx.new_turn_spans[0].type == "CARD"


def test_analyze_turn_uses_latest_turn_only():
    ctx = AnalysisContext(
        session_id="sess_1",
        direction="input",
        provider="openai",
        role="user",
        turns=[
            Turn(role="user", text="이전 턴 카드번호 4111-1111-1111-1111"),
            Turn(role="assistant", text="네 확인했습니다"),
            Turn(role="user", text="신용등급도 확인해주세요"),
        ],
    )
    analyze_turn(ctx)
    types = {s.type for s in ctx.new_turn_spans}
    assert "CARD" not in types  # 이전 턴 것이라 반영 안 됨
    assert "CREDIT_INFO" in types  # 최신 턴


def test_analyze_turn_empty_turns():
    ctx = AnalysisContext(
        session_id="sess_1", direction="input", provider="openai", role="user", turns=[]
    )
    analyze_turn(ctx)
    assert ctx.new_turn_spans == []
