"""tests/test_detect_integration.py — regex_rules + dictionary + merge 통합 테스트.

detect 패키지에 아직 pipeline.py 오케스트레이터가 없어서, 여기서는
"세 레이어를 이어붙이면 실제로 뭐가 나오는가"를 검증한다.
나중에 app/detect/__init__.py 나 app/pipeline.py 에 orchestrator 함수가
생기면 그걸 직접 호출하는 테스트로 대체해도 된다.
"""

from app.detect.dictionary import detect as dict_detect
from app.detect.merge import merge_spans
from app.detect.regex_rules import detect as regex_detect


def run_pipeline(text: str, dict_automaton=None) -> list:
    """세 레이어를 순서대로 돌리고 병합한 결과를 반환하는 임시 헬퍼."""
    spans = []
    spans += regex_detect(text)
    spans += dict_detect(text, automaton=dict_automaton)
    return merge_spans(spans)


def test_mixed_regex_and_dict_hits_in_one_text():
    text = (
        "고객 김민준님 계좌 110-234-567890 관련하여, "
        "신용등급 확인 후 카드번호 4111-1111-1111-1111 로 재발급 처리해주세요."
    )
    result = run_pipeline(text)
    types = {s.type for s in result}

    assert "ACCOUNT" in types
    assert "CARD" in types
    assert "NAME" in types  # 기본 사전(financial_terms.txt)에 김민준 등록돼 있음
    assert "CREDIT_INFO" in types  # 신용등급

    # 서로 다른 구간이니 겹치지 않고 5개 다 살아있어야 함 (전화번호 패턴 오검출 없다고 가정)
    for span in result:
        assert span.confidence > 0


def test_overlapping_regex_types_resolved_by_merge():
    # CARD 패턴(13~19자리 숫자)이 ACCOUNT 패턴과 겹칠 수 있는 경우
    # -> merge.py 가 confidence/우선순위로 하나만 남겨야 함 (완전히 겹치는 구간 기준)
    text = "번호 4111-1111-1111-1111"
    result = run_pipeline(text)
    # 최소한 CARD 가 결과에 있어야 함 (계좌 패턴과 겹쳐도 confidence 높은 CARD 우선)
    assert any(s.type == "CARD" for s in result)


def test_dictionary_term_not_confused_with_regex_pii():
    text = "신용등급이 좋으신 고객님, 다음 달 대출한도가 상향됩니다."
    result = run_pipeline(text)
    types = [s.type for s in result]
    assert "CREDIT_INFO" in types
    # 이 문장엔 카드/계좌/전화번호 패턴이 전혀 없어야 함
    assert "CARD" not in types
    assert "ACCOUNT" not in types
    assert "PHONE" not in types


def test_empty_text_returns_empty():
    assert run_pipeline("") == []


def test_plain_conversation_no_false_positive():
    text = "안녕하세요, 오늘 상담 예약 확인차 연락드렸습니다. 감사합니다."
    result = run_pipeline(text)
    assert result == []
