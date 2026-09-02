"""tests/test_regex_rules.py — detect/regex_rules.py 단위 테스트."""

from app.detect.regex_rules import detect


def test_valid_rrn_high_confidence():
    text = "제 주민번호는 900101-1234568 입니다."
    spans = [s for s in detect(text) if s.type == "RRN"]
    assert len(spans) == 1
    assert spans[0].confidence >= 0.9


def test_invalid_rrn_low_confidence():
    text = "주민번호 900101-1234567"  # 체크섬 실패 (마지막 자리 8 -> 7)
    spans = [s for s in detect(text) if s.type == "RRN"]
    assert len(spans) == 1
    assert spans[0].confidence < 0.5


def test_valid_card_luhn_pass():
    text = "카드번호 4111-1111-1111-1111 로 결제해주세요."
    spans = [s for s in detect(text) if s.type == "CARD"]
    assert len(spans) == 1
    assert spans[0].confidence >= 0.9


def test_invalid_card_luhn_fail():
    text = "카드번호 4111-1111-1111-1112"  # Luhn 체크 실패
    spans = [s for s in detect(text) if s.type == "CARD"]
    assert len(spans) == 1
    assert spans[0].confidence < 0.5


def test_valid_bizno():
    text = "사업자등록번호: 128-86-19631"
    spans = [s for s in detect(text) if s.type == "BIZNO"]
    assert len(spans) == 1
    assert spans[0].confidence >= 0.9


def test_phone_pattern():
    text = "연락처는 010-1234-5678 입니다."
    spans = [s for s in detect(text) if s.type == "PHONE"]
    assert len(spans) == 1
    assert spans[0].value == "010-1234-5678"


def test_email_pattern():
    text = "메일은 test.user@example.co.kr 로 보내주세요."
    spans = [s for s in detect(text) if s.type == "EMAIL"]
    assert len(spans) == 1
    assert spans[0].value == "test.user@example.co.kr"


def test_account_pattern_low_confidence():
    text = "계좌번호는 110-234-567890 입니다."
    spans = [s for s in detect(text) if s.type == "ACCOUNT"]
    assert len(spans) == 1
    assert spans[0].confidence < 0.9  # 체크섬 없어서 상한 낮음


def test_no_false_positive_on_plain_text():
    text = "오늘 회의는 3시에 시작합니다."
    spans = detect(text)
    assert spans == []


def test_multiple_pii_in_one_text():
    text = "계좌 110-234-567890, 카드 4111-1111-1111-1111, 연락처 010-1234-5678"
    spans = detect(text)
    types = {s.type for s in spans}
    assert "ACCOUNT" in types
    assert "CARD" in types
    assert "PHONE" in types
