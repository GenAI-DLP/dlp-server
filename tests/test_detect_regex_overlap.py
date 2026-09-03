"""
detect/regex_rules.py 의 PHONE/ACCOUNT/CARD 겹침 해결 검증.

실제 gRPC 클라이언트 테스트에서 재현됐던 두 사례를 그대로 재현한다:
  1) "010-1234-5678" 이 ACCOUNT 패턴에도 매치되던 문제
  2) 카드번호+계좌번호가 같은 문장에 있을 때 CARD/ACCOUNT 가 겹치던 문제
"""

from app.detect.regex_rules import detect


def test_phone_shaped_number_is_not_also_detected_as_account():
    text = "고객 연락처는 010-1234-5678 입니다."
    spans = detect(text)

    types_at_phone_position = {s.type for s in spans if "010-1234-5678" in s.value}
    assert types_at_phone_position == {"PHONE"}, (
        f"010-1234-5678 은 PHONE 으로만 분류돼야 함, 실제: {types_at_phone_position}"
    )


def test_card_number_wins_over_overlapping_account_pattern():
    # Luhn 유효 카드번호 (4111 1111 1111 1111 — 흔히 쓰는 테스트용 Visa 번호)
    text = "카드번호 4111-1111-1111-1111 로 결제해주세요."
    spans = detect(text)

    types = {s.type for s in spans}
    assert "CARD" in types
    # 같은 구간에서 ACCOUNT 로도 잡혀서 중복 타입이 나오면 안 됨
    card_span = next(s for s in spans if s.type == "CARD")
    overlapping_account = [
        s
        for s in spans
        if s.type == "ACCOUNT" and s.start < card_span.end and card_span.start < s.end
    ]
    assert overlapping_account == []


def test_non_overlapping_account_still_detected():
    """겹치지 않는 정상적인 계좌번호는 여전히 ACCOUNT 로 잡혀야 한다 (과도한 억제 방지)."""
    text = "계좌번호 110-234-567890 으로 입금 부탁드립니다."
    spans = detect(text)

    assert any(s.type == "ACCOUNT" and "110-234-567890" in s.value for s in spans)