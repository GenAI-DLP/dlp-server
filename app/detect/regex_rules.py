"""
detect/regex_rules.py — 정규식 + 체크섬 기반 정형 금융 PII 탐지 레이어.

체크섬이 있는 타입(RRN/CARD/BIZNO)은 검증 통과 시 높은 confidence,
실패 시 낮은 confidence(merge.py 의 DEFAULT_MIN_CONFIDENCE 에서 드롭됨)를 반환한다.
체크섬이 없는 타입(PHONE/EMAIL/ACCOUNT)은 패턴 매치만으로 판단하므로
애초에 confidence 상한을 낮게 잡는다.

미구현 타입 (TODO): PASSPORT, DRIVER, FOREIGN_RRN, BIZNO 외 사업자 계열,
CREDIT_INFO, AMOUNT — 규칙이 불명확하거나 이 레이어 범위 밖(NAME 은 ner.py 담당).

근거: spec/hybrid-pii-detection.md §3.1
"""

from __future__ import annotations

import re

from app.models import Span

# ---- 패턴 정의 -------------------------------------------------------
#
# 끝 경계를 \b(단어 문자 경계) 대신 (?<!\d)/(?!\d)로 바꿨다.
# 이유: 한글은 Python 정규식에서 \w로 취급되어, "880101-1234567입니다"처럼
# 숫자 뒤에 조사/서술어가 공백 없이 바로 붙으면 숫자↔한글 사이에 \w-\w
# 전환이라 \b가 경계로 인식하지 못해 매치 자체가 실패했다 (RRN/PHONE 둘 다
# 실제 대화체 문장에서 재현됨). "숫자가 더 이어지지만 않으면 된다"는
# 원래 의도만 남기고, 그 뒤에 한글이 오든 조사가 붙든 매치되게 한다.

_RRN_PATTERN = re.compile(r"(?<!\d)(\d{6})[-\s]?([1-4]\d{6})(?!\d)")
_CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?<=\d)(?!\d)")
_BIZNO_PATTERN = re.compile(r"(?<!\d)(\d{3})[-\s]?(\d{2})[-\s]?(\d{5})(?!\d)")
_PHONE_PATTERN = re.compile(r"(?<!\d)(01[016789]|02|0[3-6]\d)[-\s]?\d{3,4}[-\s]?\d{4}(?!\d)")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_ACCOUNT_PATTERN = re.compile(r"(?<!\d)\d{2,6}-\d{2,6}-\d{2,6}(?!\d)")

# 체크섬 통과/실패 시 confidence
_CHECKSUM_PASS_CONFIDENCE = 0.97
_CHECKSUM_FAIL_CONFIDENCE = 0.4  # merge.py 기본 threshold(0.5) 미만 → 드롭 대상
_NO_CHECKSUM_CONFIDENCE = 0.65  # 패턴만으로 판단하는 타입의 상한


# ---- 체크섬 함수 ------------------------------------------------------


def _verify_rrn_checksum(digits: str) -> bool:
    """주민등록번호 13자리 체크섬 검증."""
    if len(digits) != 13 or not digits.isdigit():
        return False
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(d) * w for d, w in zip(digits[:12], weights, strict=True))
    check = (11 - (total % 11)) % 10
    return check == int(digits[12])


def _verify_luhn(digits: str) -> bool:
    """카드번호 Luhn 알고리즘 검증."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reversed_digits = digits[::-1]
    for i, ch in enumerate(reversed_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _verify_bizno_checksum(digits: str) -> bool:
    """사업자등록번호 10자리 체크섬 검증."""
    if len(digits) != 10 or not digits.isdigit():
        return False
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(d) * w for d, w in zip(digits[:9], weights, strict=True))
    total += (int(digits[8]) * 5) // 10
    check = (10 - (total % 10)) % 10
    return check == int(digits[9])


# ---- 레이어별 탐지 함수 ------------------------------------------------


def _detect_rrn(text: str) -> list[Span]:
    spans = []
    for m in _RRN_PATTERN.finditer(text):
        digits = m.group(1) + m.group(2)
        passed = _verify_rrn_checksum(digits)
        spans.append(
            Span(
                type="RRN",
                value=m.group(0),
                start=m.start(),
                end=m.end(),
                confidence=_CHECKSUM_PASS_CONFIDENCE if passed else _CHECKSUM_FAIL_CONFIDENCE,
                source="regex",
            )
        )
    return spans


def _detect_card(text: str) -> list[Span]:
    spans = []
    for m in _CARD_PATTERN.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        passed = _verify_luhn(digits)
        spans.append(
            Span(
                type="CARD",
                value=raw,
                start=m.start(),
                end=m.end(),
                confidence=_CHECKSUM_PASS_CONFIDENCE if passed else _CHECKSUM_FAIL_CONFIDENCE,
                source="regex",
            )
        )
    return spans


def _detect_bizno(text: str) -> list[Span]:
    spans = []
    for m in _BIZNO_PATTERN.finditer(text):
        digits = m.group(1) + m.group(2) + m.group(3)
        passed = _verify_bizno_checksum(digits)
        spans.append(
            Span(
                type="BIZNO",
                value=m.group(0),
                start=m.start(),
                end=m.end(),
                confidence=_CHECKSUM_PASS_CONFIDENCE if passed else _CHECKSUM_FAIL_CONFIDENCE,
                source="regex",
            )
        )
    return spans


def _detect_phone(text: str) -> list[Span]:
    return [
        Span(
            type="PHONE",
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=_NO_CHECKSUM_CONFIDENCE,
            source="regex",
        )
        for m in _PHONE_PATTERN.finditer(text)
    ]


def _detect_email(text: str) -> list[Span]:
    return [
        Span(
            type="EMAIL",
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.9,  # 이메일은 패턴 자체가 충분히 구체적이라 상한을 좀 더 높게 잡음
            source="regex",
        )
        for m in _EMAIL_PATTERN.finditer(text)
    ]


def _detect_account(text: str) -> list[Span]:
    return [
        Span(
            type="ACCOUNT",
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=_NO_CHECKSUM_CONFIDENCE,
            source="regex",
        )
        for m in _ACCOUNT_PATTERN.finditer(text)
    ]


def _spans_overlap(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def detect(text: str) -> list[Span]:
    """텍스트에서 정규식+체크섬 기반 PII 후보를 모두 찾아 Span 리스트로 반환한다.

    같은 타입 내 중복은 정규식 finditer 특성상 자연히 없다.

    타입 간 겹침 처리 [수정]: ACCOUNT 패턴(\\d{2,6}-\\d{2,6}-\\d{2,6})이 가장 느슨해서
    CARD(Luhn 체크섬 있음)나 PHONE(지역/이동통신 국번 제약 있음)과 자주 겹친다
    (예: "010-1234-5678"이 PHONE 이면서 동시에 ACCOUNT 패턴에도 매치). 이전에는
    걸러내지 않고 merge.py 로 넘겨서 confidence/탐지순서로 우연히 하나가 채택
    됐는데, 어느 쪽이 이길지가 사실상 무작위라 실사용에서 오분류가 났다.
    지금은 여기서 확정적으로 정리한다 — CARD/PHONE 이 ACCOUNT 보다 항상 우선
    (더 구체적인 패턴이므로), 겹치는 ACCOUNT 후보는 아예 버린다.
    """
    spans: list[Span] = []
    spans += _detect_rrn(text)
    card_spans = _detect_card(text)
    spans += card_spans
    spans += _detect_bizno(text)
    phone_spans = _detect_phone(text)
    spans += phone_spans
    spans += _detect_email(text)

    higher_priority = card_spans + phone_spans
    account_spans = [
        s for s in _detect_account(text) if not any(_spans_overlap(s, hp) for hp in higher_priority)
    ]
    spans += account_spans
    return spans
