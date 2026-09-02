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

_RRN_PATTERN = re.compile(r"\b(\d{6})[-\s]?([1-4]\d{6})\b")
_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_BIZNO_PATTERN = re.compile(r"\b(\d{3})[-\s]?(\d{2})[-\s]?(\d{5})\b")
_PHONE_PATTERN = re.compile(r"\b(01[016789]|02|0[3-6]\d)[-\s]?\d{3,4}[-\s]?\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# 계좌번호: 은행별 자릿수·구분자가 제각각이라 "숫자-숫자-숫자" 형태의
# 10~14자리 조합을 느슨하게 매치. 체크섬 없음 → confidence 낮게.
_ACCOUNT_PATTERN = re.compile(r"\b\d{2,6}-\d{2,6}-\d{2,6}\b")

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


def detect(text: str) -> list[Span]:
    """텍스트에서 정규식+체크섬 기반 PII 후보를 모두 찾아 Span 리스트로 반환한다.

    같은 타입 내 중복은 정규식 finditer 특성상 자연히 없지만,
    타입 간 겹침(예: CARD 패턴이 ACCOUNT 패턴과 겹치는 구간)은
    여기서 걸러내지 않고 그대로 반환한다 — 최종 정리는 merge.py 몫.
    """
    spans: list[Span] = []
    spans += _detect_rrn(text)
    spans += _detect_card(text)
    spans += _detect_bizno(text)
    spans += _detect_phone(text)
    spans += _detect_email(text)
    spans += _detect_account(text)
    return spans
