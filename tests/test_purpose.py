"""목적 분류 + role 해석 (기능 f) 테스트 — DB 불필요, 순수 함수."""

from __future__ import annotations

import pytest

from app.purpose.classifier import classify
from app.purpose.role_resolver import resolve

# ---------------------------------------------------------------------------
# 목적 분류 — 키워드 매핑
# ---------------------------------------------------------------------------
_HITS = [
    ("doc_summarize", "이 문서 3장만 요약해줘"),
    ("doc_summarize", "please summarize the attached report"),
    ("code_help", "이 함수에서 나는 에러 좀 봐줘"),
    ("code_help", "why does this raise a NullPointer exception"),
    ("data_analysis", "지난달 가입 고객이 몇 명이야"),
    ("data_analysis", "give me the average transaction amount"),
    ("customer_support", "고객 민원 접수 건 확인 부탁해"),
    ("fraud_investigation", "이상거래 조사 의뢰 들어왔어"),
]


@pytest.mark.parametrize(("expected", "text"), _HITS)
def test_classify_keyword_hit(expected, text):
    purpose, confidence = classify(text)
    assert purpose == expected
    assert confidence > 0.0


@pytest.mark.parametrize(
    "text",
    [
        "",
        "안녕하세요 반갑습니다",
        "오늘 날씨 어때",
        "다음 주 회의 일정 알려줘",
    ],
)
def test_classify_unmatched_is_unknown(text):
    purpose, confidence = classify(text)
    assert purpose == "unknown"
    assert confidence == 0.0


def test_classify_first_matching_rule_wins():
    # 사기/조사 키워드가 고객 키워드보다 먼저 정의돼 있어 우선한다.
    purpose, _ = classify("고객 계좌 관련 이상거래 조사")
    assert purpose == "fraud_investigation"


# ---------------------------------------------------------------------------
# role 해석 — 헤더 우선순위
# ---------------------------------------------------------------------------
def test_resolve_from_role_header():
    assert resolve({"X-Corp-User-Role": "agent_l1"}) == "agent_l1"


def test_resolve_header_case_insensitive():
    assert resolve({"x-corp-user-role": "agent_l2"}) == "agent_l2"


def test_resolve_none_when_absent():
    assert resolve({}) is None
    assert resolve(None) is None
    assert resolve({"X-Corp-User-Id": "unmapped-user"}) is None


def test_resolve_blank_role_header_falls_through():
    assert resolve({"X-Corp-User-Role": "   "}) is None
