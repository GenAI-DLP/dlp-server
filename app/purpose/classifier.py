"""
목적 분류 (기능 f) — 요청 텍스트에서 업무 목적을 뽑는다.

규칙(키워드) 분류가 기본이다. 미매칭은 unknown 으로 보수 처리한다.
모델 기반 분류기는 config.purpose.backend == "llm" 일 때 _classifier 를 바꿔 끼운다

분류 대상은 이번 요청의 마지막 user 턴이다.

근거: docs/architecture/dlp-server-architecture.md §6-f (목적 확보)
"""

from __future__ import annotations

import logging
import re
from typing import Protocol

logger = logging.getLogger(__name__)

# purpose_ref 코드. 미매칭 시 unknown.
PURPOSES = (
    "customer_support",
    "doc_summarize",
    "code_help",
    "data_analysis",
    "fraud_investigation",
)

# (purpose, 키워드 정규식) — 위에서부터 먼저 맞는 것을 채택.
_RAW_RULES: list[tuple[str, str]] = [
    (
        "fraud_investigation",
        r"사기|이상\s?거래|부정\s?사용|자금\s?세탁|조사\s?의뢰|fraud|money\s?launder",
    ),
    (
        "data_analysis",
        r"몇\s?명|건수|평균|합계|통계|분포|집계|비율|추이|aggregate|average|how\s+many",
    ),
    (
        "code_help",
        r"코드|함수|메서드|에러|버그|디버그|스택\s?트레이스|traceback|exception|stack\s?trace",
    ),
    ("doc_summarize", r"요약|번역|정리|초록|개조식|bullet|summari[sz]e|translate|tl;dr"),
    ("customer_support", r"고객|민원|문의|상담|접수|응대|클레임|inquiry|complaint|ticket"),
]

_COMPILED: list[tuple[str, re.Pattern[str]]] = [
    (purpose, re.compile(src, re.IGNORECASE)) for purpose, src in _RAW_RULES
]

_RULE_CONFIDENCE = 0.8
_UNKNOWN_CONFIDENCE = 0.0


class Classifier(Protocol):
    def classify(self, text: str) -> tuple[str, float]:
        """(purpose, confidence 0~1) 를 반환한다."""
        ...


class RuleClassifier:
    """키워드 정규식 분류기. 첫 매칭 규칙의 purpose 를 채택, 없으면 unknown."""

    def __init__(self, rules: list[tuple[str, re.Pattern[str]]] | None = None) -> None:
        self._rules = _COMPILED if rules is None else rules

    def classify(self, text: str) -> tuple[str, float]:
        for purpose, pattern in self._rules:
            try:
                if pattern.search(text):
                    return purpose, _RULE_CONFIDENCE
            except Exception:  # 규칙 하나가 터져도 나머지는 계속 본다
                logger.exception("purpose 규칙 평가 실패: %s", purpose)
        return "unknown", _UNKNOWN_CONFIDENCE


# 추후 필요시 교체. config.purpose.backend == "llm" 이면 여기에 LLMClassifier 로 변경
_classifier: Classifier = RuleClassifier()


def classify(text: str) -> tuple[str, float]:
    """단일 텍스트의 목적을 판정한다. 내부 오류 시 unknown 으로 보수 처리."""
    try:
        return _classifier.classify(text or "")
    except Exception:
        logger.exception("purpose.classify 실패 — unknown 처리")
        return "unknown", _UNKNOWN_CONFIDENCE
