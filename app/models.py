"""
계약 타입 — 구현보다 먼저 고정하는 공용 데이터 구조.

여러 기능 모듈(a~h)이 직접 import 하므로 시그니처 변경은 주의할 것.

근거: docs/architecture/dlp-server-architecture.md §5
"""

from __future__ import annotations

from dataclasses import dataclass, field

# gRPC Verdict.action 에 실리는 3값 (docs/architecture/dlp-proto.md §3.1).
# 세부 변환 전략은 전부 "transform" 으로 직렬화하고 종류는 reason_obj 에 담는다.
WIRE_ACTIONS = ("allow", "block", "transform")

# 동적 변환 전략 (docs/schemas/dlp-server/postgres-schema.sql: action_type ENUM)
TRANSFORM_ACTIONS = (
    "keep",
    "mask",
    "generalize",
    "aggregate",
    "tokenize",
    "synthetic",
    "redact",
    "block",
)


@dataclass
class Turn:
    """대화 한 턴. 어댑터가 body 에서 추출한다."""

    role: str  # user | assistant | system
    text: str


@dataclass
class Span:
    """탐지된 PII/민감정보 한 구간."""

    type: str  # RRN | FOREIGN_RRN | CARD | ACCOUNT | PHONE | EMAIL
    #           | PASSPORT | DRIVER | BIZNO | NAME | CREDIT_INFO | AMOUNT
    value: str
    start: int
    end: int
    confidence: float
    source: str  # regex | dict | ner


@dataclass
class InjectionVerdict:
    """Input Guard 결과."""

    hit: bool
    score: float
    pattern: str | None = None


@dataclass
class AnalysisContext:
    """탐지 단계 산출물. 스테이지 간에 넘겨지며 갱신된다."""

    session_id: str
    direction: str  # input | output
    provider: str  # gateway | openai | anthropic
    role: str | None  # role_resolver 결과 (접근 제어 축)
    turns: list[Turn]
    new_turn_spans: list[Span] = field(default_factory=list)
    accumulated: dict[str, list[Span]] = field(default_factory=dict)  # 세션 누적 (멀티턴)
    risk_score: float = 0.0  # 0.0 ~ 1.0
    injection: InjectionVerdict = field(
        default_factory=lambda: InjectionVerdict(hit=False, score=0.0, pattern=None)
    )


@dataclass
class Decision:
    """판정 단계 산출물 → gRPC Verdict 로 직렬화된다."""

    action: str  # allow | block | transform  (WIRE_ACTIONS)
    transformed_body: bytes | None = None
    reason_obj: dict = field(default_factory=dict)  # 세부 변환 종류·근거·엔티티 요약 → Verdict.reason
