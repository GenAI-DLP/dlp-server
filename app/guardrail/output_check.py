"""
Output Guard (기능 c 출력측) — _OUTPUT_STAGES 에서 detokenize_stage **앞** 스테이지.

  (1) 응답의 정형 PII 재스캔 → 재마스킹 (regex_rules 만)
  (2) 인젝션 순응(시스템 프롬프트/지시 노출) 탐지 → block

detokenize 앞 : 이 시점엔 <PII:..> 가 아직 라벨이라 정규식에 안 걸린다
→ 재스캔에 잡히는 건 "모델이 새로 만든 PII" 뿐.
  detokenize 뒤에 하면 복원된 인가 PII 까지 다시 가려버린다.

오류 시 fail-closed(block) — 출력은 마지막 방어선이라 입력측(fail-open)과 다르다.

근거: docs/architecture/dlp-server-architecture.md §3.2 / §6-c
"""

from __future__ import annotations

import logging
import re

from app.config import GuardrailConfig, load_config
from app.detect import regex_rules
from app.models import AnalysisContext
from app.transform.apply import mask_preview  # 원문 노출 없는 부분 마스킹 (apply.py 규칙 재사용)

logger = logging.getLogger(__name__)

# 응답이 시스템 프롬프트·내부 지시를 노출하는 패턴. 입력측(injection.py = "이전 지시 무시"
# 요구)과 방향이 반대라 규칙을 공유하지 않는다. 얕게 시작 → red-team eval 후 정밀화.
_RAW_OUTPUT_RULES: list[tuple[str, str]] = [
    (
        "system_prompt_leak.ko",
        r"(제|내|나의|저의|시스템)\s*(지시\s?사항|프롬프트|규칙|지침)\s*(은|는)?\s*"
        r"(다음|아래|이것|이거)",
    ),
    (
        "system_prompt_leak.en",
        r"(here\s+(is|are)|the\s+following\s+(is|are))\s+(my|the)\s+"
        r"(system\s+)?(prompt|instructions?|rules?|guidelines?)",
    ),
    (
        "instruction_disclosure.en",
        r"my\s+(system\s+)?(instructions?|prompt|directives?)\s+(are|is|state|say)\b",
    ),
    (
        "role_disclosure.ko",
        r"(나는|저는)\s*.{0,20}(DLP|게이트웨이|가드레일)\s*.{0,10}(지시\s?받|프로그래밍|설정)",
    ),
]
_OUTPUT_RULES = [(name, re.compile(src, re.IGNORECASE)) for name, src in _RAW_OUTPUT_RULES]

# 설정값은 프로세스당 1회 로드 후 재사용 (injection.py 의 _threshold_cache 선례).
# 테스트는 _guardrail_cfg 를 None 으로 리셋해 초기화한다.
_guardrail_cfg: GuardrailConfig | None = None


def _cfg() -> GuardrailConfig:
    global _guardrail_cfg
    if _guardrail_cfg is None:
        _guardrail_cfg = load_config().guardrail
    return _guardrail_cfg


def _rescan_and_mask(text: str, min_confidence: float) -> str:
    """응답의 정형 PII 를 뒤→앞 순서로 재마스킹한다 (offset 안 밀리게)."""
    spans = [s for s in regex_rules.detect(text) if s.confidence >= min_confidence]
    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        text = text[: span.start] + mask_preview(span) + text[span.end :]
    return text


def _injection_compliance(text: str) -> str | None:
    """응답이 시스템 프롬프트/지시 노출 패턴이면 적중 규칙 이름을 반환. 아니면 None."""
    for name, pattern in _OUTPUT_RULES:
        try:
            if pattern.search(text):
                return name
        except Exception:  # 규칙 하나가 터져도 나머지는 계속 본다
            logger.exception("output injection 규칙 평가 실패: %s", name)
    return None


def output_guard(ctx: AnalysisContext) -> AnalysisContext:
    """출력 경로 스테이지 — detokenize_stage 앞.

    (1) 재스캔 재마스킹 → (2) 인젝션 순응 시 block. 오류는 fail-closed(block).
    assistant 턴이 없거나 direction 이 output 이 아니면 아무것도 하지 않는다.
    """
    if ctx.direction != "output" or not ctx.turns:
        return ctx
    try:
        cfg = _cfg()
        text = _rescan_and_mask(ctx.turns[0].text, cfg.output_pii_min_confidence)

        if cfg.output_injection_check:
            hit = _injection_compliance(text)
            if hit is not None:
                ctx.blocked = True
                ctx.block_reason = {
                    "type": "output_guard",
                    "note": "injection_compliance",
                    "pattern": hit,
                }
                return ctx

        ctx.turns[0].text = text
    except Exception:
        logger.exception("output_guard 실패 — fail-closed(block)")
        ctx.blocked = True
        ctx.block_reason = {"type": "output_guard", "note": "stage_error"}
    return ctx
