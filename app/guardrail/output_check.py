"""
Output Guard (기능 c 출력측) — _OUTPUT_STAGES 에서 detokenize_stage **앞** 스테이지.

  (1) 응답의 정형 PII 재스캔 → 재마스킹 (regex_rules 만)
  (2) 인젝션 순응(시스템 프롬프트/지시 노출) 탐지 → block

detokenize 앞 : 이 시점엔 <PII:..> 가 아직 라벨이라 정규식에 안 걸린다
→ 재스캔에 잡히는 건 "모델이 새로 만든 PII" 뿐.
  detokenize 뒤에 하면 복원된 인가 PII 까지 다시 가려버린다.

오류 시 fail-closed(block) — 출력은 마지막 방어선이라 입력측(fail-open)과 다르다.

[수정] 재스캔으로 찾은 span을 ctx.new_turn_spans / ctx.span_actions에도 기록한다.
이전엔 텍스트만 바로 마스킹하고 span 정보를 어디에도 안 남겨서, pipeline._reason()이
읽는 entities_summary/transforms가 output 경로에서는 항상 빈 배열로 나갔다 —
즉 실제로 뭘 찾아서 마스킹했는지 판정 근거(reason)로 전혀 보이지 않는 구조였다.

근거: docs/architecture/dlp-server-architecture.md §3.2 / §6-c
"""

from __future__ import annotations

import logging
import re

from app.config import GuardrailConfig, load_config
from app.detect import regex_rules
from app.models import AnalysisContext, Span
from app.transform.apply import mask_preview  # 원문 노출 없는 부분 마스킹 (apply.py 규칙 재사용)

logger = logging.getLogger(__name__)

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

_guardrail_cfg: GuardrailConfig | None = None


def _cfg() -> GuardrailConfig:
    global _guardrail_cfg
    if _guardrail_cfg is None:
        _guardrail_cfg = load_config().guardrail
    return _guardrail_cfg


def _rescan_and_mask(text: str, min_confidence: float) -> tuple[str, list[Span]]:
    all_spans = regex_rules.detect(text)
    logger.info("output_guard: 재스캔 대상 텍스트(첫 200자) = %r", text[:200])
    logger.info(
        "output_guard: regex 재스캔 — 후보 %d개(%s), threshold=%.2f",
        len(all_spans),
        [(s.type, round(s.confidence, 3)) for s in all_spans],
        min_confidence,
    )

    spans = [s for s in all_spans if s.confidence >= min_confidence]
    if not spans:
        return text, []

    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        text = text[: span.start] + mask_preview(span) + text[span.end :]

    logger.info(
        "output_guard: %d개 마스킹 적용 — %s",
        len(spans),
        [s.type for s in spans],
    )
    return text, spans


def _injection_compliance(text: str) -> str | None:
    for name, pattern in _OUTPUT_RULES:
        try:
            if pattern.search(text):
                return name
        except Exception:
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
        text, spans = _rescan_and_mask(ctx.turns[0].text, cfg.output_pii_min_confidence)

        # [수정] reason(_reason() → entities_summary/transforms)에 결과가 보이도록 기록.
        # output 경로엔 policy 엔진이 없으므로 action은 항상 "mask"로 고정 표기한다
        # (input 경로처럼 정책에 따라 달라지는 게 아니라, output_guard 자체가 결정하는 조치).
        ctx.new_turn_spans = spans
        ctx.span_actions = [(s, "mask") for s in spans]

        if cfg.output_injection_check:
            hit = _injection_compliance(text)
            if hit is not None:
                logger.warning("output_guard: 인젝션 순응 탐지 — pattern=%s", hit)
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
