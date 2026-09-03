"""
app/detect — 하이브리드 PII 탐지 orchestrator.

pipeline.py 의 analyze() 가 이 모듈의 analyze_turn() 을 호출해
AnalysisContext.new_turn_spans 를 채우는 그림을 가정한다.

레이어 실행 순서: regex_rules -> dictionary -> ner -> merge.
세 레이어 모두 구현 완료 (2026-09-03). ner.py 는 GLiNER 기반 제로샷 NER —
모델/threshold 설정은 main.py 부트스트랩의 preload() 에서 주입한다.

근거: spec/hybrid-pii-detection.md, docs/architecture/dlp-server-architecture.md §6
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from app.detect import dictionary, ner, regex_rules
from app.detect.merge import merge_spans
from app.models import AnalysisContext, Span

logger = logging.getLogger(__name__)

# 레이어 이름 -> 탐지 함수. enabled_layers 필터링과 min_confidence 매핑(merge.py 의
# source 값과 동일한 키)에 모두 이 이름을 쓴다.
_LAYER_FUNCS: dict[str, Callable[[str], list[Span]]] = {
    "regex": regex_rules.detect,
    "dict": dictionary.detect,
    "ner": ner.detect,
}


def _active_layers() -> list[Callable[[str], list[Span]]]:
    """config.detect.enabled_layers 로 레이어를 거른다. 빈 값이면 구현된 것 전부."""
    try:
        from app.config import load_config

        raw = load_config().detect.enabled_layers
    except Exception:
        logger.debug("detect: config 로드 실패 — 전체 레이어 사용", exc_info=True)
        raw = ""

    if not raw:
        return list(_LAYER_FUNCS.values())

    names = {n.strip() for n in raw.split(",") if n.strip()}
    unknown = names - _LAYER_FUNCS.keys()
    if unknown:
        logger.warning("detect: enabled_layers 에 알 수 없는 레이어 %s — 무시", unknown)
    return [func for name, func in _LAYER_FUNCS.items() if name in names]


def _merge_kwargs() -> dict:
    """config.detect 값을 merge_spans() 인자로 변환. 실패 시 merge.py 기본값 사용."""
    try:
        from app.config import load_config

        d = load_config().detect
    except Exception:
        logger.debug("detect: config 로드 실패 — merge 기본값 사용", exc_info=True)
        return {}

    return {
        "min_confidence": {
            "regex": d.regex_min_confidence,
            "dict": d.dict_min_confidence,
            "ner": d.ner_threshold,
        },
        "overlap_bonus": d.merge_overlap_bonus,
    }


def detect(text: str) -> list[Span]:
    """단일 텍스트에 대해 활성화된 모든 레이어를 실행하고 병합한 결과를 반환한다.

    레이어 하나가 예외를 던져도 나머지 레이어 결과는 살리는 게 안전 원칙에
    맞다고 판단해서, 레이어별로 예외를 격리한다 (예: 사전 파일이 깨져도
    regex 탐지는 계속 동작해야 함 — DLP_FAIL_ACTION=block 기본 정책과는
    별개로, 탐지 레이어 자체의 부분 장애가 전체를 죽이면 안 됨).

    ner 레이어는 모델 워밍업(main.py preload())이 안 됐거나 실패한 경우
    첫 호출에서 lazy-load를 시도한다 — 이 경우 해당 요청만 느려지고
    실패해도 예외는 여기서 격리되어 나머지 레이어 결과는 살아남는다.
    """
    if not text:
        return []

    raw_spans: list[Span] = []
    for layer in _active_layers():
        try:
            raw_spans.extend(layer(text))
        except Exception:
            # TODO: app/db.py 감사 로그 연동되면 레이어명·에러를 구조화 로깅.
            # 지금은 해당 레이어만 스킵하고 나머지 레이어로 계속 진행.
            logger.exception(
                "detect: 레이어 %s 실행 중 예외 발생 — 해당 레이어 결과 제외",
                getattr(layer, "__module__", layer),
            )

    return merge_spans(raw_spans, **_merge_kwargs())


def analyze_turn(ctx: AnalysisContext) -> AnalysisContext:
    """AnalysisContext 의 최신 턴을 분석해 new_turn_spans 를 채운다.

    turns 리스트의 마지막 항목을 "새로 들어온 턴"으로 간주한다
    (이전 턴들은 이미 이전 단계에서 accumulated 에 반영됐다고 가정 —
    멀티턴 누적 로직 자체는 아직 미구현, TODO).
    """
    if not ctx.turns:
        ctx.new_turn_spans = []
        return ctx

    latest_turn = ctx.turns[-1]
    ctx.new_turn_spans = detect(latest_turn.text)
    return ctx


def pii_detect_stage(ctx: AnalysisContext) -> AnalysisContext:
    """pipeline.py 의 Stage 규약(Callable[[AnalysisContext], AnalysisContext]) 을
    따르는 이름으로 analyze_turn() 을 감싼 wrapper. pipeline._INPUT_STAGES 에
    injection_guard / purpose_policy_stage 와 같은 네이밍으로 들어간다.

    근거: docs/architecture/dlp-server-architecture.md §3.1 [3] 하이브리드 PII 탐지
    """
    return analyze_turn(ctx)