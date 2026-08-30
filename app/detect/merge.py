"""
detect/merge.py — regex / dictionary / ner 세 레이어의 Span 을 병합한다.

계약: app/models.py 의 Span (type, value, start, end, confidence, source).
Span 자체에는 부가 메타 필드가 없으므로, 다중 레이어 합의는 source 를
"regex+ner" 형태의 조합 문자열로, 충돌·근거 기록은 logging 으로 남긴다.

근거: spec/hybrid-pii-detection.md §3.2
"""

from __future__ import annotations

import logging

from app.models import Span

logger = logging.getLogger(__name__)

# 소스 우선순위 — 라벨 충돌 시 채택 기준 (숫자가 클수록 우선)
SOURCE_PRIORITY: dict[str, int] = {
    "regex": 3,
    "dict": 2,
    "ner": 1,
}

# 다중 레이어가 동일 타입에 합의했을 때 confidence 가산치
OVERLAP_BONUS = 0.02
MAX_CONFIDENCE = 0.999

# 레이어별 최소 통과 confidence (이 미만은 병합 전에 드롭)
DEFAULT_MIN_CONFIDENCE: dict[str, float] = {
    "regex": 0.5,   # 체크섬 실패로 낮아진 regex 결과 등
    "dict": 0.0,    # 사전 매치는 boolean 성격이라 기본적으로 필터링 안 함
    "ner": 0.7,     # DLP_DETECT__NER_THRESHOLD 기본값과 동일
}


def _passes_min_confidence(span: Span, thresholds: dict[str, float]) -> bool:
    min_conf = thresholds.get(span.source, 0.0)
    return span.confidence >= min_conf


def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def _cluster_overlapping(spans: list[Span]) -> list[list[Span]]:
    """start 기준 정렬 후 sweep 으로 상호 겹치는 span 들을 클러스터링한다.

    transitive overlap 을 다루기 위해 클러스터의 max_end 를 계속 갱신한다.
    (예: A-B 겹치고 B-C 겹치면 A-C 가 직접 안 겹쳐도 한 클러스터)
    """
    if not spans:
        return []

    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    clusters: list[list[Span]] = [[ordered[0]]]
    cluster_max_end = ordered[0].end

    for span in ordered[1:]:
        if span.start < cluster_max_end:
            clusters[-1].append(span)
            cluster_max_end = max(cluster_max_end, span.end)
        else:
            clusters.append([span])
            cluster_max_end = span.end

    return clusters


def _resolve_cluster(cluster: list[Span]) -> Span:
    """겹치는 span 클러스터 하나를 최종 Span 하나로 합친다."""
    if len(cluster) == 1:
        return cluster[0]

    types_in_cluster = {s.type for s in cluster}

    if len(types_in_cluster) > 1:
        logger.warning(
            "merge: 타입 충돌 — %s (구간 %d-%d)",
            {(s.type, s.source) for s in cluster},
            min(s.start for s in cluster),
            max(s.end for s in cluster),
        )

    # 우선순위가 가장 높은 span 을 canonical 로 채택.
    # 동점이면 confidence 높은 것, 그다음 구간이 긴 것.
    canonical = max(
        cluster,
        key=lambda s: (
            SOURCE_PRIORITY.get(s.source, 0),
            s.confidence,
            s.end - s.start,
        ),
    )

    # canonical 과 같은 타입으로 합의한 span 들만 confidence 가산 대상.
    agreeing = [s for s in cluster if s.type == canonical.type]
    distinct_sources = sorted(
        {s.source for s in agreeing},
        key=lambda src: -SOURCE_PRIORITY.get(src, 0),
    )

    if len(distinct_sources) > 1:
        boosted_confidence = min(
            canonical.confidence + OVERLAP_BONUS * (len(distinct_sources) - 1),
            MAX_CONFIDENCE,
        )
        merged_source = "+".join(distinct_sources)
    else:
        boosted_confidence = canonical.confidence
        merged_source = canonical.source

    return Span(
        type=canonical.type,
        value=canonical.value,
        start=canonical.start,
        end=canonical.end,
        confidence=boosted_confidence,
        source=merged_source,
    )


def merge_spans(
    spans: list[Span],
    *,
    min_confidence: dict[str, float] | None = None,
) -> list[Span]:
    """세 레이어(regex/dict/ner)에서 나온 Span 리스트를 하나로 병합한다.

    Args:
        spans: regex_rules.detect() + dictionary.detect() + ner.detect() 결과를
            한 리스트로 이어붙인 것. 순서는 무관.
        min_confidence: 소스별 최소 통과 confidence. 미지정 시
            DEFAULT_MIN_CONFIDENCE 사용 (TODO: app/config.py 의
            DLP_DETECT__* 값과 연동).

    Returns:
        구간이 겹치지 않도록 정리된 최종 Span 리스트. start 기준 정렬됨.
    """
    thresholds = min_confidence or DEFAULT_MIN_CONFIDENCE

    filtered = [s for s in spans if _passes_min_confidence(s, thresholds)]
    if not filtered:
        return []

    clusters = _cluster_overlapping(filtered)
    merged = [_resolve_cluster(cluster) for cluster in clusters]

    return sorted(merged, key=lambda s: s.start)