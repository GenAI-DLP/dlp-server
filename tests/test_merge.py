"""tests/test_merge.py — detect/merge.py 단위 테스트."""

from app.detect.merge import merge_spans
from app.models import Span


def make_span(type_, value, start, end, confidence, source):
    return Span(
        type=type_, value=value, start=start, end=end,
        confidence=confidence, source=source,
    )


def test_no_overlap_passthrough():
    spans = [
        make_span("ACCOUNT", "110-234-567890", 8, 21, 0.99, "regex"),
        make_span("CARD", "4111-1111-1111-1111", 30, 49, 0.99, "regex"),
    ]
    result = merge_spans(spans)
    assert len(result) == 2
    assert [s.type for s in result] == ["ACCOUNT", "CARD"]


def test_same_type_overlap_boosts_confidence():
    spans = [
        make_span("CARD", "4111-1111-1111-1111", 30, 49, 0.95, "regex"),
        make_span("CARD", "4111-1111-1111-1111", 30, 49, 0.80, "ner"),
    ]
    result = merge_spans(spans)
    assert len(result) == 1
    merged = result[0]
    assert merged.source == "regex+ner"
    assert merged.confidence > 0.95
    assert merged.confidence <= 0.999


def test_type_conflict_prefers_higher_priority_source():
    spans = [
        make_span("ACCOUNT", "110-234-567890", 8, 21, 0.9, "regex"),
        make_span("NAME", "김철수", 8, 21, 0.6, "ner"),  # 같은 구간, 다른 타입
    ]
    result = merge_spans(spans)
    assert len(result) == 1
    assert result[0].type == "ACCOUNT"
    assert result[0].source == "regex"  # ner 은 다른 타입이라 합의 대상 아님


def test_below_min_confidence_dropped():
    spans = [
        # 체크섬 실패로 confidence 낮게 나온 regex 결과 (기본 threshold 0.5 미만)
        make_span("CARD", "1234-5678-9999-0000", 0, 19, 0.4, "regex"),
    ]
    result = merge_spans(spans)
    assert result == []


def test_transitive_overlap_clusters_together():
    # A(0-10) - B(5-15) - C(12-20) 는 A-C 직접 안 겹쳐도 한 클러스터
    spans = [
        make_span("PHONE", "010-1234-5678", 0, 10, 0.9, "regex"),
        make_span("PHONE", "010-1234-5678", 5, 15, 0.85, "dict"),
        make_span("PHONE", "010-1234-5678", 12, 20, 0.7, "ner"),
    ]
    result = merge_spans(spans)
    assert len(result) == 1
    assert set(result[0].source.split("+")) == {"regex", "dict", "ner"}


def test_empty_input():
    assert merge_spans([]) == []
