"""
멀티턴 엔티티 누적 + 위험도 산정.

근거: docs/architecture/dlp-server-architecture.md §6-e
스펙: docs/spec/dlp-server/multiturn-context.md §3(판정 로직), §4(파라미터)

책임 경계 (스펙 §3.5):
  accumulator 는 risk_score 를 계산할 뿐 스스로 block 하지 않는다.
  AnalysisContext.risk_score 로 실려 정책 엔진(§6-f, risk_overrides:
  risk_score >= 0.8)의 입력이 된다. accumulate() 결과를 block 트리거로
  바로 쓰고 싶다면 그 판단은 pipeline.py 스테이지 조합 순서에서 결정한다.

위험도 재계산 방식:
  턴마다 델타를 더하는 대신, 매 턴 "현재 활성 윈도우 상태"로부터 risk_score
  를 처음부터 다시 계산한다. 델타 누적 방식은 턴 재전송·순서 뒤바뀜 시
  이중 계산될 위험이 있어(스펙 §5 엣지케이스 참고) 결정론적 재계산을 택했다.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from app.context.store import EntityKey, EntityRecord, GraphEdge, SessionState
from app.models import Span

# ── 설정값 (초안 — Phase 2 eval 튜닝 전까지 [논의] 상태, 스펙 §4) ──────────
# 배포 시에는 config.yaml 로 옮긴다. 여기서는 기본값만 고정한다.


@dataclass(frozen=True)
class AccumulatorConfig:
    # 엔티티 그래프 엣지 생성에 사용하는 슬라이딩 윈도우 턴 수.
    window_size_turns: int = 5
    # 조합 가중치 합산 상한 (§3.3).
    # 0.6: NAME+RRN(0.25)+RRN+ACCOUNT(0.20)+NAME+RRN+ACCOUNT(0.35)=0.80 이 여기서 눌린다.
    # cfg.risk.hard_block(파이프라인 설정, 권장 0.6)과 짝을 맞춰야 한다 — 조합만으로
    # (반복·속도 없이) 로드맵 §9 Phase 2 대표 시나리오가 block 되도록 하기 위함.
    combo_cap: float = 0.6
    # 동일 엔티티 반복 언급 가중치 및 상한 (§3.3).
    repeat_weight: float = 0.05
    repeat_cap: float = 0.15
    # 조합별 가중치 — frozenset(엔티티 타입들) -> weight (§3.3 표).
    #
    # NAME 이 들어간 조합(NAME+RRN, NAME+RRN+ACCOUNT, NAME+PHONE+ACCOUNT)은
    # detect/dictionary.py 의 사전(financial_terms.txt)에 등재된 이름에 대해서만
    # 발동한다. 이 사전은 현재 데모용 샘플(4명)이라 커버리지가 매우 좁다 — NER
    # (§6-b, 로드맵 Phase 5) 또는 실제 운영 사전(컴플라이언스팀 리스트)이 갖춰지기
    # 전까지는 등재 안 된 이름에 대해 이 조합들이 발동하지 않는다.
    # 그 공백을 메우기 위해 "정규식만으로 탐지되는" 조합도 별도로 둔다.
    combo_weights: dict[frozenset, float] = field(
        default_factory=lambda: {
            # 사전 등재 이름에 한해 지금도 발동 (커버리지 좁음, 위 설명 참고).
            frozenset({"NAME", "RRN"}): 0.25,
            frozenset({"NAME", "RRN", "ACCOUNT"}): 0.35,
            frozenset({"NAME", "PHONE", "ACCOUNT"}): 0.30,
            # 사전 등재 여부와 무관하게 항상 발동 (정규식만으로 탐지 가능한 타입들).
            frozenset({"RRN", "ACCOUNT"}): 0.20,
            frozenset({"RRN", "ACCOUNT", "PHONE"}): 0.35,
        }
    )
    # (최소 턴 수, 최대 경과 초, 가중치) — 조건을 만족하는 항목을 모두 합산한다 (§3.4).
    velocity_thresholds: tuple[tuple[int, float, float], ...] = (
        (3, 60.0, 0.05),
        (5, 120.0, 0.10),
    )


DEFAULT_CONFIG = AccumulatorConfig()


def from_app_config(multiturn_cfg) -> AccumulatorConfig:
    """app.config.Config.multiturn(MultiturnConfig) → AccumulatorConfig.

    스칼라 4개(window_size_turns, combo_cap, repeat_weight, repeat_cap)만
    Config 에서 가져온다. combo_weights / velocity_thresholds 는 이 파일의
    DEFAULT_CONFIG 값을 그대로 쓴다 — 이유는 AccumulatorConfig 클래스 docstring
    (combo_weights 필드 주석) 참고.
    """
    return AccumulatorConfig(
        window_size_turns=multiturn_cfg.window_size_turns,
        combo_cap=multiturn_cfg.combo_cap,
        repeat_weight=multiturn_cfg.repeat_weight,
        repeat_cap=multiturn_cfg.repeat_cap,
        combo_weights=DEFAULT_CONFIG.combo_weights,
        velocity_thresholds=DEFAULT_CONFIG.velocity_thresholds,
    )


def hash_value(value: str) -> str:
    """평문 PII 값을 세션 상태에 남기지 않기 위한 해시.

    세션 상태(store.py)에는 이 해시만 저장한다 — 원문은 accumulate() 호출이
    끝나면 파이프라인의 다른 스테이지(변환 등)로만 흐르고 여기 남지 않는다.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def accumulate(
    state: SessionState,
    new_turn_spans: list[Span],
    turn_index: int,
    config: AccumulatorConfig = DEFAULT_CONFIG,
    now: float | None = None,
) -> list[str]:
    """이번 턴의 탐지 결과를 세션 상태(state)에 in-place로 누적하고
    risk_score / risk_reasons / graph_edges 를 갱신한다.

    Returns:
        이번 턴 위험도 산정 근거 문자열 목록 (감사 로그 reason_obj 에 실린다).
    """
    now = now if now is not None else time.time()

    state.turn_count = max(state.turn_count, turn_index)
    state.turn_timestamps.append(now)

    _register_spans(state, new_turn_spans, turn_index, config)

    active_nodes = _active_nodes(state, turn_index, config)
    state.graph_edges = _build_edges(active_nodes, turn_index)

    combo_delta, combo_reasons = _score_combos(active_nodes, config)
    repeat_delta, repeat_reasons = _score_repeats(active_nodes, state, config)
    velocity_delta, velocity_reasons = _score_velocity(state, turn_index, now, config)

    state.risk_score = min(1.0, combo_delta + repeat_delta + velocity_delta)
    state.risk_reasons = combo_reasons + repeat_reasons + velocity_reasons

    return state.risk_reasons


# ── 내부 헬퍼 ────────────────────────────────────────────────────────────


def _register_spans(
    state: SessionState,
    new_turn_spans: list[Span],
    turn_index: int,
    config: AccumulatorConfig,
) -> list[EntityKey]:
    """이번 턴 span 들을 세션 전체 엔티티 이력(state.entities)에 반영한다.

    엔티티 이력은 윈도우와 무관하게 세션 전체 기간 유지한다 — "재등장" 판정
    (스펙 §5 엣지케이스 5번: 윈도우 밖 재등장 시 first_turn 새로 만들지 않음)
    을 위해서다.
    """
    touched: list[EntityKey] = []
    for span in new_turn_spans:
        key: EntityKey = (span.type, hash_value(span.value))
        touched.append(key)
        existing = state.entities.get(key)
        if existing is None:
            state.entities[key] = EntityRecord(
                type=span.type,
                value_hash=key[1],
                first_turn=turn_index,
                last_turn=turn_index,
                count=1,
            )
        else:
            existing.last_turn = turn_index
            existing.count += 1
    return touched


def _active_nodes(
    state: SessionState, turn_index: int, config: AccumulatorConfig
) -> list[EntityRecord]:
    """슬라이딩 윈도우 내에서 "최근에 언급된" 엔티티만 골라낸다 (§3.2).

    화제가 바뀐 뒤에도 초반 PII 조합을 계속 위험으로 잡아 오탐이 누적되는
    것을 막기 위해, 그래프/조합 위험도 계산은 윈도우 기준으로 제한한다.
    """
    window_start = turn_index - config.window_size_turns + 1
    return [rec for rec in state.entities.values() if rec.last_turn >= window_start]


def _build_edges(active_nodes: list[EntityRecord], turn_index: int) -> list[GraphEdge]:
    """활성 노드들 사이의 완전 그래프 스냅샷을 만든다.

    데모 규모(세션당 활성 엔티티 수가 작음)를 전제로 O(n^2) 로 충분하다.
    노드 수가 커지면 조합 판정에 필요한 타입 집합만 쓰고 엣지 리스트 자체는
    생략하는 방향으로 최적화한다 (감사 로그 표시용 부가 정보이기 때문).
    """
    edges: list[GraphEdge] = []
    for i in range(len(active_nodes)):
        for j in range(i + 1, len(active_nodes)):
            a = (active_nodes[i].type, active_nodes[i].value_hash)
            b = (active_nodes[j].type, active_nodes[j].value_hash)
            edges.append(GraphEdge(node_a=a, node_b=b, turn_index=turn_index))
    return edges


def _score_combos(
    active_nodes: list[EntityRecord], config: AccumulatorConfig
) -> tuple[float, list[str]]:
    """활성 윈도우 내 엔티티 타입 조합에 대해 가중치를 합산한다 (§3.3).

    조합이 여러 개 겹쳐도(예: NAME+RRN, RRN+ACCOUNT, NAME+PHONE+ACCOUNT 가
    모두 성립) 단순 합산이 아니라 combo_cap 으로 총합을 제한한다.
    """
    active_types = {rec.type for rec in active_nodes}
    total = 0.0
    reasons: list[str] = []
    for combo, weight in config.combo_weights.items():
        if combo.issubset(active_types):
            total += weight
            reasons.append(f"combo:{'+'.join(sorted(combo))}(+{weight:.2f})")
    capped = min(total, config.combo_cap)
    if capped < total:
        reasons.append(f"combo_cap_applied(capped {total:.2f} -> {capped:.2f})")
    return capped, reasons


def _score_repeats(
    active_nodes: list[EntityRecord], state: SessionState, config: AccumulatorConfig
) -> tuple[float, list[str]]:
    """동일 엔티티 반복 언급에 가중치를 더한다 (§3.3: count >= 3부터 반영).

    첫 2회는 정상 범위로 보고, 3회째부터 1회당 repeat_weight 를 더하며
    repeat_cap 으로 전체 합을 제한한다.
    """
    total = 0.0
    reasons: list[str] = []
    for rec in active_nodes:
        extra = max(0, rec.count - 2)
        if extra > 0:
            delta = extra * config.repeat_weight
            total += delta
            reasons.append(f"repeat:{rec.type}:{rec.value_hash}(count={rec.count}, +{delta:.2f})")
    capped = min(total, config.repeat_cap)
    if capped < total:
        reasons.append(f"repeat_cap_applied(capped {total:.2f} -> {capped:.2f})")
    return capped, reasons


def _score_velocity(
    state: SessionState, turn_index: int, now: float, config: AccumulatorConfig
) -> tuple[float, list[str]]:
    """짧은 시간에 다수 턴이 이어지는 패턴에 가중치를 더한다 (§3.4).

    "우회 분산 입력"의 전형적 신호 — 서로 다른 타입의 PII가 빠르게 연속
    입력되는 경우를 잡기 위함이다. 타입 다양성 자체는 combo 점수가 이미
    반영하므로 여기서는 순수 속도(턴 수/경과 시간)만 본다.
    """
    total = 0.0
    reasons: list[str] = []
    timestamps = state.turn_timestamps
    for min_turns, max_elapsed, weight in config.velocity_thresholds:
        if turn_index < min_turns or len(timestamps) < min_turns:
            continue
        elapsed = now - timestamps[-min_turns]
        if elapsed <= max_elapsed:
            total += weight
            reasons.append(f"velocity:{min_turns}turns/{elapsed:.0f}s(+{weight:.2f})")
    return total, reasons
