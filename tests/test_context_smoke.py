"""
context/store.py + context/accumulator.py 스모크 테스트 (pytest 버전).

docs/spec/dlp-server/multiturn-context.md §6 테스트 케이스표의
#3(3턴 분산 조합), #4(반복), #5(윈도우 밖 재등장), #6(속도), #7(TTL 만료)를 재현한다.
정식 케이스 전체(§6 전체 표)는 tests/test_accumulator.py 에서 다룬다.
"""

import asyncio

import pytest

from app.context.accumulator import DEFAULT_CONFIG, accumulate
from app.context.store import InMemorySessionStore
from app.models import Span


def make_span(type_: str, value: str) -> Span:
    return Span(type=type_, value=value, start=0, end=len(value), confidence=0.95, source="regex")


@pytest.mark.asyncio
async def test_case3_combo_triggers_threshold():
    """#3: NAME(T1) + RRN(T2) + ACCOUNT(T3) -> combo_cap까지 위험도 상승."""
    store = InMemorySessionStore()
    sid = "sess-case3"
    state = store.new_session(sid)
    await store.save(state)

    t = 1000.0
    spans = [
        make_span("NAME", "홍길동"),
        make_span("RRN", "900101-1234567"),
        make_span("ACCOUNT", "110-234-567890"),
    ]
    for turn, span in enumerate(spans, start=1):
        state = await store.load(sid)
        accumulate(state, [span], turn_index=turn, now=t + turn)
        await store.save(state)

    assert state.risk_score >= DEFAULT_CONFIG.combo_cap - 1e-9, "combo 가중치가 반영되지 않음"
    assert any("combo:" in r for r in state.risk_reasons)


@pytest.mark.asyncio
async def test_case4_repeat_capped():
    """#4: 같은 RRN을 4번 반복 -> repeat_cap(0.15) 이내로 제한."""
    store = InMemorySessionStore()
    sid = "sess-case4"
    state = store.new_session(sid)
    await store.save(state)

    t = 2000.0
    for turn in range(1, 5):
        state = await store.load(sid)
        accumulate(state, [make_span("RRN", "900101-1234567")], turn_index=turn, now=t + turn * 30)
        await store.save(state)

    assert state.risk_score <= DEFAULT_CONFIG.repeat_cap + 1e-9
    assert any("repeat_cap_applied" in r for r in state.risk_reasons) or state.risk_score > 0


@pytest.mark.asyncio
async def test_case6_velocity():
    """#6: 5턴을 100초 내에 서로 다른 타입으로 입력 -> velocity 가중치 반영."""
    store = InMemorySessionStore()
    sid = "sess-case6"
    state = store.new_session(sid)
    await store.save(state)

    types = ["NAME", "PHONE", "EMAIL", "BIZNO", "PASSPORT"]
    base_t = 3000.0
    for i, ty in enumerate(types, start=1):
        state = await store.load(sid)
        accumulate(state, [make_span(ty, f"value-{i}")], turn_index=i, now=base_t + i * 20)
        await store.save(state)

    assert any("velocity:" in r for r in state.risk_reasons)


@pytest.mark.asyncio
async def test_case5_window_reentry_no_new_first_turn():
    """#5: 1턴 NAME, 7턴에 같은 NAME 재등장 (window=5) -> first_turn 유지, last_turn만 갱신."""
    store = InMemorySessionStore()
    sid = "sess-case5"
    state = store.new_session(sid)
    await store.save(state)

    state = await store.load(sid)
    accumulate(state, [make_span("NAME", "홍길동")], turn_index=1, now=5000.0)
    await store.save(state)

    for turn in range(2, 7):
        state = await store.load(sid)
        accumulate(state, [], turn_index=turn, now=5000.0 + turn * 60)
        await store.save(state)

    state = await store.load(sid)
    accumulate(state, [make_span("NAME", "홍길동")], turn_index=7, now=5000.0 + 7 * 60)
    await store.save(state)

    key = ("NAME", next(iter(state.entities.values())).value_hash)
    rec = state.entities[key]

    assert rec.first_turn == 1, "재등장 시 first_turn이 새로 생성되면 안 됨"
    assert rec.last_turn == 7
    assert rec.count == 2


@pytest.mark.asyncio
async def test_case7_ttl_expiry_resets_session():
    """#7: TTL 만료 후 재요청 -> 신규 세션으로 초기화, 이전 이력 미반영."""
    store = InMemorySessionStore(default_ttl_seconds=1.0)
    sid = "sess-case-ttl"
    state = store.new_session(sid, ttl_seconds=1.0)
    accumulate(state, [make_span("RRN", "900101-1234567")], turn_index=1, now=6000.0)
    await store.save(state)

    loaded = await store.load(sid)
    assert loaded is not None, "TTL 이전에는 세션이 조회되어야 함"

    await asyncio.sleep(1.1)
    loaded_after = await store.load(sid)
    assert loaded_after is None, "TTL 경과 후에는 세션이 조회되지 않아야 함"


def test_default_config_loads_from_app_config_without_explicit_configure():
    """configure() 를 호출하지 않아도 app.config.load_config().multiturn 에서
    지연 로드되어야 한다 (context/stage.py::_get_accumulator_config).

    combo_cap 이 cfg.risk.hard_block 과 짝이 맞는 값(0.6)으로 흘러들어오는지가
    핵심 — 둘이 어긋나면 §3.5 에서 설명한 "조합만으로는 절대 block 불가" 버그가
    재발한다.
    """
    import app.context.stage as stage_module
    from app.config import load_config

    # 다른 테스트가 configure() 로 이미 채워놨을 수 있으니 모듈 상태를 초기화
    stage_module._accumulator_config = None
    stage_module._store = None

    cfg = stage_module._get_accumulator_config()
    app_cfg = load_config()

    assert cfg.combo_cap == app_cfg.risk.hard_block, (
        "accumulator.combo_cap 과 pipeline 의 risk.hard_block 이 어긋나면 "
        "조합 위험도만으로는 block 임계값에 절대 도달할 수 없다"
    )
    assert cfg.window_size_turns == app_cfg.multiturn.window_size_turns
    assert cfg.repeat_cap == app_cfg.multiturn.repeat_cap
    # combo_weights/velocity_thresholds 는 config 가 아니라 accumulator.py 코드 기본값을 따름
    assert cfg.combo_weights == stage_module.AccumulatorConfig().combo_weights
