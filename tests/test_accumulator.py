"""
context/accumulator.py + context/store.py 단위 테스트 — §6 테스트 케이스표 나머지.

test_context_smoke.py 에 이미 있는 #3~7 과 상호보완적이다. 여기서는:
  #1  단일 턴 단일 엔티티 — 조합 위험도 없음
  #2  2턴 분산 — 부분 조합만 (combo_cap 미도달)
  #8  세션 만료 시 on_expire 콜백 발화 (vault 동반 정리의 연결 지점)
  #10 여러 조합이 동시 성립해도 combo_cap 을 넘지 않음

#9(injection 동시 발생 시 override 우선)는 accumulator 단위 문제가 아니라
파이프라인 스테이지 순서 문제라 tests/test_context_integration.py 에 있다.
"""

import asyncio
import time

import pytest

from app.context.accumulator import DEFAULT_CONFIG, accumulate
from app.context.store import InMemorySessionStore
from app.models import Span


def make_span(type_: str, value: str) -> Span:
    return Span(type=type_, value=value, start=0, end=len(value), confidence=0.95, source="regex")


@pytest.mark.asyncio
async def test_case1_single_turn_single_entity_no_combo_risk():
    """#1: 단일 턴에 엔티티 하나만 있으면 조합/반복/속도 어느 것도 안 붙어야 한다."""
    store = InMemorySessionStore()
    sid = "sess-case1"
    state = store.new_session(sid)
    await store.save(state)

    state = await store.load(sid)
    accumulate(state, [make_span("RRN", "900101-1234568")], turn_index=1, now=8000.0)
    await store.save(state)

    assert state.risk_score == 0.0
    assert state.risk_reasons == []


@pytest.mark.asyncio
async def test_case2_two_turn_partial_combo_below_cap():
    """#2: 2턴에 NAME+RRN 만 분산 -> 부분 조합 가중치만 붙고 combo_cap 에는 못 미침.

    3종 조합(NAME+RRN+ACCOUNT)은 ACCOUNT 가 아직 없으니 발동하면 안 된다.
    """
    store = InMemorySessionStore()
    sid = "sess-case2"
    state = store.new_session(sid)
    await store.save(state)

    t = 9000.0
    spans = [make_span("NAME", "김민준"), make_span("RRN", "900101-1234568")]
    for turn, span in enumerate(spans, start=1):
        state = await store.load(sid)
        accumulate(state, [span], turn_index=turn, now=t + turn)
        await store.save(state)

    assert any("combo:NAME+RRN" in r for r in state.risk_reasons)
    assert not any("NAME+RRN+ACCOUNT" in r for r in state.risk_reasons)
    assert state.risk_score < DEFAULT_CONFIG.combo_cap


@pytest.mark.asyncio
async def test_case8_on_expire_fires_on_load_triggered_expiry():
    """#8: load() 호출 시점에 만료가 확인되면 on_expire 콜백이 호출된다.

    실제 vault 정리 코드는 아직 이 콜백에 연결 안 됨(§5 엣지케이스 9, 진행목록 4번) —
    이 테스트는 콜백 발화 메커니즘 자체만 검증한다. 실제 배선 시 이 자리에
    vault.purge_expired 류를 넣으면 된다.
    """
    expired_session_ids: list[str] = []

    async def on_expire(state):
        expired_session_ids.append(state.session_id)

    store = InMemorySessionStore(default_ttl_seconds=1.0, on_expire=on_expire)
    sid = "sess-case8-load"
    state = store.new_session(sid, ttl_seconds=1.0)
    accumulate(state, [make_span("RRN", "900101-1234568")], turn_index=1, now=11000.0)
    await store.save(state)

    await asyncio.sleep(1.1)
    result = await store.load(sid)

    assert result is None
    assert expired_session_ids == [sid]


@pytest.mark.asyncio
async def test_case8_on_expire_fires_on_sweep():
    """#8 변형: 조회 없이 백그라운드 스윕(_sweep_once)만으로도 on_expire 가 발화해야 한다."""
    expired_session_ids: list[str] = []

    async def on_expire(state):
        expired_session_ids.append(state.session_id)

    store = InMemorySessionStore(default_ttl_seconds=1.0, on_expire=on_expire)
    sid = "sess-case8-sweep"
    state = store.new_session(sid, ttl_seconds=1.0)
    await store.save(state)

    await asyncio.sleep(1.1)
    await store._sweep_once()

    assert expired_session_ids == [sid]


@pytest.mark.asyncio
async def test_case10_combo_cap_prevents_overflow():
    """#10: NAME+RRN+ACCOUNT+PHONE 이 전부 모이면 이론상 조합 가중치 합은

    0.25(NAME+RRN) + 0.35(NAME+RRN+ACCOUNT) + 0.30(NAME+PHONE+ACCOUNT)
    + 0.20(RRN+ACCOUNT) + 0.35(RRN+ACCOUNT+PHONE) = 1.45

    combo_cap(기본 0.6)을 훌쩍 넘지만, 실제로는 cap 이하로 눌려야 한다.
    """
    store = InMemorySessionStore()
    sid = "sess-case10"
    state = store.new_session(sid)
    await store.save(state)

    t = 10000.0
    spans = [
        make_span("NAME", "김민준"),
        make_span("RRN", "900101-1234568"),
        make_span("ACCOUNT", "110-234-567890"),
        make_span("PHONE", "010-1234-5678"),
    ]
    for turn, span in enumerate(spans, start=1):
        state = await store.load(sid)
        accumulate(state, [span], turn_index=turn, now=t + turn)
        await store.save(state)

    assert any("combo_cap_applied" in r for r in state.risk_reasons)
    # combo_cap + repeat_cap + velocity 최대치를 다 더해도 이 상한을 넘으면 안 됨
    max_possible = DEFAULT_CONFIG.combo_cap + DEFAULT_CONFIG.repeat_cap + 0.15
    assert state.risk_score <= max_possible + 1e-9
    assert state.risk_score <= 1.0


@pytest.mark.asyncio
async def test_default_store_on_expire_hook_calls_vault_revoke_session(monkeypatch):
    """§7.2/§6-e 정합 — context.stage._get_store() 의 기본 InMemorySessionStore
    는 세션 만료 시 vault.revoke_session() 을 자동 호출해야 한다.

    실제 DB 를 안 타도록 vault.revoke_session 자체를 몽키패치해서, 호출됐는지와
    session_id 가 정확히 넘어갔는지만 확인한다.
    """
    import app.context.stage as stage_module
    from app.transform import vault as vault_module

    called_with: list[str] = []
    monkeypatch.setattr(
        vault_module, "revoke_session", lambda session_id: called_with.append(session_id)
    )

    # 이 테스트 전용으로 모듈 상태 초기화 — configure() 로 직접 주입하면 훅이
    # 안 붙으므로, _get_store() 의 lazy 기본 경로를 그대로 타게 둔다.
    stage_module._store = None
    sid = "sess-vault-hook"
    store = stage_module._get_store()
    state = store.new_session(sid, ttl_seconds=1.0)
    await store.save(state)

    await asyncio.sleep(1.1)
    result = await store.load(sid)  # 만료 확인 -> on_expire 콜백 발화

    assert result is None
    assert called_with == [sid]


@pytest.mark.asyncio
async def test_explicitly_configured_store_has_no_vault_hook():
    """configure() 로 직접 주입한 InMemorySessionStore() 는 vault 훅이 안 붙어야 한다
    (기본 경로와 달리 순수 세션 로직만 테스트하고 싶을 때 이 방식을 쓴다).
    """
    store = InMemorySessionStore(default_ttl_seconds=1.0)  # on_expire 미지정
    sid = "sess-no-hook"
    state = store.new_session(sid, ttl_seconds=1.0)
    await store.save(state)

    await asyncio.sleep(1.1)
    # on_expire 콜백이 없어도 예외 없이 정상적으로 만료 처리되어야 함
    result = await store.load(sid)
    assert result is None


def test_concurrent_threads_same_session_no_lost_updates():
    """실제 배포 동시성 모델(grpc.server ThreadPoolExecutor) 재현.

    N개의 OS 스레드가 각자 asyncio.run() 으로 자기만의 이벤트 루프를 만들어
    동시에 같은 세션에 접근한다 — asyncio.Lock 을 쓰던 예전 구현에서는 이
    조건에서 RuntimeError 또는 레이스 컨디션이 났었다. threading.Lock 이
    실제로 스레드 경계를 보호하는지 확인한다.
    """
    import concurrent.futures

    store = InMemorySessionStore()
    sid = "sess-concurrent"
    state = store.new_session(sid)
    asyncio.run(store.save(state))

    n_threads = 20

    def worker(i: int) -> None:
        async def _do():
            s = await store.load(sid)
            assert s is not None
            s.turn_count += 1
            await store.save(s)

        asyncio.run(_do())

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(n_threads)]
        for f in futures:
            f.result(timeout=10)  # 예외(RuntimeError 등)가 있었으면 여기서 재발생

    final_state = asyncio.run(store.load(sid))
    assert final_state.turn_count == n_threads, (
        f"락이 제대로 안 걸리면 일부 증가분이 유실된다: "
        f"기대={n_threads}, 실제={final_state.turn_count}"
    )


def test_sweeper_thread_runs_in_background_without_event_loop():
    """threading.Thread 기반 스윕이 별도 이벤트 루프 없이도 정상 동작해야 한다.

    asyncio.create_task() 기반이었다면 이 테스트처럼 '지속되는 루프가 없는
    컨텍스트'에서는 애초에 스윕을 못 띄웠다.
    """
    store = InMemorySessionStore(default_ttl_seconds=0.3, sweep_interval_seconds=0.2)
    sid = "sess-sweep-thread"
    state = store.new_session(sid, ttl_seconds=0.3)
    asyncio.run(store.save(state))

    store.start_sweeper()
    try:
        time.sleep(0.8)  # TTL(0.3s) + 스윕 주기(0.2s) 를 넉넉히 넘김
        # 스윕이 실행됐다면 내부 딕셔너리에서 이미 지워져 있어야 한다
        assert sid not in store._states
    finally:
        store.stop_sweeper()
