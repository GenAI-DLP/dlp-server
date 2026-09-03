"""
멀티턴 누적(§6-e)을 pipeline.py 의 Stage 계약에 맞춰 배선하는 어댑터.

pipeline.py::_INPUT_STAGES 에 두 지점에서 삽입한다:

    from .context import multiturn_stage, remember_purpose_stage
    _INPUT_STAGES: list[Stage] = [
        injection_guard,
        pii_detect_stage,
        multiturn_stage,          # ← [3] PII 탐지 다음, [5] 목적+정책 이전
        purpose_policy_stage,
        remember_purpose_stage,   # ← [5] 목적+정책 다음, transform_stage 이전
        transform_stage,
    ]

remember_purpose_stage 가 왜 따로 있는가: multiturn_stage 는 purpose_policy_stage 보다
먼저 돈다(risk_score 가 정책 판단의 입력이라서) — 그 시점엔 아직 ctx.purpose 가 None
이라 그 안에서 저장할 수 없다. purpose_policy_stage 가 채운 뒤에 별도 스테이지로
세션에 기록한다. output 경로(detokenize_stage, transform/apply.py)가
get_last_purpose() 로 이 값을 읽어간다 — output InspectRequest 는 원 input 요청과
별개 호출이라 자체적으로 purpose 를 모르기 때문(transform/apply.py::detokenize_stage
docstring 의 TODO 참고).

책임 경계 (스펙 docs/spec/dlp-server/multiturn-context.md §3.5):
  multiturn_stage 는 ctx.risk_score 를 채울 뿐 ctx.blocked 를 세팅하지 않는다.
  block 여부는 pipeline.py::_block_check() 가 cfg.risk.hard_block 과 비교해 결정한다
  (accumulator.AccumulatorConfig.combo_cap 과 짝을 맞춰야 함 — accumulator.py 상단 주석 참고).

Stage 시그니처가 동기(sync)이므로, 비동기 SessionStore(context/store.py)를 동기 경계에서
asyncio.run() 으로 브리지한다. 이는 pipeline.analyze() 가 이벤트 루프가 없는 스레드에서
호출된다는 전제에 의존한다 — 실제 grpc_server.py 가 grpc.server(동기, ThreadPoolExecutor)
를 쓰는 것으로 확인됐다. 위반 시 조용히 깨지는 대신 명확한 RuntimeError 를 낸다.

세션 만료 시 vault 정리: _get_store() 의 기본 InMemorySessionStore 는 on_expire 훅으로
_default_on_expire() 가 연결돼 있어, 세션이 만료되면 vault.revoke_session() 이 자동
호출된다 (아래 _default_on_expire docstring 참고). configure() 로 직접 주입한 store
에는 이 훅이 안 붙으니, vault 연동 없이 테스트하려면 InMemorySessionStore() 를 직접
만들어 configure() 에 넘기면 된다.
"""

from __future__ import annotations

import asyncio
import logging

from app.context.accumulator import AccumulatorConfig, accumulate, from_app_config
from app.context.store import InMemorySessionStore, SessionState, SessionStore
from app.models import AnalysisContext, Span
from app.transform import vault

logger = logging.getLogger(__name__)

_store: SessionStore | None = None
_accumulator_config: AccumulatorConfig | None = (
    None  # None = app.config.load_config() 에서 지연 로드
)


def configure(store: SessionStore | None = None, config: AccumulatorConfig | None = None) -> None:
    """app 부트스트랩(main.py)에서 store 구현체·설정을 주입할 때, 또는 테스트에서 사용.

    호출하지 않으면 InMemorySessionStore + app.config.load_config().multiturn 으로
    지연 초기화된다 (store.backend=memory 가 §7.3/§12 미정 상태의 현재 기본값).
    """
    global _store, _accumulator_config
    if store is not None:
        _store = store
    if config is not None:
        _accumulator_config = config


def _get_store() -> SessionStore:
    global _store
    if _store is None:
        _store = InMemorySessionStore(on_expire=_default_on_expire)
    return _store


def _default_on_expire(state: SessionState) -> None:
    """세션 만료 시 기본 훅 — 해당 세션의 vault 레코드를 조기 soft revoke 한다.

    vault.py::revoke_session 참고 — 세션과 볼트는 원래 수명이 분리돼 있지만,
    세션이 볼트보다 먼저 끝나면 거기 딸린 토큰을 계속 살려둘 이유가 없다는
    판단으로 추가한 트리거다. vault 자체의 정기 purge_expired() 스케줄과는
    독립적으로 동작한다.

    이 훅은 configure() 로 store 를 직접 주입하지 않고 _get_store() 의 기본값
    (InMemorySessionStore lazy 생성)을 쓸 때만 적용된다 — 테스트에서
    InMemorySessionStore() 를 직접 만들어 쓰면 이 훅이 안 붙으니 vault 연동
    없이 순수하게 세션 로직만 검증할 수 있다.
    """
    try:
        vault.revoke_session(state.session_id)
    except Exception:
        logger.exception("session 만료 훅에서 vault revoke 실패 — session=%s", state.session_id)


def _get_accumulator_config() -> AccumulatorConfig:
    global _accumulator_config
    if _accumulator_config is None:
        from app.config import load_config  # 지연 import — pipeline.py 와 순환 참조 방지

        _accumulator_config = from_app_config(load_config().multiturn)
    return _accumulator_config


def _run_sync(coro):
    """이벤트 루프가 없는 스레드에서만 안전하게 async 코드를 실행한다.

    이미 실행 중인 루프 안에서 호출되면(예: grpc.aio 서비서 안에서 await 없이 직접
    호출) asyncio.run() 이 예측 불가하게 실패하거나 데드락 나는 대신, 여기서 먼저
    명확한 에러로 알린다 — 나중에 grpc_server.py 를 짤 때 반드시 확인해야 할 제약.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError(
        "multiturn_stage 는 실행 중인 이벤트 루프 안에서 호출할 수 없습니다. "
        "grpc_server.py 가 grpc.aio 를 쓴다면 pipeline.analyze() 를 "
        "loop.run_in_executor() 등으로 별도 스레드에서 동기 호출하도록 배선하세요."
    )


def multiturn_stage(ctx: AnalysisContext) -> AnalysisContext:
    """세션 상태를 로드 → 이번 턴 span 누적 → 저장하고 ctx.risk_score 를 갱신한다.

    ctx.accumulated 는 "세션 전체 이력"이 아니라 "이번 턴에 탐지된 span을 타입별로
    묶은 것"으로 채운다. 과거 턴의 Span.start/end 는 현재 턴 본문(ctx.turns[*].text)
    기준으로는 의미가 없고(변환 스테이지 g가 고칠 수 있는 건 이번 턴 텍스트뿐),
    세션 상태(store.py)는 평문 값을 애초에 보관하지 않으므로 과거 span을 복원할
    수도 없다 — 세션 전체의 위험 정도는 ctx.risk_score 로 충분히 전달된다.
    """
    store = _get_store()
    cfg = _get_accumulator_config()

    state = _run_sync(store.load(ctx.session_id))
    if state is None:
        state = store.new_session(ctx.session_id)

    turn_index = state.turn_count + 1
    reasons = accumulate(state, ctx.new_turn_spans, turn_index=turn_index, config=cfg)
    _run_sync(store.save(state))

    ctx.risk_score = state.risk_score
    ctx.accumulated = _group_by_type(ctx.new_turn_spans)

    logger.debug(
        "multiturn_stage session=%s turn=%d risk_score=%.3f reasons=%s",
        ctx.session_id,
        turn_index,
        state.risk_score,
        reasons,
    )
    return ctx


def _group_by_type(spans: list[Span]) -> dict[str, list[Span]]:
    grouped: dict[str, list[Span]] = {}
    for span in spans:
        grouped.setdefault(span.type, []).append(span)
    return grouped


def remember_purpose_stage(ctx: AnalysisContext) -> AnalysisContext:
    """purpose_policy_stage 가 채운 ctx.purpose 를 세션 상태에 기록한다.

    output 경로(transform/apply.py::detokenize_stage)가 get_last_purpose() 로
    조회해 쓴다. direction != "input" 이거나 purpose 가 아직 없으면(예: 상위
    스테이지에서 이미 blocked 되어 여기까지 못 옴) 아무것도 하지 않는다.

    multiturn_stage 와 별도로 세션을 한 번 더 로드/저장한다 — 인메모리 스토어
    에서는 비용이 미미하지만, 나중에 PostgreSQL 세션 스토어(§7.3)로 바뀌면
    턴당 두 번째 왕복이 추가된다는 점은 성능 튜닝 시 고려 대상이다.
    """
    if ctx.direction != "input" or ctx.purpose is None:
        return ctx

    store = _get_store()
    state = _run_sync(store.load(ctx.session_id))
    if state is None:
        # multiturn_stage 가 이미 세션을 만들어뒀어야 정상 — 방어적으로만 처리.
        state = store.new_session(ctx.session_id)
    state.purpose = ctx.purpose
    _run_sync(store.save(state))
    return ctx


def get_last_purpose(session_id: str) -> str | None:
    """세션에 마지막으로 기록된 purpose 를 조회한다. 세션이 없거나 만료됐으면 None.

    output 경로(detokenize_stage)가 vault.detokenize_text() 호출 시 purpose
    인자로 넘기기 위해 쓴다. 동기 함수다 — multiturn_stage 와 동일하게
    _run_sync() 로 브리지하므로, 이벤트 루프가 없는 스레드에서만 호출 가능하다
    (모듈 docstring 참고).
    """
    store = _get_store()
    state = _run_sync(store.load(session_id))
    return state.purpose if state is not None else None