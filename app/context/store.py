"""
SessionStore — 멀티턴 세션 상태의 로드/저장 인터페이스와 인메모리 구현.

근거: docs/architecture/dlp-server-architecture.md §6-e, §7.3
스펙: docs/spec/dlp-server/multiturn-context.md §4 (store.backend, session.ttl_seconds)

설계 원칙:
- 평문 PII 값은 절대 세션 상태에 저장하지 않는다. value_hash 만 보관한다
  (아키텍처 §7.2 최소 보관 원칙과 동일선상).
- 이 인터페이스 뒤에 인메모리 구현과 PostgreSQL 구현을 모두 둘 수 있어야 한다
  (§7.3, §12 "외부 세션 스토어 도입 여부" 미결정 항목과 연동). 상위 파이프라인
  (accumulator.py, pipeline.py)은 SessionStore 프로토콜에만 의존한다.
- 감사 로그(log_events)·토큰 볼트(token_vault)는 세션과 FK가 없으므로
  (§7.2) 이 스토어의 삭제/만료가 감사·볼트에 영향을 주지 않는다. 세션 만료 시
  vault 도 함께 정리하는 트리거는 context/stage.py 의 on_expire 훅(§6-e)이 담당
  — 이 모듈은 콜백만 호출하고 vault 모듈에 직접 의존하지 않는다.

동시성 모델 [중요]:
  실제 배포 환경(grpc_server.py)은 grpc.server(ThreadPoolExecutor) — 즉 동시 요청이
  여러 OS 스레드에서 처리된다. pipeline.analyze() 는 완전히 동기 함수이고, 각
  스테이지(context/stage.py)는 store 호출을 asyncio.run() 으로 브리지하는데,
  asyncio.run() 은 호출될 때마다 새 이벤트 루프를 만든다. 즉 이 클래스의 async
  메서드들은 "요청마다 다른 스레드, 요청마다 다른 이벤트 루프"에서 실행된다.
  asyncio.Lock/asyncio.Task 는 단일 이벤트 루프 안에서만 안전을 보장하므로,
  이 조건에서는 사용할 수 없다(다른 루프에 바인딩된 락을 다른 루프에서 쓰면
  RuntimeError, 최악의 경우 보호 없이 레이스). 그래서 내부 잠금은
  threading.Lock, 백그라운드 스윕은 threading.Thread 로 구현한다 — 외부
  인터페이스(async def)는 SessionStore 프로토콜과의 호환을 위해 그대로 두되,
  내부에서 실제 동시성 경계(스레드)에 맞는 원시 자료형만 쓴다.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

# 기본 TTL. app/config.yaml 의 session.ttl_seconds 로 덮어쓴다 (스펙 §4).
DEFAULT_TTL_SECONDS = 1800.0
# 인메모리 스윕 주기. app/config.yaml 의 store.sweep_interval_seconds 로 덮어쓴다.
DEFAULT_SWEEP_INTERVAL_SECONDS = 300.0

# (type, value_hash) — 엔티티 그래프의 노드 키.
EntityKey = tuple[str, str]


@dataclass
class EntityRecord:
    """세션 내 누적된 단일 엔티티(타입+값 해시)의 이력.

    value 원문은 저장하지 않는다 — accumulator.py 가 해시로 변환한 뒤 넘긴다.
    """

    type: str
    value_hash: str
    first_turn: int
    last_turn: int
    count: int = 1


@dataclass
class GraphEdge:
    """슬라이딩 윈도우 내에서 함께 언급된 두 엔티티 노드 사이의 연결.

    엣지는 매 턴 활성 윈도우 기준으로 재계산되므로(스펙 §3.1) 영구 이력이
    아니라 "현재 시점의 스냅샷"에 가깝다. turn_index 는 이 엣지가 마지막으로
    확인된 턴을 기록해 디버깅·감사 시 참고용으로만 쓴다.
    """

    node_a: EntityKey
    node_b: EntityKey
    turn_index: int


@dataclass
class SessionState:
    """세션 단위로 유지되는 멀티턴 컨텍스트 상태.

    entities 는 세션 전체 이력(윈도우 밖도 포함, 감사·재등장 판정용, 스펙 §5
    엣지케이스), graph_edges 는 "현재 활성 윈도우 기준" 스냅샷이다(§3.1~3.2).
    """

    session_id: str
    created_at: float  # epoch seconds
    expires_at: float
    turn_count: int = 0
    entities: dict[EntityKey, EntityRecord] = field(default_factory=dict)
    graph_edges: list[GraphEdge] = field(default_factory=list)
    # 턴이 발생한 시각들 (velocity 판정용, 최근 것부터가 아니라 턴 순서대로 저장).
    turn_timestamps: list[float] = field(default_factory=list)
    risk_score: float = 0.0
    # 가장 최근 accumulate() 호출의 위험도 산정 근거 (감사 로그 참고용, 누적 아님).
    risk_reasons: list[str] = field(default_factory=list)
    # 가장 최근 input 턴의 목적 분류 결과 (purpose_policy_stage 산출물).
    # output 경로(detokenize_stage)는 자체 InspectRequest 라 목적을 모르므로
    # (§3.9), 여기 저장해둔 값을 stage.get_last_purpose() 로 조회해 쓴다.
    purpose: str | None = None

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at


class SessionStore(Protocol):
    """context/accumulator.py 및 pipeline.py 가 의존하는 저장소 인터페이스.

    구현체를 교체해도(§7.3, §12: 인메모리 ↔ PostgreSQL/Redis 미정) 상위
    파이프라인은 영향받지 않는다.
    """

    async def load(self, session_id: str) -> SessionState | None: ...

    async def save(self, state: SessionState) -> None: ...

    async def delete(self, session_id: str) -> None: ...

    def new_session(self, session_id: str, ttl_seconds: float | None = None) -> SessionState: ...


class InMemorySessionStore:
    """TTL 스윕 기반 인메모리 구현. 데모/Phase 2 기본값 (스펙 §4 store.backend=memory).

    프로세스 재시작 시 상태가 사라진다. threading.Lock 으로 실제 동시성 경계
    (OS 스레드, 모듈 docstring 참고)에 맞춘 보호를 하며, 다중 프로세스/다중
    인스턴스 배포 시에는 PostgreSQL/Redis 구현으로 전환해야 한다(§12 미결정 사항).
    """

    def __init__(
        self,
        default_ttl_seconds: float = DEFAULT_TTL_SECONDS,
        sweep_interval_seconds: float = DEFAULT_SWEEP_INTERVAL_SECONDS,
        on_expire=None,  # Callable[[SessionState], Awaitable[None] | None] | None
    ) -> None:
        self._states: dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._default_ttl_seconds = default_ttl_seconds
        self._sweep_interval_seconds = sweep_interval_seconds
        self._sweep_thread: threading.Thread | None = None
        self._sweep_stop_event = threading.Event()
        # 만료 시 vault 정리 등을 트리거하기 위한 콜백 (§6-e "세션 TTL 만료 시
        # 해당 세션의 vault도 함께 정리"). 이 스토어는 콜백만 호출하고 vault
        # 모듈에 직접 의존하지 않는다.
        self._on_expire = on_expire

    async def load(self, session_id: str) -> SessionState | None:
        with self._lock:
            state = self._states.get(session_id)
            if state is None:
                return None
            if state.is_expired():
                # 조회 시점에 만료가 확인되면 스윕 주기를 기다리지 않고 즉시 정리한다.
                del self._states[session_id]
                expired_state = state
            else:
                return state
        # 콜백은 락 밖에서 호출한다 — on_expire 가 (예: vault DB 호출로) 오래 걸려도
        # 다른 스레드의 세션 접근을 막지 않기 위함.
        await self._fire_on_expire(expired_state)
        return None

    async def save(self, state: SessionState) -> None:
        with self._lock:
            self._states[state.session_id] = state

    async def delete(self, session_id: str) -> None:
        with self._lock:
            state = self._states.pop(session_id, None)
        if state is not None:
            await self._fire_on_expire(state)

    def new_session(self, session_id: str, ttl_seconds: float | None = None) -> SessionState:
        """세션이 없거나 만료됐을 때 accumulator 가 호출하는 초기화 헬퍼.

        엣지케이스 #1(세션 만료 직후 요청 도착): 기본 정책은 "신규 세션으로
        취급, 누적 위험도 초기화"다(스펙 §5-1). grace period 를 두는 정책으로
        바뀌면 이 메서드가 아니라 load() 쪽에 만료 유예 로직을 추가한다.
        """
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        return SessionState(
            session_id=session_id,
            created_at=now,
            expires_at=now + ttl,
        )

    def start_sweeper(self) -> None:
        """만료 세션을 주기적으로 청소하는 백그라운드 스레드 시작 (app 부트스트랩에서 호출).

        asyncio.create_task() 가 아니라 threading.Thread 를 쓴다 — 실제 서버가
        오래 사는 이벤트 루프를 하나 유지하는 구조가 아니라(grpc.server, 동기),
        asyncio 태스크를 붙일 지속적인 루프 자체가 없기 때문이다. 데몬 스레드로
        띄우므로 프로세스 종료 시 별도 join 없이 함께 죽는다(stop_sweeper 로
        명시적으로 멈출 수도 있음).
        """
        if self._sweep_thread is not None:
            return
        self._sweep_stop_event.clear()
        self._sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True)
        self._sweep_thread.start()

    def stop_sweeper(self) -> None:
        self._sweep_stop_event.set()
        if self._sweep_thread is not None:
            self._sweep_thread.join(timeout=self._sweep_interval_seconds + 1)
            self._sweep_thread = None

    def _sweep_loop(self) -> None:
        while not self._sweep_stop_event.wait(timeout=self._sweep_interval_seconds):
            self._sweep_once_sync()

    def _sweep_once_sync(self) -> None:
        """동기 버전 — 스윕 스레드는 asyncio 루프가 없으므로 락/딕셔너리 조작만
        동기로 하고, on_expire 콜백만 각 세션별로 필요 시 asyncio.run() 브리지한다.
        """
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self._states.items() if s.is_expired(now)]
            expired_states = [self._states.pop(sid) for sid in expired]
        for state in expired_states:
            self._fire_on_expire_sync(state)

    async def _sweep_once(self) -> None:
        """비동기 컨텍스트(테스트 등)에서 쓰는 버전 — on_expire 콜백을 await 로 처리한다.

        threading.Thread 기반 프로덕션 스윕 루프(_sweep_loop)는 이미 실행 중인
        이벤트 루프가 없는 일반 스레드에서 돌기 때문에 _sweep_once_sync() +
        asyncio.run() 조합을 쓰지만, 여기(async 컨텍스트)서 그 조합을 그대로
        쓰면 "이미 실행 중인 루프 안에서 asyncio.run() 호출" 에러가 난다.
        """
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self._states.items() if s.is_expired(now)]
            expired_states = [self._states.pop(sid) for sid in expired]
        for state in expired_states:
            await self._fire_on_expire(state)

    def _fire_on_expire_sync(self, state: SessionState) -> None:
        if self._on_expire is None:
            return
        result = self._on_expire(state)
        if asyncio.iscoroutine(result):
            asyncio.run(result)

    async def _fire_on_expire(self, state: SessionState) -> None:
        if self._on_expire is None:
            return
        result = self._on_expire(state)
        if asyncio.iscoroutine(result):
            await result