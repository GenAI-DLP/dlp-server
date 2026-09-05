"""판정 이벤트 in-process pub/sub. write_pg() → publish() → /events/stream(SSE) 구독자.

프로세스 내부에서만 동작(재시작 시 상태 없음). gRPC 스레드(쓰기)와 FastAPI 이벤트 루프
(읽기)가 다른 스레드라 queue.Queue + Lock으로 넘긴다.
"""

from __future__ import annotations

import queue
import threading

_SUBSCRIBER_MAXSIZE = 1000


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=_SUBSCRIBER_MAXSIZE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # 느린 구독자는 최신 이벤트를 유실 — 라이브 tail이므로 허용


bus = EventBus()
