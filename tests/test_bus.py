"""판정 이벤트 in-process pub/sub (EventBus) 테스트."""

from __future__ import annotations

import queue

from app.logging.bus import EventBus


def test_publish_broadcasts_to_all_subscribers():
    bus = EventBus()
    q1 = bus.subscribe()
    q2 = bus.subscribe()

    bus.publish({"event_id": 1})

    assert q1.get_nowait() == {"event_id": 1}
    assert q2.get_nowait() == {"event_id": 1}


def test_publish_with_no_subscribers_does_not_raise():
    bus = EventBus()
    bus.publish({"event_id": 1})  # 구독자 없어도 에러 없이 무시


def test_unsubscribe_stops_delivery():
    bus = EventBus()
    q = bus.subscribe()
    bus.unsubscribe(q)

    bus.publish({"event_id": 1})

    assert q.empty()


def test_unsubscribe_unknown_queue_is_noop():
    bus = EventBus()
    bus.unsubscribe(queue.Queue())  # 등록된 적 없는 큐 — 조용히 무시


def test_slow_subscriber_drops_when_full_without_raising():
    bus = EventBus()
    q = bus.subscribe()
    q.maxsize = 1
    bus.publish({"event_id": 1})

    bus.publish({"event_id": 2})  # 큐가 가득 차도 예외 없이 유실

    assert q.get_nowait() == {"event_id": 1}
    assert q.empty()
