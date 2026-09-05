"""GET /events/stream (SSE 라이브 tail) 테스트.

``_event_stream()`` 제너레이터는 자연 종료 없는 무한 루프라 TestClient(httpx ASGI
transport)로 실제 HTTP 스트리밍을 태우면 데드락난다 — 그 transport는 ASGI 앱 코루틴이
끝날 때까지 기다렸다가 응답을 만들기 때문. 그래서 제너레이터를 직접 구동해서 검증하고,
라우팅/유효성 검사(요청이 제너레이터까지 가지 않고 즉시 끝나는 경우)만 TestClient로 확인한다.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.api import _event_stream, create_app
from app.logging.bus import bus


@pytest.fixture
def client(db):
    return TestClient(create_app())


async def _never_disconnected() -> bool:
    return False


def _evt(event_id: int, *, direction="input", verdict="allow", session_id="s") -> dict:
    return {
        "event_id": event_id,
        "session_id": session_id,
        "direction": direction,
        "verdict_action": verdict,
        "provider": "gateway",
        "purpose": None,
        "transforms": [],
        "entities_summary": [],
        "guardrail_hits": [],
        "fail_policy_applied": False,
        "latency_ms": 5,
        "risk_score": None,
        "note": None,
        "created_at": "2026-09-05T00:00:00+09:00",
    }


async def _anext(gen, timeout=1.0):
    return await asyncio.wait_for(gen.__anext__(), timeout=timeout)


@pytest.mark.asyncio
async def test_stream_opens_with_connected_comment():
    gen = _event_stream(None, None, None, _never_disconnected)
    try:
        assert await _anext(gen) == ": connected\n\n"
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_stream_pushes_published_event():
    gen = _event_stream(None, None, None, _never_disconnected)
    try:
        await _anext(gen)  # connected
        bus.publish(_evt(1))

        chunk = await _anext(gen)

        assert chunk.startswith("id: 1\n")
        data_line = chunk.splitlines()[1]
        assert json.loads(data_line[len("data: ") :])["event_id"] == 1
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_stream_filters_by_direction():
    gen = _event_stream("output", None, None, _never_disconnected)
    try:
        await _anext(gen)  # connected
        bus.publish(_evt(1, direction="input"))
        bus.publish(_evt(2, direction="output"))

        chunk = await _anext(gen)

        assert chunk.startswith("id: 2\n")  # input(1) 은 걸러짐
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_stream_filters_by_verdict():
    gen = _event_stream(None, "block", None, _never_disconnected)
    try:
        await _anext(gen)  # connected
        bus.publish(_evt(1, verdict="allow"))
        bus.publish(_evt(2, verdict="block"))

        chunk = await _anext(gen)

        assert chunk.startswith("id: 2\n")
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_stream_filters_by_session_id():
    gen = _event_stream(None, None, "sess-b", _never_disconnected)
    try:
        await _anext(gen)  # connected
        bus.publish(_evt(1, session_id="sess-a"))
        bus.publish(_evt(2, session_id="sess-b"))

        chunk = await _anext(gen)

        assert chunk.startswith("id: 2\n")
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_stream_unsubscribes_on_close():
    before = len(bus._subscribers)
    gen = _event_stream(None, None, None, _never_disconnected)
    await _anext(gen)  # connected — subscribe 완료
    assert len(bus._subscribers) == before + 1

    await gen.aclose()  # GeneratorExit → finally: bus.unsubscribe

    assert len(bus._subscribers) == before


def test_stream_rejects_bad_params(client):
    """직접 client.get 을 쓴다 — 유효성 검사가 즉시 실패해 제너레이터로 들어가지 않으므로 안전.
    /events/{session_id} 라우트에 가려지지 않고 이 라우트가 매칭되는지도 함께 확인한다."""
    assert client.get("/events/stream", params={"direction": "sideways"}).status_code == 422
    assert client.get("/events/stream", params={"verdict": "nope"}).status_code == 422
