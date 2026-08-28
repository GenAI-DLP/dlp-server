"""
gRPC 계층 통합 테스트 — 인메모리로 서버를 띄우고 Inspect 를 호출한다.

현재 상태
- 판정 로직이 없음 (항상 allow)
- transport 배선(InspectRequest ↔ analyze ↔ Verdict)과 fail-closed 동작을 검증
"""

from __future__ import annotations

import json

import grpc
import pytest

from app import pipeline
from app.config import load_config
from app.grpc_server import create_server
from app.proto import dlp_pb2, dlp_pb2_grpc

_TEST_PORT = 50077


@pytest.fixture()
def stub():
    cfg = load_config()
    cfg.grpc.port = _TEST_PORT
    server = create_server(cfg)
    server.start()
    channel = grpc.insecure_channel(f"localhost:{_TEST_PORT}")
    try:
        yield dlp_pb2_grpc.DLPInspectorStub(channel)
    finally:
        channel.close()
        server.stop(grace=0)


def _req(direction: str) -> dlp_pb2.InspectRequest:
    return dlp_pb2.InspectRequest(
        session_id="s-test",
        direction=direction,
        method="POST",
        path="/v1/chat/completions",
        headers={"x-corp-user-id": "u1"},
        body=b'{"messages":[{"role":"user","content":"hello"}]}',
    )


def test_inspect_input_allow(stub):
    """input → allow, reason 은 파싱 가능한 JSON, transformed_body 는 비어 있음."""
    v = stub.Inspect(_req("input"))
    assert v.action == "allow"
    assert json.loads(v.reason)["verdict"] == "allow"
    assert v.transformed_body == b""


def test_inspect_output_allow(stub):
    """output 방향도 같은 경로로 allow."""
    assert stub.Inspect(_req("output")).action == "allow"


def test_unknown_direction_allow(stub):
    """모르는 direction 도 스켈레톤은 allow."""
    assert stub.Inspect(_req("sideways")).action == "allow"


def test_action_is_wire_value(stub):
    """action 은 wire 3값 중 하나."""
    assert stub.Inspect(_req("input")).action in ("allow", "block", "transform")


def test_grpc_layer_fail_closed(stub, monkeypatch):
    """grpc_server.Inspect 예외 → gRPC 에러 대신 Verdict(fail_action)."""

    def boom(*_a, **_kw):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.grpc_server.analyze", boom)
    v = stub.Inspect(_req("input"))
    assert v.action == "block"
    assert json.loads(v.reason).get("fail_policy_applied") is True


def test_pipeline_fail_closed(monkeypatch):
    """pipeline.analyze 스테이지 예외 → 유효한 Decision(fail_action)."""

    def _raise(*_a, **_kw):
        raise RuntimeError("stage blew up")

    monkeypatch.setattr("app.pipeline._analyze_input", _raise)
    cfg = load_config()
    d = pipeline.analyze("s", "input", "POST", "/x", {}, b"{}", config=cfg)
    assert d.action == cfg.fail_action
    assert d.reason_obj.get("fail_policy_applied") is True
