"""
gRPC 어댑터 — proto 메시지 ↔ 내부 호출 변환만 담당한다. 판정 로직은 pipeline.analyze() 에 위임.

내부 오류 시에도 유효한 Verdict 를 반환한다 (gRPC 에러를 던지지 않는다).

근거: docs/architecture/dlp-proto.md, docs/architecture/dlp-server-architecture.md §4
"""

from __future__ import annotations

import json
import logging
from concurrent import futures

import grpc

from app.proto import dlp_pb2, dlp_pb2_grpc

from .config import Config, load_config
from .pipeline import analyze

logger = logging.getLogger(__name__)


class DLPInspectorServicer(dlp_pb2_grpc.DLPInspectorServicer):
    def __init__(self, config: Config) -> None:
        self._config = config

    def Inspect(self, request: dlp_pb2.InspectRequest, context) -> dlp_pb2.Verdict:
        try:
            decision = analyze(
                session_id=request.session_id,
                direction=request.direction,
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                body=request.body,
                config=self._config,
            )
        except Exception:  # pipeline 이 이미 감싸지만 이중 안전장치
            logger.exception("Inspect 처리 실패 — fail_action=%s", self._config.fail_action)
            return dlp_pb2.Verdict(
                action=self._config.fail_action,
                reason=json.dumps({"fail_policy_applied": True, "stage": "grpc"}),
            )

        return dlp_pb2.Verdict(
            action=decision.action,
            transformed_body=decision.transformed_body or b"",
            reason=json.dumps(decision.reason_obj, ensure_ascii=False),
        )


def create_server(config: Config | None = None, max_workers: int = 8) -> grpc.Server:
    cfg = config or load_config()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    dlp_pb2_grpc.add_DLPInspectorServicer_to_server(DLPInspectorServicer(cfg), server)
    server.add_insecure_port(f"{cfg.grpc.host}:{cfg.grpc.port}")
    return server
