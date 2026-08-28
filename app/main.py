"""
부트스트랩 — config 로드 후 gRPC 서버(:50051)와 FastAPI(/health)를 함께 기동한다.

    python -m app.main

근거: docs/architecture/dlp-server-architecture.md §4, Phase 0
"""

from __future__ import annotations

import logging
import signal
import threading

import uvicorn

from . import db
from .api import create_app
from .config import load_config
from .grpc_server import create_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("app.main")


def main() -> None:
    cfg = load_config()

    grpc_server = create_server(cfg)
    grpc_server.start()
    logger.info("gRPC 서버 기동: %s:%s", cfg.grpc.host, cfg.grpc.port)

    stop = threading.Event()

    def _handle(signum, _frame):
        logger.info("신호 %s 수신 — 종료", signum)
        stop.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    api_conf = uvicorn.Config(
        create_app(),
        host=cfg.api.host,
        port=cfg.api.port,
        log_level="info",
    )
    api_server = uvicorn.Server(api_conf)
    api_thread = threading.Thread(target=api_server.run, name="uvicorn", daemon=True)
    api_thread.start()
    logger.info("FastAPI 기동: %s:%s", cfg.api.host, cfg.api.port)

    stop.wait()

    api_server.should_exit = True
    grpc_server.stop(grace=2.0)
    api_thread.join(timeout=5.0)
    db.close()
    logger.info("종료 완료")


if __name__ == "__main__":
    main()
