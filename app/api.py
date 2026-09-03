"""
FastAPI 앱 — 얇은 어댑터.

현재: /health. 대시보드용 읽기 라우트(/events 계열)는 이 뒤에 추가된다.
모든 라우트는 읽기 전용이며 ``db.connection()`` 을 재사용한다.

근거: docs/architecture/dlp-server-architecture.md §4
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db
from .config import Config, load_config


def create_app(config: Config | None = None) -> FastAPI:
    cfg = config or load_config()
    app = FastAPI(title="dlp-server", version="0.0.1")

    # 대시보드(별도 오리진)의 브라우저 요청을 허용한다. 읽기 API 라 GET 만 연다.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api.cors_origins,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict:
        db_status = "ok"
        try:
            with db.connection() as conn:
                conn.execute("SELECT 1")
        except Exception:
            db_status = "down"
        return {"status": "ok", "db": db_status}

    return app


app = create_app()
