"""
FastAPI 앱 — 얇은 어댑터.

현재: /health 만.

근거: docs/architecture/dlp-server-architecture.md §4
"""

from __future__ import annotations

from fastapi import FastAPI

from . import db


def create_app() -> FastAPI:
    app = FastAPI(title="dlp-server", version="0.0.1")

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
