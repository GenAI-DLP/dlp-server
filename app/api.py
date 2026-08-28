"""
FastAPI 앱 — 얇은 어댑터.

현재: /health 만.

근거: docs/architecture/dlp-server-architecture.md §4
"""

from __future__ import annotations

from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(title="dlp-server", version="0.0.1")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
