"""
FastAPI 앱 — 얇은 어댑터.

라우트:
    GET /health                 — 헬스체크 (DB 포함)
    GET /events                 — 감사 로그 최신순 조회 (대시보드 tail)
    GET /events/{session_id}    — 세션 타임라인 (input→output)

모든 읽기 라우트는 읽기 전용 SELECT 만 수행하며 ``db.connection()`` 을 재사용한다.
``session_id`` 는 wire 문자열/UUID 아무거나 받아 ``coerce_session_uuid`` 로 정규화한다
(``log_events.session_id`` 컬럼이 UUID, 원본 문자열은 ``reason.session_id_raw``).

``created_at`` 응답은 KST(+09:00)로 통일한다 — 대시보드가 한국 시간으로 표시한다.

근거: docs/architecture/dlp-server-architecture.md §4, docs/schemas/dlp-server/log-event.md
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row

from . import db
from .config import Config, load_config
from .ids import coerce_session_uuid

_DIRECTIONS = ("input", "output")
_VERDICTS = ("allow", "block", "transform")
_EVENTS_LIMIT_MAX = 500
_KST = timezone(timedelta(hours=9), "KST")  # 한국은 DST 없음 → 고정 오프셋

# log_events 조회 컬럼 (created_at 은 마지막). reason 은 목록에서 접었다가
# 세션 타임라인에서만 통째로 돌려준다.
_EVENT_COLS = (
    "event_id, session_id, direction, provider, purpose, verdict_action, "
    "transforms, entities_summary, guardrail_hits, fail_policy_applied, "
    "latency_ms, reason, created_at"
)


def _parse_since(since: str) -> datetime:
    """ISO 8601 문자열 → tz-aware datetime. naive 는 KST 로 간주. 실패 시 422."""
    try:
        ts = datetime.fromisoformat(since)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="since 는 ISO 8601 타임스탬프여야 함") from exc
    return ts.replace(tzinfo=_KST) if ts.tzinfo is None else ts


def _serialize_event(row: dict, *, include_reason: bool = False) -> dict:
    """log_events 한 행 → 대시보드용 dict.

    ``reason`` 의 ``risk_score`` / ``note`` / ``session_id_raw`` 를 top-level 로 끌어올려
    대시보드가 reason 전체를 파싱하지 않아도 되게 한다. JSONB 컬럼은 psycopg3 가
    dict/list 로 돌려주므로 그대로 싣는다.
    """
    reason = row.get("reason") or {}
    out = {
        "event_id": row["event_id"],
        "session_id": str(row["session_id"]),
        "session_id_raw": reason.get("session_id_raw"),
        "direction": row["direction"],
        "provider": row["provider"],
        "purpose": row["purpose"],
        "verdict_action": row["verdict_action"],
        "transforms": row["transforms"] or [],
        "entities_summary": row["entities_summary"] or [],
        "guardrail_hits": row["guardrail_hits"] or [],
        "fail_policy_applied": row["fail_policy_applied"],
        "latency_ms": row["latency_ms"],
        "risk_score": reason.get("risk_score"),
        "note": reason.get("note"),
        # TIMESTAMPTZ 는 서버 세션 tz 로 돌아온다 — 응답은 KST(+09:00)로 통일한다.
        "created_at": (
            row["created_at"].astimezone(_KST).isoformat() if row["created_at"] else None
        ),
    }
    if include_reason:
        out["reason"] = reason
    return out


def _fetch_events(where: list[str], params: list, *, order: str, limit: int | None) -> list[dict]:
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    sql = f"SELECT {_EVENT_COLS} FROM log_events{clause} ORDER BY {order}"
    if limit is not None:
        sql += " LIMIT %s"
        params = [*params, limit]
    with db.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(sql, params)
        return cur.fetchall()


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

    @app.get("/events")
    def events(
        limit: int = Query(100, ge=1),
        direction: str | None = Query(None),
        verdict: str | None = Query(None),
        session_id: str | None = Query(None),
        since: str | None = Query(None),
    ) -> list[dict]:
        """감사 로그 최신순. 필터는 모두 선택. 원문은 담기지 않는다(스키마 보장)."""
        where: list[str] = []
        params: list = []

        if direction is not None:
            if direction not in _DIRECTIONS:
                raise HTTPException(status_code=422, detail="direction 은 input|output")
            where.append("direction = %s")
            params.append(direction)

        if verdict is not None:
            if verdict not in _VERDICTS:
                raise HTTPException(status_code=422, detail="verdict 은 allow|block|transform")
            where.append("verdict_action = %s")
            params.append(verdict)

        if session_id is not None:
            where.append("session_id = %s")
            params.append(str(coerce_session_uuid(session_id)))

        if since is not None:
            where.append("created_at >= %s")
            params.append(_parse_since(since))

        rows = _fetch_events(
            where,
            params,
            order="created_at DESC, event_id DESC",
            limit=min(limit, _EVENTS_LIMIT_MAX),
        )
        return [_serialize_event(r) for r in rows]

    @app.get("/events/{session_id}")
    def session_timeline(session_id: str) -> list[dict]:
        """한 세션의 판정 흐름 (created_at 오름차순 = input→output). reason 전체 포함."""
        rows = _fetch_events(
            ["session_id = %s"],
            [str(coerce_session_uuid(session_id))],
            order="created_at ASC, event_id ASC",
            limit=None,
        )
        return [_serialize_event(r, include_reason=True) for r in rows]

    return app


app = create_app()
