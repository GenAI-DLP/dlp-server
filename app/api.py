"""
FastAPI 앱 — 얇은 어댑터.

라우트:
    GET /health                 — 헬스체크 (DB 포함)
    GET /events                 — 감사 로그 최신순 조회 (대시보드 tail)
    GET /events/stream          — 판정 즉시 push되는 SSE 라이브 tail (라우트 등록 순서상
                                   /events/{session_id} 보다 먼저 와야 함)
    GET /events/{session_id}    — 세션 타임라인 (input→output)
    GET /stats                  — window 별 집계 (대시보드 KPI·차트)
    GET /vault-access           — 토큰 복원 시도 감사 조회

모든 읽기 라우트는 읽기 전용 SELECT 만 수행하며 ``db.connection()`` 을 재사용한다.
``session_id`` 는 wire 문자열/UUID 아무거나 받아 ``coerce_session_uuid`` 로 정규화한다
(``log_events.session_id`` 컬럼이 UUID, 원본 문자열은 ``reason.session_id_raw``).

``created_at`` 응답은 KST(+09:00)로 통일한다 — 대시보드가 한국 시간으로 표시한다.

근거: docs/architecture/dlp-server-architecture.md §4, docs/schemas/dlp-server/log-event.md
"""

from __future__ import annotations

import asyncio
import json
import queue
import re
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row

from . import db
from .config import Config, load_config
from .ids import coerce_session_uuid
from .logging.bus import bus
from .logging.events import serialize_event

_STREAM_HEARTBEAT_SEC = 15

_DIRECTIONS = ("input", "output")
_VERDICTS = ("allow", "block", "transform")
_EVENTS_LIMIT_MAX = 500
_VAULT_LIMIT_MAX = 500
_STATS_TOP_N = 10
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


def _parse_window(window: str) -> int:
    """``15m`` / ``2h`` → 분(int). 실패 시 422."""
    m = re.fullmatch(r"(\d+)([mh])", window.strip())
    if not m or int(m.group(1)) == 0:
        raise HTTPException(status_code=422, detail="window 은 예: 15m, 1h")
    n = int(m.group(1))
    return n if m.group(2) == "m" else n * 60


def _kst_iso(dt: datetime | None) -> str | None:
    return dt.astimezone(_KST).isoformat() if dt else None


def _run(sql: str, params: list | tuple) -> list[dict]:
    with db.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(sql, params)
        return cur.fetchall()


def _json_array_elems(col: str) -> str:
    """JSONB 배열이 아닌 과거 행을 만나도 깨지지 않게 감싼 ``jsonb_array_elements`` 소스."""
    return (
        f"jsonb_array_elements("
        f"CASE WHEN jsonb_typeof({col}) = 'array' THEN {col} ELSE '[]'::jsonb END)"
    )


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


async def _event_stream(
    direction: str | None,
    verdict: str | None,
    session_id: str | None,
    is_disconnected,
):
    """``/events/stream`` 본체. ``is_disconnected`` 를 주입받아 실제 요청(Request.is_disconnected)
    없이도 직접 구동해 테스트할 수 있게 한다 — TestClient(ASGI transport)는 앱이 끝날 때까지
    기다렸다가 응답을 만들기 때문에, 자연 종료 없는 이 제너레이터를 HTTP 계층으로 테스트하면
    데드락난다."""
    q = bus.subscribe()
    try:
        yield ": connected\n\n"
        while True:
            if await is_disconnected():
                break
            try:
                event = await asyncio.to_thread(q.get, timeout=_STREAM_HEARTBEAT_SEC)
            except queue.Empty:
                yield ": ping\n\n"
                continue
            if direction is not None and event["direction"] != direction:
                continue
            if verdict is not None and event["verdict_action"] != verdict:
                continue
            if session_id is not None and event["session_id"] != session_id:
                continue
            yield f"id: {event['event_id']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
    finally:
        bus.unsubscribe(q)


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
        return [serialize_event(r) for r in rows]

    # /events/{session_id} 보다 먼저 등록해야 한다 — 안 그러면 "stream"이 session_id로 매칭된다.
    @app.get("/events/stream")
    async def events_stream(
        request: Request,
        direction: str | None = Query(None),
        verdict: str | None = Query(None),
        session_id: str | None = Query(None),
    ) -> StreamingResponse:
        """판정 즉시 push되는 SSE 라이브 tail. 필터 의미는 ``/events`` 와 동일.

        연결 끊긴 동안의 이벤트는 이 스트림에서만 유실된다 — ``log_events`` 에는
        그대로 남아있어 ``/events``·``/events/{session_id}`` 로 조회 가능하다.
        """
        if direction is not None and direction not in _DIRECTIONS:
            raise HTTPException(status_code=422, detail="direction 은 input|output")
        if verdict is not None and verdict not in _VERDICTS:
            raise HTTPException(status_code=422, detail="verdict 은 allow|block|transform")
        norm_session_id = str(coerce_session_uuid(session_id)) if session_id is not None else None

        return StreamingResponse(
            _event_stream(direction, verdict, norm_session_id, request.is_disconnected),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/events/{session_id}")
    def session_timeline(session_id: str) -> list[dict]:
        """한 세션의 판정 흐름 (created_at 오름차순 = input→output). reason 전체 포함."""
        rows = _fetch_events(
            ["session_id = %s"],
            [str(coerce_session_uuid(session_id))],
            order="created_at ASC, event_id ASC",
            limit=None,
        )
        return [serialize_event(r, include_reason=True) for r in rows]

    @app.get("/stats")
    def stats(window: str = Query("1h")) -> dict:
        """최근 ``window`` 구간 집계. 대시보드 KPI·차트가 소비한다.

        fail_policy_applied 행(장애 대응)은 verdict 카운트에 그대로 포함되며
        ``fail_closed`` 로 따로 노출한다.
        """
        minutes = _parse_window(window)
        since = datetime.now(_KST) - timedelta(minutes=minutes)
        bucket = "minute" if minutes <= 120 else "hour"

        summary = _run(
            "SELECT "
            "count(*) AS events, "
            "count(DISTINCT session_id) AS sessions, "
            "count(*) FILTER (WHERE direction = 'input') AS input, "
            "count(*) FILTER (WHERE direction = 'output') AS output, "
            "count(*) FILTER (WHERE verdict_action = 'allow') AS allow, "
            "count(*) FILTER (WHERE verdict_action = 'block') AS block, "
            "count(*) FILTER (WHERE verdict_action = 'transform') AS transform, "
            "count(*) FILTER (WHERE jsonb_typeof(guardrail_hits) = 'array' "
            "AND jsonb_array_length(guardrail_hits) > 0) AS guardrail_hits, "
            "count(*) FILTER (WHERE fail_policy_applied) AS fail_closed, "
            "coalesce(avg(latency_ms), 0) AS latency_avg, "
            "coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0) AS latency_p95 "
            "FROM log_events WHERE created_at >= %s",
            [since],
        )[0]

        by_purpose = _run(
            "SELECT coalesce(purpose, '(none)') AS purpose, count(*) AS count "
            "FROM log_events WHERE created_at >= %s GROUP BY 1 ORDER BY 2 DESC",
            [since],
        )
        by_entity_type = _run(
            f"SELECT e->>'type' AS type, count(*) AS count "
            f"FROM log_events, {_json_array_elems('entities_summary')} AS e "
            f"WHERE created_at >= %s GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %s",
            [since, _STATS_TOP_N],
        )
        by_action = _run(
            f"SELECT e->>'action' AS action, count(*) AS count "
            f"FROM log_events, {_json_array_elems('transforms')} AS e "
            f"WHERE created_at >= %s GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %s",
            [since, _STATS_TOP_N],
        )
        buckets = _run(
            "SELECT date_trunc(%s, created_at) AS ts, "
            "count(*) FILTER (WHERE verdict_action = 'allow') AS allow, "
            "count(*) FILTER (WHERE verdict_action = 'block') AS block, "
            "count(*) FILTER (WHERE verdict_action = 'transform') AS transform "
            "FROM log_events WHERE created_at >= %s GROUP BY 1 ORDER BY 1",
            [bucket, since],
        )

        return {
            "window": window,
            "generated_at": _kst_iso(datetime.now(_KST)),
            "totals": {
                "events": summary["events"],
                "sessions": summary["sessions"],
                "input": summary["input"],
                "output": summary["output"],
            },
            "verdict": {
                "allow": summary["allow"],
                "block": summary["block"],
                "transform": summary["transform"],
            },
            "guardrail_hits": summary["guardrail_hits"],
            "fail_closed": summary["fail_closed"],
            "latency_ms": {
                "avg": round(float(summary["latency_avg"]), 1),
                "p95": round(float(summary["latency_p95"]), 1),
            },
            "by_purpose": by_purpose,
            "by_entity_type": by_entity_type,
            "by_action": by_action,
            "buckets": [
                {
                    "ts": _kst_iso(b["ts"]),
                    "allow": b["allow"],
                    "block": b["block"],
                    "transform": b["transform"],
                }
                for b in buckets
            ],
        }

    @app.get("/vault-access")
    def vault_access(
        session_id: str = Query(...),
        limit: int = Query(100, ge=1),
    ) -> list[dict]:
        """세션의 토큰 복원 시도 감사(``token_vault_access_log``). granted=false = 인가 실패."""
        rows = _run(
            "SELECT access_id, token_id, session_id, token_label, requested_role, "
            "requested_purpose, granted, denied_reason, accessed_at "
            "FROM token_vault_access_log WHERE session_id = %s "
            "ORDER BY accessed_at DESC LIMIT %s",
            [str(coerce_session_uuid(session_id)), min(limit, _VAULT_LIMIT_MAX)],
        )
        for r in rows:
            r["token_id"] = str(r["token_id"])
            r["session_id"] = str(r["session_id"])
            r["accessed_at"] = _kst_iso(r["accessed_at"])
        return rows

    return app


app = create_app()
