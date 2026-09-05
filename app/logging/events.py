"""
감사 로그 — 모든 파이프라인 판정이 수렴하는 sink.

기본은 PostgreSQL ``log_events`` INSERT(:func:`write_pg`).
DB 장애 시 JSONL append (:func:`log_event`)로 폴백한다.
sink 선택은 ``config.log_sink`` (pg | jsonl | both).

``write_pg`` 는 INSERT 성공 시 :func:`serialize_event` 로 직렬화해 :mod:`app.logging.bus`
로 broadcast한다 (``/events/stream`` SSE 구독). ``api.py`` 읽기 경로도 같은 함수를 쓴다.

**원문 무저장.** ``entities_summary`` 는 마스킹 프리뷰만, ``reason`` 에도 원문을 넣지 않는다
(reason 은 pipeline 의 reason_obj 를 그대로 받으며 그쪽에서 원문을 담지 않는 것이 계약).

근거: docs/schemas/dlp-server/log-event.md
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

from app import db
from app.ids import coerce_session_uuid

from .bus import bus

_KST = timezone(timedelta(hours=9), "KST")  # 한국은 DST 없음 → 고정 오프셋


@dataclass
class LogEvent:
    session_id: str
    direction: str  # input | output
    provider: str  # gateway | openai | anthropic
    verdict_action: str  # allow | block | transform
    latency_ms: int
    purpose: str | None = None
    transforms: list = field(default_factory=list)
    entities_summary: list = field(default_factory=list)  # [{type, masked_preview, confidence}]
    guardrail_hits: list = field(default_factory=list)
    fail_policy_applied: bool = False
    reason: dict | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


_INSERT_SQL = (
    "INSERT INTO log_events "
    "(session_id, direction, provider, purpose, verdict_action, transforms, "
    "entities_summary, guardrail_hits, fail_policy_applied, latency_ms, reason) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "RETURNING event_id, created_at"
)


def serialize_event(row: dict, *, include_reason: bool = False) -> dict:
    """log_events 한 행(dict) → API/SSE 공용 표현.

    ``reason`` 의 ``risk_score`` / ``note`` / ``session_id_raw`` 를 top-level 로 끌어올려
    호출부가 reason 전체를 파싱하지 않아도 되게 한다. ``created_at`` 은 KST(+09:00)로 통일.
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
        "created_at": (
            row["created_at"].astimezone(_KST).isoformat() if row["created_at"] else None
        ),
    }
    if include_reason:
        out["reason"] = reason
    return out


def write_pg(event: LogEvent) -> None:
    """이벤트 1건을 ``log_events`` 에 INSERT. ``created_at`` 은 DB 기본값(now()).

    ``session_id`` 는 UUID 로 정규화하고 원본 문자열은 ``reason.session_id_raw`` 로 남긴다.
    INSERT 성공 시 실제 ``event_id``/``created_at`` 을 담아 :mod:`app.logging.bus` 로
    broadcast한다 (``/events/stream`` 라이브 tail이 구독).
    """
    session_uuid = coerce_session_uuid(event.session_id)
    reason = {**(event.reason or {}), "session_id_raw": event.session_id}
    params = (
        session_uuid,
        event.direction,
        event.provider,
        event.purpose,
        event.verdict_action,
        Jsonb(event.transforms),
        Jsonb(event.entities_summary),
        Jsonb(event.guardrail_hits),
        event.fail_policy_applied,
        event.latency_ms,
        Jsonb(reason),
    )
    with db.connection() as conn:
        cur = conn.execute(_INSERT_SQL, params)
        event_id, created_at = cur.fetchone()

    bus.publish(
        serialize_event(
            {
                "event_id": event_id,
                "session_id": session_uuid,
                "direction": event.direction,
                "provider": event.provider,
                "purpose": event.purpose,
                "verdict_action": event.verdict_action,
                "transforms": event.transforms,
                "entities_summary": event.entities_summary,
                "guardrail_hits": event.guardrail_hits,
                "fail_policy_applied": event.fail_policy_applied,
                "latency_ms": event.latency_ms,
                "reason": reason,
                "created_at": created_at,
            }
        )
    )


def log_event(event: LogEvent, path: str | Path) -> None:
    """이벤트 1건을 JSONL 한 줄로 append (폴백 / jsonl 모드)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
