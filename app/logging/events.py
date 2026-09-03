"""
감사 로그 — 모든 파이프라인 판정이 수렴하는 sink.

기본은 PostgreSQL ``log_events`` INSERT(:func:`write_pg`).
DB 장애 시 JSONL append (:func:`log_event`)로 폴백한다.
sink 선택은 ``config.log_sink`` (pg | jsonl | both).

**원문 무저장.** ``entities_summary`` 는 마스킹 프리뷰만, ``reason`` 에도 원문을 넣지 않는다
(reason 은 pipeline 의 reason_obj 를 그대로 받으며 그쪽에서 원문을 담지 않는 것이 계약).

근거: docs/schemas/dlp-server/log-event.md
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from psycopg.types.json import Jsonb

from app import db
from app.ids import coerce_session_uuid


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
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


def write_pg(event: LogEvent) -> None:
    """이벤트 1건을 ``log_events`` 에 INSERT. ``created_at`` 은 DB 기본값(now()).

    ``session_id`` 는 UUID 로 정규화하고 원본 문자열은 ``reason.session_id_raw`` 로 남긴다.
    """
    reason = {**(event.reason or {}), "session_id_raw": event.session_id}
    params = (
        coerce_session_uuid(event.session_id),
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
        conn.execute(_INSERT_SQL, params)


def log_event(event: LogEvent, path: str | Path) -> None:
    """이벤트 1건을 JSONL 한 줄로 append (폴백 / jsonl 모드)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
