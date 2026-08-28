"""
감사 로그 — 모든 파이프라인 판정이 수렴하는 sink. JSONL append.

**원문 무저장.** `entities_summary` 는 마스킹 프리뷰만, `reason` 에도 원문을 넣지 않는다
(reason 은 pipeline 의 reason_obj 를 그대로 받으며 그쪽에서 원문을 담지 않는 것이 계약).

근거: docs/schemas/dlp-server/log-event.md
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


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


def log_event(event: LogEvent, path: str | Path) -> None:
    """이벤트 1건을 JSONL 한 줄로 append."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
