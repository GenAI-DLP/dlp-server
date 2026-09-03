"""
동적 데이터 변환 (기능 g) — 입력 파이프라인 [6] 스테이지.

정책(f)이 span 마다 정한 조치(mask/redact/tokenize/keep)를
마지막 user 턴에 적용한다.
tokenize 는 볼트(a) 호출, access_scope 는 요청 role·목적으로 조립.
변환 중 오류는 fail-closed(ctx.blocked)

근거: docs/architecture/dlp-server-architecture.md §6-g
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

from app.models import AnalysisContext, Span, Turn
from app.transform.vault import tokenize

logger = logging.getLogger(__name__)

_REDACTED = "[삭제됨]"

# 조치를 실제로 실행하지 않는 값 (치환 스킵)
_NOOP_ACTIONS = frozenset({"keep", "block"})


# ---------------------------------------------------------------------------
# 타입별 마스킹
# ---------------------------------------------------------------------------
def _mask_rrn(value: str) -> str:
    head, sep, tail = value.partition("-")
    if sep:
        return f"{head}-{'*' * len(tail)}"
    return value[:6] + "*" * max(len(value) - 6, 0)


def _mask_keep_last4(value: str) -> str:
    """뒤 4자리만 남기고 나머지 숫자를 가린다 (카드번호). 구분자는 보존."""
    return re.sub(r"\d(?=(?:\D*\d){4})", "*", value)


def _mask_phone(value: str) -> str:
    parts = value.split("-")
    if len(parts) == 3:
        parts[1] = "*" * len(parts[1])
        return "-".join(parts)
    return _mask_keep_last4(value)


def _mask_email(value: str) -> str:
    local, at, domain = value.partition("@")
    if not at or not local:
        return "*" * len(value)
    return f"{local[0]}***{at}{domain}"


def _mask_name(value: str) -> str:
    if len(value) <= 1:
        return "*"
    if len(value) == 2:
        return value[0] + "*"
    return value[0] + "*" * (len(value) - 2) + value[-1]


_MASKERS: dict[str, Callable[[str], str]] = {
    "RRN": _mask_rrn,
    "FOREIGN_RRN": _mask_rrn,
    "CARD": _mask_keep_last4,
    "ACCOUNT": _mask_keep_last4,
    "PHONE": _mask_phone,
    "EMAIL": _mask_email,
    "NAME": _mask_name,
}


def _mask(entity_type: str, value: str) -> str:
    """타입별 마스킹. 규칙이 없으면 값 전체를 `*` 로."""
    masker = _MASKERS.get(entity_type)
    if masker is None:
        return "*" * len(value)
    return masker(value)


def mask_preview(span: Span) -> str:
    """감사 로그 entities_summary 용 마스킹 미리보기 (원문 금지)."""
    return _mask(span.type, span.value)


# ---------------------------------------------------------------------------
# 조치 실행
# ---------------------------------------------------------------------------
def _access_scope(ctx: AnalysisContext) -> dict:
    """토큰 복원 허용 범위 — 요청 role·목적 기준 (정책 확장 시 규칙에서 가져옴)."""
    return {
        "roles": [ctx.role] if ctx.role else ["*"],
        "purposes": [ctx.purpose] if ctx.purpose else ["*"],
    }


def _render(ctx: AnalysisContext, span: Span, action: str) -> str:
    if action == "mask":
        return _mask(span.type, span.value)
    if action == "redact":
        return _REDACTED
    if action == "tokenize":
        return tokenize(ctx.session_id, span.type, span.value, access_scope=_access_scope(ctx))
    # generalize / aggregate / synthetic — MVP 미구현. 원문 노출 방지로 mask 폴백.
    logger.warning("apply: 미구현 조치 %r — mask 로 폴백", action)
    return _mask(span.type, span.value)


def _last_user_turn_index(turns: list[Turn]) -> int | None:
    for i in range(len(turns) - 1, -1, -1):
        if turns[i].role == "user":
            return i
    return None


def apply_transforms(ctx: AnalysisContext) -> AnalysisContext:
    """`ctx.span_actions` 를 마지막 user 턴 텍스트에 적용한다.

    span 을 start 역순(뒤→앞)으로 치환해 앞 span 의 offset 이 안 밀리게 한다.
    오류는 fail-closed(block).
    """
    if ctx.direction != "input" or not ctx.span_actions:
        return ctx
    try:
        idx = _last_user_turn_index(ctx.turns)
        if idx is None:
            return ctx
        text = ctx.turns[idx].text
        for span, action in sorted(ctx.span_actions, key=lambda sa: sa[0].start, reverse=True):
            if action in _NOOP_ACTIONS:
                continue
            text = text[: span.start] + _render(ctx, span, action) + text[span.end :]
        ctx.turns[idx].text = text
    except Exception:
        logger.exception("apply_transforms 실패 — fail-closed(block)")
        ctx.blocked = True
        ctx.block_reason = {"type": "transform", "note": "stage_error"}
    return ctx
