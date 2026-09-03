"""
transform/apply.py — 동적 데이터 변환 (기능 g). ctx.span_actions 를 실행해
ctx.turns[*].text 를 갱신하는 파이프라인 [6] 스테이지.

정책 엔진(f)이 채운 (Span, action) 목록을 소비하는 실행 계층이다. 같은 PII 타입도
action 에 따라 다르게 처리되는 게 핵심 — 정적 마스킹 규칙표가 아니다.

action 별 처리:
    keep       원본 유지
    mask       비가역 부분 마스킹 (타입별 규칙, §아래 _mask 참고)
    generalize 범주로 일반화 — 현재 RRN 만 구현(<AGE:x대><SEX:y>), 그 외는 mask 로 폴백
    aggregate  같은 턴의 aggregate 대상 span 전부를 모아 합계/평균으로 치환 (개별 span 아님)
    tokenize   transform/vault.py 위임 — DB 필요
    synthetic  형식이 같은 무작위 값 (이름은 이름 풀, 나머지는 자릿수 유지한 무작위 숫자)
    redact     "[삭제됨]" 으로 완전 치환
    block      여기 도달 안 함 — purpose_policy_stage 가 이미 ctx.blocked 로 조기 차단

근거: docs/architecture/dlp-server-architecture.md §6-g
"""

from __future__ import annotations

import logging
import random
import re
from datetime import datetime

from app.models import AnalysisContext, Span
from app.transform import vault

logger = logging.getLogger(__name__)

_REDACT_TEXT = "[삭제됨]"
_MASK_KEEP_LAST_N = 4  # PHONE/ACCOUNT/CARD 마스킹 시 뒤에 남길 자릿수

_FAKE_NAMES = ("김도윤", "이하은", "박서준", "최지우", "정민재", "한소율", "윤지호", "임서아")


# ---------------------------------------------------------------------------
# 파이프라인 스테이지 — output 경로 [2] detokenize
# ---------------------------------------------------------------------------
def detokenize_stage(ctx: AnalysisContext) -> AnalysisContext:
    """output 경로에서 응답 안의 <PII:TYPE:n> 토큰 라벨을 원본으로 복원한다.

    vault.detokenize_text 는 access_scope(role/purpose) 를 통과 못 하면 라벨을
    그대로 둔다 (fail-closed) — 여기서 추가로 예외 처리할 필요 없음.

    ⚠️ 알려진 한계: ctx.purpose 는 output 요청에서 항상 None 이다.
    purpose_policy_stage 는 direction == "input" 일 때만 돌기 때문에, 이 별개의
    output InspectRequest 는 애초에 원 요청의 purpose 를 모른다. 세션 스토어
    (기능 e, context 쪽)가 세션별 purpose 를 기억해뒀다가 여기서 읽어오게
    되면 이 TODO 는 해소된다. 그 전까지는 access_scope 에 "*" 가 없는 토큰은
    output 단계에서 복원되지 않는다.
    """
    if ctx.direction != "output" or not ctx.turns:
        return ctx
    turn = ctx.turns[0]
    turn.text = vault.detokenize_text(ctx.session_id, turn.text, ctx.role, ctx.purpose)
    return ctx


# ---------------------------------------------------------------------------
# 파이프라인 스테이지 [6]
# ---------------------------------------------------------------------------
def transform_stage(ctx: AnalysisContext) -> AnalysisContext:
    """ctx.span_actions 를 실행해 최신 턴(analyze_turn 이 분석한 턴)의 텍스트를 갱신한다.

    aggregate 는 개별 span 치환이 아니라 그룹 처리라 별도로 분리한다.
    나머지는 span.start/end 를 오른쪽부터(내림차순) 치환해서 앞쪽 오프셋이
    안 틀어지게 한다.
    """
    if not ctx.span_actions or not ctx.turns:
        return ctx

    turn = ctx.turns[-1]
    text = turn.text

    per_span = [(s, a) for s, a in ctx.span_actions if a != "aggregate"]
    aggregate_group = [(s, a) for s, a in ctx.span_actions if a == "aggregate"]

    replacements: list[tuple[int, int, str]] = []
    for span, action in per_span:
        new_value = _render(action, ctx, span)
        replacements.append((span.start, span.end, new_value))
    for span, _ in aggregate_group:
        replacements.append((span.start, span.end, ""))  # 자리 비우고 요약은 뒤에 덧붙임

    for start, end, new_value in sorted(replacements, key=lambda r: r[0], reverse=True):
        text = text[:start] + new_value + text[end:]

    if aggregate_group:
        text = _append_aggregate_summary(text, [s for s, _ in aggregate_group])

    turn.text = text
    return ctx


def _render(action: str, ctx: AnalysisContext, span: Span) -> str:
    if action == "keep":
        return span.value
    if action == "mask":
        return _mask(span)
    if action == "generalize":
        return _generalize(span)
    if action == "tokenize":
        return _tokenize(ctx, span)
    if action == "synthetic":
        return _synthetic(span)
    if action == "redact":
        return _REDACT_TEXT
    logger.warning("transform: 알 수 없는 action=%r (type=%s) — keep 으로 폴백", action, span.type)
    return span.value


# ---------------------------------------------------------------------------
# tokenize — vault 위임
# ---------------------------------------------------------------------------
def _tokenize(ctx: AnalysisContext, span: Span) -> str:
    try:
        return vault.tokenize(ctx.session_id, span.type, span.value)
    except Exception:
        # tokenize 의 DB 오류는 vault.py 가 raise 하도록 설계돼 있음(fail-closed 원칙과
        # 별개로, 볼트 실패로 원본이 그대로 나가면 안 되니 redact 로 대체).
        logger.exception("transform: tokenize 실패 — redact 로 폴백 (type=%s)", span.type)
        return _REDACT_TEXT


# ---------------------------------------------------------------------------
# mask
# ---------------------------------------------------------------------------
def _mask(span: Span) -> str:
    t, v = span.type, span.value
    if t == "RRN":
        return _mask_rrn(v)
    if t in ("CARD", "PHONE", "ACCOUNT"):
        return _mask_keep_last_digits(v, keep=_MASK_KEEP_LAST_N)
    if t == "EMAIL":
        return _mask_email(v)
    if t == "NAME":
        return _mask_middle(v)
    return _mask_generic(v)


def _mask_rrn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13:
        return _mask_generic(value)
    return f"{digits[:6]}-{'*' * 7}"


def _mask_keep_last_digits(value: str, *, keep: int) -> str:
    digit_positions = [i for i, c in enumerate(value) if c.isdigit()]
    if len(digit_positions) <= keep:
        return value  # 자릿수가 keep 이하면 마스킹해도 의미 없어 원본 유지
    keep_set = set(digit_positions[-keep:])
    return "".join(c if (not c.isdigit() or i in keep_set) else "*" for i, c in enumerate(value))


def _mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return _mask_generic(value)
    return f"{_mask_middle(local)}@{domain}"


def _mask_middle(value: str) -> str:
    if len(value) <= 1:
        return "*" * len(value)
    if len(value) == 2:
        return value[0] + "*"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _mask_generic(value: str) -> str:
    return _mask_middle(value)


# ---------------------------------------------------------------------------
# generalize — 현재 RRN 만 규칙 있음, 나머지는 mask 로 안전하게 폴백
# ---------------------------------------------------------------------------
_GENDER_DIGIT_CENTURY = {
    "1": (1900, "남"),
    "2": (1900, "여"),
    "3": (2000, "남"),
    "4": (2000, "여"),
    "5": (1800, "남"),
    "6": (1800, "여"),
}


def _generalize(span: Span) -> str:
    if span.type == "RRN":
        result = _generalize_rrn(span.value)
        if result is not None:
            return result
    logger.info("transform: type=%s 의 generalize 규칙 미정의 — mask 로 폴백", span.type)
    return _mask(span)


def _generalize_rrn(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13:
        return None
    gender_digit = digits[6]
    century_sex = _GENDER_DIGIT_CENTURY.get(gender_digit)
    if century_sex is None:
        return None
    century, sex = century_sex
    birth_year = century + int(digits[0:2])
    age = datetime.now().year - birth_year
    bracket = max((age // 10) * 10, 0)
    return f"<AGE:{bracket}대><SEX:{sex}>"


# ---------------------------------------------------------------------------
# aggregate — 그룹 처리 (개별 span 치환이 아님)
# ---------------------------------------------------------------------------
def _parse_amount(value: str) -> float | None:
    cleaned = re.sub(r"[^\d.]", "", value)
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def _append_aggregate_summary(text: str, spans: list[Span]) -> str:
    amounts = [a for a in (_parse_amount(s.value) for s in spans) if a is not None]
    if not amounts:
        return text
    total = sum(amounts)
    avg = total / len(amounts)
    summary = f" [집계: 합계 {total:,.0f} / 평균 {avg:,.0f} / 건수 {len(amounts)}]"
    return text.rstrip() + summary


# ---------------------------------------------------------------------------
# synthetic
# ---------------------------------------------------------------------------
def _synthetic(span: Span) -> str:
    if span.type == "NAME":
        return random.choice(_FAKE_NAMES)

    if not any(c.isdigit() for c in span.value):
        # 숫자가 없는 타입(현재 스펙엔 없지만 안전장치)은 합성할 형식 기준이 없어 mask 로 대체
        return _mask(span)

    chars = list(span.value)
    for i, c in enumerate(chars):
        if c.isdigit():
            chars[i] = str(random.randint(0, 9))
    return "".join(chars)
