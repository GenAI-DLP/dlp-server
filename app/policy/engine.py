"""
정책 엔진 (기능 f) — (목적 × role × 엔티티 타입) → 조치 + 위험도 오버라이드.

활성 정책 버전의 규칙을 PostgreSQL 에서 읽어(프로세스당 1회 캐시) 엔티티마다 action 을
결정한다. 스테이지 purpose_policy_stage 가 span 마다 decide() 를 호출해 ctx.span_actions 를
채우고, block 이 하나라도 나오면 ctx.blocked 로 조기 차단한다.

condition_expr 는 화이트리스트 파서로만 평가한다 — injection.hit / risk_score >= N 두 종류.
eval() 은 절대 쓰지 않는다.

근거: docs/architecture/dlp-server-architecture.md §6-f, docs/schemas/dlp-server/policy.md
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from app import db
from app.models import AnalysisContext, Turn
from app.purpose.classifier import classify

logger = logging.getLogger(__name__)

# 활성 정책 버전이 없을 때의 보수적 기본 — 가역적이라 안전한 편.
_FALLBACK_ACTION = "tokenize"

_RISK_SCORE_RE = re.compile(r"risk_score\s*>=\s*(0(?:\.\d+)?|1(?:\.0+)?)")


@dataclass(frozen=True)
class _Rule:
    purpose: str | None  # None = 와일드카드
    role: str | None
    entity_type: str | None
    action: str
    priority: int


@dataclass(frozen=True)
class _Override:
    condition_expr: str
    action: str
    priority: int


@dataclass(frozen=True)
class Ruleset:
    rules: list[_Rule] = field(default_factory=list)
    overrides: list[_Override] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 순수 판정 — DB 불필요
# ---------------------------------------------------------------------------
def eval_condition(expr: str, *, risk_score: float, injection_hit: bool) -> bool:
    """risk_override 조건식 평가. 지원: 'injection.hit', 'risk_score >= N'. 그 외는 False."""
    expr = (expr or "").strip()
    if expr == "injection.hit":
        return injection_hit
    m = _RISK_SCORE_RE.fullmatch(expr)
    if m:
        return risk_score >= float(m.group(1))
    logger.warning("policy: 알 수 없는 condition_expr=%r — 무시", expr)
    return False


def pick_action(
    rs: Ruleset,
    purpose: str,
    role: str | None,
    entity_type: str,
    *,
    risk_score: float,
    injection_hit: bool,
) -> str:
    """규칙셋과 컨텍스트로 action 하나를 고른다. risk_override 우선, 없으면 매트릭스 매칭."""
    fired = [
        o
        for o in rs.overrides
        if eval_condition(o.condition_expr, risk_score=risk_score, injection_hit=injection_hit)
    ]
    if fired:
        return max(fired, key=lambda o: o.priority).action

    def matches(r: _Rule) -> bool:
        return (
            (r.purpose is None or r.purpose == purpose)
            and (r.role is None or r.role == role)
            and (r.entity_type is None or r.entity_type == entity_type)
        )

    def specificity(r: _Rule) -> int:
        return (r.purpose is not None) + (r.role is not None) + (r.entity_type is not None)

    candidates = [r for r in rs.rules if matches(r)]
    if candidates:
        return max(candidates, key=lambda r: (specificity(r), r.priority)).action

    logger.warning(
        "policy: 매칭 규칙 없음 (purpose=%s role=%s entity=%s) — fallback=%s",
        purpose,
        role,
        entity_type,
        _FALLBACK_ACTION,
    )
    return _FALLBACK_ACTION


# ---------------------------------------------------------------------------
# 규칙셋 로드 + 캐시
# ---------------------------------------------------------------------------
_cache: Ruleset | None = None


def _load_ruleset() -> Ruleset:
    """활성 정책 버전의 규칙·오버라이드를 읽는다. 활성 버전이 없으면 빈 규칙셋."""
    with db.connection() as conn:
        ver = conn.execute(
            "SELECT policy_version_id FROM policy_versions WHERE is_active LIMIT 1"
        ).fetchone()
        if ver is None:
            logger.warning("policy: 활성 정책 버전 없음 — 빈 규칙셋 사용")
            return Ruleset()
        vid = ver[0]
        rules = [
            _Rule(purpose=p, role=r, entity_type=e, action=a, priority=pr)
            for (p, r, e, a, pr) in conn.execute(
                "SELECT purpose, role, entity_type, action, priority "
                "FROM policy_rules WHERE policy_version_id = %s",
                (vid,),
            ).fetchall()
        ]
        overrides = [
            _Override(condition_expr=c, action=a, priority=pr)
            for (c, a, pr) in conn.execute(
                "SELECT condition_expr, action, priority "
                "FROM policy_risk_overrides WHERE policy_version_id = %s",
                (vid,),
            ).fetchall()
        ]
    return Ruleset(rules=rules, overrides=overrides)


def ruleset() -> Ruleset:
    """캐시된 활성 규칙셋. 최초 1회 DB 로드."""
    global _cache
    if _cache is None:
        _cache = _load_ruleset()
    return _cache


def _reset() -> None:
    """테스트 전용 — 규칙셋 캐시 무효화."""
    global _cache
    _cache = None


def decide(
    purpose: str,
    role: str | None,
    entity_type: str,
    *,
    risk_score: float,
    injection_hit: bool,
) -> str:
    """엔티티 하나에 대한 조치를 결정한다."""
    return pick_action(
        ruleset(),
        purpose,
        role,
        entity_type,
        risk_score=risk_score,
        injection_hit=injection_hit,
    )


# ---------------------------------------------------------------------------
# 파이프라인 스테이지 [5]
# ---------------------------------------------------------------------------
def _last_user_text(turns: list[Turn]) -> str | None:
    for turn in reversed(turns):
        if turn.role == "user":
            return turn.text
    return None


def purpose_policy_stage(ctx: AnalysisContext) -> AnalysisContext:
    """마지막 user 턴으로 목적을 분류하고, 탐지된 span 마다 조치를 결정한다.

    ctx.purpose / ctx.purpose_confidence / ctx.span_actions 를 채운다.
    span action 이 하나라도 block 이면 ctx.blocked 로 요청 전체를 차단한다.
    내부 오류는 fail-closed(block) — PII 보호 경로라 통과시키지 않는다.
    """
    if ctx.direction != "input":
        return ctx
    try:
        ctx.purpose, ctx.purpose_confidence = classify(_last_user_text(ctx.turns) or "")
        for span in ctx.new_turn_spans:
            action = decide(
                ctx.purpose,
                ctx.role,
                span.type,
                risk_score=ctx.risk_score,
                injection_hit=ctx.injection.hit,
            )
            ctx.span_actions.append((span, action))
            if action == "block":
                ctx.blocked = True
                ctx.block_reason = {
                    "type": "policy",
                    "entity": span.type,
                    "purpose": ctx.purpose,
                }
    except Exception:
        logger.exception("purpose_policy_stage 실패 — fail-closed(block)")
        ctx.blocked = True
        ctx.block_reason = {"type": "policy", "note": "stage_error"}
    return ctx
