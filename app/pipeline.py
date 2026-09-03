"""
pipeline.analyze() — dlp-server 의 유일한 판정 진입점.

gRPC 서버 · HTTP API · eval 스크립트가 모두 이 함수를 호출한다 (transport-agnostic 코어).
전체를 try/except 로 감싸 내부 오류 시에도 유효한 Decision 을 반환한다.

스테이지 규약:
    Stage = Callable[[AnalysisContext], AnalysisContext]
    각 스테이지는 ctx 를 받아 필드를 갱신해 반환한다. "차단" 신호는 별도 반환값이 아니라
    ctx 필드로 표현한다:
      - ctx.blocked == True                      → block (ctx.block_reason 을 근거로 첨부)
      - ctx.injection.hit == True                → block
      - ctx.risk_score >= cfg.risk.hard_block    → block (input 경로만)
    본문 변경은 ctx.turns[*].text 를 바꾸면 되고, 파이프라인이 adapter.rebuild 로 재조립한다.

현재: [2] Input Guard, [3] PII 탐지(b), [4] 멀티턴 누적(e) 까지 배선됨.
ctx.risk_score 는 이제 세션 누적 결과를 반영한다 (docs/spec/dlp-server/multiturn-context.md).
[5] 목적+정책(f) 은 purpose 만 채우고, span_actions(변환 대상 결정)는 span 정보를 아직
활용하지 않을 수 있음 — policy/engine.py 쪽에서 new_turn_spans 소비 여부 확인 필요.
출력 경로: [3] Output Guard(c, 재스캔+인젝션 순응) → [2] detokenize(a) 순으로 배선됨.
(재스캔이 detokenize 앞이어야 복원된 인가 PII 를 재마스킹하지 않는다 — output_check.py 참고.)

근거: docs/architecture/dlp-server-architecture.md §3 (요청 파이프라인)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from app.transform.apply import mask_preview

from .adapters import select_adapter
from .config import Config, load_config
from .context import (
    multiturn_stage,  # [4] 멀티턴 누적 (e) — docs/spec/dlp-server/multiturn-context.md
    remember_purpose_stage,  # 세션에 purpose 기록 — output detokenize_stage 가 조회
)
from .detect import pii_detect_stage
from .guardrail.injection import injection_guard
from .guardrail.output_check import output_guard
from .logging.events import LogEvent, log_event
from .models import AnalysisContext, Decision, Turn
from .policy.engine import purpose_policy_stage
from .purpose.role_resolver import resolve as resolve_role
from .transform.apply import detokenize_stage, transform_stage

logger = logging.getLogger(__name__)

Stage = Callable[[AnalysisContext], AnalysisContext]

# 순서 (docs/architecture/dlp-server-architecture.md §3.1)
#   [2] Input Guard (c)      : ctx.injection 채움. hit 이면 ctx.blocked 도 세팅해 조기 종료
#   [3] PII 탐지 (b)        : ctx.new_turn_spans — pii_detect_stage 가
#                              app.detect.detect() 호출
#   [4] 멀티턴 누적 (e)     : ctx.accumulated / ctx.risk_score
#                              (탐지 결과를 세션에 누적) — multiturn_stage 로 배선됨
#   [5] 목적+정책 (f)       : ctx.purpose / ctx.span_actions 채움.
#                              block action 이면 ctx.blocked
#         └ remember_purpose_stage : ctx.purpose 를 세션에 기록 (output 경로가 조회)
#   [6] 변환+토큰화 (g, a)  : ctx.turns[*].text 갱신
_INPUT_STAGES: list[Stage] = [
    injection_guard,
    pii_detect_stage,
    multiturn_stage,
    purpose_policy_stage,
    remember_purpose_stage,
    transform_stage,
]
# 출력: [3] Output Guard (c) 재스캔+인젝션 순응 → [2] detokenize (a) 인가 복원.
#   재스캔은 detokenize 앞 — 라벨은 정규식에 안 걸리므로 모델이 새로 만든 PII 만 잡고,
#   복원된 인가 PII 를 다시 마스킹하는 사고를 막는다.
_OUTPUT_STAGES: list[Stage] = [output_guard, detokenize_stage]

_config: Config | None = None


def _default_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def analyze(
    session_id: str,
    direction: str,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    *,
    config: Config | None = None,
) -> Decision:
    """평문 요청/응답을 받아 판정(Decision)을 돌려준다. 예외를 전파하지 않는다."""
    cfg = config or _default_config()
    t0 = time.perf_counter()
    try:
        decision = _dispatch(session_id, direction, path, headers, body, cfg)
    except Exception:  # 파이프라인은 절대 예외를 밖으로 던지지 않는다
        logger.exception("pipeline.analyze 내부 오류 — fail_action=%s 로 판정", cfg.fail_action)
        decision = Decision(
            action=cfg.fail_action,
            reason_obj={"fail_policy_applied": True, "stage": "pipeline"},
        )
    latency_ms = int((time.perf_counter() - t0) * 1000)
    _emit_log(session_id, direction, decision, latency_ms, cfg)
    return decision


def _dispatch(
    session_id: str,
    direction: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    cfg: Config,
) -> Decision:
    if direction == "input":
        return _analyze_input(session_id, path, headers, body, cfg)
    if direction == "output":
        return _analyze_output(session_id, path, headers, body, cfg)
    logger.warning("알 수 없는 direction=%r — allow 처리", direction)
    return Decision(action="allow", reason_obj={"note": f"unknown direction {direction!r}"})


def _emit_log(
    session_id: str, direction: str, decision: Decision, latency_ms: int, cfg: Config
) -> None:
    r = decision.reason_obj or {}
    event = LogEvent(
        session_id=session_id,
        direction=direction,
        provider=r.get("provider", "unknown"),
        verdict_action=decision.action,
        latency_ms=latency_ms,
        purpose=r.get("purpose"),
        transforms=r.get("transforms", []),
        entities_summary=r.get("entities_summary", []),
        guardrail_hits=r.get("guardrail_hits", []),
        fail_policy_applied=bool(r.get("fail_policy_applied", False)),
        reason=r,
    )
    try:
        log_event(event, cfg.log_path)
    except Exception:  # 로그 실패가 판정을 막지 않는다
        logger.exception("감사 로그 기록 실패")


def _run_stages(ctx: AnalysisContext, stages: list[Stage]) -> AnalysisContext:
    for stage in stages:
        ctx = stage(ctx)
        if ctx.blocked:  # 차단 확정 시 이후 스테이지 스킵
            break
    return ctx


def _block_check(ctx: AnalysisContext, cfg: Config, *, check_risk: bool) -> Decision | None:
    """스테이지 실행 후 ctx 를 보고 block 여부를 판정. block 이 아니면 None."""
    if ctx.blocked:
        hits = [ctx.block_reason] if ctx.block_reason else []
        return Decision(action="block", reason_obj=_reason(ctx, "block", guardrail_hits=hits))
    if ctx.injection.hit:
        hits = [{"type": "injection", "pattern": ctx.injection.pattern}]
        return Decision(action="block", reason_obj=_reason(ctx, "block", guardrail_hits=hits))
    if check_risk and ctx.risk_score >= cfg.risk.hard_block:
        return Decision(action="block", reason_obj=_reason(ctx, "block", note="risk_hard_block"))
    return None


def _transforms_summary(ctx: AnalysisContext) -> list[dict]:
    """span별 조치 요약 (g). token_label 등 상세는 이후 확장."""
    return [{"entity": s.type, "action": a} for s, a in ctx.span_actions if a != "keep"]


def _entities_summary(ctx: AnalysisContext) -> list[dict]:
    """탐지된 엔티티 요약 — 마스킹 미리보기만, 원문 금지 (b)."""
    return [
        {"type": s.type, "confidence": round(s.confidence, 4), "masked_preview": mask_preview(s)}
        for s in ctx.new_turn_spans
    ]


def _reason(ctx: AnalysisContext, verdict: str, **extra: object) -> dict:
    reason: dict = {
        "verdict": verdict,
        "provider": ctx.provider,
        "transforms": _transforms_summary(ctx),
        "entities_summary": _entities_summary(ctx),
        "purpose": ctx.purpose,
        "risk_score": round(ctx.risk_score, 4),
        "guardrail_hits": [],
        "fail_policy_applied": False,
    }
    reason.update(extra)
    return reason


def _analyze_input(
    session_id: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    cfg: Config,
) -> Decision:
    adapter = select_adapter(path, headers, body)
    ctx = AnalysisContext(
        session_id=session_id,
        direction="input",
        provider=adapter.name,
        role=resolve_role(headers),  # 헤더 → role. 정책(f) 입력 축
        turns=adapter.extract_turns(body),
    )
    original_texts = [t.text for t in ctx.turns]

    ctx = _run_stages(ctx, _INPUT_STAGES)

    blocked = _block_check(ctx, cfg, check_risk=True)
    if blocked is not None:
        return blocked

    # 스테이지가 turn 텍스트를 안 바꿨으면 원본 본문을 그대로 통과 (재직렬화로 인한 diff 방지)
    if [t.text for t in ctx.turns] == original_texts:
        return Decision(action="allow", reason_obj=_reason(ctx, "allow"))
    new_body = adapter.rebuild(body, ctx.turns)
    return Decision(
        action="transform", transformed_body=new_body, reason_obj=_reason(ctx, "transform")
    )


def _analyze_output(
    session_id: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    cfg: Config,
) -> Decision:
    adapter = select_adapter(path, headers, body)
    text = adapter.parse_response(body)
    ctx = AnalysisContext(
        session_id=session_id,
        direction="output",
        provider=adapter.name,
        role=resolve_role(headers),  # detokenize 인가 검사(c-output)용
        turns=[Turn(role="assistant", text=text)],
    )

    ctx = _run_stages(ctx, _OUTPUT_STAGES)

    # output 경로는 risk_score 를 누적하는 스테이지가 없어 check_risk=False
    blocked = _block_check(ctx, cfg, check_risk=False)
    if blocked is not None:
        return blocked

    new_text = ctx.turns[0].text if ctx.turns else text
    if new_text == text:
        return Decision(action="allow", reason_obj=_reason(ctx, "allow"))
    new_body = adapter.rebuild_response(body, new_text)
    return Decision(
        action="transform", transformed_body=new_body, reason_obj=_reason(ctx, "transform")
    )
