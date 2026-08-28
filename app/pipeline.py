"""
pipeline.analyze() — dlp-server 의 유일한 판정 진입점.

gRPC 서버 · HTTP API · eval 스크립트가 모두 이 함수를 호출한다 (transport-agnostic 코어).
전체를 try/except 로 감싸 내부 오류 시에도 유효한 Decision 을 반환한다.

스테이지 규약:
    Stage = Callable[[AnalysisContext], AnalysisContext]
    각 스테이지는 ctx 를 받아 필드를 갱신해 반환한다. "차단" 신호는 별도 반환값이 아니라
    ctx 필드로 표현한다:
      - ctx.injection.hit == True                → block
      - ctx.risk_score >= cfg.risk.hard_block    → block
    본문 변경은 ctx.turns[*].text 를 바꾸면 되고, 파이프라인이 adapter.rebuild 로 재조립한다.

현재: 스테이지 목록이 비어 있어 실질 판정은 없다(항상 allow). 각 기능(a~h)이 자리에 stage 를 채운다.

근거: docs/architecture/dlp-server-architecture.md §3 (요청 파이프라인)
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .adapters import select_adapter
from .config import Config, load_config
from .models import AnalysisContext, Decision, Turn

logger = logging.getLogger(__name__)

Stage = Callable[[AnalysisContext], AnalysisContext]

# 순서 (docs/architecture/dlp-server-architecture.md §3.1)
#   [2] Input Guard (c)      : ctx.injection 채움 (hit 이면 block)
#   [3] PII 탐지 (b)        : ctx.new_turn_spans  (detect.run(text) -> list[Span])
#   [4] 멀티턴 누적 (e)     : ctx.accumulated / ctx.risk_score  (탐지 결과를 세션에 누적)
#   [5] 목적+정책 (f)       : span 별 action 결정
#   [6] 변환+토큰화 (g, a)  : ctx.turns[*].text 갱신
_INPUT_STAGES: list[Stage] = []
# 출력: [2] detokenize (a) / [3] Output Guard (c)
_OUTPUT_STAGES: list[Stage] = []

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
    try:
        if direction == "input":
            return _analyze_input(session_id, path, headers, body, cfg)
        if direction == "output":
            return _analyze_output(session_id, path, headers, body, cfg)

        logger.warning("알 수 없는 direction=%r — allow 처리", direction)
        return Decision(action="allow", reason_obj={"note": f"unknown direction {direction!r}"})
    except Exception:  # 파이프라인은 절대 예외를 밖으로 던지지 않는다
        logger.exception("pipeline.analyze 내부 오류 — fail_action=%s 로 판정", cfg.fail_action)
        return Decision(
            action=cfg.fail_action,
            reason_obj={"fail_policy_applied": True, "stage": "pipeline"},
        )


def _run_stages(ctx: AnalysisContext, stages: list[Stage]) -> AnalysisContext:
    for stage in stages:
        ctx = stage(ctx)
    return ctx


def _reason(ctx: AnalysisContext, verdict: str, **extra: object) -> dict:
    reason: dict = {
        "verdict": verdict,
        "transforms": [],
        "entities_summary": [],
        "purpose": None,
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
        role=None,  # role 은 [5] 목적+정책(f)에서 role_resolver 로 채움
        turns=adapter.extract_turns(body),
    )
    original_texts = [t.text for t in ctx.turns]

    ctx = _run_stages(ctx, _INPUT_STAGES)

    if ctx.injection.hit:
        hits = [{"type": "injection", "pattern": ctx.injection.pattern}]
        return Decision(action="block", reason_obj=_reason(ctx, "block", guardrail_hits=hits))
    if ctx.risk_score >= cfg.risk.hard_block:
        return Decision(action="block", reason_obj=_reason(ctx, "block", note="risk_hard_block"))

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
        role=None,
        turns=[Turn(role="assistant", text=text)],
    )

    ctx = _run_stages(ctx, _OUTPUT_STAGES)

    if ctx.injection.hit:
        return Decision(
            action="block",
            reason_obj=_reason(ctx, "block", guardrail_hits=[{"type": "output_guard"}]),
        )

    new_text = ctx.turns[0].text if ctx.turns else text
    if new_text == text:
        return Decision(action="allow", reason_obj=_reason(ctx, "allow"))
    new_body = adapter.rebuild_response(body, new_text)
    return Decision(
        action="transform", transformed_body=new_body, reason_obj=_reason(ctx, "transform")
    )
