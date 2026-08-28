"""
pipeline.analyze() — dlp-server 의 유일한 판정 진입점.

gRPC 서버 · HTTP API · eval 스크립트가 모두 이 함수를 호출한다 (transport-agnostic 코어).
전체를 try/except 로 감싸 내부 오류 시에도 유효한 Decision 을 반환한다.

현재: Phase 0 스켈레톤. 스테이지 자리만 잡고 무조건 allow 를 반환한다.

근거: docs/architecture/dlp-server-architecture.md §3 (요청 파이프라인)
"""

from __future__ import annotations

import logging

from .config import Config, load_config
from .models import Decision

logger = logging.getLogger(__name__)

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
            return _analyze_input(session_id, method, path, headers, body, cfg)
        if direction == "output":
            return _analyze_output(session_id, method, path, headers, body, cfg)

        logger.warning("알 수 없는 direction=%r — allow 처리", direction)
        return Decision(action="allow", reason_obj={"note": f"unknown direction {direction!r}"})
    except Exception:  # 파이프라인은 절대 예외를 밖으로 던지지 않는다
        logger.exception("pipeline.analyze 내부 오류 — fail_action=%s 로 판정", cfg.fail_action)
        return Decision(
            action=cfg.fail_action,
            reason_obj={"fail_policy_applied": True, "stage": "pipeline"},
        )


def _analyze_input(
    session_id: str,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    cfg: Config,
) -> Decision:
    # [1] 어댑터 선택 (body → turns)        — adapters/           (#3)
    # [2] Input Guard                        — guardrail/injection.py (c)
    # [3] 멀티턴 분석 (세션 누적/위험도)      — context/            (e)
    # [4] 하이브리드 PII 탐지                 — detect/             (b)
    # [5] 목적 분석 + 정책 엔진               — purpose/, policy/   (f)
    # [6] 동적 변환 + 토큰화 → 본문 재조립    — transform/          (g, a)
    # [7] 감사 로그                           — logging/events.py
    return Decision(action="allow", reason_obj={"verdict": "allow", "stage": "input-skeleton"})


def _analyze_output(
    session_id: str,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    cfg: Config,
) -> Decision:
    # [1] 응답 파싱 (SSE 조각 조합)          — adapters/           (#3)
    # [2] detokenize (인가 검사)             — transform/vault.py  (a)
    # [3] Output Guard                       — guardrail/output_check.py (c)
    # [4] 본문 재조립 + 감사 로그
    return Decision(action="allow", reason_obj={"verdict": "allow", "stage": "output-skeleton"})
