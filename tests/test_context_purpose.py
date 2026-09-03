"""
세션별 purpose 기억 — output 경로(detokenize_stage)가 조회하는 기능 검증.

transform/apply.py::detokenize_stage 의 TODO("세션 스토어가 세션별 purpose 를
기억해뒀다가 여기서 읽어오게 되면 이 TODO 는 해소된다")에 대응하는 기능이다.

근거: docs/spec/dlp-server/multiturn-context.md §3.9 (신규)
"""

import pytest

from app.context.stage import configure, get_last_purpose, remember_purpose_stage
from app.context.store import InMemorySessionStore
from app.models import AnalysisContext


def make_input_ctx(session_id: str, purpose: str | None) -> AnalysisContext:
    ctx = AnalysisContext(
        session_id=session_id,
        direction="input",
        provider="gateway",
        role=None,
        turns=[],
    )
    ctx.purpose = purpose
    return ctx


@pytest.fixture(autouse=True)
def _fresh_store():
    configure(store=InMemorySessionStore())
    yield


def test_remember_purpose_then_get_last_purpose_roundtrip():
    """remember_purpose_stage 로 저장한 값을 get_last_purpose 로 그대로 조회."""
    sid = "sess-purpose-1"
    ctx = make_input_ctx(sid, "doc_summarize")

    remember_purpose_stage(ctx)

    assert get_last_purpose(sid) == "doc_summarize"


def test_get_last_purpose_returns_none_for_unknown_session():
    """세션이 아예 없으면 None."""
    assert get_last_purpose("sess-never-existed") is None


def test_remember_purpose_stage_noop_when_purpose_is_none():
    """purpose 가 아직 안 채워졌으면(예: 상위 스테이지에서 blocked 됨) 아무것도 안 함."""
    sid = "sess-purpose-noop"
    ctx = make_input_ctx(sid, None)

    remember_purpose_stage(ctx)

    # 세션 자체가 생성되지 않았어야 함 (multiturn_stage 가 먼저 안 만들었다면)
    assert get_last_purpose(sid) is None


def test_remember_purpose_stage_noop_for_output_direction():
    """output 경로 ctx 에는 이 스테이지가 관여하지 않는다."""
    sid = "sess-purpose-output"
    ctx = AnalysisContext(
        session_id=sid, direction="output", provider="gateway", role=None, turns=[]
    )
    ctx.purpose = "doc_summarize"  # 정상적으로는 output ctx 에 안 채워지지만 방어 로직 확인용

    remember_purpose_stage(ctx)

    assert get_last_purpose(sid) is None


def test_last_purpose_updates_across_turns():
    """세션 중간에 purpose 가 바뀌면 가장 최근 값으로 갱신되어야 한다."""
    sid = "sess-purpose-update"
    remember_purpose_stage(make_input_ctx(sid, "doc_summarize"))
    assert get_last_purpose(sid) == "doc_summarize"

    remember_purpose_stage(make_input_ctx(sid, "code_help"))
    assert get_last_purpose(sid) == "code_help"


def test_e2e_pipeline_analyze_persists_purpose_for_output_stage(monkeypatch):
    """실제 pipeline.analyze() 를 돌려서, purpose_policy_stage 가 분류한 값이
    remember_purpose_stage 를 거쳐 get_last_purpose 로 조회되는지 확인한다.

    detokenize_stage(다른 담당자 파일) 자체는 호출하지 않는다 — 여기서 검증하는
    건 "기능 e가 제공하는 조회 API가 실제 파이프라인 실행 뒤에 맞는 값을
    돌려주는가"까지다. output 요청까지 태우는 건 vault/DB 가 필요해 범위 밖.
    """
    import json

    import app.db as db_module
    import app.policy.engine as policy_engine
    from app.config import Config, RiskConfig
    from app.context import get_last_purpose
    from app.pipeline import analyze

    def _fail_connection(*args, **kwargs):
        raise RuntimeError("db 연결 없음 (테스트 몽키패치)")

    monkeypatch.setattr(db_module, "connection", _fail_connection)
    policy_engine._cache = policy_engine.Ruleset()

    cfg = Config(risk=RiskConfig(hard_block=0.6))
    session_id = "sess-e2e-purpose"
    body = json.dumps({"messages": [{"role": "user", "content": "이 문서 요약해줘"}]}).encode(
        "utf-8"
    )

    analyze(
        session_id=session_id,
        direction="input",
        method="POST",
        path="/v1/chat",
        headers={},
        body=body,
        config=cfg,
    )

    assert get_last_purpose(session_id) == "doc_summarize"
