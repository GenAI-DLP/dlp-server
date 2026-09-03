"""동적 데이터 변환 (기능 g) — transform_stage 스테이지 계약 테스트.

주 관심사: tokenize 조치가 vault.tokenize 에 access_scope 를 넘기는지.
access_scope 없이 토큰화하면 볼트 기본값(빈 리스트)으로 저장돼 detokenize 가 전면 실패한다.
마스킹 세부 규칙표는 여기서 깊게 다루지 않는다 — 스테이지가 조치를 올바로 실행하는지만 본다.
"""

from __future__ import annotations

import base64

from app.models import AnalysisContext, Span, Turn
from app.transform import vault
from app.transform.apply import _access_scope, transform_stage

_TEST_KEY = base64.b64encode(bytes(range(32))).decode()


def _ctx(*, turns, span_actions, role=None, purpose=None, session_id="s1"):
    ctx = AnalysisContext(
        session_id=session_id,
        direction="input",
        provider="gateway",
        role=role,
        turns=turns,
    )
    ctx.purpose = purpose
    ctx.span_actions = span_actions
    ctx.new_turn_spans = [s for s, _ in span_actions]
    return ctx


# ---------------------------------------------------------------------------
# _access_scope — 요청 맥락으로 복원 허용 범위 조립 (F2 = B안)
# ---------------------------------------------------------------------------
def test_access_scope_uses_request_role_and_purpose():
    ctx = _ctx(
        turns=[Turn("user", "x")], span_actions=[], role="agent_l1", purpose="customer_support"
    )
    assert _access_scope(ctx) == {"roles": ["agent_l1"], "purposes": ["customer_support"]}


def test_access_scope_wildcards_when_absent():
    ctx = _ctx(turns=[Turn("user", "x")], span_actions=[])
    assert _access_scope(ctx) == {"roles": ["*"], "purposes": ["*"]}


# ---------------------------------------------------------------------------
# transform_stage — 기본 조치
# ---------------------------------------------------------------------------
def test_keep_is_noop():
    span = Span("NAME", "홍길동", 3, 6, 0.6, "dict")
    ctx = _ctx(turns=[Turn("user", "이름 홍길동")], span_actions=[(span, "keep")])
    transform_stage(ctx)
    assert ctx.turns[-1].text == "이름 홍길동"


def test_no_span_actions_is_noop():
    ctx = _ctx(turns=[Turn("user", "그냥 텍스트")], span_actions=[])
    transform_stage(ctx)
    assert ctx.turns[-1].text == "그냥 텍스트"


def test_mask_and_redact_back_to_front():
    ctx = _ctx(
        turns=[Turn("user", "이름 홍길동 번호 010-1234-5678")],
        span_actions=[
            (Span("NAME", "홍길동", 3, 6, 0.6, "dict"), "mask"),
            (Span("PHONE", "010-1234-5678", 10, 23, 0.9, "regex"), "redact"),
        ],
    )
    transform_stage(ctx)
    assert ctx.turns[-1].text == "이름 홍*동 번호 [삭제됨]"


# ---------------------------------------------------------------------------
# 이슈 #25 — tokenize 조치가 vault.tokenize 에 access_scope 를 넘겨야 한다
# ---------------------------------------------------------------------------
def test_tokenize_passes_request_scope_to_vault(monkeypatch):
    scopes: list[dict | None] = []

    def fake_tokenize(session_id, entity_type, value, access_scope=None):
        scopes.append(access_scope)
        return f"<PII:{entity_type}:1>"

    monkeypatch.setattr("app.transform.apply.vault.tokenize", fake_tokenize)
    ctx = _ctx(
        turns=[Turn("user", "번호 010-1234-5678")],
        span_actions=[(Span("PHONE", "010-1234-5678", 3, 16, 0.9, "regex"), "tokenize")],
        role="agent_l1",
        purpose="customer_support",
    )
    transform_stage(ctx)
    assert ctx.turns[-1].text == "번호 <PII:PHONE:1>"
    assert scopes == [{"roles": ["agent_l1"], "purposes": ["customer_support"]}]


def test_tokenize_scope_wildcards_when_role_absent(monkeypatch):
    scopes: list[dict | None] = []

    def fake_tokenize(session_id, entity_type, value, access_scope=None):
        scopes.append(access_scope)
        return "<PII:RRN:1>"

    monkeypatch.setattr("app.transform.apply.vault.tokenize", fake_tokenize)
    ctx = _ctx(
        turns=[Turn("user", "880101-1234567")],
        span_actions=[(Span("RRN", "880101-1234567", 0, 14, 0.9, "regex"), "tokenize")],
    )
    transform_stage(ctx)
    assert scopes == [{"roles": ["*"], "purposes": ["*"]}]


def test_tokenize_roundtrips_and_scope_gates(db, monkeypatch):
    """이슈 #25 회귀: transform_stage 로 만든 토큰이 같은 role·목적으로 복원돼야 한다.

    access_scope 를 안 넘기던 버그에서는 아래 detokenize 가 전부 None 이었다.
    """
    monkeypatch.setenv("DLP_VAULT__KEY", _TEST_KEY)
    vault._reset()
    sid = "00000000-0000-0000-0000-0000000000a1"
    ctx = _ctx(
        turns=[Turn("user", "카드 4111-1111-1111-1111")],
        span_actions=[(Span("CARD", "4111-1111-1111-1111", 3, 22, 0.97, "regex"), "tokenize")],
        role="agent_l1",
        purpose="customer_support",
        session_id=sid,
    )
    transform_stage(ctx)
    assert ctx.turns[-1].text == "카드 <PII:CARD:1>"

    label = "<PII:CARD:1>"
    # 같은 role·목적 → 복원 성공
    assert vault.detokenize(sid, label, "agent_l1", "customer_support") == "4111-1111-1111-1111"
    # 다른 role → 거부 (요청 맥락으로 scope 를 조립하므로)
    assert vault.detokenize(sid, label, "agent_l2", "customer_support") is None
