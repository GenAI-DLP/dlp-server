"""동적 데이터 변환 (기능 g) 테스트 — 마스킹 규칙 / 뒤→앞 치환 / 토큰화 / 파이프라인 배선.

`_mask` · `apply_transforms` 는 DB 불필요(토큰화는 monkeypatch). 실 볼트 왕복만 `db` fixture.
"""

from __future__ import annotations

import base64
import json

import pytest

from app import pipeline
from app.config import load_config
from app.models import AnalysisContext, Span, Turn
from app.transform import vault
from app.transform.apply import _mask, apply_transforms

_KEY = base64.b64encode(bytes(range(32))).decode()


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
    ctx.new_turn_spans = [sa[0] for sa in span_actions]
    return ctx


# ---------------------------------------------------------------------------
# 타입별 마스킹
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("etype", "value", "expected"),
    [
        ("RRN", "880101-1234567", "880101-*******"),
        ("RRN", "8801011234567", "880101*******"),
        ("CARD", "4111-1111-1111-1111", "****-****-****-1111"),
        ("PHONE", "010-1234-5678", "010-****-5678"),
        ("PHONE", "01012345678", "*******5678"),
        ("EMAIL", "test.user@example.co.kr", "t***@example.co.kr"),
        ("NAME", "홍길동", "홍*동"),
        ("NAME", "김구", "김*"),
        ("NAME", "A", "*"),
        ("AMOUNT", "1000000", "*******"),  # 규칙 없는 타입 → 전체 마스킹
    ],
)
def test_mask_by_type(etype, value, expected):
    assert _mask(etype, value) == expected


# ---------------------------------------------------------------------------
# apply_transforms — 조치 실행
# ---------------------------------------------------------------------------
def test_keep_leaves_text_unchanged():
    turns = [Turn("user", "이름 홍길동")]
    span = Span("NAME", "홍길동", 3, 6, 0.6, "dict")
    ctx = _ctx(turns=turns, span_actions=[(span, "keep")])
    apply_transforms(ctx)
    assert ctx.turns[0].text == "이름 홍길동"


def test_mask_and_redact_applied():
    turns = [Turn("user", "이름 홍길동 번호 010-1234-5678")]
    spans = [
        (Span("NAME", "홍길동", 3, 6, 0.6, "dict"), "mask"),
        (Span("PHONE", "010-1234-5678", 10, 23, 0.9, "regex"), "redact"),
    ]
    ctx = _ctx(turns=turns, span_actions=spans)
    apply_transforms(ctx)
    assert ctx.turns[0].text == "이름 홍*동 번호 [삭제됨]"


def test_replacement_is_back_to_front():
    # 두 span 을 모두 [삭제됨](길이 변화)으로 치환 — 앞 span offset 이 안 밀려야 함
    turns = [Turn("user", "A 880101-1234567 B 4111-1111-1111-1111 C")]
    spans = [
        (Span("RRN", "880101-1234567", 2, 16, 0.9, "regex"), "redact"),
        (Span("CARD", "4111-1111-1111-1111", 19, 38, 0.97, "regex"), "redact"),
    ]
    ctx = _ctx(turns=turns, span_actions=spans)
    apply_transforms(ctx)
    assert ctx.turns[0].text == "A [삭제됨] B [삭제됨] C"


def test_applies_to_last_user_turn_only():
    turns = [
        Turn("user", "옛 번호 010-1234-5678"),
        Turn("assistant", "확인했습니다"),
        Turn("user", "새 번호 010-9999-8888"),
    ]
    span = Span("PHONE", "010-9999-8888", 5, 18, 0.9, "regex")
    ctx = _ctx(turns=turns, span_actions=[(span, "mask")])
    apply_transforms(ctx)
    assert ctx.turns[0].text == "옛 번호 010-1234-5678"  # 과거 턴 무변경
    assert ctx.turns[2].text == "새 번호 010-****-8888"


def test_no_span_actions_is_noop():
    turns = [Turn("user", "그냥 텍스트")]
    ctx = _ctx(turns=turns, span_actions=[])
    out = apply_transforms(ctx)
    assert out.turns[0].text == "그냥 텍스트"
    assert out.blocked is False


# ---------------------------------------------------------------------------
# tokenize 조치
# ---------------------------------------------------------------------------
def test_tokenize_calls_vault_with_request_scope(monkeypatch):
    calls = []

    def fake_tokenize(session_id, entity_type, value, access_scope=None):
        calls.append((session_id, entity_type, value, access_scope))
        return f"<PII:{entity_type}:1>"

    monkeypatch.setattr("app.transform.apply.tokenize", fake_tokenize)

    turns = [Turn("user", "번호 010-1234-5678")]
    span = Span("PHONE", "010-1234-5678", 3, 16, 0.9, "regex")
    ctx = _ctx(
        turns=turns,
        span_actions=[(span, "tokenize")],
        role="agent_l1",
        purpose="customer_support",
    )
    apply_transforms(ctx)

    assert ctx.turns[0].text == "번호 <PII:PHONE:1>"
    assert calls[0][3] == {"roles": ["agent_l1"], "purposes": ["customer_support"]}


def test_tokenize_scope_wildcards_when_role_absent(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.transform.apply.tokenize",
        lambda s, t, v, access_scope=None: calls.append(access_scope) or "<PII:RRN:1>",
    )
    span = Span("RRN", "880101-1234567", 0, 14, 0.9, "regex")
    ctx = _ctx(turns=[Turn("user", "880101-1234567")], span_actions=[(span, "tokenize")])
    apply_transforms(ctx)
    assert calls[0] == {"roles": ["*"], "purposes": ["*"]}


def test_stage_failure_is_fail_closed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("vault key missing")

    monkeypatch.setattr("app.transform.apply.tokenize", boom)
    span = Span("RRN", "880101-1234567", 2, 16, 0.9, "regex")
    ctx = _ctx(turns=[Turn("user", "x 880101-1234567")], span_actions=[(span, "tokenize")])
    out = apply_transforms(ctx)
    assert out.blocked is True
    assert out.block_reason == {"type": "transform", "note": "stage_error"}


def test_tokenize_roundtrips_and_scope_gates(db, monkeypatch):
    monkeypatch.setenv("DLP_VAULT__KEY", _KEY)
    sid = "00000000-0000-0000-0000-0000000000a1"
    span = Span("CARD", "4111-1111-1111-1111", 3, 22, 0.97, "regex")
    ctx = _ctx(
        turns=[Turn("user", "카드 4111-1111-1111-1111")],
        span_actions=[(span, "tokenize")],
        role="agent_l1",
        purpose="customer_support",
        session_id=sid,
    )
    apply_transforms(ctx)
    assert ctx.turns[0].text == "카드 <PII:CARD:1>"

    label = "<PII:CARD:1>"
    # 같은 role·목적 → 복원 성공
    assert vault.detokenize(sid, label, "agent_l1", "customer_support") == "4111-1111-1111-1111"
    # 다른 role → 거부 (F2 = B: 요청 맥락으로 scope 조립)
    assert vault.detokenize(sid, label, "agent_l2", "customer_support") is None


# ---------------------------------------------------------------------------
# 파이프라인 배선
# ---------------------------------------------------------------------------
_BODY = json.dumps(
    {"model": "x", "messages": [{"role": "user", "content": "연락처 010-1234-5678"}]},
    ensure_ascii=False,
).encode("utf-8")


def test_pipeline_transforms_and_summarizes(monkeypatch):
    cfg = load_config()

    def fake_detect_policy(ctx: AnalysisContext) -> AnalysisContext:
        ctx.purpose = "customer_support"
        s = Span("PHONE", "010-1234-5678", 4, 17, 0.9, "regex")
        ctx.new_turn_spans = [s]
        ctx.span_actions = [(s, "mask")]
        return ctx

    monkeypatch.setattr("app.pipeline._INPUT_STAGES", [fake_detect_policy, apply_transforms])
    d = pipeline.analyze("s1", "input", "POST", "/x", {}, _BODY, config=cfg)

    assert d.action == "transform"
    assert b"010-1234-5678" not in d.transformed_body
    assert b"010-****-5678" in d.transformed_body
    assert d.reason_obj["transforms"] == [{"entity": "PHONE", "action": "mask"}]
    assert d.reason_obj["entities_summary"][0]["masked_preview"] == "010-****-5678"
