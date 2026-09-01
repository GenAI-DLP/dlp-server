"""정책 엔진 (기능 f) 테스트.

- pick_action / eval_condition : 순수 함수, DB 불필요. policy.yaml 내용을 규칙셋으로 변환해 검증.
- seed + decide : db fixture (PostgreSQL 없으면 skip).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.policy import engine
from app.policy.engine import Ruleset, _Override, _Rule, eval_condition, pick_action

_SPEC = yaml.safe_load(
    (Path(__file__).resolve().parent.parent / "app" / "policy" / "policy.yaml").read_text(
        encoding="utf-8"
    )
)

_WILDCARD = {None, "", "*"}


def _n(v):
    return None if v in _WILDCARD else v


def _ruleset_from_spec(spec: dict) -> Ruleset:
    rules = [
        _Rule(
            purpose=_n(r.get("purpose")),
            role=_n(r.get("role")),
            entity_type=_n(r.get("entity")),
            action=r["action"],
            priority=int(r.get("priority", 0)),
        )
        for r in spec.get("rules", [])
    ]
    default_action = (spec.get("defaults") or {}).get("action")
    if default_action:
        rules.append(_Rule(None, None, None, default_action, -1))
    overrides = [
        _Override(o["when"], o["action"], int(o.get("priority", 100)))
        for o in spec.get("risk_overrides", [])
    ]
    return Ruleset(rules=rules, overrides=overrides)


@pytest.fixture(autouse=True)
def _reset_engine_cache():
    engine._reset()
    yield
    engine._reset()


@pytest.fixture
def rs() -> Ruleset:
    return _ruleset_from_spec(_SPEC)


# ---------------------------------------------------------------------------
# 매트릭스 매칭 — 구체 > 와일드카드, 미매칭 시 defaults
# ---------------------------------------------------------------------------
_MATRIX = [
    ("doc_summarize", "someone", "NAME", "tokenize"),  # doc_summarize/*/* 와일드카드
    ("doc_summarize", "someone", "CARD", "block"),  # entity=CARD 가 더 구체적
    ("data_analysis", "x", "RRN", "generalize"),
    ("data_analysis", "x", "AMOUNT", "aggregate"),
    ("data_analysis", "x", "NAME", "tokenize"),  # 규칙 없음 → defaults
    ("code_help", "x", "NAME", "block"),
    ("customer_support", "agent_l1", "PHONE", "mask"),
    ("customer_support", "agent_l2", "PHONE", "tokenize"),  # role 불일치 → defaults
    ("fraud_investigation", "agent_l2", "PHONE", "keep"),
    ("unknown", "x", "RRN", "tokenize"),
    ("brand_new_purpose", None, "NAME", "tokenize"),  # 전부 미매칭 → defaults
]


@pytest.mark.parametrize(("purpose", "role", "entity", "expected"), _MATRIX)
def test_pick_action_matrix(rs, purpose, role, entity, expected):
    action = pick_action(rs, purpose, role, entity, risk_score=0.0, injection_hit=False)
    assert action == expected


def test_empty_ruleset_falls_back_to_tokenize():
    action = pick_action(Ruleset(), "x", None, "y", risk_score=0.0, injection_hit=False)
    assert action == "tokenize"


def test_priority_breaks_specificity_tie():
    rs = Ruleset(
        rules=[
            _Rule("doc_summarize", None, "PHONE", "mask", priority=1),
            _Rule("doc_summarize", None, "PHONE", "redact", priority=9),
        ]
    )
    action = pick_action(rs, "doc_summarize", None, "PHONE", risk_score=0.0, injection_hit=False)
    assert action == "redact"


# ---------------------------------------------------------------------------
# risk_override — rule 결과를 덮는다
# ---------------------------------------------------------------------------
def test_injection_override_beats_rule(rs):
    # doc_summarize/*/* 는 tokenize 지만 injection.hit → block
    action = pick_action(rs, "doc_summarize", None, "NAME", risk_score=0.0, injection_hit=True)
    assert action == "block"


def test_risk_score_override_beats_rule(rs):
    action = pick_action(rs, "doc_summarize", None, "NAME", risk_score=0.9, injection_hit=False)
    assert action == "block"


def test_no_override_below_threshold(rs):
    action = pick_action(rs, "doc_summarize", None, "NAME", risk_score=0.79, injection_hit=False)
    assert action == "tokenize"


# ---------------------------------------------------------------------------
# 조건 파서 — 화이트리스트 두 종류만, 그 외는 False (예외 없음)
# ---------------------------------------------------------------------------
def test_eval_condition_injection_hit():
    assert eval_condition("injection.hit", risk_score=0.0, injection_hit=True) is True
    assert eval_condition("injection.hit", risk_score=0.0, injection_hit=False) is False


@pytest.mark.parametrize(
    ("expr", "score", "expected"),
    [
        ("risk_score >= 0.8", 0.8, True),
        ("risk_score >= 0.8", 0.81, True),
        ("risk_score >= 0.8", 0.79, False),
        ("risk_score>=0.5", 0.5, True),
        ("risk_score >= 0", 0.0, True),
    ],
)
def test_eval_condition_risk_score(expr, score, expected):
    assert eval_condition(expr, risk_score=score, injection_hit=False) is expected


@pytest.mark.parametrize(
    "expr",
    [
        "__import__('os').system('rm -rf /')",
        "1 == 1",
        "risk_score > 0.8",  # '>' 는 미지원
        "risk_score >= 2.0",  # 0~1 범위 밖 표현 → 미매칭
        "injection.hit or True",
        "",
    ],
)
def test_eval_condition_rejects_unknown(expr):
    # 알 수 없는 조건은 예외 없이 False
    assert eval_condition(expr, risk_score=1.0, injection_hit=True) is False


# ---------------------------------------------------------------------------
# 시드 → decide (DB)
# ---------------------------------------------------------------------------
def test_seed_and_decide(db):
    from scripts.seed_policy import seed

    with db.connection() as conn:
        version_id = seed(conn, _SPEC)
    assert version_id > 0

    engine._reset()  # 캐시가 빈 규칙셋을 물고 있을 수 있음

    def act(purpose, role, entity, *, risk=0.0, inj=False):
        return engine.decide(purpose, role, entity, risk_score=risk, injection_hit=inj)

    assert act("doc_summarize", None, "CARD") == "block"
    assert act("customer_support", "agent_l1", "PHONE") == "mask"
    assert act("data_analysis", None, "RRN") == "generalize"
    assert act("unknown", None, "NAME") == "tokenize"
    assert act("doc_summarize", None, "NAME", risk=0.9) == "block"  # risk override


def test_seed_replaces_active_version(db):
    from scripts.seed_policy import seed

    with db.connection() as conn:
        v1 = seed(conn, _SPEC)
        v2 = seed(conn, _SPEC)
        active = conn.execute(
            "SELECT policy_version_id FROM policy_versions WHERE is_active"
        ).fetchall()

    assert v2 != v1
    assert active == [(v2,)]  # 활성 버전은 항상 1개
