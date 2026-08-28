"""gateway 어댑터 왕복 테스트."""

from __future__ import annotations

import json

from app.adapters import select_adapter
from app.adapters.gateway import GatewayAdapter
from app.models import Turn

_BODY = json.dumps(
    {
        "model": "gpt-x",
        "messages": [
            {"role": "system", "content": "너는 도우미"},
            {"role": "user", "content": "홍길동 주민번호 880101-1234567"},
        ],
        "temperature": 0.7,
    },
    ensure_ascii=False,
).encode("utf-8")


def test_select_adapter_gateway():
    assert select_adapter(body=_BODY).name == "gateway"


def test_extract_turns():
    turns = GatewayAdapter().extract_turns(_BODY)
    assert [t.role for t in turns] == ["system", "user"]
    assert turns[1].text == "홍길동 주민번호 880101-1234567"


def test_roundtrip_identity():
    a = GatewayAdapter()
    turns = a.extract_turns(_BODY)
    rebuilt = a.rebuild(_BODY, turns)
    assert json.loads(rebuilt)["temperature"] == 0.7  # 기타 키 보존
    assert a.extract_turns(rebuilt) == turns


def test_rebuild_replaces_only_changed_turn():
    a = GatewayAdapter()
    turns = a.extract_turns(_BODY)
    turns[1] = Turn(role="user", text="홍길동 주민번호 <PII:RRN:1>")
    msgs = json.loads(a.rebuild(_BODY, turns))["messages"]
    assert msgs[0]["content"] == "너는 도우미"
    assert msgs[1]["content"] == "홍길동 주민번호 <PII:RRN:1>"


def test_response_roundtrip():
    a = GatewayAdapter()
    resp = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": "안녕하세요"}}]}
    ).encode("utf-8")
    assert a.parse_response(resp) == "안녕하세요"
    assert a.parse_response(a.rebuild_response(resp, "복원된 텍스트")) == "복원된 텍스트"
