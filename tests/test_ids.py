"""tests/test_ids.py — ids.coerce_session_uuid 단위 테스트."""

from __future__ import annotations

import uuid

from app.ids import coerce_session_uuid


def test_uuid_string_passthrough():
    sid = "11111111-1111-1111-1111-111111111111"
    assert coerce_session_uuid(sid) == uuid.UUID(sid)


def test_non_uuid_is_deterministic():
    a = coerce_session_uuid("s1")
    b = coerce_session_uuid("s1")
    assert a == b
    assert isinstance(a, uuid.UUID)


def test_distinct_inputs_distinct_uuids():
    seen = {
        coerce_session_uuid(v) for v in ("s1", "s2", "10.1.2.3:52344", "alice@corp", "sess_abc123")
    }
    assert len(seen) == 5


def test_return_type_is_uuid():
    assert isinstance(coerce_session_uuid("10.1.2.3:52344"), uuid.UUID)
