"""
transform/vault.py::_session_uuid() 검증 — token_vault.session_id UUID 타입 불일치 수정.

DB 연결 없이 순수 함수만 테스트한다 (tokenize/detokenize 자체는 실제 DB가 필요해
이 테스트 범위 밖).
"""

import uuid

from app.transform.vault import _session_uuid


def test_session_uuid_is_deterministic():
    """같은 session_id 문자열은 항상 같은 UUID 로 매핑되어야 한다 (조회/삽입 일관성)."""
    sid = "arbitrary-session-id-from-proxy-header"
    assert _session_uuid(sid) == _session_uuid(sid)


def test_session_uuid_produces_valid_uuid_format():
    """반환값이 실제로 유효한 UUID 문자열 형식이어야 DB 의 UUID 컬럼에 들어간다."""
    result = _session_uuid("sess-abc-123")
    parsed = uuid.UUID(result)  # 파싱 실패하면 여기서 ValueError
    assert str(parsed) == result


def test_different_session_ids_map_to_different_uuids():
    """서로 다른 session_id 는 (사실상) 서로 다른 UUID 로 매핑되어야 한다."""
    a = _session_uuid("session-a")
    b = _session_uuid("session-b")
    assert a != b


def test_session_uuid_handles_non_uuid_shaped_strings():
    """프록시가 뽑아내는 임의 문자열(UUID 형식이 전혀 아닌 것) 도 에러 없이 처리돼야 한다."""
    weird_ids = ["", "192.168.0.1", "user@example.com", "🙂-session", "a" * 500]
    for sid in weird_ids:
        result = _session_uuid(sid)
        uuid.UUID(result)  # 파싱 가능해야 함 — 실패하면 여기서 예외