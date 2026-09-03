"""세션 식별자 정규화 — 저장 계층(감사 로그·토큰 볼트) 공용.

wire ``session_id`` 는 자유 문자열(헤더/쿠키/원격주소)인데 ``log_events`` /
``token_vault`` 의 ``session_id`` 컬럼은 ``UUID`` 라, 경계에서 결정론적 UUID 로
바꾼다. UUID 꼴이면 그대로 통과 → 세션 스토어(기능 e)가 session_id 를 UUID 로
확정하면 no-op 이 된다. 원본 문자열은 호출부에서 보존한다(감사 로그는
``reason.session_id_raw``).

같은 wire id 가 감사·볼트에서 같은 UUID 로 사상돼야 두 테이블을 대조(JOIN)할 수
있으므로, 이 함수를 두 곳이 공유한다.
"""

from __future__ import annotations

import uuid

# 비 UUID session_id 를 uuid5 로 사상할 때 쓰는 네임스페이스 (RFC 4122 URL).
_SESSION_NS = uuid.NAMESPACE_URL


def coerce_session_uuid(session_id: str) -> uuid.UUID:
    """UUID 꼴이면 그대로, 아니면 ``uuid5(_SESSION_NS, session_id)``. 같은 입력 → 같은 UUID."""
    try:
        return uuid.UUID(str(session_id))
    except (ValueError, AttributeError, TypeError):
        return uuid.uuid5(_SESSION_NS, str(session_id))
