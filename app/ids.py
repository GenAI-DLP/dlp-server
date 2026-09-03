"""세션 식별자 정규화.

wire ``session_id`` 는 자유 문자열(헤더/쿠키/원격주소)인데 저장 계층 컬럼은 ``UUID`` 라
경계에서 결정론적 UUID 로 바꾼다. UUID 꼴이면 그대로 통과 → 세션 스토어(기능 e)가
session_id 를 UUID 로 확정하면 no-op 이 된다. 원본은 호출부에서 보존한다.
"""

from __future__ import annotations

import uuid

# 비 UUID session_id 를 uuid5 로 사상할 때 쓰는 프로젝트 네임스페이스.
_DLP_NS = uuid.UUID("8fbfc305-008a-47e0-9d6b-58326755b731")


def coerce_session_uuid(session_id: str) -> uuid.UUID:
    """UUID 꼴이면 그대로, 아니면 ``uuid5(_DLP_NS, session_id)``. 같은 입력 → 같은 UUID."""
    try:
        return uuid.UUID(str(session_id))
    except (ValueError, AttributeError, TypeError):
        return uuid.uuid5(_DLP_NS, str(session_id))
