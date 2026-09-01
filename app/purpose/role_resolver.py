"""
요청자 role 해석 (기능 f) — 헤더에서 접근 제어용 role 문자열을 뽑는다.

파이프라인이 ctx 를 만들 때 호출한다. 스테이지가 아니라 순수 함수이며,
raw 헤더를 AnalysisContext 에 싣지 않으려고 여기서 role 만 추출한다.

데모: 프록시가 사내 게이트웨이에서 확인한 role 을 X-Corp-User-Role 로 그대로 넘긴다고 본다.
없으면 X-Corp-User-Id → _ROLE_MAP 조회(자리표시), 그것도 없으면 None(정책은 role 와일드카드만 매칭).

근거: docs/architecture/dlp-server-architecture.md §6-f (role 축), §2.3 (세션 상관관계와 role)
"""

from __future__ import annotations

_ROLE_HEADER = "x-corp-user-role"
_USER_ID_HEADER = "x-corp-user-id"

# 자리표시 — 실제로는 사내 IAM 조회. 데모 시연용 고정 매핑.
_ROLE_MAP: dict[str, str] = {}


def resolve(headers: dict[str, str] | None) -> str | None:
    """헤더 → role 문자열 또는 None. 헤더 키는 대소문자 무시."""
    if not headers:
        return None
    lower = {k.lower(): v for k, v in headers.items()}

    role = (lower.get(_ROLE_HEADER) or "").strip()
    if role:
        return role

    user_id = (lower.get(_USER_ID_HEADER) or "").strip()
    if user_id and user_id in _ROLE_MAP:
        return _ROLE_MAP[user_id]

    return None
