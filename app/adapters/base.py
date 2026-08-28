"""
Adapter — provider별 본문 포맷을 대화 턴 배열로 풀고 다시 조립하는 계층.

`body`(bytes) 에서 messages 를 꺼내고(`extract_turns`), 스테이지가 `turn.text` 를
바꾼 뒤 원본 구조에 되꽂는다(`rebuild`). 출력 경로는 `parse_response` / `rebuild_response`.
이 계층이 없으면 파이프라인이 raw JSON 을 평문으로 오탐한다.

근거: docs/architecture/dlp-server-architecture.md §5
"""

from __future__ import annotations

from typing import Protocol

from app.models import Turn


class Adapter(Protocol):
    name: str  # gateway | openai | anthropic

    def matches(self, path: str, headers: dict[str, str], body: bytes) -> bool:
        """이 어댑터가 처리할 본문인지 판별."""
        ...

    def extract_turns(self, body: bytes) -> list[Turn]:
        """요청 본문 → 대화 턴 배열."""
        ...

    def rebuild(self, body: bytes, turns: list[Turn]) -> bytes:
        """원본 본문 구조에 (갱신된) turns 를 되꽂아 직렬화.

        turns 의 순서·개수는 같은 어댑터의 `extract_turns` 결과와 동일하다고 가정한다.
        """
        ...

    def parse_response(self, body: bytes) -> str:
        """응답 본문 → assistant 텍스트 (SSE 조각이면 합쳐서)."""
        ...

    def rebuild_response(self, body: bytes, text: str) -> bytes:
        """원본 응답 구조에 (갱신된) text 를 되꽂아 직렬화."""
        ...
