"""어댑터 레지스트리 + 선택."""

from __future__ import annotations

from app.adapters.base import Adapter
from app.adapters.gateway import GatewayAdapter
from app.adapters.gemini import GeminiAdapter

_GATEWAY = GatewayAdapter()
_GEMINI = GeminiAdapter()
_ADAPTERS: list[Adapter] = [_GEMINI, _GATEWAY]


def select_adapter(
    path: str = "",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> Adapter:
    """본문·경로·헤더로 어댑터 선택. 미매칭 시 gateway 로 폴백."""
    headers = headers or {}
    for adapter in _ADAPTERS:
        if adapter.matches(path, headers, body):
            return adapter
    return _GATEWAY


__all__ = ["Adapter", "GatewayAdapter", "GeminiAdapter", "select_adapter"]
