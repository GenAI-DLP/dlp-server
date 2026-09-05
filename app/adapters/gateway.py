"""
사내 AI Gateway 어댑터 — `{"messages": [{"role", "content"}], ...}` 포맷.

v1 유일 어댑터. openai / anthropic 은 이후 단계.
"""

from __future__ import annotations

import json

from app.models import Turn


class GatewayAdapter:
    name = "gateway"

    def matches(self, path: str, headers: dict[str, str], body: bytes) -> bool:
        try:
            data = json.loads(body or b"{}")
        except (json.JSONDecodeError, ValueError):
            return False
        return isinstance(data, dict) and isinstance(data.get("messages"), list)

    def extract_turns(self, body: bytes) -> list[Turn]:
        data = json.loads(body or b"{}")
        turns: list[Turn] = []
        for msg in data.get("messages", []):
            if isinstance(msg, dict):
                turns.append(
                    Turn(role=str(msg.get("role", "user")), text=str(msg.get("content", "")))
                )
        return turns

    def rebuild(self, body: bytes, turns: list[Turn]) -> bytes:
        data = json.loads(body or b"{}")
        messages = data.get("messages", [])
        # extract_turns 와 같은 순서·개수 가정. 매칭되는 만큼만 content 교체.
        for msg, turn in zip(messages, turns, strict=False):
            if isinstance(msg, dict):
                msg["content"] = turn.text
        data["messages"] = messages
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    def parse_response(self, body: bytes) -> str:
        data = json.loads(body or b"{}")
        # 사내 Gateway 응답 포맷 — extract_turns/matches와 동일하게 messages 배열을 우선 본다.
        messages = data.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, dict):
                return str(last.get("content", ""))

        # OpenAI chat.completions 형태(다른 provider 경유 등) 하위 호환
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            return str(choices[0].get("message", {}).get("content", ""))
        if isinstance(data.get("message"), dict):
            return str(data["message"].get("content", ""))
        return ""

    def rebuild_response(self, body: bytes, text: str) -> bytes:
        data = json.loads(body or b"{}")
        messages = data.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, dict):
                last["content"] = text
                data["messages"] = messages
                return json.dumps(data, ensure_ascii=False).encode("utf-8")

        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            choices[0].setdefault("message", {})["content"] = text
            data["choices"] = choices
        elif isinstance(data.get("message"), dict):
            data["message"]["content"] = text
        return json.dumps(data, ensure_ascii=False).encode("utf-8")
