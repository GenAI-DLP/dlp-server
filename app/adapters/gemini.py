"""
Gemini 공식 API 어댑터 — {"contents":[{role, parts:[{text}]}], "system_instruction":{...}}
요청 포맷과 {"candidates":[{content:{parts:[{text}]}}]} 응답 포맷.

역할 분담(Turn.role): Gemini 는 user/model 두 role 만 쓰고 system 은
별도 system_instruction 필드다. 내부적으로는 다른 어댑터(gateway)와
동일하게 Turn(role=user|assistant|system) 로 통일한다:
  model  -> assistant
  system_instruction -> role="system" 인 Turn 하나로 변환, contents 맨 앞에 둠

matches() 는 request 형태(contents)와 response 형태(candidates) 둘 다
인식해야 한다 — pipeline.py 가 input/output 양쪽에서 동일한
select_adapter(path, headers, body) 를 호출하기 때문 (gateway.py 는
입출력 모두 {"messages":[...]} 형태라 이 구분이 필요 없었지만, Gemini는
요청/응답 스키마 자체가 다르다).

멀티파트(parts 여러 개)는 다루지 않는다 — Relay(gemini_client.py)가
항상 parts 길이 1로만 보내고, 우리가 만드는 응답도 parts 길이 1로
합쳐서 돌려준다. 실제 Gemini 응답이 여러 parts 로 쪼개져 오면
parse_response 에서 전부 이어붙이되, rebuild_response 는 단일 부분으로
교체한다 (원본 구조 보존보다 안전한 텍스트 치환을 우선).
"""

from __future__ import annotations

import json

from app.models import Turn

_ROLE_TO_INTERNAL = {"model": "assistant"}


class GeminiAdapter:
    name = "gemini"

    def matches(self, path: str, headers: dict[str, str], body: bytes) -> bool:
        try:
            data = json.loads(body or b"{}")
        except (json.JSONDecodeError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        # 요청(input) 형태
        if isinstance(data.get("contents"), list):
            return True
        # 응답(output) 형태
        if isinstance(data.get("candidates"), list):
            return True
        return False

    def extract_turns(self, body: bytes) -> list[Turn]:
        data = json.loads(body or b"{}")
        turns: list[Turn] = []

        system_instruction = data.get("system_instruction")
        if isinstance(system_instruction, dict):
            parts = system_instruction.get("parts", [])
            text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
            if text:
                turns.append(Turn(role="system", text=text))

        for item in data.get("contents", []):
            if not isinstance(item, dict):
                continue
            role = _ROLE_TO_INTERNAL.get(item.get("role"), item.get("role", "user"))
            parts = item.get("parts", [])
            text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
            turns.append(Turn(role=str(role), text=text))

        return turns

    def rebuild(self, body: bytes, turns: list[Turn]) -> bytes:
        data = json.loads(body or b"{}")

        remaining = list(turns)
        has_system = isinstance(data.get("system_instruction"), dict)
        if has_system and remaining and remaining[0].role == "system":
            sys_turn = remaining.pop(0)
            data["system_instruction"] = {"parts": [{"text": sys_turn.text}]}

        contents = data.get("contents", [])
        # extract_turns 와 같은 순서·개수 가정 (system 제외 나머지가 1:1 대응).
        for item, turn in zip(contents, remaining, strict=False):
            if isinstance(item, dict):
                item["parts"] = [{"text": turn.text}]
        data["contents"] = contents

        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    def parse_response(self, body: bytes) -> str:
        data = json.loads(body or b"{}")
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            return ""
        first = candidates[0]
        if not isinstance(first, dict):
            return ""
        content = first.get("content", {})
        if not isinstance(content, dict):
            return ""
        parts = content.get("parts", [])
        return "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))

    def rebuild_response(self, body: bytes, text: str) -> bytes:
        data = json.loads(body or b"{}")
        candidates = data.get("candidates")
        if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict):
            candidates[0].setdefault("content", {})["parts"] = [{"text": text}]
            data["candidates"] = candidates
        return json.dumps(data, ensure_ascii=False).encode("utf-8")
