"""
scripts/test_grpc_client.py (임시 스크립트) — 로컬에 띄운 dlp-server 에
gRPC 요청 하나를 진짜로 보내서 판정 결과를 눈으로 확인한다.

사용 전제:
    - python -m app.main 으로 서버가 이미 떠있어야 함 (gRPC :50051)
    - proto 코드 생성이 끝나 있어야 함 (python scripts/gen_proto.py)

실행:
    python scripts/test_grpc_client.py

필드명이 실제 dlp.proto 와 다르면 AttributeError 가 날 수 있는데, 그때는
에러 메시지에 나온 실제 필드명으로 맞춰서 고치면 된다.
"""

from __future__ import annotations

import json
import uuid

import grpc

from app.proto import dlp_pb2, dlp_pb2_grpc


def build_request() -> dlp_pb2.InspectRequest:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "고객 김민준님 연락처는 010-1234-5678 이고, "
                        "카드번호 4111-1111-1111-1111 로 결제 부탁드립니다."
                    ),
                }
            ]
        }
    ).encode("utf-8")

    return dlp_pb2.InspectRequest(
        session_id=str(uuid.uuid4()),  # token_vault.session_id 가 uuid 타입이라 형식 맞춰야 함
        direction="input",
        method="POST",
        path="/v1/chat",
        headers={},  # 실제 헤더 필드가 map<string,string> 이 아니면 여기서 에러날 수 있음
        body=body,
    )


def main() -> None:
    channel = grpc.insecure_channel("localhost:50051")
    stub = dlp_pb2_grpc.DLPInspectorStub(channel)

    request = build_request()
    print("--- 요청 본문 ---")
    print(request.body.decode("utf-8"))
    print()

    try:
        verdict = stub.Inspect(request, timeout=5.0)
    except grpc.RpcError as e:
        print(f"gRPC 호출 실패: {e.code()} — {e.details()}")
        return

    print("--- 판정 결과 ---")
    print("action:", verdict.action)
    if verdict.transformed_body:
        print("transformed_body:", verdict.transformed_body.decode("utf-8"))
    if verdict.reason:
        try:
            reason = json.loads(verdict.reason)
            print("reason:", json.dumps(reason, ensure_ascii=False, indent=2))
        except (json.JSONDecodeError, TypeError):
            print("reason (raw):", verdict.reason)


if __name__ == "__main__":
    main()
