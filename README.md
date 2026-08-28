# dlp-server

생성형 AI Dynamic DLP Gateway 의 **의미 기반 검사 백엔드** (FastAPI + gRPC).
Go 프록시(`dlp-proxy-server`)가 gRPC 로 판정을 요청하면 `pipeline.analyze()` 가
`allow` / `block` / `transform` 을 돌려준다. 외부 LLM 은 직접 호출하지 않는다.

- 전체 설계: [`docs/architecture/dlp-server-architecture.md`](../docs/architecture/dlp-server-architecture.md)
- gRPC 계약: [`docs/architecture/dlp-proto.md`](../docs/architecture/dlp-proto.md) — 임의 변경 금지

---

## 요구사항

- Python 3.11+
- gRPC 계약(`proto/dlp.proto`)은 git submodule (`GenAI-DLP/dlp-proto`)

## 셋업

```bash
# 1. proto 계약 가져오기 (proto/dlp.proto)
git submodule update --init

# 2. 의존성 설치
pip install -r requirements.txt

# 3. protoc 생성물 만들기 (app/proto/dlp_pb2*.py — VCS 미포함, 로컬에서 생성)
python scripts/gen_proto.py
```

`scripts/gen_proto.py` 는 `grpc_tools.protoc` 로 `dlp_pb2.py` / `dlp_pb2_grpc.py` 를 만들고,
gRPC 스텁의 import 경로를 `app.proto` 패키지 기준으로 보정한다. `proto/dlp.proto` 가 바뀌면 다시 실행.

> macOS/Linux 는 `make proto` / `make install` / `make test` 단축키 사용 가능.
> Windows(conda)는 위 명령을 직접 실행.

## 실행

```bash
python -m app.main
```

- gRPC 서버: `0.0.0.0:50051` — `DLPInspector.Inspect` (unary)
- FastAPI:   `0.0.0.0:8000` — `GET /health`

동작 확인:

```bash
curl http://localhost:8000/health      # {"status":"ok"}
```

## 설정

기본값은 [`app/config.yaml`](app/config.yaml) (경로는 `DLP_CONFIG` 로 변경). 자주 쓰는 값은 환경변수 오버라이드:

| 환경변수 | 의미 |
|---|---|
| `DLP_FAIL_ACTION` | `block`(기본) \| `allow` — 내부 예외 시 반환할 판정 (시연 안정용) |
| `DLP_GRPC_PORT` | gRPC 포트 (기본 `50051`) |
| `DLP_CONFIG` | 설정 파일 경로 |

## 테스트

```bash
pytest -q
```

## 구조 (요약)

모듈 경계·책임은 [`docs/architecture/dlp-server-architecture.md`](../docs/architecture/dlp-server-architecture.md) §3.

| 경로 | 역할 |
|---|---|
| `app/pipeline.py` | 유일 판정 진입점 `analyze()`. gRPC / HTTP / eval 이 공유 |
| `app/models.py` | 계약 타입 (`Turn` / `Span` / `AnalysisContext` / `Decision`) |
| `app/config.py`, `config.yaml` | 런타임 설정 |
| `app/grpc_server.py`, `app/api.py`, `app/main.py` | transport 어댑터 + 부트스트랩 |
| `app/adapters/` | 본문 형식 파서 (gateway / openai / anthropic) |
| `app/{detect,guardrail,context,purpose,policy,transform}/` | 기능 a~h (구현 예정) |
| `app/proto/` | protoc 생성물 (VCS 미포함) |
| `eval/`, `tests/` | 성능 평가 / 단위·통합 테스트 |
