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

> `make` 단축키는 아래 [make 단축키](#make-단축키) 절 참고. Windows(conda)는 명령을 직접 실행.

## DB (PostgreSQL)

볼트·정책·감사 계층은 PostgreSQL 을 쓴다. 서버는 DB 없이도 뜨지만 `/health` 의 `db` 가 `down` 이
되고 `tests/test_db.py` 는 skip 된다. `dlp`(개발용) · `dlp_test`(pytest용) 두 DB 를 쓴다.

### 빠른 시작 — Docker

```bash
# 1) DB 컨테이너 (dlp 유저=슈퍼유저 → pgcrypto 확장 OK)
docker run -d --name dlp-pg \
  -e POSTGRES_USER=dlp -e POSTGRES_PASSWORD=dlp -e POSTGRES_DB=dlp \
  -p 5432:5432 postgres:16

# 2) 테스트 DB 추가
docker exec dlp-pg createdb -U dlp dlp_test

# 3) 스키마 적용 (양쪽)
python scripts/apply_schema.py
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test python scripts/apply_schema.py
```

3번 각각 `[apply_schema] 적용 완료: dlp` / `... dlp_test` 가 나오면 성공.

컨테이너 재시작: `docker start dlp-pg` / 정지: `docker stop dlp-pg` / 삭제: `docker rm -f dlp-pg`

### 확인

```bash
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test pytest -q
```

`28 passed` (기존 23 + `test_db.py` 5), skip 0 이면 정상.
서버 `/health` 로도 확인 가능 → [실행](#실행) 절.

### 로컬에 PostgreSQL 이 이미 있으면

컨테이너 대신, 관리자 계정으로 역할·DB 만 만들고 위 "3) 스키마 적용" 부터:

```bash
psql -U postgres -c "CREATE ROLE dlp SUPERUSER LOGIN PASSWORD 'dlp';"
psql -U postgres -c "CREATE DATABASE dlp      OWNER dlp;"
psql -U postgres -c "CREATE DATABASE dlp_test OWNER dlp;"
```

`SUPERUSER` 는 스키마의 `CREATE EXTENSION pgcrypto` 때문 — 로컬 개발용.

### 참고

- `apply_schema.py` 기본 동작 = `DROP SCHEMA public CASCADE` 후 재적용. `--keep`(DROP 생략) /
  `--force`(DB 이름이 `dlp`·`dlp_test` 아닐 때 강제).
- DSN 오버라이드: 환경변수 `DLP_DB__DSN` (중첩 필드라 밑줄 2개) 또는 repo 루트 `.env`
  (`.env.example` 복사). PowerShell 은 `$env:DLP_DB__DSN = "..."`.
- `db/schema.sql` 은 `docs` 레포 `schemas/dlp-server/postgres-schema.sql` 의 복사본 (SSOT 는 docs).
  스키마가 바뀌면 그 내용으로 교체 후 다시 적용.

## 실행

```bash
python -m app.main
```

- gRPC 서버: `0.0.0.0:50051` — `DLPInspector.Inspect` (unary)
- FastAPI:   `0.0.0.0:8000` — `GET /health`

동작 확인:

```bash
curl http://localhost:8000/health      # {"status":"ok","db":"ok"}  ("db":"down" → DB 미기동/스키마 미적용)
```

## 설정

우선순위: **환경변수(`DLP_*`) / `.env` > [`app/config.yaml`](app/config.yaml) > 코드 기본값.**
`.env` 는 repo 루트에 두며 (`.env.example` 참고, `.gitignore` 됨) 환경변수와 같은 이름을 쓴다.
중첩 필드는 이중 밑줄: `DLP_DB__DSN` → `db.dsn`, `DLP_GRPC__PORT` → `grpc.port`.

| 환경변수 / .env 키 | 의미 |
|---|---|
| `DLP_DB__DSN` | PostgreSQL 접속 문자열 (기본 `postgresql://dlp:dlp@localhost:5432/dlp`) |
| `DLP_FAIL_ACTION` | `block`(기본) \| `allow` — 내부 예외 시 반환할 판정 (시연 안정용) |
| `DLP_GRPC__PORT` | gRPC 포트 (기본 `50051`) |
| `DLP_LOG_PATH` | 감사 로그 JSONL 경로 |
| `DLP_CONFIG` | 설정 파일(yaml) 경로 |

## 테스트

```bash
pytest -q
```

`tests/test_db.py` 는 PostgreSQL 이 붙어 있을 때만 돈다 (없으면 skip). DB 포함해 돌리려면:

```bash
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test pytest -q
```

## make 단축키

`make` 가 있으면 (macOS/Linux, 또는 Windows에 별도 설치한 경우):

| 명령 | 실행 내용 |
|---|---|
| `make install` | `pip install -r requirements.txt` |
| `make proto` | `python scripts/gen_proto.py` |
| `make db-apply` | `python scripts/apply_schema.py` (`db/schema.sql` 적용, DSN 은 `DLP_DB__DSN`) |
| `make run` | `python -m app.main` (gRPC :50051 + FastAPI :8000) |
| `make test` | `pytest -q` |
| `make lint` | `ruff check .` |
| `make fmt` | `ruff format .` |

`make` 가 없으면 오른쪽 명령을 직접 실행하면 된다.

## 구조 (요약)

모듈 경계·책임은 [`docs/architecture/dlp-server-architecture.md`](../docs/architecture/dlp-server-architecture.md) §3.

| 경로 | 역할 |
|---|---|
| `app/pipeline.py` | 유일 판정 진입점 `analyze()`. gRPC / HTTP / eval 이 공유 |
| `app/models.py` | 계약 타입 (`Turn` / `Span` / `AnalysisContext` / `Decision`) |
| `app/config.py`, `config.yaml` | 런타임 설정 |
| `app/db.py` | PostgreSQL 커넥션 풀 (psycopg3). 볼트·정책·감사가 공유 |
| `app/grpc_server.py`, `app/api.py`, `app/main.py` | transport 어댑터 + 부트스트랩 |
| `app/adapters/` | 본문 형식 파서 (gateway / openai / anthropic) |
| `app/{detect,guardrail,context,purpose,policy,transform}/` | 기능 a~h (구현 예정) |
| `app/proto/` | protoc 생성물 (VCS 미포함) |
| `db/schema.sql` | PostgreSQL 스키마 (docs SSOT 의 복사본). `scripts/apply_schema.py` 로 적용 |
| `eval/`, `tests/` | 성능 평가 / 단위·통합 테스트 |
