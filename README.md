# dlp-server

생성형 AI Dynamic DLP Gateway 의 **의미 기반 검사 백엔드** (FastAPI + gRPC).
Go 프록시(`dlp-proxy-server`)가 gRPC 로 판정을 요청하면 `pipeline.analyze()` 가
`allow` / `block` / `transform` 을 돌려준다. 외부 LLM 은 직접 호출하지 않는다.

- 전체 설계: [`docs/architecture/dlp-server-architecture.md`](../docs/architecture/dlp-server-architecture.md)
- gRPC 계약: [`docs/architecture/dlp-proto.md`](../docs/architecture/dlp-proto.md) — 임의 변경 금지

---

## 요구사항

- Python 3.11+
- PostgreSQL 16 — 볼트·정책·감사 계층 ([DB (PostgreSQL)](#db-postgresql) 절)
- gRPC 계약(`proto/dlp.proto`)은 git submodule (`GenAI-DLP/dlp-proto`)

## 셋업

### 1. `.env` 세팅

**`DLP_VAULT__KEY` 는 채워야 한다** — 가역적 토큰화가 이 키로
`token_vault.cipher_value` 를 AES-GCM 암·복호하며, 없으면 토큰 경로에서 에러가 난다.

base64 32바이트 키 생성:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

나머지 키(`DLP_DB__DSN` 등)는 기본값이 있어 로컬에선 그대로 둬도 된다. 전체 목록은
[설정](#설정) 절 참고.

### 2. 의존성 · proto

```bash
# (권장) 가상환경
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate

git submodule update --init          # proto/dlp.proto 가져오기
pip install -r requirements.txt
python scripts/gen_proto.py          # app/proto/dlp_pb2*.py (VCS 미포함, 로컬 생성)
```

`scripts/gen_proto.py` 는 `grpc_tools.protoc` 로 `dlp_pb2.py` / `dlp_pb2_grpc.py` 를 만들고,
gRPC 스텁의 import 경로를 `app.proto` 패키지 기준으로 보정한다. `proto/dlp.proto` 가 바뀌면 다시 실행.

### 3. pre-commit 설정

`pre-commit` 패키지가 설치된 후(위 `pip install -r requirements.txt` 에 포함) Git hook 을 등록한다:

```bash
pre-commit install
```

최초 1회만 하면 되고, `.git/hooks/pre-commit` 에 훅이 등록된다. 이후 커밋할 때마다
`.pre-commit-config.yaml` 에 정의된 Ruff lint + format 이 자동으로 실행된다

커밋 시 자동으로 실행되지만, 수동으로도 실행할 수 있다.

자동 수정:

```bash
ruff check . --fix
ruff format .
```

검사만:

```bash
ruff check .
ruff format --check .
```

### 4. DB

아래 [DB (PostgreSQL)](#db-postgresql) 절을 따라 컨테이너 기동 + 스키마 적용.

> `make` 단축키는 아래 [make 단축키](#make-단축키) 절 참고. Windows(conda)는 명령을 직접 실행.

## DB (PostgreSQL)

볼트·정책·감사 계층은 PostgreSQL 을 쓴다. 
서버는 DB 없이도 뜨지만 `/health` 의 `db` 가 `down` 이 되고 DB 의존 테스트(`test_db.py` · `test_vault.py`)는 skip 된다. 
`dlp`(개발용) · `dlp_test`(pytest용) 두 DB 를 쓴다.

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

# 4) 정책 시드 (기능 f — app/policy/policy.yaml → policy_* 테이블)
python scripts/seed_policy.py
```

3번 각각 `[apply_schema] 적용 완료: dlp` / `... dlp_test`, 4번 `[seed_policy] 버전 1 활성화 …`
가 나오면 성공. 스키마를 다시 적용하면 정책도 날아가니 `seed_policy.py` 를 다시 실행한다
(`--reset` 으로 재적재). pytest 는 시드 없이도 된다(테스트가 자체 시드).

컨테이너 재시작: `docker start dlp-pg` / 정지: `docker stop dlp-pg` / 삭제: `docker rm -f dlp-pg`

### 확인

```bash
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test pytest -q
```

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
| `DLP_VAULT__KEY` | 볼트 `cipher_value` AES-GCM 키 — base64 32바이트. 가역적 토큰화(기능 a) 필수, 미설정 시 토큰 암·복호에서 에러 |
| `DLP_FAIL_ACTION` | `block`(기본) \| `allow` — 내부 예외 시 반환할 판정 (시연 안정용) |
| `DLP_GUARDRAIL__INJECTION_THRESHOLD` | Input Guard(기능 c 입력) hit 판정 임계 0~1 (기본 `0.7`). 매칭된 규칙 score 가 이 값 이상이면 `block` |
| `DLP_GRPC__PORT` | gRPC 포트 (기본 `50051`) |
| `DLP_LOG_SINK` | 감사 로그 sink — `pg`(기본) \| `jsonl` \| `both`. `pg` 실패 시 JSONL 로 폴백 |
| `DLP_LOG_PATH` | JSONL sink / PG 폴백 파일 경로 |
| `DLP_CONFIG` | 설정 파일(yaml) 경로 |

## 테스트

```bash
pytest -q
```

`tests/test_db.py` · `tests/test_vault.py` 와 `tests/test_events.py` 의 PG sink 테스트는
PostgreSQL 이 붙어 있을 때만 돈다 (없으면 skip). 그 외 테스트는 `DLP_LOG_SINK=jsonl` 로 돈다.

DB 포함해 돌리려면:

```bash
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test pytest -q
```

`test_vault.py` 는 볼트 키를 테스트 안에서 주입하므로 `DLP_VAULT__KEY` 없이도 돈다.

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
| `app/logging/events.py` | 감사 로그 sink — `log_events` INSERT, 실패 시 JSONL 폴백. 원문 무저장 |
| `app/ids.py` | wire `session_id` → UUID 정규화 (저장 계층 공용) |
| `app/grpc_server.py`, `app/api.py`, `app/main.py` | transport 어댑터 + 부트스트랩 |
| `app/adapters/` | 본문 형식 파서 (gateway / openai / anthropic) |
| `app/transform/vault.py` | 가역적 토큰화 (기능 a) — `token_vault` 레포지토리 + AES-GCM + 복원 인가 |
| `app/guardrail/injection.py` | Input Guard (기능 c 입력) — 프롬프트 인젝션·탈옥·반출 규칙 탐지, 적중 시 조기 `block` |
| `app/purpose/`, `app/policy/` | 목적 기반 접근 제어 (기능 f) — 목적 분류 + role 해석 + `(목적×role×엔티티)→조치` 정책 엔진. 입력 [5] 스테이지 |
| `app/detect/` | 하이브리드 PII 탐지 (기능 b) — regex/사전/병합 레이어 (파이프라인 배선은 예정) |
| `app/{context}/`, `guardrail/output_check.py`, `transform/apply.py` | 기능 c(출력) · e · g · h (구현 예정) |
| `app/proto/` | protoc 생성물 (VCS 미포함) |
| `db/schema.sql` | PostgreSQL 스키마 (docs SSOT 의 복사본). `scripts/apply_schema.py` 로 적용 |
| `eval/`, `tests/` | 성능 평가 / 단위·통합 테스트 |
