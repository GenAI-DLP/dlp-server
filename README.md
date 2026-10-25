# 🧠 DLP Main Server

생성형 AI DLP Gateway의 **의미 기반 검사 엔진** (Python · FastAPI · gRPC · PostgreSQL)

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![gRPC](https://img.shields.io/badge/gRPC-244c5a?style=flat-square&logo=google&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![GLiNER](https://img.shields.io/badge/NER-GLiNER-FF6F00?style=flat-square)

기존 DLP는 "이 요청에 주민번호 패턴이 있는가"만 보고 무조건 차단합니다. 그래서 개인정보를 **여러 턴에 나눠 입력**하거나, **우회 표현**을 쓰거나, AI에게 **조합·재구성**을 시키면 쉽게 뚫리고, 반대로 정상 업무까지 막아버립니다.

dlp-server는 여기서 한 단계 더 나아가 다음 세 가지를 판단합니다.

1. **무엇이 들어 있는가** — 정규식 + 사전 + NER 하이브리드 탐지
2. **대화에 무엇이 쌓이고 있는가** — 세션 단위 엔티티 누적과 조합 위험도
3. **사용자가 AI로 무엇을 하려는가** — 업무 목적 × 직무(role) 기반 정책

그리고 발견 즉시 차단하는 대신, **업무에 필요한 최소한의 정보만 남도록 데이터를 동적으로 변환**합니다. 토큰화한 값은 응답이 돌아올 때 권한이 있는 사람에게만 원본으로 복원됩니다.


## 🗺️ 시스템 내 위치

```
[직원 PC] ──TLS──▶ [dlp-proxy-server (Go)] ──gRPC Inspect(input)──▶ [dlp-server]  ◀── 이 레포
                          │                ◀────── Verdict ──────────┘
                          ▼
                   [외부 LLM (Gemini 등)]
                          │
                          ▼
                   [dlp-proxy-server] ──gRPC Inspect(output)──▶ [dlp-server]
                          │                ◀────── Verdict ──────────┘
                          ▼
                     [직원 PC]                [dashboard] ◀── /events · /stats · SSE
```

- 프록시(또는 [gateway](https://github.com/GenAI-DLP/gateway) Relay)가 트래픽을 Hold한 채 `Inspect`를 호출하면, dlp-server는 `allow` / `block` / `transform` 중 하나를 돌려줍니다.
- dlp-server는 **외부 LLM을 직접 호출하지 않습니다.** 판단만 하고, 중계는 프록시가 합니다.
- gRPC 계약은 [dlp-proto](https://github.com/GenAI-DLP/dlp-proto) 서브모듈로 프록시와 공유합니다.

---

## ✨ 구현한 기능

### 요청(input) 파이프라인

```
본문 어댑터 → [Input Guard] → [하이브리드 PII 탐지] → [멀티턴 누적] → [목적 분석 + 정책] → [동적 변환 + 토큰화] → 본문 재조립
```

### 응답(output) 파이프라인

```
본문 어댑터 → [Output Guard: 재스캔·인젝션 순응] → [detokenize: 인가된 경우만 복원] → 본문 재조립
```

모든 스테이지는 `AnalysisContext`를 받아 갱신하고 돌려주는 동일한 시그니처(`Stage = Callable[[AnalysisContext], AnalysisContext]`)를 가집니다. 차단은 예외가 아니라 `ctx.blocked`로 표현하므로, 새 기능을 스테이지 하나로 끼워 넣을 수 있습니다.

| 기능 | 모듈 | 내용 |
|---|---|---|
| **a. 가역적 토큰화** | `transform/vault.py` | 같은 세션의 같은 값은 항상 같은 토큰(`<PII:RRN:1>`)으로 치환. 원본은 **AES-GCM**으로 암호화해 PostgreSQL `token_vault`에 저장. 복원 시 role·목적 기반 **접근 범위(access scope)** 검사, 모든 복원 시도를 `token_vault_access_log`에 기록. TTL 만료 시 soft revoke → 유예 후 파기 |
| **b. 하이브리드 PII 탐지** | `detect/` | ① 정규식 + 체크섬(주민번호 mod-11, 카드 Luhn, 사업자번호 검증, 전화, 이메일, 계좌 문맥 가중) ② Aho-Corasick 사전(직원명·VIP·내부 용어) ③ **GLiNER 제로샷 NER**(이름·주소·조직·내부 프로젝트명·연체/대출잔액/신용등급). `merge.py`가 정규식 > 사전 > NER 우선순위로 겹치는 span을 병합 |
| **c. 양방향 가드레일** | `guardrail/` | **Input Guard**: 한/영 프롬프트 인젝션·탈옥·반출 요청을 구(句) 단위 규칙으로 탐지, 적중 시 파이프라인 초입에서 즉시 block. **Output Guard**: 모델이 새로 만든 PII 재스캔·재마스킹, 시스템 프롬프트 노출 등 인젝션 순응 탐지 |
| **e. 멀티턴 문맥 분석** | `context/` | 세션별로 엔티티를 **값 해시로만** 누적(평문 미보관). 엔티티 그래프 + 슬라이딩 윈도우(최근 5턴), 조합 가중(예: 주민번호+계좌 0.20 → +전화 0.35), 반복 언급·입력 속도 신호를 합산. 누적 위험도가 임계값을 넘으면 block |
| **f. 목적 기반 접근 제어** | `purpose/`, `policy/` | 마지막 사용자 턴에서 업무 목적 분류(고객 응대·문서 요약·코딩·데이터 분석·이상거래 조사·unknown). `X-Corp-User-Role` 헤더로 role 해석. **(목적 × role × 엔티티 타입) → 조치** 를 엔티티 단위로 결정하는 ABAC 정책 엔진. 정책은 PostgreSQL에 **버전 관리** |
| **g. 동적 데이터 변환** | `transform/apply.py` | `keep` / `mask` / `generalize` / `aggregate` / `tokenize` / `synthetic` / `redact` / `block` 8가지 전략. 같은 주민번호라도 문서 요약이면 토큰화, 데이터 분석이면 `<AGE:30대><SEX:여>`로 일반화, 코딩 지원이면 차단 |
| **감사 로그 · 대시보드 API** | `logging/`, `api.py` | 모든 판정을 `log_events`에 기록(**원문 없이 마스킹 미리보기만**). 대시보드용 조회·집계 API와 **SSE 실시간 스트림** 제공 |

### 정책 예시 (`app/policy/policy.yaml`)

```yaml
rules:
  - {purpose: doc_summarize,       role: "*",      entity: "*",    action: tokenize}
  - {purpose: doc_summarize,       role: "*",      entity: CARD,   action: block}
  - {purpose: data_analysis,       role: "*",      entity: RRN,    action: generalize}
  - {purpose: data_analysis,       role: "*",      entity: AMOUNT, action: aggregate}
  - {purpose: code_help,           role: "*",      entity: "*",    action: block}
  - {purpose: customer_support,    role: agent_l1, entity: PHONE,  action: mask}   # 1선 상담원: 뒤 4자리만
  - {purpose: fraud_investigation, role: agent_l2, entity: PHONE,  action: keep}   # 2선 조사역: 원본
risk_overrides:
  - {when: "injection.hit",     action: block}
  - {when: "risk_score >= 0.8", action: block}
```

### 지원 본문 포맷 (어댑터)

| 어댑터 | 포맷 | 상태 |
|---|---|---|
| `gateway` | 사내 AI Gateway `{"messages":[{role, content}]}` | ✅ |
| `gemini` | Gemini 공식 API `contents` / `candidates` (요청·응답 스키마 모두) | ✅ |
| `openai`, `anthropic` | 공식 API 포맷 | 🚧 예정 |


## 🔍 설계하며 고민한 지점

1. **Output Guard를 detokenize *앞*에 배치**
   - 재스캔 시점에는 PII가 아직 `<PII:..>` 라벨이라 정규식에 걸리지 않습니다.
   - 그래서 재스캔에는 "모델이 새로 만든 PII"만 잡히고, 권한 있는 사용자에게 복원된 원본을 다시 가려버리는 사고를 막습니다.
2. **입력은 fail-open, 출력은 fail-closed 가드레일**
   - Input Guard 내부 결함이 정상 요청까지 막지 않게 하고(PII 보호는 뒤 스테이지가 담당), 마지막 방어선인 Output Guard는 오류 시 차단합니다.
   - 파이프라인 전체는 `try/except`로 감싸 **gRPC 오류를 절대 던지지 않고** 항상 유효한 판정(기본 `block`)을 돌려줍니다.
3. **위험도는 델타 누적이 아니라 매 턴 재계산**
   - 턴 재전송이나 순서 뒤바뀜 시 이중 계산되는 문제를 피하려고, 현재 윈도우 상태에서 결정론적으로 다시 계산합니다.
4. **스레드 경계에 맞는 동시성 원시 자료형**
   - gRPC 서버는 스레드 풀에서 돌고 스테이지는 요청마다 `asyncio.run()`으로 새 이벤트 루프를 만듭니다.
   - `asyncio.Lock`은 이 조건에서 안전하지 않아 세션 스토어 내부는 `threading.Lock` / `threading.Thread` 스윕으로 구현했습니다.
5. **감사·볼트 테이블은 세션 FK 없음**
   - 세션 TTL 삭제가 CASCADE로 감사 로그를 지우는 일을 원천 차단합니다.
   - 볼트도 세션과 수명을 분리해 자체 `expires_at`으로 관리합니다.
6. **임의 session_id → 결정론적 UUID** (`app/ids.py`)
   - 프록시가 넘기는 세션 식별자(헤더·쿠키·원격 주소)를 UUID로 정규화해, 감사 로그와 볼트 접근 로그를 JOIN할 수 있게 했습니다.
7. **정책 조건식은 화이트리스트 파서로만 평가**
   - `injection.hit`, `risk_score >= N` 두 종류만 허용하고 `eval()`은 쓰지 않습니다.
8. **한국어 NER 경계 보정**
   - GLiNER의 공백 토크나이저가 조사를 span에 붙이는 문제를 `_trim_trailing_particle()` 후처리로 완화했습니다.
   - 실측 문장당 110~184ms로 로컬 파이프라인 목표(600ms) 안에 들어옵니다.


## 🚀 빠른 시작

### 요구사항

- Python 3.11+
- PostgreSQL 16 (볼트·정책·감사 계층)
- `proto/dlp.proto`는 git submodule ([GenAI-DLP/dlp-proto](https://github.com/GenAI-DLP/dlp-proto))

### 1. 설치

```bash
git clone --recurse-submodules https://github.com/GenAI-DLP/dlp-server.git
cd dlp-server

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/gen_proto.py          # app/proto/dlp_pb2*.py 생성 (VCS 제외)
pre-commit install                   # 커밋 시 Ruff lint + format 자동 실행
```

### 2. 환경 변수

```bash
cp .env.example .env
# 볼트 AES-GCM 키 (필수) — base64 32바이트
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
# 출력값을 .env 의 DLP_VAULT__KEY 에 넣는다
```

### 3. DB 준비

```bash
docker run -d --name dlp-pg \
  -e POSTGRES_USER=dlp -e POSTGRES_PASSWORD=dlp -e POSTGRES_DB=dlp \
  -p 5432:5432 postgres:16
docker exec dlp-pg createdb -U dlp dlp_test

python scripts/apply_schema.py                     # 스키마 적용 (dlp)
python scripts/run_migrations.py                   # db/migrations/*.sql 순서대로 적용
python scripts/seed_policy.py                      # policy.yaml → policy_* 테이블
```

> `apply_schema.py`는 기본적으로 `DROP SCHEMA public CASCADE` 후 재적용합니다. 다시 적용했다면 `seed_policy.py`도 다시 실행하세요.

### 4. 실행

```bash
python -m app.main
```

| 포트 | 프로토콜 | 엔드포인트 |
|---|---|---|
| `50051` | gRPC | `DLPInspector.Inspect` (unary) |
| `8000` | HTTP | `/health`, `/events`, `/events/stream`, `/events/{session_id}`, `/stats`, `/vault-access` |

```bash
curl http://localhost:8000/health              # {"status":"ok","db":"ok"}
curl "http://localhost:8000/events?limit=5"    # 감사 로그 최신순
curl "http://localhost:8000/stats?window=1h"   # verdict·지연·엔티티 집계
curl -N http://localhost:8000/events/stream    # SSE 실시간 판정 스트림
python scripts/test_grpc_client.py             # gRPC Inspect 직접 호출
```

> `python app/main.py`로 실행하면 `app/logging/` 패키지가 표준 라이브러리 `logging`을 가립니다. 반드시 `python -m app.main`으로 실행하세요.

### 5. 데모 데이터 시딩

대시보드 시연용으로 대표 시나리오를 파이프라인에 흘려 `log_events`를 채웁니다.

```bash
python scripts/demo_seed.py --reset
```

| 세션 | 시나리오 | 기대 판정 |
|---|---|---|
| `demo-allow` | 코딩 질문 (PII 없음) | allow |
| `demo-transform` | 개인정보가 포함된 문서 요약 | transform (토큰화) |
| `demo-block-policy` | 카드번호가 포함된 문서 요약 | block (정책) |
| `demo-block-injection` | 프롬프트 인젝션 | block (Input Guard) |
| `demo-multiturn` | 이름·주민번호·계좌를 여러 턴에 나눠 입력 | 3턴째 block (누적 위험도) |
| `demo-detok` | 토큰화 후 응답에서 원본 복원 | detokenize |

`--no-ner`로 NER 워밍업을 건너뛸 수 있지만, 멀티턴 시나리오는 NER이 있어야 3턴째 block이 됩니다.

### Docker

```bash
docker build -t dlp-server .
docker run -p 50051:50051 -p 8000:8000 --env-file .env dlp-server
```

빌드 시 GLiNER 모델을 이미지에 미리 받아 두어, 기동 시 네트워크에 의존하지 않습니다.


## ⚙️ 설정

우선순위: **환경변수(`DLP_*`) / `.env` > [`app/config.yaml`](app/config.yaml) > 코드 기본값.** 중첩 필드는 밑줄 두 개(`DLP_DB__DSN` → `db.dsn`).

| 키 | 기본값 | 설명 |
|---|---|---|
| `DLP_DB__DSN` | `postgresql://dlp:dlp@localhost:5432/dlp` | PostgreSQL 접속 문자열 |
| `DLP_VAULT__KEY` | — (필수) | 볼트 AES-GCM 키, base64 32바이트 |
| `DLP_FAIL_ACTION` | `block` | 내부 예외 시 판정 (`allow`는 시연 안정용) |
| `DLP_GUARDRAIL__INJECTION_THRESHOLD` | `0.7` | Input Guard 적중 임계값 |
| `DLP_RISK__HARD_BLOCK` | `0.8` | 멀티턴 누적 위험도 차단 임계값 |
| `DLP_PURPOSE__BACKEND` | `rule` | 목적 분류기 (`rule` / 모델 드롭인 예정) |
| `DLP_DETECT__NER_THRESHOLD` | `0.55` | NER 신뢰도 임계값 |
| `DLP_DETECT__ENABLED_LAYERS` | 전체 | `regex,dict,ner` 중 사용할 레이어 |
| `DLP_LOG_SINK` | `pg` | `pg` / `jsonl` / `both` (pg 실패 시 JSONL 폴백) |
| `DLP_GRPC__PORT` | `50051` | gRPC 포트 |
| `DLP_API__CORS_ORIGINS` | `["*"]` | 읽기 API CORS 허용 오리진 |

지연 예산: 프록시 deadline 3초 / dlp-server soft budget 2.5초.


## 🧪 Test · CI

```bash
pytest -q                                                              # DB 없으면 DB 테스트 skip
DLP_DB__DSN=postgresql://dlp:dlp@localhost:5432/dlp_test pytest -q    # DB 포함
ruff check . && ruff format --check .
```

- 테스트 파일 28개 / 테스트 케이스 약 200개 — 탐지(정탐·오탐 표), 볼트 왕복·접근 범위, 정책 전 조합, 어댑터, 누적기, Output Guard, gRPC 인메모리 서버, SSE 스트림 등
- GitHub Actions: PostgreSQL 16 서비스 컨테이너를 띄워 lint · format · test 전체 실행
- `scripts/verify_detect_pipeline.py` + `eval/datasets/benign/`으로 정상 금융 대화의 오탐 여부 검증

`make install | proto | db-apply | run | test | lint | fmt` 단축키도 제공합니다.


## 📁 프로젝트 폴더 구조

```
app/
├── main.py              # gRPC(:50051) + FastAPI(:8000) 동시 기동, NER 프리로드
├── grpc_server.py       # proto ↔ 내부 타입 변환 (얇은 어댑터)
├── api.py               # 대시보드용 읽기 API + SSE
├── pipeline.py          # ⭐ analyze() 단일 판정 진입점 — gRPC·HTTP·스크립트가 공유
├── models.py            # 계약 타입: Turn / Span / AnalysisContext / Decision
├── adapters/            # 본문 포맷 파서 (gateway, gemini)
├── guardrail/           # Input Guard / Output Guard
├── detect/              # regex · dictionary · ner · merge
├── context/             # SessionStore(인메모리 TTL) · accumulator · stage
├── purpose/             # 목적 분류기 · role 해석기
├── policy/              # 정책 엔진 + policy.yaml(시드)
├── transform/           # vault(토큰화·복원) · apply(8가지 변환)
├── logging/             # 감사 로그 sink · SSE용 in-process 이벤트 버스
└── agent_control/       # MCP tool 통제 · 행동 시퀀스 분석 (스켈레톤)
db/                      # schema.sql(docs SSOT 복사본) · migrations/
scripts/                 # 스키마 적용 · 마이그레이션 · 정책 시드 · 데모 시더 · proto 생성
eval/                    # 평가 데이터셋 · baseline vs full 비교 (예정)
tests/
```


## 🛣️ 진행 현황

| Phase | 내용 | 상태 |
|---|---|---|
| 0 | 스캐폴딩, proto 연결, gRPC 서버 · `/health` | ✅ |
| 1 | PostgreSQL 스키마, Gateway 어댑터, 정규식·사전 탐지, AES-GCM 볼트 | ✅ |
| 2 | 세션 컨텍스트 + 멀티턴 누적 위험도 | ✅ |
| 3 | Input Guard · Output Guard · detokenize | ✅ |
| 4 | 목적 분류 + role + 정책 엔진 + 동적 변환 | ✅ |
| 5 | 감사 로그 PG 정착, 대시보드 API · SSE, GLiNER NER | ✅ |
| 6 | 평가 데이터셋(공격·멀티턴), `run_eval.py` baseline vs full | 🚧 benign 데이터셋만 완료 |
| — | OpenAI · Anthropic 어댑터, 여권·운전면허·외국인등록번호 정규식, 모델 기반 목적 분류기 | 🚧 |
| — | MCP tool 통제, Agent 행동 시퀀스 분석 | 📋 스켈레톤 |


## 📚 관련 문서

- [DLP 서버 아키텍처](https://github.com/GenAI-DLP/docs/blob/main/architecture/dlp-server-architecture.md)
- [gRPC 계약 (dlp-proto)](https://github.com/GenAI-DLP/docs/blob/main/architecture/dlp-proto.md)
- [기능별 스펙 (a~h)](https://github.com/GenAI-DLP/docs/blob/main/specs/spec-index.md)
- [PostgreSQL 스키마 SSOT](https://github.com/GenAI-DLP/docs/blob/main/schemas/dlp-server/postgres-schema.sql)
