-- ================================================================
-- docs 레포 schemas/dlp-server/postgres-schema.sql 의 복사본.
-- SSOT 는 docs 이며, 여기서 직접 편집하지 않는다.
-- docs 쪽 스키마가 바뀌면 그 파일 내용으로 이 파일을 교체한다.
-- ================================================================

-- =====================================================================
-- dlp-server PostgreSQL 스키마 (표준 원본 / SSOT)
--
-- 이 파일이 네 개 데이터 계약의 단일 기준이다:
--   session-context.md · token-vault.md · policy.md · log-event.md
--
-- 데이터 3계층:
--   운영(TTL purge) : sessions, session_turns, session_entities
--   볼트(자체 TTL)   : token_vault  ← sessions 와 수명 분리
--   감사(장기 보존)   : log_events, token_vault_access_log  ← 운영 테이블로의 FK 없음
--
-- 볼트(token_vault*)·정책(policy_*)·감사(log_events)는 데모부터 PostgreSQL로 이 스키마를 그대로 쓴다.
-- 세션(운영: sessions*)은 미정 — 인메모리(TTL 스윕) 또는 PostgreSQL. 어느 쪽이든 컬럼·제약·인덱스의
-- 의미는 이 파일을 따른다. 각 테이블의 설계 근거는 같은 폴더의 *.md 문서를 참조.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()

-- ---------------------------------------------------------------------
-- 0. ENUM — 값 집합이 안정적인 것만. entity/purpose 는 아래 조회 테이블로.
-- ---------------------------------------------------------------------
CREATE TYPE direction_type AS ENUM ('input', 'output');
CREATE TYPE span_source     AS ENUM ('regex', 'dict', 'ner');

-- gRPC Verdict.action 과 3값 고정 일치 (architecture/dlp-proto.md)
CREATE TYPE verdict_action  AS ENUM ('allow', 'block', 'transform');

-- 동적 변환 전략 (specs/dlp-server/g_dynamic-data-transformation.md)
CREATE TYPE action_type AS ENUM (
    'keep', 'mask', 'generalize', 'aggregate', 'tokenize', 'synthetic', 'redact', 'block'
);

-- ---------------------------------------------------------------------
-- 0-b. 엔티티 타입 / 목적 조회 테이블
--      (목록 미확정 → ENUM ALTER 마찰 회피, 민감도 등급도 흡수)
-- ---------------------------------------------------------------------
CREATE TABLE entity_type_ref (
    code TEXT PRIMARY KEY,
    tier TEXT NOT NULL CHECK (tier IN ('low','medium','high','critical')),
    note TEXT
);
INSERT INTO entity_type_ref (code, tier) VALUES
    ('RRN','critical'), ('FOREIGN_RRN','critical'), ('CARD','critical'),
    ('ACCOUNT','high'), ('PASSPORT','high'), ('DRIVER','high'), ('CREDIT_INFO','high'),
    ('PHONE','medium'), ('EMAIL','medium'), ('BIZNO','medium'), ('AMOUNT','medium'),
    ('NAME','low'),
    ('UNKNOWN','low');

CREATE TABLE purpose_ref (
    code TEXT PRIMARY KEY,
    note TEXT
);
INSERT INTO purpose_ref (code) VALUES
    ('customer_support'), ('doc_summarize'), ('code_help'),
    ('data_analysis'), ('fraud_investigation'), ('unknown');


-- =====================================================================
-- 1. session-context  (운영, TTL purge 대상)
-- =====================================================================
CREATE TABLE sessions (
    session_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider           VARCHAR(32) NOT NULL,              -- gateway | openai | anthropic
    role               VARCHAR(64),                       -- 헤더에서 resolve
    purpose            TEXT REFERENCES purpose_ref(code) DEFAULT 'unknown',
    purpose_confidence REAL,
    turn_count         INT  NOT NULL DEFAULT 0,
    risk_score         REAL NOT NULL DEFAULT 0.0,         -- 누적 위험도 0.0~1.0
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,              -- TTL
    CHECK (risk_score >= 0.0 AND risk_score <= 1.0)
);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX idx_sessions_last_seen  ON sessions (last_seen_at);

CREATE TABLE session_turns (
    turn_id     BIGSERIAL PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_index  INT NOT NULL,                             -- 세션 내 순번 (0부터)
    role        VARCHAR(16) NOT NULL,                     -- user | assistant | system
    direction   direction_type NOT NULL,
    text_hash   VARCHAR(64) NOT NULL,                     -- 원문 저장 금지, SHA-256 만
    text_length INT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, turn_index)
);
CREATE INDEX idx_session_turns_session ON session_turns (session_id);

-- 멀티턴: 턴별 탐지 엔티티 누적. 그래프 엣지는 동일 turn_id 공유로 쿼리 시점 계산.
CREATE TABLE session_entities (
    entity_id   BIGSERIAL PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id     BIGINT NOT NULL REFERENCES session_turns(turn_id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL REFERENCES entity_type_ref(code),
    value_hash  VARCHAR(64) NOT NULL,                     -- 원본 값은 볼트로 별도 관리
    confidence  REAL NOT NULL,
    source      span_source NOT NULL,
    span_start  INT,
    span_end    INT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_session_entities_session ON session_entities (session_id);
CREATE INDEX idx_session_entities_type    ON session_entities (session_id, entity_type);
CREATE INDEX idx_session_entities_value   ON session_entities (session_id, value_hash);


-- =====================================================================
-- 2. token-vault
--    sessions 로의 FK/CASCADE 제거 → 자체 expires_at 로만 수명 관리
-- =====================================================================
CREATE TABLE token_vault (
    token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   UUID NOT NULL,                           -- 값 컬럼 (FK 없음)
    entity_type  TEXT NOT NULL REFERENCES entity_type_ref(code),
    token_label  VARCHAR(64) NOT NULL,                    -- 응답 노출 문자열, 예: "<PII:RRN:1>"
    cipher_value BYTEA NOT NULL,                          -- 앱레벨 AES-GCM (KMS 키), 저장소에 키 없음
    value_hash   VARCHAR(64) NOT NULL,                    -- 결정론적 재사용 매칭
    access_scope JSONB NOT NULL DEFAULT '{"roles": [], "purposes": []}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,                    -- TTL
    revoked_at   TIMESTAMPTZ                              -- soft delete (파기 예약)
);
-- 입력 경로: 동일 값 → 동일 토큰 재사용
CREATE UNIQUE INDEX idx_token_vault_session_value ON token_vault (session_id, value_hash)
    WHERE revoked_at IS NULL;
-- 출력 경로: 응답에서 찾은 token_label 로 복원 조회
CREATE INDEX idx_token_vault_label   ON token_vault (session_id, token_label)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_token_vault_session ON token_vault (session_id);
CREATE INDEX idx_token_vault_expires ON token_vault (expires_at) WHERE revoked_at IS NULL;

-- 복원 시도 이력 — 운영 테이블로의 FK 없음 (감사 장기 보존)
CREATE TABLE token_vault_access_log (
    access_id         BIGSERIAL PRIMARY KEY,
    token_id          UUID NOT NULL,                      -- 값 컬럼
    session_id        UUID NOT NULL,                      -- 조회 편의 denormalize
    token_label       VARCHAR(64) NOT NULL,
    requested_role    VARCHAR(64) NOT NULL,
    requested_purpose TEXT,                               -- FK 없음 (감사 테이블)
    granted           BOOLEAN NOT NULL,                   -- access_scope 통과 여부
    denied_reason     TEXT,
    accessed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_vault_access_log_token   ON token_vault_access_log (token_id);
CREATE INDEX idx_vault_access_log_session ON token_vault_access_log (session_id, accessed_at);


-- =====================================================================
-- 3. policy
-- =====================================================================
CREATE TABLE policy_versions (
    policy_version_id SERIAL PRIMARY KEY,
    description       TEXT,
    is_active         BOOLEAN NOT NULL DEFAULT false,
    created_by        VARCHAR(64),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_policy_versions_active ON policy_versions (is_active) WHERE is_active = true;

-- purpose × role × entity → action
CREATE TABLE policy_rules (
    rule_id           BIGSERIAL PRIMARY KEY,
    policy_version_id INT NOT NULL REFERENCES policy_versions(policy_version_id) ON DELETE CASCADE,
    purpose           TEXT REFERENCES purpose_ref(code),       -- NULL = 전체(*)
    role              VARCHAR(64),                             -- NULL = 전체(*)
    entity_type       TEXT REFERENCES entity_type_ref(code),   -- NULL = 전체(*)
    action            action_type NOT NULL,
    priority          INT NOT NULL DEFAULT 0,                  -- 높을수록 우선
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_policy_rules_lookup ON policy_rules (policy_version_id, purpose, role, entity_type);

-- risk_overrides: condition_expr 는 앱의 화이트리스트 파서로만 평가 (eval() 금지)
CREATE TABLE policy_risk_overrides (
    override_id       BIGSERIAL PRIMARY KEY,
    policy_version_id INT NOT NULL REFERENCES policy_versions(policy_version_id) ON DELETE CASCADE,
    condition_expr    TEXT NOT NULL,                           -- "injection.hit", "risk_score >= 0.8"
    action            action_type NOT NULL,
    priority          INT NOT NULL DEFAULT 100,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- =====================================================================
-- 4. log-event  (감사, append-only 지향)
--    sessions 로의 FK 제거 → 세션 purge 후에도 로그 보존
-- =====================================================================
CREATE TABLE log_events (
    event_id            BIGSERIAL PRIMARY KEY,
    session_id          UUID NOT NULL,                         -- 값 컬럼 (FK 없음)
    direction           direction_type NOT NULL,
    provider            VARCHAR(32) NOT NULL,
    purpose             TEXT,                                  -- FK 없음 (감사)
    verdict_action      verdict_action NOT NULL,               -- 실제 전송된 3값
    transforms          JSONB DEFAULT '[]'::jsonb,             -- 세부 변환 종류 리스트
    entities_summary    JSONB DEFAULT '[]'::jsonb,             -- [{type, masked_preview, confidence}] — 원문 금지
    guardrail_hits      JSONB DEFAULT '[]'::jsonb,
    fail_policy_applied  BOOLEAN NOT NULL DEFAULT false,
    latency_ms          INT NOT NULL,
    reason              JSONB,                                 -- Decision.reason_obj 전체
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_log_events_session     ON log_events (session_id, created_at);
CREATE INDEX idx_log_events_created     ON log_events (created_at DESC);
CREATE INDEX idx_log_events_action      ON log_events (verdict_action);
CREATE INDEX idx_log_events_summary_gin ON log_events USING gin (entities_summary);

-- 운영: REVOKE UPDATE, DELETE ON log_events, token_vault_access_log FROM app_role;
-- 운영: created_at 월별 파티셔닝
--   CREATE TABLE log_events_2026_09 PARTITION OF log_events
--     FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');


-- =====================================================================
-- 5. TTL 정리  (스케줄러 또는 앱 배치에서 주기 실행)
--    감사 테이블은 FK 없어 건드리지 않음
-- =====================================================================
CREATE OR REPLACE FUNCTION purge_expired() RETURNS void AS $$
BEGIN
    -- 1. 만료 볼트 → soft revoke (즉시 복원 차단)
    UPDATE token_vault
       SET revoked_at = now()
     WHERE expires_at < now()
       AND revoked_at IS NULL;

    -- 2. revoke 후 유예기간 지난 볼트 → 하드 삭제 (cipher_value 완전 파기)
    DELETE FROM token_vault
     WHERE revoked_at IS NOT NULL
       AND revoked_at < now() - interval '1 day';

    -- 3. 만료 세션 → 하드 삭제 (CASCADE: turns/entities 동반). 감사 로그는 FK 없어 보존.
    DELETE FROM sessions
     WHERE expires_at < now();
END;
$$ LANGUAGE plpgsql;

-- SELECT cron.schedule('dlp-purge', '*/5 * * * *', 'SELECT purge_expired();');
