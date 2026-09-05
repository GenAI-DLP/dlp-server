-- 000_create_schema_migrations.sql
--
-- 마이그레이션 적용 이력 추적 테이블. 이후 모든 마이그레이션 파일은
-- 끝에 자기 자신을 이 테이블에 기록해서, "이 DB에 뭐가 적용됐는지"를
-- SELECT 한 번으로 확인할 수 있게 한다.
--
-- 이 파일 자체는 딱 한 번, 다른 마이그레이션보다 먼저 적용한다.
-- (번호를 000으로 둔 이유: 001부터 시작하는 실제 변경 이력보다
--  먼저 실행되어야 함을 파일명 정렬 순서로도 드러내기 위함)

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (filename) VALUES ('000_create_schema_migrations.sql')
ON CONFLICT (filename) DO NOTHING;