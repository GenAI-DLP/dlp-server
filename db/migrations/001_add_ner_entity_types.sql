-- 001_add_ner_entity_types.sql
-- ner.py(GLiNER)가 추가한 ADDRESS/ORG/PROJECT 타입을 entity_type_ref에 반영.
-- 이 세 타입이 없으면 vault.tokenize()에서 ForeignKeyViolation 발생.
INSERT INTO entity_type_ref (code, tier, note) VALUES
    ('ADDRESS', 'medium', 'NER 레이어(ner.py) 추가 — 주소'),
    ('ORG',     'low',    'NER 레이어(ner.py) 추가 — 회사명'),
    ('PROJECT', 'medium', 'NER 레이어(ner.py) 추가 — 내부 프로젝트명')
ON CONFLICT (code) DO NOTHING;