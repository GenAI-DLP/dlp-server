.PHONY: proto install run test lint fmt db-apply

# macOS / Linux 용 shortcut. Windows(conda)에서는
# `python scripts/gen_proto.py` 를 직접 실행하세요.
proto:
	python scripts/gen_proto.py

# db/schema.sql 을 DB 에 적용 (기본: DROP 후 재생성). DSN 은 DLP_DB_DSN 로.
db-apply:
	python scripts/apply_schema.py

install:
	pip install -r requirements.txt

run:
	python -m app.main

test:
	pytest -q

lint:
	ruff check .

fmt:
	ruff format .