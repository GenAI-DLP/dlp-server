.PHONY: proto install run test lint fmt

# macOS / Linux 용 shortcut. Windows(conda)에서는
# `python scripts/gen_proto.py` 를 직접 실행하세요.
proto:
	python scripts/gen_proto.py

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