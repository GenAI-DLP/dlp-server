"""공통 테스트 설정."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _audit_log_to_tmp(tmp_path, monkeypatch):
    """감사 로그를 테스트별 tmp 파일로 보내 repo 오염 방지."""
    monkeypatch.setenv("DLP_LOG_PATH", str(tmp_path / "events.jsonl"))
