"""
런타임 설정 로더.

우선순위: 환경변수(DLP_* 일부) > config.yaml > 코드 기본값.
설정 파일 경로는 DLP_CONFIG 환경변수로 바꿀 수 있다.

근거: docs/architecture/dlp-server-architecture.md §9 (에러·성능 정책)
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")


class PurposeConfig(BaseModel):
    backend: str = "rule"  # rule | llm
    llm_timeout_sec: float = 1.5


class RiskConfig(BaseModel):
    hard_block: float = 0.8  # 누적 위험도 임계값 — 초과 시 block


class GrpcConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 50051


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class Config(BaseModel):
    # DLP 내부 예외 시 반환할 판정. 기본 block, 시연 안정용 allow 스위치.
    fail_action: str = "block"  # block | allow
    soft_budget_sec: float = 2.5  # 프록시 deadline 3s 대비 내부 예산
    session_ttl_sec: int = 1800  # 세션 컨텍스트 TTL
    vault_ttl_sec: int = 1800  # 토큰 볼트 TTL (세션과 수명 분리)

    purpose: PurposeConfig = Field(default_factory=PurposeConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    grpc: GrpcConfig = Field(default_factory=GrpcConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)


def load_config(path: str | Path | None = None) -> Config:
    resolved = Path(path or os.environ.get("DLP_CONFIG", DEFAULT_CONFIG_PATH))
    data: dict = {}
    if resolved.exists():
        data = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}

    cfg = Config(**data)

    # 자주 바꾸는 값만 환경변수 오버라이드
    if os.environ.get("DLP_FAIL_ACTION"):
        cfg.fail_action = os.environ["DLP_FAIL_ACTION"]
    if os.environ.get("DLP_GRPC_PORT"):
        cfg.grpc.port = int(os.environ["DLP_GRPC_PORT"])

    if cfg.fail_action not in ("block", "allow"):
        raise ValueError(f"fail_action 은 block|allow 여야 함: {cfg.fail_action!r}")

    return cfg
