"""
런타임 설정 로더.

우선순위: 환경변수(DLP_*) / .env > config.yaml > 코드 기본값.
중첩 필드는 이중 밑줄: DLP_DB__DSN → db.dsn, DLP_GRPC__PORT → grpc.port.
평면 필드는 그대로: DLP_FAIL_ACTION → fail_action, DLP_LOG_PATH → log_path.
yaml 경로는 DLP_CONFIG 환경변수로 바꿀 수 있다.

근거: docs/architecture/dlp-server-architecture.md §9 (에러·성능 정책)
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")

# load_config(path=...) 또는 DLP_CONFIG 로 지정된 yaml 경로.
# settings_customise_sources() 가 이 값을 읽어 yaml 소스를 만든다.
_yaml_path: Path = DEFAULT_CONFIG_PATH


class PurposeConfig(BaseModel):
    backend: str = "rule"  # rule | llm
    llm_timeout_sec: float = 1.5


class RiskConfig(BaseModel):
    hard_block: float = 0.8  # 누적 위험도 임계값 — 초과 시 block


class DbConfig(BaseModel):
    dsn: str = "postgresql://dlp:dlp@localhost:5432/dlp"  # DLP_DB__DSN 로 오버라이드
    pool_min: int = 1
    pool_max: int = 8


class GrpcConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 50051


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DLP_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # DLP 내부 예외 시 반환할 판정. 기본 block, 시연 안정용 allow 스위치.
    fail_action: str = "block"  # block | allow  (DLP_FAIL_ACTION)
    soft_budget_sec: float = 2.5  # 프록시 deadline 3s 대비 내부 예산
    session_ttl_sec: int = 1800  # 세션 컨텍스트 TTL
    vault_ttl_sec: int = 1800  # 토큰 볼트 TTL (세션과 수명 분리)
    log_path: str = "log_events.jsonl"  # 감사 로그 JSONL sink 경로 (DLP_LOG_PATH)

    db: DbConfig = Field(default_factory=DbConfig)  # DLP_DB__DSN, DLP_DB__POOL_MIN ...
    purpose: PurposeConfig = Field(default_factory=PurposeConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    grpc: GrpcConfig = Field(default_factory=GrpcConfig)  # DLP_GRPC__PORT ...
    api: ApiConfig = Field(default_factory=ApiConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """우선순위: init > 환경변수 > .env > config.yaml > secrets."""
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings, dotenv_settings]
        if _yaml_path.exists():
            sources.append(
                YamlConfigSettingsSource(
                    settings_cls, yaml_file=_yaml_path, yaml_file_encoding="utf-8"
                )
            )
        sources.append(file_secret_settings)
        return tuple(sources)


def load_config(path: str | Path | None = None) -> Config:
    """설정을 로드한다.

    path 를 주면 그 yaml 을, 아니면 DLP_CONFIG 또는 기본 config.yaml 을 base 로 하고
    그 위에 환경변수 / .env 를 얹는다.
    """
    global _yaml_path
    _yaml_path = Path(path or os.environ.get("DLP_CONFIG", DEFAULT_CONFIG_PATH))

    cfg = Config()

    if cfg.fail_action not in ("block", "allow"):
        raise ValueError(f"fail_action 은 block|allow 여야 함: {cfg.fail_action!r}")

    return cfg
