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

_yaml_path: Path = DEFAULT_CONFIG_PATH


class PurposeConfig(BaseModel):
    backend: str = "rule"
    llm_timeout_sec: float = 1.5


class RiskConfig(BaseModel):
    hard_block: float = 0.6


class MultiturnConfig(BaseModel):
    window_size_turns: int = 5
    combo_cap: float = 0.6
    repeat_weight: float = 0.05
    repeat_cap: float = 0.15


class GuardrailConfig(BaseModel):
    injection_threshold: float = 0.7


class DetectConfig(BaseModel):
    """하이브리드 PII 탐지(§6-b) 설정. app/detect/ 의 세 레이어 + merge 가 소비한다.

    근거: spec/hybrid-pii-detection.md §4
    """

    # regex 레이어 결과 중 체크섬 실패 등으로 낮게 나온 값의 최소 통과 confidence.
    # merge.py 의 DEFAULT_MIN_CONFIDENCE["regex"] 대체. env DLP_DETECT__REGEX_MIN_CONFIDENCE
    regex_min_confidence: float = 0.5
    # dict 레이어는 boolean 성격이라 기본은 필터링 안 함 (0.0).
    dict_min_confidence: float = 0.0
    # ner.py 미구현이라 지금은 안 쓰이지만, 붙을 때 merge threshold 로 바로 연결되게 미리 둠.
    ner_threshold: float = 0.7
    # 다중 레이어 합의 시 confidence 가산치. merge.py 의 OVERLAP_BONUS 대체.
    merge_overlap_bonus: float = 0.02
    # 사전 파일 경로. 빈 문자열이면 dictionary.py 의 내장 기본 경로
    # (app/detect/dictionaries/financial_terms.txt) 를 그대로 쓴다.
    dictionary_path: str = ""
    # 콤마 구분 레이어 이름 목록 (예: "regex,dict,ner"). 테스트/부분 배포 시
    # 특정 레이어만 켜고 싶을 때 사용. 빈 문자열이면 구현된 레이어 전부 사용.
    enabled_layers: str = ""


class DbConfig(BaseModel):
    dsn: str = "postgresql://dlp:dlp@localhost:5432/dlp"
    pool_min: int = 1
    pool_max: int = 8


class VaultConfig(BaseModel):
    key: str = ""


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

    fail_action: str = "block"
    soft_budget_sec: float = 2.5
    session_ttl_sec: int = 1800
    vault_ttl_sec: int = 1800
    log_path: str = "log_events.jsonl"

    db: DbConfig = Field(default_factory=DbConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    purpose: PurposeConfig = Field(default_factory=PurposeConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    multiturn: MultiturnConfig = Field(default_factory=MultiturnConfig)
    guardrail: GuardrailConfig = Field(default_factory=GuardrailConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)
    grpc: GrpcConfig = Field(default_factory=GrpcConfig)
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
    global _yaml_path
    _yaml_path = Path(path or os.environ.get("DLP_CONFIG", DEFAULT_CONFIG_PATH))

    cfg = Config()

    if cfg.fail_action not in ("block", "allow"):
        raise ValueError(f"fail_action 은 block|allow 여야 함: {cfg.fail_action!r}")

    return cfg