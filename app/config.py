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
    combo_cap: float = 0.8
    repeat_weight: float = 0.05
    repeat_cap: float = 0.15


class GuardrailConfig(BaseModel):
    # Input Guard hit 판정 임계 (0~1). env DLP_GUARDRAIL__INJECTION_THRESHOLD
    injection_threshold: float = 0.7
    # Output Guard — 응답 재스캔 재마스킹 최소 confidence.
    # env DLP_GUARDRAIL__OUTPUT_PII_MIN_CONFIDENCE
    output_pii_min_confidence: float = 0.5
    # Output Guard 인젝션 순응(시스템 프롬프트/지시 노출) 검사 on/off.
    # env DLP_GUARDRAIL__OUTPUT_INJECTION_CHECK
    output_injection_check: bool = True


class DetectConfig(BaseModel):
    """하이브리드 PII 탐지(§6-b) 설정. app/detect/ 의 세 레이어 + merge 가 소비한다.

    근거: spec/hybrid-pii-detection.md §4
    """

    regex_min_confidence: float = 0.5
    dict_min_confidence: float = 0.0
    # detect/ner.py 가 소비. merge.py 병합 시 이 threshold 미만인 NER span은 버려진다.
    # 2026-09-03 실측(gliner_multi-v2.1) 기준 임시값 — eval/run_eval.py로 정식 튜닝 예정.
    ner_threshold: float = 0.55
    # GLiNER 모델 식별자. Apache 2.0 유지가 조건이라, 상용 전환 시에도
    # gliner_ko(CC-BY-NC-4.0)로 바꾸지 말 것 — 대안은 아키텍처 문서 §12 참고.
    ner_model_name: str = "urchade/gliner_multi-v2.1"
    merge_overlap_bonus: float = 0.02
    dictionary_path: str = ""
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

    # DLP 내부 예외 시 반환할 판정. 기본 block, 시연 안정용 allow 스위치.
    fail_action: str = "block"  # block | allow  (DLP_FAIL_ACTION)
    soft_budget_sec: float = 2.5  # 프록시 deadline 3s 대비 내부 예산
    session_ttl_sec: int = 1800  # 세션 컨텍스트 TTL
    vault_ttl_sec: int = 1800  # 토큰 볼트 TTL (세션과 수명 분리)
    log_sink: str = "pg"  # pg | jsonl | both — 감사 로그 sink (DLP_LOG_SINK)
    log_path: str = "log_events.jsonl"  # JSONL sink / PG 폴백 경로 (DLP_LOG_PATH)

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

    if cfg.log_sink not in ("pg", "jsonl", "both"):
        raise ValueError(f"log_sink 은 pg|jsonl|both 여야 함: {cfg.log_sink!r}")

    return cfg
