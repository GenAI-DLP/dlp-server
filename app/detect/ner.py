"""
app/detect/ner.py — 한국어 경량 NER (GLiNER 기반, 커스텀 라벨 제로샷)

역할 (아키텍처 문서 §3.1, §4, §6-b):
  하이브리드 PII 탐지의 세 번째 레이어. 정규식/사전으로 못 잡는 개체
  (주소, 조직명, 비정형 신용정보: 연체/대출잔액/신용등급)를 커스텀 라벨
  제로샷으로 탐지한다. merge.py에서 정규식 > 사전 > NER 우선순위로 병합된다.

모델: urchade/gliner_multi-v2.1 (Apache 2.0, CPU 추론, mecab-ko 불필요)
  - taeminlee/gliner_ko(한국어 전용) 대비 형태소 경계는 거칠지만
    라이선스가 상용 가능하고 배포 환경 제약이 적어 채택.
  - whitespace 토크나이저 한계로 조사가 span 끝에 붙는 문제가 있어
    _trim_trailing_particle()로 후처리한다. 정밀 형태소 분석 수준은
    아니므로, 실사용 로그에서 새로운 패턴이 보이면 정규식을 계속 보강할 것.

실측 기준 (2026-09-03, gliner_multi-v2.1, threshold=0.3):
  - 문장당 지연 110~184ms → 로컬 파이프라인 목표(600ms) 대비 여유 있음.
    ONNX/INT8 양자화는 현재 불필요.
  - 알려진 오탐: "3개월" 같은 기간 표현이 CREDIT_INFO로 잘못 잡히는 경우,
    "(주)회사명"의 "주"가 ADDRESS로 잘못 잡히는 경우 → 후자는 회사명이
    사전 레이어(Aho-Corasick)로 이미 커버되므로 merge.py 우선순위상
    치명적이지 않음.
"""

from __future__ import annotations

import logging
import re
import threading
import time

from app.models import Span

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 라벨 ↔ Span.type 매핑
#   §7.2의 entity_type_ref 조회 테이블과 코드 레벨에서 일치시켜 관리한다.
#   라벨 문구(자연어)는 GLiNER 프롬프트 그 자체라 정확도에 직접 영향을 준다.
#   바꿀 때는 반드시 회귀 테스트(test_gliner_ko.py류)로 확인할 것.
# ---------------------------------------------------------------------------
LABEL_TO_SPAN_TYPE: dict[str, str] = {
    "사람 이름": "NAME",
    "주소": "ADDRESS",
    "회사명": "ORG",
    "내부 프로젝트명": "PROJECT",
    "연체 정보": "CREDIT_INFO",
    "대출 잔액": "CREDIT_INFO",
    "신용등급": "CREDIT_INFO",
}

GLINER_LABELS: list[str] = list(LABEL_TO_SPAN_TYPE.keys())

DEFAULT_MODEL_NAME = "urchade/gliner_multi-v2.1"
DEFAULT_THRESHOLD = 0.4  # 실측값(0.3)보다 살짝 보수적으로 시작, eval로 튜닝

# ---------------------------------------------------------------------------
# 조사/존칭 트리밍
#   whitespace 스플리터가 한국어 조사를 분리하지 못해 생기는 span 경계
#   오차를 완화하는 경량 후처리. 긴 패턴을 먼저 매칭하도록 순서에 주의.
# ---------------------------------------------------------------------------
_TRAILING_PARTICLES = re.compile(
    r"(님의|님|씨가|씨는|씨|이고|이며|으로|에서|에게|은|는|이|가|을|를|의|에|로)$"
)


def _trim_trailing_particle(text: str) -> str:
    trimmed = _TRAILING_PARTICLES.sub("", text)
    return trimmed if trimmed else text


class NEREngine:
    """GLiNER 기반 제로샷 NER 엔진.

    프로세스당 1개 인스턴스로 재사용한다 (모델 로딩 비용이 크므로 요청마다
    새로 만들지 않는다). 모델 자체는 lazy-load하되, main.py 부트스트랩에서
    preload()를 호출해 첫 요청의 콜드스타트 지연을 없앨 것을 권장한다.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self._model = None
        self._lock = threading.Lock()

    def preload(self) -> None:
        """앱 시작 시 명시적으로 호출해 모델을 미리 로딩한다.
        main.py에서 get_ner_engine(...).preload() 형태로, gRPC 서버 기동
        전에 호출할 것을 권장."""
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:  # double-checked locking
                return
            logger.info("NER 모델 로딩 시작: %s", self.model_name)
            t0 = time.time()
            from gliner import GLiNER  # 지연 import: 미사용 시 torch 로딩 비용 회피

            self._model = GLiNER.from_pretrained(self.model_name)
            logger.info("NER 모델 로딩 완료 (%.1fs)", time.time() - t0)

    def extract(self, text: str) -> list[Span]:
        """텍스트에서 Span 목록을 추출한다.

        실패 시 예외를 삼키고 빈 리스트를 반환한다 — NER은 하이브리드 탐지의
        세 레이어 중 하나일 뿐이므로, 여기서 발생한 예외가 전체 파이프라인을
        막아서는 안 된다 (§10 에러 정책과 동일한 원칙: 개별 스테이지 실패는
        fallback 후 계속 진행).
        """
        if not text or not text.strip():
            return []

        try:
            self._ensure_loaded()
            raw_entities = self._model.predict_entities(
                text, GLINER_LABELS, threshold=self.threshold
            )
        except Exception:
            logger.exception("NER 추론 실패, 빈 결과로 계속 진행")
            return []

        spans: list[Span] = []
        for ent in raw_entities:
            span_type = LABEL_TO_SPAN_TYPE.get(ent["label"])
            if span_type is None:
                # 라벨셋 불일치(모델/코드 버전 스큐) 방어. 조용히 무시하되
                # 감사 로그 분석 시 드러나도록 warning으로 남긴다.
                logger.warning("알 수 없는 NER 라벨 무시: %s", ent["label"])
                continue

            value = ent["text"]
            start = ent["start"]
            end = ent["end"]

            trimmed = _trim_trailing_particle(value)
            if trimmed != value:
                end = start + len(trimmed)
                value = trimmed

            if not value:
                continue

            spans.append(
                Span(
                    type=span_type,
                    value=value,
                    start=start,
                    end=end,
                    confidence=float(ent["score"]),
                    source="ner",
                )
            )

        return spans


# ---------------------------------------------------------------------------
# 프로세스 전역 싱글턴
#   pipeline.py / merge.py는 이 모듈의 extract_spans()만 알면 되고,
#   모델 로딩·설정 디테일은 몰라도 된다 (regex_rules.py, dictionary.py와
#   동일한 진입점 시그니처를 맞춰 merge.py에서 균일하게 다룬다).
# ---------------------------------------------------------------------------
_engine: NEREngine | None = None
_engine_lock = threading.Lock()


def get_ner_engine(
    model_name: str | None = None,
    threshold: float | None = None,
) -> NEREngine:
    """엔진 싱글턴을 반환한다.

    최초 호출 시 model_name/threshold가 주어지면 그 값으로 구성한다
    (main.py의 preload() 호출에서 cfg.detect 값을 넘겨준다). 이후 호출은
    인자를 무시하고 이미 만들어진 인스턴스를 그대로 반환한다 — 재구성이
    필요하면 프로세스를 재시작해야 한다.

    app.config.DetectConfig를 직접 import하지 않는 이유: ner.py가 config
    모듈에 결합되지 않도록, 호출부(main.py)에서 값만 꺼내 넘기게 한다.
    """
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = NEREngine(
                    model_name=model_name or DEFAULT_MODEL_NAME,
                    threshold=threshold if threshold is not None else DEFAULT_THRESHOLD,
                )
    return _engine


def detect(text: str) -> list[Span]:
    """app/detect/__init__.py의 _LAYER_FUNCS가 호출하는 진입점.

    regex_rules.detect() / dictionary.detect()와 동일한 시그니처
    (text -> list[Span])를 맞춰서 세 레이어를 orchestrator에서 균일하게
    다룰 수 있게 한다. 엔진 자체의 model_name/threshold는 main.py가
    부트스트랩 시점에 get_ner_engine(model_name=..., threshold=...)로
    미리 구성해두는 것을 전제로 한다 — 여기서는 인자 없이 싱글턴을
    가져다 쓰기만 한다.
    """
    return get_ner_engine().extract(text)
