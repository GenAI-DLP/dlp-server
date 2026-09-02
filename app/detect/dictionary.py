"""
detect/dictionary.py — Aho-Corasick 다중 패턴 매칭 기반 사전 탐지 레이어.

정규식/체크섬으로 못 잡는 비정형 금융 PII(인명, 금융 도메인 용어 등)를
사전 등재어 매칭으로 보완한다. 정규식과 달리 "정답 형식"이 없는 대상이라
confidence 는 사전 항목별로 고정값을 설정 파일에서 관리한다.

⚠️ 한글은 정규식 \\b 같은 단어 경계가 없다. Aho-Corasick 은 텍스트 어디서든
부분 문자열을 찾기 때문에, 너무 짧은 term(특히 한 글자 성씨)을 등록하면
오탐이 폭증한다. 그래서 로딩 시 2자 미만 term 은 스킵한다 — 근본적으로
정확한 한글 단어 경계 처리가 필요하면 형태소 분석기 도입을 검토해야 한다
(현재 범위 밖, TODO).

사전 파일 형식: term<TAB>type<TAB>confidence  (#으로 시작하는 줄은 주석)
기본 경로: DLP_DETECT__DICTIONARY_PATH (app/config.py 연동은 TODO — 현재는
이 모듈의 DEFAULT_DICT_PATH 상수 사용)

근거: spec/hybrid-pii-detection.md §3.1
"""

from __future__ import annotations

import logging
from pathlib import Path

import ahocorasick

from app.models import Span

logger = logging.getLogger(__name__)

DEFAULT_DICT_PATH = Path(__file__).parent / "dictionaries" / "financial_terms.txt"
MIN_TERM_LENGTH = 2  # 이보다 짧은 term 은 오탐 방지를 위해 로딩 시 스킵


def load_dictionary(path: Path | str = DEFAULT_DICT_PATH) -> ahocorasick.Automaton:
    """사전 파일을 읽어 Aho-Corasick 오토마톤을 빌드한다.

    각 term 에 대해 (type, confidence) 를 payload 로 저장한다.
    """
    automaton = ahocorasick.Automaton()
    path = Path(path)

    if not path.exists():
        logger.warning("dictionary: 사전 파일을 찾을 수 없음 — %s (빈 오토마톤 사용)", path)
        automaton.make_automaton()
        return automaton

    loaded, skipped = 0, 0
    with path.open(encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")
            if len(parts) != 3:
                logger.warning("dictionary: %s:%d 형식 오류 (탭 3필드 아님) — 스킵", path, lineno)
                continue

            term, type_, confidence_str = parts
            if len(term) < MIN_TERM_LENGTH:
                logger.debug(
                    "dictionary: %s:%d '%s' 는 %d자 미만이라 스킵",
                    path, lineno, term, MIN_TERM_LENGTH,
                )
                skipped += 1
                continue

            try:
                confidence = float(confidence_str)
            except ValueError:
                logger.warning(
                    "dictionary: %s:%d confidence 파싱 실패 ('%s') — 스킵",
                    path, lineno, confidence_str,
                )
                continue

            automaton.add_word(term, (type_, confidence, len(term)))
            loaded += 1

    automaton.make_automaton()
    logger.info("dictionary: %s 로딩 완료 — %d개 등록, %d개 스킵", path, loaded, skipped)
    return automaton


# 모듈 최초 사용 시 1회 빌드 후 캐시 (매 요청마다 파일 재파싱 방지)
_default_automaton: ahocorasick.Automaton | None = None


def _get_default_automaton() -> ahocorasick.Automaton:
    global _default_automaton
    if _default_automaton is None:
        _default_automaton = load_dictionary()
    return _default_automaton


def detect(text: str, automaton: ahocorasick.Automaton | None = None) -> list[Span]:
    """텍스트에서 사전 등재어를 모두 찾아 Span 리스트로 반환한다.

    Args:
        text: 탐지 대상 텍스트.
        automaton: 테스트/커스텀 사전 주입용. 미지정 시 기본 사전(캐시됨) 사용.

    Returns:
        겹치는 매치(예: 짧은 term 이 긴 term 안에 포함되는 경우)를 그대로
        반환한다 — 정리는 merge.py 몫.
    """
    ac = automaton if automaton is not None else _get_default_automaton()

    if len(ac) == 0:
        # pyahocorasick 은 단어가 0개인 상태에서 make_automaton() 을 호출해도
        # 정상적으로 AHOCORASICK 상태로 전환되지 않는 케이스가 있다 (빈 사전 파일 등).
        # iter() 호출 시 AttributeError 가 나므로 여기서 미리 빈 리스트로 반환한다.
        return []

    spans: list[Span] = []
    for end_index, (type_, confidence, term_len) in ac.iter(text):
        start = end_index - term_len + 1
        spans.append(
            Span(
                type=type_,
                value=text[start : end_index + 1],
                start=start,
                end=end_index + 1,
                confidence=confidence,
                source="dict",
            )
        )
    return spans