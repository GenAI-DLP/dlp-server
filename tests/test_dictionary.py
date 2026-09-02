"""tests/test_dictionary.py — detect/dictionary.py 단위 테스트."""

import ahocorasick
import pytest

from app.detect.dictionary import detect, load_dictionary


@pytest.fixture
def small_automaton(tmp_path):
    dict_file = tmp_path / "terms.txt"
    dict_file.write_text(
        "\n".join(
            [
                "# comment line",
                "김민준\tNAME\t0.55",
                "신용등급\tCREDIT_INFO\t0.7",
                "가\tNAME\t0.9",  # 1자 -> 로딩 시 스킵되어야 함
            ]
        ),
        encoding="utf-8",
    )
    return load_dictionary(dict_file)


def test_matches_known_term(small_automaton):
    text = "고객 김민준님의 신용등급을 확인해주세요."
    spans = detect(text, automaton=small_automaton)
    types = {s.type for s in spans}
    assert "NAME" in types
    assert "CREDIT_INFO" in types


def test_span_boundaries_correct(small_automaton):
    text = "고객 김민준님"
    spans = detect(text, automaton=small_automaton)
    name_span = next(s for s in spans if s.type == "NAME")
    assert text[name_span.start : name_span.end] == "김민준"
    assert name_span.value == "김민준"


def test_short_term_skipped_on_load(small_automaton):
    # '가' 는 1자라 로딩 시 스킵되어야 하므로, '가'만 있는 문장에서 매치가 없어야 함
    text = "가나다라"
    spans = detect(text, automaton=small_automaton)
    assert spans == []


def test_no_match_returns_empty(small_automaton):
    text = "오늘 날씨가 좋네요."
    spans = detect(text, automaton=small_automaton)
    assert spans == []


def test_missing_dict_file_returns_empty_automaton(tmp_path):
    missing = tmp_path / "does_not_exist.txt"
    automaton = load_dictionary(missing)
    assert isinstance(automaton, ahocorasick.Automaton)
    spans = detect("김민준", automaton=automaton)
    assert spans == []


def test_malformed_line_skipped(tmp_path):
    dict_file = tmp_path / "terms.txt"
    dict_file.write_text(
        "\n".join(
            [
                "잘못된줄인데탭없음",
                "정상용어\tNAME\t0.6",
            ]
        ),
        encoding="utf-8",
    )
    automaton = load_dictionary(dict_file)
    spans = detect("정상용어 테스트", automaton=automaton)
    assert len(spans) == 1
    assert spans[0].value == "정상용어"
