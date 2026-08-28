"""
Input Guard (기능 c 입력측) — 외부 LLM 요청에서 프롬프트 인젝션·탈옥·반출 의도를 규칙으로 탐지한다.

요청 파이프라인의 첫 스테이지다. 이번 요청의 마지막 사용자 입력만 보는 무상태 판정이며,
적중하면 컨텍스트에 차단 신호를 세팅해 파이프라인이 조기에 block 하도록 한다.
PII 자체 처리(마스킹·토큰화)나 여러 턴에 걸친 누적 분석은 여기서 다루지 않는다.

정규식 규칙이 기본 구현이다. 교체 가능한 소형 분류 모델은 이후 단계에서 _engine 을 바꿔 끼운다

fail-safe: scan 내부 오류는 예외를 전파하지 않고 hit=False 로 처리한다. 가드레일 결함이
정상 요청까지 막지 않게 하려는 것이며, PII 보호는 탐지·정책·변환 스테이지가 따로 수행한다.
예기치 못한 예외는 pipeline.analyze() 의 상위 처리기가 fail_action 으로 잡는다.

근거: docs/architecture/dlp-server-architecture.md §3.1
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from app.config import load_config
from app.models import AnalysisContext, InjectionVerdict, Turn

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rule:
    """패턴 규칙 하나.

    name 은 '<category>.<슬러그>' 형식이며 적중 시 이 값만 근거로 남긴다
    (사용자 입력 원문은 감사 로그·근거에 절대 넣지 않는다).
    """

    name: str
    category: str
    score: float
    regex: re.Pattern


# (name, category, score, 정규식) — 한국어·영어.
# 단어 단독이 아니라 구(句) 단위로 매칭하고, "지시 / 고객" 같은 대상 명사를 앵커로 두어
# 정상 업무 문장("이전 버전은 무시하고 정리해줘" 등)의 오탐을 줄인다.
_RAW_RULES: list[tuple[str, str, float, str]] = [
    # instruction_override — 앞선 지시를 무효화하려는 시도
    (
        "instruction_override.ignore_prior_ko",
        "instruction_override",
        0.9,
        r"(이전|이제까지|지금까지|그동안|앞선|기존|위|모든)\s*.{0,8}"
        r"(지시|명령|지침|규칙|안내|프롬프트|설정)\s*.{0,12}(무시|잊|따르지\s*마|신경\s*쓰지\s*마)",
    ),
    (
        "instruction_override.ignore_prior_en",
        "instruction_override",
        0.9,
        r"ignore\s+(all\s+|any\s+)?(previous|prior|earlier|above|the\s+above)\s+"
        r"(instruction|prompt|message|rule|direction|context)s?",
    ),
    (
        "instruction_override.disregard_en",
        "instruction_override",
        0.9,
        r"(disregard|forget)\s+(all\s+|the\s+|everything\s+)?(above|previous|prior|earlier)\b",
    ),
    # jailbreak — 제약 없는 페르소나로 전환하거나 안전장치 해제를 요구
    (
        "jailbreak.dan",
        "jailbreak",
        0.8,
        r"(you\s+are\s+(now\s+)?dan\b|\bdan\b.{0,20}(mode|jailbreak|모드))",
    ),
    ("jailbreak.dev_mode", "jailbreak", 0.8, r"(개발자\s*모드|developer\s+mode|dev\s+mode)"),
    (
        "jailbreak.no_limits_en",
        "jailbreak",
        0.8,
        r"(no\s+restrictions?|without\s+(any\s+)?restrictions?|no\s+longer\s+bound|"
        r"ignore\s+(your\s+)?(safety|guidelines?|policy))",
    ),
    ("jailbreak.pretend_en", "jailbreak", 0.75, r"pretend\s+(you\s+are|to\s+be)\b"),
    # system_prompt_leak — 시스템 프롬프트·지침 노출 유도
    (
        "system_prompt_leak.reveal_ko",
        "system_prompt_leak",
        0.8,
        r"(위|시스템|이전|당신의)\s*.{0,6}(규칙|프롬프트|지침|instruction)\s*.{0,12}"
        r"(그대로|출력|보여|알려|말해)",
    ),
    (
        "system_prompt_leak.print_en",
        "system_prompt_leak",
        0.8,
        r"(print|show|reveal|repeat|display)\s+(me\s+)?(your\s+)?(system\s+)?"
        r"(prompt|instructions?|rules?)",
    ),
    (
        "system_prompt_leak.whatare_en",
        "system_prompt_leak",
        0.8,
        r"what\s+(is|are)\s+your\s+(initial\s+|original\s+|system\s+)?"
        r"(instruction|prompt|rule|directive)s?",
    ),
    # bulk_exfiltration — 대량 데이터 반출 요구. 데이터 대상 명사를 앵커로 둔다.
    (
        "bulk_exfiltration.all_records_ko",
        "bulk_exfiltration",
        0.85,
        r"(전체|모든|모두|전\s?직원|전\s?고객)\s*.{0,6}"
        r"(고객|사용자|회원|계정|직원|이메일|전화번호|주민(등록)?번호|계좌)\s*.{0,12}"
        r"(목록|나열|출력|덤프|csv|엑셀|내보내|추출)",
    ),
    (
        "bulk_exfiltration.all_records_en",
        "bulk_exfiltration",
        0.85,
        r"(list|dump|export|show|give\s+me)\s+(all|every|the\s+entire)\s+"
        r"(customer|user|account|employee|client|record|email|phone)s?\b",
    ),
    ("bulk_exfiltration.select_star", "bulk_exfiltration", 0.85, r"select\s+\*\s+from\s+\w"),
    # role_manipulation — 사용자 턴에서 system 역할을 사칭하거나 역할을 재정의
    (
        "role_manipulation.you_are_now_en",
        "role_manipulation",
        0.7,
        r"(you\s+are\s+now\s+(a|an|the|my|going|allowed|able|permitted|free|unrestricted|"
        r"operating|running)\b|from\s+now\s+on,?\s+you\s+(are|will|must|should\s+act))",
    ),
    (
        "role_manipulation.you_are_now_ko",
        "role_manipulation",
        0.7,
        r"(이제부터|지금부터|앞으로)\s*.{0,4}(너는|넌|당신은|당신이|네가)",
    ),
    (
        "role_manipulation.fake_system",
        "role_manipulation",
        0.7,
        r"((^|\n)\s*(system|시스템)\s*[:：]|<\s*/?\s*system\s*>)",
    ),
]

DEFAULT_RULES: list[Rule] = [
    Rule(name=n, category=c, score=s, regex=re.compile(src, re.IGNORECASE))
    for (n, c, s, src) in _RAW_RULES
]


class RuleEngine:
    """정규식 규칙 기반 Input Guard.

    규칙을 순회해 매칭된 것 중 가장 높은 score 를 채택한다. 이후 소형 분류 모델로
    바꿔 끼울 교체 지점이다(모듈 하단 _engine).
    """

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = DEFAULT_RULES if rules is None else rules

    def scan(self, text: str, *, threshold: float) -> InjectionVerdict:
        best_score = 0.0
        best_name: str | None = None
        for rule in self._rules:
            try:
                matched = rule.regex.search(text) is not None
            except Exception:  # 규칙 하나가 터져도 나머지는 계속 본다
                logger.exception("injection 규칙 평가 실패: %s", rule.name)
                continue
            if matched and rule.score > best_score:
                best_score = rule.score
                best_name = rule.name
        return InjectionVerdict(
            hit=best_score >= threshold,
            score=best_score,
            pattern=best_name if best_score >= threshold else None,
        )


_engine: RuleEngine = RuleEngine()

# injection_threshold 를 매 요청 config 로드 없이 재사용. 테스트는 이 값을 직접 덮어써 초기화한다.
_threshold_cache: float | None = None


def _threshold() -> float:
    global _threshold_cache
    if _threshold_cache is None:
        _threshold_cache = float(load_config().guardrail.injection_threshold)
    return _threshold_cache


def scan(text: str, *, threshold: float | None = None) -> InjectionVerdict:
    """단일 텍스트를 판정한다.

    threshold 를 주지 않으면 설정값을 쓴다. 내부 오류 시 예외를 던지지 않고
    hit=False 를 반환한다(가드레일 결함이 정상 요청을 막지 않도록).
    """
    try:
        thr = _threshold() if threshold is None else threshold
        return _engine.scan(text, threshold=thr)
    except Exception:
        logger.exception("injection.scan 실패 — hit=False 로 통과 처리")
        return InjectionVerdict(hit=False, score=0.0, pattern=None)


def _last_user_text(turns: list[Turn]) -> str | None:
    for turn in reversed(turns):
        if turn.role == "user":
            return turn.text
    return None


def injection_guard(ctx: AnalysisContext) -> AnalysisContext:
    """파이프라인 스테이지.

    마지막 사용자 턴을 scan 해 ctx.injection 을 갱신한다. 적중 시 ctx.blocked /
    ctx.block_reason 도 세팅해 이후 입력 스테이지를 건너뛰게 한다. 사용자 턴이 없으면
    아무것도 하지 않는다.
    """
    text = _last_user_text(ctx.turns)
    if not text:
        return ctx
    verdict = scan(text)
    ctx.injection = verdict
    if verdict.hit:
        ctx.blocked = True
        ctx.block_reason = {"type": "injection", "pattern": verdict.pattern}
    return ctx
