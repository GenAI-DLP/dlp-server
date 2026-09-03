"""
test_detect_pipeline.py (임시 검증용 — 리포에 커밋 안 해도 됨)

app.detect.detect(text)를 직접 호출해서 regex + dict + ner 세 레이어가
병합된 최종 Span 결과를 확인한다. gRPC/FastAPI를 안 띄우고도 탐지
파이프라인만 빠르게 검증하기 위한 용도. DB 연결도 필요 없다
(app.detect는 db.py를 안 건드림).

실행 (dlp-server 프로젝트 루트, venv 활성화된 상태에서):
    python test_detect_pipeline.py

main.py와 동일하게 config.yaml 값으로 NER 엔진을 preload한 뒤 실행하므로,
실제 서버가 뜬 상태와 같은 조건에서 병합 결과를 볼 수 있다.
"""

from __future__ import annotations

from app.config import load_config
from app.detect import detect
from app.detect.ner import get_ner_engine

# main.py와 동일한 순서: config 로드 -> NER 엔진 preload
cfg = load_config()
print(f"[*] NER 모델 워밍업: {cfg.detect.ner_model_name} (threshold={cfg.detect.ner_threshold})")
get_ner_engine(
    model_name=cfg.detect.ner_model_name,
    threshold=cfg.detect.ner_threshold,
).preload()
print("[*] 워밍업 완료\n")

TEST_SENTENCES = [
    "홍길동 고객님은 서울시 강남구 테헤란로에 거주하시고, 현재 3개월 연체 상태입니다.",
    "김철수 고객의 대출 잔액은 5천만원이고 신용등급은 4등급으로 확인됩니다.",
    "이영희 씨가 소속된 (주)한빛전자에서 근무 중이며, 최근 카드 연체 이력이 있습니다.",
    "박민수 고객님, 신용등급이 7등급으로 하락했고 대출 잔액이 1억 2천만원입니다.",
    "이 건은 내부 프로젝트 '프로젝트 오로라'와 관련된 고객 최지훈님의 문의입니다.",
    # regex 레이어 확인용 — RRN/전화/이메일이 NER과 안 겹치고 잘 잡히는지
    "고객님 전화번호는 010-1234-5678이고 이메일은 hong@example.com 입니다.",
]

print("=" * 70)
for sent in TEST_SENTENCES:
    spans = detect(sent)
    print(f"\n문장: {sent}")
    if not spans:
        print("  (탐지 결과 없음)")
    for s in sorted(spans, key=lambda x: x.start):
        print(
            f'  [{s.type}] "{s.value}" ({s.start}-{s.end}) '
            f"conf={s.confidence:.2f} source={s.source}"
        )
print("\n" + "=" * 70)
print("""
확인 포인트:
  1. 이름(NAME)이 NER에서만 잡히고 source가 "ner"로 나오는가?
     -> regex/dict는 이름 규칙이 없으므로 이게 정상.
  2. 신용정보(CREDIT_INFO)가 살아남았는가?
     -> merge.py의 min_confidence["ner"]=0.4 통과 여부 확인.
  3. 전화번호/이메일이 NER 결과와 겹칠 때 source가 "regex"로 채택되는가?
     -> merge.py SOURCE_PRIORITY(regex > dict > ner)가 의도대로 동작하는지.
  4. 겹치는 구간에서 값(value)이 이상하게 잘리거나 합쳐지지 않았는가?
     -> _resolve_cluster()가 canonical span의 start/end를 그대로 쓰므로,
        NER 쪽 트리밍(조사 제거)이 이미 반영된 상태로 나와야 정상.
""")
