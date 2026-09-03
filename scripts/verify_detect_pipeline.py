"""
scripts/verify_detect_pipeline.py

app.detect.detect(text)를 직접 호출해서 regex + dict + ner 세 레이어가
병합된 최종 Span 결과를 확인한다. gRPC/FastAPI를 안 띄우고도 탐지
파이프라인만 빠르게 검증하기 위한 용도. DB 연결도 필요 없다
(app.detect는 db.py를 안 건드림).

실행 (dlp-server 프로젝트 루트, venv 활성화된 상태에서):
    python scripts/verify_detect_pipeline.py
    python scripts/verify_detect_pipeline.py --file eval/datasets/benign/other.jsonl

기본으로 eval/datasets/benign/benign_financial_conversations.jsonl 을 읽어서
전부 detect() 에 태우고, 스팬이 하나라도 잡힌 문장(= 잠재 오탐 후보)만
따로 모아 보여준다. benign 데이터셋이므로 이상적으로는 전부 빈 결과여야
하고, 뭔가 잡히면 그게 진짜 정탐인지(예: "신용등급"이라는 단어 자체를
정책적으로 걸러야 하는지) 오탐인지 문장 단위로 판단해야 한다.

main.py와 동일하게 config.yaml 값으로 NER 엔진을 preload한 뒤 실행하므로,
실제 서버가 뜬 상태와 같은 조건에서 병합 결과를 볼 수 있다.

정식 run_eval.py(Phase 6, baseline vs full 비교)는 attack/multiturn
데이터셋이 채워진 뒤에 별도로 만든다 — 이 스크립트는 그 전 단계의
빠른 수동 확인용.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# scripts/ 밑에서 실행돼도 app 패키지를 import할 수 있도록 프로젝트 루트를
# sys.path에 추가한다. 호출 방식(python scripts/x.py 든 다른 cwd에서든)에
# 안 흔들리게 하려고 -m 대신 이 방식을 씀.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import load_config
from app.detect import detect
from app.detect.ner import get_ner_engine

DEFAULT_DATASET = "eval/datasets/benign/benign_financial_conversations.jsonl"

# main.py와 동일한 순서: config 로드 -> NER 엔진 preload
cfg = load_config()
print(f"[*] NER 모델 워밍업: {cfg.detect.ner_model_name} (threshold={cfg.detect.ner_threshold})")
get_ner_engine(
    model_name=cfg.detect.ner_model_name,
    threshold=cfg.detect.ner_threshold,
).preload()
print("[*] 워밍업 완료\n")

def load_dataset(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[!] {path}:{line_no} JSON 파싱 실패 — 건너뜀 ({e})")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        default=DEFAULT_DATASET,
        help=f"jsonl 데이터셋 경로 (기본: {DEFAULT_DATASET})",
    )
    args = parser.parse_args()

    dataset_path = Path(args.file)
    if not dataset_path.is_absolute():
        dataset_path = Path(__file__).resolve().parent.parent / dataset_path

    if not dataset_path.exists():
        print(f"[!] 데이터셋 파일을 찾을 수 없음: {dataset_path}")
        sys.exit(1)

    rows = load_dataset(dataset_path)
    print(f"[*] 데이터셋 로드: {dataset_path} ({len(rows)}건)\n")

    print("=" * 70)
    flagged: list[tuple[dict, list]] = []
    for row in rows:
        text = row.get("text", "")
        spans = detect(text)
        if spans:
            flagged.append((row, spans))

    # ---- 요약 ----
    total = len(rows)
    n_flagged = len(flagged)
    print(f"\n총 {total}건 중 {n_flagged}건에서 스팬 탐지됨 "
          f"(benign 데이터셋이므로 이 {n_flagged}건이 오탐 후보)\n")

    if not flagged:
        print("전부 빈 결과 — 이번 threshold/라벨 조합에서는 오탐 없음.")
    else:
        for row, spans in flagged:
            print(f"[{row.get('id', '?')}] ({row.get('category', '?')}) {row.get('text', '')!r}")
            if row.get("notes"):
                print(f"  note: {row['notes']}")
            for s in sorted(spans, key=lambda x: x.start):
                print(
                    f"  -> [{s.type}] \"{s.value}\" ({s.start}-{s.end}) "
                    f"conf={s.confidence:.2f} source={s.source}"
                )
            print()

    print("=" * 70)
    print(f"""
판단 기준:
  - notes에 "오탐 재현 케이스"라고 적힌 문장이 여기 걸렸다면 -> 아직 안 고쳐진 것.
  - notes 없는 문장인데 걸렸다면 -> 새로운 오탐 패턴 발견. threshold/라벨 재검토 필요.
  - "credit_term_generic" 카테고리가 걸렸다면 -> threshold 문제가 아니라 라벨 문구
    자체("신용등급" 같은 단어가 나오기만 해도 매칭)를 손봐야 할 가능성 높음.

오탐률 = {n_flagged}/{total} = {(n_flagged / total * 100) if total else 0:.1f}%
""")


if __name__ == "__main__":
    main()