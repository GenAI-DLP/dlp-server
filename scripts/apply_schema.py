"""
db/schema.sql 을 대상 PostgreSQL DB 에 적용한다.

사용법:
    python scripts/apply_schema.py [--dsn DSN] [--keep] [--force]

기본 동작: DROP SCHEMA public CASCADE 후 db/schema.sql 재적용 (개발용 리셋).
    --keep : DROP 생략, 스키마만 재실행 (누적 적용 확인용)
    --force: 안전 DB 이름 가드(dlp / dlp_test) 무시

DSN 우선순위: --dsn > 환경변수 DLP_DB_DSN > postgresql://dlp:dlp@localhost:5432/dlp
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "db" / "schema.sql"
SAFE_DBS = {"dlp", "dlp_test"}
DEFAULT_DSN = "postgresql://dlp:dlp@localhost:5432/dlp"


def main() -> None:
    parser = argparse.ArgumentParser(description="db/schema.sql 을 대상 DB 에 적용")
    parser.add_argument("--dsn", default=os.environ.get("DLP_DB_DSN", DEFAULT_DSN))
    parser.add_argument("--keep", action="store_true", help="DROP SCHEMA 를 생략한다")
    parser.add_argument("--force", action="store_true", help="안전 DB 이름 가드를 무시한다")
    args = parser.parse_args()

    if not SCHEMA.exists():
        print(f"[apply_schema] {SCHEMA} 가 없습니다.", file=sys.stderr)
        sys.exit(1)

    dbname = conninfo_to_dict(args.dsn).get("dbname", "")
    if not args.keep and not args.force and dbname not in SAFE_DBS:
        print(
            f"[apply_schema] 거부: DB '{dbname}' 은 {sorted(SAFE_DBS)} 가 아닙니다. "
            "DROP SCHEMA 는 그 DB 의 모든 객체를 지웁니다. "
            "--force 로 강제하거나 --keep 을 쓰세요.",
            file=sys.stderr,
        )
        sys.exit(2)

    sql = SCHEMA.read_text(encoding="utf-8")
    with psycopg.connect(args.dsn, autocommit=True) as conn:
        if not args.keep:
            conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            print("[apply_schema] DROP SCHEMA public CASCADE 완료")
        conn.execute(sql)
    print(f"[apply_schema] 적용 완료: {dbname or args.dsn}")


if __name__ == "__main__":
    main()
