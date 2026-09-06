"""
migrations/ 폴더 아래 .sql 파일을 파일명 순서대로 적용한다.
각 파일은 멱등(ON CONFLICT DO NOTHING 등)하게 작성되어 있어 재실행해도 안전하다.
DLP_DB__DSN 환경변수를 사용한다 (apply_schema.py와 동일).

사용법:
    python scripts/run_migrations.py                # 기본 경로: db/migrations
    python scripts/run_migrations.py --dir path/to/migrations
"""
import argparse
import glob
import os
import sys

import psycopg2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="db/migrations", help="마이그레이션 SQL 폴더 경로")
    args = parser.parse_args()

    dsn = os.environ.get("DLP_DB__DSN")
    if not dsn:
        print("[run_migrations] DLP_DB__DSN 환경변수가 없습니다.", file=sys.stderr)
        sys.exit(1)

    files = sorted(glob.glob(os.path.join(args.dir, "*.sql")))
    if not files:
        print(f"[run_migrations] 적용할 파일 없음: {args.dir}")
        return

    conn = psycopg2.connect(dsn)
    try:
        cur = conn.cursor()
        for path in files:
            print(f"[run_migrations] applying {path}")
            with open(path, encoding="utf-8") as f:
                cur.execute(f.read())
            conn.commit()
        print(f"[run_migrations] 완료: {len(files)}개 파일 적용")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
