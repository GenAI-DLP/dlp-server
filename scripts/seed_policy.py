"""
app/policy/policy.yaml 을 PostgreSQL 정책 테이블에 적재한다 (기능 f 부트스트랩).

사용법:
    python scripts/seed_policy.py [--dsn DSN] [--file PATH] [--reset]

기본 동작: 활성 정책 버전이 이미 있으면 거부한다(중복 시드 방지).
    --reset : policy_versions / policy_rules / policy_risk_overrides 를 비우고 다시 적재.

컬럼 매핑:
    rules[*]          -> policy_rules            ("*" / 키 누락 = NULL 와일드카드)
    defaults.action   -> policy_rules 한 줄      (purpose=role=entity=NULL, priority=-1 최저)
    risk_overrides[*] -> policy_risk_overrides

DSN 우선순위: --dsn > 환경변수 DLP_DB__DSN > postgresql://dlp:dlp@localhost:5432/dlp
SSOT: docs/schemas/dlp-server/policy.md
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import psycopg
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILE = ROOT / "app" / "policy" / "policy.yaml"
DEFAULT_DSN = "postgresql://dlp:dlp@localhost:5432/dlp"

_WILDCARD = {None, "", "*"}


def load_spec(path: Path | str = DEFAULT_FILE) -> dict[str, Any]:
    """policy.yaml 을 파싱해 dict 로 돌려준다."""
    with Path(path).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _norm(value: Any) -> Any:
    """와일드카드 표기('*', '', 누락)를 SQL NULL 로."""
    return None if value in _WILDCARD else value


def seed(conn: psycopg.Connection, spec: dict[str, Any], *, description: str = "bootstrap") -> int:
    """spec 을 새 정책 버전으로 적재하고 활성화한다. 반환값은 policy_version_id."""
    with conn.transaction():
        conn.execute("UPDATE policy_versions SET is_active = false WHERE is_active")
        version_id = conn.execute(
            "INSERT INTO policy_versions (description, is_active, created_by) "
            "VALUES (%s, true, %s) RETURNING policy_version_id",
            (description, "seed_policy.py"),
        ).fetchone()[0]

        for rule in spec.get("rules", []):
            conn.execute(
                "INSERT INTO policy_rules "
                "(policy_version_id, purpose, role, entity_type, action, priority) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    version_id,
                    _norm(rule.get("purpose")),
                    _norm(rule.get("role")),
                    _norm(rule.get("entity")),
                    rule["action"],
                    int(rule.get("priority", 0)),
                ),
            )

        default_action = (spec.get("defaults") or {}).get("action")
        if default_action:
            conn.execute(
                "INSERT INTO policy_rules "
                "(policy_version_id, purpose, role, entity_type, action, priority) "
                "VALUES (%s, NULL, NULL, NULL, %s, -1)",
                (version_id, default_action),
            )

        for ov in spec.get("risk_overrides", []):
            conn.execute(
                "INSERT INTO policy_risk_overrides "
                "(policy_version_id, condition_expr, action, priority) "
                "VALUES (%s, %s, %s, %s)",
                (version_id, ov["when"], ov["action"], int(ov.get("priority", 100))),
            )

    return version_id


def main() -> None:
    parser = argparse.ArgumentParser(description="policy.yaml 을 DB 에 적재")
    parser.add_argument("--dsn", default=os.environ.get("DLP_DB__DSN", DEFAULT_DSN))
    parser.add_argument("--file", default=str(DEFAULT_FILE))
    parser.add_argument("--reset", action="store_true", help="정책 테이블을 비우고 다시 적재")
    args = parser.parse_args()

    spec = load_spec(args.file)

    with psycopg.connect(args.dsn) as conn:
        if args.reset:
            conn.execute(
                "TRUNCATE policy_versions, policy_rules, policy_risk_overrides "
                "RESTART IDENTITY CASCADE"
            )
            conn.commit()
        elif conn.execute("SELECT 1 FROM policy_versions WHERE is_active LIMIT 1").fetchone():
            print(
                "[seed_policy] 거부: 활성 정책 버전이 이미 있습니다. --reset 을 쓰세요.",
                file=sys.stderr,
            )
            sys.exit(2)

        version_id = seed(conn, spec)
        conn.commit()

    n_rules = len(spec.get("rules", [])) + (1 if (spec.get("defaults") or {}).get("action") else 0)
    n_ov = len(spec.get("risk_overrides", []))
    print(f"[seed_policy] 버전 {version_id} 활성화 — 규칙 {n_rules}개, 오버라이드 {n_ov}개")


if __name__ == "__main__":
    main()
