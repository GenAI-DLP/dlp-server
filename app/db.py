"""
PostgreSQL 커넥션 풀

psycopg3 sync + psycopg_pool.ConnectionPool. 풀은 최초 사용 시 lazy 생성되며
(DB 를 쓰지 않는 테스트는 연결하지 않는다), 프로세스 종료 시 close() 로 정리한다.

"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager

from psycopg import Connection
from psycopg_pool import ConnectionPool

from .config import Config, load_config

logger = logging.getLogger(__name__)

_pool: ConnectionPool | None = None


def pool(config: Config | None = None) -> ConnectionPool:
    """공유 커넥션 풀. 없으면 config 기준으로 생성한다."""
    global _pool
    if _pool is None:
        cfg = config or load_config()
        _pool = ConnectionPool(
            cfg.db.dsn,
            min_size=cfg.db.pool_min,
            max_size=cfg.db.pool_max,
            open=True,
        )
        logger.info("DB 풀 생성: %s", _redact(cfg.db.dsn))
    return _pool


@contextmanager
def connection() -> Iterator[Connection]:
    """풀에서 커넥션 하나를 빌린다. with 블록을 나가면 반납된다."""
    with pool().connection() as conn:
        yield conn


def close() -> None:
    """풀을 닫는다. 프로세스 종료 시 호출. 풀이 없으면 no-op."""
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
        logger.info("DB 풀 종료")


def _redact(dsn: str) -> str:
    """로그용 — DSN 에서 비밀번호를 가린다."""
    dsn = re.sub(r"(://[^:/@]+:)[^@]+(@)", r"\1***\2", dsn)
    dsn = re.sub(r"(password=)\S+", r"\1***", dsn)
    return dsn
