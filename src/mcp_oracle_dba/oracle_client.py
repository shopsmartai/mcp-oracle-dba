"""
Oracle connection helper for the MCP server.

Uses a single-connection-per-tool-call pattern (not a long-lived pool)
because MCP requests are sparse and connection setup cost is low. If
volume grows, swap in oracledb.create_pool().

`call_timeout` enforces server-side statement timeout in milliseconds —
matches the `MCP_STATEMENT_TIMEOUT_SECONDS` setting.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import oracledb

from .config import settings


def connect() -> oracledb.Connection:
    s = settings()
    conn = oracledb.connect(user=s.ora_user, password=s.ora_password, dsn=s.ora_dsn)
    conn.call_timeout = s.statement_timeout_seconds * 1000
    return conn


@contextmanager
def cursor() -> Iterator[oracledb.Cursor]:
    conn = connect()
    try:
        cur = conn.cursor()
        try:
            yield cur
        finally:
            cur.close()
    finally:
        conn.close()


def rows_to_dicts(cur: oracledb.Cursor) -> list[dict]:
    """Fetch all rows from `cur` and return as list of column-name dicts."""
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]
