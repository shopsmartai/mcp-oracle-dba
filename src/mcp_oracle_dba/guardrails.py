"""
SQL guardrails for the Oracle MCP server.

The threat model: an LLM (or a careless user) could send arbitrary SQL
through `run_select`. Even with a read-only DB user, we want defense
in depth — block obvious destructive intent, multi-statement injection,
and dangerous package calls before they reach Oracle.

Rules enforced:
  1. Exactly one statement (no `; DROP TABLE` chained injections)
  2. First token must be SELECT or WITH
  3. Banned keywords list (INSERT/UPDATE/DELETE/MERGE/DDL/EXECUTE/BEGIN)
  4. Block DBMS_*, UTL_*, SYS. package calls (DBMS_LOCK.sleep, etc.)
  5. Wrap the query in FETCH FIRST :N ROWS ONLY to cap rows
  6. Statement timeout enforced separately by the oracledb client

The guardrails ALONE are not sufficient — they're one layer of defense.
The DB user (`mcp_ro`) is also restricted at the privilege level, and
the audit log records every call for review.
"""
from __future__ import annotations

import re

import sqlparse


class SqlGuardError(Exception):
    """Raised when a SQL string fails guardrail validation."""


BANNED_KEYWORDS = {
    # DML
    "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE",
    # DDL
    "DROP", "CREATE", "ALTER", "RENAME",
    # Privilege
    "GRANT", "REVOKE",
    # PL/SQL blocks
    "BEGIN", "DECLARE", "CALL", "EXECUTE", "EXEC",
    # Transaction control (read-only user can't but defense in depth)
    "COMMIT", "ROLLBACK", "SAVEPOINT",
    # Session-altering — could escalate privilege or change behavior
    "LOCK", "FLASHBACK",
}

# Packages that can execute commands, manipulate state, or read files
DANGEROUS_PACKAGE_RE = re.compile(
    r"\b(DBMS_[A-Z_]+|UTL_[A-Z_]+|SYS\.)", re.IGNORECASE
)


def validate_select(sql: str, max_rows: int = 100) -> str:
    """Validate `sql` and return a row-capped version.

    Raises SqlGuardError on any rule violation.
    """
    if not sql or not sql.strip():
        raise SqlGuardError("Empty SQL")

    stripped = sql.strip().rstrip(";").strip()
    if ";" in stripped:
        raise SqlGuardError("Multiple statements not allowed")

    parsed = sqlparse.parse(stripped)
    if len(parsed) != 1:
        raise SqlGuardError("Exactly one statement required")

    stmt = parsed[0]
    first_token = next((t for t in stmt.tokens if not t.is_whitespace), None)
    if first_token is None:
        raise SqlGuardError("Could not parse statement")

    first_val = first_token.value.upper().strip()
    # Accept SELECT or WITH as the first keyword. We rely on the
    # value check here rather than sqlparse's token-type taxonomy
    # because sqlparse tags CTEs as Keyword.CTE (different ttype
    # path from DML), and being too strict on ttype rejects valid
    # WITH ... SELECT queries. The OTHER guardrails (banned-keyword
    # scan, dangerous-package regex, single-statement check) catch
    # anything dangerous that slips past this first-token check.
    if first_val not in {"SELECT", "WITH"}:
        raise SqlGuardError(
            f"Only SELECT and WITH allowed; got: {first_val[:20]}"
        )

    upper = stripped.upper()
    for kw in BANNED_KEYWORDS:
        if re.search(rf"\b{kw}\b", upper):
            raise SqlGuardError(f"Banned keyword in SQL: {kw}")

    m = DANGEROUS_PACKAGE_RE.search(stripped)
    if m:
        raise SqlGuardError(
            f"Calls to {m.group(1)}* are not allowed via MCP run_select"
        )

    # Defensive row cap. Even if the LLM forgot LIMIT, we enforce one.
    return f"SELECT * FROM ({stripped}) FETCH FIRST {max_rows} ROWS ONLY"


def redact_pii_columns(rows: list[dict], denylist: list[str]) -> list[dict]:
    """Replace values in any column whose name matches a denylist substring."""
    if not rows or not denylist:
        return rows
    deny_upper = [d.upper() for d in denylist]
    out = []
    for r in rows:
        out.append({
            k: ("[REDACTED]" if any(d in k.upper() for d in deny_upper) else v)
            for k, v in r.items()
        })
    return out
