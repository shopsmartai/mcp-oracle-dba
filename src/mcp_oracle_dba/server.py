"""
MCP server entry point. Exposes Oracle read tools via the Model
Context Protocol so any MCP client (Claude Desktop, Claude Code,
Cursor, etc.) can safely query the database.

Tools exposed:
  - list_schemas       : the allowlist of schemas the MCP user can query
  - describe_table     : column metadata for SCHEMA.TABLE
  - run_select         : guarded SELECT, row-capped + PII-redacted
  - explain_plan       : Oracle EXPLAIN PLAN for a SELECT
  - top_sql            : top SQL by elapsed time from v$sql (last N minutes)

Run:
    uv run mcp-oracle-dba

Or hook into Claude Desktop via ~/.config/claude/claude_desktop_config.json:
    {
      "mcpServers": {
        "oracle-dba": {
          "command": "uvx",
          "args": ["--from", "/abs/path/to/mcp-oracle-dba", "mcp-oracle-dba"],
          "env": {"ORA_PASSWORD": "..."}
        }
      }
    }
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from mcp.server.fastmcp import FastMCP

from .config import settings
from .guardrails import SqlGuardError, redact_pii_columns, validate_select
from .oracle_client import cursor, rows_to_dicts


cfg = settings()

# ─── Audit logger ────────────────────────────────────────────────────
audit = logging.getLogger("mcp-oracle-dba.audit")
audit.setLevel(logging.INFO)
_handler = logging.FileHandler(cfg.audit_log)
_handler.setFormatter(logging.Formatter("%(message)s"))
audit.addHandler(_handler)


def _audit(tool: str, payload: dict) -> None:
    audit.info(json.dumps({
        "ts": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "tool": tool,
        **payload,
    }))


# ─── MCP server ──────────────────────────────────────────────────────
mcp = FastMCP("oracle-dba")


@mcp.tool()
def list_schemas() -> list[str]:
    """List schemas the MCP server is allowed to query.

    Schemas are configured via MCP_SCHEMA_ALLOWLIST. This is a
    metadata tool — no DB call required.
    """
    _audit("list_schemas", {})
    return cfg.schema_allowlist


@mcp.tool()
def describe_table(schema: str, table: str) -> list[dict]:
    """Return column metadata for SCHEMA.TABLE.

    Errors if `schema` is not in the configured allowlist.
    """
    if schema.upper() not in [s.upper() for s in cfg.schema_allowlist]:
        raise ValueError(
            f"Schema {schema!r} is not in the allowlist: "
            f"{cfg.schema_allowlist}"
        )
    _audit("describe_table", {"schema": schema, "table": table})
    with cursor() as cur:
        cur.execute("""
            SELECT column_name, data_type, data_length, nullable, column_id
              FROM all_tab_columns
             WHERE owner = :o AND table_name = :t
             ORDER BY column_id
        """, o=schema.upper(), t=table.upper())
        return rows_to_dicts(cur)


@mcp.tool()
def run_select(sql: str) -> list[dict]:
    """Run a SELECT or WITH query against Oracle.

    Guardrails:
      - Only SELECT / WITH statements allowed
      - DDL, DML, PL/SQL blocks, DBMS_/UTL_/SYS. calls are rejected
      - Result row count is capped (see MCP_MAX_ROWS)
      - PII-named columns (SSN, SALARY, PASSWORD, …) are auto-redacted
      - Server-side statement timeout enforced

    Returns a list of column-name dicts.
    """
    try:
        safe_sql = validate_select(sql, max_rows=cfg.max_rows)
    except SqlGuardError as e:
        _audit("run_select", {"sql": sql, "rejected": str(e)})
        raise ValueError(f"SQL rejected: {e}") from e

    _audit("run_select", {"sql": sql})
    with cursor() as cur:
        cur.execute(safe_sql)
        rows = rows_to_dicts(cur)
    return redact_pii_columns(rows, cfg.column_denylist)


@mcp.tool()
def explain_plan(sql: str) -> str:
    """Return Oracle EXPLAIN PLAN output for a SELECT query."""
    try:
        validate_select(sql, max_rows=cfg.max_rows)
    except SqlGuardError as e:
        _audit("explain_plan", {"sql": sql, "rejected": str(e)})
        raise ValueError(f"SQL rejected: {e}") from e

    _audit("explain_plan", {"sql": sql})
    with cursor() as cur:
        cur.execute(f"EXPLAIN PLAN FOR {sql.strip().rstrip(';')}")
        cur.execute(
            "SELECT plan_table_output "
            "  FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, NULL, 'ALL'))"
        )
        return "\n".join(r[0] for r in cur.fetchall())


@mcp.tool()
def top_sql(window_minutes: int = 60, limit: int = 10) -> list[dict]:
    """Top SQL by elapsed time from v$sql within the last N minutes.

    Useful for "what's been slow recently?" investigations from
    Claude Desktop.
    """
    _audit("top_sql", {"window_minutes": window_minutes, "limit": limit})
    with cursor() as cur:
        cur.execute("""
            SELECT sql_id,
                   ROUND(elapsed_time/1e6, 2)              AS elapsed_seconds,
                   executions,
                   ROUND(buffer_gets/GREATEST(executions,1)) AS gets_per_exec,
                   SUBSTR(sql_text, 1, 200)                  AS sql_preview
              FROM v$sql
             WHERE last_active_time >= SYSDATE - :mins/1440
             ORDER BY elapsed_time DESC
             FETCH FIRST :lim ROWS ONLY
        """, mins=window_minutes, lim=limit)
        return rows_to_dicts(cur)


def main() -> None:
    """Entry point. Runs the MCP server over stdio (default for Claude
    Desktop) until killed."""
    mcp.run()


if __name__ == "__main__":
    main()
