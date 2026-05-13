"""
Typed configuration for the Oracle MCP server.

All settings load from .env via python-dotenv. Required values fail
fast at import time so misconfigured deployments don't silently expose
the wrong tables.
"""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


def _required(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise RuntimeError(f"Missing required env var: {key}")
    return v


def _csv(key: str, default: str = "") -> list[str]:
    raw = os.environ.get(key, default)
    return [s.strip() for s in raw.split(",") if s.strip()]


class Settings(BaseModel):
    ora_user: str = Field(default_factory=lambda: _required("ORA_USER"))
    ora_password: str = Field(default_factory=lambda: _required("ORA_PASSWORD"))
    ora_dsn: str = Field(default_factory=lambda: _required("ORA_DSN"))

    max_rows: int = Field(
        default_factory=lambda: int(os.environ.get("MCP_MAX_ROWS", "100"))
    )
    statement_timeout_seconds: int = Field(
        default_factory=lambda: int(os.environ.get("MCP_STATEMENT_TIMEOUT_SECONDS", "5"))
    )

    schema_allowlist: list[str] = Field(
        default_factory=lambda: _csv("MCP_SCHEMA_ALLOWLIST",
                                      "APPS,APPLSYS,SYS,RAGAPP")
    )
    column_denylist: list[str] = Field(
        default_factory=lambda: _csv("MCP_COLUMN_DENYLIST",
                                      "SSN,SALARY,TAX_ID,PASSWORD,"
                                      "BANK_ACCOUNT,CREDIT_CARD,DOB")
    )
    audit_log: str = Field(
        default_factory=lambda: os.environ.get("MCP_AUDIT_LOG", "./audit.log")
    )


@lru_cache(maxsize=1)
def settings() -> Settings:
    return Settings()
