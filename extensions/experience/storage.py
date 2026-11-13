"""Small PostgreSQL adapter for the independent ARTEX experience schema.

The adapter uses the installed ``psql`` executable, not a Python database
dependency. Credentials are supplied only in the child process environment;
SQL travels on stdin and is never included in an exception.
"""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
from urllib.parse import parse_qs, unquote, urlsplit


DEFAULT_CONFIG = "/home/maming/apps/artex-1/config.json"
DEFAULT_SCHEMA = "artex_experience"
_IDENTIFIER = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}\Z")


class StorageError(RuntimeError):
    """An intentionally sanitized database or configuration failure."""


def identifier(value: str) -> str:
    """Validate and quote a single SQL identifier (never a dotted path)."""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid SQL identifier")
    return '"' + value + '"'


def literal(value):
    """Encode an SQL value without interpolating its source text into SQL.

    UTF-8 strings are carried as base64, which keeps quotes, backslashes,
    newlines and psql metacommands out of the SQL source. Containers are JSONB.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite SQL number")
        return repr(value)
    is_json = isinstance(value, (dict, list))
    if is_json:
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if not isinstance(value, str):
        raise TypeError("Unsupported SQL value type")
    if "\x00" in value:
        raise ValueError("NUL is not a PostgreSQL text value")
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    result = "convert_from(decode('" + encoded + "','base64'),'UTF8')"
    return result + ("::jsonb" if is_json else "")


def _connection_settings(config):
    if not isinstance(config, dict) or not isinstance(config.get("database"), dict):
        raise StorageError("Experience database configuration is unavailable")
    values = dict(config["database"])
    dsn = values.get("dsn")
    if dsn:
        if not isinstance(dsn, str):
            raise StorageError("Experience database configuration is invalid")
        try:
            if dsn.startswith(("postgres://", "postgresql://")):
                uri = urlsplit(dsn)
                query = parse_qs(uri.query, keep_blank_values=True)
                values.update({
                    "host": uri.hostname or values.get("host", "127.0.0.1"),
                    "port": uri.port or values.get("port", 5432),
                    "user": unquote(uri.username or ""),
                    "password": unquote(uri.password or ""),
                    "dbname": unquote(uri.path.lstrip("/")),
                })
                for key in ("host", "port", "user", "password", "dbname", "sslmode", "sslrootcert"):
                    if key in query:
                        values[key] = query[key][-1]
            else:
                # PostgreSQL also accepts a libpq keyword DSN. shlex handles
                # its quoted whitespace without executing shell syntax.
                pairs = shlex.split(dsn)
                if not pairs or any("=" not in pair for pair in pairs):
                    raise ValueError("Invalid DSN")
                values.update(dict(pair.split("=", 1) for pair in pairs))
            port = int(values.get("port", 5432))
            if not 1 <= port <= 65535:
                raise ValueError("Invalid port")
        except (TypeError, ValueError, UnicodeError):
            raise StorageError("Experience database configuration is invalid") from None
    else:
        try:
            port = int(values.get("port", 5432))
            if not 1 <= port <= 65535:
                raise ValueError("Invalid port")
        except (TypeError, ValueError):
            raise StorageError("Experience database configuration is invalid") from None
    result = {
        "PGHOST": str(values.get("host") or "127.0.0.1"),
        "PGPORT": str(port),
        "PGUSER": str(values.get("user") or ""),
        "PGPASSWORD": str(values.get("password") or ""),
        "PGDATABASE": str(values.get("dbname") or values.get("database") or "postgres"),
    }
    for key, env_key in (("sslmode", "PGSSLMODE"), ("sslrootcert", "PGSSLROOTCERT")):
        if values.get(key):
            result[env_key] = str(values[key])
    return result


class Database:
    def __init__(self, config_path=DEFAULT_CONFIG, schema=DEFAULT_SCHEMA, readonly=False):
        self.config_path = Path(os.environ.get("ARTEX_EXPERIENCE_CONFIG") or config_path)
        self.schema = schema
        self.qualified_schema = identifier(schema)
        self.readonly = bool(readonly)

    def _environment(self, *, read_only):
        try:
            config = json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, UnicodeError):
            raise StorageError("Experience database configuration is unavailable") from None
        env = os.environ.copy()
        env.update(_connection_settings(config))
        # Do not inherit unrelated PGOPTIONS. These are fixed operational
        # bounds, and every query() invocation gets a database read-only guard.
        env.update({
            "PGCONNECT_TIMEOUT": "8",
            "PGAPPNAME": "artex-experience",
            "PGOPTIONS": (
                "-c statement_timeout=12000 -c lock_timeout=5000 "
                "-c idle_in_transaction_session_timeout=15000 "
                "-c default_transaction_read_only=" + ("on" if read_only else "off")
            ),
            "PSQL_PAGER": "",
        })
        return env

    def _run(self, sql, *, read_only=False):
        if not isinstance(sql, str) or not sql.strip() or "\x00" in sql:
            raise ValueError("Invalid SQL statement")
        env = self._environment(read_only=self.readonly or read_only)
        try:
            result = subprocess.run(
                ["psql", "-X", "-A", "-t", "-q", "-w", "-v", "ON_ERROR_STOP=1", "-P", "pager=off"],
                input=sql.rstrip() + "\n", env=env, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise StorageError("Experience database operation timed out") from None
        except OSError:
            raise StorageError("Experience database client is unavailable") from None
        if result.returncode:
            # psql stderr can contain source SQL and evidence, so it must not
            # cross the boundary into agent output or installer logs.
            raise StorageError("Experience database operation failed")
        return result.stdout.strip()

    def query(self, sql):
        """Run a SELECT and return JSON records under a read-only connection."""
        if not isinstance(sql, str):
            raise ValueError("Expected SELECT statement")
        statement = sql.strip().rstrip(";").strip()
        if not re.match(r"(?:SELECT|WITH)\b", statement, flags=re.IGNORECASE):
            raise ValueError("Expected SELECT statement")
        wrapped = (
            "SELECT coalesce(json_agg(row_to_json(_experience_result)),'[]'::json) "
            "FROM (" + statement + ") AS _experience_result;"
        )
        raw = self._run(wrapped, read_only=True)
        try:
            records = json.loads(raw)
            if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
                raise ValueError("Invalid record shape")
        except (ValueError, TypeError):
            raise StorageError("Experience database returned an invalid result") from None
        return records

    def execute(self, sql):
        """Execute controlled DDL/DML; callers may pass one transaction script."""
        self._run(sql)

    def migrate(self):
        """Apply the additive experience migration in a single transaction."""
        if self.readonly:
            raise StorageError("Read-only experience database cannot migrate")
        try:
            sql = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise StorageError("Experience schema migration is unavailable") from None
        # The template uses this exact quoted token only for identifiers.
        sql = sql.replace('"artex_experience"', self.qualified_schema)
        self.execute("BEGIN;\n" + sql + "\nCOMMIT;")
