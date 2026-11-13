import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from storage import Database, StorageError, _connection_settings, identifier, literal


class LiteralTests(unittest.TestCase):
    def test_untrusted_text_is_encoded_not_interpolated(self):
        value = "'; DROP SCHEMA public CASCADE; --\n\\! echo secret\n中文\\'"
        encoded = literal(value)
        self.assertNotIn("DROP", encoded)
        self.assertNotIn("\\!", encoded)
        token = re.search(r"decode\('([^']*)','base64'\)", encoded).group(1)
        self.assertEqual(base64.b64decode(token).decode("utf-8"), value)

    def test_json_is_preserved_and_cast(self):
        value = {"a": ["汉字", "x'y", True, None]}
        encoded = literal(value)
        self.assertTrue(encoded.endswith("::jsonb"))
        token = re.search(r"decode\('([^']*)','base64'\)", encoded).group(1)
        self.assertEqual(json.loads(base64.b64decode(token)), value)

    def test_native_values_and_invalid_text(self):
        self.assertEqual([literal(v) for v in (None, True, False, 42, -2, 0.5)],
                         ["NULL", "TRUE", "FALSE", "42", "-2", "0.5"])
        for bad in (float("nan"), float("inf"), "bad\0text"):
            with self.assertRaises(ValueError):
                literal(bad)
        with self.assertRaises(TypeError):
            literal(b"bad")

    def test_identifier_rejects_sql_and_dotted_paths(self):
        self.assertEqual(identifier("test_memory_11"), '"test_memory_11"')
        for bad in ("public.entries", "x; DROP TABLE tasks", "x\"", "", "a" * 64):
            with self.assertRaises(ValueError):
                identifier(bad)


class ConfigTests(unittest.TestCase):
    def test_url_dsn_decodes_credentials_and_ssl(self):
        settings = _connection_settings({"database": {"dsn":
            "postgresql://some%40user:p%27a%3Ass@127.0.0.1:5433/artex_test?sslmode=require"}})
        self.assertEqual(settings["PGUSER"], "some@user")
        self.assertEqual(settings["PGPASSWORD"], "p'a:ss")
        self.assertEqual(settings["PGDATABASE"], "artex_test")
        self.assertEqual(settings["PGPORT"], "5433")
        self.assertEqual(settings["PGSSLMODE"], "require")

    def test_keyword_dsn_and_field_config(self):
        settings = _connection_settings({"database": {"dsn":
            "host=localhost port=5434 user=worker password='a b' dbname=memory"}})
        self.assertEqual(settings["PGPASSWORD"], "a b")
        self.assertEqual(settings["PGDATABASE"], "memory")
        fields = _connection_settings({"database": {"host": "127.0.0.1", "user": "u", "password": "p", "dbname": "d"}})
        self.assertEqual(fields["PGPORT"], "5432")
        self.assertEqual(fields["PGDATABASE"], "d")

    def test_invalid_config_errors_do_not_expose_dsn(self):
        for config in ({}, {"database": {}}, {"database": {"dsn": "secret-broken-dsn"}},
                       {"database": {"dsn": "postgresql://u:secret@localhost:BAD/db"}}):
            if config == {"database": {}}:
                self.assertEqual(_connection_settings(config)["PGDATABASE"], "postgres")
                continue
            with self.assertRaises(StorageError) as exc:
                _connection_settings(config)
            self.assertNotIn("secret", str(exc.exception))


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "config.json"
        self.config.write_text(json.dumps({"database": {"host": "127.0.0.1", "user": "test", "password": "TOP_SECRET", "dbname": "memory_test"}}), encoding="utf-8")
        self.db = Database(self.config, schema="isolated_memory_test")

    def fake_result(self, stdout="[]", returncode=0, stderr=""):
        return subprocess.CompletedProcess(["psql"], returncode, stdout, stderr)

    @patch("storage.subprocess.run")
    def test_query_uses_stdin_and_readonly_guard(self, run):
        run.return_value = self.fake_result('[{"n":1}]')
        self.assertEqual(self.db.query("SELECT 1 AS n;"), [{"n": 1}])
        args, kwargs = run.call_args
        self.assertNotIn("TOP_SECRET", repr(args))
        self.assertEqual(kwargs["env"]["PGPASSWORD"], "TOP_SECRET")
        self.assertIn("default_transaction_read_only=on", kwargs["env"]["PGOPTIONS"])
        self.assertIn("json_agg", kwargs["input"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], 20)

    @patch("storage.subprocess.run")
    def test_execute_preserves_transaction_and_instance_readonly(self, run):
        run.return_value = self.fake_result("")
        self.db.execute("BEGIN; SELECT 1; COMMIT;")
        self.assertEqual(run.call_args.kwargs["input"], "BEGIN; SELECT 1; COMMIT;\n")
        self.assertIn("default_transaction_read_only=off", run.call_args.kwargs["env"]["PGOPTIONS"])
        readonly = Database(self.config, readonly=True)
        readonly.execute("SELECT 1")
        self.assertIn("default_transaction_read_only=on", run.call_args.kwargs["env"]["PGOPTIONS"])
        with self.assertRaises(StorageError):
            readonly.migrate()

    @patch("storage.subprocess.run")
    def test_psql_failure_is_sanitized(self, run):
        run.return_value = self.fake_result("", 1, "TOP_SECRET / SELECT raw private evidence")
        with self.assertRaises(StorageError) as exc:
            self.db.execute("SELECT raw_private_evidence")
        self.assertEqual(str(exc.exception), "Experience database operation failed")
        self.assertNotIn("TOP_SECRET", str(exc.exception))
        run.side_effect = subprocess.TimeoutExpired(["psql", "TOP_SECRET"], 20)
        with self.assertRaises(StorageError) as exc:
            self.db.query("SELECT 1")
        self.assertEqual(str(exc.exception), "Experience database operation timed out")

    @patch("storage.subprocess.run")
    def test_query_rejects_invalid_shape_and_nonselect(self, run):
        run.return_value = self.fake_result('{"not":"records"}')
        with self.assertRaises(StorageError):
            self.db.query("SELECT 1")
        with self.assertRaises(ValueError):
            self.db.query("DELETE FROM tasks")

    @patch("storage.subprocess.run")
    def test_migration_is_atomic_and_schema_scoped(self, run):
        run.return_value = self.fake_result("")
        self.db.migrate()
        sql = run.call_args.kwargs["input"]
        self.assertTrue(sql.startswith("BEGIN;\n"))
        self.assertTrue(sql.endswith("COMMIT;\n"))
        self.assertIn('"isolated_memory_test".entries', sql)
        self.assertNotIn('"artex_experience"', sql)
        self.assertNotRegex(sql, r"REFERENCES\s+(tasks|findings)\b")
        self.assertNotRegex(sql, r"\bALTER\s+TABLE\s+(tasks|findings)\b")

    def test_explicit_environment_config_override(self):
        with patch.dict(os.environ, {"ARTEX_EXPERIENCE_CONFIG": str(self.config)}):
            self.assertEqual(Database("/does/not/exist").config_path, self.config)
        missing = Database(Path(self.tmp.name) / "missing.json")
        with self.assertRaises(StorageError) as exc:
            missing.query("SELECT 1")
        self.assertEqual(str(exc.exception), "Experience database configuration is unavailable")


if __name__ == "__main__":
    unittest.main()
