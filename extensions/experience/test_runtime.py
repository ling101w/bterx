"""Behavioral tests for the memory boundary; no production database calls."""
import base64
import copy
import json
import re
import unittest

from experience_runtime import (MAX_SNAPSHOT_BYTES, Runtime, compact, handle,
                                positive, rank_entry, redact, report_sections, tokens)
from storage import StorageError


class FakeDatabase:
    qualified_schema = '"isolated_memory_test"'

    def __init__(self, *, entries=None, companies=None, retrieved=True):
        self.entries = entries or []
        self.companies = companies or []
        self.retrieved = retrieved
        self.queries = []
        self.executions = []

    def query(self, sql):
        self.queries.append(sql)
        if "FROM companies c" in sql:
            return copy.deepcopy(self.companies)
        if "FROM tasks WHERE" in sql:
            return [{"id": 99}]
        if 'FROM "isolated_memory_test".entries e' in sql:
            return copy.deepcopy(self.entries)
        if 'FROM "isolated_memory_test".usage' in sql:
            return [{"id": 1}] if self.retrieved else []
        if "FROM exploration_nodes n JOIN tasks t" in sql:
            return [{"id": 17}]
        return []

    def execute(self, sql):
        self.executions.append(sql)


def source_fixture(level="confirmed"):
    return {
        "source_key": "finding:7", "source_type": "finding", "source_id": 7,
        "revision": "source-revision-1", "source_task_id": 42,
        "source_company_ids": [5], "company_names": ["青杉项目"],
        "snapshot_id": "a" * 24, "verification_level": level,
        "verification_basis": "来源已确认" if level == "confirmed" else "候选发现",
        "evidence": [
            {"id": "finding:7/evidence", "text": "通过两种独立身份的对照请求得到不同响应，保留了用于核验的完整原始证据。"},
            {"id": "finding:7/report", "text": "报告摘要不能单独证明验证成功。"},
            {"id": "activity:44", "text": "某一步执行结果。"},
        ],
    }


def item_fixture(**updates):
    item = {
        "title": "接口权限检查需要身份对照", "category": "authorization",
        "tags": ["权限检查", "身份对照"],
        "applicable_when": "存在两个获准使用的身份，并能请求同一资源。",
        "steps": ["先记录同一身份的基线，再比较不同身份的结果。"],
        "success_criteria": "证据支持真实权限差异，而非网络错误。",
        "pitfalls": ["不能把单次错误响应当作漏洞成立。"],
        "not_applicable": "身份或资源前提尚未到位时不适用。",
        "outcome": "success", "transfer_scope": "generic",
        "evidence_ids": ["finding:7/evidence"],
    }
    item.update(updates)
    return item


def entry_fixture(**updates):
    entry = Runtime(FakeDatabase())._entry(item_fixture(), source_fixture())
    entry.update(updates)
    return entry


class InputValidationTests(unittest.TestCase):
    def test_positive_rejects_boolean_fraction_and_sql(self):
        self.assertEqual(positive("42", "task"), 42)
        self.assertEqual(positive(0, "task", zero=True), 0)
        for bad in (True, None, -1, 1.5, "1;DROP TABLE tasks", [], {}):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                positive(bad, "task")

    def test_dispatch_rejects_invalid_modes_without_database_calls(self):
        database = FakeDatabase()
        for payload in (None, [], {"_mode": "shell"}, {"_mode": []}, {"_mode": {}}):
            with self.subTest(value=payload), self.assertRaises(ValueError):
                handle(payload, database)
        self.assertFalse(database.queries)
        self.assertFalse(database.executions)

    def test_entry_invalid_types_are_validation_errors(self):
        runtime = Runtime(FakeDatabase())
        for update in ({"outcome": []}, {"transfer_scope": {}}, {"steps": "text"},
                       {"title": None}, {"tags": [3]}, {"evidence_ids": [7]}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                runtime._entry(item_fixture(**update), source_fixture())

    def test_feedback_invalid_event_is_validation_error(self):
        runtime = Runtime(FakeDatabase())
        for event in ("verified", {}, [], None):
            with self.subTest(event=event), self.assertRaises(ValueError):
                runtime.feedback({"event": event})


class RedactionTests(unittest.TestCase):
    def test_credentials_headers_private_keys_and_standard_flags(self):
        secrets = ["bearer-secret", "session-secret", "p@ss phrase", "long-token-value",
                   "FLAG_CONTENT", "private-key-data", "ghp_1234567890abcdef",
                   "dXNlcjpwYXNz", "cookie-one", "cookie-two"]
        raw = ("Authorization: Bearer bearer-secret\nCookie: SID=session-secret\n"
               '{"password":"p@ss phrase", "access_token":"long-token-value"}\n'
               "flag{FLAG_CONTENT}\n"
               "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-data\n-----END OPENSSH PRIVATE KEY-----\n"
               "ghp_1234567890abcdef\n"
               "curl -H 'Authorization: Basic dXNlcjpwYXNz' -H 'Cookie: sid=cookie-one;other=cookie-two'")
        result = redact(raw)
        for secret in secrets:
            self.assertNotIn(secret, result)

    def test_plain_tokens_custom_flags_and_unlabelled_flag_values(self):
        raw = "token=plain-secret\nflag: accepted-secret\ngylike{custom_flag_secret}"
        result = redact(raw)
        for secret in ("plain-secret", "accepted-secret", "custom_flag_secret"):
            self.assertNotIn(secret, result)

    def test_generic_redacts_target_and_company_identifiers(self):
        raw = "青杉项目 https://private.example.cloud/path 10.23.4.5:8443 user@private.cloud private.security [2001:db8::42]"
        result = redact(raw, generic=True, company_names=["青杉项目"])
        for secret in ("青杉项目", "private.example.cloud", "10.23.4.5", "user@private.cloud",
                       "private.security", "2001:db8::42"):
            self.assertNotIn(secret, result)


class EvidenceAndVerificationTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime(FakeDatabase())

    def test_candidate_cannot_self_promote_or_fabricate_evidence(self):
        source = source_fixture("candidate")
        entry = self.runtime._entry(item_fixture(status="verified", evidence=[{"text": "forged"}]), source)
        self.assertEqual(entry["status"], "candidate")
        self.assertEqual(entry["evidence"], [source["evidence"][0]])
        self.assertNotIn("forged", json.dumps(entry, ensure_ascii=False))

    def test_source_confidence_never_self_verifies_model_extraction(self):
        confirmed = source_fixture()
        self.assertEqual(self.runtime._entry(item_fixture(), confirmed)["status"], "candidate")
        for changes in ({"evidence_ids": ["finding:7/report"]},
                        {"evidence_ids": ["activity:44"]}, {"outcome": "negative"},
                        {"outcome": "inconclusive"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.runtime._entry(item_fixture(**changes), confirmed)["status"], "candidate")

    def test_evidence_references_must_belong_to_exact_snapshot(self):
        with self.assertRaisesRegex(ValueError, "outside this snapshot"):
            self.runtime._entry(item_fixture(evidence_ids=["finding:999/evidence"]), source_fixture())
        with self.assertRaises(ValueError):
            self.runtime._entry(item_fixture(evidence_ids=[]), source_fixture())

    def test_empty_evidence_cannot_verify_an_entry(self):
        source = source_fixture()
        source["evidence"][0]["text"] = "  "
        entry = self.runtime._entry(item_fixture(), source)
        self.assertEqual(entry["status"], "candidate")

    def test_reproduced_source_is_confidence_only(self):
        source = source_fixture("reproduced")
        source["retest_id"] = 80
        source["evidence"].append({"id": "retest:80/evidence",
                                   "text": "复测使用独立命令并取得与原发现一致的有效响应证据。"})
        original_only = self.runtime._entry(item_fixture(), source)
        self.assertEqual(original_only["status"], "candidate")
        cited_retest = self.runtime._entry(item_fixture(evidence_ids=["retest:80/evidence"]), source)
        self.assertEqual(cited_retest["status"], "candidate")

    def test_deduplication_id_depends_on_source_revision_not_model_wording(self):
        source = source_fixture()
        first = self.runtime._entry(item_fixture(), source)
        second = self.runtime._entry(item_fixture(title="另一种表述"), source)
        newer = dict(source, revision="source-revision-2")
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["id"], self.runtime._entry(item_fixture(), newer)["id"])

    def test_generic_entry_sanitizes_all_method_fields(self):
        raw = "青杉项目 https://secret.example.com/x password=hidden-value"
        entry = self.runtime._entry(item_fixture(title=raw, steps=[raw], tags=["example.com"]), source_fixture())
        for field in (entry["title"], entry["steps"][0], entry["tags"][0]):
            self.assertNotIn("青杉项目", field)
            self.assertNotIn("secret.example.com", field)
            self.assertNotIn("hidden-value", field)

    def test_attack_chain_requires_real_per_step_citations_and_redacts_method(self):
        step = {"step": 1, "prerequisite": "青杉项目 has a controlled identity",
                "action": "Compare https://private.example.cloud/ with the baseline",
                "observed_result": "A controlled request returned the documented result",
                "evidence_ids": ["activity:44"]}
        entry = self.runtime._entry(item_fixture(attack_chain=[step], root_cause="青杉项目 缺少资源归属校验"),
                                    source_fixture())
        self.assertEqual(entry["status"], "candidate")
        self.assertEqual(entry["attack_chain"][0]["evidence_ids"], ["activity:44"])
        self.assertIn("activity:44", [e["id"] for e in entry["evidence"]])
        self.assertNotIn("青杉项目", entry["root_cause"])
        self.assertNotIn("private.example.cloud", compact(entry["attack_chain"]))
        invalid = dict(step, evidence_ids=["activity:999"])
        with self.assertRaisesRegex(ValueError, "outside this snapshot"):
            self.runtime._entry(item_fixture(attack_chain=[invalid]), source_fixture())
        with self.assertRaisesRegex(ValueError, "ordered"):
            self.runtime._entry(item_fixture(attack_chain=[step, step]), source_fixture())

    def test_cross_project_generic_chain_hides_refs_but_own_scope_keeps_them(self):
        chain = [{"step": 1, "prerequisite": "Control identity", "action": "Compare results",
                  "observed_result": "A response differed", "evidence_ids": ["activity:44"]}]
        entry = self.runtime._entry(item_fixture(attack_chain=chain), source_fixture())
        runtime = Runtime(FakeDatabase(entries=[entry]))
        public = runtime.get({"id": entry["id"], "task_id": 99})["experience"]
        own = runtime.get({"id": entry["id"], "task_id": 42})["experience"]
        self.assertEqual(public["attack_chain"][0]["evidence_ids"], [])
        self.assertEqual(own["attack_chain"][0]["evidence_ids"], ["activity:44"])


def report_row(**updates):
    row = {"id": 7, "task_id": 42, "node_id": 70, "exploration_id": 42,
           "status": "confirmed", "revision": "revision-report-1", "name": "Controlled report",
           "vulnclass": "authorization", "evidence": "", "evidence_version": 2,
           "report_evidence_version": 1, "evidence_hash": "evidence-hash", "report_hash": "report-hash",
           "report": "## 前置条件\n两个受控身份。\n## 复现步骤\n1. 请求基线。\n2. 比较资源归属。\n"
                     "## 验证证据\n响应差异需要当前任务独立核对。\n## 限制与边界\n未覆盖其他身份。"}
    row.update(updates)
    return row


class ReportAndExecutionTests(unittest.TestCase):
    def test_later_report_sections_survive_large_intro_and_code_headings(self):
        report = "## 概述\n" + "Intro material. " * 500 + (
            "\n## 前置条件\nTwo controlled identities.\n## 复现步骤\n1. Compare requests.\n"
            "```python\n# a code comment must not become a report section\n```\n"
            "2. Inspect the final response.\n## 验证证据\nAn independent result was observed.\n"
            "## 根因分析\nThe resource ownership guard is absent.\n## 限制\nOther roles remain untested.")
        sections, truncated = report_sections(report)
        kinds = {section["kind"]: section["text"] for section in sections}
        self.assertIn("Compare requests", kinds["steps"])
        self.assertIn("independent result", kinds["verification"])
        self.assertIn("Other roles", kinds["limitations"])
        self.assertIn("ownership guard", kinds["root_cause"])
        self.assertTrue(truncated)

    def test_report_only_stale_source_is_marked_and_never_verified(self):
        runtime = Runtime(FakeDatabase())
        source = runtime._finding_snapshot(report_row(node_id=0))
        self.assertEqual(source["report_context"]["freshness"], "stale")
        self.assertEqual(source["report_evidence_version"], 1)
        self.assertEqual(source["evidence_version"], 2)
        self.assertTrue(any("Report-only" in warning for warning in source["warnings"]))
        source["snapshot_id"] = "b" * 24
        ref = next(e["id"] for e in source["evidence"] if "/report/steps" in e["id"])
        entry = runtime._entry(item_fixture(evidence_ids=[ref]), source)
        self.assertEqual(entry["status"], "candidate")

    def test_activity_reads_use_one_exact_node_and_only_direct_source_links(self):
        class LinkedDatabase(FakeDatabase):
            def query(self, sql):
                self.queries.append(sql)
                if "FROM exploration_edges e" in sql:
                    return [{"src_id": 71, "dst_id": 70, "rel": "yields"}] if "e.dst_id=70" in sql else []
                if "FROM activity a" in sql:
                    return [{"id": 900, "node_id": 71, "kind": "result", "tool": "", "is_error": False,
                             "summary": "Synthetic source execution", "detail": "Independent controlled observation"}] if "a.node_id=71" in sql else []
                return []
        database = LinkedDatabase()
        source = Runtime(database)._finding_snapshot(report_row())
        queries = [query for query in database.queries if "FROM activity a" in query]
        self.assertEqual(len(queries), 2)
        for query in queries:
            self.assertRegex(query, r"a.exploration_id=42 AND a.node_id=(70|71)")
            self.assertNotIn(" OR ", query)
            self.assertNotIn("node_id IN", query)
            self.assertIn("LIMIT 3", query)
        self.assertEqual(source["chain_context"]["source_work_ids"], [71])
        self.assertIn("activity:900", [e["id"] for e in source["evidence"]])

    def test_execution_timeout_keeps_report_but_database_outage_surfaces(self):
        class SlowActivity(FakeDatabase):
            def query(self, sql):
                self.queries.append(sql)
                if "FROM activity a" in sql:
                    raise StorageError("Experience database operation timed out")
                return []
        database = SlowActivity()
        source = Runtime(database)._finding_snapshot(report_row())
        self.assertTrue(any("Execution excerpt unavailable" in warning for warning in source["warnings"]))
        self.assertTrue(any("/report/steps" in e["id"] for e in source["evidence"]))
        self.assertIn("SELECT 1 AS experience_health", database.queries)
        class Offline(SlowActivity):
            def query(self, sql):
                if "experience_health" in sql:
                    raise StorageError("Experience database operation failed")
                return super().query(sql)
        with self.assertRaises(StorageError):
            Runtime(Offline())._finding_snapshot(report_row())

    def test_dense_three_source_snapshot_stays_within_tool_budget(self):
        class ClaimDatabase(FakeDatabase):
            def execute(self, sql):
                super().execute(sql)
                self.claim = None
                for value in re.findall(r"decode\('([^']*)','base64'\)", sql):
                    try:
                        row = json.loads(base64.b64decode(value).decode())
                    except ValueError:
                        continue
                    if isinstance(row, dict) and "snapshot_id" in row:
                        self.claim = row["snapshot_id"]
            def query(self, sql):
                if "SELECT snapshot_id FROM" in sql:
                    return [{"snapshot_id": self.claim}]
                return super().query(sql)
        class DenseRuntime(Runtime):
            def reconcile(self):
                pass
            def _finding_candidates(self, limit, task_id):
                report = "\n".join("## " + heading + "\n" + "受控条件与实际观察。" * 300
                                   for heading in ("前置条件", "复现步骤", "验证证据", "根因分析", "限制", "概述"))
                return [report_row(id=i, report=report, node_id=0, evidence="直接证据。" * 300) for i in (1, 2, 3)]
            def _task_candidates(self, limit, task_id):
                return []
        result = DenseRuntime(ClaimDatabase()).snapshot({"limit": 3})
        self.assertEqual(len(result["sources"]), 3)
        self.assertLessEqual(len(compact(result).encode("utf-8")), MAX_SNAPSHOT_BYTES)


class RetrievalTests(unittest.TestCase):
    def test_cjk_bigrams_and_feedback_cannot_replace_relevance(self):
        self.assertIn("权限", tokens("接口权限验证"))
        self.assertIn("检查", tokens("权限检查"))
        relevant = entry_fixture()
        irrelevant = entry_fixture(title="压缩文件结构", tags=["归档"], category="archive",
                                   applicable_when="存在压缩文件", steps=["检查文件头"],
                                   pitfalls=["不要猜测文件类型"], helpful=1000000)
        self.assertGreater(rank_entry(relevant, "权限对照", []), 0)
        self.assertEqual(rank_entry(irrelevant, "权限对照", []), 0)

    def test_sql_scope_contains_generic_task_and_project_boundaries(self):
        runtime = Runtime(FakeDatabase())
        scoped = runtime._accessible(42, [5, 8])
        self.assertIn("e.transfer_scope='generic'", scoped)
        self.assertIn("e.source_task_id=42 AND 42>0", scoped)
        self.assertEqual(scoped.count("source_company_ids @>"), 2)
        anonymous = runtime._accessible(0, [])
        self.assertIn("e.source_task_id=0 AND 0>0", anonymous)
        self.assertIn("OR (false)", anonymous)

    def test_generic_get_hides_other_project_evidence_and_source_ids(self):
        entry = entry_fixture()
        database = FakeDatabase(entries=[entry])
        result = Runtime(database).get({"id": entry["id"], "task_id": 99})["experience"]
        self.assertIn("steps", result)
        self.assertNotIn("evidence", result)
        self.assertNotIn("source_task_id", result)
        self.assertNotIn("source_key", result)
        self.assertNotIn("snapshot_id", result)

    def test_own_task_or_same_company_can_get_scoped_evidence(self):
        entry = entry_fixture()
        own = Runtime(FakeDatabase(entries=[entry])).get({"id": entry["id"], "task_id": 42})["experience"]
        self.assertEqual(own["evidence"], entry["evidence"])
        same_company = Runtime(FakeDatabase(entries=[entry], companies=[{"id": 5, "name": "青杉项目"}]))
        self.assertEqual(same_company.get({"id": entry["id"], "task_id": 99})["experience"]["evidence"], entry["evidence"])

    def test_search_returns_method_summary_without_raw_evidence(self):
        # A verified row represents a separately reviewed entry, never the
        # unreviewed model extraction returned by _entry().
        entry = entry_fixture(status="verified")
        database = FakeDatabase(entries=[entry])
        result = Runtime(database).search({"task_id": 99, "query": "权限检查 ' DROP TABLE tasks", "include_candidates": False})
        self.assertEqual(len(result["experiences"]), 1)
        item = result["experiences"][0]
        for key in ("evidence", "source_task_id", "source_key", "snapshot_id", "steps"):
            self.assertNotIn(key, item)
        query = next(q for q in database.queries if 'FROM "isolated_memory_test".entries e' in q)
        self.assertIn("e.status='verified'", query)
        self.assertNotIn("DROP TABLE tasks", query)
        self.assertTrue(any(".usage" in sql and "INSERT" in sql for sql in database.executions))

    def test_feedback_does_not_promote_candidate(self):
        entry = entry_fixture(status="candidate")
        database = FakeDatabase(entries=[entry])
        result = Runtime(database).feedback({"id": entry["id"], "task_id": 99,
                                           "event": "helpful", "note": "该方法符合前提并减少了重复尝试。"})
        self.assertTrue(result["recorded"])
        writes = "\n".join(database.executions)
        self.assertNotRegex(writes, r"SET\s+status\s*=\s*'verified'")
        self.assertEqual(database.entries[0]["status"], "candidate")

    def test_feedback_requires_actual_prior_retrieval(self):
        entry = entry_fixture()
        database = FakeDatabase(entries=[entry], retrieved=False)
        with self.assertRaisesRegex(ValueError, "Retrieve the experience"):
            Runtime(database).feedback({"id": entry["id"], "task_id": 99,
                                       "event": "helpful", "note": "尝试直接投票。"})


class LeaseDatabase(FakeDatabase):
    """Simulate two workers that selected the same source before its claim."""
    def __init__(self):
        super().__init__()
        self.held_snapshot = None

    def execute(self, sql):
        super().execute(sql)
        if ".sources" in sql and "INSERT INTO" in sql:
            for value in re.findall(r"decode\('([^']*)','base64'\)", sql):
                decoded = base64.b64decode(value).decode("utf-8")
                try:
                    data = json.loads(decoded)
                except ValueError:
                    continue
                if isinstance(data, dict) and "snapshot_id" in data and "source_key" in data:
                    # ON CONFLICT's live lease rejects the second insertion.
                    if self.held_snapshot is None:
                        self.held_snapshot = data["snapshot_id"]

    def query(self, sql):
        if "SELECT snapshot_id FROM" in sql:
            self.queries.append(sql)
            return [{"snapshot_id": self.held_snapshot}]
        return super().query(sql)


class SnapshotRuntime(Runtime):
    def reconcile(self):
        pass

    def _finding_candidates(self, limit, task_id):
        return [{}]

    def _finding_snapshot(self, row):
        return source_fixture()

    def _task_candidates(self, limit, task_id):
        return []


class LeaseTests(unittest.TestCase):
    def test_losing_a_claim_does_not_receive_another_curators_snapshot(self):
        database = LeaseDatabase()
        first = SnapshotRuntime(database).snapshot({"limit": 1})
        second = SnapshotRuntime(database).snapshot({"limit": 1})
        self.assertEqual(len(first["sources"]), 1)
        self.assertEqual(second["sources"], [])


if __name__ == "__main__":
    unittest.main()
