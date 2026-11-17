"""Regression checks for stable provenance, diversity and result attribution."""
import copy
import unittest

from experience_runtime import Runtime, handle
from test_runtime import FakeDatabase, entry_fixture, item_fixture, source_fixture
from integration_test import IsolatedDatabase


class MemoryPolicyTests(unittest.TestCase):
    def test_task_method_depends_only_on_its_cited_facts(self):
        source = source_fixture()
        source.update(source_key="task:42", source_type="task", source_id=42,
                      evidence=[{"id": "node:11", "text": "Observed negative boundary.", "dependency_revision": "a" * 32},
                                {"id": "node:12", "text": "Unrelated new evidence.", "dependency_revision": "b" * 32}])
        entry = Runtime(FakeDatabase())._entry(item_fixture(evidence_ids=["node:11"], outcome="negative"), source)
        self.assertEqual(entry["dependency_revisions"], {"node:11": "a" * 32})
        self.assertEqual(entry["outcome"], "negative")
        self.assertEqual(entry["status"], "candidate")

    def test_method_identity_survives_source_revision_but_conditions_and_outcome_matter(self):
        runtime, source = Runtime(FakeDatabase()), source_fixture()
        first = runtime._entry(item_fixture(), source)
        second = runtime._entry(item_fixture(title="另一种标题"), dict(source, revision="new"))
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["method_key"], second["method_key"])
        self.assertNotEqual(first["method_key"], runtime._entry(item_fixture(outcome="negative"), source)["method_key"])
        self.assertNotEqual(first["method_key"], runtime._entry(item_fixture(applicable_when="不同身份和前提"), source)["method_key"])

    def test_search_collapses_identical_methods_but_preserves_negative_boundary(self):
        first = entry_fixture(id="a" * 24)
        second = dict(first, id="b" * 24, source_key="finding:8")
        negative = entry_fixture(id="c" * 24, outcome="negative", method_key="negative-method")
        result = Runtime(FakeDatabase(entries=[first, second, negative])).search(
            {"task_id": 42, "query": "权限对照", "limit": 3})
        self.assertEqual({row["id"] for row in result["experiences"]}, {first["id"], negative["id"]})

    def test_result_feedback_needs_an_intent_and_result_references(self):
        entry = entry_fixture()
        for event in ("helpful", "unhelpful"):
            for extra in ({}, {"intent_id": 17}, {"evidence_node_ids": [18]}):
                with self.subTest(event=event, extra=extra), self.assertRaisesRegex(ValueError, "Result feedback requires"):
                    Runtime(FakeDatabase(entries=[entry])).feedback(
                        {"task_id": 42, "id": entry["id"], "event": event, "note": "需要证据。", **extra})

    def test_feedback_rejects_unrelated_or_foreign_results(self):
        entry = entry_fixture()
        with self.assertRaisesRegex(ValueError, "Feedback evidence"):
            Runtime(FakeDatabase(entries=[entry])).feedback(
                {"task_id": 42, "id": entry["id"], "event": "helpful", "note": "不能借用无关证据。",
                 "intent_id": 17, "evidence_node_ids": [999]})

    def test_missing_prerequisite_can_be_reported_without_executing(self):
        entry = entry_fixture()
        result = Runtime(FakeDatabase(entries=[entry])).feedback(
            {"task_id": 42, "id": entry["id"], "event": "not_applicable", "note": "缺少第二个受控身份。"})
        self.assertTrue(result["recorded"])
        self.assertFalse(result["evidence_linked"])

    def test_direct_get_counts_as_retrieval_without_feedback_inventing_one(self):
        entry = entry_fixture()
        database = FakeDatabase(entries=[entry])
        handle({"_mode": "get", "id": entry["id"], "task_id": 42}, database)
        self.assertTrue(any(".usage" in sql and "INSERT" in sql for sql in database.executions))
        database = FakeDatabase(entries=[entry], retrieved=False)
        with self.assertRaisesRegex(ValueError, "Retrieve the experience"):
            Runtime(database).feedback({"id": entry["id"], "task_id": 42,
                "event": "adopted", "note": "Feedback is not a retrieval."})

    def test_isolated_test_adapter_rejects_unqualified_source_ddl_before_connection(self):
        database = IsolatedDatabase(config_path="missing-config", schema="owned_fixture")
        for sql in ("ALTER TABLE activity ADD COLUMN example text", "DROP TABLE public.tasks", "TRUNCATE findings"):
            with self.subTest(sql=sql), self.assertRaisesRegex(ValueError, "owned schema"):
                database.execute(sql)


if __name__ == "__main__":
    unittest.main()
