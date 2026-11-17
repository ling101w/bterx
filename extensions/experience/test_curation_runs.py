import os
import unittest

from experience_runtime import Runtime
from experience_runs import public_result, publish_run, TERMINAL
import integration_review_test as reviewtests
from storage import literal


class CurationValidationTests(unittest.TestCase):
    def test_text_cannot_be_a_success_state(self):
        self.assertNotIn("completed", TERMINAL)
        self.assertNotIn("running", TERMINAL)
        result = public_result({"id": "a"*24, "status": "failed", "error_code": "delivery_missing"})
        self.assertEqual(result["saved_entry_ids"], [])
        self.assertEqual(result["status"], "failed")


@unittest.skipUnless(os.environ.get("ARTEX_EXPERIENCE_REVIEW_TEST") == "1", "Isolated PostgreSQL opt-in required")
class CurationDatabaseTests(unittest.TestCase):
    setUp = reviewtests.ReviewRegressionTests.setUp
    cleanup_schema = reviewtests.ReviewRegressionTests.cleanup_schema
    item = reviewtests.ReviewRegressionTests.item

    def prepared(self, cid=601):
        from experience_runs import prepare
        return prepare(self.rt, {"conversation_id": cid, "source_task_id": 1, "limit": 1})

    def payload(self, batch, cid=601):
        return {"run_id": batch["run_id"], "_host_run_id": batch["run_id"],
                "_host_conversation_id": cid, "entries": [self.item(batch["sources"][0])]}

    def test_publish_has_actual_rows_and_is_idempotent(self):
        from experience_runs import inspect
        batch = self.prepared()
        self.assertEqual(batch["status"], "running")
        result = self.rt.publish(self.payload(batch))
        self.assertEqual(result["status"], "saved")
        self.assertEqual(len(result["saved"]), 1)
        sealed = inspect(self.rt, batch["run_id"], 601)
        self.assertEqual(sealed["saved_entry_ids"], [result["saved"][0]["id"]])
        retry = self.rt.publish(self.payload(batch))
        self.assertTrue(retry["duplicate"])
        self.assertEqual(len(self.db.query(f"SELECT id FROM {self.s}.entries")), 1)

    def test_foreign_conversation_and_source_cannot_deliver(self):
        batch = self.prepared()
        payload = self.payload(batch)
        payload["_host_conversation_id"] = 602
        with self.assertRaises(ValueError):self.rt.publish(payload)
        payload = self.payload(batch)
        payload["entries"][0]["snapshot_id"] = "f"*24
        result = self.rt.publish(payload)
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["saved"], [])
        self.assertTrue(result["rejected"])

    def test_unperformed_turn_is_failed_and_empty_source_is_distinct(self):
        from experience_runs import prepare, finish
        batch = self.prepared()
        result = finish(self.rt, {"run_id": batch["run_id"], "conversation_id": 601})
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "delivery_missing")
        no_source = prepare(self.rt, {"conversation_id": 602, "source_task_id": 9999, "limit": 1})
        self.assertEqual(no_source["status"], "no_source")

    def test_explicit_skip_is_audited_and_cancel_is_not_success(self):
        from experience_runs import finish
        batch = self.prepared()
        p = self.payload(batch)
        p["entries"] = []
        p["skipped"] = [{"snapshot_id": batch["sources"][0]["snapshot_id"],
                         "reason": "insufficient_evidence", "note": "Synthetic source lacks a transferable independently supported method."}]
        r = self.rt.publish(p)
        self.assertEqual(r["status"], "skipped")
        self.assertEqual(r["saved"], [])
        self.assertEqual(self.rt.snapshot({"source_task_id": 1, "limit": 1})["sources"], [])
        # New run with a different source owns independent cancellation state.
        from experience_runs import prepare
        b = prepare(self.rt, {"conversation_id": 603, "source_task_id": 4, "limit": 1})
        cancelled = finish(self.rt, {"run_id": b["run_id"], "conversation_id": 603, "cancelled": True})
        self.assertEqual(cancelled["status"], "cancelled")

    def test_intent_retrospective_keeps_scoped_negative_evidence(self):
        self.raw.execute(f"""INSERT INTO {self.s}.exploration_nodes VALUES
          (301,11,'intent','planner','done','{{"summary":"Synthetic authorization hypothesis"}}',now()-interval '20 minutes'),
          (302,11,'fact','worker','done','{{"summary":"Synthetic controlled denial","evidence":"Synthetic HTTP 200 body code 401 with independent control.","confidence":"observed"}}',now()-interval '20 minutes');
          INSERT INTO {self.s}.exploration_edges VALUES(11,301,302,'yields');""")
        batch = self.rt.snapshot({"source_task_id": 1, "limit": 2})
        source = next(s for s in batch["sources"] if s["source_type"] == "intent")
        item = self.item(source)
        item["outcome"] = "negative"
        result = self.rt.publish({"entries": [item]})
        self.assertEqual(result["saved"][0]["status"], "candidate")
        self.db.execute("UPDATE exploration_nodes SET payload="+literal({"summary": "Corrected evidence", "evidence": "The initial control was invalidated by a new observation."})+" WHERE id=302")
        self.rt.reconcile()
        row = self.db.query(f"SELECT status FROM {self.s}.entries WHERE id={literal(result['saved'][0]['id'])}")[0]
        self.assertEqual(row["status"], "deprecated")


if __name__ == "__main__":unittest.main()
