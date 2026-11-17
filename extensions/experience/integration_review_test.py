"""Regression checks for the independent experience review.

Opt in with ARTEX_EXPERIENCE_REVIEW_TEST=1. All source records are synthetic;
the only writes are inside a freshly generated, owned PostgreSQL schema.
"""
import os
import re
import secrets
import unittest

from experience_runtime import Runtime
from integration_test import IsolatedDatabase
from storage import Database, literal


@unittest.skipUnless(os.environ.get("ARTEX_EXPERIENCE_REVIEW_TEST") == "1",
                     "Explicit isolated PostgreSQL review test opt-in is required")
class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.schema = "artex_experience_review_" + secrets.token_hex(6)
        self.db = IsolatedDatabase(schema=self.schema)
        self.raw = Database(schema=self.schema)
        self.s = self.db.qualified_schema
        self.addCleanup(self.cleanup_schema)
        self.db.migrate()
        s = self.s
        self.raw.execute(f"""BEGIN;
          CREATE TABLE {s}.companies(id bigint PRIMARY KEY,name text);
          CREATE TABLE {s}.tasks(id bigint PRIMARY KEY,company_id bigint,name text,goal text,
            description text,exploration_id bigint,status text,deleted_at timestamptz,
            completed_at timestamptz,updated_at timestamptz);
          CREATE TABLE {s}.task_scope(task_id bigint,kind text,company_id bigint);
          CREATE TABLE {s}.findings(id bigint PRIMARY KEY,task_id bigint,node_id bigint,vulnclass text,
            name text,summary text,evidence text,report text,status text,evidence_version bigint);
          ALTER TABLE {s}.findings ADD COLUMN report_evidence_version bigint NOT NULL DEFAULT 0;
          CREATE TABLE {s}.finding_retests(id bigint PRIMARY KEY,finding_id bigint,status text,
            verdict text,evidence text);
          CREATE TABLE {s}.exploration_nodes(id bigint PRIMARY KEY,exploration_id bigint,kind text,
            origin text,state text,payload jsonb,updated_at timestamptz);
          CREATE TABLE {s}.exploration_edges(exploration_id bigint,src_id bigint,dst_id bigint,rel text);
          CREATE TABLE {s}.activity(id bigint PRIMARY KEY,exploration_id bigint,node_id bigint,
            kind text,tool text,summary text,detail text,is_error boolean);
          INSERT INTO {s}.companies VALUES(1,'Synthetic review scope'),(2,'Synthetic other scope');
          INSERT INTO {s}.tasks VALUES
            (1,1,'Synthetic source','Synthetic goal','Synthetic description',11,'running',NULL,NULL,now()),
            (2,2,'Synthetic other task','Synthetic goal','Synthetic description',22,'running',NULL,NULL,now()),
            (4,NULL,'Synthetic CTF source','Synthetic CTF goal','Synthetic description',44,'done',NULL,now(),now());
          INSERT INTO {s}.findings VALUES
            (101,1,201,'auth','Synthetic finding','Synthetic finding summary',
             'Synthetic evidence with independent controlled observations and response comparison.',
             '', 'confirmed',0,0);
          INSERT INTO {s}.exploration_nodes VALUES
            (201,11,'finding','worker','done','{{}}',now()),
            (401,44,'fact','worker','done','{{"summary":"Synthetic initial method and observed result."}}',now());
          UPDATE {s}.tasks SET updated_at=now()-interval '30 minutes',completed_at=now()-interval '30 minutes' WHERE id=4;
          UPDATE {s}.exploration_nodes SET updated_at=now()-interval '30 minutes' WHERE id=401;
          COMMIT;""")
        self.rt = Runtime(self.db)

    def cleanup_schema(self):
        # Never accept a caller-provided path/schema for cleanup.
        if re.fullmatch(r"artex_experience_review_[0-9a-f]{12}", self.schema):
            self.raw.execute(f"DROP SCHEMA IF EXISTS {self.s} CASCADE")

    def source(self, task_id=1):
        sources = self.rt.snapshot({"limit": 1, "source_task_id": task_id})["sources"]
        self.assertEqual(len(sources), 1)
        return sources[0]

    def item(self, source, title="Synthetic authorization method", scope="generic"):
        return {
            "snapshot_id": source["snapshot_id"], "title": title, "category": "authorization",
            "tags": ["synthetic", "authorization"],
            "applicable_when": "Controlled identities and an authorized resource are available.",
            "steps": ["Compare independent controlled observations with the baseline."],
            "success_criteria": "Current observations independently support the stated result.",
            "pitfalls": ["One status code or one model judgment is not confirmation."],
            "not_applicable": "The controlled identities or authorization are unavailable.",
            "outcome": "success", "transfer_scope": scope,
            "evidence_ids": [source["evidence"][0]["id"]],
        }

    def test_status_revision_cycle_restores_a_searchable_candidate(self):
        for source_status in ("confirmed", "pending", "confirmed"):
            self.db.execute("UPDATE findings SET status=" + literal(source_status) + " WHERE id=101")
            saved = self.rt.publish({"entries": [self.item(self.source())]})["saved"][0]
            self.assertEqual(saved["status"], "candidate")
        entries = self.db.query(f"SELECT id,status FROM {self.s}.entries ORDER BY created_at")
        self.assertEqual(sum(row["status"] == "candidate" for row in entries), 1)
        self.assertEqual(sum(row["status"] == "verified" for row in entries), 0)
        matches = self.rt.search({"task_id": 1, "query": "authorization"})["experiences"]
        self.assertEqual(len(matches), 1)

    def test_publish_retry_reports_the_actual_stored_entry(self):
        source = self.source()
        self.rt.publish({"entries": [self.item(source, title="Synthetic original title")]})
        retry = self.rt.publish({"entries": [self.item(source, title="Synthetic retry title")]})["saved"][0]
        stored = self.db.query(f"SELECT id,status,title FROM {self.s}.entries WHERE id={literal(retry['id'])}")[0]
        self.assertEqual(retry, stored)

    def test_partial_publish_saves_valid_entry_and_rejects_duplicate_and_invalid_sources(self):
        valid_source = self.source()
        untouched_source = self.source(task_id=4)
        valid = self.item(valid_source, title="Synthetic valid batch entry")
        duplicate = self.item(valid_source, title="Synthetic duplicate source entry")
        invalid = self.item(valid_source, title="Synthetic invalid source entry")
        invalid["snapshot_id"] = "invalid-snapshot-id"
        result = self.rt.publish({"entries": [valid, duplicate, invalid]})
        self.assertEqual(len(result["saved"]), 1)
        self.assertEqual(len(result["rejected"]), 2)
        stored = self.db.query(f"SELECT id,status,title FROM {self.s}.entries")
        self.assertEqual(stored, result["saved"])
        sources = self.db.query(f"SELECT source_key,published_revision,revision FROM {self.s}.sources")
        published = [row for row in sources if row["published_revision"] == row["revision"]]
        self.assertEqual([row["source_key"] for row in published], [valid_source["source_key"]])
        pending = next(row for row in sources if row["source_key"] == untouched_source["source_key"])
        self.assertEqual(pending["published_revision"], "")

    def test_changed_task_fact_is_collected_as_a_new_source_revision(self):
        first = self.source(task_id=4)
        self.rt.publish({"entries": [self.item(first, title="Synthetic CTF method")]})
        original_task_stamp = self.db.query("SELECT updated_at FROM tasks WHERE id=4")[0]["updated_at"]
        self.db.execute("UPDATE exploration_nodes SET payload=" +
                        literal({"summary": "Synthetic corrected method based on a later observation."}) +
                        ",updated_at=now() WHERE id=401")
        self.assertEqual(self.db.query("SELECT updated_at FROM tasks WHERE id=4")[0]["updated_at"],
                         original_task_stamp)
        self.assertEqual(self.rt.snapshot({"source_task_id": 4})["sources"], [])
        self.db.execute("UPDATE exploration_nodes SET updated_at=now()-interval '30 minutes' WHERE id=401")
        second = self.source(task_id=4)
        self.assertNotEqual(first["revision"], second["revision"])
        self.assertIn("corrected", second["evidence"][0]["text"])

    def test_statistics_reconcile_a_withdrawn_source_before_counting(self):
        saved = self.rt.publish({"entries": [self.item(self.source())]})["saved"][0]
        # Simulate a separately reviewed fixture. This never touches real data.
        self.db.execute(f"UPDATE {self.s}.entries SET status='verified' WHERE id={literal(saved['id'])}")
        self.db.execute("UPDATE findings SET status='false_positive' WHERE id=101")
        stats = self.rt.stats({})
        counts = {row["status"]: int(row["count"]) for row in stats["entries"]}
        self.assertEqual(counts.get("verified", 0), 0)
        self.assertEqual(counts.get("deprecated", 0), 1)

    def test_report_only_chain_sections_versions_and_scoped_step_citations(self):
        report = "## 概述\n" + "Synthetic introductory material. " * 180 + (
            "\n## 前置条件\nTwo controlled identities and an authorized resource."
            "\n## 复现步骤\n1. Observe the baseline.\n2. Compare a second identity."
            "\n## 验证证据\nThe response comparison is recorded, method still requires review."
            "\n## 根因分析\nResource ownership validation was absent."
            "\n## 限制\nOther identity roles remain untested.")
        self.db.execute("UPDATE findings SET evidence='',report=" + literal(report) +
                        ",evidence_version=2,report_evidence_version=1 WHERE id=101")
        source = self.source()
        self.assertEqual(source["report_context"]["freshness"], "stale")
        step_ref = next(e["id"] for e in source["evidence"] if e["id"].endswith("/report/steps"))
        verification_ref = next(e["id"] for e in source["evidence"] if e["id"].endswith("/report/verification"))
        item = self.item(source)
        item["evidence_ids"] = [step_ref]
        item["root_cause"] = "Synthetic resource ownership validation was absent."
        item["attack_chain"] = [{"step": 1, "prerequisite": "Two controlled identities are available.",
                                  "action": "Compare the baseline and second identity responses.",
                                  "observed_result": "The report records a controlled difference; independent method review remains pending.",
                                  "evidence_ids": [step_ref, verification_ref]}]
        saved = self.rt.publish({"entries": [item]})["saved"][0]
        self.assertEqual(saved["status"], "candidate")
        own = self.rt.get({"task_id": 1, "id": saved["id"]})["experience"]
        other = self.rt.get({"task_id": 2, "id": saved["id"]})["experience"]
        self.assertEqual(own["attack_chain"][0]["evidence_ids"], [step_ref, verification_ref])
        self.assertEqual(other["attack_chain"][0]["evidence_ids"], [])
        self.assertIn("ownership", other["root_cause"])
        # Freshness metadata is versioned independently from the report body.
        self.db.execute("UPDATE findings SET report_evidence_version=2 WHERE id=101")
        self.assertFalse(self.rt.search({"task_id": 1, "query": "authorization"})["experiences"])

    def test_chain_context_activity_reads_only_direct_related_nodes(self):
        self.db.execute("""INSERT INTO exploration_nodes VALUES
          (202,11,'intent','planner','done','{}',now()),
          (203,11,'fact','worker','confirmed','{"summary":"Synthetic direct prerequisite"}',now()),
          (204,11,'intent','planner','done','{}',now());
          INSERT INTO exploration_edges VALUES(11,202,201,'yields'),(11,203,202,'derived_from');
          INSERT INTO activity VALUES
            (901,11,202,'result','','Synthetic source result','Controlled related observation',false),
            (902,11,204,'result','','Synthetic unrelated result','Must never enter this finding snapshot',false);""")
        source = self.source()
        refs = [e["id"] for e in source["evidence"]]
        self.assertEqual(source["chain_context"]["source_work_ids"], [202])
        self.assertIn("activity:901", refs)
        self.assertNotIn("activity:902", refs)
        self.assertIn("node:203", refs)

    def test_explicit_task_and_finding_exclusions_prevent_self_test_pollution(self):
        # Both a task retrospective and a finding were already collected and
        # published before the operator recognized the task as a self-test.
        self.db.execute("""UPDATE tasks SET status='done',completed_at=now()-interval '30 minutes',updated_at=now()-interval '30 minutes' WHERE id=1;
          INSERT INTO exploration_nodes VALUES
            (205,11,'fact','worker','confirmed','{"summary":"Synthetic acceptance-only observation"}',now()-interval '30 minutes');
          INSERT INTO findings VALUES
            (102,2,0,'auth','Synthetic unaffected finding','Synthetic independent source',
             'Controlled independent evidence belongs to an unaffected task.',
             '', 'confirmed',0,0);""")
        sources = self.rt.snapshot({"source_task_id": 1, "limit": 2})["sources"]
        self.assertEqual({source["source_type"] for source in sources}, {"finding", "task"})
        saved = self.rt.publish({"entries": [self.item(source) for source in sources]})["saved"]
        self.assertEqual(len(saved), 2)
        unaffected = self.source(task_id=2)
        unaffected_id = self.rt.publish({"entries": [self.item(unaffected)]})["saved"][0]["id"]
        self.db.execute(f"INSERT INTO {self.s}.source_exclusions(source_key,reason) "
                        "VALUES('task:1','Synthetic acceptance task, not a learning source')")
        self.rt.reconcile()
        entries = self.db.query(f"SELECT source_task_id,status FROM {self.s}.entries ORDER BY source_task_id")
        self.assertTrue(all(entry["status"] == "deprecated" for entry in entries if entry["source_task_id"] == 1))
        self.assertEqual(next(entry["status"] for entry in entries if entry["source_task_id"] == 2), "candidate")
        self.assertEqual(self.rt._finding_candidates(10, 1), [])
        self.assertEqual(self.rt._task_candidates(10, 1), [])
        retry = self.rt.publish({"entries": [self.item(sources[0])]})
        self.assertEqual(retry["saved"], [])
        self.assertIn("explicitly excluded", retry["rejected"][0]["error"])
        self.assertEqual([entry["id"] for entry in self.rt.search({"task_id": 2, "query": "authorization"})["experiences"]],
                         [unaffected_id])
        # A finding-level exclusion leaves its task's other sources eligible.
        self.db.execute(f"INSERT INTO {self.s}.source_exclusions(source_key,reason) "
                        "VALUES('finding:102','Synthetic finding excluded independently')")
        self.rt.reconcile()
        self.assertEqual(self.db.query(f"SELECT status FROM {self.s}.entries WHERE id={literal(unaffected_id)}")[0]["status"],
                         "deprecated")
        self.assertEqual(self.rt._finding_candidates(10, 2), [])


    def test_running_task_with_an_old_met_goal_is_not_repeatedly_curated(self):
        self.db.execute("UPDATE tasks SET status='running' WHERE id=4")
        self.db.execute("INSERT INTO exploration_nodes VALUES(402,44,'goal','planner','met','{}',now()-interval '30 minutes')")
        self.assertEqual(self.rt.snapshot({"source_task_id": 4})["sources"], [])

    def test_unrelated_new_facts_do_not_erase_a_negative_method_but_correction_does(self):
        first = self.source(task_id=4)
        item = self.item(first, title="Synthetic negative boundary")
        item["outcome"] = "negative"
        negative_id = self.rt.publish({"entries": [item]})["saved"][0]["id"]
        for node_id in range(402, 408):
            self.db.execute("INSERT INTO exploration_nodes VALUES(" + str(node_id) +
                ",44,'fact','worker','done'," + literal({"summary": "Unrelated observation " + str(node_id)}) +
                ",now()-interval '30 minutes')")
        self.assertEqual(self.rt.get({"id": negative_id, "task_id": 4})["experience"]["outcome"], "negative")
        later = self.source(task_id=4)
        later_id = self.rt.publish({"entries": [self.item(later, title="Synthetic different method")]})["saved"][0]["id"]
        self.assertEqual(self.rt.get({"id": negative_id, "task_id": 4})["experience"]["status"], "candidate")
        self.db.execute("UPDATE exploration_nodes SET payload=" + literal({"summary": "Original negative evidence was corrected."}) + " WHERE id=401")
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.rt.get({"id": negative_id, "task_id": 4})
        self.assertEqual(self.rt.get({"id": later_id, "task_id": 4})["experience"]["status"], "candidate")

    def test_task_snapshot_cannot_publish_after_a_cited_fact_changes(self):
        source = self.source(task_id=4)
        self.db.execute("UPDATE exploration_nodes SET payload=" + literal({"summary": "Corrected after snapshot."}) + " WHERE id=401")
        result = self.rt.publish({"entries": [self.item(source)]})
        self.assertEqual(result["saved"], [])
        self.assertIn("Cited task facts changed", result["rejected"][0]["error"])

    def test_feedback_requires_fresh_results_from_the_actual_intent(self):
        entry_id = self.rt.publish({"entries": [self.item(self.source())]})["saved"][0]["id"]
        self.rt.search({"task_id": 2, "query": "authorization"})
        self.db.execute("""INSERT INTO exploration_nodes VALUES
          (501,22,'intent','planner','done','{}',now()),
          (502,22,'work','worker','done','{}',now()),
          (503,22,'fact','worker','done','{}',now()),
          (504,22,'fact','worker','done','{}',now()),
          (505,22,'fact','worker','done','{}',now()-interval '1 day')""")
        self.db.execute("INSERT INTO exploration_edges VALUES(22,501,502,'runs'),(22,502,503,'produces'),(22,502,505,'produces')")
        payload = {"id": entry_id, "task_id": 2, "intent_id": 501, "event": "helpful", "note": "Synthetic observed result.", "evidence_node_ids": [503]}
        for node_id in (201, 504, 505):
            with self.subTest(node_id=node_id), self.assertRaisesRegex(ValueError, "Feedback evidence"):
                self.rt.feedback(dict(payload, evidence_node_ids=[node_id]))
        self.assertTrue(self.rt.feedback(payload)["evidence_linked"])
        record = self.db.query(f"SELECT evidence_node_ids FROM {self.s}.usage WHERE event='helpful'")[0]
        self.assertEqual(record["evidence_node_ids"], [503])
        self.assertEqual(self.rt.get({"id": entry_id, "task_id": 2})["experience"]["status"], "candidate")

    def test_activity_feedback_rejects_errors_as_positive_evidence(self):
        entry_id = self.rt.publish({"entries": [self.item(self.source())]})["saved"][0]["id"]
        self.rt.search({"task_id": 2, "query": "authorization"})
        self.raw.execute(f"ALTER TABLE {self.s}.activity ADD COLUMN created_at timestamptz DEFAULT now()")
        self.db.execute("INSERT INTO exploration_nodes VALUES(701,22,'intent','planner','done','{}',now()),(702,22,'work','worker','done','{}',now())")
        self.db.execute("INSERT INTO exploration_edges VALUES(22,701,702,'runs')")
        self.db.execute("""INSERT INTO activity VALUES
          (711,22,702,'tool_result','fixture','Observed','Synthetic independent result',false,now()),
          (712,22,702,'tool_result','fixture','Error','Synthetic transport error',true,now())""")
        payload = {"id": entry_id, "task_id": 2, "intent_id": 701, "event": "helpful", "note": "Synthetic current observation."}
        with self.assertRaisesRegex(ValueError, "Feedback evidence"):
            self.rt.feedback(dict(payload, evidence_activity_ids=[712]))
        self.assertTrue(self.rt.feedback(dict(payload, evidence_activity_ids=[711]))["evidence_linked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
