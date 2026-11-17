"""Real PostgreSQL checks using synthetic sources in a disposable owned schema.

Never reads target evidence or mutates ARTEX's original tables. The runtime's
source table names are redirected to synthetic fixtures inside this schema.
"""
import json
import re
import secrets

from experience_runtime import Runtime
from review_entry import review
from storage import Database, literal


SOURCE_TABLES = ("tasks", "companies", "task_scope", "findings", "finding_retests",
                 "exploration_nodes", "exploration_edges", "activity")


class IsolatedDatabase(Database):
    def _rewrite(self, sql):
        for table in SOURCE_TABLES:
            sql = re.sub(r"((?:\bFROM|\bJOIN|\bUPDATE|\bINTO)\s+|,\s*)" + table + r"\b",
                         lambda match: match.group(1) + self.qualified_schema + "." + table,
                         sql, flags=re.I)
        return sql

    def query(self, sql):
        return super().query(self._rewrite(sql))

    def execute(self, sql):
        rewritten = self._rewrite(sql)
        original_tables = "|".join(SOURCE_TABLES)
        if re.search(r"\b(?:ALTER\s+TABLE|DROP\s+TABLE|TRUNCATE(?:\s+TABLE)?)\s+(?:public\.)?(?:" + original_tables + r")\b",
                     rewritten, flags=re.I):
            raise ValueError("Isolated tests must qualify source-table DDL with their owned schema")
        return super().execute(rewritten)


def run():
    schema = "artex_experience_test_" + secrets.token_hex(6)
    db = IsolatedDatabase(schema=schema)
    raw = Database(schema=schema)
    checks = []
    try:
        db.migrate()
        db.migrate()
        s = db.qualified_schema
        # All IDs, names, and outputs below are synthetic fixtures.
        raw.execute(f"""BEGIN;
          CREATE TABLE {s}.companies(id bigint PRIMARY KEY,name text);
          CREATE TABLE {s}.tasks(id bigint PRIMARY KEY,company_id bigint,name text,goal text,
            description text,exploration_id bigint,status text,deleted_at timestamptz,
            completed_at timestamptz,updated_at timestamptz);
          CREATE TABLE {s}.task_scope(task_id bigint,kind text,company_id bigint);
          CREATE TABLE {s}.findings(id bigint PRIMARY KEY,task_id bigint,node_id bigint,vulnclass text,
            name text,summary text,evidence text,report text,status text,evidence_version bigint);
          CREATE TABLE {s}.finding_retests(id bigint PRIMARY KEY,finding_id bigint,status text,
            verdict text,evidence text);
          CREATE TABLE {s}.exploration_nodes(id bigint PRIMARY KEY,exploration_id bigint,kind text,
            origin text,state text,payload jsonb,updated_at timestamptz);
          CREATE TABLE {s}.exploration_edges(exploration_id bigint,src_id bigint,dst_id bigint,rel text);
          CREATE TABLE {s}.activity(id bigint PRIMARY KEY,exploration_id bigint,node_id bigint,
            kind text,tool text,summary text,detail text,is_error boolean);
          INSERT INTO {s}.companies VALUES(1,'Fixture One'),(2,'Fixture Two');
          INSERT INTO {s}.tasks VALUES
            (1,1,'Synthetic task one','Synthetic goal','fixture',11,'running',NULL,NULL,now()),
            (2,2,'Synthetic task two','Synthetic goal','fixture',22,'running',NULL,NULL,now()),
            (3,1,'Synthetic shared scope','Synthetic goal','fixture',33,'running',NULL,NULL,now()),
            (4,NULL,'Synthetic CTF','Synthetic goal','fixture',44,'done',NULL,now(),now());
          INSERT INTO {s}.findings VALUES
            (101,1,201,'auth','Synthetic authorization comparison','A controlled fixture result',
              'Synthetic direct output: identity A allowed and identity B denied. No real endpoint.',
              '', 'confirmed',0),
            (102,1,202,'parser','Synthetic parser hypothesis','A controlled candidate result',
              'Synthetic candidate output: response differed, independent proof is still absent.',
              '', 'pending',0);
          ALTER TABLE {s}.findings ADD COLUMN report_evidence_version bigint NOT NULL DEFAULT 0;
          INSERT INTO {s}.exploration_nodes VALUES
            (201,11,'finding','worker','done','{{}}',now()),
            (202,11,'finding','worker','done','{{}}',now()),
            (401,44,'fact','worker','done','{{"summary":"Synthetic task ended; no judge proof. flag{{fixture_only}}"}}',now());
          UPDATE {s}.tasks SET updated_at=now()-interval '30 minutes',completed_at=now()-interval '30 minutes' WHERE id=4;
          UPDATE {s}.exploration_nodes SET updated_at=now()-interval '30 minutes' WHERE id=401;
          COMMIT;""")
        rt = Runtime(db)
        snapshots = rt.snapshot({"limit": 2, "source_task_id": 1})["sources"]
        assert len(snapshots) == 2, snapshots
        checks.append("bounded source collection")

        entries = []
        for source in snapshots:
            entries.append({"snapshot_id": source["snapshot_id"],
                "title": "Authorization comparison" if source["source_id"] == 101 else "Parser hypothesis",
                "category": "auth" if source["source_id"] == 101 else "parser",
                "tags": ["authorization", "权限对照"] if source["source_id"] == 101 else ["parser"],
                "applicable_when": "Two identities are available for the same controlled resource.",
                "steps": ["Compare allowed results with an independent control."],
                "success_criteria": "Independent observable result supports the claim.",
                "pitfalls": ["An error response alone is not confirmation."],
                "not_applicable": "The required identities or authorization are missing.",
                "outcome": "success",
                "transfer_scope": "generic" if source["source_id"] == 101 else "project",
                "evidence_ids": [f"finding:{source['source_id']}/evidence"]})
        published = rt.publish({"entries": entries})["saved"]
        by_title = {entry["title"]: entry for entry in published}
        generic_id = by_title["Authorization comparison"]["id"]
        project_id = by_title["Parser hypothesis"]["id"]
        assert by_title["Authorization comparison"]["status"] == "candidate"
        assert by_title["Parser hypothesis"]["status"] == "candidate"
        rt.publish({"entries": entries})
        assert db.query(f"SELECT count(*) AS n FROM {s}.entries")[0]["n"] == 2
        review(db, generic_id, "verified", "Synthetic operator independently checked the method and original evidence.", True)
        checks.append("citation-linked publication, explicit method review, idempotency")

        # Untrusted SQL-like text is a value and cannot change any fixture table.
        injected = rt.search({"task_id": 2, "query": "authorization '; DROP TABLE tasks; --"})
        assert any(e["id"] == generic_id for e in injected["experiences"])
        assert db.query("SELECT count(*) AS n FROM tasks")[0]["n"] == 4
        assert not rt.search({"task_id": 2, "query": "parser"})["experiences"]
        assert rt.search({"task_id": 3, "query": "parser"})["experiences"]
        assert not rt.search({"task_id": 3, "query": "parser", "include_candidates": False})["experiences"]
        assert rt.search({"task_id": 0, "query": "权限对照"})["experiences"]
        cross = rt.get({"task_id": 2, "id": generic_id})["experience"]
        assert "evidence" not in cross and "source_task_id" not in cross
        assert "evidence" in rt.get({"task_id": 1, "id": generic_id})["experience"]
        try:
            rt.get({"task_id": 2, "id": project_id})
            raise AssertionError("Cross-project entry leaked")
        except ValueError:
            pass
        checks.append("keyword/CJK retrieval, injection resistance, project/evidence boundaries")

        db.execute("INSERT INTO exploration_nodes VALUES(601,22,'intent','planner','done','{}',now()),(602,22,'fact','worker','done','{}',now())")
        db.execute("INSERT INTO exploration_edges VALUES(22,601,602,'produces')")
        for unused in range(2):
            rt.feedback({"task_id": 2, "id": generic_id, "event": "helpful", "note": "Synthetic independent fixture used this method.",
                         "intent_id": 601, "evidence_node_ids": [602]})
        assert db.query(f"SELECT count(*) AS n FROM {s}.usage WHERE event='helpful'")[0]["n"] == 1
        assert rt.stats({})["entries"]
        checks.append("feedback prerequisites, retry deduplication, statistics")

        # Rejected source changes invalidate retrieval before a curator revisits it.
        db.execute("UPDATE findings SET status='false_positive' WHERE id=101")
        assert not rt.search({"task_id": 2, "query": "authorization"})["experiences"]
        db.execute("UPDATE findings SET evidence=evidence||' Source evidence updated.' WHERE id=102")
        assert not rt.search({"task_id": 1, "query": "parser"})["experiences"]
        assert db.query(f"SELECT count(*) AS n FROM {s}.entries WHERE status='deprecated'")[0]["n"] == 2
        checks.append("withdrawal and evidence-change invalidation")

        task_sources = rt.snapshot({"limit": 1, "source_task_id": 4})["sources"]
        assert len(task_sources) == 1 and task_sources[0]["verification_level"] == "candidate"
        assert "fixture_only" not in json.dumps(task_sources)
        task_entry = dict(entries[0], snapshot_id=task_sources[0]["snapshot_id"],
                          evidence_ids=["node:401"], title="Synthetic CTF method")
        assert rt.publish({"entries": [task_entry]})["saved"][0]["status"] == "candidate"
        db.execute("DELETE FROM tasks WHERE id=4")
        assert db.query(f"SELECT count(*) AS n FROM {s}.entries")[0]["n"] == 3
        checks.append("task completion never becomes judge proof; source deletion preserves memories")
        return {"passed": True, "checks": checks, "isolated_schema": schema}
    finally:
        # Exact, freshly generated ownership prefix; never a production schema.
        if re.fullmatch(r"artex_experience_test_[0-9a-f]{12}", schema):
            raw.execute(f"DROP SCHEMA IF EXISTS {raw.qualified_schema} CASCADE")


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False))
