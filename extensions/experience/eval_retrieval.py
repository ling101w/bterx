"""Frozen synthetic retrieval check in a disposable PostgreSQL schema.

No target is contacted. Results measure this fixture corpus, not CTF success.
Use ARTEX_EXPERIENCE_REVIEW_TEST=1 with a dedicated test database configuration.
"""
import hashlib
import json
import os
from pathlib import Path
import statistics
import time

import experience_runtime as memory
from experience_terms import lexical_tokens
import integration_review_test as fixtures
from storage import literal


METHODS = (
    ("auth", "authorization identity comparison", "Two controlled identities and a resource are required.", "success"),
    ("ssrf", "ssrf callback validation", "An authorized callback observer is required.", "success"),
    ("path", "path traversal canonicalization", "A controlled file read and a normal baseline are required.", "success"),
    ("upload", "file upload parser boundary", "An authorized upload and a known parser are required.", "success"),
    ("lfi", "lfi inclusion preconditions", "A confirmed inclusion operation is required.", "success"),
    ("deserialize", "deserialization format recognition", "The serialized format and consumer must be observed.", "success"),
    ("ssti", "ssti template expression comparison", "A template context and control are required.", "success"),
    ("race", "race condition controlled concurrency", "Independent controlled operations are required.", "success"),
    ("pitfall", "false positive business denial in HTTP 200", "The body and business status must be read.", "negative"),
    ("sqli", "sql injection parameter comparison", "A stable parameter baseline is required.", "success"),
    ("private", "private_scope_method", "Only the source project has the required context.", "success"),
    ("old", "retired_unique_method", "This method was explicitly deprecated.", "success"),
    ("corrected", "corrected_unique_method", "The original evidence has been replaced.", "success"),
    ("negative", "authorization current guard negative", "The current identity is denied; another role would need a new comparison.", "negative"),
    ("chain", "file upload lfi chain prerequisites", "Both the writable location and inclusion context must be independently observed.", "inconclusive"),
)


def seed(fixture):
    rt, s = fixture.rt, fixture.s
    ids, statements = {}, ["BEGIN;"]
    for index, (key, title, condition, outcome) in enumerate(METHODS):
        fid = 1000 + index
        proof = "Synthetic independently controlled observation for " + key
        source = {"source_key": f"finding:{fid}", "source_type": "finding", "source_id": fid,
                  "source_task_id": 1, "source_company_ids": [1], "company_names": ["Synthetic review scope"],
                  "revision": "fixture-" + key, "snapshot_id": f"{fid:024x}",
                  "verification_level": "confirmed", "verification_basis": "Synthetic fixture, method remains candidate",
                  "evidence_version": 0, "evidence_hash": hashlib.md5(proof.encode()).hexdigest(),
                  "report_hash": hashlib.md5(b"").hexdigest(), "report_evidence_version": 0,
                  "evidence": [{"id": f"finding:{fid}/evidence", "text": proof}]}
        item = fixture.item(source, title=title, scope="project" if key == "private" else "generic")
        item.update(category=key, tags=[key], applicable_when=condition, outcome=outcome,
                    steps=["Use independent controls to evaluate " + title], root_cause=title)
        entry = rt._entry(item, source)
        if key == "old":entry["status"] = "deprecated"
        ids[key] = entry["id"]
        statements.append(f"INSERT INTO {s}.findings(id,task_id,name,summary,evidence,report,status,evidence_version,report_evidence_version) VALUES({fid},1,{literal(title)},'Synthetic fixture',{literal(proof)},'','confirmed',0,0);")
        statements.append(f"INSERT INTO {s}.sources(source_key,source_type,source_id,source_task_id,revision,snapshot_id,snapshot) VALUES({literal(source['source_key'])},'finding',{fid},1,{literal(source['revision'])},{literal(source['snapshot_id'])},{literal(source)});")
        statements.append(f"INSERT INTO {s}.entries({','.join(entry)}) VALUES({','.join(literal(v) for v in entry.values())});")
    statements.append(f"UPDATE {s}.findings SET evidence='Synthetic corrected evidence' WHERE id=1012;")
    statements.append("COMMIT;")
    fixture.raw.execute("\n".join(statements))
    return ids


def evaluate(rt, ids, cases, tokenize):
    original = memory.tokens
    memory.tokens = tokenize
    rows, elapsed = [], []
    try:
        for case in cases:
            start = time.monotonic()
            result = rt.search({"task_id": case.get("task_id", 2), "query": case["query"], "limit": 3})["experiences"]
            elapsed.append((time.monotonic() - start) * 1000)
            got = {row["id"] for row in result}
            expected = {ids[key] for key in case["expected"]}
            passed = bool(got & expected) if expected else not got
            limitations = all(row.get("applicable_when") and row.get("not_applicable") for row in result)
            rows.append({"case": case["id"], "pass": passed and limitations, "returned": len(result),
                         "expected_match": bool(expected), "limitations_present": limitations})
    finally:
        memory.tokens = original
    match = [r for r in rows if r["expected_match"]]
    empty = [r for r in rows if not r["expected_match"]]
    return {"cases": len(rows), "passed": sum(r["pass"] for r in rows),
            "top3_hit_rate": round(sum(r["pass"] for r in match) / len(match), 4),
            "no_hit_false_recommendations": sum(not r["pass"] for r in empty),
            "p50_ms": round(statistics.median(elapsed), 1),
            "p95_ms": round(sorted(elapsed)[int((len(elapsed)-1)*.95)], 1),
            "model_calls": 0, "details": rows}


def main():
    if os.environ.get("ARTEX_EXPERIENCE_REVIEW_TEST") != "1":
        raise SystemExit("Explicit disposable PostgreSQL opt-in required")
    fixture = fixtures.ReviewRegressionTests("runTest")
    try:
        fixture.setUp()
        ids = seed(fixture)
        cases = json.loads(Path(__file__).with_name("retrieval_cases.json").read_text())
        baseline = evaluate(fixture.rt, ids, cases, lexical_tokens)
        current = evaluate(fixture.rt, ids, cases, memory.tokens)
        print(json.dumps({"corpus": "15 synthetic cards, 30 frozen queries; not a CTF success evaluation",
                          "baseline_without_aliases": baseline, "current": current}, ensure_ascii=False, indent=2))
        if current["passed"] != len(cases):raise SystemExit(1)
    finally:
        fixture.doCleanups()


if __name__ == "__main__":main()
