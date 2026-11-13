"""Explicit operator review; deliberately not registered as an agent tool."""
import argparse
import json
import re

from experience_runtime import Runtime, redact
from storage import Database, literal


def review(db, entry_id, decision, note, acknowledged=False):
    if not re.fullmatch(r"[0-9a-f]{24}", entry_id):
        raise ValueError("Invalid experience id")
    if decision not in ("verified", "candidate", "deprecated"):
        raise ValueError("Invalid decision")
    if not isinstance(note, str) or not 20 <= len(note.strip()) <= 1800:
        raise ValueError("Review note must explain the evidence and method checks (20-1800 characters)")
    if decision == "verified" and not acknowledged:
        raise ValueError("Verify requires explicit --method-and-evidence-reviewed acknowledgment")
    Runtime(db).reconcile()
    s = db.qualified_schema
    existing = db.query(f"SELECT id,status FROM {s}.entries WHERE id={literal(entry_id)}")
    if not existing:
        raise ValueError("Experience is unavailable")
    if decision == "verified" and existing[0]["status"] == "deprecated":
        raise ValueError("Deprecated evidence cannot be verified; obtain a fresh source revision")
    db.execute(f"""BEGIN; SELECT pg_advisory_xact_lock(7337741121);
      INSERT INTO {s}.reviews(experience_id,decision,note)
        VALUES({literal(entry_id)},{literal(decision)},{literal(redact(note.strip(), 1800))});
      UPDATE {s}.entries SET status={literal(decision)},
        verification_basis={literal('Explicit method and evidence review recorded; detailed notes are retained in the operator audit.')},updated_at=now()
        WHERE id={literal(entry_id)}; COMMIT;""")
    return db.query(f"SELECT id,title,status,verification_basis FROM {s}.entries WHERE id={literal(entry_id)}")[0]


def main():
    parser = argparse.ArgumentParser(description="Explicitly review an ARTEX experience method")
    parser.add_argument("id")
    parser.add_argument("decision", choices=("verified", "candidate", "deprecated"))
    parser.add_argument("--note", required=True)
    parser.add_argument("--method-and-evidence-reviewed", action="store_true")
    args = parser.parse_args()
    try:
        result = review(Database(), args.id, args.decision, args.note, args.method_and_evidence_reviewed)
    except Exception as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "Review operation failed"}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
