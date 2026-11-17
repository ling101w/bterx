"""Host-owned curation batches. Model prose never decides delivery status."""
import json
import secrets

from storage import literal

TERMINAL = {"no_source", "saved", "partial", "skipped", "failed", "cancelled"}
SKIP_REASONS = {"duplicate", "not_applicable", "insufficient_evidence", "no_transferable_method"}


def inspect(runtime, run_id, conversation_id):
    from experience_runtime import ENTRY_ID, positive
    if not isinstance(run_id, str) or not ENTRY_ID.fullmatch(run_id):
        raise ValueError("Invalid curation run ID")
    cid = positive(conversation_id, "conversation_id")
    rows = runtime.db.query(f"SELECT * FROM {runtime.s}.curation_runs WHERE id={literal(run_id)} AND conversation_id={cid}")
    if not rows:
        raise ValueError("Curation run is not owned by this conversation")
    return rows[0]


def public_result(row):
    return {"run_id": row["id"], "status": row["status"],
            "saved_entry_ids": row.get("saved_entry_ids") or [],
            "rejected": row.get("rejected_items") or [], "skipped": row.get("skipped_items") or [],
            "error_code": row.get("error_code") or ""}


def prepare(runtime, payload):
    from experience_runtime import positive
    cid = positive(payload.get("conversation_id"), "conversation_id")
    runtime.db.execute(f"UPDATE {runtime.s}.curation_runs SET status='failed',error_code='lease_expired',finished_at=now() WHERE status IN ('prepared','running') AND lease_until<now()")
    active = runtime.db.query(f"SELECT * FROM {runtime.s}.curation_runs WHERE conversation_id={cid} AND status IN ('prepared','running') ORDER BY started_at DESC LIMIT 1")
    if active:
        row = active[0]
        return {**public_result(row), "sources": list((row.get("snapshots") or {}).values())}
    run_id = secrets.token_hex(12)
    trigger = payload.get("trigger_type", "manual")
    if trigger not in ("manual", "trigger"):
        raise ValueError("Invalid curation trigger type")
    runtime.db.execute(f"INSERT INTO {runtime.s}.curation_runs(id,conversation_id,status,trigger_type) VALUES ({literal(run_id)},{cid},'prepared',{literal(trigger)})")
    try:
        source_payload = {"limit": payload.get("limit", 2)}
        if payload.get("source_task_id"):
            source_payload["source_task_id"] = positive(payload["source_task_id"], "source_task_id")
        batch = runtime.snapshot(source_payload)
        sources = batch.get("sources") or []
        snapshots = {source["snapshot_id"]: source for source in sources}
        # Empty results after a failed read are not a successful no-source run.
        status = "running" if sources else "failed" if batch.get("warnings") else "no_source"
        error_code = "source_read_incomplete" if status == "failed" else ""
        runtime.db.execute(f"UPDATE {runtime.s}.curation_runs SET snapshots={literal(snapshots)},status={literal(status)},error_code={literal(error_code)},finished_at=CASE WHEN {literal(status)}='running' THEN NULL ELSE now() END WHERE id={literal(run_id)} AND status='prepared'")
        return {"run_id": run_id, "status": status, **batch}
    except Exception:
        runtime.db.execute(f"UPDATE {runtime.s}.curation_runs SET status='failed',error_code='source_prepare_failed',finished_at=now() WHERE id={literal(run_id)} AND status='prepared'")
        raise


def finish(runtime, payload):
    row = inspect(runtime, payload.get("run_id"), payload.get("conversation_id"))
    if row["status"] in TERMINAL:
        return public_result(row)
    status = "cancelled" if payload.get("cancelled") else "failed"
    code = "run_cancelled" if status == "cancelled" else "delivery_missing"
    runtime.db.execute(f"UPDATE {runtime.s}.curation_runs SET status={literal(status)},error_code={literal(code)},finished_at=now() WHERE id={literal(row['id'])} AND status IN ('prepared','running')")
    return public_result(inspect(runtime, row["id"], row["conversation_id"]))


def publish_run(runtime, payload):
    row = inspect(runtime, payload.get("_host_run_id"), payload.get("_host_conversation_id"))
    if payload.get("run_id") != row["id"]:
        raise ValueError("Publication must use the host's current run")
    if row["status"] in TERMINAL:
        return {**public_result(row), "duplicate": True, "saved": runtime.db.query(
            f"SELECT id,title,status FROM {runtime.s}.entries WHERE id IN (SELECT jsonb_array_elements_text({literal(row.get('saved_entry_ids') or [])}))")}
    expected = row.get("snapshots") or {}
    items, skips = payload.get("entries", []), payload.get("skipped", [])
    if not isinstance(items, list) or len(items) > 3 or not isinstance(skips, list) or len(skips) > 3:
        raise ValueError("A batch accepts at most three entries and skipped sources")
    entries, rejected, accepted_skips, handled = [], [], [], set()
    runtime.reconcile()
    for index, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("Entry must be an object")
            sid = item.get("snapshot_id")
            if not isinstance(sid, str) or sid not in expected or sid in handled:
                raise ValueError("Entry snapshot is outside this batch or duplicated")
            entry = runtime._prepare_publication(item, sid)
            if entry["source_revision"] != expected[sid]["revision"]:
                raise ValueError("Source revision changed after batch preparation")
            entries.append(entry)
            handled.add(sid)
        except ValueError as exc:
            rejected.append({"index": index, "error": str(exc)[:180]})
    for index, item in enumerate(skips):
        if not isinstance(item, dict):
            raise ValueError("Skipped source must be an object")
        sid, reason, note = item.get("snapshot_id"), item.get("reason"), item.get("note")
        if not isinstance(sid, str) or sid not in expected or sid in handled:
            raise ValueError("Skipped snapshot is outside this batch or duplicated")
        if not isinstance(reason, str) or reason not in SKIP_REASONS or not isinstance(note, str) or not 8 <= len(note.strip()) <= 600:
            raise ValueError("A skipped source requires a supported reason and a concrete note")
        current = runtime._publication_source(sid)
        if current["revision"] != expected[sid]["revision"]:
            raise ValueError("Skipped source revision changed after batch preparation")
        from experience_runtime import redact
        accepted_skips.append({"snapshot_id": sid, "reason": reason, "note": redact(note, 600)})
        handled.add(sid)
    missing = set(expected) - handled
    for sid in sorted(missing):
        rejected.append({"snapshot_id": sid, "error": "Source was not delivered or explicitly skipped"})
    if not entries and not accepted_skips:
        # One bounded repair remains possible; the host later seals the run.
        runtime.db.execute(f"UPDATE {runtime.s}.curation_runs SET rejected_items={literal(rejected)},attempt_count=attempt_count+1 WHERE id={literal(row['id'])} AND status='running'")
        return {"run_id": row["id"], "status": "running", "saved": [], "rejected": rejected, "skipped": []}
    status = "partial" if rejected else "saved" if entries else "skipped"
    saved_ids = [entry["id"] for entry in entries]
    prefix = [f"""DO $curation_guard$ BEGIN
      PERFORM 1 FROM {runtime.s}.curation_runs WHERE id={literal(row['id'])}
        AND conversation_id={row['conversation_id']} AND status='running' AND lease_until>now() FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'curation batch no longer active'; END IF;
      END $curation_guard$;"""]
    suffix = []
    for sid in handled:
        source = expected[sid]
        prefix.append(f"""DO $source_guard$ BEGIN
          PERFORM 1 FROM {runtime.s}.sources s WHERE s.source_key={literal(source['source_key'])}
            AND s.revision={literal(source['revision'])} AND s.snapshot_id={literal(sid)}
            AND NOT EXISTS (SELECT 1 FROM {runtime.s}.source_exclusions x
              WHERE x.source_key=s.source_key OR x.source_key='task:'||s.source_task_id::text) FOR SHARE;
          IF NOT FOUND THEN RAISE EXCEPTION 'curation source changed'; END IF;
          END $source_guard$;""")
    for skip in accepted_skips:
        source = expected[skip["snapshot_id"]]
        from experience_runtime import EXTRACTOR_VERSION
        suffix.append(f"UPDATE {runtime.s}.sources SET published_revision=revision,published_extractor_version={literal(EXTRACTOR_VERSION)},published_at=now(),lease_until=NULL WHERE source_key={literal(source['source_key'])} AND revision={literal(source['revision'])} AND snapshot_id={literal(skip['snapshot_id'])};")
    suffix.append(f"UPDATE {runtime.s}.curation_runs SET status={literal(status)},saved_entry_ids={literal(saved_ids)},rejected_items={literal(rejected)},skipped_items={literal(accepted_skips)},attempt_count=attempt_count+1,finished_at=now() WHERE id={literal(row['id'])} AND status='running';")
    saved = runtime._persist_entries(entries, prefix, suffix)
    return {"run_id": row["id"], "status": status, "saved": saved, "saved_entry_ids": saved_ids,
            "rejected": rejected, "skipped": accepted_skips}


def handle(payload, database=None):
    from experience_runtime import Runtime
    runtime = Runtime(database)
    mode = payload.get("_mode")
    if mode == "prepare": return prepare(runtime, payload)
    if mode == "inspect": return public_result(inspect(runtime, payload.get("run_id"), payload.get("conversation_id")))
    if mode == "finish": return finish(runtime, payload)
    raise ValueError("Unsupported curation host operation")


if __name__ == "__main__":
    import sys
    try: print(json.dumps(handle(json.load(sys.stdin)), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"error": "Curation host operation failed", "error_type": type(exc).__name__}))
        sys.exit(1)
