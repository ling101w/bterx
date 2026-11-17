"""Stable intent-level retrospective sources, including negative results."""
from storage import literal


def revision_sql():
    return """md5(concat_ws(chr(31),n.state,n.payload::text,
      (SELECT string_agg(x.id::text||':'||md5(x.payload::text)||':'||x.state,'|' ORDER BY x.id)
       FROM (SELECT f.id,f.payload,f.state FROM exploration_edges ed
         JOIN exploration_nodes f ON f.id=ed.dst_id AND f.exploration_id=ed.exploration_id
         WHERE ed.exploration_id=n.exploration_id AND ed.src_id=n.id AND ed.rel='yields'
         AND f.kind='fact' ORDER BY f.id DESC LIMIT 5) x)))"""


def candidates(runtime, limit, task_id):
    from experience_runtime import EXTRACTOR_VERSION
    scope = f"AND t.id={task_id}" if task_id else ""
    rev = revision_sql()
    return runtime.db.query(f"""WITH recent AS MATERIALIZED (
      SELECT n.*,t.id AS task_id,s.published_revision,s.published_extractor_version
      FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
      LEFT JOIN {runtime.s}.sources s ON s.source_key='intent:'||n.id::text
      WHERE n.kind='intent' AND n.state IN ('done','exhausted','blocked','stopped')
      AND t.deleted_at IS NULL AND n.updated_at<now()-interval '15 minutes' {scope}
      AND NOT EXISTS (SELECT 1 FROM {runtime.s}.source_exclusions x
        WHERE x.source_key='task:'||t.id::text OR x.source_key='intent:'||n.id::text)
      AND (s.source_key IS NULL OR s.published_extractor_version<>{literal(EXTRACTOR_VERSION)}
        OR s.published_revision<>s.revision OR n.updated_at>s.observed_at OR EXISTS (
          SELECT 1 FROM exploration_edges ed JOIN exploration_nodes f ON f.id=ed.dst_id
          AND f.exploration_id=ed.exploration_id WHERE ed.exploration_id=n.exploration_id
          AND ed.src_id=n.id AND ed.rel='yields' AND f.kind='fact' AND f.updated_at>s.observed_at))
      AND (s.lease_until IS NULL OR s.lease_until<now() OR n.updated_at>s.observed_at)
      ORDER BY n.id DESC LIMIT 128), eligible AS MATERIALIZED (
      SELECT n.* FROM recent n WHERE
      EXISTS (SELECT 1 FROM exploration_edges ed JOIN exploration_nodes f
        ON f.id=ed.dst_id AND f.exploration_id=ed.exploration_id
        WHERE ed.exploration_id=n.exploration_id AND ed.src_id=n.id AND ed.rel='yields'
        AND f.kind='fact' AND f.state<>'dismissed' AND length(trim(coalesce(f.payload->>'evidence','')))>15)
      AND NOT EXISTS (SELECT 1 FROM exploration_edges ed JOIN exploration_nodes f
        ON f.id=ed.dst_id AND f.exploration_id=ed.exploration_id
        WHERE ed.exploration_id=n.exploration_id AND ed.src_id=n.id AND ed.rel='yields'
        AND f.kind='fact' AND f.updated_at>now()-interval '15 minutes')
      ORDER BY (n.state<>'done') DESC,n.id DESC LIMIT 32),
      versioned AS MATERIALIZED (SELECT n.id,n.task_id,n.exploration_id,n.state,
      left(n.payload->>'summary',500) AS summary,{rev} AS revision
      ,n.published_revision,n.published_extractor_version FROM eligible n)
      SELECT id,task_id,exploration_id,state,summary,revision FROM versioned
      WHERE published_revision IS NULL OR published_revision<>revision
        OR published_extractor_version<>{literal(EXTRACTOR_VERSION)}
      ORDER BY (state<>'done') DESC,id DESC LIMIT {limit}""")


def snapshot(runtime, row):
    from experience_runtime import compact, redact
    tid, exp, intent_id = int(row["task_id"]), int(row["exploration_id"]), int(row["id"])
    companies, names = runtime.company_context(tid)
    facts = runtime.db.query(f"""SELECT f.id,f.state,f.payload,
      md5(concat_ws(chr(31),f.payload::text,f.state)) AS dependency_revision
      FROM exploration_edges ed JOIN exploration_nodes f ON f.id=ed.dst_id AND f.exploration_id=ed.exploration_id
      WHERE ed.exploration_id={exp} AND ed.src_id={intent_id} AND ed.rel='yields'
      AND f.kind='fact' AND f.state<>'dismissed' ORDER BY f.id DESC LIMIT 5""")
    evidence = [{"id": f"node:{f['id']}", "kind": "intent_result",
                 "dependency_revision": f["dependency_revision"], "text": redact(compact(f.get("payload") or {}), 1200)} for f in facts]
    warnings = []
    activities = runtime._optional_read(f"""SELECT id,is_error,left(summary,180) AS summary,left(detail,600) AS detail
      FROM activity WHERE exploration_id={exp} AND node_id={intent_id}
      AND kind IN ('result','tool_result') ORDER BY id DESC LIMIT 3""", warnings, "Intent execution excerpts")
    for activity in activities:
        evidence.append({"id": f"activity:{activity['id']}", "kind": "execution",
            "text": redact((activity.get("summary") or "")+"\n"+(activity.get("detail") or ""), 650),
            "is_error": bool(activity.get("is_error"))})
    return {"source_key": f"intent:{intent_id}", "source_type": "intent", "source_id": intent_id,
        "source_task_id": tid, "source_company_ids": companies, "company_names": names,
        "source_status": row["state"], "revision": row["revision"], "verification_level": "candidate",
        "verification_basis": "意图级局部结果；结束不等于成功，网络/模型错误不能当作方法无效",
        "title": redact(row.get("summary"), 500), "category": "intent_retrospective",
        "warnings": warnings, "evidence": evidence,
        "instruction": "优先提炼有证据的否定、失败边界或部分进展；必须写清前提和重开条件。纯工具/网络/模型故障通常跳过，不能总结成技术死路。"}
