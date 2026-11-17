"""Install ARTEX experience tools through existing hot-loaded extension tables."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

from prompts import (BLOCK_BEGIN, BLOCK_END, COLLABORATION, CURATOR_KEY,
                     CURATOR_PROMPT, EXTENSION_REVISION, OWNER, RETRIEVER_KEY,
                     RETRIEVER_PROMPT, TOOL_DEFINITIONS, collaboration_block)

DEFAULT_CONFIG = "/home/maming/apps/artex-1/config.json"
DEFAULT_APP = "/home/maming/apps/artex-experience"
LOCK_ID = 7611120261111
TOOL_FIELDS = ("key", "system", "description", "schema", "agents", "enabled", "kind", "exec", "deferred")
TRIGGER_FIELDS = ("id", "agent_key", "enabled", "interval_sec", "on_finding", "on_goal_met", "on_task_timeout",
                  "on_tool_call", "on_task_create", "interval_message", "finding_message", "goal_message",
                  "task_timeout_message", "tool_call_message", "task_create_message", "tool_names")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def json_write_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if temp.exists():
            temp.unlink()


def load_state(path):
    if not Path(path).exists():
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("owner") != OWNER or not value.get("marker"):
        raise RuntimeError("安装状态文件不属于本扩展，已拒绝覆盖")
    return value


def wrapper_code(mode, app_dir, config_path=DEFAULT_CONFIG, schema="artex_experience"):
    # The tool decides the mode; callers cannot turn a read tool into a writer.
    return (
        "import json,sys\n"
        f"sys.path.insert(0,{str(app_dir)!r})\n"
        "try:\n"
        f" import {'experience_retrieval' if mode == 'ask' else 'experience_runtime'} as experience_handler\n"
        " from storage import Database\n"
        " payload=json.load(sys.stdin)\n"
        " if not isinstance(payload,dict): raise ValueError('参数必须是JSON对象')\n"
        f" payload['_mode']={mode!r}\n"
        f" database=Database(config_path={str(config_path)!r},schema={schema!r})\n"
        " result=experience_handler.handle(payload,database=database)\n"
        "except ValueError as exc:\n"
        " result={'error':str(exc)[:240],'error_type':'ValueError'}\n"
        "except Exception:\n"
        " result={'error':'经验工具执行失败，请查看扩展状态或由管理员检查；未输出配置或堆栈'}\n"
        "print(json.dumps(result,ensure_ascii=False,default=str))\n"
    )


def tool_manifest(app_dir, solver_keys, marker, config_path=DEFAULT_CONFIG, schema="artex_experience"):
    out = []
    for key, definition in TOOL_DEFINITIONS.items():
        bindings = [CURATOR_KEY] if definition["audience"] == "curator" else list(solver_keys)
        if key == "experience_snapshot":
            bindings = []  # Host prepares the batch; the curator only publishes.
        if key in ("experience_search", "experience_get", "experience_stats"):
            bindings.append(RETRIEVER_KEY)
        out.append({
            "key": key, "system": False,
            "description": definition["description"] + " " + marker,
            "schema": definition["schema"],
            "agents": list(dict.fromkeys(bindings)),
            "enabled": True, "kind": "script", "deferred": False,
            "exec": {"code": wrapper_code(definition["mode"], app_dir, config_path, schema),
                     "timeout_ms": 210000 if definition["mode"] == "ask" else 45000},
        })
    return out


def db_for(args):
    from storage import Database
    return Database(config_path=args.config, schema=args.schema)


def lit(value):
    from storage import literal
    return literal(value)


def json_lit(value):
    return lit(json.dumps(value, ensure_ascii=False)) + "::jsonb"


def metadata(db):
    agents = db.query("""SELECT a.id,a.key,a.name,a.description,a.builtin,a.enabled,a.role,
        a.llm_profile_id,a.current_prompt_id,p.version,p.template_text,p.note
        FROM agents a LEFT JOIN agent_prompts p ON p.id=a.current_prompt_id
        WHERE a.key IN ('planner','worker','auto','mainagent','pentest','chain_reviewer','experience_curator','experience_retriever')
           OR a.role IN ('planner','worker','main') ORDER BY a.id""")
    keys = ",".join(lit(key) for key in TOOL_DEFINITIONS)
    tools = db.query(f"SELECT key,system,description,schema,agents,enabled,kind,exec,deferred,updated_at FROM tools WHERE key IN ({keys}) ORDER BY key")
    triggers = db.query(f"SELECT {','.join(TRIGGER_FIELDS)},updated_at FROM agent_triggers WHERE agent_key={lit(CURATOR_KEY)} ORDER BY id")
    return {"agents": agents, "tools": tools, "triggers": triggers}


def solver_keys(meta):
    return [row["key"] for row in meta["agents"]
            if row["key"] in ("auto", "pentest") or row["role"] in ("planner", "worker", "main")]


def check_collisions(meta, state=None):
    marker = state["marker"] if state else None
    for tool in meta["tools"]:
        if not marker or marker not in (tool.get("description") or "") or tool.get("system") or tool.get("kind") != "script":
            raise RuntimeError(f"工具 {tool['key']} 已存在且不能确认归属本次安装，已拒绝覆盖")
    for row in meta["agents"]:
        if row["key"] in (CURATOR_KEY, RETRIEVER_KEY) and (not marker or marker not in (row.get("description") or "") or row.get("builtin")):
            raise RuntimeError(f"{row['key']} 已存在且不能确认归属，已拒绝覆盖")
    for row in meta["triggers"]:
        if not marker or marker not in (row.get("interval_message") or ""):
            raise RuntimeError("经验整理Agent已有其他触发器，已拒绝覆盖")


def capture_created(db, state):
    marker = state["marker"]
    state["agent_ids"] = [row["id"] for row in db.query(
        f"SELECT id FROM agents WHERE key IN ({lit(CURATOR_KEY)},{lit(RETRIEVER_KEY)}) AND position({lit(marker)} in coalesce(description,''))>0")]
    state["trigger_ids"] = [row["id"] for row in db.query(
        f"SELECT id FROM agent_triggers WHERE agent_key={lit(CURATOR_KEY)} AND position({lit(marker)} in interval_message)>0")]
    rows = db.query(f"""SELECT p.id,a.id AS agent_id,a.key FROM agent_prompts p
        JOIN agents a ON a.id=p.agent_id AND a.current_prompt_id=p.id
        WHERE p.note={lit(marker + ':curator')}
           OR p.note={lit(marker + ':retriever')}
           OR p.note={lit(marker + ':collaboration')}
           OR position({lit(marker + ':upgrade:')} in coalesce(p.note,''))=1 ORDER BY p.id""")
    for row in rows:
        state.setdefault("created_prompts", {})[row["key"]] = row["id"]
    return state


def fingerprint(row, fields):
    value = {key: row.get(key) for key in fields}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def record_managed(db, state, tool_keys=None, trigger_ids=None):
    meta = metadata(db)
    marker = state["marker"]
    tool_keys = set(tool_keys) if tool_keys is not None else None
    trigger_ids = {str(value) for value in trigger_ids} if trigger_ids is not None else None
    for row in meta["tools"]:
        if marker in (row.get("description") or "") and (tool_keys is None or row["key"] in tool_keys):
            state.setdefault("managed_tools", {})[row["key"]] = fingerprint(row, TOOL_FIELDS)
    for row in meta["triggers"]:
        if marker in (row.get("interval_message") or "") and (trigger_ids is None or str(row["id"]) in trigger_ids):
            state.setdefault("managed_triggers", {})[str(row["id"])] = fingerprint(row, TRIGGER_FIELDS)
    return state


def is_untouched(row, baseline, installed_at, fields):
    if baseline:
        return fingerprint(row, fields) == baseline
    # Older install-state files did not contain hashes. A row modified after
    # the initial install cannot safely be assumed to be installer-controlled.
    if not row.get("updated_at") or not installed_at:
        return False
    try:
        updated = datetime.fromisoformat(str(row["updated_at"]).replace("Z", "+00:00"))
        installed = datetime.fromisoformat(str(installed_at).replace("Z", "+00:00"))
        return updated <= installed
    except (ValueError, TypeError):
        return False


def trigger_messages(marker):
    message = ("只按当前经验整理提示词读取一次 experience_snapshot(limit=2)。有可迁移来源则保存，"
               "没有来源立即结束；不要扫描、访问目标或执行历史命令。 " + marker)
    event = message + " 若本次事件上下文提供了真实任务编号，快照额外传 source_task_id=该编号，只整理这个任务；不要猜测编号。"
    return message, event


def legacy_trigger_unchanged(row, marker):
    """Compare initial contents; scheduler last_fire also changes updated_at."""
    message, event_message = trigger_messages(marker)
    expected = dict(id=row["id"], agent_key=CURATOR_KEY, enabled=True, interval_sec=1800,
                    on_finding=False, on_goal_met=True, on_task_timeout=True,
                    on_tool_call=False, on_task_create=False, interval_message=message,
                    finding_message="", goal_message=message, task_timeout_message=message,
                    tool_call_message="", task_create_message="", tool_names="")
    if fingerprint(row, TRIGGER_FIELDS) == fingerprint(expected, TRIGGER_FIELDS):
        return True
    # Some first installations already carried the event-scoped message.
    expected.update(goal_message=event_message, task_timeout_message=event_message)
    return fingerprint(row, TRIGGER_FIELDS) == fingerprint(expected, TRIGGER_FIELDS)


def retriever_seed_sql(marker, note):
    return f"""DO $experience_retriever_seed$ DECLARE aid bigint; pid bigint; BEGIN
      IF EXISTS(SELECT 1 FROM agents WHERE key={lit(RETRIEVER_KEY)} AND
        (builtin OR position({lit(marker)} in coalesce(description,''))=0)) THEN
        RAISE EXCEPTION 'experience retriever ownership conflict'; END IF;
      INSERT INTO agents(key,name,description,role,builtin,enabled,llm_profile_id,
        max_turns,run_seconds,web_search,interactive_shell,trigger_run_mode,trigger_merge_mode,
        trigger_max_parallel,wrapup_prompt,wrapup_max_turns)
        VALUES({lit(RETRIEVER_KEY)},'经验检索',
          {lit('按需检索已有经验和报告链路，只返回条件、编号和限制，不验证目标。 ' + marker)},
          'assistant',false,true,NULL,4,100,false,false,'serial','none',1,
          '立即停止检索，只根据已读到的经验给出简短答复；未检索成功如实说明。',1)
        ON CONFLICT(key) DO NOTHING RETURNING id INTO aid;
      IF aid IS NOT NULL THEN
        INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
          VALUES(aid,1,{lit(RETRIEVER_PROMPT)},{lit(note)},'experience-installer') RETURNING id INTO pid;
        UPDATE agents SET current_prompt_id=pid WHERE id=aid;
      END IF;
      END $experience_retriever_seed$;"""


def build_install_sql(meta, state, manifest):
    marker = state["marker"]
    statements = ["BEGIN;", f"SELECT pg_advisory_xact_lock({LOCK_ID});"]
    # Recheck collisions inside the transaction, so another installer cannot win a race.
    keys = ",".join(lit(key) for key in TOOL_DEFINITIONS)
    statements.append(f"""DO $experience_guard$ BEGIN
        IF EXISTS(SELECT 1 FROM tools WHERE key IN ({keys}) AND
          (system OR kind<>'script' OR position({lit(marker)} in description)=0)) THEN
          RAISE EXCEPTION 'experience tool ownership conflict'; END IF;
        IF EXISTS(SELECT 1 FROM agents WHERE key IN ({lit(CURATOR_KEY)},{lit(RETRIEVER_KEY)}) AND
          (builtin OR position({lit(marker)} in coalesce(description,''))=0)) THEN
          RAISE EXCEPTION 'experience agent ownership conflict'; END IF;
        END $experience_guard$;""")
    statements.append(f"""INSERT INTO agents(key,name,description,role,builtin,enabled,llm_profile_id,
        max_turns,run_seconds,web_search,interactive_shell,trigger_run_mode,trigger_merge_mode,trigger_max_parallel,
        wrapup_prompt,wrapup_max_turns)
        VALUES ({lit(CURATOR_KEY)},'经验整理',{lit('把已发生证据整理为可检索的跨任务经验。 ' + marker)},
        'assistant',false,true,NULL,6,180,false,false,'serial','all',1,
        {lit('停止整理，不运行命令或访问目标；只如实报告已保存的经验及未完成原因。')},1)
        ON CONFLICT(key) DO NOTHING;""")
    statements.append(f"""INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
        SELECT a.id,coalesce((SELECT max(p.version) FROM agent_prompts p WHERE p.agent_id=a.id),0)+1,
        {lit(CURATOR_PROMPT)},{lit(marker + ':curator')},'experience-installer'
        FROM agents a WHERE a.key={lit(CURATOR_KEY)} AND NOT EXISTS
        (SELECT 1 FROM agent_prompts p WHERE p.agent_id=a.id AND p.note={lit(marker + ':curator')});""")
    statements.append(f"""UPDATE agents SET current_prompt_id=(SELECT id FROM agent_prompts WHERE agent_id=agents.id
        AND note={lit(marker + ':curator')} ORDER BY version DESC LIMIT 1)
        WHERE key={lit(CURATOR_KEY)} AND current_prompt_id IS NULL;""")
    statements.append(retriever_seed_sql(marker, marker + ':retriever'))
    for tool in manifest:
        statements.append(f"""INSERT INTO tools(key,system,description,schema,agents,enabled,kind,exec,deferred)
            VALUES ({lit(tool['key'])},false,{lit(tool['description'])},{json_lit(tool['schema'])},
            {json_lit(tool['agents'])},true,'script',{json_lit(tool['exec'])},false)
            ON CONFLICT(key) DO NOTHING;""")
    for row in meta["agents"]:
        if row["key"] not in COLLABORATION:
            continue
        if not row.get("template_text"):
            raise RuntimeError(f"{row['key']} 没有可备份的当前提示词，不能用简短协作段替换其默认正文")
        if BLOCK_BEGIN in row["template_text"] or BLOCK_END in row["template_text"]:
            raise RuntimeError(f"{row['key']} 已有经验协作标记但无可用安装状态，已拒绝重复追加")
        updated = row["template_text"].rstrip() + "\n\n" + collaboration_block(row["key"]) + "\n"
        statements.append(f"""DO $experience_prompt$ DECLARE new_id bigint; BEGIN
          IF (SELECT current_prompt_id FROM agents WHERE id={int(row['id'])} FOR UPDATE)
             IS DISTINCT FROM {lit(row['current_prompt_id'])} THEN
             RAISE EXCEPTION 'agent prompt changed during installation'; END IF;
          INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
          SELECT {int(row['id'])},coalesce(max(version),0)+1,{lit(updated)},
             {lit(marker + ':collaboration')},'experience-installer'
          FROM agent_prompts WHERE agent_id={int(row['id'])} RETURNING id INTO new_id;
          UPDATE agents SET current_prompt_id=new_id WHERE id={int(row['id'])};
          END $experience_prompt$;""")
    message, event_message = trigger_messages(marker)
    statements.append(f"""INSERT INTO agent_triggers(agent_key,enabled,interval_sec,on_goal_met,on_task_timeout,
        interval_message,goal_message,task_timeout_message)
        SELECT {lit(CURATOR_KEY)},true,3600,false,true,{lit(message)},{lit(event_message)},{lit(event_message)}
        WHERE NOT EXISTS(SELECT 1 FROM agent_triggers WHERE agent_key={lit(CURATOR_KEY)}
        AND position({lit(marker)} in interval_message)>0);""")
    statements.append("COMMIT;")
    return "\n".join(statements)


def status(db, state=None):
    meta = metadata(db)
    public = {
        "extension": OWNER, "installed": bool(state),
        "installation_status": state.get("status") if state else "not_installed",
        "revision": state.get("revision", "initial") if state else None,
        "pending_upgrade": bool(state and state.get("pending_upgrade")),
        "tools": [{k: row[k] for k in ("key", "kind", "enabled", "agents")} for row in meta["tools"]],
        "curator": [{k: row.get(k) for k in ("id", "key", "enabled", "llm_profile_id")}
                    for row in meta["agents"] if row["key"] == CURATOR_KEY],
        "retriever": [{k: row.get(k) for k in ("id", "key", "enabled", "llm_profile_id")}
                      for row in meta["agents"] if row["key"] == RETRIEVER_KEY],
        "triggers": [{k: row[k] for k in ("id", "enabled", "interval_sec")} for row in meta["triggers"]],
    }
    if state:
        current = {row["key"]: row.get("current_prompt_id") for row in meta["agents"]}
        public["collaboration_prompts"] = {
            key: {"installed_version_id": pid, "current_is_installed": current.get(key) == pid}
            for key, pid in state.get("created_prompts", {}).items() if key in COLLABORATION}
    return public


def install(args, db, state_path, state):
    meta = metadata(db)
    check_collisions(meta, state)
    if state and state.get("status") == "installed":
        result = status(db, state)
        result["idempotent"] = True
        result["message"] = "已安装；保留安装后的用户修改，没有重写工具、提示词或触发器。"
        return result
    if state:
        # A process failure after COMMIT may leave the private state at 'installing'.
        state = capture_created(db, state)
        if state.get("agent_ids") and state.get("trigger_ids") and len(meta["tools"]) == len(TOOL_DEFINITIONS):
            if state.get("status") == "rolled_back":
                raise RuntimeError("该安装已回滚；请保留数据并核对现有配置后再决定重新启用，安装器不覆盖后续修改")
            state["status"] = "installed"
            json_write_private(state_path, state)
            return status(db, state)
        raise RuntimeError("发现未完成的安装状态；请先运行 rollback 安全停用，再核对备份，不能盲目覆盖")
    install_id = secrets.token_hex(8)
    marker = f"[{OWNER}:{install_id}]"
    manifest = tool_manifest(args.app_dir, solver_keys(meta), marker, args.config, args.schema)
    if not solver_keys(meta):
        raise RuntimeError("没有找到可绑定的解题Agent，已停止安装")
    state = {"owner": OWNER, "state_version": 1, "install_id": install_id, "marker": marker,
             "status": "installing", "created_at": utc_now(), "schema": args.schema,
             "app_dir": str(args.app_dir), "tool_keys": list(TOOL_DEFINITIONS),
             "before": meta, "created_prompts": {}, "agent_ids": [], "trigger_ids": []}
    sql = build_install_sql(meta, state, manifest)
    backup_path = Path(args.app_dir) / "backups" / f"install-before-{install_id}.json"
    state["backup_path"] = str(backup_path)
    json_write_private(backup_path, state)
    json_write_private(state_path, state)
    try:
        db.migrate()
        db.execute(sql)
        state = capture_created(db, state)
        state = record_managed(db, state)
        state["status"] = "installed"
        state["installed_at"] = utc_now()
        json_write_private(state_path, state)
        json_write_private(backup_path, state)
    except Exception:
        state["status"] = "installing"
        json_write_private(state_path, state)
        raise
    result = status(db, state)
    result["message"] = "安装完成；新规划轮和新worker运行会读取扩展配置，无需重启。"
    return result


def replace_collaboration(text, key):
    if text.count(BLOCK_BEGIN) != 1 or text.count(BLOCK_END) != 1:
        raise RuntimeError("协作标记不完整或重复，不能安全自动替换")
    start = text.index(BLOCK_BEGIN)
    end = text.index(BLOCK_END, start) + len(BLOCK_END)
    return text[:start] + collaboration_block(key) + text[end:]


def extract_collaboration(text):
    if not isinstance(text, str) or text.count(BLOCK_BEGIN) != 1 or text.count(BLOCK_END) != 1:
        return None
    start=text.index(BLOCK_BEGIN)
    end=text.index(BLOCK_END,start)+len(BLOCK_END)
    return text[start:end]


def compare_row_sql(row, fields):
    conditions = []
    for field in fields:
        value = row.get(field)
        conditions.append(f"{field} IS NOT DISTINCT FROM {lit(value)}")
    if row.get("updated_at"):
        conditions.append(f"updated_at={lit(str(row['updated_at']))}::timestamptz")
    return " AND ".join(conditions)


def build_upgrade_sql(args, meta, state, upgrade_id):
    marker = state["marker"]
    plan = {"revision": EXTENSION_REVISION, "agents": [], "tools": [], "prompts": [], "triggers": [],
            "preserved_user_prompt_ids": {}, "skipped": {}}
    statements = ["BEGIN;", f"SELECT pg_advisory_xact_lock({LOCK_ID});"]
    if not any(row['key']==RETRIEVER_KEY for row in meta['agents']):
        statements.append(retriever_seed_sql(marker, marker + ':upgrade:' + EXTENSION_REVISION + ':' + upgrade_id + ':retriever'))
        plan['agents'].append(RETRIEVER_KEY)
        plan['prompts'].append(RETRIEVER_KEY)
    desired_tools = {row["key"]: row for row in tool_manifest(
        args.app_dir, solver_keys(meta), marker, args.config, args.schema)}
    existing_keys={row['key'] for row in meta['tools']}
    for key,desired in desired_tools.items():
        if key in existing_keys:
            continue
        statements.append(f"""DO $experience_new_tool$ BEGIN
          IF EXISTS(SELECT 1 FROM tools WHERE key={lit(key)}) THEN
            RAISE EXCEPTION 'experience new tool ownership conflict'; END IF;
          INSERT INTO tools(key,system,description,schema,agents,enabled,kind,exec,deferred)
          VALUES({lit(key)},false,{lit(desired['description'])},{json_lit(desired['schema'])},
            {json_lit(desired['agents'])},true,'script',{json_lit(desired['exec'])},false);
          END $experience_new_tool$;""")
        plan['tools'].append(key)
    for row in meta["tools"]:
        key = row["key"]
        baseline = state.get("managed_tools", {}).get(key)
        if not is_untouched(row, baseline, state.get("installed_at"), TOOL_FIELDS):
            plan["skipped"]["tool:" + key] = "安装后有修改或无法确认基线，保留现状"
            continue
        desired = desired_tools[key]
        if fingerprint(row, TOOL_FIELDS) == fingerprint(desired, TOOL_FIELDS):
            continue
        guard = compare_row_sql(row, TOOL_FIELDS)
        statements.append(f"""DO $experience_tool_upgrade$ BEGIN
          IF NOT EXISTS(SELECT 1 FROM tools WHERE key={lit(key)} AND {guard} FOR UPDATE) THEN
            RAISE EXCEPTION 'experience tool changed during upgrade'; END IF;
          UPDATE tools SET description={lit(desired['description'])},schema={json_lit(desired['schema'])},
            agents={json_lit(desired['agents'])},kind='script',exec={json_lit(desired['exec'])},deferred=false
            WHERE key={lit(key)};
          END $experience_tool_upgrade$;""")
        plan["tools"].append(key)
    before_by_key = {row["key"]: row for row in state["before"]["agents"]}
    for row in meta["agents"]:
        key = row["key"]
        if key not in (CURATOR_KEY,RETRIEVER_KEY) and key not in COLLABORATION:
            continue
        current_id = row.get("current_prompt_id")
        managed_id = state.get("created_prompts", {}).get(key)
        if managed_id is not None:
            if current_id != managed_id:
                old_text=meta.get('owned_prompt_baselines',{}).get(key)
                old_block=extract_collaboration(old_text)
                current_block=extract_collaboration(row.get('template_text'))
                if key in COLLABORATION and old_block and current_block==old_block:
                    plan['preserved_user_prompt_ids'][key]=current_id
                else:
                    plan["skipped"]["prompt:" + key] = "当前已是用户后续版本且协作块也有修改或无基线，保留现状"
                    continue
        else:
            original = before_by_key.get(key)
            if not original or current_id != original.get("current_prompt_id"):
                plan["skipped"]["prompt:" + key] = "首次追加时原提示词已变化或无安装前基线，保留现状"
                continue
        text = row.get("template_text")
        if not text:
            plan["skipped"]["prompt:" + key] = "当前提示词为空，不能覆盖默认正文"
            continue
        if key in (CURATOR_KEY,RETRIEVER_KEY):
            updated = CURATOR_PROMPT if key==CURATOR_KEY else RETRIEVER_PROMPT
        elif managed_id is not None:
            try:
                updated = replace_collaboration(text, key)
            except RuntimeError:
                plan["skipped"]["prompt:" + key] = "协作标记异常，保留现状"
                continue
        else:
            if BLOCK_BEGIN in text or BLOCK_END in text:
                plan["skipped"]["prompt:" + key] = "已有未登记协作块，保留现状"
                continue
            updated = text.rstrip() + "\n\n" + collaboration_block(key) + "\n"
        if updated == text:
            continue
        suffix = "curator" if key == CURATOR_KEY else "retriever" if key==RETRIEVER_KEY else "collaboration"
        note = marker + ":upgrade:" + EXTENSION_REVISION + ":" + upgrade_id + ":" + suffix
        statements.append(f"""DO $experience_prompt_upgrade$ DECLARE new_id bigint; BEGIN
          IF NOT EXISTS(SELECT 1 FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id
            WHERE a.id={int(row['id'])} AND a.current_prompt_id={lit(current_id)}
              AND p.template_text={lit(text)} FOR UPDATE OF a) THEN
            RAISE EXCEPTION 'agent prompt changed during upgrade'; END IF;
          INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
            SELECT {int(row['id'])},coalesce(max(version),0)+1,{lit(updated)},
              {lit(note)},'experience-installer' FROM agent_prompts
              WHERE agent_id={int(row['id'])} RETURNING id INTO new_id;
          UPDATE agents SET current_prompt_id=new_id WHERE id={int(row['id'])};
          END $experience_prompt_upgrade$;""")
        plan["prompts"].append(key)
    message, event_message = trigger_messages(marker)
    for row in meta["triggers"]:
        key = str(row["id"])
        baseline = state.get("managed_triggers", {}).get(key)
        untouched = (fingerprint(row, TRIGGER_FIELDS) == baseline if baseline
                     else legacy_trigger_unchanged(row, marker))
        if not untouched:
            plan["skipped"]["trigger:" + key] = "触发器安装后有修改或无法确认基线，保留现状"
            continue
        if (row.get("interval_sec") == 3600 and not row.get("on_goal_met")
                and row.get("interval_message") == message and row.get("goal_message") == event_message
                and row.get("task_timeout_message") == event_message):
            continue
        guard = compare_row_sql(row, TRIGGER_FIELDS)
        statements.append(f"""DO $experience_trigger_upgrade$ BEGIN
          IF NOT EXISTS(SELECT 1 FROM agent_triggers WHERE id={int(row['id'])} AND {guard} FOR UPDATE) THEN
            RAISE EXCEPTION 'experience trigger changed during upgrade'; END IF;
          UPDATE agent_triggers SET interval_sec=3600,on_goal_met=false,
            interval_message={lit(message)},goal_message={lit(event_message)},
            task_timeout_message={lit(event_message)} WHERE id={int(row['id'])};
          END $experience_trigger_upgrade$;""")
        plan["triggers"].append(row["id"])
    statements.append("COMMIT;")
    return "\n".join(statements), plan


def upgrade(args, db, state_path, state):
    if not state or state.get("status") != "installed":
        raise RuntimeError("只有已安装且未回滚的本扩展可以增量升级")
    if state.get("pending_upgrade"):
        raise RuntimeError("发现未核对完成的升级，请先检查私有升级备份和实际当前版本，不会盲目重复覆盖")
    meta = metadata(db)
    check_collisions(meta, state)
    ids=[int(pid) for pid in state.get('created_prompts',{}).values()]
    if ids:
        rows=db.query(f"SELECT a.key,p.template_text FROM agent_prompts p JOIN agents a ON a.id=p.agent_id WHERE p.id IN ({','.join(str(pid) for pid in ids)}) AND position({lit(state['marker'])} in coalesce(p.note,''))=1")
        meta['owned_prompt_baselines']={row['key']:row['template_text'] for row in rows}
    upgrade_id = secrets.token_hex(8)
    sql, plan = build_upgrade_sql(args, meta, state, upgrade_id)
    if args.dry_run:
        return {"dry_run": True, "writes": False, "upgrade": plan}
    if not (plan["agents"] or plan["tools"] or plan["prompts"] or plan["triggers"]):
        return {"idempotent": True, "message": "没有可安全应用的差异；未覆盖用户后续修改。", "upgrade": plan}
    backup_path = Path(args.app_dir) / "backups" / f"upgrade-before-{upgrade_id}.json"
    backup = {"owner": OWNER, "marker": state["marker"], "upgrade_id": upgrade_id,
              "revision": EXTENSION_REVISION, "created_at": utc_now(), "before": meta,
              "plan": plan, "state_before": deepcopy(state)}
    json_write_private(backup_path, backup)
    state["pending_upgrade"] = {"id": upgrade_id, "revision": EXTENSION_REVISION,
                                "backup_path": str(backup_path)}
    json_write_private(state_path, state)
    db.migrate()
    db.execute(sql)
    state = capture_created(db, state)
    state['tool_keys']=list(dict.fromkeys(state.get('tool_keys',[])+plan['tools']))
    state.setdefault('rollback_prompt_ids',{}).update(plan['preserved_user_prompt_ids'])
    # Store what this transaction wrote, not a later user's possible edit.
    expected_tools = {row["key"]: row for row in tool_manifest(
        args.app_dir, solver_keys(meta), state["marker"], args.config, args.schema)}
    for key in plan["tools"]:
        state.setdefault("managed_tools", {})[key] = fingerprint(expected_tools[key], TOOL_FIELDS)
    message, event_message = trigger_messages(state["marker"])
    for row in meta["triggers"]:
        if row["id"] in plan["triggers"]:
            expected = dict(row, interval_sec=3600,on_goal_met=False,interval_message=message, goal_message=event_message,
                            task_timeout_message=event_message)
            state.setdefault("managed_triggers", {})[str(row["id"])] = fingerprint(expected, TRIGGER_FIELDS)
    applied = {"id": upgrade_id, "revision": EXTENSION_REVISION, "applied_at": utc_now(),
               "backup_path": str(backup_path), "plan": plan,
               "before_prompts": {row["key"]: row.get("current_prompt_id") for row in meta["agents"]
                                  if row["key"] in plan["prompts"]},
               "created_prompts": {key: state["created_prompts"][key] for key in plan["prompts"]}}
    state.setdefault("upgrades", []).append(applied)
    state["revision"] = EXTENSION_REVISION
    state.pop("pending_upgrade", None)
    json_write_private(state_path, state)
    backup["applied"] = applied
    json_write_private(backup_path, backup)
    return {"message": "已安全增量升级；跳过项保留用户修改，未触发解题或扫描。", "upgrade": plan,
            "status": status(db, state)}


def rollback(args, db, state_path, state):
    if not state:
        raise RuntimeError("没有本扩展的安装状态，不会猜测或修改现有配置")
    marker = state["marker"]
    state = capture_created(db, state)
    statements = ["BEGIN;", f"SELECT pg_advisory_xact_lock({LOCK_ID});"]
    keys = ",".join(lit(key) for key in state["tool_keys"])
    statements.append(f"UPDATE tools SET enabled=false WHERE key IN ({keys}) AND NOT system AND position({lit(marker)} in description)>0;")
    statements.append(f"UPDATE agents SET enabled=false WHERE key IN ({lit(CURATOR_KEY)},{lit(RETRIEVER_KEY)}) AND NOT builtin AND position({lit(marker)} in coalesce(description,''))>0;")
    statements.append(f"UPDATE agent_triggers SET enabled=false WHERE agent_key={lit(CURATOR_KEY)} AND position({lit(marker)} in interval_message)>0;")
    restored = []
    before_by_key = {row["key"]: row for row in state["before"]["agents"]}
    for key, created_id in state.get("created_prompts", {}).items():
        if key not in COLLABORATION or key not in before_by_key:
            continue
        row = before_by_key[key]
        restore_id=state.get('rollback_prompt_ids',{}).get(key,row['current_prompt_id'])
        statements.append(f"UPDATE agents SET current_prompt_id={lit(restore_id)} WHERE id={int(row['id'])} AND current_prompt_id={int(created_id)};")
        restored.append(key)
    statements.append("COMMIT;")
    db.execute("\n".join(statements))
    state["status"] = "rolled_back"
    state["rolled_back_at"] = utc_now()
    json_write_private(state_path, state)
    result = status(db, state)
    result["message"] = "已停用本扩展工具、整理Agent和触发器；仅恢复仍指向安装版本的协作提示词。用户后续修改和经验数据均保留。"
    result["prompt_restore_checked"] = restored
    return result


def dry_run(args, db=None, state=None):
    if args.offline:
        roles = ["planner", "worker", "mainagent", "auto", "pentest"]
        return {"dry_run": True, "offline": True, "writes": False,
                "app_dir": str(args.app_dir), "schema": args.schema,
                "tool_keys": list(TOOL_DEFINITIONS), "solver_binding_example": roles,
                "prompt_targets": list(COLLABORATION), "curator": CURATOR_KEY,
                "interval_seconds": 1800, "events": ["goal_met", "task_timeout"]}
    meta = metadata(db)
    check_collisions(meta, state)
    return {"dry_run": True, "offline": False, "writes": False,
            "already_installed": bool(state), "solver_bindings": solver_keys(meta),
            "prompt_targets": [a["key"] for a in meta["agents"] if a["key"] in COLLABORATION],
            "tool_keys": list(TOOL_DEFINITIONS), "existing_owned_tools": [t["key"] for t in meta["tools"]]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="ARTEX经验扩展安装、状态与安全回滚")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="现有ARTEX配置路径（不输出其内容）")
    parser.add_argument("--schema", default="artex_experience")
    parser.add_argument("--app-dir", default=DEFAULT_APP)
    parser.add_argument("--state", help="私有安装状态JSON路径，默认扩展目录/install-state.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install")
    sub.add_parser("status")
    sub.add_parser("rollback")
    upgr = sub.add_parser("upgrade")
    upgr.add_argument("--dry-run", action="store_true", help="只读检查可升级项，不写数据库或安装状态")
    dry = sub.add_parser("dry-run")
    dry.add_argument("--offline", action="store_true", help="不连接数据库，只显示安装清单")
    args = parser.parse_args(argv)
    state_path = Path(args.state or str(Path(args.app_dir) / "install-state.json"))
    try:
        if args.command == "dry-run" and args.offline:
            result = dry_run(args)
        else:
            db = db_for(args)
            state = load_state(state_path)
            if state and state.get("schema") != args.schema:
                raise RuntimeError("schema 与私有安装记录不一致，已拒绝操作")
            if args.command == "install":
                result = install(args, db, state_path, state)
            elif args.command == "rollback":
                result = rollback(args, db, state_path, state)
            elif args.command == "status":
                result = status(db, state)
            elif args.command == "upgrade":
                result = upgrade(args, db, state_path, state)
            else:
                result = dry_run(args, db, state)
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0
    except (RuntimeError, ValueError) as exc:
        # Runtime errors in this module are deliberately operator-safe messages.
        # Storage errors must themselves suppress DSNs and subprocess diagnostics.
        print(json.dumps({"error": str(exc)[:240], "error_type": type(exc).__name__}, ensure_ascii=False))
        return 1
    except Exception as exc:
        print(json.dumps({"error": "安装器操作失败；未输出配置或数据库诊断，请检查私有安装状态和文件权限。",
                          "error_type": type(exc).__name__}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
