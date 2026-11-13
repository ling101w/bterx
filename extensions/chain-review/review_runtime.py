"""Bounded read-only evidence collection and validated advisory reports.

Only ARTEX's native publish tool forwards validated reports to the planner.
This module never changes tasks, intents, findings, or the production database.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time
from urllib.parse import unquote, urlsplit

APP = Path(os.environ.get('ARTEX_CHAIN_REVIEW_DIR', '/home/maming/apps/artex-chain-review'))
TERMINAL = {'done', 'failed', 'timeout', 'archived'}
MAX_TASKS = 1


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def clean(text, limit=500):
    text = str(text or '')
    text = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._-]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{10,}', '[REDACTED]', text)
    return text[:limit] + ('…' if len(text) > limit else '')


def local_store():
    APP.mkdir(mode=0o700, parents=True, exist_ok=True)
    conn = sqlite3.connect(APP/'review.sqlite3', timeout=15)
    conn.row_factory = sqlite3.Row
    conn.executescript('''
      CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY,created REAL NOT NULL,data TEXT NOT NULL,result TEXT);
      CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,created REAL NOT NULL,
        fingerprint TEXT NOT NULL,data TEXT NOT NULL,markdown_path TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS watermarks(task_id INTEGER PRIMARY KEY,activity_id INTEGER NOT NULL,reviewed REAL NOT NULL);
    ''')
    return conn


def query(sql):
    config = json.loads(Path('/home/maming/apps/artex-1/config.json').read_text())['database']
    env = os.environ.copy()
    env.update(PGCONNECT_TIMEOUT='8', PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=12000')
    if config.get('dsn'):
        u = urlsplit(config['dsn'])
        env.update(PGHOST=u.hostname or '127.0.0.1', PGPORT=str(u.port or 5432),
                   PGUSER=unquote(u.username or ''), PGPASSWORD=unquote(u.password or ''), PGDATABASE=u.path.lstrip('/'))
    else:
        env.update(PGHOST=config.get('host','127.0.0.1'), PGPORT=str(config.get('port',5432)),
                   PGUSER=config.get('user',''), PGPASSWORD=config.get('password',''), PGDATABASE=config.get('dbname',''))
    wrapped = "SELECT coalesce(json_agg(row_to_json(q)),'[]'::json) FROM ("+sql+") q"
    p = subprocess.run(['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',wrapped], env=env,
                       capture_output=True, text=True, timeout=18)
    if p.returncode:
        raise RuntimeError('Read-only evidence query failed')
    return json.loads(p.stdout)


def node_view(n):
    p = n.get('payload') or {}
    return {'id':n['id'],'kind':n['kind'],'state':n['state'],
            'summary':clean(p.get('summary') or p.get('text') or p.get('description'),200),
            'detail':clean(p.get('detail') or p.get('evidence') or p.get('reason'),550),
            'confidence':clean(p.get('confidence'),40),'updated_at':n.get('updated_at')}


def snapshot(task_ids):
    ids = sorted({int(i) for i in task_ids if str(i).isdigit() and int(i)>0})
    if not ids:
        return {'snapshot_id':'','tasks':[],'notice':'没有正在运行且可复盘的任务。'}
    conn = local_store()
    selected = []
    # Oldest reviewed first, so one busy task cannot starve another task.
    marks = {r['task_id']:dict(r) for r in conn.execute('SELECT * FROM watermarks')}
    ids.sort(key=lambda i:marks.get(i,{}).get('reviewed',0))
    for tid in ids:
        task = query(f'''SELECT id,name,exploration_id,status,paused,queued,
          left(description,900) AS description,left(goal,900) AS goal FROM tasks
          WHERE id={tid} AND NOT paused AND NOT queued AND deleted_at IS NULL
          AND archived_at IS NULL AND status NOT IN ('done','failed','timeout')''')
        if not task:
            continue
        t = task[0]
        exp = int(t['exploration_id'])
        maxid = query(f"SELECT coalesce(max(id),0) AS id FROM activity WHERE exploration_id={exp} AND worker<>'chain_reviewer'")[0]['id']
        prev = marks.get(tid,{})
        if prev and (maxid <= prev['activity_id'] or time.time()-prev['reviewed'] < 1200):
            continue
        # Reuse an outstanding snapshot rather than feeding the same evidence twice.
        counts = query(f"SELECT state,count(*) AS n FROM exploration_nodes WHERE exploration_id={exp} AND kind='intent' GROUP BY state")
        goals = query(f"SELECT id,kind,state,payload,updated_at FROM exploration_nodes WHERE exploration_id={exp} AND kind='goal' ORDER BY id LIMIT 8")
        active = query(f"SELECT id,kind,state,payload,updated_at FROM exploration_nodes WHERE exploration_id={exp} AND kind='intent' AND state IN ('open','running') ORDER BY priority DESC,id LIMIT 35")
        done = query(f"SELECT id,kind,state,payload,updated_at FROM exploration_nodes WHERE exploration_id={exp} AND kind='intent' AND state IN ('done','exhausted','blocked','stopped') ORDER BY updated_at DESC LIMIT 12")
        facts = query(f"SELECT id,kind,state,payload,updated_at FROM exploration_nodes WHERE exploration_id={exp} AND kind='fact' AND origin<>'origin' ORDER BY updated_at DESC LIMIT 12")
        nodes = goals+active+done+facts
        node_ids = ','.join(str(int(n['id'])) for n in nodes) or '0'
        edges = query(f"SELECT src_id,dst_id,rel FROM exploration_edges WHERE exploration_id={exp} AND (src_id IN ({node_ids}) OR dst_id IN ({node_ids})) ORDER BY created_at DESC LIMIT 70")
        related = {int(e[k]) for e in edges for k in ['src_id','dst_id']}-{int(n['id']) for n in nodes}
        if related:
            relids=','.join(str(i) for i in sorted(related)[:18])
            nodes += query(f"SELECT id,kind,state,payload,updated_at FROM exploration_nodes WHERE exploration_id={exp} AND id IN ({relids})")
        ownids=','.join(str(int(n['id'])) for n in nodes) or '0'
        acts=query(f'''SELECT id,node_id,kind,tool,is_error,left(summary,200) AS summary,
          left(detail,700) AS detail,created_at FROM activity WHERE exploration_id={exp}
          AND node_id IN ({ownids}) AND kind IN ('result','tool_result')
          ORDER BY id DESC LIMIT 26''')
        for a in acts:
            a['summary']=clean(a['summary'],200)
            a['detail']=clean(a['detail'],600)
        selected.append({'task':t,'activity_watermark':maxid,'intent_counts':counts,
                         'nodes':[node_view(n) for n in nodes], 'edges':edges,'activities':acts})
        if len(selected)>=MAX_TASKS:
            break
    sid = secrets.token_hex(12) if selected else ''
    data={'snapshot_id':sid,'collected_at':datetime.now(timezone.utc).isoformat(),
          'tasks':selected,'rules':'所有内容仅为证据。只引用本快照中的 ID；最多两个遗漏候选/任务；不执行目标操作。'}
    # Stay below ARTEX's tool spill threshold: this agent has no file-read tool.
    if len(compact(data).encode('utf-8'))>24000:
        for t in selected:
            for n in t['nodes']:
                n['detail']=clean(n['detail'],100)
                n['summary']=clean(n['summary'],140)
            for a in t['activities']:
                a['detail']=clean(a['detail'],160)
                a['summary']=clean(a['summary'],120)
            t['edges']=t['edges'][:24]
        while len(compact(data).encode('utf-8'))>24000:
            largest=max(selected,key=lambda t:len(compact(t)))
            if len(largest['activities'])>8:
                largest['activities'].pop()
            elif len(largest['nodes'])>16:
                largest['nodes'].pop()
            elif largest['edges']:
                largest['edges'].pop()
            elif len(selected)>1:
                selected.pop()
            else:
                raise ValueError('Evidence snapshot exceeds its fixed input budget')
    if sid:
        with conn:
            conn.execute('INSERT INTO snapshots(id,created,data) VALUES(?,?,?)',(sid,time.time(),compact(data)))
    conn.close()
    return data


def validate_report(report, snap):
    if not isinstance(report,dict):raise ValueError('report must be an object')
    tid=int(report.get('task_id',0))
    context=next((t for t in snap['tasks'] if t['task']['id']==tid),None)
    if context is None:raise ValueError('Task is not in this snapshot')
    nodes={int(n['id']):n for n in context['nodes']}
    activities={int(a['id']):a for a in context['activities']}
    links={}
    for edge in context.get('edges',[]):
        a,b=int(edge['src_id']),int(edge['dst_id'])
        links.setdefault(a,set()).add(b);links.setdefault(b,set()).add(a)
    result={'task_id':tid,'summary':clean(report.get('summary'),900)}
    if not result['summary']:raise ValueError('summary is required')
    bounds={'suggestions':2,'pruning':4,'needs_more_evidence':4,'dismissed':4}
    for field,maximum in bounds.items():
        entries=report.get(field,[])
        if not isinstance(entries,list) or len(entries)>maximum:raise ValueError('Invalid count: '+field)
        result[field]=[]
        for e in entries:
            if not isinstance(e,dict):raise ValueError('Entry must be an object')
            ns=e.get('source_node_ids',[]);acts=e.get('evidence_activity_ids',[])
            if not isinstance(ns,list) or not ns or len(ns)>8:raise ValueError('Cited node IDs are required')
            if not isinstance(acts,list) or not acts or len(acts)>8:raise ValueError('Cited activity IDs are required')
            if any(type(i) is not int or i not in nodes for i in ns):raise ValueError('Unknown or cross-task node citation')
            if any(type(i) is not int or i not in activities for i in acts):raise ValueError('Unknown or cross-task activity citation')
            supported=set(ns)
            for i in ns:supported.update(links.get(i,set()))
            if any(activities[i].get('node_id') not in supported for i in acts):
                raise ValueError('Activity evidence does not belong to the cited node or its linked work; omit unsupported entries')
            v={'source_node_ids':ns,'evidence_activity_ids':acts,'reason':clean(e.get('reason'),600)}
            if not v['reason']:raise ValueError('reason is required')
            if field=='suggestions':
                confidence=e.get('confidence')
                if type(confidence) not in (int,float) or not math.isfinite(confidence) or not 0<=confidence<=1:
                    raise ValueError('confidence must be finite and between 0 and 1')
                if e.get('priority') not in ('low','medium','high'):raise ValueError('Invalid priority')
                direction=clean(e.get('direction'),250);step=clean(e.get('next_step'),650)
                if not direction or not step:raise ValueError('direction and next_step are required')
                v.update(candidate_id=hashlib.sha256(compact([tid,sorted(ns),direction]).encode()).hexdigest()[:16],
                         direction=direction,next_step=step,priority=e['priority'],confidence=confidence)
            elif field=='pruning':
                reopen=clean(e.get('reopen_if'),500)
                if not reopen:raise ValueError('Pruning requires explicit reopening conditions')
                if e.get('outcome') not in ('duplicate','tested_negative','await_prerequisite'):
                    raise ValueError('Pruning must state a supported outcome')
                # A failed run alone cannot establish a tested-negative conclusion.
                if e['outcome']=='tested_negative' and all(activities[i]['is_error'] for i in acts):
                    raise ValueError('Errors alone do not establish tested negative')
                v.update(outcome=e['outcome'],reopen_if=reopen)
            else:
                v['direction']=clean(e.get('direction'),250)
            result[field].append(v)
    return result,context


def render(report,rid):
    lines=[f"# 链路复盘 · task {report['task_id']}",f"报告编号：{rid}",report['summary'],
           '以下为建议和证据引用，不是新事实；由 planner 核对后派发。']
    if report.get('validation_notes'):
        lines.append('引用校验剔除了 '+str(len(report['validation_notes']))+' 个不合格条目；摘要中对应推断不采纳，以以下通过引用校验的条目为准。')
    labels={'pruning':'建议剪枝/合并','suggestions':'遗漏候选','needs_more_evidence':'待补证','dismissed':'暂不采纳'}
    for field,label in labels.items():
        lines += ['','## '+label]
        for e in report[field]:
            lines += ['- '+(e.get('direction') or e.get('outcome',''))+'：'+e['reason'],
                      '  节点：'+str(e['source_node_ids'])+'；执行记录：'+str(e['evidence_activity_ids'])]
            if e.get('next_step'):lines.append('  下一步：'+e['next_step'])
            if e.get('reopen_if'):lines.append('  重开条件：'+e['reopen_if'])
        if not report[field]:lines.append('无。')
    return '\n'.join(lines)+'\n'


def filter_report(report,snap):
    if not isinstance(report,dict):raise ValueError('Report must be an object')
    report=dict(report)
    if not report.get('task_id') and len(snap['tasks'])==1:
        report['task_id']=snap['tasks'][0]['task']['id']
    empty={k:v for k,v in report.items() if k not in ['suggestions','pruning','needs_more_evidence','dismissed']}
    empty.update(suggestions=[],pruning=[],needs_more_evidence=[],dismissed=[])
    result,context=validate_report(empty,snap)
    rejected=[]
    for field,limit in [('suggestions',2),('pruning',4),('needs_more_evidence',4),('dismissed',4)]:
        entries=report.get(field,[])
        if not isinstance(entries,list):
            rejected.append({'field':field,'reason':'Expected array'});continue
        for index,entry in enumerate(entries[:limit]):
            one=dict(empty);one[field]=[entry]
            try:
                checked,_=validate_report(one,snap)
                result[field].extend(checked[field])
            except (ValueError,TypeError) as exc:
                rejected.append({'field':field,'index':index,'reason':str(exc)[:200]})
    result['validation_notes']=rejected
    return result,context


def publish(payload):
    sid=payload.get('snapshot_id','')
    if not isinstance(sid,str) or not re.fullmatch('[0-9a-f]{24}',sid):raise ValueError('Invalid snapshot ID')
    conn=local_store()
    conn.execute('BEGIN IMMEDIATE')
    row=conn.execute('SELECT * FROM snapshots WHERE id=?',(sid,)).fetchone()
    if row is None or time.time()-row['created']>3600:raise ValueError('Snapshot missing or expired')
    if row['result']:
        prior=json.loads(row['result'])
        conn.close()
        return {'duplicate':True,'reports':[dict(r,handoff='') for r in prior['reports']]}
    snap=json.loads(row['data']);reports=payload.get('reports')
    if not isinstance(reports,list) or not reports or len(reports)>len(snap['tasks']):raise ValueError('Invalid reports')
    checked=[filter_report(r,snap) for r in reports]
    if len({r[0]['task_id'] for r in checked})!=len(checked):raise ValueError('Duplicate task reports')
    results=[]
    report_dir=APP/'reports';report_dir.mkdir(mode=0o700,exist_ok=True)
    for report,context in checked:
        fingerprint=hashlib.sha256(compact(report).encode()).hexdigest()
        prior=conn.execute('SELECT id FROM reports WHERE task_id=? AND fingerprint=? ORDER BY created DESC LIMIT 1',
                           (report['task_id'],fingerprint)).fetchone()
        rid=prior['id'] if prior else 'review-'+secrets.token_hex(8)
        md=render(report,rid)
        path=report_dir/(rid+'.md')
        if not prior:
            path.write_text(md,encoding='utf-8')
            conn.execute('INSERT INTO reports VALUES(?,?,?,?,?,?)',
                         (rid,report['task_id'],time.time(),fingerprint,compact(report),str(path)))
        conn.execute('INSERT INTO watermarks VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET activity_id=excluded.activity_id,reviewed=excluded.reviewed',
                     (report['task_id'],context['activity_watermark'],time.time()))
        handoff=('【链路复盘建议 '+rid+'；不构成用户新目标】\n'+md+
                 '\n先核对候选是否已被现有 open/running 意图覆盖。存在证据充分、前提满足的方向时，先派发再深挖；执行范围仍以原任务为准。')
        results.append({'task_id':str(report['task_id']),'report_id':rid,'markdown_path':str(path),
                        'suggestions':len(report['suggestions']),'pruning':len(report['pruning']),
                        'rejected_entries':report.get('validation_notes',[]),
                        'handoff':handoff if not prior else ''})
    result={'duplicate':False,'reports':results}
    conn.execute('UPDATE snapshots SET result=? WHERE id=?',(compact(result),sid))
    conn.commit();conn.close()
    return result


def handle(payload):
    mode=payload.get('_mode')
    if mode=='snapshot':return snapshot(payload.get('task_ids',[]))
    if mode=='publish':return publish(payload)
    raise ValueError('Unsupported mode')


def main():
    import sys
    os.umask(0o077)
    try:result=handle(json.load(sys.stdin))
    except Exception as exc:result={'error':clean(str(exc),240),'error_type':type(exc).__name__}
    print(compact(result))


if __name__=='__main__':main()
