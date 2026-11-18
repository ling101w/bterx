package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ExperienceRef struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// Source freshness is checked inside the adoption transaction. A prior search
// must not be sufficient to adopt evidence that has since been withdrawn.
const currentExperienceSQL = `
 AND EXISTS (SELECT 1 FROM tasks st WHERE st.id=e.source_task_id AND st.deleted_at IS NULL)
 AND EXISTS (SELECT 1 FROM artex_experience.sources s WHERE s.source_key=e.source_key
   AND s.revision=e.source_revision AND (
   (s.source_type='finding' AND EXISTS (SELECT 1 FROM findings f
      WHERE f.id=s.source_id AND f.status NOT IN ('false_positive','duplicate','ignored','fixed','resolved')
      AND f.evidence_version=coalesce((s.snapshot->>'evidence_version')::bigint,-1)
      AND md5(coalesce(f.evidence,''))=s.snapshot->>'evidence_hash'
      AND md5(coalesce(f.report,''))=s.snapshot->>'report_hash'
      AND (NOT s.snapshot ? 'report_evidence_version' OR coalesce(f.report_evidence_version,0)=coalesce((s.snapshot->>'report_evidence_version')::bigint,0))
      AND (s.snapshot->>'verification_level'<>'reproduced' OR EXISTS (
        SELECT 1 FROM finding_retests r WHERE r.finding_id=f.id AND r.status='completed'
        AND r.id=(SELECT max(r2.id) FROM finding_retests r2 WHERE r2.finding_id=f.id AND r2.status='completed')
        AND r.verdict='reproduced' AND r.id=coalesce((s.snapshot->>'retest_id')::bigint,0)
        AND md5(coalesce(r.evidence,''))=s.snapshot->>'retest_hash'))
      AND (e.status<>'verified' OR f.status='confirmed' OR EXISTS (
        SELECT 1 FROM finding_retests r WHERE r.finding_id=f.id AND r.status='completed' AND r.verdict='reproduced'
        AND length(trim(r.evidence))>0 AND r.id=(SELECT max(r2.id) FROM finding_retests r2 WHERE r2.finding_id=f.id AND r2.status='completed')))))
   OR (s.source_type='task' AND (e.dependency_revisions<>'{}'::jsonb OR EXISTS (
     SELECT 1 FROM tasks t WHERE t.id=s.source_task_id AND e.source_revision=md5(concat_ws(chr(31),t.status,t.goal,t.description,t.completed_at::text,
       (SELECT string_agg(x.id::text||':'||md5(x.payload::text)||':'||x.state,'|' ORDER BY x.id)
        FROM (SELECT n.id,n.payload,n.state FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id
        AND n.kind='fact' AND n.origin<>'origin' ORDER BY n.updated_at DESC,n.id DESC LIMIT 5) x))))))
   OR (s.source_type='intent' AND EXISTS (SELECT 1 FROM exploration_nodes n WHERE n.id=s.source_id AND n.kind='intent'
     AND n.state IN ('done','blocked','exhausted','stopped') AND e.source_revision=md5(concat_ws(chr(31),n.state,n.payload::text,
       (SELECT string_agg(x.id::text||':'||md5(x.payload::text)||':'||x.state,'|' ORDER BY x.id)
        FROM (SELECT f.id,f.payload,f.state FROM exploration_edges ed JOIN exploration_nodes f
          ON f.id=ed.dst_id AND f.exploration_id=ed.exploration_id WHERE ed.exploration_id=n.exploration_id
          AND ed.src_id=n.id AND ed.rel='yields' AND f.kind='fact' ORDER BY f.id DESC LIMIT 5) x)))))
 ))
 AND NOT EXISTS (SELECT 1 FROM jsonb_each_text(e.dependency_revisions) d WHERE NOT EXISTS (
   SELECT 1 FROM exploration_nodes f JOIN tasks st ON st.exploration_id=f.exploration_id
   WHERE st.id=e.source_task_id AND f.id::text=split_part(d.key,':',2) AND f.kind='fact'
   AND md5(concat_ws(chr(31),f.payload::text,f.state))=d.value))`

func boundedExperienceMethod(raw []byte) (json.RawMessage, error) {
	var method map[string]any
	if err := json.Unmarshal(raw, &method); err != nil {
		return nil, err
	}
	cut := func(value any, limit int) string {
		text, _ := value.(string)
		r := []rune(text)
		if len(r) > limit {
			return string(r[:limit]) + "…"
		}
		return text
	}
	for _, key := range []string{"title", "category", "applicable_when", "not_applicable", "success_criteria", "root_cause"} {
		method[key] = cut(method[key], 200)
	}
	for _, key := range []string{"steps", "pitfalls"} {
		var kept []string
		if list, ok := method[key].([]any); ok {
			for i, value := range list {
				if i >= 3 {
					break
				}
				kept = append(kept, cut(value, 180))
			}
		}
		method[key] = kept
	}
	var chain []map[string]any
	if list, ok := method["attack_chain"].([]any); ok {
		for i, value := range list {
			if i >= 2 {
				break
			}
			if link, ok := value.(map[string]any); ok {
				chain = append(chain, map[string]any{"step": i + 1, "prerequisite": cut(link["prerequisite"], 150), "action": cut(link["action"], 180), "observed_result": cut(link["observed_result"], 150)})
			}
		}
	}
	method["attack_chain"] = chain
	method["notice"] = "有界历史方法摘要；可能省略步骤，需按需读取详情并核对当前前提。"
	return json.Marshal(method)
}

func ValidateExperienceRefs(refs []ExperienceRef) error {
	if len(refs) > 3 {
		return fmt.Errorf("每个意图最多关联3条经验")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if len(ref.ID) != 24 || strings.Trim(ref.ID, "0123456789abcdef") != "" || len(ref.Revision) < 3 || len(ref.Revision) > 100 || seen[ref.ID] {
			return fmt.Errorf("experience_refs需要真实、不同的经验编号及刚读取的revision")
		}
		seen[ref.ID] = true
	}
	return nil
}

// This is an adoption link, not a fact or an authorization source. Intent,
// anchors, lineage, frozen method and adopted event commit together.
func (s *ExplorationStore) AddIntentWithExperiences(payload map[string]any, priority int, anchors, parents []int64, refs []ExperienceRef) (int64, error) {
	return s.AddIntentWithExperiencesContext(context.Background(), payload, priority, anchors, parents, refs)
}

func (s *ExplorationStore) AddIntentWithExperiencesContext(ctx context.Context, payload map[string]any, priority int, anchors, parents []int64, refs []ExperienceRef) (int64, error) {
	if err := ValidateExperienceRefs(refs); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var taskID int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.expID).Scan(&taskID); err != nil {
		return 0, fmt.Errorf("经验采用需要有效任务上下文")
	}
	methods := make([]json.RawMessage, len(refs))
	for i, ref := range refs {
		var revision, status string
		var method []byte
		err = tx.QueryRowContext(ctx, `SELECT e.source_revision||':'||e.extractor_version,e.status,
          jsonb_build_object('id',e.id,'title',e.title,'category',e.category,'status',e.status,
            'revision',e.source_revision||':'||e.extractor_version,'applicable_when',e.applicable_when,
            'not_applicable',e.not_applicable,'success_criteria',e.success_criteria,'steps',e.steps,
            'root_cause',e.root_cause,'outcome',e.outcome,'pitfalls',e.pitfalls,'attack_chain',coalesce((SELECT jsonb_agg(link-'evidence_ids')
              FROM jsonb_array_elements(e.attack_chain) link),'[]'::jsonb))
          FROM artex_experience.entries e WHERE e.id=$1 AND e.status IN ('candidate','verified')
          AND (e.transfer_scope='generic' OR e.source_task_id=$2 OR EXISTS (
            SELECT 1 FROM task_scope sc WHERE sc.task_id=$2 AND sc.kind='company'
            AND e.source_company_ids @> jsonb_build_array(sc.company_id)) OR EXISTS (
            SELECT 1 FROM tasks t WHERE t.id=$2 AND t.company_id IS NOT NULL
            AND e.source_company_ids @> jsonb_build_array(t.company_id))) `+currentExperienceSQL+` FOR SHARE OF e`, ref.ID, taskID).Scan(&revision, &status, &method)
		if err != nil {
			return 0, fmt.Errorf("经验%s不存在、已失效或不在本任务可见范围", ref.ID)
		}
		if revision != ref.Revision {
			return 0, fmt.Errorf("经验%s版本已改变，请重新读取", ref.ID)
		}
		var excluded bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM artex_experience.entries e JOIN artex_experience.source_exclusions x
          ON x.source_key=e.source_key OR x.source_key='task:'||e.source_task_id::text WHERE e.id=$1)`, ref.ID).Scan(&excluded); err != nil {
			return 0, err
		}
		if excluded {
			return 0, fmt.Errorf("经验%s的来源已被排除", ref.ID)
		}
		methods[i], err = boundedExperienceMethod(method)
		if err != nil {
			return 0, fmt.Errorf("经验方法格式不可用")
		}
	}
	var id int64
	raw, _ := json.Marshal(payload)
	if err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
      VALUES($1,'intent',$2,$3,'open','planner') RETURNING id`, s.expID, string(raw), priority).Scan(&id); err != nil {
		return 0, err
	}
	for _, a := range anchors {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, a); err != nil {
			return 0, err
		}
	}
	for _, parent := range parents {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'derived_from',$3) ON CONFLICT DO NOTHING`, s.expID, parent, id); err != nil {
			return 0, err
		}
	}
	for i, ref := range refs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO artex_experience.intent_experiences(exploration_id,task_id,intent_id,experience_id,experience_revision,method_snapshot)
          VALUES($1,$2,$3,$4,$5,$6)`, s.expID, taskID, id, ref.ID, ref.Revision, string(methods[i])); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO artex_experience.usage(experience_id,task_id,intent_id,event,note,run_key)
          VALUES($1,$2,$3,'adopted','Structured adoption at intent creation',$4) ON CONFLICT DO NOTHING`, ref.ID, taskID, id, fmt.Sprintf("intent:%d", id)); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *ExplorationStore) experienceTablePresent() bool {
	var table sql.NullString
	err := s.db.QueryRow(`SELECT to_regclass('artex_experience.intent_experiences')::text`).Scan(&table)
	return err == nil && table.Valid
}

func (s *ExplorationStore) IntentExperienceCards(intentID int64) ([]json.RawMessage, error) {
	if !s.experienceTablePresent() {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT x.method_snapshot FROM artex_experience.intent_experiences x
       JOIN artex_experience.entries e ON e.id=x.experience_id
       WHERE x.exploration_id=$1 AND x.intent_id=$2 AND e.status IN ('candidate','verified')
       AND x.experience_revision=e.source_revision||':'||e.extractor_version
       AND NOT EXISTS (SELECT 1 FROM artex_experience.source_exclusions z WHERE z.source_key=e.source_key OR z.source_key='task:'||e.source_task_id::text)
       `+currentExperienceSQL+` ORDER BY x.experience_id`, s.expID, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(b))
	}
	return out, rows.Err()
}

// Execution produces an evidence queue, never an automatic helpful judgment.
func (s *ExplorationStore) SealIntentExperiences(intentID int64) error {
	if !s.experienceTablePresent() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, `UPDATE artex_experience.intent_experiences x SET
      result_state=CASE WHEN n.state='done' AND (
        EXISTS(SELECT 1 FROM exploration_edges e JOIN exploration_nodes f ON f.id=e.dst_id AND f.exploration_id=e.exploration_id
          WHERE e.exploration_id=x.exploration_id AND e.src_id=x.intent_id AND e.rel='yields'
          AND f.kind IN ('fact','finding') AND f.state<>'dismissed' AND f.created_at>=x.adopted_at)
        OR EXISTS(SELECT 1 FROM activity a WHERE a.exploration_id=x.exploration_id AND a.node_id=x.intent_id
          AND a.kind='tool_result' AND NOT a.is_error AND a.created_at>=x.adopted_at))
        THEN 'result_available' ELSE 'execution_interrupted' END,
      feedback_state=CASE WHEN n.state='done' AND (
        EXISTS(SELECT 1 FROM exploration_edges e JOIN exploration_nodes f ON f.id=e.dst_id AND f.exploration_id=e.exploration_id
          WHERE e.exploration_id=x.exploration_id AND e.src_id=x.intent_id AND e.rel='yields'
          AND f.kind IN ('fact','finding') AND f.state<>'dismissed' AND f.created_at>=x.adopted_at)
        OR EXISTS(SELECT 1 FROM activity a WHERE a.exploration_id=x.exploration_id AND a.node_id=x.intent_id
          AND a.kind='tool_result' AND NOT a.is_error AND a.created_at>=x.adopted_at))
        THEN 'pending_review' ELSE 'inconclusive' END,
      terminal_state=n.state,
      evidence_node_ids=coalesce((SELECT jsonb_agg(r.id) FROM (SELECT f.id FROM exploration_edges e
        JOIN exploration_nodes f ON f.id=e.dst_id AND f.exploration_id=e.exploration_id
        WHERE e.exploration_id=x.exploration_id AND e.src_id=x.intent_id AND e.rel='yields'
        AND f.kind IN ('fact','finding') AND f.state<>'dismissed' AND f.created_at>=x.adopted_at ORDER BY f.id DESC LIMIT 6) r),'[]'),
      evidence_activity_ids=coalesce((SELECT jsonb_agg(r.id) FROM (SELECT a.id FROM activity a
        WHERE a.exploration_id=x.exploration_id AND a.node_id=x.intent_id AND a.kind IN ('result','tool_result')
        AND NOT a.is_error AND a.created_at>=x.adopted_at ORDER BY a.id DESC LIMIT 6) r),'[]'),updated_at=now()
      FROM exploration_nodes n WHERE x.exploration_id=$1 AND x.intent_id=$2 AND n.id=x.intent_id
      AND n.exploration_id=x.exploration_id AND n.state IN ('done','blocked','exhausted','stopped')
      AND x.result_state='pending_execution'`, s.expID, intentID)
	return err
}
