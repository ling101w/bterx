package db

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestExperienceRefValidation(t *testing.T) {
	valid := ExperienceRef{"0123456789abcdef01234567", "source:5"}
	if ValidateExperienceRefs(nil) != nil || ValidateExperienceRefs([]ExperienceRef{valid}) != nil {
		t.Fatal("valid reference rejected")
	}
	for _, refs := range [][]ExperienceRef{{{ID: "wrong", Revision: "x"}}, {valid, valid}, {valid, valid, valid, valid}, {{ID: valid.ID, Revision: ""}}} {
		if ValidateExperienceRefs(refs) == nil {
			t.Fatal("invalid method contract accepted")
		}
	}
}

func TestExperienceAdoptionTransaction(t *testing.T) {
	if os.Getenv("ARTEX_EXPERIENCE_NATIVE_TEST") != "1" {
		t.Skip("Disposable database opt-in required")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || !strings.HasPrefix(u.Path, "/artex_memory_test") {
		t.Fatal("Use a dedicated localhost artex_memory_test database")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ddl, err := os.ReadFile("../extensions/experience/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(string(ddl)); err != nil {
		t.Fatal(err)
	}
	var exp, task, finding int64
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.QueryRow(`INSERT INTO explorations(description,goal) VALUES('Synthetic memory regression','Synthetic local evidence') RETURNING id`).Scan(&exp))
	must(d.QueryRow(`INSERT INTO tasks(exploration_id,description,goal) VALUES($1,'Synthetic memory regression','Synthetic local evidence') RETURNING id`, exp).Scan(&task))
	must(d.QueryRow(`INSERT INTO findings(task_id,name,evidence,status) VALUES($1,'Synthetic independent finding','Synthetic control evidence only','confirmed') RETURNING id`, task).Scan(&finding))
	const eid = "0123456789abcdefabcdef01"
	_, err = d.Exec(`INSERT INTO artex_experience.sources(source_key,source_type,source_id,source_task_id,revision,snapshot_id,snapshot)
   SELECT 'finding:'||id,'finding',id,task_id,'fixture-revision',$2,
   jsonb_build_object('evidence_version',evidence_version,'evidence_hash',md5(evidence),'report_hash',md5(report),'report_evidence_version',report_evidence_version,'verification_level','confirmed')
   FROM findings WHERE id=$1`, finding, eid)
	must(err)
	_, err = d.Exec(`INSERT INTO artex_experience.entries(id,source_key,source_revision,source_task_id,snapshot_id,title,steps,transfer_scope,extractor_version)
   VALUES($1,'finding:'||$2::bigint,'fixture-revision',$3,$1,'Synthetic bounded method','["Compare controls"]','generic','5')`, eid, finding, task)
	must(err)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM artex_experience.usage WHERE experience_id=$1`, eid)
		_, _ = d.Exec(`DELETE FROM artex_experience.intent_experiences WHERE experience_id=$1`, eid)
		_, _ = d.Exec(`DELETE FROM artex_experience.entries WHERE id=$1`, eid)
		_, _ = d.Exec(`DELETE FROM artex_experience.sources WHERE snapshot_id=$1`, eid)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	})
	store := d.Exploration(exp)
	ref := ExperienceRef{eid, "fixture-revision:5"}
	add := func(refs []ExperienceRef) (int64, error) {
		return store.AddIntentWithExperiences(map[string]any{"summary": "Synthetic intent"}, 1, nil, nil, refs)
	}
	for _, tc := range []struct {
		name, sql string
		refs      []ExperienceRef
	}{
		{"missing", "", []ExperienceRef{{"ffffffffffffffffffffffff", "fixture:5"}}},
		{"wrong_version", "", []ExperienceRef{{eid, "older:4"}}},
		{"duplicate", "", []ExperienceRef{ref, ref}},
		{"withdrawn", `UPDATE findings SET status='false_positive' WHERE id=$1`, []ExperienceRef{ref}},
		{"corrected", `UPDATE findings SET evidence='Synthetic replacement control' WHERE id=$1`, []ExperienceRef{ref}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before, after int
			must(d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, exp).Scan(&before))
			if tc.sql != "" {
				_, err = d.Exec(tc.sql, finding)
				must(err)
			}
			if _, err = add(tc.refs); err == nil {
				t.Fatal("invalid experience adopted")
			}
			must(d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, exp).Scan(&after))
			if before != after {
				t.Fatal("orphan intent after failed adoption")
			}
			_, err = d.Exec(`UPDATE findings SET evidence='Synthetic control evidence only',status='confirmed' WHERE id=$1`, finding)
			must(err)
			_, err = d.Exec(`UPDATE artex_experience.sources s SET snapshot=jsonb_set(s.snapshot,'{evidence_version}',to_jsonb(f.evidence_version)) FROM findings f WHERE f.id=$1 AND s.source_id=f.id`, finding)
			must(err)
		})
	}
	id, err := add([]ExperienceRef{ref})
	must(err)
	var count int
	must(d.QueryRow(`SELECT count(*) FROM artex_experience.intent_experiences WHERE intent_id=$1`, id).Scan(&count))
	if count != 1 {
		t.Fatal("missing atomic adoption")
	}
	cards, err := store.IntentExperienceCards(id)
	must(err)
	if len(cards) != 1 {
		t.Fatal("worker missing frozen method")
	}
	_, err = d.Exec(`UPDATE exploration_nodes SET state='done' WHERE id=$1`, id)
	must(err)
	must(store.SealIntentExperiences(id))
	var state, feedback string
	must(d.QueryRow(`SELECT result_state,feedback_state FROM artex_experience.intent_experiences WHERE intent_id=$1`, id).Scan(&state, &feedback))
	if state != "execution_interrupted" || feedback != "inconclusive" {
		t.Fatal("done without evidence was treated as a useful result")
	}
	id, err = add([]ExperienceRef{ref})
	must(err)
	var fact int64
	must(d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,state,origin,payload) VALUES($1,'fact','confirmed','worker','{"summary":"Synthetic control result","evidence":"Synthetic observed local result"}') RETURNING id`, exp).Scan(&fact))
	_, err = d.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'yields',$3)`, exp, id, fact)
	must(err)
	_, err = d.Exec(`UPDATE exploration_nodes SET state='done' WHERE id=$1`, id)
	must(err)
	must(store.SealIntentExperiences(id))
	must(d.QueryRow(`SELECT result_state,feedback_state FROM artex_experience.intent_experiences WHERE intent_id=$1`, id).Scan(&state, &feedback))
	if state != "result_available" || feedback != "pending_review" {
		t.Fatal("actual result not linked for independent review")
	}
	must(d.QueryRow(`SELECT count(*) FROM artex_experience.usage WHERE experience_id=$1 AND event='helpful'`, eid).Scan(&count))
	if count != 0 {
		t.Fatal("helpful must not be inferred from task completion")
	}
	_, err = d.Exec(`UPDATE findings SET status='false_positive' WHERE id=$1`, finding)
	must(err)
	cards, err = store.IntentExperienceCards(id)
	must(err)
	if len(cards) != 0 {
		t.Fatal("worker received withdrawn method")
	}
}

func TestExperienceMethodBound(t *testing.T) {
	long := strings.Repeat("测", 2000)
	payload := map[string]any{"id": "0123456789abcdefabcdef01", "steps": []string{long, long, long, long}, "pitfalls": []string{long, long, long, long}}
	for _, key := range []string{"title", "category", "applicable_when", "not_applicable", "success_criteria", "root_cause"} {
		payload[key] = long
	}
	var chain []map[string]any
	for i := 0; i < 6; i++ {
		chain = append(chain, map[string]any{"step": i + 1, "prerequisite": long, "action": long, "observed_result": long, "evidence_ids": []string{"private-source"}})
	}
	payload["attack_chain"] = chain
	raw, _ := json.Marshal(payload)
	method, err := boundedExperienceMethod(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(method) > 12000 || strings.Contains(string(method), "private-source") {
		t.Fatal("historical method is not bounded or leaks source IDs")
	}
}
