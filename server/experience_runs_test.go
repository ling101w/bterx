package server

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Real host subprocess, real PostgreSQL ledger, and deterministic fake model.
// This exercises tool publication rather than trusting an assistant's prose.
func TestExperienceCurationHostDelivery(t *testing.T) {
	if os.Getenv("ARTEX_EXPERIENCE_NATIVE_TEST") != "1" {
		t.Skip("Dedicated local PostgreSQL opt-in required")
	}
	u, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/artex_memory_test") || os.Getenv("ARTEX_EXPERIENCE_CONFIG") == "" {
		t.Fatal("Explicit isolated database configuration required")
	}
	root, err := filepath.Abs("../extensions/experience")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_EXPERIENCE_DIR", root)
	for _, mode := range []string{"no_source", "prose_only", "saved", "skipped", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := newRetestServer(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := os.ReadFile(filepath.Join(root, "schema.sql"))
			must(err)
			_, err = s.m.pg.Exec(string(ddl))
			must(err)
			_, err = s.m.pg.Exec(`INSERT INTO agents(key,name,role,builtin,enabled,max_turns,run_seconds)
      VALUES('experience_curator','Synthetic curator','assistant',false,true,4,40) ON CONFLICT(key) DO NOTHING`)
			must(err)
			var exp, task int64
			must(s.m.pg.QueryRow(`INSERT INTO explorations(description,goal) VALUES('Synthetic curation fixture','Local only') RETURNING id`).Scan(&exp))
			must(s.m.pg.QueryRow(`INSERT INTO tasks(exploration_id,description,goal) VALUES($1,'Synthetic host fixture','Local only') RETURNING id`, exp).Scan(&task))
			_, err = s.m.pg.Exec(`INSERT INTO findings(task_id,name,evidence,status) VALUES($1,'Synthetic curation evidence','Synthetic independent controlled observation; no target traffic.','confirmed')`, task)
			must(err)
			if mode == "no_source" {
				_, err = s.m.pg.Exec(`INSERT INTO artex_experience.source_exclusions(source_key,reason) VALUES('task:'||$1::bigint,'Synthetic no-source validation')`, task)
				must(err)
			}
			c, err := s.m.pg.CreateConversation(agent.ExperienceCuratorKey, "Synthetic host delivery fixture", nil)
			must(err)
			t.Cleanup(func() {
				_, _ = s.m.pg.Exec(`DELETE FROM artex_experience.curation_runs WHERE conversation_id=$1`, c.ID)
				_, _ = s.m.pg.Exec(`DELETE FROM artex_experience.entries WHERE source_task_id=$1`, task)
				_, _ = s.m.pg.Exec(`DELETE FROM artex_experience.sources WHERE source_task_id=$1`, task)
				_, _ = s.m.pg.Exec(`DELETE FROM artex_experience.source_exclusions WHERE source_key='task:'||$1::bigint`, task)
				_, _ = s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID)
				_, _ = s.m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task)
				_, _ = s.m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
			})
			code := "import sys,json\nsys.path.insert(0," + string(experienceTestJSON(root)) + ")\nfrom experience_runtime import Runtime\ntry:\n r=Runtime().publish(json.load(sys.stdin))\nexcept Exception:\n r={'error':'Synthetic invalid publication'}\nprint(json.dumps(r))\n"
			tool := s.buildCustomTool(&db.Tool{Key: "experience_publish", Kind: "script", Schema: json.RawMessage(`{"type":"object","properties":{"run_id":{"type":"string"},"entries":{"type":"array"},"skipped":{"type":"array"}},"required":["run_id","entries"]}`), Exec: experienceTestJSON(map[string]any{"code": code, "timeout_ms": 20000})})
			agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
				return []actool.CoreTool{tool}, agent.DeferredInfo{}, func() {}
			}
			agent.PromptOverride = func(string) (string, bool) { return "Only publish the provided evidence, or explicitly skip.", true }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx = context.WithValue(ctx, curationSourceKey{}, curationSource{TaskID: task, Trigger: "trigger"})
			calls := 0
			setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				if mode == "cancelled" {
					cancel()
					return llm.Message{}, "", llm.Usage{}, context.Canceled
				}
				if mode == "prose_only" || calls > 1 {
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("Claimed completion without independent delivery")}}, "end_turn", llm.Usage{}, nil
				}
				var batch struct {
					RunID   string `json:"run_id"`
					Sources []struct {
						SnapshotID string `json:"snapshot_id"`
						Evidence   []struct {
							ID string `json:"id"`
						} `json:"evidence"`
					} `json:"sources"`
				}
				for _, message := range req.Messages {
					if message.Role == llm.RoleUser {
						text := message.Text()
						if at := strings.Index(text, `{"run_id"`); at >= 0 {
							must(json.NewDecoder(strings.NewReader(text[at:])).Decode(&batch))
							break
						}
					}
				}
				if batch.RunID == "" || len(batch.Sources) == 0 {
					t.Fatal("host did not supply fixed source batch")
				}
				source := batch.Sources[0]
				payload := map[string]any{"run_id": batch.RunID, "entries": []any{}}
				if mode == "skipped" {
					payload["skipped"] = []any{map[string]any{"snapshot_id": source.SnapshotID, "reason": "no_transferable_method", "note": "Synthetic fixture intentionally contains no reusable method for this mode."}}
				} else {
					payload["entries"] = []any{map[string]any{"snapshot_id": source.SnapshotID, "title": "Synthetic independent controls", "category": "authorization", "tags": []string{"synthetic"}, "applicable_when": "Two controlled observations are available.", "steps": []string{"Compare independently observed results."}, "success_criteria": "New evidence independently supports the current claim.", "pitfalls": []string{"Completion alone does not establish truth."}, "not_applicable": "The independent control is unavailable.", "outcome": "success", "transfer_scope": "generic", "evidence_ids": []string{source.Evidence[0].ID}}}
				}
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "publish", Name: "experience_publish", Input: experienceTestJSON(payload)}}}, "tool_use", llm.Usage{}, nil
			}})
			var records []db.Activity
			s.runCuration(ctx, c, "experience-host-test", func(row db.Activity) { records = append(records, row) })
			var status, codeResult string
			var saved int
			must(s.m.pg.QueryRow(`SELECT status,error_code,jsonb_array_length(saved_entry_ids) FROM artex_experience.curation_runs WHERE conversation_id=$1 ORDER BY started_at DESC LIMIT 1`, c.ID).Scan(&status, &codeResult, &saved))
			want := mode
			if mode == "prose_only" {
				want = "failed"
			}
			if status != want {
				t.Fatalf("status=%s want=%s code=%s", status, want, codeResult)
			}
			if mode == "no_source" && calls != 0 {
				t.Fatal("empty source batch invoked a model")
			}
			if mode == "prose_only" && (calls != 2 || saved != 0 || codeResult != "delivery_missing") {
				t.Fatal("prose-only result was accepted or repair was not bounded")
			}
			if mode == "saved" && saved != 1 {
				t.Fatal("host success without a saved entry")
			}
			if len(records) == 0 || !strings.Contains(records[len(records)-1].Summary, "经验整理实际结果") {
				t.Fatal("missing authoritative final activity")
			}
			if (mode == "prose_only" || mode == "cancelled") && !records[len(records)-1].IsError {
				t.Fatal("failed delivery displayed as success")
			}
		})
	}
}

func experienceTestJSON(value any) json.RawMessage { raw, _ := json.Marshal(value); return raw }
