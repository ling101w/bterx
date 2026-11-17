package agent

import (
	"context"
	actool "github.com/Autumn-27/norma/tool"
	"testing"
)

func TestExperienceRolesBlockExecutionBeforeToolCall(t *testing.T) {
	for _, key := range []string{ExperienceCuratorKey, ExperienceRetrieverKey} {
		tools := []actool.CoreTool{}
		for _, name := range []string{"Bash", "Read", "WebFetch", "Monitor", "TaskOutput", "ask_experience", "add_intent", "experience_snapshot", "experience_publish", "experience_get", "experience_search", "experience_stats"} {
			tool := actool.Build(actool.Spec{Name: name, Schema: map[string]any{"type": "object"}})
			tools = append(tools, tool)
			blocked, _, _ := experienceHooks(key).PreToolUse(context.Background(), name, []byte(`{}`))
			if blocked == experienceToolAllowed(key, name) {
				t.Fatalf("%s hook mismatch for %s", key, name)
			}
		}
		filtered := experienceTools(key, tools)
		want := 1
		if key == ExperienceRetrieverKey {
			want = 3
		}
		if len(filtered) != want {
			t.Fatalf("%s: exposed %d tools", key, len(filtered))
		}
	}
}
func TestExperiencePublicationCannotSelectForeignRun(t *testing.T) {
	ctx := WithExperienceRun(context.Background(), "host-run", 44)
	in := map[string]any{"run_id": "foreign", "_host_run_id": "foreign", "_host_conversation_id": 99}
	BindExperiencePublication(ctx, in)
	if in["run_id"] != "host-run" || in["_host_run_id"] != "host-run" || in["_host_conversation_id"] != int64(44) {
		t.Fatal("model controlled run identity")
	}
	BindExperiencePublication(context.Background(), in)
	if in["_host_run_id"] != "" || in["_host_conversation_id"] != int64(0) {
		t.Fatal("host identity leaked across runs")
	}
}
