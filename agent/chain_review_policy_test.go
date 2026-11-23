package agent

import (
	"context"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestChainReviewerRejectsInjectedBackgroundAndNetworkTools(t *testing.T) {
	hooks := chainReviewHooks()
	for _, name := range []string{"Monitor", "TaskOutput", "Bash", "WebFetch", "Read", "Write", "Edit", "add_intent"} {
		blocked, _, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if !blocked {
			t.Fatalf("unexpected tool allowed: %s", name)
		}
	}
	allowed := []string{
		"chain_review_snapshot",
		"chain_review_publish",
		"supervisor_board",
		"supervisor_inspect",
		"supervisor_kill_intent",
		"supervisor_dispatch_intent",
		"supervisor_retract_fact",
		"supervisor_steer_worker",
		"supervisor_record_asset_note",
	}
	for _, name := range allowed {
		blocked, _, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if blocked {
			t.Fatalf("expected supervisor/review tool allowed, got blocked: %s", name)
		}
	}
}

func TestChainReviewerToolIsolation(t *testing.T) {
	names := []string{
		"Bash", "Read", "WebFetch", "add_intent",
		"chain_review_snapshot", "chain_review_publish",
		"supervisor_board", "supervisor_inspect", "supervisor_kill_intent",
		"supervisor_dispatch_intent", "supervisor_retract_fact",
		"supervisor_steer_worker", "supervisor_record_asset_note",
	}
	var tools []actool.CoreTool
	for _, name := range names {
		tools = append(tools, actool.Build(actool.Spec{Name: name, Description: name, Schema: map[string]any{"type": "object"}}))
	}
	got := chainReviewTools(ChainReviewerKey, tools)
	if len(got) != 9 {
		t.Fatalf("expected 9 allowed supervisor/review tools, got %d: %v", len(got), got)
	}
	for _, tool := range got {
		if !supervisorAllowedTools[tool.Name()] {
			t.Fatalf("supervisor exposed unexpected tool: %s", tool.Name())
		}
	}
	if len(chainReviewTools("planner", tools)) != len(tools) {
		t.Fatal("unrelated agent tool surface changed")
	}
}
