package agent

import (
	"context"
	actool "github.com/Autumn-27/norma/tool"
	"testing"
)

func TestChainReviewerRejectsInjectedBackgroundAndNetworkTools(t *testing.T) {
	hooks := chainReviewHooks()
	for _, name := range []string{"Monitor", "TaskOutput", "Bash", "WebFetch", "Read", "add_intent"} {
		blocked, _, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if !blocked {
			t.Fatalf("unexpected tool allowed: %s", name)
		}
	}
	for _, name := range []string{"chain_review_snapshot", "chain_review_publish"} {
		blocked, _, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if blocked {
			t.Fatalf("expected review tool blocked: %s", name)
		}
	}
}

func TestChainReviewerToolIsolation(t *testing.T) {
	var tools []actool.CoreTool
	for _, name := range []string{"Bash", "Read", "WebFetch", "add_intent", "chain_review_snapshot", "chain_review_publish"} {
		tools = append(tools, actool.Build(actool.Spec{Name: name, Description: name, Schema: map[string]any{"type": "object"}}))
	}
	got := chainReviewTools(ChainReviewerKey, tools)
	if len(got) != 2 || got[0].Name() != "chain_review_snapshot" || got[1].Name() != "chain_review_publish" {
		t.Fatalf("reviewer exposed unexpected tools: %v", got)
	}
	if len(chainReviewTools("planner", tools)) != len(tools) {
		t.Fatal("unrelated agent tool surface changed")
	}
}
