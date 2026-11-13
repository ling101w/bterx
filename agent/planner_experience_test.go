package agent

import (
	"context"
	"encoding/json"
	actool "github.com/Autumn-27/norma/tool"
	"testing"
)

func TestPlannerExperienceToolsSurviveFilterAndHook(t *testing.T) {
	p := newPlannerRoundPolicy(func() (bool, error) { return true, nil }, func() (bool, error) { return true, nil }, false)
	h := p.hooks()
	cache := newPlannerReadCache(nil)
	for _, name := range []string{"ask_experience", "experience_search", "experience_get", "experience_feedback", "experience_stats"} {
		t.Run(name, func(t *testing.T) {
			tool := actool.Build(actool.Spec{Name: name, Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
					return actool.Text("available"), nil
				}})
			filtered := cache.wrap([]actool.CoreTool{tool})
			if len(filtered) != 1 || filtered[0].Name() != name {
				t.Fatal("experience tool removed by filter")
			}
			blocked, _, _ := h.PreToolUse(context.Background(), name, []byte(`{}`))
			if blocked {
				t.Fatal("experience tool blocked by hook")
			}
		})
	}
	for _, name := range []string{"Bash", "Read", "WebFetch", "shell_open", "mcp__browser__navigate", "experience_publish", "experience_snapshot"} {
		blocked, _, _ := h.PreToolUse(context.Background(), name, []byte(`{}`))
		if !blocked {
			t.Fatalf("unrelated execution or curation tool admitted: %s", name)
		}
	}
}
