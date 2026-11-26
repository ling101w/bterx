package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestPlannerDispatchGateLeavesHonestExitAndTargetedEvidence(t *testing.T) {
	p := newPlannerRoundPolicy(func() (bool, error) { return false, nil }, func() (bool, error) { return true, nil }, false)
	h := p.hooks()
	for i := 0; i < 6; i++ {
		blocked, _, _ := h.PreToolUse(context.Background(), "list_facts", []byte(fmt.Sprintf(`{"q":"q%d"}`, i)))
		if blocked {
			t.Fatalf("read %d unexpectedly blocked", i)
		}
	}
	blocked, _, _ := h.PreToolUse(context.Background(), "list_facts", []byte(`{"q":"another"}`))
	if !blocked {
		t.Fatal("unbounded broad history walk allowed with empty queue")
	}
	for _, name := range []string{"node_detail", "add_intent", "planner_decision"} {
		blocked, _, _ := h.PreToolUse(context.Background(), name, []byte(`{}`))
		if blocked {
			t.Fatalf("needed progress tool blocked: %s", name)
		}
	}
	_, blockers, _ := h.Stop(context.Background(), nil)
	if len(blockers) == 0 {
		t.Fatal("empty queue silently ended without a decision")
	}
	res, err := p.decisionTool().Call(context.Background(), json.RawMessage(`{"reason_kind":"missing_prerequisite","reason":"现有线索缺少已授权测试身份","next_requirement":"等待用户提供测试账户"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("honest no-action decision failed: %v %v", res, err)
	}
	_, blockers, _ = h.Stop(context.Background(), nil)
	if len(blockers) != 0 {
		t.Fatal("honest decision did not release stop")
	}
}

func TestPlannerDispatchedIntentIsRecognizedFromSDKHook(t *testing.T) {
	p := newPlannerRoundPolicy(func() (bool, error) { return false, nil }, func() (bool, error) { return true, nil }, false)
	h := p.hooks()
	raw, _ := json.Marshal(`{"ids":[0,42],"errors":{"0":"invalid"}}`)
	h.PostToolUse(context.Background(), "add_intent", []byte(`{}`), raw, false)
	_, blockers, _ := h.Stop(context.Background(), nil)
	if len(blockers) != 0 || !p.dispatched {
		t.Fatal("successful partial batch dispatch was not recognized")
	}
	if plannerCreatedIntent(actool.Text(`{"ids":[0,0]}`)) {
		t.Fatal("failed batch counted as dispatch")
	}
}

func TestPlannerCannotExecuteCommandsOrSDKInjectedTools(t *testing.T) {
	p := newPlannerRoundPolicy(func() (bool, error) { return true, nil }, func() (bool, error) { return true, nil }, false)
	h := p.hooks()
	for _, name := range []string{"Bash", "Read", "WebFetch", "Monitor", "TaskOutput", "shell_open", "mcp__browser__navigate"} {
		blocked, _, _ := h.PreToolUse(context.Background(), name, []byte(`{}`))
		if !blocked {
			t.Fatalf("execution capability leaked to planner: %s", name)
		}
	}
}

func TestPlannerReadCacheCanonicalInputRevisionMutationAndErrors(t *testing.T) {
	revision := "1"
	calls := 0
	errorRead := false
	c := newPlannerReadCache(func(context.Context) (string, error) { return revision, nil })
	tool := actool.Build(actool.Spec{Name: "list_facts", Schema: map[string]any{"type": "object"},
		ReadOnly: func(json.RawMessage) bool { return true },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			calls++
			if errorRead {
				return actool.Errorf("temporary failure"), nil
			}
			return actool.Text("evidence"), nil
		}})
	wrapped := &plannerCachedTool{CoreTool: tool, cache: c}
	ctx := context.Background()
	wrapped.Call(ctx, json.RawMessage(`{"q":"x","limit":5}`), &actool.ToolContext{ToolUseID: "first"})
	r, _ := wrapped.Call(ctx, json.RawMessage(`{"limit":5, "q":"x"}`), nil)
	if calls != 1 || !strings.Contains(r.Flatten(), `"cache_hit":true`) || !strings.Contains(r.Flatten(), "first") {
		t.Fatal("equivalent query was not reused")
	}
	revision = "2"
	wrapped.Call(ctx, json.RawMessage(`{"q":"x","limit":5}`), nil)
	if calls != 2 {
		t.Fatal("evidence revision did not invalidate cached result")
	}
	write := &plannerCachedTool{CoreTool: actool.Build(actool.Spec{Name: "add_intent", Schema: map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("intent created: 1"), nil
		}}), cache: c}
	write.Call(ctx, json.RawMessage(`{}`), nil)
	wrapped.Call(ctx, json.RawMessage(`{"q":"x","limit":5}`), nil)
	if calls != 3 {
		t.Fatal("write did not invalidate cached result")
	}
	revision = "3"
	errorRead = true
	wrapped.Call(ctx, json.RawMessage(`{}`), nil)
	wrapped.Call(ctx, json.RawMessage(`{}`), nil)
	if calls != 5 {
		t.Fatal("error result was cached")
	}
}

func TestPlannerCompactOverviewPreservesGoalsHintsAndOriginal(t *testing.T) {
	body := strings.Repeat("已验证摘要", 300)
	view := map[string]any{"goals": "all user goals", "hints": "all user hints",
		"cold_digests": []map[string]any{{"id": int64(11), "body": body, "member_count": 5}}}
	got := plannerCompactOverview(view)
	if got["goals"] != view["goals"] || got["hints"] != view["hints"] {
		t.Fatal("user instructions changed")
	}
	entry := got["cold_digests"].([]map[string]any)[0]
	if entry["id"] != int64(11) || entry["body_truncated"] != true {
		t.Fatal("digest identity or truncation missing")
	}
	if view["cold_digests"].([]map[string]any)[0]["body"] != body {
		t.Fatal("source evidence mutated")
	}
}

func TestPlannerCompactOverviewContractsReviewHintsAndColdDigests(t *testing.T) {
	var hints []map[string]any
	hints = append(hints, map[string]any{"id": int64(1), "origin": "human", "state": "active", "text": "人工重要提示：重点测登录接口"})
	for i := int64(2); i <= 40; i++ {
		hints = append(hints, map[string]any{
			"id":     i,
			"origin": ChainReviewerKey,
			"state":  "active",
			"text":   "【链路复盘建议 review-x】" + strings.Repeat("详细复盘内容", 200),
		})
	}
	var digests []map[string]any
	for i := int64(100); i < 115; i++ {
		digests = append(digests, map[string]any{
			"id":           i,
			"member_count": 6,
			"body":         strings.Repeat("冷区汇总结论", 80),
		})
	}
	view := map[string]any{
		"goals":        []map[string]any{{"id": int64(1), "text": "goal"}},
		"hints":        hints,
		"cold_digests": digests,
		"coverage":     map[string]any{"pct": 50},
	}
	got := plannerCompactOverview(view)
	keptHints := got["hints"].([]map[string]any)
	// 1 human + latest 2 chain_reviewer hints = 3 kept; remaining 37 archived.
	if len(keptHints) != 3 {
		t.Fatalf("expected 3 kept hints (1 human + 2 review), got %d", len(keptHints))
	}
	if keptHints[0]["text"] != "人工重要提示：重点测登录接口" {
		t.Fatalf("human hint altered: %v", keptHints[0])
	}
	arch, ok := got["archived_review_hints"].(map[string]any)
	if !ok || arch["count"] != 37 {
		t.Fatalf("expected 37 archived review hints, got %#v", got["archived_review_hints"])
	}
	keptDigests := got["cold_digests"].([]map[string]any)
	if len(keptDigests) != contractedColdDigestsInline {
		t.Fatalf("expected %d inline cold_digests, got %d", contractedColdDigestsInline, len(keptDigests))
	}
	idx := got["cold_digest_index"].([]string)
	if len(idx) != 10 {
		t.Fatalf("expected 10 indexed older cold_digests, got %d", len(idx))
	}
	// Original view must remain unmutated.
	if len(view["hints"].([]map[string]any)) != 40 || len(view["cold_digests"].([]map[string]any)) != 15 {
		t.Fatal("source overview mutated")
	}
	// Worker overview keeps at most 1 review hint and preserves human hints.
	wgot := workerCompactOverview(view)
	if len(wgot["hints"].([]map[string]any)) != 2 {
		t.Fatalf("expected worker overview to keep 2 hints (1 human + 1 review), got %d", len(wgot["hints"].([]map[string]any)))
	}
}
