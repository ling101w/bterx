package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMatchPitfallCardsBuiltinsAndCustomDir(t *testing.T) {
	dir := t.TempDir()
	customJSON := `{"id":"custom-k8s","title":"自定义网关特征","match_techs":["envoy"],"match_keywords":["x-envoy"],"guidance":"检查 X-Envoy 响应头区分网关拦截。"}`
	if err := os.WriteFile(filepath.Join(dir, "envoy.json"), []byte(customJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	assets := []*db.Asset{
		{
			ID:           10,
			URL:          "https://app.example.com/api/v1/user",
			Technologies: []string{"Vue", "Spring Boot", "Envoy"},
		},
	}
	cards := MatchPitfallCards(assets, "检查鉴权与未授权访问", dir, 3)
	if len(cards) != 3 {
		t.Fatalf("expected 3 matched cards, got %d: %+v", len(cards), cards)
	}
	rendered := RenderPitfallCardsBlock(cards)
	if !strings.Contains(rendered, "自动推送核验与避坑卡") {
		t.Fatalf("unexpected rendered pitfall block: %s", rendered)
	}
	// Verify custom card matches when specifically targeted.
	envoyCards := MatchPitfallCards([]*db.Asset{{Technologies: []string{"Envoy"}}}, "", dir, 2)
	foundCustom := false
	for _, c := range envoyCards {
		if c.ID == "custom-k8s" {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Fatalf("expected custom-k8s card to match Envoy asset, got %+v", envoyCards)
	}
}

func TestRenderAssetNotesBlock(t *testing.T) {
	p1, _ := json.Marshal(map[string]any{"summary": "存在 Cloudflare WAF，触发规则返回 403", "detail": "单 IP 超过 20req/s 触发拦截", "asset_note": true})
	nodes := []*db.Node{
		{ID: 77, Origin: "supervisor", Anchors: []int64{10}, Payload: p1},
	}
	out := RenderAssetNotesBlock(nodes)
	if !strings.Contains(out, "同资产实时共享备注") || !strings.Contains(out, "Cloudflare WAF") {
		t.Fatalf("unexpected asset notes block: %s", out)
	}
	if RenderAssetNotesBlock(nil) != "" {
		t.Fatal("expected empty block for nil notes")
	}
}

func TestClassifyFactInitialStateAntiHallucinationGate(t *testing.T) {
	okAct := &db.Activity{ID: 101, IsError: false}
	errAct := &db.Activity{ID: 102, IsError: true}

	cases := []struct {
		name      string
		item      factItem
		act       *db.Activity
		wantState string
	}{
		{
			name:      "observed without evidence downgrades to unverified",
			item:      factItem{Summary: "后台接口返回 200", Confidence: "observed"},
			wantState: db.StateFactUnverified,
		},
		{
			name:      "high impact claim without evidence downgrades to unverified",
			item:      factItem{Summary: "存在未授权访问管理员接口", Confidence: "inferred"},
			wantState: db.StateFactUnverified,
		},
		{
			name:      "observed with text evidence stays confirmed",
			item:      factItem{Summary: "后台接口返回 200", Confidence: "observed", Evidence: "curl -i /admin -> 200 {\"users\":[]}"},
			wantState: db.StateFactConfirmed,
		},
		{
			name:      "high impact claim with verified non-error activity stays confirmed",
			item:      factItem{Summary: "确认越权访问", Confidence: "observed"},
			act:       okAct,
			wantState: db.StateFactConfirmed,
		},
		{
			name:      "observed with error activity and no evidence downgrades to unverified",
			item:      factItem{Summary: "接口可执行命令", Confidence: "observed"},
			act:       errAct,
			wantState: db.StateFactUnverified,
		},
		{
			name:      "ordinary inferred observation remains confirmed",
			item:      factItem{Summary: "站点可能使用 Nginx 反代", Confidence: "inferred"},
			wantState: db.StateFactConfirmed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyFactInitialState(tc.item, tc.act)
			if got != tc.wantState {
				t.Fatalf("got state=%q (reason=%q), want %q", got, reason, tc.wantState)
			}
			if tc.wantState == db.StateFactUnverified && reason == "" {
				t.Fatal("expected non-empty downgrade reason for unverified state")
			}
		})
	}
}

func TestBuildLayeredChainViewAndTombstones(t *testing.T) {
	intents := []*db.Node{
		{ID: 1, Kind: db.KindIntent, State: "running", Payload: json.RawMessage(`{"summary":"深挖 /api/admin 鉴权","asset_ids":[10],"pinned_profile_id":5}`)},
		{ID: 2, Kind: db.KindIntent, State: "stopped", DeleteReason: "SPA 回退页误报", Payload: json.RawMessage(`{"summary":"测试 /fake 路径","asset_ids":[10]}`)},
		{ID: 3, Kind: db.KindIntent, State: "open", Payload: json.RawMessage(`{"summary":"常规子域探测","asset_ids":[20]}`)},
	}
	facts := []*db.Node{
		{ID: 11, Kind: db.KindFact, State: db.StateFactUnverified, Payload: json.RawMessage(`{"summary":"疑似未授权访问"}`)},
		{ID: 12, Kind: db.KindFact, State: db.StateFactRetracted, Payload: json.RawMessage(`{"summary":"假越权","retraction":{"reason":"200 实际是登录页"}}`)},
		{ID: 13, Kind: db.KindFact, State: db.StateFactConfirmed, Payload: json.RawMessage(`{"summary":"WAF 拦截规则","asset_note":true}`)},
	}
	findings := []*db.Node{
		{ID: 21, Kind: db.KindFinding, State: "confirmed", Payload: json.RawMessage(`{"summary":"订单接口 IDOR"}`)},
	}
	anchors := map[int64][]int64{
		1: {10}, 2: {10}, 3: {20}, 11: {10}, 12: {10}, 13: {10}, 21: {10},
	}
	tm := map[int64]IntentTelemetryInfo{
		1: {IntentID: 1, Alerts: []string{"consecutive_errors"}},
	}
	chain := buildLayeredChainView(intents, facts, findings, anchors, tm)
	if len(chain) != 2 {
		t.Fatalf("expected 2 branches, got %d: %+v", len(chain), chain)
	}
	// Branch asset:10 has alerts + unverified fact + finding so it must sort first.
	b0 := chain[0]
	if b0.AssetID != 10 || !b0.HasAlerts || !b0.HasUnverifiedFact || b0.AssetNotes != 1 {
		t.Fatalf("unexpected top branch: %+v", b0)
	}
	if len(b0.ActiveIntents) != 1 || !strings.Contains(b0.ActiveIntents[0], "ALERT:consecutive_errors") || !strings.Contains(b0.ActiveIntents[0], "pin#5") {
		t.Fatalf("expected alert & pin marker in active intent: %+v", b0.ActiveIntents)
	}
	if len(b0.Tombstones) != 2 {
		t.Fatalf("expected 2 tombstones (stopped intent + retracted fact), got %+v", b0.Tombstones)
	}
}

func TestPlannerCommanderPolicyAllowlist(t *testing.T) {
	for _, allowed := range []string{"list_llm_profiles", "retract_fact", "record_asset_note", "add_intent", "kill_work", "steer_work"} {
		if !plannerToolNames[allowed] {
			t.Fatalf("expected %s in plannerToolNames", allowed)
		}
	}
	for _, forbidden := range []string{"Bash", "WebFetch", "Write", "Edit"} {
		if plannerToolNames[forbidden] {
			t.Fatalf("unexpected execution tool %s allowed for planner", forbidden)
		}
	}
}
