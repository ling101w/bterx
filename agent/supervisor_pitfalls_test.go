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
	edges := []db.Edge{
		{From: 11, Rel: db.RelDerivedFrom, To: 3}, // cross-asset link: asset 10 -> asset 20
	}
	anchors := map[int64][]int64{
		1: {10}, 2: {10}, 3: {20}, 11: {10}, 12: {10}, 13: {10}, 21: {10},
	}
	tm := map[int64]IntentTelemetryInfo{
		1: {IntentID: 1, Alerts: []string{"consecutive_errors"}},
	}
	assetMeta := map[int64]chainAssetMeta{
		10: {ID: 10, Label: "https://admin.corp.test", Technologies: []string{"Spring Boot", "Vue"}},
		20: {ID: 20, Label: "https://api.corp.test", Technologies: []string{"Nginx"}},
	}
	untested := []chainAssetMeta{
		{ID: 30, Label: "https://sso.corp.test/login", Technologies: []string{"Keycloak"}},
	}
	chain := buildLayeredChainView(intents, facts, findings, edges, anchors, tm, assetMeta, untested)
	if len(chain) != 3 {
		t.Fatalf("expected 3 branches (2 active + 1 untested dangling), got %d: %+v", len(chain), chain)
	}
	// Branch asset:10 has alerts + unverified fact + finding so it sorts first.
	b0 := chain[0]
	if b0.AssetID != 10 || b0.Label != "https://admin.corp.test" || !b0.HasAlerts || !b0.HasUnverifiedFact || b0.AssetNotes != 1 {
		t.Fatalf("unexpected top branch: %+v", b0)
	}
	if len(b0.RelatedAssets) != 1 || b0.RelatedAssets[0] != 20 {
		t.Fatalf("expected cross-asset related_assets=[20], got %+v", b0.RelatedAssets)
	}
	if len(b0.ActiveIntents) != 1 || !strings.Contains(b0.ActiveIntents[0], "ALERT:consecutive_errors") || !strings.Contains(b0.ActiveIntents[0], "pin#5") {
		t.Fatalf("expected alert & pin marker in active intent: %+v", b0.ActiveIntents)
	}
	if len(b0.Tombstones) != 2 {
		t.Fatalf("expected 2 tombstones (stopped intent + retracted fact), got %+v", b0.Tombstones)
	}
	// Untested asset 30 must be preserved in dangling bucket with stage="untested".
	foundUntested := false
	for _, b := range chain {
		if b.AssetID == 30 && b.Stage == "untested" && b.Label == "https://sso.corp.test/login" {
			foundUntested = true
		}
	}
	if !foundUntested {
		t.Fatalf("expected untested asset 30 in chain_view: %+v", chain)
	}
}

func TestChainViewReservesQuotaForDanglingLeads(t *testing.T) {
	// Even with 14 busy active branches, a brand-new untested asset must not be crowded out.
	var intents []*db.Node
	anchors := map[int64][]int64{}
	for i := int64(1); i <= 14; i++ {
		intents = append(intents, &db.Node{
			ID: i, Kind: db.KindIntent, State: "running",
			Payload: json.RawMessage(`{"summary":"busy branch"}`),
		})
		anchors[i] = []int64{100 + i}
	}
	untested := []chainAssetMeta{{ID: 999, Label: "https://new-admin.corp.test"}}
	chain := buildLayeredChainView(intents, nil, nil, nil, anchors, nil, nil, untested)
	if len(chain) != 12 {
		t.Fatalf("expected cap 12, got %d", len(chain))
	}
	found := false
	for _, b := range chain {
		if b.AssetID == 999 {
			found = true
		}
	}
	if !found {
		t.Fatalf("dangling untested lead #999 was crowded out of chain_view")
	}
}

func TestPlannerDecisionAntiEarlyStopGuard(t *testing.T) {
	noActive := func() (bool, error) { return false, nil }
	hasGoals := func() (bool, error) { return true, nil }
	policy := newPlannerRoundPolicy(noActive, hasGoals, false)
	policy.setBacklogCheck(func() []string {
		return []string{"仍有 2 个未测资产（如 #30(https://sso.corp.test)）"}
	})
	tool := policy.decisionTool()

	// 1. await_running must be rejected when no active intents exist.
	res, err := tool.Call(t.Context(), json.RawMessage(`{"reason_kind":"await_running","reason":"等待当前在跑任务返回结果","next_requirement":"等待结果"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected await_running rejected with empty queue, got err=%v res=%+v", err, res)
	}

	// 2. First bailout attempt with unexplored backlog must be rejected.
	res, err = tool.Call(t.Context(), json.RawMessage(`{"reason_kind":"missing_prerequisite","reason":"缺少管理员测试凭据","next_requirement":"提供管理员账号"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected first early-stop attempt rejected when backlog exists, got err=%v res=%+v", err, res)
	}

	// 3. Second attempt with short vague reason is still rejected.
	res, err = tool.Call(t.Context(), json.RawMessage(`{"reason_kind":"missing_prerequisite","reason":"还是缺少管理员账号","next_requirement":"提供管理员账号"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected short second reason rejected, got err=%v res=%+v", err, res)
	}

	// 4. Second attempt with explicit detailed justification (>=20 runes) is accepted to avoid deadlock.
	res, err = tool.Call(t.Context(), json.RawMessage(`{"reason_kind":"missing_prerequisite","reason":"已逐一核查未测资产 #30 均强依赖企业内部 SSO 硬件令牌登录，当前无匿名入口可继续探测","next_requirement":"提供企业 SSO 测试会话"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("expected justified second decision accepted, got err=%v res=%+v", err, res)
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
