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
