package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestNormalizeIntentBudget(t *testing.T) {
	tier, sec, err := NormalizeIntentBudget("", 0)
	if err != nil || tier != "" || sec != 0 {
		t.Fatalf("empty budget should pass through as unset, got (%q, %d, %v)", tier, sec, err)
	}
	tier, sec, err = NormalizeIntentBudget("DEEP", 0)
	if err != nil || tier != BudgetTierDeep || sec != 2400 {
		t.Fatalf("deep tier mismatch: (%q, %d, %v)", tier, sec, err)
	}
	tier, sec, err = NormalizeIntentBudget("quick", 900)
	if err != nil || tier != BudgetTierQuick || sec != 900 {
		t.Fatalf("explicit run_seconds should override tier default: (%q, %d, %v)", tier, sec, err)
	}
	if _, _, err := NormalizeIntentBudget("turbo", 0); err == nil {
		t.Fatal("expected invalid budget_tier to error")
	}
	if _, _, err := NormalizeIntentBudget("", 60); err == nil {
		t.Fatal("expected run_seconds below minimum to error")
	}
	if _, _, err := NormalizeIntentBudget("", 7200); err == nil {
		t.Fatal("expected run_seconds above maximum to error")
	}
}

func TestIntentRunTimeout(t *testing.T) {
	def := 20 * time.Minute
	mk := func(payload map[string]any) *db.Node {
		b, _ := json.Marshal(payload)
		return &db.Node{ID: 1, Kind: db.KindIntent, Payload: b}
	}
	if d, tier := IntentRunTimeout(mk(map[string]any{"summary": "x"}), def); d != def || tier != "" {
		t.Fatalf("expected default %v, got %v (%q)", def, d, tier)
	}
	if d, tier := IntentRunTimeout(mk(map[string]any{"budget_tier": "endgame"}), def); d != 60*time.Minute || tier != "endgame" {
		t.Fatalf("expected 60m endgame, got %v (%q)", d, tier)
	}
	if d, _ := IntentRunTimeout(mk(map[string]any{"budget_tier": "quick", "run_seconds": "1800"}), def); d != 30*time.Minute {
		t.Fatalf("expected string run_seconds override 30m, got %v", d)
	}
	if d, _ := IntentRunTimeout(mk(map[string]any{"run_seconds": 99999}), def); d != time.Duration(MaxIntentRunSeconds)*time.Second {
		t.Fatalf("expected clamped max timeout, got %v", d)
	}
}
