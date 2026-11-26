package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Per-intent dynamic wall-clock budget tiers. Planner can assign a tier or an
// explicit run_seconds when creating an intent via add_intent so fast sweeps
// finish quickly while deep/endgame exploit chains get enough runway without
// suffering multi-baton container rebuild taxes.
const (
	BudgetTierQuick    = "quick"    // 10m: quick recon, probe, single-point check
	BudgetTierStandard = "standard" // 20m: default exploration / standard challenge
	BudgetTierDeep     = "deep"     // 40m: complex chain, reverse engineering, slow reasoning model
	BudgetTierEndgame  = "endgame"  // 60m: high-value endgame / hard-target final push

	MinIntentRunSeconds = 180  // 3m floor
	MaxIntentRunSeconds = 3600 // 60m cap (still clamped by task-level deadline)
)

var budgetTierSeconds = map[string]int{
	BudgetTierQuick:    600,
	BudgetTierStandard: 1200,
	BudgetTierDeep:     2400,
	BudgetTierEndgame:  3600,
}

// NormalizeIntentBudget validates and resolves optional budget_tier and
// run_seconds parameters from add_intent. Returns ("", 0, nil) when neither is
// specified so the worker falls back to its configured agent run_seconds.
func NormalizeIntentBudget(tier string, runSeconds int) (normTier string, normSec int, err error) {
	normTier = strings.ToLower(strings.TrimSpace(tier))
	if normTier != "" {
		sec, ok := budgetTierSeconds[normTier]
		if !ok {
			return "", 0, fmt.Errorf("budget_tier 必须是 quick / standard / deep / endgame 之一，收到 %q", tier)
		}
		normSec = sec
	}
	if runSeconds < 0 {
		return "", 0, fmt.Errorf("run_seconds 不能为负数")
	}
	if runSeconds > 0 {
		if runSeconds < MinIntentRunSeconds || runSeconds > MaxIntentRunSeconds {
			return "", 0, fmt.Errorf("run_seconds 必须在 %d~%d 秒（%d~%d 分钟）之间，收到 %d",
				MinIntentRunSeconds, MaxIntentRunSeconds, MinIntentRunSeconds/60, MaxIntentRunSeconds/60, runSeconds)
		}
		normSec = runSeconds
	}
	return normTier, normSec, nil
}

// IntentRunTimeout extracts the effective wall-clock timeout for one intent.
// Explicit run_seconds takes precedence over budget_tier, both fall back to
// defaultTimeout when unset. Out-of-bounds persisted values are safely clamped.
func IntentRunTimeout(intent *db.Node, defaultTimeout time.Duration) (time.Duration, string) {
	if intent == nil || len(intent.Payload) == 0 {
		return defaultTimeout, ""
	}
	var p struct {
		BudgetTier string          `json:"budget_tier"`
		RunSeconds json.RawMessage `json:"run_seconds"`
	}
	if json.Unmarshal(intent.Payload, &p) != nil {
		return defaultTimeout, ""
	}
	tier := strings.ToLower(strings.TrimSpace(p.BudgetTier))
	sec := int(pid(p.RunSeconds))
	if sec <= 0 && tier != "" {
		sec = budgetTierSeconds[tier]
	}
	if sec <= 0 {
		return defaultTimeout, tier
	}
	if sec < MinIntentRunSeconds {
		sec = MinIntentRunSeconds
	}
	if sec > MaxIntentRunSeconds {
		sec = MaxIntentRunSeconds
	}
	return time.Duration(sec) * time.Second, tier
}
