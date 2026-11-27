package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaybookValidationAndGuards(t *testing.T) {
	// 1. disproved without evidence_ref must be rejected.
	pb := Playbook{
		Phase: "deep_push",
		Hypotheses: []PlaybookHypothesis{
			{TargetID: "bctf2026-08", Path: "double URL encode SQLi", Status: HypothesisDisproved},
		},
	}
	if err := ValidatePlaybook(&pb); err == nil {
		t.Fatal("expected disproved without evidence_ref to fail validation")
	}

	// 2. timeout-only excuse must not pass as disproved.
	pb.Hypotheses[0].EvidenceRef = "timeout"
	if err := ValidatePlaybook(&pb); err == nil {
		t.Fatal("expected timeout-only evidence_ref for disproved to fail validation")
	}

	// 3. inconclusive with timeout is valid.
	pb.Hypotheses[0].Status = HypothesisInconclusive
	if err := ValidatePlaybook(&pb); err != nil {
		t.Fatalf("expected inconclusive to pass, got %v", err)
	}

	// 4. disproved with concrete evidence_ref passes.
	pb.Hypotheses[0].Status = HypothesisDisproved
	pb.Hypotheses[0].EvidenceRef = "fact#1010 FreeMarker ?new disabled by engine"
	if err := ValidatePlaybook(&pb); err != nil {
		t.Fatalf("expected concrete disproved ref to pass, got %v", err)
	}

	// 5. >10 global_rules rejected.
	pb.GlobalRules = []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}
	if err := ValidatePlaybook(&pb); err == nil {
		t.Fatal("expected >10 global_rules to fail")
	}
	pb.GlobalRules = pb.GlobalRules[:10]

	// 6. >5 hypotheses on one target_id rejected.
	pb.Hypotheses = nil
	for i := 0; i < 6; i++ {
		pb.Hypotheses = append(pb.Hypotheses, PlaybookHypothesis{
			TargetID: "bctf2026-36",
			Path:     "path-" + string(rune('a'+i)),
			Status:   HypothesisActive,
		})
	}
	if err := ValidatePlaybook(&pb); err == nil {
		t.Fatal("expected >5 hypotheses for one target to fail")
	}

	// 7. Hard 4KB byte ceiling enforced.
	big := Playbook{Phase: "salvage"}
	for i := 0; i < 35; i++ {
		big.Hypotheses = append(big.Hypotheses, PlaybookHypothesis{
			TargetID:    "target-" + string(rune('a'+(i%26))) + string(rune('0'+(i/26))),
			Path:        strings.Repeat("x", 120),
			Status:      HypothesisActive,
			EvidenceRef: "fact#999",
		})
	}
	if err := ValidatePlaybook(&big); err == nil {
		t.Fatal("expected >4KB playbook to fail validation")
	}
}

func TestPlaybookSharedIndexAndReconcileAutoPrune(t *testing.T) {
	workDir := t.TempDir()
	taskDir := filepath.Join(workDir, "tasks", "4")
	if err := os.MkdirAll(filepath.Join(taskDir, "shared_tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, ".benchctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(taskDir, "shared_tools", "sqli.py"), []byte("# ok"), 0o644)
	_ = os.WriteFile(filepath.Join(workDir, "benchctl.py"), []byte("# ok"), 0o644)
	_ = os.MkdirAll(filepath.Join(workDir, "skills", "jwt-audit"), 0o755)
	_ = os.WriteFile(filepath.Join(workDir, ".benchctl", "state_abc.json"), []byte(`{
		"challenges": {
			"bctf2026-21": {"solved_at": 1795590710},
			"bctf2026-23": {"env_broken": true, "last_reason": "nginx 502"},
			"bctf2026-08": {"deferred": true}
		}
	}`), 0o644)

	// Persist initial playbook via helper.
	initial := Playbook{
		Phase:       "deep_push",
		GlobalRules: []string{"profile #30 disabled"},
		Hypotheses: []PlaybookHypothesis{
			{TargetID: "bctf2026-21", Path: "boolean sqli", Status: HypothesisActive, EvidenceRef: "fact#957"},
			{TargetID: "bctf2026-23", Path: "502 probe", Status: HypothesisInconclusive, EvidenceRef: "fact#940"},
			{TargetID: "bctf2026-08", Path: "pg_read_file heap", Status: HypothesisActive, EvidenceRef: "fact#1095"},
		},
	}
	if err := savePlaybookUnlocked(playbookPath(taskDir), initial); err != nil {
		t.Fatalf("save initial playbook: %v", err)
	}

	pb, pruned, err := ReconcilePlaybook(workDir, taskDir, nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(pruned) != 2 || pruned[0] != "bctf2026-21" || pruned[1] != "bctf2026-23" {
		t.Fatalf("expected solved/env_broken pruned [bctf2026-21 bctf2026-23], got %v", pruned)
	}
	if len(pb.Hypotheses) != 1 || pb.Hypotheses[0].TargetID != "bctf2026-08" {
		t.Fatalf("expected only bctf2026-08 kept, got %+v", pb.Hypotheses)
	}
	if !strings.Contains(pb.SharedIndex, "benchctl.py") || !strings.Contains(pb.SharedIndex, "sqli.py") || !strings.Contains(pb.SharedIndex, "jwt-audit") {
		t.Fatalf("shared_index missing discovered L1 artifacts: %q", pb.SharedIndex)
	}

	// Tail render must include JSON and pruned notice, and stay within budget.
	tail := renderPlaybookTail(pb, pruned)
	if !strings.Contains(tail, "PLAYBOOK.json") || !strings.Contains(tail, "bctf2026-08") {
		t.Fatalf("unexpected tail render: %s", tail)
	}
}

func TestPlaybookUpdateToolRoundTrip(t *testing.T) {
	workDir := t.TempDir()
	taskDir := filepath.Join(workDir, "tasks", "9")
	_ = os.MkdirAll(taskDir, 0o755)
	ts := &ToolSet{playbookWorkDir: workDir, playbookTaskDir: taskDir}
	// Call the underlying logic directly via updatePlaybookTool with a non-nil stub store?
	// needExploration requires non-nil ts; test applyPlaybookUpdate + save/load via direct helper.
	pb := Playbook{}
	phase := "sweep"
	applyPlaybookUpdate(&pb, playbookUpdateInput{
		Phase:    &phase,
		AddRules: []string{"use glm-5.3 only for deep_push"},
		UpsertHypotheses: []PlaybookHypothesis{
			{TargetID: "creator.douyin.com", Path: "method-level auth gap", Status: HypothesisActive, EvidenceRef: "fact#10"},
		},
	})
	if err := ValidatePlaybook(&pb); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := savePlaybookUnlocked(playbookPath(taskDir), pb); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Upsert same (target_id, path) to disproved with concrete ref.
	loaded, err := LoadPlaybook(taskDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	applyPlaybookUpdate(&loaded, playbookUpdateInput{
		UpsertHypotheses: []PlaybookHypothesis{
			{TargetID: "creator.douyin.com", Path: "method-level auth gap", Status: HypothesisDisproved, EvidenceRef: "fact#22 gateway enforces middleware on all verbs"},
		},
	})
	if err := ValidatePlaybook(&loaded); err != nil {
		t.Fatalf("validate updated: %v", err)
	}
	if len(loaded.Hypotheses) != 1 || loaded.Hypotheses[0].Status != HypothesisDisproved {
		t.Fatalf("expected in-place upsert, got %+v", loaded.Hypotheses)
	}
	// Verify tool refuses when store is nil (safety guard).
	res, err := ts.updatePlaybookTool().Call(context.Background(), json.RawMessage(`{"phase":"sweep"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected nil-store safety error, got res=%+v err=%v", res, err)
	}
}
