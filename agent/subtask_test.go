package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestSubtaskRoleNormalizationAndTimeoutClamp(t *testing.T) {
	if got := normalizeSubtaskRole(" JS Auditor / v2! "); got != "js_auditor___v2" {
		t.Fatalf("role=%q", got)
	}
	if got := normalizeSubtaskRole("   "); got != "helper" {
		t.Fatalf("empty role=%q, want helper", got)
	}
	if got := clampSubtaskTimeout(0); got != time.Duration(subtaskDefaultTimeoutSeconds)*time.Second {
		t.Fatalf("default timeout=%v", got)
	}
	if got := clampSubtaskTimeout(10); got != time.Duration(subtaskMinTimeoutSeconds)*time.Second {
		t.Fatalf("min timeout=%v", got)
	}
	if got := clampSubtaskTimeout(9999); got != time.Duration(subtaskMaxTimeoutSeconds)*time.Second {
		t.Fatalf("max timeout=%v", got)
	}
}

func TestSubtaskToolsEnforceSingleDepthAndReadOnly(t *testing.T) {
	forbidden := map[string]bool{
		SubtaskToolName:  true,
		"add_intent":     true,
		"record_fact":    true,
		"report_finding": true,
		"insert_assets":  true,
	}
	for _, readOnly := range []bool{false, true} {
		tools := subtaskTools(readOnly)
		names := map[string]bool{}
		for _, tool := range tools {
			name := tool.Name()
			if forbidden[name] {
				t.Fatalf("readOnly=%v exposed forbidden tool %q", readOnly, name)
			}
			names[name] = true
		}
		if readOnly && (names["Write"] || names["Edit"]) {
			t.Fatalf("readOnly subtask still exposed Write/Edit: %v", names)
		}
		if !readOnly && !names["Write"] {
			t.Fatalf("rw subtask missing Write: %v", names)
		}
	}
}

func TestDelegateSubtaskToolValidationAndSummaryArtifact(t *testing.T) {
	ts := NewToolSet(&db.ExplorationStore{}, "work#1")
	var gotReq SubtaskRequest
	ts.SetSubtaskRunner(func(ctx context.Context, req SubtaskRequest) (string, error) {
		gotReq = req
		return `{"ok":true,"role":"` + req.Role + `"}`, nil
	})
	tool := ts.delegateSubtask()

	// Empty task must be rejected.
	res, err := tool.Call(context.Background(), json.RawMessage(`{"role":"js_auditor","task":"   "}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected error result on empty task, got res=%+v err=%v", res, err)
	}

	// Valid call normalizes role and delegates cleanly.
	res, err = tool.Call(context.Background(), json.RawMessage(`{"role":"JS_Auditor","task":"extract API paths","read_only":true,"timeout_seconds":120}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("unexpected error: res=%+v err=%v", res, err)
	}
	if gotReq.Role != "js_auditor" || !gotReq.ReadOnly || gotReq.TimeoutSeconds != 120 {
		t.Fatalf("unexpected forwarded request: %+v", gotReq)
	}

	// Oversized output clamps summary and persists full artifact under .subtasks/.
	dir := t.TempDir()
	longText := strings.Repeat("结果片段", 1000)
	summary, art := finalizeSubtaskOutput(dir, 1, "js_auditor", longText)
	if len([]rune(summary)) > subtaskMaxOutputRunes+80 {
		t.Fatalf("summary not clamped: %d runes", len([]rune(summary)))
	}
	if art == "" {
		t.Fatal("expected artifact file path for oversized summary")
	}
	raw, err := os.ReadFile(art)
	if err != nil || string(raw) != longText {
		t.Fatalf("artifact content mismatch: err=%v len=%d", err, len(raw))
	}
}
