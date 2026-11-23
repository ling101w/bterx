package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestIntentPinnedProfileIDParsing(t *testing.T) {
	cases := []struct {
		payload string
		want    int64
	}{
		{`{"summary":"test","pinned_profile_id":7}`, 7},
		{`{"summary":"test","pinned_profile_id":"12"}`, 12},
		{`{"summary":"test","pinned_profile_id":0}`, 0},
		{`{"summary":"test","pinned_profile_id":-3}`, 0},
		{`{"summary":"test"}`, 0},
	}
	for _, tc := range cases {
		node := &db.Node{Payload: json.RawMessage(tc.payload)}
		if got := intentPinnedProfileID(node); got != tc.want {
			t.Fatalf("payload %s: got %d, want %d", tc.payload, got, tc.want)
		}
	}
}

func TestIntentTelemetryAlertsAndFiltering(t *testing.T) {
	e := &Engine{}
	tm := e.beginIntentTelemetry("1", 101, "work#1", 9)
	defer e.endIntentTelemetry(101)
	tmOther := e.beginIntentTelemetry("2", 202, "work#1", 0)
	defer e.endIntentTelemetry(202)
	_ = tmOther

	// Simulate 4 repeated identical tool calls and 3 consecutive errors.
	for i := 0; i < 4; i++ {
		tm.observe(db.Activity{Kind: "tool_use", Tool: "Bash", Summary: "curl https://t/api"})
		tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true})
	}

	// Simulate long idle & run duration.
	tm.mu.Lock()
	tm.startedAt = time.Now().Add(-15 * time.Minute)
	tm.lastActAt = time.Now().Add(-6 * time.Minute)
	tm.mu.Unlock()

	snaps := e.RunningIntentTelemetry("1")
	if len(snaps) != 1 || snaps[0].IntentID != 101 {
		t.Fatalf("unexpected filtered snapshots: %+v", snaps)
	}
	s := snaps[0]
	if s.PinnedProfileID != 9 || s.ToolCalls != 4 || s.ToolErrors != 4 || s.ConsecutiveErrors != 4 || s.RepeatedToolCalls != 4 {
		t.Fatalf("unexpected telemetry counters: %+v", s)
	}
	alertSet := map[string]bool{}
	for _, a := range s.Alerts {
		alertSet[a] = true
	}
	for _, want := range []string{"idle_stall", "consecutive_errors", "repeated_tool_loop", "long_run_no_output"} {
		if !alertSet[want] {
			t.Fatalf("missing expected alert %q in %v", want, s.Alerts)
		}
	}
}

func TestResolveWorkerForIntentUsesPinnedProfile(t *testing.T) {
	fallback := &agent.Worker{}
	pinned := &agent.Worker{}
	var gotSlot WorkerSlot

	e := &Engine{
		workerResolve: func(_ *Task, slot WorkerSlot) (*agent.Worker, error) {
			gotSlot = slot
			return pinned, nil
		},
	}
	task := &Task{ID: "1"}

	// Without pinned_profile_id → fallback.
	normalIntent := &db.Node{ID: 10, Payload: json.RawMessage(`{"summary":"recon"}`)}
	w, pid := e.resolveWorkerForIntent(task, "work#1", normalIntent, fallback)
	if w != fallback || pid != 0 {
		t.Fatalf("expected fallback worker for unpinned intent, got pid=%d", pid)
	}

	// With pinned_profile_id → pinned worker via workerResolve.
	pinnedIntent := &db.Node{ID: 11, Payload: json.RawMessage(`{"summary":"deep chain","pinned_profile_id":42}`)}
	w, pid = e.resolveWorkerForIntent(task, "work#1", pinnedIntent, fallback)
	if w != pinned || pid != 42 || gotSlot.ProfileID != 42 || gotSlot.Name != "work#1" {
		t.Fatalf("expected pinned worker for profile 42, got pid=%d slot=%+v", pid, gotSlot)
	}
}

func callSupervisorTool(t *testing.T, tool actool.CoreTool, args map[string]any) (string, bool) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("%s returned error: %v", tool.Name(), err)
	}
	var b strings.Builder
	for _, blk := range res.Content {
		b.WriteString(blk.Text)
	}
	return b.String(), res.IsError
}

// TestSupervisorWorkflowPG exercises the full Supervisor workflow against a real
// PostgreSQL database: board inspection, anti-hallucination fact retraction with
// cascade intent stopping, retracted-parent rejection, model-tiered dispatch,
// live steering + asset note recording & lookup.
func TestSupervisorWorkflowPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)

	task, err := m.CreateTask("supervisor-test", "测试 Supervisor 督战流程", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	defer func() {
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	}()

	// Create a valid LLM profile for pinned dispatch testing.
	profID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name:    "strong-tier",
		Format:  "openai",
		BaseURL: "https://api.example.invalid/v1",
		APIKey:  "sk-test-key",
		Model:   "gpt-5.4",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	defer func() { _ = m.pg.DeleteProfile(profID) }()
	prof := &db.LLMProfile{ID: profID}

	// Seed an asset in task scope.
	taskIDInt, _ := strconv.ParseInt(task.ID, 10, 64)
	assetID, err := m.assets.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:          "https://target.example.test/api",
		Technologies: []string{"Spring Boot", "Cloudflare"},
		TaskID:       taskIDInt,
	})
	if err != nil {
		t.Fatalf("UpsertHTTPService: %v", err)
	}

	// Seed an origin fact, a hallucinated fact, and a downstream open intent derived from it.
	factID, err := task.Store.AddNode(db.KindFact, map[string]any{
		"summary":    "疑似越权访问 /api/admin（HTTP 200）",
		"confidence": "observed",
	}, 5, db.StateFactUnverified, "work#1", []int64{assetID})
	if err != nil {
		t.Fatalf("AddNode fact: %v", err)
	}
	childIntentID, err := task.Store.AddIntentWithParentsContext(
		context.Background(),
		map[string]any{"summary": "基于假越权事实继续深挖", "asset_ids": []int64{assetID}},
		6, []int64{assetID}, []int64{factID}, "planner",
	)
	if err != nil {
		t.Fatalf("AddIntentWithParentsContext: %v", err)
	}

	// 1. supervisor_board shows the task, unverified fact, and llm_profiles.
	boardOut, isErr := callSupervisorTool(t, s.toolSupervisorBoard(), map[string]any{"task_id": task.ID})
	if isErr || !strings.Contains(boardOut, "strong-tier") || !strings.Contains(boardOut, "unverified") {
		t.Fatalf("unexpected supervisor_board output (isErr=%v): %s", isErr, boardOut)
	}

	// 2. supervisor_retract_fact retracts fact and cascade-stops childIntentID.
	retractOut, isErr := callSupervisorTool(t, s.toolSupervisorRetractFact(), map[string]any{
		"task_id": task.ID,
		"fact_id": factID,
		"reason":  "HTTP 200 正文实际为 SPA 登录回退页，非真实越权",
	})
	if isErr {
		t.Fatalf("supervisor_retract_fact failed: %s", retractOut)
	}
	var retractRes struct {
		State            string  `json:"state"`
		StoppedIntentIDs []int64 `json:"stopped_intent_ids"`
	}
	if err := json.Unmarshal([]byte(retractOut), &retractRes); err != nil {
		t.Fatal(err)
	}
	if retractRes.State != db.StateFactRetracted || len(retractRes.StoppedIntentIDs) != 1 || retractRes.StoppedIntentIDs[0] != childIntentID {
		t.Fatalf("unexpected retract result: %+v", retractRes)
	}
	stoppedNode, _ := task.Store.GetNode(childIntentID)
	if stoppedNode == nil || stoppedNode.State != "stopped" {
		t.Fatalf("expected child intent stopped, got %+v", stoppedNode)
	}

	// 3. Dispatching a new intent anchored on the retracted fact must be rejected.
	_, isErr = callSupervisorTool(t, s.toolSupervisorDispatchIntent(), map[string]any{
		"task_id":    task.ID,
		"summary":    "继续使用已撤回事实",
		"reason":     "测试拒绝逻辑",
		"parent_ids": []int64{factID},
	})
	if !isErr {
		t.Fatal("expected supervisor_dispatch_intent to reject retracted parent fact")
	}

	// 4. supervisor_dispatch_intent with pinned_profile_id succeeds and stores pin in payload.
	dispOut, isErr := callSupervisorTool(t, s.toolSupervisorDispatchIntent(), map[string]any{
		"task_id":           task.ID,
		"summary":           "换强模型深挖认证逻辑",
		"reason":            "弱模型卡住，升级强模型突破",
		"asset_ids":         []int64{assetID},
		"pinned_profile_id": prof.ID,
		"priority":          9,
	})
	if isErr {
		t.Fatalf("supervisor_dispatch_intent failed: %s", dispOut)
	}
	var dispRes struct {
		IntentID        int64 `json:"intent_id"`
		PinnedProfileID int64 `json:"pinned_profile_id"`
	}
	_ = json.Unmarshal([]byte(dispOut), &dispRes)
	if dispRes.IntentID <= 0 || dispRes.PinnedProfileID != prof.ID {
		t.Fatalf("unexpected dispatch result: %+v", dispRes)
	}
	dispNode, _ := task.Store.GetNode(dispRes.IntentID)
	if intentPinnedProfileID(dispNode) != prof.ID {
		t.Fatalf("persisted intent missing pinned_profile_id=%d: %s", prof.ID, string(dispNode.Payload))
	}

	// 5. supervisor_record_asset_note persists note retrievable via AssetNotesForAssets.
	noteOut, isErr := callSupervisorTool(t, s.toolSupervisorRecordAssetNote(), map[string]any{
		"task_id":   task.ID,
		"asset_ids": []int64{assetID},
		"summary":   "Cloudflare WAF 拦截单引号 payload，需先确认业务基线",
		"detail":    "返回 403 且含 cf-ray 响应头",
	})
	if isErr {
		t.Fatalf("supervisor_record_asset_note failed: %s", noteOut)
	}
	notes, err := task.Store.AssetNotesForAssets([]int64{assetID}, 5)
	if err != nil || len(notes) != 1 {
		t.Fatalf("expected 1 asset note for asset %d, got len=%d err=%v", assetID, len(notes), err)
	}

	// 6. supervisor_kill_intent stops the open dispatched intent cleanly.
	killOut, isErr := callSupervisorTool(t, s.toolSupervisorKillIntent(), map[string]any{
		"task_id":   task.ID,
		"intent_id": dispRes.IntentID,
		"reason":    "测试止损关闭",
	})
	if isErr || !strings.Contains(killOut, `"stopped":true`) {
		t.Fatalf("supervisor_kill_intent failed (isErr=%v): %s", isErr, killOut)
	}
}
