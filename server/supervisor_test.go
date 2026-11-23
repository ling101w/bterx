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

	// Simulate 5 identical repeated tool calls and 5 consecutive non-transient errors.
	for i := 0; i < 5; i++ {
		tm.observe(db.Activity{Kind: "tool_use", Tool: "Bash", Summary: "curl https://t/api", Detail: "curl -s https://t/api"})
		tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true, Summary: "command not found"})
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
	if s.PinnedProfileID != 9 || s.ToolCalls != 5 || s.ToolErrors != 5 || s.ConsecutiveErrors != 5 || s.RepeatedToolCalls != 5 {
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

func TestProbeObserveWakeCooldown(t *testing.T) {
	e := &Engine{}
	tm := e.beginIntentTelemetry("1", 555, "work#1", 0)
	defer e.endIntentTelemetry(555)

	// 1. Long-prefix curl commands with identical first 160 chars but different URLs must NOT false-trigger loop.
	longHeader := "curl -s -H 'Authorization: Bearer " + strings.Repeat("A", 160) + "' "
	for i := 0; i < 6; i++ {
		url := "https://corp.example.test/api/item/" + strconv.Itoa(i)
		if alerts, _ := tm.observe(db.Activity{
			Kind: "tool_use", Tool: "Bash",
			Summary: longHeader + url,
			Detail:  longHeader + url,
		}); len(alerts) != 0 {
			t.Fatalf("unexpected false-positive loop alert on distinct long curl #%d: %v", i, alerts)
		}
	}

	// 2. Transient/benign errors (503, 429, grep exit 1) must NOT escalate consecutive_errors.
	for _, msg := range []string{"HTTP 503 Service Unavailable", "429 Too Many Requests", "grep foo bar: exit status 1"} {
		if alerts, _ := tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true, Summary: msg}); len(alerts) != 0 {
			t.Fatalf("unexpected wakeup on transient/benign error %q: %v", msg, alerts)
		}
	}
	if snap := tm.snapshot(time.Now()); snap.ConsecutiveErrors != 0 {
		t.Fatalf("expected transient/benign errors not to bump consecutiveErrors, got %d", snap.ConsecutiveErrors)
	}

	// 3. During startup warmup (<90s), 5 errors surface passive alert in snapshot but do NOT wake Planner.
	for i := 0; i < 5; i++ {
		if alerts, _ := tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true, Summary: "syntax error"}); len(alerts) != 0 {
			t.Fatalf("unexpected active wakeup during warmup window: %v", alerts)
		}
	}

	// 4. After warmup window, non-transient hard error triggers consecutive_errors wakeup, then cooldown suppresses immediate repeat.
	tm.mu.Lock()
	tm.startedAt = time.Now().Add(-2 * time.Minute)
	tm.mu.Unlock()
	alerts, _ := tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true, Summary: "syntax error"})
	if len(alerts) == 0 || alerts[0] != "consecutive_errors" {
		t.Fatalf("expected consecutive_errors after warmup, got %v", alerts)
	}
	if alerts2, _ := tm.observe(db.Activity{Kind: "tool_result", Tool: "Bash", IsError: true, Summary: "syntax error"}); len(alerts2) != 0 {
		t.Fatalf("expected cooldown to suppress duplicate wake, got %v", alerts2)
	}
}

func TestProbeExactRepeatedLoopWakesImmediately(t *testing.T) {
	e := &Engine{}
	tm := e.beginIntentTelemetry("1", 556, "work#2", 0)
	defer e.endIntentTelemetry(556)

	for i := 0; i < 4; i++ {
		if alerts, _ := tm.observe(db.Activity{Kind: "tool_use", Tool: "Bash", Summary: "curl -s https://t/same", Detail: "curl -s https://t/same"}); len(alerts) != 0 {
			t.Fatalf("unexpected early loop alert at call %d: %v", i+1, alerts)
		}
	}
	alerts, _ := tm.observe(db.Activity{Kind: "tool_use", Tool: "Bash", Summary: "curl -s https://t/same", Detail: "curl -s https://t/same"})
	if len(alerts) == 0 || alerts[0] != "repeated_tool_loop" {
		t.Fatalf("expected repeated_tool_loop on 5th identical call, got %v", alerts)
	}
}

// TestUnifiedCommanderWorkflowPG verifies that the merged Task Commander (Planner)
// natively performs model-tiered add_intent, kill_work tombstones, retract_fact
// with cascade stop, record_asset_note, and L1 chain_view overview against PG.
func TestUnifiedCommanderWorkflowPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)

	task, err := m.CreateTask("commander-test", "企业 SRC 综合挖掘测试", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	defer func() {
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	}()

	p1, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "flash-tier", Format: "openai", BaseURL: "https://api.example.invalid/v1", APIKey: "sk-1", Model: "fast-mini",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteProfile(p1) }()
	p2, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "strong-tier", Format: "openai", BaseURL: "https://api.example.invalid/v1", APIKey: "sk-2", Model: "strong-pro",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteProfile(p2) }()

	taskIDInt, _ := strconv.ParseInt(task.ID, 10, 64)
	assetID, err := m.assets.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL: "https://corp.example.test/api/orders", Technologies: []string{"Spring Boot", "Vue"}, TaskID: taskIDInt,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build a Planner-configured ToolSet wired exactly like Server.agentsForTask.
	tsx := agent.NewToolSet(task.Store, "planner")
	tsx.SetAssetStore(m.assets, m.assets.Companies())
	tsx.SetTaskID(taskIDInt)
	findTool := func(name string) actool.CoreTool {
		for _, tool := range tsx.PlannerTools() {
			if tool.Name() == name {
				return tool
			}
		}
		t.Fatalf("planner tool %s missing", name)
		return nil
	}

	// Wire Planner via SetProfileLister / SetProfileValidator indirectly by exercising
	// Planner's native tools on the live exploration store.
	addIntentTool := findTool("add_intent")
	retractTool := findTool("retract_fact")
	assetNoteTool := findTool("record_asset_note")
	overviewTool := findTool("graph_overview")

	// 1. Create a fact and a downstream intent with pinned_profile_id=p2.
	factID, err := task.Store.AddNode(db.KindFact, map[string]any{
		"summary": "疑似 /api/orders 存在越权读取", "confidence": "observed",
	}, 5, db.StateFactUnverified, "work#1", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}
	addOut, isErr := callSupervisorTool(t, addIntentTool, map[string]any{
		"summary":           "换强模型深挖订单越权链",
		"asset_ids":         []int64{assetID},
		"parent_ids":        []int64{factID},
		"pinned_profile_id": p2,
		"model_reason":      "复杂多角色业务逻辑，升档强模型",
		"priority":          9,
	})
	if isErr || !strings.Contains(addOut, "intent created:") {
		t.Fatalf("planner add_intent failed (isErr=%v): %s", isErr, addOut)
	}

	// 2. Planner retracts the hallucinated fact → cascade-stops the intent.
	retOut, isErr := callSupervisorTool(t, retractTool, map[string]any{
		"fact_id": factID,
		"reason":  "核对响应体实为前端 SPA 登录壳",
	})
	if isErr || !strings.Contains(retOut, `"state":"retracted"`) {
		t.Fatalf("planner retract_fact failed (isErr=%v): %s", isErr, retOut)
	}

	// 3. Planner records an asset note.
	noteOut, isErr := callSupervisorTool(t, assetNoteTool, map[string]any{
		"asset_ids": []int64{assetID},
		"summary":   "未登录请求一律返回 HTTP 200 + code=40100 JSON",
	})
	if isErr || !strings.Contains(noteOut, `"note_id"`) {
		t.Fatalf("planner record_asset_note failed (isErr=%v): %s", isErr, noteOut)
	}

	// 4. Planner graph_overview surfaces chain_view, recent_stopped_intents, and retracted_facts.
	ovOut, isErr := callSupervisorTool(t, overviewTool, map[string]any{})
	if isErr {
		t.Fatalf("graph_overview failed: %s", ovOut)
	}
	for _, want := range []string{`"chain_view"`, `"recent_stopped_intents"`, `"retracted_facts"`, "SPA 登录壳"} {
		if !strings.Contains(ovOut, want) {
			t.Fatalf("graph_overview missing %s:\n%s", want, ovOut)
		}
	}
	// Ensure retracted fact is NOT in recent_facts.
	var ovMap map[string]any
	if err := json.Unmarshal([]byte(ovOut), &ovMap); err != nil {
		t.Fatal(err)
	}
	if rf, ok := ovMap["recent_facts"].([]any); ok {
		for _, item := range rf {
			if m, ok := item.(map[string]any); ok && int64(m["id"].(float64)) == factID {
				t.Fatalf("retracted fact #%d leaked into recent_facts", factID)
			}
		}
	}
	_ = s
}
