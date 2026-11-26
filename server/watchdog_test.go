package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestWatchdogNudgesThenRecyclesLoopingWorker(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "99"}
	base := time.Now().Add(-3 * time.Minute)

	ctx, cancel := context.WithCancelCause(context.Background())
	e.registerWork(101, cancel)
	tm := e.beginIntentTelemetry(task.ID, 101, "work#1", 0)
	tm.mu.Lock()
	tm.startedAt = base
	tm.lastActAt = base.Add(2 * time.Minute)
	tm.repeatedToolCalls = probeRepeatedToolCallLimit
	tm.mu.Unlock()

	// Stage 1: first tick emits a single mechanical nudge without cancelling.
	now1 := base.Add(3 * time.Minute)
	nudged, recycled, _ := e.watchdogTick(task, now1)
	if nudged != 1 || recycled != 0 {
		t.Fatalf("stage1: nudged=%d recycled=%d, want 1,0", nudged, recycled)
	}
	if ctx.Err() != nil {
		t.Fatal("stage1 should nudge without cancelling")
	}
	msg, ok := e.drainSteer(101)
	if !ok || msg == "" {
		t.Fatal("expected queued watchdog steer message")
	}

	// Stage 2: still looping >=10 after post-nudge grace -> hard recycle with AbortWatchdogRecycle.
	tm.mu.Lock()
	tm.repeatedToolCalls = watchdogHardLoopThreshold
	tm.mu.Unlock()
	now2 := now1.Add(watchdogPostNudgeGrace + time.Second)
	nudged, recycled, _ = e.watchdogTick(task, now2)
	if nudged != 0 || recycled != 1 {
		t.Fatalf("stage2: nudged=%d recycled=%d, want 0,1", nudged, recycled)
	}
	if !errors.Is(context.Cause(ctx), agent.AbortWatchdogRecycle) {
		t.Fatalf("cancel cause = %v, want AbortWatchdogRecycle", context.Cause(ctx))
	}
}

func TestWatchdogHardIdleRecyclesSilentWorker(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "100"}
	base := time.Now().Add(-12 * time.Minute)

	ctx, cancel := context.WithCancelCause(context.Background())
	e.registerWork(202, cancel)
	tm := e.beginIntentTelemetry(task.ID, 202, "work#2", 0)
	tm.mu.Lock()
	tm.startedAt = base
	tm.lastActAt = base
	tm.mu.Unlock()

	_, recycled, _ := e.watchdogTick(task, base.Add(watchdogHardIdleThreshold+time.Second))
	if recycled != 1 {
		t.Fatalf("recycled=%d, want 1", recycled)
	}
	if !errors.Is(context.Cause(ctx), agent.AbortWatchdogRecycle) {
		t.Fatalf("cause=%v, want AbortWatchdogRecycle", context.Cause(ctx))
	}
}

func TestWatchdogRestartBudgetAndPlannerBackoff(t *testing.T) {
	e := NewEngine(nil)
	if n := e.bumpWatchdogRestart(303); n != 1 {
		t.Fatalf("first restart=%d, want 1", n)
	}
	if n := e.bumpWatchdogRestart(303); n != 2 {
		t.Fatalf("second restart=%d, want 2", n)
	}
	if n := e.bumpWatchdogRestart(303); n != 3 {
		t.Fatalf("third restart=%d, want 3", n)
	}

	normal := 10 * time.Minute
	want := []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second}
	for i, w := range want {
		got, ok := watchdogPlannerBackoff(i+1, normal)
		if !ok || got != w {
			t.Fatalf("attempt %d: got (%v,%v), want (%v,true)", i+1, got, ok, w)
		}
	}
	if _, ok := watchdogPlannerBackoff(4, normal); ok {
		t.Fatal("attempt 4 should fall back to normal heartbeat")
	}
}

func TestSelectSameFamilyHealthyRotation(t *testing.T) {
	target := &db.LLMProfile{ID: 10, Name: "glm-key-1", Model: "glm-5.3", APIKey: "k1"}
	all := []*db.LLMProfile{
		target,
		{ID: 11, Name: "ds-flash", Model: "deepseek-v4.1-flash", APIKey: "k2"},
		{ID: 12, Name: "glm-flash", Model: "glm-5.3-flash", APIKey: "k3"},
		{ID: 13, Name: "glm-key-2", Model: "glm-5.3", APIKey: "k4"},
		{ID: 14, Name: "jev-local", Format: "jev", Model: "glm-5.3", APIKey: "k5"},
		{ID: 15, Name: "glm-excluded", Model: "glm-5.3", APIKey: "k6", PoolExclude: true},
	}

	// Exact model match (#13) must beat family-prefix match (#12), skipping jev (#14) and excluded (#15).
	id, _ := selectSameFamilyHealthy(target, all, func(pid int64) bool { return pid == 10 })
	if id != 13 {
		t.Fatalf("exact match id=%d, want 13", id)
	}

	// When exact match #13 is also tripped, fall back to same-family #12 (not unrelated deepseek #11).
	id, _ = selectSameFamilyHealthy(target, all, func(pid int64) bool { return pid == 10 || pid == 13 })
	if id != 12 {
		t.Fatalf("family fallback id=%d, want 12", id)
	}

	// When all same-family keys are tripped, return 0 (do not silently jump to unrelated vendor).
	id, _ = selectSameFamilyHealthy(target, all, func(pid int64) bool { return pid == 10 || pid == 12 || pid == 13 })
	if id != 0 {
		t.Fatalf("exhausted family id=%d, want 0", id)
	}
}
