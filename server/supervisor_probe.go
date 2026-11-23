package server

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const (
	probeIdleStallThreshold    = 5 * time.Minute
	probeLongRunNoOutputWindow = 10 * time.Minute
	probeConsecutiveErrorLimit = 3
	probeRepeatedToolCallLimit = 4
)

// intentTelemetry tracks zero-cost in-memory runtime health metrics for one
// running worker intent so the Supervisor board can flag stalls, error loops,
// and zero-output runs without scanning raw logs.
type intentTelemetry struct {
	mu                sync.Mutex
	taskID            string
	intentID          int64
	worker            string
	pinnedProfileID   int64
	startedAt         time.Time
	lastActAt         time.Time
	toolCalls         int
	toolErrors        int
	consecutiveErrors int
	lastToolSig       string
	repeatedToolCalls int
	factsWritten      int
	findingsWritten   int
}

// IntentTelemetrySnapshot is a lock-free point-in-time view exposed on the
// Supervisor board.
type IntentTelemetrySnapshot struct {
	TaskID            string   `json:"task_id"`
	IntentID          int64    `json:"intent_id"`
	Worker            string   `json:"worker"`
	PinnedProfileID   int64    `json:"pinned_profile_id,omitempty"`
	RunningSeconds    int64    `json:"running_seconds"`
	IdleSeconds       int64    `json:"idle_seconds"`
	ToolCalls         int      `json:"tool_calls"`
	ToolErrors        int      `json:"tool_errors"`
	ConsecutiveErrors int      `json:"consecutive_errors"`
	RepeatedToolCalls int      `json:"repeated_tool_calls"`
	FactsWritten      int      `json:"facts_written"`
	FindingsWritten   int      `json:"findings_written"`
	Alerts            []string `json:"alerts,omitempty"`
}

// intentPinnedProfileID extracts an optional Supervisor-assigned model profile
// id from an intent node's JSON payload. Returns 0 when absent or invalid.
func intentPinnedProfileID(intent *db.Node) int64 {
	if intent == nil || len(intent.Payload) == 0 {
		return 0
	}
	var p struct {
		PinnedProfileID json.RawMessage `json:"pinned_profile_id"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return 0
	}
	id := parseProfileID(p.PinnedProfileID)
	if id < 0 {
		return 0
	}
	return id
}

func (e *Engine) beginIntentTelemetry(taskID string, intentID int64, worker string, pinnedProfileID int64) *intentTelemetry {
	now := time.Now()
	tm := &intentTelemetry{
		taskID:          taskID,
		intentID:        intentID,
		worker:          worker,
		pinnedProfileID: pinnedProfileID,
		startedAt:       now,
		lastActAt:       now,
	}
	e.telemetry.Store(intentID, tm)
	return tm
}

func (e *Engine) endIntentTelemetry(intentID int64) {
	e.telemetry.Delete(intentID)
}

func (tm *intentTelemetry) observe(r db.Activity) {
	if tm == nil {
		return
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.lastActAt = time.Now()
	switch r.Kind {
	case "tool_use":
		tm.toolCalls++
		sig := strings.TrimSpace(r.Tool) + "|" + preview(strings.TrimSpace(r.Summary), 120)
		if sig != "|" && sig == tm.lastToolSig {
			tm.repeatedToolCalls++
		} else {
			tm.lastToolSig = sig
			tm.repeatedToolCalls = 1
		}
	case "tool_result":
		if r.IsError {
			tm.toolErrors++
			tm.consecutiveErrors++
		} else {
			tm.consecutiveErrors = 0
			switch r.Tool {
			case "record_fact":
				tm.factsWritten++
			case "report_finding":
				tm.findingsWritten++
			}
		}
	}
}

func (tm *intentTelemetry) snapshot(now time.Time) IntentTelemetrySnapshot {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	runDur := now.Sub(tm.startedAt)
	idleDur := now.Sub(tm.lastActAt)
	if runDur < 0 {
		runDur = 0
	}
	if idleDur < 0 {
		idleDur = 0
	}
	var alerts []string
	if idleDur >= probeIdleStallThreshold {
		alerts = append(alerts, "idle_stall")
	}
	if tm.consecutiveErrors >= probeConsecutiveErrorLimit {
		alerts = append(alerts, "consecutive_errors")
	}
	if tm.repeatedToolCalls >= probeRepeatedToolCallLimit {
		alerts = append(alerts, "repeated_tool_loop")
	}
	if runDur >= probeLongRunNoOutputWindow && tm.factsWritten == 0 && tm.findingsWritten == 0 {
		alerts = append(alerts, "long_run_no_output")
	}
	return IntentTelemetrySnapshot{
		TaskID:            tm.taskID,
		IntentID:          tm.intentID,
		Worker:            tm.worker,
		PinnedProfileID:   tm.pinnedProfileID,
		RunningSeconds:    int64(runDur.Seconds()),
		IdleSeconds:       int64(idleDur.Seconds()),
		ToolCalls:         tm.toolCalls,
		ToolErrors:        tm.toolErrors,
		ConsecutiveErrors: tm.consecutiveErrors,
		RepeatedToolCalls: tm.repeatedToolCalls,
		FactsWritten:      tm.factsWritten,
		FindingsWritten:   tm.findingsWritten,
		Alerts:            alerts,
	}
}

// RunningIntentTelemetry returns live health snapshots for all currently running
// intents belonging to taskID (or across all tasks when taskID == "").
func (e *Engine) RunningIntentTelemetry(taskID string) []IntentTelemetrySnapshot {
	now := time.Now()
	var out []IntentTelemetrySnapshot
	e.telemetry.Range(func(_, v any) bool {
		tm, ok := v.(*intentTelemetry)
		if !ok || tm == nil {
			return true
		}
		if taskID != "" && tm.taskID != taskID {
			return true
		}
		out = append(out, tm.snapshot(now))
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].IntentID < out[j].IntentID })
	return out
}

// resolveWorkerForIntent returns the pinned worker when an intent explicitly
// carries a Supervisor-assigned pinned_profile_id; otherwise it returns fallback.
func (e *Engine) resolveWorkerForIntent(t *Task, slotName string, intent *db.Node, fallback *agent.Worker) (*agent.Worker, int64) {
	pinnedID := intentPinnedProfileID(intent)
	if pinnedID <= 0 || e.workerResolve == nil {
		return fallback, pinnedID
	}
	pinnedWorker, err := e.workerResolve(t, WorkerSlot{Name: slotName, ProfileID: pinnedID})
	if err != nil || pinnedWorker == nil {
		iid := intent.ID
		msg := "指定模型配置不可用，已回退默认 Worker 模型"
		if err != nil {
			msg = msg + ": " + err.Error()
		}
		e.emitActivity(t, db.Activity{
			NodeID:  &iid,
			Worker:  slotName,
			Kind:    "text",
			IsError: true,
			Summary: msg,
			Detail:  msg,
		})
		return fallback, 0
	}
	return pinnedWorker, pinnedID
}
