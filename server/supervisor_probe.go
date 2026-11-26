package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const (
	probeIdleStallThreshold     = 5 * time.Minute
	probeLongRunNoOutputWindow  = 10 * time.Minute
	probeSoftErrorStreakLimit   = 3                // passive indicator on overview only (does not wake Planner)
	probeHardConsecutiveErrCap  = 5                // active NotifyProbeAlert wakeup threshold
	probeRepeatedToolCallLimit  = 5                // exact full-payload SHA-256 repeat threshold
	probeMinWakeAgeForErrors    = 90 * time.Second // ignore early startup command-typo bursts
	probeAlertWakeCooldown      = 3 * time.Minute
)

// intentTelemetry tracks zero-cost in-memory runtime health metrics for one
// running worker intent so the Task Commander (Planner) and Supervisor board
// can flag stalls, error loops, and zero-output runs without scanning raw logs.
type intentTelemetry struct {
	mu                sync.Mutex
	taskID            string
	intentID          int64
	worker            string
	pinnedProfileID   int64
	startedAt         time.Time
	lastActAt         time.Time
	lastAlertAt       time.Time
	toolCalls         int
	toolErrors        int
	consecutiveErrors int
	lastToolHash      string
	repeatedToolCalls int
	factsWritten      int
	findingsWritten   int
	watchdogNudged    bool
	watchdogNudgedAt  time.Time
}

// IntentTelemetrySnapshot is a lock-free point-in-time view exposed on the
// Supervisor board and Planner overview.
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

// intentPinnedProfileID extracts an optional Commander/Supervisor-assigned model
// profile id from an intent node's JSON payload. Returns 0 when absent or invalid.
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

// toolCallFingerprint hashes the full tool name, summary, and detail so long
// commands sharing a common header/JWT prefix never collide as false repeats.
func toolCallFingerprint(tool, summary, detail string) string {
	tool = strings.TrimSpace(tool)
	summary = strings.TrimSpace(summary)
	detail = strings.TrimSpace(detail)
	if tool == "" && summary == "" && detail == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tool + "\x00" + summary + "\x00" + detail))
	return hex.EncodeToString(sum[:12])
}

// isTransientOrBenignToolError filters out temporary network/rate-limit jitter
// and benign grep exit-1 no-match errors so they don't trip error-streak alarms.
func isTransientOrBenignToolError(tool, summary, detail string) bool {
	text := strings.ToLower(summary + " " + detail)
	transientMarkers := []string{
		"502 bad gateway", "503 service unavailable", "504 gateway timeout",
		"429 too many requests", "rate limit", "connection reset by peer",
		"tls handshake timeout", "i/o timeout", "temporary failure in name resolution",
		"eof", "context deadline exceeded",
	}
	for _, m := range transientMarkers {
		if strings.Contains(text, m) {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(tool), "Bash") &&
		strings.Contains(text, "exit status 1") &&
		(strings.Contains(text, "grep ") || strings.Contains(text, "rg ")) {
		return true
	}
	return false
}

// observe updates in-memory telemetry for one emitted activity and returns
// immediate high-confidence anomaly alerts (rate-limited by probeAlertWakeCooldown)
// when the Task Commander should be woken proactively.
func (tm *intentTelemetry) observe(r db.Activity) (alerts []string, detail string) {
	if tm == nil {
		return nil, ""
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	now := time.Now()
	tm.lastActAt = now
	switch r.Kind {
	case "tool_use":
		tm.toolCalls++
		hash := toolCallFingerprint(r.Tool, r.Summary, r.Detail)
		if hash != "" && hash == tm.lastToolHash {
			tm.repeatedToolCalls++
		} else {
			tm.lastToolHash = hash
			tm.repeatedToolCalls = 1
		}
	case "tool_result":
		if r.IsError {
			tm.toolErrors++
			if !isTransientOrBenignToolError(r.Tool, r.Summary, r.Detail) {
				tm.consecutiveErrors++
			}
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
	// Tiered active wakeup:
	// 1) Exact identical tool call repeated >= 5 times (guaranteed real loop).
	// 2) >= 5 consecutive non-transient errors after the initial warmup window.
	if tm.repeatedToolCalls >= probeRepeatedToolCallLimit {
		alerts = append(alerts, "repeated_tool_loop")
	}
	if tm.consecutiveErrors >= probeHardConsecutiveErrCap && now.Sub(tm.startedAt) >= probeMinWakeAgeForErrors {
		alerts = append(alerts, "consecutive_errors")
	}
	if len(alerts) == 0 {
		return nil, ""
	}
	if !tm.lastAlertAt.IsZero() && now.Sub(tm.lastAlertAt) < probeAlertWakeCooldown {
		return nil, ""
	}
	tm.lastAlertAt = now
	detail = preview(strings.TrimSpace(r.Tool+" "+r.Summary), 120)
	return alerts, detail
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
	if tm.consecutiveErrors >= probeHardConsecutiveErrCap {
		alerts = append(alerts, "consecutive_errors")
	} else if tm.consecutiveErrors >= probeSoftErrorStreakLimit {
		alerts = append(alerts, "error_streak")
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

// RunningIntentTelemetryForPlanner converts live engine snapshots into the
// agent-layer representation consumed by the unified Task Commander.
func (e *Engine) RunningIntentTelemetryForPlanner(taskID string) []agent.IntentTelemetryInfo {
	snaps := e.RunningIntentTelemetry(taskID)
	out := make([]agent.IntentTelemetryInfo, len(snaps))
	for i, s := range snaps {
		out[i] = agent.IntentTelemetryInfo{
			IntentID:          s.IntentID,
			Worker:            s.Worker,
			PinnedProfileID:   s.PinnedProfileID,
			RunningSeconds:    s.RunningSeconds,
			IdleSeconds:       s.IdleSeconds,
			ToolCalls:         s.ToolCalls,
			ToolErrors:        s.ToolErrors,
			ConsecutiveErrors: s.ConsecutiveErrors,
			RepeatedToolCalls: s.RepeatedToolCalls,
			FactsWritten:      s.FactsWritten,
			FindingsWritten:   s.FindingsWritten,
			Alerts:            s.Alerts,
		}
	}
	return out
}

// resolveWorkerForIntent returns the pinned worker when an intent explicitly
// carries a Supervisor/Commander-assigned pinned_profile_id; otherwise fallback.
// When the pinned profile is currently circuit-broken, Watchdog transparently
// rotates to a healthy same-model / same-family profile before falling back.
func (e *Engine) resolveWorkerForIntent(t *Task, slotName string, intent *db.Node, fallback *agent.Worker) (*agent.Worker, int64) {
	pinnedID := intentPinnedProfileID(intent)
	if pinnedID <= 0 || e.workerResolve == nil {
		return fallback, pinnedID
	}
	effectiveID := pinnedID
	if e.sameFamilyRotate != nil {
		if altID, altLabel := e.sameFamilyRotate(pinnedID); altID > 0 && altID != pinnedID {
			effectiveID = altID
			iid := intent.ID
			msg := fmt.Sprintf("[Watchdog] 意图 #%d 指定的配置 #%d 正在熔断冷却，已自动同家族轮换至 #%d (%s)", iid, pinnedID, altID, altLabel)
			log.Printf("[watchdog] task %s %s", t.ID, msg)
			e.emitActivity(t, db.Activity{
				NodeID:  &iid,
				Worker:  "watchdog",
				Kind:    "text",
				Summary: msg,
				Detail:  msg,
			})
		}
	}
	pinnedWorker, err := e.workerResolve(t, WorkerSlot{Name: slotName, ProfileID: effectiveID})
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
	return pinnedWorker, effectiveID
}
