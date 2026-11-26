package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// Zero-policy Watchdog layer: owns purely mechanical liveness and recovery
// (stuck/looping worker nudges & recycles, zombie running-intent sweeps,
// quota-blocked intent auto-reopening, same-family key rotation, and planner
// transient-error retry backoff) so the Planner stays focused strictly on
// offensive/defensive tactics.
const (
	watchdogDefaultTick          = 30 * time.Second
	watchdogSoftIdleThreshold    = 5 * time.Minute
	watchdogHardIdleThreshold    = 10 * time.Minute
	watchdogHardLoopThreshold    = 10
	watchdogHardErrorThreshold   = 10
	watchdogPostNudgeGrace       = 90 * time.Second
	watchdogMaxRestartsPerIntent = 2
	watchdogQuotaReopenCooldown  = 60 * time.Second
)

var plannerErrorRetryBackoffs = []time.Duration{
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

func watchdogPlannerBackoff(consecutiveErrs int, normalInterval time.Duration) (time.Duration, bool) {
	if consecutiveErrs <= 0 || consecutiveErrs > len(plannerErrorRetryBackoffs) {
		return 0, false
	}
	d := plannerErrorRetryBackoffs[consecutiveErrs-1]
	if normalInterval > 0 && d > normalInterval {
		d = normalInterval
	}
	return d, true
}

func (e *Engine) watchdogTickDuration() time.Duration {
	if e.watchdogInterval > 0 {
		return e.watchdogInterval
	}
	return watchdogDefaultTick
}

func (e *Engine) bumpWatchdogRestart(intentID int64) int {
	for {
		cur, loaded := e.watchdogRestarts.LoadOrStore(intentID, 1)
		if !loaded {
			return 1
		}
		n := cur.(int)
		if e.watchdogRestarts.CompareAndSwap(intentID, n, n+1) {
			return n + 1
		}
	}
}

func (e *Engine) recycleWork(intentID int64) bool {
	e.workMu.Lock()
	run := e.work[intentID]
	e.workMu.Unlock()
	if run == nil {
		return false
	}
	run.cancel(agent.AbortWatchdogRecycle)
	return true
}

func (e *Engine) watchdogLoop(ctx context.Context, t *Task) {
	ticker := time.NewTicker(e.watchdogTickDuration())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			e.watchdogTick(t, now)
		}
	}
}

// watchdogTick performs one zero-policy health & recovery sweep for task t.
// Returns (nudged, recycled, reopenedQuota) for deterministic testing and logs.
func (e *Engine) watchdogTick(t *Task, now time.Time) (nudged, recycled, reopenedQuota int) {
	if t == nil || e.IsPaused(t.ID) || e.IsDeleting(t.ID) || e.isSettling(t.ID) {
		return 0, 0, 0
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		return 0, 0, 0
	}

	// 1. Periodic zombie running-intent sweep (works even while all workers are busy).
	e.reconcileZombieIntentsThrottled(t)

	// 2. Live worker liveness / loop self-heal (nudge once → hard recycle if still wedged).
	e.telemetry.Range(func(_, v any) bool {
		tm, ok := v.(*intentTelemetry)
		if !ok || tm == nil || tm.taskID != t.ID {
			return true
		}
		tm.mu.Lock()
		idleDur := now.Sub(tm.lastActAt)
		runDur := now.Sub(tm.startedAt)
		consecErrs := tm.consecutiveErrors
		repeats := tm.repeatedToolCalls
		alreadyNudged := tm.watchdogNudged
		nudgedAt := tm.watchdogNudgedAt
		intentID := tm.intentID
		tm.mu.Unlock()

		// Stage 2: Hard recycle on deep silence (>=10m) or unbreakable loop/errors post-nudge.
		hardIdle := idleDur >= watchdogHardIdleThreshold
		hardLoop := alreadyNudged && now.Sub(nudgedAt) >= watchdogPostNudgeGrace &&
			(repeats >= watchdogHardLoopThreshold || consecErrs >= watchdogHardErrorThreshold)
		if hardIdle || hardLoop {
			if e.recycleWork(intentID) {
				recycled++
			}
			return true
		}

		// Stage 1: Single zero-policy mechanical nudge before ever escalating or recycling.
		var reason string
		switch {
		case repeats >= probeRepeatedToolCallLimit:
			reason = fmt.Sprintf("检测到连续 %d 次完全相同的工具调用", repeats)
		case consecErrs >= probeHardConsecutiveErrCap && runDur >= probeMinWakeAgeForErrors:
			reason = fmt.Sprintf("检测到连续 %d 次非瞬时工具报错", consecErrs)
		case idleDur >= watchdogSoftIdleThreshold:
			reason = fmt.Sprintf("检测到已静默 %d 秒无新工具产出", int(idleDur.Seconds()))
		}
		if reason != "" && !alreadyNudged {
			tm.mu.Lock()
			if !tm.watchdogNudged {
				tm.watchdogNudged = true
				tm.watchdogNudgedAt = now
				alreadyNudged = false
			} else {
				alreadyNudged = true
			}
			tm.mu.Unlock()
			if !alreadyNudged {
				msg := "[Watchdog] " + reason + "。请检查上一步输出或报错，更换命令/参数或直接记录当前事实后收尾，避免原地空转。"
				if err := e.SteerWork(intentID, msg); err == nil {
					nudged++
					if t.Store != nil {
						iid := intentID
						e.emitActivity(t, db.Activity{
							NodeID:  &iid,
							Worker:  "watchdog",
							Kind:    "text",
							Summary: "[Watchdog] " + reason + "，已自动注入机械纠偏（未打扰规划者）",
							Detail:  msg,
						})
					}
				}
			}
		}
		return true
	})

	// 3. Auto-reopen llm_quota-blocked intents once provider health recovers.
	if t.Store != nil && e.ReadyFor(t) {
		if last, ok := e.lastQuotaReopen.Load(t.ID); !ok || now.Sub(last.(time.Time)) >= watchdogQuotaReopenCooldown {
			e.lastQuotaReopen.Store(t.ID, now)
			if n, err := t.Store.ReopenIntentsByBlockedReason(db.IntentBlockedLLMQuota); err == nil && n > 0 {
				reopenedQuota = int(n)
				msg := fmt.Sprintf("[Watchdog] LLM 配额/链路已恢复，自动重开 %d 条被限流阻塞的意图", n)
				log.Printf("[watchdog] task %s %s", t.ID, msg)
				e.emitActivity(t, db.Activity{Worker: "watchdog", Kind: "text", Summary: msg, Detail: msg})
			}
		}
	}
	return nudged, recycled, reopenedQuota
}

// sameFamilyHealthyProfile returns a healthy backup profile in the same model
// family (exact model match first, then same family prefix) when pinnedID is
// currently circuit-broken in s.llmHealth. Returns (0, "") when pinnedID is
// healthy or no same-family replacement exists.
func (s *Server) sameFamilyHealthyProfile(pinnedID int64) (int64, string) {
	if s == nil || s.m == nil || s.m.pg == nil || s.llmHealth == nil || pinnedID <= 0 {
		return 0, ""
	}
	if !s.llmHealth.IsOpen(pinnedID) {
		return 0, ""
	}
	target, err := s.m.pg.ProfileByID(pinnedID)
	if err != nil || target == nil {
		return 0, ""
	}
	all, err := s.m.pg.ListProfiles()
	if err != nil {
		return 0, ""
	}
	return selectSameFamilyHealthy(target, all, s.llmHealth.IsOpen)
}

func selectSameFamilyHealthy(target *db.LLMProfile, candidates []*db.LLMProfile, isTripped func(int64) bool) (int64, string) {
	if target == nil {
		return 0, ""
	}
	wantModel := strings.ToLower(strings.TrimSpace(target.Model))
	wantFam := modelFamilyPrefix(wantModel)
	if wantModel == "" {
		return 0, ""
	}
	var familyMatch *db.LLMProfile
	for _, p := range candidates {
		if p == nil || p.ID == target.ID || p.PoolExclude || p.Format == "jev" || strings.TrimSpace(p.APIKey) == "" {
			continue
		}
		if isTripped != nil && isTripped(p.ID) {
			continue
		}
		m := strings.ToLower(strings.TrimSpace(p.Model))
		if m == wantModel {
			return p.ID, p.Name + "/" + p.Model
		}
		if familyMatch == nil && wantFam != "" && modelFamilyPrefix(m) == wantFam {
			familyMatch = p
		}
	}
	if familyMatch != nil {
		return familyMatch.ID, familyMatch.Name + "/" + familyMatch.Model
	}
	return 0, ""
}

// modelFamilyPrefix extracts the model family key (e.g. "glm-5" from "glm-5.3",
// "deepseek-v4" from "deepseek-v4.1-flash", "claude-sonnet" from "claude-sonnet-4-6")
// so key rotation prefers same-family backup keys before crossing vendors.
func modelFamilyPrefix(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" {
		return ""
	}
	// Strip optional provider prefix like "openai/gpt-5".
	if idx := strings.LastIndex(model, "/"); idx >= 0 && idx+1 < len(model) {
		model = model[idx+1:]
	}
	parts := strings.Split(model, "-")
	if len(parts) == 1 {
		return parts[0]
	}
	second := parts[1]
	if dot := strings.IndexByte(second, '.'); dot > 0 {
		second = second[:dot]
	}
	return parts[0] + "-" + second
}
