package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const supervisorWorkerName = "chain_reviewer"

func toolErrorf(format string, args ...any) actool.Result {
	return actool.Errorf(fmt.Sprintf(format, args...))
}

// supervisorTools returns the native Go Supervisor toolset bound to
// chain_reviewer. It provides bounded situational awareness, drill-down
// inspection, stop-loss killing, model-tiered re-dispatch, hallucinated-fact
// retraction with cascade stopping, live worker steering, and asset-scoped
// note sharing — without exposing shell, file, or network tools.
func (s *Server) supervisorTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSupervisorBoard(),
		s.toolSupervisorInspect(),
		s.toolSupervisorKillIntent(),
		s.toolSupervisorDispatchIntent(),
		s.toolSupervisorRetractFact(),
		s.toolSupervisorSteerWorker(),
		s.toolSupervisorRecordAssetNote(),
	}
}

func supervisorToolNames() []string {
	return []string{
		"supervisor_board",
		"supervisor_inspect",
		"supervisor_kill_intent",
		"supervisor_dispatch_intent",
		"supervisor_retract_fact",
		"supervisor_steer_worker",
		"supervisor_record_asset_note",
	}
}

func parseIDSlice(raws []json.RawMessage) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(raws))
	for _, r := range raws {
		id := parseProfileID(r)
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func taskRunnableError(s *Server, t *Task) string {
	if t == nil {
		return "任务不存在"
	}
	if s.engine.IsDeleting(t.ID) {
		return "任务正在删除"
	}
	st := t.lifecycleSnapshot()
	switch {
	case st.Paused || s.engine.IsPaused(t.ID):
		return "任务已暂停"
	case st.Queued:
		return "任务正在排队"
	case isTerminalStatus(st.Status):
		return "任务已终态(" + st.Status + ")"
	case s.engine.isSettling(t.ID):
		return "任务正在收尾"
	}
	return ""
}

func (s *Server) stopOneIntent(t *Task, intentID int64) (prevState string, killedLive bool, err error) {
	node, err := t.Store.GetNode(intentID)
	if err != nil {
		return "", false, err
	}
	if node == nil || node.Kind != db.KindIntent {
		return "", false, fmt.Errorf("intent #%d 不存在", intentID)
	}
	prevState = node.State
	switch node.State {
	case "running":
		if killErr := s.engine.KillWork(intentID); killErr == nil {
			// Best-effort CAS so even a worker that just detached settles cleanly.
			_, _ = t.Store.CompareAndSetIntentState(intentID, "running", "stopped")
			return prevState, true, nil
		}
		// Stale DB running row with no live goroutine: settle directly to stopped.
		if _, err := t.Store.CompareAndSetIntentState(intentID, "running", "stopped"); err != nil {
			return prevState, false, err
		}
		return prevState, false, nil
	case "open", "paused":
		if _, err := t.Store.CompareAndSetIntentState(intentID, node.State, "stopped"); err != nil {
			return prevState, false, err
		}
		return prevState, false, nil
	default:
		return prevState, false, nil
	}
}

func payloadStringField(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func payloadInt64SliceField(raw json.RawMessage, key string) []int64 {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var arr []json.RawMessage
	if json.Unmarshal(m[key], &arr) != nil {
		return nil
	}
	return parseIDSlice(arr)
}

func (s *Server) toolSupervisorBoard() actool.CoreTool {
	return roTool("supervisor_board",
		"读取面向 Supervisor 的紧凑全局态势板：列出活跃任务的运行中意图（含空转/连错/重复循环探针告警、指定模型档位）、近期失败/耗尽意图、待核验或高影响事实、以及平台可用 LLM 模型档位（不含密钥）。可选传 task_id 聚焦单任务。",
		objSchema(map[string]any{
			"task_id": strParam("可选：聚焦指定任务 id；留空则聚合所有正在运行的任务（最多 8 个）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)

			var targets []*Task
			if tid := strings.TrimSpace(a.TaskID); tid != "" {
				t := s.m.ResolveTask(tid)
				if t == nil {
					return toolErrorf("任务不存在: %s", tid), nil
				}
				targets = []*Task{t}
			} else {
				for _, t := range s.m.List() {
					if taskRunnableError(s, t) != "" {
						continue
					}
					targets = append(targets, t)
					if len(targets) >= 8 {
						break
					}
				}
			}

			profilesOut := []map[string]any{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profilesOut = append(profilesOut, map[string]any{
						"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_default": p.IsDefault,
					})
				}
			}

			tasksOut := make([]map[string]any, 0, len(targets))
			for _, t := range targets {
				tasksOut = append(tasksOut, s.buildSupervisorTaskSummary(t))
			}
			return jsonResult(map[string]any{
				"llm_profiles": profilesOut,
				"tasks":        tasksOut,
			})
		})
}

func (s *Server) buildSupervisorTaskSummary(t *Task) map[string]any {
	desc, goal, _ := t.Store.Root()
	counts := map[string]int{}
	intents, _ := t.Store.ListByKind(db.KindIntent, 120)

	tmByIntent := map[int64]IntentTelemetrySnapshot{}
	for _, snap := range s.engine.RunningIntentTelemetry(t.ID) {
		tmByIntent[snap.IntentID] = snap
	}

	runningOut := []map[string]any{}
	recentFailed := []map[string]any{}
	for _, n := range intents {
		counts[n.State]++
		switch n.State {
		case "running":
			row := map[string]any{
				"intent_id": n.ID,
				"owner":     n.Owner,
				"priority":  n.Priority,
				"summary":   preview(payloadStringField(n.Payload, "summary"), 140),
			}
			if aids := payloadInt64SliceField(n.Payload, "asset_ids"); len(aids) > 0 {
				row["asset_ids"] = aids
			}
			if pid := intentPinnedProfileID(n); pid > 0 {
				row["pinned_profile_id"] = pid
			}
			if tm, ok := tmByIntent[n.ID]; ok {
				row["running_seconds"] = tm.RunningSeconds
				row["idle_seconds"] = tm.IdleSeconds
				row["tool_calls"] = tm.ToolCalls
				row["tool_errors"] = tm.ToolErrors
				row["consecutive_errors"] = tm.ConsecutiveErrors
				row["repeated_tool_calls"] = tm.RepeatedToolCalls
				row["facts_written"] = tm.FactsWritten
				if len(tm.Alerts) > 0 {
					row["alerts"] = tm.Alerts
				}
			}
			runningOut = append(runningOut, row)
		case "exhausted", "blocked":
			if len(recentFailed) < 6 {
				row := map[string]any{
					"intent_id": n.ID,
					"state":     n.State,
					"summary":   preview(payloadStringField(n.Payload, "summary"), 140),
				}
				if n.BlockedReason != "" {
					row["blocked_reason"] = n.BlockedReason
				}
				if pid := intentPinnedProfileID(n); pid > 0 {
					row["pinned_profile_id"] = pid
				}
				if aids := payloadInt64SliceField(n.Payload, "asset_ids"); len(aids) > 0 {
					row["asset_ids"] = aids
				}
				recentFailed = append(recentFailed, row)
			}
		}
	}

	facts, _ := t.Store.ListByKind(db.KindFact, 60)
	factIDs := make([]int64, 0, len(facts))
	for _, f := range facts {
		factIDs = append(factIDs, f.ID)
	}
	anchorsMap, _ := t.Store.NodeAnchors(factIDs)

	assetNotesCount := 0
	var watchFacts []map[string]any
	var normalFacts []map[string]any
	for _, f := range facts {
		if f.State == db.StateOrigin || f.State == db.StateFactRetracted {
			continue
		}
		var fp map[string]any
		_ = json.Unmarshal(f.Payload, &fp)
		isNote, _ := fp["asset_note"].(bool)
		if (isNote || f.Origin == "supervisor") && f.State == db.StateFactConfirmed {
			assetNotesCount++
		}
		row := map[string]any{
			"fact_id": f.ID,
			"state":   f.State,
			"summary": preview(payloadStringField(f.Payload, "summary"), 140),
		}
		if c, _ := fp["confidence"].(string); c != "" {
			row["confidence"] = c
		}
		if actID, ok := fp["evidence_activity_id"]; ok && actID != nil {
			row["evidence_activity_id"] = actID
		}
		if isNote {
			row["asset_note"] = true
		}
		if aids := anchorsMap[f.ID]; len(aids) > 0 {
			row["asset_ids"] = aids
		}
		if f.State == db.StateFactUnverified || f.State == db.StateFactDisputed {
			watchFacts = append(watchFacts, row)
		} else if len(normalFacts) < 8 {
			normalFacts = append(normalFacts, row)
		}
	}
	// Surface unverified/disputed facts first, then recent confirmed facts (cap 12).
	factsOut := append(watchFacts, normalFacts...)
	if len(factsOut) > 12 {
		factsOut = factsOut[:12]
	}

	goals, _ := t.Store.ListByKind(db.KindGoal, 10)
	openGoals := 0
	for _, g := range goals {
		if g.State == "open" {
			openGoals++
		}
	}

	return map[string]any{
		"task_id":            t.ID,
		"status":             s.deriveTaskStatus(t),
		"description":        preview(desc, 120),
		"goal":               preview(goal, 160),
		"open_goals":         openGoals,
		"intent_counts":      counts,
		"running_intents":    runningOut,
		"recent_failed":      recentFailed,
		"facts_to_watch":     factsOut,
		"asset_notes_count":  assetNotesCount,
	}
}

func (s *Server) toolSupervisorInspect() actool.CoreTool {
	return roTool("supervisor_inspect",
		"下钻核查指定任务里的意图执行轨迹(intent_id)、探索节点全文(node_id)或某条原始执行记录(activity_id)。在决定 kill 意图或撤回可疑 fact 之前，先用此工具核对原始证据。",
		objSchema(map[string]any{
			"task_id":     strParam("任务 id"),
			"intent_id":   map[string]any{"type": "integer", "description": "可选：查看该意图的最近执行步骤摘要"},
			"step_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：配合 intent_id 拉取最多 5 条步骤的截断原文"},
			"node_id":     map[string]any{"type": "integer", "description": "可选：查看某个 fact/intent/finding 节点的完整 payload、状态与关联边"},
			"activity_id": map[string]any{"type": "integer", "description": "可选：查看单条原始执行记录的截断原文"},
		}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID     string            `json:"task_id"`
				IntentID   json.RawMessage   `json:"intent_id"`
				StepIDs    []json.RawMessage `json:"step_ids"`
				NodeID     json.RawMessage   `json:"node_id"`
				ActivityID json.RawMessage   `json:"activity_id"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if t == nil {
				return toolErrorf("任务不存在: %s", a.TaskID), nil
			}
			out := map[string]any{"task_id": t.ID}
			if aid := parseProfileID(a.ActivityID); aid > 0 {
				act, err := t.Store.GetActivityWithDetail(aid)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if act == nil {
					return toolErrorf("activity #%d 不存在", aid), nil
				}
				out["activity"] = map[string]any{
					"id": act.ID, "node_id": act.NodeID, "worker": act.Worker,
					"kind": act.Kind, "tool": act.Tool, "is_error": act.IsError,
					"summary": preview(act.Summary, 300), "detail": preview(act.Detail, 3000),
					"created_at": act.CreatedAt,
				}
			}
			if nid := parseProfileID(a.NodeID); nid > 0 {
				node, err := t.Store.GetNode(nid)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if node == nil {
					return toolErrorf("node #%d 不存在", nid), nil
				}
				edges, _ := t.Store.EdgesTouching([]int64{nid})
				anchors, _ := t.Store.NodeAnchors([]int64{nid})
				var payload any
				_ = json.Unmarshal(node.Payload, &payload)
				out["node"] = map[string]any{
					"id": node.ID, "kind": node.Kind, "state": node.State,
					"origin": node.Origin, "owner": node.Owner,
					"asset_ids": anchors[nid], "payload": payload, "edges": edges,
				}
			}
			if iid := parseProfileID(a.IntentID); iid > 0 {
				trace, err := t.Store.ActivityTrace(iid, 16)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(trace))
				for _, act := range trace {
					steps = append(steps, map[string]any{
						"id": act.ID, "kind": act.Kind, "tool": act.Tool,
						"is_error": act.IsError, "summary": preview(act.Summary, 220),
						"created_at": act.CreatedAt,
					})
				}
				out["intent_trace"] = steps
				stepIDs := parseIDSlice(a.StepIDs)
				if len(stepIDs) > 5 {
					stepIDs = stepIDs[:5]
				}
				if len(stepIDs) > 0 {
					details := make([]map[string]any, 0, len(stepIDs))
					for _, sid := range stepIDs {
						if act, err := t.Store.GetActivityWithDetail(sid); err == nil && act != nil {
							details = append(details, map[string]any{
								"id": act.ID, "kind": act.Kind, "tool": act.Tool,
								"is_error": act.IsError, "summary": preview(act.Summary, 240),
								"detail": preview(act.Detail, 2400),
							})
						}
					}
					out["step_details"] = details
				}
			}
			if len(out) == 1 {
				return toolErrorf("请至少提供 intent_id、node_id 或 activity_id 之一"), nil
			}
			return jsonResult(out)
		})
}

func (s *Server) toolSupervisorKillIntent() actool.CoreTool {
	return wrTool("supervisor_kill_intent",
		"止损终止一条无意义、空转、死循环或方向错误的意图（running/open/paused → stopped）。终止前应先用 supervisor_inspect 核对执行轨迹。",
		objSchema(map[string]any{
			"task_id":   strParam("任务 id"),
			"intent_id": map[string]any{"type": "integer", "description": "要终止的意图 id"},
			"reason":    strParam("止损原因（会写入审计活动）"),
		}, "task_id", "intent_id", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID   string          `json:"task_id"`
				IntentID json.RawMessage `json:"intent_id"`
				Reason   string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if msg := taskRunnableError(s, t); msg != "" {
				return toolErrorf("无法终止意图：%s", msg), nil
			}
			iid := parseProfileID(a.IntentID)
			if iid <= 0 {
				return toolErrorf("intent_id 无效"), nil
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return toolErrorf("reason 不能为空"), nil
			}
			prev, killedLive, err := s.stopOneIntent(t, iid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if prev != "running" && prev != "open" && prev != "paused" {
				return jsonResult(map[string]any{
					"intent_id": iid, "previous_state": prev, "stopped": false,
					"note": "意图已处于终态，无需终止",
				})
			}
			nid := iid
			msg := fmt.Sprintf("Supervisor 止损终止意图 #%d（原状态 %s）：%s", iid, prev, reason)
			s.engine.emitActivity(t, db.Activity{
				NodeID: &nid, Worker: supervisorWorkerName, Kind: "text",
				Summary: preview(msg, 200), Detail: msg,
			})
			t.Notify()
			return jsonResult(map[string]any{
				"intent_id": iid, "previous_state": prev, "stopped": true, "killed_live": killedLive,
			})
		})
}

func (s *Server) toolSupervisorDispatchIntent() actool.CoreTool {
	return wrTool("supervisor_dispatch_intent",
		"由 Supervisor 派发或重派一条意图，并可指定 pinned_profile_id 实现主动模型分级（例如弱模型卡住时升档到强模型、同厂商死循环时换厂商破局、收尾阶段降回快模型）。可选传 replace_intent_id 一步完成“止损旧意图 + 重派新意图”。",
		objSchema(map[string]any{
			"task_id":           strParam("任务 id"),
			"summary":           strParam("新意图的清晰探索/验证指令"),
			"reason":            strParam("调度或换模型决策依据"),
			"asset_ids":         map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：目标资产 id 列表"},
			"parent_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：上游 fact/finding 节点 id 列表（禁止引用 retracted 事实）"},
			"priority":          map[string]any{"type": "integer", "description": "可选：优先级 0-10，默认 7"},
			"pinned_profile_id": map[string]any{"type": "integer", "description": "可选：指定执行该意图的 LLM profile id（来自 supervisor_board.llm_profiles）；0 或省略则使用默认档位"},
			"replace_intent_id": map[string]any{"type": "integer", "description": "可选：先终止该旧意图，再派发本新意图"},
		}, "task_id", "summary", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID          string            `json:"task_id"`
				Summary         string            `json:"summary"`
				Reason          string            `json:"reason"`
				AssetIDs        []json.RawMessage `json:"asset_ids"`
				ParentIDs       []json.RawMessage `json:"parent_ids"`
				Priority        int               `json:"priority"`
				PinnedProfileID json.RawMessage   `json:"pinned_profile_id"`
				ReplaceIntentID json.RawMessage   `json:"replace_intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if msg := taskRunnableError(s, t); msg != "" {
				return toolErrorf("无法派发意图：%s", msg), nil
			}
			summary := strings.TrimSpace(a.Summary)
			reason := strings.TrimSpace(a.Reason)
			if summary == "" || reason == "" {
				return toolErrorf("summary 和 reason 均不能为空"), nil
			}
			pinnedID := parseProfileID(a.PinnedProfileID)
			var pinnedModel string
			if pinnedID > 0 {
				_, cfg, ok := s.providerForProfile(pinnedID)
				if !ok {
					return toolErrorf("pinned_profile_id #%d 不存在或配置无效", pinnedID), nil
				}
				pinnedModel = cfg.Model
			}

			anchors := parseIDSlice(a.AssetIDs)
			taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
			if s.m.assets != nil && taskIDInt > 0 && len(anchors) > 0 {
				visible, err := s.m.assets.GetByIDsInScope(taskIDInt, anchors)
				if err != nil {
					return toolErrorf("资产可见范围校验失败：%v", err), nil
				}
				if len(visible) != len(anchors) {
					return toolErrorf("目标资产不属于本任务可见范围"), nil
				}
				hits, err := s.m.assets.CheckAssetsIntercept(taskIDInt, anchors)
				if err != nil {
					return toolErrorf("资产拦截校验失败：%v", err), nil
				}
				if len(hits) > 0 {
					return toolErrorf("目标资产命中资产拦截规则，禁止派发"), nil
				}
			}

			parents := parseIDSlice(a.ParentIDs)
			for _, pidv := range parents {
				n, err := t.Store.GetNodeWithSources(pidv)
				if err != nil || n == nil {
					return toolErrorf("parent_id #%d 不存在", pidv), nil
				}
				if n.Kind != db.KindFact && n.Kind != db.KindFinding {
					return toolErrorf("parent_id #%d 是 %q 节点，只能锚在 fact/finding 上", pidv, n.Kind), nil
				}
				if n.Kind == db.KindFact && n.State == db.StateFactRetracted {
					return toolErrorf("parent_id #%d 已被撤回(retracted)，不能作为新意图锚点", pidv), nil
				}
			}
			if len(parents) == 0 {
				if origin, _ := t.Store.OriginFactID(); origin > 0 {
					parents = []int64{origin}
				}
			}

			replaceID := parseProfileID(a.ReplaceIntentID)
			var replacedPrev string
			if replaceID > 0 {
				prev, _, err := s.stopOneIntent(t, replaceID)
				if err != nil {
					return toolErrorf("终止待替换意图 #%d 失败：%v", replaceID, err), nil
				}
				replacedPrev = prev
			}

			priority := a.Priority
			if priority <= 0 {
				priority = 7
			}
			if priority > 10 {
				priority = 10
			}
			payload := map[string]any{
				"summary":           summary,
				"supervisor_reason": reason,
			}
			if len(anchors) > 0 {
				payload["asset_ids"] = anchors
			}
			if pinnedID > 0 {
				payload["pinned_profile_id"] = pinnedID
				if pinnedModel != "" {
					payload["pinned_model"] = pinnedModel
				}
			}
			if replaceID > 0 {
				payload["replaced_intent_id"] = replaceID
			}
			id, err := t.Store.AddIntentWithParentsContext(ctx, payload, priority, anchors, parents, "supervisor")
			if err != nil {
				return toolErrorf("创建意图失败：%v", err), nil
			}
			nid := id
			actMsg := fmt.Sprintf("Supervisor 派发意图 #%d (priority=%d", id, priority)
			if pinnedID > 0 {
				actMsg += fmt.Sprintf(", pinned_profile=#%d %s", pinnedID, pinnedModel)
			}
			if replaceID > 0 {
				actMsg += fmt.Sprintf(", 替换 #%d", replaceID)
			}
			actMsg += ")：" + reason
			s.engine.emitActivity(t, db.Activity{
				NodeID: &nid, Worker: supervisorWorkerName, Kind: "text",
				Summary: preview(actMsg, 200), Detail: actMsg + "\n意图内容：" + summary,
			})
			t.Notify()
			res := map[string]any{
				"intent_id":         id,
				"priority":          priority,
				"pinned_profile_id": pinnedID,
				"pinned_model":      pinnedModel,
			}
			if replaceID > 0 {
				res["replaced_intent_id"] = replaceID
				res["replaced_previous_state"] = replacedPrev
			}
			return jsonResult(res)
		})
}

func (s *Server) toolSupervisorRetractFact() actool.CoreTool {
	return wrTool("supervisor_retract_fact",
		"将核查确认为幻觉、假阳性（如 HTTP 200 拦截页/SPA 回退页误判）或已失效的 fact 标为 retracted 或 disputed，保留历史审计，并默认级联终止所有依赖该 fact 的 open/running/paused 下游意图。",
		objSchema(map[string]any{
			"task_id":              strParam("任务 id"),
			"fact_id":              map[string]any{"type": "integer", "description": "要撤回或质疑的 fact 节点 id"},
			"state":                map[string]any{"type": "string", "enum": []string{db.StateFactRetracted, db.StateFactDisputed}, "description": "默认 retracted；存疑待补证填 disputed"},
			"reason":               strParam("撤回/质疑的明确技术依据"),
			"evidence_activity_id": map[string]any{"type": "integer", "description": "可选：支撑本判定的真实执行记录 id"},
			"cascade_stop_intents": map[string]any{"type": "boolean", "description": "默认 true：自动终止所有依赖该 fact 的 open/running/paused 下游意图"},
		}, "task_id", "fact_id", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID             string          `json:"task_id"`
				FactID             json.RawMessage `json:"fact_id"`
				State              string          `json:"state"`
				Reason             string          `json:"reason"`
				EvidenceActivityID json.RawMessage `json:"evidence_activity_id"`
				CascadeStopIntents *bool           `json:"cascade_stop_intents"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if msg := taskRunnableError(s, t); msg != "" {
				return toolErrorf("无法撤回事实：%s", msg), nil
			}
			fid := parseProfileID(a.FactID)
			if fid <= 0 {
				return toolErrorf("fact_id 无效"), nil
			}
			state := strings.TrimSpace(a.State)
			if state == "" {
				state = db.StateFactRetracted
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return toolErrorf("reason 不能为空"), nil
			}
			evID := parseProfileID(a.EvidenceActivityID)
			if evID > 0 {
				act, err := t.Store.VerifyActivityBelongsToExploration(evID)
				if err != nil {
					return toolErrorf("校验 evidence_activity_id 失败：%v", err), nil
				}
				if act == nil {
					return toolErrorf("evidence_activity_id #%d 不存在于本任务", evID), nil
				}
			}

			updated, err := t.Store.RetractFact(fid, state, reason, "supervisor", evID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			cascade := a.CascadeStopIntents == nil || *a.CascadeStopIntents
			var stoppedIDs []int64
			if cascade {
				deps, err := t.Store.DependentActiveIntents(fid)
				if err == nil {
					for _, dep := range deps {
						prev, _, stopErr := s.stopOneIntent(t, dep.ID)
						if stopErr == nil && (prev == "running" || prev == "open" || prev == "paused") {
							stoppedIDs = append(stoppedIDs, dep.ID)
						}
					}
				}
			}
			sort.Slice(stoppedIDs, func(i, j int) bool { return stoppedIDs[i] < stoppedIDs[j] })

			nid := fid
			msg := fmt.Sprintf("Supervisor 将事实 #%d 标记为 %s（级联止损意图 %d 条）：%s", fid, updated.State, len(stoppedIDs), reason)
			s.engine.emitActivity(t, db.Activity{
				NodeID: &nid, Worker: supervisorWorkerName, Kind: "text",
				Summary: preview(msg, 200), Detail: msg,
			})
			t.NotifyHint([]string{msg})
			return jsonResult(map[string]any{
				"fact_id":            fid,
				"state":              updated.State,
				"stopped_intent_ids": stoppedIDs,
			})
		})
}

func (s *Server) toolSupervisorSteerWorker() actool.CoreTool {
	return wrTool("supervisor_steer_worker",
		"向正在运行的 Worker 实时注入情报或纠偏指令（不中断、不丢上下文，在下一步工具调用前生效）。适用于同任务情报搬运（例如把刚确认的 WAF 绕过/鉴权特征同步给正在撞墙的另一个 Worker）。可选同时落盘为同资产共享备注。",
		objSchema(map[string]any{
			"task_id":         strParam("任务 id"),
			"intent_id":       map[string]any{"type": "integer", "description": "正在运行的意图 id"},
			"message":         strParam("要实时注入的情报或纠偏指令"),
			"also_asset_note": map[string]any{"type": "boolean", "description": "可选：若为 true，同时将本条情报存为同资产共享备注，供后续新 Worker 自动继承"},
			"asset_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：also_asset_note=true 时锚定的资产 id；省略时自动继承该意图的 asset_ids"},
		}, "task_id", "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        string            `json:"task_id"`
				IntentID      json.RawMessage   `json:"intent_id"`
				Message       string            `json:"message"`
				AlsoAssetNote bool              `json:"also_asset_note"`
				AssetIDs      []json.RawMessage `json:"asset_ids"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if msg := taskRunnableError(s, t); msg != "" {
				return toolErrorf("无法注入情报：%s", msg), nil
			}
			iid := parseProfileID(a.IntentID)
			if iid <= 0 {
				return toolErrorf("intent_id 无效"), nil
			}
			message := strings.TrimSpace(a.Message)
			if message == "" {
				return toolErrorf("message 不能为空"), nil
			}
			node, err := t.Store.GetNode(iid)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return toolErrorf("意图 #%d 不存在", iid), nil
			}
			if err := s.engine.SteerWork(iid, "[Supervisor 实时情报/纠偏] "+message); err != nil {
				return toolErrorf("实时注入失败（可能意图当前未在运行）：%v", err), nil
			}
			nid := iid
			s.engine.emitActivity(t, db.Activity{
				NodeID: &nid, Worker: supervisorWorkerName, Kind: "text",
				Summary: preview("Supervisor 向运行中意图 #"+strconv.FormatInt(iid, 10)+" 注入情报："+message, 200),
				Detail:  message,
			})
			res := map[string]any{"intent_id": iid, "steered": true}
			if a.AlsoAssetNote {
				aids := parseIDSlice(a.AssetIDs)
				if len(aids) == 0 {
					aids = payloadInt64SliceField(node.Payload, "asset_ids")
				}
				if len(aids) > 0 {
					noteID, noteErr := t.Store.AddNode(db.KindFact, map[string]any{
						"summary":    preview(message, 180),
						"detail":     message,
						"asset_note": true,
						"confidence": "observed",
					}, 6, db.StateFactConfirmed, "supervisor", aids)
					if noteErr == nil {
						res["asset_note_id"] = noteID
						res["asset_ids"] = aids
					}
				}
			}
			return jsonResult(res)
		})
}

func (s *Server) toolSupervisorRecordAssetNote() actool.CoreTool {
	return wrTool("supervisor_record_asset_note",
		"在探索图中登记一条同资产实时共享备注（如确认的 WAF 特征、HTTP 200 软报错规则、真实鉴权方式或绕过要点）。后续任何新 Worker 领取锚定到这些资产的意图时，程序会自动将其注入系统提示，无需模型主动检索。",
		objSchema(map[string]any{
			"task_id":              strParam("任务 id"),
			"asset_ids":            map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "integer"}, "description": "必填：该备注适用的资产 id 列表"},
			"summary":              strParam("简短明确的资产特征/避坑要点（一句话）"),
			"detail":               strParam("可选：补充细节或关键响应特征"),
			"evidence_activity_id": map[string]any{"type": "integer", "description": "可选：支撑该备注的真实执行记录 id"},
		}, "task_id", "asset_ids", "summary"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID             string            `json:"task_id"`
				AssetIDs           []json.RawMessage `json:"asset_ids"`
				Summary            string            `json:"summary"`
				Detail             string            `json:"detail"`
				EvidenceActivityID json.RawMessage   `json:"evidence_activity_id"`
			}
			_ = json.Unmarshal(in, &a)
			t := s.m.ResolveTask(strings.TrimSpace(a.TaskID))
			if msg := taskRunnableError(s, t); msg != "" {
				return toolErrorf("无法登记资产备注：%s", msg), nil
			}
			aids := parseIDSlice(a.AssetIDs)
			if len(aids) == 0 {
				return toolErrorf("asset_ids 不能为空"), nil
			}
			summary := strings.TrimSpace(a.Summary)
			if summary == "" {
				return toolErrorf("summary 不能为空"), nil
			}
			taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
			if s.m.assets != nil && taskIDInt > 0 {
				visible, err := s.m.assets.GetByIDsInScope(taskIDInt, aids)
				if err != nil {
					return toolErrorf("资产范围校验失败：%v", err), nil
				}
				if len(visible) != len(aids) {
					return toolErrorf("部分 asset_ids 不属于本任务可见范围"), nil
				}
			}
			evID := parseProfileID(a.EvidenceActivityID)
			if evID > 0 {
				act, err := t.Store.VerifyActivityBelongsToExploration(evID)
				if err != nil {
					return toolErrorf("校验 evidence_activity_id 失败：%v", err), nil
				}
				if act == nil {
					return toolErrorf("evidence_activity_id #%d 不存在于本任务", evID), nil
				}
			}
			payload := map[string]any{
				"summary":    summary,
				"asset_note": true,
				"confidence": "observed",
			}
			if d := strings.TrimSpace(a.Detail); d != "" {
				payload["detail"] = d
			}
			if evID > 0 {
				payload["evidence_activity_id"] = evID
			}
			id, err := t.Store.AddNode(db.KindFact, payload, 6, db.StateFactConfirmed, "supervisor", aids)
			if err != nil {
				return toolErrorf("保存资产备注失败：%v", err), nil
			}
			nid := id
			s.engine.emitActivity(t, db.Activity{
				NodeID: &nid, Worker: supervisorWorkerName, Kind: "text",
				Summary: preview("Supervisor 登记资产共享备注 #"+strconv.FormatInt(id, 10)+"："+summary, 200),
				Detail:  summary + "\n" + strings.TrimSpace(a.Detail),
			})
			return jsonResult(map[string]any{
				"note_id":   id,
				"asset_ids": aids,
			})
		})
}
