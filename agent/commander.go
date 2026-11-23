package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// PlannerLLMProfile is the secret-free model profile metadata exposed to the
// unified Task Commander (Planner) for active model tiering.
type PlannerLLMProfile struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Model     string `json:"model"`
	Format    string `json:"format"`
	IsDefault bool   `json:"is_default,omitempty"`
}

// IntentTelemetryInfo carries live zero-cost runtime health metrics for a
// running worker intent into the Planner's graph overview.
type IntentTelemetryInfo struct {
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

func (t *ToolSet) retractFactTool() actool.CoreTool {
	return t.writeExpTool("retract_fact",
		"将核查确认为幻觉、假阳性（如 HTTP 200 拦截页/SPA 回退页误判）或已失效的 fact 标为 retracted 或 disputed（保留审计不物理删除），并默认级联终止所有依赖该 fact 的 open/running/paused 下游意图。调用前请先用 node_detail 或 get_worker_trace 核实原始证据。",
		obj(map[string]any{
			"fact_id":              idp("要撤回或质疑的 fact 节点 id"),
			"state":                map[string]any{"type": "string", "enum": []string{db.StateFactRetracted, db.StateFactDisputed}, "description": "默认 retracted；存疑待补证填 disputed"},
			"reason":               str("撤回或质疑的明确技术依据"),
			"evidence_activity_id": idp("可选：支撑本判定的真实执行记录 id"),
			"cascade_stop_intents": map[string]any{"type": "boolean", "description": "默认 true：自动终止所有依赖该 fact 的 open/running/paused 下游意图"},
		}, "fact_id", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FactID             json.RawMessage `json:"fact_id"`
				State              string          `json:"state"`
				Reason             string          `json:"reason"`
				EvidenceActivityID json.RawMessage `json:"evidence_activity_id"`
				CascadeStopIntents *bool           `json:"cascade_stop_intents"`
			}
			_ = json.Unmarshal(in, &a)
			fid := pid(a.FactID)
			if fid <= 0 {
				return actool.Errorf("fact_id 必填"), nil
			}
			state := strings.TrimSpace(a.State)
			if state == "" {
				state = db.StateFactRetracted
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("reason 不能为空"), nil
			}
			evID := pid(a.EvidenceActivityID)
			if evID > 0 {
				act, err := t.ts.VerifyActivityBelongsToExploration(evID)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("校验 evidence_activity_id 失败: %v", err)), nil
				}
				if act == nil {
					return actool.Errorf(fmt.Sprintf("evidence_activity_id #%d 不存在于本任务", evID)), nil
				}
			}
			updated, err := t.ts.RetractFact(fid, state, reason, "planner", evID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cascade := a.CascadeStopIntents == nil || *a.CascadeStopIntents
			var stoppedIDs []int64
			if cascade {
				deps, err := t.ts.DependentActiveIntents(fid)
				if err == nil {
					for _, dep := range deps {
						stopped := false
						switch dep.State {
						case "running":
							if t.killWork != nil && t.killWork(dep.ID) == nil {
								stopped = true
							}
							if ok, _ := t.ts.CompareAndSetIntentState(dep.ID, "running", "stopped"); ok {
								stopped = true
							}
						case "open", "paused":
							if ok, _ := t.ts.CompareAndSetIntentState(dep.ID, dep.State, "stopped"); ok {
								stopped = true
							}
						}
						if stopped {
							_ = t.ts.SetIntentStopReason(dep.ID, fmt.Sprintf("上游事实 #%d 已%s：%s", fid, state, reason))
							stoppedIDs = append(stoppedIDs, dep.ID)
						}
					}
				}
			}
			sort.Slice(stoppedIDs, func(i, j int) bool { return stoppedIDs[i] < stoppedIDs[j] })
			return jsonResult(map[string]any{
				"fact_id":            fid,
				"state":              updated.State,
				"stopped_intent_ids": stoppedIDs,
			})
		})
}

func (t *ToolSet) recordAssetNoteTool() actool.CoreTool {
	return t.writeExpTool("record_asset_note",
		"在探索图中登记一条同资产实时共享备注（如已确认的 WAF 规则、HTTP 200 软报错特征、有效鉴权头/测试会话规范、框架真实版本）。后续任何新 Worker 领取锚定到这些 asset_ids 的意图时，程序会自动将其注入系统提示，零检索开销。",
		obj(map[string]any{
			"asset_ids":            map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "integer"}, "description": "必填：适用的资产 id 列表"},
			"summary":              str("一句话资产特征或避坑要点"),
			"detail":               str("可选：补充细节、触发特征或复现条件"),
			"evidence_activity_id": idp("可选：支撑该备注的真实执行记录 id"),
		}, "asset_ids", "summary"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				AssetIDs           []json.RawMessage `json:"asset_ids"`
				Summary            string            `json:"summary"`
				Detail             string            `json:"detail"`
				EvidenceActivityID json.RawMessage   `json:"evidence_activity_id"`
			}
			_ = json.Unmarshal(in, &a)
			aids := dedupInt64(pidList(a.AssetIDs))
			if len(aids) == 0 {
				return actool.Errorf("asset_ids 不能为空"), nil
			}
			summary := strings.TrimSpace(a.Summary)
			if summary == "" {
				return actool.Errorf("summary 不能为空"), nil
			}
			if t.as != nil && t.taskID > 0 {
				visible, err := t.as.GetByIDsInScope(t.taskID, aids)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("资产范围校验失败: %v", err)), nil
				}
				if len(visible) != len(aids) {
					return actool.Errorf("部分 asset_ids 不属于本任务可见范围"), nil
				}
			}
			evID := pid(a.EvidenceActivityID)
			if evID > 0 {
				act, err := t.ts.VerifyActivityBelongsToExploration(evID)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("校验 evidence_activity_id 失败: %v", err)), nil
				}
				if act == nil {
					return actool.Errorf(fmt.Sprintf("evidence_activity_id #%d 不存在于本任务", evID)), nil
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
			id, err := t.ts.AddNode(db.KindFact, payload, 6, db.StateFactConfirmed, "planner", aids)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t.writes.Facts++
			return jsonResult(map[string]any{"note_id": id, "asset_ids": aids})
		})
}

func dedupInt64(ids []int64) []int64 {
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// unexploredBacklogHints inspects the live exploration and asset stores for
// concrete unexplored work before allowing planner_decision to end an empty
// queue round without dispatching any intent.
func (t *ToolSet) unexploredBacklogHints() []string {
	var hints []string
	if t.as != nil && t.taskID > 0 && !t.coverageDisabled {
		if untested, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, "", 3, 0); err == nil && total > 0 {
			labels := make([]string, 0, len(untested))
			for _, u := range untested {
				if lbl := strings.TrimSpace(u.Label); lbl != "" {
					labels = append(labels, fmt.Sprintf("#%d(%s)", u.ID, truncateRunes(lbl, 40)))
				}
			}
			sample := strings.Join(labels, "、")
			if sample != "" {
				hints = append(hints, fmt.Sprintf("仍有 %d 个未测资产（如 %s）", total, sample))
			} else {
				hints = append(hints, fmt.Sprintf("仍有 %d 个未测资产（可用 list_untested_assets 查看）", total))
			}
		}
	}
	if t.ts != nil {
		if facts, err := t.ts.ListByKind(db.KindFact, 40); err == nil {
			var unverifiedIDs []string
			for _, f := range facts {
				if f.State == db.StateFactUnverified || f.State == db.StateFactDisputed {
					if len(unverifiedIDs) < 3 {
						unverifiedIDs = append(unverifiedIDs, fmt.Sprintf("#%d", f.ID))
					}
				}
			}
			if len(unverifiedIDs) > 0 {
				hints = append(hints, fmt.Sprintf("仍有待核验/存疑事实（%s）未处理", strings.Join(unverifiedIDs, "、")))
			}
		}
		if intents, err := t.ts.ListByKind(db.KindIntent, 40); err == nil {
			var retryable []string
			for _, n := range intents {
				if n.State != "exhausted" && n.State != "blocked" {
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				if p["pinned_profile_id"] == nil && len(retryable) < 3 {
					retryable = append(retryable, fmt.Sprintf("#%d(%s)", n.ID, n.State))
				}
			}
			if len(retryable) > 0 {
				hints = append(hints, fmt.Sprintf("仍有未升级强模型重试的耗尽/阻塞意图（%s）", strings.Join(retryable, "、")))
			}
		}
	}
	return hints
}

// chainAssetMeta carries concise asset identity for L1 chain_view display.
type chainAssetMeta struct {
	ID           int64
	Type         string
	Label        string
	Technologies []string
}

// chainBranch is one L1 layered-blackboard entry grouped by primary asset (or
// "global" for unanchored nodes) so the Commander sees each attack line's real
// asset identity, exploration stage, cross-asset links, live alerts, and tombstones.
type chainBranch struct {
	Scope             string   `json:"scope"`
	AssetID           int64    `json:"asset_id,omitempty"`
	Label             string   `json:"label,omitempty"`
	Technologies      []string `json:"technologies,omitempty"`
	Stage             string   `json:"stage,omitempty"` // untested | recon_only | active | finding | stalled
	RelatedAssets     []int64  `json:"related_assets,omitempty"`
	ActiveIntents     []string `json:"active_intents,omitempty"`
	Findings          []string `json:"findings,omitempty"`
	RecentFacts       []string `json:"recent_facts,omitempty"`
	Tombstones        []string `json:"tombstones,omitempty"`
	AssetNotes        int      `json:"asset_notes,omitempty"`
	HasAlerts         bool     `json:"has_alerts,omitempty"`
	HasUnverifiedFact bool     `json:"has_unverified_fact,omitempty"`
	latestNodeID      int64
	priorityScore     int
}

func primaryAssetForNode(nodeID int64, payload json.RawMessage, anchors map[int64][]int64) int64 {
	if ids := anchors[nodeID]; len(ids) > 0 {
		return ids[0]
	}
	var p struct {
		AssetIDs []json.RawMessage `json:"asset_ids"`
	}
	if json.Unmarshal(payload, &p) == nil {
		if parsed := pidList(p.AssetIDs); len(parsed) > 0 {
			return parsed[0]
		}
	}
	return 0
}

func buildLayeredChainView(
	intents, facts, findings []*db.Node,
	edges []db.Edge,
	anchors map[int64][]int64,
	tmByIntent map[int64]IntentTelemetryInfo,
	assetMeta map[int64]chainAssetMeta,
	untestedAssets []chainAssetMeta,
) []chainBranch {
	branches := map[string]*chainBranch{}
	nodeAsset := map[int64]int64{}

	ensureBranch := func(aid int64) *chainBranch {
		key := "global"
		if aid > 0 {
			key = fmt.Sprintf("asset:%d", aid)
		}
		b := branches[key]
		if b == nil {
			b = &chainBranch{Scope: key, AssetID: aid}
			if aid > 0 {
				if meta, ok := assetMeta[aid]; ok {
					b.Label = truncateRunes(meta.Label, 80)
					if len(meta.Technologies) > 4 {
						b.Technologies = meta.Technologies[:4]
					} else if len(meta.Technologies) > 0 {
						b.Technologies = meta.Technologies
					}
				}
			}
			branches[key] = b
		}
		return b
	}
	getBranch := func(n *db.Node) *chainBranch {
		aid := primaryAssetForNode(n.ID, n.Payload, anchors)
		if aid > 0 {
			nodeAsset[n.ID] = aid
		}
		b := ensureBranch(aid)
		if n.ID > b.latestNodeID {
			b.latestNodeID = n.ID
		}
		return b
	}

	payloadStr := func(raw json.RawMessage, field string) string {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return ""
		}
		s, _ := m[field].(string)
		return strings.TrimSpace(s)
	}

	for _, n := range intents {
		if n == nil {
			continue
		}
		b := getBranch(n)
		sm := truncateRunes(payloadStr(n.Payload, "summary"), 72)
		switch n.State {
		case "running", "open":
			if len(b.ActiveIntents) < 3 {
				tag := n.State
				var meta map[string]any
				_ = json.Unmarshal(n.Payload, &meta)
				if pin := meta["pinned_profile_id"]; pin != nil {
					tag += fmt.Sprintf("|pin#%v", pin)
				}
				if tm, ok := tmByIntent[n.ID]; ok && len(tm.Alerts) > 0 {
					tag += "|ALERT:" + strings.Join(tm.Alerts, ",")
					b.HasAlerts = true
					b.priorityScore += 20
				}
				b.ActiveIntents = append(b.ActiveIntents, fmt.Sprintf("#%d [%s] %s", n.ID, tag, sm))
				b.priorityScore += 5
			}
		case "stopped", "exhausted", "blocked":
			if len(b.Tombstones) < 3 {
				why := strings.TrimSpace(n.DeleteReason)
				if why == "" {
					why = strings.TrimSpace(n.BlockedReason)
				}
				line := fmt.Sprintf("#%d [%s] %s", n.ID, n.State, sm)
				if why != "" {
					line += " (" + truncateRunes(why, 56) + ")"
				}
				b.Tombstones = append(b.Tombstones, line)
				b.priorityScore += 2
			}
		}
	}

	for _, n := range findings {
		if n == nil {
			continue
		}
		b := getBranch(n)
		if len(b.Findings) < 3 {
			b.Findings = append(b.Findings, fmt.Sprintf("#%d %s", n.ID, truncateRunes(payloadStr(n.Payload, "summary"), 72)))
			b.priorityScore += 10
		}
	}

	for _, n := range facts {
		if n == nil || n.State == db.StateOrigin {
			continue
		}
		b := getBranch(n)
		sm := truncateRunes(payloadStr(n.Payload, "summary"), 72)
		if n.State == db.StateFactRetracted {
			if len(b.Tombstones) < 3 {
				var fp map[string]any
				_ = json.Unmarshal(n.Payload, &fp)
				why := ""
				if r, ok := fp["retraction"].(map[string]any); ok {
					why, _ = r["reason"].(string)
				}
				line := fmt.Sprintf("#%d [retracted_fact] %s", n.ID, sm)
				if why != "" {
					line += " (" + truncateRunes(why, 56) + ")"
				}
				b.Tombstones = append(b.Tombstones, line)
			}
			continue
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		isNote, _ := fp["asset_note"].(bool)
		if isNote && n.State == db.StateFactConfirmed {
			b.AssetNotes++
		}
		if n.State == db.StateFactUnverified || n.State == db.StateFactDisputed {
			b.HasUnverifiedFact = true
			b.priorityScore += 8
		}
		if len(b.RecentFacts) < 3 {
			tag := n.State
			if isNote {
				tag += "|note"
			}
			b.RecentFacts = append(b.RecentFacts, fmt.Sprintf("#%d [%s] %s", n.ID, tag, sm))
			b.priorityScore += 1
		}
	}

	// Surface recently discovered untested assets directly as dangling branches so
	// newly enumerated services/endpoints are visible without guessing DSL queries.
	for _, ua := range untestedAssets {
		if ua.ID <= 0 {
			continue
		}
		key := fmt.Sprintf("asset:%d", ua.ID)
		if _, exists := branches[key]; exists {
			continue
		}
		b := ensureBranch(ua.ID)
		if b.Label == "" {
			b.Label = truncateRunes(ua.Label, 80)
		}
		if len(b.Technologies) == 0 && len(ua.Technologies) > 0 {
			if len(ua.Technologies) > 4 {
				b.Technologies = ua.Technologies[:4]
			} else {
				b.Technologies = ua.Technologies
			}
		}
		b.Stage = "untested"
	}

	// Preserve cross-asset lineage via derived_from / yields edges so multi-asset
	// chains (e.g. subdomain A cred leak -> admin B login) stay visibly linked.
	relSeen := map[string]map[int64]bool{}
	addRel := func(scope string, otherAsset int64) {
		if otherAsset <= 0 {
			return
		}
		b := branches[scope]
		if b == nil || b.AssetID == otherAsset {
			return
		}
		if relSeen[scope] == nil {
			relSeen[scope] = map[int64]bool{}
		}
		if relSeen[scope][otherAsset] || len(b.RelatedAssets) >= 4 {
			return
		}
		relSeen[scope][otherAsset] = true
		b.RelatedAssets = append(b.RelatedAssets, otherAsset)
	}
	for _, e := range edges {
		if e.Rel != db.RelDerivedFrom && e.Rel != db.RelYields {
			continue
		}
		srcA, dstA := nodeAsset[e.From], nodeAsset[e.To]
		if srcA > 0 && dstA > 0 && srcA != dstA {
			addRel(fmt.Sprintf("asset:%d", srcA), dstA)
			addRel(fmt.Sprintf("asset:%d", dstA), srcA)
		}
	}

	// Classify exploration stage and split into 3 quota-reserved buckets (max 12):
	//   Bucket A (up to 4): Urgent branches (probe alerts or unverified/disputed facts)
	//   Bucket B (up to 4): Dangling leads (0 active intents, with fresh facts/findings or untested asset)
	//   Bucket C (fill to 12): Remaining active/recent branches
	var urgent, dangling, rest []*chainBranch
	for _, b := range branches {
		if b.Stage == "" {
			switch {
			case len(b.Findings) > 0:
				b.Stage = "finding"
			case len(b.ActiveIntents) > 0:
				b.Stage = "active"
			case len(b.RecentFacts) > 0:
				b.Stage = "recon_only"
			case len(b.Tombstones) > 0:
				b.Stage = "stalled"
			default:
				continue
			}
		}
		switch {
		case b.HasAlerts || b.HasUnverifiedFact:
			urgent = append(urgent, b)
		case len(b.ActiveIntents) == 0 && (b.Stage == "untested" || b.Stage == "recon_only" || b.Stage == "finding"):
			dangling = append(dangling, b)
		default:
			rest = append(rest, b)
		}
	}

	sortByUrgency := func(s []*chainBranch) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].HasAlerts != s[j].HasAlerts {
				return s[i].HasAlerts
			}
			if s[i].priorityScore != s[j].priorityScore {
				return s[i].priorityScore > s[j].priorityScore
			}
			if s[i].latestNodeID != s[j].latestNodeID {
				return s[i].latestNodeID > s[j].latestNodeID
			}
			return s[i].Scope < s[j].Scope
		})
	}
	sortByRecency := func(s []*chainBranch) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].latestNodeID != s[j].latestNodeID {
				return s[i].latestNodeID > s[j].latestNodeID
			}
			if s[i].priorityScore != s[j].priorityScore {
				return s[i].priorityScore > s[j].priorityScore
			}
			return s[i].Scope < s[j].Scope
		})
	}
	sortByUrgency(urgent)
	sortByRecency(dangling)
	sortByRecency(rest)

	const totalCap = 12
	const urgentQuota = 4
	const danglingQuota = 4

	selected := make([]chainBranch, 0, totalCap)
	seen := map[string]bool{}
	take := func(src []*chainBranch, maxN int) {
		taken := 0
		for _, b := range src {
			if len(selected) >= totalCap || taken >= maxN {
				break
			}
			if seen[b.Scope] {
				continue
			}
			seen[b.Scope] = true
			selected = append(selected, *b)
			taken++
		}
	}
	take(urgent, urgentQuota)
	take(dangling, danglingQuota)
	take(rest, totalCap)
	// Fill any leftover capacity from overflow urgent/dangling items.
	take(urgent, totalCap)
	take(dangling, totalCap)
	return selected
}
