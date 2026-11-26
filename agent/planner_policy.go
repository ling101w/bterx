package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Execution stays with workers; the planner retains evidence, queue, goal and
// worker-steering tools. This also closes SDK-injected command/network paths.
var plannerToolNames = map[string]bool{
	"graph_overview": true, "list_findings": true, "list_facts": true, "node_detail": true,
	"expand_digest": true, "get_worker_output": true, "get_worker_trace": true,
	"search_all_worker_traces": true, "list_worker_traces": true, "list_goals": true,
	"add_intent": true, "prove_goal": true, "goal_met": true, "kill_work": true,
	"steer_work": true, "report_finding": true, "list_companies": true,
	"list_assets": true, "add_company_scope": true, "add_task_scope": true,
	"list_untested_assets": true, "TodoWrite": true, "planner_decision": true,
	// Unified Task Commander tools (model tiering, anti-hallucination retraction, asset-scoped intel, L0 playbook).
	"list_llm_profiles": true, "retract_fact": true, "record_asset_note": true, "update_playbook": true,
	// Experience retrieval is optional and never grants target execution.
	"ask_experience": true, "experience_search": true, "experience_get": true, "experience_feedback": true, "experience_stats": true,
}

var plannerCachedReads = map[string]bool{
	"list_facts": true, "list_goals": true, "expand_digest": true,
	"get_worker_output": true, "get_worker_trace": true, "search_all_worker_traces": true,
}

const plannerDispatchInstruction = `
【先派发、再深挖】你只负责规划与核对，不运行命令、不访问目标。已有具备前提、未被覆盖的方向时，先 add_intent 交给 worker，明确入口/假设、验证目标和停止条件，然后再继续规划。不要创建“planner 自执行/禁止 worker 领取”的意图。
队列完全为空时，最多进行六次不同的宽泛历史检索；定点 node_detail 等证据读取仍可使用。准备好就派发；证据不足、前提未到位或已经没有合理方向时，调用 planner_decision 如实说明原因和缺少条件，再结束本轮。不能为了非空队列编造方向。
重复查询在证据未变化时返回前次 tool_use_id 与短摘要；完整原结果已在本轮上下文中。不要为读取相同内容更换 JSON 字段顺序或改写同义查询。`

const plannerCommanderInstruction = `

【单任务指挥官职责（规划 + 督战 + 模型分级 + 防污染）】
1. **先看 L1 链路与墓碑**：先扫 graph_overview 的 chain_view、running_intents（含探针告警 alerts）、recent_stopped_intents 与 retracted_facts。已被止损（stopped）或已撤回（retracted）的方向除非出现实质性新证据，禁止原地重派。
2. **先核查再止损**：遇到探针告警（idle_stall / consecutive_errors / repeated_tool_loop / long_run_no_output）或 unverified/disputed 高影响事实时，先调 get_worker_trace / node_detail 核对原始输出，再决定 steer_work 纠偏、kill_work（必填 reason 留墓碑）或 retract_fact（自动级联止损下游意图）。
3. **主动模型分级**：广度侦察、常规指纹/目录/基础验证留空 pinned_profile_id（走默认快模型）；仅当弱模型卡住、或面对复杂业务逻辑/越权/多步利用链时，结合 llm_profiles（或 list_llm_profiles）在 add_intent 中指定强模型或跨厂商模型的 pinned_profile_id 破局；突破完成后机械收尾回到默认档。
4. **同资产实时共享**：一旦确认可复用的资产级特征（WAF 触发规则、HTTP 200 软鉴权失败特征、有效测试会话/鉴权头规范、真实框架版本），立即用 record_asset_note（或 steer_work 的 also_asset_note=true）锚定到对应 asset_ids，让同资产在跑与后续 Worker 直接复用，不再重复踩坑。
5. **动态时间预算（budget_tier / run_seconds）**：在 add_intent 中按任务复杂度合理配时——轻量探活/单项复核传 budget_tier="quick"(10m)；常规扫描用默认/standard(20m)；复杂多步链、逆向或升档慢推理强模型时传 budget_tier="deep"(40m)；高分残局硬骨头传 budget_tier="endgame"(60m) 或精确 run_seconds(180~3600)，减少中途超时重建税。
6. **L0 战术剧本（PLAYBOOK.json）**：尾部附带当前 PLAYBOOK.json（硬上限 2.5KB，含 phase / global_rules / hypotheses / 只读 shared_index）。用 update_playbook 维护阶段节奏、运行期热补丁（≤8 条）与未解高价值目标假设（每目标≤5 条）；严禁写流水账，无确定性反证（如源码/实测明确拦截）禁止标 disproved（弱模型超时只能标 inconclusive）；已解决或封矿目标及时 remove_targets 清理。`

type plannerRoundPolicy struct {
	mu             sync.Mutex
	queries        map[string]bool
	dispatched     bool
	decision       bool
	stopNudged     bool
	backlogRefused bool
	active         func() (bool, error)
	openGoals      func() (bool, error)
	backlogCheck   func() []string
	final          bool
}

func newPlannerRoundPolicy(active, goals func() (bool, error), final bool) *plannerRoundPolicy {
	return &plannerRoundPolicy{queries: map[string]bool{}, active: active, openGoals: goals, final: final}
}

func (p *plannerRoundPolicy) setBacklogCheck(fn func() []string) {
	p.backlogCheck = fn
}

func canonicalPlannerInput(in []byte) string {
	var value any
	if json.Unmarshal(in, &value) != nil {
		return string(in)
	}
	b, _ := json.Marshal(value)
	return string(b)
}

func (p *plannerRoundPolicy) hooks() *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, func(ctx context.Context, ev hook.Event) hook.Result {
		if !plannerToolNames[ev.ToolName] {
			return hook.Result{Decision: "block", Message: "规划者只做证据核对与派发；命令、文件读取和联网验证请生成意图交给 worker。"}
		}
		broad := ev.ToolName == "list_facts" || ev.ToolName == "list_findings" || ev.ToolName == "search_all_worker_traces"
		if !broad {
			return hook.Result{}
		}
		active, err := p.active()
		if err != nil || active || p.final {
			return hook.Result{}
		}
		key := ev.ToolName + ":" + canonicalPlannerInput(ev.Input)
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.dispatched && !p.decision && !p.queries[key] && len(p.queries) >= 6 {
			return hook.Result{Decision: "block", Message: "当前没有执行意图，已完成六次不同的历史检索。请先用已有证据 add_intent，或用 planner_decision 说明缺少的前提；定点 node_detail 仍可使用。"}
		}
		p.queries[key] = true
		return hook.Result{}
	}).On(hook.PostToolUse, func(_ context.Context, ev hook.Event) hook.Result {
		if ev.ToolName == "add_intent" && !ev.IsError {
			var text string
			if json.Unmarshal(ev.Result, &text) == nil && plannerCreatedIntent(actool.Text(text)) {
				p.mu.Lock()
				p.dispatched = true
				p.mu.Unlock()
			}
		}
		return hook.Result{}
	}).On(hook.Stop, func(_ context.Context, _ hook.Event) hook.Result {
		if p.final {
			return hook.Result{}
		}
		active, err := p.active()
		if err != nil || active {
			return hook.Result{}
		}
		goals, err := p.openGoals()
		if err != nil || !goals {
			return hook.Result{}
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.dispatched || p.decision || p.stopNudged {
			return hook.Result{}
		}
		p.stopNudged = true
		return hook.Result{Decision: "block", AdditionalContext: "目标未完成且队列为空。请把已准备好的方向 add_intent 交给 worker；若证据或前提不足，请调用 planner_decision 说明，不要静默空结束，也不要编造意图。"}
	})
}

const (
	contractedHumanHintsCap     = 12
	contractedHumanHintRunes    = 800
	contractedReviewHintsCap    = 2
	contractedReviewHintRunes   = 360
	contractedColdDigestsInline = 5
	contractedColdDigestRunes   = 220
	contractedColdIndexCap      = 16
	contractedColdIndexRunes    = 48
	contractedRecentDoneCap     = 8
	contractedRecentFactsCap    = 12
	contractedRecentSummaryRune = 160
	contractedStoppedCap        = 6
	contractedStoppedRune       = 120
	contractedFindingRunes      = 180
	contractedTaskDescRunes     = 800
)

func isChainReviewHint(entry map[string]any) bool {
	if origin, _ := entry["origin"].(string); origin == ChainReviewerKey {
		return true
	}
	if text, _ := entry["text"].(string); strings.HasPrefix(strings.TrimSpace(text), "【链路复盘建议") {
		return true
	}
	return false
}

func cloneMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func truncateFieldRunes(entry map[string]any, key string, limit int) bool {
	s, ok := entry[key].(string)
	if !ok {
		return false
	}
	r := []rune(s)
	if len(r) <= limit {
		return false
	}
	entry[key] = string(r[:limit]) + "…"
	return true
}

func firstLineSnippet(s string, maxRunes int) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…"
}

func contractHintList(hints []map[string]any, maxReviewHints int) (kept []map[string]any, archivedReviewIDs []int64, overflowHumanIDs []int64) {
	var human, review []map[string]any
	for _, h := range hints {
		if isChainReviewHint(h) {
			review = append(review, h)
		} else {
			human = append(human, h)
		}
	}
	// hints arrive newest-first from ListByKind; preserve human hints first,
	// then keep only the freshest automated chain_reviewer hints.
	for i, h := range human {
		if i >= contractedHumanHintsCap {
			if id, ok := h["id"].(int64); ok && id > 0 {
				overflowHumanIDs = append(overflowHumanIDs, id)
			}
			continue
		}
		item := cloneMap(h)
		if truncateFieldRunes(item, "text", contractedHumanHintRunes) {
			item["text_truncated"] = true
			item["detail_tool"] = "node_detail(id)"
		}
		kept = append(kept, item)
	}
	for i, h := range review {
		if i >= maxReviewHints {
			if id, ok := h["id"].(int64); ok && id > 0 {
				archivedReviewIDs = append(archivedReviewIDs, id)
			}
			continue
		}
		item := cloneMap(h)
		if truncateFieldRunes(item, "text", contractedReviewHintRunes) {
			item["text_truncated"] = true
			item["detail_tool"] = "node_detail(id)"
		}
		kept = append(kept, item)
	}
	return kept, archivedReviewIDs, overflowHumanIDs
}

func contractNodeSummaries(list []map[string]any, capN, maxRunes int) ([]map[string]any, int) {
	omitted := 0
	if capN > 0 && len(list) > capN {
		omitted = len(list) - capN
		list = list[:capN]
	}
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		item := cloneMap(entry)
		if truncateFieldRunes(item, "summary", maxRunes) {
			item["summary_truncated"] = true
		}
		out = append(out, item)
	}
	return out, omitted
}

// plannerCompactOverview builds a Sapper-style contracted situational view for
// the planner's wake-up prompt without mutating the source map. Goals, human
// hints, live intents, topology IDs and chain_view are preserved; bulk prose
// (automated chain_reviewer hint archives, older cold digests, long summaries)
// is contracted into compact previews and drill-down indices so long-running
// explorations stay compact and preserve prompt-cache efficiency.
func plannerCompactOverview(view map[string]any) map[string]any {
	return compactOverview(view, contractedReviewHintsCap)
}

// workerCompactOverview contracts the read-only global awareness snapshot
// injected into each worker's launch message, keeping human hints and concise
// topology while dropping bulky periodic chain_reviewer archives.
func workerCompactOverview(view map[string]any) map[string]any {
	return compactOverview(view, 1)
}

func compactOverview(view map[string]any, maxReviewHints int) map[string]any {
	copyView := cloneMap(view)
	copyView["overview_mode"] = "contracted"

	if hints, ok := view["hints"].([]map[string]any); ok {
		kept, archivedReviews, overflowHuman := contractHintList(hints, maxReviewHints)
		copyView["hints"] = kept
		if len(archivedReviews) > 0 {
			recent := archivedReviews
			if len(recent) > 8 {
				recent = recent[:8]
			}
			copyView["archived_review_hints"] = map[string]any{
				"count":       len(archivedReviews),
				"recent_ids":  recent,
				"detail_tool": "node_detail(id) 可按需查阅历史复盘",
			}
		}
		if len(overflowHuman) > 0 {
			copyView["hints_more_ids"] = overflowHuman
		}
	}

	if list, ok := view["cold_digests"].([]map[string]any); ok {
		inlineN := len(list)
		if inlineN > contractedColdDigestsInline {
			inlineN = contractedColdDigestsInline
		}
		out := make([]map[string]any, 0, inlineN)
		for _, entry := range list[:inlineN] {
			item := cloneMap(entry)
			if truncateFieldRunes(item, "body", contractedColdDigestRunes) {
				item["body_truncated"] = true
				item["detail_tool"] = "node_detail(id) / expand_digest(id) 可取完整摘要与成员"
			}
			out = append(out, item)
		}
		copyView["cold_digests"] = out
		if len(list) > inlineN {
			rest := list[inlineN:]
			idxCap := len(rest)
			if idxCap > contractedColdIndexCap {
				idxCap = contractedColdIndexCap
			}
			index := make([]string, 0, idxCap)
			for _, entry := range rest[:idxCap] {
				body, _ := entry["body"].(string)
				index = append(index, fmt.Sprintf("#%v(%vn): %s", entry["id"], entry["member_count"], firstLineSnippet(body, contractedColdIndexRunes)))
			}
			copyView["cold_digest_index"] = index
			if len(rest) > idxCap {
				copyView["cold_digest_index_omitted"] = len(rest) - idxCap
			}
		}
	}

	if list, ok := view["recent_done_intents"].([]map[string]any); ok {
		trimmed, omitted := contractNodeSummaries(list, contractedRecentDoneCap, contractedRecentSummaryRune)
		copyView["recent_done_intents"] = trimmed
		if omitted > 0 {
			copyView["recent_done_omitted"] = omitted
		}
	}
	if list, ok := view["recent_facts"].([]map[string]any); ok {
		trimmed, omitted := contractNodeSummaries(list, contractedRecentFactsCap, contractedRecentSummaryRune)
		copyView["recent_facts"] = trimmed
		if omitted > 0 {
			copyView["recent_facts_omitted"] = omitted
		}
	}
	if list, ok := view["recent_stopped_intents"].([]map[string]any); ok {
		trimmed, _ := contractNodeSummaries(list, contractedStoppedCap, contractedStoppedRune)
		for _, item := range trimmed {
			truncateFieldRunes(item, "stop_reason", 100)
		}
		copyView["recent_stopped_intents"] = trimmed
	}
	if list, ok := view["finding_list"].([]map[string]any); ok {
		trimmed, _ := contractNodeSummaries(list, len(list), contractedFindingRunes)
		copyView["finding_list"] = trimmed
	}
	if taskMap, ok := view["task"].(map[string]any); ok {
		tcopy := cloneMap(taskMap)
		if truncateFieldRunes(tcopy, "description", contractedTaskDescRunes) {
			tcopy["description_truncated"] = true
		}
		copyView["task"] = tcopy
	}
	return copyView
}

func plannerCreatedIntent(result actool.Result) bool {
	if result.IsError {
		return false
	}
	text := result.Flatten()
	if strings.HasPrefix(text, "intent created: ") {
		var id int64
		_, err := fmt.Sscanf(text, "intent created: %d", &id)
		return err == nil && id > 0
	}
	var data struct {
		IDs []int64 `json:"ids"`
	}
	if json.Unmarshal([]byte(text), &data) == nil {
		for _, id := range data.IDs {
			if id > 0 {
				return true
			}
		}
	}
	return false
}

func (p *plannerRoundPolicy) decisionTool() actool.CoreTool {
	return actool.Build(actool.Spec{Name: "planner_decision", Description: "无可执行新方向时记录具体原因和缺少前提，再结束本轮；不创建意图、不改变任务目标或终态。",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"reason_kind": map[string]any{"type": "string", "enum": []string{"await_running", "missing_prerequisite", "insufficient_evidence", "no_supported_direction"}},
			"reason":      map[string]any{"type": "string"}, "next_requirement": map[string]any{"type": "string"}},
			"required": []string{"reason_kind", "reason", "next_requirement"}},
		ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Kind        string `json:"reason_kind"`
				Reason      string `json:"reason"`
				Requirement string `json:"next_requirement"`
			}
			if json.Unmarshal(in, &a) != nil || len([]rune(strings.TrimSpace(a.Reason))) < 8 || strings.TrimSpace(a.Requirement) == "" {
				return actool.Errorf("请写清具体原因（至少8字）和下一步所需的证据/前提。"), nil
			}
			switch a.Kind {
			case "await_running", "missing_prerequisite", "insufficient_evidence", "no_supported_direction":
			default:
				return actool.Errorf("无效 reason_kind"), nil
			}
			active := false
			if p.active != nil {
				if v, err := p.active(); err == nil {
					active = v
				}
			}
			if a.Kind == "await_running" && !active {
				return actool.Errorf("当前没有任何 open 或 running 意图，不能以 await_running 结束本轮；请先 add_intent 派发方向，或核对真实阻塞原因。"), nil
			}
			openGoals := true
			if p.openGoals != nil {
				if v, err := p.openGoals(); err == nil {
					openGoals = v
				}
			}
			if !p.final && !active && openGoals && p.backlogCheck != nil {
				if backlog := p.backlogCheck(); len(backlog) > 0 {
					p.mu.Lock()
					alreadyRefused := p.backlogRefused
					if !alreadyRefused {
						p.backlogRefused = true
					}
					p.mu.Unlock()
					if !alreadyRefused || len([]rune(strings.TrimSpace(a.Reason))) < 20 {
						return actool.Errorf("目标尚未达成且仍有可推进线索，禁止偷懒早停：" + strings.Join(backlog, "；") + "。请优先挑高价值线索 add_intent（弱模型卡住的可传 pinned_profile_id 升档强模型）；若确均无法推进，请在 reason 中具体说明为何这些线索都不可行（至少20字）后再提交。"), nil
					}
				}
			}
			p.mu.Lock()
			p.decision = true
			p.mu.Unlock()
			log.Printf("[planner-decision] %s: %.500s; next=%.300s", a.Kind, a.Reason, a.Requirement)
			return actool.Text("已记录规划待补条件，请在本轮总结中说明：" + a.Reason + "；下一步需要：" + a.Requirement), nil
		}})
}

type plannerReadEntry struct {
	result    actool.Result
	toolUseID string
	created   time.Time
	revision  string
}

type plannerReadCache struct {
	mu            sync.Mutex
	entries       map[string]plannerReadEntry
	revision      func(context.Context) (string, error)
	traceRevision func(context.Context) (string, error)
	hits          int
	misses        int
}

func newPlannerReadCache(revision func(context.Context) (string, error)) *plannerReadCache {
	return &plannerReadCache{entries: map[string]plannerReadEntry{}, revision: revision}
}

type plannerCachedTool struct {
	actool.CoreTool
	cache *plannerReadCache
}

func (c *plannerReadCache) wrap(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		if !plannerToolNames[tool.Name()] {
			continue
		}
		out = append(out, &plannerCachedTool{CoreTool: tool, cache: c})
	}
	return out
}

func (t *plannerCachedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	c := t.cache
	if !t.IsReadOnly(in) {
		c.mu.Lock()
		c.entries = map[string]plannerReadEntry{}
		c.mu.Unlock()
		result, err := t.CoreTool.Call(ctx, in, tc)
		c.mu.Lock()
		c.entries = map[string]plannerReadEntry{}
		c.mu.Unlock()
		return result, err
	}
	if !plannerCachedReads[t.Name()] {
		return t.CoreTool.Call(ctx, in, tc)
	}
	if err := ctx.Err(); err != nil {
		return actool.Result{}, err
	}
	revision := c.revision
	if c.traceRevision != nil && (t.Name() == "get_worker_output" || t.Name() == "get_worker_trace" || t.Name() == "search_all_worker_traces") {
		revision = c.traceRevision
	}
	rev, err := revision(ctx)
	if err != nil {
		return t.CoreTool.Call(ctx, in, tc)
	}
	key := t.Name() + ":" + canonicalPlannerInput(in)
	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && entry.revision == rev && time.Since(entry.created) < 90*time.Second {
		c.hits++
		c.mu.Unlock()
		// Preserve a short self-contained excerpt if SDK compaction removed older
		// messages, and point to the full earlier tool_result in the same round.
		text := []rune(entry.result.Flatten())
		if len(text) > 1200 {
			text = text[:1200]
		}
		b, _ := json.Marshal(map[string]any{"cache_hit": true, "first_tool_use_id": entry.toolUseID,
			"note": "相同查询的证据版本未变，复用本轮之前的完整结果；只为明确新缺口读取下一节点。", "excerpt": string(text)})
		return actool.Text(string(b)), nil
	}
	c.misses++
	c.mu.Unlock()
	result, err := t.CoreTool.Call(ctx, in, tc)
	if err != nil || result.IsError {
		return result, err
	}
	// If evidence changed while the query was executing, do not cache that
	// mixed-time result under either version.
	endRev, e := revision(ctx)
	if e == nil && endRev == rev && len(result.Flatten()) <= 256000 {
		id := ""
		if tc != nil {
			id = tc.ToolUseID
		}
		c.mu.Lock()
		if len(c.entries) >= 64 {
			c.entries = map[string]plannerReadEntry{}
		}
		c.entries[key] = plannerReadEntry{result: result, toolUseID: id, created: time.Now(), revision: rev}
		c.mu.Unlock()
	}
	return result, err
}

func (c *plannerReadCache) report(exp int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("[planner-cache] exp=%d hits=%d misses=%d", exp, c.hits, c.misses)
}
