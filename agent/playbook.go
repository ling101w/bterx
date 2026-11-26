package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	playbookFileName         = "PLAYBOOK.json"
	playbookMaxBytes         = 2560 // strict 2.5KB serialized cap
	playbookMaxRules         = 8
	playbookMaxHypPerTarget  = 5
	playbookMaxPhaseRunes    = 80
	playbookMaxRuleRunes     = 160
	playbookMaxTargetRunes   = 64
	playbookMaxPathRunes     = 160
	playbookMaxRefRunes      = 120
	playbookMaxSharedIdxByte = 320
)

const (
	HypothesisActive       = "active"
	HypothesisDisproved    = "disproved"
	HypothesisInconclusive = "inconclusive"
)

// Playbook is the L0 tactical memory persisted per task under
// <workDir>/tasks/<taskID>/PLAYBOOK.json. It intentionally has only four fields
// and a strict 2.5KB byte ceiling so planner context stays bounded while
// surviving across fresh wake-up rounds and preserving static prefix KV cache.
type Playbook struct {
	Phase       string               `json:"phase,omitempty"`
	GlobalRules []string             `json:"global_rules,omitempty"`
	Hypotheses  []PlaybookHypothesis `json:"hypotheses,omitempty"`
	SharedIndex string               `json:"shared_index,omitempty"`
}

// PlaybookHypothesis records one concrete mechanism hypothesis for an active
// target/challenge. Marking status="disproved" requires a concrete evidence_ref
// (never timeout-only excuses) so weak-model timeouts cannot lock out valid paths.
type PlaybookHypothesis struct {
	TargetID    string `json:"target_id"`
	Path        string `json:"path"`
	Status      string `json:"status"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

var playbookLocks sync.Map // clean file path -> *sync.Mutex

func lockPlaybookPath(path string) func() {
	clean := filepath.Clean(path)
	v, _ := playbookLocks.LoadOrStore(clean, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func playbookPath(taskDir string) string {
	return filepath.Join(taskDir, playbookFileName)
}

// LoadPlaybook reads PLAYBOOK.json from taskDir. Missing files return an empty
// Playbook with nil error.
func LoadPlaybook(taskDir string) (Playbook, error) {
	if strings.TrimSpace(taskDir) == "" {
		return Playbook{}, nil
	}
	p := playbookPath(taskDir)
	unlock := lockPlaybookPath(p)
	defer unlock()
	return loadPlaybookUnlocked(p)
}

func loadPlaybookUnlocked(path string) (Playbook, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Playbook{}, nil
		}
		return Playbook{}, err
	}
	var pb Playbook
	if err := json.Unmarshal(raw, &pb); err != nil {
		return Playbook{}, err
	}
	return pb, nil
}

func savePlaybookUnlocked(path string, pb Playbook) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(pb)
	if err != nil {
		return err
	}
	if len(b) > playbookMaxBytes {
		return fmt.Errorf("PLAYBOOK.json 序列化后为 %d 字节，超过硬上限 %d 字节（2.5KB）；请精简文案或通过 remove_targets 清理已解决/关闭目标后再保存", len(b), playbookMaxBytes)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// BuildSharedIndex scans the L1 shared repositories (shared_tools/ and skills/
// under taskDir and workDir, plus well-known top-level helper files) and returns
// a concise single-line directory index. Empty when no shared resources exist
// (0 tokens in PLAYBOOK.json).
func BuildSharedIndex(workDir, taskDir string) string {
	listNames := func(dirs ...string) []string {
		seen := map[string]bool{}
		var names []string
		for _, dir := range dirs {
			if strings.TrimSpace(dir) == "" {
				continue
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, ".") || seen[name] {
					continue
				}
				seen[name] = true
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return names
	}
	toolDirs := []string{}
	skillDirs := []string{}
	if taskDir != "" {
		toolDirs = append(toolDirs, filepath.Join(taskDir, "shared_tools"))
		skillDirs = append(skillDirs, filepath.Join(taskDir, "skills"))
	}
	if workDir != "" && filepath.Clean(workDir) != filepath.Clean(taskDir) {
		toolDirs = append(toolDirs, filepath.Join(workDir, "shared_tools"))
		skillDirs = append(skillDirs, filepath.Join(workDir, "skills"))
	}
	tools := listNames(toolDirs...)
	// Also surface well-known shared helper files in workDir/taskDir if present.
	extraSeen := map[string]bool{}
	for _, n := range tools {
		extraSeen[n] = true
	}
	for _, candidate := range []struct {
		dir, name string
	}{
		{workDir, "benchctl.py"},
		{taskDir, "asset_inventory.md"},
	} {
		if candidate.dir == "" || extraSeen[candidate.name] {
			continue
		}
		if info, err := os.Stat(filepath.Join(candidate.dir, candidate.name)); err == nil && !info.IsDir() {
			extraSeen[candidate.name] = true
			tools = append(tools, candidate.name)
		}
	}
	sort.Strings(tools)
	skills := listNames(skillDirs...)

	var parts []string
	if len(tools) > 0 {
		parts = append(parts, "shared_tools:["+strings.Join(tools, ",")+"]")
	}
	if len(skills) > 0 {
		parts = append(parts, "skills:["+strings.Join(skills, ",")+"]")
	}
	if len(parts) == 0 {
		return ""
	}
	idx := strings.Join(parts, " ")
	if len(idx) > playbookMaxSharedIdxByte {
		idx = truncateBytesUTF8(idx, playbookMaxSharedIdxByte-3) + "..."
	}
	return idx
}

func truncateBytesUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes || maxBytes <= 0 {
		return s
	}
	out := s[:maxBytes]
	for len(out) > 0 && !isUTF8Boundary(out) {
		out = out[:len(out)-1]
	}
	return out
}

func isUTF8Boundary(s string) bool {
	if len(s) == 0 {
		return true
	}
	// Check last rune via range decoding
	var validLen int
	for i := range s {
		validLen = i
	}
	r := []rune(s[validLen:])
	return len(r) == 1 && r[0] != '\uFFFD'
}

func isWeakTimeoutOnlyRef(ref string) bool {
	low := strings.ToLower(strings.TrimSpace(ref))
	if low == "" {
		return true
	}
	// Reject bare timeout/exhaustion tokens without concrete node/code/evidence refs.
	switch low {
	case "timeout", "timed out", "exhausted", "budget", "budget_exhausted", "max_turns", "超时", "预算耗尽", "步数耗尽":
		return true
	}
	return false
}

// ValidatePlaybook enforces the strict L0 Playbook schema and 2.5KB ceiling.
func ValidatePlaybook(pb *Playbook) error {
	pb.Phase = strings.TrimSpace(pb.Phase)
	if len([]rune(pb.Phase)) > playbookMaxPhaseRunes {
		return fmt.Errorf("phase 长度不能超过 %d 字符", playbookMaxPhaseRunes)
	}
	if len(pb.GlobalRules) > playbookMaxRules {
		return fmt.Errorf("global_rules 最多保留 %d 条（当前 %d 条），请先清理过期规则", playbookMaxRules, len(pb.GlobalRules))
	}
	cleanRules := make([]string, 0, len(pb.GlobalRules))
	seenRule := map[string]bool{}
	for _, r := range pb.GlobalRules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if len([]rune(r)) > playbookMaxRuleRunes {
			return fmt.Errorf("单条 global_rule 长度不能超过 %d 字符：%q", playbookMaxRuleRunes, truncateRunes(r, 40))
		}
		key := strings.ToLower(r)
		if seenRule[key] {
			continue
		}
		seenRule[key] = true
		cleanRules = append(cleanRules, r)
	}
	pb.GlobalRules = cleanRules

	perTarget := map[string]int{}
	cleanHyps := make([]PlaybookHypothesis, 0, len(pb.Hypotheses))
	for _, h := range pb.Hypotheses {
		h.TargetID = strings.TrimSpace(h.TargetID)
		h.Path = strings.TrimSpace(h.Path)
		h.Status = strings.ToLower(strings.TrimSpace(h.Status))
		h.EvidenceRef = strings.TrimSpace(h.EvidenceRef)
		if h.TargetID == "" || h.Path == "" {
			return fmt.Errorf("hypothesis 的 target_id 和 path 均不能为空")
		}
		if len([]rune(h.TargetID)) > playbookMaxTargetRunes {
			return fmt.Errorf("target_id 超过 %d 字符：%q", playbookMaxTargetRunes, h.TargetID)
		}
		if len([]rune(h.Path)) > playbookMaxPathRunes {
			return fmt.Errorf("hypothesis path 超过 %d 字符：%q", playbookMaxPathRunes, truncateRunes(h.Path, 40))
		}
		if len([]rune(h.EvidenceRef)) > playbookMaxRefRunes {
			return fmt.Errorf("evidence_ref 超过 %d 字符", playbookMaxRefRunes)
		}
		switch h.Status {
		case HypothesisActive, HypothesisInconclusive:
		case HypothesisDisproved:
			if isWeakTimeoutOnlyRef(h.EvidenceRef) {
				return fmt.Errorf("target_id=%s 标记 status=disproved 必须提供确定性反证 evidence_ref（如 fact#ID / intent#ID / 源码拦截位置）；弱模型超时或未验证请标 inconclusive", h.TargetID)
			}
		default:
			return fmt.Errorf("hypothesis status 必须是 active / disproved / inconclusive 之一，收到 %q", h.Status)
		}
		tkey := strings.ToLower(h.TargetID)
		perTarget[tkey]++
		if perTarget[tkey] > playbookMaxHypPerTarget {
			return fmt.Errorf("target_id=%s 的假设条数超过上限 %d 条，请合并或清理旧假设", h.TargetID, playbookMaxHypPerTarget)
		}
		cleanHyps = append(cleanHyps, h)
	}
	pb.Hypotheses = cleanHyps

	b, err := json.Marshal(pb)
	if err != nil {
		return err
	}
	if len(b) > playbookMaxBytes {
		return fmt.Errorf("PLAYBOOK.json 序列化后为 %d 字节，超过硬上限 %d 字节（2.5KB）；请精简文案或通过 remove_targets 清理已解决/关闭目标", len(b), playbookMaxBytes)
	}
	return nil
}

// ReconcilePlaybook refreshes Go-owned shared_index and auto-prunes hypotheses
// whose target_id has been solved or marked env_broken (either in .benchctl
// state files or via met goals / solved findings in the exploration store).
func ReconcilePlaybook(workDir, taskDir string, ts *db.ExplorationStore) (Playbook, []string, error) {
	if strings.TrimSpace(taskDir) == "" {
		return Playbook{}, nil, nil
	}
	p := playbookPath(taskDir)
	unlock := lockPlaybookPath(p)
	defer unlock()

	pb, err := loadPlaybookUnlocked(p)
	if err != nil {
		// Corrupted file should never block planner wake-up; reset cleanly.
		pb = Playbook{}
	}

	resolved := collectResolvedPlaybookTargets(workDir, ts)
	var pruned []string
	changed := false
	if len(resolved) > 0 && len(pb.Hypotheses) > 0 {
		kept := make([]PlaybookHypothesis, 0, len(pb.Hypotheses))
		prunedSet := map[string]bool{}
		for _, h := range pb.Hypotheses {
			if resolved[strings.ToLower(strings.TrimSpace(h.TargetID))] {
				changed = true
				if !prunedSet[h.TargetID] {
					prunedSet[h.TargetID] = true
					pruned = append(pruned, h.TargetID)
				}
				continue
			}
			kept = append(kept, h)
		}
		pb.Hypotheses = kept
	}

	newIdx := BuildSharedIndex(workDir, taskDir)
	if pb.SharedIndex != newIdx {
		pb.SharedIndex = newIdx
		if _, statErr := os.Stat(p); statErr == nil {
			changed = true
		}
	}
	if changed {
		// Persist only when an existing file changed or hypotheses were pruned.
		_ = savePlaybookUnlocked(p, pb)
	}
	sort.Strings(pruned)
	return pb, pruned, nil
}

func collectResolvedPlaybookTargets(workDir string, ts *db.ExplorationStore) map[string]bool {
	resolved := map[string]bool{}
	// 1. Auto-detect solved / env_broken benchmark challenges from .benchctl state files.
	if strings.TrimSpace(workDir) != "" {
		pattern := filepath.Join(workDir, ".benchctl", "state_*.json")
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, fp := range matches {
				raw, err := os.ReadFile(fp)
				if err != nil {
					continue
				}
				var st struct {
					Challenges map[string]struct {
						SolvedAt   any    `json:"solved_at"`
						EnvBroken  bool   `json:"env_broken"`
						LastReason string `json:"last_reason"`
					} `json:"challenges"`
				}
				if json.Unmarshal(raw, &st) != nil {
					continue
				}
				for cid, info := range st.Challenges {
					lowReason := strings.ToLower(info.LastReason)
					isBroken := info.EnvBroken || strings.Contains(lowReason, "env-broken") || strings.Contains(lowReason, "env_broken")
					if info.SolvedAt != nil || isBroken {
						resolved[strings.ToLower(strings.TrimSpace(cid))] = true
					}
				}
			}
		}
	}
	// 2. Check met goals or explicitly solved benchmark findings in ExplorationStore.
	if ts != nil {
		if findings, err := ts.ListByKind(db.KindFinding, 200); err == nil {
			for _, f := range findings {
				var fp struct {
					Summary string `json:"summary"`
					Target  string `json:"target_id"`
				}
				if json.Unmarshal(f.Payload, &fp) != nil {
					continue
				}
				low := strings.ToLower(fp.Summary)
				if strings.Contains(low, "all_flags_solved") || strings.Contains(low, "满分攻破") || strings.Contains(low, "已提交全部") {
					if fp.Target != "" {
						resolved[strings.ToLower(strings.TrimSpace(fp.Target))] = true
					}
				}
			}
		}
	}
	return resolved
}

// renderPlaybookTail appends L0 PLAYBOOK.json at the TAIL of the planner wake-up
// user message (Path A: static prefix untouched, fresh playbook attached to the
// trailing event snapshot).
func renderPlaybookTail(pb Playbook, pruned []string) string {
	empty := pb.Phase == "" && len(pb.GlobalRules) == 0 && len(pb.Hypotheses) == 0 && pb.SharedIndex == ""
	if empty {
		return "\n\n【L0 战术剧本 PLAYBOOK.json（当前为空，硬上限 2.5KB）】：{}\n提示：进入多轮攻坚/发现跨目标规律或需跟踪未解高价值假设时，可用 update_playbook 维护 phase / global_rules / hypotheses（严禁写流水账；无确定性反证禁标 disproved）。"
	}
	b, err := json.Marshal(pb)
	if err != nil {
		return ""
	}
	note := ""
	if len(pruned) > 0 {
		note = fmt.Sprintf("（运行时已自动清理已解决/环境异常目标：%s）", strings.Join(pruned, ", "))
	}
	return fmt.Sprintf("\n\n【L0 战术剧本 PLAYBOOK.json（尾挂态，硬上限 2.5KB；用 update_playbook 增量维护）%s】：\n%s", note, string(b))
}

type playbookUpdateInput struct {
	Phase            *string              `json:"phase"`
	GlobalRules      *[]string            `json:"global_rules"`
	AddRules         []string             `json:"add_rules"`
	RemoveRules      []string             `json:"remove_rules"`
	UpsertHypotheses []PlaybookHypothesis `json:"upsert_hypotheses"`
	RemoveTargets    []string             `json:"remove_targets"`
}

func applyPlaybookUpdate(pb *Playbook, in playbookUpdateInput) {
	if in.Phase != nil {
		pb.Phase = strings.TrimSpace(*in.Phase)
	}
	if in.GlobalRules != nil {
		pb.GlobalRules = append([]string(nil), (*in.GlobalRules)...)
	}
	if len(in.RemoveRules) > 0 && len(pb.GlobalRules) > 0 {
		drop := map[string]bool{}
		for _, r := range in.RemoveRules {
			if s := strings.ToLower(strings.TrimSpace(r)); s != "" {
				drop[s] = true
			}
		}
		kept := pb.GlobalRules[:0]
		for _, r := range pb.GlobalRules {
			if !drop[strings.ToLower(strings.TrimSpace(r))] {
				kept = append(kept, r)
			}
		}
		pb.GlobalRules = kept
	}
	for _, r := range in.AddRules {
		if s := strings.TrimSpace(r); s != "" {
			pb.GlobalRules = append(pb.GlobalRules, s)
		}
	}
	if len(in.RemoveTargets) > 0 && len(pb.Hypotheses) > 0 {
		drop := map[string]bool{}
		for _, t := range in.RemoveTargets {
			if s := strings.ToLower(strings.TrimSpace(t)); s != "" {
				drop[s] = true
			}
		}
		kept := make([]PlaybookHypothesis, 0, len(pb.Hypotheses))
		for _, h := range pb.Hypotheses {
			if !drop[strings.ToLower(strings.TrimSpace(h.TargetID))] {
				kept = append(kept, h)
			}
		}
		pb.Hypotheses = kept
	}
	for _, up := range in.UpsertHypotheses {
		tkey := strings.ToLower(strings.TrimSpace(up.TargetID))
		pkey := strings.ToLower(strings.TrimSpace(up.Path))
		matched := false
		for i := range pb.Hypotheses {
			if strings.ToLower(strings.TrimSpace(pb.Hypotheses[i].TargetID)) == tkey &&
				strings.ToLower(strings.TrimSpace(pb.Hypotheses[i].Path)) == pkey {
				pb.Hypotheses[i].Status = up.Status
				if strings.TrimSpace(up.EvidenceRef) != "" {
					pb.Hypotheses[i].EvidenceRef = up.EvidenceRef
				}
				matched = true
				break
			}
		}
		if !matched {
			pb.Hypotheses = append(pb.Hypotheses, up)
		}
	}
}

func (t *ToolSet) updatePlaybookTool() actool.CoreTool {
	return t.writeExpTool("update_playbook",
		"维护本任务的 L0 强结构化战术剧本 PLAYBOOK.json（硬上限 2.5KB，禁止写流水账）。仅允许维护 3 个可写字段（第 4 个字段 shared_index 由运行时自动生成、只读）：\n"+
			"1. phase：当前阶段与调度节奏（如 sweep / deep_push / salvage）；\n"+
			"2. global_rules（上限 8 条）：本场运行期热补丁规则（如故障渠道避让、专项提交策略、跨目标共性 WAF 规则）；\n"+
			"3. hypotheses（每 target_id 最多 5 条）：跟踪未解高价值目标/题目的关键路径假设，严格区分 active / disproved / inconclusive；标 disproved 必须给确定性反证 evidence_ref（如 fact#ID / 代码拦截点），弱模型超时未果只能标 inconclusive；目标已解决/封矿/env_broken 请用 remove_targets 及时清理释放 2.5KB 配额。",
		obj(map[string]any{
			"phase":        str("可选：更新当前阶段与调度节奏，如 sweep / deep_push / salvage"),
			"global_rules": map[string]any{"type": "array", "maxItems": playbookMaxRules, "items": map[string]any{"type": "string"}, "description": "可选：整体替换全局热补丁规则（最多 8 条）"},
			"add_rules":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：增量追加全局热补丁规则"},
			"remove_rules": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：按精确文本移除过期规则"},
			"upsert_hypotheses": map[string]any{
				"type":        "array",
				"description": "可选：按 (target_id, path) 新增或更新假设状态（每 target_id 最多 5 条）",
				"items": obj(map[string]any{
					"target_id":    str("目标/题目/核心域名标识，如 bctf2026-08 或 creator.douyin.com"),
					"path":         str("一句精炼机理假设（禁止流水账）"),
					"status":       map[string]any{"type": "string", "enum": []string{HypothesisActive, HypothesisDisproved, HypothesisInconclusive}, "description": "active(进行中) | disproved(有确定性反证) | inconclusive(超时/未决)"},
					"evidence_ref": str("证据引用（fact#ID / intent#ID / 代码位置）；status=disproved 时必填确定性反证"),
				}, "target_id", "path", "status"),
			},
			"remove_targets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：清理已解决、已封矿或 env_broken 的 target_id 对应全部假设"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if strings.TrimSpace(t.playbookTaskDir) == "" {
				return actool.Errorf("update_playbook 当前不可用：未配置任务工作目录"), nil
			}
			var req playbookUpdateInput
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			p := playbookPath(t.playbookTaskDir)
			unlock := lockPlaybookPath(p)
			defer unlock()

			pb, err := loadPlaybookUnlocked(p)
			if err != nil {
				pb = Playbook{}
			}
			applyPlaybookUpdate(&pb, req)
			pb.SharedIndex = BuildSharedIndex(t.playbookWorkDir, t.playbookTaskDir)
			if err := ValidatePlaybook(&pb); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := savePlaybookUnlocked(p, pb); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			raw, _ := json.Marshal(pb)
			return jsonResult(map[string]any{
				"ok":       true,
				"bytes":    len(raw),
				"cap":      playbookMaxBytes,
				"playbook": pb,
			})
		})
}
