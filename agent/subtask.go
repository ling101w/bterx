package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	SubtaskToolName              = "delegate_subtask"
	subtaskMaxCallsPerIntent     = 3
	subtaskMinTimeoutSeconds     = 60
	subtaskDefaultTimeoutSeconds = 180
	subtaskMaxTimeoutSeconds     = 300
	subtaskMaxTurns              = 12
	subtaskMaxOutputRunes        = 2400
)

// SubtaskRequest defines a bounded 1-level synchronous helper delegation from a
// Worker to a short-lived sub-worker. The sub-worker runs inside the parent
// intent's workspace under the exact same Guard/Interceptor, cannot spawn
// further sub-workers, cannot mutate the exploration graph directly, and
// returns a compact summary so the parent keeps its context clean.
type SubtaskRequest struct {
	Role           string `json:"role"`
	Task           string `json:"task"`
	ReadOnly       bool   `json:"read_only"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// SubtaskRunner executes one bounded synchronous sub-worker request.
type SubtaskRunner func(ctx context.Context, req SubtaskRequest) (string, error)

// SetSubtaskRunner installs the per-intent delegate_subtask implementation.
func (t *ToolSet) SetSubtaskRunner(fn SubtaskRunner) { t.subtaskRunner = fn }

// SetSubtaskProvider configures an optional fast/cheap provider (e.g. default
// Flash model) used by delegate_subtask sub-workers so heavy side-jobs like JS
// bundle analysis or log parsing stay fast and inexpensive. nil falls back to
// the parent Worker's own provider.
func (w *Worker) SetSubtaskProvider(fn func() (llm.Provider, string)) { w.subtaskProvFn = fn }

func normalizeSubtaskRole(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	var b strings.Builder
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		} else if r == ' ' || r == '/' {
			b.WriteByte('_')
		}
		if b.Len() >= 32 {
			break
		}
	}
	s := strings.Trim(b.String(), "_-")
	if s == "" {
		return "helper"
	}
	return s
}

func clampSubtaskTimeout(sec int) time.Duration {
	if sec <= 0 {
		sec = subtaskDefaultTimeoutSeconds
	}
	if sec < subtaskMinTimeoutSeconds {
		sec = subtaskMinTimeoutSeconds
	}
	if sec > subtaskMaxTimeoutSeconds {
		sec = subtaskMaxTimeoutSeconds
	}
	return time.Duration(sec) * time.Second
}

// subtaskTools builds a strictly 1-level execution toolset: no delegate_subtask
// (impossible to fork-bomb), no graph write tools (parent owns all graph writes).
func subtaskTools(readOnly bool) []actool.CoreTool {
	if readOnly {
		return defaultToolsExcept("MultiEdit", "Glob", "Grep", "Write", "Edit")
	}
	return defaultToolsExcept("MultiEdit", "Glob", "Grep")
}

func subtaskSystemPrompt(role, runDir, proxyAddr, constraintText string, readOnly bool) string {
	var sb strings.Builder
	sb.WriteString("你是渗透测试主 Worker 临时委派的 1 层短命副手（角色：")
	sb.WriteString(role)
	sb.WriteString("）。\n")
	sb.WriteString("你的唯一职责：在有限步数与时间内高效完成主 Worker 交给你的这一项具体子任务，然后返回精炼、带直接证据（文件路径、行号、命令关键输出、提取出的接口/签名/结论）的中文汇总。\n")
	sb.WriteString("严格边界：\n")
	sb.WriteString("1. 你没有图谱写回权限，也禁止发散探索任务之外的方向；把结论交给主 Worker 由它复核落库。\n")
	sb.WriteString("2. 优先用脚本/命令行精准过滤提取，禁止把大段源码/HTML 原样倾倒进回复。\n")
	if readOnly {
		sb.WriteString("3. 当前为只读模式（read_only=true）：禁止修改或写入任何文件。\n")
	} else {
		sb.WriteString("3. 如需保存临时脚本或结果文件，一律写到工作目录 " + runDir + " 下，禁止写 /tmp。\n")
	}
	if proxyAddr != "" {
		sb.WriteString("4. 目标 HTTP 流量已通过环境变量默认走记录代理 " + proxyAddr + "。\n")
	}
	if strings.TrimSpace(constraintText) != "" {
		sb.WriteString(constraintText)
	}
	return sb.String()
}

func finalizeSubtaskOutput(runDir string, callNum int, role, raw string) (summary, artifactPath string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "(副手未产出文本结论)", ""
	}
	runes := []rune(raw)
	if len(runes) <= subtaskMaxOutputRunes {
		return raw, ""
	}
	summary = string(runes[:subtaskMaxOutputRunes]) + "\n…[已截断，完整结果见 artifact_path]"
	if runDir != "" {
		dir := filepath.Join(runDir, ".subtasks")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			p := filepath.Join(dir, fmt.Sprintf("sub-%d-%s.md", callNum, role))
			if err := os.WriteFile(p, []byte(raw), 0o644); err == nil {
				artifactPath = p
			}
		}
	}
	return summary, artifactPath
}

func (t *ToolSet) delegateSubtask() actool.CoreTool {
	return t.writeExpTool(SubtaskToolName,
		"同步委派一个 1 层短命副手（独立上下文、最多 12 轮、60~300 秒、每意图最多调用 3 次）处理会撑爆主上下文的专项脏活，例如：反编译/检索大型 JS bundle、分析长日志、解析协议/提取签名算法、批量只读探活。副手共享本意图工作目录与全部安全拦截规则，不修改探索图、不能套娃再开副手，完成后返回精炼结论给你复核落库。",
		obj(map[string]any{
			"role":            str("副手角色名（如 js_auditor / recon_scout / log_parser / code_auditor / poc_helper）"),
			"task":            str("清晰、自包含的子任务说明：要处理哪些文件/目标、具体要回答什么问题、期望返回什么格式的证据"),
			"read_only":       map[string]any{"type": "boolean", "description": "可选：true 时仅开放只读工具（禁用 Write/Edit），适合纯代码审计/日志分析"},
			"timeout_seconds": intp("可选：子任务超时秒数（60~300，默认 180），同时受主意图剩余时间夹逼"),
		}, "role", "task"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.subtaskRunner == nil {
				return actool.Errorf("当前运行模式未启用 delegate_subtask 副手能力"), nil
			}
			var req SubtaskRequest
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf(fmt.Sprintf("delegate_subtask 参数解析失败: %v", err)), nil
			}
			req.Role = normalizeSubtaskRole(req.Role)
			req.Task = strings.TrimSpace(req.Task)
			if req.Task == "" {
				return actool.Errorf("task 不能为空：请给出具体、自包含的子任务说明"), nil
			}
			out, err := t.subtaskRunner(ctx, req)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("副手执行失败: %v", err)), nil
			}
			return actool.Text(out), nil
		})
}

func (w *Worker) newSubtaskRunner(parentName string, intentID int64, runDir, proxyAddr, constraintText string, hooks harness.HookRunner, emit func(db.Activity)) SubtaskRunner {
	var used atomic.Int32
	return func(ctx context.Context, req SubtaskRequest) (string, error) {
		n := int(used.Add(1))
		if n > subtaskMaxCallsPerIntent {
			used.Add(-1)
			return "", fmt.Errorf("本意图 delegate_subtask 调用已达上限（%d 次），请直接使用已有结果完成主意图", subtaskMaxCallsPerIntent)
		}
		role := normalizeSubtaskRole(req.Role)
		timeout := clampSubtaskTimeout(req.TimeoutSeconds)
		subCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		subCtx = intercept.WithReviewContext(subCtx, runDir, intercept.ReviewBackground{})

		prov, model := w.prov, w.model
		if w.subtaskProvFn != nil {
			if fp, fm := w.subtaskProvFn(); fp != nil {
				prov = fp
				if fm != "" {
					model = fm
				}
			}
		}
		if prov == nil {
			return "", fmt.Errorf("无可用的副手 LLM Provider")
		}

		subWorkerLabel := fmt.Sprintf("%s/sub:%s#%d", parentName, role, n)
		emitSub := func(r db.Activity) {
			if emit != nil {
				nid := intentID
				r.NodeID, r.Worker = &nid, subWorkerLabel
				emit(r)
			}
		}
		emitSub(db.Activity{
			Kind:    "text",
			Summary: fmt.Sprintf("启动副手 [%s] (%d/%d, 上限 %ds)", role, n, subtaskMaxCallsPerIntent, int(timeout.Seconds())),
			Detail:  req.Task,
		})

		opts := agentcore.Options{
			Provider:       prov,
			SystemPrompt:   []string{subtaskSystemPrompt(role, runDir, proxyAddr, constraintText, req.ReadOnly)},
			Tools:          subtaskTools(req.ReadOnly),
			PermissionMode: permission.ModeBypass,
			EnableWebFetch: true,
			WebFetchProxy:  proxyAddr,
			WebFetchCACert: w.proxyCACert,
			BashEnv:        proxyEnv(proxyAddr, w.proxyCACert),
			WorkingDir:     runDir,
			MaxTurns:       subtaskMaxTurns,
			MaxDuration:    timeout,
			ToolOutputDir:  cmdOutDir(runDir),
			Compaction:     compactionConfig(w.compactionWindow()),
			NonStreaming:   w.nonStreaming(),
			MaxTokens:      w.maxTokens(),
		}
		if hooks != nil {
			opts.Hooks = hooks
		}

		started := time.Now()
		sess := agentcore.NewSession(opts)
		defer sess.Close()
		finalText, reason, runErr := captureRunSession(subCtx, sess, req.Task, emitSub)
		durMs := time.Since(started).Milliseconds()
		summary, artifactPath := finalizeSubtaskOutput(runDir, n, role, finalText)

		res := map[string]any{
			"ok":              runErr == nil,
			"role":            role,
			"model":           model,
			"reason":          string(reason),
			"duration_ms":     durMs,
			"calls_used":      n,
			"calls_remaining": max(0, subtaskMaxCallsPerIntent-n),
			"summary":         summary,
		}
		if artifactPath != "" {
			res["artifact_path"] = artifactPath
		}
		if runErr != nil {
			res["error"] = runErr.Error()
		}
		b, _ := json.Marshal(res)
		return string(b), nil
	}
}
