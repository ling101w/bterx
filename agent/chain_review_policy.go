package agent

import (
	"context"
	"github.com/Autumn-27/norma/hook"
	actool "github.com/Autumn-27/norma/tool"
)

const ChainReviewerKey = "chain_reviewer"

var supervisorAllowedTools = map[string]bool{
	"chain_review_snapshot":        true,
	"chain_review_publish":         true,
	"supervisor_board":             true,
	"supervisor_inspect":           true,
	"supervisor_kill_intent":       true,
	"supervisor_dispatch_intent":   true,
	"supervisor_retract_fact":      true,
	"supervisor_steer_worker":      true,
	"supervisor_record_asset_note": true,
}

func chainReviewHooks() *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, ev hook.Event) hook.Result {
		if !supervisorAllowedTools[ev.ToolName] {
			return hook.Result{Decision: "block", Message: "Supervisor/链路复盘只允许使用受控督战与复盘工具，禁止直接执行命令或访问目标。"}
		}
		return hook.Result{}
	})
}

// Enforce the supervisor/report surface independently of the model's prompt.
func chainReviewTools(key string, tools []actool.CoreTool) []actool.CoreTool {
	if key != ChainReviewerKey {
		return tools
	}
	var out []actool.CoreTool
	for _, t := range tools {
		if supervisorAllowedTools[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}
