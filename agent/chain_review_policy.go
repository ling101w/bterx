package agent

import (
	"context"
	"github.com/Autumn-27/norma/hook"
	actool "github.com/Autumn-27/norma/tool"
)

const ChainReviewerKey = "chain_reviewer"

func chainReviewHooks() *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, ev hook.Event) hook.Result {
		if ev.ToolName != "chain_review_snapshot" && ev.ToolName != "chain_review_publish" {
			return hook.Result{Decision: "block", Message: "链路复盘只允许读取有限快照和发布报告，请使用这两个工具。"}
		}
		return hook.Result{}
	})
}

// Enforce the report-only surface independently of the model's prompt.
func chainReviewTools(key string, tools []actool.CoreTool) []actool.CoreTool {
	if key != ChainReviewerKey {
		return tools
	}
	var out []actool.CoreTool
	for _, t := range tools {
		if t.Name() == "chain_review_snapshot" || t.Name() == "chain_review_publish" {
			out = append(out, t)
		}
	}
	return out
}
