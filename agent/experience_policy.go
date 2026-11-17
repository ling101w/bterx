package agent

import (
	"context"
	"github.com/Autumn-27/norma/hook"
	actool "github.com/Autumn-27/norma/tool"
)

const ExperienceCuratorKey = "experience_curator"
const ExperienceRetrieverKey = "experience_retriever"

type experienceRunKey struct{}
type ExperienceRunScope struct {
	ID             string
	ConversationID int64
}

func WithExperienceRun(ctx context.Context, id string, conversationID int64) context.Context {
	return context.WithValue(ctx, experienceRunKey{}, ExperienceRunScope{id, conversationID})
}
func ExperienceRunFrom(ctx context.Context) ExperienceRunScope {
	v, _ := ctx.Value(experienceRunKey{}).(ExperienceRunScope)
	return v
}
func experienceAgent(key string) bool {
	return key == ExperienceCuratorKey || key == ExperienceRetrieverKey
}
func experienceToolAllowed(key, name string) bool {
	if key == ExperienceCuratorKey {
		return name == "experience_publish"
	}
	if key == ExperienceRetrieverKey {
		return name == "experience_search" || name == "experience_get" || name == "experience_stats"
	}
	return true
}
func experienceTools(key string, tools []actool.CoreTool) []actool.CoreTool {
	if !experienceAgent(key) {
		return tools
	}
	var out []actool.CoreTool
	for _, tool := range tools {
		if experienceToolAllowed(key, tool.Name()) {
			out = append(out, tool)
		}
	}
	return out
}
func experienceHooks(key string) *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, ev hook.Event) hook.Result {
		if !experienceToolAllowed(key, ev.ToolName) {
			return hook.Result{Decision: "block", Message: "经验角色只能处理已有资料，当前工具不在该角色白名单。"}
		}
		return hook.Result{}
	})
}

// Publication identity is host-owned; a model cannot address a foreign batch.
func BindExperiencePublication(ctx context.Context, input map[string]any) {
	scope := ExperienceRunFrom(ctx)
	delete(input, "_host_conversation_id")
	delete(input, "_host_run_id")
	input["run_id"] = scope.ID
	input["_host_run_id"] = scope.ID
	input["_host_conversation_id"] = scope.ConversationID
}
