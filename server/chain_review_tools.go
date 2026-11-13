package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// The reviewer can only read a bounded snapshot and publish advisory reports.
// Execution intents remain the planner's responsibility.
func (s *Server) runChainReviewHelper(ctx context.Context, mode string, params map[string]any) ([]byte, error) {
	params["_mode"] = mode
	interp := s.pythonInterpreter()
	if interp == "" {
		return nil, fmt.Errorf("链路复盘需要 Python 解释器")
	}
	code := "import sys\nsys.path.insert(0, '/home/maming/apps/artex-chain-review')\nimport review_runtime\nreview_runtime.main()\n"
	body, err := execPython(ctx, interp, "chain_review_"+mode, code, params, s.m.dir, nil, 45*time.Second)
	if err != nil {
		return nil, fmt.Errorf("复盘辅助程序不可用")
	}
	var result struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &result) != nil {
		return nil, fmt.Errorf("复盘辅助程序返回格式无效")
	}
	if result.Error != "" {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return []byte(body), nil
}

func (s *Server) toolChainReviewSnapshot() actool.CoreTool {
	return roTool("chain_review_snapshot", "读取正在运行任务的有限证据快照。自动跳过暂停、排队、终态和近期已复盘任务；每次最多两个任务。只读已有节点与执行记录，不访问目标。每轮只调用一次。", objSchema(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			ids := []string{}
			for _, t := range s.m.List() {
				st := t.lifecycleSnapshot()
				if st.Paused || st.Queued || isTerminalStatus(st.Status) || s.engine.IsDeleting(t.ID) {
					continue
				}
				if open, err := t.Store.HasOpenGoal(); err == nil && open {
					ids = append(ids, t.ID)
				}
			}
			body, err := s.runChainReviewHelper(ctx, "snapshot", map[string]any{"task_ids": ids})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(string(body)), nil
		})
}

func (s *Server) toolChainReviewPublish() actool.CoreTool {
	item := objSchema(map[string]any{
		"source_node_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		"evidence_activity_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		"direction":             strParam("方向；仅限已有证据"), "reason": strParam("证据与去重依据"),
		"next_step":  strParam("提交 planner 核对的有限下一步"),
		"priority":   map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
		"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"outcome":    strParam("剪枝项：duplicate / tested_negative / await_prerequisite"),
		"reopen_if":  strParam("剪枝项必填：重新开启所需的新证据或前提"),
	}, "source_node_ids", "evidence_activity_ids", "reason")
	report := objSchema(map[string]any{
		"task_id": map[string]any{"type": "integer"}, "summary": strParam("复盘摘要"),
		"suggestions":         map[string]any{"type": "array", "maxItems": 2, "items": item},
		"pruning":             map[string]any{"type": "array", "maxItems": 4, "items": item},
		"needs_more_evidence": map[string]any{"type": "array", "maxItems": 4, "items": item},
		"dismissed":           map[string]any{"type": "array", "maxItems": 4, "items": item},
	}, "task_id", "summary", "suggestions", "pruning", "needs_more_evidence", "dismissed")
	schema := objSchema(map[string]any{"snapshot_id": strParam("chain_review_snapshot 返回的编号"),
		"reports": map[string]any{"type": "array", "minItems": 1, "maxItems": 2, "items": report}}, "snapshot_id", "reports")
	return wrTool("chain_review_publish", "校验同任务节点和执行记录引用，保存中文复盘报告，将精简建议交给仍在运行的任务 planner。只添加建议，不删历史、不创建执行意图、不修改目标。", schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var params map[string]any
			if json.Unmarshal(in, &params) != nil {
				return actool.Errorf("无效报告参数"), nil
			}
			body, err := s.runChainReviewHelper(ctx, "publish", params)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var saved struct {
				Duplicate bool `json:"duplicate"`
				Reports   []struct {
					TaskID       string `json:"task_id"`
					ReportID     string `json:"report_id"`
					MarkdownPath string `json:"markdown_path"`
					Handoff      string `json:"handoff"`
				} `json:"reports"`
			}
			if json.Unmarshal(body, &saved) != nil {
				return actool.Errorf("保存报告返回格式无效"), nil
			}
			results := []map[string]any{}
			for _, r := range saved.Reports {
				row := map[string]any{"task_id": r.TaskID, "report_id": r.ReportID, "markdown_path": r.MarkdownPath, "handoff": "skipped"}
				t := s.m.ResolveTask(r.TaskID)
				if t != nil && r.Handoff != "" && !s.engine.IsDeleting(t.ID) {
					st := t.lifecycleSnapshot()
					if !st.Paused && !st.Queued && !isTerminalStatus(st.Status) {
						// Persist as a hint, never as a fact or an executable intent.
						n, err := t.Store.AddNode(db.KindHint, map[string]any{"text": r.Handoff,
							"chain_review_report_id": r.ReportID, "advisory_only": true}, 0, "active", "chain_reviewer", nil)
						if err == nil {
							t.NotifyHint([]string{r.Handoff})
							row["hint_id"] = n
							row["handoff"] = "planner_notified"
							s.engine.emitActivity(t, db.Activity{Worker: "chain_reviewer", Kind: "text",
								Summary: "链路复盘报告 " + r.ReportID + " 已保存并交给 planner 核对", Detail: r.Handoff})
						} else {
							row["handoff"] = "hint_write_failed"
						}
					}
				}
				results = append(results, row)
			}
			return jsonResult(map[string]any{"duplicate": saved.Duplicate, "reports": results,
				"note": "报告已保存。planner 仍负责核对候选和派发，交接不等于已接受或已执行。"})
		})
}
