# Supervisor 督战调度、模型分级与防黑板污染

本方案将原有只读建议型 `chain_reviewer` 升级为具备受控执行权的 **Supervisor**，同时在 Worker 写入与启动路径补齐代码级防幻觉门禁与同资产实时共享，不引入额外常驻进程或重型跨任务检索 Agent。

## 1. Supervisor 四把钥匙（原生 Go 工具）

工具白名单在 `agent/chain_review_policy.go` 强制约束（与提示词解耦），继续禁止 `Bash`、`Read`、`Write`、`WebFetch` 等直接接触目标或宿主机文件的工具；原有 `chain_review_snapshot` / `chain_review_publish` 保持向后兼容。

| 工具 | 作用 | 代码位置 |
| --- | --- | --- |
| `supervisor_board` | 紧凑全局态势板：活跃任务意图计数、运行中意图的零成本探针告警（空转/连错/循环/长跑无产出）、近期失败意图、待核验事实与可用 LLM Profile 目录 | `server/supervisor_tools.go`、`server/supervisor_probe.go` |
| `supervisor_inspect` | 按 `intent_id` / `node_id` / `activity_id` 有界下钻原始轨迹与证据原文（先核查再止损/撤回） | `server/supervisor_tools.go` |
| `supervisor_kill_intent` | 止损终止 `running` / `open` / `paused` 意图（`stopped`）并记录审计活动 | `server/supervisor_tools.go`、`server/engine.go` |
| `supervisor_dispatch_intent` | 重派意图并支持 `pinned_profile_id` 主动模型分级（升档强模型 / 跨厂商破局 / 降回快模型），可选 `replace_intent_id` 一步替换旧意图 | `server/supervisor_tools.go`、`server/engine.go` |
| `supervisor_retract_fact` | 将幻觉/假阳性事实标为 `retracted` 或 `disputed`（保留历史审计），默认沿 `derived_from` 级联终止依赖它的活跃下游意图 | `server/supervisor_tools.go`、`db/supervisor.go` |
| `supervisor_steer_worker` | 通过 `Engine.SteerWork` 向在跑 Worker 实时注入情报或纠偏，可选同步落盘为同资产共享备注 | `server/supervisor_tools.go` |
| `supervisor_record_asset_note` | 写入锚定到 `asset_ids` 的共享备注，后续同资产新 Worker 自动注入 | `server/supervisor_tools.go`、`db/supervisor.go` |

## 2. Intent 级主动模型分级

- `supervisor_dispatch_intent` 校验 `pinned_profile_id` 有效后写入 `intent.payload.pinned_profile_id`。
- `Engine.runWorkerStep` 与 `Engine.runDetachedIntent` 在认领/恢复该意图时优先通过 `workerResolve(t, WorkerSlot{ProfileID: pinnedID})` 走对应的 `pinnedWorkers[profileID]`；未指定时保持原有任务/槽位路由不变。

## 3. 写入口防幻觉门禁与撤回传播阻断

- `record_fact` 新增可选 `evidence_activity_id`（校验归属本探索）和 `asset_note`。
- `classifyFactInitialState` 对声称 `observed` 或高影响结论（如鉴权绕过、越权、未授权访问、有效凭据等）但缺少文本 `evidence` 且无有效非错误 `evidence_activity_id` 的事实，自动降级为 `unverified` 写入。
- `graph_overview` 自动过滤 `retracted` 事实并显式标注 `unverified` / `disputed` 状态；`add_intent` 拒绝以 `retracted` 事实作为 `parent_ids`。

## 4. 资产级实时共享与确定性短避坑卡（Push）

- `Worker.execute` 在装配系统提示时，自动查询本任务 `AssetNotesForAssets(intentAssetIDs)` 并注入同资产实时共享备注（`confirmed` 且排除 `retracted` / `disputed`）。
- `agent/pitfall_cards.go` 按目标资产指纹、技术栈与意图文本做确定性匹配（内置轻量核验卡，并支持从 `<workDir>/pitfall-cards/*.json` 扩展自定义 JSON 卡片），最多推送 3 条，零模型调用开销。
