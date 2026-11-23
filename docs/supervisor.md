# 统一任务指挥官（Planner + Supervisor 合体）、主动模型分级与防黑板污染

面向高度仿真的企业 SRC 漏洞挖掘场景，本方案将单任务内的**进攻规划**与**督战调度（止损、模型分级、打假撤回、同资产情报共享）**收拢到同一个大脑（**升级后的 `planner` / Task Commander**），消除双头指挥冲突与重复上下文损耗；同时保留跨任务 `supervisor_*` 工具供按需多任务巡检使用。

## 1. 为什么合体（单任务唯一指挥官）

- **零双头冲突**：同一大脑统筹派发（`add_intent`）、实时纠偏（`steer_work`）、止损（`kill_work`）与撤回（`retract_fact`），不会出现“督战刚杀、规划又重派”的拉锯。
- **事件驱动分级止损探针**：Go 引擎层内置零成本内存探针（`server/supervisor_probe.go`），使用完整参数 SHA-256 哈希防长命令前缀误判，并自动忽略 502/503/429/超时等瞬态抖动及 `grep` exit 1；3~4 次连错仅作为被动指标 `error_streak` 展示不打断，只有**完全一致调用连续 ≥5 次（`repeated_tool_loop`）**或**过 90 秒预热期后连续 ≥5 次非瞬态硬错误（`consecutive_errors`）**才带 3 分钟冷却通过 `Task.NotifyProbeAlert` 主动唤醒 Planner。
- **Sapper 式分层黑板 + 悬空线索配额 + 墓碑机制**：`graph_overview` 新增 L1 `chain_view`（按主资产展示真实 `label`/技术栈、`stage` 探索深度、`related_assets` 跨资产血缘、探针告警与墓碑），并采用三桶配额（告警/待核验 ≤4、**悬空线索/未测资产固定预留 ≤4**、近期活跃补足至 12），防止新扫出的高价值入口被老分支挤出视野；同时显式保留 `recent_stopped_intents` 与 `retracted_facts` 墓碑。
- **防 Benchmark 偷懒早停**：当目标未达成且队列为空时，`planner_decision` 会校验是否仍有未测资产、待核验事实或未升级强模型重试的 `exhausted/blocked` 意图；存在具体待推进线索时首轮直接拒绝早停，避免无人值守跑分中空等心跳。

## 2. Task Commander（Planner）新增能力

白名单在 `agent/planner_policy.go` 强制收敛，依然严禁 Planner 直接执行命令、读写目标或联网。

| 能力 | 工具 / 字段 | 代码位置 |
| --- | --- | --- |
| 主动模型分级 | `add_intent(..., pinned_profile_id, model_reason)` + `list_llm_profiles`（且多档位时自动折入 `graph_overview.llm_profiles`） | `agent/tools.go`、`server/engine.go`、`server/supervisor_probe.go` |
| 止损留墓碑 | `kill_work(intent_id, reason)` 支持终止运行中或排队/暂停意图，并将 `reason` 写入 `delete_reason` 墓碑 | `agent/tools.go`、`db/supervisor.go` |
| 防幻觉撤回 + 级联止损 | `retract_fact(fact_id, state, reason, evidence_activity_id, cascade_stop_intents)` 将假阳性标为 `retracted` / `disputed` 并自动停掉下游活跃意图 | `agent/commander.go`、`db/supervisor.go` |
| 实时情报搬运 + 资产共享 | `steer_work(..., also_asset_note, asset_ids)` 与 `record_asset_note(asset_ids, summary, detail)` | `agent/tools.go`、`agent/commander.go` |
| 零成本运行期探针 | `running_intents` 自动附加 `running_seconds`、`idle_seconds`、`consecutive_errors`、`repeated_tool_calls`、`alerts` 并异常自动唤醒 | `server/supervisor_probe.go`、`server/engine.go`、`server/manager.go` |

## 3. Intent 级主动模型路由

- `add_intent` 校验 `pinned_profile_id` 有效后写入 `intent.payload.pinned_profile_id`。
- `Engine.runWorkerStep` 与 `Engine.runDetachedIntent` 认领/恢复意图时优先通过 `workerResolve(t, WorkerSlot{ProfileID: pinnedID})` 走对应的 `pinnedWorkers[profileID]`；常规意图留空 `pinned_profile_id` 继续走默认快模型。

## 4. 写入口防幻觉门禁与撤回传播阻断

- `record_fact` 新增可选 `evidence_activity_id`（校验归属本探索）和 `asset_note`。
- `classifyFactInitialState` 对声称 `observed` 或高影响结论（如鉴权绕过、越权、未授权访问、有效凭据等）但缺少文本 `evidence` 且无有效非错误 `evidence_activity_id` 的事实，自动降级为 `unverified`。
- `graph_overview` 过滤 `retracted` 事实（仅在 `retracted_facts` 与 `chain_view.tombstones` 留墓碑），显式标注 `unverified` / `disputed`；`add_intent` 拒绝以 `retracted` 事实作为 `parent_ids`。

## 5. 同资产实时共享与确定性短避坑卡（Push）

- `Worker.execute` 在装配系统提示时，自动查询本任务 `AssetNotesForAssets(intentAssetIDs)` 并注入同资产实时共享备注（`confirmed` 且排除 `retracted` / `disputed`）。
- `agent/pitfall_cards.go` 按目标资产指纹、技术栈与意图文本做确定性匹配（内置轻量核验卡，并支持从 `<workDir>/pitfall-cards/*.json` 扩展自定义 JSON 卡片），最多推送 3 条，零模型调用开销。

## 6. 跨任务只读/督战工具（可选）

`server/supervisor_tools.go` 保留 `supervisor_board` / `supervisor_inspect` 等 7 个跨任务原生工具并绑定给 `chain_reviewer`。单任务场景下由合体后的 `planner` 独立负责，无需开启定时 `chain_reviewer`；多任务并行时可按需启用作跨任务总览与协调。
