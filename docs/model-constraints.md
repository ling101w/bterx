# 模型在什么位置受到约束

以下主体为11月13日基线说明。v5增加了经验角色在工具装配和PreToolUse阶段的硬白名单、宿主控制的整理run、意图经验版本/范围/新鲜度检查，以及真实执行结果的关联。经验Agent不再带SDK默认执行工具；详见[memory-v5.md](memory-v5.md)。这些仍不验证所有fact的语义真值。

约束分三类：**硬控制**由代码在执行前后检查；**可配置策略**依赖管理员启用和选择；**提示词要求**依赖模型遵守。记录或引用存在，并不等于模型的语义结论已经验证。

## 各阶段控制表

| 位置 | 约束 | 类型 | 实现与边界 |
| --- | --- | --- | --- |
| Agent工具装配 | 按enabled、绑定Agent、skill/MCP可见性过滤或延迟提供工具 | 可配置+代码检查 | `server/assembly.go`、`agent/assembly.go`。读取工具配置失败时部分路径保留默认工具，不是统一fail-closed |
| Planner工具装配 | 只允许图证据、派活、目标、干预和经验工具 | 硬控制 | `agent/planner_policy.go` 的 `plannerToolNames`、`plannerReadCache.wrap` |
| Planner每次动作 | PreToolUse再查白名单，SDK附加工具也不能绕过 | 硬控制 | `plannerRoundPolicy.hooks`；Bash/Read/WebFetch/shell/MCP目标访问不能通过 |
| Planner空队列读史 | 六次不同宽泛查询后要求派发或明确待补条件，定点读取仍可用 | 硬控制 | 同一hooks；不是强迫生成任意意图。Stop最多提醒一次，避免循环阻塞 |
| Planner运行预算 | 轮数、主阶段墙钟预算及任务deadline，有限收尾 | 可配置+运行时控制 | `agent/planner.go`、`taskclock.go`、`wrapup.go`。在途请求/收尾可让总时间超过主阶段 |
| 意图创建 | 校验父节点存在、类型及归属；指定资产必须可见并通过拦截 | 硬控制 | `agent/tools.go:addOneIntent`。不核验父结论真实性，不表达必要依赖ALL/ANY |
| 任务操作边界 | allow/deny约束追加到system prompt | 提示词 | `agent/constraints.go`。不是任意shell命令URL的确定性授权证明 |
| Worker动作入口 | 工具规则allow/deny/ask；无规则时可交Judge | 可配置策略 | `guard/guard.go`、`intercept/intercept.go`。规则可被管理员修改，Judge关闭/未接入时存在放行路径 |
| 工具审查 | 当前动作与脚本上下文、审批等待、超时、重试、失败策略 | 可配置+部分硬检查 | `server/intercept.go`、`intercept/scripts.go`、`shell_static.go`等。Judge负责动作许可，不验漏洞真值 |
| Worker收尾 | 预算/任务超时阶段限制新操作，写回已有成果 | 部分硬控制+提示词 | `agent/worker.go`、`wrapup.go`。worker settlement禁Bash，不能推成所有工具都被全局停用 |
| fact写入 | summary非空；intent类型和本任务归属 | 结构硬控制 | `recordOneFact`。evidence/confidence由模型提交，可选且未独立验真；直接写state=confirmed |
| finding上报 | 统一独立finding记录、探索节点、流量引用和事务写入 | 结构/引用硬控制+提示词 | `finding_recorder.go`、`finding_workflow.go`。真实触发要求仍有模型判断，reporter不会自动证明漏洞 |
| 报告保存 | 稳定证据引用、版本一致性及冲突拒绝 | 硬控制 | `db/finding_traffic.go`、`server/finding_report.go`。防止材料串号/并发过期，不验证报告语义 |
| 目标完成 | goal属于当前任务；evidence属于当前或直接来源且为fact/finding | 结构硬控制 | `prove_goal`；语义是否满足目标仍靠planner，全met会自动完成任务 |
| 链路复盘会话 | 去掉默认执行工具、禁WebFetch/搜索/后台任务；工具白名单与hook双重限制 | 硬控制 | `agent/chat.go`、`agent/chain_review_policy.go`。仅snapshot/publish |
| 复盘取证与发布 | 有界输入；同任务节点/执行引用校验、有限候选、重开条件和去重 | 硬控制+提示词 | `extensions/chain-review/review_runtime.py`；校验引用真实性，不等于判定语义真实 |
| 复盘交接 | 发布advisory hint，只有planner决定派发 | 硬控制 | `server/chain_review_tools.go`；不删除节点、不替代用户目标、不自动熔断 |
| 经验来源 | 来源版本、状态、排除表、候选租约与去重 | 硬控制 | `experience_runtime.py`；一条辅助执行记录读取失败可保留报告并标warning |
| 经验链路写入 | 必填范围/结果等字段，每步引用必须在该快照中存在 | 硬控制 | `_entry`、`publish`。引用存在不证明动作和结果的解释正确 |
| 经验方法审核 | 自动统一candidate；管理员显式review才能verified，反馈不可升级 | 硬控制 | `review_entry.py`不注册为Agent工具；管理员CLI不是操作系统安全边界 |
| 经验检索 | generic或当前任务/同公司范围；跨项目隐藏原始证据和来源任务 | 硬控制 | `search/get/_accessible`。task_id是工具入参，不是独立多租户身份认证 |
| 检索问答桥 | 固定本地ARTEX API、固定helper key、禁止重定向、限时和响应预算 | 硬控制 | `experience_retrieval.py:NativeAPI/handle`，超时只停检索会话 |
| 检索回答返回 | 必须有真实成功search结果、完整工具结果；核对任务范围、引用和当前条目可用性 | 返回前硬控制 | `collect_answer`。发现非允许工具会拒绝回答，但检查发生在调用之后，不能称全程工具沙箱 |
| 经验Agent行为 | 不执行命令、不访问目标、不接受资料中的指令、不递归ask | 提示词+工具绑定 | `extensions/experience/prompts.py`。通用ChatAgent仍可能有SDK默认文件/命令/网络工具，不具备链路复盘同等硬隔离 |
| 审计 | 活动、工具账本、模型调用、报告及版本 | 记录机制 | `agent/capture.go`、`server/tool_usage.go`、`db/llm_usage.go`。可追溯，不自动保证真实 |

## Planner的当前白名单

图与证据读取、`add_intent`、`prove_goal`、`steer_work`、`kill_work`、范围/资产相关领域工具、TodoWrite、planner_decision，以及 `ask_experience`、experience_search/get/feedback/stats。

Planner不能调用经验发布/快照，也不能直接执行Bash、文件读取、目标HTTP、交互shell或任意MCP工具。允许`ask_experience`不等于开放任意Agent调度：桥接只启动固定的experience_retriever原生会话。

## 提示词要求与事实真值

提示词要求独立复现、观察/推断区分、禁止将超时当成安全结论、核对量化目标、已有方向去重。这些能影响模型行为，但当前后端没有把它们都变为确定性验收。

```mermaid
flowchart LR
    A[模型提出动作或结论] --> B[工具装配与角色白名单]
    B --> C[规则/审查/结构校验]
    C --> D[执行和保存原始记录]
    D --> E[Planner或复盘解释证据]
    E --> F[后续意图或目标判定]
    F -. 尚无自动真值维护 .-> G[需要独立证据复核与依赖状态机制]
```

尤其不能将三种字段混为一谈：

- graph fact的`confirmed`：当前写入状态，不代表独立核验。
- worker的`confidence=observed`：模型自报的直接观察标签。
- experience的`verified`：管理员对提炼方法做过显式独立审核，不是当前任务成功证明。

## 尚缺的硬约束

当前没有强制原始观察与Claim拆分、所有fact必填真实raw_ref、业务语义判题、ALL/ANY必要依赖、依赖失效自动取消、受污染结论恢复状态机或Linker合成节点。`parent_ids`不能直接用作“所有后代均应撤销”的依据，已经取得独立证据的下游成果应单独评估。

所谓反幻觉关键词规则只能提示矛盾，不能仅靠login/error/401字样断言漏洞不存在；成功标准也不能只凭HTTP 200或某个字段名存在。后续benchmark应同时评估误报、漏报、错误传播、正常成功率、延迟和模型成本。
