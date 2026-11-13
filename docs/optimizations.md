# 已部署优化及实际收益

本清单说明当前相关优化和保留机制；尚未实现的方案单列。代码能力、部署参数与实际收益是不同层次。

| 优化 | 当前行为 | 代码位置 |
| --- | --- | --- |
| Planner 专注派发 | 白名单保留证据、队列、目标和干预工具；禁止命令、文件和目标访问 | `agent/planner_policy.go`、`agent/planner.go` |
| 限制空队列反复读史 | 最多六次不同宽泛查询，仍可定点取证；允许诚实说明缺前提后结束 | `plannerRoundPolicy.hooks`、`decisionTool` |
| 规划预算和收尾 | 参考配置16轮、240秒主阶段，之后有限收尾，非严格总时限 | `agent/planner.go`、`agent/wrapup.go`、`presets/runtime.json` |
| 查询复用 | 单轮缓存、参数规范化、90秒TTL、64项；版本变化及写操作失效，错误不缓存 | `agent/planner_policy.go`、`db/planner_read_revision.go` |
| 冷历史减量 | 概览digest每条前400字及原ID，完整内容仍可展开 | `plannerCompactOverview`、`agent/compaction.go` |
| 任务列表查询修复 | 最新活动按原始时间列排序，避免别名表达式妨碍索引 | `db/exploration.go` 的 `TaskListMetricsAll` |
| 独立工具审查 | 可以固定审查模型，超时、重试、失败策略独立于主任务 | `server/intercept.go`、`intercept/intercept.go` |
| 异步链路复盘 | 有限快照、原记录引用、去重和重开条件，只给planner建议 | `agent/chain_review_policy.go`、`server/chain_review_tools.go`、`extensions/chain-review/` |
| 报告证据交接 | 区分finding与探索节点ID，核对报告证据版本；HTTP绑定可选，非HTTP保留其他证据 | `agent/finding_workflow.go`、`db/finding_traffic.go`、`server/finding_report.go` |
| 独立经验库 | 来源、版本、结果、作用域与任务生命周期分离，来源撤回后停止复用 | `extensions/experience/schema.sql`、`experience_runtime.py` |
| 报告链路提炼 | 分节读取前提、步骤、验证、根因、限制，每步引用快照证据 | `report_sections`、`_finding_snapshot`、`_entry` |
| 修复取证超时 | activity逐节点等值读取，辅助读取失败保留报告并提示，主库故障不吞掉 | `_finding_links`、`_optional_read` |
| 按需经验问答 | 无定时检索Agent，planner按需ask；核对真实检索、权限、状态与引用 | `experience_retrieval.py`、`prompts.py`、planner白名单 |
| 方法审核 | 自动统一candidate，管理员独立审核才能verified；反馈仅有限调整排序 | `review_entry.py`、`rank_entry`、`_entry` |
| 自测排除 | 排除task/finding、停用相应旧条目，拒绝旧快照重新导入 | `source_exclusions`、`Runtime.reconcile` |
| 安全增量配置 | 归属标记、事务、提示词CAS、保留用户正文/模型、备份和回滚 | `extensions/experience/installer.py` |

本快照保留当前任务资产隔离与直接继承策略。早期补丁中的 UNION/MATERIALIZED 资产覆盖SQL，不等于当前仍采用同一实现，不依据历史补丁宣称其已保留。

## 效果证据

同一批两个长任务，两个完整自然日的观察。成功规划只表示该轮正常结束，不证明漏洞或目标正确。

| 指标 | 2026-11-10 | 2026-11-12 |
| --- | ---: | ---: |
| 成功规划轮次 | 297 | 420 |
| 整轮耗时中位数 | 226.4秒 | 70.0秒 |
| 整轮耗时P95 | 677.1秒 | 113.1秒 |
| 每轮平均工具调用 | 12.74 | 1.92 |
| 有派发轮次首派中位数 | 245.0秒 | 65.1秒 |
| 审查请求尝试错误率 | 26.74% | 0.68% |
| 成功审查请求均值 | 1.786秒 | 2.028秒 |
| 查询缓存命中 | 0 | 0 |

模型、上游可用性和任务阶段同期变化，不能全归因于代码；缓存没有线上命中收益。成功审查请求本身稍慢，请求尝试错误和最终审批失败/回退须分开。

复盘有“报告建议→planner派发或纠偏→worker回写”的可追踪案例，帮助识别HTTP 200正文里的鉴权失败、补完模型中断方向；不能据此证明增加确认漏洞或净节省时间。

经验扩展验收包括真实报告入库、独立问答、真实planner调用。最终56项Python单元测试和8组隔离PostgreSQL回归通过；planner白名单有Go hook/filter测试。这里只保存脱敏统计与测试代码，不发布生产证据正文。

## 讨论过但尚未实现

- Observation与Claim强制分离、程序提取原始观测。
- 真值维护TMS、disputed/retracted及有依据的级联暂停。
- ALL/ANY必要依赖与失效后的执行取消、结果版本检查。
- Synthesis Node、超边与独立Linker Agent。
- 自动注入已审核的验真避坑卡。
- 每个失败意图、误报纠正的独立自动经验采集。
- 幻觉陷阱A/B、污染传播深度的受控评测。
- 向量检索和专用经验卡片前端。

这些方案未纳入当前代码，不把假设提升比例写成实测结果。
