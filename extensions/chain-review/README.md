# 链路复盘辅助程序

`review_runtime.py`是当前部署使用的标准库Python模块，Go原生`chain_review_snapshot/publish`调用它。它只读已有源证据，写自己的SQLite快照、Markdown建议报告和水位；Go宿主把通过校验的报告以`advisory_only` hint交给planner。

默认目录与配置路径仍对应现有部署，见[安装说明](../../docs/setup.md)。模块本身不创建Agent或触发器；对应system模板和planner协作补充保存在本目录，实际配置参考`presets/`。

报告引用必须存在于同一任务快照，执行记录必须属于引用节点或其直接相关work；辅助程序检查结构、归属和条目数量，不证明语义结论正确。API错误、限流、超时不应被解释成技术路线已否定。

复盘不执行目标验证、不删除历史、不创建执行意图、不改任务目标，也没有事实撤回和级联暂停机制。该专门角色在Go宿主有工具filter和PreToolUse双白名单，只允许snapshot/publish。
