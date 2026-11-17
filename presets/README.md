# 运行配置参考

`agents/`为2026-11-13快照时system正文；`runtime.json`是当时对应预算、标志、少量设置和工具绑定。它们帮助复核历史基线，不包含模型profile ID、API Key或生产任务内容。v5提示词由经验扩展的`prompts.py`和安装器生成，不能用本目录旧正文覆盖新协议。

这些文件不会被启动程序自动导入，也不是生产数据库恢复。应通过本地ARTEX管理界面按需应用；经验部分优先使用`extensions/experience/installer.py`，避免协作段重复。当前模型和触发器可能随后由管理员修改，所以配置参考不能代替实时状态。

硬约束在Go/Python代码中，提示词变更无法自动突破角色白名单。v5已为经验整理/检索增加装配过滤和PreToolUse检查，见`agent/experience_policy.go`。
