# 本次源码导入验证

日期：2026-11-13。

| 检查 | 结果 |
| --- | --- |
| 部署程序与来源 | 运行二进制版本与SHA-256和部署记录一致 |
| 原始源码传输 | 754个导出文件逐个SHA-256验证，未导入运行配置或数据 |
| Python经验单元测试 | 56项通过 |
| Python语法编译 | `compileall`通过 |
| Planner/链路复盘Go测试 | `go test ./agent -run 'TestPlanner\|TestChainReviewer' -count=1`通过 |
| 工具审查/guard/旁路问答 | `go test ./intercept ./guard ./sidequestion -count=1`通过 |
| 后端构建 | 隔离源码副本`go build -trimpath ./cmd/artex`通过 |
| DB隔离 | 本次Go检查显式使用不可达的专用测试DSN，不连接生产库；部分依赖DB测试不运行 |
| 静态前端 | 源码及lockfile完整导入，前端未改，本次未重新运行npm构建 |
| Markdown本地链接 | 新文档引用文件存在；上游CHANGELOG中既有代码围栏问题未改写历史 |
| 生产资料排除 | 未导入配置密钥、私有安装状态、数据库、流量、任务正文或运行报告 |

此前部署验收的8组PostgreSQL回归采用随机独立schema及合成数据，测试代码随扩展保留；本次源码上传没有再执行生产库测试。这里没有声称全套Go测试、前端构建或新任务成功率评测均通过。
