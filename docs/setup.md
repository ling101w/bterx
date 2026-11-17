# 构建、安装扩展和验证

## 基础系统

以仓库根README的命令构建前端与Go程序，数据库使用自己的PostgreSQL。`go.mod`当前要求Go 1.26.10；支持自动toolchain下载的Go也可以按该文件选择工具链。Node参考22。

`config.example.json`复制到本地后再配置数据库；生产`config.json`、JWT签名密钥、环境变量和数据库备份不能提交。模型、范围和审批策略通过自己的部署配置。

当前源码保留上游selfupdate、发布和Demo工作流。它们不是BTERX已经配置好的发布服务；不要把上游自动更新视为会保留本分支功能。正式升级请自行构建审核后的版本。

## 扩展程序路径

这是现有部署源码的可复核快照，辅助程序仍含部署路径默认值，不是已经完成任意目录安装改造的通用发行包：

| 内容 | 默认路径/入口 |
| --- | --- |
| 主程序和配置 | `/home/maming/apps/artex-1/` |
| 链路复盘Python模块 | `/home/maming/apps/artex-chain-review/` |
| 经验扩展Python模块 | `/home/maming/apps/artex-experience/` |
| 经验DB配置 | 默认主配置；支持`ARTEX_EXPERIENCE_CONFIG`或安装器`--config` |
| 经验问答API | 固定`http://127.0.0.1:8787` |
| 问答本机JWT密钥 | `NativeAPI`默认读取主程序目录的`jwt.key`，只在进程内使用 |

新环境可以采用这些路径；若目录、端口不同，需要统一修改`server/chain_review_tools.go`、两个Python辅助程序的默认配置/密钥路径及安装器wrapper生成路径，并重新构建相关Go代码。不能只复制文件后假设数据库已安装Agent和工具。

## 链路复盘

1. 将`extensions/chain-review/`的Python模块和提示词放到配置对应目录。
2. 在ARTEX Agent管理中创建`chain_reviewer`，参考`presets/agents/chain_reviewer.md`和`presets/runtime.json`的预算。
3. 只绑定原生`chain_review_snapshot`和`chain_review_publish`，配置900秒周期，串行、单并发。
4. 采用可用模型配置，核对真实工具调用与发布，不以触发器启用代替工作成功。

该角色key对应Go中的硬白名单，改成其他key会失去这段专门隔离，不能只改显示名。Python依赖标准库和`psql`；SQLite仅保存辅助快照、报告与水位，生产源证据通过只读查询取得。

## 经验整理和检索

```bash
# 将本目录复制到准备使用的扩展目录后执行
cd /home/maming/apps/artex-experience
python3 installer.py dry-run
python3 installer.py install
python3 installer.py status
```

安装器增加独立schema、整理Agent、按需检索Agent、七个工具、协作提示和整理触发器。检索Agent不增加定时触发；模型保持NULL跟随当前配置，升级不覆盖用户另设的模型。完整说明见[扩展README](../extensions/experience/README.md)。

已安装环境更换模块后使用`upgrade --dry-run`和`upgrade`；重复`install`按幂等规则保留现状。回滚用`rollback`，只恢复仍指向本扩展版本的提示词，保留用户后续修改和经验数据。Go白名单版本回滚与扩展配置回滚是两个步骤。

## 提示词与运行配置参考

`presets/agents/*.md`保存当前13个Agent的system正文，`presets/runtime.json`保存无凭据预算、启用状态、工具绑定和少量设置。它们是人工复核/配置参考，不是自动执行的数据库恢复文件；不含模型profile ID、API Key、Cookie、任务目标或历史报告。

经验扩展安装器会生成对应协作段；不要把preset再重复追加一次。原生部分Agent由程序seed，链路复盘需要上述手动配置。应为自己的环境选择模型并验证工具可用性。

## 测试

无需数据库的Python检查：

```bash
cd extensions/experience
python3 -m unittest -v test_storage test_runtime test_retrieval test_prompt_priority
```

v5还应运行 `test_memory_policy test_curation_runs`。数据库部分需在专用库设置 `ARTEX_EXPERIENCE_REVIEW_TEST=1`，运行 `test_curation_runs integration_review_test`；合成检索评测为 `python3 eval_retrieval.py`，不访问测试目标。

原生采用/宿主测试需要单独的本机 `artex_memory_test*` 数据库：设置 `ARTEX_PG_DSN`、`ARTEX_EXPERIENCE_CONFIG` 和 `ARTEX_EXPERIENCE_NATIVE_TEST=1`，再运行 `go test -p 1 ./agent ./db ./server -run 'TestExperience|TestPlanner|TestChainReviewer' -count=1`。不要指向生产库；这些测试会建表、创建合成任务并清理自己的记录。

真实PostgreSQL回归会新建并清理带随机后缀的隔离schema，只用合成来源。仍应使用专门测试库和配置：

```bash
ARTEX_EXPERIENCE_CONFIG=/path/to/test-config.json python3 integration_test.py
ARTEX_EXPERIENCE_CONFIG=/path/to/test-config.json \
  ARTEX_EXPERIENCE_REVIEW_TEST=1 python3 -m unittest -v integration_review_test
```

Go的DB测试可能建表和清理测试数据，必须与生产库分离。先运行无需DB的定向约束测试：

```bash
go test ./agent -run 'TestPlanner|TestChainReviewer' -count=1
go test ./intercept ./guard ./sidequestion -count=1
go build -o /tmp/bterx-check ./cmd/artex
```

默认Go构建使用无内嵌UI的stub，仅用于后端编译检查。发行程序需要先构建静态前端，再用`-tags embedui`编译。未配置数据库时部分Go集成测试会skip，不能写成全部数据库行为已测。
