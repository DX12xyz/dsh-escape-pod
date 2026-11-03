# 逃生舱（@local/dsh-escape-pod）

> 让命令活在 DSH 之外：DSH 重启或崩溃后，命令与它的输出照常继续。

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
[![License: MIT](https://img.shields.io/badge/license-MIT-2da44e)](./LICENSE)

**版本 1.1.1** · Windows only · MIT · 七个 `pod_*` 工具 · 独立插件（自带设置页）

---

## 目录

- [为什么需要它](#为什么需要它)
- [特性速览](#特性速览)
- [安装](#安装)
- [快速开始](#快速开始)
- [工具一览](#工具一览)
- [架构一览](#架构一览)
- [会话文件策略与一次性审批](#会话文件策略与一次性审批)
- [冻结模式与生命周期](#冻结模式与生命周期)
- [命令行选择](#命令行选择)
- [配置](#配置)
- [账本与安全](#账本与安全)
- [常见问题](#常见问题)
- [与 dsh-power 的关系](#与-dsh-power-的关系)
- [许可](#许可)
- [文档索引](#文档索引)

## 为什么需要它

**结论：长任务跑在 DSH 进程树里就会被「DSH 一动它就死」绑架；逃生舱把命令的寿命搬到树外，把权限留在树内。**

DSH 原生的 `pwsh` 工具把命令跑在 Host 的进程树里。Host 一退出（重启、更新插件、崩溃），命令跟着被杀；前台调用在重启时还会被平台补一条 `TOOL_OUTCOME_UNKNOWN`——长任务只能从头再来。

逃生舱的方案：一个 detached 的 pod 进程（Medium 完整性）接管命令，DSH 只是它的客户端。DSH 重启/热重载/崩溃都只关闭连接，不杀 pod；Host 重启后新 Host 连回同一个 pod，继续读输出、继续等结果。

**命令的手仍然是会话策略允许的那只手**：`read-only` / `workspace-write` 会话里，每条命令仍由 Host 用 `ctx.sandbox.confine()` 现签受限 runner 前缀，命令在 Low 完整性 + WRITE_RESTRICTED 令牌与 kill-on-close Job 里跑。逃生舱借走的只有寿命，不是权限；只有会话本身是 `danger-full-access` 时才没有前缀。

## 特性速览

- **命令活过 DSH**：pod 由 Host 以 `detached: true` 方式 spawn 并 `unref()`，不经过 `ctx.subprocess`/`ctx.jobs`/`ctx.terminal`，因此不在 DSH 的 kill-on-close Job 里；DSH 重启或崩溃只断连接，不停命令。
- **七个工具**：`pod_run`（后台）、`pod_exec`（前台）、`pod_output`（续读）、`pod_kill`、`pod_freeze`、`pod_status`、`pod_shell`。
- **跟随会话文件策略**：`read-only` 只读、`workspace-write` 现状、`danger-full-access` 完全访问；**每次调用重新解析**，会话中途切权限立即生效。
- **一次性提权**：`sandbox_permissions` + `justification` 走真实 DSH 审批，只有「仅本次允许」才执行。
- **前台调用跨重启回填**：`pod_exec` 在等待前通过 `resumableToolCalls` 登记挂起；重启后新 Host 读账本，把命令自己的输出补回同一条调用（不重跑命令、不产生 `TOOL_OUTCOME_UNKNOWN`）。
- **冻结模式**：DSH 消失 10 秒后冻结运行中的命令，回来立即解冻；长时间无人回来按 `freezeMinutes` 再生，次数耗尽自毁。
- **诚实的生命周期**：无客户端、无运行中 job、无冻结 episode ⇒ pod 自行退出，不再空等 12 小时；下一条命令按需重建。
- **解释器可选**：`shell: powershell | cmd | bash`。本插件**不提供任何 shell**，只探测本机可用的候选——其他 DSH 插件提供的（例如 dsh-ops 的 PortableGit）、系统安装的（PowerShell、Git for Windows、cmd）以及 PATH 上的；也可在设置页为当前会话指定。
- **单例**：同名命名管道即锁。
- **账本在工作区之外**：`%LOCALAPPDATA%\dsh-escape-pod-core\` 账本目录记录每条命令的完整生命周期，跨重启续读。
- **设置页**：插件页「逃生舱」卡片管理冻结与命令行默认值，红色长按 5 秒按钮关闭 pod。

## 安装

要求：Windows、可用的 `dsh` 命令。

仓库根目录就是插件包本身（`package.json`、`cordis.patch.yml`、Host/Client 入口、`locale/`、`icon.svg` 都在根目录），仓库不随附预打包的 `.tgz`。任选一种方式安装，下文命令以 Web profile（`web`）为例；桌面版把 `web` 换成 `desktop`。

### 方式一：插件页安装（推荐，人类入口）

1. 打开 DSH 插件页 →「安装插件」；
2. 安装源填仓库地址 `https://github.com/DX12xyz/dsh-escape-pod`，或 git 简写 `github:DX12xyz/dsh-escape-pod`；
3. 等待安装完成，按提示**重启 DSH**（Host 半身生效；Client 半身刷新页面即可）。

### 方式二：命令行从 git 源安装

```powershell
dsh plugin --profile web add github:DX12xyz/dsh-escape-pod
```

### 方式三：本地目录安装（改代码 / 离线可用）

把仓库的 zip/tar 解压到本机，再把解压出来的仓库根目录装进 profile：

```powershell
dsh plugin --profile web add "link:<仓库根目录绝对路径>"
```

`link:` 装的是活目录：改完代码重启 DSH（Host 半身）或刷新页面（Client 半身）即可生效。

### 方式四：离线打包 tgz

在仓库根目录打包，再安装产出的 tgz：

```powershell
cd <仓库根目录>
npm pack
# 产出 local-dsh-escape-pod-1.1.1.tgz
dsh plugin --profile web add "file:<仓库根目录>/local-dsh-escape-pod-1.1.1.tgz"
```

### 装好判据

装好后**重启 DSH**，调用一次 `pod_status` 验证四项：

- `podPid` / `podStartedAt` 有值，`podVersion=1.1.1`、`protocol=3`；
- `pipe=\\.\pipe\dsh-escape-pod-core-<seedHash>`、`auth=...`、`identity=...`；
- `jobs`（本会话）与 `freeze=supported`（或 `unsupported（原因）`）；
- 新增两行：`会话文件策略=...` 与 `命令行：powershell → ...`。

注意：

- **Host 与 pod 必须同版本**。重装插件不会替换正在运行的 pod 进程；要立刻换代码，用 `pod_status action="relaunch"`（有 running job 时会拒绝，除非 `force: true`）。**protocol < 3 的旧 pod 会让 `pod_run` / `pod_exec` 直接 `EPROTOCOL` 失败**，见[常见问题](#常见问题)中 `EPROTOCOL` 一条。
- 设置页保存只改 `<stateDir>/settings.json`，**不改 profile patch、不触发热重载**。

### 卸载与残留清理

卸载：

```powershell
dsh plugin --profile web remove @local/dsh-escape-pod
```

- 卸载前先停 pod：插件页「逃生舱」卡片 → 红色长按 5 秒的关闭按钮；detached 的 pod 不随插件卸载自动退出。
- 卸载后 `%LOCALAPPDATA%\dsh-escape-pod-core\` 仍保留 `settings.json` 与各 job 账本；确认不再需要时手动删除。
- 卸载逃生舱不影响 dsh-power：重启与关闭能力与 pod 无关，只是没了关机联动。

## 快速开始

后台跑一条长命令，DSH 重启后继续读：

```text
pod_run({ command: "1..600 | ForEach-Object { Start-Sleep -Seconds 1; $_ }",
          description: "long ticker" })
→ { jobId: "podc-...", runnerPid: 1234, ... }

pod_output({ jobId: "podc-..." })   # 只拿上次之后的新输出；内部自动 ack
pod_status({})                       # podPid / 游标 / 收养状态 / 执行预算 / 会话策略
pod_kill({ jobId: "podc-..." })      # 真杀 runner，账本写 killed
```

前台跑一条命令，拿一条结果（含跨重启）：

```text
pod_exec({ command: "npm test" })
→ stdout
  [stderr]
  ...
  [exit code: 1]
  [status: completed]
```

冻结一条正在跑的命令（或解冻）：

```text
pod_freeze({ jobId: "podc-...", action: "freeze" })
pod_freeze({ jobId: "podc-...", action: "thaw" })
```

在设置页关闭逃生舱：

> 插件 → 逃生舱 → 红色「关闭正在运行的逃生舱」→ 长按 5 秒确认 → 终止 N 个任务并关闭 pod。

## 工具一览

| 工具 | 形态 | 一句话 | 详见 TECHDOC |
|---|---|---|---|
| `pod_run` | 后台 | 启动一条命令，立即返回 `jobId` / `runnerPid`；**不设命令超时**，跨 DSH 重启继续跑 | [§2](./TECHDOC.md#2-工具参考) |
| `pod_exec` | 前台 | 同一条 spawn 路径，阻塞到结算，返回一条原生形状结果，**模型面没有 jobId/偏移**；超时跟随 DSH 原生执行器的实时 `timeoutMs` | [§2](./TECHDOC.md#2-工具参考)、[§5 跨重启 hold](./TECHDOC.md#5-pod_exec-的跨重启-hold) |
| `pod_output` | 读 | 从上次之后续读（绝对字节偏移，内部自动 ack）；可跨重启、跨 Host 续读 | [§2](./TECHDOC.md#2-工具参考) |
| `pod_kill` | 控制 | 真杀 runner（kill-on-close Job 连带结束命令），账本写 `killed` | [§2](./TECHDOC.md#2-工具参考) |
| `pod_freeze` | 控制 | 冻结 / 解冻整棵命令树；冻结期间超时预算暂停 | [§2](./TECHDOC.md#2-工具参考)、[§6 冻结模式与生命周期](./TECHDOC.md#6-冻结模式与生命周期) |
| `pod_status` | 诊断 | pod 身份与 `protocol`、形态模板、本会话 job 与游标、收养、冻结能力、执行预算、会话文件策略、当前命令行；`action:"relaunch"` 换代码 | [§2](./TECHDOC.md#2-工具参考) |
| `pod_shell` | 选择 | 列出本机 PowerShell / bash / cmd 候选（id/路径/版本/来源/是否可用）并为当前会话选一个；Host 侧探测，**不连接也不唤醒 pod** | [§2](./TECHDOC.md#2-工具参考)、[§4 命令行探测与选择](./TECHDOC.md#4-命令行探测与选择) |

> **内部标识**：模型面工具名统一以 `pod_*` 开头；跨进程与磁盘标识保持稳定——管道 stem `dsh-escape-pod-core-`、账本目录 `%LOCALAPPDATA%\dsh-escape-pod-core`、Loader id `escape-pod-core`、`jobId` 前缀 `podc-`、环境变量 `PODC_ATTEST*` / `DSH_ESCAPE_POD_BASH`、Cordis 服务 `escapePod`。

## 架构一览

```text
Host 插件（DSH，会重启）
  │  命名管道（token + 单客户端 + 可选 OS 身份校验）
  ▼
pod 进程 pod.mjs（Medium 完整性、detached；普通 Host 下不在任何 job 里，桌面 Host 用计划任务）
  ├─ read-only / workspace-write：Host 现签的受限 runner 前缀 + 目标 argv
  │    └─ 命令（Low 完整性 + WRITE_RESTRICTED，在 runner 的 kill-on-close Job 里）
  └─ danger-full-access：无前缀，直接 spawn 目标 argv（pod 自身 Medium 令牌）
```

- **账本**：`%LOCALAPPDATA%\dsh-escape-pod-core\jobs\<jobId>\` 下的五个文件（见[账本与安全](#账本与安全)）。
- **收养**：运行中的 pod job 会被收养进 `ctx.jobs`（`job_list` 可见、`job_output` 可读增量、`job_kill` 可真杀）；收养记录是 unowned，所以会话销毁不会连带杀掉命令。
- **会话边界**：`pod_status`/`pod_output`/`pod_kill` 默认只碰本 DSH 会话的 job，跨会话必须显式 `adopt: true`。

细节见 [TECHDOC.md](./TECHDOC.md)。

## 会话文件策略与一次性审批

命令跟随**当前会话**的文件策略，每次调用重新解析：

| 会话策略 | 命令怎么跑 | 能写什么 |
|---|---|---|
| `read-only` | 受限 runner，`--mode read-only`（不带写 SID） | 只能读 |
| `workspace-write` | 受限 runner，`--mode workspace-write` | 工作区 + 本次会话的临时目录 |
| `danger-full-access` | **无前缀**，pod 自身 Medium 令牌直接跑 | 当前用户能写的一切 |

窄会话里某一条命令确实需要写盘时，**申请一次**：

```text
pod_run({ command: "npm run build",
          description: "build（当前会话是只读）",
          sandbox_permissions: "workspace-write",
          justification: "构建要写 dist/ 与 node_modules/.cache，当前会话是只读" })
```

- Host 弹出真实的 DSH 审批；只有用户选「仅本次允许」（`allowed-once`）才执行。
- 规则与 DSH 原生 bash 沙箱一致：**只能变宽**（申请更窄直接 `ESANDBOXNARROWER`）、**改模式必须给理由**（`EJUSTIFICATION`）、目标等于当前模式时不审批直接执行。
- 审批**只对这一次调用有效**：不写会话策略，也不改设置；下一条命令仍按会话当时的模式解析。后台 job 的整个生命周期属于这次调用。
- 被拒绝 / 超时 / 没有审批服务 → `EAPPROVALDENIED` / `EAPPROVALUNAVAILABLE`，**一条命令都没起**。不要重试，也不要绕过这个决定。
- 审批期间用户在 UI 里把会话切了权限 → `EAUTHORITYCHANGED`（否则会在没人批准过的权威下执行）；签完前缀到发请求之间还有一次同样的复核（TOCTOU）。

> **只读模式的平台副作用**：`read-only` 前缀的受限令牌会让 PowerShell 进入 Constrained Language（不能 `new` .NET 类型，`[Console]::OutputEncoding` 赋值也会失败）。配置的 UTF-8 前缀已用 `try { … } catch { }` 包住（CLM 下静默跳过），因此只读会话里**中文输出可能仍是 GBK**：需要 UTF-8 文本时用 `shell:"bash"`，或者像上面那样申请一次 `workspace-write`。

完全访问的代价见[账本与安全](#账本与安全)。

## 冻结模式与生命周期

**冻结模式**是给「DSH 消失但命令还在跑」准备的兜底。状态机为 `idle → grace → frozen`；frozen 后按再生预算「解冻 + 立即重新冻结」回到 frozen，预算耗尽进入 `destroying`（自毁，终止所有 job 后退出 pod）：

- DSH（最后一个认证客户端）断开 **10 秒**宽限后，冻结运行中的命令；DSH 回来**立即解冻**。
- 长时间无人回来时，按 `freezeMinutes`（默认 30 分钟）看门狗**再生**：解冻后立即重新冻结、重新计时，默认允许 1 次（`regenerations`，范围 0..3）。
- 手动 `pod_freeze` 的冻结不会被策略解开（自毁除外）；冻结期间该 job 的超时预算暂停。
- 关闭开关：设置页「冻结模式」，默认 `false`；设置项与其余冻结参数同存于 `<stateDir>/settings.json`（默认 `%LOCALAPPDATA%\dsh-escape-pod-core\settings.json`）。

**诚实的生命周期**：无客户端、无运行中 job、无冻结 episode ⇒ pod 自行退出，不再空等 12 小时；下一条命令按需重建。正常 DSH 重启（无 job 且冻结模式关闭）时，pod 在最后一个客户端断开时退出、新 Host 再拉起新 pod，这是预期行为；冻结模式开启时先过 10 秒宽限，无事件路径由 15 秒兜底 tick 与启动后 30 秒宽限兜底。

**单例**：同名命名管道即锁；同一用户只有一个逃生舱，第二个实例 `EADDRINUSE` 后自行退出。

## 命令行选择

默认行为：`shell` 不传时用 `powershell`；`shell: "bash"` 时按探测顺序选第一个可用的 bash（配置 `bashPath` → 环境变量 `DSH_ESCAPE_POD_BASH` → dsh-ops 提供的 PortableGit → Git for Windows → PATH）。本插件**不自带任何 shell 二进制**，只做探测与选择；想换或看清单时用 `pod_shell`——它是**可选覆盖**，不会强制替换系统原装的解释器：

```text
pod_shell({ action: "list" })
→ 本会话命令行（会话覆盖 > 设置默认 > 自动探测）
  powershell  → Windows PowerShell 5.1  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  来源：自动
  bash        → PortableGit（dsh-ops）   %DSH_HOME%\dsh-ops\bash-ipc\3cdbe2ba…\bin\bash.exe        来源：自动
  cmd         → cmd.exe（固定）          C:\Windows\System32\cmd.exe  固定（不可选）
  候选（* = 当前应用；不可用项不会被自动选中）：…

pod_shell({ action: "use", shell: "bash", id: "bash-ops-3cdbe2ba" })   # 只对当前会话生效
pod_shell({ action: "reset", shell: "bash" })   # 回到「设置默认 > 自动探测」
pod_shell({ action: "reset" })                   # 清除本会话全部类型的选择
```

- 解析顺序：**会话选择 → 设置页默认 → 自动探测**；所选路径运行期不可用时逐级回落，并在 `pod_run` 文本与 `pod_shell` 结果里说明回落原因，不会静默换解释器。
- 会话选择存在 `<stateDir>/shell-sessions.json`（30 天清理），跨 DSH 重启保留；写文件失败只在本次 Host 内存生效（给出警告，不失败）。
- `cmd` 固定不可选（系统只有一个）：要跑 cmd 命令直接传 `shell: "cmd"`。
- 设置页「命令行」区块提供两个下拉（`自动（探测）` + 候选），失效的保存值显示红字；cmd 一行只读；探测失败显示错误行，不影响其它设置保存。
- 建议**先用默认（原装）命令行**，只有在它不可用、启动失败或版本不满足时才切换。

本机（示例，候选均来自本机安装与其他插件，本插件不自带）：PowerShell 5.1.19041.6456、未装 pwsh 7、dsh-ops PortableGit 两套（bash 5.3.15，受限令牌下可用）、系统 Git Bash 2.49 在受限令牌下会崩（`NtSetInformationToken(TokenDefaultDacl)` 被拒）、cmd 10.0.19045.6466 唯一。细节与 id 规则见 [TECHDOC.md §4](./TECHDOC.md#4-命令行探测与选择)。

## 配置

设置文件在 `<stateDir>/settings.json`（默认 `%LOCALAPPDATA%\dsh-escape-pod-core\settings.json`），schema v3，由设置页（Host）与冻结策略（pod）各自读同一份。常用项只有四个：

| 字段 | 类型 | 范围/默认 | 含义 |
|---|---|---|---|
| `freezeMode` | boolean | 默认 `false` | DSH 消失后是否冻结运行中的命令 |
| `freezeMinutes` | integer | 1..1440，默认 30 | 冻结 episode 的看门狗时长 |
| `regenerations` | integer | 0..3，默认 1 | 自毁前允许的「解冻 + 立即重新冻结」次数 |
| `shells` | `{powershell, bash}` | 各为 `"auto"` 或候选 id，默认 `auto` | 设置页的命令行默认值（v3 新增）；候选 id 来自本机探测，本插件不提供任何 shell |

```json
{ "version": 3, "freezeMode": false, "freezeMinutes": 30, "regenerations": 1,
  "shells": { "powershell": "auto", "bash": "auto" } }
```

- **没有 `enabled` 开关**：pod 始终服务命令；旧文件里的 `enabled` 读取时忽略、写入时丢弃。
- 读取永不抛：缺失/损坏一律回落到 `false/30/1/{auto, auto}`；写入是 tmp+rename 原子写。
- 打开设置页**不会**起 pod；保存 API 为 `GET /api/dsh-escape-pod/settings` 与 `POST /api/dsh-escape-pod/settings`，命令行候选实时探测走 `GET /api/dsh-escape-pod/shells`。

完整路由、schema 与归一规则见 [TECHDOC.md §4.3](./TECHDOC.md#43-设置-api-与-schema-v3) 与 [§6.1](./TECHDOC.md#61-设置-schema-v3)。

## 账本与安全

**账本是跨重启恢复的落盘依据**：每条命令在 `%LOCALAPPDATA%\dsh-escape-pod-core\jobs\<jobId>\` 下留下完整记录（绝对字节偏移、跨重启续读）：

| 文件 | 内容 |
|---|---|
| `meta.json` | 任务元数据；`meta.policy` 记录这条命令实际跑在哪个策略下 |
| `out.log` | 完整输出 |
| `segments.jsonl` | 输出分段 |
| `cursor.json` | 绝对字节偏移游标（续读用） |
| `exit.json` | 结算记录：status/exitCode/signal/endedAt/durationMs/totalBytes/lossy/writeErrors/runnerFailure/timedOut/timeoutMs；status 取 running/settled/killed/runner-failed/spawn-failed/ledger-failed/unknown |

账本刻意放在**工作区之外**：受限模式下的被托管命令写不到工作区外，账本若放在工作区内它就能伪造自己的记录——因此两侧都 fail-closed。

- **受限模式（默认）**：命令在 Low 完整性 + WRITE_RESTRICTED 令牌里跑，账本在工作区之外，被托管命令拿不到它的写权限，所以**无法伪造自己的 `exit.json`**。
- **完全访问（`danger-full-access`）会削弱这条不变量**：命令与当前用户同权，可以读写用户能读写的一切，**包括 `%LOCALAPPDATA%\dsh-escape-pod-core` 下的账本**。账本位置规则仍然保留（不在工作区里），但这时的账本**不再防篡改**——命令能改自己的 `meta/out/exit`。这是用户显式选择完全访问的代价。
- 审批是**一次性的**：它不会把会话策略改宽，也不会写进设置文件；不要把它当持久提权。
- 工具改名不影响账本归属：`jobId` 前缀仍是 `podc-`，会话边界（`EFOREIGNJOB` / `adopt:true`）也照旧。

## 常见问题

- **`pod_run` / `pod_exec` 报 `EPROTOCOL` 怎么办？** 说明还在连一台用旧代码启动的 pod（`protocol < 3`）：执行 `pod_status action="relaunch"` 让它用新代码重启（有 running job 时会拒绝，除非同时 `force: true`，那些命令会被中断），或等它空闲自己退出（无客户端 + 无运行中 job + 无冻结 episode），下一次调用自动重建。**报错时本次没有执行任何命令**。
- **本插件自带 bash 吗？** 不带。逃生舱既不打包也不下载任何 shell，只探测并列出本机可用的解释器：其他 DSH 插件提供的（例如 dsh-ops 的 PortableGit）、系统安装的（Windows PowerShell、Git for Windows、cmd）与 PATH 上的；探测与选择入口是 `pod_shell` 与 `shell:` 参数。
- **只读会话里中文输出可能出现乱码（GBK）？** 只读前缀的受限令牌让 PowerShell 进入 Constrained Language，UTF-8 前缀被静默跳过，因此中文输出可能仍是 GBK；需要 UTF-8 时用 `shell:"bash"` 或申请一次 `workspace-write`。
- **两个 DSH 会话会互相看到对方的 job 吗？** 默认不会（`EFOREIGNJOB`），显式 `adopt: true` 才接管；`pod_status` 只列本会话 job，其它会话只给 `foreignJobs` / `unownedJobs` 计数。
- **pod 会常驻占资源吗？** 不会。无客户端、无运行中 job、无冻结 episode 时 pod 自行退出，下一条命令再按需重建；打开设置页与 `pod_shell` 都不会起 pod（`pod_shell` 是 Host 侧探测，不连接也不唤醒 pod）。
- **为什么 `jobId` 前缀是 `podc-`？** 它是跨进程的稳定标识，同时充当账本目录名，与工具名 `pod_*` 互不影响。

## 与 dsh-power 的关系

逃生舱与 dsh-power（负责 DSH 的重启/关闭，**1.8.2**）是**两个独立插件**：各自安装、各自设置页、各自开关，互不依赖。

- **可选联动**：dsh-power 关机时若发现 Cordis 服务 `escapePod`，会同时关闭逃生舱（先 `killAllJobs` 再退出 pod）。服务不存在时它照常工作。
- **卸载 power 不影响逃生舱**：工具、冻结模式、账本、设置页都在本包内；只是少了关机联动。
- **卸载/关闭逃生舱不影响 power**：重启与关闭能力与 pod 无关。

## 已知限制

- 仅 Windows；桌面 Host 的 pod 拉起走计划任务，普通 Host 为普通 detached 进程（见「架构一览」）。
- `read-only` 前缀让 PowerShell 进入 Constrained Language，中文输出可能仍是 GBK；需要 UTF-8 时用 `shell:"bash"`（见「常见问题」）。
- `danger-full-access` 下账本不再防篡改：命令与用户同权，可改写 `%LOCALAPPDATA%\dsh-escape-pod-core` 下自己的记录（见「账本与安全」）。
- Host 与 pod 必须同版本：`protocol < 3` 的 pod 会让 `pod_run` / `pod_exec` 直接 `EPROTOCOL`（见「常见问题」）。

## 文档索引

| 文档 | 读者 | 内容 |
|---|---|---|
| [TECHDOC.md](./TECHDOC.md) | 开发者/运维 | 架构、协议（protocol 3）、七个工具的参数/返回、文件策略与审批、命令行探测与选择、`pod_exec` 跨重启 hold、冻结状态机、设置 API、安全模型与限制、测试方法 |
| [HISTVER.md](./HISTVER.md) | 维护者 | 正式公开（1.1.1）及之后的版本变更 |
| [HISTVER_legacy.md](./HISTVER_legacy.md) | 维护者 | 正式公开前的私有迭代记录（仅供参考，不作为对外契约） |
| [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) | 所有人 | 第三方归属与许可证（dsh-bgjobs / koffi / PortableGit / 系统组件） |

## 许可

本文件以 MIT 许可发布，版权归 DX12_XYZ 所有。完整条款见仓库根 [LICENSE](./LICENSE)。

Copyright (c) 2026 DX12_XYZ

本仓库以 MIT 公开发布。设计上借鉴了开源项目 [`bitsmug/dsh-bgjobs`](https://github.com/bitsmug/dsh-bgjobs) 把后台任务交给独立进程与账本的核心想法，**未复制其源代码**；第三方归属（`bitsmug/dsh-bgjobs`）、运行时依赖（`koffi`）以及可选探测对象（Git for Windows PortableGit、Windows PowerShell / cmd——**本插件不打包、不分发这些解释器**）的许可证说明见 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。

<!-- fused-by: glm-5.3-flash -->

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
