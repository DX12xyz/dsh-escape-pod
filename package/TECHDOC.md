# 逃生舱（`@local/dsh-escape-pod`）技术文档

> **文档状态**
>
> - **适用版本**：`1.1.1`（源包 `@local/dsh-escape-pod`，Windows only，模型面七个 `pod_*` 工具）
> - **最后校对时间**：`2026-11-01`（文档校对日；§4.4 与附录 B.6 的「本机实测」同为该日探测结果，性质不同，见各节标注）
> - **校对基线**：1.1.0-hotfix.3 之后收版为 `1.1.1`，相对 hotfix.3 无行为变更（版本线见 [HISTVER.md](./HISTVER.md)；正式公开前的私有迭代见 [HISTVER_legacy.md](./HISTVER_legacy.md)，仅供参考）
> - **读者**：开发者 / 运维（架构、协议、排障、二次开发）
> - **相关文档**：[README.md](./README.md)（定位、安装、快速开始） · [HISTVER.md](./HISTVER.md)（正式公开基线及后续版本） · [HISTVER_legacy.md](./HISTVER_legacy.md)（正式公开前的私有迭代记录，仅供参考）

> 适用版本 **1.1.1**。本文面向维护者与排障者，覆盖架构、协议、工具契约、文件
> 策略与审批、命令行探测与选择、跨重启恢复、冻结状态机、设置 API、安全模型，以及本包
> 使用的测试方法。
> 面向使用者的项目介绍与安装步骤见 [README.md](./README.md)。
>
> **工具名变更（1.1.0-hotfix.1，破坏性）**：`podc_run/podc_exec/podc_output/podc_kill/podc_freeze/podc_status`
> 改为 `pod_run/pod_exec/pod_output/pod_kill/pod_freeze/pod_status`，并新增 `pod_shell`。
> 内部标识**一个都没改**：管道 stem `dsh-escape-pod-core-`、账本目录
> `%LOCALAPPDATA%\dsh-escape-pod-core`、Loader id `escape-pod-core`、`jobId` 前缀 `podc-`、
> 环境变量 `PODC_ATTEST*` / `DSH_ESCAPE_POD_BASH`、Cordis 服务 `escapePod`。只改工具名，
> 磁盘/跨进程标识与已有账本保持兼容；版本线见 [HISTVER.md](./HISTVER.md)。

## 目录

本目录覆盖全部二级与三级标题，锚点可直接跳转；附录 A–D 由正文事实汇总而来，不引入新事实。

> 规范骨架的三类小节在本文的落点：**状态与持久化** → §1.5 / §4.2 / §5.2；**配置字段** → §6.1（schema v3）与 §4.3；**安全模型** → §8。

- [1. 架构](#1-架构)
  - [1.1 两个进程](#11-两个进程)
  - [1.2 启动器（`launcher.mjs`）](#12-启动器launchermjs)
  - [1.3 管道协议](#13-管道协议)
  - [1.4 per-call 沙箱前缀与形态模板](#14-per-call-沙箱前缀与形态模板)
  - [1.5 账本](#15-账本)
  - [1.6 收养到 `ctx.jobs`](#16-收养到-ctxjobs)
  - [1.7 会话归属](#17-会话归属)
- [2. 工具参考](#2-工具参考)
  - [2.1 公共约定](#21-公共约定)
  - [2.2 `pod_run`：后台形态](#22-pod_run后台形态)
  - [2.3 `pod_exec`：前台形态](#23-pod_exec前台形态)
  - [2.4 `pod_output`](#24-pod_output)
  - [2.5 `pod_kill`](#25-pod_kill)
  - [2.6 `pod_freeze`](#26-pod_freeze)
  - [2.7 `pod_status`](#27-pod_status)
  - [2.8 `pod_shell`：命令行探测与选择](#28-pod_shell命令行探测与选择)
  - [2.9 执行预算（输出窗口与命令超时）](#29-执行预算输出窗口与命令超时)
- [3. 文件策略与审批](#3-文件策略与审批)
  - [3.1 权威从哪来](#31-权威从哪来)
  - [3.2 三种模式的执行形态](#32-三种模式的执行形态)
  - [3.3 审批时序](#33-审批时序)
  - [3.4 错误码](#34-错误码)
  - [3.5 协议版本与旧 pod](#35-协议版本与旧-pod)
- [4. 命令行探测与选择](#4-命令行探测与选择)
  - [4.1 探测优先级与 id 规则](#41-探测优先级与-id-规则)
  - [4.2 会话选择、存储与回落](#42-会话选择存储与回落)
  - [4.3 设置 API 与 schema v3](#43-设置-api-与-schema-v3)
  - [4.4 本机事实（2026-11-01 探测，仅这台机器）](#44-本机事实2026-11-01-探测仅这台机器)
- [5. `pod_exec` 的跨重启 hold](#5-pod_exec-的跨重启-hold)
  - [5.1 时序](#51-时序)
  - [5.2 `pending-exec.json` 与恢复扫描](#52-pending-execjson-与恢复扫描)
  - [5.3 回合关闭时的送达](#53-回合关闭时的送达)
  - [5.4 边界](#54-边界)
- [6. 冻结模式与生命周期](#6-冻结模式与生命周期)
  - [6.1 设置 schema v3](#61-设置-schema-v3)
  - [6.2 状态机](#62-状态机)
  - [6.3 `pod.log`](#63-podlog)
  - [6.4 生命周期](#64-生命周期)
  - [6.5 `pod_freeze` 的 job 级语义](#65-pod_freeze-的-job-级语义)
- [7. 设置 API 与 `escapePod` 服务](#7-设置-api-与-escapepod-服务)
  - [7.1 HTTP 路由](#71-http-路由)
  - [7.2 Cordis 服务 `escapePod`](#72-cordis-服务-escapepod)
  - [7.3 单例](#73-单例)
  - [7.4 设置页 UI（`client.js`）](#74-设置页-uiclientjs)
- [8. 安全模型与限制](#8-安全模型与限制)
  - [8.1 沙箱、账本与前缀](#81-沙箱账本与前缀)
  - [8.2 管道、token 与身份通道](#82-管道token-与身份通道)
  - [8.3 已知限制（如实列出）](#83-已知限制如实列出)
- [9. 测试方法](#9-测试方法)
  - [9.1 三套测试与一条命令复算](#91-三套测试与一条命令复算)
  - [9.2 静态自测（112 项）](#92-静态自测112-项)
  - [9.3 单元测试（6 个文件，130 项）](#93-单元测试6-个文件130-项)
  - [9.4 远程自测（17 项）](#94-远程自测17-项)
  - [9.5 身份通道套件（9 项，可选）](#95-身份通道套件9-项可选)
  - [9.6 自测历史](#96-自测历史)
  - [9.7 已验证证据摘要](#97-已验证证据摘要)
  - [9.8 未覆盖 / 未验证](#98-未覆盖--未验证)
- [附录 A 错误码速查表](#附录-a-错误码速查表)
  - [A.1 管道 / 协议 / 前缀](#a1-管道--协议--前缀)
  - [A.2 文件策略与审批](#a2-文件策略与审批)
  - [A.3 账本 / 游标 / job](#a3-账本--游标--job)
  - [A.4 冻结 / 命令行 / 身份通道](#a4-冻结--命令行--身份通道)
  - [A.5 OS 侧（非本包协议码）](#a5-os-侧非本包协议码)
  - [A.6 状态与响应字面量](#a6-状态与响应字面量)
- [附录 B 常量与数字速查表](#附录-b-常量与数字速查表)
  - [B.1 版本、协议与固定标识](#b1-版本协议与固定标识)
  - [B.2 文件与目录位置](#b2-文件与目录位置)
  - [B.3 时间预算与超时](#b3-时间预算与超时)
  - [B.4 容量与数量上限](#b4-容量与数量上限)
  - [B.5 测试计数](#b5-测试计数)
  - [B.6 本机实测数字（2026-11-01 探测，仅这台机器）](#b6-本机实测数字2026-11-01-探测仅这台机器)
- [附录 C 术语表](#附录-c-术语表)
- [附录 D 文档索引与交叉链接](#附录-d-文档索引与交叉链接)
  - [D.1 按任务找章节](#d1-按任务找章节)
  - [D.2 配套文档](#d2-配套文档)
  - [D.3 书写约定](#d3-书写约定)
  - [D.4 维护约定（改标题与改链接时看这里）](#d4-维护约定改标题与改链接时看这里)

---

## 1. 架构

本包是「Host 插件 + detached pod 进程」的双进程结构：工具调用负责解析策略、现签前缀、发请求与渲染结果，真正的命令由 pod 在命名管道后 spawn，账本与鉴权是两侧唯一的共享真相。

### 1.1 两个进程

```text
Host 插件（DSH 进程内，会重启）
  index.js   工具实现 / pod 客户端 / 收养 / 恢复扫描 / 设置 API
  client.js  插件页 UI（Web）
  │
  │  命名管道（JSON Lines，token 鉴权，单客户端，可选 OS 身份校验）
  ▼
pod 进程（pod.mjs，Medium 完整性，detached；普通 Host 不在任何 job 里，桌面 Host 经计划任务）
  │
  ├─ read-only / workspace-write：Host 用 ctx.sandbox.confine() 现签的 runner 前缀 + 目标 argv
  │    └─ 受限 runner（Low 完整性 + WRITE_RESTRICTED，kill-on-close Job）
  │         └─ 命令本身（powershell / cmd / bash）
  └─ danger-full-access：无前缀，pod 直接 spawn 目标 argv（pod 自身 Medium 令牌）
       └─ 命令本身（powershell / cmd / bash）
```

- Host 用 `spawn(process.execPath, [pod.mjs, '--serve', ...], { detached: true,
  stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true })` + `unref()` 启动 pod，
  **不经过** `ctx.subprocess` / `ctx.jobs` / `ctx.terminal`（否则会进 DSH 的 kill-on-close
  Job，重启即死）。
- stdin 是唯一的 spawn 期 token 通道：Host 写一行 32 字节 hex 后立即 `stdin.end()`；pod 只读
  第一行，之后 stdin 的 EOF/EPIPE 都是正常事件（Host 退出、DSH 重启），**绝不因此退出**。
- 单客户端：pod 同时只服务一个 Host 连接，第二个连接收到 `EBUSY` 并关闭；Host 断开后 pod
  继续活着，等下一个连接。
- token 只在双方内存里（不落盘、不进 argv）。DSH 重启后的新 Host 拿不到旧 token，用
  `handover` 接管；接管由 pod 记录并在 `pod_status.auth.handoverCount` 可见。

### 1.2 启动器（`launcher.mjs`）

pod 有 `direct` 与 `schtasks` 两条启动路径，由 `launcher.json` 选择，默认 `auto` 先探测再决定。
文件形状是 `<dataRoot>/launcher.json` 的 `{ "mode": "auto" | "direct" | "schtasks" }`（缺省 `auto`）：

| 模式 | 做法 | 适用 |
|---|---|---|
| `direct` | Host 直接 detached `spawn()` | 普通 node Host：pod 是 DSH 进程的子进程，但不在任何 job object 里 |
| `schtasks` | `schtasks /Create` + `/Run` + `/Change /DISABLE`，经 `<dataRoot>/launch/` 下的 `.cmd`/`.vbs` 间接启动 | 桌面/Electron Host：Chromium 会把子进程放进 `KILL_ON_JOB_CLOSE` 的 job，Task Scheduler 拉起的进程父进程是 svchost，在 DSH 的 job 之外 |
| `auto` | 先探测 `schtasks` 是否可用，再决定 | 默认；探测失败退回 `direct` |

- 计划任务名前缀 `dsh-escape-pod-`，后缀是 dataRoot 的短哈希（一个 profile 一个任务）。
- `schtasks` 路径没有 stdin，因此 pod 必须以 `--bootstrap-handover` 启动：没有初始 token，
  只能由带「身份通道已兑换 nonce」的 `handover` 认领，且要求 `attest-policy` 处于 `enforce`。
  Host 侧用 `podSupportsStdinlessBootstrap()`（检查 `pod.mjs` 是否声明该参数）作为显式开关，
  不支持时拒绝走 `schtasks`。
- 所有 `schtasks` 调用都有 8 秒超时，失败只记录、不抛错；`pod_status` 的
  `launcherMode=` / `launcher=` / `task=` / `schtasks=` 四行如实报告选了哪条路。

### 1.3 管道协议

JSON Lines over Windows 命名管道（管道名由稳定身份种子推导，形如
`\\.\pipe\dsh-escape-pod-core-<sha256(v1|user+hostname)[0..12]>`）。

**协议版本 = 3**（`shared.mjs` 的 `PROTOCOL_VERSION`）：`2` = 鉴权 + 单客户端管道；
`3` = `run` 请求带**每次调用**的文件策略（`mode` / `unescorted`）。请求形状变了，因此两个
方向都不许猜：Host 在每条连接上只问一次 `hello` 学到 `protocolVersion` 并缓存，`pod_run` /
`pod_exec` 发请求前校验；`protocol < 3`（或旧 pod 根本不报版本）直接 `EPROTOCOL`
fail-closed，提示先 `pod_status action:"relaunch"`——**本次不执行任何命令**。升级插件后必须
relaunch，或等旧 pod 空闲退出后由下一次调用重建（见 §3.5）。

**每条请求都必须带 `token` 字段**；缺失/不匹配 → `{ok:false,error:{code:"EBADTOKEN"}}` 并关闭
连接，不产生任何状态变化。例外：`identify` 与 `handover`（新 Host 无法知道旧 token）。

| op | 作用 |
|---|---|
| `ping` / `hello` | 返回 pod 身份、`protocolVersion` 与 job 列表（Host 用它学协议版本） |
| `status` | pod 身份、钉死的形态模板、`auth`、`identity`、全量 job 投影 |
| `identify` | 公布身份通道端口（不需要 token） |
| `handover {newToken, nonce?}` | 新 Host 接管：pod 空闲（上一代连接已断）时轮换 token；`enforce` 下要求已兑换的 nonce（`EUNATTESTED`），有活动连接时 `EBUSY`，`allowHandover:false` 时 `EHANDOVERDISABLED` |
| `run {prefix, unescorted?, mode, escalated, argv, cwd, command, description?, timeoutMs?, env?, enforcement, host, sessionId}` | 校验 per-call 前缀与本次 `mode` → 先写 `meta.json` → 按模式 spawn（见 §1.4）→ 返回 `jobId/runnerPid/policy`。`mode` 是权限而不是提示：非法值 `EBADMODE`；`unescorted:true` 不给 `danger-full-access` 是 `EUNESCORTEDMODE`；`danger-full-access` 不带 `unescorted` 是 `EMODEUNESCORTED`；`unescorted` 还带前缀是 `EPREFIXUNEXPECTED`。`timeoutMs` 可选，缺省 = 不限时（`pod_run` 永不携带） |
| `output {jobId, from, maxBytes, sessionId?, adopt?}` | 从 `out.log` 绝对偏移读；`maxBytes` 被 clamp 到 1 MiB；返回 `prefixHash`、按 channel 切分的 `chunks`、`timedOut/timeoutMs`、`spillPath` |
| `ack {jobId, offset, hash}` | 原子写 `cursor.json`；单调，旧偏移只回 `skipped:"behind-cursor"`；坏 hash 报 `EPREFIXHASHMISMATCH` |
| `kill {jobId, timeoutMs?, adopt?}` | 杀 runner（kill-on-close Job 连带结束命令）；`timeoutMs` 把这次终止标记为超时 |
| `freeze {jobId, action: freeze\|thaw, maxFreezeMs?, adopt?}` | job 级冻结/解冻（见 §6.5） |
| `shutdown` | 结束所有 job 并退出（维护/设置页使用） |

### 1.4 per-call 沙箱前缀与形态模板

沙箱前缀每次调用现签、随请求下发、绝不缓存，pod 只做形状校验与拼接。Host 在每次需要执行
命令的调用里都重新向沙箱 seam 要一份前缀（占位目标永远不会被执行），`mode` 是**这一次调用**
解析出的会话文件策略：

```js
ctx.sandbox.confine([process.execPath, 'dsh-escape-pod-core-placeholder-never-executed'],
                    { mode, workspaceRoot, sessionId? })   // mode = read-only | workspace-write
// -> { argv: [node, runner.js, --workspace <ws>, --temp <tmp>, --mode <mode>,
//             (--write-sid S --temp-write-sid S)?, '--', node, <placeholder>], ... }
```

`danger-full-access` **根本不会走到这一步**：它不调用 `confine()`，`prepared` 是
`unescortedPolicy()` 的 `{ unescorted: true, prefix: null, fingerprint: 'unescorted',
enforcement: 'none' }`（windows-acl runner 的 `--mode` 只认受限两种模式，把完全访问伪装成
前缀会被 runner 以 `unknown mode` 拒绝，所以这里连前缀都不签发）。

Host 取 `--` 之前的全部作为**前缀**，然后：

1. 首次 spawn pod 时用 `--template-b64 <base64url(JSON)>` 把**形态模板**交给 pod
   （`--template-json` 只为旧调用方保留）。前缀本身不在 spawn 时传，pod 也不缓存前缀。
2. 每次 `run` 把这次现签的 `prefix` 数组随请求带过去；pod 校验形状、对照模板、要求
   `--mode` 等于请求的 `mode`、确认 `--temp` 目录仍然存在，才拼出
   `[...前缀, '--', ...argv]` 并 spawn；前缀的 sha256 指纹由 pod 自己算并写进 `meta.json`。
3. 没有 `set-prefix` 这类"重签"流程：旧 Host 的会话 temp 授权随它退出被收回，新 Host 直接为
   下一次调用现签前缀即可；拿着旧前缀的请求会 `EPREFIXSTALE` fail-closed。

pod 侧只做三件事：`validatePrefix`（fail-closed）、按 runner 的稳定 argv 契约拼出
`[...前缀, '--', ...Host 下发的目标 argv]` 再 spawn、记账。`--` 是 runner 契约的一部分，
含 `--` 的前缀会被拒绝；缺 `--workspace/--temp/--mode`、未知标志、flag 不配对、
`--mode` 不是受限两种模式之一（`EPREFIXMODE`）、与本次请求的 `mode` 不一致
（`EPREFIXMODEREQUEST`）、目录不存在（`EPREFIXSTALE`）或与钉死的形态模板不一致，一律
拒绝执行。

**形态模板不再钉 `mode`**：模板只钉 `program` + `runnerPath`（必须在 DSH 安装树内）+
`workspaceRoot`，`describeTemplate().pin` 把这条规则写在状态输出里。理由是权限本来就可以在
两次调用之间合法地变（只读会话被审批提宽、写会话被用户收窄），钉死 `mode` 只会拒绝随之而来
的合法前缀，或者逼 Host 为一个已经不在生效的模式反复签前缀。`template.modes` 只是状态展示
用的说明，真正的权限校验发生在每次请求自己的 `mode` 上（§3）。

> pod 是同一用户的 Medium 进程，前缀契约约束的是**命令的权限**，不是 pod 的权限；
> pod 侧的防护是「只拼接 Host 签发的 runner 调用」+ token/单客户端/身份通道（§8.2）。

### 1.5 账本

默认位置（工作区之外）：

```text
%LOCALAPPDATA%\dsh-escape-pod-core\jobs\<jobId>\
  meta.json      # 先写它，再 spawn。argv/argvHash/cwd/command/description/startedAt/sessionId/
                 # policy {mode, escalated, unescorted}/prefixFingerprint/prefixProfile/模板/
                 # host/podIdentity；spawn 后补 runnerPid。完全访问时 prefixFingerprint=null
  out.log        # stdout+stderr 合并、按到达顺序原样追加；偏移都是绝对字节偏移
  segments.jsonl # 每行 {offset,length,channel}，把同一段字节切成 stdout/stderr 通道
  cursor.json    # Host已消费偏移 + 该偏移之前全部字节的 sha256（tmp+rename 原子写）
  exit.json      # runner 退出后写：status/exitCode/signal/endedAt/durationMs/totalBytes/
                 # lossy/writeErrors/runnerFailure/timedOut/timeoutMs
```

- **必须在工作区之外（安全要求，不是偏好）**：被托管命令跑在 `workspace-write` 沙箱里，对
  `workspaceRoot` 有写权限；账本若在里面，它能改写三态与 argvHash，等于自己给自己出无罪证明。
  Host 与 pod 两侧都校验 `stateDir` 不在 `workspaceRoot` 内（pod 还用 realpath 复查），
  落在里面就 fail-closed（Host `ESTATEINSIDEWORKSPACE`，pod 拒绝启动）。
  **注意这条规则只对受限模式成立**：`danger-full-access` 的命令与当前用户同权，账本虽然在
  工作区之外，它照样能改写（§8.1）。
- `meta.policy` 记录这次命令**实际**跑在哪个策略下：`{mode, escalated, unescorted}`。
  `escalated:true` = 这一次调用经过 DSH 审批提宽（只对这一条 job 有效）；`unescorted:true`
  = 没有 runner 前缀、以 pod 自身 Medium 令牌运行。
- 默认 `%LOCALAPPDATA%\dsh-escape-pod-core`；没有 `LOCALAPPDATA` 时依次退到
  `$DSH_HOME\.escape-pod-core`、`<home>\.dsh-escape-pod-core`。`stateDir` 可覆盖。
- `jobId` 形如 `podc-<base36 时间戳>-<8 hex>`，同时是目录名，协议侧用
  `^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$` 做路径穿越防护。
- `status` 取值：`running` / `settled` / `killed` / `runner-failed`（退出码 127 且 stderr 出现
  `windows-acl-run:` 签名 = 命令从未运行）/ `spawn-failed` / `ledger-failed` / `unknown`
  （本 pod 实例没有该 job 句柄且账本里没有 `exit.json`——**结果未知，不要臆断退出码**）。

### 1.6 收养到 `ctx.jobs`

运行中的 pod job 会被收养成 registry job（`kind=bash`，`JobKind` 是封闭联合；pod 身份放在
label：`escape-pod <podJobId> · <命令摘要>`），因此平台工具也能看见/读/杀它。

- **unowned（有意偏离原生）**：pod 跨会话、跨重启存活；owned 记录会被会话销毁连带
  cancel+await，且别的会话看不见——那会让命令在会话结束时从 `job_list` 消失，与目标冲突。
  代价：没有完成后的自动通知（`job_notice` 只对 owned job 生效），需要模型自己收尾。
- **生死线**：Host dispose 绝不杀 pod 命令。`dsh-jobs-local` 的 teardown 与显式 kill 走同一个
  `cancel(reason)`，但 reason 不同：`disposeAll()` 用 `"jobs service disposed"`、
  `disposeOwned()` 用 `"owner disposed"`（解除收养、结算记录、不杀 pod）；`job_kill` / 其它
  `ctx.jobs.kill` 才真调 `pod.kill`。插件 effect cleanup 先 `markHostDisposing()`，此后任何
  cancel 都按 teardown 处理；`job_kill` 工具在 `tools/pre-execute` 里先打标记，即使模型给的
  reason 撞了哨兵也仍然真杀。
- **游标**：收养优先从 `cursor.json` 的 `offset` 开始（Host最后一次 `ack` 的位置），因此 DSH
  停机窗口里的输出会补进 `job_output`；没有 cursor 才退回 pod 当前 `totalBytes`。
  `cursor.state=mismatch` 时从 `totalBytes` 收养并显式报 `cursor-mismatch`。
- teardown 时必须**结算**记录（`done` 立刻 resolve，detail 写明 "left running"），否则
  `disposeAll()` 会一直 await `job.settled`，Host 退出卡住。

### 1.7 会话归属

每个 job 在 `meta.json` 记录发起它的 DSH 会话（`sessionId`，来源是 `exec.agent.id`）。
`shared.mjs` 的 `jobOwnership(jobSessionId, callerSessionId, adopt)` 是 Host 与 pod 共用的
唯一判定函数：

- `job.sessionId === caller` → 自己的 job，默认允许；
- 存在且不等于 caller → `EFOREIGNJOB`；
- `null`（旧账本/无主）→ 对任何真实会话都算 foreign，默认拒绝；
- `adopt: true` → 允许跨会话读/杀，并返回 `adoptedFrom`（旧账本为 `null`）。

Host 预检（内存归属表）与 pod 权威检查（`output`/`kill`/`cursor`/`ack`/`freeze`，`kill` 在
“已结束”捷径**之前**检查）两层都做。`pod_status` 只列本会话 job，其它会话/无主只给
`foreignJobs` / `unownedJobs` 计数，不泄露 jobId、命令与 spill 路径。会话 id 跨重启稳定，
所以原会话重启后仍能直接读写自己的 job。

---

## 2. 工具参考

模型面固定七个工具，共享同一组公共约定：不暴露偏移、每次调用重新解析执行预算 / 文件策略 / 命令行，诊断字段只出现在结构化结果里。

### 2.1 公共约定

- 模型只能看到七个工具：`pod_run`、`pod_exec`、`pod_output`、`pod_kill`、
  `pod_freeze`、`pod_status`、`pod_shell`。
  **原名 `podc_*`（`podc_run` / `podc_exec` / …），1.1.0-hotfix.1 起改为 `pod_*`**；
  `pod_shell` 是新增的。只有工具名变了，管道名、账本路径、`jobId` 前缀 `podc-`、环境变量
  `PODC_ATTEST*` 一律照旧，旧账本不用迁移。
- 模型面文本与原生 job 工具同形：stdout 在前，stderr 以 `[stderr]` 段在后，最后一行
  `[status: running|completed|killed, detail]`；非零退出码另有 `[exit code: N]`。
- **不暴露偏移**：`pod_output` 没有 `from`/`maxBytes`，只返回“上次之后的新输出”；切块按行
  边界 + UTF-8 码点对齐，拼接起来与 `out.log` 逐字节一致。截断/丢失只出现原生标记
  `[output truncated]`、`[earlier output was dropped from the pod retention window]`。
  绝对偏移读取只存在于非模型面的 `scripts/pod-raw.mjs`（维护者 CLI，不写 cursor）。
- 每次调用都重新解析三样东西，一律不在插件加载或 pod spawn 时缓存：
  执行预算（§2.9）、**会话文件策略**（§3）、**命令行**（§4）。
- `pod_run` / `pod_exec` 的返回值带两个只出现在结果里、不进 `message` 的字段：
  `policy {mode, standingMode, escalated, unescorted, source, workspaceRoot}` 与
  `shell {kind, id, path, version, source, fallback}`。文本必须与恢复路径逐字节一致，
  所以这类诊断信息只放在结构化结果里（§5.1）。

### 2.2 `pod_run`：后台形态

参数（`additionalProperties: false`）：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `command` | string | 是 | 命令文本；上限 16000 字符 |
| `shell` | `powershell` \| `cmd` \| `bash` | 否 | 解释器，默认 `powershell`；实际路径由 §4 的解析顺序决定（会话选择 → 设置默认 → 自动探测） |
| `description` | string (≤200) | 否 | 工具卡片/日志用；进 `meta.json` 与 `pod_status`，不进 label |
| `cwd` | string | 否 | 必须位于本次 policy 的 `workspaceRoot` 内（越界 `ECWDWORSKSPACE`），默认 workspace 根 |
| `sandbox_permissions` | `workspace-write` \| `danger-full-access` | 否 | 为**这一次调用**申请更宽的模式；只有 `allowed-once` 审批才执行（§3.3） |
| `justification` | string | 否 | 为什么这次要多要权限；目标模式 ≠ 会话模式时必填（`EJUSTIFICATION`） |

返回（主要字段）：`jobId`、`sessionId`、`registryJobId`（收养进 `ctx.jobs` 的 id，收养不可用
时为 `null`）、`runnerPid`、`podPid`、`status: "running"`、`command`、`description`、`cwd`、
`startedAt`、`ledgerDir`、`enforcement`、`shell`、`policy`、
`prefix {fingerprint, perCall, …}`（完全访问时是 `{fingerprint: "unescorted", unescorted: true}`）、
`template`、`policyVariant`、`pipeName`、`connection`、`spawnInfo`、`message`。

模型面文本里与本次 hotfix 相关的三行：

```text
policy=workspace-write（跟随当前会话文件策略）：命令在 runner 的受限令牌 Low 完整性 + kill-on-close Job 里运行
会话策略=workspace-write workspace=Z:\Project\DSHproject
本次调用现签前缀=1f3c9a… variant=workspace-write + sessionId
```

完全访问时换成：

```text
policy=danger-full-access（本次调用经 DSH 审批提升：只对这一次有效，不改变会话策略）：danger-full-access，**不带任何沙箱前缀**，
命令以 pod 自身 Medium 令牌运行=真正完全访问（命令与用户同权，可改写账本/任意用户可写文件）
本次没有前缀：danger-full-access 不调用 ctx.sandbox.confine（fingerprint=unescorted）
```

**没有 `timeoutMs`**：后台形态不设命令超时，这是它存在的理由。
**审批只覆盖这一次调用**：job 的整个生命周期属于这次调用，提宽不会写成会话策略。

### 2.3 `pod_exec`：前台形态

参数：`command`（必填）、`shell`（可选）、`description`（可选，≤200）、`cwd`（可选）、
`sandbox_permissions` / `justification`（可选，语义与 `pod_run` 完全相同，§3.3）。

渲染给模型的消息（`message`）：

```text
<stdout>
[stderr]
<stderr>
[exit code: 3]        ← 只在非零时出现
[status: completed]   ← completed | killed | failed
```

超时时首行加：

```text
命令超时：超过 N ms（原生 shell 执行器的 timeoutMs）后已终止；下面是终止前已经产生的部分输出。
...
[status: killed, timed out after N ms]
```

返回（主要字段）：`status`、`exitCode`、`signal`、`text`、`chunks`、`truncated`、`lossy`、
`durationMs`、`command`、`description`、`cwd`、`timedOut`、`timeoutMs`、`limits`、
`policy`、`shell`、`resume {available, held, reason}`、`message`。**模型面没有 jobId / 偏移 /
游标**；`policy` 与 `shell` 只放在结构化结果里，因为恢复路径渲染的文本必须逐字节一致。

- 与 `pod_run` 走同一条 `pod.run` 路径（同一个 `run` op、同一份现签前缀），只是阻塞到结算，
  每 200 ms 查一次账本状态。
- 调用被取消（`exec.signal` abort）→ **停止等待但不杀命令**，如实返回 `[status: running]` +
  “等待被取消，命令未中止”。命令不在 DSH 进程树里，杀它不是“取消”。
- **不收养进 `ctx.jobs`**：原生前台命令也不在 `job_list` 里；收养会占 unowned 并发配额，
  还会多出一条本不该存在的后台读路径。要后台可见就用 `pod_run`。

### 2.4 `pod_output`

参数：`jobId`（必填）、`adopt`（可选，默认 false）。

返回：`text`、`running`、`exitCode`、`status`、`truncated`、`lossy`、`hasMore`、
`adoptedFrom`（接管时）、`message`。

- 内部先读 `cursor.json` 得到已消费偏移，再向 pod 读最多**当前生效的原生
  `maxOutputBytes`**；成功后 fire-and-forget 发 `ack` 写回新偏移（失败只记日志）。
- `cursor.state=mismatch/ahead/malformed/unreadable` 时**拒绝读**（`ECURSORMISMATCH`），
  不从 0 重放；修复方式见 `pod_status`/账本（必要时删除该 job 的 `cursor.json`，退化为
  “从 total 收养”）。
- 已收养的 job 直接 `ctx.jobs.read(registryId)`（先 `pollAdopted` 逼泵追平），消费的是
  `job_output` 用的同一个 `modelCursor`，因此两条路径不可能看到同一段两次；读完按
  `baseOffset + registry output.total` ack pod 游标。

### 2.5 `pod_kill`

参数：`jobId`（必填）、`adopt`（可选）。

返回：`ok`、`killed`、`status`、`exitCode`、`signal`、`registryJobId`、`adoptedFrom`（接管时）、
`message`。已结束、或句柄属于重启前消失的 pod 实例时如实返回 `killed=false`，不假装成功。

### 2.6 `pod_freeze`

参数：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `jobId` | string | 是 | 正在运行的 job |
| `action` | `freeze` \| `thaw` | 是 | 冻结整棵命令树 / 解冻并按剩余预算重挂超时 |
| `adopt` | boolean | 否 | 跨会话接管孤儿 job |
| `maxFreezeMs` | number | 否 | 冻结看门狗上限；0/缺省 = pod 默认 30 分钟；到点自动解冻并记日志，**不杀命令** |

返回：`frozen`、`frozenAt`、`frozenForMs`、`remainingFreezeMs`、`maxFreezeMs`、`freezeCount`、
`thawable`、`alreadyFrozen`、`alreadyThawed`、`adoptedFrom`、`message`。

错误码：`EBADJOBID`、`ENOJOB`、`EFOREIGNJOB`、`ENOTHANDLE`（只有账本、没有本 pod 的句柄；
pod 重启过或赋值失败）、`ENOTRUNNING`、`EFREEZEUNSUPPORTED`、`EOSFAIL`、`EBADOP`（旧 pod
不认识 freeze op，需 `pod_status action:"relaunch"`）。

### 2.7 `pod_status`

参数：`action: "relaunch"`（可选）与 `force`（可选）。不传 = 只读。

返回（主要字段）：`podPid`、`podStartedAt`、`generation`、`freeze`（能力探测 + 最近一次入
job 失败）、`enforcement`、`connection`、`policy`（本次会话**当前**的文件策略，即下一次
`pod_run` / `pod_exec` 的默认值）、`shell`（不传 `shell` 时下一次会用的解释器）、`template`、
`workspaceRoot`、`dataRoot`、`running`、`jobs[]`（仅本会话）、`foreignJobs`、`unownedJobs`、
`adoptionSync`、`limits`、`resumeService`、`recovery`、`attestation`、`pipeName`、`spawnInfo`、
`launcher*` 四行信息、`message`。

每个 job 带 `cursor {offset, hash, state, lossy, ...}` 与
`registry {adopted, id?, status?, sessionId?, cursor?}`，以及 freeze 投影
（`frozen=剩…` / `freeze=已解冻N次`）。`message` 里与本次 hotfix 相关的行：

```text
podVersion=1.1.1 protocol=3
会话文件策略=workspace-write workspace=Z:\Project\DSHproject source=sandboxPolicy（pod_run / pod_exec 的默认；申请更宽模式要过 DSH 审批，只对本次调用有效）
（命令行：powershell → C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe，来源：自动，版本：5.1.19041.6456）（不传 shell 时 pod_run / pod_exec 的默认解释器；切换与查看候选见 pod_shell）
```

- `policy.source` 会如实写出降级原因：`sandboxPolicy`、`fallback:workspace-write`（服务不存在）、
  `fallback:sandboxPolicy-error` / `fallback:sandboxPolicy-empty`（`resolve()` 抛错或返回空），
  非法 `mode` 另有 `modeNote`。
- `pod_status` **每次调用都重新解析**这两项，所以会话中途切权限、改设置页默认值，
  下一次 `pod_status` 立刻可见。
- `protocol=3` 与 `podVersion` 同行输出；`pod_run` / `pod_exec` 的 `EPROTOCOL` 就是按这个值判的
  （§3.5）。

`message` 末行给出
`resumableToolCalls=available|unavailable（原因）` 与 `恢复扫描=…`。

`action: "relaunch"` 会杀掉当前 pod 并用当前 launcher 重新拉起（用于换代码/实测启动路径）；
pod 里还有 running job 时会拒绝，除非同时 `force: true`。

### 2.8 `pod_shell`：命令行探测与选择

**Host-only 工具**：只做探测与记录会话选择，**不连接、也不唤醒 pod**（打开设置页同理）。

参数：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `action` | `list` \| `use` \| `reset` | 是 | 其它值 → `EARGS` |
| `shell` | `powershell` \| `bash` \| `cmd` | 否 | `use` 时必填且**不能是 `cmd`**；`reset` 省略 = 清除该会话全部类型 |
| `id` | string | 否 | `use` 时必填：候选 id（见 `list`），必须存在于该类型且 `available` |

三个动作：

| action | 行为 | 错误 |
|---|---|---|
| `list` | 按类型列出全部候选（`id` / `label` / `path` / `version` / `source` / `available` / `current` / `isDefault` / `fromSession`），给出本会话最终应用（`applied`），并打印回落说明；`cmd` 固定不可选 | —— |
| `use` | 写会话选择（`<stateDir>/shell-sessions.json`），对当前会话后续所有 `pod_run` / `pod_exec` 生效并跨 DSH 重启保留；返回新状态 | `cmd` → `EARGS`（只有系统一个版本）；缺 `id` → `EARGS`；id 不在该类型候选里 → `EARGS`（附当前可用 id）；候选 `available:false` → `ESHELLUNAVAILABLE`；没有会话 id → `ENOSESSION`（先拒绝，再谈写文件） |
| `reset` | 清除会话选择，回到「设置默认 > 自动探测」；`shell` 省略清全部类型 | 非法 `shell` → `EARGS`；`shell:"cmd"` 没有可清的选择，只回说明；没有会话 id 只回说明（不写文件） |

返回：`ok`、`op: "shell"`、`action`、`sessionId`、`generatedAt`、`detectionError`、`defaults`、
`kinds[]`、`applied`、`warning`、`message`。

`message`（模型面）形如：

```text
本会话命令行（会话覆盖 > 设置默认 > 自动探测）
powershell  → Windows PowerShell 5.1  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  来源：自动
bash        → PortableGit（dsh-ops）   Z:\DSH-Data\dsh-ops\bash-ipc\3cdbe2ba…\bin\bash.exe        来源：会话覆盖
cmd         → cmd.exe（固定）          C:\Windows\System32\cmd.exe  固定（不可选）
候选（* = 当前应用；不可用项不会被自动选中）：
  powershell
    * ps-system  Windows PowerShell 5.1  C:\…\powershell.exe  [当前应用，设置默认]
       pwsh-config  PowerShell（配置 pwshPath）  …  [不可用]
  bash
    * bash-ops-3cdbe2ba  PortableGit（dsh-ops）  Z:\…\bash.exe  [当前应用，会话覆盖]
用法：action:"use" shell="powershell|bash" id="<候选 id>"；action:"reset"（省略 shell 时清除全部类型）。cmd 只有系统一个版本，固定不可选。
说明：命令行是可选覆盖，不会强制替换系统原装的解释器；不做选择时沿用设置默认/自动探测，行为与以前一致。
建议先用默认（原装）命令行，只有在它不可用、启动失败或版本不满足时才切换。所选路径运行期不可用时按「会话选择 → 设置默认 → 自动探测」逐级回落，并在结果里说明。
```

- **不强制替换原装解释器**：不做选择时行为与 1.1.0 完全一致（`powershell` → 系统
  Windows PowerShell 5.1，`bash` → dsh-ops PortableGit）。
- 写文件失败**不让调用失败**：选择在本次 Host 内存里生效，`warning` 如实写「没有写入
  `<stateDir>/shell-sessions.json`…DSH 重启后会丢失」（§4.2）。
- 探测失败不算调用失败：`detectionError` 有值、`applied` 走回落路径，`list` 仍然可用。
- 候选、id 规则、探测优先级与回落细节见 §4。

### 2.9 执行预算（输出窗口与命令超时）

两个值都属于**原生 shell 执行器**（Loader 条目 `pwsh-sandbox`，POSIX 为 `bash-sandbox`）的
实时设置：设置页「单流输出上限（字节）」「命令超时（毫秒）」。逃生舱**每次工具调用都重新
读取**，不在 pod spawn 时钉死。

读取顺序（每层失败都记进 `reasons`）：

| 顺位 | `source` | 读法 |
|---|---|---|
| 1 | `shell.resolve` | `ctx.get('shell').resolve({command: <永不执行的探针>})` → `timeoutMs` / `stdoutMaxBytes`（官方 seam，执行器自己的默认值与 cap 都算进去） |
| 2 | `shell.config` | `shell.config.timeoutMs.get()` / `shell.config.maxOutputBytes.get()` |
| 3 | `settings:<条目>` | `ctx.get('settings').describe({redactSecrets:true})` 里 `pwsh-sandbox`（POSIX 优先 `bash-sandbox`）的值 |
| 4 | `fallback:native-defaults` | `120000` / `64000`，并在 `reasons` 里逐条写清为什么读不到 |

- 输出窗口随每次 `output` 请求下发，pod 侧 clamp 到 1 MiB 硬上限（`outputChunkBytes` 只是
  旧客户端/CLI 的兜底）。
- 命令超时只随 `pod_exec` 的 `run` 请求下发；pod 用 `jobTimeoutOf()` clamp 到
  `2³¹−1`（`setTimeout` 的 32 位上限）。到期由 pod 侧 timer 终止 runner
  （`killRecord` → `taskkill /T /F` 兜底，跨 DSH 重启仍生效），账本写
  `status: killed` / `timedOut: true` / `timeoutMs`，已产生的输出全部保留。
- **`pod_run` 永远不带 `timeoutMs`**（后台形态不限时）。
- 旧 pod 忽略该字段时，Host 在 `timeoutMs + 1s` 后自己调 `kill({jobId, timeoutMs})`，
  pod 仍把这次终止标记为超时，两条路径的账本语义一致。
- `pod_status.limits` 给出实际值、`source`、`native`、`modelCeiling`、pod 兜底/硬上限与
  `appliesTo {timeout: "pod_exec", backgroundTimeout: "unlimited"}`；看到
  `fallback:native-defaults` 就该去查执行器是不是还没加载。

---

## 3. 文件策略与审批

命令的执行权限跟随 DSH 会话的实时文件策略；提宽必须逐次经过 `allowed-once` 审批，且只对这一条 job 生效、从不写回会话策略。

`pod_run` / `pod_exec` 执行的命令不再写死 `workspace-write`；策略在每次调用时重新解析，
用户在 UI 里中途切权限，下一条命令立即按新策略执行（§3.1）。

### 3.1 权威从哪来

```js
ctx.get('sandboxPolicy').resolve({ session: exec.agent.session })
// -> { mode: 'read-only' | 'workspace-write' | 'danger-full-access', workspaceRoot, sessionId }
```

| 情况 | 结果（`source` 如实标注） |
|---|---|
| 服务可用、`mode` 合法 | 用服务给出的 `mode` / `workspaceRoot` / `sessionId`（`source: "sandboxPolicy"`） |
| 服务不存在或没有 `resolve()` | `workspace-write` + 会话派生的 workspace（`source: "fallback:workspace-write"`） |
| `resolve()` 抛错 | 同上，附 `policyError`（`fallback:sandboxPolicy-error`） |
| `resolve()` 返回空值 / 非对象 | 同上（`fallback:sandboxPolicy-empty`） |
| `mode` 非法 | 回落 `workspace-write` 并带 `modeNote`（不猜更宽的） |

- `workspaceRoot` 必须是**真实存在的目录**，否则退回会话派生的根：runner 对不存在的根
  fail-closed，一个坏值不该被带进 `confine()`。
- `SANDBOX_MODES = ['read-only', 'workspace-write', 'danger-full-access']`，**数组下标就是
  权限比较**：更宽要审批、更窄是错误（审批不用于降级，见 §3.3）。
- 三处都按这条规则解析：`pod_run`、`pod_exec`、`pod_status`（状态里的 `会话文件策略=` 行）。

### 3.2 三种模式的执行形态

| 会话策略 | 前缀 | 命令的令牌 | 能写什么 |
|---|---|---|---|
| `read-only` | 有：`--mode read-only`（runner 不带写 SID） | Low 完整性 + `WRITE_RESTRICTED`，在 runner 的 kill-on-close Job 里 | 只能读 |
| `workspace-write` | 有：`--mode workspace-write`（工作区 + 会话 temp 写授权） | 同上 | `workspaceRoot` + 本次会话的临时目录 |
| `danger-full-access` | **无前缀**（`unescortedPolicy()`，连 `confine()` 都不调用） | pod 自身的 Medium 令牌 | 当前用户能写的一切 |

- 前缀每次调用现签、随命令下发、绝不缓存（§1.4）；`--mode` 必须等于本次请求的 `mode`，
  否则 `EPREFIXMODEREQUEST`；前缀里出现 `danger-full-access` 一律 `EPREFIXMODE` 拒绝。
- pod 侧 `planRunSpawn()` 是唯一决定"沙箱在不在链路里"的地方：
  escorted = `[...前缀, '--', ...argv]`；unescorted = `argv` 本身。纯函数，可单测断言。
- **完全访问的代价**：命令与当前用户同权，**可以改写账本**。旧的"命令无法伪造自己的
  `exit.json`"不变量只对受限模式成立；账本仍然放在工作区之外（位置规则不变），但不再声称
  对 `danger-full-access` 的命令防伪。这是用户显式选择完全访问的代价，工具描述、
  `pod_run` 文本、[README 的「账本与安全」节](./README.md#账本与安全) 与 §8.1 都写明。
- **只读模式的平台副作用（CLM）**：`read-only` 前缀的受限令牌会让 PowerShell 进入 Constrained
  Language（`CannotCreateTypeConstrainedLanguage`）：不能 `new` .NET 类型，`[Console]::OutputEncoding`
  赋值也会失败。插件的 UTF-8 前缀因此用 `try { … } catch { }` 包裹（CLM 下静默跳过），中文输出在
  只读会话里可能仍是 GBK——需要 UTF-8 文本时用 `shell:"bash"`，或申请一次 `workspace-write`。

### 3.3 审批时序

提宽走一条固定的十步时序，任一步失败都不起命令：

```text
resolveStandingPolicy(exec)                  → standing {mode, workspaceRoot, sessionId}
  ├─ sandbox_permissions 未给，或 = standing.mode   → 直接执行（不弹审批）
  ├─ validateEscalation(args, standing)            → ESANDBOXPERMISSIONS / EJUSTIFICATION / ESANDBOXNARROWER
  ├─ ctx.get('approval').request({agent, callId, toolName, reason, signal})
  │    └─ 只有 'allowed-once' 继续；denied / timeout / dismissed / 其它 → EAPPROVALDENIED
  ├─ 重新 resolveStandingPolicy                    → mode 或 workspaceRoot 变了 → EAUTHORITYCHANGED
  ├─ derivePrefix(..., 提宽后的 mode)              → 签这一次的前缀（danger 则 unescorted）
  ├─ assertStandingUnchanged()                     → TOCTOU 复核，变了 → EAUTHORITYCHANGED
  └─ 发 run 请求
```

规则（与 `dsh-bash-sandbox` 的 `lib/shells/approval.js` **1:1 对齐**，两个工具不能漂移）：

1. 只接受两个更宽的目标：`workspace-write` 或 `danger-full-access`；
2. 目标 ≠ 会话当前模式时**必须**给非空 `justification`；
3. 给了理由却没给目标 = 调用方写错（`EJUSTIFICATION`）；
4. 目标比当前会话**更窄** → 直接拒绝（`ESANDBOXNARROWER`）：审批从来不用于降级；
5. 目标 = 当前模式 → 不审批，按会话策略执行；
6. 没有审批服务、或这次调用没有 agent → `EAPPROVALUNAVAILABLE`，**不执行任何命令**；
7. 审批结果不是 `allowed-once` → `EAPPROVALDENIED`，不要重试、不要绕过；
8. **只对这一次调用有效**：job 的整个生命周期属于这次调用；不写会话策略、不改 `settings.json`；
9. 审批期间用户动了开关 → `EAUTHORITYCHANGED`（否则会在没人批准过的权威下执行）；
10. 签前缀与发请求之间还有窗口 → `assertStandingUnchanged()` 再复核一次（TOCTOU），
    失败时**一条命令都没起**。

`run` 请求把这次调用的权威一起带给 pod：`mode` + `escalated`。pod 不信任任何"默认值"，
它拿请求里的 `mode` 去比前缀的 `--mode`（§1.4），所以"Host 批准的"和"实际执行的"必然同一个。

### 3.4 错误码

| 错误码 | 何时 | 起了命令吗 |
|---|---|---|
| `ESANDBOXPERMISSIONS` | `sandbox_permissions` 不是两个合法值之一 | 没有 |
| `EJUSTIFICATION` | 理由不是字符串 / 没给目标却给理由 / 改模式但理由为空 | 没有 |
| `ESANDBOXNARROWER` | 申请的模式比当前会话更窄 | 没有 |
| `EAPPROVALUNAVAILABLE` | Host 没有审批服务，或这次调用没有 agent | 没有 |
| `EAPPROVALDENIED` | 审批结果是 `denied` / `timeout` / 关闭 / 其它任何非 `allowed-once` | 没有 |
| `EAUTHORITYCHANGED` | 审批期间或发请求前，会话 `mode` / `workspaceRoot` 变了 | 没有 |
| `EPROTOCOL` | 旧 pod（`protocol < 3`，或压根不报版本） | 没有 |
| `EPREFIXMODEREQUEST` / `EPREFIXMODE` | 前缀 `--mode` 与请求不一致 / 不是受限模式 | 没有 |
| `EUNESCORTEDMODE` / `EMODEUNESCORTED` / `EPREFIXUNEXPECTED` | `run` 请求的 `mode` 与 `unescorted` / `prefix` 自相矛盾 | 没有 |
| `EUNATTESTED` | `enforce` 下 `handover` 没有已兑换的 nonce（与策略无关，属管道鉴权） | 没有 |

### 3.5 协议版本与旧 pod

- `PROTOCOL_VERSION = 3`。Host 在**每条连接**上用一次 `hello` 学到 `protocolVersion` 并缓存；
  `pod_run` / `pod_exec` 在发 `run` 之前用 `checkRunProtocol()` 判定。
- `protocol < 3`（含旧 pod 不报版本）→ `EPROTOCOL` fail-closed，错误文本直接给出修复动作：
  `pod_status action:"relaunch"`。绝不允许把新字段发给旧 pod：它会忽略 `mode`/`unescorted`，
  命令会按错误策略执行而 Host 以为策略已经生效。
- 反向兼容是安全的：v3 pod 收到**不带** `mode` 的旧形状请求时，按前缀自己的 `--mode` 记账
  （`requestedMode ?? profile.mode`），所以老 Host 不会被拒。
- 升级路径：装包 → 重启 DSH → `pod_status` 看到 `protocol=3`；如果还是 2（或 `podVersion` 没变），
  执行 `pod_status action:"relaunch"`（有 running job 会拒绝，除非 `force:true`），或等旧 pod
  空闲退出后由下一次调用重建。

---

## 4. 命令行探测与选择

解释器由 Host 决定：探测结果被组织成带 id 的候选数据，解析顺序固定为「会话选择 → 设置默认 → 自动探测」，且默认不替换系统原装解释器。**本插件不自带任何 shell 二进制**：候选全部来自本机安装、PATH 与其他 DSH 插件（例如 dsh-ops 的 PortableGit）。

逃生舱只执行 Host 交给它的 `[shellPath, ...args]`，所以"选哪个解释器"完全是 Host 的事。
`shells.mjs` 把这件事变成数据：候选、来源、可用性、探测到的版本，以及一条设置页与
`pod_shell` 共用的解析路径。

### 4.1 探测优先级与 id 规则

| 类型 | 顺位（高 → 低） |
|---|---|
| `powershell` | 配置 `pwshPath` → `%ProgramFiles%\PowerShell\7\pwsh.exe` → `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` → PATH 里的 `pwsh` |
| `bash` | 配置 `bashPath` → 环境变量 `DSH_ESCAPE_POD_BASH` → dsh-ops PortableGit（由 dsh-ops 插件安装，本插件不提供；`<DSH_HOME>\dsh-ops\bash-ipc\<实例>\bin\bash.exe`，按 mtime 新 → 旧） → `%ProgramFiles%\Git\bin\bash.exe`、`%ProgramFiles(x86)%\Git\bin\bash.exe` → PATH 里的 `bash` |
| `cmd` | 只有 `%ComSpec%`（缺失时回落 `%SystemRoot%\System32\cmd.exe`），`selectable:false`、`fixed:true` |

- **显式来源（config / env）即使路径不存在也保留**，标成 `available:false`——那正是
  "我配的路径没了"该被看见的信号；自动发现的候选（system / path / plugin）只列真实存在的，
  否则一个永远跑不起来的条目会永远占据 `auto` 的第一位。
- 去重按 `realpath`（win32 大小写不敏感）：一个真实文件只出现一次，归到最高的来源。
- id 规则（会写进 `settings.json` 与 `shell-sessions.json`，所以必须可打印、可读、
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`）：

| 类型 | id 形状 |
|---|---|
| powershell | `pwsh-config`（配置）/ `ps-system`（系统 5.1）/ `pwsh-<major.minor>`（探测到版本）/ `pwsh-<major>` / `pwsh-path-<n>` |
| bash | `bash-config` / `bash-env` / `bash-ops-<实例名前 8 位>` / `bash-git` 或 `bash-git-<major.minor>` / `bash-path-<n>` |
| cmd | `cmd-system`（**故意不含版本号**：Windows 更新不该让唯一的 cmd 候选改名） |

- id 冲突时追加 `-2`、`-3`…：已保存的 id **永不复用、永不重编号**。
- 版本探测命令是数据（`shellVersionCommand()`）：powershell `-NoLogo -NoProfile -NonInteractive
  -Command $PSVersionTable.PSVersion.ToString()`、bash `--version`、cmd `/d /s /c ver`；
  3 秒超时，失败/被信号杀/非零退出都回答 `version: null`。结果按 `kind + path` 缓存 60 秒
  （失败也缓存，避免设置页每敲一下就 spawn 一个 shell）。
- 探测是纯的：`detectShells({env, platform, config, now, cache, probe, run})` 不碰 `ctx`、
  不连 pod、不改进程状态，测试用假目录与假 `run`。

### 4.2 会话选择、存储与回落

`<stateDir>/shell-sessions.json`（Host 侧，默认
`%LOCALAPPDATA%\dsh-escape-pod-core\shell-sessions.json`；pod 永远看不到这个文件）：

```json
{ "version": 1,
  "sessions": { "<sessionId>": { "powershell": "ps-system", "bash": "bash-ops-3cdbe2ba", "updatedAt": "2026-11-01T06:12:33.000Z" } } }
```

- 懒加载 + 内存缓存；写入是**原子写**（同目录 tmp + rename）。
- **写失败不失败调用**：选择在本次 Host 内存里生效，`warning` 如实写"没有写入 …；DSH 重启
  后会丢失"——一个不可写的 stateDir 退化成"到重启为止可用"，而不是"不能换"。
- **30 天 TTL**（`SHELL_SESSION_TTL_MS`）：加载时丢弃 `updatedAt` 超过 30 天或不可读的条目。
  `sessionId` 跨重启稳定，不清理的话一次性选择会永久生效。
- `'auto'` 表示"没有选择"而不是某个候选；非法值（数字、对象、手填的绝对路径）统一归一成
  `'auto'`，不会在文件里留下一个解析不出来的 id。
- 解析顺序（`resolveShellSelection()` / `resolveAppliedShell()`，每次 `pod_run` / `pod_exec`
  调用都跑一遍）：

```text
会话选择（pod_shell use）
  → 设置默认（settings.shells[kind]）
    → 自动探测（该类型第一个 available 候选）
每一级都必须命中"本次探测"里存在且 available 的候选；失效就往下走
```

- 回落信息是结果的一部分：`applied.fallback {from, to, reason}`，`pod_run` 文本里渲染成
  `回落：<id> → <id>（path 不存在）`，`pod_shell list` 打印 `└ 回落：…`。不静默换 shell。
- `cmd` 忽略两级选择：`%ComSpec%` 是唯一答案。
- 解析本身抛错也不阻塞执行：退回 1.1.0 的 `resolvePwshPath` / `resolveBashPath` 老路径，
  并在 `fallback.reason` 里写明原因。

### 4.3 设置 API 与 schema v3

| 路由 | 行为 |
|---|---|
| `GET /api/dsh-escape-pod/shells` | Host 侧实时探测，**不连接/不唤醒 pod**；`{ok, generatedAt, groups[], defaults, error?}`。探测失败仍是 HTTP 200 + `ok:false` + `error` + `groups: []`，页面显示错误行，其它设置照常可改 |
| `GET /api/dsh-escape-pod/settings` | `{ok, freezeMode, freezeMinutes, regenerations, shells: {powershell, bash}, writable}` |
| `POST /api/dsh-escape-pod/settings` | 同上字段皆可选；`shells` 用 `normalizeShellDefaults()` 归一。**允许保存暂时不可用的 id**：运行期回落，UI 用红字提示"已失效" |

`settings.json` schema **v3**（`POD_SETTINGS_VERSION = 3`）：

```json
{ "version": 3, "freezeMode": false, "freezeMinutes": 30, "regenerations": 1,
  "shells": { "powershell": "auto", "bash": "auto" } }
```

- v3 只**新增** `shells`：v2（或更早）文件没有这个键，读出来就是默认值，下次保存写全 ——
  没有迁移步骤，和当年移除 `enabled` 一样。旧文件里的 `enabled` 依旧读取时忽略、写入时丢弃。
- `shells` 归一与 `shells.mjs` 共用一套规则（`settings → shells` 单向 import，模块图无环），
  所以设置页、探测逻辑与文件格式不可能对"什么是一个合法的选择"产生分歧。
- 设置页新增「命令行」区块：PowerShell / bash 两个下拉（`自动（探测）` + 候选，不可用项禁用
  并标注「不可用」）、cmd 一行只读说明、保存值不在当前探测结果时红字「已失效，运行时会回落
  到自动」、探测失败显示 `探测失败：<message>`。打开设置页**不会**起 pod。

### 4.4 本机事实（2026-11-01 探测，仅这台机器）

| 类型 | 事实 | 候选 id |
|---|---|---|
| powershell | Windows PowerShell **5.1.19041.6456**，`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`；**未装 pwsh 7** | `ps-system` |
| bash | dsh-ops 提供的 PortableGit **两套**（本插件不自带），`bash 5.3.15`，受限令牌下可用：`Z:\DSH-Data\dsh-ops\bash-ipc\3cdbe2ba7b04bb73414cf7bd\bin\bash.exe`、`…\5032cf18df5ffba13d69f397\bin\bash.exe`（新的在前） | `bash-ops-3cdbe2ba`、`bash-ops-5032cf18` |
| bash | 系统 Git Bash **2.49**（本机装在 `Z:\Git\bin\bash.exe`，经 PATH 发现）在受限令牌下**会崩**：`NtSetInformationToken(TokenDefaultDacl)` 被拒 | `bash-path-<n>`（若装在 `%ProgramFiles%\Git` 则是 `bash-git-2.49`），带 `note` 警告 |
| cmd | **10.0.19045.6466**，唯一 | `cmd-system` |

这就是 `plugin` 源排在 `system` 之前的原因：同一台机器上 dsh-ops 的 PortableGit 能在受限
令牌里跑，系统 Git Bash 不能；默认 `auto` 因此落到 `bash-ops-*`，而不是 PATH 里的
`Z:\Git\bin\bash.exe`。

---

## 5. `pod_exec` 的跨重启 hold

`pod_exec` 在开始等待之前就同步落盘 `{callId, jobId}`，因此 DSH 重启后新 Host 只读账本就能补回同一条调用的真实结果，而不是重跑命令。

### 5.1 时序

```text
execute(pod_exec)
  ├─ pod.run(...)                                                ← 与 pod_run 同一条 spawn 路径
  ├─ hold(callId, { tool:'pod_exec', hint:{jobId}, deadlineMs }) ← 等待之前；服务同步落盘
  ├─ pending-exec.json 写 {callId, jobId, owner}                  ← 同一时刻、同步原子写
  ├─ 轮询账本状态直到 running=false
  ├─ 返回原生形状的结果
  └─ 平台写下这次调用自己的 tool/result 之后
       ├─ 成功/已取消 → complete(callId, 原生形状的结果) + 删清单条目
       └─ pod 侧查不到/异常 → fail(callId, reason) + 删清单条目

[DSH 重启：新 Host 激活]
  ├─ recovery.start()：同步读 pending-exec.json
  ├─ 等 pod 客户端连上，逐条查账本（与 pod_exec 同一个 output op / 同一个实时窗口）
  │    ├─ 已结算 → renderExecResult(同一个渲染函数) → complete(callId, {content:[...]})
  │    ├─ 仍在跑 → 刷新 hold（预算过半才重写），退避轮询，结算后再 complete
  │    └─ ENOJOB（账本里没这个 job）→ fail(callId, 原因)
  └─ 结算成功的条目从清单删除；服务不认识它（unknown-call / already-in-log）也删
```

### 5.2 `pending-exec.json` 与恢复扫描

- 路径固定为 `<stateDir>/pending-exec.json`（默认与账本同根，工作区之外），
  条目形状 `{callId, jobId, owner}`，`owner` 是写入进程 pid（用于区分 boot）。
- `recovery.mjs` **只读账本、绝不重放**：清单里只有 jobId，没有 argv，结构上不可能二次执行。
  恢复用的就是 `pod_exec` 的 `renderExecResult`，同一个 `output` op、同一个实时
  `maxOutputBytes`（扫描时重新解析），同一个 `[stderr]` / `[exit code: N]` / `[status: …]`
  形状——重启后补回的结果与直接返回的**逐字节一致**。
- **只结算上一次 boot 的条目**：激活时快照 `owner` 与本次进程不同的 callId 集合；本进程刚
  登记（包括 HMR 重载）的 `pod_exec` 由它自己的 `completeAfterCommit` 负责，恢复扫描绝不
  抢答——抢答会给同一条调用写第二条 `tool/result`。
- `hold` 失败/服务缺失/清单损坏/读账本失败都只降级记日志，不影响插件其它功能；清单留着给
  下一次 boot。清单条目上限 64（淘汰最旧），原子写不留 `.tmp-` 文件。
- **release 只停止等待**：不清服务侧挂起、不清清单条目、不写结果。只有服务明确回
  `applied` / `already-in-log` / `unknown-call` / `already-settled` 才算“这条调用已结算”，
  才删条目；服务抛错（例如关机时）一律保留。`isDisposing()` 为真时反而再 `hold` 一次推进
  `deadlineAt`，给新 Host 一个完整恢复窗口。

### 5.3 回合关闭时的送达

结果会回填到**同一条调用**上；但如果命令结算时那个回合已经结束（`turn/end`），平台不会再
接受一条新的 `tool/result`。此时由 `resumableToolCalls` 服务负责投递：把真实结果作为一条
消息用 `agent.steer` 送到 Agent 的下一步（idle 会话用 followup 唤醒），而不是写第二条工具
结果。本插件只调用服务的 `hold` / `complete` / `fail` / `release`，不直接碰会话日志；服务
在“会话日志里已有这条调用的结果”时返回 `skipped: already-in-log` 而不是追加。

### 5.4 边界

- **没有新 Host 就没人补**：DSH 进程直接消失、之后没有新进程接管时，`hold` 已在等待前落盘，
  但没有新 Host 跑恢复扫描，调用最多停在“被挂起”，到期（默认 12 小时）由服务换成平台的
  `TOOL_OUTCOME_UNKNOWN` 措辞。只要之后有新进程起来，恢复扫描会照常补回真实结果。
- **服务不存在**（`ctx.get('resumableToolCalls')` 返回 `undefined`，例如 restart-bundle 低于
  `1.7.4-hotfix.4`）：`pod_exec` 照常工作，只是 DSH 重启会丢掉这次调用的结果；
  `pod_status` 末行写 `resumableToolCalls=unavailable（原因）`，返回值里是
  `resume.available=false` + `resume.reason`。每次调用现查 `ctx.get`，不缓存。

---

## 6. 冻结模式与生命周期

冻结模式用「10 秒宽限 + 看门狗 + 有限再生」把 DSH 断开后的命令存活时间变成可控预算，预算耗尽才自毁；其余情况下，无客户端、无运行中 job、无冻结 episode 的 pod 会立即退出。

### 6.1 设置 schema v3

`<stateDir>/settings.json`（默认 `%LOCALAPPDATA%\dsh-escape-pod-core\settings.json`）：

```json
{ "version": 3, "freezeMode": false, "freezeMinutes": 30, "regenerations": 1,
  "shells": { "powershell": "auto", "bash": "auto" } }
```

| 字段 | 类型 | 范围/默认 | 含义 |
|---|---|---|---|
| `freezeMode` | boolean | 默认 `false` | DSH 消失后是否冻结运行中的命令 |
| `freezeMinutes` | integer | 1..1440，默认 30 | 冻结 episode 的看门狗时长 |
| `regenerations` | integer | 0..3，默认 1 | 自毁前允许的“解冻 + 立即重新冻结”次数 |
| `shells` | `{powershell, bash}` | 各为 `"auto"` 或候选 id，默认 `auto` | 设置页的命令行默认值（v3 新增，§4.3） |

- **没有 `enabled` 开关**：pod 始终服务命令；旧文件里的 `enabled` 读取时忽略、下次写入时丢弃。
- v3 相对 v2 只新增 `shells`：v2 文件没有这个键 ⇒ 读出默认值，下次保存写全，**无迁移步骤**。
- 读取永不抛：缺失/损坏一律回落到 `false / 30 / 1 / {auto, auto}`；写入是 tmp+rename 原子写。
- 设置文件由 Host（设置页 API）与 pod（冻结策略）**各自读同一份文件**，两边不依赖对方的进程。
  pod 只关心冻结三字段，`shells` 是纯 Host 概念，但物理上同文件（`settings.mjs` 共用 schema）。

### 6.2 状态机

冻结是一个纯状态机：`idle → grace(10s) → frozen → (再生 | destroying)`。`freeze-policy.mjs`
把时钟、定时器、设置读取与 job 操作全部注入，单测可驱动完整 30 分钟 episode：

```text
idle ──最后一个认证客户端断开──▶ grace ──10s──▶ frozen ──看门狗──┬─ 有再生预算：解冻+立即重冻，重新计时
  ▲                                │                    │        └─ 预算耗尽：杀掉所有 job，退出 pod（自毁）
  │                                │ 客户端回来          │
  └────────────────────────────────┴────────────────────┘
```

| 阶段 | 行为 |
|---|---|
| `idle` | 无 episode；只有客户端断开事件会进入 `grace` |
| `grace` | 最后一个认证客户端断开后 10 秒（`FREEZE_GRACE_MS`）宽限；期间客户端回来则取消 |
| `frozen` | 已冻结本轮所有可冻结 job；看门狗在 `freezeMinutes` 后触发；客户端连上立即解冻并结束本轮 |
| `destroying` | 再生次数耗尽：`killAll('freeze-mode self-destruct: regenerations exhausted')` 后 `exit(0)` |

关键细节：

- **宽限到点**时重新读设置：`freezeMode` 已关 → 不冻结；没有“运行中且未冻结”的 job → 不进入
  冻结；冻结全部失败 → 策略停止。冻结时给冻结控制器 `maxFreezeMs = freezeMinutes × 60000 +
  30000`（30 秒余量），保证策略自己的看门狗先于控制器看门狗触发，再生/自毁的记账不会被绕过。
- **看门狗到点**时也重新读设置：已关 → 解冻本轮自动冻结的 job 并停止。若此刻有“已接纳但尚未
  认证”的客户端连接，只**推迟一次** 2 秒（`FREEZE_CLIENT_SETTLE_MS`）等它完成握手——认证
  回来就取消 episode，迟迟不认证的 socket 不能阻止再生/自毁。
- **再生**：`thawEpisode('regeneration')` 后立即 `freezeCandidates()` 重新冻结，`used+1`，
  重新计时。没有 job 可重冻时策略结束（job 已恢复运行）。
- **自毁**：终止**所有** job（包括手动冻结的），退出码 0（kills 才是目的，不是错误）。
- **手动冻结边界**：策略只冻结“未冻结”的 job；看门狗只统计仍 `frozen` 且 `autoFrozen` 的
  job。手动 `pod_freeze` 会清掉 `autoFrozen`，所以策略**永远不会解冻手动冻结**；手动冻结在
  自毁时同样会被终止（自毁是最后手段，不是冻结管理动作）。
- **读取设置失败 → 按未启用处理**（fail open）：一个读不懂的策略文件不能让 pod 擅自冻结或
  杀命令。

### 6.3 `pod.log`

pod 的人读时间线在 `<dataRoot>/pod.log`（detached pod 的 stderr 被丢弃，所以所有关键事件
都写这里）。冻结相关行示例：

```text
freeze-mode：最后一个认证客户端断开，10000ms 宽限后冻结运行中的 job（freezeMinutes=30，regenerations=1）
freeze-mode：DSH 已断开，已冻结 1 个 job；30 分钟后再生（剩 1 次）
freeze-mode：job podc-… 已解冻（regeneration）
freeze-mode：再生 1/1 —— 已解冻并立即重新冻结 1 个 job（此前 1 个），重新计时 30 分钟
freeze-mode：再生次数已耗尽（1），自毁：杀掉所有 job 后退出 pod 进程
freeze-mode：已终止 1 个 job，退出 pod 进程（exit 0）
```

另有 `attest mode=…`、`identity ok/DENIED …`、`reject handover …`、`lifecycle: …` 等行。

### 6.4 生命周期

**无客户端 + 无运行中 job + 无冻结 episode ⇒ pod 自行退出**（不再等 12 小时 idle）。
判定函数 `maybeExitNoClientNoJobs(reason)`，日志形如
`lifecycle: <reason>：无客户端、无运行中 job、无冻结 episode → 退出 pod（jobs=0 clients=0）`。

| 触发点 | 行为 |
|---|---|
| 最后一个认证客户端断开 | 冻结模式开 → 进入 10 秒宽限；关且无 job → 立即退出 |
| 每个 job 结算后（`exit.json` 写完之后） | 无客户端 ⇒ 退出（有 job 且未开冻结时：跑完就退出） |
| 冻结 episode 结束/取消（客户端回来、设置关闭、无可冻结 job） | 仍无客户端且无 job ⇒ 退出 |
| 15 秒兜底 tick（`NO_CLIENT_TICK_MS`） | 兜底“Host 从未连上”等没有事件的路径 |
| 启动后 30 秒宽限（`STARTUP_GRACE_MS`） | 同上，只在启动阶段 |
| 冻结自毁 | 由策略自身退出，生命周期检查让路 |

`--bootstrap-handover` 的 pod 还没有 owner，**不会**按这条规则退出（它要等 Host 认领）。
正常 DSH 重启（无 job）时 pod 会立刻退出，新 Host 再拉起一个新 pod——这是预期行为。

### 6.5 `pod_freeze` 的 job 级语义

- 冻结走 `JobObjectFreezeInformation`：一次停住整棵树（runner + 受限子进程 + 其后代，含嵌套
  job），不是逐个挂起进程。
- 冻结期间该 job 的**超时预算暂停**：pod 报告剩余预算，`pod_exec` 的 Host 兜底期限据此重锚；
  解冻后按剩余量重挂。
- 默认 30 分钟看门狗到点**自动解冻并记日志，不杀命令**（`maxFreezeMs` 可覆盖）。
- pod 自建的匿名 job 不设 `KILL_ON_JOB_CLOSE`，关闭句柄/pod 死亡都不会杀命令；冻结**不改变
  kill 语义**。
- pod 进程重启后 job 句柄消失：`pod_status` 显示 `frozen-orphan`（`thawable:false`），
  `pod_kill` 如实返回 `killed=false`，不会按账本里的 PID 盲杀。
- 本机不支持时 `pod_status.freeze=unsupported（原因）`，`pod_freeze` 返回
  `EFREEZEUNSUPPORTED`。

---

## 7. 设置 API 与 `escapePod` 服务

设置页、`pod_shell` 与 `escapePod` 服务共用同一份 `settings.json`（schema v3）：保存立即生效、不需要插件热重载，pod 只关心其中的冻结三字段。

### 7.1 HTTP 路由

| 路由 | 行为 |
|---|---|
| `GET /api/dsh-escape-pod/settings` | `{ ok, freezeMode, freezeMinutes, regenerations, shells, writable }`；每次现读 `settings.json` |
| `POST /api/dsh-escape-pod/settings` | 校验整数字面量与范围（400），目录不可写/写失败（500），成功返回与 GET 相同形状；省略字段保留现值（`shells` 显式带过，不会被无关保存重置），未知字段（含旧版 `enabled`）忽略 |
| `GET /api/dsh-escape-pod/shells` | Host 侧命令行探测（**不连接/不唤醒 pod**）；`{ ok, generatedAt, groups[], defaults, error? }`；探测失败 HTTP 200 + `ok:false` + `error` + `groups: []`（§4.3） |
| `POST /api/dsh-escape-pod/shutdown` | 让 pod 先 `killAllJobs('shutdown')`（账本写 `killed`）再退出；返回 `{ ok, killed, status }`。pod 不在时 `{ ok: true, killed: 0 }` |

- 保存**不会**改 profile 补丁、不触发插件热重载：pod 在「断开 / 宽限到点 / 看门狗到点」时
  重读同一文件；命令行默认值由 Host 在下一次 `pod_run` / `pod_exec` 时重新解析，同样不需要重载。
- shutdown 有 15 秒上限（`POD_SHUTDOWN_TIMEOUT_MS`），超时/未连接/抛错都按 `ok: true` 返回并
  在 `status` 里如实写 `timeout` / `not-running` / `unavailable` / `error`——关机不能被一个
  已经不在的 pod 卡住。

### 7.2 Cordis 服务 `escapePod`

```js
ctx.provide('escapePod', {
  shutdown: async (reason) => ({ ok, killed, status }), // 超时/未连接都按 ok
  status: () => ({ ok, stateDir, mode, freezeMode, freezeMinutes, regenerations, shells, writable }),
})
```

- `dsh-power` 的关机联动按名查找该服务（`ctx.get('escapePod')`），缺失时照常工作。
- 本包不依赖 `dsh-power`；两个插件各自安装、各自设置页、各自开关。

### 7.3 单例

- 管道名由稳定身份种子推导（`sha256(v1|user+hostname|<user>|<host>)[0..12]`），不再依赖
  `DSH_HOME`。同名命名管道即锁：第二个 pod `EADDRINUSE` 后 `exit(0)`，不会出现两个逃生舱。
- 同一用户、同一机器只有一个逃生舱；`DSH_HOME` 迁移/改名不会产生孤儿 pod。

### 7.4 设置页 UI（`client.js`）

- `plugins.bundle.config`，key `@local/dsh-escape-pod`；zh/en 文案都在 `t()` 里，样式只用
  `dshpod-*` 类名。
- 标题「逃生舱」+ 说明；「冻结模式」复选框；开启后显示冻结时长与再生次数；保存按钮 POST
  设置并提示「已保存，立即生效（不会重载插件）」。
- **「命令行」区块**（v3 新增）：PowerShell / bash 两个下拉（`自动（探测）` + 候选，
  `available:false` 的选项禁用并标注「不可用」）、cmd 一行只读说明、保存值已失效时红字
  「已失效，运行时会回落到自动」、探测失败显示 `探测失败：<message>`（不阻塞其它设置保存）。
  候选来自 `GET /api/dsh-escape-pod/shells`；这个请求**不碰 pod 客户端**。
- 红色 **5 秒长按**「关闭正在运行的逃生舱」（视觉与 DSH 电源页强制档一致）：确认后 POST
  shutdown，显示「已关闭逃生舱（终止 N 个任务）」；未收到确认时如实提示。
- `view === 'summary'` 只渲染一行摘要：「冻结模式：开/关 · 30 分钟 / 1 次」。

---

## 8. 安全模型与限制

安全边界由「受限令牌 + 每次现签的前缀 + 管道鉴权」三者叠加而成；`danger-full-access` 让命令与用户同权并因此失去账本防伪，身份通道只是策略边界而非密码学边界。

### 8.1 沙箱、账本与前缀

- **受限模式**（`read-only` / `workspace-write`）：命令跑在 **Low 完整性 + WRITE_RESTRICTED**
  的受限令牌与 runner 的 kill-on-close Job 里；逃生舱不绕过沙箱，`pod_run` 与普通 `pwsh`
  使用同一套 policy。
- **完全访问**（`danger-full-access`）：命令**没有前缀**，以 pod 自身 Medium 令牌直接 spawn，
  与当前用户同权。这**削弱了旧不变量**：受限模式下"命令拿不到账本的写 ACE"，所以它无法伪造
  自己的 `meta/out/exit`；完全访问模式下命令能写用户能写的一切，**包括账本**。账本仍放在工作区
  之外（位置规则不变，不是为了让完全访问防伪），但**不再声称对这类命令防伪**。这是用户显式
  选择完全访问的代价，工具描述、`pod_run` 文本、[README 的「账本与安全」节](./README.md#账本与安全)
  都写明；要真正防伪，必须让命令与账本属于不同安全主体（本版不做）。
- 前缀由 Host 每次现签（`ctx.sandbox.confine`），pod 校验模板（program / runnerPath /
  workspaceRoot）与形状，并要求前缀 `--mode` 等于本次请求的 `mode`；没有跨调用缓存的前缀。
  旧前缀的会话 temp 授权会随 Host 退出被收回，所以重启后由新 Host 直接现签新前缀（没有
  `set-prefix` 重签这一步）。
- 账本在工作区之外；`stateDir` 落在工作区内 fail-closed（Host `ESTATEINSIDEWORKSPACE`，
  pod 拒绝启动）。

### 8.2 管道、token 与身份通道

- **spawn 期 token**（32 字节 hex，经 stdin 下发，只在双方内存）+ **单客户端**：挡“趁 DSH
  连着时挂第二个客户端”和“拿不到 token 的进程冒充 Host”。
- **handover**：新 Host 没有旧 token，只能在 pod 空闲时接管；接管被记录。`allowHandover:false`
  可禁用，代价是 DSH 一重启这个 pod 就再没人能读。
- **身份通道**（`attest.mjs` / `identity.mjs`）：pod 额外监听一个 `127.0.0.1` 临时端口，用
  `GetExtendedTcpTable` 的反向四元组把连接映射到对端 PID，再读映像路径、用户 SID、完整性
  级别、受限 SID 数量、会话 id，与 pod 自己的事实逐项比较（`user` / `session` / `integrity` /
  `token-shape` / `image`，管道路径另加 `server-side`）。
- **nonce**：身份通道本身不传协议；Host 用 `randomBytes(16)` 生成一次性 nonce，先 attest 再拿
  它兑换 `handover`。pod 侧 TTL 60 秒、最多 64 张未兑换票据、兑换即删；同一 PID 在 TTL 内
  `creationTime` 变化会被拒绝（防 PID 复用）。
- 三个模式：`warn`（默认，观察）、`enforce`（`handover` 无已兑换 nonce 即 `EUNATTESTED`）、
  `off`（不加载 attestor）。策略可写 `<dataRoot>/attest-policy.json`（`mode` / `minIntegrity` /
  `allowRestricted` / `allowedImages`，逐字段被环境变量 `PODC_ATTEST*` 覆盖），按
  `mtime+size` 逐请求重读；非法文件沿用上一份有效策略，绝不降级为 `off`。
- **这是策略边界，不是密码学边界**：同一用户下刻意用 `node.exe` 启动的进程可以通过全部
  检查；nonce 是 bearer；PID 归属只是连接时刻的快照。真正的边界需要让 Host 与 pod 属于不同
  安全主体（或经由高完整性 broker 转发），`GetNamedPipeClientProcessId` 这条路走不通（Node
  不暴露管道 socket 的 Win32 HANDLE，实测 `_handle.fd === -1`）。
- 诊断：`<dataRoot>/attest-probe.json` 记录最后一次连接的完整证据、策略来源与
  `deferred`/`denied` 计数（`deferred` = 拿不到句柄、无法判定，不算拒绝）；`pod_status` 渲染
  成「客户端鉴权=…」一行。

### 8.3 已知限制（如实列出）

- **Windows only**：命名管道、受限令牌、JobObject 冻结、计划任务都是 Windows 机制。
- **DSH 崩溃且没有新 Host**：`pod_exec` 的挂起不会被结算（见 §5.4）；命令本身仍在 pod 里跑。
- **收养前输出不重放**：`job_output` 从 `cursor.json`（Host最后一次 ack）或 pod 当前
  `totalBytes` 开始，收养之前的历史输出不会通过 registry 重放；要完整历史用账本 `out.log`
  与 `pod_status`（`pod_output` 走 pod 游标，不受收养起点影响）。
- **pod 被杀 = 句柄丢失**：正在跑的 runner 可能成为孤儿（medium），账本报 `unknown`；
  `pod_kill` 对它无能为力（如实返回 `killed=false`），未做孤儿收养。
- **不是跨 OS 重启**：注销/关机照样结束 pod（会话内进程）。
- **完全访问不防伪**：`danger-full-access` 的命令可以改写账本（§8.1）；`exit.json` 的
  "不可伪造"只对受限模式成立。
- **审批只覆盖一次调用**：`sandbox_permissions` 的授权不写进会话策略、不改 `settings.json`；
  下一条命令仍按会话当时的模式解析。后台 job 的整个生命周期属于那一次调用。
- **审批可用性取决于 Host**：没有 `approval` 服务（或调用没有 agent）时提宽请求直接
  `EAPPROVALUNAVAILABLE`，不存在"悄悄降级执行"。
- **工作区模板钉死**：同一个 pod 实例只服务一个 `workspaceRoot`；会话工作目录变化后的
  `pod_run` 会 `EPREFIXWORKSPACETEMPLATE` fail-closed（需先停掉 pod 让下一次调用重建）。
- **二进制输出**：模型面按 UTF-8 码点对齐，非 UTF-8 字节会以替换字符呈现；`job_output` 的
  `baseOffset + total` 换算建立在“append 文本 = pod 字节”上，二进制输出需要先解决转义。
- **会话可见性仍有缺口**：原生 `job_list` / `job_output` / `job_kill` 对 unowned 收养记录
  仍跨会话可见（`pod_status` 只给计数）；账本磁盘对同用户进程可读；pod 的 `status` op 向
  Host 返回全量投影（过滤发生在 `pod_status` 投影里）。
- **旧 pod 升级（protocol 3 起是硬门槛）**：已 detached 的旧 pod 不认 `mode` / `unescorted`，
  新 Host 因此 `EPROTOCOL` fail-closed；其它旧字段（`sessionId`）也只是缺失而不报错；`freeze` op 是例外——
  旧 pod 不认识它，返回 `EBADOP`，需 `pod_status action:"relaunch"`（见 §2.6）。要立刻换代码用 `pod_status action:"relaunch"`（有 running job 会拒绝，除非
  `force:true`），或等它空闲退出。
- **连续崩溃场景**：`pending-exec.json` 的记录有上限（64 条），超过后淘汰最旧，最旧的挂起
  只能等平台超时。

---

## 9. 测试方法

验证面由单元测试（6 个文件）、静态自测（112 项）、远程自测（17 项）与可选的身份通道套件（9 项）构成，未覆盖与未验证项在 §9.8 如实列出。

本节汇总测试方法：原单独的 `SELFTEST.md` 已并入这里并删除，自测记录、覆盖范围、历史计数与
未验证项都收在本节。

### 9.1 三套测试与一条命令复算

```powershell
# 1) 语法检查（不执行）
node --check index.js client.js pod.mjs settings.mjs shells.mjs freeze-policy.mjs

# 2) 单元测试（受限 shell 可跑；6 个文件共 130 项）
node test/escape-pod-shell.test.mjs          # 7
node test/pod-settings.test.mjs              # 18
node test/shells.test.mjs                    # 18
node test/pod-shell-tool.test.mjs            # 14
node test/pod-policy.test.mjs                # 46
node test/pod-freeze-policy.test.mjs         # 26
npm test                                     # 以上六个按此顺序跑

# 3) 静态自测（受限 shell 可跑：纯逻辑 + 假传输层，不 spawn、不连管道）
node scripts/selftest-static.mjs             # 112 通过 / 0 失败

# 4) 远程自测（必须由「不受限」进程跑；受限进程当命名管道客户端会 EPERM）
node scripts/selftest-remote.mjs --runner "<DSH>/node_modules/@deepseek-ai/dsh-sandbox-windows-acl/lib/runner.js"

# 5) 身份通道套件（可选；真实 127.0.0.1 TCP + 假 attestor）
node scripts/selftest-identity.mjs           # 9 通过 / 0 失败
```

静态/远程脚本只写工作区内的 `.tmp/…` 与真实账本目录，并在结束时清理。

### 9.2 静态自测（112 项）

`scripts/selftest-static.mjs`，其中一条用例断言 `POD_VERSION` 与 `package.json` 对齐
（当前 `1.1.1`）。覆盖（按主题）：

- **前缀/模板**：per-call 派生（3 次 `pod_run` ⇒ 恰好 3 次 `confine()`，相邻指纹不同；
  `status` 不触发 `confine()`）、`validatePrefix` 的 fail-closed、模板比对、`--` 边界。
- **账本**：位置在工作区外、`meta.argvHash`、先写 meta 再 spawn、三态、`unknown`、
  `runner-failed` 的 127 + `windows-acl-run:` 签名、cwd 越界两侧 `ECWDWORSKSPACE`。
- **协议/鉴权**：假传输层；token 缺失/错误 `EBADTOKEN` 且不调用 `service.handle`；单客户端
  `EBUSY`（请求行回显 id）；handover 后旧 token 失效；stdin 假流（EOF/垃圾/超时/关闭后不退出）；
  稳定身份种子；假 socket 驱动真实 `createConnectionHandler`。
- **身份通道/策略**：TCP 形态没有 `serverPid` 不得被拒、管道 `serverPid` 不匹配仍拒；
  `attest-policy.json` 合法生效/损坏不降级 `off`/env 逐字段优先；`enforce` 下
  `ECLIENTDENIED`、无管道句柄不误拒、带 nonce 的 handover；`deferred` 不再冒充 `denied`；
  同一 PID 的 `creationTime` 变化必须拒绝。
- **会话归属**：`jobOwnership` 边界（本会话/他会话/无主/`adopt`）、`meta.sessionId`、跨会话
  `EFOREIGNJOB` 与 `adopt` 接管（含 `adoptedFrom:null`）、`pod_status` 只列本会话且不泄露
  他会话 jobId/命令/spill、adopted 读路径的跨会话拒绝、`ENOJOB` 提示不泄露。
- **模型面保真**：`pod_output` 无 `from`、自动续读、行/码点对齐、原生 `[output truncated]`、
  `job_output` 推进 cursor、stderr channel 渲染、`segments.jsonl` 切块/偏移不变、编码
  preamble 逐字一致、`description` schema/下发/status、`DSH_*` env 清洗、adopted 只走
  registry read 且 ack=base+total。
- **收养**：teardown 不杀/显式真杀/游标选择/原生 label、无 jobs 服务降级、HMR dispose 不杀、
  `job_kill` 标记压过哨兵 reason、状态映射。
- **游标**：前缀 sha256、ack 单调、六态（`ok`/`lossy`/`missing`/`mismatch`/`ahead`/坏文件）、
  `job_output` ack 去重。
- **执行预算**：`shell.resolve` / `shell.config` / `settings.describe` / 原生默认四层来源与
  每次重读、`pod_exec` 带实时 `timeoutMs` 而 `pod_run` 绝不带、超时渲染与状态、旧 pod 的
  Host 兜底 kill、pod 的 `timeoutMs` clamp 与 `output` 1 MiB clamp、`pod_status.limits` 无损
  与兜底标注。
- **`pod_exec`/恢复**：前台形状（`[exit code: 3]`、`[status: completed]`、无 jobId/偏移、
  参数 schema、必须复用 `pod.run`）、`hold` 早于等待且 `complete` 晚于平台 `tool/result`、
  `ENOJOB` → `fail`、服务缺失/形状不全/`ctx.get` 抛错的降级、观察不到结果时停等而不补写、
  挂起刷新、取消不杀命令；恢复 9 条：重启后已结算结果与 `pod_exec` 逐字节一致、仍在跑不
  `complete`、`ENOJOB` → `fail`、清单原子写/删除/损坏降级/条目上限、服务不可用跳过且清单
  保留、只结算上一次 boot 的条目、**release / 关机 / 服务抛错都不得删恢复条目**（真实强制
  重启踩到的回归）。

### 9.3 单元测试（6 个文件，130 项）

| 文件 | 项数 | 覆盖 |
|---|---|---|
| `test/escape-pod-shell.test.mjs` | 7 | 解释器 argv 构造（powershell / cmd / bash、PortableGit 发现、UTF-8 preamble） |
| `test/pod-settings.test.mjs` | 18 | settings schema v3：默认值、范围 clamp、旧 `enabled` 忽略、`shells` 往返、原子写、Host 视图/校验、API 形状 |
| `test/shells.test.mjs` | 18 | 探测与解析：优先级与去重、显式路径缺失仍列出、id 规则与冲突后缀、版本解析/缓存/失败为 null、三级解析与 `fallback`、`cmd` 固定 |
| `test/pod-shell-tool.test.mjs` | 14 | `pod_shell`：`list`/`use`/`reset`、`cmd` 拒绝、未知 id 拒绝、`available:false` 拒绝、`ENOSESSION`、会话存储往返与写失败降级 |
| `test/pod-policy.test.mjs` | 46 | 文件策略与审批：解析来源与回落、三模式执行形态、模板不钉 `mode`、前缀 `--mode` 与请求一致性、`unescorted`/`prefix` 形状、`allowed-once` 才执行、拒绝零执行、`EAUTHORITYCHANGED`、TOCTOU、`protocol < 3` 的 `EPROTOCOL` |
| `test/pod-freeze-policy.test.mjs` | 26 | 冻结状态机：10 秒宽限、客户端回来、看门狗、再生、自毁、手动冻结边界、设置热读、定时器语义 |

`npm test` 顺序执行六个文件；全绿是发版门槛。

### 9.4 远程自测（17 项）

远程自测必须由不受限进程跑，因为它要真实管道、真实 runner 与真实受限命令。
`scripts/selftest-remote.mjs` 必须由**不受限**进程运行：本会话的受限 `pwsh` 令牌
（Low + WRITE_RESTRICTED）当命名管道客户端会 `EPERM`（已实测的硬边界）——这不是脚本缺陷，
而是被测边界本身。

它启动**真实 pod + 真实命名管道 + 真实 windows-acl runner + 真实受限命令**，覆盖 17 个
用例，包括：

- per-call 前缀（3 次 `pod_run` ⇒ 3 次 `confine()`）、工具层真实 `pwsh` 的
  `OUTSIDE-DENIED` / `INSIDE-WROTE`；
- 账本形状（先 meta 后 spawn、`exit.json.totalBytes` 等于 `out.log`、`argvHash`、
  `cursor.json` 原子写）、绝对偏移分片拼接逐字节一致；
- 重连（同进程内新客户端 + 同一 pod）：`podPid` 不变、旧 job 可见、旧输出逐字节一致；
- 诚实 `unknown`：SIGKILL 掉 pod 后新 pod 从账本列出旧 job 为 `unknown`，不编造退出码；
- cwd 越界两侧 `ECWDWORSKSPACE`、`EPREFIXSTALE` / `EPREFIXWORKSPACETEMPLATE` /
  `EPREFIXRUNNERPATH` 全部在执行前拒绝、`shutdown` op 后管道消失；
- 收养生死线（假 `ctx.jobs` + 真 pod）：teardown 不杀、显式 `job_kill` 真杀；
- 游标（真 pod + 真 ack + 新 Host）：ack 54 字节 → 新 Host 从 54 收养 → 追加 222 字节得到
  T0001…T0046 连续 46 行，无重放/跳号；篡改 hash → `mismatch` 且降级 `cursor-mismatch`；
- 模型面保真（含中文/emoji）：51 段 / 11347 字节逐字节等于 `out.log`、0 替换字符、0 半行、
  重启不重放；stderr 通道 297 个 chunk 字节对齐、`spillPath` 正确、收养 append 带 channel；
  `job_output` 把 cursor 推到 base+total；
- P1 对齐：`DSH_EPC_FRESH=fresh-42` 随调用下发（env 保鲜）、`description` 进 meta/status、
  adopted `pod_output` 走 registry read 并 ack pod 游标。

用例按工具 `name` 取工具，不依赖数组下标（1.7.0 插入 `pod_exec` 后下标错位过一次）。
首跑 13/17 是修复前的历史记录，修复后为 **17/17**（3 条测试脚本 bug + 1 条 pod 拒绝帧时序
竞态，均不涉及命令执行/游标/收养）。

### 9.5 身份通道套件（9 项，可选）

`scripts/selftest-identity.mjs` 用**真实 `net.connect`** 连真实 `createIdentityChannel()` 绑定的
`127.0.0.1` 临时端口（attestor 是假的，证明接线/判定/票据语义，不证明 OS 查询）：合法 attest、
nonce 二次兑换拒绝、TTL 过期、票据上限（65 张只淘汰最旧一张）、受限令牌/低完整性拒绝、
策略/attestor 异常不发票且可恢复、PID `creationTime` 复用守卫、`mode=off` 放行、协议错误码
（`EBADJSON`/`EBADNONCE`/`EBADOP`/`ETOOLONG`）且坏请求后通道仍可用。

### 9.6 自测历史

| 阶段 | 静态 | 说明 |
|---|---|---|
| 1.5.2 时代 | 48 | 前缀、账本、偏移续读、收养、游标、模型面保真首版 |
| 1.6.0 管道加固 | 55 | +7：稳定身份种子、token 原语、stdin 假流、单客户端、handover、status 投影、假 socket 全链路 |
| 1.7.0 `pod_exec` | 62 | +7：前台形状、hold 时序、降级、取消不杀 |
| 1.7.0 恢复半程 | 71 | +9：重启结算、清单、release 不删凭据（回归） |
| 1.7.0 身份通道 | 76 | +3（另有 9 项真 TCP 套件）：策略文件、`serverPid`、`enforce`/nonce |
| 1.7.0 会话归属 | 84 | +8：归属判定、跨会话拒绝、adopt、status 过滤、deferred/denied、PID 复用 |
| 1.7.0 执行预算 | 92 | +8：四层来源与实时重读、超时语义、clamp、limits |
| 1.0.0-hotfix.9 独立包 | 112 | 版本断言改随包版本；`npm test` 7/18/26 全绿 |
| 1.1.0 正式版 | 112 | 版本断言改 `1.1.0`，套件数不变 |
| 1.1.0-hotfix.1 策略分级 + 命令行 | 112 | 静态套件数不变；`npm test` 扩到 6 个文件 129 项（7/18/18/14/46/26）、全绿；`POD_VERSION` 断言改 `1.1.0-hotfix.1` |
| 1.1.0-hotfix.2 只读 CLM + 下拉框 | 112 | 套件数不变；`npm test` 6 个文件 130 项（7/18/19/14/46/26，新增中文 `ver` 解析）；只读会话的 PowerShell 前缀改 `try/catch` |
| 1.1.0-hotfix.3 工具描述精简 | 112 | 描述约 5700→4200 字；显示名「逃生舱核心」→「逃生舱」；测试 130 项不变 |

### 9.7 已验证证据摘要

- **真实 runner 沙箱**：命令自报 `inside=ok / insideDelete=ok / outside=EPERM /
  integrity=S-1-16-4096`（Low），Host helper 为 `S-1-16-8192`（Medium）。
- **账本位置**：实际位于 `%LOCALAPPDATA%\dsh-escape-pod-core\jobs\<jobId>\`，不在工作区内；
  `ledgerOutsideWorkspace=true`。
- **前缀**：3 次 `pod_run` ⇒ 恰好 3 次 `confine()`；`status` 不触发；相邻指纹不同。
- **模型面**：11347 字节 / 51 段逐字节等于 `out.log`，0 替换字符、0 半行；重启后不重放。
- **收养**：teardown 后 `pod_output` 仍 `running` 且字节增长（没杀 pod 命令）；显式
  `job_kill` 真杀；证据
  `{"replayedHistory":false,"teardownKilledPod":false,"teardownSettled":"killed","explicitKillWorked":true}`。
- **游标**：`{"ackOffset":54,"cursorState":"ok","adoptionBase":54,"appendedBytes":222,"ticks":46,"replayedHistory":false,"gap":false}`；
  Lead 侧另有一次真实重启：`cursor=ok@21` → 重启 47 秒 → 从 21 续读到 490，T0004~T0070
  不重放不丢。
- **真实重启的生命周期**：无运行中 job 时重启 DSH，pod 记录
  `lifecycle: … 无客户端、无运行中 job、无冻结 episode → 退出 pod` 并立即退出；新 Host 按需
  重建（`podVersion` 随包版本）。
- **token 不落盘**：账本 `meta/out/segments/cursor/exit` 中 token 字面量出现 0 次。

### 9.8 未覆盖 / 未验证

1. **真实 Host 的 `ctx.sandbox.confine` 路径**：自测用假 sandbox seam 返回同形态的真实 runner
   前缀（agentless）；session-managed（`--write-sid`/`--temp-write-sid`）只在静态测试里覆盖。
2. **真实 DSH 重启下的 `pod_exec` 端到端**：`ctx.get('resumableToolCalls')` 是否可见（看
   `pod_status` 末行）、`session/event` 是否投递到本插件作用域、挂起是否真的挡住
   `TOOL_OUTCOME_UNKNOWN`、恢复扫描能否在服务 1200 ms 结算窗口内抢到（抢不到只多一屏
   provisional，`complete` 会以 content-only replacement 收尾）。
3. **`job_output` 驱动 ack 的真实钩子时序**：`tools/post-execute` 与 `JobView.output.total`
   的形状已用假 registry + 真 pod 验证；真实 Host 的时序需安装后确认。
4. **真实 `ctx.jobs` + Host dispose 时序**：假 registry + 真 pod 验证了 teardown/kill 语义；
   effect cleanup 与 jobs 服务 dispose 的先后只有真实重启能证明。
5. **身份通道的真实 OS 查询**：`GetExtendedTcpTable` 反向四元组、真实 Host 的
   `identify → attest → handover`、运行中 `warn → enforce` 热切换都未在真实 Host 上跑到。
6. **真实子进程超时**：静态套件跑在受限 shell 里，`spawn` 带管道是 EPERM；timer 到期真杀
   runner 的 OS 路径由远程套件/Lead 验收负责。
7. **设置页真实保存一次**：读取路径用假 `ctx.service` 断言；真实「保存 → Loader reconcile →
   下一次调用变化」需要人工在设置页保存后跑 `pod_status` 验证。
8. **多 workspace、二进制输出**：见 §8.3，均未实现/未验证。
9. **真实审批对话框端到端**：请求 → `allowed-once` → 重解析 → `assertStandingUnchanged`
   这条时序由 `test/pod-policy.test.mjs` 用假 `ctx.approval` 驱动；真实 DSH 弹窗、用户拒绝/
   超时后的实际文案，以及审批期间在 UI 里切权限触发的 `EAUTHORITYCHANGED`，需安装后人工验证。
10. **完全访问的真实执行**：无前缀 spawn 与 `planRunSpawn()` 形状由单测覆盖；静态套件跑在受限
    shell 里（`spawn` 带管道是 EPERM），所以"命令真的能写工作区外、能改写账本"这条现象只有
   不受限进程（远程套件/人工）能证明。

---

## 附录 A 错误码速查表

四个附录都用正文已有事实做索引：错误码、常量、术语与文档链接各自成表，含义一律沿用原文措辞，不新增任何解释；「起了命令吗」只在 §3.4 原文明确标注处给出。

### A.1 管道 / 协议 / 前缀

| 错误码 | 含义（原文口径） | 出处 |
|---|---|---|
| `EBADTOKEN` | 请求缺 `token` 或 token 不匹配 → 返回错误并关闭连接，不产生任何状态变化 | §1.3 |
| `EBUSY` | 单客户端：第二个连接被拒并关闭；`handover` 时 pod 有活动连接同样返回该码 | §1.3 |
| `EHANDOVERDISABLED` | `allowHandover:false` 时拒绝 `handover` | §1.3 |
| `EUNATTESTED` | `enforce` 下 `handover` 没有已兑换的 nonce（与策略无关，属管道鉴权） | §1.3、§3.4、§8.2 |
| `ECLIENTDENIED` | `enforce` 下身份通道拒绝该客户端 | §9.2 |
| `EBADMODE` | `run` 请求的 `mode` 是非法值——`mode` 是权限而不是提示 | §1.3 |
| `EUNESCORTEDMODE` | `unescorted:true` 却没给 `danger-full-access` | §1.3、§3.4 |
| `EMODEUNESCORTED` | `danger-full-access` 不带 `unescorted` | §1.3、§3.4 |
| `EPREFIXUNEXPECTED` | `unescorted` 还带了前缀 | §1.3、§3.4 |
| `EPREFIXMODE` | 前缀 `--mode` 不是受限两种模式之一；前缀里出现 `danger-full-access` 一律拒绝 | §1.4、§3.2、§3.4 |
| `EPREFIXMODEREQUEST` | 前缀的 `--mode` 与本次请求的 `mode` 不一致 | §1.4、§3.2、§3.4 |
| `EPREFIXSTALE` | 前缀里的 `--temp` 目录已不存在（旧 Host 的会话 temp 授权随它退出被收回） | §1.4、§9.4 |
| `EPREFIXHASHMISMATCH` | `ack` 请求的 hash 校验不通过（原文措辞：「坏 hash」）；§1.3 未展开比对对象，不要与 §1.4 由 pod 自算的 `prefixHash` / 前缀 sha256 指纹混为一谈 | §1.3 |
| `EPREFIXWORKSPACETEMPLATE` | 前缀与钉死的形态模板（`workspaceRoot`）不一致；需先停掉 pod 让下一次调用重建 | §8.3、§9.4 |
| `EPREFIXRUNNERPATH` | 前缀 / 模板中的 runner 路径校验失败（模板要求 `runnerPath` 必须在 DSH 安装树内） | §9.4、§1.4 |
| `EPROTOCOL` | 旧 pod（`protocol < 3`，或压根不报版本）；fail-closed，修复动作是 `pod_status action:"relaunch"` | §1.3、§3.4、§3.5 |
| `ESTATEINSIDEWORKSPACE` | `stateDir` 落在 `workspaceRoot` 内：Host 侧 fail-closed，pod 侧拒绝启动 | §1.5、§8.1 |

### A.2 文件策略与审批

§3.4 原文给出了「何时 / 起了命令吗」两列，逐行保留如下；本表只收其中的审批相关项（6 行），
原表中与前缀 / 协议 / 鉴权相关的 4 行已归入 A.1：`EPROTOCOL`、`EPREFIXMODEREQUEST` /
`EPREFIXMODE`、`EUNESCORTEDMODE` / `EMODEUNESCORTED` / `EPREFIXUNEXPECTED`、`EUNATTESTED`。

| 错误码 | 何时 | 起了命令吗 | 出处 |
|---|---|---|---|
| `ESANDBOXPERMISSIONS` | `sandbox_permissions` 不是两个合法值之一 | 没有 | §3.4 |
| `EJUSTIFICATION` | 理由不是字符串 / 没给目标却给理由 / 改模式但理由为空 | 没有 | §3.4 |
| `ESANDBOXNARROWER` | 申请的模式比当前会话更窄——审批从来不用于降级 | 没有 | §3.4 |
| `EAPPROVALUNAVAILABLE` | Host 没有审批服务，或这次调用没有 agent | 没有 | §3.4 |
| `EAPPROVALDENIED` | 审批结果是 `denied` / `timeout` / 关闭 / 其它任何非 `allowed-once` | 没有 | §3.4 |
| `EAUTHORITYCHANGED` | 审批期间或发请求前，会话 `mode` / `workspaceRoot` 变了（含 TOCTOU 复核失败） | 没有 | §3.4 |

### A.3 账本 / 游标 / job

| 错误码 | 含义（原文口径） | 出处 |
|---|---|---|
| `ECWDWORSKSPACE` | `cwd` 越出本次 policy 的 `workspaceRoot`（原文拼写即为 `WORSKSPACE`），在执行前拒绝 | §2.2、§9.2、§9.4 |
| `ECURSORMISMATCH` | `cursor.state=mismatch/ahead/malformed/unreadable` 时拒绝读，不从 0 重放 | §2.4 |
| `EBADJOBID` | `pod_freeze` 的错误码之一（§2.6 仅列出码名，未展开语义，原文无释义） | §2.6 |
| `ENOJOB` | 账本里没有这个 job（恢复扫描据此 `fail(callId, 原因)`） | §2.6、§5.1 |
| `EFOREIGNJOB` | job 属于其它会话且未 `adopt`；无主（`null`）记录对任何真实会话都算 foreign | §1.7、§2.6 |
| `ENOTHANDLE` | 只有账本、没有本 pod 的句柄（pod 重启过或赋值失败） | §2.6 |
| `ENOTRUNNING` | `pod_freeze` 的错误码之一（§2.6 仅列出码名，未展开语义，原文无释义） | §2.6 |
| `EBADOP` | 旧 pod 不认识 freeze op，需 `pod_status action:"relaunch"` | §2.6 |

### A.4 冻结 / 命令行 / 身份通道

| 错误码 | 含义（原文口径） | 出处 |
|---|---|---|
| `EFREEZEUNSUPPORTED` | 本机不支持冻结；`pod_status.freeze=unsupported（原因）` | §2.6、§6.5 |
| `EOSFAIL` | §2.6 仅列出码名，未展开语义（原文无说明） | §2.6 |
| `EARGS` | `pod_shell` 参数非法：`action` 其它值、`use` 的 `cmd`、缺 `id`、id 不在该类型候选里 | §2.8 |
| `ESHELLUNAVAILABLE` | `use` 选中的候选 `available:false` | §2.8 |
| `ENOSESSION` | `pod_shell` 没有会话 id（先拒绝，再谈写文件） | §2.8 |
| `EBADJSON` / `EBADNONCE` / `ETOOLONG` | 身份通道协议错误码；坏请求之后通道仍可用 | §9.5 |

### A.5 OS 侧（非本包协议码）

| 错误码 | 含义（原文口径） | 出处 |
|---|---|---|
| `EPERM` | 本会话受限 `pwsh` 令牌（Low + WRITE_RESTRICTED）当命名管道客户端会 `EPERM`——已实测的硬边界 | §9.4 |
| `EADDRINUSE` | 两个 pod 撞同名命名管道：第二个 `exit(0)`，不会出现两个逃生舱 | §7.3 |

### A.6 状态与响应字面量

错误码之外，还有一组值会出现在结果与账本里，含义同样只取自原文。

| 字面量 | 语义 | 出处 |
|---|---|---|
| `running` / `settled` / `killed` / `runner-failed` / `spawn-failed` / `ledger-failed` / `unknown` | job `status` 取值。`runner-failed` = 退出码 127 且 stderr 出现 `windows-acl-run:` 签名（命令从未运行）；`unknown` = 本 pod 实例没有该 job 句柄且账本里没有 `exit.json`，**结果未知，不要臆断退出码** | §1.5 |
| `ok` / `lossy` / `missing` / `mismatch` / `ahead` / `malformed` / `unreadable` | `cursor.state`。§9.2 表述为「六态（`ok`/`lossy`/`missing`/`mismatch`/`ahead`/坏文件）」，§2.4 另举 `malformed`、`unreadable` | §2.4、§9.2 |
| `skipped:"behind-cursor"` | `ack` 单调：旧偏移只回该标记 | §1.3 |
| `applied` / `already-in-log` / `unknown-call` / `already-settled` | `resumableToolCalls` 的结算应答；只有服务明确回这几种才算「这条调用已结算」 | §5.2 |
| `idle` / `grace` / `frozen` / `destroying` | 冻结状态机的四个阶段 | §6.2 |
| `frozen` / `frozen-orphan` / `unsupported` | `pod_status` 的冻结投影；`frozen-orphan` ⇒ `thawable:false`，`pod_kill` 如实返回 `killed=false` | §6.5 |
| `timeout` / `not-running` / `unavailable` / `error` | shutdown 的 `status`，一律按 `ok: true` 返回，关机不能被一个已经不在的 pod 卡住 | §7.1 |
| `sandboxPolicy` / `fallback:workspace-write` / `fallback:sandboxPolicy-error` / `fallback:sandboxPolicy-empty` | `policy.source` 的权威来源与降级原因（非法 `mode` 另有 `modeNote`） | §2.7、§3.1 |
| `shell.resolve` / `shell.config` / `settings:<条目>` / `fallback:native-defaults` | 执行预算的读取顺位（每层失败都记进 `reasons`） | §2.9 |
| `auto` / `direct` / `schtasks` | `launcher.json` 的 `mode`（缺省 `auto`） | §1.2 |
| `auto` | 命令行选择里表示「没有选择」而不是某个候选 | §4.2 |
| `warn` / `enforce` / `off` | 身份通道三模式（`off` 不加载 attestor） | §8.2 |
| `list` / `use` / `reset` | `pod_shell` 的三个动作 | §2.8 |
| `freeze` / `thaw` | `pod_freeze` 的两个动作 | §2.6 |
| `[output truncated]` / `[earlier output was dropped from the pod retention window]` | 模型面截断 / 丢失的唯一原生标记；排障时「输出怎么少了」就靠它们判读 | §2.1 |
| `cursor-mismatch` | `cursor.state=mismatch` 时从 `totalBytes` 收养并显式报出的降级标记 | §1.6、§2.4 |
| `scripts/pod-raw.mjs` | 非模型面的维护者 CLI：按绝对偏移读、不写 cursor | §2.1 |

---

## 附录 B 常量与数字速查表

附录 B 把正文出现的版本号、协议值、时间预算、容量上限与实测数字按用途归档；每项都给出正文出处小节号，数值照抄、不做四舍五入；正文自身口径不一致的地方在「值」列显式标注，附录不代替正文下结论。

### B.1 版本、协议与固定标识

管道名的完整字面量（照抄源文档 §1.3，单独成行，以免表格内转义污染）：

`\\.\pipe\dsh-escape-pod-core-<sha256(v1|user+hostname)[0..12]>`

| 项 | 值 | 出处 |
|---|---|---|
| 包版本 `POD_VERSION` | `1.1.1`（静态套件断言其与 `package.json` 对齐） | §9.2 |
| `PROTOCOL_VERSION` | `3`（`2` = 鉴权 + 单客户端管道；`3` = `run` 请求带**每次调用**的文件策略） | §1.3、§3.5 |
| 设置 schema `POD_SETTINGS_VERSION` | `3` | §4.3、§6.1 |
| 管道名 | 两个式子在源文档中**不一致**，勿当作等价写法（FACT-CONFLICT FC-②，按源文档并存、不得据此拼管道名）：§1.3 作 `sha256(v1\|user+hostname)[0..12]`，§7.3 作 `sha256(v1\|user+hostname\|<user>\|<host>)[0..12]` | §1.3、§7.3 |
| `jobId` 形状 | `podc-<base36 时间戳>-<8 hex>`，同时是账本目录名 | §1.5 |
| `jobId` 防穿越正则 | `^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$` | §1.5 |
| 计划任务名 | 前缀 `dsh-escape-pod-`，后缀是 dataRoot 的短哈希（一个 profile 一个任务） | §1.2 |
| Cordis 服务名 | `escapePod` | §7.2 |
| Loader 条目 | `pwsh-sandbox`（POSIX 为 `bash-sandbox`） | §2.9 |
| runner 拒绝签名 | `windows-acl-run:`（`runner-failed` 的判定依据：退出码 127 且 stderr 出现该签名 = 命令从未运行） | §1.5、§9.2 |

### B.2 文件与目录位置

| 文件 / 目录 | 默认位置 | 作用 | 出处 |
|---|---|---|---|
| 账本根 `stateDir` | `%LOCALAPPDATA%\dsh-escape-pod-core` | 单 job 子目录的父目录；必须在工作区之外 | §1.5 |
| `stateDir` 退化顺序 | `$DSH_HOME\.escape-pod-core` → `<home>\.dsh-escape-pod-core`（没有 `LOCALAPPDATA` 时依次退） | `stateDir` 可覆盖 | §1.5 |
| 单个 job 目录 | `<stateDir>\jobs\<jobId>\` | 内含 `meta.json` / `out.log` / `segments.jsonl` / `cursor.json` / `exit.json` | §1.5 |
| `settings.json` | `<stateDir>/settings.json` | schema v3，Host 与 pod 各自读同一份 | §6.1 |
| `shell-sessions.json` | `<stateDir>/shell-sessions.json` | 会话命令行选择（pod 永远看不到） | §4.2 |
| `pending-exec.json` | `<stateDir>/pending-exec.json` | `pod_exec` 跨重启恢复清单 | §5.2 |
| `launcher.json` | `<dataRoot>/launcher.json` | `{ "mode": "auto" \| "direct" \| "schtasks" }` | §1.2 |
| `launch/` | `<dataRoot>/launch/` | `schtasks` 路径下的 `.cmd` / `.vbs` | §1.2 |
| `pod.log` | `<dataRoot>/pod.log` | pod 的人读时间线（detached pod 的 stderr 被丢弃） | §6.3 |
| `attest-policy.json` | `<dataRoot>/attest-policy.json` | 身份通道策略，按 `mtime+size` 逐请求重读 | §8.2 |
| `attest-probe.json` | `<dataRoot>/attest-probe.json` | 最后一次连接的完整证据与 `deferred`/`denied` 计数 | §8.2 |

### B.3 时间预算与超时

| 项 | 值 | 出处 |
|---|---|---|
| 冻结宽限 `FREEZE_GRACE_MS` | 10 秒（日志写作 `10000ms`） | §6.2 |
| 客户端 settle 推迟 `FREEZE_CLIENT_SETTLE_MS` | 2 秒，只**推迟一次** | §6.2 |
| 冻结看门狗 `freezeMinutes` | 1..1440，默认 30 分钟 | §6.1 |
| 冻结控制器 `maxFreezeMs` | 缺省 pod 默认 30 分钟；策略下发 `freezeMinutes × 60000 + 30000`（30 秒余量） | §2.6、§6.2 |
| 再生预算 `regenerations` | 0..3，默认 1 | §6.1 |
| 生命周期兜底 tick `NO_CLIENT_TICK_MS` | 15 秒 | §6.4 |
| 启动宽限 `STARTUP_GRACE_MS` | 30 秒（只在启动阶段） | §6.4 |
| 会话选择 TTL `SHELL_SESSION_TTL_MS` | 30 天 | §4.2 |
| 版本探测超时 / 缓存 | 3 秒 / 60 秒（按 `kind + path` 缓存，失败也缓存） | §4.1 |
| `schtasks` 调用超时 | 8 秒（失败只记录、不抛错） | §1.2 |
| shutdown 上限 `POD_SHUTDOWN_TIMEOUT_MS` | 15 秒 | §7.1 |
| `pod_exec` 账本轮询间隔 | 每 200 ms 查一次账本状态 | §2.3 |
| 恢复扫描的结算窗口 | 服务 1200 ms | §9.8 |
| `hold` 到期 | 默认 12 小时，之后由服务换成平台的 `TOOL_OUTCOME_UNKNOWN` 措辞 | §5.4 |
| 设置页关闭逃生舱 | 红色 **5 秒长按**确认 | §7.4 |

### B.4 容量与数量上限

| 项 | 值 | 出处 |
|---|---|---|
| `command` 文本上限 | 16000 字符 | §2.2 |
| `description` 上限 | ≤200 | §2.2 |
| 非模型面单次输出窗口 | `maxBytes` 被 clamp 到 1 MiB（`outputChunkBytes` 只是旧客户端/CLI 的兜底） | §1.3、§2.9 |
| 命令超时 clamp | `2³¹−1`（`setTimeout` 的 32 位上限） | §2.9 |
| 执行预算兜底 `fallback:native-defaults` | `120000` / `64000` | §2.9 |
| spawn 期 token | 32 字节 hex，经 stdin 下发，只在双方内存 | §1.3、§8.2 |
| nonce | `randomBytes(16)`；pod 侧 TTL 60 秒；最多 64 张未兑换票据 | §8.2 |
| `pending-exec.json` 条目上限 | 64（超过后淘汰最旧） | §5.2、§8.3 |
| 运行期回落层级 | 「会话选择 → 设置默认 → 自动探测」，逐级回落 | §4.2 |

### B.5 测试计数

前四行是当前生效的套件计数；后两行分别是静态套件的历史曲线与版本记录口径，只用于对照，不是本机实测。

| 套件 | 计数 | 出处 |
|---|---|---|
| 静态自测 `scripts/selftest-static.mjs` | 112 项（112 通过 / 0 失败） | §9.1、§9.2 |
| 单元测试 `npm test` | 6 个文件；以 **130 项**（7 / 18 / 19 / 14 / 46 / 26，含 hotfix.2 新增的中文 `ver` 解析测试）为准（FC-① 已裁决）；HISTVER 中 hotfix.1 的历史值 129 项按原文保留 | §9.1、§9.3、§9.6 |
| 远程自测 `scripts/selftest-remote.mjs` | 17 项；首跑 13/17 是修复前的历史记录，修复后为 17/17 | §9.1、§9.4 |
| 身份通道套件 `scripts/selftest-identity.mjs` | 9 项（9 通过 / 0 失败，可选） | §9.1、§9.5 |
| 静态自测历史曲线 | 48 → 55 → 62 → 71 → 76 → 84 → 92 → 112 | §9.6 |
| 工具描述长度（版本记录，非本机实测） | 七个工具 description 合计约 5700 → 4200 字（1.1.0-hotfix.3 精简） | §9.6、[HISTVER.md](./HISTVER.md) |

### B.6 本机实测数字（2026-11-01 探测，仅这台机器）

| 项 | 事实 | 出处 |
|---|---|---|
| Windows PowerShell | **5.1.19041.6456**，`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`；未装 pwsh 7 | §4.4 |
| cmd | **10.0.19045.6466**，唯一 | §4.4 |
| bash | dsh-ops PortableGit 两套，`bash 5.3.15`，受限令牌下可用 | §4.4 |
| 系统 Git Bash | **2.49**，受限令牌下会崩：`NtSetInformationToken(TokenDefaultDacl)` 被拒 | §4.4 |
| 模型面保真 | 51 段 / 11347 字节逐字节等于 `out.log`，0 替换字符、0 半行，重启不重放 | §9.4、§9.7 |
| 游标证据 | `ackOffset: 54`、`appendedBytes: 222`、`ticks: 46`；另一次真实重启 `cursor=ok@21` → 重启 47 秒 → 从 21 续读到 490（T0004~T0070 不重放不丢） | §9.4、§9.7 |
| stderr 通道 | 297 个 chunk 字节对齐 | §9.4 |
| 完整性级别证据 | 命令自报 `integrity=S-1-16-4096`（Low），Host helper 为 `S-1-16-8192`（Medium） | §9.7 |

---

## 附录 C 术语表

术语表只收录正文出现过的概念，定义按原文口径压缩成一行；少数条目把散见于多节的同类事实归拢表述，不新增事实。同一概念在正文有多个叫法时以正文首次出现的写法为准；旧称 / 历史名只在释义里标注版本脉络，不作为独立条目。

| 术语 | 含义（原文口径） | 出处 |
|---|---|---|
| 逃生舱 | 本包的整体称呼；设置页标题为「逃生舱」，显示名在 1.1.0-hotfix.3 由「逃生舱核心」改为「逃生舱」 | §7.4、§9.6 |
| Host | DSH 进程内的插件部分：工具实现 / pod 客户端 / 收养 / 恢复扫描 / 设置 API（`index.js` + 插件页 UI `client.js`），**会重启** | §1.1 |
| pod | `pod.mjs` 进程：Medium 完整性、detached；普通 node Host 下它是 DSH 进程的子进程但不在任何 job object 里，桌面/Electron Host 下经计划任务拉起 | §1.1、§1.2 |
| 命名管道 | Host 与 pod 之间的 JSON Lines 通道，token 鉴权、单客户端、可选 OS 身份校验 | §1.1、§1.3 |
| 账本（ledger） | `<stateDir>\jobs\<jobId>\` 下的五个文件：`meta.json` / `out.log` / `segments.jsonl` / `cursor.json` / `exit.json` | §1.5 |
| 账本位置不变量 | 必须在工作区之外（安全要求，不是偏好）；Host 与 pod 两侧都校验 `stateDir` 不在 `workspaceRoot` 内，落在里面 fail-closed | §1.5 |
| runner | 受限 runner：Low 完整性 + `WRITE_RESTRICTED`，在 kill-on-close Job 里；命令跑在它下面 | §1.1 |
| runner 前缀 | Host 用 `ctx.sandbox.confine()` 每次现签的 argv 前缀，pod 拼出 `[...前缀, '--', ...argv]` 再 spawn；前缀本身不缓存 | §1.4 |
| 形态模板 | 首次 spawn 时用 `--template-b64` 交给 pod 的模板，只钉 `program` + `runnerPath`（必须在 DSH 安装树内）+ `workspaceRoot`，**不再钉 `mode`** | §1.4 |
| job | 一次命令执行；账本目录名即 `jobId`，同时被收养成 `ctx.jobs` 的 registry job（`kind=bash`） | §1.5、§1.6 |
| 收养（adopt） | 把 pod job 注册进 `ctx.jobs`；unowned 记录跨会话/跨重启存活，跨会话读/杀需 `adopt:true` 并返回 `adoptedFrom` | §1.6、§1.7 |
| 游标（cursor） | `cursor.json`：Host已消费偏移 + 该偏移之前全部字节的 sha256（tmp+rename 原子写） | §1.5 |
| ack | Host 把新偏移写回 `cursor.json` 的请求；单调，旧偏移只回 `skipped:"behind-cursor"` | §1.3 |
| 游标失配 | `cursor.state` 非 `ok` 时拒绝读、不从 0 重放；必要时删该 job 的 `cursor.json` 退化为「从 total 收养」 | §2.4 |
| hold | `resumableToolCalls` 的挂起登记；`pod_exec` 在等待之前同步落盘 `pending-exec.json` | §5.1 |
| 恢复扫描 | 新 Host 激活后同步读 `pending-exec.json`、查账本、用同一个 `renderExecResult` 补回结果；只结算上一次 boot 的条目，绝不重放 | §5.1、§5.2 |
| `resumableToolCalls` | 负责跨重启投递结果的服务；不存在时 `pod_exec` 照常工作，只是 DSH 重启会丢掉这次调用的结果 | §5.3、§5.4 |
| 冻结 episode | 一次「断开 → 宽限 → 冻结 → 再生 / 自毁」的完整过程 | §6.2 |
| 宽限（grace） | 最后一个认证客户端断开后的 10 秒窗口（`FREEZE_GRACE_MS`）；期间客户端回来则取消 | §6.2 |
| 看门狗 | 冻结后 `freezeMinutes` 触发的定时器；到点自动解冻并记日志，**不杀命令** | §6.2、§6.5 |
| 再生（regeneration） | `thawEpisode('regeneration')` 后立即重新冻结，`used+1` 并重新计时；没有 job 可重冻时策略结束 | §6.2 |
| 自毁（self-destruct） | 再生次数耗尽后终止**所有** job（含手动冻结的）并 `exit(0)`——kills 才是目的，不是错误 | §6.2 |
| 手动冻结边界 | 策略只冻结「未冻结」的 job，手动 `pod_freeze` 会清掉 `autoFrozen`，所以策略永远不会解冻手动冻结 | §6.2 |
| 冻结原语 | `JobObjectFreezeInformation`：一次停住整棵树（runner + 受限子进程 + 其后代，含嵌套 job） | §6.5 |
| CLM | PowerShell Constrained Language：`read-only` 前缀的受限令牌会让 PowerShell 进入该模式，不能 `new` .NET 类型 | §3.2 |
| 身份通道 | pod 额外监听的 `127.0.0.1` 临时端口，用 `GetExtendedTcpTable` 的反向四元组把连接映射到对端 PID 再逐项比较 | §8.2 |
| handover | `handover {newToken, nonce?}`：新 Host 接管——pod 空闲（上一代连接已断）时轮换 token；`enforce` 下要求已兑换的 nonce（`EUNATTESTED`），有活动连接时 `EBUSY`，`allowHandover:false` 时 `EHANDOVERDISABLED`（§1.3）。接管被记录，`pod_status.auth.handoverCount` 可见（§8.2） | §1.3、§8.2 |
| nonce | 一次性票据：先 attest 再拿它兑换 `handover`；pod 侧 TTL 60 秒、最多 64 张未兑换、兑换即删 | §8.2 |
| attestor | 身份校验器（`attest.mjs` / `identity.mjs`），三模式 `warn` / `enforce` / `off` | §8.2 |
| deferred | 拿不到句柄、无法判定；**不算拒绝**（与 `denied` 区分） | §8.2、§9.2 |
| 策略边界（非密码学边界） | 身份通道的定位：同一用户下刻意用 `node.exe` 启动的进程可以通过全部检查 | §8.2 |
| detached | pod 不经 `ctx.subprocess` / `ctx.jobs` / `ctx.terminal` 启动，因此进不了 DSH 的 kill-on-close Job，重启即死的命运被规避 | §1.1 |
| Medium / Low 完整性 | pod 自身是 Medium 令牌；受限 runner 是 Low 完整性 + `WRITE_RESTRICTED` | §1.1、§3.2 |
| kill-on-close Job | runner 所在的 job object；pod 自建的匿名 job 不设 `KILL_ON_JOB_CLOSE`，冻结**不改变** kill 语义 | §1.1、§6.5 |
| launcher | `launcher.mjs`：`auto` / `direct` / `schtasks` 三条启动路径，由 `launcher.json` 选择 | §1.2 |
| dataRoot | pod 数据根：`launcher.json`、`launch/`、`pod.log`、`attest-policy.json`、`attest-probe.json`（正文未单独定义此术语，本行为跨节归拢） | §1.2、§6.3、§8.2 |
| stateDir | 账本、`settings.json`、`shell-sessions.json`、`pending-exec.json` 的根（正文未单独定义此术语，本行为跨节归拢）；不是固定位置——无 `LOCALAPPDATA` 时依次退化，且可被覆盖，见 §1.5 | §1.5、§4.2、§5.2 |
| workspaceRoot | 本次 policy 的工作区根；`cwd` 必须在其内（越界 `ECWDWORSKSPACE`） | §2.2 |
| 执行预算 | 单流输出上限与命令超时，属于原生 shell 执行器的实时设置，**每次工具调用都重新读取** | §2.9 |
| spill | 输出溢出到 `spillPath` 的落盘文件 | §1.3、§9.4 |

---

## 附录 D 文档索引与交叉链接

附录 D 给出三条入口：按任务找章节、按角色找配套文档、按书写约定读符号；三份文档的事实口径必须一致，冲突时以源文档为准，并在正文对应处标注 FACT-CONFLICT 编号。

### D.1 按任务找章节

| 我要解决的问题 | 去哪一节 |
|---|---|
| 搞清 Host 与 pod 谁在跑、协议版本、账本字段 | §1（§1.1–§1.7） |
| 查七个工具的参数 / 返回 / 错误码 | §2（§2.2–§2.8）、§3.4、附录 A |
| 命令为什么是只读、怎么提宽、审批卡在哪一步、`EPROTOCOL` 怎么办 | §3（§3.1–§3.5） |
| 换 shell、配 bash 路径、会话级选择不生效 | §4（§4.1–§4.2）、§2.8 |
| DSH 重启后 `pod_exec` 的结果去哪了 | §5、§8.3 |
| 冻结没触发 / 命令被杀了 / pod 什么时候退出 | §6（§6.2、§6.4） |
| 设置页保存不生效、`escapePod` 有没有被调用 | §7（§7.1–§7.4） |
| 评估安全边界、哪些是已知限制 | §8（§8.1–§8.3） |
| 跑测试、复算计数、看未验证项 | §9（§9.1–§9.8） |
| 找状态文件 / 账本 / schema | §1.5、§6.1、附录 B.2 |
| 找配置字段（设置项） | §6.1、§4.3 |
| 快速查一个错误码 / 常量 / 术语 | 附录 A / 附录 B / 附录 C |

### D.2 配套文档

| 文档 | 内容 | 建议何时读 |
|---|---|---|
| [README.md](./README.md) | 定位、价值、安装、最小上手、安全提示 | 第一次接触本包 |
| [HISTVER.md](./HISTVER.md) | 正式公开基线（1.1.1）及之后的版本变更、兼容性说明 | 排「当前版本行为」与后续升级的问题 |
| [HISTVER_legacy.md](./HISTVER_legacy.md) | 正式公开前的私有时期版本记录（未发布、不保留产物，仅供参考） | 追溯「正式公开之前的行为源流」 |
| 本文件（TECHDOC） | 架构、协议、工具契约、状态与持久化、安全、测试 | 维护、排障、二次开发 |

### D.3 书写约定

- 章节引用写作 `§x.y`，指向本文件；四个附录写作 `附录 A`–`附录 D`。
- 代码块语言标注只用 `text` / `bash` / `powershell` / `js` / `json` / `yaml`。
- 反引号里是标识符、路径、命令、错误码或字面量，逐字照抄，包括原文中的拼写（例如 `ECWDWORSKSPACE`）。
- 版本号、包名、常量、数字、日期、平台限制一律按原文，不改写、不四舍五入、不概括。
- 同目录交叉链接用相对路径：`./README.md`、`./HISTVER.md`、`./HISTVER_legacy.md`。
- 正文标题中原有的破折号「—」已统一改为中文冒号「：」（§2.2、§2.3、§2.8），本文标题统一使用中文冒号「：」；改标题须同步修改 `## 目录` 中对应锚点（当前为 `#22-pod_run后台形态`、`#23-pod_exec前台形态`、`#28-pod_shell命令行探测与选择`），否则目录断链。
- 源文档 §2.7 中重复出现的「每个 job 带 cursor / registry / freeze 投影」段落（源 L386–L388）已去重，仅保留首次出现处（本文 §2.7 前半段）；该段里 `resumableToolCalls` / `恢复扫描` 的末行说明完整保留。
- 源文档自身矛盾 / 过时之处按原文保留、不自行判定，统一记作 FACT-CONFLICT：FC-①（单元测试 129 / 130 项，已裁决以 130 为准，见 §9.1、§9.3、§9.6）、FC-②（身份种子输入集，见 §1.3、§7.3）、FC-③（旧 pod 对 `freeze` op 的处理，见 §2.6、§8.3）；两处口径按源文档并存，正文不自行统一。
- README 的节名为「账本与安全」（源 README 作「安全提示」）；§3.2 与 §8.1 指向 README 的两处链接按该节名写作 `./README.md#账本与安全`，旧节名的锚点已全局核对、零残留。

### D.4 维护约定（改标题与改链接时看这里）

本文件给维护者的几条约定：改标题、改链接、加章节时照此办，跨文件锚点就不会断。

- **目录锚点 = 正文标题的 GitHub slug**：小写、去掉反引号与标点、空格转连字符。所以带反引号的 2.2 / 2.3 / 2.8 三个标题，锚点分别是 `#22-pod_run后台形态`、`#23-pod_exec前台形态`、`#28-pod_shell命令行探测与选择`。改标题必须同步改 `## 目录`，并检查别的文件里指向它的跳转。
- **跨文件链接一律相对路径**：`./README.md`、`./HISTVER.md`、`./HISTVER_legacy.md`、`./TECHDOC.md`；README 的对应节名为「账本与安全」（源 README 作「安全提示」），§3.2 与 §8.1 两处链接按该名对齐。
- **术语以 §1.1 与附录 C 为准**：逃生舱 / pod / Host / 账本 / runner 前缀 / 冻结 episode / 收养；正文不再用「宿主」代指 Host。
- **第三方归属与许可证**：完整条款见 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)（本套文档含 README / TECHDOC / HISTVER / HISTVER_legacy 与第三方声明）。
- **事实纪律**：源文档自身矛盾处保留原样并标 FACT-CONFLICT（FC-① / FC-② / FC-③，见 D.3），不判定、不统一、不删除。
- **文末固定项**：每份文档文末保留 dsh 徽章与许可行；README 另在顶部放一次徽章。

---

## 许可

本文件以 MIT 许可发布，版权归 DX12_XYZ 所有。完整条款见仓库根 [LICENSE](./LICENSE)。

<!-- fused-by: glm-5.3-flash -->

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
