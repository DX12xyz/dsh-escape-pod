# 私有包时期变更记录（legacy）

> 本文件只记录**正式公开之前**的私有迭代，仅供追溯参考：
>
> - 这些版本从未公开发布；本套文档所在的仓库不随附这些历史时期的源码与 `.tgz` 产物（大部分版本的实物仍可在 `.del/` 归档与拆分归档目录里找到，仅作参考），收版后的正式产物由本仓库 `deliver/releases/` 提供；
> - 记录可能不完整，**不作为对外契约**，行为以当前版本为准；
> - 正式公开后的变更记录见 [HISTVER.md](./HISTVER.md)。

---

## 版本历史（私有时期）
> **私有时期最后一版：1.1.1**（Windows only，七个 `pod_*` 工具）。本文件只记录逃生舱（`@local/dsh-escape-pod`）自己的版本线，面向维护者：每个版本给出变更、动机与兼容性/迁移说明；文末另有[测试计数演变](#测试计数演变跨版本对照)与[常见问题](#常见问题faq)。

## 命名与标识演变（读历史前先弄清）

- **包名/组件名**：合并包时期目录是 `restart-bundle/escape-pod/`、模块名 `@local/dsh-restart-bundle/escape-pod`、Loader 行 `escape-pod-core`；自 **1.0.0-hotfix.9** 起是独立包 `@local/dsh-escape-pod`、Loader 行 `dsh-escape-pod`。
- **行为常量没有改**：管道 stem `dsh-escape-pod-core-`、账本目录 `%LOCALAPPDATA%\dsh-escape-pod-core`、计划任务前缀 `dsh-escape-pod-`。
- **工具名是一次例外**：1.0.0-hotfix.9 及以前是 `podc_*`，**1.1.0-hotfix.1 起改为 `pod_*`**（内部标识不变）。下文历史章节按现名书写，首次出现处注明当时的旧名。
- **版本线独立**：**1.0.0-hotfix.9 是本包的第一个独立版本**；`1.1.0` 起版本线与 `dsh-power`（原 `restart-bundle`）分开，不再跟随它的 `1.7.x-hotfix.N` 编号。

## 版本总表（倒序）

跳转：[1.1.1](#1112026-11-01正式版) · [1.1.0-hotfix.3](#110-hotfix32026-11-01hotfix) · [1.1.0-hotfix.2](#110-hotfix22026-11-01hotfix) · [1.1.0-hotfix.1](#110-hotfix12026-11-01hotfix) · [1.1.0](#1102026-11-01正式版) · [1.0.0-hotfix.9](#100-hotfix92026-11-01第一个独立版本) · [1.7.5-hotfix.8](#175-hotfix82026-10-31合并包时期设置页--冻结模式) · [1.7.5-hotfix.6](#175-hotfix62026-10-31合并包时期shell-选择) · [1.7.5-hotfix.1](#175-hotfix12026-10-31合并包时期组件化) · [前身原型](#前身原型2026-10-27非正式版本线) · [更早](#更早实验件时期170-及以前) · [测试计数](#测试计数演变跨版本对照) · [常见问题](#常见问题faq)

| 版本 | 日期 | 主题 | 一句话 |
|---|---|---|---|
| 1.1.1 | 2026-11-01 | 正式版收版 | hotfix.1 → hotfix.3 的累计改动收版，相对 hotfix.3 无行为变更 |
| 1.1.0-hotfix.3 | 2026-11-01 | 工具描述精简 + 显示名统一 | description 约 5700 → 4200 字，「逃生舱核心」改「逃生舱」 |
| 1.1.0-hotfix.2 | 2026-11-01 | 只读会话体验 + 设置页可读性 | CLM 安全前缀；下拉框显示「版本 · 绝对路径」 |
| 1.1.0-hotfix.1 | 2026-11-01 | 工具改名 + 跟随会话文件策略 + 一次性审批 + 命令行选择 + 协议 3 | 破坏性改名 `pod_*`，新增一次性审批与命令行选择 |
| 1.1.0 | 2026-11-01 | 正式版（文档拆分） | 版本号统一，文档按 GitHub 习惯拆成四份 |
| 1.0.0-hotfix.9 | 2026-11-01 | 第一个独立版本 | 从合并包拆出，pod 自主生命周期 + 设置 API |
| 1.7.5-hotfix.8 | 2026-10-31 | 合并包时期：设置页 + 冻结模式 | 冻结落地，实测 `pod_run` 180 tick 跨 DSH 重启、断连冻结与回连解冻 |
| 1.7.5-hotfix.6 | 2026-10-31 | 合并包时期：shell 选择 | `podc_run` / `podc_exec` 新增 `shell` 可选 powershell / cmd / bash（默认 powershell），bash 发现顺序规避 Git 2.49 受限令牌崩溃 |
| 1.7.5-hotfix.1 | 2026-10-31 | 合并包时期：组件化 | 实验件首次成为合并包第二个组件，六工具（当时 `podc_*`） |
| 更早 | — | 实验件时期（1.7.0 及以前） | `pod/` 目录自迭代，detached pod 到前台形态与身份校验 |

## 1.1.1（2026-11-01，正式版）

返回 [版本总表](#版本总表倒序)。

### 累计改动收版

**变更**：1.1.0-hotfix.1 → hotfix.3 的累计改动收版为 **1.1.1**：工具名统一 `pod_*`、跟随会话文件策略与一次性审批、`pod_shell`、只读 CLM 安全前缀、设置页下拉框显示版本与绝对路径、工具描述精简与显示名「逃生舱」。

**兼容性**：相对 1.1.0-hotfix.3 无行为变更。升到 1.1.1 只是把三个 hotfix 的内容定版。

## 1.1.0-hotfix.3（2026-11-01，hotfix）

返回 [版本总表](#版本总表倒序)。

### 工具描述精简 + 显示名统一

**变更**：

- 七个工具的 description 由 Qwen3.8-flash 协助精简（合计约 5700 → 4200 字），保留全部会改变行为的事实：三档文件策略与可写范围、审批语义（allowed-once / 仅本次 / 只能变宽 / 拒绝后不得重试）、完全访问无前缀与账本防伪削弱、跨重启挂起回填、job 归属与 adopt、前缀 fail-closed、输出续读与上限、冻结语义与错误码、pod_shell 的三级解析与回落。
- 模型可见文本里的「逃生舱核心」统一改为「逃生舱」（工具描述、pod_run 文本、pod_status 头部、工具卡片标题）；管道 stem / 账本目录 / Loader id 等内部标识不变。

**测试**：仍为 6 个文件 130 项 + 静态自测 112 项全绿。

**兼容性**：仅文本层改动，无协议、无 API、无参数变化。

## 1.1.0-hotfix.2（2026-11-01，hotfix）

返回 [版本总表](#版本总表倒序)。

### 只读会话体验 + 设置页可读性

**变更**：

- **只读会话的 PowerShell 前缀改为 CLM 安全**：平台给 read-only 前缀的是受限令牌，PowerShell 因此进入 Constrained Language（`CannotCreateTypeConstrainedLanguage`）。原来的 UTF-8 前缀 `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)` 属于类型创建，在 CLM 下会终止并往 stderr 打两条错误。现在每条赋值各自 `try { … } catch { }`：FullLanguage 行为不变，CLM 下静默跳过。注意 CLM 下控制台编码仍是 ANSI/GBK，中文输出可能乱码；只读会话建议用 `shell:"bash"`（UTF-8 原生）或申请一次 workspace-write。
- **设置页下拉框可区分同名项**：候选里有两套同名 PortableGit，`<select>` 现在把「版本 · 绝对路径」附在名称后面（如 `PortableGit（dsh-ops） — Z:/DSH-Data/dsh-ops/bash-ipc/…/bin/bash.exe`）。

**兼容性**：无协议变化（仍为 3）、无 API/参数变化。

**测试**：`npm test` 6 个文件 130 项全绿、静态自测 112 项。相对 hotfix.1（129 项，7 / 18 / **18** / 14 / 46 / 26）多出 1 项，落在第 3 个文件的 18 → 19；TECHDOC 的自测历史把这一项记为「新增中文 `ver` 解析」，而本文件把它的内容修正列在 hotfix.1——归属口径见文末「常见问题」。

## 1.1.0-hotfix.1（2026-11-01，hotfix）

返回 [版本总表](#版本总表倒序)。

### 工具改名 + 跟随会话文件策略 + 一次性审批 + 命令行选择 + 协议 3

本次为破坏性版本：工具改名 + 新协议（protocol 3），两类变更都要求调用方与已运行 pod 做适配。

**变更**：

- **工具改名（破坏性）**：`podc_run` / `podc_exec` / `podc_output` / `podc_kill` / `podc_freeze` / `podc_status` → `pod_run` / `pod_exec` / `pod_output` / `pod_kill` / `pod_freeze` / `pod_status`，并新增 `pod_shell`。**只改工具名**：管道 stem `dsh-escape-pod-core-`、账本目录 `%LOCALAPPDATA%\dsh-escape-pod-core`、Loader id `escape-pod-core`、`jobId` 前缀 `podc-`、环境变量 `PODC_ATTEST*` / `DSH_ESCAPE_POD_BASH`、Cordis 服务 `escapePod` 全部保持原样。
- **跟随会话文件策略**：不再写死 `workspace-write`。每次调用 `ctx.get('sandboxPolicy').resolve({ session })`：`read-only` → 只读前缀；`workspace-write` → 现状；`danger-full-access` → **无前缀**（`unescorted`，以 pod 自身 Medium 令牌运行）。会话中途切权限立即生效。形态模板不再钉 `mode`，改为钉 `program + runnerPath(DSH 安装树) + workspaceRoot`，每次前缀的 `--mode` 必须等于本次请求的 `mode`（否则 `EPREFIXMODEREQUEST`）。
- **一次性审批**：`pod_run` / `pod_exec` 新增 `sandbox_permissions`（`workspace-write` | `danger-full-access`）+ `justification`，规则与 `dsh-bash-sandbox` 一致：只能变宽、改模式必须给理由、目标等于当前模式时不审批、比当前更窄直接拒绝；`ctx.get('approval').request(...)` 必须返回 `allowed-once`，审批后重新解析，`mode`/`workspaceRoot` 变了报 `EAUTHORITYCHANGED`；审批只对本次调用有效。错误码 `EAPPROVALUNAVAILABLE` / `EAPPROVALDENIED` / `EAUTHORITYCHANGED` / `ESANDBOXNARROWER` / `ESANDBOXPERMISSIONS` / `EJUSTIFICATION`。
- **`pod_shell`（新工具）**：`action: list | use | reset`、`shell: powershell | bash | cmd`、`id`；Host 侧探测，**不连接也不唤醒 pod**；探测优先级 config（`pwshPath` / `bashPath`）> env（`DSH_ESCAPE_POD_BASH`，仅 bash）> plugin（dsh-ops PortableGit，按 mtime）> system > PATH；`cmd` 只有 `%ComSpec%`，固定不可选。会话选择存 `<stateDir>/shell-sessions.json`（`version:1`、原子写、30 天清理、写失败只在内存生效并警告）；解析顺序「会话选择 → 设置默认 → 自动探测」，失效逐级回落并在结果里说明。
- **`pod_shell` 版本探测本地化修正**：cmd 的 `ver` 输出在中/英文系统上分别是 `[版本 10.0.…]` 与 `[Version 10.0.…]`，且 OEM 编码会乱码；改为只取文本里的 `数字.数字.数字[.数字]` 版本号，不再把整行 `Microsoft Windows [版本 …]` 当作版本。
- **协议 3**：`run` 请求新增 `mode` / `unescorted` / `prefix: null` 形状；Host 在每条连接上用一次 `hello` 学协议版本，`protocol < 3` 时 `pod_run` / `pod_exec` fail-closed（`EPROTOCOL`）。
- **设置页**：新增「命令行」区块（PowerShell / bash 两个下拉 + cmd 只读行 + 失效红字 + 探测失败行）；新增 `GET /api/dsh-escape-pod/shells`（Host 侧探测；失败仍是 200 + `ok:false` + `error` + `groups: []`）；settings schema **v3** 增加 `shells: {powershell, bash}`，GET/POST 都带。
- **`pod_status`**：新增 `会话文件策略=…` 与 `命令行：…` 两行，返回值新增 `policy` / `shell`；账本 `meta.policy` 记录 `{mode, escalated, unescorted}`。

**内部标识不变对照**（改名前后逐项一致，故已有账本与运行中 job 不用迁移）：

| 标识 | 值（未变） | 说明 |
|---|---|---|
| 工具名（唯一例外） | `podc_*` → `pod_*` | 1.1.0-hotfix.1 起；另新增 `pod_shell` |
| 管道 stem | `dsh-escape-pod-core-` | 单例以同名命名管道为锁 |
| 账本目录 | `%LOCALAPPDATA%\dsh-escape-pod-core` | 在工作区之外 |
| Loader 行 id | `escape-pod-core` | 合并包时期写法沿用 |
| `jobId` 前缀 | `podc-` | 返回值里的旧名字样就是账本目录名，不是旧工具 |
| 环境变量 | `PODC_ATTEST*` / `DSH_ESCAPE_POD_BASH` | 名称保留 `PODC_` 字样 |
| Cordis 服务 | `escapePod` | dsh-power 关机联动按名查找 |

**动机（完全访问的代价）**：`danger-full-access` 的命令与当前用户同权，可以改写账本；旧的"命令无法伪造自己的 `exit.json`"不变量只对受限模式成立，README 与 TECHDOC §8.1 已写明。

**兼容性与迁移**：

- 已有账本与正在运行的 job 不用迁移（内部标识不变）。
- 协议变更需重连：提示先 `pod_status action:"relaunch"`，换上含新协议的代码后必须 relaunch，或等旧 pod 空闲退出。
- settings 旧 v2 文件读出默认值，无迁移步骤。
- `pod_shell` **不强制替换原装解释器**：不做选择时行为与 1.1.0 一致。

**测试**：`npm test` **6 个文件共 129 项**（7 / 18 / 18 / 14 / 46 / 26；新增 `shells`、`pod-shell-tool`、`pod-policy` 三个文件）；`node scripts/selftest-static.mjs` **112 / 112**（`POD_VERSION` 断言改 `1.1.0-hotfix.1`）。

## 1.1.0（2026-11-01，正式版）

返回 [版本总表](#版本总表倒序)。

### 版本线独立 + 文档拆分

**变更**：

- **版本**：`package.json` / `PLUGIN_VERSION` / `POD_VERSION` 统一为 `1.1.0`；静态自测的 `POD_VERSION` 断言同步（仍是 112 项全绿）。
- **文档按 GitHub 项目习惯拆分**：`README.md`（项目介绍、特性、安装、快速使用、与 dsh-power 的关系）、`TECHDOC.md`（架构、协议、工具参考、跨重启 hold、冻结状态机、设置 API、安全模型、测试方法）、`HISTVER.md`（本文件）、`THIRD_PARTY_NOTICES.md`（dsh-bgjobs 归属与运行时依赖许可证，新建）。
- **`SELFTEST.md` 并入 `TECHDOC.md` §7 后删除**：测试方法、覆盖范围、历史计数（48 → 55 → 62 → 71 → 76 → 84 → 92 → 112）与未验证项都在 TECHDOC 里，不再单独维护。
- `package.json` 的 `files` 移除 `SELFTEST.md`，加入 `TECHDOC.md` / `HISTVER.md` / `THIRD_PARTY_NOTICES.md`。

**兼容性**：1.0.0-hotfix.9 之后的正式版，除版本号与文档外，工具行为与 1.0.0-hotfix.9 一致。

## 1.0.0-hotfix.9（2026-11-01，第一个独立版本）

返回 [版本总表](#版本总表倒序)。

### 拆包 + 自主生命周期

从合并包（`@local/dsh-restart-bundle`）拆出的**第一个独立版本**：一个包、一个组件，`dsh plugin --profile web add` 单独安装，不再与重启/关闭组件共用 patch 行。

**变更**：

- **独立包**：`@local/dsh-escape-pod`，Loader 行 `dsh-escape-pod`，自带 `package.json` / `cordis.patch.yml` / `client.js` / `locale`；旧合并包已移除。
- **pod 生命周期**：无客户端 + 无运行中 job + 无冻结 episode ⇒ pod 自行退出（不再等 12 小时 idle）；每个 job 结算后、冻结 episode 结束时都重新判定；15 秒兜底 tick 与启动后 30 秒宽限只兜底"Host 从未连上"的路径。
- **设置页**：新增 `GET/POST /api/dsh-escape-pod/settings` 与 `POST /api/dsh-escape-pod/shutdown`；Cordis 服务 `escapePod`（`shutdown` / `status`），供 dsh-power 关机联动按名查找（缺失也能工作）。
- **红色按钮**：设置页「关闭正在运行的逃生舱」，红色、长按 5 秒确认，终止所有任务并关闭 pod。
- **移除「启用逃生舱」门禁**：设置 schema 升到 v2，字段只有 `freezeMode / freezeMinutes / regenerations`；`pod_run` / `pod_exec` 不再有 `EDISABLED` 门禁，旧文件里的 `enabled` 读取时忽略、下次保存丢弃。
- **单例**：同名命名管道即锁，第二个 pod `EADDRINUSE` 后 `exit(0)`；`pod_status` 显示 `podVersion` / `launcherMode` / `freeze=` 等诊断行。

**测试**：静态 **112 / 112**（`POD_VERSION` 断言改为 `1.0.0-hotfix.9`），单测 7 / 18 / 26 全绿；`scripts/selftest-remote.mjs` 需要不受限进程，本次拆包未重跑（历史结果为 17/17）。

## 1.7.5-hotfix.8（2026-10-31，合并包时期：设置页 + 冻结模式）

返回 [版本总表](#版本总表倒序)。

### 组件化时期的逃生舱区块与冻结落地

组件仍在 `@local/dsh-restart-bundle` 内（Loader 行 `escape-pod-core`，模块 `@local/dsh-restart-bundle/escape-pod`），与重启/关闭组件共用一个包、一个设置页保存按钮。

**变更**：

- **设置页「逃生舱」区块**：启用、冻结模式、冻结时长（1–1440 分钟，默认 30）、再生次数（0–3，默认 1）；写逃生舱自己的 `<stateDir>/settings.json`，与重启组件设置互相独立。
- **门禁**（1.0.0-hotfix.9 已移除）：关闭「启用逃生舱」后只拒绝新的 `pod_run` / `pod_exec`（`EDISABLED`），已运行的任务继续跑完。
- **冻结模式落地**：最后一个认证客户端断开 10 秒后冻结运行中的命令；DSH 回来立即解冻；看门狗按 `freezeMinutes` 再生（解冻后立即重新冻结），再生次数耗尽后杀掉所有 job 并退出 pod（自毁）。冻结走 JobObject 冻结，超时预算暂停。
- **单例**：管道独占 + `EADDRINUSE` 退出 0；`pod_status` 显示单例行。

**实测**：`pod_run` 180 tick 跨 DSH 重启；`pod.log` 记录断开 10.025 秒后冻结、回连 566 ms 后解冻，输出 `tick 15→16` 停顿 1.6 秒后继续。

**测试**：`pod-settings` 11、`pod-freeze-policy` 22，静态自测 112/112（当次口径）。

## 1.7.5-hotfix.6（2026-10-31，合并包时期：shell 选择）

返回 [版本总表](#版本总表倒序)。

### podc_run / podc_exec 新增 shell 参数

组件仍在 `@local/dsh-restart-bundle` 内（Loader 行 `escape-pod-core`）；本轮逃生舱侧面对应 dsh-power 文档 `1.7.5-hotfix.6` 一节所记的同一轮改动。

**变更**：

- **`podc_run` / `podc_exec` 新增 `shell: powershell | cmd | bash`**（默认 `powershell`，非法值报 `EARGS`）：`cmd` 走 `cmd.exe /d /s /c`（`/d` 跳过 AutoRun），`bash` 走 `bash --noprofile --norc -c`（命令文本只占一个 argv，不套额外引号层）。
- **bash 可执行文件发现顺序**：`bashPath` 配置 → `DSH_ESCAPE_POD_BASH` 环境变量 → DSH ops 自带 PortableGit（取 `<DSH_HOME>/dsh-ops/bash-ipc/<实例>/bin/bash.exe` 按 mtime 最新）→ PATH 的 `bash.exe`。
- **动机**：Windows 系统版 Git for Windows 2.49 的 bash 在沙箱受限令牌下崩溃（`NtSetInformationToken(TokenDefaultDacl)` 被拒后 Cygwin 无法创建信号管道），DSH ops 自带的 PortableGit 实例可正常存活。

**证据与边界**：本轮合并包 tgz（`local-dsh-restart-bundle-1.7.5-hotfix.6.tgz`，2026-10-31 13:50）内 README 的「版本」节停在 hotfix.2——hotfix.6/7 两包发布当时 README 均未跟上代码；上述事实以归档源码为准：`.del/DSH-Plugin-tgz-2026-11-01/local-dsh-restart-bundle-1.7.5-hotfix.7.tgz` 内 `escape-pod/index.js` 的 `normalizeShellKind` / `resolveBashPath`（注释写明上述发现顺序与 Git 2.49 崩溃原因），及 `.del/pod/restart-bundle/test/escape-pod-shell.test.mjs`（7 条测试原文）。

**测试**：新增 `escape-pod-shell` **7 条**（`normalizeShellKind` 默认与三值、`buildBashArgv`、`buildCmdArgv`、powershell UTF-8 前缀、`resolveBashPath` 显式路径/环境变量优先、PortableGit 实例选取、PATH 回落）；三种 shell 与中文管道实测通过（电源侧记录口径）。

## 1.7.5-hotfix.1（2026-10-31，合并包时期：组件化）

返回 [版本总表](#版本总表倒序)。

### 实验件首次成为合并包第二个组件

逃生舱第一次作为合并包的**第二个组件**提供（此前是独立目录里的实验件）。

**变更**：

- 同一个包里插入第二行 `escape-pod-core`（模块 `@local/dsh-restart-bundle/escape-pod`），插件页显示为「逃生舱」卡片，可单独开关；关掉它不影响重启/关闭组件，关掉重启行也不会杀 pod。
- **六个工具**（当时叫 `podc_run` / `podc_exec` / `podc_output` / `podc_kill` / `podc_freeze` / `podc_status`，1.1.0-hotfix.1 起改为 `pod_*`）：`pod_run` / `pod_exec` / `pod_output` / `pod_kill` / `pod_freeze` / `pod_status`；命令由 detached pod 托管，DSH 重启后继续运行。
- **账本**：`%LOCALAPPDATA%\dsh-escape-pod-core\jobs\<jobId>\`（`meta.json` / `out.log` / `segments.jsonl` / `cursor.json` / `exit.json`），在工作区之外，被托管命令写不到。
- **跨重启回填**：`pod_exec` 在等待前通过 `resumableToolCalls` 落盘挂起；新 Host 启动时先 restore holds、抢在 resume 之前写 provisional 结果，逃生舱的 recovery 再按账本写真实结果（必要时 content-replace）。`pod_run` 的结果落账本，重连后用 `pod_output` 续读。
- 同时恢复 `resumableToolCalls` 服务（`host/resumable.js` + `host/session-writer.js` + boot 恢复/结算 + 检查点排除 held 调用）。

## 前身原型（2026-10-27，非正式版本线）

返回 [版本总表](#版本总表倒序)。

正式版本线之外，`@local/dsh-escape-pod` 这个名字最早出现在两个**非正式原型**上。它们与正式版本线（「自 1.0.0-hotfix.9 起是独立包」，见「命名与标识演变」）**并列存在、互不矛盾**：原型用的包名/版本号体系（`1.0.0`，无基线也无 hotfix 序列）与正式独立包不连续，`.del` 内没有迁移说明，**无法断言**两者是同一产品线的同一版号；本节照实录，仅作历史参考。

### 原型 A：`@local/dsh-escape-pod` 1.0.0（内存计数器）

- 实物：`.del/escape-pod/`（目录 mtime 2026-10-27），`package.json` 为 `version 1.0.0`、`private: true`，自述「Escape-pod counter: a process-memory-only integer owned by a detached supervisor … Two tools (pod_add, pod_get); no runtime file is ever written」。
- 唯一状态是 detached supervisor（`supervisor.mjs`）进程内存里的一个整数，经命名管道 `\\\\.\\pipe\\dsh-escape-pod-<sha256(DSH_HOME)[0..12]>` 读回；管道名由 `DSH_HOME` 确定性推导，**不落盘**（没有 pid / token / 日志 / 账本文件），跨 DSH 重启存活的全部依据是「状态从一开始就不归 DSH 托管」，`connection = reused` 是连回旧 pod 的关键路径。
- 工具只有 `pod_add`（计数 +1）与 `pod_get`（读值），返回 `count` / `podPid` / `podStartedAt` / `generation` / `connection`；不执行命令、不替换 shell、不碰沙箱——与后来的账本式 pod（1.5.2 起，见「更早」一节）完全不同的能力形态。
- 已知边界（README 自述）：pod 死 = 计数丢；不跨 OS 重启 / 关机 / 注销；无鉴权（默认 DACL 只给创建者 / SYSTEM / Administrators）；DSH 的 ACL 受限令牌子进程连不上命名管道（`EPERM`）——这条观察由下面的沙箱实验接手验证。

### 原型 B：`@local/dsh-escape-pod-sbx` 1.0.0（沙箱实验）

- 实物：`.del/escape-pod-sbx/`（目录 mtime 2026-10-27），`package.json` 为 `version 1.0.0`、`private: true`。
- 判定性实验：**受限令牌（WRITE_RESTRICTED + Low 完整性）进程能否当命名管道的服务端，并被不受限的 DSH Host 当客户端连上？** 对照组即同日的原型 A（普通 detached spawn，不加限制），两个 bundle 唯一差别是启动方式：本包经 `ctx.sandbox.confine(…)` 组装受限 argv 后，由插件自己 `spawn`（detached）拉起 supervisor。
- 工具 `podx_add` / `podx_get`；管道 stem `dsh-escape-pod-sbx-`、Loader id `escape-pod-sbx`；两个 pod 可同时运行、计数互不影响。
- 实测结论（README 自述）：`stdio: 'ignore'` 下 `detached` 取真/假都能 spawn 成功，`stdio: 'pipe'` 一律 `EPERM spawn EPERM`——工程实现取 `detached: true` + `stdio: 'ignore'`；`podx_get` 返回 pod 进程内自探针（工作区内文件预期 `ok`、工作区外预期 `EPERM`/`EACCES`、`integrityHint` 解析 `S-1-16-*` 完整性级别）与 `sandbox.enforcement` / `runnerPid` / `argv` 证据，`probe` 出现 `"outside": "ok"` 即实验判负。

## 更早（实验件时期，1.7.0 及以前）

返回 [版本总表](#版本总表倒序)。

逃生舱在成为组件之前是 `pod/` 下的实验目录，按自己的版本号迭代；这些能力后来原样进入组件（当时的目录名与模块名不同，行为常量一直沿用）。

实验件时期（1.7.0 及以前）完成了从 detached pod、per-call 沙箱前缀、账本与偏移续读，到前台形态 `pod_exec`、管道 OS 级身份校验与会话归属边界的全部基础能力；静态自测由这一时期的 **48 → 55 → 62 → 71 → 76 → 84 → 92** 项起步，1.7.5-hotfix.1 起这些能力原样进入合并包组件。下面三条按版本保留细节，便于回查具体能力首次出现的时点。

**1.7.0**：新增前台形态 `pod_exec`（当时叫 `podc_exec`；阻塞到结算、一条调用一条结果、模型面无 jobId/偏移）与 `resume.mjs`（`resumableToolCalls` 桥：`hold` 在等待前、`complete`/`fail` 在平台 `tool/result` 之后）；新增 `recovery.mjs`（重启后按 `pending-exec.json` + 账本结算挂起的调用）。同轮加入：管道 OS 级身份校验（`attest.mjs` / `identity.mjs`，身份通道 + nonce + `attest-policy.json`）、会话归属边界（`sessionId` 进协议/账本，跨会话 `EFOREIGNJOB`，`adopt: true` 接管）、执行预算跟随原生实时设置（`shell.resolve` 四层来源，超时只作用于 `pod_exec`）。

**1.6.0**：管道加固——单客户端、spawn 期 token（stdin）、稳定身份种子、`handover` 接管；`pod_status` 增加 `auth` / `identity`。

**1.5.2 及以前**：detached pod、per-call 沙箱前缀、账本/偏移续读、`ctx.jobs` 收养、输出游标（ack → 重启续读）、模型面保真（行/码点对齐）、stderr channel、`pod-raw.mjs`。

### 实验件能力一览（由上面三段整理）

| 版本 | 引入的能力 | 关键文件/标识 |
|---|---|---|
| 1.5.2 及以前 | detached pod、per-call 沙箱前缀、账本与偏移续读、`ctx.jobs` 收养、输出游标（ack → 重启续读）、模型面保真（行/码点对齐）、stderr channel | `pod-raw.mjs` |
| 1.6.0 | 管道加固：单客户端、spawn 期 token（stdin）、稳定身份种子、`handover` 接管 | `pod_status` 新增 `auth` / `identity` |
| 1.7.0 | 前台形态 `pod_exec`（当时叫 `podc_exec`）、跨重启 hold 与恢复、OS 级身份校验、会话归属边界、执行预算跟随原生实时设置 | `resume.mjs`、`recovery.mjs`、`pending-exec.json`、`attest.mjs`、`identity.mjs`、`attest-policy.json`、`EFOREIGNJOB`、`adopt: true`、`shell.resolve` |

## 测试计数演变（跨版本对照）

本表只做各版本章节里已有数字的横向对照：静态自测长期为 **112 / 112**，变化发生在单元测试。实验件时期（1.5.2 → 1.7.0）的静态计数链条与 `1.1.0-hotfix.2` 一行的单测构成来自同包 TECHDOC 的[「自测历史」一节](./TECHDOC.md#96-自测历史)；其余各行与本文件上面的版本章节逐字对应。

| 版本 | 静态自测 | 单元测试 | POD_VERSION 断言 |
|---|---|---|---|
| 1.5.2 时代 | 48 | — | — |
| 1.6.0 管道加固 | 55 | — | — |
| 1.7.0 `pod_exec` | 62 | — | — |
| 1.7.0 恢复半程 | 71 | — | — |
| 1.7.0 身份通道 | 76 | — | — |
| 1.7.0 会话归属 | 84 | — | — |
| 1.7.0 执行预算 | 92 | — | — |
| 1.7.5-hotfix.6（合并包时期） | 未记录（本轮以归档源码与测试条目为准） | 新增 `escape-pod-shell`：7 条（见上文 hotfix.6 一节） | 未记录 |
| 1.7.5-hotfix.8 | 112/112（当次口径） | `pod-settings` 11、`pod-freeze-policy` 22 | 未记录 |
| 1.0.0-hotfix.9 | 112 / 112 | 7 / 18 / 26 全绿；`scripts/selftest-remote.mjs` 本次拆包未重跑（历史结果 17/17） | `1.0.0-hotfix.9` |
| 1.1.0 | 112 项全绿 | 同 1.0.0-hotfix.9 | `1.1.0` |
| 1.1.0-hotfix.1 | 112 / 112 | 6 个文件共 **129 项**（7 / 18 / 18 / 14 / 46 / 26；新增 `shells`、`pod-shell-tool`、`pod-policy` 三个文件） | `1.1.0-hotfix.1` |
| 1.1.0-hotfix.2 | 112 项 | 6 个文件 **130 项**全绿 | 未记录 |
| 1.1.0-hotfix.3 | 112 项全绿 | 6 个文件 **130 项** | 未记录 |
| 1.1.1 | 未单独记录 | 未单独记录（相对 hotfix.3 无行为变更） | `1.1.1` |

## 常见问题（FAQ）

- **问：hotfix.1 写 129 项、hotfix.2/hotfix.3 写 130 项，是不是矛盾？**
  答：不是矛盾，是时间线——hotfix.1 为 6 个文件共 129 项（7 / 18 / 18 / 14 / 46 / 26），hotfix.2 起因新增中文 `ver` 解析测试变为 130 项（7 / 18 / 19 / 14 / 46 / 26）。该口径差异已登记为 FACT-CONFLICT（FC-①），**TECHDOC 的现值描述已按裁决统一为 130 项**；本文件按版本保留各自历史值。
- **问：当前版本的单测总数到底是多少？**
  答：**130 项**（6 个文件；7 / 18 / 19 / 14 / 46 / 26，含 hotfix.2 新增的中文 `ver` 解析测试）。hotfix.1 时期的 129 项是历史值，仅用于版本对照。
- **问：换上新代码后要看到新行为，必须做什么？**
  答：协议 3 是硬门槛——若还在连旧代码启动的 pod，`pod_run` / `pod_exec` 会 fail-closed 报 `EPROTOCOL`（提示先 `pod_status action:"relaunch"`）。修复动作只有 relaunch 或等旧 pod 空闲退出。
- **问：改名会不会让已有 job 的输出读不到？**
  答：不会。管道 stem、账本目录、Loader id、`jobId` 前缀 `podc-`、环境变量、Cordis 服务名都没改，旧 job 照旧续读。
- **问：`dsh-power` 是什么版本？**
  答：**1.8.2**（本批实际发布版本，以 power 包内 `package.json` 的 `version` 字段为准；escape-pod 1.1.1 的源 README 曾写作 `1.8.0-hotfix.1`，已按本批发布更新）。两者是**两个独立插件**：各自安装、各自设置页、各自开关，互不依赖。

## 相关文档

- 项目介绍与安装：[./README.md](./README.md)
- 架构、协议、安全模型与测试方法：[./TECHDOC.md](./TECHDOC.md)

## 许可

本文件以 MIT 许可发布，版权归 DX12_XYZ 所有。完整条款见仓库根 [LICENSE](./LICENSE)。

<!-- fused-by: glm-5.3-flash -->

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
