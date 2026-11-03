# 第三方声明与许可证（THIRD_PARTY_NOTICES）

适用版本 **1.1.1**。

本包（`@local/dsh-escape-pod`）**不随包分发任何第三方源代码或二进制**。以下为设计借鉴与运行时依赖的归属声明。

## 1. `bitsmug/dsh-bgjobs`（设计借鉴）

- 项目：[`bitsmug/dsh-bgjobs`](https://github.com/bitsmug/dsh-bgjobs)
- 许可证：MIT
- 版权：Copyright (c) 2026 bgjobs-dev
- 本包**借鉴了其把后台任务交给独立进程、并把输出写入可续读账本的核心想法**，以及用 Windows
  计划任务让托管进程脱离宿主 job object 的启动配方（`launcher.mjs` 的 `schtasks` 路径）。
- **本项目的 pod 实现、管道协议、七个 `pod_*` 工具、游标/收养、冻结模式、设置页、文件策略
  与审批、命令行探测与选择、身份校验
  等外围功能均为独立实现，未复制其源代码。** 账本位置也是本项目独立决定的：bgjobs 把账本放在
  工作区内，本包放在工作区之外（`%LOCALAPPDATA%\dsh-escape-pod-core`），因此受限模式下的
  被托管命令无法改写自己的记录（`danger-full-access` 同权，代价见 README 安全提示）。

### MIT 许可证全文

```text
MIT License

Copyright (c) 2026 bgjobs-dev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 2. 运行时依赖（由环境提供，不随包分发）

### `koffi`

- 许可证：MIT
- 用途：通过 FFI 调用 `kernel32` / `ntdll` 的 JobObject 冻结 API（`freeze.mjs` 的
  `JobObjectFreezeInformation` 路径），即 `pod_freeze` 与冻结模式。
- 来源：由 **DSH 环境提供**——`attest.mjs` 的 `resolveKoffi()` 从 DSH 安装树
  （profile 的 `node_modules`，其次 npx cache）加载，ABI 与拉起 pod 的 node 一致。
- 本包**不把 `koffi` 声明为 dependency、不复制其源码或 `.node` 二进制**；环境中没有它时
  `pod_status.freeze=unsupported（原因）`，其余功能不受影响。

### Git for Windows PortableGit

- 许可证：GPL-2.0 with linking exception
- 用途：仅当调用方显式使用 `shell: "bash"` 时，作为 **bash 解释器**被调用
  （`bash --noprofile --norc -c <script>`）。它作为独立进程运行，不链接进本包。
- 来源：DSH 自带的 PortableGit（也可用配置 `bashPath` 或环境变量
  `DSH_ESCAPE_POD_BASH` 指定）；**不随本包分发**。

### Windows PowerShell / cmd

- 用途：`shell: "powershell"`（默认）与 `shell: "cmd"` 的解释器。
- 来源：Windows 系统组件；**不随本包分发**。

## 3. 其他

- 本包的 `locale/*.json`、`icon.svg`、文档与脚本均为本项目自研内容。
- 除上文列出的设计借鉴与运行时依赖外，本包不包含其他第三方代码、数据或许可证材料。
