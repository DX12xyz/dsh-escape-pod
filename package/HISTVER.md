# 版本历史

> 本文件记录**正式公开**（1.1.1）及之后的版本变更。正式公开之前的私有迭代见
> [HISTVER_legacy.md](./HISTVER_legacy.md)：其中版本从未发布、不保留源码与产物，记录也可能不完整，
> 仅供追溯参考。

## 版本总表

| 版本 | 日期 | 主题 |
|---|---|---|
| **1.1.1** | 2026-11-01 | 首次公开发布（基线） |

## 1.1.1 — 首次公开发布

- **七个 `pod_*` 工具**：`pod_run` / `pod_exec` / `pod_output` / `pod_kill` / `pod_freeze` / `pod_status` / `pod_shell`。
- **命令寿命在 DSH 进程树之外**：detached 的 pod 进程接管命令；DSH 重启、插件热重载、Host 崩溃都只关闭连接，不杀命令。
- **跟随会话文件策略**：`read-only` / `workspace-write` / `danger-full-access` 三档由 Host 现签受限前缀；需要更宽权限时必须走真实的一次性审批。
- **协议 3**：Host 与 pod 的命名管道协议版本为 3（`protocol=3`），带身份校验；账本按绝对字节偏移续读，跨重启、跨 Host 都成立。
- **`pod_shell` 解释器选择**：探测本机可用的 PowerShell / bash / cmd（包括其他 DSH 插件提供的，如 dsh-ops 的 PortableGit），解析顺序「会话选择 → 设置默认 → 自动探测」；本插件不自带任何 shell。
- **冻结模式**：DSH 消失 10 秒后冻结运行中的命令，回来立即解冻；长时间无人回来按 `freezeMinutes` 再生，次数耗尽自毁。
- **可诊断**：账本目录 `%LOCALAPPDATA%\dsh-escape-pod-core`；`pod_status` 给出 pod 身份与 `protocol`、形态模板、本会话 job 与游标、冻结能力、执行预算与当前命令行。
- **平台**：Windows；桌面 Host 的 pod 拉起走计划任务，普通 Host 为普通 detached 进程。

## 后续版本

（尚未发布。正式公开后的每次版本变更在此追加，格式：版本号 / 日期 / 变更 / 兼容性。）

## 许可

本文件以 MIT 许可发布，版权归 DX12_XYZ 所有。完整条款见仓库根 [LICENSE](./LICENSE)。

<!-- fused-by: glm-5.3-flash -->

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
