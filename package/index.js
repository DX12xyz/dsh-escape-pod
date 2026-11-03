/**
 * DSH escape pod core — Host plugin.
 *
 * The pod (this bundle's `pod.mjs`) is a detached, Medium-integrity process that
 * survives DSH restarts and keeps the commands it owns running. The Host is only
 * a named-pipe client; it never puts the pod on DSH's kill-on-close rails:
 *
 *   - `ctx.subprocess.spawn` / `ctx.jobs.start` / `ctx.terminal` are NOT used to
 *     start the pod (they would make it die with the Host);
 *   - the pod is spawned by hand with `detached: true, stdio: 'ignore'` and
 *     `unref()`, exactly like `restart-bundle` starts its relauncher.
 *
 * The capability is a prefix, and it is minted PER CALL. Before every `pod_run`
 * the Host asks the sandbox seam for a confined argv whose placeholder target
 * will never run:
 *
 *   ctx.sandbox.confine([node, <placeholder>], { mode, workspaceRoot, sessionId? })
 *     -> { argv: [node, runner.js, --workspace … --temp … --mode … (--write-sid … --temp-write-sid …)?, --, node, <placeholder>] }
 *
 * `mode` is the SESSION'S LIVE FILE POLICY, resolved on every call from
 * `ctx.get('sandboxPolicy').resolve({ session: exec.agent.session })`:
 *
 *   - `read-only`        → a read-only prefix; the command can read, not write;
 *   - `workspace-write`  → the historic behaviour (workspace + session temp dir);
 *   - `danger-full-access` → NO prefix at all: the command is spawned with the
 *     pod's own Medium token, i.e. genuinely unrestricted (the windows-acl runner
 *     cannot express this mode and fails closed on it, so confinement is skipped).
 *
 * A read-only session can raise the policy for ONE call with `sandbox_permissions`
 * + `justification`; that goes through the real DSH approval dialog and only
 * `allowed-once` executes (see `approveEscalation`).
 *
 * Everything before `--` is the runner prefix (the "token factory" invocation);
 * it is sent with the command, never cached: the `--temp-write-sid` it carries is
 * a per-session/workspace revocable capability, so a prefix captured at another
 * time (or before a DSH restart) is stale garbage. The pod pins only a shape
 * template (program + runner path inside the DSH install tree + workspace root)
 * at spawn and validates each per-call prefix against it — including that the
 * prefix's `--mode` equals the mode this call resolved. Malformed, stale or
 * mode-mismatched prefixes fail closed instead of silently running under a
 * different policy.

 *
 * Tools (pod_*): run / exec / output / kill / freeze / status / shell. `pod_exec` is
 * the foreground form: it spawns through the SAME `pod.run` path as `pod_run`,
 * then blocks until the ledger says the command settled and returns one native
 * shaped result (text + `[exit code: N]` + `[status: …]`, no jobId/offset).
 * There is no enable switch: every new command is accepted. The pod's shared
 * `settings.json` (`settings.mjs`) only carries freeze-mode knobs, and this
 * Host exposes it — plus an explicit pod shutdown — as the settings-page API
 * (`/api/dsh-escape-pod/settings`, `/api/dsh-escape-pod/shutdown`) and the
 * `escapePod` Cordis service (`shutdown` / `status`) that `dsh-power` uses for
 * its own shutdown linkage.
 * Before it starts waiting it registers a durable hold with the optional
 * `resumableToolCalls` service (restart-bundle >= 1.7.4-hotfix.4), so a DSH
 * restart during the wait makes the platform write an honest "held" result
 * instead of its synthetic `TOOL_OUTCOME_UNKNOWN`; see `resume.mjs`. Without
 * that service the tool still works, it just loses the call on a restart.
 *
 * Ledger lives OUTSIDE every
 * workspace (default `%LOCALAPPDATA%\dsh-escape-pod-core`, `stateDir` override):
 *   <stateDir>/jobs/<jobId>/{meta.json,out.log,exit.json}
 * A workspace-write command could forge a ledger placed inside its workspace, so
 * both sides refuse such a state dir. (A danger-full-access command shares the
 * user's token and therefore COULD rewrite the ledger: the location rule still
 * applies, but tamper-proofness is not claimed for that mode.) Offsets are
 * absolute byte offsets into out.log, so `pod_output(jobId, from)` continues
 * after a DSH restart without replaying anything.
 *
 * Naming: tools are `pod_*` (renamed from `podc_*` in 1.1.0-hotfix.1 — the pod
 * is no longer "core"). The pipe stem `dsh-escape-pod-core-`, the ledger
 * directory `%LOCALAPPDATA%\dsh-escape-pod-core` and the Loader id
 * `escape-pod-core` keep the historic suffix on purpose: they are on-disk and
 * cross-process identities, and renaming them would orphan live jobs and a
 * running pod. An older control pod (`escape-pod`, `pod_*`) must NOT be
 * installed alongside this one any more: its tool names now collide.
 */

import net from 'node:net'
import { createHash, randomBytes } from 'node:crypto'
import {
  accessSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CONFINED_MODES,
  DEFAULT_IDLE_EXIT_MS,
  DEFAULT_RING_BYTES,
  FALLBACK_OUTPUT_CHUNK_BYTES,
  JOB_ID_PATTERN,
  MAX_OUTPUT_CHUNK_BYTES,
  PROTOCOL_VERSION,
  SANDBOX_MODES,
  clampInt,
  collectDshEnv,
  describePipeIdentity,
  describePrefix,
  describeTemplate,
  fingerprintPrefix,
  generatePodToken,
  isInsideDirectory,
  jobOwnership,
  normalizePathKey,
  optionalString,
  resolvePipeName,
  resolveStateDir,
  tokenFingerprint,
  trimIncompleteUtf8End,
  validatePrefix,
  validateTemplate,
} from './shared.mjs'
import { ADOPT_KIND, createAdoptionManager } from './adoption.mjs'
import { EXEC_HOLD_DEADLINE_MS, EXEC_HOLD_REFRESH_MS, EXEC_TOOL_NAME, createExecHold, resolveResumeService } from './resume.mjs'
// The pod settings file (shared with the pod process). The Host reads/writes it
// through the settings-page API below; the pod re-reads it on every disconnect,
// grace expiry and watchdog tick, so a save takes effect without a reload.
import {
  FREEZE_MINUTES_MAX,
  FREEZE_MINUTES_MIN,
  POD_SETTINGS_DEFAULTS,
  POD_SETTINGS_VERSION,
  REGENERATIONS_MAX,
  REGENERATIONS_MIN,
  normalizePodSettings,
  podSettingsPath,
  readPodSettings,
  writePodSettings,
} from './settings.mjs'
// Host-side shell discovery/selection (pure + probes). The settings page, the
// `pod_shell` tool and the run path all go through this one module, so "what
// the UI shows", "what the tool reports" and "what actually executes" cannot
// disagree about ids, ordering or availability.
import {
  SHELL_KINDS,
  detectShells,
  normalizeShellDefaults,
  resolveShellSelection,
} from './shells.mjs'
import { PENDING_FILE_NAME, createExecRecovery, createPendingStore } from './recovery.mjs'
import {
  SCHTASKS_TIMEOUT_MS,
  deleteTask,
  launchDirect,
  launchViaSchtasks,
  planLauncher,
  podSupportsStdinlessBootstrap,
  probeSchtasks,
  readLauncherMode,
} from './launcher.mjs'

const PLUGIN_VERSION = '1.1.1'
const POD_PATH = fileURLToPath(new URL('./pod.mjs', import.meta.url))
/** Never executed: it only exists so `confine()` has an argv to wrap. */
const PLACEHOLDER_TARGET = 'dsh-escape-pod-core-placeholder-never-executed'
const DEFAULT_WORKSPACE = 'Z:\\Project\\DSHproject'
const CONNECT_TIMEOUT_MS = 1500
/** Loopback identity probe: local, so it either answers at once or never will. */
const ATTEST_TIMEOUT_MS = 800
const SPAWN_CONNECT_BUDGET_MS = 9000
const SPAWN_POLL_INTERVAL_MS = 150
const SPAWN_COOLDOWN_MS = 3000
const MAX_SPAWN_ATTEMPTS = 3
const REQUEST_TIMEOUT_MS = 20000
const MAX_COMMAND_CHARS = 16000
// Native shell-executor defaults, used ONLY when no live source answers (see
// `resolveShellLimits`). They mirror `@deepseek-ai/dsh-pwsh-local`'s
// `static Config`: `timeoutMs: z.number().default(12e4)` (line 142) and
// `maxOutputBytes: z.number().default(64e3)` (line 144). They are NOT policy:
// the live values are re-read on every tool call, so a settings save is visible
// to the very next call.
const NATIVE_DEFAULT_TIMEOUT_MS = 120_000
const NATIVE_DEFAULT_MAX_OUTPUT_BYTES = 64_000
/**
 * Never executed: it exists only so `shell.resolve()` can be asked "what
 * defaults and caps would you apply to a command?" without side effects (the
 * `resolve()` seam fills `timeoutMs`/`stdoutMaxBytes` and caps them).
 */
const LIMITS_PROBE_COMMAND = 'dsh-escape-pod-core:limits-probe'
// Model-facing read window (native job_output semantics). The pod is asked for
// the LIVE native `maxOutputBytes` on every call; this constant is only the
// floor used when a read had to be retried because the window was smaller than
// one UTF-8 code point (a pathological `maxOutputBytes`), and the legacy value
// `modelOutputLimitBytes` used to default to.
const MAX_MODEL_READ_BYTES = 64 * 1024
// `pod_exec` foreground wait: poll the ledger status through the same `output`
// op `pod_output` reads with (a tiny window — only the status matters), and do
// one full read once the command has settled.
const EXEC_POLL_INTERVAL_MS = 200
const EXEC_POLL_BYTES = 512
// The pod owns the native deadline (`run.timeoutMs`). The Host only acts as a
// fallback when a pod ignores that field, so it waits the native timeout plus
// this grace for the pod's own timer to win the race.
const EXEC_TIMEOUT_GRACE_MS = 1000
const HOST_BOOT_ID = createHash('sha256').update(String(process.pid) + ':' + String(Date.now()) + ':' + Math.random()).digest('hex').slice(0, 12)
const HOST_STARTED_AT = new Date().toISOString()

const NO_SANDBOX_MESSAGE = '本机没有可用的沙箱服务，无法签发受限 runner 前缀'

const CONNECTION_TEXT = {
  reused: '复用了重启前就在运行的同一个 pod-core（job 与输出账本连续）',
  reconnected: '重连到仍然存活的同一个 pod-core',
  spawned: '本次 Host 新建的 pod-core（pod 之前不存在）',
  reborn: '原 pod-core 已消失，这是新启动的 pod，之前内存里的 job 句柄不可得（账本仍在磁盘）',
}

/** @param {unknown} error */
function messageOf(error) {
  if (error instanceof Error) return error.message
  return String(error)
}

/** @param {number} ms */
function sleep(ms) {
  // Deliberately NOT unref'd: the spawn/connect retry loops are awaited by a
  // tool call, and an unref'd timer would let the Host event loop drain (and
  // Node exit with "unsettled top-level await") between two connect attempts.
  return new Promise((resolveSleep) => {
    setTimeout(resolveSleep, ms)
  })
}

/** Bounded zombie-pod recovery: 2 failed rounds or 8s, then ONE cleanup. */
export const POD_RECOVERY_MIN_ELAPSED_MS = 8000
export const POD_RECOVERY_MAX_CLEANUPS = 1

/**
 * Bounded recovery policy for a pod that answers on the pipe but cannot be
 * authenticated (a bootstrap pod whose handover keeps failing). Kept pure so
 * the self-test can prove the bound without a real zombie process.
 * @param {{ rounds: number, elapsedMs: number, recoveries: number }} state
 */
export function shouldRecoverUnresponsivePod(state) {
  const recoveries = Number.isFinite(state?.recoveries) ? Number(state.recoveries) : 0
  if (recoveries >= POD_RECOVERY_MAX_CLEANUPS) return false
  const rounds = Number.isFinite(state?.rounds) ? Number(state.rounds) : 0
  const elapsedMs = Number.isFinite(state?.elapsedMs) ? Number(state.elapsedMs) : 0
  return rounds >= 2 || elapsedMs >= POD_RECOVERY_MIN_ELAPSED_MS
}

/** @param {unknown} value @param {number} max */
function truncate(value, max) {
  const text = String(value ?? '')
  return text.length <= max ? text : text.slice(0, max - 1) + '…'
}

/**
 * Re-anchor the HOST-side fallback deadline for a frozen pod job.
 *
 * `pod_exec` keeps a wall-clock fallback deadline for a pod that ignores
 * `timeoutMs`. A freeze pauses the POD's timer (freeze.mjs `pauseDeadline`), so
 * without this the fallback would kill at the ORIGINAL wall-clock instant —
 * exactly the command the freeze is protecting. The pod reports the paused
 * budget as `remainingTimeoutMs`; re-anchor to "now + that budget + grace",
 * which is the same relation the pod's own timer has after a thaw.
 *
 * Exported for the static self-test.
 *
 * @param {number} deadlineAt current fallback deadline (0 = none)
 * @param {any} poll one `output` response
 * @param {number} [graceMs]
 * @returns {number}
 */
export function hostFallbackDeadline(deadlineAt, poll, graceMs = EXEC_TIMEOUT_GRACE_MS) {
  // `0` means "this call has no Host fallback" (unlimited): never invent one.
  if (!(Number.isFinite(deadlineAt) && deadlineAt > 0)) return deadlineAt
  if (poll?.frozen !== true) return deadlineAt
  // `null` is "the pod has no paused budget to report" (a ledger-only record or
  // a job that never had a deadline) — `Number(null)` would be a 0ms lie.
  const remaining = poll?.remainingTimeoutMs
  if (typeof remaining !== 'number' || !Number.isFinite(remaining) || remaining < 0) return deadlineAt
  return Date.now() + remaining + graceMs
}

/**
 * Human form of a freeze watchdog window (`pod_freeze` / `pod_status`).
 * The pod owns the exact deadline; this is presentation only.
 * @param {unknown} ms
 */
function renderFreezeRemaining(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '未知'
  const totalSeconds = Math.max(0, Math.round(ms / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return minutes > 0 ? String(minutes) + 'm' + String(seconds).padStart(2, '0') + 's' : String(seconds) + 's'
}

/**
 * The policy root has to be a real directory or the runner fails closed. Prefer
 * the session cwd, then the Host's own cwd, then the documented fallback.
 * @param {unknown} candidate
 * @returns {string}
 */
export function resolveWorkspaceRoot(candidate) {
  if (typeof candidate === 'string') {
    const trimmed = candidate.trim()
    if (trimmed !== '' && !trimmed.startsWith('\\\\')) {
      try {
        if (statSync(trimmed).isDirectory()) return trimmed
      } catch {
        // fall through
      }
    }
  }
  try {
    const cwd = process.cwd()
    if (statSync(cwd).isDirectory()) return cwd
  } catch {
    // fall through
  }
  return DEFAULT_WORKSPACE
}

/**
 * The session-derived half of the sandbox policy, exactly like the judgement
 * bundle reads it: `sessionId` is optional; workspaceRoot comes from the live
 * session metadata when it is usable.
 *
 * The session id comes from `exec.agent.id`. DSH's `Agent` interface names the
 * shared SessionId `id` (dsh-agent/types.d.ts: `readonly id: SessionId`), and
 * `agent.session.id` is that same value; there is no `agent.sessionId` and no
 * `exec.session`. Verified against dsh-agent/lib/index.js's `executeToolCalls`,
 * which sets `ToolExecutionInput.agent = ctx.agents.requireInitiator()`.
 *
 * @param {any} exec tool run context
 * @returns {{ sessionId: string | null, workspaceRoot: string, workspaceSource: string }}
 */
export function policyHint(exec) {
  /** @type {{ sessionId: string | null, workspaceRoot: string, workspaceSource: string }} */
  const hint = { sessionId: null, workspaceRoot: DEFAULT_WORKSPACE, workspaceSource: 'hardcoded fallback' }
  try {
    const agent = exec?.agent
    if (agent !== null && agent !== undefined) {
      const rawId = agent.id
      if (typeof rawId === 'string' && rawId !== '') hint.sessionId = rawId
      else if (typeof rawId === 'number') hint.sessionId = String(rawId)
      const cwd = agent.session?.meta?.cwd
      if (typeof cwd === 'string' && cwd !== '') {
        hint.workspaceRoot = resolveWorkspaceRoot(cwd)
        hint.workspaceSource = hint.workspaceRoot === cwd.trim() ? 'session.meta.cwd' : 'fallback (session cwd unusable)'
      }
    }
  } catch {
    // A hostile getter is not worth failing a tool call over; keep the default.
  }
  return hint
}

/**
 * One of DSH's three file-policy modes, or null for anything else.
 * @param {unknown} value
 * @returns {'read-only' | 'workspace-write' | 'danger-full-access' | null}
 */
export function normalizeSandboxMode(value) {
  return SANDBOX_MODES.includes(value) ? /** @type {any} */ (value) : null
}

/**
 * A directory a runner may actually be pointed at, or null. `resolveWorkspaceRoot`
 * falls back to the Host's cwd, which is right for a *default* but wrong for a
 * value the policy service returned: a bogus policy root must fall back to the
 * session-derived root, not silently move the command into the Host's cwd.
 * @param {unknown} candidate
 * @returns {string | null}
 */
function usableDirectory(candidate) {
  if (typeof candidate !== 'string') return null
  const trimmed = candidate.trim()
  if (trimmed === '' || trimmed.startsWith('\\\\')) return null
  try {
    return statSync(trimmed).isDirectory() ? trimmed : null
  } catch {
    return null
  }
}

/**
 * The authority one tool call must obey: the LIVE session file policy, not a
 * hard-coded `workspace-write`. `dsh-bash-sandbox` resolves exactly this way
 * (`ctx.get('sandboxPolicy')?.resolve({ session: exec.agent.session })`), so the
 * pod follows the same switch the user sees in the DSH UI.
 *
 * A missing or broken service falls back to `workspace-write`: that is what this
 * plugin did before it consulted a policy at all, it must not silently lose
 * write access in a deployment without the service, and it must certainly not
 * gain `danger-full-access` by accident. An unusable `workspaceRoot` falls back
 * through {@link resolveWorkspaceRoot} because the runner fails closed on a
 * non-existent root: a bogus value must not reach `confine()`.
 *
 * @param {any} ctx Host plugin context (null in tests / older Hosts)
 * @param {any} exec tool run context
 * @param {{ sessionId?: string | null, workspaceRoot?: string } | null} hint
 * @returns {{
 *   mode: 'read-only' | 'workspace-write' | 'danger-full-access',
 *   workspaceRoot: string,
 *   sessionId: string | null,
 *   source: string,
 *   modeNote?: string,
 *   policyError?: string,
 * }}
 */
export function resolveStandingPolicy(ctx, exec, hint = null) {
  const fallbackWorkspace = resolveWorkspaceRoot(hint?.workspaceRoot)
  const fallbackSession = typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null
  /** @type {any} */
  const fallback = {
    mode: 'workspace-write',
    workspaceRoot: fallbackWorkspace,
    sessionId: fallbackSession,
    source: 'fallback:workspace-write',
  }
  const service = serviceOrNull(ctx, 'sandboxPolicy')
  if (service === null || typeof service.resolve !== 'function') return fallback
  /** @type {any} */
  let resolved
  try {
    resolved = service.resolve({ session: exec?.agent?.session })
  } catch (error) {
    return { ...fallback, source: 'fallback:sandboxPolicy-error', policyError: messageOf(error) }
  }
  if (resolved === null || typeof resolved !== 'object') {
    return { ...fallback, source: 'fallback:sandboxPolicy-empty', policyError: 'sandboxPolicy.resolve() 返回了空值' }
  }
  const mode = normalizeSandboxMode(resolved.mode)
  const workspaceRootRaw = optionalString(resolved.workspaceRoot)
  /** @type {any} */
  const standing = {
    mode: mode ?? 'workspace-write',
    // Prefer the policy's root only when it is a real directory; otherwise keep
    // the session-derived one (the runner fails closed on a bogus root).
    workspaceRoot: usableDirectory(workspaceRootRaw) ?? fallbackWorkspace,
    sessionId: optionalString(resolved.sessionId) ?? fallbackSession,
    source: 'sandboxPolicy',
  }
  if (mode === null) {
    standing.modeNote = 'sandboxPolicy.resolve() 的 mode 非法（' + String(resolved.mode) + '），已回落到 workspace-write'
  }
  return standing
}

/**
 * The escalation contract, ported 1:1 from `dsh-bash-sandbox`
 * (`lib/shells/approval.js`) so the two tools cannot drift: only the two wider
 * modes may be requested, a real change needs a non-empty reason, a reason
 * without a target is a caller mistake, and an approval is NEVER used to
 * down-shift a policy (a user who narrows the session means "no writes").
 *
 * @param {{ sandbox_permissions?: unknown, justification?: unknown } | null | undefined} args
 * @param {{ mode: string, workspaceRoot?: string }} standing
 * @returns {void}
 */
export function validateEscalation(args, standing) {
  const target = args?.sandbox_permissions
  const reason = args?.justification
  if (target !== undefined && target !== 'workspace-write' && target !== 'danger-full-access') {
    throw new PodError(
      'invalid sandbox_permissions: 只接受 workspace-write 或 danger-full-access（收到：' + String(target) + '）',
      'ESANDBOXPERMISSIONS',
    )
  }
  if (reason !== undefined && typeof reason !== 'string') {
    throw new PodError('invalid justification: 必须是字符串', 'EJUSTIFICATION')
  }
  if (target === undefined && typeof reason === 'string' && reason.trim() !== '') {
    throw new PodError('invalid justification: 只有同时传 sandbox_permissions 时才允许给理由（收到理由却没有申请模式）', 'EJUSTIFICATION')
  }
  if (target !== undefined && target !== standing.mode && (typeof reason !== 'string' || reason.trim() === '')) {
    throw new PodError(
      'invalid justification: 申请与当前会话不同的 sandbox_permissions（' + String(standing.mode) + ' → ' + String(target) + '）时必须给一个非空理由',
      'EJUSTIFICATION',
    )
  }
  if (target !== undefined && SANDBOX_MODES.indexOf(String(target)) < SANDBOX_MODES.indexOf(standing.mode)) {
    throw new PodError(
      'invalid sandbox_permissions: 申请的模式比当前会话更窄（' + String(standing.mode) + ' → ' + String(target) +
        '），审批不会用来降级；请直接按会话策略执行',
      'ESANDBOXNARROWER',
    )
  }
}

/**
 * Raise the session policy for ONE call, through the real DSH approval dialog.
 * Only `allowed-once` proceeds: `denied`, `timeout`, a dismissed prompt or any
 * other outcome is a hard tool error, so the model can neither quietly retry nor
 * "work around" the decision.
 *
 * The policy is re-resolved after the dialog. If the user moved the session
 * switch while the prompt was open, the call would run under an authority nobody
 * approved, so it fails with AUTHORITY_CHANGED — the same rule as
 * `dsh-bash-sandbox`.
 *
 * @param {any} ctx Host plugin context
 * @param {any} exec tool run context (carries agent/callId/signal)
 * @param {string} toolName the name the approval dialog shows
 * @param {{ sandbox_permissions?: unknown, justification?: unknown }} args
 * @param {{ mode: string, workspaceRoot: string, sessionId: string | null, source: string }} standing
 * @param {{ sessionId?: string | null, workspaceRoot?: string } | null} [hint]
 * @returns {Promise<{ mode: 'read-only' | 'workspace-write' | 'danger-full-access', workspaceRoot: string, sessionId: string | null, source: string, escalated: boolean }>}
 */
export async function approveEscalation(ctx, exec, toolName, args, standing, hint = null) {
  validateEscalation(args, standing)
  const target = args?.sandbox_permissions
  if (target === undefined || target === standing.mode) return { ...standing, escalated: false, standingMode: standing.mode }
  const approval = serviceOrNull(ctx, 'approval')
  if (exec?.agent === null || exec?.agent === undefined || typeof approval?.request !== 'function') {
    throw new PodError(
      'APPROVAL_UNAVAILABLE：没有执行任何命令——本 Host 没有可用的审批服务（或这次调用没有 agent），' +
        '因此无法把会话策略提升到 ' + String(target) + '。不要绕过会话策略。',
      'EAPPROVALUNAVAILABLE',
    )
  }
  const outcome = await approval.request({
    agent: exec.agent,
    callId: exec.callId,
    toolName,
    reason: args.justification,
    signal: exec.signal,
  })
  if (outcome !== 'allowed-once') {
    throw new PodError(
      'APPROVAL_' + String(outcome).toUpperCase().replace(/-/g, '_') +
        '：没有执行任何命令——申请的更宽模式 ' + String(target) + ' 没有被批准（结果：' + String(outcome) + '）。' +
        '不要重试，也不要绕过这个决定。',
      'EAPPROVALDENIED',
    )
  }
  exec.signal?.throwIfAborted()
  const current = resolveStandingPolicy(ctx, exec, hint ?? policyHint(exec))
  if (current.mode !== standing.mode || normalizePathKey(current.workspaceRoot) !== normalizePathKey(standing.workspaceRoot)) {
    throw new PodError(
      'AUTHORITY_CHANGED：审批等待期间会话的文件策略变了（' + String(standing.mode) + ' @ ' + String(standing.workspaceRoot) +
        ' → ' + String(current.mode) + ' @ ' + String(current.workspaceRoot) + '），没有执行任何命令。',
      'EAUTHORITYCHANGED',
    )
  }
  return {
    ...standing,
    mode: /** @type {any} */ (target),
    escalated: true,
    // The session mode this call was widened FROM. Kept on the returned object
    // so every renderer can say "standing X → this call Y" without re-resolving.
    standingMode: standing.mode,
    source: String(standing.source) + '+approval',
  }
}

/**
 * TOCTOU guard between "policy resolved/approved" and "request sent": deriving
 * the prefix and reaching the pod are both async, and the user can move the
 * session switch in between. Throwing here means no command was started at all.
 *
 * @param {any} ctx @param {any} exec
 * @param {{ mode: string, workspaceRoot: string }} standing
 * @param {{ sessionId?: string | null, workspaceRoot?: string } | null} hint
 * @returns {void}
 */
export function assertStandingUnchanged(ctx, exec, standing, hint = null) {
  const current = resolveStandingPolicy(ctx, exec, hint)
  if (current.mode !== standing.mode || normalizePathKey(current.workspaceRoot) !== normalizePathKey(standing.workspaceRoot)) {
    throw new PodError(
      'AUTHORITY_CHANGED：会话的文件策略在准备执行时变了（' + String(standing.mode) + ' @ ' + String(standing.workspaceRoot) +
        ' → ' + String(current.mode) + ' @ ' + String(current.workspaceRoot) + '），没有执行任何命令。',
      'EAUTHORITYCHANGED',
    )
  }
}

/**
 * PowerShell resolution mirrors the provider DSH itself uses
 * (`dsh-pwsh-local/resolve`): PowerShell 7 install, PATH entries, then Windows
 * PowerShell 5.1, else bare `pwsh` for PATH resolution by CreateProcess.
 * @param {string | undefined} configured
 * @param {NodeJS.ProcessEnv} [env]
 * @param {NodeJS.Platform} [platform]
 */
export function resolvePwshPath(configured, env = process.env, platform = process.platform) {
  if (typeof configured === 'string' && configured.length > 0) return configured
  if (platform === 'win32') {
    const programFiles = env.ProgramFiles ?? 'C:\\Program Files'
    const systemRoot = env.SystemRoot ?? 'C:\\Windows'
    const candidates = [join(programFiles, 'PowerShell', '7', 'pwsh.exe')]
    for (const entry of (env.PATH ?? '').split(';')) {
      const trimmed = entry.trim().replace(/^"|"$/g, '')
      if (trimmed.length === 0) continue
      candidates.push(join(trimmed, 'pwsh.exe'))
    }
    candidates.push(join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'))
    for (const candidate of candidates) {
      try {
        const stat = lstatSync(candidate)
        if (stat.isFile() || stat.isSymbolicLink()) return candidate
      } catch {
        // try the next candidate
      }
    }
  }
  return 'pwsh'
}

/**
 * Native `dsh-pwsh-local` prepends this to every command so the child emits
 * UTF-8 regardless of the console code page (`lib/index.js:100`). Without it a
 * Chinese Windows console writes GBK bytes and every non-ASCII line reaches the
 * model as mojibake.
 *
 * Each assignment sits in its own `try/catch`: a read-only session runs
 * PowerShell in Constrained Language (the platform's restricted token), where
 * creating a .NET type is a terminating error. Uncaught it would print two
 * errors to stderr on every single command and pollute the model's output.
 */
const ENCODING_PREAMBLE =
  'try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }; ' +
  'try { $OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }; '

/**
 * The exact argv shape the pwsh tool family uses: one argv element carries the
 * command text, no intermediate shell quoting layer.
 * @param {string} command
 * @param {string} pwshPath
 */
export function buildShellArgv(command, pwshPath) {
  return [pwshPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', ENCODING_PREAMBLE + String(command)]
}

/**
 * Resolve a job cwd against the policy workspace: relative paths resolve under
 * the workspace, a missing directory fails closed, and — crucially — an absolute
 * path outside the policy workspace is REJECTED. Letting cwd leave the workspace
 * would give the command a working directory the policy never described (a
 * classic sandbox escape shape), so it is a hard tool-call error.
 * @param {unknown} raw
 * @param {string} workspaceRoot
 */
export function resolveJobCwd(raw, workspaceRoot) {
  const text = optionalString(raw)
  const resolved = text === undefined ? workspaceRoot : (isAbsolute(text) ? resolve(text) : resolve(workspaceRoot, text))
  let isDir = false
  try {
    isDir = statSync(resolved).isDirectory()
  } catch {
    isDir = false
  }
  if (!isDir) throw new PodError('cwd 不是已存在的目录：' + resolved, 'ECWD')
  if (!isInsideDirectory(workspaceRoot, resolved)) {
    throw new PodError(
      'cwd 必须位于本次 policy 的 workspace 内（越界会让命令站在沙箱没有描述过的目录里）：' +
      resolved + ' ⊄ ' + workspaceRoot,
      'ECWDWORSKSPACE',
    )
  }
  return resolved
}

class PodError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'EPODCUNREACHABLE') {
    super(message)
    this.name = 'PodError'
    this.code = code
  }
}

/* ------------------------------------------- settings page (Host side) ----- */

/**
 * The escape pod's own state directory. `settings.mjs` stores its file there as
 * `<podStateDir>/settings.json` and the pod (a separate process) reads the very
 * same file for `freezeMode` / `freezeMinutes` / `regenerations`.
 */
export const POD_STATE_DIR_NAME = 'dsh-escape-pod-core'

/**
 * Resolve the pod's state directory with the SAME rule the pod uses
 * (`resolveStateDir` in shared.mjs), reproduced here on purpose: the plugin
 * must not import the pod's runtime module graph.
 * `%LOCALAPPDATA%\dsh-escape-pod-core`, then `$DSH_HOME/.escape-pod-core`,
 * then `~/.dsh-escape-pod-core`.
 * @param {NodeJS.ProcessEnv} [env] environment (tests pass a fake one).
 * @param {string} [home] user home directory (tests pass a fake one).
 * @returns {string} absolute pod state directory.
 */
export function resolvePodStateDir(env = process.env, home = homedir()) {
  const text = (value) => (typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined)
  const localAppData = text(env?.LOCALAPPDATA)
  if (localAppData !== undefined) return join(localAppData, POD_STATE_DIR_NAME)
  const dshHome = text(env?.DSH_HOME)
  if (dshHome !== undefined) return join(dshHome, '.escape-pod-core')
  return join(home, '.dsh-escape-pod-core')
}

/**
 * Whether a settings directory can be written. A missing directory is judged
 * by its nearest existing ancestor, because the writer creates it recursively
 * (`mkdirSync(..., { recursive: true })`).
 * @param {string} dir - directory the settings file lives in.
 * @returns {boolean} whether a save could plausibly succeed.
 */
export function directoryWritable(dir) {
  let current = dir
  for (let depth = 0; depth < 64; depth += 1) {
    let stat = null
    try {
      stat = statSync(current)
    } catch {
      stat = null
    }
    if (stat !== null) {
      // An existing non-directory cannot host the settings file.
      if (!stat.isDirectory()) return false
      try {
        accessSync(current, fsConstants.W_OK)
        return true
      } catch {
        return false
      }
    }
    const parent = dirname(current)
    if (parent === current) return false
    current = parent
  }
  return false
}

/**
 * The settings view returned by `GET /api/dsh-escape-pod/settings`: exactly
 * what the pod will honour (missing/corrupt file = the documented defaults)
 * plus whether it can be written. Read fresh on every request — the file is the
 * single source of truth, and the pod re-reads it too.
 * @param {string} [podStateDir] pod state directory (defaults to the pod's rule).
 * @returns {{ freezeMode: boolean, freezeMinutes: number, regenerations: number, shells: { powershell: string, bash: string }, writable: boolean }}
 */
export function podConfigView(podStateDir = resolvePodStateDir()) {
  return { ...readPodSettings(podStateDir), writable: directoryWritable(podStateDir) }
}

/**
 * Validate the POSTed settings body. Values that ARE present must sit inside
 * their documented range and be integer literals; omitted ones keep what is
 * already stored, so a partial update never silently resets a knob.
 * @param {unknown} raw - the request body.
 * @param {{ freezeMode: boolean, freezeMinutes: number, regenerations: number, shells?: { powershell?: string, bash?: string } }} current
 *   settings currently stored in the pod's file (an older `current` without
 *   `shells` normalizes to the shell defaults).
 * @returns {{ settings: { freezeMode: boolean, freezeMinutes: number, regenerations: number, shells: { powershell: string, bash: string } } }
 *   | { error: string }} the normalized settings, or the first validation error.
 */
export function validatePodSettingsInput(raw, current) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return { error: '请求体必须是对象' }
  const value = /** @type {Record<string, unknown>} */ (raw)
  if (value.freezeMode !== undefined && typeof value.freezeMode !== 'boolean') {
    return { error: 'freezeMode 必须是布尔值' }
  }
  const freezeMinutes = value.freezeMinutes
  if (freezeMinutes !== undefined && !inIntegerRange(freezeMinutes, FREEZE_MINUTES_MIN, FREEZE_MINUTES_MAX)) {
    return { error: `freezeMinutes 必须是 ${FREEZE_MINUTES_MIN}..${FREEZE_MINUTES_MAX} 的整数` }
  }
  const regenerations = value.regenerations
  if (regenerations !== undefined && !inIntegerRange(regenerations, REGENERATIONS_MIN, REGENERATIONS_MAX)) {
    return { error: `regenerations 必须是 ${REGENERATIONS_MIN}..${REGENERATIONS_MAX} 的整数` }
  }
  return {
    settings: normalizePodSettings({
      freezeMode: value.freezeMode === undefined ? current.freezeMode : value.freezeMode,
      freezeMinutes: freezeMinutes === undefined ? current.freezeMinutes : freezeMinutes,
      regenerations: regenerations === undefined ? current.regenerations : regenerations,
      // `shells` is carried through explicitly: without it every unrelated save
      // (e.g. only `freezeMode`) would silently reset the shell pickers to
      // `auto`, because normalizePodSettings rebuilds the object from scratch.
      shells: value.shells === undefined ? current.shells : normalizeShellDefaults(value.shells),
    }),
  }
}

/** @param {unknown} value @param {number} min @param {number} max */
function inIntegerRange(value, min, max) {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max
}

/** How long the HTTP/service shutdown waits for the pod's own answer. */
export const POD_SHUTDOWN_TIMEOUT_MS = 15_000

/**
 * Resolve with the promise's value, or with `{ timedOut: true }` after
 * `timeoutMs`. Never rejects: shutting down must not be blocked by a pod that
 * is already gone.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @returns {Promise<T | { timedOut: true }>}
 */
function withTimeout(promise, timeoutMs) {
  return new Promise((resolveWith) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      resolveWith(/** @type {any} */ ({ timedOut: true }))
    }, timeoutMs)
    timer.unref?.()
    promise.then(
      (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolveWith(value)
      },
      () => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolveWith(/** @type {any} */ ({ timedOut: false, failed: true }))
      },
    )
  })
}

/**
 * The Host-side contract behind `/api/dsh-escape-pod/*` and the `escapePod`
 * Cordis service. Deliberately free of `ctx`: the routes, the service and the
 * tests share exactly this one implementation.
 *
 * @param {{
 *   getPod?: () => ({ shutdown?: (request?: { killJobs?: boolean }) => Promise<any>, mode?: () => string } | null) | null,
 *   stateDir?: string,
 *   shutdownTimeoutMs?: number,
 *   log?: (message: string) => void,
 *   pwshPath?: string,
 *   bashPath?: string,
 *   detectShells?: (options: any) => any,
 *   now?: number | (() => number),
 * }} [options]
 *   `pwshPath`/`bashPath` are the plugin's configured paths (they outrank the
 *   discovered ones); `detectShells`/`now` are test seams for the shells route —
 *   production always uses the real detection, which caches versions for 60s.
 */
export function createEscapePodApi(options = {}) {
  const getPod = typeof options.getPod === 'function' ? options.getPod : () => null
  const stateDir =
    typeof options.stateDir === 'string' && options.stateDir.trim() !== '' ? options.stateDir : resolvePodStateDir()
  const log = typeof options.log === 'function' ? options.log : () => {}
  const shutdownTimeoutMs = clampInt(options.shutdownTimeoutMs, POD_SHUTDOWN_TIMEOUT_MS, 100, 120_000)
  const detect = typeof options.detectShells === 'function' ? options.detectShells : detectShells
  const nowOption = options.now
  const nowMs = () => resolveShellNowMs(nowOption)

  /** `GET /settings` — and the body of a successful POST. */
  function settingsView() {
    return { ok: true, ...podConfigView(stateDir) }
  }

  /**
   * `GET /shells`: the candidate list the settings page renders, detected on
   * the Host only. Deliberately never touches the pod client — opening (or
   * re-rendering) the settings page must not spawn or wake a pod. A detection
   * failure is a normal answer with `ok:false` + `error`, so the page can show
   * the error line while every other setting stays editable.
   * @returns {{ ok: boolean, generatedAt: string, groups: any[], defaults: { powershell: string, bash: string }, error?: string }}
   */
  function shellsView() {
    /** @type {any} */
    let detection = null
    let error = null
    try {
      detection = detect({
        config: { pwshPath: options.pwshPath, bashPath: options.bashPath },
        ...(nowOption === undefined ? {} : { now: nowOption }),
      })
      if (detection === null || typeof detection !== 'object' || !Array.isArray(detection.groups) || detection.groups.length === 0) {
        error = '命令行探测没有返回任何分组'
      }
    } catch (failure) {
      error = messageOf(failure)
    }
    const groups = detection !== null && typeof detection === 'object' && Array.isArray(detection.groups) ? detection.groups : []
    return {
      ok: error === null,
      generatedAt: typeof detection?.generatedAt === 'string' ? detection.generatedAt : new Date(nowMs()).toISOString(),
      groups: error === null ? groups : [],
      defaults: readPodSettings(stateDir).shells,
      ...(error === null ? {} : { error }),
    }
  }

  /**
   * `POST /settings`. Every field is optional; a rejected value writes nothing.
   * @param {unknown} body
   * @returns {{ status: number, body: Record<string, unknown> }}
   */
  function saveSettings(body) {
    const validated = validatePodSettingsInput(body, readPodSettings(stateDir))
    if ('error' in validated) return { status: 400, body: { ok: false, error: validated.error } }
    if (!directoryWritable(stateDir)) {
      return { status: 500, body: { ok: false, error: `设置目录不可写（${stateDir}），本次未保存任何设置` } }
    }
    if (!writePodSettings(stateDir, validated.settings)) {
      return { status: 500, body: { ok: false, error: `写入设置失败（${stateDir}），本次未保存任何设置` } }
    }
    log('settings saved: ' + JSON.stringify(validated.settings))
    // Same shape as GET: the answer is what the file says NOW, not an echo.
    return { status: 200, body: settingsView() }
  }

  /**
   * Kill every job the pod owns and close it. A pod that is not running (or a
   * Host that never connected) is success with `killed: 0`: there is nothing
   * left to stop, and a DSH shutdown must never wait for it.
   * @param {string} [reason]
   * @returns {Promise<{ ok: boolean, killed: number, status: string, timedOut?: boolean, error?: string }>}
   */
  async function shutdown(reason) {
    let pod = null
    try {
      pod = getPod()
    } catch (error) {
      log('shutdown: cannot reach the pod client: ' + messageOf(error))
      return { ok: true, killed: 0, status: 'unavailable' }
    }
    if (pod === null || pod === undefined || typeof pod.shutdown !== 'function') {
      return { ok: true, killed: 0, status: 'not-running' }
    }
    /** @type {Promise<any>} */
    let pending
    try {
      pending = Promise.resolve(pod.shutdown({ killJobs: true, reason }))
    } catch (error) {
      // A client that throws synchronously is a client with nothing to close.
      log('shutdown: pod client refused: ' + messageOf(error))
      return { ok: true, killed: 0, status: 'error', error: messageOf(error) }
    }
    const outcome = await withTimeout(pending, shutdownTimeoutMs)
    if (/** @type {any} */ (outcome)?.timedOut === true) {
      log('shutdown: pod did not answer within ' + shutdownTimeoutMs + 'ms; treating as closed')
      return { ok: true, killed: 0, status: 'timeout', timedOut: true }
    }
    if (/** @type {any} */ (outcome)?.failed === true) {
      return { ok: true, killed: 0, status: 'error' }
    }
    const result = /** @type {any} */ (outcome)
    const killed = Number.isFinite(result?.killed) ? Math.max(0, Math.trunc(result.killed)) : 0
    return {
      ok: true,
      killed,
      status: typeof result?.status === 'string' ? result.status : 'closed',
      ...(typeof result?.error === 'string' ? { error: result.error } : {}),
    }
  }

  /** Cheap, side-effect-free status for the `escapePod` service. */
  function status() {
    let mode = 'unknown'
    try {
      const pod = getPod()
      mode = pod !== null && pod !== undefined && typeof pod.mode === 'function' ? String(pod.mode()) : 'none'
    } catch {
      mode = 'unknown'
    }
    return { ok: true, stateDir, mode, ...podConfigView(stateDir) }
  }

  return { settingsView, saveSettings, shutdown, status, shellsView, stateDir }
}

/**
 * Resolve the bash executable used by `shell: 'bash'`.
 *
 * Stock Git for Windows 2.49 dies under the sandbox's restricted token
 * (`NtSetInformationToken(TokenDefaultDacl)` is denied, then Cygwin cannot
 * create its signal pipe), while DSH's own ops plugin ships a PortableGit
 * runtime under `<DSH_HOME>/dsh-ops/bash-ipc/<instance>/bin/bash.exe` that
 * survives it. Preference order: configured path, `DSH_ESCAPE_POD_BASH`, the
 * newest DSH PortableGit instance, then `bash.exe` from PATH.
 *
 * @param {string | undefined} configured
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function resolveBashPath(configured, env = process.env) {
  if (typeof configured === 'string' && configured.length > 0) return configured
  const fromEnv = env.DSH_ESCAPE_POD_BASH
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv
  const home = env.DSH_HOME
  if (typeof home === 'string' && home.length > 0) {
    const root = join(home, 'dsh-ops', 'bash-ipc')
    try {
      let best
      let newest = -1
      for (const entry of readdirSync(root)) {
        const candidate = join(root, entry, 'bin', 'bash.exe')
        try {
          const stat = statSync(candidate)
          if (stat.isFile() && stat.mtimeMs > newest) {
            best = candidate
            newest = stat.mtimeMs
          }
        } catch {
          // not an extracted instance
        }
      }
      if (best !== undefined) return best
    } catch {
      // no DSH ops runtime on this machine
    }
  }
  return 'bash.exe'
}

/**
 * The exact argv shape for `shell: 'bash'`: one script argument, no extra
 * shell quoting layer (`--noprofile --norc` keeps the user's RC out of it).
 * @param {string} command
 * @param {string} bashPath
 */
export function buildBashArgv(command, bashPath) {
  return [bashPath, '--noprofile', '--norc', '-c', String(command)]
}

/**
 * The exact argv shape for `shell: 'cmd'` (`/d` skips AutoRun, `/s` keeps the
 * command as one string).
 * @param {string} command
 * @param {string} [comspec]
 */
export function buildCmdArgv(command, comspec = process.env.ComSpec) {
  return [comspec ?? 'cmd.exe', '/d', '/s', '/c', String(command)]
}

/**
 * @param {unknown} shell
 * @returns {'powershell' | 'cmd' | 'bash'}
 */
export function normalizeShellKind(shell) {
  if (shell === undefined || shell === null || shell === '') return 'powershell'
  if (shell === 'powershell' || shell === 'cmd' || shell === 'bash') return shell
  throw new PodError('shell 只能是 powershell、cmd 或 bash', 'EARGS')
}

/* ------------------------------------- shell choice: per-session overrides -- */

/**
 * How long a per-session shell choice is kept. A DSH session id survives a
 * restart, so an override made for one project would otherwise outlive it and
 * keep pointing at an interpreter the user has forgotten about. Dropped while
 * loading (never rewritten just because it aged out).
 */
export const SHELL_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000

/** The file holding per-session choices, next to `settings.json`. */
export const SHELL_SESSION_FILE = 'shell-sessions.json'

/** Its schema version (v1: a bare `sessions` map). */
export const SHELL_SESSION_VERSION = 1

/** @param {string} stateDir */
export function shellSessionsPath(stateDir) {
  return join(stateDir, SHELL_SESSION_FILE)
}

/**
 * @param {number | (() => number) | undefined} value
 * @returns {number}
 */
function resolveShellNowMs(value) {
  const candidate = typeof value === 'function' ? value() : value
  return typeof candidate === 'number' && Number.isFinite(candidate) ? candidate : Date.now()
}

/**
 * One stored id, or null. `normalizeShellDefaults` is reused instead of copying
 * the id pattern: shells.mjs already owns that rule, and a second copy would
 * drift. `'auto'` is the absence of a choice, not a choice.
 *
 * @param {unknown} value
 * @returns {string | null}
 */
function storedShellChoice(value) {
  if (typeof value !== 'string') return null
  const normalized = normalizeShellDefaults({ powershell: value }).powershell
  return normalized === 'auto' ? null : normalized
}

/**
 * Normalize one file entry. An entry without a readable `updatedAt` is dropped
 * rather than kept forever: the TTL is the only thing that bounds this file.
 *
 * @param {unknown} raw
 * @param {number} nowMs
 * @returns {{ powershell?: string, bash?: string, updatedAt: string } | null}
 */
function normalizeSessionEntry(raw, nowMs) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null
  const value = /** @type {Record<string, unknown>} */ (raw)
  const updatedAtMs = Date.parse(typeof value.updatedAt === 'string' ? value.updatedAt : '')
  if (!Number.isFinite(updatedAtMs)) return null
  if (nowMs - updatedAtMs > SHELL_SESSION_TTL_MS) return null
  /** @type {{ powershell?: string, bash?: string, updatedAt: string }} */
  const entry = {}
  const powershell = storedShellChoice(value.powershell)
  const bash = storedShellChoice(value.bash)
  if (powershell !== null) entry.powershell = powershell
  if (bash !== null) entry.bash = bash
  if (entry.powershell === undefined && entry.bash === undefined) return null
  entry.updatedAt = new Date(updatedAtMs).toISOString()
  return entry
}

/**
 * Per-session shell choices, persisted next to `settings.json`.
 *
 * Why a separate file: `settings.json` is also read by the pod process, and a
 * session-scoped override is a Host concept the pod must never see. Why the
 * TTL: session ids are stable across restarts.
 *
 * Reads are lazy and cached in memory. A broken/unreadable file is an empty
 * store — never an exception, because shell resolution runs on every command
 * and must not be able to break execution. Writes are atomic (same-directory
 * tmp + rename); a failed write still applies the choice to this Host and
 * returns a warning string instead of failing the tool call, so an unwritable
 * state directory degrades to "works until restart", not to "cannot switch".
 *
 * @param {{ stateDir?: string, now?: number | (() => number), log?: (message: string) => void }} [options]
 */
export function createShellSessionStore(options = {}) {
  const stateDir = typeof options?.stateDir === 'string' && options.stateDir.trim() !== ''
    ? options.stateDir
    : resolvePodStateDir()
  const nowOption = options?.now
  const log = typeof options?.log === 'function' ? options.log : () => {}
  const file = shellSessionsPath(stateDir)
  /** @type {Map<string, { powershell?: string, bash?: string, updatedAt: string }>} */
  const sessions = new Map()
  let loaded = false

  /** @returns {string} */
  const keyOf = (sessionId) => (typeof sessionId === 'string' ? sessionId.trim() : '')

  /** Read the file once; every later call is served from memory. */
  function load() {
    if (loaded) return
    loaded = true
    /** @type {any} */
    let parsed = null
    try {
      parsed = JSON.parse(readFileSync(file, 'utf8'))
    } catch {
      return
    }
    const raw = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed.sessions : null
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return
    const nowMs = resolveShellNowMs(nowOption)
    let dropped = 0
    for (const [sessionId, entry] of Object.entries(raw)) {
      const key = keyOf(sessionId)
      if (key === '') continue
      const normalized = normalizeSessionEntry(entry, nowMs)
      if (normalized === null) {
        dropped += 1
        continue
      }
      sessions.set(key, normalized)
    }
    if (dropped > 0) {
      log('shell-sessions: dropped ' + dropped + ' stale or unreadable entr' + (dropped === 1 ? 'y' : 'ies') + ' from ' + file)
    }
  }

  /**
   * Write every known session atomically. The temp file lives in the same
   * directory so `rename` is a real replace (no cross-volume copy window).
   * @returns {{ ok: boolean, warning: string | null }}
   */
  function persist() {
    /** @type {{ version: number, sessions: Record<string, unknown> }} */
    const payload = { version: SHELL_SESSION_VERSION, sessions: {} }
    for (const [sessionId, entry] of sessions) payload.sessions[sessionId] = entry
    const temp = file + '.' + String(process.pid) + '.' + String(Date.now()) + '.tmp'
    try {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(temp, JSON.stringify(payload, null, 2) + '\n', 'utf8')
      renameSync(temp, file)
      return { ok: true, warning: null }
    } catch (error) {
      log('shell-sessions: cannot write ' + file + ': ' + messageOf(error))
      return {
        ok: false,
        warning: '会话命令行选择已在本次 Host 生效，但没有写入 ' + file + '（' + messageOf(error) + '）；DSH 重启后会丢失',
      }
    }
  }

  /**
   * @param {string | null | undefined} sessionId
   * @returns {{ powershell?: string, bash?: string } | null}
   */
  function sessionOf(sessionId) {
    load()
    const key = keyOf(sessionId)
    if (key === '') return null
    const entry = sessions.get(key)
    if (entry === undefined) return null
    /** @type {{ powershell?: string, bash?: string }} */
    const view = {}
    if (entry.powershell !== undefined) view.powershell = entry.powershell
    if (entry.bash !== undefined) view.bash = entry.bash
    return view
  }

  /**
   * @param {string | null | undefined} sessionId
   * @param {'powershell' | 'bash' | 'cmd'} kind
   * @returns {string | null}
   */
  function choiceOf(sessionId, kind) {
    const view = sessionOf(sessionId)
    if (view === null) return null
    if (kind === 'bash') return view.bash ?? null
    if (kind === 'powershell') return view.powershell ?? null
    return null
  }

  return {
    stateDir,
    path: file,
    session: sessionOf,
    choice: choiceOf,
    /**
     * Store (or replace) one kind's choice for one session.
     * @param {string | null | undefined} sessionId
     * @param {'powershell' | 'bash' | 'cmd'} kind
     * @param {unknown} id
     * @returns {{ ok: boolean, warning: string | null }}
     */
    setChoice(sessionId, kind, id) {
      const key = keyOf(sessionId)
      if (key === '') return { ok: false, warning: '没有会话 id，无法记录会话级命令行选择' }
      const value = storedShellChoice(id)
      if (value === null) return { ok: false, warning: '候选 id 不合法：' + String(id) }
      if (kind !== 'bash' && kind !== 'powershell') return { ok: false, warning: 'cmd 是固定项，没有可保存的会话选择' }
      load()
      const next = { ...(sessions.get(key) ?? {}) }
      next[kind] = value
      next.updatedAt = new Date(resolveShellNowMs(nowOption)).toISOString()
      sessions.set(key, /** @type {any} */ (next))
      return persist()
    },
    /**
     * Clear one kind (or the whole session when `kind` is null).
     * @param {string | null | undefined} sessionId
     * @param {'powershell' | 'bash' | 'cmd' | null} [kind]
     * @returns {{ ok: boolean, removed: boolean, warning: string | null }}
     */
    clearChoices(sessionId, kind = null) {
      const key = keyOf(sessionId)
      if (key === '') return { ok: true, removed: false, warning: null }
      load()
      const current = sessions.get(key)
      if (current === undefined) return { ok: true, removed: false, warning: null }
      if (kind === null || kind === undefined) {
        sessions.delete(key)
        const written = persist()
        return { ok: written.ok, removed: true, warning: written.warning }
      }
      if (kind !== 'bash' && kind !== 'powershell') return { ok: true, removed: false, warning: null }
      if (current[kind] === undefined) return { ok: true, removed: false, warning: null }
      const next = { ...current }
      delete next[kind]
      if (next.powershell === undefined && next.bash === undefined) {
        sessions.delete(key)
      } else {
        next.updatedAt = new Date(resolveShellNowMs(nowOption)).toISOString()
        sessions.set(key, next)
      }
      const written = persist()
      return { ok: written.ok, removed: true, warning: written.warning }
    },
    /** Test/recovery seam: forget memory and read the file again. */
    reload() {
      sessions.clear()
      loaded = false
      load()
    },
  }
}

/**
 * One store per state directory. The tool that writes a choice and the run
 * path that reads it must share memory: two independent caches would make a
 * `pod_shell use` invisible until the next Host restart.
 * @type {Map<string, ReturnType<typeof createShellSessionStore>>}
 */
const shellSessionStores = new Map()

/**
 * @param {string | undefined} stateDir
 * @returns {ReturnType<typeof createShellSessionStore>}
 */
function shellSessionStoreFor(stateDir) {
  const key = typeof stateDir === 'string' && stateDir.trim() !== '' ? resolve(stateDir) : resolvePodStateDir()
  let store = shellSessionStores.get(key)
  if (store === undefined) {
    store = createShellSessionStore({ stateDir: key })
    shellSessionStores.set(key, store)
  }
  return store
}

/** Tests only: forget every cached store (nothing in production calls this). */
export function clearShellSessionStores() {
  shellSessionStores.clear()
}

/**
 * The path the legacy resolver would have produced. Only used when detection
 * gives no candidate at all (an empty/unreadable detection), so a command still
 * has an executable to run and the old behaviour is the floor, never a crash.
 *
 * @param {'powershell' | 'bash' | 'cmd'} kind
 * @param {{ pwshPath?: string, bashPath?: string } | null | undefined} config
 * @returns {string}
 */
function legacyShellPath(kind, config) {
  if (kind === 'bash') return resolveBashPath(config?.bashPath)
  if (kind === 'cmd') {
    const comspec = typeof process.env.ComSpec === 'string' ? process.env.ComSpec.trim() : ''
    return comspec === '' ? 'cmd.exe' : comspec
  }
  return resolvePwshPath(config?.pwshPath)
}

/**
 * Shape one `resolveShellSelection` result as the tools report it.
 * @param {'powershell' | 'bash' | 'cmd'} kind
 * @param {{ candidate?: any, source?: string, fallback?: any } | null} selection
 * @param {{ pwshPath?: string, bashPath?: string } | null | undefined} config
 * @returns {{
 *   kind: 'powershell' | 'bash' | 'cmd',
 *   id: string | null,
 *   path: string,
 *   version: string | null,
 *   source: 'session' | 'settings' | 'auto',
 *   fallback: { from: string, to: string | null, reason: string } | null,
 * }}
 */
function buildAppliedShell(kind, selection, config) {
  const candidate = selection !== null && typeof selection === 'object' ? selection.candidate : null
  const path = typeof candidate?.path === 'string' && candidate.path.trim() !== ''
    ? candidate.path.trim()
    : legacyShellPath(kind, config)
  const source = selection?.source === 'session' || selection?.source === 'settings' ? selection.source : 'auto'
  const rawFallback = selection?.fallback
  return {
    kind,
    id: typeof candidate?.id === 'string' && candidate.id !== '' ? candidate.id : null,
    path,
    version: typeof candidate?.version === 'string' && candidate.version !== '' ? candidate.version : null,
    source,
    fallback: rawFallback === null || typeof rawFallback !== 'object'
      ? null
      : {
          from: String(rawFallback.from ?? ''),
          to: typeof rawFallback.to === 'string' && rawFallback.to !== '' ? rawFallback.to : null,
          reason: String(rawFallback.reason ?? ''),
        },
  }
}

/**
 * The interpreter a `pod_run`/`pod_exec` call will actually execute with.
 *
 * Order (see shells.mjs `resolveShellSelection`): session override → settings
 * default → auto. Detection is the module's, so its 60s version cache is
 * reused and nothing here spawns a shell on its own. Any failure (broken
 * detection, unreadable settings, a vanished path) degrades to the next level
 * and finally to the legacy resolver path — this function never throws, because
 * it sits in front of every command.
 *
 * @param {'powershell' | 'bash' | 'cmd' | string} kind
 * @param {{ sessionId?: string | null } | null} [hint] `policyHint(exec)`.
 * @param {{
 *   stateDir?: string,
 *   config?: { pwshPath?: string, bashPath?: string },
 *   store?: ReturnType<typeof createShellSessionStore>,
 *   detection?: any,
 *   defaults?: { powershell?: string, bash?: string } | string,
 *   sessionChoice?: string | null,
 *   detect?: (options: any) => any,
 *   now?: number | (() => number),
 *   log?: (message: string) => void,
 * }} [deps] test seams and the Host-side context (state dir, configured paths).
 * @returns {{
 *   kind: 'powershell' | 'bash' | 'cmd',
 *   id: string | null,
 *   path: string,
 *   version: string | null,
 *   source: 'session' | 'settings' | 'auto',
 *   fallback: { from: string, to: string | null, reason: string } | null,
 * }}
 */
export function resolveAppliedShell(kind, hint = null, deps = {}) {
  const resolvedKind = kind === 'bash' || kind === 'cmd' ? kind : 'powershell'
  const options = deps !== null && typeof deps === 'object' ? deps : {}
  const config = options.config !== null && typeof options.config === 'object' ? options.config : {}
  const log = typeof options.log === 'function' ? options.log : () => {}
  try {
    const stateDir = typeof options.stateDir === 'string' && options.stateDir.trim() !== ''
      ? options.stateDir
      : resolvePodStateDir()
    const store = options.store ?? shellSessionStoreFor(stateDir)
    const sessionId = typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null
    const sessionChoice = options.sessionChoice !== undefined
      ? options.sessionChoice
      : sessionId === null
        ? null
        : store.choice(sessionId, resolvedKind)
    const defaults = options.defaults !== undefined ? options.defaults : readPodSettings(stateDir).shells
    const detection = options.detection !== undefined
      ? options.detection
      : (typeof options.detect === 'function' ? options.detect : detectShells)({
          config,
          ...(options.now === undefined ? {} : { now: options.now }),
        })
    const selection = resolveShellSelection(resolvedKind, { sessionChoice, defaults, detection })
    return buildAppliedShell(resolvedKind, selection, config)
  } catch (error) {
    log('shell resolution failed for ' + resolvedKind + ': ' + messageOf(error) + '; using the legacy path')
    return {
      kind: resolvedKind,
      id: null,
      path: legacyShellPath(resolvedKind, config),
      version: null,
      source: 'auto',
      fallback: { from: String(kind), to: null, reason: '解析失败：' + messageOf(error) },
    }
  }
}

/** @param {unknown} source */
function shellSourceText(source) {
  return source === 'session' ? '会话覆盖' : source === 'settings' ? '设置默认' : '自动'
}

/**
 * One line describing the interpreter an execution will use. Shared by
 * `pod_run`'s text and `pod_status`, so the two always agree.
 * @param {any} shell
 * @returns {string}
 */
function renderShellLine(shell) {
  const pieces = [
    '命令行：' + String(shell.kind) + ' → ' + String(shell.path),
    '来源：' + shellSourceText(shell.source),
  ]
  if (typeof shell.version === 'string' && shell.version !== '') pieces.push('版本：' + shell.version)
  const fallback = shell.fallback
  if (fallback !== null && typeof fallback === 'object') {
    pieces.push(
      '回落：' + String(fallback.from) + ' → ' + (typeof fallback.to === 'string' && fallback.to !== '' ? fallback.to : '无可用候选') +
        '（' + String(fallback.reason) + '）',
    )
  }
  return '（' + pieces.join('，') + '）'
}

/**
 * A candidate name with the probed version when the label does not already
 * carry it (shells.mjs labels embed major.minor for the system builds).
 * @param {any} candidate
 * @returns {string}
 */
function shellCandidateName(candidate) {
  const path = String(candidate?.path ?? '')
  const label = typeof candidate?.label === 'string' && candidate.label !== '' ? candidate.label : basename(path)
  const version = typeof candidate?.version === 'string' && candidate.version !== '' ? candidate.version : null
  if (version === null) return label
  // shells.mjs labels embed major.minor for the system builds: "Windows
  // PowerShell 5.1" must read "Windows PowerShell 5.1.19041.6456" (the design
  // shows the full build), while labels already carrying the version are kept.
  const short = version.match(/^\d+\.\d+/)
  if (short !== null && label.startsWith('Windows PowerShell ' + short[0])) return 'Windows PowerShell ' + version
  if (label.includes(version)) return label
  return label + ' ' + version
}

/**
 * The `deps` bag `resolveAppliedShell` expects, derived from the plugin config.
 * @param {{ stateDir?: string, pwshPath?: string, bashPath?: string } | null | undefined} settings
 * @param {{ detect?: Function, now?: number | (() => number), store?: any }} [extra]
 * @returns {any}
 */
function shellDepsFromSettings(settings, extra = {}) {
  const value = settings !== null && typeof settings === 'object' ? settings : {}
  const stateDir = typeof value.stateDir === 'string' && value.stateDir.trim() !== '' ? value.stateDir : resolvePodStateDir()
  return {
    stateDir,
    config: { pwshPath: value.pwshPath, bashPath: value.bashPath },
    store: extra.store ?? shellSessionStoreFor(stateDir),
    ...(extra.detect === undefined ? {} : { detect: extra.detect }),
    ...(extra.now === undefined ? {} : { now: extra.now }),
  }
}

/**
 * The access refusal is identical on every layer (Host pre-check, Host
 * post-response assertion, registry-adopted path): say what is wrong and how the
 * deliberate takeover works, without naming the owning session.
 * @param {string} action
 * @param {string} jobId
 */
export function foreignJobError(action, jobId) {
  return new PodError(
    action + ' 拒绝访问 job ' + jobId + '：它属于另一个 DSH 会话（或没有会话归属的历史 job）。' +
      '默认只允许访问本会话的 job；若确认原会话已经销毁、这是需要清理的孤儿 job，请加参数 adopt: true 显式接管。',
    'EFOREIGNJOB',
  )
}

/**
 * Split and validate what `ctx.sandbox.confine()` returned. No prefix is ever
 * synthesised here: a malformed result is a hard error, and the tail is checked
 * against the placeholder so a provider that reorders argv cannot confuse us.
 * @param {any} confined
 * @param {string[]} placeholder
 */
export function parseConfinedArgv(confined, placeholder) {
  const raw = Array.isArray(confined?.argv) ? confined.argv.map((value) => String(value)) : null
  if (raw === null || raw.length < 3) throw new PodError('沙箱服务返回的 argv 不合法（不是数组或过短）', 'EPREFIXINVALID')
  const separator = raw.indexOf('--')
  if (separator < 2) throw new PodError('沙箱服务返回的 argv 里找不到 runner 与目标之间的 `--` 分隔符', 'EPREFIXINVALID')
  const prefix = raw.slice(0, separator)
  const tail = raw.slice(separator + 1)
  if (tail.length !== placeholder.length || tail.some((value, index) => value !== placeholder[index])) {
    throw new PodError('沙箱服务返回的目标段与占位目标不一致，无法安全剥离前缀', 'EPREFIXINVALID')
  }
  const check = validatePrefix(prefix)
  if (!check.ok) throw new PodError('沙箱服务返回的 runner 前缀不合法：' + check.message, check.code)
  return { prefix: check.prefix, program: check.program, args: check.args, profile: check.profile }
}

/**
 * Can this pod be trusted with the new run fields? A `null` version means the
 * pod did not report one at all — also too old to know what `mode` means. The
 * verdict is a pure function so the rule is testable without a live pod.
 *
 * @param {number | null} version the pod's reported `protocolVersion`
 * @returns {{ ok: true, version: number } | { ok: false, code: string, message: string }}
 */
export function checkRunProtocol(version) {
  if (typeof version === 'number' && Number.isFinite(version) && version >= PROTOCOL_VERSION) {
    return { ok: /** @type {const} */ (true), version: Math.trunc(version) }
  }
  return {
    ok: /** @type {const} */ (false),
    code: 'EPROTOCOL',
    message:
      'pod 是旧版本（protocol=' + String(version ?? 'unknown') + ' < ' + PROTOCOL_VERSION + '）：新请求里的 mode/unescorted 会被它忽略，' +
      '命令可能按错误策略执行，因此 fail-closed。请先执行 pod_status action=relaunch 重新拉起 pod，然后重试；本次没有执行任何命令。',
  }
}

/**
 * The danger-full-access "prepared" object: no prefix, no runner, and therefore
 * NO `confine()` call at all. The command is spawned with the pod's own Medium
 * token, which is what "completely unrestricted" means here — the windows-acl
 * runner cannot express it (`--mode danger-full-access` makes it fail with
 * "unknown mode"), so there is no prefix to sign.
 *
 * This deliberately weakens one old invariant: under `workspace-write` a command
 * could never rewrite the ledger, because the ledger lives outside every
 * workspace a confined command can write. With the user's own token the command
 * can write wherever the user can — including the ledger. That is what the user
 * asked for by selecting danger-full-access; the ledger is still kept outside
 * the workspace, but it is no longer tamper-proof against the command itself.
 *
 * @param {{ sessionId?: string | null, workspaceRoot?: string } | null} hint
 * @param {(message: string) => void} log
 */
export function unescortedPolicy(hint, log = () => {}) {
  const workspaceRoot = resolveWorkspaceRoot(hint?.workspaceRoot)
  const sessionId = typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null
  log('policy: unescorted (mode=danger-full-access, 无 runner 前缀) workspace=' + workspaceRoot)
  return {
    unescorted: true,
    prefix: null,
    program: null,
    args: [],
    fingerprint: 'unescorted',
    enforcement: 'none',
    denialSignatures: [],
    runnerFailureRules: 0,
    policy: { mode: 'danger-full-access', workspaceRoot, sessionId },
    policyVariant: 'unescorted',
    workspaceRoot,
    sessionId,
    confinedAt: null,
    profile: {
      program: null,
      runner: null,
      mode: 'danger-full-access',
      workspaceRoot,
      tempDir: null,
      seamManaged: false,
      writeSid: null,
      tempWriteSid: null,
    },
  }
}

/**
 * Ask the sandbox seam for a confined argv and strip the never-executed target,
 * leaving the runner prefix the pod may append to. Session-scoped policy is
 * tried first (its private temp grant mirrors what a confined tool call gets),
 * then the agentless policy (the runner manages its own temp child). Any
 * malformed result is a hard failure — no prefix is ever synthesised.
 *
 * `mode` is the policy this call resolved from the session: only `read-only` and
 * `workspace-write` mint prefixes, and only attempts matching that mode are
 * tried. Quietly retrying with a wider mode would be an unreviewed escalation;
 * retrying with a narrower one would silently deny writes the user allowed.
 *
 * @param {any} sandbox
 * @param {{ sessionId?: string | null, workspaceRoot?: string } | null} hint
 * @param {(message: string) => void} log
 * @param {string} [mode]
 */
export async function derivePrefix(sandbox, hint, log = () => {}, mode = 'workspace-write') {
  const requestedMode = normalizeSandboxMode(mode) ?? 'workspace-write'
  // danger-full-access has no prefix (see `unescortedPolicy`), so it must not
  // even require the sandbox seam to exist.
  if (requestedMode === 'danger-full-access') return unescortedPolicy(hint, log)
  if (sandbox === null || sandbox === undefined || typeof sandbox.confine !== 'function') {
    throw new PodError(
      NO_SANDBOX_MESSAGE + '：ctx.get(\'sandbox\') 为 undefined 或缺少 confine()。受限模式下不会退化成不受限 spawn，因此拒绝签发前缀（danger-full-access 本来就不签发前缀，也不依赖沙箱服务）。',
      'ENOSANDBOX',
    )
  }
  const workspaceRoot = resolveWorkspaceRoot(hint?.workspaceRoot)
  const sessionId = typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null
  const placeholder = [process.execPath, PLACEHOLDER_TARGET]
  /** @type {Array<{ label: string, policy: Record<string, unknown> }>} */
  const attempts = []
  // Only attempts that MATCH this call's mode. A read-only call must never get a
  // workspace-write prefix, and a workspace-write call must never silently fall
  // back to read-only (that would deny writes the user authorized).
  if (sessionId !== null) {
    attempts.push({ label: requestedMode + ' + sessionId', policy: { mode: requestedMode, workspaceRoot, sessionId } })
  }
  attempts.push({ label: requestedMode + ' (agentless)', policy: { mode: requestedMode, workspaceRoot } })
  /** @type {string[]} */
  const failures = []
  /** @type {string | null} */
  let lastCode = null
  for (const attempt of attempts) {
    try {
      const confined = await sandbox.confine(placeholder, attempt.policy)
      const parsed = parseConfinedArgv(confined, placeholder)
      const enforcement = confined?.enforcement === 'full' || confined?.enforcement === 'partial' ? confined.enforcement : 'unknown'
      const prepared = {
        ...parsed,
        fingerprint: fingerprintPrefix(parsed.prefix),
        enforcement,
        denialSignatures: Array.isArray(confined?.denialSignatures) ? confined.denialSignatures.map(String) : [],
        runnerFailureRules: Array.isArray(confined?.runnerFailureRules) ? confined.runnerFailureRules.length : 0,
        policy: { mode: requestedMode, workspaceRoot, sessionId: attempt.policy.sessionId ?? null },
        policyVariant: attempt.label,
        workspaceRoot,
        sessionId,
        confinedAt: new Date().toISOString(),
      }
      log('prefix issued variant=' + attempt.label + ' enforcement=' + enforcement + ' workspace=' + workspaceRoot + ' fingerprint=' + prepared.fingerprint.slice(0, 12))
      return prepared
    } catch (error) {
      lastCode = typeof (/** @type {any} */ (error)?.code) === 'string' ? /** @type {any} */ (error).code : null
      failures.push(attempt.label + ' 失败：' + messageOf(error) + (lastCode === null ? '' : ' (' + lastCode + ')'))
      log('confine failed for ' + attempt.label + ': ' + messageOf(error))
    }
  }
  throw new PodError(
    '沙箱服务无法签发受限 runner 前缀（没有前缀就不会执行任何命令）：' + failures.join('；'),
    lastCode ?? 'ECONFINEFAILED',
  )
}

/**
 * One persistent pipe client. One socket per Host process, opened lazily and
 * reused; a dropped socket is reopened on the next tool call, and an existing
 * pod is always preferred over spawning a replacement.
 *
 * @param {{
 *   pipeName: string,
 *   idleExitMs: number,
 *   ringBytes: number,
 *   outputChunkBytes: number,
 *   stateDir: string,
 *   pwshPath?: string,
 *   bashPath?: string,
 *   allowHandover?: boolean,
 *   log: (message: string) => void,
 *   getSandbox: () => any,
 * }} options
 */
export function createPodClient(options) {
  const { pipeName, idleExitMs, ringBytes, outputChunkBytes, log, getSandbox } = options
  const configuredPwshPath = options.pwshPath
  const configuredBashPath = options.bashPath
  // A pod whose only client is gone may be taken over by the next Host. Turning
  // this off makes that pod unreachable after a DSH restart (jobs keep running,
  // but nobody can read them again); default on, because the alternative is
  // worse and the takeover is logged/visible in status.
  const allowHandover = options.allowHandover !== false
  // Ledger root, resolved once: OUTSIDE every workspace by default, because the
  // managed command runs with a workspace-write grant and could otherwise forge
  // its own meta.json/out.log/exit.json.
  const stateDir = resolveStateDir(options.stateDir)

  /** @type {net.Socket | null} */
  let socket = null
  let socketMode = 'none'
  /**
   * Protocol version the attached pod reported, learned lazily once per
   * connection. The run request now carries `mode`/`unescorted`; a pod that
   * predates them would IGNORE the fields and execute its own default policy —
   * a silent authority mismatch between what the Host approved and what ran, so
   * the run fails closed before sending anything.
   * @type {number | null}
   */
  let podProtocolVersion = null
  /** @type {Map<number, { resolve: (value: any) => void, reject: (error: Error) => void, timer: NodeJS.Timeout }>} */
  const pending = new Map()
  let nextRequestId = 1
  /** @type {Promise<void> | null} */
  let connecting = null
  /** @type {Promise<void> | null} */
  let booting = null
  let everConnected = false
  let spawnAttempts = 0
  let lastSpawnAt = 0
  let blockingErrorSeen = false
  let disposed = false
  /** @type {Record<string, any> | null} */
  let spawnInfo = null
  /**
   * Host-side record of the last launch decision: schtasks | spawn, the task
   * name, and the cached probe outcome. Read by `pod_status` even when this
   * Host reused a pod it did not spawn (then it is null and status says so).
   * @type {{ launcher: string, taskName: string | null, schtasksProbe: string, mode: string, modeSource: string, forced: boolean, warnings: string[], at: string, taskDeleted?: boolean } | null}
   */
  let launcherInfo = null
  /** @type {{ code: number | null, signal: string | null } | null} */
  let podExit = null
  /**
   * Bounded recovery state for a pod that is listening but cannot be
   * authenticated. `pid`/`startedAt` come from the public `identify` op, so a
   * cleanup can cross-check that the pid still names the same process.
   * @type {{ rounds: number, since: number, last: number, recoveries: number, pid: number | null, startedAt: string | null }}
   */
  const podHealth = { rounds: 0, since: 0, last: 0, recoveries: 0, pid: null, startedAt: null }
  /** True once this Host ever had to kill and retry a pod (status diagnostic). */
  let podRecoveryLog = null
  /**
   * The token this Host generation holds for the pod. Memory only — never
   * written to the ledger, config or env. Set when this process spawns the pod,
   * or negotiated through the pod's `handover` op when this process attaches to
   * a pod that an earlier Host spawned.
   * @type {string | null}
   */
  let podToken = null
  /**
   * Set once the attached pod answers `identify` with "unknown op": a pod from
   * before the identity channel exists. The handover then runs without a nonce,
   * which is exactly the pre-attestation behaviour.
   */
  let identityUnsupported = false
  /** The template this Host used when it spawned the pod (diagnostics only). */
  /** @type {import('./shared.mjs').PrefixTemplate | null} */
  let spawnedTemplate = null
  let prepareChain = /** @type {Promise<any>} */ (Promise.resolve())
  /**
   * Host-side half of the session boundary: jobId → owning session id. Filled
   * from `run` responses and every `status` snapshot, so a foreign job is
   * refused before the request leaves this process. It is deliberately
   * memory-only: after a DSH restart the map is empty and the pod's own check
   * (the authoritative one) answers. Legacy jobs and jobs created by an older
   * pod that does not echo `sessionId` are recorded as `null` only when the
   * pod/response explicitly says so; a missing field never erases what this
   * Host already knows.
   * @type {Map<string, string | null>}
   */
  const jobOwners = new Map()
  const MAX_REMEMBERED_JOB_OWNERS = 512

  /**
   * @param {string} jobId
   * @param {unknown} sessionId
   */
  function rememberJobOwner(jobId, sessionId) {
    if (typeof jobId !== 'string' || jobId === '') return
    const owner = typeof sessionId === 'string' && sessionId !== '' ? sessionId : null
    jobOwners.delete(jobId)
    jobOwners.set(jobId, owner)
    while (jobOwners.size > MAX_REMEMBERED_JOB_OWNERS) {
      const oldest = jobOwners.keys().next()
      if (oldest.done === true) break
      jobOwners.delete(oldest.value)
    }
  }

  /**
   * Refuse a foreign job whose owner this Host already knows (before the
   * request is sent). Unknown ownership is left to the pod.
   * @param {string} action
   * @param {string} jobId
   * @param {any} hint
   * @param {boolean} adopt
   */
  function assertKnownJobAccess(action, jobId, hint, adopt) {
    if (adopt === true || !jobOwners.has(jobId)) return
    const access = jobOwnership(jobOwners.get(jobId), hint?.sessionId ?? null, false)
    if (!access.allowed) throw foreignJobError(action, jobId)
  }

  /**
   * Second Host-side assertion on the pod's answer. A current pod reports the
   * job owner in `output`/`kill` responses; an older pod does not, and then the
   * Host falls back to what it already knows (a job it started in this
   * process). If neither knows, the job is unowned history and a real session
   * must adopt it — exactly the legacy rule.
   * @param {string} action
   * @param {string} jobId
   * @param {any} response
   * @param {any} hint
   * @param {boolean} adopt
   */
  function assertResponseJobAccess(action, jobId, response, hint, adopt) {
    if (adopt === true) return
    if (response === null || typeof response !== 'object') return
    const reported = Object.prototype.hasOwnProperty.call(response, 'sessionId')
      ? response.sessionId
      : (jobOwners.has(jobId) ? jobOwners.get(jobId) : null)
    const access = jobOwnership(reported, hint?.sessionId ?? null, false)
    if (!access.allowed) throw foreignJobError(action, jobId)
  }

  function sandboxOrNull() {
    let sandbox
    try {
      sandbox = getSandbox()
    } catch {
      sandbox = undefined
    }
    if (sandbox === null || sandbox === undefined) return null
    if (typeof sandbox.confine !== 'function') return null
    return sandbox
  }

  /** @param {any} task */
  function serialize(task) {
    const run = prepareChain.then(task, task)
    prepareChain = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  /** @param {net.Socket} connected @param {string} mode */
  function attach(connected, mode) {
    if (disposed) {
      connected.destroy()
      return
    }
    const previous = socket
    socket = connected
    socketMode = mode
    // A new socket may be a different pod process: never reuse the old verdict.
    podProtocolVersion = null
    everConnected = true
    if (previous !== null && previous !== connected) {
      // Superseded connection (e.g. the previous attempt was refused as EBUSY).
      try {
        previous.destroy()
      } catch {
        // already gone
      }
    }
    connected.setEncoding('utf8')
    let buffer = ''
    connected.on('data', (chunk) => {
      buffer += chunk
      let newline = buffer.indexOf('\n')
      while (newline >= 0) {
        const line = buffer.slice(0, newline)
        buffer = buffer.slice(newline + 1)
        if (line.trim() !== '') {
          try {
            const message = JSON.parse(line)
            const entry = pending.get(message.id)
            if (message?.error?.code === 'EBADTOKEN') {
              // Our token is dead (the pod was rotated by a later Host, or this
              // is a different pod). Drop the socket so the next connect goes
              // through establishAuth() and renegotiates via handover.
              podToken = null
              if (socket === connected) socket = null
              log('pod rejected this Host token (EBADTOKEN); it will be renegotiated through handover on the next connect')
            } else if (message?.error?.code === 'EBUSY') {
              // The pod still serves the connection we thought was gone. Drop
              // this socket so the next call reconnects instead of reusing it.
              if (socket === connected) socket = null
              log('pod is still busy with a previous connection (EBUSY); this socket is dropped and the next call will reconnect')
            }
            if (entry !== undefined) {
              pending.delete(message.id)
              clearTimeout(entry.timer)
              entry.resolve(message)
            }
          } catch {
            // framing noise is not worth failing a request over
          }
        }
        newline = buffer.indexOf('\n')
      }
    })
    connected.on('error', () => {
      // EPIPE after Host shutdown; surfaced as a close, never fatal.
    })
    connected.on('close', () => {
      // A superseded socket must not reject requests that belong to the socket
      // that replaced it (the pending map is shared, ids are global).
      if (socket !== connected) return
      socket = null
      for (const [id, entry] of pending) {
        pending.delete(id)
        clearTimeout(entry.timer)
        entry.reject(new PodError('pod 连接已关闭，未收到响应', 'ECLOSED'))
      }
    })
    connected.unref()
    log('connected pipe=' + pipeName + ' mode=' + mode)
  }

  /** @param {number} timeoutMs */
  function connectOnce(timeoutMs) {
    return new Promise((resolveConnect, rejectConnect) => {
      const attempt = net.connect(pipeName)
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        attempt.destroy()
        rejectConnect(new PodError('连接 pod 管道超时（' + timeoutMs + 'ms 内未连上）', 'ETIMEDOUT'))
      }, timeoutMs)
      attempt.once('connect', () => {
        if (settled) {
          attempt.destroy()
          return
        }
        settled = true
        clearTimeout(timer)
        resolveConnect(attempt)
      })
      attempt.once('error', (error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        rejectConnect(error)
      })
    })
  }

  /** @param {any} source */
  function notePodIdentity(source) {
    if (source === null || typeof source !== 'object') return
    const pid = Number(source.podPid)
    if (Number.isInteger(pid) && pid > 0) podHealth.pid = pid
    if (typeof source.podStartedAt === 'string' && source.podStartedAt !== '') podHealth.startedAt = source.podStartedAt
  }

  function resetPodHealth() {
    podHealth.rounds = 0
    podHealth.since = 0
    podHealth.last = 0
    podHealth.recoveries = 0
  }

  /**
   * One request on an already-connected socket, without touching the global
   * client state. Used only for the public `identify` probe during recovery.
   * @param {net.Socket} active @param {string} op @param {Record<string, unknown>} payload @param {number} timeoutMs
   */
  function requestOneShot(active, op, payload, timeoutMs) {
    return new Promise((resolveOne, rejectOne) => {
      let settled = false
      /** @type {string} */
      let buffer = ''
      /** @param {Error | null} error @param {any} [value] */
      const finish = (error, value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        active.off('data', onData)
        active.off('error', onError)
        active.off('close', onClose)
        if (error !== null) rejectOne(error)
        else resolveOne(value)
      }
      const onData = (/** @type {Buffer | string} */ chunk) => {
        buffer += String(chunk)
        const newline = buffer.indexOf('\n')
        if (newline < 0) return
        try {
          finish(null, JSON.parse(buffer.slice(0, newline)))
        } catch (error) {
          finish(new PodError('identify 返回非法 JSON：' + messageOf(error), 'EBADJSON'))
        }
      }
      const onError = (/** @type {any} */ error) => finish(error instanceof Error ? error : new PodError(messageOf(error)))
      const onClose = () => finish(new PodError('identify 连接已关闭', 'ECLOSED'))
      const timer = setTimeout(() => finish(new PodError('identify 超时', 'ETIMEDOUT')), timeoutMs)
      active.setEncoding('utf8')
      active.on('data', onData)
      active.on('error', onError)
      active.on('close', onClose)
      try {
        active.write(JSON.stringify({ ...payload, op, id: 'recover' }) + '\n')
      } catch (error) {
        finish(new PodError('identify 写入失败：' + messageOf(error), 'EWRITE'))
      }
    })
  }

  /**
   * Ask the live pipe who it is, on a fresh connection. The pod serves exactly
   * one client, so any stale socket is dropped first. `identify` needs no token
   * by design, which is what makes this usable for a stuck bootstrap pod.
   * @returns {Promise<any | null>}
   */
  async function identifyFresh() {
    const stale = socket
    socket = null
    if (stale !== null) {
      try {
        stale.destroy()
      } catch {
        // already gone
      }
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      /** @type {net.Socket | null} */
      let probe = null
      try {
        probe = await connectOnce(800)
        const response = await requestOneShot(probe, 'identify', {}, 800)
        if (response?.ok === true) return response
      } catch {
        // The pod may still be tearing down the previous client; retry once.
      } finally {
        try {
          probe?.destroy()
        } catch {
          // ignore
        }
      }
      await sleep(200)
    }
    return null
  }

  /**
   * Bounded self-heal for a pod that answers on the pipe but cannot be
   * authenticated (typically a bootstrap pod whose handover keeps failing).
   * Kills at most ONE process per incident: two failed rounds or 8s, plus a
   * fresh `identify` that must name the same pid/startedAt we recorded.
   * @param {string} trigger
   * @param {unknown} cause
   * @returns {Promise<number | null>} killed pid, or null when nothing was killed
   */
  async function recoverStuckPod(trigger, cause) {
    const causeCode = String(/** @type {any} */ (cause)?.causeCode ?? /** @type {any} */ (cause)?.code ?? '')
    if (causeCode === 'EBUSY' || causeCode === 'EALREADY' || causeCode === 'EBADTOKEN' || causeCode === 'EHANDOVERDISABLED') {
      // Another live Host owns/owned the pod (busy, rotated token, or handover
      // disabled). That is not a zombie; killing would drop someone else's jobs.
      log('recover: 失败原因是另一个 Host 的归属/策略（' + causeCode + '），不杀不重试')
      return null
    }
    const now = Date.now()
    // Two failures hours apart are not "one incident": restart the window.
    if (podHealth.last !== 0 && now - podHealth.last > 60_000) resetPodHealth()
    if (podHealth.since === 0) podHealth.since = now
    podHealth.last = now
    podHealth.rounds += 1
    const elapsedMs = now - podHealth.since
    if (!shouldRecoverUnresponsivePod({ rounds: podHealth.rounds, elapsedMs, recoveries: podHealth.recoveries })) {
      log(
        'recover: unresponsive pod round=' + String(podHealth.rounds) + ' elapsed=' + String(elapsedMs) +
        'ms（未达清理阈值，trigger=' + trigger + '）',
      )
      return null
    }
    const info = await identifyFresh()
    if (info === null) {
      log('recover: identify 不可用，无法核对 pid/startedAt；不盲杀（trigger=' + trigger + '）')
      return null
    }
    const pid = Number(info.podPid)
    if (!Number.isInteger(pid) || pid <= 0 || pid === process.pid) {
      log('recover: identify 返回的 pid 不可用（' + String(info.podPid) + '）；不杀')
      return null
    }
    if (podHealth.pid !== null && podHealth.pid !== pid) {
      log('recover: pid 与记录不一致（' + String(podHealth.pid) + ' vs ' + String(pid) + '）；不杀')
      return null
    }
    if (podHealth.startedAt !== null && typeof info.podStartedAt === 'string' && info.podStartedAt !== podHealth.startedAt) {
      log('recover: podStartedAt 与记录不一致（pid 复用？' + String(info.podStartedAt) + ' vs ' + String(podHealth.startedAt) + '）；不杀')
      return null
    }
    let alive = true
    try {
      process.kill(pid, 0)
    } catch (error) {
      const code = /** @type {any} */ (error)?.code
      alive = code !== 'ESRCH'
      if (!alive) {
        log('recover: pid=' + String(pid) + ' 已不存在（ESRCH），按已死处理')
        podHealth.pid = null
        return null
      }
    }
    if (!alive) return null
    try {
      process.kill(pid)
    } catch (error) {
      log('recover: 结束 pid=' + String(pid) + ' 失败：' + messageOf(error))
      return null
    }
    podHealth.recoveries += 1
    podHealth.rounds = 0
    podHealth.since = 0
    podRecoveryLog = {
      at: new Date().toISOString(),
      pid,
      trigger,
      elapsedMs,
      cause: messageOf(cause),
    }
    log(
      'recover: killed unresponsive pod pid=' + String(pid) + ' after ' + String(elapsedMs) + 'ms' +
      '（trigger=' + trigger + '，本 incident 最多清理 1 次）',
    )
    // Drop every Host-side trace so the retry starts from a clean connect.
    const oldSocket = socket
    socket = null
    socketMode = 'none'
    if (oldSocket !== null) {
      try {
        oldSocket.destroy()
      } catch {
        // already gone
      }
    }
    podToken = null
    spawnAttempts = 0
    lastSpawnAt = 0
    blockingErrorSeen = false
    podExit = null
    const deadline = Date.now() + 5000
    while (Date.now() < deadline) {
      /** @type {any} */
      let probe = null
      try {
        probe = await connectOnce(300)
      } catch (error) {
        probe = error
      }
      if (probe instanceof Error) {
        if (/** @type {any} */ (probe).code === 'ENOENT') return pid
      } else {
        try {
          probe.destroy()
        } catch {
          // ignore
        }
      }
      await sleep(100)
    }
    log('recover: pid=' + String(pid) + ' 已结束但管道 5s 内仍可连接')
    return pid
  }

  /**
   * Prove this Host's process identity to the pod over its loopback channel.
   *
   * The pipe cannot identify its peer: Node exposes no Win32 handle for a pipe
   * socket (`_handle.fd` is -1 for both the listener and an accepted
   * connection), so `GetNamedPipeClientProcessId` is not reachable from the pod.
   * The pod therefore runs a second, loopback-only listener whose only job is to
   * name the connecting process (Windows maps a TCP 4-tuple to the owning pid).
   * We ask for its port over the pipe, connect, and hand over a nonce that the
   * pod redeems when it sees `handover`.
   *
   * The nonce is not a secret and proves nothing by itself: it only binds *this*
   * pipe connection to the process the OS attributed the TCP connection to. That
   * is what makes the pod able to say "the DSH Host asked" instead of "something
   * asked".
   *
   * Best effort by design: an older pod has no identity channel, and the
   * handover then proceeds exactly as before.
   *
   * @returns {Promise<string | null>}
   */
  async function attestOnce() {
    if (identityUnsupported) return null
    /** @type {any} */
    let info = null
    try {
      info = await requestSend('identify', {})
    } catch (error) {
      const code = String(/** @type {any} */ (error)?.code ?? '')
      // A pod from before this feature answers `identify` with an auth refusal
      // and closes the socket; retrying it on every handover attempt would turn
      // one stale pod into an endless reconnect loop. Remember and move on.
      if (code === 'ECLOSED' || code === 'ECONNRESET' || code === 'ENOTCONNECTED' || code === 'EPIPE') identityUnsupported = true
      log('identify 失败（pod 可能没有身份通道）：' + messageOf(error))
      return null
    }
    // Public identity facts: recovery cross-checks these before killing a pid.
    notePodIdentity(info)
    if (info?.ok !== true) {
      if (String(info?.error?.code ?? '') === 'EBADOP') identityUnsupported = true
      log('pod 不提供身份通道（' + String(info?.error?.code ?? 'unknown') + '）；本次 handover 不带 nonce')
      return null
    }
    const port = info?.identityChannel?.port
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      log('pod 未提供身份通道端口（attestationMode=' + String(info?.attestationMode) + '）')
      return null
    }
    const nonce = randomBytes(16).toString('hex')
    /** @type {any} */
    const verdict = await new Promise((resolveProbe) => {
      /** @type {import('node:net').Socket | null} */
      let probe = null
      let settled = false
      /** @param {any} value */
      const finish = (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        try {
          probe?.destroy()
        } catch {
          // already gone
        }
        resolveProbe(value)
      }
      const timer = setTimeout(() => finish({ ok: false, code: 'ETIMEDOUT' }), ATTEST_TIMEOUT_MS)
      timer.unref?.()
      try {
        probe = net.connect({ host: '127.0.0.1', port })
      } catch (error) {
        finish({ ok: false, code: 'ECONNECT', message: messageOf(error) })
        return
      }
      /** @type {string} */
      let buffer = ''
      probe.setEncoding('utf8')
      probe.on('connect', () => {
        try {
          probe?.write(JSON.stringify({ op: 'attest', nonce }) + '\n')
        } catch (error) {
          finish({ ok: false, code: 'EWRITE', message: messageOf(error) })
        }
      })
      probe.on('data', (chunk) => {
        buffer += chunk
        const newline = buffer.indexOf('\n')
        if (newline < 0) return
        try {
          finish(JSON.parse(buffer.slice(0, newline)))
        } catch (error) {
          finish({ ok: false, code: 'EBADJSON', message: messageOf(error) })
        }
      })
      probe.on('error', (error) => finish({ ok: false, code: /** @type {any} */ (error)?.code ?? 'EIDENTITY', message: messageOf(error) }))
      probe.on('close', () => finish({ ok: false, code: 'ECLOSED' }))
    })
    if (verdict?.ok !== true) {
      log('身份通道探测失败：' + String(verdict?.code) + ' ' + String(verdict?.message ?? ''))
      return null
    }
    if (verdict.allowed !== true) {
      log(
        '身份通道判定本 Host 不满足 pod 的策略（failed=' + String((verdict.failed ?? []).join(',')) +
        '）；handover 仍会带上 nonce，由 pod 决定是否放行',
      )
    } else {
      log('身份通道已确认本 Host：pid=' + String(verdict.pid) + '（nonce 交给 pod）')
    }
    return nonce
  }

  /**
   * Make sure this Host generation can talk to the pod it is attached to.
   *
   * A pod spawned by THIS process already received its token over stdin. A pod
   * that survived a DSH restart was spawned by a previous process, and its token
   * only ever existed in that process's memory — so the new Host claims the
   * orphaned pod with the `handover` op, which rebinds the token to a fresh one
   * (memory only, logged by both sides and visible in `pod_status`). While the
   * previous Host is alive its connection is still open, so single-client
   * rejects the claim with EBUSY instead of letting a second Host steal the pod.
   *
   * @param {string} mode
   */
  async function establishAuth(mode) {
    if (podToken !== null) return
    const token = generatePodToken()
    const deadline = Date.now() + 5000
    /** @type {any} */
    let lastError = null
    // One identity proof for the whole retry loop: the nonce is single-use, so a
    // retry after EBUSY must ask for a fresh one rather than replay a spent one.
    let nonce = null
    for (;;) {
      if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
      /** @type {any} */
      let response = null
      try {
        if (nonce === null) nonce = await attestOnce()
        response = await requestSend('handover', { newToken: token, reason: 'host-boot ' + mode + ' boot=' + HOST_BOOT_ID, nonce })
      } catch (error) {
        lastError = error
      }
      if (response?.ok === true) {
        podToken = token
        log(
          'pod handover accepted: token rotated (mode=' + mode + ', count=' +
          String(response?.auth?.handoverCount ?? '?') + ', tokenFp=' + String(tokenFingerprint(token)) +
          ', attest=' + (nonce === null ? 'none' : 'nonce'),
        )
        return
      }
      const code = String(response?.error?.code ?? /** @type {any} */ (lastError)?.code ?? '')
      const message = String(response?.error?.message ?? messageOf(lastError))
      const retryable = code === 'EBUSY' || code === 'ECLOSED' || code === 'ECONNRESET' || code === 'EPIPE' || code === 'ENOTCONNECTED'
      if (retryable && Date.now() < deadline) {
        await sleep(200)
        nonce = null
        try {
          const fresh = await connectOnce(CONNECT_TIMEOUT_MS)
          attach(fresh, mode)
        } catch (error) {
          lastError = error
        }
        continue
      }
      // Leave no half-usable socket behind: the next call must retry from a
      // clean connect instead of talking on an unauthenticated connection.
      if (socket !== null) {
        try {
          socket.destroy()
        } catch {
          // already gone
        }
        socket = null
      }
      const authError = new PodError(
        '无法接管仍然存活的 pod-core（' + (code === '' ? 'EPODAUTH' : code) + '）：' + message +
        '。pod 的 token 只在上一代 Host 的内存里；接管要求它空闲（单客户端）。' +
        '若另一个 DSH 正在使用同一个 pod，请先退出那个 DSH。',
        'EPODAUTH',
      )
      // Recovery must not kill a pod another live Host is holding: the
      // underlying code (EBUSY) is the only honest signal for that.
      /** @type {any} */ (authError).causeCode = code === '' ? 'EPODAUTH' : code
      throw authError
    }
  }

  /**
   * Derive ONE fresh prefix for one `pod_run`. This deliberately happens per
   * call: the prefix carries a revocable session/workspace temp SID and its
   * policy workspaceRoot comes from the calling session's cwd, so neither can be
   * cached across calls or across a Host restart.
   * @param {any} hint
   * @param {string} [mode] the mode this call resolved (danger-full-access needs
   *   no sandbox at all, so it must not require the seam to exist)
   */
  async function deriveCallPrefix(hint, mode = 'workspace-write') {
    if (normalizeSandboxMode(mode) === 'danger-full-access') return unescortedPolicy(hint, log)
    const sandbox = sandboxOrNull()
    if (sandbox === null) {
      throw new PodError(
        NO_SANDBOX_MESSAGE + '：ctx.get(\'sandbox\') 为 undefined 或缺少 confine()。受限模式下不会退化成不受限 spawn，因此拒绝签发前缀（danger-full-access 本来就不签发前缀，也不依赖沙箱服务）。',
        'ENOSANDBOX',
      )
    }
    return await derivePrefix(sandbox, hint, log, mode)
  }

  /**
   * The pinned shape template for one pod instance: program + runner path inside
   * the DSH install tree + mode + workspace root. It carries no SID and no temp
   * path, so it stays valid across Host restarts. Sanity-checked with the same
   * validator the pod uses.
   * @param {any} prepared
   * @returns {import('./shared.mjs').PrefixTemplate}
   */
  function buildTemplate(prepared) {
    if (prepared?.unescorted === true) {
      // Internal invariant: the spawn path must hand over a CONFINED prefix,
      // because a template pins a runner path — which a danger-full-access call
      // does not have. Reaching this means the caller skipped that rule.
      throw new PodError('内部错误：不能从无前缀（danger-full-access）调用构造形态校验模板', 'ETEMPLATEUNESCORTED')
    }
    const raw = {
      program: prepared.program,
      runnerPath: prepared.prefix[1],
      // Shape, not authority: the same runner serves read-only and
      // workspace-write, and the mode is re-checked per call from the request.
      modes: [...CONFINED_MODES],
      workspaceRoot: prepared.profile.workspaceRoot,
      enforcement: prepared.enforcement === 'full' || prepared.enforcement === 'partial' ? prepared.enforcement : null,
    }
    const check = validateTemplate(raw)
    if (!check.ok) throw new PodError('Host 无法从 confine 结果构造合法的形态校验模板：' + check.message, check.code)
    return check.template
  }

  /**
   * Ask the launcher layer how this pod should be started.
   *
   * The decision is a pure function of `<dataRoot>/launcher.json` (auto /
   * direct / schtasks), the cached `schtasks` probe, and whether the on-disk
   * pod can bootstrap without stdin. `direct` must not even probe: it is the
   * rollback rope for a Host whose Task Scheduler path misbehaves.
   * @param {string} dataRoot
   */
  async function chooseLauncher(dataRoot) {
    const config = readLauncherMode(dataRoot)
    /** @type {any} */
    let probe = null
    /** @type {any} */
    let capability = null
    if (config.mode !== 'direct') {
      try {
        probe = await probeSchtasks({ timeoutMs: SCHTASKS_TIMEOUT_MS, log })
      } catch (error) {
        probe = { status: 'error', ok: false, stderr: messageOf(error), at: new Date().toISOString() }
      }
      capability = podSupportsStdinlessBootstrap({ podScript: POD_PATH })
      if (allowHandover === false) {
        // A bootstrap pod has no token, so it can only be claimed by handover.
        // With handover disabled it would be born unclaimable: stay direct.
        capability = { ok: false, reason: 'allowHandover=false：bootstrap pod 无法被认领' }
      }
    }
    return planLauncher({ config, probe, capability, dataRoot })
  }

  /**
   * Record HOW the pod was (or was meant to be) started. `pod_status` reads
   * this; a pod reused from a previous Host has no entry and status says so
   * rather than guessing.
   * @param {{ launch: any, prepared: any, template: any, reason: string, workspaceRoot: string, dataRoot: string, token: string | null, podPid: number | null }} input
   */
  function rememberLauncher(input) {
    const { launch, prepared, template, reason, workspaceRoot, dataRoot, token, podPid } = input
    const warnings = Array.isArray(launch.warnings) ? launch.warnings.map(String) : []
    spawnedTemplate = template
    spawnInfo = {
      spawnedAt: new Date().toISOString(),
      reason,
      podPid,
      launcher: launch.launcher,
      taskName: launch.taskName ?? null,
      schtasksProbe: launch.probe?.status ?? 'unknown',
      launcherMode: launch.mode ?? 'auto',
      launcherModeSource: launch.modeSource ?? 'default',
      launcherForced: launch.forced === true,
      launchWarnings: warnings,
      template,
      templateView: describeTemplate(template),
      enforcement: template.enforcement,
      probePrefixFingerprint: prepared.fingerprint,
      policyVariant: prepared.policyVariant,
      policy: prepared.policy,
      workspaceRoot,
      dataRoot,
      auth: {
        mode: 'token',
        tokenSource: launch.launcher === 'schtasks' ? 'bootstrap' : 'spawn-stdin',
        tokenFingerprint: token === null ? null : tokenFingerprint(token),
        handoverAllowed: allowHandover !== false,
      },
      get podExit() {
        return podExit
      },
    }
    launcherInfo = {
      launcher: launch.launcher,
      taskName: launch.taskName ?? null,
      schtasksProbe: launch.probe?.status ?? 'unknown',
      mode: launch.mode ?? 'auto',
      modeSource: launch.modeSource ?? 'default',
      forced: launch.forced === true,
      warnings,
      at: spawnInfo.spawnedAt,
      taskDeleted: false,
    }
    return spawnInfo
  }

  /**
   * Start the pod through the configured launcher: Task Scheduler when it is
   * available AND the pod can bootstrap without stdin, otherwise the detached
   * spawn (which is also the bounded fallback when schtasks cannot start it).
   * The pod receives only the pinned template — never a prefix (a spawn-time
   * prefix would be stale garbage after the next restart).
   * @param {any} prepared
   * @param {string} reason
   * @param {{ forceDirect?: boolean, warnings?: string[] }} [options]
   */
  function launchPod(prepared, reason, options = {}) {
    return (async () => {
      const template = buildTemplate(prepared)
      const workspaceRoot = prepared.profile.workspaceRoot
      // Fail closed rather than ever placing the ledger inside the policy
      // workspace: a workspace-write command must not be able to rewrite the
      // record of what it did.
      if (isInsideDirectory(workspaceRoot, stateDir)) {
        throw new PodError(
          '账本目录（stateDir）不能位于 workspace 内：' + stateDir + ' ⊂ ' + workspaceRoot +
          '。被托管命令对 workspace 有写权限，放在里面等于让它给自己出无罪证明。' +
          '请把 stateDir 指到工作区之外（默认 %LOCALAPPDATA%\\dsh-escape-pod-core）。',
          'ESTATEINSIDEWORKSPACE',
        )
      }
      const dataRoot = stateDir
      const args = [
        POD_PATH,
        '--serve',
        '--pipe',
        pipeName,
        '--workspace',
        workspaceRoot,
        '--data-root',
        dataRoot,
        '--idle-ms',
        String(idleExitMs),
        '--ring-bytes',
        String(ringBytes),
        '--output-chunk-bytes',
        String(outputChunkBytes),
        // base64url survives cmd.exe (the schtasks path) byte-for-byte: no
        // quotes, spaces or `& | < > ^ %` to be re-tokenized. The pod prefers
        // this over --template-json, which remains for old callers.
        '--template-b64',
        Buffer.from(JSON.stringify(template), 'utf8').toString('base64url'),
      ]

      const env = { ...process.env }
      if (process.versions.electron !== undefined) env.ELECTRON_RUN_AS_NODE = '1'
      for (const key of Object.keys(env)) if (key.includes('SUBPROCESS_CONTROL')) delete env[key]

      // Handover is a policy switch, not a secret: `--no-handover` makes the pod
      // refuse to be taken over by a later Host (it then becomes unusable after
      // a DSH restart — the honest trade-off of a memory-only token).
      const token = generatePodToken()
      if (allowHandover === false) args.push('--no-handover')

      podExit = null
      /** @type {any} */
      let choice
      if (options.forceDirect === true) {
        const config = readLauncherMode(dataRoot)
        choice = {
          launcher: 'spawn',
          mode: config.mode,
          modeSource: config.source,
          forced: false,
          probe: await probeSchtasks({ timeoutMs: SCHTASKS_TIMEOUT_MS, log }),
          capability: podSupportsStdinlessBootstrap({ podScript: POD_PATH }),
          taskName: null,
          warnings: Array.isArray(options.warnings) && options.warnings.length > 0
            ? options.warnings.map(String)
            : ['已强制使用 detached spawn'],
        }
      } else {
        choice = await chooseLauncher(dataRoot)
      }
      for (const warning of choice.warnings ?? []) log('launcher: ' + String(warning))

      if (choice.launcher === 'schtasks') {
        // Only reachable when pod.mjs advertises stdin-free bootstrap. No stdin
        // token exists on this path; this Host claims the pod through the
        // identity-channel handover (establishAuth) instead.
        // Never mutate the direct-spawn argv: the fallback below must not carry
        // bootstrap-only flags into a pod that starts from stdin.
        const schtasksArgs = [...args, '--bootstrap-handover', '--handover-grace-ms', '0']
        // A previous generation's token is dead with its process; leaving it
        // non-null would make establishAuth() skip the handover this path
        // depends on.
        podToken = null
        // Deleting a stale registration is safe HERE and only here: the caller
        // reached launchPod because no pod answered on the pipe, and doing it
        // earlier would race a /Create+/Run whose start is still queued.
        const removed = await deleteTask(choice.taskName, { timeoutMs: SCHTASKS_TIMEOUT_MS, log })
        const warnings = [...(choice.warnings ?? []), ...(removed.warnings ?? [])]
        /** @type {any} */
        let launched
        try {
          launched = await launchViaSchtasks({
            nodeExe: process.execPath,
            podScript: POD_PATH,
            podArgs: schtasksArgs.slice(1),
            env,
            dataRoot,
            taskName: choice.taskName,
            timeoutMs: SCHTASKS_TIMEOUT_MS,
            log,
          })
        } catch (error) {
          // launchViaSchtasks reports failures instead of throwing; this is the
          // last line of defence so a launcher bug degrades to direct spawn
          // instead of taking every pod_* tool down with it.
          launched = { ok: false, step: 'launcher-error', stderr: messageOf(error), warnings: [] }
        }
        warnings.push(...(launched.warnings ?? []))
        if (launched.ok !== false) {
          rememberLauncher({
            launch: {
              ...launched,
              probe: choice.probe,
              mode: choice.mode,
              modeSource: choice.modeSource,
              forced: choice.forced === true,
            },
            prepared,
            template,
            reason,
            workspaceRoot,
            dataRoot,
            token: null,
            podPid: null,
          })
          log(
            'pod launch=schtasks task=' + String(choice.taskName) + ' dataRoot=' + dataRoot +
            ' workspace=' + workspaceRoot + ' probe=' + String(choice.probe?.status ?? 'unknown'),
          )
          return {
            launcher: 'schtasks',
            taskName: choice.taskName,
            probe: choice.probe,
            mode: choice.mode,
            modeSource: choice.modeSource,
            forced: choice.forced === true,
            warnings,
            ok: true,
          }
        }
        if (choice.forced === true) {
          const detail =
            'schtasks 启动失败（' + String(launched.step) + '）：' + String(launched.stderr ?? launched.error ?? 'unknown') +
            '。launcher.json 指定 schtasks（强制模式），不回落 detached spawn。'
          log(detail)
          throw new PodError(detail, 'ESCHTASKSFAILED')
        }
        log(
          'schtasks launch failed at ' + String(launched.step) + ': ' +
          String(launched.stderr ?? launched.error ?? 'unknown') + '; falling back to detached spawn',
        )
        choice = {
          launcher: 'spawn',
          mode: choice.mode,
          modeSource: choice.modeSource,
          forced: false,
          probe: choice.probe,
          capability: choice.capability,
          taskName: null,
          warnings: [
            ...warnings,
            'schtasks 启动失败（' + String(launched.step) + '），已回落 detached spawn：' +
              String(launched.stderr ?? launched.error ?? 'unknown'),
          ],
        }
        for (const warning of choice.warnings) log('launcher: ' + String(warning))
      }
      // stdin is the ONLY place the spawn token is written: an argv secret is
      // visible in the process list, and the ledger/config must never contain it.
      // stdout/stderr stay 'ignore' (a detached pod must not hold a DSH pipe).
      const child = launchDirect({ nodeExe: process.execPath, podScript: POD_PATH, podArgs: args.slice(1), env })
      if (typeof child.pid !== 'number') throw new PodError('spawn pod-core 失败：没有拿到 pid', 'ESPAWNFAILED')
      podToken = token
      try {
        if (child.stdin !== null && child.stdin !== undefined) {
          child.stdin.on('error', () => {
            // EPIPE here means the pod died before reading its token; the exit
            // code (4 = token missing) is reported by waitForPod.
          })
          // One line, then close the write end. The pod reads the first line and
          // must survive the EOF that follows — that is the normal steady state.
          child.stdin.end(token + '\n')
        }
      } catch (error) {
        log('pod token write failed: ' + messageOf(error))
      }
      child.on('error', (error) => {
        log('pod spawn error: ' + messageOf(error))
      })
      child.on('exit', (code, signal) => {
        podExit = { code: typeof code === 'number' ? code : null, signal: signal ?? null }
        log('pod exited pid=' + String(child.pid) + ' code=' + String(code) + ' signal=' + String(signal))
      })
      child.unref()

      rememberLauncher({
        launch: { ...choice, launcher: 'spawn', taskName: null },
        prepared,
        template,
        reason,
        workspaceRoot,
        dataRoot,
        token,
        podPid: child.pid,
      })
      log(
        'pod spawned pid=' + String(child.pid) + ' dataRoot=' + dataRoot +
        ' template.runner=' + template.runnerPath + ' workspace=' + template.workspaceRoot +
        ' auth=token tokenFp=' + String(tokenFingerprint(token)),
      )
      return {
        launcher: 'spawn',
        taskName: null,
        probe: choice.probe,
        mode: choice.mode,
        modeSource: choice.modeSource,
        forced: false,
        warnings: choice.warnings ?? [],
        ok: true,
      }
    })()
  }

  /** @param {number} budgetMs */
  async function waitForPod(budgetMs) {
    const deadline = Date.now() + budgetMs
    /** @type {any} */
    let lastError = null
    while (Date.now() < deadline) {
      if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
      if (podExit !== null && podExit.code !== null && podExit.code !== 0) break
      try {
        return await connectOnce(Math.min(1000, Math.max(250, deadline - Date.now())))
      } catch (error) {
        lastError = error
        await sleep(SPAWN_POLL_INTERVAL_MS)
      }
    }
    const exitText = podExit === null
      ? (spawnInfo !== null && spawnInfo.launcher === 'schtasks'
        ? 'schtasks 拉起的进程没有可观测的本地 pid（task=' + String(spawnInfo.taskName) + '；日志见 <dataRoot>/pod.log）'
        : 'pod 进程仍在运行')
      : 'pod 已退出 code=' + String(podExit.code) + ' signal=' + String(podExit.signal) +
        (podExit.code === 3 ? '（3 = 启动参数/账本目录不合法，命令从未运行）' : '') +
        (podExit.code === 4 ? '（4 = 没从 stdin 读到 spawn 期 token，pod 拒绝在无鉴权状态下监听；Host 与 pod 版本可能不配对）' : '')
    const connectText = lastError === null ? 'pod 提前失败，尚未尝试连接' : messageOf(lastError)
    throw new PodError('已 spawn pod-core，但 ' + budgetMs + 'ms 内连不上管道：' + connectText + '；' + exitText, 'ESPAWNTIMEOUT')
  }

  /** @param {any} hint @param {any} [prepared] */
  async function connectAndMaybeSpawn(hint, prepared) {
    if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
    /** @type {net.Socket | null} */
    let connected = null
    try {
      connected = await connectOnce(CONNECT_TIMEOUT_MS)
    } catch (error) {
      const code = /** @type {any} */ (error)?.code
      if (code !== 'ENOENT') {
        // A pod may be holding the pipe while refusing to serve (the classic
        // bootstrap-handover deadlock). Bounded: 2 rounds / 8s, one kill, one
        // retry; anything past that propagates.
        const killedPid = await recoverStuckPod('connect-' + String(code ?? 'error'), error)
        if (killedPid !== null) {
          try {
            await connectAndMaybeSpawn(hint, prepared)
            return
          } catch (retryError) {
            throw new PodError(
              'pod 无响应已被清理（pid=' + String(killedPid) + '），重试仍失败：' + messageOf(retryError),
              'EPODSTUCKRECOVERED',
            )
          }
        }
        blockingErrorSeen = true
        throw new PodError('连接 pod 管道失败：' + messageOf(error) + '（' + String(code ?? 'ECONNECT') + '）', typeof code === 'string' ? code : 'ECONNECT')
      }
    }
    if (connected !== null) {
      const mode = everConnected ? 'reconnected' : 'reused'
      attach(connected, mode)
      try {
        await establishAuth(mode)
      } catch (error) {
        const killedPid = await recoverStuckPod('auth', error)
        if (killedPid !== null) {
          try {
            await connectAndMaybeSpawn(hint, prepared)
            return
          } catch (retryError) {
            throw new PodError(
              'pod 无响应已被清理（pid=' + String(killedPid) + '），重试仍失败：' + messageOf(retryError),
              'EPODSTUCKRECOVERED',
            )
          }
        }
        throw error
      }
      resetPodHealth()
      return
    }
    if (blockingErrorSeen) {
      throw new PodError('此前观察到 pod 不可达（连接超时或被拒绝），为避免覆盖可能仍在运行的 pod，本次不再启动新的 pod', 'ESPAWNREFUSED')
    }
    if (spawnAttempts >= MAX_SPAWN_ATTEMPTS) {
      throw new PodError('本次 Host 已尝试启动 pod-core ' + spawnAttempts + ' 次仍无法连接，不再重复启动', 'ESPAWNEXHAUSTED')
    }
    const waited = Date.now() - lastSpawnAt
    if (lastSpawnAt !== 0 && waited < SPAWN_COOLDOWN_MS) await sleep(SPAWN_COOLDOWN_MS - waited)
    if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
    const mode = everConnected ? 'reborn' : 'spawned'
    lastSpawnAt = Date.now()
    // Spawning needs a template, and a template can only come from a fresh
    // per-call confine result. A run that already derived one passes it in; a
    // read-only tool (status/output/kill) derives one just for the template.
    // An UNSECORTED (danger-full-access) run has no prefix to hand over, so the
    // template is derived here: it only pins the shape, never the authority.
    const effective = prepared !== null && prepared !== undefined && prepared.unescorted !== true
      ? prepared
      : await deriveCallPrefix(hint)
    const launched = await launchPod(effective, mode)
    spawnAttempts += 1
    /** @type {net.Socket} */
    let spawned
    try {
      spawned = await waitForPod(SPAWN_CONNECT_BUDGET_MS)
    } catch (error) {
      if (launched?.launcher !== 'schtasks') throw error
      if (launched.forced === true) {
        // launcher.json says schtasks: a fallback would hide the very failure
        // the operator asked to diagnose.
        const cleanup = await deleteTask(launched.taskName, { timeoutMs: SCHTASKS_TIMEOUT_MS, log })
        for (const warning of cleanup.warnings ?? []) log('launcher cleanup: ' + String(warning))
        throw new PodError(
          'schtasks 拉起的 pod 在 ' + SPAWN_CONNECT_BUDGET_MS + 'ms 内没有连上（task=' +
          String(launched.taskName) + '，注册已删除）。launcher.json 指定 schtasks（强制模式），不回落 detached spawn：' +
          messageOf(error),
          'ESCHTASKSFAILED',
        )
      }
      // The queued instance never answered. Delete the registration (it is not
      // coming back) and fall back ONCE to the detached spawn that always works;
      // a second failure propagates with both errors visible in the log.
      log('schtasks launch did not connect within budget; deleting task and falling back to detached spawn: ' + messageOf(error))
      const cleanup = await deleteTask(launched.taskName, { timeoutMs: SCHTASKS_TIMEOUT_MS, log })
      for (const warning of cleanup.warnings ?? []) log('launcher cleanup: ' + String(warning))
      const fallback = await launchPod(effective, mode, {
        forceDirect: true,
        warnings: ['schtasks 拉起后 ' + SPAWN_CONNECT_BUDGET_MS + 'ms 内连不上管道，已删除任务并回落 detached spawn'],
      })
      // Same logical attempt: the schtasks try + its direct fallback must not
      // burn two of MAX_SPAWN_ATTEMPTS, or a machine that cannot bootstrap
      // would exhaust the budget after two pod deaths.
      spawned = await waitForPod(SPAWN_CONNECT_BUDGET_MS)
      if (fallback?.launcher !== 'spawn') log('launcher: unexpected fallback launcher ' + String(fallback?.launcher))
    }
    if (launched?.launcher === 'schtasks' && launched.ok === true) {
      // The pod answered on the pipe; removing the registration cannot affect
      // the running instance, and a later /ST must never fire another one.
      const cleanup = await deleteTask(launched.taskName, { timeoutMs: SCHTASKS_TIMEOUT_MS, log })
      for (const warning of cleanup.warnings ?? []) log('launcher cleanup: ' + String(warning))
      if (launcherInfo !== null && launcherInfo.launcher === 'schtasks') launcherInfo.taskDeleted = cleanup.ok === true
    }
    attach(spawned, mode)
    await establishAuth(mode)
    resetPodHealth()
  }

  /** @param {any} hint @param {any} [prepared] */
  async function ensureConnected(hint, prepared) {
    if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
    // The plugin calls boot() fire-and-forget at load; a tool call that arrives
    // while boot is still connecting/claiming must wait instead of opening a
    // second connection (the pod serves exactly one).
    if (booting !== null) await booting
    if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
    if (socket !== null) return
    if (connecting !== null) {
      await connecting
      return
    }
    connecting = connectAndMaybeSpawn(hint, prepared)
    try {
      await connecting
    } finally {
      connecting = null
    }
  }

  /** @param {string} op @param {Record<string, unknown>} payload */
  function requestSend(op, payload) {
    const active = socket
    if (active === null) throw new PodError('pod 连接不存在', 'ENOTCONNECTED')
    const id = nextRequestId
    nextRequestId += 1
    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        if (!pending.has(id)) return
        pending.delete(id)
        active.destroy()
        if (socket === active) socket = null
        rejectRequest(new PodError('pod 在 ' + REQUEST_TIMEOUT_MS + 'ms 内没有响应（op=' + op + '）', 'ETIMEDOUT'))
      }, REQUEST_TIMEOUT_MS)
      pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer })
      try {
        /** @type {Record<string, unknown>} */
        const message = { ...payload, op, id }
        // Every request carries the current token; the pod re-checks it on each
        // request (a rotated token invalidates an old connection immediately).
        if (podToken !== null) message.token = podToken
        active.write(JSON.stringify(message) + '\n')
      } catch (error) {
        pending.delete(id)
        clearTimeout(timer)
        rejectRequest(new PodError('写入 pod 管道失败：' + messageOf(error), 'EWRITE'))
      }
    })
  }

  /**
   * Ask the pod for its protocol version, once per connection. `hello` (and
   * `ping`) has returned the snapshot — including `protocolVersion` — since the
   * authenticated single-client protocol existed, so it is the one op an older
   * pod is guaranteed to answer the same way.
   * @returns {Promise<number | null>}
   */
  async function learnPodProtocol() {
    if (podProtocolVersion !== null) return podProtocolVersion
    const response = await requestSend('hello', {})
    const value = Number(response?.protocolVersion)
    podProtocolVersion = Number.isFinite(value) && value > 0 ? Math.trunc(value) : null
    return podProtocolVersion
  }

  /**
   * Fail closed BEFORE a run when the pod is older than the request shape. There
   * is no "best effort" here: a v2 pod accepts the request and ignores `mode`,
   * so the command would run under whatever policy that pod was built with while
   * the Host believes it applied another. The remedy is explicit (relaunch), so
   * a stale pod is a one-command fix rather than a silent security difference.
   * @returns {Promise<number>}
   */
  async function assertRunProtocol() {
    /** @type {number | null} */
    let version = null
    try {
      version = await learnPodProtocol()
    } catch (error) {
      throw new PodError(
        '无法确认 pod 的协议版本（' + messageOf(error) + '）：拒绝把带 mode/unescorted 的运行请求发给可能不认识它们的旧 pod。' +
          '先用 pod_status action=relaunch 重新拉起 pod，再重试；本次没有执行任何命令。',
        'EPROTOCOL',
      )
    }
    const verdict = checkRunProtocol(version)
    if (verdict.ok !== true) throw new PodError(verdict.message, verdict.code)
    return version
  }

  /** @param {any} hint */
  function hostIdentity(hint) {
    return { pid: process.pid, bootId: HOST_BOOT_ID, startedAt: HOST_STARTED_AT, sessionId: hint?.sessionId ?? null }
  }

  /**
   * Spawn one command: the fresh per-call prefix + the Host-named target argv.
   * Retries once with a re-derived prefix if the pod reports it stale (the
   * session temp directory can be reclaimed between confine() and the spawn).
   * The derivation happens INSIDE this loop, exactly once per attempt, so one
   * `pod_run` costs exactly one `confine()` call in the normal case.
   * @param {any} hint
   * @param {() => string[]} buildTargetArgv
   * @param {unknown} rawCwd
   * @param {string} commandLabel
   * @param {{ description?: string | null, env?: Record<string, string> | null, timeoutMs?: number, mode?: string, escalated?: boolean, prefixHint?: { sessionId?: string | null, workspaceRoot?: string }, assertAuthority?: () => void }} [options]
   *   `timeoutMs` is the LIVE native foreground deadline. ONLY `pod_exec`
   *   passes it; `pod_run` must stay unlimited (a command that outlives the
   *   Host is this plugin's whole point). `mode` is the resolved session policy
   *   for THIS call (`danger-full-access` means "no prefix, spawn bare"));
   *   `escalated` is an audit label for the ledger. `prefixHint` carries the
   *   POLICY workspace/session the prefix must be minted for, and
   *   `assertAuthority` is the last-moment TOCTOU check (see
   *   `assertStandingUnchanged`).
   */
  async function executeRun(hint, buildTargetArgv, rawCwd, commandLabel, options = {}) {
    const runMode = normalizeSandboxMode(options.mode) ?? 'workspace-write'
    // Where the prefix is minted from: the session POLICY's root/session when the
    // caller resolved one, otherwise the agent-derived hint. Job ownership and
    // the host block keep using `hint` itself, so a policy refactor can never
    // silently re-own a job.
    const prefixHint = options.prefixHint ?? hint
    /** @type {any} */
    let lastResponse = null
    for (let attempt = 0; attempt < 2; attempt += 1) {
      // Per call: a fresh confine result (none at all for danger-full-access).
      // attempt > 0 is a re-derivation after the pod rejected the prefix as stale.
      const prepared = await deriveCallPrefix(prefixHint, runMode)
      let targetArgv
      let cwd
      try {
        targetArgv = buildTargetArgv()
        cwd = resolveJobCwd(rawCwd, prepared.profile.workspaceRoot)
      } catch (error) {
        throw error instanceof PodError ? error : new PodError(messageOf(error))
      }
      /** @type {any} */
      let response
      try {
        await serialize(() => ensureConnected(prefixHint, prepared))
        // Never send the new fields to a pod that would ignore them: that would
        // execute a different policy than the one approved above.
        await assertRunProtocol()
        // Last-moment authority check: the prefix took time to sign, and the
        // user can move the session switch in between. Throws before any send.
        if (typeof options.assertAuthority === 'function') options.assertAuthority()
        response = await requestSend('run', {
          // `prefix: null` + `unescorted: true` is the danger-full-access shape;
          // the pod validates the pair and refuses a half-formed request.
          prefix: prepared.unescorted === true ? null : prepared.prefix,
          ...(prepared.unescorted === true ? { unescorted: true } : {}),
          mode: prepared.policy?.mode ?? prepared.profile?.mode ?? runMode,
          escalated: options.escalated === true,
          argv: targetArgv,
          cwd,
          command: commandLabel,
          description: options.description ?? null,
          env: options.env ?? collectDshEnv(),
          enforcement: prepared.enforcement,
          // Optional foreground deadline. Absent = unlimited (background).
          // The pod arms the timer itself so it survives a Host restart, and
          // clamps it to its own hard cap.
          ...(Number.isFinite(options.timeoutMs) && Number(options.timeoutMs) > 0
            ? { timeoutMs: Math.trunc(Number(options.timeoutMs)) }
            : {}),
          host: hostIdentity(hint),
          // Job ownership is recorded by the pod in meta.json and echoed in the
          // job projection. It is part of the request, not the (forgeable)
          // host block, so the pod stores exactly what the caller claimed.
          sessionId: hint?.sessionId ?? null,
        })
      } catch (error) {
        throw error instanceof PodError ? error : new PodError(messageOf(error))
      }
      if (response?.ok === true) {
        rememberJobOwner(String(response.jobId ?? ''), response.sessionId ?? hint?.sessionId ?? null)
        return { response, prepared }
      }
      lastResponse = response
      const code = String(response?.error?.code ?? '')
      if (attempt === 0 && (code === 'EPREFIXSTALE' || code === 'EPREFIXMISMATCH')) {
        log('run rejected with ' + code + '; deriving a fresh prefix and retrying once')
        continue
      }
      throw new PodError(
        'pod_run 没有启动任何命令：' + String(response?.error?.message ?? 'unknown'),
        code === '' ? 'EPODCERROR' : code,
      )
    }
    throw new PodError(
      'pod_run 没有启动任何命令：' + String(lastResponse?.error?.message ?? 'unknown'),
      String(lastResponse?.error?.code ?? 'EPODCERROR'),
    )
  }

  /**
   * @param {any} hint
   * @param {{ command: string, shell?: string, cwd?: string, description?: string, env?: Record<string, string>, timeoutMs?: number, mode?: string, escalated?: boolean, prefixHint?: { sessionId?: string | null, workspaceRoot?: string }, assertAuthority?: () => void }} request
   */
  async function run(hint, request) {
    // Policy workspaceRoot comes from this call's session cwd, and the prefix is
    // minted for this call only (revocable temp SID). Both happen inside
    // executeRun so one pod_run == one confine() call.
    const kind = normalizeShellKind(request.shell)
    // ONE decision per call, made before the argv is built (and before the
    // sandbox prefix is signed). The argv shape is unchanged — only the
    // interpreter path now comes from the session/default/auto resolution, so a
    // pod_shell choice is honoured by the very next call and the result can
    // report what actually ran (and why, when a choice fell back).
    const shell = resolveAppliedShell(kind, hint, {
      stateDir,
      config: { pwshPath: configuredPwshPath, bashPath: configuredBashPath },
      log,
    })
    const outcome = await executeRun(
      hint,
      () =>
        kind === 'bash'
          ? buildBashArgv(request.command, shell.path)
          : kind === 'cmd'
            ? buildCmdArgv(request.command, shell.path)
            : buildShellArgv(request.command, shell.path),
      request.cwd,
      request.command,
      {
        description: request.description ?? null,
        env: request.env ?? collectDshEnv(),
        // The resolved session policy for THIS call, and whether it was raised
        // through an approval (ledger audit label only).
        mode: request.mode,
        escalated: request.escalated === true,
        // The prefix must be minted for the POLICY workspace/session, while job
        // ownership keeps using this agent's own session id.
        prefixHint: request.prefixHint,
        // Last-moment authority check, called just before the request is sent.
        assertAuthority: request.assertAuthority,
        // Present ONLY for pod_exec (see `executeRun`): pod_run must remain
        // unlimited, and this is the one place that decides.
        ...(Number.isFinite(request.timeoutMs) && Number(request.timeoutMs) > 0
          ? { timeoutMs: Number(request.timeoutMs) }
          : {}),
      },
    )
    return { ...outcome, shell }
  }

  /**
   * Spawn an explicit target argv (no shell wrapping). Exposed for the self-test
   * and for future executors; the pod still only concatenates it after the prefix.
   * @param {any} hint
   * @param {string[]} targetArgv
   * @param {string} cwd
   * @param {string} [commandLabel]
   * @param {{ description?: string | null, env?: Record<string, string> | null }} [options]
   */
  async function runArgv(hint, targetArgv, cwd, commandLabel, options = {}) {
    return await executeRun(hint, () => targetArgv, cwd, commandLabel ?? targetArgv.join(' '), options)
  }

  /**
   * Make sure a pod exists before a read-only op. If it is absent, spawning needs
   * a template, which needs one fresh confine call — that is the only reason a
   * read-only tool can ask the sandbox for a prefix.
   * @param {any} hint
   */
  async function ensurePod(hint) {
    await serialize(() => ensureConnected(hint))
  }

  /**
   * One job-scoped request. Every one of them carries the caller session id and
   * the adopt flag; the Host pre-check runs first when it already knows the
   * owner, and the pod repeats the check authoritatively.
   * @param {'output'|'kill'|'cursor'|'ack'|'freeze'} op
   * @param {any} hint
   * @param {Record<string, any>} payload
   * @param {boolean} adopt
   */
  async function jobRequest(op, hint, payload, adopt) {
    const jobId = String(payload?.jobId ?? '')
    const action = op === 'kill' ? 'pod_kill' : op === 'freeze' ? 'pod_freeze' : 'pod_output'
    assertKnownJobAccess(action, jobId, hint, adopt)
    await ensurePod(hint)
    const response = await requestSend(op, {
      ...payload,
      sessionId: hint?.sessionId ?? null,
      adopt,
    })
    if (response?.ok !== true) {
      const prefix = op === 'kill'
        ? 'pod_kill 没有执行：'
        : op === 'freeze'
          ? 'pod_freeze 没有执行：'
          : op === 'output'
            ? 'pod_output 没有读到输出：'
            : op === 'cursor'
              ? 'pod_output 无法读取游标：'
              : 'pod_output 无法写回游标：'
      throw new PodError(prefix + String(response?.error?.message ?? 'unknown'), String(response?.error?.code ?? 'EPODCERROR'))
    }
    if (op === 'output' || op === 'kill' || op === 'freeze') {
      assertResponseJobAccess(action, jobId, response, hint, adopt)
      // An older pod cannot report an owner. If this Host never knew one
      // either, the takeover was of unowned history: say so explicitly.
      if (adopt && !Object.prototype.hasOwnProperty.call(response, 'sessionId') && !jobOwners.has(jobId)) {
        response.adoptedFrom = null
      }
    }
    // Only trust an explicitly reported owner: `cursor`/`ack` do not echo one,
    // and an older pod never does. Overwriting a known owner with null here
    // would make this Host forget a job it just started.
    if (response.jobId !== undefined && Object.prototype.hasOwnProperty.call(response, 'sessionId')) {
      rememberJobOwner(jobId, response.sessionId)
    }
    return response
  }

  /** @param {any} hint @param {{ jobId: string, from?: number, maxBytes?: number, adopt?: boolean }} request */
  async function output(hint, request) {
    return await jobRequest('output', hint, { jobId: request.jobId, from: request.from, maxBytes: request.maxBytes }, request.adopt === true)
  }

  /**
   * End one job. `timeoutMs` (optional) marks the kill as a TIMEOUT enforcement
   * so the ledger records `timedOut: true` instead of looking like a user kill;
   * only the `pod_exec` Host fallback sends it.
   * @param {any} hint @param {{ jobId: string, adopt?: boolean, timeoutMs?: number }} request
   */
  async function kill(hint, request) {
    return await jobRequest(
      'kill',
      hint,
      {
        jobId: request.jobId,
        ...(Number.isFinite(request.timeoutMs) && Number(request.timeoutMs) > 0
          ? { timeoutMs: Number(request.timeoutMs) }
          : {}),
      },
      request.adopt === true,
    )
  }

  /**
   * Freeze or thaw one job. Exactly the same session boundary as output/kill:
   * the pod refuses another session's job unless `adopt:true`, and this Host
   * refuses even earlier when it already knows the owner.
   * @param {any} hint @param {{ jobId: string, action: 'freeze' | 'thaw', adopt?: boolean, maxFreezeMs?: number }} request
   */
  async function freeze(hint, request) {
    return await jobRequest(
      'freeze',
      hint,
      {
        jobId: request.jobId,
        action: request.action === 'thaw' ? 'thaw' : 'freeze',
        // 0/negative/garbage is "use the pod default", so it is not sent at all;
        // the pod decides the 30-minute default in one place.
        ...(Number.isFinite(request.maxFreezeMs) && Number(request.maxFreezeMs) > 0
          ? { maxFreezeMs: Number(request.maxFreezeMs) }
          : {}),
      },
      request.adopt === true,
    )
  }

  /**
   * The persisted consumed offset for one job (model-facing reads continue here).
   * @param {any} hint @param {{ jobId: string, adopt?: boolean }} request
   */
  async function cursor(hint, request) {
    const response = await jobRequest('cursor', hint, { jobId: request.jobId }, request.adopt === true)
    return response.cursor ?? null
  }

  /**
   * Persist the Host's consumed offset. Fire-and-forget by contract: the caller
   * never awaits it and a failure only logs, because a cursor is an optimization
   * for the next Host, not part of this read's result.
   * @param {any} hint @param {{ jobId: string, offset: number, hash?: string | null, adopt?: boolean }} request
   */
  async function ack(hint, request) {
    return await jobRequest('ack', hint, { jobId: request.jobId, offset: request.offset, hash: request.hash ?? null }, request.adopt === true)
  }

  /** @param {any} hint */
  async function status(hint) {
    /** @type {any} */
    let bootstrapError = null
    try {
      await ensurePod(hint)
    } catch (error) {
      bootstrapError = error
    }
    if (socket === null) throw bootstrapError instanceof PodError ? bootstrapError : new PodError(messageOf(bootstrapError))
    const response = await requestSend('status', {})
    if (response?.ok !== true) {
      throw new PodError('pod_status 没能读到状态：' + String(response?.error?.message ?? 'unknown'), String(response?.error?.code ?? 'EPODCERROR'))
    }
    notePodIdentity(response)
    resetPodHealth()
    // Remember every owner the pod just reported: a later output/kill in this
    // Host then refuses a foreign job before sending anything. Rows from an
    // older pod carry no sessionId at all; those must not erase what this Host
    // already knows about a job it started.
    for (const job of Array.isArray(response.jobs) ? response.jobs : []) {
      if (typeof job?.jobId === 'string' && Object.prototype.hasOwnProperty.call(job, 'sessionId')) {
        rememberJobOwner(job.jobId, job.sessionId)
      }
    }
    return { response, bootstrapError }
  }

  /**
   * Kill every job this pod owns and make it exit. The pod answers only after
   * the kills are on disk (`exit.json` status `killed`), so `killed` is honest.
   *
   * Never spawns a pod: `boot()` only attaches to one that is already
   * listening. A host with no pod answers `{ ok: true, killed: 0 }`, because
   * "nothing is running" is exactly what a caller of shutdown wants to hear.
   * @param {{ killJobs?: boolean }} [request]
   * @returns {Promise<{ ok: boolean, killed: number, status: string, error?: string }>}
   */
  async function shutdown(request = {}) {
    if (disposed) return { ok: true, killed: 0, status: 'disposed' }
    if (socket === null) {
      try {
        await boot()
      } catch {
        // boot never rejects today; keep the guard so shutdown can never throw.
      }
    }
    if (socket === null) return { ok: true, killed: 0, status: 'not-running' }
    try {
      const response = await requestSend('shutdown', { killJobs: request.killJobs !== false })
      const killed = Number.isFinite(response?.killed) ? Math.max(0, Math.trunc(Number(response.killed))) : 0
      log('shutdown: pod answered killed=' + String(killed))
      return { ok: true, killed, status: 'closed' }
    } catch (error) {
      // The goal state is "the pod is gone": a socket that closed while the
      // answer was in flight (the normal race, since the pod exits right after
      // replying) still means the shutdown happened.
      log('shutdown: no confirmation from the pod: ' + messageOf(error))
      return { ok: true, killed: 0, status: 'unknown', error: messageOf(error) }
    }
  }

  /**
   * Read status from a pod that is ALREADY listening, without spawning one.
   * `status()` would happily start a pod; relaunch must not do that just to
   * discover there was nothing to kill.
   * @param {any} hint
   */
  async function readStatusIfPresent(hint) {
    // Reuse the live connection when there is one: the pod serves exactly ONE
    // client, so opening a second socket here would be refused as EBUSY and
    // relaunch would fail against a perfectly healthy pod.
    if (socket === null && connecting !== null) await connecting
    if (socket !== null) {
      if (podToken === null) await establishAuth('relaunch-probe')
      const response = await requestSend('status', {})
      if (response?.ok !== true) {
        throw new PodError(
          'relaunch 读不到现有 pod 状态：' + String(response?.error?.message ?? 'unknown'),
          String(response?.error?.code ?? 'ERELAUNCHPROBE'),
        )
      }
      return response
    }
    /** @type {net.Socket | null} */
    let connected = null
    try {
      connected = await connectOnce(CONNECT_TIMEOUT_MS)
    } catch (error) {
      const code = /** @type {any} */ (error)?.code
      if (code === 'ENOENT') return null
      throw new PodError(
        'relaunch 无法探活 pod 管道：' + messageOf(error),
        typeof code === 'string' ? code : 'ERELAUNCHPROBE',
      )
    }
    attach(connected, 'relaunch-probe')
    await establishAuth('relaunch-probe')
    const response = await requestSend('status', {})
    if (response?.ok !== true) {
      throw new PodError(
        'relaunch 读不到现有 pod 状态：' + String(response?.error?.message ?? 'unknown'),
        String(response?.error?.code ?? 'ERELAUNCHPROBE'),
      )
    }
    return response
  }

  /**
   * Kill the current pod and start a new one through the configured launcher.
   * DSH is Medium/unrestricted, so `process.kill` is enough; spawning
   * `taskkill` would add a child process for no gain (and is exactly the
   * job-object pattern this plugin avoids).
   *
   * Without `force`, a pod that still reports running jobs is refused with the
   * job ids spelled out — relaunching would abandon those commands.
   * @param {any} hint
   * @param {{ force?: boolean }} [options]
   */
  async function relaunch(hint, options = {}) {
    const force = options.force === true
    if (disposed) throw new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED')
    /** @type {any} */
    let before = null
    try {
      before = await readStatusIfPresent(hint)
    } catch (error) {
      throw new PodError(
        'relaunch 拒绝盲杀：读不到当前 pod 状态（' + messageOf(error) + '）。先确认 pod_status / pod_output 可用，或显式重启 DSH。',
        'ERELAUNCHPROBE',
      )
    }
    const podPid = before === null ? null : Number(before.podPid)
    /** @type {any[]} */
    let runningJobs = []
    if (before !== null) {
      runningJobs = Array.isArray(before.jobs) ? before.jobs.filter((job) => job?.running === true) : []
      if (runningJobs.length > 0 && !force) {
        const ids = runningJobs.slice(0, 10).map((job) => String(job.jobId)).join(', ')
        throw new PodError(
          'relaunch 被拒绝：pod 里还有 ' + runningJobs.length + ' 个 running job（' + ids +
          (runningJobs.length > 10 ? ' …' : '') + '）。先 pod_kill 它们，或显式传 force:true（会杀掉 pod，正在跑的命令随之中断）。',
          'ERELAUNCHBUSY',
        )
      }
    }
    let killedPid = null
    if (Number.isInteger(podPid) && /** @type {number} */ (podPid) > 0) {
      if (podPid === process.pid) throw new PodError('relaunch 拒绝结束 Host 自身进程', 'ERELAUNCHSELF')
      try {
        process.kill(/** @type {number} */ (podPid), 'SIGTERM')
        killedPid = podPid
        log(
          'relaunch: killed pod pid=' + String(podPid) + ' forced=' + String(force) +
          ' running=' + String(runningJobs.length),
        )
      } catch (error) {
        const code = /** @type {any} */ (error)?.code
        if (code !== 'ESRCH') {
          throw new PodError('relaunch 无法结束 pod pid=' + String(podPid) + '：' + messageOf(error), 'ERELAUNCHKILL')
        }
        log('relaunch: pod pid=' + String(podPid) + ' 已不存在（ESRCH），按已死亡处理')
      }
    }
    // Drop every Host-side trace of the old pod: a new process means a new
    // memory-only token and a new single-client slot.
    const oldSocket = socket
    socket = null
    socketMode = 'none'
    if (oldSocket !== null) {
      try {
        oldSocket.destroy()
      } catch {
        // already gone
      }
    }
    podToken = null
    spawnAttempts = 0
    lastSpawnAt = 0
    blockingErrorSeen = false
    podExit = null
    // The pipe NAME must be free before a new pod can bind it. TerminateProcess
    // closes the handle immediately, but verify instead of assuming, bounded.
    const deadline = Date.now() + 10_000
    for (;;) {
      if (Date.now() >= deadline) {
        throw new PodError(
          'relaunch 已结束 pod pid=' + String(killedPid ?? '?') + '，但管道 10s 内仍可连接（可能有另一个 pod 占着）；未启动新 pod',
          'ERELAUNCHSTUCK',
        )
      }
      /** @type {any} */
      let probe = null
      try {
        probe = await connectOnce(500)
      } catch (error) {
        probe = error
      }
      if (probe instanceof Error) {
        if (/** @type {any} */ (probe).code === 'ENOENT') break
      } else {
        try {
          probe.destroy()
        } catch {
          // ignore
        }
      }
      await sleep(100)
    }
    await serialize(() => ensureConnected(hint))
    return {
      ok: true,
      killedPid,
      forced: force,
      runningBefore: runningJobs.length,
      spawnInfo: snapshotSpawnInfo(),
      launcher: launcherInfo,
    }
  }

  async function boot() {
    if (booting !== null) return await booting
    // boot never rejects: a failed claim is reported to the first tool call,
    // which retries from a clean connect.
    booting = (async () => {
      try {
        const connected = await connectOnce(CONNECT_TIMEOUT_MS)
        attach(connected, 'reused')
        await establishAuth('reused')
      } catch (error) {
        const code = /** @type {any} */ (error)?.code
        if (code === 'ENOENT') log('boot: no pod at ' + pipeName + ' yet; it will be spawned on the first tool call')
        else log('boot connect failed: ' + messageOf(error))
      }
    })()
    try {
      await booting
    } finally {
      booting = null
    }
  }

  function dispose() {
    disposed = true
    const active = socket
    socket = null
    if (active !== null) {
      try {
        active.destroy()
      } catch {
        // already gone
      }
    }
    for (const [id, entry] of pending) {
      pending.delete(id)
      clearTimeout(entry.timer)
      entry.reject(new PodError('插件已卸载，pod 客户端已关闭', 'EDISPOSED'))
    }
    // Deliberately NOT killing the pod: it must outlive the Host.
  }

  function snapshotSpawnInfo() {
    if (spawnInfo === null) return null
    return {
      spawnedAt: spawnInfo.spawnedAt,
      reason: spawnInfo.reason,
      podPid: spawnInfo.podPid,
      template: spawnInfo.template,
      templateView: spawnInfo.templateView,
      enforcement: spawnInfo.enforcement,
      probePrefixFingerprint: spawnInfo.probePrefixFingerprint,
      policyVariant: spawnInfo.policyVariant,
      policy: spawnInfo.policy,
      workspaceRoot: spawnInfo.workspaceRoot,
      dataRoot: spawnInfo.dataRoot,
      launcher: spawnInfo.launcher ?? null,
      taskName: spawnInfo.taskName ?? null,
      schtasksProbe: spawnInfo.schtasksProbe ?? 'unknown',
      launchWarnings: spawnInfo.launchWarnings ?? [],
      auth: spawnInfo.auth ?? null,
      podExit: spawnInfo.podExit,
    }
  }

  return {
    pipeName,
    idleExitMs,
    stateDir,
    boot,
    dispose,
    run,
    runArgv,
    output,
    cursor,
    ack,
    kill,
    freeze,
    status,
    shutdown,
    /** @param {string} jobId @returns {{ known: boolean, sessionId: string | null }} */
    ownerOf(jobId) {
      const key = String(jobId ?? '')
      return jobOwners.has(key)
        ? { known: true, sessionId: jobOwners.get(key) ?? null }
        : { known: false, sessionId: null }
    },
    mode: () => socketMode,
    /** Protocol the attached pod reported (null until the first run learns it). */
    protocolVersion: () => podProtocolVersion,
    spawnInfo: snapshotSpawnInfo,
    /** Last launch decision (schtasks vs spawn); null when this Host reused a pod. */
    launcher: () => launcherInfo,
    /** Last bounded self-heal (killed unresponsive pod), if any. */
    launcherRecovery: () => podRecoveryLog,
    relaunch,
    sandboxPresent: () => sandboxOrNull() !== null,
    template: () => spawnedTemplate,
  }
}

// ---------------------------------------------------------------------------
// Model-facing rendering
// ---------------------------------------------------------------------------

/** @param {Record<string, any>} response @param {any} prepared @param {string | null} [registryJobId] @param {any} [policy] @param {any} [shell] */
function renderRunText(response, prepared, registryJobId = null, policy = null, shell = null) {
  const mode = String(policy?.mode ?? prepared?.profile?.mode ?? '?')
  const unescorted = prepared?.unescorted === true || mode === 'danger-full-access'
  const standingMode = String(policy?.standingMode ?? mode)
  const escalated = policy?.escalated === true
  const lines = []
  lines.push('逃生舱已接管命令：jobId=' + String(response.jobId) + ' runnerPid=' + String(response.runnerPid ?? '?'))
  if (registryJobId !== null && registryJobId !== '') {
    lines.push('已收养进 ctx.jobs：registryJobId=' + String(registryJobId) + '（job_list 可见，job_output 读增量，job_kill 真杀）')
  } else {
    lines.push('未收养进 ctx.jobs（jobs 服务/控制器不可用）：请用 pod_output / pod_kill')
  }
  lines.push('podPid=' + String(response.podPid ?? '?') + ' enforcement=' + String(prepared?.enforcement ?? '?'))
  // The policy line is the honest one: which mode this command actually runs
  // under, whether it was widened for this call, and what that costs.
  lines.push(
    'policy=' + mode +
      (escalated ? '（本次调用经 DSH 审批提升：只对这一次有效，不改变会话策略）' : '（跟随当前会话文件策略）') +
      (unescorted
        ? '：danger-full-access，**不带任何沙箱前缀**，命令以 pod 自身 Medium 令牌运行=真正完全访问（命令与用户同权，可改写账本/任意用户可写文件）'
        : '：命令在 runner 的受限令牌 Low 完整性 + kill-on-close Job 里运行'),
  )
  lines.push('会话策略=' + standingMode + (escalated ? ' → 本次 ' + mode : '') + ' workspace=' + String(policy?.workspaceRoot ?? prepared?.profile?.workspaceRoot ?? '?'))
  if (unescorted) {
    lines.push('本次没有前缀：danger-full-access 不调用 ctx.sandbox.confine（fingerprint=unescorted）')
  } else {
    lines.push('本次调用现签前缀=' + String(prepared?.fingerprint ?? '?').slice(0, 16) + '… variant=' + String(prepared?.policyVariant ?? '?'))
    lines.push('prefix workspace=' + String(prepared?.profile?.workspaceRoot ?? '?') + ' temp=' + String(prepared?.profile?.tempDir ?? '?'))
  }
  lines.push('cwd=' + String(response.cwd ?? '?'))
  if (response.description !== null && response.description !== undefined) lines.push('description=' + truncate(String(response.description), 200))
  lines.push('command=' + truncate(response.command ?? '', 300))
  // Which interpreter this command actually used, and where that choice came
  // from. A fallback is spelled out instead of silently switching the shell.
  if (shell !== null && shell !== undefined) lines.push(renderShellLine(shell))
  lines.push('读输出：pod_output(jobId="' + String(response.jobId) + '")（自动续读，无需偏移）；结束：pod_kill(jobId="' + String(response.jobId) + '")')
  lines.push('台账：' + String(response.ledgerDir ?? '<stateDir>/jobs/' + String(response.jobId) + '/'))
  lines.push(unescorted
    ? '说明：完全访问没有前缀可复用/可失效；mode 由 Host 每次按会话策略现解析，审批只对本次调用有效。'
    : '说明：前缀（含可回收的会话 temp SID）只对本次调用有效；每次 pod_run 都由 Host 现签，pod 只保存形态校验模板。')
  return lines.join('\n')
}

/**
 * Native `job_output` shape: stdout, the `[stderr]` segment, `[exit code: N]`
 * when non-zero, then one bracketed status line.
 * @param {Record<string, any>} response
 * @param {{ spillPaths?: boolean }} [options] `spillPaths:false` drops the
 *   `full output: <path>` tail (the foreground form must not leak a ledger path
 *   that contains the pod jobId).
 */
function renderOutputText(response, options = {}) {
  const chunks = Array.isArray(response.chunks) ? response.chunks : []
  const stdoutText = chunks.filter((chunk) => chunk.channel !== 'stderr').map((chunk) => chunk.text).join('')
  const stderrText = chunks.filter((chunk) => chunk.channel === 'stderr').map((chunk) => chunk.text).join('')
  const separator = stdoutText.length > 0 && !stdoutText.endsWith('\n') ? '\n' : ''
  const body = stdoutText + (stderrText.length > 0 ? separator + '[stderr]\n' + stderrText : '')
  // Native `job_output` (dsh-tool-jobs/lib/index.js:61-70) has no "more output"
  // hint: it returns the delta and the status line, nothing else. An empty delta
  // therefore renders as just the status line.
  const lines = body.length === 0 ? [] : [body]
  // A read clipped to the model limit ends with the native read-tool marker.
  if (response.truncated === true) lines.push('[output truncated]')
  if (response.lossy === true) {
    lines.push(options.spillPaths === false
      ? '[some output was dropped from memory]'
      : '[some output was dropped from memory; full output: ' + spillPathsText(response) + ']')
  }
  // Native shell tools carry the exit code in the text, never in the status line.
  if (typeof response.exitCode === 'number' && response.exitCode !== 0) {
    lines.push('[exit code: ' + String(response.exitCode) + ']')
  }
  lines.push(statusLine(response))
  return lines.join('\n')
}

/**
 * One extra line for an explicit cross-session takeover. `null` means the job
 * has no owner (a ledger written before session ownership existed).
 * @param {string | null} adoptedFrom
 */
function renderAdoptedFrom(adoptedFrom) {
  const owner = adoptedFrom === null ? '无主（历史 job，meta.json 没有 sessionId）' : adoptedFrom
  return '\n[adopted: 本次调用用 adopt: true 显式接管了非本会话的 job；原会话：' + owner + ']'
}

/**
 * Clip pod channel chunks to the byte range the model actually consumes. Pod
 * segment boundaries are UTF-8 aligned and `end` is a newline boundary, so
 * slicing the decoded text by bytes is lossless.
 * @param {{ offset: number, length: number, channel: string, text: string }[]} chunks
 * @param {number} start @param {number} end
 */
export function clipChannelChunks(chunks, start, end) {
  /** @type {{ offset: number, length: number, channel: string, text: string }[]} */
  const clipped = []
  for (const chunk of chunks) {
    const chunkStart = Number(chunk.offset)
    const chunkEnd = chunkStart + Number(chunk.length)
    if (!Number.isFinite(chunkStart) || !Number.isFinite(chunkEnd)) continue
    if (chunkEnd <= start) continue
    if (chunkStart >= end) break
    const from = Math.max(chunkStart, start)
    const to = Math.min(chunkEnd, end)
    if (to <= from) continue
    const buffer = Buffer.from(String(chunk.text ?? ''), 'utf8')
    clipped.push({
      offset: from,
      length: to - from,
      channel: chunk.channel === 'stderr' ? 'stderr' : chunk.channel === 'log' ? 'log' : 'stdout',
      text: buffer.subarray(from - chunkStart, to - chunkStart).toString('utf8'),
    })
  }
  return clipped
}

/**
 * Assemble the single, native-shaped result of a foreground call: the same
 * live native `maxOutputBytes` window, the same line/code-point alignment and
 * the same `[output truncated]` marker `pod_output` uses, but deliberately no
 * jobId, no offset and no ledger path — a foreground call has no second step.
 *
 * `recovery.mjs` calls this exact function to answer a call held across a
 * restart, with the same read window, so the recovered text is byte-identical
 * to what the call would have returned had DSH not restarted — including the
 * timeout notice below, which is derived from the ledger (`response.timedOut`),
 * not from Host-local state.
 * @param {Record<string, any>} response final `output` projection
 * @param {boolean} aborted
 * @param {{ timedOut?: boolean, timeoutMs?: number | null, source?: string }} [options]
 *   Host-only knowledge for the fallback path: when an older pod ignores
 *   `run.timeoutMs`, the Host killed the job itself and knows it was a timeout
 *   even though the pod projection does not say so.
 */
export function renderExecResult(response, aborted, options = {}) {
  const raw = String(response?.text ?? '')
  const aligned = alignModelChunk({ text: raw, hasMore: response?.hasMore === true })
  const podChunks = Array.isArray(response?.chunks) && response.chunks.length > 0
    ? response.chunks
    : [{ offset: 0, length: Buffer.byteLength(raw, 'utf8'), channel: 'stdout', text: raw }]
  // Native timeout semantics: the executor kills the command, partial output is
  // still returned, and the status is `killed` — never `completed`. The ledger
  // wins over Host-local knowledge: if the pod recorded a timeout, that is the
  // authoritative value (the live setting may have been edited mid-call).
  const timedOut = options?.timedOut === true || response?.timedOut === true
  const timeoutMs = positiveIntOf(response?.timeoutMs) ?? positiveIntOf(options?.timeoutMs)
  const view = {
    text: aligned.text,
    chunks: clipChannelChunks(podChunks, 0, aligned.consumedBytes),
    truncated: aligned.truncated,
    lossy: response?.lossy === true,
    exitCode: typeof response?.exitCode === 'number' ? response.exitCode : null,
    signal: response?.signal ?? null,
    status: aborted ? 'running' : (typeof response?.status === 'string' ? response.status : 'unknown'),
    timedOut,
    timeoutMs: timeoutMs ?? null,
    detail: timedOut ? 'timed out after ' + String(timeoutMs ?? '?') + ' ms' : null,
  }
  const text = renderOutputText(view, { spillPaths: false })
  // The notice leads the result: a model that only skims the first line must
  // not mistake partial output for a completed command.
  const timeoutNotice = timedOut
    ? '命令超时：超过 ' + String(timeoutMs ?? '?') + ' ms（原生 shell 执行器的 timeoutMs）后已终止；下面是终止前已经产生的部分输出。'
    : ''
  const body = [timeoutNotice, text].filter((line) => line !== '').join('\n')
  return {
    view,
    text: aborted ? body + '\n[等待被取消：命令没有中止，仍在逃生舱里继续运行（不要重跑）]' : body,
  }
}

/** Pod ledger statuses mapped onto the native `JobStatus` vocabulary. */
const NATIVE_JOB_STATUS = {
  running: 'running',
  stopping: 'stopping',
  settled: 'completed',
  completed: 'completed',
  killed: 'killed',
  failed: 'failed',
  'runner-failed': 'failed',
  unknown: 'failed',
}

/** @param {Record<string, any>} response */
function spillPathsText(response) {
  const list = Array.isArray(response.spillPaths) ? response.spillPaths.filter((path) => typeof path === 'string' && path !== '') : []
  if (list.length > 0) return list.join(', ')
  if (typeof response.spillPath === 'string' && response.spillPath !== '') return response.spillPath
  return '(unavailable)'
}

/** Native `job_output` shape: the text, then one bracketed status line. */
function statusLine(response) {
  const status = NATIVE_JOB_STATUS[String(response.status)] ?? 'failed'
  const detail = typeof response.detail === 'string' && response.detail.length > 0 ? response.detail : null
  return detail === null ? '[status: ' + status + ']' : '[status: ' + status + ', ' + detail + ']'
}

/**
 * Cut one pod chunk for the model-facing read. The pure `text` is never split
 * inside a UTF-8 code point and, when more data follows, never inside a line:
 * the partial last line is left for the next call. Notices are returned
 * separately so concatenating `text` across calls stays byte-identical to
 * out.log.
 * @param {{ text: string, hasMore: boolean }} input
 */
export function alignModelChunk(input) {
  const buffer = Buffer.from(input.text ?? '', 'utf8')
  let cut = buffer.length
  let truncated = false
  if (buffer.length > 0 && input.hasMore === true) {
    const lastNewline = buffer.lastIndexOf(0x0a)
    if (lastNewline >= 0) cut = lastNewline + 1
    // Native `job_output` fits its content to the read limit and appends
    // `[output truncated]` whenever it had to cut — the marker means "this
    // result was clipped", not "a line was split". So it is set whenever more
    // bytes remain, no matter where the cut landed.
    truncated = true
  }
  if (cut > 0 && cut < buffer.length) {
    const safe = trimIncompleteUtf8End(buffer.subarray(0, cut))
    if (safe > 0) cut = safe
  }
  return {
    text: buffer.subarray(0, cut).toString('utf8'),
    consumedBytes: cut,
    truncated,
    droppedPartialLine: cut < buffer.length,
  }
}

/**
 * `job_output` also advances the pod cursor: after the registry read consumed
 * the job's output up to `output.total`, the equivalent pod offset is
 * `adoptionBase + output.total` (pod chunks are UTF-8 aligned, so registry
 * bytes map 1:1). Fire-and-forget; never blocks the tool result.
 * @param {{ getJobs: () => any, adoptions: any, pod: any, log?: (message: string) => void }} deps
 */
export function createJobOutputAckHook(deps) {
  const log = typeof deps.log === 'function' ? deps.log : () => {}
  return function onPostTool(exec, result) {
    if (deps.adoptions === null || deps.adoptions === undefined) return
    if (exec?.name !== 'job_output' || result?.isError === true) return
    const registryId = exec?.arguments?.job_id
    if (typeof registryId !== 'string' || registryId === '') return
    try {
      const record = deps.adoptions.recordForRegistryId(registryId)
      if (record === null || record === undefined || record.settled === true || record.detached === true) return
      const jobs = deps.getJobs()
      const total = jobs?.get?.(registryId, exec?.agent?.id)?.output?.total
      if (!Number.isInteger(total) || total < 0) return
      const offset = record.baseOffset + total
      if (offset <= (record.ackedFromJobOutput ?? -1)) return
      record.ackedFromJobOutput = offset
      void deps.pod.ack(record.hint, { jobId: record.podJobId, offset, adopt: true }).then(
        (response) => {
          if (response?.ok !== true) log('job_output cursor ack rejected for ' + record.podJobId + ': ' + String(response?.error?.message ?? 'unknown'))
        },
        (error) => {
          log('job_output cursor ack failed for ' + record.podJobId + ': ' + messageOf(error))
        },
      )
    } catch (error) {
      log('job_output cursor ack hook failed: ' + messageOf(error))
    }
  }
}

/** @param {Record<string, any>} response @param {any} bootstrapError @param {string} connection @param {any} spawnInfo @param {any} [adoptionSync] @param {any} [launcherState] */
function renderStatusText(response, bootstrapError, connection, spawnInfo, adoptionSync = null, launcherState = null) {
  const lines = []
  lines.push('逃生舱：podPid=' + String(response.podPid) + ' podStartedAt=' + String(response.podStartedAt))
  lines.push('generation=' + String(response.generation) + '（pod 自启动以来服务过的客户端连接数）')
  lines.push('connection=' + connection + '（' + (CONNECTION_TEXT[connection] ?? '未知连接状态') + '）')
  lines.push('pipe=' + String(response.pipeName))
  const identity = response.identity
  if (identity !== null && identity !== undefined) {
    lines.push('identity=' + String(identity.seedKind) + ' v' + String(identity.seedVersion) + ' seedHash=' + String(identity.seedHash) + '（管道名由稳定身份派生，不再依赖 DSH_HOME）')
  }
  const auth = response.auth
  if (auth !== null && auth !== undefined) {
    lines.push(
      'auth=mode:' + String(auth.mode) + ' tokenRequired:' + String(auth.required) + ' tokenFp:' + String(auth.tokenFingerprint) +
      ' connected:' + String(auth.connected) + ' tokenSource:' + String(auth.tokenSource) +
      ' handover:' + String(auth.handoverCount) + (auth.handoverAllowed === true ? '(allowed)' : '(disabled)') +
      ' rejectedConns:' + String(auth.rejectedConnections),
    )
  }
  lines.push('podVersion=' + String(response.podVersion) + ' protocol=' + String(response.protocolVersion))
  // The execution model in one readable line: the pipe name is derived from the
  // stable identity and the pod LISTENS EXCLUSIVELY, so one machine+user shares
  // exactly one pod and every later Host attaches through `handover` instead of
  // starting a second pod.
  lines.push(
    '单例=管道名由稳定身份派生、pod 独占监听：同机同用户共用一个 pod，后连的 Host 走 handover 接管同一个 pod（不会另起一个）',
  )
  // Capability line, exactly as the design's step 1 promises: supported, or
  // unsupported WITH the reason. A pod from before this feature has no field.
  const freezeInfo = response.freeze
  if (freezeInfo === null || freezeInfo === undefined) {
    lines.push('freeze=unknown（这个 pod 不返回冻结能力字段：旧版本 pod；pod_freeze 会返回 EBADOP/ENOTHANDLE）')
  } else if (freezeInfo.supported === true) {
    // `supported` is a property of the OS, not of this job: a runner that could
    // not be assigned to the pod's job makes freeze answer ENOTHANDLE. Surface
    // that failure here, otherwise the line looks green while the tool refuses.
    const attachError = freezeInfo.lastAttachError
    lines.push('freeze=supported（job 级冻结可用；默认看门狗 ' + renderFreezeRemaining(freezeInfo.defaultMaxFreezeMs) + '，到点自动解冻不杀命令）' +
      (attachError === null || attachError === undefined
        ? ''
        : '；最近一次 runner 入 job 失败：' + String(attachError.stage) + ' Win32 ' + String(attachError.win32) +
          '（该 job 冻结会返回 ENOTHANDLE；pod 可能运行在别的 job 里，优先用 launcher=schtasks）'))
  } else {
    lines.push('freeze=unsupported（' + String(freezeInfo.reason ?? '未知原因') + '）')
  }
  lines.push('enforcement（pod 记录）=（' + String(response.enforcement) + '）')
  const template = response.template
  if (template?.valid === true) {
    lines.push('形态校验模板（钉死在 spawn 时，不含 SID）：runnerPath=' + String(template.runnerPath))
    // `modes` is the v3 field; an older pod only knows the single `mode` it
    // pinned, so fall back to that instead of printing "?".
    const templateModes = Array.isArray(template.modes) ? template.modes.join('/') : String(template.mode ?? '?')
    lines.push('  program=' + String(template.program) + ' modes=' + templateModes + ' workspace=' + String(template.workspaceRoot))
    lines.push('  pin=' + String(template.pin) + ' lastEnforcement=' + String(template.lastEnforcement ?? '?'))
  } else {
    lines.push('形态校验模板：不可用（' + String(template?.code ?? '?') + '）' + String(template?.reason ?? ''))
  }
  if (bootstrapError !== null && bootstrapError !== undefined) lines.push('本次 Host 现场签发模板的前缀失败：' + messageOf(bootstrapError))
  lines.push('workspace=' + String(response.workspaceRoot) + ' dataRoot=' + String(response.dataRoot))
  if (spawnInfo !== null) {
    lines.push('本次 Host spawn 过 pod：podPid=' + String(spawnInfo.podPid ?? '?') + ' reason=' + String(spawnInfo.reason))
  } else {
    lines.push('本次 Host 没有 spawn pod（复用了重启前就在运行的 pod）')
  }
  // Four fixed lines for the launcher layer, present even when this Host
  // reused a pod: "probe=ok but launcher=spawn" is a real, explainable state
  // (the pod cannot bootstrap without stdin yet), not a failure to hide.
  lines.push('launcherMode=' + (launcherState === null
    ? 'unknown（本次 Host 没有 spawn pod）'
    : String(launcherState.mode ?? 'auto') +
      (launcherState.modeSource === 'file' ? '（文件）' : '（默认）') +
      (launcherState.forced === true ? '，强制不回落' : '')))
  lines.push('launcher=' + (launcherState === null
    ? 'unknown（本次 Host 没有 spawn pod）'
    : String(launcherState.launcher)))
  lines.push('task=' + (launcherState === null
    ? '（无）'
    : launcherState.taskName === null
      ? '（无；launcher=spawn 不建计划任务）'
      : String(launcherState.taskName) + (launcherState.taskDeleted === true ? '（已删除注册）' : '（注册未删）')))
  lines.push('schtasks=' + (launcherState === null
    ? 'unknown（本次 Host 未探测）'
    : String(launcherState.schtasksProbe) +
      (Array.isArray(launcherState.warnings) && launcherState.warnings.length > 0
        ? '（' + launcherState.warnings.map((warning) => truncate(String(warning), 200)).join('；') + '）'
        : '')))
  if (adoptionSync !== null && adoptionSync !== undefined) {
    const warnings = Array.isArray(adoptionSync.jobs)
      ? adoptionSync.jobs.filter((row) => row.warning !== null && row.warning !== undefined)
      : []
    lines.push(
      'ctx.jobs 收养：新收养 ' + String(adoptionSync.adopted ?? 0) + ' 个' +
      (adoptionSync.skipped === undefined ? '' : '，跳过 ' + String(adoptionSync.skipped)) +
      (adoptionSync.reason === undefined ? '' : '（' + String(adoptionSync.reason) + '）') +
      (warnings.length === 0 ? '' : '；游标告警 ' + String(warnings.length) + ' 个'),
    )
    for (const row of warnings) lines.push('  ! ' + String(row.podJobId) + ' [' + String(row.cursorMode) + '] ' + String(row.warning))
  }
  const jobs = Array.isArray(response.jobs) ? response.jobs : []
  lines.push('jobs=' + String(jobs.length) + '（running=' + String(response.running ?? 0) + '）')
  if (jobs.length === 0) {
    lines.push('（本会话还没有任何 job）')
  } else {
    for (const job of jobs.slice(0, 20)) {
      const registry = job.registry
      let registryText = ''
      if (registry?.adopted === true) {
        registryText = ' registry=' + String(registry.id) + '（' + String(registry.status ?? '?') + ', cursor=' + String(registry.cursor ?? '?') + '）'
        if (registry.lossy === true) registryText += ' lossy'
      } else if (registry !== undefined) registryText = ' registry=未收养（' + String(registry.reason ?? '已结束的历史 job，仅账本可见') + '）'
      const cursor = job.cursor
      const cursorText = cursor === null || cursor === undefined
        ? ' cursor=?'
        : ' cursor=' + String(cursor.state) + '@' + String(cursor.offset ?? '?') + (cursor.lossy === true ? '!lossy' : '')
      // The policy each job actually ran under. A job started before the policy
      // followed the session has no `policy` field at all, so the row stays
      // silent instead of guessing a mode.
      const policyRow = job.policy
      const modeText = policyRow === null || policyRow === undefined
        ? ''
        : policyRow.unescorted === true
          ? ' mode=danger-full-access(unescorted)'
          : ' mode=' + String(policyRow.mode) + (policyRow.escalated === true ? '(escalated)' : '')
      // Freeze visibility is a hard requirement (design §5): without it the
      // model sees "no output for 5 minutes" and retries a command that is
      // deliberately paused.
      const freezeRow = job.freeze
      let freezeText = ''
      if (freezeRow !== null && freezeRow !== undefined) {
        if (freezeRow.state === 'frozen') {
          freezeText = freezeRow.thawable === true
            ? ' frozen=剩' + renderFreezeRemaining(freezeRow.remainingFreezeMs) +
              (freezeRow.since === null ? '' : '（since ' + String(freezeRow.since) + (freezeRow.by === null ? '' : ' by ' + String(freezeRow.by)) + '）')
            : ' frozen-orphan=不可解冻（job 句柄随上一个 pod 消失；只有 pod_kill 还能碰它，它会如实报告 killed=false，必要时手工结束进程）'
        } else if (Number.isInteger(freezeRow.count) && freezeRow.count > 0) {
          freezeText = ' freeze=已解冻' + String(freezeRow.count) + '次'
        }
      }
      lines.push(
        '- ' + String(job.jobId) +
        ' status=' + String(job.status) +
        modeText +
        ' running=' + String(job.running) +
        ' exitCode=' + String(job.exitCode) +
        ' bytes=' + String(job.bytes) +
        ' runnerPid=' + String(job.runnerPid ?? '?') +
        ' startedAt=' + String(job.startedAt ?? '?') +
        cursorText +
        freezeText +
        registryText +
        (job.description === null || job.description === undefined ? '' : ' desc=' + truncate(String(job.description), 120)) +
        (Array.isArray(job.spillPaths) && job.spillPaths.length > 0 ? ' spill=' + job.spillPaths.join(',') : '') +
        (job.command === null || job.command === undefined ? '' : ' command=' + truncate(job.command, 80)),
      )
      if (registry?.cursorWarning !== null && registry?.cursorWarning !== undefined) {
        lines.push('    ! ' + String(registry.cursorWarning))
      }
    }
    if (jobs.length > 20) lines.push('（只显示最近 20 个）')
  }
  const foreignJobs = Number.isInteger(response.foreignJobs) ? response.foreignJobs : 0
  const unownedJobs = Number.isInteger(response.unownedJobs) ? response.unownedJobs : 0
  lines.push(
    'foreignJobs=' + String(foreignJobs) + (unownedJobs > 0 ? '（其中无主历史 job ' + String(unownedJobs) + '）' : '') +
    '：其它 DSH 会话（以及没有 sessionId 的旧账本）的 job 默认只给计数，不显示 jobId / 命令 / spill 路径。' +
    '确认原会话已销毁、需要清理孤儿时，用 pod_output / pod_kill 的 adopt: true 显式接管。',
  )
  lines.push('说明：pod 的内存只保存活句柄；out.log/exit.json 在磁盘上，重启后仍可读。exit.json 缺失的旧 job 报 unknown，不会假装已知。')
  lines.push('job_list 与这里同源：running 的 pod job 被收养成 unowned registry job（kind=' + ADOPT_KIND + '）；收养记录本身仍是跨会话的 unowned（原生 job_list/job_output/job_kill 不受本边界过滤），已结束的历史 job 不收养，只在账本可见。')
  return lines.join('\n')
}

/**
 * One status line for the session's LIVE file policy: what the next `pod_run` /
 * `pod_exec` will default to, and where that value came from. A model that
 * wonders why a write was denied reads this instead of guessing.
 * @param {any} standing `resolveStandingPolicy()` result
 */
function renderStandingPolicyLine(standing) {
  if (standing === null || standing === undefined) return 'unknown'
  const parts = [
    String(standing.mode),
    'workspace=' + String(standing.workspaceRoot),
    'source=' + String(standing.source),
  ]
  if (typeof standing.modeNote === 'string') parts.push(String(standing.modeNote))
  if (typeof standing.policyError === 'string') parts.push('policyError=' + String(standing.policyError))
  return parts.join(' ')
}

/**
 * One `pod_status` line: the live native budgets, where they came from, and
 * the pod-side fallback window / hard clamp. `source` is deliberately verbatim
 * (including the probe failures behind a fallback) so a support run can tell a
 * genuine native value from a degraded one without reading logs.
 * @param {any} limits `resolveLiveLimits()` result
 * @param {{ defaultOutputChunkBytes: number | null, maxOutputChunkBytes: number | null }} pod
 */
function renderLimitsLine(limits, pod) {
  const reasons = Array.isArray(limits?.reasons) ? limits.reasons : []
  const origin = limits?.source === 'fallback:native-defaults'
    ? '兜底（原生执行器读不到：' + (reasons.length === 0 ? '无原因' : reasons.join('；')) + '）'
    : String(limits?.source ?? '?') +
      (limits?.executor === null || limits?.executor === undefined ? '' : ' / ' + String(limits.executor)) +
      (limits?.entry === null || limits?.entry === undefined ? '' : ' / 条目 ' + String(limits.entry))
  return 'maxOutputBytes=' + String(limits?.maxOutputBytes ?? '?') +
    (limits?.modelCeiling === null || limits?.modelCeiling === undefined
      ? ''
      : '（可选部署上限 ' + String(limits.modelCeiling) + '；原生值 ' + String(limits?.native?.maxOutputBytes ?? '?') + '）') +
    ' timeoutMs=' + String(limits?.timeoutMs ?? '?') +
    ' source=' + origin +
    ' | timeoutMs 只作用于 ' + EXEC_TOOL_NAME + '，pod_run（后台）不限时' +
    ' | pod 兜底窗口=' + String(pod?.defaultOutputChunkBytes ?? '?') + ' 硬上限=' + String(pod?.maxOutputChunkBytes ?? '?')
}

/**
 * One line describing the boot recovery scan for `pod_status`: whether a
 * previous boot left `pod_exec` calls to answer, and what the last pass did.
 * @param {any} info `recovery.status()` result, or null when no scanner exists
 */
/**
 * One line describing OS-level client attestation for `pod_status`.
 * @param {any} attestation the pod's `status.attestation`, or null
 */
function renderAttestationLine(attestation) {
  if (attestation === null || attestation === undefined) return '未上报（旧版 pod 或已关闭）'
  const mode = String(attestation.mode ?? 'unknown')
  if (mode === 'off') return 'off（不做 OS 级身份校验）'
  const channel = attestation.channel !== null && attestation.channel !== undefined ? attestation.channel : null
  const head = 'mode=' + mode +
    ' available=' + String(attestation.available === true) +
    (attestation.available === true ? '' : '（' + String(attestation.unavailableReason ?? '原因未知') + '）') +
    (channel === null || channel.listening !== true
      ? '；身份通道未监听'
      : '；身份通道 127.0.0.1:' + String(channel.port) + ' 请求 ' + String(channel.requests ?? 0) +
        '（放行 ' + String(channel.allowed ?? 0) + ' / 拒绝 ' + String(channel.denied ?? 0) + '）') +
    // Pipe-connection outcome, split honestly: ENOHANDLE/deferred is not a
    // policy denial; only `denied` is. Older pods do not report these.
    (typeof attestation.denied === 'number'
      ? '；管道连接 deferred=' + String(attestation.deferred ?? 0) + ' denied=' + String(attestation.denied)
      : '')
  const last = channel?.last ?? null
  if (last === null) return head + '；还没有客户端做过身份校验'
  return head + '；最近一次：pid=' + String(last.pid ?? '?') +
    ' image=' + String(last.facts?.imagePath ?? '?') +
    ' integrity=' + String(last.facts?.integrity ?? '?') +
    ' restricted=' + String(last.facts?.restrictedSidCount ?? '?') +
    ' → ' + (last.allowed === true ? '放行' : '拒绝')
}

function renderRecoveryLine(info) {
  if (info === null || info === undefined) return '未接入（没有恢复扫描器）'
  const pending = typeof info.pending === 'number' ? info.pending : 0
  const file = typeof info.file === 'string' && info.file !== '' ? '（清单 ' + info.file + '）' : ''
  const head = pending === 0
    ? '没有待恢复的 pod_exec 调用' + file
    : '待恢复 ' + String(pending) + ' 条' + file + (info.running === true ? '，轮询中' : '')
  const last = info.last !== null && info.last !== undefined && typeof info.last === 'object' ? info.last : null
  if (last === null) return head
  return head + '；上一轮：扫描 ' + String(last.scanned ?? 0) + ' 条（complete ' + String(last.completed ?? 0) +
    '、fail ' + String(last.failed ?? 0) + '、仍在跑 ' + String(last.running ?? 0) +
    '、放弃 ' + String(last.dropped ?? 0) + '、待重试 ' + String(last.retrying ?? 0) + '）' +
    (last.skipped === true ? '；服务不可用已跳过：' + String(last.reason ?? '') : '')
}

// ---------------------------------------------------------------------------
// Live executor budgets: native `timeoutMs` / `maxOutputBytes`
// ---------------------------------------------------------------------------
//
// The escape pod must follow the NATIVE shell executor's live settings, not its
// own constants: the user edits "命令超时（毫秒）" / "单流输出上限（字节）" on the
// Settings page (the `pwsh-sandbox` / `bash-sandbox` Loader entry), and the very
// next `pod_*` call has to use the new values. Therefore nothing here is
// cached at plugin load, at pod spawn, or at `createTools` time — every tool
// call runs {@link resolveLiveLimits} again.
//
// Why "live" is not the same as "read the YAML": the Settings page writes the
// profile patch and the Loader reconciles the entry (dsh-config-editor's
// `edit()` -> `reconcileProfilePatches`), so the authoritative values are the
// RUNNING service's own config, which is exactly what the ordered probes below
// read. Sources, best -> worst:
//
//   1. `shell.resolve` — the public `ctx.shell` seam
//      (`ShellExecutor.resolve()`: "apply implementation-owned defaults and
//      caps to a request"). `PwshLocalExecutor.resolve()` fills `timeoutMs`
//      from `config.timeoutMs.get()` (capped at `maxTimeoutMs`) and
//      `stdoutMaxBytes` from `config.maxOutputBytes.get()`. Executor-agnostic:
//      works for `bash-local` too. Preferred because it is the documented seam
//      and it already applies the native caps.
//   2. `shell.config` — the same live schemastery refs
//      (`shell.config.timeoutMs.get()`), used when `resolve()` is unavailable
//      or throws (e.g. a half-loaded sandbox policy).
//   3. `settings:<entry>` — `ctx.get('settings').describe()`, the settings
//      service's projection of the live entry config. Heavier (it projects
//      every entry) and only reaches entries with volatile fields.
//   4. `fallback:native-defaults` — nothing answered; use the native schema
//      defaults (120000 / 64000) and SAY SO in `pod_status.limits.source`,
//      including every probe's failure reason.

/**
 * `ctx.get` that never throws: services may be absent, disposed, or joined to a
 * different isolate.
 * @param {any} ctx @param {string} name @param {string[] | null} [reasons]
 */
function serviceOrNull(ctx, name, reasons = null) {
  if (ctx === null || ctx === undefined) {
    reasons?.push('没有 Host context，无法读取 ' + name)
    return null
  }
  if (typeof ctx.get !== 'function') {
    reasons?.push('Host context 没有 ctx.get，无法读取 ' + name)
    return null
  }
  try {
    const value = ctx.get(name)
    if (value === null || value === undefined) {
      reasons?.push('ctx.get("' + name + '") 没有活动实现')
      return null
    }
    return value
  } catch (error) {
    reasons?.push('ctx.get("' + name + '") 抛错：' + messageOf(error))
    return null
  }
}

/** @param {unknown} value @returns {number | null} a positive integer, or null */
function positiveIntOf(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null
  return Math.max(1, Math.trunc(value))
}

/** @param {any} shell @returns {string | null} */
function executorNameOf(shell) {
  const name = shell?.constructor?.name
  return typeof name === 'string' && name !== '' && name !== 'Object' ? name : null
}

/**
 * Probe 1: ask the live executor through its public `resolve()` seam.
 * @param {any} shell @param {string[]} reasons
 * @returns {{ timeoutMs: number, maxOutputBytes: number } | null}
 */
function limitsFromShellResolve(shell, reasons) {
  if (typeof shell.resolve !== 'function') {
    reasons.push('shell.resolve 不是函数')
    return null
  }
  /** @type {any} */
  let spec
  try {
    spec = shell.resolve({ command: LIMITS_PROBE_COMMAND })
  } catch (error) {
    reasons.push('shell.resolve 抛错：' + messageOf(error))
    return null
  }
  const timeoutMs = positiveIntOf(spec?.timeoutMs)
  const maxOutputBytes = positiveIntOf(spec?.stdoutMaxBytes)
  if (timeoutMs === null || maxOutputBytes === null) {
    reasons.push(
      'shell.resolve 没有给出可用预算（timeoutMs=' + String(spec?.timeoutMs) + ', stdoutMaxBytes=' + String(spec?.stdoutMaxBytes) + '）',
    )
    return null
  }
  return { timeoutMs, maxOutputBytes }
}

/** @param {any} config @param {string} key @returns {number | null} */
function readLiveConfigNumber(config, key) {
  if (config === null || typeof config !== 'object') return null
  const ref = config[key]
  // A schemastery live ref exposes get(); a plain object is accepted too so a
  // test double (or a future non-schemastery executor) still works.
  if (typeof ref === 'number') return positiveIntOf(ref)
  if (ref !== null && typeof ref === 'object' && typeof ref.get === 'function') {
    try {
      return positiveIntOf(ref.get())
    } catch {
      return null
    }
  }
  return null
}

/**
 * Probe 2: the executor's own live config refs.
 * @param {any} shell @param {string[]} reasons
 * @returns {{ timeoutMs: number, maxOutputBytes: number } | null}
 */
function limitsFromShellConfig(shell, reasons) {
  const config = shell?.config
  if (config === null || typeof config !== 'object') {
    reasons.push('shell.config 不可读（执行器没有暴露 live config）')
    return null
  }
  const timeoutMs = readLiveConfigNumber(config, 'timeoutMs')
  const maxOutputBytes = readLiveConfigNumber(config, 'maxOutputBytes')
  if (timeoutMs === null || maxOutputBytes === null) {
    reasons.push(
      'shell.config 没有可用的 timeoutMs/maxOutputBytes（timeoutMs=' + String(timeoutMs) + ', maxOutputBytes=' + String(maxOutputBytes) + '）',
    )
    return null
  }
  return { timeoutMs, maxOutputBytes }
}

/**
 * Loader entry ids that own the native shell executor, most specific first. The
 * Settings page itself uses these ids (`dsh-client-ui-settings-shell`'s
 * `PWSH_NS`/`BASH_NS`), and `dsh-settings` keys `describe()` rows by them.
 * @param {NodeJS.Platform} platform
 */
function shellSettingsEntries(platform) {
  return platform === 'win32'
    ? ['pwsh-sandbox', 'bash-sandbox', 'shell']
    : ['bash-sandbox', 'pwsh-sandbox', 'shell']
}

/**
 * Probe 3: the settings service's projection of the live entry value.
 * @param {any} ctx
 * @param {NodeJS.Platform} platform
 * @param {string[]} reasons
 * @returns {{ timeoutMs: number, maxOutputBytes: number, entry: string } | null}
 */
function limitsFromSettings(ctx, platform, reasons) {
  const settings = serviceOrNull(ctx, 'settings', reasons)
  if (settings === null) return null
  if (typeof settings.describe !== 'function') {
    reasons.push('settings.describe 不是函数')
    return null
  }
  /** @type {any[]} */
  let rows
  try {
    rows = settings.describe({ redactSecrets: true })
  } catch (error) {
    reasons.push('settings.describe() 抛错：' + messageOf(error))
    return null
  }
  if (!Array.isArray(rows)) {
    reasons.push('settings.describe() 没有返回数组')
    return null
  }
  for (const entry of shellSettingsEntries(platform)) {
    const row = rows.find((candidate) => candidate?.ns === entry)
    if (row === undefined) continue
    const timeoutMs = positiveIntOf(row.value?.timeoutMs)
    const maxOutputBytes = positiveIntOf(row.value?.maxOutputBytes)
    if (timeoutMs === null || maxOutputBytes === null) {
      reasons.push('settings 条目 ' + entry + ' 没有可用的 timeoutMs/maxOutputBytes')
      continue
    }
    return { timeoutMs, maxOutputBytes, entry }
  }
  reasons.push('settings.describe() 里没有 ' + shellSettingsEntries(platform).join(' / ') + ' 的可用值')
  return null
}

/**
 * Resolve the live native budgets ONCE, trying every supported source in order.
 * Never throws: the returned object always has positive numbers and an honest
 * `source` (with `reasons` listing why better sources were skipped).
 *
 * @param {any} ctx Host plugin context (may be null in tests / recovery paths)
 * @param {{ platform?: NodeJS.Platform }} [options]
 * @returns {{
 *   timeoutMs: number,
 *   maxOutputBytes: number,
 *   source: 'shell.resolve' | 'shell.config' | string | 'fallback:native-defaults',
 *   executor: string | null,
 *   entry: string | null,
 *   reasons: string[],
 * }}
 */
export function resolveShellLimits(ctx, options = {}) {
  const platform = options.platform ?? process.platform
  /** @type {string[]} */
  const reasons = []
  const shell = serviceOrNull(ctx, 'shell', reasons)
  if (shell !== null) {
    const viaResolve = limitsFromShellResolve(shell, reasons)
    if (viaResolve !== null) {
      return { ...viaResolve, source: 'shell.resolve', executor: executorNameOf(shell), entry: null, reasons }
    }
    const viaConfig = limitsFromShellConfig(shell, reasons)
    if (viaConfig !== null) {
      return { ...viaConfig, source: 'shell.config', executor: executorNameOf(shell), entry: null, reasons }
    }
  }
  const viaSettings = limitsFromSettings(ctx, platform, reasons)
  if (viaSettings !== null) {
    const { entry, ...values } = viaSettings
    return { ...values, source: 'settings:' + entry, executor: null, entry, reasons }
  }
  return {
    timeoutMs: NATIVE_DEFAULT_TIMEOUT_MS,
    maxOutputBytes: NATIVE_DEFAULT_MAX_OUTPUT_BYTES,
    source: 'fallback:native-defaults',
    executor: null,
    entry: null,
    reasons,
  }
}

/**
 * The per-call budgets the tools actually use. `maxOutputBytes` follows the
 * live native value; `settings.modelOutputLimitBytes` is an OPTIONAL deployment
 * ceiling (`0` = no ceiling, i.e. follow the native value exactly). The ceiling
 * never raises the window above the native budget — it can only tighten it.
 *
 * @param {any} ctx @param {{ modelOutputLimitBytes?: number } | null | undefined} settings
 * @param {{ platform?: NodeJS.Platform }} [options]
 */
export function resolveLiveLimits(ctx, settings, options = {}) {
  const live = resolveShellLimits(ctx, options)
  const ceiling = typeof settings?.modelOutputLimitBytes === 'number' && settings.modelOutputLimitBytes > 0
    ? Math.trunc(settings.modelOutputLimitBytes)
    : 0
  const maxOutputBytes = ceiling > 0 ? Math.min(live.maxOutputBytes, ceiling) : live.maxOutputBytes
  return {
    maxOutputBytes,
    timeoutMs: live.timeoutMs,
    source: live.source,
    executor: live.executor,
    entry: live.entry,
    modelCeiling: ceiling > 0 ? ceiling : null,
    native: { maxOutputBytes: live.maxOutputBytes, timeoutMs: live.timeoutMs },
    reasons: live.reasons,
  }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const RESULT_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    op: { type: 'string' },
    jobId: { type: 'string' },
    runnerPid: { type: 'number' },
    podPid: { type: 'number' },
    generation: { type: 'number' },
    status: { type: 'string' },
    // `pod_freeze` projection. Only the NON-NULL fields are declared here:
    // DSH rejects type arrays, and `frozenAt`/`frozenForMs` may legitimately be
    // null, so `additionalProperties: true` admits them undeclared (same rule
    // as `running`/`exitCode` above).
    action: { type: 'string' },
    frozen: { type: 'boolean' },
    thawable: { type: 'boolean' },
    // `running` / `exitCode` may be null (job still running); DSH rejects type
    // arrays, and `additionalProperties: true` already admits them, so they are
    // intentionally left undeclared here.
    text: { type: 'string' },
    nextOffset: { type: 'number' },
    totalBytes: { type: 'number' },
    message: { type: 'string' },
    jobs: { type: 'array', items: { type: 'object', additionalProperties: true } },
  },
  additionalProperties: true,
}

/**
 * @param {ReturnType<typeof createPodClient>} pod
 * @param {() => any} getSandbox
 * @param {{ outputChunkBytes: number, modelOutputLimitBytes: number, stateDir?: string }} settings
 *   normalized plugin config. `outputChunkBytes` is only the pod's fallback
 *   window (sent at spawn); `modelOutputLimitBytes` is an optional ceiling on
 *   the LIVE native window (`0` = no ceiling); `stateDir` is the pod's state
 *   directory, where the shared `settings.json` (the new-command gate) lives.
 * @param {ReturnType<typeof createAdoptionManager> | null} [adoptions]
 * @param {(message: string) => void} [log]
 * @param {any} [resumeCtx] Host plugin context, used to reach the optional
 *   `resumableToolCalls` service (`ctx.get`), the `session/event` feed
 *   (`ctx.on`), and — on every tool call — the LIVE native shell budgets
 *   (`ctx.get('shell')` / `ctx.get('settings')`, see `resolveShellLimits`).
 *   `null` degrades `pod_exec` to a plain blocking call and labels the budgets
 *   `fallback:native-defaults`.
 * @param {{ store?: any, recovery?: any, isDisposing?: () => boolean, shells?: { detect?: Function, now?: number | (() => number), store?: any } } | null} [execOptions] the pending-exec
 *   store `pod_exec` writes its hold into, the recovery scanner reported by
 *   `pod_status`, and the "Host is disposing" predicate that keeps a released
 *   hold recoverable. `shells` is the shell-selection test seam (a fake
 *   detector/clock/store); production passes nothing and gets the real
 *   detection plus the shared per-stateDir session store. All are optional:
 *   `null` keeps the previous behaviour.
 */
export function createTools(pod, getSandbox, settings, adoptions = null, log = () => {}, resumeCtx = null, execOptions = null) {
  /**
   * Live native budgets. Deliberately a FUNCTION, not a value: the pod can
   * outlive the Host, the user can save the Settings page at any moment, and a
   * value captured here (or at pod spawn) would be stale by the next call.
   * `resumeCtx` is the Host plugin context; `null` degrades to the labelled
   * native defaults (see `resolveShellLimits`).
   */
  const liveLimits = () => resolveLiveLimits(resumeCtx, settings)

  /** @param {unknown} error @param {string} action */
  function contextualize(error, action) {
    if (error instanceof PodError) return error
    return new PodError(messageOf(error) + '\n本次 ' + action + ' 没有伪造任何结果。', 'EPODCERROR')
  }

  /** Keep ctx.jobs in step with the pod's live jobs before returning a view. */
  const syncAdoptions = async (hint) => {
    if (adoptions === null) return null
    try {
      return await adoptions.ensureAdopted(hint)
    } catch (error) {
      return { adopted: 0, reason: messageOf(error) }
    }
  }

  /* ------------------------------------------------------- shell selection -- */

  /**
   * Test seams for `pod_shell` (and the status line): a fake detector, clock
   * or store. Production passes nothing, which means the real `detectShells`
   * (60s version cache) and the shared per-stateDir store. Nothing here ever
   * reaches the pod client.
   * @type {{ detect?: Function, now?: number | (() => number), store?: any }}
   */
  const shellInjection = execOptions !== null && execOptions !== undefined &&
    execOptions.shells !== null && typeof execOptions.shells === 'object'
    ? execOptions.shells
    : {}

  /** @returns {any} the deps bag `resolveAppliedShell` takes. */
  function shellDependencies() {
    return shellDepsFromSettings(settings, {
      ...(typeof shellInjection.detect === 'function' ? { detect: shellInjection.detect } : {}),
      ...(shellInjection.now === undefined ? {} : { now: shellInjection.now }),
      ...(shellInjection.store === undefined ? {} : { store: shellInjection.store }),
    })
  }

  /**
   * Snapshot of every shell kind for one session: candidates, the stored
   * choices and the applied decision. Pure Host work (detection + two files), so
   * `pod_shell` can answer without connecting to — or waking — the pod.
   * @param {any} hint
   */
  function shellSnapshot(hint) {
    const deps = shellDependencies()
    const detect = typeof shellInjection.detect === 'function' ? shellInjection.detect : detectShells
    /** @type {any} */
    let detection = null
    let detectionError = null
    try {
      detection = detect({
        config: deps.config,
        ...(shellInjection.now === undefined ? {} : { now: shellInjection.now }),
      })
      if (detection === null || typeof detection !== 'object' || !Array.isArray(detection.groups)) {
        detectionError = '命令行探测没有返回分组'
        detection = null
      }
    } catch (error) {
      // A failed probe must not fail the tool: the applied decisions below
      // degrade to the legacy path and the text says why.
      detectionError = messageOf(error)
      detection = null
    }
    const defaults = readPodSettings(deps.stateDir).shells
    const sessionId = typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null
    const stored = sessionId === null ? null : deps.store.session(sessionId)
    const kinds = []
    for (const kind of SHELL_KINDS) {
      const sessionChoice = stored === null
        ? null
        : kind === 'bash'
          ? stored.bash ?? null
          : kind === 'powershell'
            ? stored.powershell ?? null
            : null
      const applied = resolveAppliedShell(kind, hint, { ...deps, detection, defaults, sessionChoice })
      const group = detection === null
        ? null
        : detection.groups.find((entry) => entry !== null && typeof entry === 'object' && entry.kind === kind) ?? null
      const candidates = (group !== null && Array.isArray(group.candidates) ? group.candidates : [])
        .filter((candidate) => candidate !== null && typeof candidate === 'object')
        .map((candidate) => ({
          id: String(candidate.id ?? ''),
          label: shellCandidateName(candidate),
          path: String(candidate.path ?? ''),
          version: typeof candidate.version === 'string' ? candidate.version : null,
          source: typeof candidate.source === 'string' ? candidate.source : null,
          available: candidate.available === true,
          note: typeof candidate.note === 'string' ? candidate.note : null,
          current: applied.id !== null && candidate.id === applied.id,
          isDefault: kind !== 'cmd' && defaults[kind] === candidate.id,
          fromSession: kind !== 'cmd' && sessionChoice !== null && sessionChoice === candidate.id,
        }))
      kinds.push({
        kind,
        selectable: kind !== 'cmd',
        fixed: kind === 'cmd',
        sessionChoice: sessionChoice ?? null,
        defaultChoice: kind === 'cmd' ? null : defaults[kind],
        applied,
        candidates,
      })
    }
    return {
      stateDir: deps.stateDir,
      sessionId,
      generatedAt: typeof detection?.generatedAt === 'string' ? detection.generatedAt : new Date().toISOString(),
      detectionError,
      defaults,
      kinds,
      applied: Object.fromEntries(kinds.map((entry) => [entry.kind, entry.applied])),
      warning: null,
    }
  }

  /**
   * The model-facing `pod_shell` text: one applied line per kind, the
   * fallback reason when a choice was dropped, then every candidate.
   * @param {any} state
   */
  function renderShellState(state) {
    const lines = ['本会话命令行（会话覆盖 > 设置默认 > 自动探测）']
    const indent = ' '.repeat(12)
    for (const entry of state.kinds) {
      const current = entry.candidates.find((candidate) => candidate.current) ?? null
      const name = current === null ? basename(entry.applied.path) : current.label
      const head = String(entry.kind).padEnd(10) + ' → ' + name + '  ' + entry.applied.path
      if (entry.fixed) {
        lines.push(head + '  固定（不可选）')
        continue
      }
      lines.push(head + '  来源：' + shellSourceText(entry.applied.source))
      const fallback = entry.applied.fallback
      if (fallback !== null) {
        lines.push(
          indent + '└ 回落：' + String(fallback.from) + ' 不可用（' + String(fallback.reason) + '）→ ' +
            (fallback.to === null ? '无可用候选' : String(fallback.to)),
        )
      }
    }
    lines.push('候选（* = 当前应用；不可用项不会被自动选中）：')
    for (const entry of state.kinds) {
      if (entry.fixed) {
        lines.push('  cmd')
        lines.push('    （系统只有一个 ' + (entry.candidates[0]?.path ?? 'cmd.exe') + '，固定不可选）')
        continue
      }
      lines.push('  ' + entry.kind)
      if (entry.candidates.length === 0) {
        lines.push('    （没有探测到候选）')
        continue
      }
      for (const candidate of entry.candidates) {
        const marks = []
        if (candidate.current) marks.push('当前应用')
        if (candidate.fromSession) marks.push('会话覆盖')
        if (candidate.isDefault) marks.push('设置默认')
        if (!candidate.available) marks.push('不可用')
        lines.push(
          '    ' + (candidate.current ? '*' : ' ') + ' ' + candidate.id + '  ' + candidate.label + '  ' + candidate.path +
            (marks.length === 0 ? '' : '  [' + marks.join('，') + ']'),
        )
      }
    }
    if (state.detectionError !== null) {
      lines.push('探测失败：' + state.detectionError + '（当前按回落路径执行；可稍后用 action:"list" 重试）')
    }
    lines.push('用法：action:"use" shell="powershell|bash" id="<候选 id>"；action:"reset"（省略 shell 时清除全部类型）。cmd 只有系统一个版本，固定不可选。')
    // The user-facing contract, stated where it is read: a choice is an
    // OVERRIDE, not a replacement policy for the machine's stock interpreter.
    lines.push('说明：命令行是可选覆盖，不会强制替换 DSH/系统原装的解释器；不做选择时沿用设置默认/自动探测，行为与以前一致。')
    lines.push('建议先用默认（原装）命令行，只有在它不可用、启动失败或版本不满足时才切换。所选路径运行期不可用时按「会话选择 → 设置默认 → 自动探测」逐级回落，并在结果里说明。')
    return lines.join('\n')
  }

  /**
   * Owner of one pod status row. A current pod reports `sessionId` (explicit
   * `null` = unowned). A pod that predates the boundary omits the field; in
   * that case this Host can still know the owner of a job it started itself,
   * but cannot invent one for anything else.
   * @param {any} job
   */
  function jobSessionIdOf(job) {
    if (job !== null && typeof job === 'object' && Object.prototype.hasOwnProperty.call(job, 'sessionId')) {
      return typeof job.sessionId === 'string' && job.sessionId !== '' ? job.sessionId : null
    }
    const known = typeof pod.ownerOf === 'function' ? pod.ownerOf(job?.jobId) : null
    return known?.known === true ? known.sessionId ?? null : null
  }

  /**
   * Adoption warnings can name pod job ids; a status projection must not show
   * those for jobs the caller may not see.
   * @param {any} sync
   * @param {Set<string>} visibleIds
   */
  function visibleAdoptionSync(sync, visibleIds) {
    if (sync === null || sync === undefined || !Array.isArray(sync.jobs)) return sync
    return { ...sync, jobs: sync.jobs.filter((row) => visibleIds.has(String(row?.podJobId ?? ''))) }
  }

  /** @type {any} */
  const runTool = {
    name: 'pod_run',
    description:
      '在「逃生舱」后台启动一条命令：pod 是脱离 DSH 托管的 detached 进程（Medium 完整性），DSH 重启后命令继续跑，且本工具不设超时（timeoutMs 只作用于前台 pod_exec）。输出写入工作区之外的账本（默认 %LOCALAPPDATA%\\dsh-escape-pod-core\\jobs\\<jobId>\\，绝不放工作区内，否则被托管命令能伪造记录）。命令跟随当前 DSH 会话的文件策略：read-only 只能读不能写；workspace-write 只有工作区 + 会话临时目录可写。每次调用由 Host 现签一份只属于本次的受限 runner 前缀，命令在 Low 完整性 + WRITE_RESTRICTED 令牌与 kill-on-close Job 里跑；前缀不合规/过期时 fail-closed 不执行并返回结构化错误。需要更宽访问时用 sandbox_permissions + justification 申请：Host 弹审批，只有「仅本次允许」（allowed-once）才执行且只对这一次调用有效；被拒绝（含超时/无审批服务）不要重试或绕过；申请比当前会话更窄的模式会被直接拒绝。会话为 danger-full-access（或本次审批到该模式）时不带任何沙箱前缀，以 pod 自身 Medium 令牌直接运行——这会削弱「命令不可能改账本」的保证：命令与用户同权，可改写账本及任何用户可写文件。返回 jobId 与 runnerPid；用 pod_output 读输出、pod_kill 结束。job 记录发起会话：默认只能操作本会话的 job；其它会话（以及旧账本无主）的 job 需 adopt: true 显式接管。',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: '要执行的命令文本：默认作为 PowerShell 的 -Command 参数；shell=cmd 时为 cmd /c 的文本；shell=bash 时为 bash -c 的脚本文本' },
        shell: { type: 'string', enum: ['powershell', 'cmd', 'bash'], description: '可选：命令解释器。默认 powershell（本机为 Windows PowerShell 5.1，未装 pwsh 7）；cmd 走 cmd.exe /d /s /c（中文输出建议先 chcp 65001）；bash 走 bash --noprofile --norc -c（自动发现 DSH 自带的 PortableGit，也可用配置 bashPath 或环境变量 DSH_ESCAPE_POD_BASH 指定；系统 Git 2.49 的 bash 在受限令牌下会崩，2.56+ 的 PortableGit 实测可用）。具体路径/版本可用 pod_shell 查看并为当前会话切换：那是可选覆盖，不强制替换原装解释器，不切换时行为与以前一致。' },
        description: { type: 'string', maxLength: 200, description: '可选：给这条命令的一句话说明（用于工具卡片/日志；不进入 job label）' },
        cwd: { type: 'string', description: '工作目录：必须位于本次 policy 的 workspace 内（绝对路径或相对 workspace 的路径；越界会 fail-closed 拒绝），默认 workspace 根' },
        sandbox_permissions: {
          type: 'string',
          enum: ['workspace-write', 'danger-full-access'],
          description: '在真实拒绝后，用最小够用的更宽模式重试这次命令，并给出理由（justification）；Host 会弹出 DSH 审批，只有「仅本次允许」才执行，且审批只对本次调用有效。目标等于当前会话模式时直接执行、不审批；比当前会话更窄的模式会被拒绝。不要绕过被拒绝的决定。',
        },
        justification: {
          type: 'string',
          description: '一句话说明为什么这次调用需要更宽权限（用用户的语言）。改变 sandbox_permissions 时必填。',
        },
      },
      required: ['command'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '逃生舱：启动命令', kind: 'other' }),
    async execute(args, exec) {
      const command = typeof args?.command === 'string' ? args.command : ''
      if (command.trim() === '') throw new PodError('command 不能为空', 'EARGS')
      if (command.length > MAX_COMMAND_CHARS) throw new PodError('command 太长（上限 ' + MAX_COMMAND_CHARS + ' 字符）', 'EARGSIZE')
      const description = typeof args?.description === 'string' && args.description.trim() !== ''
        ? truncate(args.description.trim(), 200)
        : null
      const hint = policyHint(exec)
      try {
        // The session's LIVE file policy is this call's default. Asking for a
        // wider mode goes through the real DSH approval dialog and is valid for
        // THIS call only; a rejection throws before anything reaches the pod.
        const standing = resolveStandingPolicy(resumeCtx, exec, hint)
        const policy = await approveEscalation(resumeCtx, exec, 'pod_run', args, standing, hint)
        const { response, prepared, shell: appliedShell } = await pod.run(hint, {
          command,
          shell: args?.shell,
          cwd: args?.cwd,
          description,
          mode: policy.mode,
          escalated: policy.escalated,
          // The prefix is minted for the POLICY workspace/session, while the
          // pod records job ownership from this agent's own session id.
          prefixHint: { sessionId: policy.sessionId, workspaceRoot: policy.workspaceRoot },
          // Last-moment authority check: the user can move the session switch
          // while the prefix is being signed. No command starts when it changed.
          assertAuthority: () => assertStandingUnchanged(resumeCtx, exec, standing, hint),
        })
        // Adopt immediately (base offset 0) so job_list/job_output/job_kill see it.
        const registryJobId = adoptions === null ? null : adoptions.adoptNewJob(response, hint, command)
        return {
          ok: true,
          op: 'run',
          jobId: response.jobId,
          sessionId: response.sessionId ?? hint.sessionId ?? null,
          registryJobId,
          runnerPid: response.runnerPid ?? null,
          podPid: response.podPid ?? null,
          status: 'running',
          command: truncate(command, 400),
          description: response.description ?? description,
          cwd: response.cwd ?? null,
          startedAt: response.startedAt ?? null,
          ledgerDir: join(pod.stateDir, 'jobs', String(response.jobId)),
          enforcement: prepared.enforcement,
          /** The interpreter this command actually ran with (and its source). */
          shell: appliedShell ?? null,
          /** The file policy this call ran under, and whether it was widened. */
          policy: {
            mode: policy.mode,
            standingMode: standing.mode,
            escalated: policy.escalated,
            unescorted: policy.mode === 'danger-full-access',
            source: policy.source,
            workspaceRoot: policy.workspaceRoot,
          },
          prefix: prepared.unescorted === true
            ? { fingerprint: 'unescorted', perCall: true, unescorted: true, mode: policy.mode, workspaceRoot: policy.workspaceRoot }
            : { fingerprint: prepared.fingerprint, perCall: true, ...describePrefix(prepared.profile) },
          template: pod.template(),
          policyVariant: prepared.policyVariant,
          pipeName: pod.pipeName,
          connection: pod.mode(),
          spawnInfo: pod.spawnInfo(),
          message: renderRunText(response, prepared, registryJobId, policy, appliedShell ?? null),
        }
      } catch (error) {
        throw contextualize(error, 'pod_run')
      }
    },
  }

  /**
   * Block until one pod job stops running. It reuses the `output` op that
   * `pod_output` reads with (a tiny window: only the ledger status matters),
   * so the foreground form adds no second execution or read path — it only
   * waits, then assembles one result.
   *
   * The native deadline is enforced by the POD (`run.timeoutMs` arms a timer
   * next to the process, so it keeps working across a Host restart). The
   * `deadlineAt` fallback below exists only for a pod that ignores the field
   * (an older pod reused through handover); it kills through the same
   * `killRecord` path and tags the kill with `timeoutMs`, so the ledger still
   * says "killed by timeout" rather than "killed by a user".
   *
   * @param {any} hint
   * @param {string} jobId
   * @param {AbortSignal | undefined} signal caller cancellation (host teardown
   *   or an explicit interrupt). Never kills the pod command: it lives outside
   *   DSH by design.
   * @param {any} hold the `createExecHold` handle (kept alive while we wait)
   * @param {number} [deadlineAt] Host-side fallback deadline (0 = none)
   * @param {number} [timeoutMs] the live native timeout, attached to that kill
   * @returns {Promise<{ aborted: boolean, timedOut: boolean, hostKilled: boolean }>}
   */
  async function waitForExec(hint, jobId, signal, hold = null, deadlineAt = 0, timeoutMs = 0) {
    // Long commands must not let the hold's deadline fire mid-wait (the service
    // would then append a result the platform is about to write itself).
    let nextRefresh = Date.now() + EXEC_HOLD_REFRESH_MS
    for (;;) {
      if (signal?.aborted === true) return { aborted: true, timedOut: false, hostKilled: false }
      const poll = await pod.output(hint, { jobId, from: 0, maxBytes: EXEC_POLL_BYTES })
      if (poll?.running !== true) {
        return { aborted: false, timedOut: poll?.timedOut === true, hostKilled: false }
      }
      if (signal?.aborted === true) return { aborted: true, timedOut: false, hostKilled: false }
      // A frozen command's budget is paused INSIDE the pod; re-anchor the
      // fallback or it would kill at the original wall-clock deadline.
      deadlineAt = hostFallbackDeadline(deadlineAt, poll)
      if (deadlineAt > 0 && Date.now() >= deadlineAt) {
        log(EXEC_TOOL_NAME + '：pod 没有在 timeoutMs=' + String(timeoutMs) + ' 内自行终止 job ' + jobId + '，改由 Host 兜底终止')
        let hostKilled = false
        try {
          const killed = await pod.kill(hint, timeoutMs > 0 ? { jobId, timeoutMs } : { jobId })
          hostKilled = killed?.killed === true
        } catch (error) {
          log(EXEC_TOOL_NAME + '：Host 兜底终止失败：' + messageOf(error))
        }
        return { aborted: false, timedOut: true, hostKilled }
      }
      if (Date.now() >= nextRefresh) {
        nextRefresh = hold?.refresh?.() === true ? Date.now() + EXEC_HOLD_REFRESH_MS : Number.POSITIVE_INFINITY
      }
      await sleep(EXEC_POLL_INTERVAL_MS)
    }
  }

  /**
   * Foreground form: same spawn path as `pod_run` (`pod.run` mints the same
   * per-call prefix and sends the same `run` op), then block until the ledger
   * says the command settled.
   * @type {any}
   */
  const execTool = {
    name: EXEC_TOOL_NAME,
    description:
      '在「逃生舱」前台执行一条命令：阻塞到结算，一次调用返回一条结果（stdout 在前，[stderr] 段在后，非零退出码给 [exit code: N]，末行 [status: completed|killed|failed]），不需要再读输出，结果里没有 jobId/偏移/游标。执行路径与 pod_run 完全相同（pod 是 detached 进程，DSH 重启不终止命令），但本工具有超时：跟随设置页实时 timeoutMs，超时即终止、返回部分输出、状态如实写 killed 并标注毫秒数；pod_run 后台永远不限时。命令跟随当前 DSH 会话的文件策略：read-only 能读不能写；workspace-write 只有工作区 + 会话临时目录可写（Low 完整性 + WRITE_RESTRICTED 令牌与 kill-on-close Job）。需要写盘时用 sandbox_permissions + justification 申请更宽模式：只有「仅本次允许」才执行且只对这一次调用有效；被拒绝不要重试或绕过；只能变宽不能变窄。danger-full-access（或本次审批到该模式）时不带任何沙箱前缀，以 pod 自身 Medium 令牌直接运行：会削弱「命令不可能改账本」的保证，命令与用户同权，可改写账本及任何用户可写文件。若本 Host 提供 resumableToolCalls，等待期间 DSH 重启不再补 TOOL_OUTCOME_UNKNOWN，而是先写"被挂起"结果，新 Host 激活后连 pod 读同一账本把真实结果补回这条调用（不重跑命令、不需要模型重试）；无该服务则退化为普通阻塞调用，重启会丢掉结果；DSH 直接崩溃时挂起也无能为力。输出裁剪同 pod_output（maxOutputBytes 窗口、行/UTF-8 对齐、[output truncated]），完整文本在账本 out.log。',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: '要执行的命令文本：默认作为 PowerShell 的 -Command 参数；shell=cmd 时为 cmd /c 的文本；shell=bash 时为 bash -c 的脚本文本' },
        shell: { type: 'string', enum: ['powershell', 'cmd', 'bash'], description: '可选：命令解释器。默认 powershell（本机为 Windows PowerShell 5.1，未装 pwsh 7）；cmd 走 cmd.exe /d /s /c（中文输出建议先 chcp 65001）；bash 走 bash --noprofile --norc -c（自动发现 DSH 自带的 PortableGit，也可用配置 bashPath 或环境变量 DSH_ESCAPE_POD_BASH 指定；系统 Git 2.49 的 bash 在受限令牌下会崩，2.56+ 的 PortableGit 实测可用）。具体路径/版本可用 pod_shell 查看并为当前会话切换：那是可选覆盖，不强制替换原装解释器，不切换时行为与以前一致。' },
        description: { type: 'string', maxLength: 200, description: '可选：给这条命令的一句话说明（用于工具卡片/日志；不进入 job label）' },
        cwd: { type: 'string', description: '工作目录：必须位于本次 policy 的 workspace 内（绝对路径或相对 workspace 的路径；越界会 fail-closed 拒绝），默认 workspace 根' },
        sandbox_permissions: {
          type: 'string',
          enum: ['workspace-write', 'danger-full-access'],
          description: '在真实拒绝后，用最小够用的更宽模式重试这次命令，并给出理由（justification）；Host 会弹出 DSH 审批，只有「仅本次允许」才执行，且审批只对本次调用有效。目标等于当前会话模式时直接执行、不审批；比当前会话更窄的模式会被拒绝。不要绕过被拒绝的决定。',
        },
        justification: {
          type: 'string',
          description: '一句话说明为什么这次调用需要更宽权限（用用户的语言）。改变 sandbox_permissions 时必填。',
        },
      },
      required: ['command'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '逃生舱：前台执行', kind: 'execute' }),
    async execute(args, exec) {
      const command = typeof args?.command === 'string' ? args.command : ''
      if (command.trim() === '') throw new PodError('command 不能为空', 'EARGS')
      if (command.length > MAX_COMMAND_CHARS) throw new PodError('command 太长（上限 ' + MAX_COMMAND_CHARS + ' 字符）', 'EARGSIZE')
      const description = typeof args?.description === 'string' && args.description.trim() !== ''
        ? truncate(args.description.trim(), 200)
        : null
      const hint = policyHint(exec)
      const startedAt = Date.now()
      // Live native budgets: re-read HERE, not at registration or pod spawn
      // (a Settings-page save must affect this very call).
      const limits = liveLimits()
      const timeoutMs = limits.timeoutMs
      /** @type {any} */
      let hold = null
      try {
        // Same policy path as pod_run: the session's standing mode by default,
        // an explicit wider mode only through a one-shot DSH approval, and a
        // last-moment authority check before the request is sent.
        const standing = resolveStandingPolicy(resumeCtx, exec, hint)
        const policy = await approveEscalation(resumeCtx, exec, EXEC_TOOL_NAME, args, standing, hint)
        const { response, shell: appliedShell } = await pod.run(hint, {
          command,
          shell: args?.shell,
          cwd: args?.cwd,
          description,
          timeoutMs,
          mode: policy.mode,
          escalated: policy.escalated,
          prefixHint: { sessionId: policy.sessionId, workspaceRoot: policy.workspaceRoot },
          assertAuthority: () => assertStandingUnchanged(resumeCtx, exec, standing, hint),
        })
        const jobId = String(response.jobId)
        // The pod armed its timer at spawn, which is at or before this instant,
        // so a Host deadline counted from HERE can never precede the pod's own
        // timer. It is only a fallback for a pod that ignores `timeoutMs`; the
        // grace leaves room for the pod's timer to win the race. A FREEZE pauses
        // the pod's timer, and `waitForExec` re-anchors this fallback from each
        // poll's `remainingTimeoutMs` (see `hostFallbackDeadline`).
        const deadlineAt = timeoutMs > 0 ? Date.now() + timeoutMs + EXEC_TIMEOUT_GRACE_MS : 0
        // Register the hold BEFORE the wait starts: `hold` writes its durable
        // file synchronously, so a restart checkpoint written after this point
        // always finds this call claimed.
        hold = createExecHold(resumeCtx, {
          callId: typeof exec?.callId === 'string' ? exec.callId : '',
          jobId,
          deadlineMs: EXEC_HOLD_DEADLINE_MS,
          log,
          // The pending list is the other half: it is what the next boot reads
          // to find this call and answer it from the ledger.
          store: execOptions?.store ?? null,
          // Host teardown must never be mistaken for "this call is settled".
          isDisposing: execOptions?.isDisposing ?? null,
        })
        if (hold.available !== true) log(EXEC_TOOL_NAME + ': 可跨重启挂起不可用（' + String(hold.reason) + '），退化为普通阻塞调用')
        const waited = await waitForExec(hint, jobId, exec?.signal, hold, deadlineAt, timeoutMs)
        // One full read for the live native window, whatever the polls saw.
        const finalResponse = await pod.output(hint, { jobId, from: 0, maxBytes: limits.maxOutputBytes })
        const rendered = renderExecResult(finalResponse, waited.aborted, {
          timedOut: waited.timedOut === true,
          timeoutMs: waited.timedOut === true ? timeoutMs : null,
          source: limits.source,
        })
        /** @type {Record<string, unknown>} */
        const value = {
          ok: true,
          op: 'exec',
          status: NATIVE_JOB_STATUS[rendered.view.status] ?? 'failed',
          exitCode: rendered.view.exitCode,
          signal: rendered.view.signal,
          text: rendered.view.text,
          chunks: rendered.view.chunks,
          truncated: rendered.view.truncated,
          lossy: rendered.view.lossy,
          durationMs: Date.now() - startedAt,
          command: truncate(command, 400),
          description: description ?? null,
          cwd: typeof finalResponse?.cwd === 'string' ? finalResponse.cwd : null,
          // Was the failure the native deadline? Reported explicitly so neither
          // the model nor a UI has to infer it from `status: killed`.
          timedOut: rendered.view.timedOut === true,
          timeoutMs: rendered.view.timeoutMs ?? null,
          // Where this call's budgets came from, for support/debugging only.
          limits: {
            maxOutputBytes: limits.maxOutputBytes,
            timeoutMs: limits.timeoutMs,
            source: limits.source,
          },
          /**
           * The file policy this call ran under. Kept in the RESULT rather than
           * the text on purpose: the text is byte-identical to what a recovered
           * call renders from the ledger (see `renderExecResult`), and a live
           * line the recovery path cannot reproduce would break that promise.
           */
          policy: {
            mode: policy.mode,
            standingMode: standing.mode,
            escalated: policy.escalated,
            unescorted: policy.mode === 'danger-full-access',
            source: policy.source,
            workspaceRoot: policy.workspaceRoot,
          },
          /**
           * The interpreter this call used. RESULT-only, like `policy`: the
           * message text must stay byte-identical to what a recovered call
           * renders from the ledger (see `renderExecResult`), and the ledger
           * does not remember the shell choice.
           */
          shell: appliedShell ?? null,
          // Service state is reported for the Host/UI; the model only sees `message`.
          resume: {
            available: hold.available === true,
            held: hold.held === true,
            reason: hold.reason ?? null,
          },
          message: rendered.text,
        }
        // The platform writes this call's own tool/result right after execute
        // returns; only then is a `complete` a no-op instead of a duplicate.
        hold.completeAfterCommit({ content: [{ type: 'text', text: rendered.text }], isError: false })
        return value
      } catch (error) {
        hold?.failAfterCommit(EXEC_TOOL_NAME + ' 没有拿到可用的结果：' + messageOf(error))
        throw contextualize(error, 'pod_exec')
      }
    },
  }

  /**
   * Clip registry chunks to the model window without splitting a UTF-8 code
   * point. Returns the chunks actually shown plus whether anything was cut.
   * @param {{ text: string }[]} chunks
   * @param {number} maxBytes
   */
  function clipRegistryChunks(chunks, maxBytes) {
    let remaining = Math.max(0, maxBytes)
    const out = []
    let truncated = false
    for (const chunk of chunks) {
      const bytes = Buffer.from(chunk.text, 'utf8')
      if (bytes.length <= remaining) {
        out.push(chunk)
        remaining -= bytes.length
        continue
      }
      const safe = trimIncompleteUtf8End(bytes.subarray(0, remaining))
      const take = safe > 0 ? safe : Math.min(bytes.length, remaining)
      if (take > 0) out.push({ ...chunk, text: bytes.subarray(0, take).toString('utf8'), length: take })
      truncated = true
      break
    }
    return { chunks: out, truncated }
  }

  /**
   * Read an adopted job through the registry's model cursor (the native read
   * path). This is the only cursor used for adopted jobs: `pod_output` and
   * `job_output` both consume the same `ctx.jobs` modelCursor, so double
   * delivery is structurally impossible. After the read we move the pod cursor
   * to `baseOffset + registry output.total` so a restart resumes from the same
   * place.
   * @param {string} jobId
   * @param {{ id: string, baseOffset?: number }} adoption
   * @param {any} hint
   * @param {boolean} [adopt] explicit takeover of a job owned by another session
   * @param {number} [maxBytes] the LIVE native window for this call
   */
  async function readAdoptedOutput(jobId, adoption, hint, adopt = false, maxBytes = 0) {
    const jobs = adoptions?.getJobsService?.() ?? null
    if (jobs === null || typeof jobs.read !== 'function') return null
    // Make the registry hold everything the pod produced so far; otherwise a
    // fresh read can return an empty delta while bytes are still in flight.
    try {
      await adoptions?.pollAdopted?.(jobId)
    } catch (error) {
      log('adopted output poll failed for ' + jobId + ': ' + messageOf(error))
    }
    const read = jobs.read(adoption.id)
    const base = Number.isInteger(adoption.baseOffset) ? adoption.baseOffset : 0
    const spillPath = join(pod.stateDir, 'jobs', jobId, 'out.log')
    const rawChunks = Array.isArray(read?.chunks) ? read.chunks.filter((chunk) => chunk?.channel !== 'log') : []
    /** @type {any[]} */
    const chunks = rawChunks.map((chunk) => {
      const text = typeof chunk?.text === 'string' ? chunk.text : ''
      const at = Number.isFinite(chunk?.at) ? chunk.at : 0
      return {
        offset: at,
        length: Buffer.byteLength(text, 'utf8'),
        channel: chunk?.channel === 'stderr' ? 'stderr' : 'stdout',
        text,
        gapBefore: chunk?.gapBefore === true,
      }
    })
    const total = Number.isFinite(read?.job?.output?.total)
      ? read.job.output.total
      : chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    const lossy = read?.lossy === true || chunks.some((chunk) => chunk.gapBefore === true)
    const status = typeof read?.job?.status === 'string' ? read.job.status : 'running'
    const running = status === 'running' || status === 'stopping'
    // Adopted reads use the same live native window as the pod path. The
    // fallback is only for a caller that did not resolve one.
    const windowBytes = Number.isInteger(maxBytes) && maxBytes > 0
      ? maxBytes
      : (typeof settings?.modelOutputLimitBytes === 'number' && settings.modelOutputLimitBytes > 0
        ? settings.modelOutputLimitBytes
        : MAX_MODEL_READ_BYTES)
    const clipped = clipRegistryChunks(chunks, windowBytes)
    /** @type {any} */
    const view = {
      ok: true,
      op: 'output',
      jobId,
      registryJobId: adoption.id,
      text: clipped.chunks.map((chunk) => chunk.text).join(''),
      chunks: clipped.chunks,
      spillPath,
      spillPaths: Array.isArray(read?.job?.output?.spillPaths) && read.job.output.spillPaths.length > 0
        ? read.job.output.spillPaths
        : [spillPath],
      truncated: clipped.truncated,
      lossy,
      hasMore: false,
      running,
      exitCode: null,
      signal: null,
      status,
      cursorAck: 'sent',
      message: '',
    }
    // Tool outputs must be lossless JSON: an `undefined` property is rejected by
    // the output validator, so the optional detail is only attached when present.
    if (typeof read?.job?.detail === 'string') view.detail = read.job.detail
    view.message = renderOutputText(view)
    // Keep the pod cursor aligned for the next Host: the registry total counts
    // bytes appended since adoption, so the absolute pod offset is base + total.
    void pod.ack(hint, { jobId, offset: base + total, hash: null, adopt }).then(
      (ackResponse) => {
        if (ackResponse?.ok !== true) log('adopted pod cursor ack rejected for ' + jobId + ': ' + String(ackResponse?.error?.message ?? 'unknown'))
      },
      (error) => {
        log('adopted pod cursor ack failed for ' + jobId + ': ' + messageOf(error))
      },
    )
    return view
  }

  /** @type {any} */
  const outputTool = {
    name: 'pod_output',
    description:
      '读取「逃生舱」某个 job 自上次读取之后的新输出（stdout+stderr 合并纯文本）。不接受偏移：内部用账本已落盘游标自动续读，跨 DSH 重启成立。按行和 UTF-8 码点对齐，不会出半字半行；单次最多返回当前生效的原生输出上限（maxOutputBytes，见 pod_status 的 limits），还有更多再调一次即可。任务结束后返回剩余输出与一行 [status: …]。默认只读本 DSH 会话的 job；其它会话及无归属历史 job 以 EFOREIGNJOB 拒绝，错误里说明如何 adopt: true 显式接管。running=false 且 status=unknown 表示 pod 重启过、账本没有 exit.json，结果未知，不要臆断退出码。',
    parameters: {
      type: 'object',
      properties: {
        jobId: { type: 'string', description: 'pod_run 返回的 jobId' },
        adopt: {
          type: 'boolean',
          description: '默认 false：只读本会话的 job。true = 显式接管另一个会话（或历史无主）的孤儿 job，返回里会带 adoptedFrom。只在确认原会话已销毁、需要清理时使用。',
        },
      },
      required: ['jobId'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '读取逃生舱输出', kind: 'read' }),
    async execute(args, exec) {
      const jobId = typeof args?.jobId === 'string' ? args.jobId.trim() : ''
      if (!JOB_ID_PATTERN.test(jobId)) throw new PodError('jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId, 'EBADJOBID')
      const adopt = args?.adopt === true
      const hint = policyHint(exec)
      // Live native output window, re-read on every call (never cached).
      const limits = liveLimits()
      try {
        const adoptionForRead = adoptions === null ? null : adoptions.registryInfo(jobId)
        if (adoptionForRead?.adopted === true) {
          // An adopted job is read through ctx.jobs, not the pod, so the session
          // boundary must be applied here too: the adoption record carries the
          // owner the pod reported when the job was adopted.
          const access = jobOwnership(adoptionForRead.sessionId ?? null, hint.sessionId, adopt)
          if (!access.allowed) throw foreignJobError('pod_output', jobId)
          const viaRegistry = await readAdoptedOutput(jobId, adoptionForRead, hint, adopt, limits.maxOutputBytes)
          if (viaRegistry !== null) {
            if (access.adoptedFrom !== undefined) {
              viaRegistry.adoptedFrom = access.adoptedFrom
              viaRegistry.message = String(viaRegistry.message ?? '') + renderAdoptedFrom(access.adoptedFrom)
            }
            return viaRegistry
          }
          log('adopted job ' + jobId + ': ctx.jobs.read unavailable, falling back to the pod cursor path')
        }
        const cursor = await pod.cursor(hint, { jobId, adopt })
        const state = cursor?.state ?? 'missing'
        let start = 0
        let cursorLossy = false
        if (state === 'ok' || state === 'lossy') {
          start = Number.isInteger(cursor?.offset) ? cursor.offset : 0
          cursorLossy = state === 'lossy'
        } else if (state === 'missing') {
          start = 0
        } else {
          // A bad anchor must not silently continue: that could replay or splice
          // the wrong bytes. Fail closed; the human-facing status has the details.
          throw new PodError(
            'pod_output 停止读取：账本游标与输出前缀不一致（' + String(state) + '）。为避免重放或错乱，本次不返回内容；详情见 pod_status（面向维护者）。',
            'ECURSORMISMATCH',
          )
        }
        const limit = limits.maxOutputBytes
        let response = await pod.output(hint, { jobId, from: start, maxBytes: limit, adopt })
        if (response.stalled === true) {
          // Fewer bytes than one UTF-8 code point came back: ask for a whole
          // window rather than splitting it.
          response = await pod.output(hint, { jobId, from: start, maxBytes: MAX_MODEL_READ_BYTES, adopt })
          if (response.stalled === true) {
            throw new PodError('输出暂时不足一个完整字符，无法在不破坏编码的前提下返回；请稍后重试 pod_output。', 'EOUTPUTSTALLED')
          }
        }
        const aligned = alignModelChunk({ text: response.text, hasMore: response.hasMore === true })
        const consumed = start + aligned.consumedBytes
        // Rebuild the native channel view for exactly the bytes the model gets.
        const podChunks = Array.isArray(response.chunks) && response.chunks.length > 0
          ? response.chunks
          : [{ offset: start, length: response.nextOffset - start, channel: 'stdout', text: response.text }]
        const chunks = clipChannelChunks(podChunks, start, consumed)
        let cursorAck = 'unavailable'
        if (consumed > start) {
          cursorAck = 'sent'
          const exact = consumed === response.nextOffset
          void pod.ack(hint, { jobId, offset: consumed, hash: exact ? response.prefixHash : null, adopt }).then(
            (ackResponse) => {
              if (ackResponse?.ok !== true) log('cursor ack rejected for ' + jobId + ': ' + String(ackResponse?.error?.message ?? 'unknown'))
            },
            (error) => {
              log('cursor ack failed for ' + jobId + ': ' + messageOf(error))
            },
          )
        }
        await syncAdoptions(hint)
        const adoption = adoptions === null ? null : adoptions.registryInfo(jobId)
        const view = {
          ok: true,
          op: 'output',
          jobId: response.jobId,
          registryJobId: adoption?.adopted === true ? adoption.id : null,
          text: aligned.text,
          chunks,
          spillPath: response.spillPath ?? join(pod.stateDir, 'jobs', jobId, 'out.log'),
          truncated: aligned.truncated,
          lossy: response.lossy === true || cursorLossy,
          hasMore: response.hasMore === true || aligned.droppedPartialLine,
          running: response.running,
          exitCode: response.exitCode,
          signal: response.signal ?? null,
          status: response.status,
          cursorAck,
          ...(response.adoptedFrom === undefined ? {} : { adoptedFrom: response.adoptedFrom }),
          message: '',
        }
        view.message = renderOutputText(view)
        if (response.adoptedFrom !== undefined) view.message += renderAdoptedFrom(response.adoptedFrom)
        return view
      } catch (error) {
        throw contextualize(error, 'pod_output')
      }
    },
  }

  /** @type {any} */
  const killTool = {
    name: 'pod_kill',
    description:
      '结束「逃生舱」里由本 pod 实例启动的某条命令：杀掉受限 runner，其 kill-on-close Job 随之终止。默认只能结束本 DSH 会话的 job；其它会话及无归属历史 job 以 EFOREIGNJOB 拒绝，确认是孤儿后可加 adopt: true 显式接管。job 已结束、或进程句柄属于重启前消失的 pod 实例时，如实返回 killed=false 与当前 status/exitCode，不假装成功。',
    parameters: {
      type: 'object',
      properties: {
        jobId: { type: 'string', description: 'pod_run 返回的 jobId' },
        adopt: {
          type: 'boolean',
          description: '默认 false：只能结束本会话的 job。true = 显式接管另一个会话（或历史无主）的孤儿 job，返回里会带 adoptedFrom。只在确认原会话已销毁、需要清理时使用。',
        },
      },
      required: ['jobId'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '结束逃生舱命令', kind: 'other' }),
    async execute(args, exec) {
      const jobId = typeof args?.jobId === 'string' ? args.jobId.trim() : ''
      if (!JOB_ID_PATTERN.test(jobId)) throw new PodError('jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId, 'EBADJOBID')
      const adopt = args?.adopt === true
      const hint = policyHint(exec)
      try {
        const adoption = adoptions === null ? null : adoptions.registryInfo(jobId)
        const response = await pod.kill(hint, { jobId, adopt })
        const message = [
          'pod_kill jobId=' + String(response.jobId) + '：killed=' + String(response.killed) + ' status=' + String(response.status) +
            ' exitCode=' + String(response.exitCode) + (response.signal === null || response.signal === undefined ? '' : ' signal=' + String(response.signal)) +
            (adoption?.adopted === true ? '（registry job ' + String(adoption.id) + '）' : ''),
          response.note === undefined ? '' : String(response.note),
        ].filter((line) => line !== '').join('\n')
        return {
          ok: true,
          op: 'kill',
          jobId: response.jobId,
          registryJobId: adoption?.adopted === true ? adoption.id : null,
          killed: response.killed,
          status: response.status,
          exitCode: response.exitCode,
          signal: response.signal ?? null,
          ...(response.adoptedFrom === undefined ? {} : { adoptedFrom: response.adoptedFrom }),
          pipeName: pod.pipeName,
          message: message + (response.adoptedFrom === undefined ? '' : renderAdoptedFrom(response.adoptedFrom)),
        }
      } catch (error) {
        throw contextualize(error, 'pod_kill')
      }
    },
  }

  /**
   * Freeze / thaw (one tool, one `action`): a second tool would duplicate every
   * guard and error code, and the model would have to know both to undo a
   * freeze. `pod_status` is the read-only card; this is the write action.
   * @type {any}
   */
  const freezeTool = {
    name: 'pod_freeze',
    description:
      '冻结/恢复「逃生舱」某条正在运行的命令：freeze 让整棵命令树停住（runner + 受限子进程 + 后代），thaw 从同一绝对偏移继续。走 job 级原语（JobObjectFreezeInformation），一次覆盖整棵树含嵌套 job；只会让命令变慢、不会多做事，所以不需要审批。冻结期间该 job 的超时计时器暂停（冻结时间不算预算），解冻后按剩余量重挂。默认 maxFreezeMs=30 分钟看门狗：到点自动解冻并记日志，不杀命令；冻结中的 job 仍算 running、会挡住 pod 空闲退出，此上限必须保留。DSH 退出/重启不影响冻结（pod detached）；但 pod 进程本身重启后 job 句柄消失，变成 frozen-orphan（thawable=false）无法解冻，账本 PID 不足以安全杀进程，pod_kill 如实返回 killed=false（必要时手工处理）。默认只操作本 DSH 会话的 job，其它会话/无主历史 job 以 EFOREIGNJOB 拒绝，确认孤儿后 adopt: true 接管（结果带 adoptedFrom）。错误码：EBADJOBID / ENOJOB / EFOREIGNJOB / ENOTHANDLE（只有账本、无本 pod 句柄）/ ENOTRUNNING / EFREEZEUNSUPPORTED（见 pod_status 的 freeze=）/ EOSFAIL（附 Win32 码）。',
    parameters: {
      type: 'object',
      properties: {
        jobId: { type: 'string', description: 'pod_run / pod_exec 返回的 jobId' },
        action: {
          type: 'string',
          enum: ['freeze', 'thaw'],
          description: 'freeze = 冻结整棵命令树；thaw = 解冻并按剩余时间重挂超时计时器。对同一个 job 幂等。',
        },
        adopt: {
          type: 'boolean',
          description: '默认 false：只能冻结/解冻本会话的 job。true = 显式接管另一个会话（或历史无主）的孤儿 job，返回里会带 adoptedFrom。只在确认原会话已销毁、需要清理时使用。',
        },
        maxFreezeMs: {
          type: 'number',
          description: '仅 action:"freeze"：冻结看门狗上限（毫秒）。0 或省略 = pod 默认 30 分钟；到点自动解冻并记日志，不杀命令。',
        },
      },
      required: ['jobId', 'action'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '冻结/恢复逃生舱命令', kind: 'other' }),
    async execute(args, exec) {
      const jobId = typeof args?.jobId === 'string' ? args.jobId.trim() : ''
      if (!JOB_ID_PATTERN.test(jobId)) throw new PodError('jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId, 'EBADJOBID')
      const action = args?.action === 'thaw' ? 'thaw' : args?.action === 'freeze' ? 'freeze' : null
      if (action === null) throw new PodError('pod_freeze 需要 action: "freeze" 或 "thaw"', 'EBADACTION')
      const adopt = args?.adopt === true
      const hint = policyHint(exec)
      try {
        const adoption = adoptions === null ? null : adoptions.registryInfo(jobId)
        const response = await pod.freeze(hint, {
          jobId,
          action,
          adopt,
          ...(typeof args?.maxFreezeMs === 'number' ? { maxFreezeMs: args.maxFreezeMs } : {}),
        })
        const frozen = response.frozen === true
        const lines = [
          'pod_freeze jobId=' + String(response.jobId) + ' action=' + action + '：frozen=' + String(frozen) +
            (frozen && Number.isFinite(response.remainingFreezeMs)
              ? ' 看门狗剩余=' + renderFreezeRemaining(response.remainingFreezeMs) + (Number.isFinite(response.maxFreezeMs) ? '（上限 ' + renderFreezeRemaining(response.maxFreezeMs) + '）' : '')
              : '') +
            (response.alreadyFrozen === true ? '（本来就是冻结状态，未重置看门狗）' : '') +
            (response.alreadyThawed === true ? '（本来就没有冻结）' : '') +
            (adoption?.adopted === true ? '（registry job ' + String(adoption.id) + '）' : ''),
          response.note === undefined ? '' : String(response.note),
        ].filter((line) => line !== '').join('\n')
        return {
          ok: true,
          op: 'freeze',
          jobId: response.jobId,
          action,
          registryJobId: adoption?.adopted === true ? adoption.id : null,
          frozen,
          frozenAt: response.frozenAt ?? null,
          frozenForMs: response.frozenForMs ?? null,
          remainingFreezeMs: response.remainingFreezeMs ?? null,
          maxFreezeMs: response.maxFreezeMs ?? null,
          freezeCount: response.freezeCount ?? null,
          thawable: response.thawable === true,
          alreadyFrozen: response.alreadyFrozen === true,
          alreadyThawed: response.alreadyThawed === true,
          ...(response.adoptedFrom === undefined ? {} : { adoptedFrom: response.adoptedFrom }),
          pipeName: pod.pipeName,
          message: lines + (response.adoptedFrom === undefined ? '' : renderAdoptedFrom(response.adoptedFrom)),
        }
      } catch (error) {
        // A pod spawned before this feature existed does not know the `freeze`
        // op at all (EBADOP). That is a deployment-state problem, not a user
        // error, so say exactly what fixes it.
        if (/** @type {any} */ (error)?.code === 'EBADOP') {
          throw new PodError(
            '当前 pod 实例是旧代码（不认识 freeze op）。先运行 pod_status action:"relaunch" 让 pod 用新代码重启（会中断正在跑的命令；可用 force:true），再 pod_freeze。',
            'EBADOP',
          )
        }
        throw contextualize(error, 'pod_freeze')
      }
    },
  }

  /**
   * Host-only shell selection. Deliberately never calls `pod.*`: listing or
   * switching an interpreter must not spawn, connect to or wake the pod.
   * @type {any}
   */
  const shellTool = {
    name: 'pod_shell',
    description:
      '查看本机探测到的命令行解释器并为当前会话选择逃生舱命令用哪个：只做 Host 侧探测（PowerShell/bash/cmd 的候选、路径、版本、来源、可用性），不连接也不唤醒 pod。action:"list" 按类型列出全部候选（id/名称/路径/版本/来源/是否可用/是否当前应用/是否设默认）并给出本会话最终应用；cmd 只有系统一个版本，固定不可选。action:"use" 用 shell+id 写会话选择：只接受该类型存在且 available 的候选，cmd 直接拒绝。action:"reset" 清除会话选择（省略 shell 时清全部类型）。解析顺序「会话选择 > 设置页默认 > 自动探测」；所选路径运行期不可用时逐级回落、不会卡死，结果与 pod_run 文本都说明回落原因。选择对本会话后续所有 pod_run/pod_exec 生效并跨 DSH 重启保留。命令行是可选覆盖，不强制替换 DSH/系统原装解释器：不做选择时沿用设置默认或自动探测，行为与以前一致。建议先用默认（原装）命令行（本机 Windows PowerShell 5.1 与 dsh-ops PortableGit），只有它不可用、启动失败或版本不满足时才切换到其它探测到的路径/版本。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['list', 'use', 'reset'],
          description: 'list = 查看候选与本会话当前应用（不唤醒 pod）；use = 为当前会话选择候选；reset = 清除会话选择，回到「设置默认 > 自动探测」。',
        },
        shell: {
          type: 'string',
          enum: ['powershell', 'bash', 'cmd'],
          description: '要操作的解释器类型。use 时必须且不能是 cmd（cmd 只有系统一个版本，固定不可选）；reset 省略时清除全部类型。',
        },
        id: {
          type: 'string',
          description: 'use 时必须：候选 id（见 action:"list" 中带 * 或列出的 id），必须存在于该类型且 available。',
        },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '逃生舱：命令行选择', kind: 'other' }),
    async execute(args, exec) {
      const action = args?.action
      if (action !== 'list' && action !== 'use' && action !== 'reset') {
        throw new PodError('action 只能是 list、use 或 reset', 'EARGS')
      }
      const hint = policyHint(exec)
      /** @type {any} */
      let snapshot = shellSnapshot(hint)
      let message = renderShellState(snapshot)
      if (action === 'use') {
        const kind = args?.shell
        if (kind !== 'powershell' && kind !== 'bash' && kind !== 'cmd') {
          throw new PodError('action:"use" 需要 shell（powershell 或 bash；cmd 固定不可选）', 'EARGS')
        }
        const cmdEntry = snapshot.kinds.find((entry) => entry.kind === 'cmd') ?? null
        if (kind === 'cmd') {
          throw new PodError(
            'cmd 只有系统一个版本（' + (cmdEntry?.candidates[0]?.path ?? 'cmd.exe') +
              '），固定不可选：要执行 cmd 命令直接给 pod_run/pod_exec 传 shell:"cmd" 即可，既不需要也无法用会话选择。',
            'EARGS',
          )
        }
        const wanted = typeof args?.id === 'string' ? args.id.trim() : ''
        if (wanted === '') throw new PodError('action:"use" 需要 id（候选 id，见 action:"list"）', 'EARGS')
        const entry = snapshot.kinds.find((row) => row.kind === kind) ?? null
        const candidates = entry === null ? [] : entry.candidates
        const candidate = candidates.find((row) => row.id === wanted) ?? null
        if (candidate === null) {
          const available = candidates.filter((row) => row.available).map((row) => row.id)
          throw new PodError(
            'id "' + wanted + '" 不在 ' + kind + ' 的候选里' +
              (available.length > 0 ? '；当前可用：' + available.join('、') : '；当前没有可用候选（先 action:"list" 看看）'),
            'EARGS',
          )
        }
        if (candidate.available !== true) {
          throw new PodError(
            'id "' + wanted + '" 当前不可用（' + candidate.path + '），不能选它；先 action:"list" 看可用候选，或先修好这个路径',
            'ESHELLUNAVAILABLE',
          )
        }
        if (snapshot.sessionId === null) {
          throw new PodError('当前工具调用没有会话 id，无法记录会话级命令行选择（未写任何文件）', 'ENOSESSION')
        }
        const stored = shellDependencies().store.setChoice(snapshot.sessionId, kind, candidate.id)
        snapshot = shellSnapshot(hint)
        if (typeof stored.warning === 'string' && stored.warning !== '') snapshot.warning = stored.warning
        message =
          '已为本会话选择 ' + kind + ' = ' + candidate.id + '（' + candidate.path + '）。' +
          '对当前会话后续所有 pod_run/pod_exec 生效（跨 DSH 重启保留）。' +
          (snapshot.warning === null ? '' : '\n注意：' + snapshot.warning) +
          '\n\n' + renderShellState(snapshot)
      } else if (action === 'reset') {
        const rawKind = args?.shell
        if (
          rawKind !== undefined && rawKind !== null && rawKind !== '' &&
          rawKind !== 'powershell' && rawKind !== 'bash' && rawKind !== 'cmd'
        ) {
          throw new PodError('shell 只能是 powershell、bash 或 cmd', 'EARGS')
        }
        const kind = rawKind === 'powershell' || rawKind === 'bash' ? rawKind : null
        if (snapshot.sessionId === null) {
          message = '当前工具调用没有会话 id，没有可清除的会话选择（未写任何文件）。\n\n' + renderShellState(snapshot)
        } else if (rawKind === 'cmd') {
          message = 'cmd 是系统固定项，没有会话选择可清除（未改动任何设置）。\n\n' + renderShellState(snapshot)
        } else {
          const cleared = shellDependencies().store.clearChoices(snapshot.sessionId, kind)
          snapshot = shellSnapshot(hint)
          if (typeof cleared.warning === 'string' && cleared.warning !== '') snapshot.warning = cleared.warning
          const scope = kind === null ? '全部命令行选择' : kind + ' 的选择'
          const head = cleared.removed === true
            ? (kind === null
              ? '已清除本会话的全部命令行选择，现在回到「设置默认 > 自动探测」。'
              : '已清除本会话的 ' + scope + '，现在回到「设置默认 > 自动探测」。')
            : (kind === null
              ? '本会话没有已保存的命令行选择（未改动任何设置）。'
              : '本会话没有已保存的 ' + scope + '（未改动任何设置）。')
          message = head + (snapshot.warning === null ? '' : '\n注意：' + snapshot.warning) + '\n\n' + renderShellState(snapshot)
        }
      }
      return {
        ok: true,
        op: 'shell',
        action,
        sessionId: snapshot.sessionId,
        generatedAt: snapshot.generatedAt,
        detectionError: snapshot.detectionError,
        defaults: snapshot.defaults,
        kinds: snapshot.kinds,
        applied: snapshot.applied,
        warning: snapshot.warning,
        message,
      }
    },
  }

  /** @type {any} */
  const statusTool = {
    name: 'pod_status',
    description:
      '读取「逃生舱」状态（只读）：podPid/podStartedAt/generation/enforcement、pod 启动时钉死的形态校验模板（runnerPath/modes/workspace——注意这不是当前前缀：前缀不缓存在 pod 里，每次 pod_run 由 Host 现签下发的），以及账本里本 DSH 会话的 job（running/settled/killed/runner-failed/unknown）与各自 cursor（offset/hash/state/lossy）、收养状态（registry）。其它会话及无 sessionId 的历史 job 默认只给 foreignJobs 计数；需清理孤儿时用 pod_output/pod_kill 的 adopt: true。DSH 重启后应看到重启前启动、仍在运行的 job 与同一个 podPid；exit.json 缺失报 unknown，代表结果未知，不要当作已结束。limits= 给出当前生效的输出窗口与命令超时及其来源（shell.resolve/shell.config/settings:<条目>/fallback:native-defaults），timeoutMs 只作用于 pod_exec、pod_run 不限时。launcherMode=/launcher=/task=/schtasks= 四行说明 launcher.json（auto|direct|schtasks）选路、实际启动器及能否建计划任务。freeze= 是本机冻结能力探测（supported/unsupported+原因），每个 job 行显示 frozen（看门狗剩余时间）或 frozen-orphan（句柄消失无法解冻，pod_kill 如实返回 killed=false）。shell= 给出不传 shell 时的解释器、来源与回落说明；切换见 pod_shell（Host 侧，不唤醒 pod）。action:"relaunch" 杀掉当前 pod 并用当前 launcher 重拉：有 running job 时拒绝，除非 force:true。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['relaunch'],
          description: 'relaunch = 杀掉当前 pod 并用当前 launcher 重新拉起；不传则只读状态。',
        },
        force: {
          type: 'boolean',
          description: '仅与 action:"relaunch" 一起使用：允许在仍有 running job 时强杀 pod（这些命令会中断）。',
        },
      },
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: typeof value?.message === 'string' ? value.message : JSON.stringify(value) }],
    },
    presentCall: () => ({ card: 'generic', title: '逃生舱状态', kind: 'read' }),
    async execute(args, exec) {
      const hint = policyHint(exec)
      // Resolved on every call (never cached): the session switch is live, and
      // this is the mode the next run/exec will use unless it asks for more.
      const standingPolicy = resolveStandingPolicy(resumeCtx, exec, hint)
      // The interpreter a command WITHOUT `shell` would use right now, through
      // the very same resolver the run path calls (so this line cannot drift
      // from what actually executes). Host-only: no pod request is made.
      const appliedShell = resolveAppliedShell('powershell', hint, shellDependencies())
      /** @type {any} */
      let relaunchInfo = null
      if (args?.action === 'relaunch') {
        // `force` alone must not kill anything: the action is the trigger.
        relaunchInfo = await pod.relaunch(hint, { force: args?.force === true })
      }
      // Resolved on every status call (never cached): whether the Host really
      // provided `resumableToolCalls` is exactly what an acceptance run needs to
      // see, and the service may appear after this plugin loaded.
      const resumeInfo = resolveResumeService(resumeCtx)
      // Same rule for the native budgets: this snapshot must show where the
      // values came from at THIS moment, not what they were at plugin load.
      const limits = liveLimits()
      /** @type {any} */
      let recoveryInfo = null
      try {
        recoveryInfo = execOptions?.recovery?.status?.() ?? null
      } catch (error) {
        log('recovery status failed: ' + messageOf(error))
        recoveryInfo = null
      }
      try {
        const { response, bootstrapError } = await pod.status(hint)
        // Adopt exactly this snapshot BEFORE projecting, so job_list and
        // pod_status describe the same live set; every row then carries its
        // registry counterpart explicitly. Adoption is intentionally NOT
        // filtered by session: the registry stays unowned/cross-session by
        // design (see adoption.mjs), and `job_list` visibility is unchanged by
        // this boundary. Only the MODEL-FACING status projection is filtered.
        const allJobs = Array.isArray(response.jobs) ? response.jobs : []
        const adoptionSync = adoptions === null
          ? null
          : await adoptions.ensureAdopted(hint, { jobs: allJobs })
        const callerSessionId = hint.sessionId ?? null
        /** @type {any[]} */
        const visibleJobs = []
        let foreignJobs = 0
        let unownedJobs = 0
        for (const job of allJobs) {
          const owner = jobSessionIdOf(job)
          if (jobOwnership(owner, callerSessionId, false).allowed) {
            visibleJobs.push({ ...job, sessionId: owner })
          } else {
            foreignJobs += 1
            if (owner === null) unownedJobs += 1
          }
        }
        const visibleIds = new Set(visibleJobs.map((job) => String(job.jobId ?? '')))
        const displaySync = visibleAdoptionSync(adoptionSync, visibleIds)
        const spawnInfo = pod.spawnInfo()
        // A fake/older pod client in tests may not expose the launcher seam.
        const launcherState = typeof pod.launcher === 'function' ? pod.launcher() : null
        const launcherRecovery = typeof pod.launcherRecovery === 'function' ? pod.launcherRecovery() : null
        const jobs = visibleJobs.map((job) => ({
          ...job,
          registry: adoptions === null ? { adopted: false, reason: 'adoption disabled' } : adoptions.registryInfo(job.jobId),
        }))
        const statusView = { ...response, jobs: visibleJobs, foreignJobs, unownedJobs, sessionId: callerSessionId }
        // What the pod would use if a client sent no `maxBytes`, plus its hard
        // clamp. The Host always sends the live window, so the first number is
        // diagnostic only (an old Host or the raw CLI is the only client that
        // relies on it).
        const podLimits = {
          defaultOutputChunkBytes: positiveIntOf(response.outputChunkBytes),
          maxOutputChunkBytes: positiveIntOf(response.maxOutputChunkBytes) ?? MAX_OUTPUT_CHUNK_BYTES,
        }
        const limitsView = {
          maxOutputBytes: limits.maxOutputBytes,
          timeoutMs: limits.timeoutMs,
          source: limits.source,
          executor: limits.executor,
          entry: limits.entry,
          modelCeiling: limits.modelCeiling,
          native: limits.native,
          reasons: limits.reasons,
          // Spell out the asymmetry so nobody "unifies" it later: the timeout
          // budget is a FOREGROUND-ONLY concept here.
          appliesTo: { timeout: EXEC_TOOL_NAME, backgroundTimeout: 'unlimited', outputWindow: 'pod_output / pod_exec' },
          pod: podLimits,
        }
        return {
          ok: true,
          op: 'status',
          sessionId: callerSessionId,
          podPid: response.podPid,
          podStartedAt: response.podStartedAt,
          generation: response.generation,
          podGeneration: response.podGeneration ?? null,
          // Freeze capability + per-job freeze rows (jobs are passed through
          // from the pod, see `listJobs`). `null` = a pod from before this
          // feature; the renderer says so instead of inventing "supported".
          freeze: response.freeze ?? null,
          enforcement: response.enforcement ?? null,
          connection: pod.mode(),
          /** The live session file policy the next call will default to. */
          policy: standingPolicy,
          /** The interpreter the next `shell`-less call will use (and why). */
          shell: appliedShell,
          template: response.template,
          templateBootstrapError: bootstrapError === null || bootstrapError === undefined ? null : messageOf(bootstrapError),
          workspaceRoot: response.workspaceRoot,
          dataRoot: response.dataRoot,
          running: response.running,
          jobs,
          foreignJobs,
          unownedJobs,
          adoptionSync: displaySync,
          adoptKind: ADOPT_KIND,
          limits: limitsView,
          resumeService: { available: resumeInfo.service !== null, reason: resumeInfo.reason },
          recovery: recoveryInfo,
          attestation: response.attestation ?? null,
          pipeName: response.pipeName,
          spawnInfo,
          launcher: launcherState === null ? null : launcherState.launcher,
          task: launcherState === null ? null : launcherState.taskName,
          schtasksProbe: launcherState === null ? 'unknown' : launcherState.schtasksProbe,
          launcherMode: launcherState === null ? null : launcherState.mode,
          launcherModeSource: launcherState === null ? null : launcherState.modeSource,
          launcherInfo: launcherState,
          launcherRecovery,
          relaunch: relaunchInfo,
          message: renderStatusText(statusView, bootstrapError, pod.mode(), spawnInfo, displaySync, launcherState) +
            '\n会话文件策略=' + renderStandingPolicyLine(standingPolicy) + '（pod_run / pod_exec 的默认；申请更宽模式要过 DSH 审批，只对本次调用有效）' +
            '\n' + renderShellLine(appliedShell) + '（不传 shell 时 pod_run / pod_exec 的默认解释器；切换与查看候选见 pod_shell）' +
            (launcherRecovery === null
              ? ''
              : '\nrecovery=曾清理无响应 pod：pid=' + String(launcherRecovery.pid) +
                ' after ' + String(launcherRecovery.elapsedMs) + 'ms（trigger=' + String(launcherRecovery.trigger) + '）') +
            (relaunchInfo === null
              ? ''
              : '\nrelaunch=已重启：killedPid=' + String(relaunchInfo.killedPid ?? 'none') +
                ' launcher=' + String(relaunchInfo.launcher?.launcher ?? 'unknown') +
                ' runningBefore=' + String(relaunchInfo.runningBefore) +
                (relaunchInfo.forced === true ? '（force）' : '')) +
            '\n执行预算=' + renderLimitsLine(limits, podLimits) +
            '\nresumableToolCalls=' + (resumeInfo.service !== null
              ? 'available（pod_exec 的调用可在重启时被挂起，不会被补 TOOL_OUTCOME_UNKNOWN）'
              : 'unavailable（' + String(resumeInfo.reason) + '）；pod_exec 退化为普通阻塞调用') +
            '\n恢复扫描=' + renderRecoveryLine(recoveryInfo) +
            '\n客户端鉴权=' + renderAttestationLine(response.attestation),
        }
      } catch (error) {
        throw contextualize(error, 'pod_status')
      }
    },
  }

  return [runTool, execTool, outputTool, killTool, freezeTool, shellTool, statusTool]
}

export const inject = ['tools']

/**
 * @param {any} ctx
 * @param {unknown} config
 */
export function apply(ctx, config) {
  const settings = normalizeConfig(config)
  const log = (message) => {
    try {
      ctx.logger?.debug?.('[escape-pod-core] ' + message)
    } catch {
      // logging is best-effort
    }
  }
  const getSandbox = () => {
    let sandbox
    try {
      sandbox = ctx.get('sandbox')
    } catch {
      sandbox = undefined
    }
    return sandbox ?? null
  }
  /**
   * The pod client of the live effect. `null` before the effect starts and
   * after teardown, so the settings-page API and the `escapePod` service can
   * never reach a disposed client.
   * @type {ReturnType<typeof createPodClient> | null}
   */
  let livePod = null
  /**
   * `ctx.jobs.start` refuses work that no attached job controller serves, so the
   * controller is attached lazily the first time the service is visible. The
   * disposer is kept so plugin teardown can detach it.
   * @type {(() => void) | null}
   */
  let detachJobsController = null
  const getJobs = () => {
    let jobs
    try {
      jobs = ctx.get('jobs')
    } catch {
      jobs = undefined
    }
    if (jobs === null || jobs === undefined) return null
    if (detachJobsController === null && typeof jobs.attachController === 'function') {
      try {
        detachJobsController = jobs.attachController('escape-pod-core')
      } catch (error) {
        log('ctx.jobs.attachController failed: ' + messageOf(error))
      }
    }
    return jobs
  }

  ctx.effect(() => {
    const pod = createPodClient({ ...settings, log, getSandbox })
    livePod = pod
    const adoptions = settings.adoptJobs
      ? createAdoptionManager({ getJobs, pod, log, pollMs: settings.adoptPollMs })
      : null
    const identity = describePipeIdentity()
    log(
      'plugin v' + PLUGIN_VERSION + ' pipe=' + pod.pipeName + ' seedHash=' + identity.seedHash +
      ' identity=' + identity.seedKind + ' idleExitMs=' + String(pod.idleExitMs) +
      ' sandbox=' + String(pod.sandboxPresent()) + ' adoptJobs=' + String(adoptions !== null) +
      ' allowHandover=' + String(settings.allowHandover !== false),
    )
    if (adoptions !== null && getJobs() === null) {
      log('ctx.jobs is not available; pod jobs will not appear in job_list (adoption disabled until service appears)')
    }
    // ---- cross-restart recovery: answer what the previous Host held ----------
    // Host teardown is NOT "the call is settled": while this is true, a hold
    // that stops waiting keeps both the service-side hold and its pending entry,
    // so the next boot can still fill in the real result.
    let hostDisposing = false
    // The list is read synchronously HERE (before any await), so the scan starts
    // inside the service's 1200ms boot settlement window; when it wins, no
    // provisional result is ever written. Every failure of this path is logged
    // and swallowed: recovery must never affect the tools themselves.
    const pendingStore = createPendingStore({
      file: join(settings.stateDir, PENDING_FILE_NAME),
      log,
      bootId: HOST_BOOT_ID,
    })
    const recovery = createExecRecovery({
      store: pendingStore,
      pod,
      log,
      // No live session exists yet; a read-only `output` op only needs the
      // policy workspace for the (rare) spawn path.
      hint: () => policyHint(null),
      resolveService: () => resolveResumeService(ctx),
      // Wait for the client's first connection attempt before reading a ledger
      // (`boot` is idempotent), so the scan never races it on the pipe.
      ready: () => pod.boot(),
      // Literally the renderer `pod_exec` returns with: a recovered call and a
      // call that never saw a restart are byte-identical.
      renderExec: (response) => renderExecResult(response, false),
      // A GETTER, not a number: the recovery scan may run hours after the call
      // it answers, and the native window may have been edited in between.
      modelOutputLimitBytes: () => resolveLiveLimits(ctx, settings).maxOutputBytes,
    })
    try {
      const started = recovery.start()
      log('recovery scan ' + JSON.stringify(started))
    } catch (error) {
      log('recovery scan failed to start: ' + messageOf(error))
    }
    // An explicit job_kill must beat a teardown-sentinel reason: the marker is
    // set before the tool reaches ctx.jobs.kill, so cancel() can tell them apart.
    /** @type {(() => void) | null} */
    let disposePreExecute = null
    try {
      disposePreExecute = ctx.on('tools/pre-execute', async (exec, next) => {
        try {
          if (adoptions !== null && exec?.name === 'job_kill') adoptions.noteExplicitKill(exec?.arguments?.job_id)
        } catch {
          // an observation hook must never break a tool call
        }
        return next()
      }, { prepend: true })
    } catch (error) {
      log('tools/pre-execute hook unavailable (explicit kill still detected by reason): ' + messageOf(error))
    }
    // job_output consumes registry bytes too; mirror that into the pod cursor so
    // a restart resumes exactly where the model stopped.
    const jobOutputAck = createJobOutputAckHook({ getJobs, adoptions, pod, log })
    /** @type {(() => void) | null} */
    let disposePostExecute = null
    try {
      disposePostExecute = ctx.on('tools/post-execute', (exec, result, next) => {
        try {
          jobOutputAck(exec, result)
        } catch {
          // an observation hook must never break a tool result
        }
        return next()
      })
    } catch (error) {
      log('tools/post-execute hook unavailable (job_output will not advance the pod cursor): ' + messageOf(error))
    }
    const disposers = createTools(pod, getSandbox, settings, adoptions, log, ctx, {
      store: pendingStore,
      recovery,
      isDisposing: () => hostDisposing,
    }).map((tool) => ctx.tools.register(tool))
    void pod.boot().then(() => {
      // Best effort: if a pod from before this Host boot is already connected,
      // adopt its running jobs immediately so job_list agrees from the start.
      if (adoptions !== null) {
        void adoptions.ensureAdopted(null, { onlyIfConnected: true, force: true }).catch((error) => {
          log('initial adoption failed: ' + messageOf(error))
        })
      }
    })
    return () => {
      // First of all: any hold that stops waiting from now on must keep its
      // service-side hold and its pending entry (see resume.mjs `release()`).
      hostDisposing = true
      // Order matters: mark hosting-down BEFORE any registry teardown cancel can
      // run, so a cancel during Host disposal can never kill a pod command.
      adoptions?.markHostDisposing()
      adoptions?.dispose()
      // Stop the recovery loop first: it only reads the ledger and writes to the
      // service, but a pending sleep must not outlive the plugin.
      try {
        recovery.dispose()
      } catch {
        // already disposed
      }
      // Detach only after the host-disposing mark: if detaching itself cancels
      // served jobs, those cancels are already no-ops.
      try {
        detachJobsController?.()
      } catch {
        // already detached
      }
      detachJobsController = null
      try {
        disposePreExecute?.()
      } catch {
        // already disposed
      }
      for (const disposeTool of disposers) {
        try {
          disposeTool()
        } catch {
          // already disposed
        }
      }
      pod.dispose()
      if (livePod === pod) livePod = null
    }
  }, 'escape-pod-core: pod_run/pod_exec/pod_output/pod_kill/pod_freeze/pod_shell/pod_status, ctx.jobs adoption, resumableToolCalls holds, and detached token-factory pod client')

  /* ------------------------------------------------------- settings page -- */

  const api = createEscapePodApi({
    getPod: () => livePod,
    // `normalizeConfig` already resolved the exact directory the pod was told
    // to use (`--data-root`), so the API reads the file the pod actually reads.
    stateDir: settings.stateDir,
    // Configured paths outrank the discovered ones in `detectShells`; passing
    // them here keeps the settings page honest about what will be used.
    pwshPath: settings.pwshPath,
    bashPath: settings.bashPath,
    log,
  })

  // The documented cross-plugin name: `dsh-power` links its own shutdown to
  // `ctx.get('escapePod').shutdown(reason)` and never requires it to exist.
  try {
    ctx.provide('escapePod', {
      shutdown: (reason) => api.shutdown(reason),
      status: () => api.status(),
    })
    log('provided service escapePod (shutdown/status)')
  } catch (error) {
    log('cannot provide escapePod: ' + messageOf(error))
  }

  const jsonResponse = (payload, status = 200) =>
    new Response(JSON.stringify(payload), {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    })
  const readJsonBody = async (request) => {
    try {
      const text = await request.text()
      if (text.length === 0) return {}
      const parsed = JSON.parse(text)
      return parsed !== null && typeof parsed === 'object' ? parsed : {}
    } catch {
      return {}
    }
  }

  ctx.inject(['connection'], (scope) => {
    try {
      scope.effect(
        () =>
          scope.connection.fetch.register({
            path: '/api/dsh-escape-pod/settings',
            methods: ['GET', 'POST'],
            requestBody: 'buffered',
            fetch: async (request) => {
              try {
                if (request.method === 'POST') {
                  const result = api.saveSettings(await readJsonBody(request))
                  return jsonResponse(result.body, result.status)
                }
                return jsonResponse(api.settingsView())
              } catch (error) {
                return jsonResponse({ ok: false, error: messageOf(error) }, 500)
              }
            },
          }),
        'escape-pod: settings route',
      )
      scope.effect(
        () =>
          scope.connection.fetch.register({
            path: '/api/dsh-escape-pod/shells',
            methods: ['GET'],
            requestBody: 'buffered',
            fetch: async () => {
              // Host-side detection only: opening or re-rendering the settings
              // page must never connect to (or wake) a pod.
              try {
                return jsonResponse(api.shellsView())
              } catch (error) {
                return jsonResponse({ ok: false, error: messageOf(error) }, 500)
              }
            },
          }),
        'escape-pod: shells route',
      )
      scope.effect(
        () =>
          scope.connection.fetch.register({
            path: '/api/dsh-escape-pod/shutdown',
            methods: ['POST'],
            requestBody: 'buffered',
            fetch: async (request) => {
              // Human-only: the settings page's 5-second hold is the guard, and
              // this route is never exposed as an AI tool. The pod itself
              // records every killed job in its ledger.
              const body = await readJsonBody(request)
              const reason = typeof body.reason === 'string' && body.reason.trim() !== ''
                ? body.reason.trim().slice(0, 200)
                : 'settings page'
              return jsonResponse(await api.shutdown(reason))
            },
          }),
        'escape-pod: shutdown route',
      )
    } catch (error) {
      log('settings routes unavailable: ' + messageOf(error))
    }
  })
}

/**
 * @param {unknown} config
 * @returns {{ pipeName: string, idleExitMs: number, ringBytes: number, outputChunkBytes: number, stateDir: string, pwshPath: string | undefined, bashPath: string | undefined, adoptJobs: boolean, adoptPollMs: number, modelOutputLimitBytes: number, allowHandover: boolean }}
 */
export function normalizeConfig(config) {
  const raw = config !== null && typeof config === 'object' ? /** @type {Record<string, unknown>} */ (config) : {}
  return {
    pipeName: resolvePipeName(typeof raw.pipeName === 'string' ? raw.pipeName : undefined),
    idleExitMs: clampInt(raw.idleExitMs, DEFAULT_IDLE_EXIT_MS, 1000, 7 * 24 * 60 * 60 * 1000),
    ringBytes: clampInt(raw.ringBytes, DEFAULT_RING_BYTES, 4096, 16 * 1024 * 1024),
    outputChunkBytes: clampInt(raw.outputChunkBytes, FALLBACK_OUTPUT_CHUNK_BYTES, 1024, 1024 * 1024),
    // OPTIONAL deployment ceiling for the model-facing read window, NOT the
    // window's source. `0` (default) = follow the live native `maxOutputBytes`
    // exactly; a positive value can only tighten it, never raise it above what
    // the native executor allows. See `resolveLiveLimits`.
    modelOutputLimitBytes: clampInt(raw.modelOutputLimitBytes, 0, 0, 1024 * 1024),
    stateDir: resolveStateDir(optionalString(raw.stateDir)),
    pwshPath: optionalString(raw.pwshPath),
    bashPath: optionalString(raw.bashPath),
    adoptJobs: raw.adoptJobs !== false,
    adoptPollMs: clampInt(raw.adoptPollMs, 250, 50, 10_000),
    // A memory-only token cannot survive a Host restart, so the next Host must
    // be able to take the pod over. Set `allowHandover:false` to forbid that:
    // secure against a later rogue client, but the pod's jobs become unreadable
    // after every DSH restart (and a stale pod blocks the pipe until it exits).
    allowHandover: raw.allowHandover !== false,
  }
}

/**
 * Pure internals exported for the self-test scripts. Not part of the plugin API.
 */
export const __internals = {
  PodError,
  createPodClient,
  createTools,
  createEscapePodApi,
  resolvePodStateDir,
  directoryWritable,
  podConfigView,
  validatePodSettingsInput,
  normalizeConfig,
  parseConfinedArgv,
  derivePrefix,
  unescortedPolicy,
  checkRunProtocol,
  policyHint,
  normalizeSandboxMode,
  resolveStandingPolicy,
  validateEscalation,
  approveEscalation,
  assertStandingUnchanged,
  renderStandingPolicyLine,
  resolvePwshPath,
  resolveBashPath,
  normalizeShellKind,
  resolveAppliedShell,
  createShellSessionStore,
  clearShellSessionStores,
  shellSessionsPath,
  SHELL_SESSION_FILE,
  SHELL_SESSION_TTL_MS,
  SHELL_SESSION_VERSION,
  buildBashArgv,
  buildCmdArgv,
  resolveJobCwd,
  resolveWorkspaceRoot,
  buildShellArgv,
  createAdoptionManager,
  ADOPT_KIND,
  createExecHold,
  createExecRecovery,
  createPendingStore,
  renderExecResult,
  resolveShellLimits,
  resolveLiveLimits,
  PENDING_FILE_NAME,
  resolveResumeService,
  hostIdentity: (hint) => ({ pid: process.pid, bootId: HOST_BOOT_ID, startedAt: HOST_STARTED_AT, sessionId: hint?.sessionId ?? null }),
  constants: {
    POD_PATH,
    PLACEHOLDER_TARGET,
    DEFAULT_WORKSPACE,
    PROTOCOL_VERSION,
    NATIVE_DEFAULT_TIMEOUT_MS,
    NATIVE_DEFAULT_MAX_OUTPUT_BYTES,
    EXEC_TIMEOUT_GRACE_MS,
    POD_STATE_DIR_NAME,
    POD_SETTINGS_VERSION,
    POD_SETTINGS_DEFAULTS,
    POD_SHUTDOWN_TIMEOUT_MS,
    API_PREFIX: '/api/dsh-escape-pod',
  },
}
