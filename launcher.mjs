/**
 * Windows launch paths for the pod.
 *
 * A pod is a long-lived Medium-integrity process that must outlive DSH. The
 * original path is a detached `spawn()` from the Host, which inherits DSH's job
 * object; a desktop/Electron Host puts children in a `KILL_ON_JOB_CLOSE` job and
 * takes the pod down with it. A Task Scheduler process is a child of the service
 * (svchost), i.e. outside every DSH job object — that is the only reason this
 * file exists.
 *
 * The recipe is fixed (see `pod/research/逃生舱-v2-存活方案.md` §3):
 *
 *   schtasks /Create /TN <task> /TR "<wscript.exe> \"<launch.vbs>\"" /SC ONCE /ST <now+60s> /F
 *   schtasks /Run /TN <task>
 *   schtasks /Change /TN <task> /DISABLE      ← immediately after /Run
 *
 * and NOT `/Delete` in the same breath as `/Run`: the started instance is
 * queued asynchronously and deleting the registration can drop it before it
 * ever runs (bgjobs measured this). The caller deletes the registration only
 * after the pod answered on the pipe, or after a bounded failure.
 *
 * Everything here is best-effort and reports what happened; nothing throws on a
 * denied/failed `schtasks` call. The caller decides between schtasks and the
 * detached spawn, and records the decision in `pod_status`.
 *
 * IMPORTANT — stdin gap: a Task Scheduler process inherits no stdin pipe, and
 * `pod.mjs` currently refuses to listen until it read the spawn-time token from
 * stdin (exit 4). Until pod.mjs offers a token-free bootstrap, the Host must
 * keep using the detached spawn; `podSupportsStdinlessBootstrap()` is the
 * explicit gate, and `index.js` refuses to route a launch through schtasks when
 * it says no. See `pod/research/pod-无stdin握手缺口.md`.
 */

import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import { join, resolve } from 'node:path'

/** A `schtasks` call that hangs is as bad as one that fails; bound every step. */
export const SCHTASKS_TIMEOUT_MS = 8000
/** `<dataRoot>/launch/` holds the generated `.cmd`/`.vbs` indirection layer. */
export const LAUNCH_DIR_NAME = 'launch'
/** Task-name prefix; the suffix is a short hash of the data root (one per profile). */
export const TASK_PREFIX = 'dsh-escape-pod-'
/** One-shot probe task; deleted immediately after creation. */
const PROBE_TASK_PREFIX = 'dsh-escape-pod-probe-'
const MAX_TOOL_OUTPUT_CHARS = 8192

/**
 * The env the pod itself needs. Deliberately NOT `{ ...process.env }`: a
 * launcher file must not carry the Host's unrelated secrets onto disk. `DSH_*`
 * and `PODC_*` are included because the pod reads `PODC_ATTEST` and forwards
 * `DSH_*` to managed commands.
 */
const POD_ENV_KEYS = [
  'SystemRoot',
  'SystemDrive',
  'windir',
  'ComSpec',
  'PATH',
  'PATHEXT',
  'TEMP',
  'TMP',
  'USERPROFILE',
  'HOMEDRIVE',
  'HOMEPATH',
  'APPDATA',
  'LOCALAPPDATA',
  'PROGRAMDATA',
  'PROGRAMFILES',
  'PROGRAMFILES(X86)',
  'COMMONPROGRAMFILES',
  'COMMONPROGRAMFILES(X86)',
  'NUMBER_OF_PROCESSORS',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'OS',
  'USERNAME',
  'USERDOMAIN',
  'COMPUTERNAME',
  'ELECTRON_RUN_AS_NODE',
]
const POD_ENV_PREFIXES = ['DSH_', 'PODC_']
const ENV_KEY_PATTERN = /^[^\s="%]+$/

const ACCESS_DENIED = /拒绝访问|access is denied|ERROR_ACCESS_DENIED|0x80070005|错误:\s*5\b/i
const NOT_AVAILABLE = /不是内部或外部命令|not recognized as an internal|找不到\s*schtasks|ERROR_FILE_NOT_FOUND|0x80070002|ENOENT/i

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/** @param {NodeJS.ProcessEnv} [env] */
function systemRootOf(env = process.env) {
  const root = env?.SystemRoot
  return typeof root === 'string' && root !== '' ? root : 'C:\\Windows'
}

/** @param {NodeJS.ProcessEnv} [env] */
export function schtasksExe(env = process.env) {
  const candidate = join(systemRootOf(env), 'System32', 'schtasks.exe')
  try {
    if (fs.statSync(candidate).isFile()) return candidate
  } catch {
    // fall through to PATH
  }
  return 'schtasks'
}

/** @param {NodeJS.ProcessEnv} [env] */
export function wscriptExe(env = process.env) {
  const candidate = join(systemRootOf(env), 'System32', 'wscript.exe')
  try {
    if (fs.statSync(candidate).isFile()) return candidate
  } catch {
    // fall through to PATH
  }
  return 'wscript.exe'
}

/** Local 24h `HH:mm`, the format `schtasks /ST` expects. @param {number} epochMs */
function clockTime(epochMs) {
  const date = new Date(epochMs)
  return String(date.getHours()).padStart(2, '0') + ':' + String(date.getMinutes()).padStart(2, '0')
}

/**
 * Run one native tool without a shell and without inherited stdin. Bounded by
 * `timeoutMs`; output is truncated so a hostile/locale-mangled stderr cannot
 * bloat a tool result.
 * @param {string} exe
 * @param {string[]} args
 * @param {{ timeoutMs?: number, env?: NodeJS.ProcessEnv }} [options]
 * @returns {Promise<{ ok: boolean, code: number | null, signal: string | null, error: string | null, stdout: string, stderr: string, timedOut: boolean }>}
 */
function runCommand(exe, args, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(100, Number(options.timeoutMs)) : SCHTASKS_TIMEOUT_MS
  const env = options.env ?? process.env
  return new Promise((resolveRun) => {
    /** @type {import('node:child_process').ChildProcess | null} */
    let child = null
    let settled = false
    let timedOut = false
    let timer = null
    let stdout = ''
    let stderr = ''
    /** @param {{ ok: boolean, code: number | null, signal: string | null, error: string | null }} outcome */
    const finish = (outcome) => {
      if (settled) return
      settled = true
      if (timer !== null) clearTimeout(timer)
      resolveRun({ stdout, stderr, timedOut, ...outcome })
    }
    /** @param {string} target */
    const collect = (target) => (/** @type {Buffer | string} */ chunk) => {
      const text = String(chunk)
      if (target === 'stdout') {
        if (stdout.length < MAX_TOOL_OUTPUT_CHARS) stdout += text.slice(0, MAX_TOOL_OUTPUT_CHARS - stdout.length)
      } else if (stderr.length < MAX_TOOL_OUTPUT_CHARS) {
        stderr += text.slice(0, MAX_TOOL_OUTPUT_CHARS - stderr.length)
      }
    }
    timer = setTimeout(() => {
      timedOut = true
      try {
        child?.kill()
      } catch {
        // already gone
      }
      // Last-resort settlement: a wedged process must not wedge a launch.
      setTimeout(() => finish({ ok: false, code: null, signal: null, error: 'timeout' }), 1000)
    }, timeoutMs)
    try {
      child = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env })
    } catch (error) {
      finish({ ok: false, code: null, signal: null, error: messageOf(error) })
      return
    }
    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', collect('stdout'))
    child.stderr?.on('data', collect('stderr'))
    child.on('error', (error) => {
      finish({ ok: false, code: null, signal: null, error: /** @type {any} */ (error)?.code ?? messageOf(error) })
    })
    child.on('close', (code, signal) => {
      finish({ ok: code === 0, code: typeof code === 'number' ? code : null, signal: signal ?? null, error: null })
    })
  })
}

/** One-line, bounded summary of a tool result for warnings/status. */
function summarizeResult(result) {
  const parts = []
  if (result.timedOut === true) parts.push('超时')
  if (result.error !== null && result.error !== undefined) parts.push('error=' + String(result.error))
  if (result.code !== null && result.code !== undefined) parts.push('exit=' + String(result.code))
  const text = (String(result.stderr ?? '') + ' ' + String(result.stdout ?? '')).replace(/\s+/g, ' ').trim()
  if (text !== '') parts.push(text.slice(0, 400))
  return parts.length === 0 ? 'no output' : parts.join(' ')
}

/** @type {{ status: 'ok' | 'denied' | 'missing', ok: boolean, stderr: string | null, at: string, cached: boolean } | null} */
let probeCache = null

/** Test seam: forget the cached probe so the next call really probes. */
export function resetSchtasksProbeCache() {
  probeCache = null
}

/**
 * Can this host create a scheduled task at all? Creates one throw-away task and
 * deletes it immediately; the answer is cached per process because the outcome
 * is a property of the machine/policy, not of a launch. `refresh: true` forces a
 * fresh probe (e.g. after an operator granted the right).
 *
 * Returns `ok` / `denied` / `missing` plus the raw stderr summary, never throws.
 * @param {{ timeoutMs?: number, refresh?: boolean, env?: NodeJS.ProcessEnv, log?: (message: string) => void }} [options]
 * @returns {Promise<{ status: 'ok' | 'denied' | 'missing', ok: boolean, stderr: string | null, at: string, cached: boolean }>}
 */
export async function probeSchtasks(options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(100, Number(options.timeoutMs)) : SCHTASKS_TIMEOUT_MS
  const env = options.env ?? process.env
  const log = typeof options.log === 'function' ? options.log : () => {}
  if (options.refresh !== true && probeCache !== null) return { ...probeCache, cached: true }

  const exe = schtasksExe(env)
  const taskName = PROBE_TASK_PREFIX + String(process.pid) + '-' + randomBytes(4).toString('hex')
  /** @type {'ok' | 'denied' | 'missing'} */
  let status = 'denied'
  /** @type {string | null} */
  let detail = null
  const create = await runCommand(
    exe,
    ['/Create', '/TN', taskName, '/TR', 'cmd.exe /c exit 0', '/SC', 'ONCE', '/ST', clockTime(Date.now() + 60_000), '/F'],
    { timeoutMs, env },
  )
  if (create.error === 'ENOENT') {
    status = 'missing'
    detail = 'schtasks.exe 不存在（' + exe + '）'
  } else if (create.ok) {
    status = 'ok'
    const removed = await runCommand(exe, ['/Delete', '/TN', taskName, '/F'], { timeoutMs, env })
    if (!removed.ok && !NOT_AVAILABLE.test(removed.stderr + ' ' + removed.stdout)) {
      // Leave no armed task behind: disabling is the fallback when the
      // registration cannot be deleted (the probe body is harmless, the residue
      // is not).
      const disabled = await runCommand(exe, ['/Change', '/TN', taskName, '/DISABLE'], { timeoutMs, env })
      detail = '探针任务创建成功但删除失败：' + summarizeResult(removed) +
        (disabled.ok ? '；已 /Change /DISABLE 兜底' : '；禁用也失败：' + summarizeResult(disabled))
      log('schtasks probe cleanup failed: ' + detail)
    }
  } else {
    const text = create.stderr + ' ' + create.stdout
    if (NOT_AVAILABLE.test(text)) {
      status = 'missing'
      detail = 'schtasks 不可用：' + summarizeResult(create)
    } else if (ACCESS_DENIED.test(text)) {
      status = 'denied'
      detail = '创建计划任务被拒绝：' + summarizeResult(create)
    } else {
      status = 'denied'
      detail = '无法创建计划任务（非明确拒绝，保守按 denied）：' + summarizeResult(create)
    }
  }
  const result = { status, ok: status === 'ok', stderr: detail, at: new Date().toISOString(), cached: false }
  probeCache = result
  log('schtasks probe=' + status + (detail === null ? '' : '（' + detail + '）'))
  return result
}

/** Optional per-dataRoot switch: `<dataRoot>/launcher.json` `{ "mode": ... }`. */
export const LAUNCHER_CONFIG_NAME = 'launcher.json'
export const LAUNCHER_MODES = ['auto', 'direct', 'schtasks']

/**
 * Read the optional launcher switch. Missing file = `auto` (the default);
 * malformed file = `auto` plus a warning, because a broken knobs file must not
 * turn into "no pod at all".
 *
 *   direct   — never probe, never create a task (the rollback rope)
 *   schtasks — force it, even when the probe says no (diagnostics; no fallback)
 *   auto     — schtasks when probe+capability say yes, otherwise direct
 *
 * @param {string} dataRoot
 * @returns {{ mode: 'auto' | 'direct' | 'schtasks', source: 'default' | 'file', path: string | null, warning: string | null }}
 */
export function readLauncherMode(dataRoot) {
  /** @type {{ mode: 'auto' | 'direct' | 'schtasks', source: 'default' | 'file', path: string | null, warning: string | null }} */
  const result = { mode: 'auto', source: 'default', path: null, warning: null }
  if (typeof dataRoot !== 'string' || dataRoot.trim() === '') return result
  const configPath = join(dataRoot, LAUNCHER_CONFIG_NAME)
  result.path = configPath
  let raw = ''
  try {
    raw = fs.readFileSync(configPath, 'utf8')
  } catch (error) {
    if (/** @type {any} */ (error)?.code === 'ENOENT') return result
    result.warning = '读取 launcher.json 失败，按 auto 处理：' + messageOf(error)
    return result
  }
  try {
    const parsed = JSON.parse(raw)
    const mode = typeof parsed?.mode === 'string' ? parsed.mode.trim().toLowerCase() : ''
    if (!LAUNCHER_MODES.includes(mode)) {
      result.warning = 'launcher.json 的 mode 非法（' + String(parsed?.mode) + '），按 auto 处理'
      return result
    }
    result.mode = /** @type {'auto' | 'direct' | 'schtasks'} */ (mode)
    result.source = 'file'
    return result
  } catch (error) {
    result.warning = 'launcher.json 不是合法 JSON，按 auto 处理：' + messageOf(error)
    return result
  }
}

/**
 * Pure launch decision (no I/O), so the switch can be tested without touching
 * Task Scheduler. `probe === null` encodes "direct mode: do not probe".
 *
 * @param {{ config: ReturnType<typeof readLauncherMode>, probe: any, capability: any, dataRoot: string }} input
 * @returns {{ launcher: 'schtasks' | 'spawn', mode: string, modeSource: string, configPath: string | null, forced: boolean, probe: any, capability: any, taskName: string | null, warnings: string[] }}
 */
export function planLauncher(input) {
  const config = input.config ?? { mode: 'auto', source: 'default', path: null, warning: null }
  const mode = LAUNCHER_MODES.includes(config.mode) ? config.mode : 'auto'
  const base = {
    mode,
    modeSource: config.source ?? 'default',
    configPath: config.path ?? null,
    forced: false,
    probe: input.probe ?? null,
    capability: input.capability ?? null,
    taskName: /** @type {string | null} */ (null),
    launcher: /** @type {'schtasks' | 'spawn'} */ ('spawn'),
  }
  /** @type {string[]} */
  const warnings = config.warning === null || config.warning === undefined ? [] : [String(config.warning)]

  if (mode === 'direct') {
    return {
      ...base,
      taskName: null,
      forced: false,
      warnings: [...warnings, 'launcher.json 指定 direct：不探测 schtasks，直接 detached spawn'],
    }
  }

  const probe = base.probe
  const capability = base.capability
  if (mode === 'schtasks') {
    if (probe?.status !== 'ok') {
      warnings.push('launcher.json 强制 schtasks，但探测结果=' + String(probe?.status ?? 'unknown') + '；仍按配置尝试')
    }
    if (capability?.ok !== true) {
      warnings.push('launcher.json 强制 schtasks，但 pod 不支持 --bootstrap-handover：拉起后很可能 exit 4')
    }
    return { ...base, launcher: 'schtasks', taskName: taskNameFor(input.dataRoot), forced: true, warnings }
  }

  // auto
  if (probe?.status !== 'ok') {
    warnings.push(
      probe?.status === 'denied'
        ? '本机不能创建计划任务（schtasks 被拒绝），回落 detached spawn'
        : probe?.status === 'missing'
          ? '本机没有可用的 schtasks，回落 detached spawn'
          : 'schtasks 探测异常，回落 detached spawn：' + String(probe?.stderr ?? 'unknown'),
    )
    return { ...base, launcher: 'spawn', taskName: null, forced: false, warnings }
  }
  if (capability?.ok !== true) {
    warnings.push(
      'schtasks 可用，但 ' + String(capability?.reason ?? 'pod 不支持无 stdin 引导') + '；为免拉起即退出，本次仍用 detached spawn',
    )
    return { ...base, launcher: 'spawn', taskName: null, forced: false, warnings }
  }
  return { ...base, launcher: 'schtasks', taskName: taskNameFor(input.dataRoot), forced: false, warnings }
}

/**
 * Stable task name for one data root: `dsh-escape-pod-<10 hex>`. Case and a
 * trailing separator must not create a second task for the same profile.
 * @param {string} dataRoot
 */
export function taskNameFor(dataRoot) {
  const root = typeof dataRoot === 'string' ? dataRoot.trim() : ''
  if (root === '') throw new Error('taskNameFor 需要 dataRoot')
  const normalized = resolve(root).replace(/[\\/]+$/, '').toLowerCase()
  if (normalized === '') throw new Error('taskNameFor 拿到空的 dataRoot')
  const hash = createHash('sha256').update(normalized).digest('hex').slice(0, 10)
  return TASK_PREFIX + hash
}

/**
 * Quote one argument for a Windows command line (CommandLineToArgvW rules).
 * @param {unknown} value
 */
function quoteWindowsArg(value) {
  const text = String(value)
  if (text === '') return '""'
  if (!/[\s"]/.test(text)) return text
  let out = '"'
  let backslashes = 0
  for (const character of text) {
    if (character === '\\') {
      backslashes += 1
      continue
    }
    if (character === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"'
      backslashes = 0
      continue
    }
    out += '\\'.repeat(backslashes) + character
    backslashes = 0
  }
  out += '\\'.repeat(backslashes * 2) + '"'
  return out
}

/**
 * The `%` in a batch file is expanded before the command line exists; doubling
 * it is how a literal percent survives. Quotes/backslashes are handled first.
 * @param {unknown} value
 */
function quoteBatchArg(value) {
  return quoteWindowsArg(value).replace(/%/g, '%%')
}

/** @param {unknown} value */
function escapeBatchValue(value) {
  return String(value).replace(/\r?\n/g, ' ').replace(/%/g, '%%')
}

/** @param {unknown} value */
function escapeVbsString(value) {
  return String(value).replace(/"/g, '""').replace(/\r?\n/g, ' ')
}

/**
 * The pod's own environment. Whitelisted so `launch.cmd` cannot leak unrelated
 * Host secrets onto disk; returns the skipped keys for the warning trail.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ env: Record<string, string>, skipped: string[] }}
 */
export function selectPodEnv(env = process.env) {
  /** @type {Record<string, string>} */
  const picked = {}
  /** @type {string[]} */
  const skipped = []
  for (const [key, value] of Object.entries(env ?? {})) {
    if (typeof value !== 'string') continue
    const allowed = POD_ENV_KEYS.includes(key) || POD_ENV_PREFIXES.some((prefix) => key.startsWith(prefix))
    if (!allowed) continue
    if (!ENV_KEY_PATTERN.test(key) || value.includes('\u0000') || /[\r\n]/.test(value)) {
      skipped.push(key)
      continue
    }
    picked[key] = value
  }
  return { env: picked, skipped }
}

/**
 * Write `<dataRoot>/launch/launch.cmd` + `launch.vbs`.
 *
 * `/TR` has a length limit and deep paths fail silently (Last Result 64), so the
 * registered action stays short: `wscript.exe "<launch.vbs>"` runs the `.cmd`
 * with a hidden window, and the `.cmd` is the only place the full command line
 * lives. No secret goes into either file.
 *
 * @param {{ nodeExe?: string, podScript: string, podArgs?: string[], env?: NodeJS.ProcessEnv, dataRoot: string, log?: (message: string) => void }} options
 * @returns {{ launchDir: string, cmdPath: string, vbsPath: string, warnings: string[], envKeys: string[], dangerous: { line: number, chars: string }[] }}
 */
export function buildLaunchFiles(options) {
  const { podScript, dataRoot } = options
  const nodeExe = typeof options.nodeExe === 'string' && options.nodeExe !== '' ? options.nodeExe : process.execPath
  const podArgs = Array.isArray(options.podArgs) ? options.podArgs : []
  const env = options.env ?? process.env
  if (typeof podScript !== 'string' || podScript === '') throw new Error('buildLaunchFiles 需要 podScript')
  if (typeof dataRoot !== 'string' || dataRoot === '') throw new Error('buildLaunchFiles 需要 dataRoot')

  // cmd.exe re-tokenizes the line: a `&`/`|`/`<`/`>` outside its idea of a
  // quoted region becomes a command separator, and it does NOT understand
  // backslash-escaped quotes. Refuse instead of writing a command that silently
  // changes meaning. `--template-b64` is base64url, so it never trips this.
  const CMD_METACHARS = /[&|<>^"\r\n]/
  const guardedArgs = [
    ['nodeExe', nodeExe],
    ['podScript', podScript],
    ...podArgs.map((item, index) => ['podArgs[' + String(index) + ']', String(item)]),
  ]
  for (const [label, value] of guardedArgs) {
    const hit = CMD_METACHARS.exec(value)
    if (hit !== null) {
      throw new Error(
        'launch.cmd 拒绝生成：参数 ' + label + ' 含 cmd.exe 元字符 ' + JSON.stringify(hit[0]) +
        '（& | < > ^ " 或换行）。cmd 会重解析它而不是原样传给 pod；' +
        '模板请用 --template-b64（base64url 无元字符），路径请避开这些字符。值=' + value.slice(0, 160),
      )
    }
  }

  const launchDir = join(dataRoot, LAUNCH_DIR_NAME)
  fs.mkdirSync(launchDir, { recursive: true })
  const { env: podEnv, skipped } = selectPodEnv(env)
  /** @type {string[]} */
  const warnings = []
  if (skipped.length > 0) warnings.push('launch.cmd 跳过了带控制字符/非法名字的环境变量：' + skipped.join(','))

  const argv = [nodeExe, podScript, ...podArgs.map((item) => String(item))]
  const lines = ['@echo off', 'rem dsh-escape-pod-core launcher (generated; contains no secret)']
  for (const key of Object.keys(podEnv).sort()) {
    lines.push('set "' + key + '=' + escapeBatchValue(podEnv[key]) + '"')
  }
  lines.push(argv.map(quoteBatchArg).join(' '))
  const cmdText = lines.join('\r\n') + '\r\n'

  // Self-check the generated file as a user would read it: every non-syntax
  // line must be free of cmd metacharacters. This is defence in depth for env
  // values (`set` lines) and for any future argument that skips the guard.
  /** @type {{ line: number, chars: string }[]} */
  const dangerous = []
  const cmdLines = cmdText.split('\r\n')
  for (let index = 0; index < cmdLines.length; index += 1) {
    const line = cmdLines[index]
    if (line === '' || line.startsWith('@echo') || line.startsWith('rem ')) continue
    let probeText = line
    const setMatch = /^set "(.*)"$/.exec(line)
    if (setMatch !== null) probeText = setMatch[1].slice(setMatch[1].indexOf('=') + 1)
    const hits = probeText.match(/[&|<>^"]/g)
    if (hits !== null) dangerous.push({ line: index + 1, chars: [...new Set(hits)].join('') })
  }
  if (dangerous.length > 0) {
    warnings.push(
      'launch.cmd 自检：以下行含 cmd 元字符，可能被 cmd.exe 重解析 → ' +
      dangerous.map((entry) => 'L' + String(entry.line) + '(' + entry.chars + ')').join(', '),
    )
  }

  const cmdPath = join(launchDir, 'launch.cmd')
  const vbsPath = join(launchDir, 'launch.vbs')
  const vbsText = [
    "' dsh-escape-pod-core launcher (generated; contains no secret)",
    'Option Explicit',
    'Dim shell, target',
    'Set shell = CreateObject("WScript.Shell")',
    'target = Chr(34) & "' + escapeVbsString(cmdPath) + '" & Chr(34)',
    'shell.Run target, 0, False',
    '',
  ].join('\r\n')

  // Both interpreters read ANSI/OEM, not UTF-8. Non-ASCII paths still usually
  // work because the console code page matches the file system, but say so.
  if (!/^[\x00-\x7f]*$/.test(cmdText)) warnings.push('launch.cmd 含非 ASCII 字符：cmd.exe 按代码页解析，深/中文路径可能乱码')
  if (!/^[\x00-\x7f]*$/.test(vbsText)) warnings.push('launch.vbs 含非 ASCII 字符：wscript.exe 按 ANSI 读取，中文路径可能乱码')

  fs.writeFileSync(cmdPath, cmdText, 'utf8')
  fs.writeFileSync(vbsPath, vbsText, 'utf8')
  return { launchDir, cmdPath, vbsPath, warnings, envKeys: Object.keys(podEnv).sort(), dangerous }
}

/**
 * Idempotent `/Delete /F`. A missing task is success ("already gone"), every
 * other failure is only a warning: a leftover registration must never block a
 * launch.
 * @param {string | null | undefined} taskName
 * @param {{ timeoutMs?: number, env?: NodeJS.ProcessEnv, log?: (message: string) => void }} [options]
 * @returns {Promise<{ ok: boolean, taskName: string | null, warnings: string[], existed?: boolean }>}
 */
export async function deleteTask(taskName, options = {}) {
  const name = typeof taskName === 'string' ? taskName.trim() : ''
  if (name === '') return { ok: true, taskName: null, warnings: [] }
  const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(100, Number(options.timeoutMs)) : SCHTASKS_TIMEOUT_MS
  const env = options.env ?? process.env
  const log = typeof options.log === 'function' ? options.log : () => {}
  /** @type {string[]} */
  const warnings = []
  try {
    const result = await runCommand(schtasksExe(env), ['/Delete', '/TN', name, '/F'], { timeoutMs, env })
    if (result.ok) return { ok: true, taskName: name, warnings, existed: true }
    const text = result.stderr + ' ' + result.stdout
    if (NOT_AVAILABLE.test(text) || /找不到|does not exist|cannot find the (task|file)|ERROR: The system cannot find/i.test(text)) {
      return { ok: true, taskName: name, warnings, existed: false }
    }
    const warning = '删除计划任务失败（' + name + '）：' + summarizeResult(result)
    warnings.push(warning)
    log(warning)
    return { ok: false, taskName: name, warnings }
  } catch (error) {
    const warning = '删除计划任务失败（' + name + '）：' + messageOf(error)
    warnings.push(warning)
    log(warning)
    return { ok: false, taskName: name, warnings }
  }
}

/**
 * Register + run the task, then IMMEDIATELY disable it so the `/ST` minute can
 * never fire a second instance. The registration is deliberately left behind
 * for the caller to delete once the pod answered (or after a bounded failure):
 * `/Delete` here could drop the still-queued instance.
 *
 * @param {{ nodeExe?: string, podScript: string, podArgs?: string[], env?: NodeJS.ProcessEnv, dataRoot: string, taskName?: string, timeoutMs?: number, log?: (message: string) => void }} options
 * @returns {Promise<{ ok: boolean, launcher: 'schtasks', taskName: string, step: string, warnings: string[], stderr?: string | null, code?: number | null, error?: string | null, launcherDir?: string, steps?: Record<string, string> }>}
 */
export async function launchViaSchtasks(options) {
  const { podScript, dataRoot } = options
  const nodeExe = typeof options.nodeExe === 'string' && options.nodeExe !== '' ? options.nodeExe : process.execPath
  const podArgs = Array.isArray(options.podArgs) ? options.podArgs : []
  const env = options.env ?? process.env
  const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(100, Number(options.timeoutMs)) : SCHTASKS_TIMEOUT_MS
  const log = typeof options.log === 'function' ? options.log : () => {}
  /** @type {string[]} */
  const warnings = []
  /** @type {Record<string, string>} */
  const steps = {}

  if (typeof podScript !== 'string' || podScript === '') throw new Error('launchViaSchtasks 需要 podScript')
  if (typeof dataRoot !== 'string' || dataRoot === '') throw new Error('launchViaSchtasks 需要 dataRoot')
  const taskName = typeof options.taskName === 'string' && options.taskName.trim() !== '' ? options.taskName.trim() : taskNameFor(dataRoot)

  /** @type {ReturnType<typeof buildLaunchFiles> | null} */
  let files = null
  try {
    files = buildLaunchFiles({ nodeExe, podScript, podArgs, env, dataRoot, log })
    warnings.push(...files.warnings)
  } catch (error) {
    return { ok: false, launcher: 'schtasks', taskName, step: 'write-launch-files', warnings, error: messageOf(error) }
  }

  const exe = schtasksExe(env)
  const wscript = wscriptExe(env)
  /** `/TR` stays short: the long command line lives in launch.cmd. */
  const tr = '"' + wscript + '" "' + files.vbsPath + '"'
  const startTime = clockTime(Date.now() + 60_000)
  const base = {
    launcher: /** @type {const} */ ('schtasks'),
    taskName,
    launcherDir: files.launchDir,
    warnings,
    steps,
    dangerous: files.dangerous,
  }

  const create = await runCommand(
    exe,
    ['/Create', '/TN', taskName, '/TR', tr, '/SC', 'ONCE', '/ST', startTime, '/F'],
    { timeoutMs, env },
  )
  steps.create = summarizeResult(create)
  if (!create.ok) {
    // Nothing can have been queued reliably; drop the registration so a later
    // `/ST` cannot start a pod behind the caller's back.
    const removed = await deleteTask(taskName, { timeoutMs, env, log })
    warnings.push(...removed.warnings)
    log('schtasks create failed for ' + taskName + ': ' + summarizeResult(create))
    return {
      ...base,
      ok: false,
      step: 'create',
      stderr: summarizeResult(create),
      code: create.code ?? null,
      error: create.error ?? null,
    }
  }

  const run = await runCommand(exe, ['/Run', '/TN', taskName], { timeoutMs, env })
  steps.run = summarizeResult(run)

  // MUST follow /Run immediately — even when /Run reported failure: the task is
  // also registered for an ONCE trigger one minute out, and a second instance
  // would fail to own the single-instance pipe. /Change (not /Delete) keeps the
  // queued instance; the /Delete below only happens after this /Change.
  const disable = await runCommand(exe, ['/Change', '/TN', taskName, '/DISABLE'], { timeoutMs, env })
  steps.disable = summarizeResult(disable)
  if (!disable.ok) {
    warnings.push(
      (run.ok ? '任务已 /Run' : '任务 /Run 失败') + ' 且 /Change /DISABLE 失败（' + taskName + '）：' + summarizeResult(disable) +
      (run.ok ? '；注册会在 pod 确认连上后由 Host 删除' : ''),
    )
    log(warnings[warnings.length - 1])
  }

  if (!run.ok) {
    // /Run reported failure: drop the registration. If it had actually queued
    // an instance, that instance belongs to a launch the caller is about to
    // replace; leaving it would race the fallback pod for the pipe.
    const removed = await deleteTask(taskName, { timeoutMs, env, log })
    warnings.push(...removed.warnings)
    log('schtasks run failed for ' + taskName + ': ' + summarizeResult(run))
    return {
      ...base,
      ok: false,
      step: 'run',
      stderr: summarizeResult(run),
      code: run.code ?? null,
      error: run.error ?? null,
    }
  }

  log('schtasks started: task=' + taskName + ' /ST=' + startTime + ' vbs=' + files.vbsPath)
  return { ...base, ok: true, step: 'started', stderr: null, code: 0, steps }
}

/**
 * The original launch path: a detached spawn with a stdin pipe for the token.
 * The caller writes `${token}\n` and immediately closes its end; the pod reads
 * the first line and must survive the EOF.
 * @param {{ nodeExe?: string, podScript: string, podArgs?: string[], env?: NodeJS.ProcessEnv, detached?: boolean, windowsHide?: boolean }} options
 */
export function launchDirect(options) {
  const { podScript } = options
  const nodeExe = typeof options.nodeExe === 'string' && options.nodeExe !== '' ? options.nodeExe : process.execPath
  const podArgs = Array.isArray(options.podArgs) ? options.podArgs : []
  if (typeof podScript !== 'string' || podScript === '') throw new Error('launchDirect 需要 podScript')
  return spawn(nodeExe, [podScript, ...podArgs], {
    detached: options.detached !== false,
    stdio: ['pipe', 'ignore', 'ignore'],
    windowsHide: options.windowsHide !== false,
    env: options.env ?? process.env,
  })
}

/** @type {{ path: string, mtimeMs: number, size: number, result: { ok: boolean, reason: string } } | null} */
let bootstrapCache = null

/**
 * Does the on-disk pod know how to start without a stdin token?
 *
 * A Task Scheduler process inherits no stdin pipe, so `--serve` alone would
 * exit 4 before it ever listens. This is a capability probe over the pod source
 * (cached by mtime/size), not a policy switch: it flips only when pod.mjs gains
 * the documented `--bootstrap-handover` bootstrap (no token on the wire until
 * the identity-channel handover completes). Until then the Host must stay on
 * the detached spawn; see `pod/research/pod-无stdin握手缺口.md`.
 * @param {{ podScript?: string }} [options]
 * @returns {{ ok: boolean, reason: string }}
 */
export function podSupportsStdinlessBootstrap(options = {}) {
  const podScript = options.podScript
  if (typeof podScript !== 'string' || podScript === '') return { ok: false, reason: '未提供 podScript' }
  try {
    const stat = fs.statSync(podScript)
    if (
      bootstrapCache !== null &&
      bootstrapCache.path === podScript &&
      bootstrapCache.mtimeMs === stat.mtimeMs &&
      bootstrapCache.size === stat.size
    ) {
      return bootstrapCache.result
    }
    const source = fs.readFileSync(podScript, 'utf8')
    const supported = source.includes("'--bootstrap-handover'") || source.includes('"--bootstrap-handover"')
    const result = supported
      ? { ok: true, reason: 'pod.mjs 声明支持 --bootstrap-handover（无 stdin 引导）' }
      : { ok: false, reason: 'pod.mjs 仍只从 stdin 读 spawn 期 token（readTokenFromStdin → 无 token 时 exit 4）' }
    bootstrapCache = { path: podScript, mtimeMs: stat.mtimeMs, size: stat.size, result }
    return result
  } catch (error) {
    return { ok: false, reason: '无法读取 pod.mjs：' + messageOf(error) }
  }
}
