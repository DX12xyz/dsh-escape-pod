/**
 * Command-line shell discovery for the escape pod.
 *
 * Why this module exists: the pod only ever executes the `[shellPath, ...args]`
 * argv the Host hands it, so *choosing* that path is a Host concern. Until now
 * the answer was a single ordered list inside `resolvePwshPath` /
 * `resolveBashPath` (index.js), which is invisible to the settings page and
 * cannot explain itself when a configured path disappears. This module turns
 * that ordering into data — candidates with stable ids, sources, availability
 * and a probed version — plus one resolution function shared by the settings
 * page and `pod_shell`.
 *
 * It is deliberately pure: no `ctx`, no pod client, no config-file reads, no
 * mutation of process state. `detectShells` takes the environment, platform and
 * plugin config as arguments and only touches the filesystem to stat/probe the
 * candidates it was told about, which is what makes it testable with fake
 * directories.
 *
 * Windows facts encoded here (kept identical to index.js, do not diverge):
 *   - PowerShell 7 is an optional install at %ProgramFiles%\PowerShell\7;
 *   - Windows PowerShell 5.1 ships with the OS at
 *     %SystemRoot%\System32\WindowsPowerShell\v1.0 and is the fallback;
 *   - stock Git Bash 2.49 dies under the sandbox restricted token
 *     (NtSetInformationToken / TokenDefaultDacl denied, then Cygwin cannot
 *     create its signal pipe), while the PortableGit runtime shipped by
 *     dsh-ops under <DSH_HOME>\dsh-ops\bash-ipc\<instance> survives it, so the
 *     plugin source outranks the system Git install;
 *   - cmd.exe is never selectable: `%ComSpec%` is the OS answer and the pod's
 *     cmd argv shape is fixed.
 */

import { spawnSync } from 'node:child_process'
import { lstatSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'

/** Display order of the shell groups (settings, detection and UI all follow it). */
export const SHELL_KINDS = ['powershell', 'bash', 'cmd']

/**
 * What a fresh settings file says about shells. `cmd` is absent on purpose: it
 * is fixed (`selectable:false`), so there is no choice to persist for it.
 */
export const SHELL_SETTINGS_DEFAULTS = Object.freeze({ powershell: 'auto', bash: 'auto' })

/** How long a probed version is reused before the interpreter is asked again. */
export const SHELL_VERSION_TTL_MS = 60_000

const SHELL_PROBE_TIMEOUT_MS = 3_000

/**
 * Candidate ids end up in settings.json, so they must stay printable and
 * shell-safe: letters, digits, dot, underscore and hyphen.
 */
const SHELL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/**
 * The restricted-token failure is a real, reproduced fact on this platform, not
 * a guess: it is why the dsh-ops PortableGit instance outranks Git Bash. The
 * note is attached to every bash candidate that did NOT come from an explicit
 * choice (config/env) or from dsh-ops itself.
 */
const BASH_RESTRICTED_TOKEN_NOTE =
  '系统 Git Bash 在受限令牌下可能启动失败（历史实测 NtSetInformationToken/T_DEFAULT_DACL 被拒）；优先用 dsh-ops PortableGit'

/**
 * @typedef {'powershell' | 'bash' | 'cmd'} ShellKind
 * @typedef {'config' | 'env' | 'plugin' | 'system' | 'path'} ShellSource
 * @typedef {{
 *   id: string,
 *   kind: ShellKind,
 *   path: string,
 *   version: string | null,
 *   source: ShellSource,
 *   available: boolean,
 *   label: string,
 *   note: string | null,
 * }} ShellCandidate
 * @typedef {{ kind: ShellKind, selectable: boolean, fixed: boolean, candidates: ShellCandidate[] }} ShellGroup
 * @typedef {{ generatedAt: string, groups: ShellGroup[] }} ShellDetection
 * @typedef {{ version: string | null, at: number }} ShellVersionCacheEntry
 */

/** Probed versions, keyed by `kind + '\0' + normalized path` (see probeShellVersion). */
/** @type {Map<string, ShellVersionCacheEntry>} */
const versionCache = new Map()

/**
 * Forget every cached version. Tests use it so a run never depends on what an
 * earlier test probed; production code never needs it.
 */
export function clearShellVersionCache() {
  versionCache.clear()
}

/**
 * The exact argv used to ask a shell for its version.
 *
 * Exported because it is the seam a test (or a future permission dialog) needs:
 * the command is data, so it can be asserted and fed to a fake runner instead
 * of executing anything.
 *
 * @param {ShellKind | string} kind
 * @param {string} path
 * @returns {{ file: string, args: string[] }}
 */
export function shellVersionCommand(kind, path) {
  if (kind === 'bash') return { file: path, args: ['--version'] }
  if (kind === 'cmd') return { file: path, args: ['/d', '/s', '/c', 'ver'] }
  return {
    file: path,
    args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'],
  }
}

/**
 * Normalize a persisted or user-supplied shell choice.
 *
 * `'auto'` means "the first available candidate"; anything else must look like
 * an id this module could have produced. Garbage (numbers, objects, strings
 * with spaces, absolute paths pasted by hand) collapses to `'auto'` instead of
 * becoming an unresolvable id in settings.json — an unusable choice must degrade
 * to the automatic behaviour, never to a broken shell.
 *
 * @param {unknown} raw
 * @returns {{ powershell: string, bash: string }}
 */
export function normalizeShellDefaults(raw) {
  const value = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  return {
    powershell: normalizeShellChoice(value.powershell),
    bash: normalizeShellChoice(value.bash),
  }
}

/**
 * Probe every shell this machine can offer, in preference order.
 *
 * Ordering rules (lower index = higher priority, `auto` takes the first
 * available candidate of a group):
 *   powershell: config pwshPath, PowerShell 7 install, Windows PowerShell 5.1, PATH
 *   bash:       config bashPath, DSH_ESCAPE_POD_BASH, dsh-ops PortableGit
 *               (newest instance first), Git for Windows, PATH
 *   cmd:        %ComSpec% only
 *
 * Only candidates that exist are listed for *discovered* sources (system
 * installs, PATH entries, dsh-ops instances): an entry that can never run would
 * sit at the top of the auto order forever. Explicitly configured paths
 * (config/env) are kept even when missing — that is exactly the "the path I
 * chose disappeared" signal the settings page needs.
 *
 * @param {{
 *   env?: Record<string, string | undefined>,
 *   platform?: NodeJS.Platform | string,
 *   config?: { pwshPath?: unknown, bashPath?: unknown },
 *   now?: number | (() => number),
 *   cache?: boolean,
 *   probe?: boolean,
 *   run?: (file: string, args: string[]) => unknown,
 * }} [options]
 *   env/platform: test seams; config: plugin config paths; now: clock override
 *   for cache TTL tests; cache:false bypasses the version cache; probe:false
 *   performs no spawning at all; run: replacement for spawnSync (tests).
 * @returns {ShellDetection}
 */
export function detectShells(options = {}) {
  const settings = options !== null && typeof options === 'object' ? options : {}
  const ctx = {
    env: settings.env ?? process.env,
    platform: settings.platform ?? process.platform,
    config: settings.config === null || typeof settings.config !== 'object' ? {} : settings.config,
    cache: settings.cache !== false,
    probe: settings.probe !== false,
    run: typeof settings.run === 'function' ? settings.run : defaultVersionRun,
    nowMs: resolveNowMs(settings.now),
  }
  const groups = []
  for (const kind of SHELL_KINDS) {
    if (kind === 'powershell') groups.push(buildGroup(kind, collectPowershellCandidates(ctx), ctx))
    else if (kind === 'bash') groups.push(buildGroup(kind, collectBashCandidates(ctx), ctx))
    else groups.push(buildGroup(kind, collectCmdCandidates(ctx), ctx))
  }
  return { generatedAt: new Date(ctx.nowMs).toISOString(), groups }
}

/**
 * Decide which candidate actually gets used.
 *
 * The three levels are tried in order and each one must name a candidate from
 * *this* detection that is still available: a session choice, then the stored
 * default, then the first available candidate. Whenever an explicit choice is
 * dropped, `fallback` says where we came from, where we landed and why — the
 * settings page shows that instead of silently switching shells.
 *
 * `cmd` ignores both choices: `%ComSpec%` is the only cmd answer.
 *
 * @param {ShellKind | string} kind
 * @param {{
 *   sessionChoice?: unknown,
 *   defaults?: unknown,
 *   detection?: ShellDetection | null,
 * }} [options]
 *   sessionChoice: one id or 'auto' for this kind. defaults: the stored
 *   `{ powershell, bash }` object (settings.mjs), or a single id/'auto' when a
 *   caller has only one decision to pass.
 * @returns {{
 *   candidate: ShellCandidate | null,
 *   source: 'session' | 'settings' | 'auto',
 *   fallback: { from: string, to: string | null, reason: string } | null,
 * }}
 */
export function resolveShellSelection(kind, options = {}) {
  const settings = options !== null && typeof options === 'object' ? options : {}
  const detection = settings.detection ?? null

  if (kind === 'cmd') {
    const group = findShellGroup(detection, 'cmd')
    const candidates = group !== null && Array.isArray(group.candidates) ? group.candidates : []
    const fixed = candidates.find((candidate) => candidate !== null && candidate !== undefined && candidate.id === 'cmd-system') ??
      candidates[0] ??
      null
    return { candidate: fixed ?? fallbackCmdCandidate(), source: 'auto', fallback: null }
  }
  if (kind !== 'powershell' && kind !== 'bash') {
    return {
      candidate: null,
      source: 'auto',
      fallback: { from: String(kind), to: null, reason: '未知 shell 类型' },
    }
  }

  const group = findShellGroup(detection, kind)
  const candidates = group === null || !Array.isArray(group.candidates)
    ? []
    : group.candidates.filter((candidate) => candidate !== null && typeof candidate === 'object')
  const sessionChoice = normalizeShellChoice(settings.sessionChoice)
  const defaults = normalizeShellDefaults(settings.defaults)
  // The file stores the per-kind object; a caller that passes only one decision
  // (a future pod_shell argument, a test) is accepted too.
  const defaultChoice = typeof settings.defaults === 'string' ? normalizeShellChoice(settings.defaults) : defaults[kind]
  /** @type {{ from: string, reason: string }[]} */
  const failures = []

  /**
   * @param {string} choice normalized id or 'auto'
   * @returns {ShellCandidate | null}
   */
  const pick = (choice) => {
    if (choice === 'auto') return null
    const candidate = candidates.find((entry) => entry.id === choice) ?? null
    if (candidate !== null && candidate.available === true) return candidate
    failures.push({ from: choice, reason: failureReason(group, candidate) })
    return null
  }

  let candidate = pick(sessionChoice)
  let source = candidate === null ? 'auto' : 'session'
  if (candidate === null) {
    candidate = pick(defaultChoice)
    if (candidate !== null) source = 'settings'
  }
  if (candidate === null) {
    candidate = candidates.find((entry) => entry.available === true) ?? null
    source = 'auto'
  }
  const fallback = failures.length === 0
    ? null
    : {
        from: failures[0].from,
        to: candidate === null ? null : candidate.id,
        reason: failures.map((failure) => failure.reason).join('；'),
      }
  return { candidate, source, fallback }
}

/* ------------------------------------------------------------- internals ----- */

/**
 * @param {unknown} value
 * @returns {string}
 */
function normalizeShellChoice(value) {
  if (typeof value !== 'string') return 'auto'
  const text = value.trim()
  if (text === '' || text.toLowerCase() === 'auto') return 'auto'
  return SHELL_ID_PATTERN.test(text) ? text : 'auto'
}

/**
 * @param {number | (() => number) | undefined} now
 * @returns {number}
 */
function resolveNowMs(now) {
  const value = typeof now === 'function' ? now() : now
  return typeof value === 'number' && Number.isFinite(value) ? value : Date.now()
}

/**
 * @param {unknown} value
 * @returns {string | undefined}
 */
function textValue(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined
}

/**
 * Normalize a path for identity comparisons only; the candidate keeps the path
 * the caller supplied, so a configured value stays recognizable in the UI.
 *
 * Windows paths are case-insensitive and may be reached through symlinks, short
 * names or `..`, so `realpathSync.native` is the authority. A missing file has
 * no real path: fall back to `resolve` (still catches `..` and relative paths)
 * and case-fold on win32.
 *
 * @param {string} file
 * @param {NodeJS.Platform | string} platform
 * @returns {string}
 */
function normalizedPathKey(file, platform) {
  let normalized
  try {
    normalized = realpathSync.native(file)
  } catch {
    normalized = resolve(file)
  }
  return platform === 'win32' ? normalized.toLowerCase() : normalized
}

/**
 * Existence test used for `available`. A file or a symlink counts (a symlink is
 * a deliberate installation shape); a dangling symlink still counts, because
 * the candidate is then reported with `available:true` and a null version
 * instead of being silently dropped.
 *
 * @param {string} file
 * @returns {boolean}
 */
function pathAvailability(file) {
  try {
    if (statSync(file).isFile()) return true
  } catch {
    // fall through: maybe it is a symlink whose target is gone
  }
  try {
    return lstatSync(file).isSymbolicLink()
  } catch {
    return false
  }
}

/**
 * @param {unknown} env
 * @param {NodeJS.Platform | string} platform
 * @returns {string[]}
 */
function pathDirectories(env, platform) {
  const record = env !== null && typeof env === 'object' ? env : {}
  const raw = typeof record.PATH === 'string' ? record.PATH : typeof record.Path === 'string' ? record.Path : ''
  const directories = []
  for (const part of raw.split(platform === 'win32' ? ';' : ':')) {
    // PATH entries are frequently quoted (and empty entries mean "current
    // directory" on Windows, which is never a shell installation).
    const trimmed = part.trim().replace(/^"(.*)"$/, '$1').trim()
    if (trimmed !== '') directories.push(trimmed)
  }
  return directories
}

/**
 * @param {string} name
 * @param {NodeJS.Platform | string} platform
 * @returns {string}
 */
function executableName(name, platform) {
  return platform === 'win32' ? name + '.exe' : name
}

/**
 * dsh-ops PortableGit instances, newest first. The instance directory is the
 * id suffix, which is why the whole list is returned instead of only the
 * winner: the settings page may offer an older instance.
 *
 * @param {unknown} env
 * @returns {{ name: string, file: string }[]}
 */
function opsBashInstances(env) {
  const record = env !== null && typeof env === 'object' ? env : {}
  const home = textValue(record.DSH_HOME)
  if (home === undefined) return []
  const root = join(home, 'dsh-ops', 'bash-ipc')
  let names
  try {
    names = readdirSync(root)
  } catch {
    return []
  }
  const found = []
  for (const name of names) {
    const file = join(root, name, 'bin', 'bash.exe')
    try {
      const stat = statSync(file)
      if (!stat.isFile()) continue
      found.push({ name, file, mtimeMs: stat.mtimeMs })
    } catch {
      // not an extracted instance
    }
  }
  // mtime decides; the name keeps the order deterministic when two instances
  // were written in the same millisecond (a single extraction can do that).
  found.sort((left, right) => right.mtimeMs - left.mtimeMs || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
  return found.map(({ name, file }) => ({ name, file }))
}

/**
 * @param {{ env: any, platform: string }} ctx
 * @returns {{ path: string, source: ShellSource, onlyIfAvailable?: boolean, variant?: string, major?: string }[]}
 */
function collectPowershellCandidates(ctx) {
  const entries = []
  const configured = textValue(ctx.config.pwshPath)
  if (configured !== undefined) entries.push({ path: configured, source: 'config' })
  if (ctx.platform === 'win32') {
    const programFiles = textValue(ctx.env.ProgramFiles) ?? 'C:\\Program Files'
    entries.push({
      path: join(programFiles, 'PowerShell', '7', 'pwsh.exe'),
      source: 'system',
      variant: 'pwsh7',
      major: '7',
      onlyIfAvailable: true,
    })
    const systemRoot = textValue(ctx.env.SystemRoot) ?? 'C:\\Windows'
    // The OS component is always offered: it is the fallback the pod has always
    // used, and its absence should be visible, not silently papered over.
    entries.push({
      path: join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      source: 'system',
      variant: 'windows-powershell',
    })
  }
  for (const directory of pathDirectories(ctx.env, ctx.platform)) {
    entries.push({ path: join(directory, executableName('pwsh', ctx.platform)), source: 'path', onlyIfAvailable: true })
  }
  return entries
}

/**
 * @param {{ env: any, platform: string }} ctx
 * @returns {{ path: string, source: ShellSource, onlyIfAvailable?: boolean, variant?: string, instance?: string }[]}
 */
function collectBashCandidates(ctx) {
  const entries = []
  const configured = textValue(ctx.config.bashPath)
  if (configured !== undefined) entries.push({ path: configured, source: 'config' })
  const fromEnv = textValue(ctx.env.DSH_ESCAPE_POD_BASH)
  if (fromEnv !== undefined) entries.push({ path: fromEnv, source: 'env' })
  for (const instance of opsBashInstances(ctx.env)) {
    entries.push({ path: instance.file, source: 'plugin', instance: instance.name, onlyIfAvailable: true })
  }
  if (ctx.platform === 'win32') {
    const programFiles = textValue(ctx.env.ProgramFiles) ?? 'C:\\Program Files'
    entries.push({
      path: join(programFiles, 'Git', 'bin', 'bash.exe'),
      source: 'system',
      variant: 'git',
      onlyIfAvailable: true,
    })
    const programFilesX86 = textValue(ctx.env['ProgramFiles(x86)']) ?? 'C:\\Program Files (x86)'
    entries.push({
      path: join(programFilesX86, 'Git', 'bin', 'bash.exe'),
      source: 'system',
      variant: 'git-x86',
      onlyIfAvailable: true,
    })
  }
  for (const directory of pathDirectories(ctx.env, ctx.platform)) {
    entries.push({ path: join(directory, executableName('bash', ctx.platform)), source: 'path', onlyIfAvailable: true })
  }
  return entries
}

/**
 * @param {{ env: any, platform: string }} ctx
 * @returns {{ path: string, source: ShellSource }[]}
 */
function collectCmdCandidates(ctx) {
  const comspec = textValue(ctx.env.ComSpec)
  const systemRoot = textValue(ctx.env.SystemRoot) ?? 'C:\\Windows'
  return [{ path: comspec ?? join(systemRoot, 'System32', 'cmd.exe'), source: 'system' }]
}

/**
 * Turn ordered raw paths into one group: dedupe, stat, probe, id.
 *
 * @param {ShellKind} kind
 * @param {{ path: string, source: ShellSource, onlyIfAvailable?: boolean, variant?: string, major?: string, instance?: string }[]} rawEntries
 * @param {{ platform: string, probe: boolean, cache: boolean, run: Function, nowMs: number }} ctx
 * @returns {ShellGroup}
 */
function buildGroup(kind, rawEntries, ctx) {
  const seen = new Set()
  const unique = []
  for (const entry of rawEntries) {
    const file = typeof entry.path === 'string' ? entry.path.trim() : ''
    if (file === '') continue
    // One real file = one candidate, at the highest-priority source that
    // reached it (the collectors already ordered sources).
    const key = normalizedPathKey(file, ctx.platform)
    if (seen.has(key)) continue
    seen.add(key)
    unique.push({ ...entry, path: file })
  }

  const prepared = []
  for (const entry of unique) {
    const available = pathAvailability(entry.path)
    if (entry.onlyIfAvailable === true && !available) continue
    // A missing file is reported as unavailable with no version: spawning it
    // would only produce a misleading error, and `null` is the honest answer.
    const version = ctx.probe && available ? probeShellVersion(kind, entry.path, ctx) : null
    prepared.push({ ...entry, available, version })
  }

  const used = new Set()
  let pathOrdinal = 0
  const candidates = []
  for (const entry of prepared) {
    if (entry.source === 'path') pathOrdinal += 1
    candidates.push({
      id: useShellId(baseShellId(kind, entry, pathOrdinal), used),
      kind,
      path: entry.path,
      version: entry.version,
      source: entry.source,
      available: entry.available,
      label: shellLabel(kind, entry),
      note: shellNote(kind, entry),
    })
  }
  return { kind, selectable: kind !== 'cmd', fixed: kind === 'cmd', candidates }
}

/**
 * Prefer the version as the readable half of the id, exactly as specified:
 * `pwsh-7.4` for PowerShell 7.4.6, `bash-git-5.2` for Git Bash 5.2.37. When the
 * probe was skipped or failed there is no version to name the build, so the id
 * falls back to something that is still deterministic without probing.
 *
 * @param {ShellKind} kind
 * @param {{ source: ShellSource, variant?: string, major?: string, version: string | null, instance?: string }} entry
 * @param {number} pathOrdinal
 * @returns {string}
 */
function baseShellId(kind, entry, pathOrdinal) {
  // cmd is a fixed, non-selectable answer: the id must never encode a version,
  // or a Windows build update would silently rename the only cmd candidate.
  if (kind === 'cmd') return 'cmd-system'
  if (kind === 'powershell') {
    if (entry.source === 'config') return 'pwsh-config'
    if (entry.variant === 'windows-powershell') return 'ps-system'
    const fromVersion = majorMinor(entry.version)
    if (fromVersion !== null) return 'pwsh-' + fromVersion
    if (typeof entry.major === 'string' && entry.major !== '') return 'pwsh-' + entry.major
    return 'pwsh-path-' + pathOrdinal
  }
  if (entry.source === 'config') return 'bash-config'
  if (entry.source === 'env') return 'bash-env'
  if (entry.source === 'plugin') return 'bash-ops-' + instanceSuffix(entry.instance)
  if (entry.source === 'system') {
    const fromVersion = majorMinor(entry.version)
    return fromVersion === null ? 'bash-git' : 'bash-git-' + fromVersion
  }
  return 'bash-path-' + pathOrdinal
}

/**
 * Ids are stable strings a user may have saved, so a collision must never
 * overwrite, renumber or reuse one: append `-2`, `-3`, …
 *
 * @param {string} base
 * @param {Set<string>} used
 * @returns {string}
 */
function useShellId(base, used) {
  if (!used.has(base)) {
    used.add(base)
    return base
  }
  let suffix = 2
  while (used.has(base + '-' + suffix)) suffix += 1
  const id = base + '-' + suffix
  used.add(id)
  return id
}

/**
 * @param {string | null | undefined} version
 * @returns {string | null}
 */
function majorMinor(version) {
  if (typeof version !== 'string') return null
  const match = version.match(/^(\d+)(?:\.(\d+))?/)
  if (match === null) return null
  return match[2] === undefined ? match[1] : match[1] + '.' + match[2]
}

/**
 * @param {unknown} instance
 * @returns {string}
 */
function instanceSuffix(instance) {
  const text = typeof instance === 'string' ? instance.replace(/[^A-Za-z0-9_-]/g, '') : ''
  return text === '' ? 'x' : text.slice(0, 8)
}

/**
 * @param {ShellKind} kind
 * @param {{ source: ShellSource, variant?: string, major?: string, version: string | null }} entry
 * @returns {string}
 */
function shellLabel(kind, entry) {
  if (kind === 'cmd') return 'cmd.exe（固定）'
  if (kind === 'powershell') {
    if (entry.variant === 'windows-powershell') {
      const key = majorMinor(entry.version)
      return 'Windows PowerShell ' + (key === null ? '5.1' : key)
    }
    if (entry.source === 'config') return 'PowerShell（配置 pwshPath）'
    if (entry.source === 'system') {
      return entry.version === null ? 'PowerShell ' + (entry.major ?? '7') : 'PowerShell ' + entry.version
    }
    return entry.version === null ? 'PATH 中的 pwsh' : 'PowerShell ' + entry.version + '（PATH）'
  }
  if (entry.source === 'config') return 'bash（配置 bashPath）'
  if (entry.source === 'env') return 'bash（环境变量 DSH_ESCAPE_POD_BASH）'
  if (entry.source === 'plugin') return 'PortableGit（dsh-ops）'
  if (entry.source === 'system') return entry.variant === 'git-x86' ? 'Git Bash（x86）' : 'Git Bash'
  return 'PATH 中的 bash'
}

/**
 * @param {ShellKind} kind
 * @param {{ source: ShellSource }} entry
 * @returns {string | null}
 */
function shellNote(kind, entry) {
  if (kind === 'bash' && (entry.source === 'system' || entry.source === 'path')) return BASH_RESTRICTED_TOKEN_NOTE
  return null
}

/**
 * @param {string} file
 * @param {string[]} args
 * @returns {unknown}
 */
function defaultVersionRun(file, args) {
  return spawnSync(file, args, {
    timeout: SHELL_PROBE_TIMEOUT_MS,
    windowsHide: true,
    encoding: 'utf8',
  })
}

/**
 * Ask one executable for its version, through the cache.
 *
 * The key includes the kind because the same path is invoked differently per
 * kind, and the TTL exists so a settings page that re-renders does not spawn a
 * shell per keystroke. Failures are cached too: a probe that fails for a
 * transient reason must not flip ids back and forth within one minute.
 *
 * @param {ShellKind} kind
 * @param {string} file
 * @param {{ platform: string, cache: boolean, run: Function, nowMs: number }} ctx
 * @returns {string | null}
 */
function probeShellVersion(kind, file, ctx) {
  const key = kind + '\u0000' + normalizedPathKey(file, ctx.platform)
  if (ctx.cache) {
    const cached = versionCache.get(key)
    if (cached !== undefined && ctx.nowMs - cached.at < SHELL_VERSION_TTL_MS) return cached.version
  }
  const version = runVersionCommand(kind, file, ctx.run)
  if (ctx.cache) versionCache.set(key, { version, at: ctx.nowMs })
  return version
}

/**
 * Execute the probe and normalize its answer. Everything about the child is
 * untrusted (it may be missing, not executable, hung, or killed by the
 * sandbox), so every failure path answers `null` — this function must never
 * throw: shell discovery runs on a settings request and may not break it.
 *
 * @param {ShellKind} kind
 * @param {string} file
 * @param {Function} run
 * @returns {string | null}
 */
function runVersionCommand(kind, file, run) {
  let command
  try {
    command = shellVersionCommand(kind, file)
  } catch {
    return null
  }
  let result
  try {
    result = run(command.file, command.args)
  } catch {
    return null
  }
  if (result === null || typeof result !== 'object') return null
  const outcome = /** @type {{ error?: unknown, signal?: unknown, status?: unknown, stdout?: unknown }} */ (result)
  if (outcome.error !== undefined && outcome.error !== null) return null
  if (outcome.signal !== undefined && outcome.signal !== null) return null
  if (typeof outcome.status === 'number' && outcome.status !== 0) return null
  return parseVersionOutput(kind, outcome.stdout)
}

/**
 * Read the version out of the probe's first meaningful line.
 *
 * bash prints a whole sentence ("GNU bash, version 5.2.37(1)-release …"), so
 * the numeric token is extracted; keeping the sentence would make
 * `bash-git-<major.minor>` impossible and the label unreadable. cmd prints
 * "Microsoft Windows [Version 10.0.…]". PowerShell prints the bare version
 * (possibly after a warning line).
 *
 * @param {ShellKind} kind
 * @param {unknown} stdout
 * @returns {string | null}
 */
function parseVersionOutput(kind, stdout) {
  const text = String(stdout ?? '').replace(/\r\n/g, '\n').trim()
  if (text === '') return null
  if (kind === 'powershell') {
    const match = text.match(/\d+(?:\.\d+)+/)
    return match === null ? firstLine(text) : match[0]
  }
  if (kind === 'bash') {
    const line = firstLine(text)
    if (line === null) return null
    const match = line.match(/version\s+(\d+(?:\.\d+)+)/i)
    return match === null ? line : match[1]
  }
  // cmd's `ver` is localized ("[Version 10.0.…]" / "[版本 10.0.…]"), and its
  // stdout is OEM-encoded, so the numeric token is the only locale-proof part.
  const match = text.match(/\d+(?:\.\d+){2,}/)
  if (match !== null) return match[0]
  return firstLine(text)
}

/**
 * @param {string} text
 * @returns {string | null}
 */
function firstLine(text) {
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed !== '') return trimmed
  }
  return null
}

/**
 * @param {ShellDetection | null} detection
 * @param {ShellKind} kind
 * @returns {ShellGroup | null}
 */
function findShellGroup(detection, kind) {
  if (detection === null || typeof detection !== 'object' || !Array.isArray(detection.groups)) return null
  return detection.groups.find((group) => group !== null && typeof group === 'object' && group.kind === kind) ?? null
}

/**
 * @param {ShellGroup | null} group
 * @param {ShellCandidate | null} candidate
 * @returns {string}
 */
function failureReason(group, candidate) {
  if (group === null) return '探测结果缺失，已失效'
  if (candidate === null) return '候选未探测到'
  return 'path 不存在'
}

/**
 * `cmd` has no detection on which to hang its answer when the caller passes no
 * detection at all. The pod's cmd argv path already relies on CreateProcess
 * resolving a bare `cmd.exe`, so this fallback is the same fact stated as data.
 *
 * @returns {ShellCandidate}
 */
function fallbackCmdCandidate() {
  return {
    id: 'cmd-system',
    kind: 'cmd',
    path: 'cmd.exe',
    version: null,
    source: 'system',
    available: false,
    label: 'cmd.exe（固定）',
    note: '未探测到 ComSpec，交给 CreateProcess 按 PATH 解析',
  }
}
