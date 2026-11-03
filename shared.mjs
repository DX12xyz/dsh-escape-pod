/**
 * Shared vocabulary for the escape-pod-core bundle: the Host plugin (`index.js`)
 * and the detached pod (`pod.mjs`) must agree byte-for-byte on the pipe name
 * derivation, the windows-acl runner prefix contract, the ledger layout and the
 * output-offset arithmetic. Keeping them in one module is what stops the two
 * sides from drifting.
 *
 * THE PREFIX IS PER CALL. `ctx.sandbox.confine()` mints a `--temp-write-sid` that
 * belongs to exactly one session/workspace pair and is revocable when that Host
 * exits, so a prefix captured at pod-spawn time would be stale-garbage after a
 * DSH restart (the runner validates its SIDs and exits 127). Therefore:
 *
 *   - the Host calls `confine(['node', <placeholder>], policy)` before EVERY
 *     `pod_run`, takes everything before `--`, and sends it with the command;
 *   - the pod holds no prefix at rest — only a pinned SHAPE TEMPLATE
 *     (program + runner path inside the DSH install tree + mode + workspace
 *     root). A per-call prefix is accepted only if it matches that template,
 *     the runner path is structurally inside the DSH install tree, the flags are
 *     the known ones and paired correctly, the paths exist, and the array stops
 *     before `--` (so the pod's `prefix + argv` concatenation is the only way a
 *     command line is formed). Anything else fails closed.
 */

import os from 'node:os'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import { statSync } from 'node:fs'

// 2 = authenticated + single-client pipe (spawn token, handover op, stable seed).
// 3 = per-call `mode` + `unescorted` run requests (the command now follows the
//     DSH session's file policy instead of one hard-coded workspace-write).
//     The run request SHAPE changed, so a Host must not send the new fields to a
//     v2 pod (it would run the command under the old policy while believing the
//     narrower/wider mode was in effect) and a v3 pod must not serve them blind.
export const PROTOCOL_VERSION = 3
/**
 * Session file-policy modes, ordered narrow → wide. The index is the whole
 * authority comparison: a wider mode needs approval, a narrower one is a
 * protocol error (an approval is never used to down-shift a policy).
 */
export const SANDBOX_MODES = ['read-only', 'workspace-write', 'danger-full-access']
/**
 * The only modes that produce a confined runner prefix. `danger-full-access`
 * has NO prefix: the command is spawned with the pod's own Medium token (see
 * pod.mjs), so a prefix claiming that mode is a protocol violation.
 */
export const CONFINED_MODES = ['read-only', 'workspace-write']
export const PIPE_PREFIX = '\\\\.\\pipe\\'
export const PIPE_STEM = 'dsh-escape-pod-core-'
export const DEFAULT_IDLE_EXIT_MS = 12 * 60 * 60 * 1000
/**
 * LAST-RESORT pod-side read window, not the escape pod's own policy knob.
 *
 * The Host reads the live native shell budgets (`timeoutMs` / `maxOutputBytes`)
 * on EVERY tool call and sends the output window with the request; the pod only
 * clamps whatever it receives to {@link MAX_OUTPUT_CHUNK_BYTES}. This constant
 * therefore matters in exactly two cases: a pod spawned by an OLD Host that
 * predates the live-limit request fields, and the maintenance CLI
 * (`scripts/pod-raw.mjs`) that has no Host context at all.
 *
 * 64000 is the native default of `@deepseek-ai/dsh-pwsh-local`
 * (`lib/index.js` `Config.maxOutputBytes = z.number().default(64e3)`), so a
 * client that sends nothing gets what the native shell would have allowed. The
 * previous hard-coded 65536 was 1536 bytes ABOVE that native budget — that is
 * exactly why this is a fallback with a cited source instead of a magic number.
 */
export const FALLBACK_OUTPUT_CHUNK_BYTES = 64_000
/** @deprecated Import {@link FALLBACK_OUTPUT_CHUNK_BYTES}; kept for older importers (same value). */
export const DEFAULT_OUTPUT_CHUNK_BYTES = FALLBACK_OUTPUT_CHUNK_BYTES
export const MAX_OUTPUT_CHUNK_BYTES = 1024 * 1024
export const DEFAULT_RING_BYTES = 256 * 1024
export const MAX_PROTOCOL_LINE_BYTES = 2 * 1024 * 1024
export const LEDGER_DIR_NAME = 'escape-pod-core'
/** Job ids are directory names, so the shape is also the path-traversal guard. */
export const JOB_ID_PATTERN = /^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$/
/**
 * Session-ownership decision for one ledger job, shared by the Host and the pod
 * so the two layers cannot disagree.
 *
 * `null` means "no session": a ledger entry written before the boundary existed
 * (legacy meta.json) or a Host-level operation. A null job is only accessible
 * to a null caller — a real DSH session must pass `adopt: true` for it, exactly
 * like a job owned by another session. A null caller likewise cannot read a
 * session-owned job without adopting it.
 *
 * @param {unknown} jobSessionId owner recorded on the job (`string | null`)
 * @param {unknown} callerSessionId asking session (`string | null`)
 * @param {boolean} [adopt] explicit cross-session takeover flag
 * @returns {{
 *   owner: string | null,
 *   caller: string | null,
 *   foreign: boolean,
 *   allowed: boolean,
 *   adoptedFrom: string | null | undefined,
 * }}
 */
export function jobOwnership(jobSessionId, callerSessionId, adopt = false) {
  const owner = typeof jobSessionId === 'string' && jobSessionId !== '' ? jobSessionId : null
  const caller = typeof callerSessionId === 'string' && callerSessionId !== '' ? callerSessionId : null
  const foreign = owner !== caller
  return {
    owner,
    caller,
    foreign,
    allowed: foreign !== true || adopt === true,
    // Present only for an explicit takeover that actually crossed a boundary;
    // `null` is a real answer here (the job is unowned history).
    adoptedFrom: foreign === true && adopt === true ? owner : undefined,
  }
}
export const RUNNER_BASENAME = 'runner.js'
export const PREFIX_FLAGS = ['--workspace', '--temp', '--mode', '--write-sid', '--temp-write-sid']
/** Longest spawn command line this pod accepts (Windows CreateProcess limit is 32767). */
export const MAX_COMMAND_LINE_CHARS = 30000

/** @param {unknown} value */
export function optionalString(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined
}

/**
 * Deterministic pipe name shared by the Host plugin and the pod. The stem is
 * pod-core's own (`dsh-escape-pod-core-`), so it can never collide with the
 * control pod (`dsh-escape-pod-`) or the sandboxed judgement pod
 * (`dsh-escape-pod-sbx-`).
 *
 * The suffix is derived from a STABLE IDENTITY, not from `DSH_HOME`: an install
 * path is configuration, and using it as the seed made a DSH_HOME rename spawn a
 * second pod while the first one (and every job it owned) became an unreachable
 * orphan. See {@link resolveIdentitySeed} for the seed and its limits.
 * @param {string | undefined} override
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function resolvePipeName(override, env = process.env) {
  const explicit = optionalString(override)
  if (explicit !== undefined) return explicit.startsWith(PIPE_PREFIX) ? explicit : PIPE_PREFIX + explicit
  const seed = resolveIdentitySeed(env)
  const digest = createHash('sha256')
    .update(seed.replace(/[\\/]+$/, '').toLowerCase())
    .digest('hex')
    .slice(0, 12)
  return PIPE_PREFIX + PIPE_STEM + digest
}

/**
 * Version of the identity seed derivation. Bumping it deliberately renames the
 * pipe (all running pods become unreachable orphans, by design), so the value is
 * part of the seed string and therefore visible in the hash.
 */
export const IDENTITY_SEED_VERSION = 1
export const IDENTITY_SEED_KIND = 'user+hostname'

/**
 * Stable identity parts for the pipe seed: the current user and the machine.
 * Both come from the OS, not from DSH configuration, so moving/renaming
 * `DSH_HOME`, reinstalling DSH or switching profiles does NOT change the pipe
 * name and orphan a running pod.
 *
 * THIS IS AN APPROXIMATION, not an OS identity:
 *   - `os.userInfo().username` is a display name, not a SID (a renamed account
 *     looks like a different user; two same-named accounts look identical);
 *   - it does not distinguish sessions or Windows logon sessions.
 *
 * TODO(P2, native): replace this with the real user SID
 * (`GetTokenInformation(TokenUser)` / `whoami /user`), so "one escape pod per
 * user" is anchored to the OS identity. That needs a native binding and was
 * explicitly out of scope for this round.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ user: string, host: string }}
 */
export function resolveIdentityParts(env = process.env) {
  let user = ''
  try {
    user = os.userInfo().username
  } catch {
    user = optionalString(env.USERNAME) ?? optionalString(env.USER) ?? ''
  }
  let host = ''
  try {
    host = os.hostname()
  } catch {
    host = optionalString(env.COMPUTERNAME) ?? ''
  }
  return { user: String(user).toLowerCase(), host: String(host).toLowerCase() }
}

/**
 * The exact string whose hash names the pipe. Stable across DSH_HOME/profile
 * changes; changes only when the user, the machine or
 * {@link IDENTITY_SEED_VERSION} changes.
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveIdentitySeed(env = process.env) {
  const parts = resolveIdentityParts(env)
  return 'v' + String(IDENTITY_SEED_VERSION) + '|' + IDENTITY_SEED_KIND + '|' + parts.user + '|' + parts.host
}

/** @param {string} [seed] */
export function identitySeedHash(seed = resolveIdentitySeed()) {
  return createHash('sha256')
    .update(seed.replace(/[\\/]+$/, '').toLowerCase())
    .digest('hex')
    .slice(0, 12)
}

/**
 * Human-facing description of the identity a pipe name was derived from. Logged
 * by the pod at startup and reported by `pod_status`, so "which identity
 * computed this pipe" is answerable without guessing. The raw seed is not a
 * secret (user + machine name), but only the hash is needed to compare.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ seedKind: string, seedVersion: number, user: string, host: string, seedHash: string, note: string }}
 */
export function describePipeIdentity(env = process.env) {
  const parts = resolveIdentityParts(env)
  return {
    seedKind: IDENTITY_SEED_KIND,
    seedVersion: IDENTITY_SEED_VERSION,
    user: parts.user,
    host: parts.host,
    seedHash: identitySeedHash(resolveIdentitySeed(env)),
    note: 'approximation: os.userInfo().username + os.hostname(); TODO(P2): native user SID',
  }
}

/**
 * Spawn-time pipe token: 32 random bytes, hex. It travels from the Host to the
 * pod through the pod's STDIN (never argv, which is visible in the process list)
 * and lives ONLY in the two processes' memory — it is never written to the
 * ledger, a config file or an env var.
 */
export const POD_TOKEN_BYTES = 32
export const POD_TOKEN_HEX_LENGTH = POD_TOKEN_BYTES * 2
export const POD_TOKEN_PATTERN = /^[0-9a-f]{64}$/

/** @returns {string} */
export function generatePodToken() {
  return randomBytes(POD_TOKEN_BYTES).toString('hex')
}

/** @param {unknown} value */
export function isPodToken(value) {
  return typeof value === 'string' && POD_TOKEN_PATTERN.test(value)
}

/**
 * Constant-time token comparison. Length/format are rejected first (the token
 * shape is public), then the 32 bytes are compared without an early exit.
 * @param {unknown} left @param {unknown} right
 */
export function tokensEqual(left, right) {
  if (!isPodToken(left) || !isPodToken(right)) return false
  return timingSafeEqual(Buffer.from(/** @type {string} */ (left), 'hex'), Buffer.from(/** @type {string} */ (right), 'hex'))
}

/** Safe-to-log fingerprint of a token; never log or return the token itself. */
export function tokenFingerprint(token) {
  if (typeof token !== 'string' || token === '') return null
  return createHash('sha256').update(token).digest('hex').slice(0, 12)
}

/** @param {unknown} value */
export function toFiniteInt(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/**
 * Clamp an optional integer argument into `[min, max]`, falling back to
 * `fallback` when it is absent or not a finite number.
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 */
export function clampInt(value, fallback, min, max) {
  const numeric = toFiniteInt(value)
  if (numeric === undefined) return fallback
  return Math.min(max, Math.max(min, Math.trunc(numeric)))
}

/** @param {string} path */
export function isDirectorySync(path) {
  try {
    return statSync(path).isDirectory()
  } catch {
    return false
  }
}

/** @param {string} path */
export function isFileSync(path) {
  try {
    return statSync(path).isFile()
  } catch {
    return false
  }
}

/**
 * Whether `candidate` is `root` or lives below it (canonicalized, Windows
 * case-insensitive through path.relative). Used to keep the ledger inside the
 * workspace the policy named.
 * @param {string} root
 * @param {string} candidate
 */
export function isInsideDirectory(root, candidate) {
  try {
    const rel = relative(resolve(root), resolve(candidate))
    return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith('..\\') && !rel.startsWith('../'))
  } catch {
    return false
  }
}

/**
 * Comparison key for host paths: resolved separators + Windows case folding.
 * @param {string} path
 */
export function normalizePathKey(path) {
  return resolve(path).replaceAll('/', '\\').toLowerCase()
}

/**
 * Structural "the runner lives inside a DSH installation tree" check. The
 * windows-acl runner is always resolved from the sandbox package inside a
 * `node_modules` tree (`…/node_modules/@deepseek-ai/dsh-sandbox-windows-acl/lib/
 * runner.js`, pnpm layouts included). A runner anywhere else — including the
 * tsx/source fallback the provider uses in a development checkout — is rejected
 * fail-closed: this experiment only supports the built runner contract.
 * @param {unknown} path
 */
export function isDshInstallRunnerPath(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) return false
  if (basename(path).toLowerCase() !== RUNNER_BASENAME) return false
  const folded = path.replaceAll('/', '\\').toLowerCase()
  return (
    folded.includes('\\node_modules\\@deepseek-ai\\') &&
    folded.includes('\\dsh-sandbox-windows-acl\\') &&
    folded.endsWith('\\lib\\' + RUNNER_BASENAME)
  )
}

/**
 * The ledger root for one workspace is deliberately OUTSIDE the workspace: a
 * managed command runs under a `workspace-write` grant, so a ledger inside the
 * workspace would be writable by the very command it records — the command could
 * forge `meta.json`/`out.log`/`exit.json` and fake its own verdict. Default is
 * `%LOCALAPPDATA%\dsh-escape-pod-core\` (research note §6.3), which the confined
 * command cannot write; `DSH_HOME\.escape-pod-core` and the home directory are
 * fallbacks, and the `stateDir` config may override it with another directory
 * that must still be outside the policy workspace (both the Host and the pod
 * re-check that with {@link isInsideDirectory}).
 * @param {string | undefined} configured
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function resolveStateDir(configured, env = process.env) {
  const explicit = optionalString(configured)
  if (explicit !== undefined) return resolve(explicit)
  const localAppData = optionalString(env.LOCALAPPDATA)
  if (localAppData !== undefined) return join(localAppData, 'dsh-escape-pod-core')
  const dshHome = optionalString(env.DSH_HOME)
  if (dshHome !== undefined) return join(dshHome, '.escape-pod-core')
  return join(os.homedir(), '.dsh-escape-pod-core')
}

/** @param {readonly string[]} prefix */
export function fingerprintPrefix(prefix) {
  return createHash('sha256').update(JSON.stringify(prefix)).digest('hex')
}

/**
 * Audit hash of the exact target argv a job runs. Stored in `meta.json` next to
 * the full argv, so a log/ledger copy can be checked without re-persisting the
 * whole command line in human-facing reports.
 * @param {readonly string[]} argv
 */
export function hashArgv(argv) {
  return createHash('sha256').update(JSON.stringify(argv)).digest('hex')
}

/**
 * @typedef {{
 *   program: string,
 *   runnerPath: string,
 *   workspaceRoot: string,
 *   enforcement: 'full' | 'partial' | null,
 *   modes: string[],
 * }} PrefixTemplate
 */

/**
 * Validate the pinned shape template the pod holds. The template is *not* a
 * prefix: it carries no SID and no temp path, so it stays valid across Host
 * restarts. It pins the program, the runner path (inside the DSH install tree)
 * and the workspace root.
 *
 * MODE IS DELIBERATELY NOT PINNED. The session's file policy can legitimately
 * change between calls (a read-only session is widened by an approval, a
 * workspace-write session is narrowed by the user), and a mode-pinned template
 * would reject the legal per-call prefix that follows — or force the Host to
 * keep minting prefixes for a mode that is no longer in effect. What must stay
 * pinned is what an attacker cannot renegotiate: which binary and which runner
 * (and therefore which confinement implementation) may ever appear in a
 * prefix, and which workspace the command may stand in.
 *
 * `modes` is documentation for status output only; the authority check happens
 * per call from the request's own `mode` (see {@link validatePrefix}).
 * @param {unknown} raw
 * @returns {{ ok: true, template: PrefixTemplate } | { ok: false, code: string, message: string }}
 */
export function validateTemplate(raw) {
  /** @param {string} code @param {string} message */
  const fail = (code, message) => ({ ok: /** @type {const} */ (false), code, message })
  if (raw === null || typeof raw !== 'object') return fail('EPREFIXTEMPLATE', '形态校验模板不是对象')
  const source = /** @type {Record<string, unknown>} */ (raw)
  const program = optionalString(source.program)
  const runnerPath = optionalString(source.runnerPath)
  const workspaceRoot = optionalString(source.workspaceRoot)
  if (program === undefined || !isAbsolute(program)) return fail('EPREFIXPROGRAM', '模板的 program 不是绝对路径')
  if (runnerPath === undefined || !isAbsolute(runnerPath)) return fail('EPREFIXRUNNERPATH', '模板的 runnerPath 不是绝对路径')
  if (!isDshInstallRunnerPath(runnerPath)) {
    return fail('EPREFIXRUNNERPATH', '模板的 runnerPath 不在 DSH 安装树内（必须形如 …\\node_modules\\@deepseek-ai\\dsh-sandbox-windows-acl\\lib\\runner.js）：' + runnerPath)
  }
  if (!isFileSync(runnerPath)) return fail('EPREFIXRUNNERPATH', '模板的 runnerPath 不是已存在的文件：' + runnerPath)
  if (workspaceRoot === undefined || !isAbsolute(workspaceRoot)) return fail('EPREFIXWORKSPACE', '模板的 workspaceRoot 不是绝对路径')
  if (!isDirectorySync(workspaceRoot)) return fail('EPREFIXWORKSPACE', '模板的 workspaceRoot 不是已存在的目录：' + workspaceRoot)
  const enforcementRaw = source.enforcement
  const enforcement = enforcementRaw === 'full' || enforcementRaw === 'partial' ? enforcementRaw : null
  if (enforcementRaw !== null && enforcementRaw !== undefined && enforcement === null) {
    return fail('EPREFIXENFORCEMENT', '模板的 enforcement 只能是 full/partial/null')
  }
  /** @type {string[]} */
  let modes = [...CONFINED_MODES]
  const modesRaw = source.modes
  if (modesRaw !== undefined) {
    if (!Array.isArray(modesRaw) || modesRaw.length === 0) {
      return fail('EPREFIXMODE', '模板的 modes 必须是非空数组（只允许 read-only / workspace-write）')
    }
    for (const candidate of modesRaw) {
      if (!CONFINED_MODES.includes(candidate)) {
        return fail('EPREFIXMODE', '模板的 modes 只能包含 read-only / workspace-write，收到：' + String(candidate))
      }
    }
    modes = [...new Set(modesRaw)]
  }
  return {
    ok: /** @type {const} */ (true),
    template: { program, runnerPath, workspaceRoot, enforcement, modes },
  }
}

/**
 * @typedef {{
 *   program: string,
 *   runner: string,
 *   mode: string,
 *   workspaceRoot: string,
 *   tempDir: string,
 *   seamManaged: boolean,
 *   writeSid: string | null,
 *   tempWriteSid: string | null,
 * }} PrefixProfile
 */

/**
 * Shape-check one Host-issued per-call runner prefix. This is deliberately a
 * validator, not a builder: every failure returns `ok: false` and the caller
 * must refuse to run anything.
 *
 * With a template, the prefix must also match the pinned program / runner path /
 * workspace root. Without one (the Host validating what `confine()`
 * returned, before a template exists) the generic shape plus the DSH-install-tree
 * runner check is enough.
 *
 * `expectedMode` is the mode the CALLER resolved from the session policy (the
 * pod requires it on every run request). The prefix's own `--mode` must equal
 * it: otherwise the Host approved one policy and the pod would execute another.
 * When it is omitted (the Host validating its own confine result, or an older
 * caller), the prefix's mode is accepted as long as it is one of the confined
 * modes.
 *
 * Existence checks turn a stale prefix (the session temp directory the previous
 * Host owned and reclaimed on shutdown) into a distinct, actionable error instead
 * of a runner exit 127.
 *
 * @param {unknown} raw
 * @param {PrefixTemplate | null} [template]
 * @param {string | null} [expectedMode]
 * @returns {{ ok: true, prefix: string[], program: string, args: string[], profile: PrefixProfile, fingerprint: string }
 *   | { ok: false, code: string, message: string }}
 */
export function validatePrefix(raw, template = null, expectedMode = null) {
  /** @param {string} code @param {string} message */
  const fail = (code, message) => ({ ok: /** @type {const} */ (false), code, message })

  if (!Array.isArray(raw)) return fail('EPREFIXINVALID', 'runner 前缀不是数组')
  if (raw.length < 2) return fail('EPREFIXINVALID', 'runner 前缀过短（至少要有程序与 runner.js）')
  /** @type {string[]} */
  const prefix = []
  for (const value of raw) {
    if (typeof value !== 'string') return fail('EPREFIXINVALID', 'runner 前缀包含非字符串元素')
    if (value.includes('\u0000')) return fail('EPREFIXINVALID', 'runner 前缀包含 NUL 字符')
    prefix.push(value)
  }
  if (prefix[0] === '') return fail('EPREFIXINVALID', 'runner 前缀的程序为空')
  if (basename(prefix[1]).toLowerCase() !== RUNNER_BASENAME) {
    return fail('EPREFIXRUNNER', 'runner 前缀的第二个元素不是 ' + RUNNER_BASENAME + '：' + basename(prefix[1]))
  }
  if (!isDshInstallRunnerPath(prefix[1])) {
    return fail('EPREFIXRUNNERPATH', 'runner 路径不在 DSH 安装树内（必须形如 …\\node_modules\\@deepseek-ai\\dsh-sandbox-windows-acl\\lib\\runner.js）：' + prefix[1])
  }
  // The prefix must stop BEFORE the `--` separator: the pod forms the command
  // line only as `prefix + argv`, never by re-parsing a full confined argv.
  if (prefix.includes('--')) {
    return fail('EPREFIXINVALID', 'runner 前缀必须只包含 `--` 之前的部分（分隔符由 pod 拼接时构造）')
  }

  /** @type {Record<string, string>} */
  const flags = {}
  for (let index = 2; index < prefix.length; index += 1) {
    const token = prefix[index]
    if (!token.startsWith('--')) return fail('EPREFIXTOKEN', 'runner 前缀出现位置参数：' + token)
    if (!PREFIX_FLAGS.includes(token)) return fail('EPREFIXFLAG', 'runner 前缀出现未知标志：' + token)
    const value = prefix[index + 1]
    if (value === undefined || value.startsWith('--')) return fail('EPREFIXVALUE', token + ' 缺少值')
    if (Object.prototype.hasOwnProperty.call(flags, token)) return fail('EPREFIXDUP', 'runner 前缀出现重复标志：' + token)
    flags[token] = value
    index += 1
  }

  const workspaceRoot = flags['--workspace']
  const tempDir = flags['--temp']
  const mode = flags['--mode']
  if (workspaceRoot === undefined) return fail('EPREFIXINVALID', 'runner 前缀缺少 --workspace')
  if (tempDir === undefined) return fail('EPREFIXINVALID', 'runner 前缀缺少 --temp')
  // Only the two confined modes may ever appear in a prefix. `danger-full-access`
  // runs as a bare argv with the pod's own token, so a prefix claiming it is a
  // protocol violation rather than a stronger grant.
  if (!CONFINED_MODES.includes(mode)) {
    return fail('EPREFIXMODE', 'runner 前缀的 --mode 只能是 read-only 或 workspace-write（danger-full-access 从不带前缀），收到：' + String(mode))
  }
  if (expectedMode !== null && expectedMode !== undefined && mode !== expectedMode) {
    return fail(
      'EPREFIXMODEREQUEST',
      'runner 前缀的 --mode 与本次请求的 mode 不一致：前缀 ' + String(mode) + '，请求 ' + String(expectedMode) +
        '。Host 批准的策略与实际执行的策略必须同一个，因此拒绝执行。',
    )
  }
  if (!isAbsolute(workspaceRoot)) return fail('EPREFIXINVALID', '--workspace 不是绝对路径：' + workspaceRoot)
  if (!isAbsolute(tempDir)) return fail('EPREFIXINVALID', '--temp 不是绝对路径：' + tempDir)
  if (!isDirectorySync(workspaceRoot)) {
    return fail('EPREFIXWORKSPACE', '--workspace 不是已存在的目录：' + workspaceRoot)
  }
  if (!isDirectorySync(tempDir)) {
    return fail('EPREFIXSTALE', '--temp 不是已存在的目录（Host 退出会收回旧会话临时目录，旧前缀失效）：' + tempDir)
  }

  const writeSid = flags['--write-sid'] ?? null
  const tempWriteSid = flags['--temp-write-sid'] ?? null
  if ((writeSid === null) !== (tempWriteSid === null)) {
    return fail('EPREFIXGRANT', '--write-sid 与 --temp-write-sid 必须成对出现')
  }

  if (template !== null && template !== undefined) {
    if (normalizePathKey(prefix[0]) !== normalizePathKey(template.program)) {
      return fail('EPREFIXPROGRAMTEMPLATE', 'per-call program 与钉死模板不一致：' + prefix[0])
    }
    if (normalizePathKey(prefix[1]) !== normalizePathKey(template.runnerPath)) {
      return fail('EPREFIXRUNNERTEMPLATE', 'per-call runner 与钉死模板不一致：' + prefix[1])
    }
    // No mode comparison here on purpose: the mode is a per-call authority fact
    // (checked above against the request), not part of the pinned shape.
    if (normalizePathKey(workspaceRoot) !== normalizePathKey(template.workspaceRoot)) {
      return fail('EPREFIXWORKSPACETEMPLATE', 'per-call workspaceRoot 与钉死模板不一致：' + workspaceRoot + ' ≠ ' + template.workspaceRoot)
    }
  }

  return {
    ok: /** @type {const} */ (true),
    prefix,
    program: prefix[0],
    args: prefix.slice(1),
    profile: {
      program: basename(prefix[0]),
      runner: basename(prefix[1]),
      mode,
      workspaceRoot,
      tempDir,
      seamManaged: writeSid !== null,
      writeSid,
      tempWriteSid,
    },
    fingerprint: fingerprintPrefix(prefix),
  }
}

/**
 * A safe summary of a prefix for tool output / logging. Never dump whole SIDs
 * into model-facing text; the shape is enough to audit the wiring.
 * @param {PrefixProfile} profile
 */
export function describePrefix(profile) {
  return {
    program: profile.program,
    runner: profile.runner,
    mode: profile.mode,
    workspaceRoot: profile.workspaceRoot,
    tempDir: profile.tempDir,
    seamManaged: profile.seamManaged,
    grant: profile.seamManaged ? 'write-sid + temp-write-sid (seam-managed)' : 'agentless (runner-managed temp)',
  }
}

/**
 * Safe summary of the pinned template for status output.
 * @param {PrefixTemplate} template
 */
export function describeTemplate(template) {
  return {
    program: basename(template.program),
    programPath: template.program,
    runnerPath: template.runnerPath,
    modes: Array.isArray(template.modes) ? [...template.modes] : [...CONFINED_MODES],
    workspaceRoot: template.workspaceRoot,
    enforcement: template.enforcement,
    pin: 'program + runnerPath(DSH install tree) + workspaceRoot（mode 不再钉死：每次调用按会话策略现校验）',
  }
}

/**
 * Trim a trailing incomplete UTF-8 sequence so a chunk boundary can never split
 * a multi-byte character in two. Returns the number of bytes that are safe to
 * decode; 0 only happens for a chunk shorter than the sequence, which callers
 * must handle by keeping at least the requested length.
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function trimIncompleteUtf8End(bytes) {
  const end = bytes.length
  if (end === 0) return 0
  let index = end - 1
  let continuation = 0
  while (index >= 0 && (bytes[index] & 0xc0) === 0x80 && continuation < 3) {
    index -= 1
    continuation += 1
  }
  if (index < 0) return end
  const lead = bytes[index]
  let needed = 0
  if ((lead & 0x80) === 0x00) needed = 1
  else if ((lead & 0xe0) === 0xc0) needed = 2
  else if ((lead & 0xf0) === 0xe0) needed = 3
  else if ((lead & 0xf8) === 0xf0) needed = 4
  else return end
  const available = end - index
  return available < needed ? index : end
}

/**
 * The env vars the Host is allowed to forward with a command. Only `DSH_*`:
 * they are the Harness-managed facts the model expects to stay fresh across a
 * DSH restart, and forwarding everything else would leak unrelated secrets into
 * the pod ledger/process.
 */
export const DSH_ENV_PREFIX = 'DSH_'
export const MAX_DSH_ENV_VARS = 128
export const MAX_DSH_ENV_VALUE_BYTES = 8192
const DSH_ENV_KEY = /^DSH_[A-Za-z0-9_]+$/

/**
 * Keep only well-formed DSH_* entries. Used on both sides: the Host builds the
 * payload with it, the pod re-validates it before merging into the child env.
 * @param {unknown} raw
 * @returns {{ env: Record<string, string>, rejected: string[] }}
 */
export function sanitizeDshEnv(raw) {
  /** @type {Record<string, string>} */
  const env = {}
  /** @type {string[]} */
  const rejected = []
  if (raw === null || raw === undefined || typeof raw !== 'object') return { env, rejected }
  for (const [key, value] of Object.entries(raw)) {
    if (Object.keys(env).length >= MAX_DSH_ENV_VARS) {
      rejected.push(key + ' (too many)')
      continue
    }
    if (!DSH_ENV_KEY.test(key)) {
      rejected.push(key + ' (bad key)')
      continue
    }
    if (typeof value !== 'string' || value.includes('\u0000') || Buffer.byteLength(value, 'utf8') > MAX_DSH_ENV_VALUE_BYTES) {
      rejected.push(key + ' (bad value)')
      continue
    }
    env[key] = value
  }
  return { env, rejected }
}

/**
 * Snapshot the current Host `DSH_*` env. Called on every `pod_run`, so the pod
 * never keeps a stale restart-time environment.
 * @param {Record<string, string | undefined>} [source]
 */
export function collectDshEnv(source = process.env) {
  /** @type {Record<string, string>} */
  const picked = {}
  for (const [key, value] of Object.entries(source)) {
    if (typeof value !== 'string') continue
    if (!key.startsWith(DSH_ENV_PREFIX)) continue
    picked[key] = value
  }
  return sanitizeDshEnv(picked).env
}
