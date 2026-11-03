#!/usr/bin/env node
/**
 * escape-pod-core pod — the detached, Medium-integrity process that owns command
 * lifetimes and output ledgers, and that is *not* a child of DSH.
 *
 * Topology this file implements:
 *
 *   Host (DSH, restarts) ──named pipe──▶ pod-core (this file, detached, Medium,
 *                                        survives the Host; owns ONE anonymous
 *                                        job object per command for freeze/thaw)
 *                                          └─ per command, spawn:
 *                                             <Host-issued prefix> + target argv
 *                                             = node runner.js --workspace … -- <target>
 *                                                    └─ restricted token (Low IAL,
 *                                                       WRITE_RESTRICTED) + kill-on-close Job
 *
 * The pod's job object is deliberately NOT kill-on-close: it only groups the
 * runner so one `SetInformationJobObject(JobObjectFreezeInformation)` can stop
 * the whole tree (see freeze.mjs). Closing it — at finalize, or when the pod
 * dies — must never kill the command, which is the escape pod's whole point.
 *
 * The prefix (the windows-acl runner invocation, everything before `--`) is a
 * capability issued by the Host via `ctx.sandbox.confine()`, and it arrives with
 * EVERY `run` request — never cached at spawn, because its `--temp-write-sid`
 * belongs to one revocable session/workspace grant. What this pod pins at spawn
 * is only a shape template (program, runner path inside the DSH install tree,
 * workspace root). It NEVER builds, edits or "repairs" a prefix: it validates
 * each per-call prefix against the template, additionally requires the prefix's
 * `--mode` to equal the mode the request resolved (`read-only` or
 * `workspace-write`), and, when the shape is wrong, the mode differs or the temp
 * directory is stale, refuses to run (`EPREFIX*` / `EPREFIXSTALE`). That is the
 * structural half of "the pod can only execute prefixes the Host signed".
 *
 * `danger-full-access` is the one mode with NO prefix: the request says
 * `unescorted: true` and the pod spawns the target argv itself, with its own
 * Medium token. That is genuinely unrestricted (the windows-acl runner has no
 * such mode), and it is why this pod never accepts a prefix for that mode.
 *
 * Capture: the pod is Medium, so it can create anonymous pipes. Each runner is
 * spawned with `stdio: ['ignore','pipe','pipe']`; the runner spawns its restricted
 * child with the caller's stdio inherited (`bytes flow straight through`), so
 * stdout+stderr reach this process. Bytes are appended verbatim to out.log
 * (arrival order, stdout and stderr interleaved) and mirrored into a bounded
 * memory ring; every offset in the protocol is an ABSOLUTE byte offset into
 * out.log.
 *
 * Ledger (`<dataRoot>/jobs/<jobId>/`, where dataRoot defaults to
 * `%LOCALAPPDATA%\dsh-escape-pod-core` and MUST be outside the policy workspace):
 *   meta.json  — written BEFORE the runner is spawned (argv, argvHash, cwd,
 *                policy {mode, escalated, unescorted}, prefix fingerprint, host
 *                identity); runnerPid/spawnedAt are added right after a
 *                successful spawn.
 *   out.log    — raw merged output bytes, append-only, the authoritative stream.
 *   segments.jsonl — `{offset,length,channel}` per written run; splits a byte
 *                range into native stdout/stderr chunks without moving offsets.
 *   cursor.json — the Host-consumed offset plus sha256 of bytes [0, offset);
 *                written atomically by the `ack` op, absent until the first ack.
 *   exit.json  — written when the runner exits; absent means "unknown" for a
 *                job this pod instance does not own.
 * The ledger lives outside the workspace on purpose: a managed command runs with
 * a workspace-write grant, so a ledger inside the workspace would let the command
 * forge its own meta/out/exit (bags of "not guilty"). Both the Host and this pod
 * refuse a data root inside the workspace. (A danger-full-access command shares
 * the user's token and could rewrite the ledger; that mode is the user's explicit
 * choice, and the location rule is kept anyway.)
 *
 * Invariants (deliberate, do not "fix"):
 *   - no ppid watchdog and no exit handler that kills jobs: the pod outlives the
 *     Host and keeps running commands across a DSH restart;
 *   - the named pipe is the single-instance lock (second instance exits 0);
 *   - the pipe serves exactly ONE client at a time: a second connection is
 *     refused, told why (a correlated `EBUSY` frame for its first request), and
 *     closed; the first connection is untouched. When that client disconnects
 *     the pod stays alive and accepts the next one;
 *   - the pipe is token-authenticated. The Host generates 32 random bytes at
 *     spawn and writes them to the pod's STDIN (never argv: a command line is
 *     world-readable). Every request must carry the current token; a missing or
 *     wrong token is refused and the connection is closed;
 *   - the token lives ONLY in memory (never the ledger, config or env). Because
 *     a later Host cannot present a dead process's memory, an orphaned pod
 *     accepts exactly one `handover` request that rebinds the token to a fresh
 *     one. It is logged and visible in `status` — an audit trail, not an OS
 *     identity (see TODO(P2) below);
 *   - an idle exit only happens with no clients AND no running jobs, and it
 *     terminates running jobs first so no orphan runner is left behind;
 *   - the pod never spawns anything that the Host did not name: the target argv
 *     comes from the Host, the prefix comes from the Host. In `danger-full-access`
 *     there is no prefix on purpose — that mode means "run the Host-named argv
 *     with the pod's own token", and it is the only mode without a sandbox in
 *     the loop.
 *
 * Pipe name: `\\.\pipe\dsh-escape-pod-core-<sha256(stable identity)[0..12]>`.
 * The seed is the OS user + machine name (approximation), NOT DSH_HOME: an
 * install path is configuration, and a DSH_HOME change used to orphan the pod.
 * TODO(P2, native): replace the seed with the real user SID
 * (`GetTokenInformation(TokenUser)`), and authenticate the peer with
 * `GetNamedPipeClientProcessId` + image-path/token checks. Neither is in this
 * round (they need a native binding); the token above is defence in depth, not
 * an OS boundary.
 *
 * Usage:
 *   node pod.mjs --serve --pipe <name> --workspace <dir> --data-root <dir>
 *                [--idle-ms <ms>] [--template-json <json>]
 *                [--auth token|open] [--no-handover] [--handover-grace-ms <ms>]
 *
 * Exit codes: 0 ok/duplicate instance, 1 listen failure, 3 bad arguments/ledger,
 *             4 no spawn token on stdin (fail closed; never listens unauthenticated).
 */

import net from 'node:net'
import fs from 'node:fs'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { StringDecoder } from 'node:string_decoder'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CONFINED_MODES,
  DEFAULT_IDLE_EXIT_MS,
  DEFAULT_RING_BYTES,
  FALLBACK_OUTPUT_CHUNK_BYTES,
  JOB_ID_PATTERN,
  MAX_COMMAND_LINE_CHARS,
  MAX_OUTPUT_CHUNK_BYTES,
  MAX_PROTOCOL_LINE_BYTES,
  PROTOCOL_VERSION,
  SANDBOX_MODES,
  clampInt,
  describePipeIdentity,
  describePrefix,
  describeTemplate,
  hashArgv,
  isDirectorySync,
  isInsideDirectory,
  isPodToken,
  jobOwnership,
  optionalString,
  resolvePipeName,
  resolveStateDir,
  sanitizeDshEnv,
  tokenFingerprint,
  tokensEqual,
  trimIncompleteUtf8End,
  validatePrefix,
  validateTemplate,
} from './shared.mjs'
import { CURSOR_ALGORITHM, CURSOR_SCHEMA, createPrefixHasher, validateCursor } from './cursor.mjs'
import { SEGMENTS_FILE, buildChunks, normalizeChannel, parseSegments, sanitizeSegments } from './segments.mjs'
import { createAttestor, createAttestPolicySource, evaluateClient, normalizeAttestMode } from './attest.mjs'
import { createIdentityChannel } from './identity.mjs'
import { FREEZE_DEFAULT_MAX_MS, createFreezeController, metaFreezeOf } from './freeze.mjs'
import { createFreezePolicy } from './freeze-policy.mjs'
import { readPodSettings } from './settings.mjs'

const POD_VERSION = '1.1.1'
const POD_FLAVOR = 'medium-detached-token-factory'
const LEDGER_SCHEMA = 1
const READY_STATUSES = new Set(['running', 'settled', 'killed', 'runner-failed', 'spawn-failed', 'ledger-failed', 'unknown'])
/**
 * Hard cap for a per-job deadline. `setTimeout` stores its delay in a signed
 * 32-bit integer, so a bigger value silently fires almost immediately — a
 * misspelled timeout must fail safe, not kill a command at once. The Host's
 * live value is already capped by the native executor's `maxTimeoutMs`
 * (600000 by default), so this only ever matters for a hand-written request.
 */
export const MAX_JOB_TIMEOUT_MS = 2_147_483_647
/** Grace between "timeout fired" and the taskkill fallback, same as a user kill. */
const TIMEOUT_KILL_GRACE_MS = 3000
/** @type {number | null} */
let activePodLog = null

// A detached pod must never die because the console that spawned it went away,
// and its stdio is 'ignore' anyway: guard the streams so a broken handle can
// never become an uncaught stream error.
try {
  process.stdout.on('error', () => {})
  process.stderr.on('error', () => {})
} catch {
  // best-effort only
}

/** @param {unknown} error */
function messageOf(error) {
  if (error instanceof Error) return error.message
  return String(error)
}

/** @param {unknown} error */
function codeOf(error) {
  const code = /** @type {any} */ (error)?.code
  return typeof code === 'string' && code !== '' ? code : 'EUNKNOWN'
}

/**
 * A plain-object check for ledger fields that may be absent or malformed.
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlainRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nowIso() {
  return new Date().toISOString()
}

/**
 * Normalize the OPTIONAL per-run deadline (`run.timeoutMs`) and the
 * timeout-marked kill (`kill.timeoutMs`).
 *
 * `0` means "no deadline", and that is also what a missing/garbage/negative
 * value becomes. This is the single place that decides it, because ONLY the
 * foreground `pod_exec` ever sends a deadline: `pod_run` must stay unlimited
 * — a command that outlives DSH is the entire reason this pod exists, and
 * "unifying" the two tools behind the native 120s budget would break that.
 *
 * @param {any} payload the `run` or `kill` payload
 * @returns {number} 0 (unlimited) or 1..{@link MAX_JOB_TIMEOUT_MS}
 */
export function jobTimeoutOf(payload) {
  const raw = payload?.timeoutMs
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) return 0
  return Math.min(MAX_JOB_TIMEOUT_MS, Math.max(1, Math.trunc(raw)))
}

/**
 * Classify one connection-attestation record.
 *
 * `deferred` is NOT a refusal: it means this transport (Node's named-pipe
 * socket, whose Win32 HANDLE Node never exposes) cannot produce the facts, so
 * the handover-nonce gate makes the identity decision instead. Counting it as
 * `denied` made two ordinary Host connections look like two policy rejections
 * in attest-probe.json, which is exactly the diagnostic lie this split fixes.
 *
 * @param {any} record
 * @returns {'accepted' | 'deferred' | 'denied'}
 */
export function attestationOutcome(record) {
  if (record?.allowed === true) return 'accepted'
  if (record?.deferred === true) return 'deferred'
  return 'denied'
}

/**
 * Fold one record into the pod's attestation counters.
 * @param {any} state attestationState-shaped object (denied/deferred are numbers)
 * @param {any} record one `attestConnection` record
 */
export function recordAttestationOutcome(state, record) {
  const outcome = attestationOutcome(record)
  if (outcome === 'accepted') {
    state.lastAcceptedAt = record?.at ?? nowIso()
  } else if (outcome === 'deferred') {
    state.deferred = (Number.isInteger(state.deferred) ? state.deferred : 0) + 1
    state.lastDeferredAt = record?.at ?? nowIso()
  } else {
    state.denied = (Number.isInteger(state.denied) ? state.denied : 0) + 1
    state.lastDeniedAt = record?.at ?? nowIso()
  }
  return outcome
}

/** @param {string} text @param {number} max */
function truncate(text, max) {
  const value = String(text ?? '')
  return value.length <= max ? value : value.slice(0, max - 1) + '…'
}

/** @param {string} path */
function readJsonOrNull(path) {
  try {
    return JSON.parse(fs.readFileSync(path, 'utf8'))
  } catch {
    return null
  }
}

/** @param {string} path */
function fileSizeOrZero(path) {
  try {
    return fs.statSync(path).size
  } catch {
    return 0
  }
}

/** @param {string} path */
function readFileOrEmpty(path) {
  try {
    return fs.readFileSync(path, 'utf8')
  } catch {
    return ''
  }
}

/**
 * Atomic JSON write: temp file in the same directory, fsync, rename. The ledger
 * is the only cross-restart truth, so a torn meta.json / exit.json would make a
 * job look unknowable for the wrong reason.
 * @param {string} path
 * @param {unknown} value
 */
function writeJsonAtomic(path, value) {
  const temporary = path + '.tmp-' + String(process.pid)
  const fd = fs.openSync(temporary, 'w')
  try {
    fs.writeSync(fd, JSON.stringify(value, null, 2) + '\n')
    fs.fsyncSync(fd)
  } finally {
    fs.closeSync(fd)
  }
  fs.renameSync(temporary, path)
}

// ---------------------------------------------------------------------------
// Auth: the spawn-time token (delivered on stdin) and the single-client gate.
// ---------------------------------------------------------------------------

/** How long the pod waits for the token line before failing closed (Host writes it immediately). */
export const TOKEN_STDIN_TIMEOUT_MS = 5000
/** How long a refused second connection may spend sending the line whose id we echo. */
export const REJECT_READ_TIMEOUT_MS = 1000
/** A token line is 64 hex chars; anything longer than this is garbage. */
export const TOKEN_STDIN_MAX_CHARS = 4096
/** Grace before a pod whose spawn owner never connected may be taken over. */
export const HANDOVER_GRACE_MS = 60 * 1000
/**
 * A bootstrap pod has no token and therefore no owner until a Host redeems an
 * identity nonce. If nobody does that within this window it exits 0 instead of
 * lingering as an unclaimable process holding the pipe.
 */
export const BOOTSTRAP_CLAIM_TIMEOUT_MS = 120 * 1000

/**
 * Read the FIRST line of the given stream (the pod's stdin) and interpret it as
 * the spawn-time token. Resolves `null` when the line is missing/malformed, the
 * stream ends first, or the timeout expires; the caller must then fail closed.
 *
 * Only the first line is consumed. The write end may (and will) close later —
 * when the Host dies — which is a normal event for this pod, never a shutdown
 * signal. See {@link neutralizePodStdin}.
 *
 * @param {NodeJS.ReadableStream} [stream]
 * @param {{ timeoutMs?: number, maxChars?: number }} [options]
 * @returns {Promise<string | null>}
 */
export function readTokenFromStdin(stream = process.stdin, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(1, Number(options.timeoutMs)) : TOKEN_STDIN_TIMEOUT_MS
  const maxChars = Number.isFinite(options.maxChars) ? Math.max(1, Number(options.maxChars)) : TOKEN_STDIN_MAX_CHARS
  return new Promise((resolveToken) => {
    let settled = false
    let buffer = ''
    /** @param {string | null} token */
    const finish = (token) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        stream.removeListener('data', onData)
        stream.removeListener('end', onEnd)
        stream.removeListener('error', onEnd)
        stream.pause?.()
      } catch {
        // a dying stream must not become an uncaught error
      }
      resolveToken(token)
    }
    /** @param {Buffer | string} chunk */
    const onData = (chunk) => {
      buffer += String(chunk)
      const newline = buffer.indexOf('\n')
      if (newline >= 0) {
        const line = buffer.slice(0, newline).trim()
        finish(isPodToken(line) ? line : null)
        return
      }
      if (buffer.length > maxChars) finish(null)
    }
    const onEnd = () => finish(null)
    // Deliberately NOT unref'd: this is the startup gate. If the Host never
    // writes a token the pod must time out and exit 4, not silently drain the
    // event loop and look like a clean exit.
    const timer = setTimeout(() => finish(null), timeoutMs)
    try {
      stream.setEncoding?.('utf8')
      stream.on('data', onData)
      stream.once('end', onEnd)
      stream.once('error', onEnd)
      stream.resume?.()
    } catch {
      finish(null)
    }
  })
}

/**
 * Make stdin permanently harmless once the token has been read. The Host closes
 * the write end right after writing the token, and the OS closes it if the Host
 * dies; neither may take the pod down.
 * @param {NodeJS.ReadableStream} [stream]
 */
export function neutralizePodStdin(stream = process.stdin) {
  try {
    stream.on('error', () => {})
    stream.on('end', () => {})
    stream.on('close', () => {})
    stream.pause?.()
    stream.unref?.()
  } catch {
    // best effort only
  }
}

/**
 * One admitted pipe connection. `authenticated` flips on the first request that
 * carries the current token (or a successful handover) and is re-checked on
 * every request, so a token rotation invalidates it.
 * @typedef {{
 *   socket?: any,
 *   peer: string,
 *   connectedAt: string,
 *   authenticated: boolean,
 *   tokenFingerprint: string | null,
 * }} PodConnection
 */

/** Stable shape for `status.auth` before serve() installs the real guard. */
export function emptyAuthSnapshot() {
  return {
    mode: 'open',
    required: false,
    tokenSource: 'none',
    tokenFingerprint: null,
    tokenRotatedAt: null,
    ownerAccepted: false,
    connected: false,
    activePeer: null,
    firstClientAt: null,
    lastClientClosedAt: null,
    handoverAllowed: false,
    handoverCount: 0,
    lastHandoverAt: null,
    handoverGraceMs: null,
    rejectedConnections: 0,
    lastRejectedAt: null,
    startedAt: null,
  }
}

/**
 * The pod-side auth state machine: one client at a time, token on every request,
 * and a single audited `handover` path for the Host that comes after a restart.
 * Transport-free on purpose, so the static self-test can drive it without a pipe.
 *
 * @param {{
 *   mode?: 'token' | 'open',
 *   token?: string | null,
 *   allowHandover?: boolean,
 *   handoverGraceMs?: number,
 *   bootstrapHandover?: boolean,
 *   startedAtMs?: number,
 *   log?: (message: string) => void,
 * }} [options]
 */
export function createPodAuth(options = {}) {
  const mode = options.mode === 'open' ? 'open' : 'token'
  const initialToken = isPodToken(options.token) ? String(options.token) : null
  // A bootstrap pod is spawned without a stdin token on purpose; its first
  // owner is established by a nonce-attested handover (see the connection
  // handler). Any other no-token token-mode start is still a hard error.
  const bootstrap = options.bootstrapHandover === true && mode === 'token' && initialToken === null
  if (mode === 'token' && initialToken === null && !bootstrap) {
    throw new Error('createPodAuth: token 模式必须提供 32 字节 hex 的 spawn 期 token（无 stdin 引导请显式 bootstrapHandover）')
  }
  const allowHandover = options.allowHandover !== false
  const graceMs = Number.isFinite(options.handoverGraceMs) ? Math.max(0, Number(options.handoverGraceMs)) : HANDOVER_GRACE_MS
  const log = typeof options.log === 'function' ? options.log : () => {}
  const startedAtMs = Number.isFinite(options.startedAtMs) ? Number(options.startedAtMs) : Date.now()
  let token = initialToken
  /** True from process start until the first nonce-attested handover lands. */
  let bootstrapMode = bootstrap
  /** Keep `tokenSource:bootstrap` visible after the claim (diagnostics only). */
  let bootstrapClaimed = false
  /** @type {PodConnection | null} */
  let active = null
  let ownerAccepted = false
  let firstClientAt = null
  let lastClientClosedAt = null
  let tokenRotatedAt = null
  let handoverCount = 0
  let lastHandoverAt = null
  let rejectedConnections = 0
  let lastRejectedAt = null
  /**
   * Freeze-mode observer. Called on AUTHENTICATED transitions only: a raw
   * admitted socket (a stray same-user process, or the Host mid-handshake) must
   * not be able to cancel a pending freeze, and an unauthenticated connection
   * that closes must not start the grace timer.
   * @type {((state: { connected: boolean, peer: string | null, at: string }) => void) | null}
   */
  let clientStateHandler = null

  function fingerprint() {
    return token === null ? null : tokenFingerprint(token)
  }

  /** @param {PodConnection | null} connection null = nobody authenticated is connected. */
  function notifyClientState(connection) {
    if (clientStateHandler === null) return
    try {
      clientStateHandler({
        connected: connection !== null,
        peer: connection === null ? null : connection.peer,
        at: nowIso(),
      })
    } catch (error) {
      // A broken observer must never break authentication itself.
      log('client state handler failed: ' + messageOf(error))
    }
  }

  /** @param {PodConnection} connection */
  function admitConnection(connection) {
    if (active !== null) {
      rejectedConnections += 1
      lastRejectedAt = nowIso()
      const message =
        'pod 同时只服务一个 Host 连接：已有连接（peer=' + active.peer + '，connectedAt=' + active.connectedAt +
        '）仍在，第二个连接（peer=' + connection.peer + '）被拒绝并关闭'
      log('reject second client: ' + message)
      return { ok: false, code: 'EBUSY', message }
    }
    active = connection
    return { ok: true, code: null, message: null }
  }

  /** @param {PodConnection} connection */
  function detachConnection(connection) {
    if (active !== connection) return
    active = null
    if (connection.authenticated) {
      lastClientClosedAt = nowIso()
      // The LAST authenticated client is gone: this is the moment freeze mode
      // starts its grace clock (the policy owns the 10s timer, not auth).
      notifyClientState(null)
    }
  }

  /** @param {PodConnection} connection */
  function canHandover(connection) {
    if (mode !== 'token' || !allowHandover) return false
    if (connection.authenticated) return false
    // Bootstrap has no spawn owner by construction, so the nonce gate (not a
    // grace timer) is what decides the first claim. Grace exists only for the
    // "a token-authenticated owner existed before" restart case below.
    if (bootstrapMode) return true
    // Single-client means the requester is the only admitted connection, so a
    // takeover can only happen after the previous owner's connection closed
    // (or, if it never authenticated, after the spawn-owner grace period).
    return ownerAccepted ? lastClientClosedAt !== null : Date.now() - startedAtMs >= graceMs
  }

  /**
   * @param {PodConnection} connection
   * @param {unknown} message
   */
  function authorize(connection, message) {
    if (mode === 'open') {
      const firstRequest = connection.authenticated !== true
      connection.authenticated = true
      if (firstRequest) notifyClientState(connection)
      return { ok: true, code: null, message: null }
    }
    if (!tokensEqual(/** @type {any} */ (message)?.token, token)) {
      return {
        ok: false,
        code: 'EBADTOKEN',
        message: bootstrapMode
          ? 'pod 处于 bootstrap（还没有 Host 通过 identity nonce 完成 handover）：除 identify / handover 外的请求一律拒绝'
          : connection.authenticated
            ? '请求携带的 token 与 pod 当前 token 不一致（token 每代只在内存里，换代后旧值立即失效）'
            : '缺少或不匹配的 spawn 期 token（32 字节 hex）；pod 只服务持有当前 token 的 Host',
      }
    }
    if (!connection.authenticated) {
      connection.authenticated = true
      connection.tokenFingerprint = fingerprint()
      notifyClientState(connection)
    }
    if (!ownerAccepted) {
      ownerAccepted = true
      firstClientAt = nowIso()
      log('owner accepted: first token-authenticated client peer=' + connection.peer + ' tokenFp=' + String(fingerprint()))
    }
    return { ok: true, code: null, message: null }
  }

  /**
   * Rebind the token for a Host that cannot possibly know the previous one.
   * Accepted only when no authenticated client is connected.
   * @param {PodConnection} connection
   * @param {unknown} message
   */
  function handover(connection, message) {
    if (mode === 'open') return { ok: false, code: 'ENOTOKEN', message: 'pod 以 --auth open 启动，没有 token 可续' }
    if (connection.authenticated) return { ok: false, code: 'EALREADY', message: '当前连接已经通过 token 认证，不需要 handover' }
    if (!allowHandover) {
      return { ok: false, code: 'EHANDOVERDISABLED', message: 'pod 启动时用了 --no-handover：新 Host 不能接管这个 pod' }
    }
    if (!canHandover(connection)) {
      const retryAfterMs = ownerAccepted ? 0 : Math.max(0, graceMs - (Date.now() - startedAtMs))
      return {
        ok: false,
        code: 'EAUTHREQUIRED',
        message: ownerAccepted
          ? 'pod 仍绑在上一代 Host 的 token 上，且当前不是可接管的空闲状态（上一代连接还没断开）'
          : 'pod 刚启动，仍在等待 spawn 它的 Host 用 stdin 下发的 token；' + String(retryAfterMs) + 'ms 后才允许接管',
        retryAfterMs,
      }
    }
    const newToken = /** @type {any} */ (message)?.newToken
    if (!isPodToken(newToken)) {
      return { ok: false, code: 'EBADTOKEN', message: 'handover.newToken 必须是 32 字节 hex（64 个小写十六进制字符）；旧 token 不会通过任何字段传回' }
    }
    const previous = fingerprint()
    token = newToken
    if (bootstrapMode) bootstrapClaimed = true
    bootstrapMode = false
    tokenRotatedAt = nowIso()
    handoverCount += 1
    lastHandoverAt = tokenRotatedAt
    ownerAccepted = true
    if (firstClientAt === null) firstClientAt = tokenRotatedAt
    connection.authenticated = true
    connection.tokenFingerprint = fingerprint()
    log('handover accepted: previous=' + String(previous) + ' next=' + String(connection.tokenFingerprint) + ' count=' + String(handoverCount))
    // A handover IS the returning Host: cancel any pending freeze immediately.
    notifyClientState(connection)
    return { ok: true, code: null, message: null }
  }

  function snapshot() {
    return {
      mode: bootstrapMode ? 'bootstrap' : mode,
      required: mode === 'token',
      tokenSource: bootstrapMode || bootstrapClaimed ? 'bootstrap' : mode === 'token' ? 'spawn-stdin' : 'none',
      tokenFingerprint: bootstrapMode ? null : mode === 'token' ? fingerprint() : null,
      tokenRotatedAt,
      ownerAccepted,
      connected: active !== null,
      activePeer: active === null ? null : active.peer,
      firstClientAt,
      lastClientClosedAt,
      handoverAllowed: mode === 'token' && allowHandover,
      handoverCount,
      lastHandoverAt,
      handoverGraceMs: mode === 'token' ? graceMs : null,
      rejectedConnections,
      lastRejectedAt,
      startedAt: new Date(startedAtMs).toISOString(),
    }
  }

  return {
    admitConnection,
    detachConnection,
    authorize,
    handover,
    snapshot,
    /**
     * Install the freeze-mode observer (see freeze-policy.mjs). Called by
     * `serve()`; `null` removes it. Transport-free like the rest of auth.
     * @param {((state: { connected: boolean, peer: string | null, at: string }) => void) | null} handler
     */
    setClientStateHandler(handler) {
      clientStateHandler = typeof handler === 'function' ? handler : null
    },
    isOpen() {
      return mode === 'open'
    },
    hasToken() {
      return token !== null
    },
    /** True until the first nonce-attested handover establishes an owner. */
    isBootstrap() {
      return bootstrapMode
    },
  }
}

/**
 * Keep `status.identity` a fixed, JSON-safe shape.
 * @param {unknown} raw
 */
function normalizeIdentity(raw) {
  if (raw === null || typeof raw !== 'object') {
    return { seedKind: 'unknown', seedVersion: null, seedHash: null, note: null }
  }
  const source = /** @type {Record<string, unknown>} */ (raw)
  return {
    seedKind: typeof source.seedKind === 'string' ? source.seedKind : 'unknown',
    seedVersion: Number.isInteger(source.seedVersion) ? source.seedVersion : null,
    seedHash: typeof source.seedHash === 'string' ? source.seedHash : null,
    note: typeof source.note === 'string' ? source.note : null,
  }
}

/**
 * The exact process one run starts.
 *
 *   - escorted (`read-only` / `workspace-write`): `prefix + '--' + target argv`,
 *     so the windows-acl runner confines the target;
 *   - unescorted (`danger-full-access`): the target argv ITSELF, with no runner
 *     and no prefix — the command then runs with this pod's own Medium token.
 *
 * Pure and exported so the shape (the part that decides whether a sandbox is in
 * the loop at all) can be asserted without creating a process.
 *
 * @param {{ unescorted: boolean, check: { program: string, args: string[] } | null, argv: string[] }} input
 * @returns {{ program: string, args: string[] }}
 */
export function planRunSpawn({ unescorted, check, argv }) {
  if (unescorted === true) return { program: argv[0], args: argv.slice(1) }
  return { program: check.program, args: [...check.args, '--', ...argv] }
}

/**
 * Create the pod service (protocol state machine). Separated from the socket
 * layer so a test can drive `handle()` directly over a fake transport: the
 * ledger, offset arithmetic and fail-closed prefix checks are the parts worth
 * testing without pipes.
 *
 * @param {{
 *   workspaceRoot: string,
 *   dataRoot: string,
 *   pipeName: string,
 *   idleExitMs: number,
 *   ringBytes: number,
 *   outputChunkBytes: number,
 *   template?: unknown,
 *   unsafeAllowDataRootInsideWorkspace?: boolean,
 *   authSnapshot?: () => Record<string, unknown>,
 *   identity?: unknown,
 *   freezeProbe?: () => { supported: boolean, reason?: string | null },
 *   log?: (message: string) => void,
 *   spawnProcess?: (program: string, args: string[], options: Record<string, unknown>) => any,
 * }} options
 */
export function createPodService(options) {
  const workspaceRoot = resolve(options.workspaceRoot)
  const dataRoot = resolve(options.dataRoot)
  const jobsRoot = join(dataRoot, 'jobs')
  // Test seam only: the production `serve()` never sets this. The ledger must
  // live outside the workspace a managed command can write, otherwise the
  // command could forge meta.json/out.log/exit.json — its own verdict.
  const unsafeAllowDataRootInsideWorkspace = options.unsafeAllowDataRootInsideWorkspace === true
  const idleExitMs = options.idleExitMs
  const ringBytes = options.ringBytes
  const outputChunkBytes = options.outputChunkBytes
  const pipeName = options.pipeName
  const log = typeof options.log === 'function' ? options.log : () => {}
  // Test seam only: the real pod (Medium integrity) always uses `spawn`, but
  // DSH's restricted test shell cannot create child processes at all (spawn
  // EPERM), and the ledger/policy half of a run is still worth testing. `serve()`
  // never passes this option, so production behaviour is unchanged.
  const spawnProcess = typeof options.spawnProcess === 'function' ? options.spawnProcess : spawn
  // Transport-level auth state lives in `serve()`; the service only projects it,
  // so a static test can drive `handle()` without a socket and still get a
  // stable `status.auth` shape.
  const authSnapshot = typeof options.authSnapshot === 'function' ? options.authSnapshot : emptyAuthSnapshot
  // Client attestation is computed by `serve()` (it needs the socket), and the
  // service only projects the last result, exactly like `authSnapshot`.
  const attestationSnapshot = typeof options.attestationSnapshot === 'function' ? options.attestationSnapshot : () => null
  const identityInfo = normalizeIdentity(options.identity)
  const startedAt = new Date()
  const jobs = new Map()
  let generation = 0
  /**
   * Identity of THIS pod process, used only to reconcile `meta.json.freeze`.
   *
   * It is deliberately NOT `generation`: that counter is bumped for every
   * admitted client connection, so a Host restart — or merely a reconnect —
   * would change it while a frozen job was still perfectly thawable, because
   * the handle and the process that owns it are still here. What
   * `frozen-orphan` must answer is "did the pod process that froze this job
   * die?", and only a per-process id answers that.
   */
  const podGeneration = String(process.pid) + '-' + startedAt.getTime().toString(36) + '-' + randomBytes(3).toString('hex')
  let lastActivity = Date.now()
  let shuttingDown = false
  let initialized = false
  let lastEnforcement = null
  /** @type {((reason: string) => void) | null} */
  let shutdownHandler = null
  /**
   * Called once per job settlement (after exit.json is written). The pod uses
   * it as a lifecycle checkpoint: with no client and no other running job there
   * is nothing left to protect, so it exits instead of idling for 12 hours.
   * @type {((record: any) => void) | null}
   */
  let settlementHandler = null

  /** Fire the settlement hook; a broken hook must never fail a settlement. */
  function notifySettlement(rec) {
    if (settlementHandler === null) return
    try {
      settlementHandler(rec)
    } catch (error) {
      log('settlement handler failed job=' + String(rec?.jobId ?? '?') + ': ' + messageOf(error))
    }
  }

  /** @param {unknown} raw */
  function normalizeEnforcement(raw) {
    return raw === 'full' || raw === 'partial' ? raw : null
  }

  /**
   * The pod holds NO prefix at rest: a prefix carries a revocable per-session
   * temp SID and is dead after a Host restart. It holds this shape template
   * instead, pinned once at spawn, and validates every per-call prefix against
   * it. An absent/invalid template means every run fails closed.
   * @param {unknown} raw
   */
  function initialTemplateState(raw) {
    const present = raw !== null && raw !== undefined
    /** @type {any} */
    const base = {
      present,
      valid: false,
      code: 'EPREFIXTEMPLATE',
      message: 'pod 启动时没有收到 Host 下发的形态校验模板；pod_run 会 fail-closed 拒绝执行',
      template: null,
      source: present ? 'spawn-argv' : 'none',
      receivedAt: present ? nowIso() : null,
    }
    if (!present) return base
    const check = validateTemplate(raw)
    if (!check.ok) {
      return { ...base, code: check.code, message: 'pod 启动参数里的形态校验模板不合法：' + check.message }
    }
    return { present: true, valid: true, code: null, message: null, template: check.template, source: 'spawn-argv', receivedAt: nowIso() }
  }

  const templateState = initialTemplateState(options.template ?? null)
  if (templateState.valid) lastEnforcement = templateState.template.enforcement

  function templateSummary() {
    if (!templateState.valid) {
      return {
        present: templateState.present,
        valid: false,
        code: templateState.code,
        reason: templateState.message,
        source: templateState.source,
        receivedAt: templateState.receivedAt,
      }
    }
    return {
      present: true,
      valid: true,
      source: templateState.source,
      receivedAt: templateState.receivedAt,
      ...describeTemplate(templateState.template),
      lastEnforcement,
    }
  }

  /**
   * Freeze/thaw state machine (see freeze.mjs). It owns the per-job job handle,
   * the freeze watchdog AND the pausable job deadline: freezing a job must stop
   * its timeout clock, otherwise a 60s foreground deadline would kill the
   * command the instant it is thawed after a 5-minute freeze.
   *
   * `onStateChange` is the ONLY writer of `meta.json.freeze` (six whitelisted
   * fields). The job handle itself never leaves this process.
   */
  const freeze = createFreezeController({
    log,
    podPid: process.pid,
    podGeneration,
    probe: typeof options.freezeProbe === 'function' ? options.freezeProbe : undefined,
    onDeadline: (rec) => {
      // Same guard the old inline timer had: a timer that fires while the job
      // is already finalizing must not mark a finished job as timed out.
      if (rec.finalized === true) return
      rec.timedOut = true
      log('job ' + rec.jobId + ' 超时（' + String(rec.timeoutMs) + 'ms）：终止 runner')
      void killRecord(rec, TIMEOUT_KILL_GRACE_MS)
    },
    onStateChange: (rec, record) => writeMetaFreeze(rec, record),
  })

  /**
   * `pod_status.freeze`: the process-level capability answer. The probe is
   * memoized inside the controller, so this is one Win32 round-trip per pod
   * process, never per status call.
   */
  function freezeSnapshot() {
    const support = freeze.support()
    const attachFailure = freeze.lastAttachFailure()
    return {
      supported: support.supported === true,
      state: support.supported === true ? 'supported' : 'unsupported',
      reason: support.supported === true ? null : (support.reason ?? '未知原因'),
      checkedAt: support.checkedAt ?? null,
      defaultMaxFreezeMs: FREEZE_DEFAULT_MAX_MS,
      // `supported` only means the OS accepts class 18. If the runner could not
      // be put into the pod's own job (the pod itself running inside DSH's job
      // is the usual cause), freeze on such a job answers ENOTHANDLE — say so
      // here instead of letting a supported line hide it.
      lastAttachError: attachFailure === null ? null : {
        at: attachFailure.at,
        stage: attachFailure.stage,
        win32: attachFailure.win32,
        runnerPid: attachFailure.runnerPid,
      },
      note: support.supported === true
        ? 'job 冻结可用（JobObjectFreezeInformation）：pod_freeze action=freeze|thaw，默认 ' + String(Math.round(FREEZE_DEFAULT_MAX_MS / 60000)) + ' 分钟看门狗自动解冻'
        : 'job 冻结不可用：pod_freeze 会返回 EFREEZEUNSUPPORTED；其余功能不受影响',
    }
  }

  /** @param {string} jobId */
  function allocateJobId() {
    const stamp = Date.now().toString(36)
    for (;;) {
      const candidate = 'podc-' + stamp + '-' + randomBytes(4).toString('hex')
      if (!jobs.has(candidate) && !fs.existsSync(join(jobsRoot, candidate))) return candidate
    }
  }

  /** @param {string} jobId */
  function jobPaths(jobId) {
    const dir = join(jobsRoot, jobId)
    return {
      dir,
      metaPath: join(dir, 'meta.json'),
      outPath: join(dir, 'out.log'),
      segmentsPath: join(dir, SEGMENTS_FILE),
      exitPath: join(dir, 'exit.json'),
      cursorPath: join(dir, 'cursor.json'),
    }
  }

  /** @param {any} rec */
  function isRunning(rec) {
    return rec.diskOnly !== true && rec.finalized !== true && rec.child !== null
  }

  /** @param {any} rec */
  function ringStartOffset(rec) {
    return rec.totalBytes - rec.ring.length
  }

  /**
   * Write one decoded run of bytes to `out.log` and record its channel segment.
   * The segment is appended only after the bytes are on disk; an interrupted
   * append leaves an over-long entry that {@link sanitizeSegments} drops on the
   * next start.
   * @param {any} rec @param {Buffer} bytes @param {string} channel
   */
  function writeDecoded(rec, bytes, channel) {
    if (bytes.length === 0) return
    let written = 0
    if (rec.outFd !== null) {
      let offset = 0
      while (offset < bytes.length) {
        let count = 0
        try {
          count = fs.writeSync(rec.outFd, bytes, offset, bytes.length - offset)
        } catch (error) {
          rec.lossy = true
          rec.writeErrors += 1
          log('out.log write failed job=' + rec.jobId + ': ' + messageOf(error))
          break
        }
        if (!(count > 0)) {
          rec.lossy = true
          rec.writeErrors += 1
          break
        }
        offset += count
      }
      written = offset
    } else {
      rec.lossy = true
    }
    if (!(written > 0)) return
    const segment = { offset: rec.totalBytes, length: written, channel: normalizeChannel(channel) }
    rec.segments.push(segment)
    try {
      fs.appendFileSync(jobPaths(rec.jobId).segmentsPath, JSON.stringify(segment) + '\n')
    } catch (error) {
      rec.lossy = true
      rec.writeErrors += 1
      log('segments.jsonl write failed job=' + rec.jobId + ': ' + messageOf(error))
    }
    rec.totalBytes += written
    const merged = rec.ring.length === 0 ? bytes.subarray(0, written) : Buffer.concat([rec.ring, bytes.subarray(0, written)])
    rec.ring = merged.length > ringBytes ? merged.subarray(merged.length - ringBytes) : merged
  }

  /**
   * Decode one raw stream chunk through the channel's streaming decoder, then
   * persist the decoded text. Decoding first guarantees every segment boundary
   * is a UTF-8 code-point boundary, so a later channel split never mangles a
   * character.
   * @param {any} rec @param {Buffer} chunk @param {string} channel
   */
  function appendOutput(rec, chunk, channel = 'stdout') {
    if (!Buffer.isBuffer(chunk) || chunk.length === 0) return
    const key = normalizeChannel(channel)
    if (rec.decoders === undefined) rec.decoders = {}
    if (rec.decoders[key] === undefined) rec.decoders[key] = new StringDecoder('utf8')
    const text = rec.decoders[key].write(chunk)
    if (text.length === 0) return
    writeDecoded(rec, Buffer.from(text, 'utf8'), key)
  }

  /** Flush every channel decoder's held tail (a multibyte character split by the last event). */
  function flushDecoders(rec) {
    if (rec.decoders === undefined) return
    for (const [channel, decoder] of Object.entries(rec.decoders)) {
      const tail = decoder.end()
      if (tail.length > 0) writeDecoded(rec, Buffer.from(tail, 'utf8'), channel)
    }
    rec.decoders = {}
  }

  /** @param {any} rec @param {number} code @param {string | null} signal */
  function finalize(rec, code, signal) {
    if (rec.finalized) return
    rec.finalized = true
    // The deadline only exists while the command runs; a settled job must not
    // keep a live timer that could "time out" a finished process.
    if (rec.timeoutTimer !== null && rec.timeoutTimer !== undefined) {
      clearTimeout(rec.timeoutTimer)
      rec.timeoutTimer = null
    }
    // Release the freeze side BEFORE the exit record is built: settle() counts
    // an open freeze episode, best-effort thaws/resumes anything this pod
    // suspended, closes the job handle and clears the watchdog. Skipping the
    // thaw would leave a suspended process frozen with no handle left to fix it.
    const freezeStats = freeze.settle(rec)
    // Freeze-mode bookkeeping is memory-only and dies with the job.
    rec.freezeAuto = false
    flushDecoders(rec)
    rec.endedAt = nowIso()
    rec.endedAtMs = Date.now()
    rec.exitCode = typeof code === 'number' ? code : null
    rec.signal = typeof signal === 'string' && signal !== '' ? signal : null
    const signature = /windows-acl-run:\s*([^\r\n]*)/.exec(rec.stderrTail)
    const runnerFailure = rec.exitCode === 127 && signature !== null
    rec.status = rec.spawnFailed === true
      ? 'spawn-failed'
      : runnerFailure
        ? 'runner-failed'
        : rec.killRequested === true || rec.signal !== null
          ? 'killed'
          : 'settled'
    rec.durationMs = rec.startedAtMs > 0 ? Math.max(0, rec.endedAtMs - rec.startedAtMs) : null
    if (rec.outFd !== null) {
      try {
        fs.closeSync(rec.outFd)
      } catch {
        // already closed
      }
      rec.outFd = null
    }
    const exit = {
      schema: LEDGER_SCHEMA,
      jobId: rec.jobId,
      status: rec.status,
      exitCode: rec.exitCode,
      signal: rec.signal,
      startedAt: rec.startedAt,
      endedAt: rec.endedAt,
      durationMs: rec.durationMs,
      totalBytes: rec.totalBytes,
      lossy: rec.lossy === true,
      writeErrors: rec.writeErrors,
      runnerFailure: runnerFailure
        ? { matched: true, signatureLine: String(signature?.[0] ?? '').slice(0, 512) }
        : { matched: false },
      runnerPid: rec.runnerPid,
      podPid: process.pid,
      spawnError: rec.spawnError,
      // Native foreground semantics: a timeout is a KILL (status `killed`,
      // `timedOut: true`), never a fake `settled`. Partial output is kept:
      // this record is written only after the output file has been closed.
      timedOut: rec.timedOut === true,
      timeoutMs: rec.timeoutMs ?? null,
      // Freeze accounting. The HANDLE is not here (and never will be): it is
      // process-private; these three numbers are what a later reader needs to
      // understand a command that "did nothing for 10 minutes".
      frozenMs: freezeStats.frozenMs,
      freezeCount: freezeStats.freezeCount,
      killedWhileFrozen: freezeStats.killedWhileFrozen,
    }
    try {
      writeJsonAtomic(rec.exitPath, exit)
    } catch (error) {
      log('exit.json write failed job=' + rec.jobId + ': ' + messageOf(error))
    }
    const waiters = rec.closeWaiters.splice(0)
    for (const resolveWaiter of waiters) resolveWaiter(true)
    log('job ' + rec.jobId + ' ' + rec.status + ' exitCode=' + String(rec.exitCode) + ' bytes=' + String(rec.totalBytes))
    // After the ledger is final, never before: a lifecycle check that exits the
    // pod must not be able to race the exit.json write.
    notifySettlement(rec)
  }

  /** @param {any} rec */
  function updateMetaAfterSpawn(rec) {
    try {
      const current = readJsonOrNull(rec.metaPath) ?? {}
      writeJsonAtomic(rec.metaPath, {
        ...current,
        runnerPid: rec.runnerPid,
        spawnedAt: rec.spawnedAt,
        spawnError: rec.spawnError,
      })
    } catch (error) {
      log('meta.json update failed job=' + rec.jobId + ': ' + messageOf(error))
    }
  }

  /**
   * Persist ONLY the six ledger-safe freeze fields (freeze.mjs builds them).
   * The handle is process-private and is deliberately absent: a handle written
   * into the ledger would be a lie to the next pod instance.
   * @param {any} rec @param {any} record `freezeLedgerFields()` output
   */
  function writeMetaFreeze(rec, record) {
    try {
      const current = readJsonOrNull(rec.metaPath) ?? {}
      writeJsonAtomic(rec.metaPath, { ...current, freeze: record })
    } catch (error) {
      log('meta.json freeze update failed job=' + rec.jobId + ': ' + messageOf(error))
    }
  }

  /** @param {any} rec */
  function waitForClose(rec, timeoutMs) {
    if (rec.finalized) return Promise.resolve(true)
    return new Promise((resolvePromise) => {
      /** @param {boolean} value */
      const finish = (value) => {
        clearTimeout(timer)
        const index = rec.closeWaiters.indexOf(finish)
        if (index >= 0) rec.closeWaiters.splice(index, 1)
        resolvePromise(value)
      }
      const timer = setTimeout(() => finish(false), timeoutMs)
      if (typeof timer.unref === 'function') timer.unref()
      rec.closeWaiters.push(finish)
    })
  }

  /**
   * Terminate one runner. Killing the runner is enough to kill the command: the
   * restricted child lives in the runner's kill-on-close Job Object, so closing
   * the runner process closes the Job and terminates its members.
   * @param {any} rec
   * @param {number} graceMs
   */
  async function killRecord(rec, graceMs) {
    if (!isRunning(rec)) return false
    rec.killRequested = true
    // TerminateProcess does not need a runnable target, so killing a frozen
    // tree works; record that this is how it ended (TerminateJobObject and
    // taskkill /T /F both work on frozen processes too). The runner's own
    // kill-on-close job then takes the restricted child down with it.
    if (rec.freezeState === 'frozen') rec.killedWhileFrozen = true
    try {
      rec.child?.kill()
    } catch (error) {
      log('runner kill failed job=' + rec.jobId + ': ' + messageOf(error))
    }
    let closed = await waitForClose(rec, graceMs)
    if (!closed && rec.runnerPid !== null) {
      try {
        const killer = spawn('taskkill.exe', ['/PID', String(rec.runnerPid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
        killer.on('error', () => {})
        killer.unref()
      } catch (error) {
        log('taskkill failed job=' + rec.jobId + ': ' + messageOf(error))
      }
      closed = await waitForClose(rec, graceMs)
    }
    return closed
  }

  /** @param {string} jobId */
  function loadJobFromDisk(jobId) {
    if (!JOB_ID_PATTERN.test(jobId)) return null
    const { dir, metaPath, outPath, segmentsPath, exitPath } = jobPaths(jobId)
    if (!fs.existsSync(dir)) return null
    const meta = readJsonOrNull(metaPath)
    const exit = readJsonOrNull(exitPath)
    // A ledger-only record can still say "this job was frozen by a pod whose
    // handle is gone". Two facts make it an orphan: no exit.json (it did not
    // finish) AND the freeze was written by a DIFFERENT pod instance
    // (`meta.freeze.podGeneration !==` this process's id, design §4). Matching
    // the generation cannot actually help here — there is no handle in this
    // process either way, and `freezeRowOf` reports `thawable:false` — but the
    // comparison is what labels the row, so it is done explicitly.
    const ledgerFreeze = metaFreezeOf(meta)
    const frozenOrphan = exit === null && ledgerFreeze?.state === 'frozen' && ledgerFreeze.podGeneration !== podGeneration
    /** @type {any} */
    const rec = {
      jobId,
      diskOnly: true,
      child: null,
      outFd: null,
      jobHandle: null,
      runnerPid: typeof meta?.runnerPid === 'number' ? meta.runnerPid : null,
      status: frozenOrphan ? 'frozen-orphan' : (typeof exit?.status === 'string' ? exit.status : 'unknown'),
      finalized: true,
      killRequested: false,
      /** A timeout is recorded in exit.json (`timedOut`) and never invented on reload. */
      timedOut: exit?.timedOut === true || meta?.timedOut === true,
      timeoutMs: Number.isFinite(meta?.timeoutMs)
        ? Number(meta.timeoutMs)
        : (Number.isFinite(exit?.timeoutMs) ? Number(exit.timeoutMs) : null),
      timeoutTimer: null,
      spawnFailed: false,
      spawnError: typeof meta?.spawnError === 'string' ? meta.spawnError : null,
      exitCode: typeof exit?.exitCode === 'number' ? exit.exitCode : null,
      signal: typeof exit?.signal === 'string' ? exit.signal : null,
      startedAt: typeof meta?.startedAt === 'string' ? meta.startedAt : null,
      startedAtMs: typeof meta?.startedAt === 'string' ? Date.parse(meta.startedAt) || 0 : 0,
      endedAt: typeof exit?.endedAt === 'string' ? exit.endedAt : null,
      durationMs: typeof exit?.durationMs === 'number' ? exit.durationMs : null,
      command: typeof meta?.command === 'string' ? meta.command : null,
      description: typeof meta?.description === 'string' ? meta.description : null,
      /** Missing in a pre-boundary ledger: that job is unowned history, not this session's. */
      sessionId: typeof meta?.sessionId === 'string' && meta.sessionId !== '' ? meta.sessionId : null,
      cwd: typeof meta?.cwd === 'string' ? meta.cwd : null,
      prefixFingerprint: typeof meta?.prefixFingerprint === 'string' ? meta.prefixFingerprint : null,
      // Policy is ledger truth (written at spawn). A pre-policy ledger has no
      // field at all, so the row says "unknown" instead of inventing one.
      policy: isPlainRecord(meta?.policy) ? { ...meta.policy } : null,
      totalBytes: fileSizeOrZero(outPath),
      ring: Buffer.alloc(0),
      segments: sanitizeSegments(parseSegments(readFileOrEmpty(segmentsPath)), fileSizeOrZero(outPath)),
      decoders: {},
      stderrTail: '',
      lossy: exit?.lossy === true,
      writeErrors: typeof exit?.writeErrors === 'number' ? exit.writeErrors : 0,
      // Freeze state comes from the ledger, but the HANDLE cannot: it lived in
      // the process that wrote the ledger and is gone. `freezeRowOf` derives
      // `thawable:false` / `orphan:true` from that absence. A job WITH exit.json
      // is finished, so a stale `frozen` in meta must not make it an orphan (a
      // finished job is not stuck); only a missing exit.json can.
      freezeState: frozenOrphan ? 'frozen' : 'none',
      frozenAt: frozenOrphan ? (ledgerFreeze?.since ?? null) : null,
      frozenAtMs: frozenOrphan && typeof ledgerFreeze?.since === 'string' ? (Date.parse(ledgerFreeze.since) || null) : null,
      freezeBy: ledgerFreeze?.by ?? null,
      freezeCount: ledgerFreeze?.count ?? 0,
      freezeMaxMs: null,
      freezePodGeneration: ledgerFreeze?.podGeneration ?? null,
      frozenMsTotal: typeof exit?.frozenMs === 'number' ? exit.frozenMs : 0,
      freezeWatchdogTimer: null,
      suspendedProcs: [],
      killedWhileFrozen: exit?.killedWhileFrozen === true,
      /** A ledger-only record has no in-memory auto flag; see runJob's rec. */
      freezeAuto: false,
      deadlineAtMs: null,
      deadlineRemainingMs: null,
      closeWaiters: [],
      metaPath,
      outPath,
      exitPath,
    }
    if (frozenOrphan) log('ledger job ' + jobId + ' 停在冻结状态，但没有任何本 pod 的 job 句柄：frozen-orphan（只能用 pod_kill 清理）')
    jobs.set(jobId, rec)
    return rec
  }

  function scanLedger() {
    let entries = []
    try {
      entries = fs.readdirSync(jobsRoot, { withFileTypes: true })
    } catch (error) {
      if (codeOf(error) !== 'ENOENT') throw error
      fs.mkdirSync(jobsRoot, { recursive: true })
      return
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || !JOB_ID_PATTERN.test(entry.name)) continue
      const rec = loadJobFromDisk(entry.name)
      if (rec !== null) log('ledger job ' + rec.jobId + ' status=' + rec.status)
    }
  }

  function init() {
    if (!isDirectorySync(workspaceRoot)) throw new Error('--workspace 不是已存在的目录：' + workspaceRoot)
    // The ledger must be OUTSIDE the policy workspace: commands run with a
    // workspace-write grant and could otherwise rewrite their own record.
    // Check the lexical path, then again through realpath after creating the
    // directory, so a symlink/junction cannot smuggle it back inside.
    if (!unsafeAllowDataRootInsideWorkspace) {
      if (isInsideDirectory(workspaceRoot, dataRoot)) {
        throw new Error('--data-root 必须位于 --workspace 之外（否则被托管命令可伪造自己的账本）：' + dataRoot + ' ⊂ ' + workspaceRoot)
      }
    }
    fs.mkdirSync(jobsRoot, { recursive: true })
    if (!unsafeAllowDataRootInsideWorkspace) {
      try {
        if (isInsideDirectory(fs.realpathSync.native(workspaceRoot), fs.realpathSync.native(dataRoot))) {
          throw new Error('--data-root 的真实路径位于 --workspace 内（符号链接/联接绕道）：' + dataRoot)
        }
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('--data-root')) throw error
        // realpath failure is not a ledger-inside-workspace proof; the lexical
        // check above already passed, so keep going.
      }
    }
    scanLedger()
    initialized = true
    return { ok: true }
  }

  /** @param {string} jobId @param {number} start @param {number} length */
  function readBytes(jobId, start, length) {
    const { outPath } = jobPaths(jobId)
    const fd = fs.openSync(outPath, 'r')
    try {
      const buffer = Buffer.alloc(length)
      let filled = 0
      while (filled < length) {
        const count = fs.readSync(fd, buffer, filled, length - filled, start + filled)
        if (count <= 0) break
        filled += count
      }
      return buffer.subarray(0, filled)
    } finally {
      fs.closeSync(fd)
    }
  }

  /**
   * One prefix hasher per job record. It streams `out.log` lazily, so the first
   * hash request pays one sequential read and later requests only hash the new
   * interval (checkpointed every 64 KiB).
   * @param {any} rec
   */
  function prefixHasherFor(rec) {
    if (rec.prefixHasher === undefined) {
      rec.prefixHasher = createPrefixHasher({
        readRange: (start, length) => readBytes(rec.jobId, start, length),
      })
    }
    return rec.prefixHasher
  }

  /** @param {any} rec @param {number} offset */
  function prefixHashAt(rec, offset) {
    const clamped = Math.max(0, Math.min(Math.trunc(offset), rec.totalBytes))
    return prefixHasherFor(rec).hashAt(clamped)
  }

  /**
   * Where the live retention window starts. Disk-only records (a ledger left by
   * a previous pod) use 0: out.log itself is the window there.
   * @param {any} rec
   */
  function retentionWindowStart(rec) {
    if (rec.diskOnly === true) return 0
    return Math.max(0, ringStartOffset(rec))
  }

  /**
   * Session boundary for one job-scoped op, enforced HERE in the pod and not
   * only in the Host: a modified/older Host must not be able to read or stop a
   * job that belongs to another DSH session. `jobOwnership` is the same pure
   * rule the Host pre-check uses.
   * @param {any} rec
   * @param {any} payload
   */
  function jobAccess(rec, payload) {
    return jobOwnership(rec?.sessionId, payload?.sessionId, payload?.adopt === true)
  }

  /**
   * The refusal deliberately does not name the owning session or the command:
   * the caller learns only that the job is not its own and how to take it over
   * if it really is an orphan.
   * @param {string} jobId
   */
  function foreignJobError(jobId) {
    return {
      ok: false,
      error: {
        code: 'EFOREIGNJOB',
        message: 'job ' + jobId + ' 属于另一个 DSH 会话（或没有会话归属的历史 job），默认拒绝读写。' +
          '若确认原会话已经销毁、这是需要清理的孤儿 job，请在本次调用里加 adopt: true 显式接管。',
      },
    }
  }

  /**
   * Known job ids the CALLER may be told about. The ENOJOB hint must not leak
   * other sessions' job ids.
   * @param {any} payload
   */
  function visibleJobIds(payload) {
    return [...jobs.values()]
      .filter((rec) => jobAccess(rec, payload).allowed === true)
      .slice(-10)
      .map((rec) => rec.jobId)
  }

  /** @param {any} rec */
  function cursorProjection(rec) {
    const { cursorPath } = jobPaths(rec.jobId)
    const raw = readJsonOrNull(cursorPath)
    const totalBytes = rec.totalBytes
    const windowStart = retentionWindowStart(rec)
    /** @type {any} */
    let evaluated
    try {
      evaluated = validateCursor({
        cursor: raw,
        totalBytes,
        windowStart,
        hashAt: (offset) => prefixHashAt(rec, offset),
      })
    } catch (error) {
      evaluated = {
        state: 'unreadable',
        valid: false,
        lossy: false,
        offset: typeof raw?.offset === 'number' ? raw.offset : null,
        hash: null,
        reason: messageOf(error),
      }
    }
    return {
      present: raw !== null && raw !== undefined,
      schema: raw?.schema ?? null,
      algorithm: raw?.algorithm ?? CURSOR_ALGORITHM,
      offset: evaluated.offset ?? (typeof raw?.offset === 'number' ? raw.offset : null),
      hash: typeof raw?.hash === 'string' ? raw.hash : null,
      updatedAt: typeof raw?.updatedAt === 'string' ? raw.updatedAt : null,
      state: evaluated.state,
      valid: evaluated.valid === true,
      lossy: evaluated.lossy === true,
      reason: evaluated.reason ?? null,
      windowStart,
      totalBytes,
    }
  }

  /**
   * Record the Host's consumed offset. The hash is the sha256 of bytes
   * [0, offset) in `out.log`, so a later Host can prove the prefix it consumed
   * is still the prefix in the file. Monotonic: a re-read from an older offset
   * never moves the cursor backwards.
   * @param {unknown} payload
   */
  function ackJob(payload) {
    const jobId = String(payload?.jobId ?? '')
    if (!JOB_ID_PATTERN.test(jobId)) {
      return { ok: false, error: { code: 'EBADJOBID', message: 'jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId } }
    }
    const rec = jobs.get(jobId) ?? loadJobFromDisk(jobId)
    if (rec === null || rec === undefined) {
      return { ok: false, error: { code: 'ENOJOB', message: '账本里没有这个 job：' + jobId } }
    }
    // Writing cursor.json is a write to that job's ledger, so the same session
    // boundary as output/kill applies (an adopted read acks with adopt: true).
    const access = jobAccess(rec, payload)
    if (!access.allowed) return foreignJobError(jobId)
    const offset = payload?.offset
    if (!Number.isInteger(offset) || offset < 0) {
      return { ok: false, error: { code: 'EACKOFFSET', message: 'ack.offset 必须是非负整数：' + String(offset) } }
    }
    if (offset > rec.totalBytes) {
      return {
        ok: false,
        error: { code: 'EACKOFFSET', message: 'ack.offset=' + String(offset) + ' 超过 totalBytes=' + String(rec.totalBytes) + '（游标超前，拒绝锚定）' },
      }
    }
    let hash
    try {
      hash = prefixHashAt(rec, offset)
    } catch (error) {
      return {
        ok: false,
        error: { code: 'EHASHUNAVAILABLE', message: '无法计算前缀 hash（账本可能被截断）：' + messageOf(error) },
      }
    }
    const provided = payload?.hash === undefined || payload?.hash === null ? null : String(payload.hash).toLowerCase()
    if (provided !== null && !/^[0-9a-f]{64}$/.test(provided)) {
      return { ok: false, error: { code: 'EPREFIXHASHFORMAT', message: 'ack.hash 必须是 sha256 hex：' + truncate(String(payload?.hash), 80) } }
    }
    if (provided !== null && provided !== hash) {
      return {
        ok: false,
        error: {
          code: 'EPREFIXHASHMISMATCH',
          message: 'ack.hash 与 out.log 前缀不一致（cursor=' + provided.slice(0, 12) + '… 实际=' + hash.slice(0, 12) + '…）；拒绝写游标',
        },
      }
    }
    const { cursorPath } = jobPaths(jobId)
    const existing = readJsonOrNull(cursorPath)
    if (existing !== null && Number.isInteger(existing?.offset) && existing.offset >= offset) {
      return {
        ok: true,
        op: 'ack',
        jobId,
        offset: existing.offset,
        hash: typeof existing.hash === 'string' ? existing.hash : null,
        skipped: 'behind-cursor',
        cursor: cursorProjection(rec),
      }
    }
    const cursor = {
      schema: CURSOR_SCHEMA,
      jobId,
      algorithm: CURSOR_ALGORITHM,
      offset,
      hash,
      totalBytes: rec.totalBytes,
      updatedAt: nowIso(),
    }
    try {
      writeJsonAtomic(cursorPath, cursor)
    } catch (error) {
      return { ok: false, error: { code: 'ECURSORWRITE', message: '写 cursor.json 失败：' + messageOf(error) } }
    }
    return { ok: true, op: 'ack', jobId, offset, hash, cursor: cursorProjection(rec) }
  }

  /**
   * Cursor-only projection, so the model-facing read can continue exactly where
   * the last acknowledged read stopped without moving offsets through the model.
   * @param {unknown} payload
   */
  function cursorOp(payload) {
    const jobId = String(payload?.jobId ?? '')
    if (!JOB_ID_PATTERN.test(jobId)) {
      return { ok: false, error: { code: 'EBADJOBID', message: 'jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId } }
    }
    const rec = jobs.get(jobId) ?? loadJobFromDisk(jobId)
    if (rec === null || rec === undefined) {
      return { ok: false, error: { code: 'ENOJOB', message: '账本里没有这个 job：' + jobId } }
    }
    const access = jobAccess(rec, payload)
    if (!access.allowed) return foreignJobError(jobId)
    return { ok: true, op: 'cursor', jobId, cursor: cursorProjection(rec) }
  }

  /** @param {unknown} payload */
  function readOutput(payload) {
    const jobId = String(payload?.jobId ?? '')
    if (!JOB_ID_PATTERN.test(jobId)) {
      return { ok: false, error: { code: 'EBADJOBID', message: 'jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId } }
    }
    const rec = jobs.get(jobId) ?? loadJobFromDisk(jobId)
    if (rec === null || rec === undefined) {
      const known = visibleJobIds(payload)
      return {
        ok: false,
        error: {
          code: 'ENOJOB',
          message: '账本里没有这个 job：' + jobId + (known.length === 0 ? '（当前没有任何 job）' : '；已知 job：' + known.join(', ')),
        },
      }
    }
    const access = jobAccess(rec, payload)
    if (!access.allowed) return foreignJobError(jobId)
    const from = clampInt(payload?.from, 0, 0, Number.MAX_SAFE_INTEGER)
    const maxBytes = clampInt(payload?.maxBytes, outputChunkBytes, 1, MAX_OUTPUT_CHUNK_BYTES)
    const total = rec.totalBytes
    const start = Math.min(from, total)
    const wanted = Math.min(maxBytes, total - start)
    /** @type {Buffer | null} */
    let bytes = null
    let source = 'disk'
    if (wanted > 0) {
      try {
        bytes = readBytes(jobId, start, wanted)
      } catch (error) {
        const ringStart = ringStartOffset(rec)
        if (rec.ring.length > 0 && from >= ringStart) {
          source = 'ring'
          bytes = rec.ring.subarray(from - ringStart, Math.min(rec.ring.length, from - ringStart + wanted))
        } else {
          return { ok: false, error: { code: 'EOUTPUTREAD', message: '读取 out.log 失败：' + messageOf(error) } }
        }
      }
    } else {
      bytes = Buffer.alloc(0)
    }
    let length = bytes.length
    let stalled = false
    if (length > 0 && start + length < total) {
      const trimmed = trimIncompleteUtf8End(bytes)
      if (trimmed === 0 && bytes.length > 0) {
        // A chunk shorter than one complete UTF-8 sequence cannot be returned
        // without splitting a codepoint; ask the caller for a bigger chunk.
        length = 0
        stalled = true
      } else {
        length = trimmed === 0 ? bytes.length : trimmed
      }
    }
    const nextOffset = start + length
    const hasMore = nextOffset < total
    let prefixHash = null
    let prefixHashError = null
    try {
      prefixHash = prefixHashAt(rec, nextOffset)
    } catch (error) {
      prefixHashError = messageOf(error)
    }
    let chunks = []
    try {
      chunks = buildChunks({
        segments: rec.segments ?? [],
        from: start,
        to: nextOffset,
        readBytes: (offset, count) => readBytes(jobId, offset, count),
      })
    } catch (error) {
      // Segment metadata is an enhancement; the merged bytes remain authoritative.
      chunks = []
    }
    return {
      ok: true,
      op: 'output',
      jobId,
      status: rec.status,
      running: isRunning(rec),
      exitCode: rec.exitCode,
      signal: rec.signal,
      timedOut: rec.timedOut === true,
      timeoutMs: rec.timeoutMs ?? null,
      // Freeze visibility for a foreground caller: while frozen, the pod's own
      // deadline is paused, and the Host fallback must re-anchor instead of
      // killing at the original wall-clock deadline. `remainingTimeoutMs` is the
      // paused budget (null when the job never had a deadline).
      freeze: freeze.view(rec),
      frozen: rec.freezeState === 'frozen',
      remainingTimeoutMs: rec.freezeState === 'frozen' && Number.isFinite(rec.deadlineRemainingMs)
        ? Number(rec.deadlineRemainingMs)
        : null,
      text: bytes.subarray(0, length).toString('utf8'),
      chunks,
      spillPath: jobPaths(jobId).outPath,
      from: start,
      nextOffset,
      totalBytes: total,
      hasMore,
      truncated: length >= maxBytes && hasMore,
      eof: !hasMore,
      stalled,
      source,
      ring: { startOffset: ringStartOffset(rec), bytes: rec.ring.length },
      lossy: rec.lossy === true,
      prefixHash,
      prefixHashError,
      runnerPid: rec.runnerPid,
      command: rec.command,
      cwd: rec.cwd,
      startedAt: rec.startedAt,
      endedAt: rec.endedAt,
      durationMs: rec.durationMs,
      // Job projection: the caller can see the owner of a job it may read, and
      // an explicit takeover says exactly which session it took over from
      // (`null` = legacy/unowned). `adoptedFrom` is omitted unless adopt was
      // actually needed.
      sessionId: access.owner,
      ...(access.adoptedFrom === undefined ? {} : { adoptedFrom: access.adoptedFrom }),
    }
  }

  /** @param {unknown} payload */
  async function runJob(payload) {
    // The request names the file policy THIS command must run under. `mode` is
    // authority, not a hint: the pod re-checks it against the prefix it is
    // given, so a Host that approved read-only can never execute workspace-write
    // (or the reverse) because a stale field was left behind.
    const unescorted = payload?.unescorted === true
    const requestedMode = optionalString(payload?.mode)
    if (requestedMode !== undefined && !SANDBOX_MODES.includes(requestedMode)) {
      return {
        ok: false,
        error: {
          code: 'EBADMODE',
          message: 'run.mode 只能是 read-only / workspace-write / danger-full-access，收到：' + requestedMode,
        },
      }
    }
    if (unescorted && requestedMode !== 'danger-full-access') {
      return {
        ok: false,
        error: {
          code: 'EUNESCORTEDMODE',
          message: 'run.unescorted=true 必须同时给 mode="danger-full-access"（收到：' + String(requestedMode ?? '未提供') + '）',
        },
      }
    }
    if (!unescorted && requestedMode === 'danger-full-access') {
      return {
        ok: false,
        error: {
          code: 'EMODEUNESCORTED',
          message: 'danger-full-access 必须用 unescorted:true 且不带 runner 前缀：本 pod 不会把完全访问伪装成受限前缀',
        },
      }
    }
    // An escorted run still needs the pinned template; an unescorted run has no
    // prefix to compare, and pins the workspace through the template when one
    // exists (see `policyWorkspace` below).
    if (!unescorted && !templateState.valid) {
      return {
        ok: false,
        error: {
          code: templateState.code ?? 'EPREFIXTEMPLATE',
          message: (templateState.message ?? '形态校验模板不可用') + '（pod 不会自行构造前缀，因此拒绝执行）',
        },
      }
    }
    // The prefix arrives with THIS call (never cached at spawn): it carries a
    // fresh revocable temp SID. Validate its shape against the pinned template
    // AND its --mode against this request; a mismatch, a danger-full-access
    // prefix or a stale temp directory fails closed here, before spawning.
    /** @type {any} */
    let check = null
    if (!unescorted) {
      check = validatePrefix(payload?.prefix, templateState.template, requestedMode ?? null)
      if (!check.ok) {
        return { ok: false, error: { code: check.code, message: '本次调用的 runner 前缀未通过 fail-closed 校验：' + check.message } }
      }
    } else if (payload?.prefix !== null && payload?.prefix !== undefined) {
      // Explicit, not merely ignored: a caller that sends a prefix WITH
      // unescorted is confused about which policy it is asking for.
      return {
        ok: false,
        error: {
          code: 'EPREFIXUNEXPECTED',
          message: 'unescorted 请求不能携带 runner 前缀（danger-full-access 不用前缀）：前缀必须是 null 或省略',
        },
      }
    }
    const enforcement = normalizeEnforcement(payload?.enforcement)
    if (enforcement !== null) lastEnforcement = enforcement
    const rawArgv = payload?.argv
    if (!Array.isArray(rawArgv) || rawArgv.length === 0) {
      return { ok: false, error: { code: 'EARGS', message: 'run.argv 必须是非空字符串数组（Host 下发的目标 argv）' } }
    }
    /** @type {string[]} */
    const argv = []
    for (const value of rawArgv) {
      if (typeof value !== 'string' || value === '') {
        return { ok: false, error: { code: 'EARGS', message: 'run.argv 只能包含非空字符串' } }
      }
      if (value.includes('\u0000')) return { ok: false, error: { code: 'EARGS', message: 'run.argv 含 NUL 字符' } }
      argv.push(value)
    }
    // The windows-acl runner's stable argv contract is
    //   [node, runner.js, --profile…, '--', <target program>, <args…>]
    // The Host sends everything BEFORE the separator (`prefix`); appending the
    // documented `--` separator plus the Host-named target argv is the only
    // composition this pod performs. A prefix that already contains `--` is
    // rejected by validatePrefix, so this is unambiguous.
    //
    // `unescorted` (danger-full-access) has NO runner: the target argv IS the
    // command line, executed with this pod's own Medium token. That is the whole
    // difference, and it is why the prefix-shape check above is skipped for it.
    const { program: spawnProgram, args: spawnArgs } = planRunSpawn({ unescorted, check, argv })
    const commandLineChars =
      spawnProgram.length +
      1 +
      spawnArgs.reduce((sum, value) => sum + value.length + 1, 0)
    if (commandLineChars > MAX_COMMAND_LINE_CHARS) {
      return { ok: false, error: { code: 'EARGSIZE', message: '拼接后的命令行过长（' + commandLineChars + ' > ' + MAX_COMMAND_LINE_CHARS + '），Windows 拒绝创建进程' } }
    }
    // The workspace root the command may stand in. An escorted run takes it from
    // the validated prefix; an unescorted one still uses the template's pinned
    // root when the pod has one, and only falls back to the pod's own
    // --workspace when it was started without a template.
    const policyWorkspace = unescorted
      ? (templateState.template?.workspaceRoot ?? workspaceRoot)
      : check.profile.workspaceRoot
    const cwd = optionalString(payload?.cwd) ?? policyWorkspace
    if (!isDirectorySync(cwd)) return { ok: false, error: { code: 'ECWD', message: 'cwd 不是已存在的目录：' + cwd } }
    // Defense in depth: the Host already resolves cwd inside the policy
    // workspace, but the pod re-checks — a cwd outside the workspace would give
    // the command a directory the policy never described.
    if (!isInsideDirectory(policyWorkspace, cwd)) {
      return {
        ok: false,
        error: {
          code: 'ECWDWORSKSPACE',
          message: 'cwd 必须位于本次 policy 的 workspace 内：' + cwd + ' ⊄ ' + policyWorkspace,
        },
      }
    }
    const commandLabel = typeof payload?.command === 'string' && payload.command !== '' ? payload.command : argv.join(' ')
    const description = typeof payload?.description === 'string' ? truncate(payload.description.trim(), 500) : null
    // Session ownership is recorded with the job so a later Host (and this pod)
    // can answer "is this job mine?" without trusting the caller. Absent/empty
    // is the legacy/unowned case and is stored as null, never as "".
    const sessionId = typeof payload?.sessionId === 'string' && payload.sessionId !== '' ? payload.sessionId : null
    // The mode this command REALLY runs under. For an escorted run the prefix's
    // --mode was just proven equal to the request's mode, so both sources agree;
    // the prefix is used when an older caller sent no mode. `unescorted` is
    // always danger-full-access (validated above).
    const effectiveMode = unescorted ? 'danger-full-access' : (requestedMode ?? check.profile.mode)
    // Audit label only: the pod records what the Host says it approved. It grants
    // nothing — the authority is `effectiveMode` plus the prefix check above.
    const escalated = payload?.escalated === true
    const policyRecord = { mode: effectiveMode, escalated, unescorted }
    const dshEnv = sanitizeDshEnv(payload?.env)
    const hostInfo = payload?.host !== null && typeof payload?.host === 'object' ? payload.host : null
    const jobId = allocateJobId()
    const { dir, metaPath, outPath, exitPath } = jobPaths(jobId)
    try {
      fs.mkdirSync(dir, { recursive: true })
    } catch (error) {
      return { ok: false, error: { code: 'ELEDGER', message: '无法创建 job 账本目录：' + messageOf(error) } }
    }
    const startedAt = nowIso()
    // OPTIONAL foreground deadline (see `jobTimeoutOf`). A background
    // `pod_run` never sends it, so this stays null and nothing is armed.
    const timeoutMs = jobTimeoutOf(payload)
    const meta = {
      schema: LEDGER_SCHEMA,
      jobId,
      podPid: process.pid,
      podVersion: POD_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      // Which stable identity (and therefore which pipe) this pod serves. Lets a
      // ledger left behind by an unreachable pod still answer "which seed did
      // the process that ran this command use?".
      podIdentity: identityInfo,
      command: truncate(commandLabel, 4000),
      description,
      /** DSH session that started this job (`null` = legacy/unowned). */
      sessionId,
      /** Foreground deadline requested by the Host (`null` = unlimited). */
      timeoutMs: timeoutMs > 0 ? timeoutMs : null,
      argv,
      /** Audit hash of the exact target argv (the full argv is stored too). */
      argvHash: hashArgv(argv),
      /** Only the DSH_* vars the Host forwarded; values stay out of the ledger. */
      envKeys: Object.keys(dshEnv.env),
      cwd,
      startedAt,
      /** The file policy this command actually ran under. */
      policy: { ...policyRecord },
      // No runner prefix exists for an unescorted run; `null` is the honest
      // value and tells a later reader that danger-full-access was in effect.
      prefixFingerprint: unescorted ? null : check.fingerprint,
      prefixProfile: unescorted ? null : describePrefix(check.profile),
      template: templateState.valid
        ? {
            runnerPath: templateState.template.runnerPath,
            modes: templateState.template.modes,
            workspaceRoot: templateState.template.workspaceRoot,
          }
        : null,
      enforcement: enforcement ?? lastEnforcement,
      host: hostInfo === null ? null : {
        pid: typeof hostInfo.pid === 'number' ? hostInfo.pid : null,
        bootId: typeof hostInfo.bootId === 'string' ? hostInfo.bootId : null,
        startedAt: typeof hostInfo.startedAt === 'string' ? hostInfo.startedAt : null,
      },
      runnerPid: null,
      spawnedAt: null,
      spawnError: null,
    }
    try {
      writeJsonAtomic(metaPath, meta)
    } catch (error) {
      return { ok: false, error: { code: 'ELEDGER', message: '无法写 meta.json（命令未启动）：' + messageOf(error) } }
    }
    /** @type {any} */
    const rec = {
      jobId,
      diskOnly: false,
      child: null,
      outFd: null,
      /**
       * This pod's anonymous job handle for the runner. Process-private, never
       * in the ledger: its only job is to make freeze/thaw one kernel call over
       * the whole tree. Created before spawn, filled by `attachRunner` after.
       */
      jobHandle: null,
      runnerPid: null,
      status: 'running',
      finalized: false,
      killRequested: false,
      /** True once the deadline (or the Host's timeout-marked kill) stopped it. */
      timedOut: false,
      timeoutMs: timeoutMs > 0 ? timeoutMs : null,
      timeoutTimer: null,
      deadlineAtMs: null,
      deadlineRemainingMs: null,
      /** Freeze state machine (see freeze.mjs); all of it is memory only. */
      freezeState: 'none',
      frozenAt: null,
      frozenAtMs: null,
      freezeBy: null,
      freezeCount: 0,
      freezeMaxMs: null,
      freezePodGeneration: podGeneration,
      frozenMsTotal: 0,
      freezeWatchdogTimer: null,
      suspendedProcs: [],
      killedWhileFrozen: false,
      /**
       * True when THIS policy (freeze-policy.mjs) froze the job because DSH
       * disappeared. Memory-only and never written to meta.json: it exists so a
       * returning DSH never thaws a job a user froze by hand.
       */
      freezeAuto: false,
      spawnFailed: false,
      spawnError: null,
      exitCode: null,
      signal: null,
      startedAt,
      startedAtMs: Date.parse(startedAt) || Date.now(),
      endedAt: null,
      durationMs: null,
      command: truncate(commandLabel, 1000),
      description,
      sessionId,
      dshEnv: dshEnv.env,
      cwd,
      /** `null` for an unescorted run: there is no prefix to fingerprint. */
      prefixFingerprint: unescorted ? null : check.fingerprint,
      /** The policy this job runs under; also written to meta.json. */
      policy: { ...policyRecord },
      totalBytes: 0,
      ring: Buffer.alloc(0),
      segments: [],
      decoders: {},
      stderrTail: '',
      lossy: false,
      writeErrors: 0,
      closeWaiters: [],
      metaPath,
      outPath,
      exitPath,
      spawnedAt: null,
    }
    let outFd = null
    try {
      outFd = fs.openSync(outPath, 'a')
    } catch (error) {
      rec.finalized = true
      rec.status = 'ledger-failed'
      rec.spawnFailed = true
      rec.spawnError = '无法打开 out.log：' + messageOf(error)
      jobs.set(jobId, rec)
      try {
        writeJsonAtomic(exitPath, {
          schema: LEDGER_SCHEMA,
          jobId,
          status: rec.status,
          exitCode: null,
          signal: null,
          startedAt,
          endedAt: nowIso(),
          durationMs: 0,
          totalBytes: 0,
          lossy: true,
          writeErrors: 0,
          runnerFailure: { matched: false },
          runnerPid: null,
          podPid: process.pid,
          spawnError: rec.spawnError,
          // Same freeze keys as a normal exit record, so a reader never has to
          // branch on "was this record written before the command even existed".
          frozenMs: 0,
          freezeCount: 0,
          killedWhileFrozen: false,
        })
      } catch {
        // nothing else to do
      }
      // This job is final (status `ledger-failed`): a lifecycle checkpoint too.
      notifySettlement(rec)
      return { ok: false, jobId, error: { code: 'ELEDGER', message: rec.spawnError } }
    }
    rec.outFd = outFd
    jobs.set(jobId, rec)

    // Freeze ownership starts here, BEFORE the runner exists: create the pod's
    // anonymous job object, then put the runner in it as soon as it has a pid.
    // NOT kill-on-close (see freeze.mjs): closing this handle — at finalize, or
    // when the pod dies — must not kill the command.
    freeze.createJob(rec)

    const env = { ...process.env }
    for (const key of Object.keys(env)) if (key.includes('SUBPROCESS_CONTROL')) delete env[key]
    // Fresh per-run DSH_* values win over the stale env this pod was spawned with.
    for (const [key, value] of Object.entries(rec.dshEnv ?? {})) env[key] = value
    env.NO_COLOR = '1'
    env.PAGER = 'cat'
    env.GIT_PAGER = 'cat'
    let child
    try {
      // Escorted: `prefix + '--' + target argv`, so the runner confines the
      // target. Unescorted: `spawnProgram/spawnArgs` ARE the target argv — no
      // runner, no prefix — so the command inherits this pod's own Medium
      // integrity token. That is exactly what danger-full-access means, and it
      // is also why the ledger lives outside every workspace (an unrestricted
      // command could otherwise rewrite its own meta.json/out.log/exit.json).
      child = spawnProcess(spawnProgram, spawnArgs, {
        cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env,
      })
    } catch (error) {
      rec.spawnFailed = true
      rec.spawnError = messageOf(error)
      finalize(rec, null, null)
      return {
        ok: false,
        jobId,
        error: {
          code: 'ESPAWNFAILED',
          message: (unescorted ? '无法启动命令（danger-full-access 无前缀）：' : '无法启动受限 runner：') + messageOf(error),
        },
      }
    }
    rec.child = child
    if (typeof child.pid === 'number') {
      rec.runnerPid = child.pid
      rec.spawnedAt = nowIso()
      // ASSIGNMENT RACE: the runner may already have spawned the restricted
      // command. It is then NOT a member of this job, so the kernel freeze will
      // not cover it; `freeze.freeze()` finds such escapees with a Toolhelp walk
      // + IsProcessInJob and suspends them individually. That is a documented
      // second-class fallback with its own gaps (see freeze.mjs), not a claim of
      // full coverage — the step-3 coverage repair is deliberately not here.
      freeze.attachRunner(rec, child.pid)
      updateMetaAfterSpawn(rec)
    }
    if (rec.timeoutMs !== null && rec.timeoutMs !== undefined && typeof child.pid === 'number') {
      // The deadline lives HERE, next to the process it polices, not in the
      // Host: a DSH restart must not extend (or drop) a foreground deadline.
      // `killRecord` is the same kill path `pod_kill` uses (runner kill, then
      // taskkill /T /F fallback), so a killed command still reports partial
      // output and an honest `killed` ledger status.
      // The freeze controller owns the timer because a freeze must PAUSE it and
      // a thaw must re-arm it with the remaining budget (design §5).
      freeze.armDeadline(rec, rec.timeoutMs)
    }
    child.stdout?.on('data', (chunk) => appendOutput(rec, chunk, 'stdout'))
    child.stderr?.on('data', (chunk) => {
      rec.stderrTail = (rec.stderrTail + chunk.toString('utf8')).slice(-8192)
      appendOutput(rec, chunk, 'stderr')
    })
    child.on('error', (error) => {
      rec.spawnError = messageOf(error)
      if (typeof child.pid !== 'number') {
        rec.spawnFailed = true
        finalize(rec, null, null)
      }
    })
    child.on('close', (code, signal) => finalize(rec, code, signal))

    // Give the runtime a turn to surface an immediate spawn error (ENOENT and
    // friends) so a bad prefix reports at `pod_run` time instead of looking
    // like a running job that never prints.
    await new Promise((resolveTick) => {
      const timer = setTimeout(resolveTick, 15)
      if (typeof timer.unref === 'function') timer.unref()
    })
    if (rec.finalized && rec.status === 'spawn-failed') {
      return { ok: false, jobId, error: { code: 'ESPAWNFAILED', message: rec.spawnError ?? (unescorted ? '命令未能启动（danger-full-access 无前缀）' : '受限 runner 未能启动') } }
    }
    log('job ' + jobId + ' spawned runnerPid=' + String(rec.runnerPid) + ' mode=' + effectiveMode + (unescorted ? '(unescorted)' : ''))
    return {
      ok: true,
      op: 'run',
      jobId,
      runnerPid: rec.runnerPid,
      podPid: process.pid,
      prefixFingerprint: unescorted ? null : check.fingerprint,
      enforcement: enforcement ?? lastEnforcement,
      policy: { ...policyRecord },
      startedAt: rec.startedAt,
      cwd,
      command: truncate(commandLabel, 400),
      description,
      sessionId,
      timeoutMs: rec.timeoutMs,
      status: 'running',
    }
  }

  /** @param {unknown} payload */
  async function killJob(payload) {
    const jobId = String(payload?.jobId ?? '')
    if (!JOB_ID_PATTERN.test(jobId)) {
      return { ok: false, error: { code: 'EBADJOBID', message: 'jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId } }
    }
    const rec = jobs.get(jobId) ?? loadJobFromDisk(jobId)
    if (rec === null || rec === undefined) {
      return { ok: false, error: { code: 'ENOJOB', message: '账本里没有这个 job：' + jobId } }
    }
    // Enforced before the "already finished" shortcut: even a settled foreign
    // job must not be inspectable/controllable without an explicit adopt.
    const access = jobAccess(rec, payload)
    if (!access.allowed) return foreignJobError(jobId)
    if (!isRunning(rec)) {
      return {
        ok: true,
        op: 'kill',
        jobId,
        killed: false,
        status: rec.status,
        exitCode: rec.exitCode,
        signal: rec.signal,
        sessionId: access.owner,
        ...(access.adoptedFrom === undefined ? {} : { adoptedFrom: access.adoptedFrom }),
        note: '这个 job 已经结束，或本次 pod 实例没有它的进程句柄（状态见 status/exitCode）',
      }
    }
    // A timeout-marked kill (the `pod_exec` Host fallback for an older pod)
    // must be recorded as a TIMEOUT, not as a user kill. Set before killing so
    // `finalize()` writes `timedOut: true` into exit.json.
    const timeoutMs = jobTimeoutOf(payload)
    if (timeoutMs > 0) {
      rec.timedOut = true
      rec.timeoutMs = timeoutMs
      log('job ' + jobId + ' 收到超时终止请求（' + timeoutMs + 'ms）：终止 runner')
    }
    const closed = await killRecord(rec, timeoutMs > 0 ? TIMEOUT_KILL_GRACE_MS : 3000)
    return {
      ok: true,
      op: 'kill',
      jobId,
      killed: closed,
      status: rec.status,
      exitCode: rec.exitCode,
      signal: rec.signal,
      timedOut: rec.timedOut === true,
      timeoutMs: rec.timeoutMs ?? null,
      sessionId: access.owner,
      ...(access.adoptedFrom === undefined ? {} : { adoptedFrom: access.adoptedFrom }),
    }
  }

  /**
   * Freeze OR thaw one job (`pod_freeze`, and the `thaw` protocol alias).
   *
   * One implementation for both actions on purpose: the ownership guard, the
   * error vocabulary and the state checks are identical, and two copies would
   * drift (design §4). Freezing someone else's job is a denial of service — the
   * command never finishes — so the session boundary is enforced HERE as well
   * as on the Host (same `jobAccess` rule as output/kill/cursor/ack).
   *
   * Error vocabulary:
   *   EBADJOBID            jobId is not shaped like a pod job id
   *   ENOJOB               not in the ledger
   *   EFOREIGNJOB          another session's job (needs adopt:true)
   *   ENOTHANDLE           ledger-only record, or a running job this pod has no
   *                        job handle for; the handle is process-private and
   *                        never persisted, so a restarted pod cannot adopt one
   *   ENOTRUNNING          the job already finished
   *   EFREEZEUNSUPPORTED   the capability probe says this machine cannot freeze
   *   EOSFAIL              SetInformationJobObject refused (carries the Win32 code)
   *
   * @param {unknown} payload
   * @param {'freeze' | 'thaw'} [forcedAction] set by the `thaw` protocol op
   */
  function freezeJob(payload, forcedAction) {
    const action = forcedAction === 'thaw' || payload?.action === 'thaw' ? 'thaw' : 'freeze'
    const jobId = String(payload?.jobId ?? '')
    if (!JOB_ID_PATTERN.test(jobId)) {
      return { ok: false, op: 'freeze', error: { code: 'EBADJOBID', message: 'jobId 形状不合法（应形如 podc-<stamp>-<hex8>）：' + jobId } }
    }
    const rec = jobs.get(jobId) ?? loadJobFromDisk(jobId)
    if (rec === null || rec === undefined) {
      return { ok: false, op: 'freeze', error: { code: 'ENOJOB', message: '账本里没有这个 job：' + jobId } }
    }
    const access = jobAccess(rec, payload)
    if (!access.allowed) return foreignJobError(jobId)
    const adopted = access.adoptedFrom === undefined ? {} : { adoptedFrom: access.adoptedFrom }
    if (rec.diskOnly === true) {
      return {
        ok: false,
        op: 'freeze',
        jobId,
        error: {
          code: 'ENOTHANDLE',
          message: 'job ' + jobId + ' 只是账本记录：job 句柄是进程私有的，已随上一个 pod 进程消失。' +
            '若它停在冻结状态（status=frozen-orphan），本 pod 没有任何句柄可以解冻；账本里的 runnerPid 也不足以安全地杀进程（PID 可能已被复用），' +
            '所以 pod_kill 会如实返回 killed=false，而不是盲杀。',
        },
      }
    }
    if (!isRunning(rec)) {
      return {
        ok: false,
        op: 'freeze',
        jobId,
        error: { code: 'ENOTRUNNING', message: 'job ' + jobId + ' 已经结束（status=' + String(rec.status) + '），没有可冻结/解冻的进程' },
      }
    }
    // Capability before handle: on a machine that cannot freeze, "unsupported"
    // is the honest answer even though no job can have a handle there either.
    if (action === 'freeze' && freeze.support().supported !== true) {
      return {
        ok: false,
        op: 'freeze',
        jobId,
        error: { code: 'EFREEZEUNSUPPORTED', message: freeze.support().reason ?? '本机不支持 job 冻结' },
      }
    }
    if (action === 'thaw' && rec.freezeState !== 'frozen') {
      // Nothing to resume: answer from the record. A missing handle must not
      // turn a harmless no-op into ENOTHANDLE.
      const row = freeze.view(rec)
      return {
        ok: true,
        op: 'freeze',
        jobId,
        action,
        frozen: false,
        frozenAt: null,
        frozenForMs: row.frozenForMs,
        remainingFreezeMs: null,
        maxFreezeMs: row.maxFreezeMs,
        freezeCount: row.count,
        thawable: row.thawable,
        alreadyFrozen: false,
        alreadyThawed: true,
        sessionId: access.owner,
        ...adopted,
        note: '这个 job 本来就没有在冻结状态（无需解冻）',
      }
    }
    if (rec.jobHandle === null || rec.jobHandle === undefined) {
      return {
        ok: false,
        op: 'freeze',
        jobId,
        error: {
          code: 'ENOTHANDLE',
          message: 'job ' + jobId + ' 在运行，但本 pod 没有它的 job 句柄（赋值失败或本次 pod 没有启用 job 归属），无法' + (action === 'freeze' ? '冻结' : '解冻'),
        },
      }
    }
    const outcome = action === 'freeze'
      ? freeze.freeze(rec, { by: typeof payload?.sessionId === 'string' ? payload.sessionId : null, maxFreezeMs: payload?.maxFreezeMs })
      : freeze.thaw(rec, 'manual')
    if (outcome.ok !== true) {
      return {
        ok: false,
        op: 'freeze',
        jobId,
        error: {
          code: typeof outcome.code === 'string' ? outcome.code : 'EOSFAIL',
          message: String(outcome.message ?? '冻结操作失败'),
          ...(typeof outcome.win32 === 'number' ? { win32: outcome.win32 } : {}),
        },
      }
    }
    // An explicit pod_freeze is a MANUAL claim: even when it finds the job
    // already auto-frozen, the freeze-mode policy must stop owning it, so a
    // returning DSH leaves it frozen. An explicit thaw likewise releases it.
    rec.freezeAuto = false
    const row = freeze.view(rec)
    const frozen = row.state === 'frozen'
    return {
      ok: true,
      op: 'freeze',
      jobId,
      action,
      frozen,
      frozenAt: row.since,
      frozenForMs: row.frozenForMs,
      remainingFreezeMs: row.remainingFreezeMs,
      maxFreezeMs: row.maxFreezeMs,
      freezeCount: row.count,
      thawable: row.thawable,
      alreadyFrozen: outcome.alreadyFrozen === true,
      alreadyThawed: outcome.alreadyThawed === true,
      sessionId: access.owner,
      ...adopted,
      note: frozen
        ? '命令已冻结（CPU 与输出停止）；' + String(Math.round((row.remainingFreezeMs ?? 0) / 1000)) + 's 后看门狗会自动解冻。DSH 退出后冻结保持；pod 进程若重启，它变成 frozen-orphan，只能用 pod_kill 清理。'
        : (outcome.alreadyThawed === true
          ? '这个 job 本来就没有在冻结状态（无需解冻）'
          : '命令已恢复运行；输出从同一绝对偏移继续，时间预算按剩余量重挂'),
    }
  }

  function listJobs() {
    return [...jobs.values()]
      .map((rec) => ({
        jobId: rec.jobId,
        status: rec.status,
        running: isRunning(rec),
        exitCode: rec.exitCode,
        signal: rec.signal,
        timedOut: rec.timedOut === true,
        timeoutMs: rec.timeoutMs ?? null,
        runnerPid: rec.runnerPid,
        startedAt: rec.startedAt,
        endedAt: rec.endedAt,
        durationMs: rec.durationMs,
        bytes: rec.totalBytes,
        lossy: rec.lossy === true,
        cursor: cursorProjection(rec),
        spillPaths: [jobPaths(rec.jobId).outPath],
        channels: [...new Set((rec.segments ?? []).map((segment) => segment.channel))],
        command: rec.command === null ? null : truncate(rec.command, 1000),
        description: rec.description ?? null,
        sessionId: rec.sessionId ?? null,
        cwd: rec.cwd,
        prefixFingerprint: rec.prefixFingerprint,
        /**
         * The file policy this job ran under: `{ mode, escalated, unescorted }`.
         * `null` for a ledger written before the policy followed the session.
         */
        policy: rec.policy ?? null,
        // Freeze projection: state, since, who, remaining watchdog time and —
        // the one field that matters for an operator — whether THIS process can
        // still thaw it. A ledger-only job is always `thawable:false`.
        freeze: freeze.view(rec),
      }))
      .sort((left, right) => Date.parse(right.startedAt ?? '') - Date.parse(left.startedAt ?? ''))
  }

  // -------------------------------------------------------------------------
  // Freeze mode support (see freeze-policy.mjs). The policy owns WHEN; these
  // four primitives own HOW, and deliberately stay inside the service so the
  // policy handles no `rec`, no job handle and no ledger path.
  // -------------------------------------------------------------------------

  /**
   * The policy's view of the world: only RUNNING jobs, with the two flags it
   * needs. `autoFrozen` is memory-only and distinguishes "this pod's policy
   * froze it" from "a user ran pod_freeze".
   */
  function jobsForFreezePolicy() {
    return [...jobs.values()]
      .filter((rec) => isRunning(rec))
      .map((rec) => ({
        jobId: rec.jobId,
        frozen: rec.freezeState === 'frozen',
        autoFrozen: rec.freezeAuto === true,
      }))
  }

  /**
   * Freeze one job on behalf of the policy (no client is connected, so there is
   * no session-ownership check: the policy is the pod itself).
   * @param {string} jobId
   * @param {{ maxFreezeMs?: number, by?: string }} [options]
   */
  function autoFreezeJob(jobId, options = {}) {
    const rec = jobs.get(jobId)
    if (rec === undefined) return { ok: false, code: 'ENOJOB', message: '本 pod 没有这个 job：' + jobId }
    if (!isRunning(rec)) return { ok: false, code: 'ENOTRUNNING', message: 'job ' + jobId + ' 已经结束，无法冻结' }
    if (rec.freezeState === 'frozen') return { ok: true, alreadyFrozen: true }
    const maxFreezeMs = Number(options?.maxFreezeMs)
    let outcome
    try {
      outcome = freeze.freeze(rec, {
        by: typeof options?.by === 'string' && options.by !== '' ? options.by : 'freeze-mode',
        maxFreezeMs: Number.isFinite(maxFreezeMs) ? maxFreezeMs : undefined,
      })
    } catch (error) {
      return { ok: false, code: 'ETHROW', message: messageOf(error) }
    }
    if (outcome.ok !== true) {
      return {
        ok: false,
        code: typeof outcome.code === 'string' ? outcome.code : 'EOSFAIL',
        message: String(outcome.message ?? '冻结失败'),
        ...(typeof outcome.win32 === 'number' ? { win32: outcome.win32 } : {}),
      }
    }
    rec.freezeAuto = true
    return { ok: true, alreadyFrozen: outcome.alreadyFrozen === true }
  }

  /**
   * Thaw ONLY a job the policy froze. A manual pod_freeze is never undone here,
   * and a job that already finished is a harmless no-op.
   * @param {string} jobId
   * @param {string} [reason]
   */
  function autoThawJob(jobId, reason = 'client-returned') {
    const rec = jobs.get(jobId)
    if (rec === undefined) return { ok: true, alreadyThawed: true, skipped: 'ENOJOB' }
    if (rec.freezeState !== 'frozen') {
      rec.freezeAuto = false
      return { ok: true, alreadyThawed: true }
    }
    if (rec.freezeAuto !== true) {
      return { ok: false, code: 'EMANUALFREEZE', message: 'job ' + jobId + ' 是手动冻结的，自动策略不会解冻它' }
    }
    let outcome
    try {
      outcome = freeze.thaw(rec, reason)
    } catch (error) {
      return { ok: false, code: 'ETHROW', message: messageOf(error) }
    }
    if (outcome.ok !== true) {
      return {
        ok: false,
        code: typeof outcome.code === 'string' ? outcome.code : 'EOSFAIL',
        message: String(outcome.message ?? '解冻失败'),
        ...(typeof outcome.win32 === 'number' ? { win32: outcome.win32 } : {}),
      }
    }
    rec.freezeAuto = false
    return { ok: true, alreadyThawed: outcome.alreadyThawed === true }
  }

  /**
   * Self-destruct: terminate every running job (frozen ones included — that is
   * what `killedWhileFrozen` in exit.json is for) and wait for the ledger to
   * settle before the caller exits the process.
   * @param {string} reason
   * @returns {Promise<number>} how many jobs were running
   */
  async function killAllJobs(reason) {
    const active = [...jobs.values()].filter((rec) => isRunning(rec))
    if (active.length === 0) {
      log('killAll (' + reason + ')：没有运行中的 job')
      return 0
    }
    const frozen = active.filter((rec) => rec.freezeState === 'frozen').length
    log(
      'killAll (' + reason + ')：终止 ' + String(active.length) + ' 个 job' +
      (frozen > 0 ? '（其中 ' + String(frozen) + ' 个冻结中，exit.json 会写 killedWhileFrozen）' : ''),
    )
    await Promise.all(active.map((rec) => killRecord(rec, 2000)))
    const confirmed = active.filter((rec) => rec.finalized === true).length
    if (confirmed < active.length) {
      // Never claim a clean kill the ledger cannot back: the rest may still be
      // taken down by killRecord's taskkill fallback, but exit.json is truth.
      log(
        'killAll：' + String(active.length) + ' 个 job 中只有 ' + String(confirmed) +
        ' 个已确认结束（其余走 taskkill 兜底，账本状态为准）',
      )
    }
    return active.length
  }

  /**
   * @param {{ freeze?: boolean }} [snapshotOptions] `freeze:false` keeps the
   *   capability probe out of the bootstrap/handshake path (`identify` and
   *   `handover` spread this snapshot); every `status` call includes it.
   */
  function snapshot(snapshotOptions = {}) {
    const records = [...jobs.values()]
    return {
      ok: true,
      podPid: process.pid,
      podStartedAt: startedAt.toISOString(),
      generation,
      /** This pod PROCESS (not the connection counter); see its declaration. */
      podGeneration,
      podVersion: POD_VERSION,
      podFlavor: POD_FLAVOR,
      protocolVersion: PROTOCOL_VERSION,
      idleExitMs,
      // The window a client gets when it sends no `maxBytes` (an older Host or
      // the raw CLI), and the hard clamp every request is held to. The Host
      // normally sends the live native window with every read.
      outputChunkBytes,
      maxOutputChunkBytes: MAX_OUTPUT_CHUNK_BYTES,
      pipeName,
      workspaceRoot,
      dataRoot,
      identity: identityInfo,
      auth: authSnapshot(),
      attestation: attestationSnapshot(),
      ...(snapshotOptions.freeze === false ? {} : { freeze: freezeSnapshot() }),
      enforcement: lastEnforcement ?? templateState.template?.enforcement ?? null,
      template: templateSummary(),
      running: records.filter((rec) => isRunning(rec)).length,
      jobs: listJobs(),
    }
  }

  /** @param {string} reason */
  async function shutdown(reason) {
    if (shuttingDown) return
    shuttingDown = true
    log('shutdown: ' + reason)
    const active = [...jobs.values()].filter((rec) => isRunning(rec))
    await Promise.all(active.map((rec) => killRecord(rec, 2000)))
    if (shutdownHandler !== null) shutdownHandler(reason)
  }

  /** @param {string} op @param {any} payload */
  async function handle(op, payload) {
    lastActivity = Date.now()
    switch (op) {
      case 'ping':
      case 'hello':
        return { ...snapshot({ freeze: false }), op }
      case 'status':
        return { ...snapshot(), op: 'status' }
      case 'run':
        return await runJob(payload ?? {})
      case 'output':
        return readOutput(payload ?? {})
      case 'ack':
        return ackJob(payload ?? {})
      case 'cursor':
        return cursorOp(payload ?? {})
      case 'kill':
        return await killJob(payload ?? {})
      case 'freeze':
        return freezeJob(payload ?? {})
      // Alias: a caller may send op:'thaw' with no `action`. The single
      // implementation above stays authoritative for both.
      case 'thaw':
        return freezeJob(payload ?? {}, 'thaw')
      case 'shutdown': {
        // Protocol shutdown (settings page's hold-to-confirm button, and the
        // `escapePod` service dsh-power links its own shutdown to). The kills
        // are recorded BEFORE the answer is written, so `killed` is never
        // optimistic: every exit.json already says `killed` when this replies.
        const killJobs = payload !== null && typeof payload === 'object' && payload.killJobs === true
        const killed = killJobs ? await killAllJobs('shutdown') : 0
        // Give the response a moment to flush before the socket dies: the Host
        // uses `killed` to report how many jobs the ledger recorded. The exit
        // itself is owned by `shutdown()`, which cancels the policy first.
        setTimeout(() => {
          void shutdown('protocol shutdown op')
        }, 120).unref?.()
        return {
          ok: true,
          op: 'shutdown',
          podPid: process.pid,
          killed,
          message: killJobs
            ? 'pod 已终止 ' + String(killed) + ' 个 job 并退出'
            : 'pod 将结束所有任务并退出',
        }
      }
      default:
        return { ok: false, error: { code: 'EBADOP', message: 'unknown op: ' + String(op) } }
    }
  }

  return {
    init,
    handle,
    shutdown,
    snapshot,
    listJobs,
    /** Freeze-mode primitives (see the support block above). */
    jobsForFreezePolicy,
    autoFreezeJob,
    autoThawJob,
    killAllJobs,
    templateSummary,
    bumpGeneration() {
      generation += 1
      lastActivity = Date.now()
      return generation
    },
    touchActivity() {
      lastActivity = Date.now()
    },
    lastActivity() {
      return lastActivity
    },
    runningJobCount() {
      return [...jobs.values()].filter((rec) => isRunning(rec)).length
    },
    isRunning,
    setShutdownHandler(handler) {
      shutdownHandler = typeof handler === 'function' ? handler : null
    },
    /** @param {(record: any) => void} handler */
    setSettlementHandler(handler) {
      settlementHandler = typeof handler === 'function' ? handler : null
    },
    isInitialized() {
      return initialized
    },
  }
}

// ---------------------------------------------------------------------------
// Socket layer: JSON Lines over the deterministic named pipe.
// ---------------------------------------------------------------------------

/**
 * Build the per-connection handler: JSON Lines framing, single-client admission
 * and token auth. Exported so the static self-test can drive the real refusal
 * paths over a fake socket (no named pipe is needed to prove them).
 * @param {ReturnType<typeof createPodService>} service
 * @param {ReturnType<typeof createPodAuth>} auth
 * @param {{ clients?: Set<any>, log?: (message: string) => void, attestor?: any, attestPolicy?: any, onAttestation?: (record: any) => void, onClientChange?: (connected: boolean) => void }} [options]
 */
export function createConnectionHandler(service, auth, options = {}) {
  const clients = options.clients instanceof Set ? options.clients : new Set()
  const log = typeof options.log === 'function' ? options.log : () => {}
  /**
   * Admission/close notification for the pod's lifecycle rule. Called with
   * `true` right after a socket is admitted and `false` after it is removed;
   * the pod only uses it as a checkpoint (the authoritative "no clients" test
   * remains `clients.size`).
   */
  const onClientChange = typeof options.onClientChange === 'function' ? options.onClientChange : () => {}
  const attestor = options.attestor ?? null
  // A plain policy object (tests, older callers) or a live source with
  // `current()`. A source is re-read per decision: the operator may have
  // flipped warn→enforce in `attest-policy.json` since the connection arrived.
  const policyInput = options.attestPolicy ?? null
  const identityChannel = options.identityChannel ?? null
  const onAttestation = typeof options.onAttestation === 'function' ? options.onAttestation : () => {}

  /**
   * Current policy, or null when attestation is disabled/unresolvable.
   *
   * A throwing source is logged and treated as "no policy": failing closed here
   * would deny even the token-authenticated Host and leave the only surviving
   * process unreachable. The token gate still applies, and the source itself
   * never throws for a corrupt file (it keeps the last valid policy).
   *
   * @returns {any}
   */
  function currentPolicy() {
    if (policyInput === null) return null
    try {
      if (typeof policyInput === 'function') return policyInput()
      if (typeof policyInput === 'object' && typeof policyInput.current === 'function') return policyInput.current()
      return policyInput
    } catch (error) {
      log('attest policy 解析失败（继续按无策略处理，token 仍然有效）：' + messageOf(error))
      return null
    }
  }

  /**
   * Identify the process on the other end and decide whether it may talk to us.
   *
   * This runs BEFORE `auth.admitConnection`: the `handover` op is the one request
   * that cannot carry a token (a Host after a restart has no way to know the
   * previous process's memory-only token), so if the OS cannot tell us who is
   * asking, the takeover request is exactly the one we must not answer.
   *
   * @param {any} socket
   * @param {any} connection
   * @returns {{ allowed: boolean, record: any }}
   */
  function attestConnection(socket, connection) {
    const attestPolicy = currentPolicy()
    if (attestor === null || attestPolicy === null || attestPolicy.mode === 'off') return { allowed: true, deferred: false, record: null }
    /** @type {any} */
    let attestation = null
    try {
      attestation = attestor.describeClient(socket)
    } catch (error) {
      attestation = { ok: false, code: 'EATTESTCRASH', message: messageOf(error) }
    }
    let verdict = null
    try {
      verdict = evaluateClient(attestation, attestPolicy)
    } catch (error) {
      verdict = { allowed: false, checks: [{ name: 'evaluate', ok: false, detail: messageOf(error) }] }
    }
    // `describeClient` needs a Win32 HANDLE for the pipe socket, and Node never
    // exposes one (`_handle.fd` is -1 for a pod's accepted pipe connections).
    // "No handle" is not evidence against the client: it only means this
    // transport cannot answer the pipe question. Treating it as a denial would
    // close every connection in enforce mode before `identify` could hand out a
    // nonce — locking every Host out of the only process that survived a
    // restart. The decision is therefore deferred to the handover gate, which
    // refuses a takeover without a redeemed identity nonce.
    const deferred = attestation?.ok !== true
    const record = {
      at: nowIso(),
      mode: attestPolicy.mode,
      allowed: verdict.allowed === true,
      deferred,
      client: attestation?.ok === true ? attestation.client : null,
      handle: attestation?.ok === true ? { fd: attestation.fd, instances: attestation.instances, serverPid: attestation.serverPid } : null,
      failure: attestation?.ok === true ? null : { code: attestation?.code ?? 'unknown', message: attestation?.message ?? null },
      checks: verdict.checks,
      peer: connection.peer,
    }
    connection.attestation = record
    const failed = verdict.checks.filter((check) => !check.ok)
    if (deferred) {
      log(
        'attest 无法确认 peer=' + connection.peer + ' ' + String(attestation?.code ?? 'unknown') +
        '（管道句柄不可用）；enforce 下由 handover 的 nonce 通道强制',
      )
    } else if (failed.length === 0) {
      log(
        'attest ok peer=' + connection.peer + ' pid=' + String(record.client?.pid) + ' image=' + String(record.client?.imagePath) +
        ' integrity=' + String(record.client?.integrity) + ' restricted=' + String(record.client?.restrictedSidCount),
      )
    } else {
      log(
        'attest ' + (attestPolicy.mode === 'enforce' ? 'DENIED' : 'WARN') + ' peer=' + connection.peer + ' pid=' + String(record.client?.pid) +
        ' reason=' + failed.map((check) => check.name + '(' + check.detail + ')').join(' '),
      )
    }
    try {
      onAttestation(record)
    } catch (error) {
      log('attestation sink failed: ' + messageOf(error))
    }
    return { allowed: verdict.allowed === true, deferred, record }
  }

  /** @param {net.Socket} socket @param {Record<string, unknown>} payload */
  function sendLine(socket, payload) {
    if (socket.destroyed || !socket.writable) return
    try {
      socket.write(JSON.stringify(payload) + '\n')
    } catch {
      // a dying client is not the pod's problem
    }
  }

  /**
   * Flush one terminal response and close the connection. Used for refusals
   * (second client, bad/missing token): `end()` flushes the reason, the timer is
   * only a backstop for a peer that never reads.
   * @param {net.Socket} socket @param {Record<string, unknown>} payload
   */
  function sendLineAndClose(socket, payload) {
    if (socket.destroyed) return
    try {
      if (socket.writable) socket.end(JSON.stringify(payload) + '\n')
      else socket.destroy()
    } catch {
      try {
        socket.destroy()
      } catch {
        // already gone
      }
    }
    const timer = setTimeout(() => {
      try {
        socket.destroy()
      } catch {
        // already gone
      }
    }, 250)
    if (typeof timer.unref === 'function') timer.unref()
  }

  /**
   * Refuse a second client with a CORRELATED error frame, then close.
   *
   * Writing the frame at accept time and closing immediately is a race the
   * client cannot win: it has not sent its request yet, so the frame carries no
   * `id`, the client's pending-request map drops it, and the client only sees
   * "connection closed" (ECLOSED) instead of the real reason. Instead, read ONE
   * request line (bounded, short timeout) and echo its `id`. Nothing from this
   * socket ever reaches `service` or `auth`: one line, one refusal, then gone.
   * @param {any} socket @param {string} message
   */
  function refuseBusy(socket, message) {
    if (socket.destroyed) return
    const payload = { ok: false, error: { code: 'EBUSY', message } }
    let settled = false
    let buffer = ''
    /** @param {unknown} id */
    const finish = (id) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.removeListener('data', onData)
        socket.removeListener('end', onEnd)
        socket.removeListener('close', onEnd)
      } catch {
        // already gone
      }
      sendLineAndClose(socket, id === undefined || id === null ? payload : { ...payload, id })
    }
    /** @param {Buffer | string} chunk */
    const onData = (chunk) => {
      buffer += String(chunk)
      const newline = buffer.indexOf('\n')
      if (newline < 0) {
        if (buffer.length > MAX_PROTOCOL_LINE_BYTES) finish(undefined)
        return
      }
      /** @type {any} */
      let id
      try {
        id = JSON.parse(buffer.slice(0, newline))?.id
      } catch {
        id = undefined
      }
      finish(id)
    }
    const onEnd = () => finish(undefined)
    const timer = setTimeout(() => finish(undefined), REJECT_READ_TIMEOUT_MS)
    if (typeof timer.unref === 'function') timer.unref()
    try {
      socket.setEncoding('utf8')
      socket.on('data', onData)
      socket.once('end', onEnd)
      socket.once('close', onEnd)
      socket.resume?.()
    } catch {
      finish(undefined)
    }
  }

  /** @param {string} line @param {net.Socket} socket @param {PodConnection} connection */
  async function dispatch(line, socket, connection) {
    const text = line.trim()
    if (text === '') return
    /** @type {any} */
    let message
    try {
      message = JSON.parse(text)
    } catch {
      // No auth state exists for this line; refuse and close rather than guess.
      sendLineAndClose(socket, { ok: false, error: { code: 'EBADJSON', message: 'request is not valid JSON' } })
      return
    }
    const op = typeof message?.op === 'string' ? message.op : ''
    const id = message?.id

    // Two bootstrap ops that do not carry a valid token:
    //   identify — publish the identity-channel port (public, no secret)
    //   handover — the only way a Host after a restart can take the pod over,
    //              which is exactly why it must carry an OS-attested nonce
    if (op === 'identify') {
      sendLine(socket, {
        ok: true,
        op: 'identify',
        id,
        podPid: process.pid,
        podStartedAt: service.snapshot({ freeze: false }).podStartedAt,
        identityChannel: identityChannel === null ? null : { port: identityChannel.port(), protocol: 1 },
        attestationMode: currentPolicy()?.mode ?? 'off',
      })
      return
    }

    if (op === 'handover') {
      // Resolve again (not at accept time): flipping the policy file to
      // enforce must protect the very next takeover, not only new sockets.
      const attestPolicy = currentPolicy()
      const nonce = typeof message?.nonce === 'string' ? message.nonce.trim() : ''
      if (identityChannel !== null && nonce !== '') {
        const redeemed = identityChannel.consume(nonce)
        if (redeemed.ok === true) {
          connection.identity = redeemed.ticket
        } else {
          connection.identityError = redeemed
        }
      }
      // Bootstrap: the nonce is not merely "nice in enforce mode" — it is the
      // only credential this pod has, so require it regardless of policy mode.
      // Without this, warn/off deployments would let any same-user process race
      // the Host and claim the pod. The policy itself must also still be
      // enforce: a nonce issued under warn/off does not prove integrity.
      const bootstrapHandover = typeof auth.isBootstrap === 'function' ? auth.isBootstrap() === true : false
      const bootstrapPolicy = currentPolicy()
      const bootstrapPolicyOk = bootstrapPolicy !== null && bootstrapPolicy.mode === 'enforce'
      if (bootstrapHandover && (connection.identity === undefined || !bootstrapPolicyOk)) {
        const reason = connection.identity === undefined
          ? (connection.identityError ?? {
            code: 'EUNATTESTED',
            message: 'bootstrap handover 必须携带 identity 通道已兑换的 nonce（这是无 stdin 启动的唯一安全边界）',
          })
          : {
            code: 'EUNATTESTED',
            message: 'bootstrap handover 需要 attest-policy 处于 enforce（当前 ' + String(bootstrapPolicy?.mode ?? 'off') + '）',
          }
        log('reject bootstrap handover peer=' + connection.peer + ': ' + String(reason.code) + ' ' + String(reason.message))
        auth.detachConnection(connection)
        sendLineAndClose(socket, { ok: false, error: { code: reason.code, message: reason.message, retryAfterMs: null }, id })
        return
      }
      // In enforce mode the takeover is refused unless the requester proved its
      // process identity over the loopback channel first. `warn` keeps the old
      // behaviour and only records the miss, so an operator can promote later
      // without ever locking a legitimate Host out of a pod that outlives it.
      if (attestPolicy !== null && attestPolicy.mode === 'enforce' && connection.identity === undefined) {
        const reason = connection.identityError ?? { code: 'EUNATTESTED', message: 'handover 没有携带已登记的身份 nonce' }
        log('reject handover peer=' + connection.peer + ': ' + String(reason.code) + ' ' + String(reason.message))
        auth.detachConnection(connection)
        sendLineAndClose(socket, { ok: false, error: { code: reason.code, message: reason.message, retryAfterMs: null }, id })
        return
      }
      const verdict = auth.handover(connection, message)
      if (verdict.ok !== true) {
        log('reject handover peer=' + connection.peer + ': ' + String(verdict.code))
        // Free the single-client slot right away: the next (legitimate) retry
        // must not bounce on EBUSY just because this socket is still closing.
        auth.detachConnection(connection)
        sendLineAndClose(socket, { ok: false, error: { code: verdict.code, message: verdict.message, retryAfterMs: verdict.retryAfterMs ?? null }, id })
        return
      }
      service.touchActivity()
      sendLine(socket, { ...service.snapshot({ freeze: false }), op: 'handover', id })
      return
    }

    const verdict = auth.authorize(connection, message)
    if (verdict.ok !== true) {
      log('reject request op=' + op + ' peer=' + connection.peer + ': ' + String(verdict.code))
      auth.detachConnection(connection)
      sendLineAndClose(socket, { ok: false, error: { code: verdict.code, message: verdict.message }, id })
      return
    }

    /** @type {any} */
    let response
    try {
      response = await service.handle(op, message)
    } catch (error) {
      response = { ok: false, error: { code: 'EINTERNAL', message: messageOf(error) } }
    }
    sendLine(socket, { ...response, id })
  }

  /** @param {any} socket */
  return function onConnection(socket) {
    /** @type {PodConnection} */
    const connection = {
      socket,
      peer: typeof socket.remoteAddress === 'string' && socket.remoteAddress !== '' ? socket.remoteAddress : 'local-pipe',
      connectedAt: nowIso(),
      authenticated: false,
      tokenFingerprint: null,
    }
    // Attach BEFORE admission: a refused socket must never emit an unhandled
    // 'error' (that would crash the pod instead of refusing the client).
    socket.on('error', () => {})
    const attested = attestConnection(socket, connection)
    const attestPolicy = currentPolicy()
    if (!attested.allowed && attested.deferred !== true && attestPolicy?.mode === 'enforce') {
      // A peer we *did* attest and the policy rejected is closed before it can
      // ask for anything. A peer this transport cannot attest (deferred) is not
      // closed here: it still has to survive the handover nonce gate below, and
      // closing it would make enforce unusable on Node's pipes (see the long
      // comment in attestConnection()).
      sendLineAndClose(socket, {
        ok: false,
        error: {
          code: 'ECLIENTDENIED',
          message: '客户端未通过 OS 级身份校验：' + (attested.record?.checks ?? [])
            .filter((check) => !check.ok)
            .map((check) => check.name + '=' + check.detail)
            .join('; '),
        },
      })
      return
    }
    const admitted = auth.admitConnection(connection)
    if (admitted.ok !== true) {
      // Single-client: keep the first connection untouched, tell the second one
      // why, and close it. See refuseBusy(): the refusal must carry the rejected
      // request's id, otherwise the client sees a bare close (ECLOSED) and the
      // pod looks crashed instead of busy.
      refuseBusy(socket, admitted.message)
      return
    }
    service.bumpGeneration()
    clients.add(socket)
    try {
      onClientChange(true)
    } catch (error) {
      log('onClientChange(connect) failed: ' + messageOf(error))
    }
    socket.setEncoding('utf8')
    /** @type {string} */
    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk
      if (buffer.length > MAX_PROTOCOL_LINE_BYTES && buffer.indexOf('\n') < 0) {
        auth.detachConnection(connection)
        sendLineAndClose(socket, { ok: false, error: { code: 'ETOOLONG', message: 'request line too long' } })
        return
      }
      let newline = buffer.indexOf('\n')
      while (newline >= 0) {
        const line = buffer.slice(0, newline)
        buffer = buffer.slice(newline + 1)
        void dispatch(line, socket, connection)
        newline = buffer.indexOf('\n')
      }
    })
    socket.on('error', () => {
      // EPIPE / ECONNRESET from a dead Host: expected, never fatal.
    })
    socket.on('close', () => {
      clients.delete(socket)
      auth.detachConnection(connection)
      service.touchActivity()
      try {
        onClientChange(false)
      } catch (error) {
        log('onClientChange(close) failed: ' + messageOf(error))
      }
    })
  }
}

/**
 * @param {ReturnType<typeof createPodService>} service
 * @param {string} workspaceRoot
 * @param {string} dataRoot
 * @param {string} pipeName
 * @param {ReturnType<typeof createPodAuth>} auth
 * @param {(message: string) => void} [log]
 * @param {{ attestor?: any, attestPolicy?: any, identityChannel?: any, onAttestation?: (record: any) => void }} [extras]
 */
function serve(service, workspaceRoot, dataRoot, pipeName, auth, log = () => {}, extras = {}) {
  const clients = new Set()
  /**
   * Lifecycle. The pod is a helper, not a daemon: it never has anything to do
   * without a client, a running job or a freeze episode, so it leaves instead
   * of idling for 12 hours. `--idle-ms` (DEFAULT_IDLE_EXIT_MS) is still parsed
   * and reported, but it is no longer a gate — see `maybeExitNoClientNoJobs`.
   */
  const STARTUP_GRACE_MS = 30_000
  const NO_CLIENT_TICK_MS = 15_000
  const startedAtWall = Date.now()
  let sawClient = false
  let exiting = false
  const onConnection = createConnectionHandler(service, auth, {
    clients,
    log,
    attestor: extras.attestor ?? null,
    attestPolicy: extras.attestPolicy ?? null,
    identityChannel: extras.identityChannel ?? null,
    onAttestation: extras.onAttestation,
    // Admission/close is a lifecycle checkpoint too. The authoritative "no
    // clients" test stays `clients.size`; this only makes the pod react at the
    // exact moment instead of on the next tick.
    onClientChange: (connected) => {
      if (connected) {
        sawClient = true
        return
      }
      maybeExitNoClientNoJobs('last client socket closed')
    },
  })
  const server = net.createServer(onConnection)

  /**
   * Leave deliberately (freeze-mode self-destruct). The kills already happened
   * inside the policy (`killAllJobs` resolves only after every exit.json is
   * written), so this only closes the process-owned handles and exits.
   * @param {number} code
   */
  function exitPod(code) {
    exiting = true
    freezePolicy.dispose()
    clearInterval(idleTimer)
    try {
      server.close()
    } catch {
      // already closed
    }
    for (const socket of clients) {
      try {
        socket.destroy()
      } catch {
        // already gone
      }
    }
    clients.clear()
    closePodLog()
    process.exit(code)
  }

  /**
   * Freeze mode exists across the socket layer and the service: the policy owns
   * the clock/settings/regeneration accounting, the service owns the jobs. All
   * of `dataRoot`'s pod log lines below come through the same `log`, so every
   * freeze/thaw/regeneration/self-destruct step is timestamped in pod.log.
   */
  const freezePolicy = createFreezePolicy({
    readSettings: () => readPodSettings(dataRoot),
    listRunningJobs: () => service.jobsForFreezePolicy(),
    freezeJob: (jobId, options) => service.autoFreezeJob(jobId, options),
    thawJob: (jobId, reason) => service.autoThawJob(jobId, reason),
    killAll: (reason) => service.killAllJobs(reason),
    hasClients: () => clients.size > 0,
    log,
    exit: (code) => exitPod(code),
    // An episode that ends (or a grace timer that stands down) is a lifecycle
    // checkpoint: if no client and no job is left, there is nothing to protect.
    onIdle: (reason) => maybeExitNoClientNoJobs('freeze episode ended: ' + reason),
    now: () => Date.now(),
    setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimeout: (timer) => clearTimeout(timer),
  })

  /**
   * The one exit rule: **no client + no running job + no freeze episode**.
   *
   * Called from every transition that can reach that state — the last
   * authenticated client disconnecting, every job settlement, the end of a
   * freeze episode — plus the safety-net tick below. A pod that has never seen
   * a client gets STARTUP_GRACE_MS first, because the Host spawns it and then
   * connects; exiting before that first connection would just make the Host
   * spawn another one.
   *
   * Deliberately NOT called while the freeze policy is destroying: the
   * self-destruct owns the exit in that phase.
   * @param {string} reason
   * @returns {boolean} whether a shutdown was started
   */
  function maybeExitNoClientNoJobs(reason) {
    if (exiting) return false
    if (freezePolicy.phase() === 'destroying') return false
    // A pending grace timer or a live freeze episode must not be cut short: the
    // whole point of staying alive is the regeneration/self-destruct watchdog.
    if (freezePolicy.active()) return false
    if (clients.size > 0) return false
    if (service.runningJobCount() > 0) return false
    if (!sawClient) {
      // A `--bootstrap-handover` pod has no owner yet and owns its own claim
      // window (BOOTSTRAP_CLAIM_TIMEOUT_MS): that timer, not this rule, decides
      // when an unclaimed pod leaves.
      const bootstrap = typeof auth.isBootstrap === 'function' && auth.isBootstrap() === true
      if (bootstrap) return false
      if (Date.now() - startedAtWall < STARTUP_GRACE_MS) return false
    }
    exiting = true
    log(
      'lifecycle: ' + reason + '：无客户端、无运行中 job、无冻结 episode → 退出 pod（jobs=0 clients=0）',
    )
    void service.shutdown('no client and no jobs')
    return true
  }

  // Only AUTHENTICATED transitions reach the policy (see createPodAuth): a raw
  // admitted socket must neither cancel a freeze nor start a grace timer.
  if (typeof auth.setClientStateHandler === 'function') {
    auth.setClientStateHandler((state) => {
      if (state.connected) {
        sawClient = true
        freezePolicy.clientConnected()
      } else {
        freezePolicy.clientDisconnected()
        maybeExitNoClientNoJobs('last authenticated client disconnected')
      }
    })
  }
  // One startup line makes the settings file and its live values visible even
  // before the first disconnect; every decision re-reads the file regardless.
  {
    const startup = readPodSettings(dataRoot)
    log(
      'freeze-mode: freezeMode=' + String(startup.freezeMode) +
      ' freezeMinutes=' + String(startup.freezeMinutes) + ' regenerations=' + String(startup.regenerations) +
      '（settings.json 在每次断开/宽限到点/看门狗到点时重读）',
    )
  }

  server.on('error', (error) => {
    // The pipe name is the single-instance lock: losing the race is success,
    // the winner is already serving this exact name. Both outcomes are recorded
    // in pod.log, because a detached pod's stderr is discarded.
    if (codeOf(error) === 'EADDRINUSE') {
      log('listen: 管道名已被另一个 pod 占用（单例锁），本次启动直接退出 0')
      process.exit(0)
    }
    log('listen failed: ' + messageOf(error))
    process.stderr.write('escape-pod-core: listen failed: ' + messageOf(error) + '\n')
    process.exit(1)
  })
  server.on('listening', () => {
    log('listen: pipe=' + pipeName + '（单例锁生效：同一身份同一时刻只有一个 pod 能 listen）')
  })

  server.listen(pipeName)

  // Safety net only: every explicit transition already checked. This tick
  // catches a Host that never managed to connect (spawned, then the Host died
  // before its first handshake), which no event would ever report.
  const idleTimer = setInterval(() => {
    maybeExitNoClientNoJobs('no-client check')
  }, NO_CLIENT_TICK_MS)
  idleTimer.unref()

  service.setShutdownHandler((reason) => {
    exiting = true
    // Stop the policy first: a shutdown must not race a watchdog that would
    // kill jobs and exit on its own after the process is already leaving.
    freezePolicy.dispose()
    clearInterval(idleTimer)
    try {
      server.close()
    } catch {
      // already closed
    }
    for (const socket of clients) {
      try {
        socket.destroy()
      } catch {
        // already gone
      }
    }
    clients.clear()
    process.stderr.write('escape-pod-core: shutdown (' + reason + ')\n')
    setTimeout(() => process.exit(0), 50).unref?.()
  })

  // A finished job is a lifecycle checkpoint: with no client connected and no
  // other job running, the only thing this pod was keeping alive is over.
  service.setSettlementHandler((record) => {
    maybeExitNoClientNoJobs('job settled: ' + String(record?.jobId ?? '?'))
  })

  // A detached pod must not die with the console that happened to spawn it.
  process.on('SIGHUP', () => {})
  process.on('SIGBREAK', () => {})
  process.on('SIGTERM', () => {
    void service.shutdown('SIGTERM')
  })
  process.on('SIGINT', () => {
    void service.shutdown('SIGINT')
  })
  // The pod must outlive the Host. A stray rejection inside a socket handler is
  // logged, never allowed to take the whole ledger down with it.
  process.on('unhandledRejection', (reason) => {
    process.stderr.write('escape-pod-core: unhandled rejection: ' + messageOf(reason) + '\n')
  })
  process.on('uncaughtException', (error) => {
    process.stderr.write('escape-pod-core: uncaught exception: ' + messageOf(error) + '\n')
  })

  return { server, clients, workspaceRoot, dataRoot }
}

/**
 * @param {string[]} argv
 */
export function parseArgs(argv) {
  /** @type {{ mode: string, pipe: string | undefined, workspace: string | undefined, dataRoot: string | undefined, idleExitMs: number, ringBytes: number, outputChunkBytes: number, templateJson: string | undefined, templateB64: string | undefined, auth: 'token' | 'open', tokenTimeoutMs: number, allowHandover: boolean, handoverGraceMs: number, bootstrapHandover: boolean }} */
  const options = {
    mode: 'serve',
    pipe: undefined,
    workspace: undefined,
    dataRoot: undefined,
    idleExitMs: DEFAULT_IDLE_EXIT_MS,
    ringBytes: DEFAULT_RING_BYTES,
    outputChunkBytes: FALLBACK_OUTPUT_CHUNK_BYTES,
    templateJson: undefined,
    templateB64: undefined,
    auth: 'token',
    tokenTimeoutMs: TOKEN_STDIN_TIMEOUT_MS,
    allowHandover: true,
    handoverGraceMs: HANDOVER_GRACE_MS,
    bootstrapHandover: false,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--serve') options.mode = 'serve'
    else if (arg === '--help' || arg === '-h') options.mode = 'help'
    else if (arg === '--pipe') {
      options.pipe = argv[index + 1]
      index += 1
    } else if (arg === '--workspace') {
      options.workspace = argv[index + 1]
      index += 1
    } else if (arg === '--data-root') {
      options.dataRoot = argv[index + 1]
      index += 1
    } else if (arg === '--idle-ms') {
      options.idleExitMs = clampInt(Number(argv[index + 1]), DEFAULT_IDLE_EXIT_MS, 1000, 7 * 24 * 60 * 60 * 1000)
      index += 1
    } else if (arg === '--ring-bytes') {
      options.ringBytes = clampInt(Number(argv[index + 1]), DEFAULT_RING_BYTES, 4096, 16 * 1024 * 1024)
      index += 1
    } else if (arg === '--output-chunk-bytes') {
      options.outputChunkBytes = clampInt(Number(argv[index + 1]), FALLBACK_OUTPUT_CHUNK_BYTES, 1024, MAX_OUTPUT_CHUNK_BYTES)
      index += 1
    } else if (arg === '--template-json') {
      options.templateJson = argv[index + 1]
      index += 1
    } else if (arg === '--template-b64') {
      // Base64url survives `cmd.exe` unchanged: no quotes, no spaces and no
      // metacharacters (&|<>^%). The Host uses this on the schtasks path.
      options.templateB64 = argv[index + 1]
      index += 1
    } else if (arg === '--bootstrap-handover') {
      // No stdin token: the first Host must claim the pod through an
      // identity-channel nonce. The token gate still applies to every op.
      options.bootstrapHandover = true
    } else if (arg === '--auth') {
      // `open` exists only for maintenance/self-test; the Host never uses it.
      options.auth = argv[index + 1] === 'open' ? 'open' : 'token'
      index += 1
    } else if (arg === '--token-timeout-ms') {
      options.tokenTimeoutMs = clampInt(Number(argv[index + 1]), TOKEN_STDIN_TIMEOUT_MS, 100, 60000)
      index += 1
    } else if (arg === '--no-handover') {
      options.allowHandover = false
    } else if (arg === '--handover-grace-ms') {
      options.handoverGraceMs = clampInt(Number(argv[index + 1]), HANDOVER_GRACE_MS, 0, 3600000)
      index += 1
    }
  }
  return options
}

function printHelp() {
  process.stdout.write(
    [
      'DSH escape pod core (detached token factory)',
      '',
      '  node pod.mjs --serve --pipe <name> --workspace <dir> --data-root <dir>',
      '               [--idle-ms <ms>] [--ring-bytes <n>] [--output-chunk-bytes <n>]',
      '               [--template-json <json>] [--template-b64 <base64url>] [--auth token|open]',
      '               [--token-timeout-ms <ms>] [--no-handover] [--handover-grace-ms <ms>]',
      '               [--bootstrap-handover]',
      '',
      '  The spawn token is read from the FIRST LINE of stdin (64 hex chars) and',
      '  kept in memory only; stdin may close right after it. Every request must',
      '  carry that token. Without a token the pod exits 4 instead of listening.',
      '',
      '  --bootstrap-handover starts without a stdin token instead: until one Host',
      '  completes a handover carrying a redeemed identity nonce, every op except',
      '  identify/handover is refused. It exits 0 if nobody claims it in 120s.',
      '',
      '  Single client: while one Host connection is open, a second connection is',
      '  refused (EBUSY) and closed. The refusal is sent after the second client\'s',
      '  first request line so it can carry that request id; a bare early close',
      '  would surface as ECLOSED on the client. When the client leaves, the pod',
      '  stays up and accepts the next one; a Host that cannot present the',
      '  (memory-only) old token uses the `handover` op to rebind a fresh one.',
      '',
      '  The prefix is delivered per call (it carries a revocable session temp SID)',
      '  and is validated against the pinned shape template this process was started',
      '  with, including that its --mode equals the mode the request resolved. The',
      '  pod never constructs a prefix; a missing/invalid template makes every',
      '  escorted run fail closed (danger-full-access runs carry no prefix and need',
      '  none). Normally spawned by the Host plugin, not by hand.',
      '',
    ].join('\n'),
  )
}

/** @param {string} message @param {number} exitCode */
function fatal(message, exitCode) {
  process.stderr.write('escape-pod-core: ' + message + '\n')
  if (activePodLog !== null) {
    try {
      fs.writeSync(activePodLog, new Date().toISOString() + ' FATAL ' + message + '\n')
    } catch {
      // logging is best-effort
    }
  }
  process.exitCode = exitCode
}

/**
 * Open the pod's own log file.
 *
 * The Host spawns the pod with `stdio: ['pipe','ignore','ignore']` — a detached
 * pod must not hold a DSH pipe — so stderr goes nowhere. That is fine for a pod
 * that runs, and useless for one that does not: a startup failure would leave no
 * trace at all. This file is the trace, and it lives in the data root next to the
 * ledger (never in the workspace, which managed commands can write).
 *
 * @param {string} dataRoot
 * @returns {{ path: string | null, write: (message: string) => void }}
 */
function openPodLog(dataRoot) {
  /** @type {number | null} */
  let fd = null
  /** @type {string | null} */
  let path = null
  try {
    fs.mkdirSync(dataRoot, { recursive: true })
    path = join(dataRoot, 'pod.log')
    const existing = fs.statSync(path, { throwIfNoEntry: false })
    const append = existing !== undefined && existing.size < 2 * 1024 * 1024
    fd = fs.openSync(path, append ? 'a' : 'w')
  } catch {
    fd = null
  }
  activePodLog = fd
  return {
    path,
    write(message) {
      if (fd === null) return
      try {
        fs.writeSync(fd, new Date().toISOString() + ' ' + message + '\n')
      } catch {
        // logging is best-effort
      }
    },
  }
}

/**
 * Close the process-wide pod log before an intentional `process.exit` (freeze
 * mode self-destruct). Every line is written with `writeSync`, so nothing is
 * buffered; closing is only about leaving a tidy descriptor behind.
 */
function closePodLog() {
  if (activePodLog === null) return
  try {
    fs.closeSync(activePodLog)
  } catch {
    // already closed
  }
  activePodLog = null
}

/**
 * Exit when this pod's own source changes, so the next tool call respawns it
 * with the new code.
 *
 * OFF BY DEFAULT (opt in with `PODC_WATCH=1`). Auto-exit on a source edit is a
 * foot-gun: a save lands mid-edit, the pod goes away, and the Host's
 * reconnect/regenerate path has to win a race it previously lost three times in
 * a row (`ESPAWNEXHAUSTED`), which hangs the whole escape hatch. A pod that
 * keeps running old code until it is restarted deliberately is the safer
 * default; the log line below says so.
 *
 * The guard is absolute: never exit while a managed job is running.
 *
 * @param {ReturnType<typeof createPodService>} service
 * @param {(message: string) => void} log
 */
function watchSources(service, log) {
  if (process.env.PODC_WATCH !== '1') {
    log('watch: 源码监视默认关闭（PODC_WATCH=1 才启用）；改动 pod/插件源码不会让本 pod 退出，需要时请显式重启 pod')
    return
  }
  const directory = import.meta.dirname
  if (typeof directory !== 'string' || directory === '') return
  /** @type {string[]} */
  let names = []
  try {
    names = fs.readdirSync(directory).filter((name) => name.endsWith('.mjs') || name.endsWith('.js'))
  } catch {
    return
  }
  if (names.length === 0) return
  /** @type {NodeJS.Timeout | null} */
  let pending = null
  for (const name of names) {
    fs.watchFile(join(directory, name), { interval: 1000 }, (current, previous) => {
      if (current.mtimeMs === previous.mtimeMs) return
      if (pending !== null) clearTimeout(pending)
      pending = setTimeout(() => {
        pending = null
        if (service.runningJobCount() > 0) {
          log('watch: ' + name + ' 已变化，但仍有 running job，暂不退出')
          return
        }
        log('watch: ' + name + ' 已变化 → pod 退出，下一次工具调用会带新代码重启')
        void service.shutdown('source changed: ' + name)
      }, 1200)
      pending.unref?.()
    })
  }
  log('watch: 监视 ' + String(names.length) + ' 个源文件（PODC_WATCH=1；源码变化时若无 running job 会让 pod 退出）')
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  if (options.mode === 'help') {
    printHelp()
    return
  }
  const workspaceRoot = optionalString(options.workspace)
  const dataRootOption = optionalString(options.dataRoot)
  // Standalone default keeps the ledger outside the workspace too; the Host
  // always passes --data-root explicitly.
  const dataRoot = dataRootOption ?? resolveStateDir(undefined)
  // The Host spawns the pod with stderr ignored, so without a file of its own a
  // pod that fails to start leaves *no* evidence anywhere. This log is written
  // before anything else can fail, and every line also goes to stderr.
  const fileLog = openPodLog(dataRoot)
  const log = (message) => {
    process.stderr.write('escape-pod-core: ' + message + '\n')
    fileLog.write(message)
  }
  log('start pid=' + String(process.pid) + ' version=' + POD_VERSION + ' argv=' + process.argv.slice(2).join(' '))
  // An uncaught throw in a detached, stderr-less process is invisible by
  // default; record it and leave a distinct exit code (5) so the Host's
  // "pod exited" line is diagnosable.
  process.on('uncaughtException', (error) => {
    log('uncaught exception: ' + String(error?.stack ?? messageOf(error)))
    process.exit(5)
  })
  process.on('unhandledRejection', (reason) => {
    log('unhandled rejection: ' + String(reason instanceof Error ? reason.stack : reason))
    process.exit(5)
  })
  if (workspaceRoot === undefined) {
    fatal('缺少 --workspace', 3)
    return
  }
  let template = null
  if (optionalString(options.templateB64) !== undefined) {
    // Base64url first: it is the only form that survives a `cmd.exe` launch
    // verbatim (no quotes/spaces/metacharacters to re-tokenize).
    try {
      const decoded = Buffer.from(String(options.templateB64), 'base64url').toString('utf8')
      template = JSON.parse(decoded)
      if (template === null || typeof template !== 'object') throw new Error('not an object')
    } catch (error) {
      fatal('--template-b64 不是合法的 base64url 对象：' + messageOf(error), 3)
      return
    }
  } else if (optionalString(options.templateJson) !== undefined) {
    try {
      template = JSON.parse(String(options.templateJson))
      if (template === null || typeof template !== 'object') throw new Error('not an object')
    } catch (error) {
      fatal('--template-json 不是合法的对象：' + messageOf(error), 3)
      return
    }
  }
  const pipeName = resolvePipeName(options.pipe)

  // The pipe name is now a hash of a STABLE identity, not of DSH_HOME. Logging
  // the seed hash is what makes "which identity computed this pipe" answerable
  // when an old pod looks orphaned after an upgrade.
  const identity = describePipeIdentity()
  log(
    'identity seedKind=' + identity.seedKind + ' v' + String(identity.seedVersion) +
    ' user=' + identity.user + ' host=' + identity.host + ' seedHash=' + identity.seedHash,
  )
  const derivedPipeName = resolvePipeName()
  log('pipe=' + pipeName + (pipeName === derivedPipeName ? ' (derived from identity seed)' : ' (EXPLICIT; this identity seed derives ' + derivedPipeName + ')'))

  /** @type {string | null} */
  let token = null
  if (options.auth === 'open') {
    log('WARNING: --auth open —— 管道不校验 token，同用户任何进程都能驱动这个 pod（只用于维护/自测）')
  } else if (options.bootstrapHandover) {
    // No stdin token exists on the schtasks path. The pod listens, but only
    // identify + a nonce-attested handover can establish the first token; every
    // other op is refused as unauthenticated until then.
    neutralizePodStdin()
    log(
      'auth=bootstrap（无 stdin token；只接受 identify + 带 identity nonce 的 handover；' +
      String(BOOTSTRAP_CLAIM_TIMEOUT_MS) + 'ms 内无人认领则退出）',
    )
  } else {
    token = await readTokenFromStdin(process.stdin, { timeoutMs: options.tokenTimeoutMs })
    // Close/EOF/EPIPE on stdin is normal from here on: the Host closes the write
    // end after the token, and the OS closes it if the Host dies. The pod's job
    // is to outlive that, so nothing below may treat it as a shutdown signal.
    neutralizePodStdin()
    if (token === null) {
      fatal(
        '没有从 stdin 读到 spawn 期 token（第一行应为 64 个十六进制字符）；拒绝启动，避免出现无鉴权管道。' +
        '正常由 Host 启动并写入 token；手工维护请显式加 --auth open。',
        4,
      )
      return
    }
    log('auth=token tokenFp=' + String(tokenFingerprint(token)) + ' handover=' + String(options.allowHandover) + ' graceMs=' + String(options.handoverGraceMs))
  }

  const auth = createPodAuth({
    mode: options.auth,
    token,
    bootstrapHandover: options.bootstrapHandover,
    allowHandover: options.allowHandover,
    handoverGraceMs: options.handoverGraceMs,
    log,
  })

  // --- client attestation ---------------------------------------------------
  // The pod's own facts are the baseline: the client must be the same user, in
  // the same session, at least as privileged as the pod, and the same image the
  // Host spawned us with. A koffi problem must not be fatal — the pod is the
  // only thing that survived the restart — so `off`/unavailable degrades to a
  // logged warning and the token check still applies.
  //
  // `PODC_ATTEST=off` is the only hard switch, and it must come from the
  // environment the Host chose: a policy file must not be able to turn
  // attestation *on* by itself. Everything else is an env pin when one exists,
  // otherwise `<dataRoot>/attest-policy.json`, which is re-read (mtime-keyed)
  // on every identity request so warn→enforce needs no restart.
  const envAttestRaw = typeof process.env.PODC_ATTEST === 'string' ? process.env.PODC_ATTEST : ''
  const attestDisabledByEnv = envAttestRaw.trim() !== '' && normalizeAttestMode(envAttestRaw) === 'off'
  const attestor = attestDisabledByEnv ? null : createAttestor({ log })
  /** @type {any} */
  const attestationState = {
    mode: attestDisabledByEnv ? 'off' : 'warn',
    available: false,
    unavailableReason: null,
    policy: null,
    last: null,
    denied: 0,
    lastDeniedAt: null,
    deferred: 0,
    lastDeferredAt: null,
    lastAcceptedAt: null,
    probePath: join(dataRoot, 'attest-probe.json'),
  }
  const attestorUnavailable = attestDisabledByEnv ? 'PODC_ATTEST=off' : attestor.warmUp()
  const selfFacts = !attestDisabledByEnv && attestorUnavailable === null ? attestor.describePid(process.pid) : null
  attestationState.available = !attestDisabledByEnv && attestorUnavailable === null && selfFacts !== null && typeof selfFacts.userSid === 'string'
  attestationState.unavailableReason = attestDisabledByEnv ? null : attestorUnavailable
  /** @type {any} */
  const attestPolicySource = attestDisabledByEnv
    ? null
    : createAttestPolicySource({ dataRoot, selfFacts, env: process.env, log })
  const initialPolicy = attestPolicySource === null ? null : attestPolicySource.current()
  attestationState.mode = initialPolicy === null ? 'off' : initialPolicy.mode
  attestationState.policy = initialPolicy
  if (attestDisabledByEnv) {
    log('attest mode=off（PODC_ATTEST=off）：不做 OS 级身份校验，只保留 token')
  } else {
    const policyPath = String(attestPolicySource?.path?.() ?? '')
    log(
      'attest mode=' + String(initialPolicy?.mode) + ' available=' + String(attestationState.available) +
      ' userSid=' + String(selfFacts?.userSid) + ' session=' + String(selfFacts?.sessionId) +
      ' integrity=' + String(selfFacts?.integrity) + ' restricted=' + String(selfFacts?.restrictedSidCount) +
      ' images=' + String(initialPolicy?.allowedImages?.join('|')) +
      ' policyFile=' + policyPath,
    )
    log('attest-policy: 环境变量逐项优先，其余取自 ' + (policyPath === '' ? '(未配置文件)' : policyPath) +
      '（每次身份请求按 mtime 重读；损坏/非法时沿用上一份有效策略，绝不降级为 off）')
    if (attestationState.available !== true) {
      log('attest 降级：无法读取 Win32 身份（' + String(attestorUnavailable) + '），只保留 token 校验')
    }
  }

  // The identity channel is a second, loopback-only listener whose only job is
  // to name the process on the other end. It is created before `serve()` so the
  // very first `identify` request can already advertise a port. It stays up even
  // while the file says `off`, so promoting the file to `enforce` later needs no
  // pod restart.
  /** @type {any} */
  let identityChannel = null
  if (attestPolicySource !== null && attestationState.available === true) {
    identityChannel = createIdentityChannel({ attestor, policy: attestPolicySource, log })
    try {
      await identityChannel.start()
    } catch (error) {
      log('identity channel 启动失败：' + messageOf(error) + '（只保留 token 校验）')
      identityChannel = null
    }
  }

  if (options.bootstrapHandover) {
    // Bootstrap has no token: the identity nonce is the ONLY credential. If
    // attestation is unavailable or merely in warn/off, a nonce would not prove
    // client integrity, so this launch mode must fail closed instead of
    // accepting whoever races the Host.
    const policyNow = attestPolicySource === null ? null : attestPolicySource.current()
    if (identityChannel === null || attestationState.available !== true) {
      fatal('--bootstrap-handover 需要可用的 identity 通道（attest 不可用）：拒绝启动无 nonce 可验的 bootstrap pod', 3)
      return
    }
    if (policyNow === null || policyNow.mode !== 'enforce') {
      fatal(
        '--bootstrap-handover 需要 attest-policy 为 enforce（当前 ' + String(policyNow?.mode ?? 'off') +
        '）：warn/off 下 nonce 无法证明客户端完整性，拒绝以 bootstrap 启动',
        3,
      )
      return
    }
  }

  const service = createPodService({
    workspaceRoot,
    dataRoot,
    pipeName,
    idleExitMs: options.idleExitMs,
    ringBytes: options.ringBytes,
    outputChunkBytes: options.outputChunkBytes,
    template,
    authSnapshot: () => auth.snapshot(),
    attestationSnapshot: () => {
      // Re-read here too: `pod_status` should show the mode currently in
      // force, not the one that happened to be in force at pod start.
      const active = attestPolicySource === null ? null : attestPolicySource.current()
      if (active !== null) {
        attestationState.mode = active.mode
        attestationState.policy = active
      }
      return { ...attestationState, channel: identityChannel === null ? null : identityChannel.snapshot() }
    },
    identity,
    log,
  })
  try {
    service.init()
  } catch (error) {
    fatal(messageOf(error), 3)
    return
  }
  serve(service, workspaceRoot, dataRoot, pipeName, auth, log, {
    attestor: attestPolicySource === null ? null : attestor,
    attestPolicy: attestPolicySource,
    identityChannel,
    onAttestation: (record) => {
      attestationState.last = record
      recordAttestationOutcome(attestationState, record)
      // A file, because the pod is spawned with stderr ignored: without this the
      // only record of a refused client would be a stream nobody can read.
      try {
        const active = attestPolicySource === null ? null : attestPolicySource.current()
        writeJsonAtomic(attestationState.probePath, {
          schema: 1,
          note: '最后一次管道连接的 OS 级客户端身份。last.deferred=true 表示该传输拿不到管道句柄，身份改由 handover 的 nonce 通道强制；' +
            'deferred 计数只统计这种"拿不到句柄、无法判定"的连接，denied 只统计真正被策略拒绝的连接。诊断用，不含任何秘密。',
          policy: {
            mode: active === null ? 'off' : active.mode,
            available: attestationState.available,
            unavailableReason: attestationState.unavailableReason,
            expected: active === null ? null : {
              userSid: active.userSid,
              sessionId: active.sessionId,
              minIntegrityRid: active.minIntegrityRid,
              allowRestricted: active.allowRestricted,
              allowedImages: active.allowedImages,
            },
            source: attestPolicySource === null ? null : attestPolicySource.describe(),
          },
          self: selfFacts === null ? null : { pid: process.pid, imagePath: selfFacts.imagePath, integrity: selfFacts.integrity, restrictedSidCount: selfFacts.restrictedSidCount },
          channel: identityChannel === null ? null : identityChannel.snapshot(),
          last: record,
          denied: attestationState.denied,
          deferred: attestationState.deferred,
        })
      } catch (error) {
        log('attest probe write failed: ' + messageOf(error))
      }
    },
  })

  if (options.bootstrapHandover) {
    // No owner yet: if no Host redeems an identity nonce within the window,
    // exit 0 instead of lingering as an unclaimable process on the pipe.
    const bootstrapTimer = setTimeout(() => {
      if (!auth.isBootstrap()) return
      log(
        'bootstrap ' + String(BOOTSTRAP_CLAIM_TIMEOUT_MS) +
        'ms 内没有任何 Host 完成 identity handover：pod 自行退出（exit 0），避免留下无主孤儿',
      )
      void service.shutdown('bootstrap-handover-timeout')
    }, BOOTSTRAP_CLAIM_TIMEOUT_MS)
    bootstrapTimer.unref?.()
  }
  watchSources(service, log)
}

/** @returns {boolean} */
function isEntryPoint() {
  const entry = process.argv[1]
  if (entry === undefined) return false
  try {
    return resolve(entry).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase()
  } catch {
    return false
  }
}

if (isEntryPoint()) await main()

export { READY_STATUSES, writeJsonAtomic, readJsonOrNull }
