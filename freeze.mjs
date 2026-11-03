/**
 * Freeze / thaw primitives for the escape pod.
 *
 * WHY A JOB OBJECT: `SetInformationJobObject(JobObjectFreezeInformation)` stops
 * every thread of every process in a job — including processes in nested jobs —
 * in ONE kernel call, and the same call with `Freeze=0` resumes them. That is
 * the only primitive that covers a runner's whole tree atomically. The
 * per-process fallback (`NtSuspendProcess`) is kept for one purpose only: the
 * runner may spawn its restricted child BEFORE the pod finished
 * `AssignProcessToJobObject(runner)`, and such a child is outside the job. It is
 * never the primary path: it is not atomic, it needs `PROCESS_SUSPEND_RESUME` per
 * pid, and a failure halfway leaves a half-suspended tree we cannot roll back.
 *
 * The pod owns its job handle; the runner's own inner job (created by
 * windows-acl, with KILL_ON_JOB_CLOSE) is untouched and stays nested inside.
 * This module NEVER sets KILL_ON_JOB_CLOSE on the pod's job: the escape pod's
 * contract is "a command keeps running when the pod dies", and a kill-on-close
 * job would silently change that.
 *
 * Verified on this machine (Windows 10.0.19045, node 24, koffi 3.1.1):
 *   - an EMPTY job accepts `{Flags:1, Freeze:1}` and `{Flags:1, Freeze:0}`;
 *   - an all-zero buffer is rejected with Win32 87 — every call must carry
 *     `Flags=1`, so freeze and thaw are always a pair;
 *   - `QueryInformationJobObject(job, 18, …)` reports `Flags=0x7, Freeze=0|1`.
 *
 * The handle is an opaque koffi pointer value (a BigInt on x64). It is process
 * private and meaningless across processes/restarts, so it is NEVER written to
 * the ledger: `meta.json.freeze` carries identity and timing only (see
 * {@link freezeLedgerFields}), and `pod_status` derives `thawable` from "do I
 * still hold a live handle in this very process".
 *
 * @see pod/research/逃生舱-冻结方案.md (design, decisions in §7)
 */

import { resolveKoffi } from './attest.mjs'

/** `JobObjectFreezeInformation` in the `JOBOBJECTINFOCLASS` enum (Win8+). */
export const FREEZE_INFORMATION_CLASS = 18
/**
 * Default freeze watchdog. Windows has NO kernel-level freeze timeout, so the
 * pod must thaw on its own before a forgotten freeze becomes a permanent hang.
 * 30 minutes matches the design decision (§7 ①).
 */
export const FREEZE_DEFAULT_MAX_MS = 30 * 60 * 1000
/**
 * `setTimeout` stores its delay in a signed 32-bit int; a larger value fires
 * almost immediately. Same cap as the job deadline in pod.mjs.
 */
export const FREEZE_MAX_MS = 2_147_483_647

/** The only two actions the protocol/`pod_freeze` accept. */
export const FREEZE_ACTIONS = Object.freeze(['freeze', 'thaw'])
/** The machine-facing error codes this module (and pod.mjs's op) can return. */
export const FREEZE_ERROR_CODES = Object.freeze([
  'EBADJOBID',
  'ENOJOB',
  'EFOREIGNJOB',
  'ENOTHANDLE',
  'ENOTRUNNING',
  'EFREEZEUNSUPPORTED',
  'EOSFAIL',
])

const PROCESS_SUSPEND_RESUME = 0x0800
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
const PROCESS_SET_QUOTA = 0x0100
const PROCESS_TERMINATE = 0x0001
const TH32CS_SNAPPROCESS = 0x00000002
/** Defensive bound for the Toolhelp walk: no tree here is that big. */
const MAX_DESCENDANTS = 4096

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

function nowIso() {
  return new Date().toISOString()
}

// ---------------------------------------------------------------------------
// Ledger record / status projection (pure, no Win32)
// ---------------------------------------------------------------------------

/**
 * The EXACT six fields written to `meta.json.freeze`. Deliberately a whitelist:
 * `handle`, `jobHandle`, `suspendedProcs` and every other process-private value
 * must never reach the ledger — a handle written down would only lie to the
 * next pod. Exported so the static self-test can assert the key set.
 *
 * @param {{ state?: unknown, since?: unknown, by?: unknown, podPid?: unknown, podGeneration?: unknown, count?: unknown }} [fields]
 */
export function freezeLedgerFields(fields = {}) {
  const state = fields.state === 'frozen' ? 'frozen' : 'none'
  return {
    state,
    since: state === 'frozen' && typeof fields.since === 'string' && fields.since !== '' ? fields.since : null,
    by: typeof fields.by === 'string' && fields.by !== '' ? fields.by : null,
    podPid: Number.isInteger(fields.podPid) ? fields.podPid : process.pid,
    podGeneration: typeof fields.podGeneration === 'string' && fields.podGeneration !== '' ? fields.podGeneration : null,
    count: Number.isInteger(fields.count) && fields.count > 0 ? fields.count : 0,
  }
}

/**
 * Read `meta.json.freeze` back into the same six-field shape. Anything missing
 * or malformed degrades to `none`/nulls instead of throwing: a hand-edited or
 * pre-freeze ledger must never make the pod fail to start.
 * @param {unknown} meta parsed meta.json
 */
export function metaFreezeOf(meta) {
  const raw = /** @type {any} */ (meta)?.freeze
  if (raw === null || raw === undefined || typeof raw !== 'object') return null
  return {
    state: raw.state === 'frozen' ? 'frozen' : 'none',
    since: typeof raw.since === 'string' && raw.since !== '' ? raw.since : null,
    by: typeof raw.by === 'string' && raw.by !== '' ? raw.by : null,
    podPid: Number.isInteger(raw.podPid) ? raw.podPid : null,
    podGeneration: typeof raw.podGeneration === 'string' && raw.podGeneration !== '' ? raw.podGeneration : null,
    count: Number.isInteger(raw.count) && raw.count > 0 ? raw.count : 0,
  }
}

/**
 * `maxFreezeMs` normalization: absent/0/garbage = the 30-minute default (0 means
 * "use the pod default", not "no limit" — an unlimited freeze is exactly the
 * failure mode the watchdog exists to prevent).
 *
 * @param {unknown} payload a `freeze` payload
 * @returns {number} 1..{@link FREEZE_MAX_MS}
 */
export function freezeMaxOf(payload) {
  const raw = /** @type {any} */ (payload)?.maxFreezeMs
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) return FREEZE_DEFAULT_MAX_MS
  return Math.min(FREEZE_MAX_MS, Math.max(1, Math.trunc(raw)))
}

/**
 * One status-row projection for a live or ledger-only record.
 *
 * `thawable` is deliberately strict: a frozen job can only be resumed by the
 * pod process that still owns the job handle (`rec.jobHandle`). A handle in the
 * ledger would be meaningless, so a job loaded from disk is never thawable —
 * that is the `frozen-orphan` state (§4/§5 of the design).
 *
 * @param {any} rec pod job record (live or `loadJobFromDisk`)
 * @param {{ podGeneration?: string | null, now?: number }} [context]
 */
export function freezeRowOf(rec, context = {}) {
  const now = Number.isFinite(context.now) ? Number(context.now) : Date.now()
  const state = rec?.freezeState === 'frozen' ? 'frozen' : 'none'
  const since = typeof rec?.frozenAt === 'string' ? rec.frozenAt : null
  const frozenAtMs = Number.isFinite(rec?.frozenAtMs)
    ? Number(rec.frozenAtMs)
    : since === null
      ? null
      : Date.parse(since)
  const frozenForMs = state === 'frozen'
    ? Math.max(0, now - (Number.isFinite(frozenAtMs) ? frozenAtMs : now))
    : (Number.isFinite(rec?.frozenMsTotal) ? Number(rec.frozenMsTotal) : 0)
  const maxFreezeMs = Number.isFinite(rec?.freezeMaxMs) ? Number(rec.freezeMaxMs) : null
  const remainingFreezeMs = state === 'frozen' && maxFreezeMs !== null
    ? Math.max(0, maxFreezeMs - frozenForMs)
    : null
  const hasHandle = rec?.jobHandle !== null && rec?.jobHandle !== undefined
  const generation = typeof context.podGeneration === 'string' ? context.podGeneration : null
  const samePod = generation !== null && typeof rec?.freezePodGeneration === 'string' && rec.freezePodGeneration === generation
  const thawable = state === 'frozen' && rec?.diskOnly !== true && rec?.finalized !== true && hasHandle && samePod
  return {
    state,
    since,
    by: typeof rec?.freezeBy === 'string' && rec.freezeBy !== '' ? rec.freezeBy : null,
    count: Number.isInteger(rec?.freezeCount) && rec.freezeCount > 0 ? rec.freezeCount : 0,
    frozenForMs,
    maxFreezeMs,
    remainingFreezeMs,
    podGeneration: typeof rec?.freezePodGeneration === 'string' ? rec.freezePodGeneration : null,
    thawable,
    orphan: state === 'frozen' && !thawable,
  }
}

// ---------------------------------------------------------------------------
// Win32 bindings (lazy; a binding failure must never take the pod down)
// ---------------------------------------------------------------------------

/** koffi module → registered struct types (a koffi type can only be declared once). */
const typeCache = new WeakMap()

/**
 * `JOBOBJECT_FREEZE_INFORMATION` is 16 bytes / align 4 (verified against the
 * ABI with koffi 3.1.1):
 *   offset 0 ULONG Flags, 4 BOOLEAN Freeze, 5 BOOLEAN Swap,
 *   6 UCHAR[2] Reserved0, 8 ULONG[2] Reserved1.
 * `Flags` MUST be 1 ("a freeze operation is requested"); an all-zero buffer is
 * rejected with Win32 87, and `Freeze` selects the target state (1 = freeze,
 * 0 = thaw). `Swap` must stay 0.
 *
 * @param {any} koffi
 */
function typesFor(koffi) {
  const cached = typeCache.get(koffi)
  if (cached !== undefined) return cached
  const types = {
    freeze: koffi.struct('ESCAPE_POD_JOBOBJECT_FREEZE_INFORMATION', {
      Flags: 'uint32',
      Freeze: 'uint8',
      Swap: 'uint8',
      Reserved0: koffi.array('uint8', 2),
      Reserved1: koffi.array('uint32', 2),
    }),
    processEntry: koffi.struct('ESCAPE_POD_PROCESSENTRY32W', {
      dwSize: 'uint32',
      cntUsage: 'uint32',
      th32ProcessID: 'uint32',
      th32DefaultHeapID: 'uintptr_t',
      th32ModuleID: 'uint32',
      cntThreads: 'uint32',
      th32ParentProcessID: 'uint32',
      pcPriClassBase: 'long',
      dwFlags: 'uint32',
      szExeFile: koffi.array('uint16', 260),
    }),
  }
  types.freezeSize = koffi.sizeof(types.freeze)
  types.processEntrySize = koffi.sizeof(types.processEntry)
  typeCache.set(koffi, types)
  return types
}

/**
 * Bind the calls freeze/thaw needs and expose small helpers that keep pointer
 * handling in one place. Every helper returns `{ ok, win32 }`-shaped values and
 * never throws for an OS-level failure (a throw is only for a programming bug).
 *
 * @param {any} koffi
 */
function buildApi(koffi) {
  const PVOID = koffi.pointer('void')
  const PINT = koffi.pointer('int')
  const kernel32 = koffi.load('kernel32.dll')
  const ntdll = koffi.load('ntdll.dll')
  /** @param {any} library @param {string} name @param {any} result @param {any[]} args */
  const bind = (library, name, result, args) => library.func('__stdcall', name, result, args)
  const types = typesFor(koffi)

  const api = {
    createJobObjectW: bind(kernel32, 'CreateJobObjectW', PVOID, [PVOID, 'str16']),
    assignProcessToJobObject: bind(kernel32, 'AssignProcessToJobObject', 'int', [PVOID, PVOID]),
    setInformationJobObject: bind(kernel32, 'SetInformationJobObject', 'int', [PVOID, 'int', PVOID, 'uint32']),
    queryInformationJobObject: bind(kernel32, 'QueryInformationJobObject', 'int', [PVOID, 'int', PVOID, 'uint32', PVOID]),
    openProcess: bind(kernel32, 'OpenProcess', PVOID, ['uint32', 'int', 'uint32']),
    closeHandle: bind(kernel32, 'CloseHandle', 'int', [PVOID]),
    isProcessInJob: bind(kernel32, 'IsProcessInJob', 'int', [PVOID, PVOID, PINT]),
    getLastError: bind(kernel32, 'GetLastError', 'uint32', []),
    createToolhelp32Snapshot: bind(kernel32, 'CreateToolhelp32Snapshot', PVOID, ['uint32', 'uint32']),
    process32FirstW: bind(kernel32, 'Process32FirstW', 'int', [PVOID, PVOID]),
    process32NextW: bind(kernel32, 'Process32NextW', 'int', [PVOID, PVOID]),
    // NTSTATUS, not BOOL: 0 = success. These are the fallback path only.
    ntSuspendProcess: bind(ntdll, 'NtSuspendProcess', 'int32', [PVOID]),
    ntResumeProcess: bind(ntdll, 'NtResumeProcess', 'int32', [PVOID]),
  }

  /** @param {any} handle */
  function close(handle) {
    if (handle === null || handle === undefined) return false
    try {
      return api.closeHandle(handle) !== 0
    } catch {
      return false
    }
  }

  /**
   * koffi returns a `PVOID` as a BigInt on x64, but "no handle" may surface as
   * null/0/0n depending on the binding; one predicate keeps the checks honest.
   * @param {any} value
   */
  function isNullHandle(value) {
    return value === null || value === undefined || value === 0 || value === 0n
  }

  /** @returns {any | null} a job handle, or null when the OS refused */
  function createJob() {
    try {
      const handle = api.createJobObjectW(null, null)
      return isNullHandle(handle) ? null : handle
    } catch {
      return null
    }
  }

  /**
   * Freeze (or thaw) the whole job. One call, one target state; a failure
   * means NOTHING changed (the kernel rejects the request wholesale), which is
   * exactly why job freeze is preferred over per-pid suspension.
   * @param {any} job @param {boolean} shouldFreeze
   * @returns {{ ok: boolean, win32: number }}
   */
  function setFreeze(job, shouldFreeze) {
    const buffer = Buffer.alloc(types.freezeSize)
    koffi.encode(buffer, types.freeze, {
      Flags: 1,
      Freeze: shouldFreeze ? 1 : 0,
      Swap: 0,
      Reserved0: [0, 0],
      Reserved1: [0, 0],
    })
    const ok = api.setInformationJobObject(job, FREEZE_INFORMATION_CLASS, buffer, buffer.length)
    return { ok: ok !== 0, win32: ok !== 0 ? 0 : api.getLastError() }
  }

  /**
   * Reverse-check the kernel state after a call (diagnostics only; a query
   * failure never turns a successful freeze into an error).
   * @param {any} job
   * @returns {{ ok: boolean, win32: number, frozen?: boolean, flags?: number }}
   */
  function queryFreeze(job) {
    const buffer = Buffer.alloc(types.freezeSize)
    const ok = api.queryInformationJobObject(job, FREEZE_INFORMATION_CLASS, buffer, buffer.length, null)
    if (ok === 0) return { ok: false, win32: api.getLastError() }
    const decoded = koffi.decode(buffer, types.freeze)
    return {
      ok: true,
      win32: 0,
      frozen: decoded.Freeze === 1,
      flags: Number(decoded.Flags) >>> 0,
    }
  }

  /**
   * The argv contract of `AssignProcessToJobObject` requires BOTH
   * PROCESS_SET_QUOTA and PROCESS_TERMINATE on the target handle.
   * @param {any} job @param {number} pid
   */
  function assignRunner(job, pid) {
    const process = api.openProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid)
    if (isNullHandle(process)) {
      return { ok: false, stage: 'OpenProcess', win32: api.getLastError() }
    }
    try {
      const ok = api.assignProcessToJobObject(job, process)
      return ok !== 0
        ? { ok: true, stage: 'Assigned', win32: 0 }
        : { ok: false, stage: 'AssignProcessToJobObject', win32: api.getLastError() }
    } finally {
      close(process)
    }
  }

  /**
   * @param {number} pid
   * @returns {boolean | null} null = the question could not be asked
   */
  function pidInJob(pid, job) {
    const process = api.openProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if (isNullHandle(process)) return null
    try {
      const slot = koffi.alloc('int', 1)
      if (api.isProcessInJob(process, job, slot) === 0) return null
      return koffi.decode(slot, 'int') !== 0
    } finally {
      close(process)
    }
  }

  /** @returns {{ pid: number, ppid: number, name: string }[]} */
  function listProcesses() {
    const snapshot = api.createToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if (isNullHandle(snapshot)) {
      throw new Error('CreateToolhelp32Snapshot 失败（Win32 ' + String(api.getLastError()) + '）')
    }
    try {
      const buffer = Buffer.alloc(types.processEntrySize)
      koffi.encode(buffer, types.processEntry, { dwSize: types.processEntrySize })
      const rows = []
      if (api.process32FirstW(snapshot, buffer) === 0) return rows
      do {
        rows.push({
          pid: buffer.readUInt32LE(8),
          ppid: buffer.readUInt32LE(32),
          name: buffer.toString('utf16le', 44, 44 + 520).split('\u0000')[0],
        })
        if (rows.length >= MAX_DESCENDANTS * 4) break
      } while (api.process32NextW(snapshot, buffer) !== 0)
      return rows
    } finally {
      close(snapshot)
    }
  }

  /**
   * Every descendant pid of `rootPid`, breadth-first over the Toolhelp parent
   * map. This is what finds a child the runner spawned BEFORE it was assigned
   * to the pod's job: such a process is not a job member, so the kernel freeze
   * does not cover it (see the gap note in `createFreezeController().freeze`).
   * @param {number} rootPid
   */
  function descendantsOf(rootPid) {
    const rows = listProcesses()
    /** @type {Map<number, number[]>} */
    const children = new Map()
    for (const row of rows) {
      if (row.pid <= 0 || row.ppid <= 0) continue
      const bucket = children.get(row.ppid)
      if (bucket === undefined) children.set(row.ppid, [row.pid])
      else bucket.push(row.pid)
    }
    /** @type {number[]} */
    const out = []
    const seen = new Set([rootPid])
    const queue = [...(children.get(rootPid) ?? [])]
    while (queue.length > 0 && out.length < MAX_DESCENDANTS) {
      const pid = queue.shift()
      if (!Number.isInteger(pid) || seen.has(pid)) continue
      seen.add(pid)
      out.push(pid)
      for (const child of children.get(pid) ?? []) queue.push(child)
    }
    return out
  }

  /**
   * Suspend one process, keeping its HANDLE. The handle (not the pid) is what
   * thaw resumes with, so pid reuse between freeze and thaw cannot make us
   * resume an unrelated process.
   * @param {number} pid
   * @returns {{ ok: true, pid: number, handle: any } | { ok: false, pid: number, win32?: number, status?: number }}
   */
  function suspendProcess(pid) {
    const process = api.openProcess(PROCESS_SUSPEND_RESUME, 0, pid)
    if (isNullHandle(process)) {
      return { ok: false, pid, win32: api.getLastError() }
    }
    const status = api.ntSuspendProcess(process)
    if (status !== 0) {
      close(process)
      return { ok: false, pid, status }
    }
    return { ok: true, pid, handle: process }
  }

  /**
   * @param {any} process handle opened with PROCESS_SUSPEND_RESUME
   * @returns {number} NTSTATUS (0 = success); the caller closes the handle
   */
  function resumeProcess(process) {
    return api.ntResumeProcess(process)
  }

  return {
    setFreeze,
    queryFreeze,
    createJob,
    assignRunner,
    pidInJob,
    descendantsOf,
    suspendProcess,
    resumeProcess,
    close,
    getLastError: () => api.getLastError(),
  }
}

/** @type {{ ok: true, api: any, root: string | null } | { ok: false, reason: string } | null} */
let moduleBindings = null
/** @type {{ supported: boolean, reason: string | null, checkedAt: string, koffiRoot?: string | null } | null} */
let moduleProbe = null

/** @param {unknown} resolved */
function bindingsFrom(resolved) {
  try {
    const root = typeof resolved?.root === 'string' ? resolved.root : null
    return { ok: true, api: buildApi(resolved.koffi), root }
  } catch (error) {
    return { ok: false, reason: 'Win32 绑定失败：' + messageOf(error) }
  }
}

/**
 * Resolve koffi + build the bindings ONCE per process.
 * @param {{ log?: (message: string) => void }} [options]
 */
function ensureBindings(options = {}) {
  if (moduleBindings !== null) return moduleBindings
  const log = typeof options.log === 'function' ? options.log : () => {}
  let resolved
  try {
    resolved = resolveKoffi({})
  } catch (error) {
    resolved = { ok: false, tried: ['resolveKoffi 抛错：' + messageOf(error)] }
  }
  if (resolved.ok !== true) {
    moduleBindings = { ok: false, reason: 'koffi 不可用：' + resolved.tried.join('; ') }
    log('freeze unavailable: ' + moduleBindings.reason)
    return moduleBindings
  }
  moduleBindings = bindingsFrom(resolved)
  if (moduleBindings.ok !== true) log('freeze unavailable: ' + moduleBindings.reason)
  return moduleBindings
}

/**
 * Probe once per process: freeze and thaw a ONE-OFF empty job. An empty job is
 * enough to prove the OS accepts class 18 (verified: it returns 1), it touches
 * no real process, and any failure (old Windows, koffi missing, policy) is
 * reported instead of thrown. A failed probe must never affect startup or any
 * execution path — the caller only uses the answer to decide between
 * `EFREEZEUNSUPPORTED` and a real attempt.
 *
 * @param {{ log?: (message: string) => void, resolveKoffi?: (options?: any) => any, koffi?: any, fresh?: boolean }} [options]
 * @returns {{ supported: boolean, reason: string | null, checkedAt: string, koffiRoot?: string | null }}
 */
export function probeFreezeSupport(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const custom = options.koffi !== undefined || options.resolveKoffi !== undefined
  if (!custom && options.fresh !== true && moduleProbe !== null) return moduleProbe

  let bindings
  if (custom) {
    // Injected bindings are a test seam: never touch the process-level cache,
    // otherwise one synthetic failure would poison the whole pod.
    try {
      const resolved = options.koffi !== undefined
        ? { ok: true, koffi: options.koffi, root: 'injected' }
        : (options.resolveKoffi ?? resolveKoffi)({})
      bindings = resolved.ok === true ? bindingsFrom(resolved) : { ok: false, reason: 'koffi 不可用：' + (resolved.tried ?? []).join('; ') }
    } catch (error) {
      bindings = { ok: false, reason: 'koffi/Win32 绑定失败：' + messageOf(error) }
    }
  } else {
    bindings = ensureBindings({ log })
  }

  let result
  if (bindings.ok !== true) {
    result = { supported: false, reason: bindings.reason, checkedAt: nowIso() }
  } else {
    result = probeWith(bindings.api, log, bindings.root ?? null)
  }
  if (!custom) moduleProbe = result
  return result
}

/**
 * @param {any} api @param {(message: string) => void} log @param {string | null} root
 */
function probeWith(api, log, root) {
  let job = null
  try {
    job = api.createJob()
    if (job === null) {
      return { supported: false, reason: 'CreateJobObjectW 失败（Win32 ' + String(api.getLastError()) + '）', checkedAt: nowIso() }
    }
    const frozen = api.setFreeze(job, true)
    if (frozen.ok !== true) {
      return {
        supported: false,
        reason: 'SetInformationJobObject(JobObjectFreezeInformation, 18) 对空 job 冻结失败（Win32 ' + String(frozen.win32) + '）：本机不支持 job 冻结',
        checkedAt: nowIso(),
      }
    }
    const thawed = api.setFreeze(job, false)
    if (thawed.ok !== true) log('freeze probe: 空 job 解冻失败（Win32 ' + String(thawed.win32) + '），冻结本身可用')
    const observed = api.queryFreeze(job)
    if (observed.ok === true && observed.frozen === false && thawed.ok === true) {
      return { supported: true, reason: null, checkedAt: nowIso(), koffiRoot: root }
    }
    if (observed.ok === true && observed.frozen === true && thawed.ok === true) {
      return { supported: false, reason: '空 job 解冻后内核仍报告 frozen=1；不信任这台机器的句柄语义', checkedAt: nowIso() }
    }
    return { supported: true, reason: null, checkedAt: nowIso(), koffiRoot: root }
  } catch (error) {
    return { supported: false, reason: '探测异常：' + messageOf(error), checkedAt: nowIso() }
  } finally {
    if (job !== null) api.close(job)
  }
}

/** Test seam: forget the process-level probe/bindings cache. */
export function resetFreezeProbe() {
  moduleBindings = null
  moduleProbe = null
}

// ---------------------------------------------------------------------------
// Controller: owns the job handle and the freeze state machine
// ---------------------------------------------------------------------------

/**
 * The pod's freeze state machine. It owns:
 *   - the anonymous job handle of ONE job (never the ledger),
 *   - the freeze/thaw state and the watchdog timer,
 *   - the job deadline timer, because a freeze must PAUSE that deadline (a
 *     60s-timeout command must not be killed the instant it is thawed after a
 *     5-minute freeze: the frozen time is not command budget).
 *
 * `onStateChange(rec, ledgerRecord)` is how the pod persists `meta.json.freeze`
 * with EXACTLY {@link freezeLedgerFields}' six keys. `onDeadline(rec)` is the
 * pod's existing timeout kill path (runner kill + taskkill fallback), kept
 * outside this module so freeze never re-implements a kill.
 *
 * @param {{
 *   log?: (message: string) => void,
 *   podPid?: number,
 *   podGeneration?: string | null,
 *   now?: () => number,
 *   api?: any,
 *   probe?: () => { supported: boolean, reason?: string | null },
 *   onDeadline?: (rec: any) => void,
 *   onStateChange?: (rec: any, ledgerRecord: any) => void,
 * }} [options]
 */
export function createFreezeController(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const podPid = Number.isInteger(options.podPid) ? options.podPid : process.pid
  const podGeneration = typeof options.podGeneration === 'string' ? options.podGeneration : null
  const customApi = options.api ?? null
  const probeInput = typeof options.probe === 'function' ? options.probe : null
  const onDeadline = typeof options.onDeadline === 'function' ? options.onDeadline : () => {}
  const onStateChange = typeof options.onStateChange === 'function' ? options.onStateChange : () => {}
  /** @type {{ supported: boolean, reason: string | null, checkedAt: string } | null} */
  let supportMemo = null
  /**
   * The last `AssignProcessToJobObject` failure. This is the one failure a
   * `pod_status` reader must be able to see: when the pod itself was started
   * inside another job (the detached-spawn path inherits DSH's job), assigning
   * the runner to the pod's own job can be refused (Win32 5), and freeze then
   * answers ENOTHANDLE even though the capability probe said supported.
   * @type {{ at: string, stage: string, win32: number, runnerPid: number } | null}
   */
  let lastAttachFailure = null
  /** @type {any} */
  let apiMemo
  let apiResolved = false

  /**
   * The probe answer, normalized and memoized for this controller. A throwing
   * probe is an unsupported probe, never a pod failure.
   */
  function support() {
    if (supportMemo !== null) return supportMemo
    let raw
    try {
      raw = probeInput === null ? probeFreezeSupport({ log }) : probeInput()
    } catch (error) {
      raw = { supported: false, reason: '冻结探测抛错：' + messageOf(error) }
    }
    supportMemo = {
      supported: raw?.supported === true,
      reason: typeof raw?.reason === 'string' && raw.reason !== '' ? raw.reason : null,
      checkedAt: typeof raw?.checkedAt === 'string' ? raw.checkedAt : nowIso(),
      podGeneration,
    }
    return supportMemo
  }

  /** Bindings are loaded only when a freeze is actually possible. */
  function api() {
    if (apiResolved) return apiMemo
    apiResolved = true
    if (customApi !== null) {
      apiMemo = customApi
      return apiMemo
    }
    if (support().supported !== true) {
      apiMemo = null
      return null
    }
    const bindings = ensureBindings({ log })
    apiMemo = bindings.ok === true ? bindings.api : null
    return apiMemo
  }

  // ---- deadline (the existing per-job timeout, now pausable) --------------

  /** @param {any} rec */
  function clearDeadline(rec) {
    if (rec?.timeoutTimer !== null && rec?.timeoutTimer !== undefined) {
      try {
        clearTimeout(rec.timeoutTimer)
      } catch {
        // already gone
      }
      rec.timeoutTimer = null
    }
  }

  /**
   * Arm the timeout exactly like the old inline `setTimeout` did: no timer when
   * there is no deadline, unref'd so a pending deadline never keeps the pod up.
   * @param {any} rec @param {number} delayMs
   */
  function armDeadline(rec, delayMs) {
    if (!(Number.isFinite(delayMs) && delayMs > 0)) return false
    clearDeadline(rec)
    const delay = Math.min(FREEZE_MAX_MS, Math.trunc(delayMs))
    rec.deadlineAtMs = now() + delay
    rec.deadlineRemainingMs = delay
    const timer = setTimeout(() => {
      rec.timeoutTimer = null
      rec.deadlineRemainingMs = null
      onDeadline(rec)
    }, delay)
    if (typeof timer.unref === 'function') timer.unref()
    rec.timeoutTimer = timer
    return true
  }

  /**
   * Stop the deadline clock without losing what is left. THE reason a freeze is
   * not just "a slower command": a 60s foreground deadline must not expire while
   * the command is frozen (design §5). The remaining ms is re-armed on thaw.
   * @param {any} rec
   */
  function pauseDeadline(rec) {
    if (rec?.timeoutTimer === null || rec?.timeoutTimer === undefined) return 0
    clearTimeout(rec.timeoutTimer)
    rec.timeoutTimer = null
    const deadlineAt = Number.isFinite(rec.deadlineAtMs) ? Number(rec.deadlineAtMs) : now()
    rec.deadlineRemainingMs = Math.max(0, deadlineAt - now())
    return rec.deadlineRemainingMs
  }

  /** @param {any} rec */
  function resumeDeadline(rec) {
    if (rec?.timeoutTimer !== null && rec?.timeoutTimer !== undefined) return false
    const remaining = rec?.deadlineRemainingMs
    if (!Number.isFinite(remaining)) return false
    rec.deadlineRemainingMs = null
    return armDeadline(rec, Math.max(1, Number(remaining)))
  }

  // ---- watchdog -----------------------------------------------------------

  /** @param {any} rec */
  function clearWatchdog(rec) {
    if (rec?.freezeWatchdogTimer !== null && rec?.freezeWatchdogTimer !== undefined) {
      try {
        clearTimeout(rec.freezeWatchdogTimer)
      } catch {
        // already gone
      }
      rec.freezeWatchdogTimer = null
    }
  }

  /**
   * Windows has no kernel-level freeze timeout. The pod is OUTSIDE the job, so
   * this timer keeps ticking while everything else is stopped; when it fires
   * the pod THAWS (never kills: the design's "freeze = make room", not "kill").
   * @param {any} rec @param {number} maxFreezeMs
   */
  function armWatchdog(rec, maxFreezeMs) {
    clearWatchdog(rec)
    const delay = Math.max(1, Math.min(FREEZE_MAX_MS, Math.trunc(maxFreezeMs)))
    const timer = setTimeout(() => {
      rec.freezeWatchdogTimer = null
      rec.autoThawedAt = nowIso()
      log(
        'job ' + String(rec.jobId) + ' 冻结超过 ' + String(delay) + 'ms（maxFreezeMs 看门狗）：自动解冻，不杀命令',
      )
      const outcome = thaw(rec, 'watchdog')
      if (outcome.ok !== true) {
        log('job ' + String(rec.jobId) + ' 看门狗解冻失败：' + String(outcome.message ?? outcome.code ?? 'unknown') + '（冻结保持，等下一次看门狗）')
        armWatchdog(rec, delay)
      }
    }, delay)
    if (typeof timer.unref === 'function') timer.unref()
    rec.freezeWatchdogTimer = timer
  }

  // ---- persistence + projection ------------------------------------------

  /** @param {any} rec */
  function ledgerRecordOf(rec) {
    return freezeLedgerFields({
      state: rec?.freezeState,
      since: rec?.frozenAt,
      by: rec?.freezeBy,
      podPid,
      podGeneration: rec?.freezePodGeneration ?? podGeneration,
      count: rec?.freezeCount,
    })
  }

  /** @param {any} rec */
  function emitState(rec) {
    const record = ledgerRecordOf(rec)
    try {
      onStateChange(rec, record)
    } catch (error) {
      log('job ' + String(rec?.jobId) + ' freeze 状态写入账本失败：' + messageOf(error))
    }
    return record
  }

  /** @param {any} rec @param {Record<string, unknown>} [extra] */
  function stateSnapshot(rec, extra = {}) {
    const row = freezeRowOf(rec, { podGeneration, now: now() })
    return {
      frozen: row.state === 'frozen',
      frozenAt: row.since,
      frozenForMs: row.frozenForMs,
      remainingFreezeMs: row.remainingFreezeMs,
      maxFreezeMs: row.maxFreezeMs,
      thawable: row.thawable,
      freezeCount: row.count,
      ...extra,
    }
  }

  // ---- job handle ---------------------------------------------------------

  /**
   * Create this job's anonymous job object. Deliberately NO
   * `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: closing the handle must never kill
   * the command. Without that limit the pod can die and the runner (and its
   * inner kill-on-close job) keeps running — the escape pod's whole point.
   * @param {any} rec
   */
  function createJob(rec) {
    const live = api()
    if (live === null) return null
    const handle = live.createJob()
    if (handle === null) {
      log('job ' + String(rec?.jobId) + ' CreateJobObjectW 失败（Win32 ' + String(live.getLastError()) + '）：该 job 不支持冻结')
      return null
    }
    rec.jobHandle = handle
    rec.freezePodGeneration = podGeneration
    return handle
  }

  /**
   * Put the runner into the pod's job. Runs immediately after `spawn()`, so the
   * runner normally has not spawned the command yet — but it MAY have (see the
   * race note in `freeze`). A failed assignment drops the handle instead of
   * pretending: freezing a job the runner is not in would report success while
   * the command kept running.
   * @param {any} rec @param {number} pid
   */
  function attachRunner(rec, pid) {
    if (rec?.jobHandle === null || rec?.jobHandle === undefined) return false
    if (!Number.isInteger(pid) || pid <= 0) return false
    const live = api()
    if (live === null) return false
    const assigned = live.assignRunner(rec.jobHandle, pid)
    if (assigned.ok !== true) {
      lastAttachFailure = {
        at: nowIso(),
        stage: String(assigned.stage),
        win32: Number(assigned.win32),
        runnerPid: pid,
      }
      log(
        'job ' + String(rec?.jobId) + ' 无法把 runner(pid ' + String(pid) + ') 放进 pod 的 job：' +
        String(assigned.stage) + ' Win32 ' + String(assigned.win32) + '；该 job 的冻结会返回 ENOTHANDLE',
      )
      live.close(rec.jobHandle)
      rec.jobHandle = null
      return false
    }
    return true
  }

  /**
   * Suspend every descendant that is NOT a member of the pod's job: that is the
   * assignment-race escapee. Each suspended process keeps its own handle so thaw
   * resumes the exact process object (pid reuse cannot hit a stranger).
   * @param {any} rec @param {any} live
   */
  function suspendStragglers(rec, live) {
    /** @type {{ pid: number, handle: any }[]} */
    const suspended = []
    if (!Number.isInteger(rec?.runnerPid) || rec.runnerPid <= 0) return suspended
    let descendants
    try {
      descendants = live.descendantsOf(rec.runnerPid)
    } catch (error) {
      log('job ' + String(rec?.jobId) + ' 枚举子孙进程失败（job 冻结仍然生效）：' + messageOf(error))
      return suspended
    }
    for (const pid of descendants) {
      if (pid === process.pid) continue
      const inJob = live.pidInJob(pid, rec.jobHandle)
      if (inJob === true) continue
      if (inJob === null) {
        log('job ' + String(rec?.jobId) + ' 无法询问 pid ' + String(pid) + ' 是否在 job 内（OpenProcess 被拒），尝试直接挂起')
      }
      const result = live.suspendProcess(pid)
      if (result.ok === true) {
        suspended.push({ pid: result.pid, handle: result.handle })
      } else {
        log(
          'job ' + String(rec?.jobId) + ' 兜底挂起 pid ' + String(pid) + ' 失败（' +
          (result.win32 !== undefined ? 'Win32 ' + String(result.win32) : 'NTSTATUS 0x' + Number(result.status).toString(16)) +
          '）；该进程仍在运行',
        )
      }
    }
    return suspended
  }

  /** @param {any} rec @param {any} live */
  function resumeStragglers(rec, live) {
    const list = Array.isArray(rec?.suspendedProcs) ? rec.suspendedProcs : []
    rec.suspendedProcs = []
    for (const entry of list) {
      const status = live.resumeProcess(entry.handle)
      if (status !== 0) {
        log('job ' + String(rec?.jobId) + ' 恢复 pid ' + String(entry.pid) + ' 失败（NTSTATUS 0x' + Number(status).toString(16) + '）')
      }
      live.close(entry.handle)
    }
  }

  // ---- freeze / thaw ------------------------------------------------------

  /**
   * Freeze one running job.
   *
   * KNOWN GAP (accepted for this round, coverage repair is step 3 of the design):
   * the runner can spawn the restricted command before `attachRunner()` assigns
   * it to the pod's job. Such a process is not in the job, so the kernel freeze
   * covers only the runner. We enumerate the runner's descendants, verify each
   * with `IsProcessInJob`, and `NtSuspendProcess` the ones that are outside.
   * What this still cannot cover:
   *   - a process spawned by a leaked descendant BETWEEN the enumeration and its
   *     suspend (the window is one synchronous loop, but the OS runs in parallel);
   *   - a descendant we are not allowed to open (`PROCESS_SUSPEND_RESUME`
   *     denied) — it is logged and keeps running;
   *   - a process that leaves the job while frozen (`CREATE_BREAKAWAY_FROM_JOB`
   *     needs JOB_OBJECT_LIMIT_BREAKAWAY_OK, which this job never sets).
   * It is NOT a silent lie: every failure is logged and every suspended pid is
   * resumed on thaw with the handle it was suspended with.
   *
   * @param {any} rec @param {{ by?: string | null, maxFreezeMs?: number }} [request]
   */
  function freeze(rec, request = {}) {
    if (rec?.freezeState === 'frozen') {
      return { ok: true, action: 'freeze', alreadyFrozen: true, ...stateSnapshot(rec) }
    }
    if (rec?.jobHandle === null || rec?.jobHandle === undefined) {
      return { ok: false, code: 'ENOTHANDLE', message: '这个 job 没有本 pod 持有的 job 句柄（只有账本），无法冻结' }
    }
    if (support().supported !== true) {
      return { ok: false, code: 'EFREEZEUNSUPPORTED', message: support().reason ?? '本机不支持 job 冻结' }
    }
    const live = api()
    if (live === null) {
      return { ok: false, code: 'EFREEZEUNSUPPORTED', message: support().reason ?? '冻结绑定不可用' }
    }
    const maxFreezeMs = freezeMaxOf({ maxFreezeMs: request.maxFreezeMs })
    const applied = live.setFreeze(rec.jobHandle, true)
    if (applied.ok !== true) {
      return {
        ok: false,
        code: 'EOSFAIL',
        win32: applied.win32,
        message: 'SetInformationJobObject(JobObjectFreezeInformation) 冻结失败（Win32 ' + String(applied.win32) + '）；本次没有冻结任何进程',
      }
    }
    // The job is frozen: the runner and everything inside it stopped. Only the
    // race escapees are still running.
    const suspended = suspendStragglers(rec, live)
    rec.freezeState = 'frozen'
    rec.frozenAt = nowIso()
    rec.frozenAtMs = now()
    rec.freezeBy = typeof request.by === 'string' && request.by !== '' ? request.by : null
    rec.freezeMaxMs = maxFreezeMs
    rec.freezeCount = (Number.isInteger(rec.freezeCount) ? rec.freezeCount : 0) + 1
    rec.suspendedProcs = suspended
    const pausedRemaining = pauseDeadline(rec)
    armWatchdog(rec, maxFreezeMs)
    emitState(rec)
    const observed = live.queryFreeze(rec.jobHandle)
    if (observed.ok === true && observed.frozen !== true) {
      log('job ' + String(rec?.jobId) + ' 冻结调用成功但内核反查不是 frozen=1（flags=0x' + Number(observed.flags ?? 0).toString(16) + '）')
    }
    log(
      'job ' + String(rec.jobId) + ' 已冻结：job 句柄 + 兜底挂起 ' + String(suspended.length) + ' 个 job 外子孙，' +
      'maxFreezeMs=' + String(maxFreezeMs) + (pausedRemaining > 0 ? '，超时计时器暂停（剩 ' + String(pausedRemaining) + 'ms）' : ''),
    )
    return { ok: true, action: 'freeze', alreadyFrozen: false, ...stateSnapshot(rec) }
  }

  /**
   * Thaw one frozen job. Idempotent. A failed kernel call keeps the frozen
   * state and leaves the watchdog armed, because a half-thawed job is worse
   * than an honestly frozen one.
   * @param {any} rec @param {string} [reason]
   */
  function thaw(rec, reason = 'manual') {
    if (rec?.freezeState !== 'frozen') {
      return { ok: true, action: 'thaw', alreadyThawed: true, ...stateSnapshot(rec) }
    }
    const live = api()
    const handle = rec.jobHandle
    if (live === null) {
      return { ok: false, code: 'EFREEZEUNSUPPORTED', message: support().reason ?? '冻结绑定不可用，无法解冻' }
    }
    if (handle !== null && handle !== undefined) {
      const applied = live.setFreeze(handle, false)
      if (applied.ok !== true) {
        return {
          ok: false,
          code: 'EOSFAIL',
          win32: applied.win32,
          message: 'SetInformationJobObject(JobObjectFreezeInformation) 解冻失败（Win32 ' + String(applied.win32) + '）；保持冻结状态，看门狗会重试',
        }
      }
    }
    resumeStragglers(rec, live)
    clearWatchdog(rec)
    const episodeMs = Number.isFinite(rec.frozenAtMs) ? Math.max(0, now() - rec.frozenAtMs) : 0
    rec.frozenMsTotal = (Number.isFinite(rec.frozenMsTotal) ? rec.frozenMsTotal : 0) + episodeMs
    rec.freezeState = 'none'
    rec.frozenAt = null
    rec.frozenAtMs = null
    const resumed = resumeDeadline(rec)
    emitState(rec)
    log(
      'job ' + String(rec.jobId) + ' 已解冻（reason=' + String(reason) + '）：本次冻结 ' + String(episodeMs) + 'ms' +
      (resumed ? '，超时计时器按剩余量重挂' : ''),
    )
    return { ok: true, action: 'thaw', alreadyThawed: false, frozenForMs: episodeMs, ...stateSnapshot(rec) }
  }

  /**
   * Final settlement: stop both timers, count the last (possibly open) freeze
   * episode, best-effort thaw/resume anything this pod suspended, then close
   * the job handle. Skipping the thaw here would leave a suspended process
   * frozen forever once the handle is gone. Returns the numbers `exit.json`
   * records (`frozenMs` / `freezeCount` / `killedWhileFrozen`).
   * @param {any} rec
   */
  function settle(rec) {
    const live = api()
    clearWatchdog(rec)
    clearDeadline(rec)
    let frozenMs = Number.isFinite(rec?.frozenMsTotal) ? Number(rec.frozenMsTotal) : 0
    const wasFrozen = rec?.freezeState === 'frozen'
    if (wasFrozen) {
      if (Number.isFinite(rec?.frozenAtMs)) frozenMs += Math.max(0, now() - Number(rec.frozenAtMs))
      if (live !== null) {
        if (rec.jobHandle !== null && rec.jobHandle !== undefined) {
          const applied = live.setFreeze(rec.jobHandle, false)
          if (applied.ok !== true) {
            log('job ' + String(rec?.jobId) + ' 结算时解冻失败（Win32 ' + String(applied.win32) + '）；仍关闭句柄')
          }
        }
        resumeStragglers(rec, live)
      }
      rec.freezeState = 'none'
      rec.frozenAt = null
      rec.frozenAtMs = null
    } else if (Array.isArray(rec?.suspendedProcs) && rec.suspendedProcs.length > 0) {
      if (live !== null) resumeStragglers(rec, live)
      else rec.suspendedProcs = []
    }
    if (live !== null && rec.jobHandle !== null && rec.jobHandle !== undefined) {
      live.close(rec.jobHandle)
    }
    rec.jobHandle = null
    // Only jobs that were frozen at least once need the ledger updated: a job
    // that never froze keeps the pre-freeze meta untouched (no extra writes).
    if (wasFrozen || (Number.isInteger(rec?.freezeCount) && rec.freezeCount > 0)) emitState(rec)
    return {
      frozenMs,
      freezeCount: Number.isInteger(rec?.freezeCount) ? rec.freezeCount : 0,
      killedWhileFrozen: rec?.killedWhileFrozen === true,
    }
  }

  return {
    support,
    /** Last runner→job assignment failure, for `pod_status` diagnostics. */
    lastAttachFailure: () => lastAttachFailure,
    createJob,
    attachRunner,
    freeze,
    thaw,
    settle,
    view: (rec) => freezeRowOf(rec, { podGeneration, now: now() }),
    armDeadline,
    pauseDeadline,
    resumeDeadline,
    ledgerRecordOf,
    /** The pod instance id this controller believes it owns (diagnostics). */
    podGeneration,
  }
}
