/**
 * 恢复半程：DSH 重启后，把上一个 Host 挂起的 `pod_exec` 调用结算掉。
 *
 * `resume.mjs` 只做了前半程：等待命令结算之前先 `hold(callId, {tool:'pod_exec',
 * hint:{jobId}, deadlineMs})`，于是重启后平台不会给这条调用补
 * `TOOL_OUTCOME_UNKNOWN`，而是写一条如实的"被挂起 / 结果尚未产生"。若没有本模块，
 * 那条调用就永远停在这个中间态，12 小时后被服务的 deadline 换成 `TOOL_OUTCOME_UNKNOWN`
 * 的措辞——模型看到的仍是"结果未知"，而命令其实早就结束、结论就在账本里。
 *
 * 本模块负责后半程，在插件激活时跑一次（pod 客户端连上之后）：
 *
 *   pending-exec.json（本 boot 的清单）→ 逐条
 *     查 pod 账本（与 pod_exec 同一个 `output` op、同一个窗口）
 *       ├─ job 已结算 → 用与 pod_exec 完全相同的渲染函数构造结果 → complete(callId, …)
 *       ├─ job 仍在跑 → 刷新 hold（推进 deadlineAt），继续轮询，结算后再 complete
 *       └─ job 不存在 / 账本缺失（ENOJOB）→ fail(callId, 原因)   ← 措辞由服务负责，与平台一致
 *   结算成功的条目从清单删除；服务不认识的条目（unknown-call / already-in-log）也删，
 *   因为服务才是"这条调用还能不能被回答"的权威，重复重试只会空转。
 *
 * ## 为什么自己存一份清单，而不是只读 `resumableToolCalls.status()`
 *
 * 服务的 `status()` 只给 `{callId, sessionId, tool, status, deadlineAt, pendingWritten}`，
 * **没有 jobId**（见 restart-bundle `host/resumable.js`），恢复所需的全部信息（哪个 pod job）
 * 只在 `hold` 的 `hint` 里。`$DSH_HOME/.dsh-restart/resumable-holds.json` 里虽然有 hint，
 * 但那是另一个 bundle 的私有文件，本插件不去读它。所以本插件在 `hold` 之前同步原子写一份
 * `{callId, jobId, owner, deadlineMs}` 清单到自己的账本根（`<stateDir>/pending-exec.json`，默认在
 * `%LOCALAPPDATA%\dsh-escape-pod-core\`，工作区之外），结算后删除。`owner` 是写入进程的 pid：
 * 只有 `owner` 与本次进程不同的条目才可能是"上一个 boot 的挂起"，本进程刚登记的（含插件 HMR
 * 重载）由它自己的 `completeAfterCommit` 结算。清单损坏 / 版本不符
 * 时按空清单继续（下一次写入会覆盖），绝不让恢复路径把插件带崩。
 *
 * ## 时序
 *
 * 服务的 boot 结算窗口只有 1200ms（`settleGraceMs`），超时它就写 provisional。所以恢复扫描
 * 在插件激活的同一个同步栈里就读清单、立刻发第一次账本查询；若晚于窗口，`complete` 会走
 * "只换 content 的 surface replacement"（restart-bundle 的 `replaceResultContent`），
 * 模型最终看到的仍是真实文本——provisional 只是中途的一屏。
 *
 * 这里**只读账本、绝不重放命令**：hint 里只有 jobId，恢复路径没有 argv，结构上就不可能
 * 二次执行。
 */

import fs from 'node:fs'
import { dirname } from 'node:path'

import { EXEC_TOOL_NAME } from './resume.mjs'

/** 清单文件名（位于 `<stateDir>` 根下，与 jobs/ 同级）。 */
export const PENDING_FILE_NAME = 'pending-exec.json'
/** 清单的 schema 版本；版本不符按空清单处理，不尝试迁移。 */
export const PENDING_VERSION = 1
/** 清单条目的固定上限（服务侧 holds 也是 64）。 */
export const PENDING_LIMITS = Object.freeze({
  entries: 64,
  callIdChars: 200,
  jobIdChars: 120,
  toolChars: 120,
  ownerChars: 40,
  deadlineMs: 24 * 60 * 60 * 1000,
})
/** 恢复扫描的默认节奏与上限（全部可由调用方覆盖，自测用它换确定性）。 */
export const RECOVERY_DEFAULTS = Object.freeze({
  /** 第一次重扫前的等待；之后按 1.5 倍退避到 pollMaxMs。 */
  pollMinMs: 1000,
  pollMaxMs: 30 * 1000,
  /** 服务可能比本插件更晚 `ctx.provide`，激活时有限次重试。 */
  serviceAttempts: 4,
  serviceRetryMs: 200,
  /** 一次 boot 内最多扫多久；到点保留清单，交给下一次 boot。 */
  maxWaitMs: 12 * 60 * 60 * 1000,
  /** 与 pod_exec 的最后一次读完全相同的模型窗口。插件传的是实时 getter（原生
   *  maxOutputBytes），这里只是"调用方没给 / getter 抛错"时的兜底；64000 与原生默认一致。 */
  modelOutputLimitBytes: 64_000,
})

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/** @param {unknown} value */
function nonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== ''
}

/** @param {unknown} value @param {number} max */
function boundString(value, max) {
  return nonEmptyString(value) ? value.trim().slice(0, max) : ''
}

/** @param {unknown} value @param {number} fallback */
function clampMs(value, fallback) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return fallback
  return Math.min(Math.floor(value), PENDING_LIMITS.deadlineMs)
}

/**
 * 把一条清单记录收成固定形状。形状不合法就返回 `null`（调用方丢弃并记日志），
 * 这样一份被改坏的清单最多丢掉坏条目，不会让恢复扫描抛错。
 *
 * `owner` 是"哪一进程写的"（默认 `process.pid`），用来区分"上一次 boot 留下的"与
 * "本进程这一轮刚登记的"——后者由它自己的 `completeAfterCommit` 负责结算，恢复扫描
 * 绝不能抢答（否则会给同一条调用写第二条 `tool/result`，那会写坏会话）。
 *
 * @param {unknown} record
 * @param {number} [now]
 * @returns {null | {callId: string, jobId: string, tool: string, deadlineMs: number, recordedAt: number, owner: string}}
 */
export function sanitizePendingEntry(record, now = Date.now()) {
  if (record === null || typeof record !== 'object') return null
  const source = /** @type {Record<string, unknown>} */ (record)
  const callId = boundString(source.callId, PENDING_LIMITS.callIdChars)
  const jobId = boundString(source.jobId, PENDING_LIMITS.jobIdChars)
  if (callId === '' || jobId === '') return null
  const tool = boundString(source.tool, PENDING_LIMITS.toolChars) || EXEC_TOOL_NAME
  const deadlineMs = clampMs(source.deadlineMs, RECOVERY_DEFAULTS.maxWaitMs)
  const recordedAt = typeof source.recordedAt === 'number' && Number.isFinite(source.recordedAt) && source.recordedAt > 0
    ? Math.floor(source.recordedAt)
    : now
  const owner = boundString(source.owner, PENDING_LIMITS.ownerChars)
  return { callId, jobId, tool, deadlineMs, recordedAt, owner }
}

/**
 * 原子 JSON 写：同目录临时文件 + fsync + rename。清单是"重启后还有没有东西要结算"的
 * 唯一凭据，写到一半的 JSON 会让下一次 boot 误判（少恢复一条调用），所以和账本一样
 * 用原子写。
 * @param {string} file @param {unknown} value
 */
function writeJsonAtomic(file, value) {
  fs.mkdirSync(dirname(file), { recursive: true })
  const temporary = file + '.tmp-' + String(process.pid)
  const fd = fs.openSync(temporary, 'w')
  try {
    fs.writeSync(fd, JSON.stringify(value, null, 2) + '\n')
    fs.fsyncSync(fd)
  } finally {
    fs.closeSync(fd)
  }
  fs.renameSync(temporary, file)
}

/**
 * 待恢复清单：内存里的 Map + 每次变更同步原子落盘。
 *
 * 接口（`createExecHold` 只用到前两个，且全部可空）：
 *   `load() add(record) remove(callId) has(callId) list() snapshot() path disabled`
 *
 * 所有磁盘错误都只记日志：清单坏了要降级，不能让 `pod_exec` 因为写不了恢复清单而失败。
 *
 * @param {{ file?: string, log?: (message: string) => void, now?: () => number, bootId?: string, owner?: string }} [options]
 *   `owner` 是"哪个进程写的"（默认 `process.pid`），随条目落盘；恢复扫描据此区分
 *   "上一次 boot 留下的"与"本进程刚登记的"。
 */
export function createPendingStore(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const file = nonEmptyString(options.file) ? options.file : ''
  const disabled = file === ''
  const bootId = nonEmptyString(options.bootId) ? String(options.bootId) : 'boot'
  const owner = boundString(options.owner, PENDING_LIMITS.ownerChars) || String(process.pid)
  /** @type {Map<string, {callId: string, jobId: string, tool: string, deadlineMs: number, recordedAt: number, owner: string}>} */
  const entries = new Map()
  let loaded = false
  let corrupt = false

  /** 当前快照（稳定字段顺序，便于人眼看 diff）。 */
  function snapshot() {
    const rows = []
    for (const entry of entries.values()) {
      if (rows.length >= PENDING_LIMITS.entries) break
      rows.push({
        callId: entry.callId,
        jobId: entry.jobId,
        tool: entry.tool,
        deadlineMs: entry.deadlineMs,
        recordedAt: entry.recordedAt,
        owner: entry.owner,
      })
    }
    return { version: PENDING_VERSION, bootId, updatedAt: now(), entries: rows }
  }

  /** @returns {boolean} */
  function persist() {
    if (disabled) return false
    try {
      writeJsonAtomic(file, snapshot())
      return true
    } catch (error) {
      log('恢复清单写入失败（' + file + '）：' + messageOf(error))
      return false
    }
  }

  /**
   * 读清单。缺失 / 坏 JSON / 版本不符 / 形状不符都降级成"空清单 + 日志"，
   * 绝不抛错。重复调用只在第一次真正读盘（用 `load()` 的返回值观察结果）。
   * @returns {{ ok: boolean, file: string, entries: number, corrupt: boolean, skipped: number }}
   */
  function load() {
    if (loaded) return { ok: true, file, entries: entries.size, corrupt, skipped: 0 }
    loaded = true
    if (disabled) return { ok: false, file, entries: 0, corrupt: false, skipped: 0 }
    let text
    try {
      text = fs.readFileSync(file, 'utf8')
    } catch (error) {
      const code = /** @type {any} */ (error)?.code
      if (code !== 'ENOENT') log('恢复清单读取失败（' + file + '）：' + messageOf(error))
      return { ok: true, file, entries: 0, corrupt: false, skipped: 0 }
    }
    let parsed = null
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      /** @type {any} */ (parsed).version !== PENDING_VERSION ||
      !Array.isArray(/** @type {any} */ (parsed).entries)
    ) {
      // 坏清单留在原地（下次写入自然覆盖）；恢复扫描按空清单继续。
      corrupt = true
      log('恢复清单不可用（损坏或版本不符），按空清单继续：' + file)
      return { ok: true, file, entries: 0, corrupt: true, skipped: 0 }
    }
    let skipped = 0
    for (const record of /** @type {any[]} */ (/** @type {any} */ (parsed).entries)) {
      const entry = sanitizePendingEntry(record, now())
      if (entry === null) {
        skipped += 1
        continue
      }
      if (entries.has(entry.callId)) continue
      if (entries.size >= PENDING_LIMITS.entries) {
        skipped += 1
        continue
      }
      entries.set(entry.callId, entry)
    }
    if (skipped > 0) log('恢复清单里有 ' + String(skipped) + ' 条记录形状不合法，已忽略：' + file)
    return { ok: true, file, entries: entries.size, corrupt: false, skipped }
  }

  /**
   * 登记一条待恢复调用（同步落盘，早于任何检查点）。已存在的 callId 覆盖为最新值。
   * @param {{ callId?: unknown, jobId?: unknown, tool?: unknown, deadlineMs?: unknown }} record
   * @returns {null | {callId: string, jobId: string, tool: string, deadlineMs: number, recordedAt: number, owner: string}}
   */
  function add(record) {
    if (disabled) return null
    if (!loaded) load()
    const entry = sanitizePendingEntry(record, now())
    if (entry === null) {
      log('恢复清单拒绝一条形状不合法的记录（不回写）')
      return null
    }
    // 写入者身份由 store 决定，调用方不必关心；重启后这个字段就是"上一次 boot"的凭据。
    entry.owner = owner
    if (!entries.has(entry.callId) && entries.size >= PENDING_LIMITS.entries) {
      // 有界：淘汰最旧的一条。服务侧 holds 上限也是 64，超出时它自己也会拒；
      // 这里先丢最旧的，保证清单不会无限增长。
      let oldestId = null
      let oldestAt = Number.POSITIVE_INFINITY
      for (const [id, existing] of entries) {
        if (existing.recordedAt < oldestAt) {
          oldestAt = existing.recordedAt
          oldestId = id
        }
      }
      if (oldestId !== null) {
        entries.delete(oldestId)
        log('恢复清单已满（' + String(PENDING_LIMITS.entries) + '），淘汰最旧的一条：' + oldestId)
      }
    }
    entries.set(entry.callId, entry)
    persist()
    return entry
  }

  /**
   * 结算后删除。只有真的删掉了才落盘（避免无谓写）。
   * @param {unknown} callId
   * @returns {boolean}
   */
  function remove(callId) {
    if (disabled) return false
    if (!loaded) load()
    if (!nonEmptyString(callId)) return false
    if (!entries.delete(String(callId).trim().slice(0, PENDING_LIMITS.callIdChars))) return false
    persist()
    return true
  }

  /** @param {unknown} callId */
  function has(callId) {
    if (disabled) return false
    if (!loaded) load()
    return nonEmptyString(callId) && entries.has(String(callId).trim().slice(0, PENDING_LIMITS.callIdChars))
  }

  /** 按登记时间排序的副本。 */
  function list() {
    if (!loaded) load()
    return [...entries.values()].sort((left, right) => left.recordedAt - right.recordedAt).map((entry) => ({ ...entry }))
  }

  return {
    /** 清单绝对路径（`stateDir` 配置决定）。 */
    path: file,
    /** `stateDir` 为空时清单被禁用（只影响跨重启恢复，不影响 pod_exec 本身）。 */
    disabled,
    load,
    add,
    remove,
    has,
    list,
    snapshot,
  }
}

/**
 * 恢复扫描器。它只做三件事：查账本、调 `complete/fail`、维护清单；渲染交给注入的
 * `renderExec`（插件传的就是 `pod_exec` 自己用的那个函数，保证逐字节一致）。
 *
 * @param {object} options
 * @param {ReturnType<typeof createPendingStore>} options.store 待恢复清单。
 * @param {{ output: (hint: any, request: { jobId: string, from?: number, maxBytes?: number, adopt?: boolean }) => Promise<any> }} options.pod pod 客户端的只读投影（只要 `output`）。
 * @param {(response: any, aborted?: boolean) => { text: string }} options.renderExec `pod_exec` 的渲染函数。
 * @param {() => any} [options.hint] 只读 op 用的 policy hint（没有会话，取默认工作区）。
 * @param {() => { service: any, reason: string | null }} [options.resolveService] 每次扫描都重新解析服务（服务可能后到）。
 * @param {() => Promise<void>} [options.ready] 第一次读账本前等它（插件传 `pod.boot`）：
 *   与 boot 的首次连接错开，避免两个客户端同时连同一条管道。
 * @param {(message: string) => void} [options.log]
 * @param {() => number} [options.now]
 * @param {(ms: number) => Promise<void>} [options.sleep] 注入睡眠（自测用它换确定性）。
 * @param {number | (() => number)} [options.modelOutputLimitBytes] fixed window,
 *   or a getter re-read at each settlement (the plugin passes the live native
 *   `maxOutputBytes`; see `resolveLiveLimits` in index.js).
 * @param {string} [options.currentOwner] 本进程的写入者身份（默认 `process.pid`），
 *   清单里 `owner` 与它不同的条目才属于"上一次 boot"。
 * @param {number} [options.pollMinMs] @param {number} [options.pollMaxMs]
 * @param {number} [options.serviceAttempts] @param {number} [options.serviceRetryMs]
 * @param {number} [options.maxWaitMs]
 */
export function createExecRecovery(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const store = options.store ?? createPendingStore({ log })
  const pod = options.pod ?? null
  const renderExec = typeof options.renderExec === 'function' ? options.renderExec : () => ({ text: '' })
  const hint = typeof options.hint === 'function' ? options.hint : () => ({ sessionId: null })
  const resolveService = typeof options.resolveService === 'function'
    ? options.resolveService
    : () => ({ service: null, reason: '调用方没有提供 resumableToolCalls 解析器' })
  const ready = typeof options.ready === 'function' ? options.ready : null
  const currentOwner = boundString(options.currentOwner, PENDING_LIMITS.ownerChars) || String(process.pid)
  // The read window used to assemble the `complete` payload. A number keeps the
  // old contract (embedders/tests); a FUNCTION is re-evaluated on every
  // settlement because the plugin passes the LIVE native `maxOutputBytes`, and
  // a scan can run hours after the call it is answering.
  const fixedModelOutputLimitBytes =
    typeof options.modelOutputLimitBytes === 'number' && Number.isFinite(options.modelOutputLimitBytes) && options.modelOutputLimitBytes > 0
      ? Math.floor(options.modelOutputLimitBytes)
      : RECOVERY_DEFAULTS.modelOutputLimitBytes
  const modelOutputLimitBytes = typeof options.modelOutputLimitBytes === 'function'
    ? () => {
        let value = Number.NaN
        try {
          value = Number(options.modelOutputLimitBytes())
        } catch {
          value = Number.NaN
        }
        return Number.isFinite(value) && value > 0 ? Math.floor(value) : fixedModelOutputLimitBytes
      }
    : () => fixedModelOutputLimitBytes
  const pollMinMs = clampMs(options.pollMinMs, RECOVERY_DEFAULTS.pollMinMs)
  const pollMaxMs = Math.max(pollMinMs, clampMs(options.pollMaxMs, RECOVERY_DEFAULTS.pollMaxMs))
  const serviceAttempts = Number.isInteger(options.serviceAttempts) && options.serviceAttempts > 0
    ? options.serviceAttempts
    : RECOVERY_DEFAULTS.serviceAttempts
  const serviceRetryMs = clampMs(options.serviceRetryMs, RECOVERY_DEFAULTS.serviceRetryMs)
  const maxWaitMs = clampMs(options.maxWaitMs, RECOVERY_DEFAULTS.maxWaitMs)

  let started = false
  let disposed = false
  let loopRunning = false
  let startedAt = 0
  let lastOutcome = null
  let lastServiceReason = null
  /** 本 boot 激活前就在清单里的 callId：只有它们可能属于上一个 Host。 */
  /** @type {Set<string>} */
  let carried = new Set()
  /** @type {Promise<void>} */
  let done = Promise.resolve()
  /** @type {Set<() => void>} */
  const sleepers = new Set()
  /** 同一 (callId, 原因) 的失败只记一次日志，避免 12 小时里刷 1400 行。 */
  const loggedFailures = new Set()

  /** @param {number} ms */
  function defaultSleep(ms) {
    return new Promise((resolve) => {
      /** @type {{ wake: () => void }} */
      let handle
      const timer = setTimeout(() => {
        sleepers.delete(handle.wake)
        resolve()
      }, ms)
      if (typeof timer?.unref === 'function') timer.unref()
      handle = {
        wake: () => {
          clearTimeout(timer)
          sleepers.delete(handle.wake)
          resolve()
        },
      }
      sleepers.add(handle.wake)
    })
  }

  const sleep = typeof options.sleep === 'function' ? options.sleep : defaultSleep

  /** @param {string} key @param {string} message */
  function logFailureOnce(key, message) {
    if (loggedFailures.has(key)) return
    loggedFailures.add(key)
    log(message)
  }

  /** @returns {{ service: any, reason: string | null }} */
  function resolveOnce() {
    let resolution
    try {
      resolution = resolveService()
    } catch (error) {
      return { service: null, reason: '解析 resumableToolCalls 抛错：' + messageOf(error) }
    }
    const service = resolution?.service ?? null
    const reason = typeof resolution?.reason === 'string' ? resolution.reason : null
    if (service === null) {
      lastServiceReason = reason ?? 'Host 没有提供 resumableToolCalls'
      return { service: null, reason: lastServiceReason }
    }
    // A resolver that hands back half a service is worse than none: answering a
    // call needs complete/fail, keeping it alive needs hold.
    const missing = ['complete', 'fail'].filter((name) => typeof service[name] !== 'function')
    if (missing.length > 0) {
      lastServiceReason = 'resumableToolCalls 形状不完整（缺少 ' + missing.join('/') + '）'
      return { service: null, reason: lastServiceReason }
    }
    return { service, reason: lastServiceReason }
  }

  /** 服务可能比本插件更晚 `ctx.provide`（Loader 顺序），激活时有限次重试。 */
  async function resolveServiceWithRetry() {
    for (let attempt = 1; attempt <= serviceAttempts; attempt += 1) {
      if (disposed) return null
      const resolution = resolveOnce()
      if (resolution.service !== null) return resolution.service
      if (attempt < serviceAttempts) await sleep(serviceRetryMs)
    }
    return null
  }

  /**
   * 保持挂起活着。命令跑很久时服务的 deadline 绝不能中途到期（一到期它就补一条
   * `TOOL_OUTCOME_UNKNOWN`，与之后真实结果重复）。已经结算的挂起不复活。
   * @param {{ callId: string, jobId: string, deadlineMs: number }} entry
   * @param {any} service
   * @returns {'held' | 'refreshed' | 'absent' | 'settled' | 'failed'}
   */
  function refreshHold(entry, service) {
    let rows = null
    try {
      const snapshot = typeof service.status === 'function' ? service.status() : null
      rows = Array.isArray(snapshot?.holds) ? snapshot.holds : null
    } catch (error) {
      logFailureOnce('status:' + entry.callId, '恢复扫描：读 ' + entry.callId + ' 的挂起状态失败：' + messageOf(error))
      rows = null
    }
    if (rows !== null) {
      const row = rows.find((candidate) => candidate !== null && typeof candidate === 'object' && candidate.callId === entry.callId)
      if (row === undefined) return 'absent'
      if (row.status !== 'held') return 'settled'
      // 不每轮都重写服务的 holds 文件：只在预算过半时续一次（12h 的挂起约每 6h 一次）。
      const remaining = typeof row.deadlineAt === 'number' ? row.deadlineAt - now() : Number.NaN
      if (Number.isFinite(remaining) && remaining > entry.deadlineMs / 2) return 'held'
    }
    try {
      const returned = service.hold(entry.callId, { tool: entry.tool, hint: { jobId: entry.jobId }, deadlineMs: entry.deadlineMs })
      // 恢复期间一直持有；返回的 release 故意不调用（结算后由服务自己清）。
      void returned
      return 'refreshed'
    } catch (error) {
      logFailureOnce('hold:' + entry.callId, '恢复扫描：刷新 ' + entry.callId + ' 的挂起失败：' + messageOf(error))
      return 'failed'
    }
  }

  /**
   * 写回结果并（成功时）删清单条目。
   * @param {string} callId
   * @param {'complete' | 'fail'} kind
   * @param {any} value
   * @returns {Promise<{ kind: string, reason: string | null }>}
   */
  async function answer(service, callId, kind, value) {
    let outcome
    try {
      outcome = kind === 'complete'
        ? await service.complete(callId, value)
        : await service.fail(callId, value)
    } catch (error) {
      logFailureOnce(kind + ':' + callId + ':' + messageOf(error),
        '恢复扫描：' + kind + '(' + callId + ') 失败：' + messageOf(error))
      return { kind: 'retry', reason: messageOf(error) }
    }
    const applied = outcome?.applied === true
    const reason = typeof outcome?.reason === 'string' ? outcome.reason : ''
    // already-in-log：平台日志里已有这条调用的结果（服务按幂等跳过）；
    // unknown-call：服务不再持有它（已结算 / 换了 boot / 从未登记）。
    // 两种都说明"这条调用已经轮不到我们再回答"，清单条目没有意义，删掉。
    if (applied || reason === 'already-in-log' || reason === 'unknown-call') {
      store.remove(callId)
      log('恢复扫描：' + callId + ' → ' + kind +
        (applied ? '（已写入）' : '（服务未写入：' + (reason === '' ? '未知原因' : reason) + '）'))
      return { kind: kind === 'complete' ? 'completed' : 'failed', reason: reason === '' ? null : reason }
    }
    logFailureOnce('unconfirmed:' + callId + ':' + reason,
      '恢复扫描：' + callId + ' 的 ' + kind + ' 未被服务确认（' + (reason === '' ? '无原因' : reason) + '），下轮重试')
    return { kind: 'retry', reason: reason === '' ? '服务未确认' : reason }
  }

  /**
   * 结算一条：查账本 → 已结算就 complete；仍跑就刷新挂起；找不到就 fail。
   * @param {{ callId: string, jobId: string, tool: string, deadlineMs: number }} entry
   * @param {any} service
   * @returns {Promise<{ kind: string, reason: string | null }>}
   */
  async function settleEntry(entry, service) {
    if (pod === null || typeof pod.output !== 'function') {
      return { kind: 'retry', reason: 'pod 客户端不可用' }
    }
    /** @type {any} */
    let response
    try {
      // 与 pod_exec 的最后一次读完全同形：from 0，窗口 modelOutputLimitBytes。
      // 恢复扫描没有会话上下文（清单里只有 callId/jobId，hint 不带 sessionId），
      // 但它恢复的是"本调用自己的" job；如果原会话 id 已不可得，用 adopt: true
      // 显式接管（否则 pod 会按 EFOREIGNJOB 拒绝，恢复永远卡住）。
      response = await pod.output(hint(), { jobId: entry.jobId, from: 0, maxBytes: modelOutputLimitBytes(), adopt: true })
    } catch (error) {
      const code = String(/** @type {any} */ (error)?.code ?? '')
      if (code === 'ENOJOB') {
        const reason = 'pod_exec 的 pod job 在账本里不存在（ENOJOB）：' + entry.jobId + '；结果不可恢复'
        const settled = await answer(service, entry.callId, 'fail', reason)
        return settled.kind === 'retry' ? settled : { kind: 'failed', reason: 'ENOJOB' }
      }
      logFailureOnce('output:' + entry.callId + ':' + code + ':' + messageOf(error),
        '恢复扫描：读 ' + entry.jobId + ' 的账本失败：' + messageOf(error))
      return { kind: 'retry', reason: messageOf(error) }
    }
    const status = typeof response?.status === 'string' ? response.status : 'unknown'
    const running = response?.running === true || status === 'running' || status === 'stopping'
    if (running) {
      const refreshed = refreshHold(entry, service)
      if (refreshed === 'absent' || refreshed === 'settled') {
        store.remove(entry.callId)
        log('恢复扫描：' + entry.callId + ' 仍对应运行中的 ' + entry.jobId +
          '，但服务不再持有该调用（' + refreshed + '）；删掉清单条目，命令继续在 pod 里跑')
        return { kind: 'dropped', reason: refreshed }
      }
      return { kind: 'running', reason: null }
    }
    // 已结算：用与 pod_exec 相同的渲染函数构造结果（同一窗口、同一对齐、同一状态行）。
    const rendered = renderExec(response, false)
    const text = typeof rendered?.text === 'string' ? rendered.text : ''
    return await answer(service, entry.callId, 'complete', { content: [{ type: 'text', text }], isError: false })
  }

  /**
   * 扫一遍。`only` 用于"只结算上一个 boot 留下的条目"（本 boot 新登记的 `pod_exec`
   * 由它自己的 `completeAfterCommit` 负责，恢复扫描绝不抢答）。
   * @param {{ only?: Set<string> | null, service?: any }} [scanOptions]
   * @returns {Promise<{ ok: boolean, scanned: number, completed: number, failed: number, running: number, dropped: number, retrying: number, skipped: boolean, reason: string | null }>}
   */
  async function scan(scanOptions = {}) {
    const outcome = {
      ok: true,
      scanned: 0,
      completed: 0,
      failed: 0,
      running: 0,
      dropped: 0,
      retrying: 0,
      skipped: false,
      reason: null,
    }
    if (disposed) {
      outcome.skipped = true
      outcome.reason = '恢复扫描已停止'
      return outcome
    }
    const only = scanOptions.only instanceof Set ? scanOptions.only : null
    const entries = store.list().filter((entry) => only === null || only.has(entry.callId))
    if (entries.length === 0) return outcome
    let service = scanOptions.service ?? null
    if (service === null) {
      const resolution = resolveOnce()
      service = resolution.service
      if (service === null) {
        // 服务不可用：整段跳过（降级），清单原样保留，绝不假装结算过。
        outcome.skipped = true
        outcome.reason = lastServiceReason
        log('恢复扫描：resumableToolCalls 不可用（' + String(lastServiceReason) + '），跳过；清单保留待下次 boot')
        return outcome
      }
    }
    for (const entry of entries) {
      if (disposed) break
      outcome.scanned += 1
      /** @type {{ kind: string, reason: string | null }} */
      let result
      try {
        result = await settleEntry(entry, service)
      } catch (error) {
        log('恢复扫描：结算 ' + entry.callId + ' 抛错：' + messageOf(error))
        result = { kind: 'retry', reason: messageOf(error) }
      }
      switch (result.kind) {
        case 'completed':
          outcome.completed += 1
          break
        case 'failed':
          outcome.failed += 1
          break
        case 'running':
          outcome.running += 1
          break
        case 'dropped':
          outcome.dropped += 1
          break
        default:
          outcome.retrying += 1
          break
      }
    }
    lastOutcome = outcome
    return outcome
  }

  /**
   * 轮询循环：只要还有 running / retry 的条目就退避重扫；清单空了或到上限就停。
   * @param {any} service
   */
  async function run(service) {
    let interval = pollMinMs
    for (;;) {
      if (disposed) return
      if (now() - startedAt >= maxWaitMs) {
        log('恢复扫描：本次 boot 已达等待上限（' + String(maxWaitMs) + 'ms），剩余清单保留给下一次 boot')
        return
      }
      const outcome = await scan({ only: carried, service })
      if (disposed) return
      if (outcome.skipped === true) return
      if (outcome.running === 0 && outcome.retrying === 0) {
        log('恢复扫描：本轮结束（' + JSON.stringify(outcome) + '）')
        return
      }
      await sleep(interval)
      interval = Math.min(Math.round(interval * 1.5), pollMaxMs)
    }
  }

  /**
   * 插件激活时调用（同步部分只读清单，其余全部异步）。返回的对象是诊断快照，
   * `done` 在循环结束（或降级跳过）后 resolve，永不会 reject。
   * @returns {{ started: boolean, already: boolean, file: string, pending: number, carried: number, corrupt: boolean }}
   */
  function start() {
    if (started) {
      return {
        started: true,
        already: true,
        file: store.path,
        pending: store.list().length,
        carried: carried.size,
        corrupt: false,
      }
    }
    started = true
    startedAt = now()
    // 同步读清单：pod 客户端连上之前就知道"有没有东西要结算"。
    const loaded = store.load()
    const entries = store.list()
    // 只有**别的进程**写下的条目才可能是上一个 boot 的挂起。同一进程（插件 HMR 重载）
    // 刚登记的条目属于正在跑的 `pod_exec`，由它自己的 `completeAfterCommit` 结算；
    // 恢复扫描去碰它会给同一条调用写第二条 tool/result。
    const carriedEntries = entries.filter((entry) => entry.owner !== currentOwner)
    carried = new Set(carriedEntries.map((entry) => entry.callId))
    const summary = {
      started: true,
      already: false,
      file: store.path,
      pending: entries.length,
      carried: carriedEntries.length,
      corrupt: loaded.corrupt === true,
    }
    if (entries.length === 0) {
      log('恢复扫描：清单为空，没有待恢复的 ' + EXEC_TOOL_NAME + ' 调用')
      return summary
    }
    if (carriedEntries.length === 0) {
      log('恢复扫描：清单里 ' + String(entries.length) + ' 条都是本进程刚登记的（' + currentOwner + '），不结算，留给它们自己的 completeAfterCommit')
      return summary
    }
    log('恢复扫描：发现 ' + String(carriedEntries.length) + ' 条上次 boot 留下的待恢复调用，立即开始（' + store.path + '）')
    done = (async () => {
      // 等 pod 客户端连上再读账本：与 boot 的首次连接错开，避免两个客户端同时
      // 敲同一条管道（pod 的 single-client gate 会把第二个连上来的踢掉并记入审计）。
      if (ready !== null) {
        try {
          await ready()
        } catch (error) {
          log('恢复扫描：等待 pod 客户端就绪失败，仍继续尝试读账本：' + messageOf(error))
        }
      }
      if (disposed) return
      const service = await resolveServiceWithRetry()
      if (service === null) {
        log('恢复扫描：resumableToolCalls 不可用（' + String(lastServiceReason) + '），跳过；清单保留待下次 boot')
        return
      }
      loopRunning = true
      try {
        await run(service)
      } catch (error) {
        log('恢复扫描异常结束：' + messageOf(error))
      } finally {
        loopRunning = false
      }
    })().catch((error) => {
      log('恢复扫描异常结束：' + messageOf(error))
    })
    return summary
  }

  /** 只读诊断（JSON 安全，供 `pod_status` 用）。 */
  function status() {
    const entries = store.list()
    return {
      started,
      running: loopRunning,
      file: store.path,
      pending: entries.length,
      carried: entries.filter((entry) => entry.owner !== currentOwner).length,
      service: lastServiceReason,
      last: lastOutcome === null ? null : { ...lastOutcome },
    }
  }

  function dispose() {
    disposed = true
    for (const wake of [...sleepers]) {
      try {
        wake()
      } catch {
        // already resolved
      }
    }
    sleepers.clear()
  }

  return { start, scan, status, dispose, get done() { return done } }
}
