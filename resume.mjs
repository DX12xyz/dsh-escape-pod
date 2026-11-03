/**
 * `pod_exec` ↔ `resumableToolCalls` 桥。
 *
 * 服务由 `dsh-restart-bundle` ≥ 1.7.4-hotfix.4 在 Host 上 `ctx.provide('resumableToolCalls', …)`，
 * 只保证 `hold` / `complete` / `fail` / `status` 四个方法；它**可能不存在**（旧 bundle、未启用、
 * 或插件先于它加载），所以每次工具执行都重新 `ctx.get()` 并判空。
 *
 * 为什么这里不直接 `hold` → 等 → `complete`：
 *
 * `complete` / `fail` 的落地实现（restart-bundle `writeResumeResult`）在**会话日志里已经有这条
 * 调用的结果**时返回 `{ skipped: true }`，否则会**追加**一条新的 `tool/result`。而本 Host 里
 * 这次调用最终由平台的 agent loop 在 `execute()` 返回之后写它自己的 `tool/result`。如果插件在
 * 返回之前就 `complete`，日志里会出现同一条 `callId` 的两条结果（模型请求会带两个相同
 * `tool_call_id` 的 tool 消息）——这是会污染会话的写坏，不是"多一条日志"。
 *
 * 所以本模块的时序是：
 *
 *   hold(callId, …)                        ← 开始等待之前，同步落盘
 *   … 阻塞等待命令结算 …
 *   execute() 返回原生形状的结果
 *   session/event 观察到平台写下的 tool/result（同 callId）
 *   complete(callId, 原生形状的结果) / fail(callId, reason)   ← 此时只会被 skipped
 *
 * 若一直观察不到平台的结果事件（进程要退了、或事件作用域没覆盖到），调 `release()` 停止等待：
 * **不清挂起、不清清单、不写结果**。清掉的后果是实测过的：旧 Host 关机时把服务侧挂起和
 * `pending-exec.json` 条目一起删掉，新 Host 启动时清单是空的、job 还在跑却没人接，那次挂起
 * 白做了。只有"服务确认这条调用已结算"才删条目（`applied` / `already-in-log` / `unknown-call`）。
 *
 * 另一半（重启后谁去结算这条挂起）在 `recovery.mjs`：本模块通过可选的 `store` 参数把
 * `{callId, jobId, owner}` 同步写进 `<stateDir>/pending-exec.json`，新 Host 激活时读它、查账本、
 * 用与 `pod_exec` 完全相同的渲染函数 `complete`。没有 `store`（自测、或账本根不可写）时
 * 退化为"只挂起不恢复"：重启后的调用由服务写一条如实的"被挂起"结果，到期换成平台的
 * `TOOL_OUTCOME_UNKNOWN` 措辞。
 */

/** Host 服务的名字（restart-bundle `RESUME_SERVICE_NAME`）。 */
export const RESUME_SERVICE_NAME = 'resumableToolCalls'
/** 登记挂起时声明的工具名（恢复读方按它找 owner）。 */
export const EXEC_TOOL_NAME = 'pod_exec'
/**
 * 挂起的存活上限。本 Host 内它是"命令最长能跑多久"的上限（命令跑不完也会被服务判超时），
 * 重启后它是"结果未知"措辞替换"被挂起"的时间点。取 12 小时：前台命令的实际时长不可预知，
 * 而服务侧上限是 24 小时。
 */
export const EXEC_HOLD_DEADLINE_MS = 12 * 60 * 60 * 1000
/**
 * 重新登记挂起的间隔（远小于上面的上限）。前台调用真的可能跑很久，而服务的 deadline 定时器
 * 一旦在等待期间到期，会**追加**一条结果（那时平台还没写结果）→ 与随后平台写的结果重复。
 * 只要命令还在跑就刷新一次，`deadlineAt` 永远不会在等待期间到期。
 */
export const EXEC_HOLD_REFRESH_MS = 30 * 60 * 1000
/** 等平台写 tool/result 的观察窗口；观察不到就停等（不清挂起、不清恢复条目）。 */
export const RESULT_COMMIT_TIMEOUT_MS = 60 * 1000

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * 解析可选的 `resumableToolCalls` 服务。
 * @param {any} ctx Host 插件上下文（可能没有 `get`）
 * @returns {{ service: any, reason: string | null }}
 */
export function resolveResumeService(ctx) {
  if (ctx === null || ctx === undefined || typeof ctx.get !== 'function') {
    return { service: null, reason: 'Host 上下文没有 ctx.get，无法查询 ' + RESUME_SERVICE_NAME }
  }
  let service
  try {
    service = ctx.get(RESUME_SERVICE_NAME)
  } catch (error) {
    return { service: null, reason: 'ctx.get("' + RESUME_SERVICE_NAME + '") 抛错：' + messageOf(error) }
  }
  if (service === null || service === undefined) {
    return { service: null, reason: 'Host 没有提供 ' + RESUME_SERVICE_NAME + '（restart-bundle 早于 1.7.4-hotfix.4，或该 bundle 未启用）' }
  }
  const missing = ['hold', 'complete', 'fail'].filter((name) => typeof service[name] !== 'function')
  if (missing.length > 0) {
    return { service: null, reason: RESUME_SERVICE_NAME + ' 形状不完整（缺少 ' + missing.join('/') + '）' }
  }
  return { service, reason: null }
}

/**
 * 等平台把这条调用自己的 `tool/result` 写进会话日志，然后执行回调。
 *
 * 平台事件是 `session/event`（`(session, event)`，`event.type === 'tool/result'`）；本插件注册在
 * Host 作用域，因此不是 agent 作用域监听，能看到所有会话的事件。拿不到 `ctx.on`、或订阅失败、
 * 或窗口内没等到，都走 `timedOut`（调用方用它 `release`，绝不抢先写结果）。
 *
 * @param {any} ctx Host 插件上下文
 * @param {string} callId 平台工具调用 id
 * @param {{ committed?: () => void, timedOut?: () => void }} handlers
 * @param {{ timeoutMs?: number, log?: (message: string) => void }} [options]
 * @returns {() => void} 取消（等价于立即走 `timedOut`）
 */
export function afterToolResultCommit(ctx, callId, handlers, options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? Math.floor(options.timeoutMs)
    : RESULT_COMMIT_TIMEOUT_MS
  const onCommitted = typeof handlers?.committed === 'function' ? handlers.committed : () => {}
  const onTimedOut = typeof handlers?.timedOut === 'function' ? handlers.timedOut : () => {}
  const id = typeof callId === 'string' ? callId : ''
  let finished = false
  /** @type {null | (() => void)} */
  let dispose = null
  /** @type {any} */
  let timer = null
  /** @param {'committed' | 'timedOut'} kind */
  const finish = (kind) => {
    if (finished) return
    finished = true
    if (timer !== null) {
      try {
        clearTimeout(timer)
      } catch {
        /* already fired */
      }
      timer = null
    }
    const detach = dispose
    dispose = null
    if (typeof detach === 'function') {
      try {
        detach()
      } catch {
        /* already disposed */
      }
    }
    try {
      if (kind === 'committed') onCommitted()
      else onTimedOut()
    } catch (error) {
      log('工具结果观察回调失败：' + messageOf(error))
    }
  }
  if (id === '' || ctx === null || ctx === undefined || typeof ctx.on !== 'function') {
    // 无法观察平台结果：宁可不结算挂起，也绝不抢先写第二条 tool/result。
    finish('timedOut')
    return () => {}
  }
  /** @param {any} event */
  const matches = (event) => {
    if (event === null || typeof event !== 'object' || event.type !== 'tool/result') return false
    const message = event.data?.message
    return String(message?.toolCallId ?? '') === id || String(message?.source?.callId ?? '') === id
  }
  try {
    const returned = ctx.on('session/event', (_session, event) => {
      if (matches(event)) finish('committed')
    })
    dispose = typeof returned === 'function' ? returned : null
  } catch (error) {
    log('订阅 session/event 失败：' + messageOf(error))
    dispose = null
  }
  if (dispose === null) {
    finish('timedOut')
    return () => {}
  }
  timer = setTimeout(() => finish('timedOut'), timeoutMs)
  if (timer !== null && typeof timer.unref === 'function') timer.unref()
  return () => finish('timedOut')
}

/**
 * 为一条 `pod_exec` 调用登记可跨重启的挂起。
 *
 * 返回的 handle 永远可用（服务缺失时是一组空操作），调用方不必再判空：
 *
 *   { available, held, reason, tool, callId, deadlineMs,
 *     release(), refresh(), completeAfterCommit(payload), failAfterCommit(reason) }
 *
 * @param {any} ctx Host 插件上下文
 * @param {{ callId?: string, jobId?: string, deadlineMs?: number, log?: (message: string) => void, store?: any, isDisposing?: () => boolean }} options
 *   `store` 是 `createPendingStore()` 的实例：挂起登记成功后同步写 `{callId, jobId}`，
 *   **只有确认这条调用已结算时才删除**（`release()` 绝不删，见下）。
 *   `isDisposing` 由插件提供：Host 正在关闭时返回 true。
 */
export function createExecHold(ctx, options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const store = options.store ?? null
  const isDisposing = typeof options.isDisposing === 'function' ? options.isDisposing : () => false
  const callId = typeof options.callId === 'string' ? options.callId.trim() : ''
  const jobId = typeof options.jobId === 'string' ? options.jobId.trim() : ''
  const deadlineMs = Number.isFinite(options.deadlineMs) && options.deadlineMs > 0
    ? Math.floor(options.deadlineMs)
    : EXEC_HOLD_DEADLINE_MS
  const resolution = resolveResumeService(ctx)
  /**
   * `hold()` 返回的 release 句柄。**故意不调用**：服务侧挂起是"重启后既不补
   * `TOOL_OUTCOME_UNKNOWN`、又能让新 Host 补回真实结果"的唯一凭据。旧实现会在
   * "没观察到平台的 tool/result"时调它，实测的后果是：旧 Host 关机时把挂起和
   * 待恢复条目一起删掉，新 Host 清单为空、job 还在跑却没人接。
   */
  /** @type {null | (() => void)} */
  let releaseHold = null
  let released = false
  /**
   * 待恢复清单的写入点是"挂起真的登记成功之后"：清单里出现一条 callId，就意味着
   * 上一次 boot 欠它一条结果。写失败只是少了后半程，绝不能让本次调用失败。
   * @param {'add' | 'remove'} kind
   */
  const remember = (kind) => {
    if (store === null) return
    try {
      if (kind === 'add') store.add?.({ callId, jobId, tool: EXEC_TOOL_NAME, deadlineMs })
      else store.remove?.(callId)
    } catch (error) {
      log('待恢复清单更新失败（' + callId + '）：' + messageOf(error))
    }
  }
  /**
   * 服务回什么才算"这条调用已经被结算、清单条目可以删"。只有这些情况才删：
   * 真写进去了（`applied`）、会话日志里已有结果（`already-in-log`）、服务不再持有它
   * （`unknown-call` / `already-settled`）。抛错 / 未确认一律保留，交给下一个 Host
   * 的恢复扫描重试。
   * @param {any} outcome
   */
  function settledOutcome(outcome) {
    if (outcome === null || typeof outcome !== 'object') return false
    if (outcome.applied === true) return true
    const reason = typeof outcome.reason === 'string' ? outcome.reason : ''
    if (reason === 'already-in-log' || reason === 'unknown-call' || reason === 'already-settled') return true
    const status = typeof outcome.status === 'string' ? outcome.status : ''
    return status === 'completed' || status === 'failed' || status === 'observed'
  }
  const handle = {
    available: resolution.service !== null,
    held: false,
    reason: resolution.reason,
    tool: EXEC_TOOL_NAME,
    callId,
    deadlineMs,
    /**
     * Stop waiting. 不是"结算"，所以两者都不清理：
     * - 服务侧挂起保留（新 Host 靠它避免 `TOOL_OUTCOME_UNKNOWN` 并刷新 deadline）；
     * - 待恢复条目保留（若平台确实写了结果，下一个 Host 的恢复扫描会以
     *   `already-in-log` 收尾；若没写，正好由它补真实结果）。
     * Host 关闭时尤其不能动——那是恢复半程唯一的凭据。
     */
    release() {
      if (released) return
      released = true
      const disposing = isDisposing()
      log(
        EXEC_TOOL_NAME + ' 挂起 ' + callId + (disposing ? '：Host 正在关闭' : '：停止等待') +
        '，服务侧挂起与待恢复条目都保留（交给下一个 Host 的恢复扫描）',
      )
      if (disposing) {
        // Give the next Host a full recovery window even if this command has
        // been running for hours: refresh (never release) the hold on the way
        // out. Refuses nothing — a settled hold just ends up 'observed' on the
        // next boot because a result already exists in the session log.
        try {
          resolution.service?.hold?.(callId, { tool: EXEC_TOOL_NAME, hint: { jobId }, deadlineMs })
        } catch (error) {
          log('关机前刷新 ' + EXEC_TOOL_NAME + ' 挂起失败（' + callId + '）：' + messageOf(error))
        }
      }
    },
    /**
     * Re-register the hold (the service refreshes `deadlineAt` and re-persists) so
     * the deadline can never fire while the command is still being waited on.
     * Refuses to resurrect a hold this boot already settled.
     * @returns {boolean} whether the hold is still live
     */
    refresh() {
      if (!handle.held || released) return false
      try {
        const snapshot = typeof resolution.service.status === 'function' ? resolution.service.status() : null
        const row = Array.isArray(snapshot?.holds) ? snapshot.holds.find((entry) => entry?.callId === callId) : undefined
        if (row !== undefined && row !== null && row.status !== 'held') {
          handle.held = false
          return false
        }
      } catch {
        // status is diagnostics only; refreshing is still the safe direction.
      }
      try {
        const returned = resolution.service.hold(callId, { tool: EXEC_TOOL_NAME, hint: { jobId }, deadlineMs })
        if (typeof returned === 'function') releaseHold = returned
        return true
      } catch (error) {
        log('刷新 ' + EXEC_TOOL_NAME + ' 挂起失败（' + callId + '）：' + messageOf(error))
        return false
      }
    },
    /** @param {any} _payload */
    completeAfterCommit(_payload) {},
    /** @param {string} _reason */
    failAfterCommit(_reason) {},
  }
  if (resolution.service === null) return handle
  if (callId === '') {
    handle.reason = '执行上下文没有 callId，无法登记可跨重启的挂起'
    return handle
  }
  if (jobId === '') {
    handle.reason = '没有 pod jobId，无法登记可跨重启的挂起'
    return handle
  }
  try {
    const returned = resolution.service.hold(callId, { tool: EXEC_TOOL_NAME, hint: { jobId }, deadlineMs })
    releaseHold = typeof returned === 'function' ? returned : null
    handle.held = true
    handle.reason = null
    // 与 `hold` 一样同步落盘：这份清单必须在任何检查点之前就在磁盘上。
    remember('add')
  } catch (error) {
    handle.reason = 'hold 失败：' + messageOf(error)
    return handle
  }
  /**
   * 平台写下本次调用自己的结果之后再结算挂起（见文件头注释）。
   * @param {'complete' | 'fail'} kind @param {any} value
   */
  const settleAfterCommit = (kind, value) => {
    afterToolResultCommit(ctx, callId, {
      committed: () => {
        let pending
        try {
          pending = kind === 'complete'
            ? resolution.service.complete(callId, value)
            : resolution.service.fail(callId, value)
        } catch (error) {
          log(EXEC_TOOL_NAME + ' 挂起 ' + kind + ' 抛错（' + callId + '）：' + messageOf(error))
          // 服务没确认 = 这条调用还没被结算（Host 正在关闭时最常见的形态）。
          // 条目必须留着：新 Host 要靠它读账本、补回真实结果。
          log(EXEC_TOOL_NAME + ' 挂起 ' + callId + ' 的恢复条目保留，交给下一个 Host')
          return
        }
        Promise.resolve(pending).then(
          (outcome) => {
            log(EXEC_TOOL_NAME + ' 挂起 ' + kind + '(' + callId + ') → ' + JSON.stringify(outcome ?? null))
            if (settledOutcome(outcome)) remember('remove')
            else log(EXEC_TOOL_NAME + ' 挂起 ' + callId + ' 未被服务确认，恢复条目保留，交给下一个 Host')
          },
          (error) => {
            log(EXEC_TOOL_NAME + ' 挂起 ' + kind + ' 失败（' + callId + '）：' + messageOf(error))
            log(EXEC_TOOL_NAME + ' 挂起 ' + callId + ' 的恢复条目保留，交给下一个 Host')
          },
        )
      },
      timedOut: () => {
        // 不能补写第二条 tool/result，也不能清掉凭据：停等即可。
        handle.release()
      },
    }, { log })
  }
  handle.completeAfterCommit = (payload) => settleAfterCommit('complete', payload)
  handle.failAfterCommit = (reason) => settleAfterCommit('fail', typeof reason === 'string' ? reason : String(reason ?? ''))
  return handle
}
