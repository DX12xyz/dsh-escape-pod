/**
 * Freeze mode: what the pod does when DSH disappears.
 *
 * The pod outlives the Host on purpose, so "DSH is gone" is not an error — it
 * is the normal case this policy exists for. The rules are fixed by
 * `settings.json` (see settings.mjs) and implemented here as a PURE state
 * machine: every clock, timer, settings read and job operation is injected, so
 * `test/pod-freeze-policy.test.mjs` can drive an entire 30-minute episode
 * without a pipe, a koffi binding or a real `setTimeout`.
 *
 *   idle --clientDisconnected()--> grace --10s--> frozen --watchdog--> ...
 *     ^                              |                 |
 *     |                              | clientConnected()| clientConnected()
 *     +------------------------------+-----------------+
 *     |                                                |
 *     +-- (regenerations left) thaw + immediate refreeze, watchdog re-armed
 *     +-- (exhausted)            kill every job, then exit the pod process
 *
 * The policy never touches process state itself. The pod supplies:
 *   readSettings()      -> { freezeMode, freezeMinutes, regenerations }
 *   listRunningJobs()   -> [{ jobId, frozen, autoFrozen }]
 *   freezeJob(jobId, { maxFreezeMs, by }) -> { ok, code?, message? }
 *   thawJob(jobId, reason)               -> { ok, code?, message? }
 *   killAll(reason)                      -> number | Promise<number>
 *   log(message)                         -> appended to <dataRoot>/pod.log
 *   exit(code)                           -> process.exit(...), after the kills
 *   hasClients()                         -> true while a pipe client is admitted
 *   onIdle(reason)                       -> the policy went back to idle (or
 *                                           never left it); the pod uses this to
 *                                           exit when no client and no job is left
 *   now(), setTimeout(fn, ms), clearTimeout(timer)
 *
 * Only the jobs this policy froze are ever thawed by it: `autoFrozen` is the
 * record flag the service sets on a successful auto-freeze and clears on a
 * manual `pod_freeze`, so a manual freeze made while DSH is away is never
 * undone here. `meta.json.freeze` is written by the freeze controller alone —
 * this module only calls freeze/thaw and logs.
 */

/** Grace between "the last authenticated client disconnected" and the freeze. */
export const FREEZE_GRACE_MS = 10_000
/**
 * Extra time added to the controller's own `maxFreezeMs` watchdog. The policy
 * must win the race: if the controller thawed first, an episode would end
 * silently and the regeneration/self-destruct accounting would never run.
 */
export const FREEZE_WATCHDOG_MARGIN_MS = 30_000
/** Exit code of a freeze-mode self-destruct (kills are the point, not an error). */
export const FREEZE_SELF_DESTRUCT_EXIT_CODE = 0
/**
 * How long a watchdog decision waits when a client socket is admitted but has
 * not authenticated yet. A Host that reconnects at the exact watchdog tick is
 * mid-handshake for a few milliseconds; regenerating or self-destructing under
 * it would kill the very jobs this mode exists to protect. A socket that stays
 * unauthenticated does NOT cancel the policy: the decision is only deferred once.
 */
export const FREEZE_CLIENT_SETTLE_MS = 2_000

/**
 * `setTimeout` stores its delay in a signed 32-bit integer; a larger value fires
 * almost immediately. freezeMinutes is already clamped to 1..1440 by
 * settings.mjs, so this only guards a hand-built dependency.
 */
const MAX_TIMER_MS = 2_147_483_647
/** Minutes are clamped 1..1440 by settings.mjs; repeat the bound locally. */
const FREEZE_MINUTES_MIN = 1
const FREEZE_MINUTES_MAX = 1440
/** Regenerations are clamped 0..3 by settings.mjs; repeat the bound locally. */
const REGENERATIONS_MAX = 3

/** @typedef {'idle' | 'grace' | 'frozen' | 'destroying' | 'disposed'} FreezePhase */

/**
 * The `maxFreezeMs` to hand the freeze controller for an episode of
 * `minutes`. Deliberately a little longer than the episode: the policy's own
 * watchdog has to fire first so regeneration/self-destruct stay authoritative.
 *
 * @param {unknown} minutes
 * @param {unknown} [marginMs]
 * @returns {number}
 */
export function freezeMaxForMinutes(minutes, marginMs = FREEZE_WATCHDOG_MARGIN_MS) {
  const parsed = Number(minutes)
  const safeMinutes = Number.isFinite(parsed)
    ? Math.min(FREEZE_MINUTES_MAX, Math.max(FREEZE_MINUTES_MIN, Math.trunc(parsed)))
    : 30
  const parsedMargin = Number(marginMs)
  const margin = Number.isFinite(parsedMargin) ? Math.max(0, Math.trunc(parsedMargin)) : 0
  return Math.min(MAX_TIMER_MS, safeMinutes * 60_000 + margin)
}

/**
 * @param {unknown} value
 * @returns {number}
 */
export function normalizeRegenerations(value) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return 0
  return Math.min(REGENERATIONS_MAX, Math.max(0, Math.trunc(parsed)))
}

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isRecord(value) {
  return value !== null && typeof value === 'object'
}

/**
 * Build one policy instance. There is exactly one per pod process, created by
 * `serve()`; the socket layer forwards authenticate/disconnect transitions and
 * the service supplies the job primitives.
 *
 * @param {{
 *   readSettings?: () => { freezeMode?: boolean, freezeMinutes?: number, regenerations?: number } | null,
 *   listRunningJobs?: () => Array<{ jobId?: unknown, frozen?: boolean, autoFrozen?: boolean }>,
 *   freezeJob?: (jobId: string, options: { maxFreezeMs: number, by: string }) => { ok?: boolean, code?: string, message?: string } | null,
 *   thawJob?: (jobId: string, reason: string) => { ok?: boolean, code?: string, message?: string } | null,
 *   killAll?: (reason: string) => number | Promise<number>,
 *   log?: (message: string) => void,
 *   exit?: (code: number) => void,
 *   hasClients?: () => boolean,
 *   onIdle?: (reason: string) => void,
 *   now?: () => number,
 *   setTimeout?: (callback: () => void, delayMs: number) => any,
 *   clearTimeout?: (timer: any) => void,
 *   graceMs?: number,
 *   clientSettleMs?: number,
 * }} [deps]
 */
export function createFreezePolicy(deps = {}) {
  const now = typeof deps.now === 'function' ? deps.now : () => Date.now()
  const setTimeoutFn = typeof deps.setTimeout === 'function' ? deps.setTimeout : setTimeout
  const clearTimeoutFn = typeof deps.clearTimeout === 'function' ? deps.clearTimeout : clearTimeout
  const readSettingsFn = typeof deps.readSettings === 'function' ? deps.readSettings : () => null
  const listRunningJobsFn = typeof deps.listRunningJobs === 'function' ? deps.listRunningJobs : () => []
  const freezeJobFn = typeof deps.freezeJob === 'function' ? deps.freezeJob : () => ({ ok: false, code: 'ENOHOOK', message: '没有注入 freezeJob' })
  const thawJobFn = typeof deps.thawJob === 'function' ? deps.thawJob : () => ({ ok: false, code: 'ENOHOOK', message: '没有注入 thawJob' })
  const killAllFn = typeof deps.killAll === 'function' ? deps.killAll : async () => 0
  const logFn = typeof deps.log === 'function' ? deps.log : () => {}
  const exitFn = typeof deps.exit === 'function' ? deps.exit : (code) => process.exit(code)
  const hasClientsFn = typeof deps.hasClients === 'function' ? deps.hasClients : () => false
  const onIdleFn = typeof deps.onIdle === 'function' ? deps.onIdle : () => {}
  const requestedGrace = Number(deps.graceMs)
  const graceMs = Number.isFinite(requestedGrace) && requestedGrace >= 0
    ? Math.min(MAX_TIMER_MS, Math.trunc(requestedGrace))
    : FREEZE_GRACE_MS
  const requestedSettle = Number(deps.clientSettleMs)
  const clientSettleMs = Number.isFinite(requestedSettle) && requestedSettle >= 0
    ? Math.min(MAX_TIMER_MS, Math.trunc(requestedSettle))
    : FREEZE_CLIENT_SETTLE_MS

  /** @type {FreezePhase} */
  let phase = 'idle'
  /** @type {any} */
  let graceTimer = null
  /** @type {any} */
  let watchdogTimer = null
  /**
   * The current episode, or null when idle. `jobIds` holds only jobs this
   * policy froze successfully and has not thawed yet.
   * @type {{ jobIds: Set<string>, regenerationsBudget: number, regenerationsUsed: number, startedAt: number, watchdogAt: number | null, freezeMinutes: number, clientDeferrals: number } | null}
   */
  let episode = null
  /** Last successfully read settings, for `snapshot()` only. @type {any} */
  let lastSettings = null
  /** Pending self-destruct, so a test can await the kills before asserting exit. @type {Promise<void> | null} */
  let pending = null
  let exited = false

  /** Never let a broken dependency throw out of a timer callback. */
  function log(message) {
    try {
      logFn(message)
    } catch {
      // logging is best-effort
    }
  }

  /**
   * Announce "the policy is idle and owns nothing right now". The pod's only
   * use is its lifecycle rule (no client + no job + no episode -> exit), but
   * the decision stays OUT of this module: the policy knows nothing about
   * process lifetime. Never throws and never re-enters a timer.
   * @param {string} reason
   */
  function notifyIdle(reason) {
    if (phase !== 'idle') return
    try {
      onIdleFn(reason)
    } catch (error) {
      log('freeze-mode：onIdle 回调失败（' + reason + '）：' + messageOf(error))
    }
  }

  /** @param {any} timer */
  function cancel(timer) {
    if (timer === null || timer === undefined) return
    try {
      clearTimeoutFn(timer)
    } catch {
      // already gone
    }
  }

  /**
   * Arm an unref'd timer. Unref is deliberate: a pending grace/watchdog timer
   * must never be the reason a pod process stays alive, exactly like the job
   * deadline timers. The listening server keeps the process up while there is
   * anything to protect.
   * @param {() => void} callback
   * @param {number} delayMs
   * @returns {any}
   */
  function schedule(callback, delayMs) {
    const delay = Math.max(1, Math.min(MAX_TIMER_MS, Math.trunc(Number(delayMs) || 0)))
    const timer = setTimeoutFn(callback, delay)
    if (isRecord(timer) && typeof timer.unref === 'function') {
      try {
        timer.unref()
      } catch {
        // unref is an optimisation, never a requirement
      }
    }
    return timer
  }

  /**
   * Re-read settings. A throwing/broken reader answers null, which the policy
   * treats as "disabled": an unreadable policy file must fail OPEN (jobs keep
   * running) rather than freeze or kill without a mandate.
   * @returns {{ freezeMode: boolean, freezeMinutes: number, regenerations: number } | null}
   */
  function settingsNow() {
    let value
    try {
      value = readSettingsFn()
    } catch (error) {
      log('freeze-mode：读取 settings 失败，按未启用处理：' + messageOf(error))
      return null
    }
    if (!isRecord(value)) return null
    lastSettings = value
    return /** @type {any} */ (value)
  }

  /** @param {any} settings */
  function disabled(settings) {
    // There is no `enabled` switch any more (see settings.mjs): freeze mode is
    // the only mandate. A legacy file that still carries `enabled:false` is
    // deliberately ignored, so an old settings file keeps working.
    return settings === null || settings.freezeMode !== true
  }

  /** @returns {Array<{ jobId: string, frozen: boolean, autoFrozen: boolean }>} */
  function jobsNow() {
    let rows
    try {
      rows = listRunningJobsFn()
    } catch (error) {
      log('freeze-mode：枚举运行中的 job 失败：' + messageOf(error))
      return []
    }
    if (!Array.isArray(rows)) return []
    /** @type {Array<{ jobId: string, frozen: boolean, autoFrozen: boolean }>} */
    const normalized = []
    for (const row of rows) {
      if (!isRecord(row) || typeof row.jobId !== 'string' || row.jobId === '') continue
      normalized.push({
        jobId: row.jobId,
        frozen: row.frozen === true,
        // A row that predates the flag is treated as auto only when it is
        // frozen; the pod adapter always sets it explicitly.
        autoFrozen: row.autoFrozen !== false,
      })
    }
    return normalized
  }

  /**
   * Freeze every running, not-yet-frozen job. Frozen jobs (manual or leftover)
   * are skipped and counted: a manual `pod_freeze` must never be re-frozen or
   * re-labelled by this policy.
   * @param {any} settings
   * @returns {Set<string>}
   */
  function freezeCandidates(settings) {
    const rows = jobsNow()
    const frozen = new Set()
    let skippedFrozen = 0
    for (const row of rows) {
      if (row.frozen === true) {
        skippedFrozen += 1
        continue
      }
      let outcome
      try {
        outcome = freezeJobFn(row.jobId, {
          maxFreezeMs: freezeMaxForMinutes(settings.freezeMinutes),
          by: 'freeze-mode',
        })
      } catch (error) {
        outcome = { ok: false, code: 'ETHROW', message: messageOf(error) }
      }
      if (outcome !== null && typeof outcome === 'object' && outcome.ok === true) {
        frozen.add(row.jobId)
        log('freeze-mode：job ' + row.jobId + ' 已冻结（看门狗 ' + String(settings.freezeMinutes) + ' 分钟）')
      } else {
        const code = isRecord(outcome) && typeof outcome.code === 'string' ? outcome.code : 'EUNKNOWN'
        const message = isRecord(outcome) && typeof outcome.message === 'string' ? outcome.message : '冻结失败'
        log('freeze-mode：跳过 job ' + row.jobId + '（' + code + '：' + message + '）')
      }
    }
    if (skippedFrozen > 0) {
      log('freeze-mode：跳过 ' + String(skippedFrozen) + ' 个已冻结（手动）job')
    }
    return frozen
  }

  /**
   * Thaw the jobs this episode froze. The pod-side thaw refuses anything that
   * was re-labelled manual, and its failure is logged but never fatal: the
   * freeze controller's own `maxFreezeMs` watchdog is the backstop.
   * @param {string} reason
   * @returns {number} how many jobs were thawed
   */
  function thawEpisode(reason) {
    if (episode === null) return 0
    let thawed = 0
    for (const jobId of [...episode.jobIds]) {
      let outcome
      try {
        outcome = thawJobFn(jobId, reason)
      } catch (error) {
        outcome = { ok: false, code: 'ETHROW', message: messageOf(error) }
      }
      if (outcome !== null && typeof outcome === 'object' && outcome.ok === true) {
        episode.jobIds.delete(jobId)
        thawed += 1
        log('freeze-mode：job ' + jobId + ' 已解冻（' + reason + '）')
      } else {
        const code = isRecord(outcome) && typeof outcome.code === 'string' ? outcome.code : 'EUNKNOWN'
        const message = isRecord(outcome) && typeof outcome.message === 'string' ? outcome.message : '解冻失败'
        log('freeze-mode：job ' + jobId + ' 未解冻（' + code + '：' + message + '）')
      }
    }
    return thawed
  }

  /** @param {number} minutes */
  function armWatchdog(minutes) {
    cancel(watchdogTimer)
    watchdogTimer = null
    if (episode === null) return
    // A fresh episode gets its one deferral back (see onWatchdog).
    episode.clientDeferrals = 0
    const parsed = Number(minutes)
    const safeMinutes = Number.isFinite(parsed)
      ? Math.min(FREEZE_MINUTES_MAX, Math.max(FREEZE_MINUTES_MIN, Math.trunc(parsed)))
      : 30
    const delay = Math.min(MAX_TIMER_MS, safeMinutes * 60_000)
    episode.watchdogAt = now() + delay
    watchdogTimer = schedule(onWatchdog, delay)
  }

  /**
   * @param {string} reason
   * @param {string} [message]
   */
  function endEpisode(reason, message) {
    cancel(watchdogTimer)
    watchdogTimer = null
    const had = episode !== null
    episode = null
    phase = 'idle'
    if (had) log('freeze-mode：本轮结束（' + reason + '）' + (message === undefined ? '' : '：' + message))
    notifyIdle('episode:' + reason)
  }

  /** Grace timer fired: freeze everything that can be frozen. */
  function onGrace() {
    graceTimer = null
    if (phase !== 'grace') return
    const settings = settingsNow()
    if (disabled(settings)) {
      log('freeze-mode：宽限期到点时设置已关闭（freezeMode），不冻结')
      phase = 'idle'
      notifyIdle('grace-settings-off')
      return
    }
    const candidates = jobsNow().filter((row) => row.frozen !== true)
    if (candidates.length === 0) {
      log('freeze-mode：宽限期到点，但没有正在运行且未冻结的 job：不进入冻结')
      phase = 'idle'
      notifyIdle('grace-no-jobs')
      return
    }
    const frozen = freezeCandidates(settings)
    if (frozen.size === 0) {
      log('freeze-mode：宽限期到点，但没有 job 冻结成功：策略停止')
      phase = 'idle'
      notifyIdle('grace-freeze-failed')
      return
    }
    episode = {
      jobIds: frozen,
      regenerationsBudget: normalizeRegenerations(settings.regenerations),
      regenerationsUsed: 0,
      startedAt: now(),
      watchdogAt: null,
      freezeMinutes: Number(settings.freezeMinutes),
      clientDeferrals: 0,
    }
    phase = 'frozen'
    const budget = episode.regenerationsBudget
    log(
      'freeze-mode：DSH 已断开，已冻结 ' + String(frozen.size) + ' 个 job；' +
      String(settings.freezeMinutes) + ' 分钟后' + (budget > 0 ? '再生（剩 ' + String(budget) + ' 次）' : '自毁'),
    )
    armWatchdog(settings.freezeMinutes)
  }

  /** Policy watchdog fired: regenerate, self-destruct, or stand down. */
  function onWatchdog() {
    watchdogTimer = null
    if (phase !== 'frozen' || episode === null) return

    // Every decision below re-reads the file: an operator may have flipped
    // freezeMode while DSH was away, and that must stop the policy.
    const settings = settingsNow()
    if (disabled(settings)) {
      log('freeze-mode：看门狗到点时设置已关闭（freezeMode），解冻自动冻结的 job 并停止策略')
      thawEpisode('settings-off')
      endEpisode('settings-off')
      return
    }
    // A client socket admitted just before this timer fired may be a returning
    // DSH that has not authenticated yet. Defer the decision ONCE, briefly: an
    // authenticated reconnect cancels the episode in that window, while a
    // lingering unauthenticated socket cannot stop regeneration/self-destruct.
    if (hasClientsFn() === true && episode !== null && episode.clientDeferrals === 0) {
      episode.clientDeferrals = 1
      episode.watchdogAt = now() + clientSettleMs
      watchdogTimer = schedule(onWatchdog, clientSettleMs)
      log(
        'freeze-mode：看门狗到点时有尚未认证的客户端连接，先等待 ' + String(clientSettleMs) +
        'ms 确认是否 DSH 回来（不解除冻结）',
      )
      return
    }

    // The episode only owns jobs that are still running AND still auto-frozen.
    // A job that finished, or one a client re-labelled as a manual freeze, must
    // not keep the policy alive (and must never be thawed here).
    const still = jobsNow().filter((row) => episode !== null && episode.jobIds.has(row.jobId) && row.frozen === true && row.autoFrozen === true)
    if (still.length === 0) {
      log('freeze-mode：自动冻结的 job 已全部结束或转为手动冻结，本轮无需再生/自毁')
      endEpisode('no-jobs')
      return
    }

    if (episode !== null && episode.regenerationsUsed < episode.regenerationsBudget) {
      const previous = episode.jobIds.size
      const used = episode.regenerationsUsed + 1
      const budget = episode.regenerationsBudget
      thawEpisode('regeneration')
      if (episode !== null) episode.regenerationsUsed = used
      // "Instant thaw then freeze again": same synchronous pass, fresh deadline.
      const again = freezeCandidates(settings)
      if (again.size === 0) {
        log('freeze-mode：再生时没有 job 可重新冻结：策略结束（job 已恢复运行）')
        endEpisode('regeneration-empty')
        return
      }
      if (episode !== null) {
        episode.jobIds = again
        episode.freezeMinutes = Number(settings.freezeMinutes)
      }
      armWatchdog(settings.freezeMinutes)
      log(
        'freeze-mode：再生 ' + String(used) + '/' + String(budget) + ' —— 已解冻并立即重新冻结 ' +
        String(again.size) + ' 个 job（此前 ' + String(previous) + ' 个），重新计时 ' + String(settings.freezeMinutes) + ' 分钟',
      )
      return
    }

    // Regenerations exhausted: kill every job (including manual-frozen ones —
    // self-destruct is the last resort, not a freeze-management action) and
    // leave the process.
    phase = 'destroying'
    cancel(watchdogTimer)
    watchdogTimer = null
    log(
      'freeze-mode：再生次数已耗尽（' + String(episode.regenerationsBudget) +
      '），自毁：杀掉所有 job 后退出 pod 进程',
    )
    pending = selfDestruct()
  }

  /** @returns {Promise<void>} */
  async function selfDestruct() {
    let killed = 0
    try {
      const result = await killAllFn('freeze-mode self-destruct: regenerations exhausted')
      if (typeof result === 'number' && Number.isFinite(result)) killed = Math.max(0, Math.trunc(result))
    } catch (error) {
      log('freeze-mode：自毁时终止 job 失败：' + messageOf(error))
    }
    episode = null
    cancel(graceTimer)
    graceTimer = null
    cancel(watchdogTimer)
    watchdogTimer = null
    if (exited) return
    exited = true
    log('freeze-mode：已终止 ' + String(killed) + ' 个 job，退出 pod 进程（exit ' + String(FREEZE_SELF_DESTRUCT_EXIT_CODE) + '）')
    try {
      exitFn(FREEZE_SELF_DESTRUCT_EXIT_CODE)
    } catch (error) {
      log('freeze-mode：调用 exit 失败：' + messageOf(error))
    }
  }

  /**
   * A client authenticated: the pod is no longer alone. Cancel the grace timer,
   * thaw what this policy froze (manual freezes are untouched via `autoFrozen`),
   * and reset the round so the next disappearance starts from a full budget.
   */
  function clientConnected() {
    if (phase === 'disposed' || phase === 'destroying') return
    const wasWaiting = phase === 'grace' || phase === 'frozen' || graceTimer !== null || watchdogTimer !== null
    cancel(graceTimer)
    graceTimer = null
    cancel(watchdogTimer)
    watchdogTimer = null
    const thawed = thawEpisode('client-returned')
    episode = null
    phase = 'idle'
    if (wasWaiting || thawed > 0) {
      log('freeze-mode：客户端已连上，取消宽限/解冻 ' + String(thawed) + ' 个自动冻结的 job，本轮结束')
    }
    notifyIdle('client-connected')
  }

  /**
   * The last authenticated client went away. Re-read settings at this moment:
   * with freezeMode off the pod stays exactly as before this feature existed.
   */
  function clientDisconnected() {
    if (phase === 'disposed' || phase === 'destroying') return
    cancel(graceTimer)
    graceTimer = null
    cancel(watchdogTimer)
    watchdogTimer = null
    if (episode !== null) {
      // Defensive: a disconnect without a matching connect callback must not
      // strand jobs in a freeze the policy will never end.
      thawEpisode('client-cycle')
      episode = null
    }
    phase = 'idle'
    const settings = settingsNow()
    if (disabled(settings)) {
      const freezeMode = settings === null ? 'unknown' : String(settings.freezeMode)
      log('freeze-mode：认证客户端断开，但 freezeMode 未开启（freezeMode=' + freezeMode + '）：不安排冻结')
      notifyIdle('client-disconnected')
      return
    }
    phase = 'grace'
    graceTimer = schedule(onGrace, graceMs)
    log(
      'freeze-mode：最后一个认证客户端断开，' + String(graceMs) + 'ms 宽限后冻结运行中的 job（freezeMinutes=' +
      String(settings.freezeMinutes) + '，regenerations=' + String(settings.regenerations) + '）',
    )
  }

  /** Stop the policy without touching jobs (process shutdown owns the kill). */
  function dispose() {
    cancel(graceTimer)
    graceTimer = null
    cancel(watchdogTimer)
    watchdogTimer = null
    episode = null
    phase = 'disposed'
  }

  /** True while a grace timer or a freeze episode is pending. The pod must not idle-exit then. */
  function active() {
    return phase === 'grace' || phase === 'frozen' || phase === 'destroying'
  }

  function snapshot() {
    return {
      phase,
      graceMs,
      freezeMinutes: lastSettings === null ? null : lastSettings.freezeMinutes,
      regenerationsBudget: episode === null
        ? (lastSettings === null ? null : normalizeRegenerations(lastSettings.regenerations))
        : episode.regenerationsBudget,
      regenerationsUsed: episode === null ? 0 : episode.regenerationsUsed,
      autoFrozenJobIds: episode === null ? [] : [...episode.jobIds],
      watchdogRemainingMs: episode === null || episode.watchdogAt === null
        ? null
        : Math.max(0, episode.watchdogAt - now()),
    }
  }

  return {
    clientConnected,
    clientDisconnected,
    active,
    dispose,
    snapshot,
    /** Resolve after a pending self-destruct has finished its kills (tests/diagnostics). */
    settled() {
      return pending === null ? Promise.resolve() : pending
    },
    phase() {
      return phase
    },
  }
}
