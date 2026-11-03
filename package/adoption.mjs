/**
 * Adoption of escape-pod-core jobs into the Host `ctx.jobs` registry, so a pod
 * command also appears in `job_list`, can be read with `job_output`, and can be
 * stopped with `job_kill`.
 *
 * THE LIFELINE — Host teardown must NEVER kill a pod command. `dsh-jobs-local`
 * cancels every live record when the Host exits:
 *
 *   cancelForTeardown(jobs, "jobs service disposed")   // disposeAll(), line ~833
 *   cancelForTeardown(owned, "owner disposed")         // agent disposal, line ~813
 *
 * and in both paths it calls the producer's `cancel(reason)` with that literal
 * sentinel. An explicit `job_kill` goes through `killJob()` instead, which calls
 * `cancel(reason)` with the caller's optional reason (usually `undefined`), and
 * marks the settle cause `kill`. Therefore:
 *
 *   - a teardown-sentinel cancel (or a cancel while our own plugin is disposing,
 *     `hostDisposing`) only DETACHES the adoption and settles the registry
 *     record — it never calls the pod's kill;
 *   - anything else is an explicit kill and does call the pod's kill.
 *
 * A second, independent signal sharpens the explicit case: the `job_kill` tool
 * sets `explicitKills` through the `tools/pre-execute` hook before it calls
 * `ctx.jobs.kill`, so even a user-supplied reason equal to a teardown sentinel
 * still kills for real.
 *
 * Teardown cancellation must also RESOLVE `done` promptly: `disposeAll()`
 * awaits every `job.settled`, so a cancel that returns without settling would
 * hang Host shutdown. We settle as `killed` with a detail that says the pod job
 * was intentionally left running; teardown records are dropped immediately and
 * the session log carries `cause: 'teardown'`.
 *
 * MODEL CURSOR — adoption never replays history. The registry's model cursor
 * starts at 0 for a fresh ring, so this manager starts pumping the pod output at
 * the pod job's byte offset AT ADOPTION TIME (`baseOffset`). For a job started
 * in this Host that is 0 (normal first read); for a job adopted after a DSH
 * restart it is the pod job's current total, so `job_output` yields only bytes
 * produced after adoption. The complete earlier stream stays readable through
 * `pod_output` (the ledger's absolute offsets).
 *
 * Jobs are adopted UNOWNED (`owner` omitted). The pod is process-scoped and
 * outlives sessions; an owned record would be invisible to other sessions and
 * would be cancelled+awaited on that agent's disposal, which is exactly the
 * teardown path we must never turn into a kill. Unowned records are visible to
 * every session (`list(undefined)` / any caller) and killable by any caller.
 *
 * This module deliberately imports no Cordis symbols: the manager is driven by
 * duck-typed `ctx.jobs` and pod-client objects, so both the static and the
 * remote self-tests can exercise it with a fake registry against the real pod.
 */

// `JobKind` is a closed union in this DSH build (only `'bash'`), and
// `ctx.jobs.start` rejects anything else. The label is the command verbatim,
// matching the native pwsh tool; the pod jobId stays in pod_status.
export const ADOPT_KIND = 'bash'
/** Exact literals `dsh-jobs-local` passes for teardown cancellation. */
export const TEARDOWN_REASONS = Object.freeze(['jobs service disposed', 'owner disposed'])
const TEARDOWN_SET = new Set(TEARDOWN_REASONS)

/** @param {unknown} reason @param {boolean} hostDisposing */
export function isTeardownReason(reason, hostDisposing = false) {
  if (hostDisposing === true) return true
  return typeof reason === 'string' && TEARDOWN_SET.has(reason)
}

/** @param {string} text @param {number} max */
function truncate(text, max) {
  const value = String(text ?? '')
  return value.length <= max ? value : value.slice(0, max - 1) + '…'
}

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Map one pod `output`/`status` projection to a registry `JobOutcome`.
 * The two vocabularies must agree: `job_list` and `pod_status` describe the
 * same job, so every mapping is explicit. `detail` follows the native status
 * line: only killed/failed outcomes carry one — a clean `completed` must render
 * `[status: completed]` with no extra text (native shell tools put a non-zero
 * exit code in the command text, never in the status detail).
 * @param {{ status: string, exitCode?: number | null, signal?: string | null, totalBytes?: number }} chunk
 */
export function mapPodOutcome(chunk) {
  switch (chunk.status) {
    case 'settled':
      return { status: 'completed' }
    case 'killed':
      return { status: 'killed', detail: chunk.signal === null || chunk.signal === undefined ? 'killed' : String(chunk.signal) }
    case 'runner-failed':
      return { status: 'failed', detail: 'runner failed (exit 127; command never ran)' }
    case 'spawn-failed':
      return { status: 'failed', detail: 'runner spawn failed' }
    case 'ledger-failed':
      return { status: 'failed', detail: 'pod ledger could not be written' }
    case 'unknown':
      return { status: 'failed', detail: 'unknown: ledger has no exit.json; host/pod died before the outcome was known' }
    default:
      return { status: 'failed', detail: 'unrecognized pod status: ' + String(chunk.status) }
  }
}

/**
 * @param {{
 *   getJobs: () => any,
 *   pod: any,
 *   log?: (message: string) => void,
 *   pollMs?: number,
 *   autoPoll?: boolean,
 * }} options
 */
export function createAdoptionManager(options) {
  const { getJobs, pod } = options
  const log = typeof options.log === 'function' ? options.log : () => {}
  const pollMs = Number.isFinite(options.pollMs) && options.pollMs >= 50 ? options.pollMs : 250
  const autoPoll = options.autoPoll !== false

  /** @type {Map<string, any>} pod jobId → adoption record */
  const records = new Map()
  /** @type {Map<string, any>} registry jobId → adoption record */
  const byRegistryId = new Map()
  /** @type {Set<string>} pod jobIds the model explicitly killed through job_kill */
  const explicitKills = new Set()
  let hostDisposing = false
  let disposed = false
  /** @type {ReturnType<typeof setInterval> | null} */
  let timer = null
  let lastEnsureAt = 0

  function jobsOrNull() {
    try {
      const jobs = getJobs()
      return jobs === null || jobs === undefined ? null : jobs
    } catch {
      return null
    }
  }

  function ensureTimer() {
    if (!autoPoll || disposed || timer !== null) return
    const active = [...records.values()].some((record) => record.settled === false && record.detached === false)
    if (!active) return
    timer = setInterval(() => {
      void pollAllOnce()
    }, pollMs)
    if (typeof timer.unref === 'function') timer.unref()
  }

  /** @param {any} record @param {{ status: string, detail?: string }} outcome */
  function finish(record, outcome) {
    if (record.settled === true) return
    record.settled = true
    record.outcome = outcome
    record.handle?.updateProgress(outcome.detail ?? outcome.status)
    record.resolveDone(outcome)
    log('adopted job ' + record.podJobId + ' → ' + outcome.status + (outcome.detail === undefined ? '' : ' (' + outcome.detail + ')'))
    stopTimerIfIdle()
  }

  /**
   * Detach the adoption without touching the pod job. Used for teardown and for
   * plugin disposal (HMR); the registry record settles so Host disposal cannot
   * hang, while the command keeps running in the escape pod.
   * @param {any} record @param {string} detail */
  function detach(record, detail) {
    if (record.settled === true) return
    record.detached = true
    record.settled = true
    record.outcome = { status: 'killed', detail }
    record.resolveDone(record.outcome)
    log('detached adopted job ' + record.podJobId + ': ' + detail)
    stopTimerIfIdle()
  }

  function stopTimerIfIdle() {
    if (timer === null) return
    const active = [...records.values()].some((record) => record.settled === false && record.detached === false)
    if (active) return
    clearInterval(timer)
    timer = null
  }

  /**
   * The registry calls this for both kill and teardown; the reason sentinel is
   * the only distinction the API offers, backed by our own hostDisposing flag
   * and the job_kill pre-execute marker.
   * @param {any} record @param {unknown} reason */
  function cancel(record, reason) {
    if (record.settled === true) return
    const explicit = explicitKills.delete(record.podJobId) || byRegistryIdExplicit(record)
    if (!explicit && isTeardownReason(reason, hostDisposing)) {
      detach(record, 'registry teardown: pod job intentionally left running (escape-pod-core)')
      return
    }
    record.killRequested = true
    try {
      record.handle?.updateProgress('stopping: asked the pod to kill ' + record.podJobId)
    } catch {
      // progress is cosmetic
    }
    void (async () => {
      try {
        // Adoption is a deliberate cross-session takeover (records are unowned
        // on purpose), so its pod calls carry adopt: true. The model-facing
        // boundary lives in pod_output/pod_kill, not in this maintenance path.
        const response = await pod.kill(record.hint, { jobId: record.podJobId, adopt: true })
        if (response?.ok !== true) log('pod kill for ' + record.podJobId + ' returned not-ok: ' + JSON.stringify(response))
      } catch (error) {
        log('pod kill for ' + record.podJobId + ' failed (the poller will still observe the ledger): ' + messageOf(error))
      }
    })()
  }

  /** @param {any} record */
  function byRegistryIdExplicit(record) {
    // The explicit marker may arrive keyed by registry id (job_kill arguments).
    const marked = explicitKills.has(record.registryId)
    if (marked) explicitKills.delete(record.registryId)
    return marked
  }

  /** @param {any} chunk */
  function appendChunk(record, chunk) {
    const pieces = Array.isArray(chunk?.chunks) && chunk.chunks.length > 0
      ? chunk.chunks
      : [{ text: typeof chunk?.text === 'string' ? chunk.text : '', channel: undefined, lossy: chunk?.lossy }]
    let appended = 0
    for (const piece of pieces) {
      const text = typeof piece?.text === 'string' ? piece.text : ''
      if (text.length === 0) continue
      const gap = piece.lossy === true || chunk?.lossy === true || (record.lossy === true && record.firstAppend === true)
      /** @type {any} */
      const options = { channel: piece.channel }
      if (gap) options.gapBefore = true
      record.handle.append(text, options)
      record.firstAppend = false
      appended += Buffer.byteLength(text, 'utf8')
    }
    record.podCursor = Number.isFinite(chunk.nextOffset) ? chunk.nextOffset : record.podCursor + appended
    record.bytes = Number.isFinite(chunk.totalBytes) ? chunk.totalBytes : record.podCursor
  }

  /**
   * Drain a bounded number of chunks from the pod for one adoption. Called by
   * the poller and directly by tests (`pollAllOnce`).
   * @param {any} record */
  function pollRecord(record) {
    // If a pump round is already in flight, JOIN it instead of returning early:
    // a caller that needs a caught-up registry total must not observe a stale one.
    if (record.pollBusy === true && record.pollWait !== null && record.pollWait !== undefined) return record.pollWait
    if (disposed || record.pollBusy === true || record.settled === true || record.detached === true) return Promise.resolve()
    record.pollBusy = true
    record.pollWait = (async () => {
      try {
        for (let round = 0; round < 4; round += 1) {
          const chunk = await pod.output(record.hint, { jobId: record.podJobId, from: record.podCursor, maxBytes: 65536, adopt: true })
          appendChunk(record, chunk)
          if (chunk.status !== 'running') {
            finish(record, mapPodOutcome(chunk))
            return
          }
          if (chunk.hasMore !== true) break
        }
        record.handle.updateProgress('pod ' + record.podJobId + ' · ' + String(record.bytes) + 'B')
      } catch (error) {
        record.lastError = messageOf(error)
        // A job this Host cannot read any more must not look live in job_list.
        finish(record, { status: 'failed', detail: 'pod output unreadable: ' + record.lastError })
      } finally {
        record.pollBusy = false
        record.pollWait = null
      }
    })()
    return record.pollWait
  }

  /** Drain every live adoption once (also the deterministic test entry point). */
  async function pollAllOnce() {
    const sweeps = []
    for (const record of records.values()) {
      if (record.settled === true || record.detached === true) continue
      sweeps.push(pollRecord(record))
    }
    await Promise.all(sweeps)
  }

  /**
   * Adopt one pod job into `ctx.jobs`. Returns the registry id, or null when the
   * jobs service/controller is not available (adoption is optional, the pod
   * remains authoritative).
   * @param {{
   *   podJobId: string, command: string, startedAt?: string, baseOffset?: number, hint?: any,
   *   cursorMode?: string, cursorWarning?: string | null, lossy?: boolean,
   *   sessionId?: string | null,
   * }} request
   */
  function adopt(request) {
    if (disposed) return null
    const jobs = jobsOrNull()
    if (jobs === null) return null
    const podJobId = String(request.podJobId ?? '')
    if (podJobId === '') return null
    const existing = records.get(podJobId)
    if (existing !== undefined) return existing.registryId
    if (typeof jobs.start !== 'function') return null
    const baseOffset = Number.isFinite(request.baseOffset) && request.baseOffset >= 0 ? request.baseOffset : 0
    let resolveDone
    const done = new Promise((resolve) => {
      resolveDone = resolve
    })
    /** @type {any} */
    const record = {
      podJobId,
      command: String(request.command ?? ''),
      hint: request.hint ?? null,
      // The pod reported this job's DSH session; `null` is unowned history.
      // Stored so pod_output can apply the same boundary to the registry read
      // path (which never talks to the pod) and report adoptedFrom.
      sessionId: typeof request.sessionId === 'string' && request.sessionId !== '' ? request.sessionId : null,
      baseOffset,
      podCursor: baseOffset,
      bytes: baseOffset,
      startedAt: request.startedAt ?? new Date().toISOString(),
      cursorMode: String(request.cursorMode ?? 'explicit-offset'),
      cursorWarning: request.cursorWarning ?? null,
      lossy: request.lossy === true,
      firstAppend: true,
      registryId: null,
      handle: null,
      settled: false,
      detached: false,
      killRequested: false,
      pollBusy: false,
      pollWait: null,
      outcome: null,
      lastError: null,
      resolveDone,
    }
    let registryId = null
    try {
      registryId = jobs.start({
        kind: ADOPT_KIND,
        // Native label: the command verbatim, no producer prefix. The pod jobId
        // stays visible in pod_status instead of the job list.
        label: String(record.command),
        // Unowned on purpose: the pod outlives sessions and an owned record would
        // be cancelled (and awaited) by that agent's disposal.
        outputLimitBytes: 64 * 1024,
        run(job) {
          record.handle = job
          job.updateProgress(
            record.cursorWarning === null
              ? 'pod ' + podJobId + ' · adopted'
              : 'pod ' + podJobId + ' · ' + truncate(record.cursorWarning, 120),
          )
          return {
            cancel: (reason) => cancel(record, reason),
            done,
          }
        },
      })
    } catch (error) {
      log('adoption unavailable for ' + podJobId + ': ' + messageOf(error))
      return null
    }
    if (typeof registryId !== 'string' || registryId === '') return null
    record.registryId = registryId
    records.set(podJobId, record)
    byRegistryId.set(registryId, record)
    ensureTimer()
    log('adopted pod job ' + podJobId + ' as registry job ' + registryId + ' (base offset ' + String(baseOffset) + ')')
    return registryId
  }

  /**
   * Adopt every RUNNING pod job that is not adopted yet. Running jobs are read
   * from the pod's own status, so `job_list` and `pod_status` describe the same
   * set. Historical (settled) jobs are deliberately not adopted: adoption is for
   * live control, and `pod_status` remains the ledger view for finished work.
   * @param {any} [hint] @param {{ force?: boolean, onlyIfConnected?: boolean, jobs?: any[] }} [options]
   */
  async function ensureAdopted(hint, options = {}) {
    if (disposed) return { adopted: 0, reason: 'disposed' }
    const jobs = jobsOrNull()
    if (jobs === null) return { adopted: 0, reason: 'no-jobs-service' }
    const now = Date.now()
    if (options.force !== true && now - lastEnsureAt < 1000) return { adopted: 0, reason: 'throttled' }
    if (options.onlyIfConnected === true && pod.mode() === 'none') return { adopted: 0, reason: 'no-pod-connection' }
    lastEnsureAt = now
    /** @type {any[]} */
    let jobsList
    if (Array.isArray(options.jobs)) {
      // The caller already has a pod status snapshot: adopt exactly that set, so
      // the row this caller renders and the registry record cannot disagree.
      jobsList = options.jobs
    } else {
      /** @type {any} */
      let status
      try {
        status = await pod.status(hint ?? null)
      } catch (error) {
        return { adopted: 0, reason: 'pod-status-failed: ' + messageOf(error) }
      }
      jobsList = Array.isArray(status?.response?.jobs) ? status.response.jobs : []
    }
    let adopted = 0
    let skipped = 0
    /** @type {{ podJobId: string, registryId: string, cursorMode: string, warning: string | null }[]} */
    const adoptedJobs = []
    for (const job of jobsList) {
      if (job?.status !== 'running') continue
      if (records.has(String(job.jobId))) continue
      const decision = adoptionOffset(job)
      const registryId = adopt({
        podJobId: String(job.jobId),
        command: String(job.command ?? ''),
        startedAt: typeof job.startedAt === 'string' ? job.startedAt : undefined,
        baseOffset: decision.baseOffset,
        cursorMode: decision.cursorMode,
        cursorWarning: decision.warning,
        lossy: decision.lossy,
        sessionId: typeof job.sessionId === 'string' && job.sessionId !== '' ? job.sessionId : null,
        hint,
      })
      if (registryId === null) skipped += 1
      else {
        adopted += 1
        adoptedJobs.push({ podJobId: String(job.jobId), registryId, cursorMode: decision.cursorMode, warning: decision.warning })
      }
    }
    return { adopted, skipped, running: jobsList.filter((job) => job?.status === 'running').length, jobs: adoptedJobs }
  }

  /**
   * Pick the adoption offset for one pod job.
   *
   * A persisted cursor is the only way `job_output` can continue across a DSH
   * restart without a gap: the Host had consumed `cursor.offset` bytes, output
   * produced while DSH was down lives in [offset, total), and adoption starts
   * exactly there. Without a cursor the old behaviour (start at the pod total)
   * is the only honest choice, because we cannot know what the model saw.
   *
   * A cursor whose prefix hash no longer matches is NOT silently trusted: the
   * adoption falls back to the total (never rewinds into an unverified prefix)
   * and reports `cursor-mismatch` so the model and the tools can see it.
   * @param {any} job pod status projection
   */
  function adoptionOffset(job) {
    const total = Number.isFinite(job?.bytes) ? job.bytes : 0
    const cursor = job?.cursor
    if (cursor === null || cursor === undefined || cursor.state === 'missing') {
      return { baseOffset: total, cursorMode: 'no-cursor', warning: null, lossy: false }
    }
    if (cursor.state === 'ok' || cursor.state === 'lossy') {
      const offset = Number.isFinite(cursor.offset) ? Math.min(cursor.offset, total) : total
      return {
        baseOffset: offset,
        cursorMode: cursor.state,
        warning: cursor.state === 'lossy' ? String(cursor.reason ?? 'cursor 早于保留窗口') : null,
        lossy: cursor.state === 'lossy',
      }
    }
    return {
      baseOffset: total,
      cursorMode: 'cursor-mismatch',
      warning: 'cursor-mismatch (' + String(cursor.state) + '): ' + String(cursor.reason ?? '前缀校验失败') + '；本次从 pod 当前 totalBytes 收养，不回退到未验证的前缀',
      lossy: false,
    }
  }

  /**
   * Adopt a job that this Host just started through `pod_run`. Offset 0 is the
   * job's start, so a normal first `job_output` reads from the beginning.
   * `command` is the verbatim tool argument (the native label); the pod's own
   * projection may already be shortened.
   * @param {{ jobId: string, command?: string, startedAt?: string, sessionId?: string | null }} response
   * @param {any} hint
   * @param {string} [command]
   */
  function adoptNewJob(response, hint, command) {
    if (response === null || response === undefined) return null
    return adopt({
      podJobId: String(response.jobId ?? ''),
      command: typeof command === 'string' && command.trim() !== '' ? command : String(response.command ?? ''),
      startedAt: response.startedAt,
      baseOffset: 0,
      cursorMode: 'fresh',
      sessionId: typeof response.sessionId === 'string' && response.sessionId !== ''
        ? response.sessionId
        : (typeof hint?.sessionId === 'string' && hint.sessionId !== '' ? hint.sessionId : null),
      hint,
    })
  }

  /**
   * Registry-side projection for one pod job, used by `pod_status` so the two
   * views cannot disagree: either the job is adopted (with the registry id and
   * live registry status) or it explicitly says it is not adopted (finished
   * history, or adoption unavailable).
   * @param {string} podJobId
   */
  function registryInfo(podJobId) {
    const record = records.get(String(podJobId))
    if (record === undefined) return { adopted: false }
    const jobs = jobsOrNull()
    /** @type {string | null} */
    let status = null
    if (record.detached === true) status = 'detached'
    else if (record.settled === true) status = record.outcome?.status ?? 'settled'
    else if (jobs !== null && typeof jobs.get === 'function') {
      try {
        status = jobs.get(record.registryId)?.status ?? null
      } catch {
        status = null
      }
    }
    return {
      adopted: true,
      id: record.registryId,
      status,
      sessionId: record.sessionId ?? null,
      baseOffset: record.baseOffset,
      cursor: record.cursorMode,
      cursorWarning: record.cursorWarning,
      lossy: record.lossy === true,
    }
  }

  /**
   * Drain one adoption so the registry holds every byte the pod has produced so
   * far. `pod_output` calls this before `ctx.jobs.read` on an adopted job;
   * without it a fresh read could see an empty ring while the pod already has
   * output.
   * @param {string} jobId
   */
  async function pollAdopted(jobId) {
    const key = String(jobId)
    const record = records.get(key) ?? byRegistryId.get(key)
    if (record === undefined) return false
    await pollRecord(record)
    return true
  }

  /**
   * Mark an explicit `job_kill` for one registry job before the tool executes.
   * The marker beats a teardown-sentinel reason, so a user-supplied reason can
   * never accidentally turn a real kill into a detach.
   * @param {unknown} jobId
   */
  function noteExplicitKill(jobId) {
    if (typeof jobId !== 'string' || jobId === '') return
    const record = byRegistryId.get(jobId) ?? records.get(jobId)
    if (record === undefined) return
    explicitKills.add(record.podJobId)
    explicitKills.add(record.registryId)
  }

  /** Our plugin is disposing (Host shutdown or HMR): no cancel may kill the pod. */
  function markHostDisposing() {
    hostDisposing = true
  }

  /**
   * Stop polling and detach every adoption without killing pod jobs. Called from
   * the plugin effect cleanup, after which a fresh instance can re-adopt.
   */
  function dispose() {
    if (disposed) return
    disposed = true
    hostDisposing = true
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
    for (const record of records.values()) {
      if (record.settled !== true && record.detached !== true) {
        detach(record, 'adoption manager disposed: pod job intentionally left running (escape-pod-core)')
      }
    }
  }

  return {
    adopt,
    adoptNewJob,
    ensureAdopted,
    registryInfo,
    pollAdopted,
    getJobsService: jobsOrNull,
    noteExplicitKill,
    markHostDisposing,
    pollAllOnce,
    dispose,
    // test/diagnostic surface
    recordFor(podJobId) {
      return records.get(String(podJobId)) ?? null
    },
    recordForRegistryId(registryId) {
      return byRegistryId.get(String(registryId)) ?? null
    },
    stats() {
      let active = 0
      let settled = 0
      for (const record of records.values()) {
        if (record.settled === true) settled += 1
        else active += 1
      }
      return { adopted: records.size, active, settled, hostDisposing, disposed, polling: timer !== null }
    },
    constants: { ADOPT_KIND, TEARDOWN_REASONS },
  }
}
