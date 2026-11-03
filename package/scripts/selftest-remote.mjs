#!/usr/bin/env node
/**
 * End-to-end self-test for @local/dsh-escape-pod. MUST run as an UNRESTRICTED process:
 * a Low-integrity / WRITE_RESTRICTED process cannot be a named-pipe CLIENT
 * (documented EPERM boundary), so this script cannot run from DSH's own pwsh
 * tool. Launch it from a normal user console/desktop process.
 *
 * What it proves, with the real windows-acl runner and the real named pipe:
 *   1. the helper really is unrestricted (it can write the C:\ root; a confined
 *      command cannot);
 *   2. the Host plugin spawns the detached pod, the pod spawns the REAL
 *      runner per command, and the runner's constrained child's stdout/stderr
 *      reach the pod through pipes (the big unknown of the design);
 *   3. the command is genuinely confined: writing C:\ is denied while writing
 *      the workspace succeeds, and the mandatory integrity label is Low;
 *   4. the prefix is minted PER CALL (confine() called exactly once per
 *      `pod_run`, distinct per-call prefixes) and the pod holds only the pinned
 *      shape template — never a prefix, never a SID;
 *   5. absolute output offsets: incremental reads concatenate exactly, and a
 *      post-kill tail read is empty at the frozen total;
 *   6. the ledger (`meta.json` before spawn, `out.log`, `exit.json`) is coherent
 *      and byte-exact;
 *   7. the runner-failure contract (127 + `windows-acl-run:` signature) is
 *      classified as `runner-failed`, not normal exit;
 *   8. reconnect: a second client (the DSH-restart analogue) reuses the SAME pod,
 *      sees the same podPid/template/jobs, keeps reading old output and can run
 *      a fresh command with its own freshly minted prefix;
 *   9. a pod killed mid-job leaves the job `unknown` (never a fabricated
 *      exit code), and a new pod is spawned honestly;
 *  10. a stale per-call prefix is rejected with EPREFIXSTALE before any spawn.
 *
 * Usage:
 *   node selftest-remote.mjs --runner "<dsh install>/node_modules/@deepseek-ai/dsh-sandbox-windows-acl/lib/runner.js"
 *                            [--workspace Z:\Project\DSHproject]
 *
 * Writes `.tmp/escape-pod-core-selftest/remote-result.json` and prints a summary.
 */

import net from 'node:net'
import os from 'node:os'
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { PIPE_PREFIX, describePipeIdentity, fingerprintPrefix, hashArgv, isDshInstallRunnerPath, isInsideDirectory, resolveStateDir } from '../shared.mjs'
import { createAdoptionManager } from '../adoption.mjs'
import { createJobOutputAckHook, createPodClient, createTools } from '../index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, 'fixtures')
const CONFINEMENT_PROBE = join(FIXTURES, 'confinement-probe.mjs')
const SLOW_PRINT = join(FIXTURES, 'slow-print.mjs')
const TICK_LINES = join(FIXTURES, 'tick-lines.mjs')
const TEXT_LINES = join(FIXTURES, 'text-lines.mjs')
const FAIL_127 = join(FIXTURES, 'fail-127.mjs')

const RUN_ID = String(process.pid) + '-' + randomBytes(3).toString('hex')
const WORKSPACE = 'Z:\\Project\\DSHproject'
const RESULT_DIR = join(WORKSPACE, '.tmp', 'escape-pod-core-selftest')
const RESULT_PATH = join(RESULT_DIR, 'remote-result.json')
// The ledger MUST live outside the workspace: managed commands are
// workspace-write and could otherwise forge their own meta/out/exit records.
// This is the production default (LOCALAPPDATA), not a test-only location.
const DATA_ROOT = resolveStateDir(undefined)
const LEGACY_WORKSPACE_LEDGER = join(WORKSPACE, 'local-data', 'escape-pod-core')
const PIPE = PIPE_PREFIX + 'dsh-escape-pod-core-selftest-' + RUN_ID

const results = []
const logs = []
const tempDirs = []
const jobIds = []
const runnerPids = []
const clients = []
const helpers = { constants: null, only: null, keep: false }
/** Last started job, used to attach diagnostics to a failing assertion. */
let lastJobContext = null

/** @param {string} name @param {boolean} ok @param {Record<string, unknown>} [evidence] */
function record(name, ok, evidence) {
  const entry = { name, ok, evidence: evidence ?? null }
  results.push(entry)
  process.stdout.write((ok ? '[PASS] ' : '[FAIL] ') + name + (ok ? '' : ' — ' + JSON.stringify(evidence ?? null)) + '\n')
  return ok
}

/** @param {any} client @param {any} hint @param {string} jobId */
async function safeSnapshot(client, hint, jobId) {
  try {
    const chunk = await client.output(hint, { jobId, from: 0, maxBytes: 8192 })
    return {
      jobId,
      status: chunk.status,
      running: chunk.running,
      exitCode: chunk.exitCode,
      signal: chunk.signal,
      totalBytes: chunk.totalBytes,
      text: String(chunk.text ?? '').slice(0, 4000),
    }
  } catch (error) {
    return { jobId, snapshotError: messageOf(error) }
  }
}

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/** @param {string} name @param {() => Promise<Record<string, unknown> | void>} fn */
async function runCase(name, fn) {
  if (helpers.only !== null && helpers.only !== name) {
    results.push({ name, ok: true, skipped: true })
    process.stdout.write('[SKIP] ' + name + '\n')
    return
  }
  try {
    const evidence = await fn()
    record(name, true, evidence ?? undefined)
  } catch (error) {
    /** @type {Record<string, unknown>} */
    const evidence = { error: messageOf(error) }
    if (lastJobContext !== null) {
      evidence.job = await safeSnapshot(lastJobContext.client, lastJobContext.hint, lastJobContext.jobId)
    }
    record(name, false, evidence)
  }
}

/** @param {unknown} condition @param {string} message */
function assert(condition, message) {
  if (!condition) throw new Error(message)
}

/** @param {unknown} actual @param {unknown} expected @param {string} message */
function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(message + '：期望 ' + JSON.stringify(expected) + '，实际 ' + JSON.stringify(actual))
}

/** @param {number} ms */
function sleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms))
}

/** @param {string} text */
function lastJsonLine(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '').reverse()
  for (const line of lines) {
    try {
      return JSON.parse(line)
    } catch {
      // keep looking
    }
  }
  return null
}

function parseArgs(argv) {
  /** @type {{ runner: string | undefined, workspace: string, only: string | null, keep: boolean }} */
  const options = { runner: undefined, workspace: WORKSPACE, only: null, keep: false }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--runner') {
      options.runner = argv[index + 1]
      index += 1
    } else if (arg === '--workspace') {
      options.workspace = argv[index + 1] ?? WORKSPACE
      index += 1
    } else if (arg === '--only') {
      options.only = argv[index + 1] ?? null
      index += 1
    } else if (arg === '--keep') {
      options.keep = true
    }
  }
  return options
}

// ---------------------------------------------------------------------------
// Fake sandbox seam: returns a REAL windows-acl runner prefix per call.
// The temp root is a fresh directory per call, so each per-call prefix really is
// distinct (in production the session-managed variant differs the same way).
// ---------------------------------------------------------------------------

/** @param {string} runnerPath @param {string} workspaceRoot */
function makeFakeSandbox(runnerPath, workspaceRoot) {
  return {
    confineCalls: 0,
    prefixes: [],
    policies: [],
    async confine(argv, policy) {
      const tempDir = fs.mkdtempSync(join(os.tmpdir(), 'epc-prefix-'))
      tempDirs.push(tempDir)
      this.confineCalls += 1
      this.policies.push(policy)
      const prefix = [
        process.execPath,
        runnerPath,
        '--workspace',
        policy.workspaceRoot,
        '--temp',
        tempDir,
        '--mode',
        policy.mode,
      ]
      this.prefixes.push(prefix)
      return {
        argv: [...prefix, '--', ...argv],
        enforcement: 'partial',
        denialSignatures: ['access is denied', 'access to the path', 'permission denied', 'operation not permitted'],
        runnerFailureRules: [{ allowedExitCodes: [127], fatalSignatures: ['windows-acl-run: '] }],
      }
    },
  }
}

/** @param {string} pipeName */
class RawPipeClient {
  /** @param {string} pipeName */
  constructor(pipeName) {
    this.pipeName = pipeName
    this.socket = null
    this.buffer = ''
    this.nextId = 1
    /** The pod's current memory-only token; set by a successful handover. */
    this.token = null
    /** @type {Map<number, { resolve: (value: any) => void, reject: (error: Error) => void, timer: NodeJS.Timeout }>} */
    this.pending = new Map()
  }

  async connect(timeoutMs = 3000) {
    await new Promise((resolveConnect, rejectConnect) => {
      const socket = net.connect(this.pipeName)
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        socket.destroy()
        rejectConnect(Object.assign(new Error('raw pipe connect timeout'), { code: 'ETIMEDOUT' }))
      }, timeoutMs)
      socket.once('connect', () => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        this.socket = socket
        socket.setEncoding('utf8')
        socket.on('data', (chunk) => {
          this.buffer += chunk
          let newline = this.buffer.indexOf('\n')
          while (newline >= 0) {
            const line = this.buffer.slice(0, newline)
            this.buffer = this.buffer.slice(newline + 1)
            if (line.trim() !== '') {
              try {
                const message = JSON.parse(line)
                const entry = this.pending.get(message.id)
                if (entry !== undefined) {
                  this.pending.delete(message.id)
                  clearTimeout(entry.timer)
                  entry.resolve(message)
                }
              } catch {
                // ignore framing noise
              }
            }
            newline = this.buffer.indexOf('\n')
          }
        })
        socket.on('error', () => {})
        socket.on('close', () => {
          for (const [id, entry] of this.pending) {
            this.pending.delete(id)
            clearTimeout(entry.timer)
            entry.reject(Object.assign(new Error('raw pipe closed'), { code: 'ECLOSED' }))
          }
        })
        resolveConnect(undefined)
      })
      socket.once('error', (error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        rejectConnect(error)
      })
    })
  }

  /** @param {string} op @param {Record<string, unknown>} payload */
  request(op, payload, timeoutMs = 20000) {
    const socket = this.socket
    if (socket === null || socket.destroyed) throw new Error('raw pipe not connected')
    const id = this.nextId
    this.nextId += 1
    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return
        this.pending.delete(id)
        rejectRequest(Object.assign(new Error('raw pipe request timeout'), { code: 'ETIMEDOUT' }))
      }, timeoutMs)
      this.pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer })
      /** @type {Record<string, unknown>} */
      const body = { ...payload, op, id }
      if (this.token !== null) body.token = this.token
      try {
        socket.write(JSON.stringify(body) + '\n')
      } catch (error) {
        this.pending.delete(id)
        clearTimeout(timer)
        rejectRequest(Object.assign(new Error('raw pipe write failed'), { code: 'EWRITE', cause: error }))
      }
    })
  }

  close() {
    if (this.socket !== null) {
      try {
        this.socket.destroy()
      } catch {
        // already gone
      }
      this.socket = null
    }
  }
}

/**
 * The Host wallet for tests: one client per "Host boot". Each client uses its own
 * fake sandbox (fresh prefixes per call), exactly like a new Host process would.
 * @param {string} runnerPath
 */
function newClient(runnerPath) {
  const sandbox = makeFakeSandbox(runnerPath, WORKSPACE)
  const client = createPodClient({
    pipeName: PIPE,
    idleExitMs: 120000,
    ringBytes: 262144,
    outputChunkBytes: 65536,
    log: (message) => logs.push(message),
    getSandbox: () => sandbox,
  })
  clients.push({ client, sandbox })
  return { client, sandbox }
}

/**
 * A duck-typed `ctx.jobs` for the adoption test. It records the JobSpec and
 * returns a fake handle; `cancel()` is the real registry entry point, so the
 * teardown/kill distinction is exercised through the same API dsh-jobs-local uses.
 */
function createFakeJobsForAdoption() {
  /** @type {Map<string, any>} */
  const started = new Map()
  const fake = {
    started,
    reads: [],
    start(spec) {
      const id = 'registry-' + String(started.size + 1)
      const handle = {
        id,
        appended: [],
        progress: null,
        append(text, options) {
          this.appended.push({ text, options })
        },
        updateProgress(text) {
          this.progress = text
        },
      }
      const hooks = spec.run(handle)
      started.set(id, { id, spec, handle, hooks })
      return id
    },
    get() {
      return null
    },
    read(id) {
      fake.reads.push(id)
      const row = started.get(id)
      if (row === undefined) return { chunks: [], lossy: false, job: { status: 'running', output: { total: 0 } } }
      const rows = row.handle.appended
      let position = 0
      let cursor = typeof row.modelCursor === 'number' ? row.modelCursor : 0
      const chunks = []
      for (const entry of rows) {
        const bytes = Buffer.from(entry.text, 'utf8')
        const start = position
        position += bytes.length
        if (position <= cursor) continue
        const local = cursor > start ? cursor - start : 0
        const text = bytes.subarray(local).toString('utf8')
        if (text !== '') chunks.push({ at: start + local, text, channel: entry.options?.channel })
      }
      row.modelCursor = position
      return { chunks, lossy: false, job: { status: 'running', output: { total: position } } }
    },
  }
  return fake
}

/** @param {any} client @param {any} hint @param {string} jobId @param {number} [timeoutMs] */
async function waitSettled(client, hint, jobId, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const chunk = await client.output(hint, { jobId, from: 0, maxBytes: 2 })
    if (chunk.status !== 'running') return chunk
    if (Date.now() > deadline) throw new Error('job 未在 ' + timeoutMs + 'ms 内结束：' + jobId)
    await sleep(200)
  }
}

/** @param {any} client @param {any} hint @param {string} jobId */
async function readAll(client, hint, jobId) {
  let from = 0
  let text = ''
  for (let guard = 0; guard < 2000; guard += 1) {
    const chunk = await client.output(hint, { jobId, from })
    text += chunk.text
    if (chunk.eof) return { text, totalBytes: chunk.totalBytes, status: chunk.status, exitCode: chunk.exitCode }
    assert(chunk.nextOffset > from, 'nextOffset 必须前进')
    from = chunk.nextOffset
  }
  throw new Error('readAll 没有到达 eof：' + jobId)
}

function readIntegrity() {
  const result = spawnSync('C:\\Windows\\System32\\whoami.exe', ['/groups', '/fo', 'csv', '/nh'], { encoding: 'utf8' })
  if (result.error !== undefined && result.error !== null) return 'whoami-error:' + /** @type {any} */ (result.error).code
  const match = /S-1-16-(\d+)/.exec(String(result.stdout ?? ''))
  return match === null ? 'unknown:no-S-1-16-line' : 'S-1-16-' + match[1]
}

function probeWriteCRoot() {
  const path = 'C:\\dsh-escape-pod-core-helper-probe-' + String(process.pid) + '.txt'
  try {
    fs.writeFileSync(path, 'helper\n', 'utf8')
    try {
      fs.unlinkSync(path)
    } catch {
      // leftover is harmless
    }
    return { ok: true, code: null }
  } catch (error) {
    return { ok: false, code: /** @type {any} */ (error)?.code ?? 'EUNKNOWN' }
  }
}

function canConnectPipe(pipeName, timeoutMs = 400) {
  return new Promise((resolveConnect) => {
    const socket = net.connect(pipeName)
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      resolveConnect(value)
    }
    const timer = setTimeout(() => finish({ ok: false, code: 'ETIMEDOUT' }), timeoutMs)
    socket.once('connect', () => finish({ ok: true, code: null }))
    socket.once('error', (error) => finish({ ok: false, code: /** @type {any} */ (error)?.code ?? 'EUNKNOWN' }))
  })
}

async function waitPipeGone(pipeName, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const probe = await canConnectPipe(pipeName)
    if (probe.code === 'ENOENT') return true
    if (Date.now() > deadline) return false
    await sleep(250)
  }
}

/**
 * @param {Record<string, any>} result
 */
function writeResult(result) {
  fs.mkdirSync(RESULT_DIR, { recursive: true })
  fs.writeFileSync(RESULT_PATH, JSON.stringify(result, null, 2) + '\n')
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  helpers.constants = { workspace: WORKSPACE, dataRoot: DATA_ROOT, pipe: PIPE, runId: RUN_ID }
  helpers.only = options.only
  helpers.keep = options.keep
  const result = {
    ok: false,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    constants: { ...helpers.constants, runner: options.runner ?? null, only: options.only, keep: options.keep },
    env: null,
    cases: results,
    cleanup: null,
    logs: logs.slice(-200),
  }

  const RUNNER = options.runner === undefined ? '' : resolve(options.runner)
  if (RUNNER === '' || !fs.existsSync(RUNNER) || !isDshInstallRunnerPath(RUNNER)) {
    writeResult({ ...result, ok: false, fatal: '缺少/非法的 --runner（必须指向 DSH 安装树里的 dsh-sandbox-windows-acl/lib/runner.js）：' + String(options.runner) })
    process.stdout.write('[FAIL] fatal: --runner 不合法\n')
    process.exitCode = 2
    return result
  }
  helpers.constants.runner = RUNNER

  const hint = { sessionId: 'selftest-session-' + RUN_ID, workspaceRoot: WORKSPACE }
  const fakeExec = { agent: { id: 'selftest-session-' + RUN_ID, session: { meta: { cwd: WORKSPACE } } } }

  /** @type {{ client: any, sandbox: any } | null} */
  let active = null
  /** @type {any} */
  let settledToolJob = null

  /**
   * Switch test "Hosts". The pod serves ONE client at a time, so a new Host can
   * only attach after the previous client is gone; the pod then has no live
   * token holder and is claimed through the same `handover` op a real restarted
   * Host uses. Returns the new active client.
   * @param {string} runnerPath
   */
  async function switchHost(runnerPath) {
    for (const entry of clients) {
      try {
        entry.client.dispose()
      } catch {
        // best effort
      }
    }
    const next = newClient(runnerPath)
    await next.client.boot()
    active = next
    return next
  }

  /**
   * Take the pipe as a raw maintenance client. Single-client means the Host
   * clients must be gone; the token lives only in the Host's memory, so claim
   * the orphaned pod with `handover`. `withToken=false` leaves the client
   * unauthenticated on purpose (the negative test).
   * @param {boolean} [withToken]
   */
  async function connectRaw(withToken = true) {
    for (const entry of clients) {
      try {
        entry.client.dispose()
      } catch {
        // best effort
      }
    }
    /** @type {any} */
    let lastError = null
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const raw = new RawPipeClient(PIPE)
      try {
        await raw.connect()
      } catch (error) {
        lastError = error
        await sleep(150)
        continue
      }
      if (!withToken) return raw
      const token = randomBytes(32).toString('hex')
      /** @type {any} */
      let claimed = null
      try {
        claimed = await raw.request('handover', { newToken: token })
      } catch (error) {
        lastError = error
      }
      if (claimed?.ok === true) {
        raw.token = token
        return raw
      }
      lastError = new Error(
        'handover 被拒：' + String(claimed?.error?.code ?? '') + ' ' + String(claimed?.error?.message ?? ''),
      )
      raw.close()
      await sleep(150)
    }
    throw lastError instanceof Error ? lastError : new Error('无法接管管道（' + PIPE + '）')
  }

  try {
    // -----------------------------------------------------------------------
    // 0. Environment evidence: this helper must be the unrestricted side.
    //    NOTE: some machines also deny C:\ root creation to Medium tokens (a
    //    hardened ACL), so C:\ writability is recorded as evidence, not asserted;
    //    the decisive restriction proof is the confined probe below, which shows
    //    the helper's integrity label above the command's Low label.
    // -----------------------------------------------------------------------
    await runCase('env-helper-is-unrestricted', async () => {
      const integrity = readIntegrity()
      const cRoot = probeWriteCRoot()
      const match = /S-1-16-(\d+)/.exec(integrity)
      assert(match !== null, 'helper 应有完整性标签（谁在跑这个测试）')
      const level = Number(match[1])
      assert(level >= 8192, 'helper 不应是 Low/受限令牌，实际：' + integrity)
      assertEqual(isInsideDirectory(WORKSPACE, DATA_ROOT), false, '账本目录必须在 workspace 之外：' + DATA_ROOT)
      return {
        helperIntegrity: integrity,
        canWriteCRoot: cRoot,
        ledgerRoot: DATA_ROOT,
        ledgerOutsideWorkspace: !isInsideDirectory(WORKSPACE, DATA_ROOT),
        note: 'C:\\ root writability is environment-dependent; the confined probe is the decisive evidence',
      }
    })

    // -----------------------------------------------------------------------
    // 1. Pod spawn + real runner + real confinement + pipe capture
    // -----------------------------------------------------------------------
    const first = newClient(RUNNER)
    active = first
    const { client, sandbox } = first
    await client.boot()

    await runCase('pod-spawn-and-real-confinement', async () => {
      assertEqual(client.mode(), 'none', 'boot 只连接，不应在启动时 spawn pod')
      const callsBefore = sandbox.confineCalls
      const { response, prepared } = await client.runArgv(hint, [process.execPath, CONFINEMENT_PROBE], WORKSPACE, 'confinement-probe')
      jobIds.push(response.jobId)
      runnerPids.push(response.runnerPid)
      lastJobContext = { client, hint, jobId: response.jobId }
      assertEqual(client.mode(), 'spawned', '首次 run 应 spawn pod')
      assertEqual(sandbox.confineCalls, callsBefore + 1, 'pod_run 必须恰好调用一次 confine（per-call 前缀）')
      const settled = await waitSettled(client, hint, response.jobId)
      assertEqual(settled.status, 'settled', 'confinement probe 应正常结束')
      assertEqual(settled.exitCode, 0, 'confinement probe 退出码')
      const all = await readAll(client, hint, response.jobId)
      const probe = lastJsonLine(all.text)
      assert(probe !== null, 'probe 应输出 JSON：' + all.text.slice(0, 500))
      assertEqual(probe.inside, 'ok', '工作区内的写入/删除应成功')
      assert(probe.outside !== 'ok', 'C:\\ 根写入必须被拒绝，实际：' + String(probe.outside))
      assertEqual(probe.whoamiStatus, 0, '受限进程内 whoami（文件重定向）应成功')
      assert(/S-1-16-(4096|2048|0)$/.test(String(probe.integrity)), '命令令牌应为 Low 完整性，实际：' + String(probe.integrity))
      const spawnInfo = client.spawnInfo()
      assert(typeof spawnInfo?.podPid === 'number', 'spawnInfo.podPid')
      const status = await client.status(hint)
      assertEqual(status.response.template.valid, true, 'pod 的形态模板应有效')
      assertEqual(status.response.template.runnerPath, RUNNER, '模板 runnerPath 应是真实 runner')
      assertEqual(status.response.template.workspaceRoot, WORKSPACE, '模板 workspace')
      assert(!('prefix' in status.response), 'pod 状态里不应存在缓存的 prefix 字段')
      return {
        podPid: spawnInfo.podPid,
        runnerPid: response.runnerPid,
        probe,
        perCallPrefixFingerprint: prepared.fingerprint.slice(0, 16),
        template: { runnerPath: status.response.template.runnerPath, modes: status.response.template.modes, workspaceRoot: status.response.template.workspaceRoot },
      }
    })

    // -----------------------------------------------------------------------
    // 2. Per-call prefix: exactly one fresh confine per pod_run, distinct values
    // -----------------------------------------------------------------------
    await runCase('per-call-prefix-freshness', async () => {
      const callsBefore = sandbox.confineCalls
      const firstRun = await client.runArgv(hint, [process.execPath, SLOW_PRINT, '2', '80'], WORKSPACE, 'fresh-1')
      jobIds.push(firstRun.response.jobId)
      runnerPids.push(firstRun.response.runnerPid)
      lastJobContext = { client, hint, jobId: firstRun.response.jobId }
      await waitSettled(client, hint, firstRun.response.jobId)
      const secondRun = await client.runArgv(hint, [process.execPath, SLOW_PRINT, '2', '80'], WORKSPACE, 'fresh-2')
      jobIds.push(secondRun.response.jobId)
      runnerPids.push(secondRun.response.runnerPid)
      lastJobContext = { client, hint, jobId: secondRun.response.jobId }
      await waitSettled(client, hint, secondRun.response.jobId)
      assertEqual(sandbox.confineCalls, callsBefore + 2, '两次 pod_run 必须恰好两次 confine')
      assert(firstRun.prepared.fingerprint !== secondRun.prepared.fingerprint, '两次调用的前缀必须不同（per-call 签发，非缓存）')
      const status = await client.status(hint)
      assertEqual(status.response.template.valid, true, '模板仍有效')
      assertEqual(status.response.template.runnerPath, RUNNER, '模板未被改写')
      const callsAfterStatus = sandbox.confineCalls
      await client.status(hint)
      assertEqual(sandbox.confineCalls, callsAfterStatus, 'pod 已连接时 status 不应再 confine')
      return {
        confineCalls: sandbox.confineCalls,
        fingerprint1: firstRun.prepared.fingerprint.slice(0, 16),
        fingerprint2: secondRun.prepared.fingerprint.slice(0, 16),
        distinct: firstRun.prepared.fingerprint !== secondRun.prepared.fingerprint,
      }
    })

    // -----------------------------------------------------------------------
    // 3. Tool layer: pod_run/pod_output through a real pwsh + confinement
    // -----------------------------------------------------------------------
    const tools = createTools(client, () => sandbox, { outputChunkBytes: 65536 })
    await runCase('tool-layer-pwsh-and-confined-write-denied', async () => {
      const insidePath = join(WORKSPACE, '.tmp', 'epc-tool-inside-' + RUN_ID + '.txt')
      const outsidePath = 'C:\\dsh-escape-pod-core-tool-probe.txt'
      // Select by NAME: the tool list is not a stable ordering contract (a new
      // tool inserted at index 1 used to make this case call pod_exec with a
      // pod_output argument map and fail with "command 不能为空").
      const runTool = tools.find((candidate) => candidate.name === 'pod_run')
      const outputTool = tools.find((candidate) => candidate.name === 'pod_output')
      assert(runTool !== undefined, 'pod_run 工具应存在')
      assert(outputTool !== undefined, 'pod_output 工具应存在')
      const runValue = await runTool.execute(
        {
          command:
            "try { [IO.File]::WriteAllText('" + outsidePath + "','x'); 'OUTSIDE-WROTE' } catch { 'OUTSIDE-DENIED: ' + $_.Exception.Message }; " +
            "[IO.File]::WriteAllText('" + insidePath + "','inside'); 'INSIDE-WROTE'",
        },
        fakeExec,
      )
      jobIds.push(runValue.jobId)
      lastJobContext = { client, hint, jobId: runValue.jobId }
      const settled = await waitSettled(client, hint, runValue.jobId)
      assertEqual(settled.status, 'settled', '工具层 job 应正常结束：' + JSON.stringify(settled).slice(0, 500))
      const output = await outputTool.execute({ jobId: runValue.jobId }, fakeExec)
      const outputText = String(output.text ?? '')
      assert(fs.existsSync(insidePath), '工具层命令应能在 workspace 内写文件；实际输出：' + outputText.slice(0, 1200))
      fs.unlinkSync(insidePath)
      assert(!fs.existsSync(outsidePath), '工具层命令不得在 C:\\ 根写出文件')
      assert(/OUTSIDE-DENIED/.test(outputText), '工具层输出应包含 C:\\ 写入被拒的证据：' + outputText.slice(0, 1200))
      assert(/INSIDE-WROTE/.test(outputText), '工具层输出应包含工作区写入成功的证据：' + outputText.slice(0, 1200))
      settledToolJob = runValue.jobId
      return { jobId: runValue.jobId, outputExcerpt: outputText.slice(0, 400), insidePath, outsideDenied: true }
    })

    // -----------------------------------------------------------------------
    // 4. Absolute offsets, meta-before-spawn, kill
    // -----------------------------------------------------------------------
    await runCase('absolute-offsets-and-kill', async () => {
      const { response } = await client.runArgv(hint, [process.execPath, SLOW_PRINT, '40', '200'], WORKSPACE, 'slow-print')
      jobIds.push(response.jobId)
      runnerPids.push(response.runnerPid)
      lastJobContext = { client, hint, jobId: response.jobId }
      const jobDir = join(DATA_ROOT, 'jobs', response.jobId)
      await sleep(500)
      const metaWhileRunning = fs.existsSync(join(jobDir, 'meta.json'))
      const exitWhileRunning = fs.existsSync(join(jobDir, 'exit.json'))
      assertEqual(metaWhileRunning, true, '运行中的 job 必须有 meta.json（先写 meta 再 spawn）')
      assertEqual(
        exitWhileRunning,
        false,
        '运行中的 job 不应有 exit.json；job 快照：' + JSON.stringify(await safeSnapshot(client, hint, response.jobId)).slice(0, 1500),
      )
      const firstChunk = await client.output(hint, { jobId: response.jobId, from: 0 })
      assert(String(firstChunk.text).includes('tick 0'), '首块应包含 tick 0')
      const firstOffset = firstChunk.nextOffset
      await sleep(700)
      const secondChunk = await client.output(hint, { jobId: response.jobId, from: firstOffset })
      assert(secondChunk.nextOffset > firstOffset, '续读应前进')
      assert(String(secondChunk.text).length > 0, '续读应拿到新字节')
      const kill = await client.kill(hint, { jobId: response.jobId })
      assertEqual(kill.ok, true, 'kill 应成功')
      const settled = await waitSettled(client, hint, response.jobId)
      assertEqual(settled.status, 'killed', 'kill 后状态应为 killed')
      const all = await readAll(client, hint, response.jobId)
      assert(all.text.startsWith(firstChunk.text), '完整输出应以首块为前缀')
      assertEqual(
        all.text.slice(firstOffset, firstOffset + String(secondChunk.text).length),
        String(secondChunk.text),
        '绝对偏移续读必须与完整输出逐字节对齐',
      )
      const frozen = all.totalBytes
      await sleep(900)
      const tail = await client.output(hint, { jobId: response.jobId, from: frozen })
      assertEqual(String(tail.text), '', 'kill 后从 total 偏移读应无新字节')
      assertEqual(tail.totalBytes, frozen, 'kill 后 totalBytes 不应再增长')
      assertEqual(tail.running, false, 'kill 后 running=false')
      return { jobId: response.jobId, metaWhileRunning, firstOffset, totalBytes: frozen, status: settled.status, exitCode: settled.exitCode }
    })

    // -----------------------------------------------------------------------
    // 5. Runner-failure classification (127 + windows-acl-run: signature)
    // -----------------------------------------------------------------------
    await runCase('runner-failure-classification', async () => {
      const { response } = await client.runArgv(hint, [process.execPath, FAIL_127], WORKSPACE, 'fail-127')
      jobIds.push(response.jobId)
      runnerPids.push(response.runnerPid)
      lastJobContext = { client, hint, jobId: response.jobId }
      const settled = await waitSettled(client, hint, response.jobId)
      assertEqual(settled.status, 'runner-failed', '127 + 签名应判定为 runner-failed')
      assertEqual(settled.exitCode, 127, 'exitCode 应保留 127')
      const all = await readAll(client, hint, response.jobId)
      assert(String(all.text).includes('windows-acl-run:'), '输出里应能看到 runner 的失败签名')
      return { jobId: response.jobId, status: settled.status, exitCode: settled.exitCode }
    })

    // -----------------------------------------------------------------------
    // 6. Ledger coherence (meta / out.log / exit.json)
    // -----------------------------------------------------------------------
    await runCase('ledger-shape-and-bytes', async () => {
      assert(settledToolJob !== null, '前一个工具层 job 应已存在')
      // The ledger must be OUTSIDE the workspace (a workspace-write command
      // could otherwise forge its own meta/out/exit).
      assertEqual(isInsideDirectory(WORKSPACE, DATA_ROOT), false, '账本根必须在 workspace 之外：' + DATA_ROOT)
      const jobDir = join(DATA_ROOT, 'jobs', settledToolJob)
      assert(jobDir.toLowerCase().startsWith(DATA_ROOT.toLowerCase()), 'job 目录应位于 stateDir 下：' + jobDir)
      const metaPath = join(jobDir, 'meta.json')
      const outPath = join(jobDir, 'out.log')
      const exitPath = join(jobDir, 'exit.json')
      assert(fs.existsSync(metaPath), 'meta.json 存在：' + metaPath)
      assert(fs.existsSync(outPath), 'out.log 存在：' + outPath)
      assert(fs.existsSync(exitPath), 'exit.json 存在：' + exitPath)
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'))
      const exit = JSON.parse(fs.readFileSync(exitPath, 'utf8'))
      const outBytes = fs.statSync(outPath).size
      assertEqual(meta.jobId, settledToolJob, 'meta.jobId')
      assert(typeof meta.runnerPid === 'number', 'meta.runnerPid 应为数字（spawn 后补齐）')
      assert(Array.isArray(meta.argv), 'meta.argv 应为数组')
      assertEqual(meta.argvHash, hashArgv(meta.argv), 'meta.argvHash 应为目标 argv 的 sha256')
      assertEqual(String(meta.argvHash).length, 64, 'argvHash 长度')
      assertEqual(String(meta.prefixFingerprint).length, 64, 'meta.prefixFingerprint 应为 sha256')
      assertEqual(meta.prefixProfile.grant, 'agentless (runner-managed temp)', 'meta 应记录 per-call 前缀的授权形态')
      assertEqual(meta.template.runnerPath, RUNNER, 'meta.template.runnerPath 应是真实 runner')
      assertEqual(exit.status, 'settled', 'exit.status')
      assertEqual(exit.exitCode, 0, 'exit.exitCode')
      assertEqual(exit.totalBytes, outBytes, 'exit.totalBytes 应等于 out.log 字节数')
      assert(Date.parse(meta.startedAt) <= Date.parse(exit.endedAt), 'startedAt 应不晚于 endedAt')
      return {
        dir: jobDir,
        outBytes,
        status: exit.status,
        metaRunnerPid: meta.runnerPid,
        prefixGrant: meta.prefixProfile.grant,
        argvHash: meta.argvHash,
        ledgerOutsideWorkspace: true,
      }
    })

    // -----------------------------------------------------------------------
    // 7. Reconnect (the DSH-restart analogue): same pod, same ledger, new prefix
    // -----------------------------------------------------------------------
    /** @type {any} */
    let reconnectClient = null
    await runCase('reconnect-same-pod-and-continue-reads', async () => {
      const beforeStatus = (await client.status(hint)).response
      const podPid = beforeStatus.podPid
      const beforeRead = await readAll(client, hint, settledToolJob)
      // Single-client: dispose the old Host BEFORE the new one connects; the pod
      // is then orphaned and the new Host claims it through `handover`.
      const second = await switchHost(RUNNER)
      const client2 = second.client
      assertEqual(client2.mode(), 'reused', '新客户端应复用仍然存活的 pod')
      const afterStatus = (await client2.status(hint)).response
      assertEqual(afterStatus.auth?.mode, 'token', 'pod 必须报告 token 鉴权')
      assertEqual(afterStatus.auth?.required, true, 'pod 必须要求每个请求带 token')
      assert(afterStatus.auth?.handoverCount >= 1, '新 Host 必须通过 handover 接管：' + JSON.stringify(afterStatus.auth ?? null))
      assertEqual(afterStatus.auth?.ownerAccepted, true, '接管后 ownerAccepted')
      assertEqual(afterStatus.identity?.seedHash, describePipeIdentity().seedHash, 'pod 报告的管道身份种子必须与 Host 一致')
      assertEqual(afterStatus.podPid, podPid, 'podPid 必须不变（同一 OS 进程）')
      assertEqual(afterStatus.podStartedAt, beforeStatus.podStartedAt, 'podStartedAt 不变')
      assertEqual(afterStatus.template.valid, true, '模板仍有效')
      assert(afterStatus.jobs.some((job) => job.jobId === settledToolJob), '新客户端应看到旧 job')
      const afterRead = await readAll(client2, hint, settledToolJob)
      assertEqual(afterRead.text, beforeRead.text, '重连后旧输出必须逐字节一致')
      const callsBefore = second.sandbox.confineCalls
      const run = await client2.runArgv(hint, [process.execPath, '-e', 'process.stdout.write("after-reconnect\\n")'], WORKSPACE, 'after-reconnect')
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      lastJobContext = { client: client2, hint, jobId: run.response.jobId }
      await waitSettled(client2, hint, run.response.jobId)
      const out = await readAll(client2, hint, run.response.jobId)
      assert(String(out.text).includes('after-reconnect'), '重连后应能执行新命令')
      assertEqual(second.sandbox.confineCalls, callsBefore + 1, '重连后的新 run 也应恰好一次 confine')
      reconnectClient = client2
      active = second
      return { podPid, jobsVisible: afterStatus.jobs.length, reused: client2.mode() === 'reused', newJob: run.response.jobId }
    })

    // -----------------------------------------------------------------------
    // 7b. Auth: no-token refusal + single-client EBUSY (real pipe)
    // -----------------------------------------------------------------------
    await runCase('auth-token-and-single-client', async () => {
      // 1. While a Host client holds the pipe, a second connection is refused
      //    as a second client — the first connection is untouched. The refusal
      //    is correlated to the rejected request, so it must arrive as EBUSY
      //    (not as a bare close/ECLOSED).
      const busy = new RawPipeClient(PIPE)
      await busy.connect()
      /** @type {any} */
      let busyResponse = null
      try {
        busyResponse = await busy.request('status', {})
      } catch (error) {
        busyResponse = { ok: false, error: { code: 'ECLOSED', message: messageOf(error) } }
      }
      busy.close()
      assertEqual(busyResponse?.ok, false, '第二条连接必须被拒')
      assertEqual(busyResponse?.error?.code, 'EBUSY', '已有连接时的第二个连接应 EBUSY（不是 ECLOSED）：' + JSON.stringify(busyResponse ?? null))

      // 2. Free the pipe; a request without the token must be refused and closed.
      for (const entry of clients) {
        try {
          entry.client.dispose()
        } catch {
          // best effort
        }
      }
      await sleep(250)
      const untokened = new RawPipeClient(PIPE)
      await untokened.connect()
      const closed = new Promise((resolveClose) => {
        untokened.socket.once('close', () => resolveClose(true))
        setTimeout(() => resolveClose(false), 1500)
      })
      const denied = await untokened.request('status', {})
      assertEqual(denied.ok, false, '无 token 请求必须被拒')
      assertEqual(denied.error.code, 'EBADTOKEN', '无 token 应 EBADTOKEN：' + JSON.stringify(denied))
      assertEqual(await closed, true, '鉴权失败后 pod 必须关闭连接')
      untokened.close()

      // 3. Claim the orphaned pod; a concurrent second connection is EBUSY and
      //    the first one keeps working.
      const claimed = await connectRaw()
      const second = new RawPipeClient(PIPE)
      await second.connect()
      /** @type {any} */
      let secondResponse = null
      try {
        secondResponse = await second.request('status', {})
      } catch (error) {
        secondResponse = { ok: false, error: { code: 'ECLOSED', message: messageOf(error) } }
      }
      second.close()
      assertEqual(secondResponse?.error?.code, 'EBUSY', '被接管的 pod 同时只服务一个连接')
      const stillOk = await claimed.request('status', {})
      assertEqual(stillOk.ok, true, '拒绝第二个连接不得影响第一个连接')
      claimed.close()
      active = await switchHost(RUNNER)
      return {
        busyCode: busyResponse?.error?.code ?? null,
        noTokenCode: denied.error.code,
        connectionClosedOnBadToken: true,
        secondConnectionCode: secondResponse?.error?.code ?? null,
        firstConnectionUnaffected: stillOk.ok === true,
      }
    })

    // -----------------------------------------------------------------------
    // 8. Honest unknown after the pod dies mid-job
    // -----------------------------------------------------------------------
    await runCase('honest-unknown-after-pod-death', async () => {
      const clientCurrent = active === null ? client : active.client
      const sandboxCurrent = active === null ? sandbox : active.sandbox
      const run = await clientCurrent.runArgv(hint, [process.execPath, SLOW_PRINT, '60', '200'], WORKSPACE, 'long-job')
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      lastJobContext = { client: clientCurrent, hint, jobId: run.response.jobId }
      await sleep(500)
      const podPid = (await clientCurrent.status(hint)).response.podPid
      process.kill(podPid, 'SIGKILL')
      await sleep(700)
      const third = await switchHost(RUNNER)
      const status = await third.client.status(hint)
      assert(status.response.podPid !== podPid, 'pod 被杀后应重建（新 podPid）')
      const oldJob = status.response.jobs.find((job) => job.jobId === run.response.jobId)
      assert(oldJob !== undefined, '新 pod 应从账本列出旧 job')
      assertEqual(
        oldJob.status,
        'unknown',
        '没有 exit.json 的旧 job 必须如实报 unknown；实际：' + JSON.stringify(oldJob ?? null).slice(0, 800),
      )
      // reap the orphan runner this pod left behind (it is not ours any more)
      if (typeof run.response.runnerPid === 'number') {
        spawnSync('taskkill.exe', ['/PID', String(run.response.runnerPid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
      }
      active = third
      void sandboxCurrent
      return { killedPodPid: podPid, rebuiltPodPid: status.response.podPid, oldJobStatus: oldJob.status }
    })

    // -----------------------------------------------------------------------
    // 9. Stale per-call prefix rejected before any spawn (raw protocol)
    // -----------------------------------------------------------------------
    await runCase('stale-prefix-fail-closed', async () => {
      const raw = await connectRaw()
      try {
        const missingTemp = join(os.tmpdir(), 'epc-missing-temp-' + RUN_ID)
        const stalePrefix = [process.execPath, RUNNER, '--workspace', WORKSPACE, '--temp', missingTemp, '--mode', 'workspace-write']
        const staleResponse = await raw.request('run', { prefix: stalePrefix, argv: [process.execPath, '-e', '1'], cwd: WORKSPACE })
        assertEqual(staleResponse.ok, false, 'temp 不存在的 per-call 前缀应被拒绝')
        assertEqual(staleResponse.error.code, 'EPREFIXSTALE', 'EPREFIXSTALE')
        const otherWorkspace = join(WORKSPACE, '.tmp')
        const wrongWorkspacePrefix = [process.execPath, RUNNER, '--workspace', otherWorkspace, '--temp', os.tmpdir(), '--mode', 'workspace-write']
        const mismatch = await raw.request('run', { prefix: wrongWorkspacePrefix, argv: [process.execPath, '-e', '1'], cwd: WORKSPACE })
        assertEqual(mismatch.ok, false, 'workspace 与模板不一致的 per-call 前缀应被拒绝')
        assertEqual(mismatch.error.code, 'EPREFIXWORKSPACETEMPLATE', 'EPREFIXWORKSPACETEMPLATE')
        const notInTree = [process.execPath, join(WORKSPACE, 'runner.js'), '--workspace', WORKSPACE, '--temp', os.tmpdir(), '--mode', 'workspace-write']
        const tree = await raw.request('run', { prefix: notInTree, argv: [process.execPath, '-e', '1'], cwd: WORKSPACE })
        assertEqual(tree.error.code, 'EPREFIXRUNNERPATH', 'DSH 安装树外的 runner 应被拒绝')
        return { stale: staleResponse.error.code, workspaceMismatch: mismatch.error.code, runnerOutsideTree: tree.error.code }
      } finally {
        raw.close()
      }
    })
    // The raw client closed the pipe; the next Host boots (and handovers) again.
    active = await switchHost(RUNNER)

    // -----------------------------------------------------------------------
    // 10. cwd containment: workspaces are the only legal job cwd
    // -----------------------------------------------------------------------
    await runCase('cwd-outside-workspace-rejected', async () => {
      const activeClient = active === null ? client : active.client
      let hostCode = null
      try {
        await activeClient.runArgv(hint, [process.execPath, '-e', 'process.stdout.write("should-not-run\\n")'], 'C:\\', 'cwd-outside')
      } catch (error) {
        hostCode = /** @type {any} */ (error)?.code ?? null
      }
      assertEqual(hostCode, 'ECWDWORSKSPACE', 'Host 侧必须拒绝 workspace 外的 cwd')
      // Pod side re-checks too: send a template-shaped prefix with a cwd outside.
      const raw = await connectRaw()
      try {
        const prefix = [process.execPath, RUNNER, '--workspace', WORKSPACE, '--temp', os.tmpdir(), '--mode', 'workspace-write']
        const response = await raw.request('run', { prefix, argv: [process.execPath, '-e', '1'], cwd: 'C:\\' })
        assertEqual(response.ok, false, 'pod 侧也必须拒绝 workspace 外的 cwd')
        assertEqual(response.error.code, 'ECWDWORSKSPACE', 'pod 侧错误码')
        const status = await raw.request('status', {})
        assertEqual(status.ok, true, 'status 仍可用（拒绝没有破坏 pod）')
        return { hostCode, podCode: response.error.code }
      } finally {
        raw.close()
      }
    })
    active = await switchHost(RUNNER)

    // -----------------------------------------------------------------------
    // 10b. ctx.jobs adoption against the REAL pod (fake registry): no replay,
    //      teardown never kills, explicit kill really kills.
    // -----------------------------------------------------------------------
    await runCase('adoption-real-pod-teardown-no-kill', async () => {
      const clientCurrent = active === null ? client : active.client
      const run = await clientCurrent.runArgv(hint, [process.execPath, SLOW_PRINT, '200', '60'], WORKSPACE, 'adoption-slow')
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      await sleep(600)
      const initial = await clientCurrent.output(hint, { jobId: run.response.jobId, from: 0, maxBytes: 262144 })
      assertEqual(initial.running, true, 'adoption probe job 应仍在 running')
      assert(initial.totalBytes > 0, 'adoption 前应已有输出')
      assert(String(initial.text).includes('tick 0'), '应有早期输出作为“不可重放”的判据')

      const jobs = createFakeJobsForAdoption()
      const manager = createAdoptionManager({ getJobs: () => jobs, pod: clientCurrent, autoPoll: false, log: () => {} })
      const registryId = manager.adopt({
        podJobId: run.response.jobId,
        command: 'adoption slow print',
        baseOffset: initial.totalBytes,
        hint,
      })
      assert(registryId !== null, '真 pod job 应能收养')
      assertEqual(manager.recordFor(run.response.jobId).baseOffset, initial.totalBytes, '收养偏移 = 收养时已读偏移')
      await sleep(500)
      await manager.pollAllOnce()
      const appended = jobs.started.get(registryId).handle.appended.map((row) => row.text).join('')
      assert(appended.length > 0, '收养后应泵到新输出')
      assert(!appended.includes('tick 0'), 'job_output 不能重放收养前的历史：' + JSON.stringify(appended.slice(0, 160)))

      // THE LIFELINE: a registry teardown cancel must settle the record and keep
      // the pod command running.
      jobs.started.get(registryId).hooks.cancel('jobs service disposed')
      const tornDown = await jobs.started.get(registryId).hooks.done
      assertEqual(tornDown.status, 'killed', 'teardown 应结算（否则 dispose 会挂起）')
      assert(String(tornDown.detail).includes('left running'), 'detail 必须说明命令仍在跑')
      await sleep(500)
      const stillRunning = await clientCurrent.output(hint, { jobId: run.response.jobId, from: 0, maxBytes: 262144 })
      assertEqual(stillRunning.running, true, 'teardown 后 pod 命令必须仍在运行')
      assert(stillRunning.totalBytes > initial.totalBytes, 'pod 命令必须还在产出')

      // Explicit job_kill path: the pre-execute marker beats even a sentinel reason.
      const jobs2 = createFakeJobsForAdoption()
      const manager2 = createAdoptionManager({ getJobs: () => jobs2, pod: clientCurrent, autoPoll: false, log: () => {} })
      const registryId2 = manager2.adopt({
        podJobId: run.response.jobId,
        command: 'adoption slow print',
        baseOffset: stillRunning.totalBytes,
        hint,
      })
      manager2.noteExplicitKill(registryId2)
      jobs2.started.get(registryId2).hooks.cancel('jobs service disposed')
      const done2 = jobs2.started.get(registryId2).hooks.done
      let settled2 = false
      for (let round = 0; round < 80; round += 1) {
        await manager2.pollAllOnce()
        settled2 = await Promise.race([done2.then(() => true), sleep(100).then(() => false)])
        if (settled2) break
        await sleep(100)
      }
      assertEqual(settled2, true, '显式 kill 后 registry 记录应结算')
      const outcome2 = await done2
      assertEqual(outcome2.status, 'killed', '显式 kill 应映射 killed')
      const final = await clientCurrent.output(hint, { jobId: run.response.jobId, from: 0, maxBytes: 262144 })
      assertEqual(final.running, false, '显式 kill 必须真杀掉 pod 命令')
      assertEqual(final.status, 'killed', 'pod 侧状态应为 killed')
      manager.dispose()
      manager2.dispose()
      return {
        jobId: run.response.jobId,
        adoptionBase: initial.totalBytes,
        appendedBytes: appended.length,
        replayedHistory: false,
        teardownKilledPod: false,
        teardownSettled: tornDown.status,
        explicitKillWorked: true,
        finalStatus: final.status,
      }
    })

    // -----------------------------------------------------------------------
    // 10c. Output cursor: ack → "restart" (new Host client) → seamless
    //      continuation. Ticks must be contiguous, with no replay and no gap.
    // -----------------------------------------------------------------------
    await runCase('cursor-ack-restart-continuity', async () => {
      const clientCurrent = active === null ? client : active.client
      const run = await clientCurrent.runArgv(hint, [process.execPath, TICK_LINES, '400', '40'], WORKSPACE, 'tick-lines')
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      const jobId = run.response.jobId
      await sleep(500)

      const first = await clientCurrent.output(hint, { jobId, from: 0, maxBytes: 65536 })
      assertEqual(first.running, true, '游标用例的 job 应仍在 running')
      assert(first.text.startsWith('T0001'), '首读应从 T0001 开始：' + JSON.stringify(first.text.slice(0, 20)))
      assertEqual(typeof first.prefixHash, 'string', 'output 应返回 prefixHash')
      assertEqual(first.prefixHash.length, 64, 'prefixHash 应为 sha256')

      // What pod_output does after a successful read.
      const ack = await clientCurrent.ack(hint, { jobId, offset: first.nextOffset, hash: first.prefixHash })
      assertEqual(ack.ok, true, 'ack 应成功：' + JSON.stringify(ack))
      assertEqual(ack.offset, first.nextOffset, 'ack 回显 offset')
      const cursorPath = join(DATA_ROOT, 'jobs', jobId, 'cursor.json')
      assert(fs.existsSync(cursorPath), 'cursor.json 应写入账本：' + cursorPath)
      const stored = JSON.parse(fs.readFileSync(cursorPath, 'utf8'))
      assertEqual(stored.offset, first.nextOffset, 'cursor.offset')
      assertEqual(stored.hash, first.prefixHash, 'cursor.hash')
      assertEqual(stored.algorithm, 'sha256-prefix', 'cursor.algorithm')

      // "Restart DSH": a brand-new Host client. The pod serves one client at a
      // time, so the old client is gone first; the pod and its ledger persist
      // and the new Host takes the pod over through `handover`.
      const second = await switchHost(RUNNER)
      await sleep(800)
      const status2 = await second.client.status(hint)
      const job2 = status2.response.jobs.find((job) => job.jobId === jobId)
      assert(job2 !== undefined, '新 Host 应从 pod 看到该 job')
      assertEqual(job2.cursor.state, 'ok', '新 Host 应看到可用的 cursor：' + JSON.stringify(job2.cursor))
      assertEqual(job2.cursor.offset, first.nextOffset, 'cursor.offset 应等于上次 ack 的偏移')

      const jobs = createFakeJobsForAdoption()
      const manager = createAdoptionManager({ getJobs: () => jobs, pod: second.client, autoPoll: false, log: () => {} })
      const adoption = await manager.ensureAdopted(hint, { force: true, jobs: status2.response.jobs })
      assert(adoption.adopted >= 1, '新 Host 应收养 running job')
      const adoptedRecord = manager.recordFor(jobId)
      assert(adoptedRecord !== null, '应能拿到收养记录')
      assertEqual(adoptedRecord.baseOffset, first.nextOffset, '收养应从 cursor.offset 开始，而不是 pod 当前 totalBytes')
      assertEqual(adoptedRecord.cursorMode, 'ok', 'cursorMode=ok')
      await sleep(900)
      await manager.pollAllOnce()
      const registryId = adoptedRecord.registryId
      const appended = jobs.started.get(registryId).handle.appended.map((row) => row.text).join('')

      // Continuity: consumed prefix + adopted delta must be the same tick run,
      // contiguous from T0001, with no replay and no skipped line.
      const combined = first.text + appended
      const lines = combined.split('\n')
      const complete = combined.endsWith('\n') ? lines.slice(0, -1) : lines.slice(0, -1)
      const numbers = complete.map((line) => {
        const match = /^T(\d{4})$/.exec(line)
        return match === null ? null : Number(match[1])
      })
      assert(numbers.every((value) => value !== null), '拼接后应只有 T#### 行：' + JSON.stringify(complete.slice(0, 5)))
      assertEqual(numbers[0], 1, '应从 T0001 开始')
      for (let index = 1; index < numbers.length; index += 1) {
        assertEqual(numbers[index], numbers[index - 1] + 1, 'tick 必须连续（缺口在 ' + String(numbers[index - 1]) + '→' + String(numbers[index]) + '）')
      }
      assert(numbers.length >= 8, '应至少拼出 8 行，实际=' + String(numbers.length))
      assert(!appended.includes('T0001'), 'adoption 不能重放 cursor 之前的历史')

      // Tamper the anchor: the pod must report mismatch; a fresh adoption must
      // NOT silently continue from the unverified offset.
      fs.writeFileSync(cursorPath, JSON.stringify({ ...stored, hash: '0'.repeat(64) }))
      const status3 = await second.client.status(hint)
      const job3 = status3.response.jobs.find((job) => job.jobId === jobId)
      assertEqual(job3.cursor.state, 'mismatch', '篡改 hash 后 cursor 应为 mismatch')
      assertEqual(job3.cursor.valid, false, 'mismatch 不 valid')
      const jobs2 = createFakeJobsForAdoption()
      const manager2 = createAdoptionManager({ getJobs: () => jobs2, pod: second.client, autoPoll: false, log: () => {} })
      const adoption2 = await manager2.ensureAdopted(hint, { force: true, jobs: status3.response.jobs })
      assert(adoption2.adopted >= 1, 'mismatch 仍应收养（用于 job_list/job_kill）')
      const record2 = manager2.recordFor(jobId)
      assertEqual(record2.cursorMode, 'cursor-mismatch', '应明确标记 cursor-mismatch')
      assertEqual(record2.baseOffset, job3.bytes, 'mismatch 时应从 pod 当前 totalBytes 起，不静默续读')
      assert(String(record2.cursorWarning).includes('cursor-mismatch'), '应带告警文本')
      manager.dispose()
      manager2.dispose()
      await second.client.kill(hint, { jobId })
      return {
        jobId,
        ackOffset: first.nextOffset,
        cursorState: job2.cursor.state,
        adoptionBase: adoptedRecord.baseOffset,
        appendedBytes: appended.length,
        ticks: numbers.length,
        replayedHistory: false,
        gap: false,
        mismatchState: job3.cursor.state,
        mismatchAdoption: record2.cursorMode,
      }
    })

    // -----------------------------------------------------------------------
    // 10d. Model-face fidelity: no offsets, auto cursor, UTF-8/line aligned
    //      chunks, byte-identical concatenation, job_output-driven ack.
    // -----------------------------------------------------------------------
    await runCase('model-face-fidelity', async () => {
      const clientCurrent = active === null ? client : active.client
      const run = await clientCurrent.runArgv(hint, [process.execPath, TEXT_LINES, '260', '10'], WORKSPACE, 'text-lines')
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      const jobId = run.response.jobId
      const settings = { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }
      const tools = createTools(clientCurrent, () => null, settings, null, () => {})
      const outputTool = tools.find((candidate) => candidate.name === 'pod_output')
      assert(outputTool !== undefined, 'pod_output 应存在')
      assert(!Object.hasOwn(outputTool.parameters.properties, 'from'), '模型面 schema 不得有 from')
      const exec = { agent: { id: 'selftest-model', session: { meta: { cwd: WORKSPACE } } } }
      const pieces = []
      let value = null
      for (let round = 0; round < 400; round += 1) {
        value = await outputTool.execute({ jobId }, exec)
        for (const forbidden of ['from', 'nextOffset', 'totalBytes', 'prefixHash']) {
          assertEqual(Object.hasOwn(value, forbidden), false, '模型返回值不得含 ' + forbidden)
        }
        assert(!/offset|nextOffset/.test(String(value.message)), '模型主文本不得含偏移：' + String(value.message).slice(0, 120))
        assert(!value.text.includes('\uFFFD'), '不得返回替换字符')
        if (value.text.length > 0) pieces.push(Buffer.from(value.text, 'utf8'))
        if (value.running === false && value.text === '') break
        await sleep(60)
      }
      assert(value !== null && value.running === false, '命令应在循环内结束')
      const outPath = join(DATA_ROOT, 'jobs', jobId, 'out.log')
      const fileBytes = fs.readFileSync(outPath)
      const joined = Buffer.concat(pieces)
      assertEqual(joined.equals(fileBytes), true, '模型面多次读取拼接必须与 out.log 逐字节一致')
      assert(joined.toString('utf8').includes('中文测试😀🚀'), '应包含多字节内容')
      assert(!joined.toString('utf8').includes('\uFFFD'), '拼接后不得有替换字符')
      for (const piece of pieces.slice(0, -1)) {
        assert(piece.length === 0 || piece[piece.length - 1] === 0x0a, '中间块必须以换行结尾（不在行中切断）')
      }

      // Channel fidelity on the raw pod read: segments split stdout/stderr
      // without moving offsets, and re-concatenating the chunks is byte-identical.
      const raw = await clientCurrent.output(hint, { jobId, from: 0, maxBytes: fileBytes.length + 64 })
      assert(raw.chunks.length > 0, 'output 应返回 channel chunks')
      const channels = new Set(raw.chunks.map((chunk) => chunk.channel))
      assert(channels.has('stdout'), '应包含 stdout chunk')
      assert(channels.has('stderr'), '应包含 stderr chunk（fixture 每 3 行写 stderr）')
      let walk = 0
      const channelBytes = []
      for (const chunk of raw.chunks) {
        assertEqual(chunk.offset, walk, 'chunk.offset 必须连续且不移动既有偏移')
        const slice = fileBytes.subarray(chunk.offset, chunk.offset + chunk.length)
        assertEqual(Buffer.from(chunk.text, 'utf8').equals(slice), true, 'chunk 文本字节必须等于 out.log 切片')
        channelBytes.push(Buffer.from(chunk.text, 'utf8'))
        walk += chunk.length
      }
      assertEqual(walk, fileBytes.length, 'chunks 应覆盖整个 out.log')
      assertEqual(Buffer.concat(channelBytes).equals(fileBytes), true, '按 chunk 顺序拼接仍逐字节一致')
      assertEqual(typeof raw.spillPath, 'string', 'output 应报告 spillPath')
      assertEqual(raw.spillPath, outPath, 'spillPath 指向 out.log')

      const cursor = await clientCurrent.cursor(hint, { jobId })
      assertEqual(cursor.state, 'ok', 'cursor.state')
      assertEqual(cursor.offset, fileBytes.length, '模型面读取应把 cursor 推进到全文末尾')

      // Restart: the cursor is already at the end, so a new Host must not replay.
      const second = await switchHost(RUNNER)
      const tools2 = createTools(second.client, () => null, settings, null, () => {})
      const replay = await tools2.find((candidate) => candidate.name === 'pod_output').execute({ jobId }, exec)
      assertEqual(replay.text, '', '重启后已读游标在末尾 → 不应重放任何历史输出')

      // job_output path: registry consumption also advances the pod cursor.
      const run2 = await second.client.runArgv(hint, [process.execPath, TEXT_LINES, '120', '10'], WORKSPACE, 'text-lines-ack')
      jobIds.push(run2.response.jobId)
      runnerPids.push(run2.response.runnerPid)
      const jobs2 = createFakeJobsForAdoption()
      const manager = createAdoptionManager({ getJobs: () => jobs2, pod: second.client, autoPoll: false, log: () => {} })
      const registryId = manager.adopt({ podJobId: run2.response.jobId, command: 'job_output ack probe', baseOffset: 0, hint })
      assert(registryId !== null, '应能收养')
      await sleep(500)
      await manager.pollAllOnce()
      const rows = jobs2.started.get(registryId).handle.appended
      const appended = rows.reduce((total, row) => total + Buffer.byteLength(row.text, 'utf8'), 0)
      assert(appended > 0, '收养泵应先追加一些输出')
      const adoptedChannels = new Set(rows.map((row) => row.options?.channel))
      assert(adoptedChannels.has('stdout'), 'adoption 应以 channel=stdout append')
      assert(adoptedChannels.has('stderr'), 'adoption 应以 channel=stderr append')
      const adoptedBytes = Buffer.concat(rows.map((row) => Buffer.from(row.text, 'utf8')))
      const full2 = fs.readFileSync(join(DATA_ROOT, 'jobs', run2.response.jobId, 'out.log'))
      assert(full2.length >= adoptedBytes.length, 'out.log 应至少包含已收养字节')
      assertEqual(full2.subarray(0, adoptedBytes.length).equals(adoptedBytes), true, '收养追加的字节必须是 out.log 前缀')
      const views = { get: () => ({ output: { total: appended } }) }
      createJobOutputAckHook({ getJobs: () => views, adoptions: manager, pod: second.client, log: () => {} })(
        { name: 'job_output', arguments: { job_id: registryId }, agent: { id: 'selftest-model' } },
        { isError: false },
      )
      await sleep(500)
      const cursor2 = await second.client.cursor(hint, { jobId: run2.response.jobId })
      assertEqual(cursor2.offset, appended, 'job_output 后 cursor 应 = baseOffset + output.total')
      manager.dispose()
      await second.client.kill(hint, { jobId: run2.response.jobId })
      return {
        jobId,
        bytes: fileBytes.length,
        chunks: pieces.length,
        byteIdentical: true,
        replacementChars: 0,
        midLineCuts: 0,
        channelChunks: raw.chunks.length,
        channels: [...channels].join(','),
        chunkBytesAligned: true,
        spillPath: raw.spillPath,
        adoptedChannels: [...adoptedChannels].join(','),
        restartedNoReplay: replay.text === '',
        jobOutputAckOffset: cursor2.offset,
      }
    })

    // -----------------------------------------------------------------------
    // 10e. P1 alignment: fresh DSH_* env per run, description in meta/status,
    //      and pod_output → registry-cursor sync on an adopted job.
    // -----------------------------------------------------------------------
    await runCase('p1-env-description-cursor', async () => {
      const clientCurrent = active === null ? client : active.client
      const exec = { agent: { id: 'selftest-p1', session: { meta: { cwd: WORKSPACE } } } }
      // Set AFTER the pod may already exist: only a per-call snapshot can see it.
      process.env.DSH_EPC_FRESH = 'fresh-42'
      const probe = [process.execPath, '-e', "process.stdout.write(String(process.env.DSH_EPC_FRESH ?? 'missing'))"]
      const run = await clientCurrent.runArgv(hint, probe, WORKSPACE, 'env probe', { description: 'env freshness probe' })
      jobIds.push(run.response.jobId)
      runnerPids.push(run.response.runnerPid)
      const settled = await waitSettled(clientCurrent, hint, run.response.jobId)
      const fullProbe = await clientCurrent.output(hint, { jobId: run.response.jobId, from: 0, maxBytes: 65536 })
      assertEqual(fullProbe.text.includes('fresh-42'), true, 'DSH_* 必须按调用时的当前值下发（不是 spawn 时快照）：' + fullProbe.text)
      const status = await clientCurrent.status(hint)
      const row = status.response.jobs.find((job) => job.jobId === run.response.jobId)
      assert(row !== undefined, 'status 应包含该 job')
      assertEqual(row.description, 'env freshness probe', 'description 存进 meta 并出现在 status')

      const jobs = createFakeJobsForAdoption()
      const manager = createAdoptionManager({ getJobs: () => jobs, pod: clientCurrent, autoPoll: false, log: () => {} })
      const registryId = manager.adopt({ podJobId: run.response.jobId, command: 'env probe', baseOffset: 0, hint })
      assert(registryId !== null, '应能收养 env probe')
      const tools = createTools(clientCurrent, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 65536 }, manager, () => {})
      const outputTool = tools.find((candidate) => candidate.name === 'pod_output')
      const value = await outputTool.execute({ jobId: run.response.jobId }, exec)
      assert(value.text.includes('fresh-42'), 'pod_output 应读到 env probe 输出')
      await sleep(150)
      assertEqual(jobs.reads.includes(registryId), true, 'pod_output 成功推进 pod 游标后应同步 registry read')
      await manager.pollAllOnce()
      const record = manager.recordFor(run.response.jobId)
      assertEqual(record.settled, true, '已结束的 job 应结算')
      assertEqual(record.outcome.status, 'completed', '正常结束 → completed')
      assertEqual(record.outcome.detail, undefined, 'completed 不得带 detail（原生 [status: completed]）')
      manager.dispose()
      await clientCurrent.kill(hint, { jobId: run.response.jobId })
      return {
        jobId: run.response.jobId,
        envFresh: fullProbe.text.trim(),
        description: row.description,
        registryCursorSynced: jobs.reads.includes(registryId),
      }
    })

    // -----------------------------------------------------------------------
    // 11. Graceful pod shutdown via the maintenance op
    // -----------------------------------------------------------------------
    await runCase('pod-shutdown', async () => {
      const raw = await connectRaw()
      try {
        const status = await raw.request('status', {})
        for (const job of Array.isArray(status.jobs) ? status.jobs : []) {
          if (job.running === true) await raw.request('kill', { jobId: job.jobId })
        }
        const response = await raw.request('shutdown', {})
        assertEqual(response.ok, true, 'shutdown op 应被接受')
      } finally {
        raw.close()
      }
      const gone = await waitPipeGone(PIPE, 10000)
      assertEqual(gone, true, 'pod 应退出、管道应消失')
      return { pipeGone: true }
    })
  } finally {
    // -----------------------------------------------------------------------
    // Cleanup: clients, leftover jobs, temp dirs, orphan runners, result file
    // -----------------------------------------------------------------------
    for (const entry of clients) {
      try {
        entry.client.dispose()
      } catch {
        // best effort
      }
    }
    const cleanup = { removedJobs: [], removedTempDirs: 0, orphanKills: [] }
    // Best effort: ask the pod to die if a case failed before case 10.
    const probe = await canConnectPipe(PIPE)
    if (probe.ok === true) {
      /** @type {any} */
      let raw = null
      try {
        raw = await connectRaw()
        const status = await raw.request('status', {})
        for (const job of Array.isArray(status.jobs) ? status.jobs : []) {
          if (job.running === true) {
            try {
              await raw.request('kill', { jobId: job.jobId })
            } catch {
              // ignore
            }
          }
        }
        await raw.request('shutdown', {})
      } catch {
        // ignore: the pod may be held by a live Host (EBUSY) or already gone
      } finally {
        if (raw !== null) raw.close()
      }
      await waitPipeGone(PIPE, 5000)
    }
    for (const runnerPid of runnerPids) {
      if (typeof runnerPid !== 'number') continue
      const kill = spawnSync('taskkill.exe', ['/PID', String(runnerPid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
      if (kill.status === 0) cleanup.orphanKills.push(runnerPid)
    }
    for (const jobId of jobIds) {
      if (helpers.keep === true) break
      const dir = join(DATA_ROOT, 'jobs', jobId)
      try {
        fs.rmSync(dir, { recursive: true, force: true })
        cleanup.removedJobs.push(jobId)
      } catch {
        // ignore
      }
    }
    cleanup.keptJobs = helpers.keep === true ? jobIds.slice() : []
    if (helpers.keep !== true) {
      for (const dir of tempDirs) {
        try {
          fs.rmSync(dir, { recursive: true, force: true })
          cleanup.removedTempDirs += 1
        } catch {
          // ignore
        }
      }
    }
    try {
      const jobsRoot = join(DATA_ROOT, 'jobs')
      if (fs.existsSync(jobsRoot) && fs.readdirSync(jobsRoot).length === 0) fs.rmdirSync(jobsRoot)
      if (fs.existsSync(DATA_ROOT) && fs.readdirSync(DATA_ROOT).length === 0) fs.rmdirSync(DATA_ROOT)
    } catch {
      // ignore
    }
    // Remove a legacy in-workspace ledger left over from an older build, so the
    // inspected tree cannot suggest the ledger is still inside the workspace.
    try {
      if (fs.existsSync(LEGACY_WORKSPACE_LEDGER)) {
        const entries = fs.readdirSync(LEGACY_WORKSPACE_LEDGER)
        if (entries.length === 0) fs.rmdirSync(LEGACY_WORKSPACE_LEDGER)
        cleanup.legacyWorkspaceLedger = entries.length === 0 ? 'removed-empty' : 'kept-nonempty'
      }
    } catch {
      // ignore
    }
    result.finishedAt = new Date().toISOString()
    result.cleanup = cleanup
    result.cases = results
    result.logs = logs.slice(-200)
    result.ok = results.length > 0 && results.every((row) => row.ok)
    writeResult(result)
  }

  const passed = results.filter((row) => row.ok).length
  const failed = results.length - passed
  process.stdout.write('\n远端自测：' + passed + ' 通过 / ' + failed + ' 失败 → ' + RESULT_PATH + '\n')
  process.stdout.write(JSON.stringify({ ok: failed === 0, passed, failed }) + '\n')
  return result
}

const watchdog = setTimeout(() => {
  process.stdout.write('[FAIL] watchdog: 远端自测超时\n')
  process.exitCode = 3
  process.exit(3)
}, 240000)
watchdog.unref?.()

const outcome = await main()
clearTimeout(watchdog)
process.exitCode = outcome.ok === true ? 0 : 1
