#!/usr/bin/env node
/**
 * Static self-test for @local/dsh-escape-pod (the standalone escape pod; revised contract).
 *
 * Runs inside a *restricted* (Low integrity / WRITE_RESTRICTED) shell: it does
 * not spawn children with pipes and does not open a named-pipe client, both of
 * which are documented EPERM boundaries of a restricted token. What it covers:
 *
 *   - shared pipe-name derivation, prefix/template validators, DSH-install-tree
 *     runner check, UTF-8 offset math, state-dir defaults (outside workspace)
 *     and argvHash;
 *   - the Host-side per-call prefix derivation (`derivePrefix`) against a fake
 *     sandbox seam, including session -> agentless fallback and fail-closed cases;
 *   - cwd containment (must stay inside the policy workspace);
 *   - the pod's protocol state machine (`createPodService().handle()`) over a
 *     fake transport: template pinning, run rejections, stale temp, output
 *     offsets, kill, three job states, spawn failure, ledger outside workspace.
 *
 * Full pipe + real windows-acl runner + real `C:\` denial is covered by
 * `selftest-remote.mjs`, which must run as an unrestricted process.
 *
 * Usage: node scripts/selftest-static.mjs
 */

import fs from 'node:fs'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes, createHash } from 'node:crypto'

import {
  DEFAULT_IDLE_EXIT_MS,
  DEFAULT_OUTPUT_CHUNK_BYTES,
  DEFAULT_RING_BYTES,
  FALLBACK_OUTPUT_CHUNK_BYTES,
  MAX_OUTPUT_CHUNK_BYTES,
  PIPE_PREFIX,
  PIPE_STEM,
  describePipeIdentity,
  describeTemplate,
  fingerprintPrefix,
  generatePodToken,
  hashArgv,
  identitySeedHash,
  isDshInstallRunnerPath,
  isInsideDirectory,
  isPodToken,
  jobOwnership,
  resolveIdentitySeed,
  resolvePipeName,
  resolveStateDir,
  tokenFingerprint,
  tokensEqual,
  trimIncompleteUtf8End,
  validatePrefix,
  validateTemplate,
} from '../shared.mjs'
import { MAX_JOB_TIMEOUT_MS, attestationOutcome, createConnectionHandler, createPodAuth, createPodService, jobTimeoutOf, neutralizePodStdin, parseArgs, readTokenFromStdin, recordAttestationOutcome, BOOTSTRAP_CLAIM_TIMEOUT_MS } from '../pod.mjs'
import { createAttestPolicySource, createPidCreationTimeGuard, evaluateClient } from '../attest.mjs'
import {
  ADOPT_KIND,
  TEARDOWN_REASONS,
  createAdoptionManager,
  isTeardownReason,
  mapPodOutcome,
} from '../adoption.mjs'
import { CHECKPOINT_BYTES, createPrefixHasher, validateCursor } from '../cursor.mjs'
import { afterToolResultCommit, createExecHold, resolveResumeService } from '../resume.mjs'
import {
  PENDING_FILE_NAME,
  PENDING_LIMITS,
  PENDING_VERSION,
  RECOVERY_DEFAULTS,
  createExecRecovery,
  createPendingStore,
  sanitizePendingEntry,
} from '../recovery.mjs'
import { buildChunks, coverRange, parseSegments, sanitizeSegments } from '../segments.mjs'
import { collectDshEnv, sanitizeDshEnv } from '../shared.mjs'
import {
  __internals,
  alignModelChunk,
  buildShellArgv,
  createJobOutputAckHook,
  createTools,
  derivePrefix,
  hostFallbackDeadline,
  normalizeConfig,
  parseConfinedArgv,
  policyHint,
  renderExecResult,
  resolveJobCwd,
  resolveLiveLimits,
  resolvePwshPath,
  resolveShellLimits,
  shouldRecoverUnresponsivePod,
} from '../index.js'
import {
  buildLaunchFiles,
  planLauncher,
  podSupportsStdinlessBootstrap,
  readLauncherMode,
  selectPodEnv,
  taskNameFor,
} from '../launcher.mjs'
import {
  FREEZE_DEFAULT_MAX_MS,
  FREEZE_ERROR_CODES,
  FREEZE_MAX_MS,
  createFreezeController,
  freezeLedgerFields,
  freezeMaxOf,
  freezeRowOf,
  metaFreezeOf,
} from '../freeze.mjs'

const WORKSPACE = resolve('Z:\\Project\\DSHproject')
const RUN_ID = String(process.pid) + '-' + randomBytes(3).toString('hex')
const TMP_ROOT = join(WORKSPACE, '.tmp', 'escape-pod-core-selftest', RUN_ID)
/** Package root (the directory holding index.js / launcher.mjs). */
const PKG_ROOT = fileURLToPath(new URL('..', import.meta.url))
const FAKE_RUNNER = join(TMP_ROOT, 'node_modules', '@deepseek-ai', 'dsh-sandbox-windows-acl', 'lib', 'runner.js')
const ALT_RUNNER = join(TMP_ROOT, 'other', 'node_modules', '@deepseek-ai', 'dsh-sandbox-windows-acl', 'lib', 'runner.js')
const results = []

/** @param {string} name @param {() => (void | Promise<void>)} fn */
async function test(name, fn) {
  try {
    await fn()
    results.push({ name, ok: true })
    process.stdout.write('[PASS] ' + name + '\n')
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) })
    process.stdout.write('[FAIL] ' + name + ' — ' + (error instanceof Error ? error.message : String(error)) + '\n')
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

/** @param {() => unknown} fn @param {string} expectedCode @param {string} message */
function assertThrowsCode(fn, expectedCode, message) {
  let code = null
  try {
    fn()
  } catch (error) {
    code = /** @type {any} */ (error)?.code ?? null
  }
  if (code !== expectedCode) throw new Error(message + '：期望 code=' + expectedCode + '，实际 ' + String(code))
}

function jsonWrite(path, value) {
  fs.mkdirSync(join(path, '..'), { recursive: true })
  fs.writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf8')
}

/** A synthetic prefix that mimics the windows-acl runner argv contract. */
function makePrefix({ workspaceRoot = WORKSPACE, tempDir, seamManaged = true, mode = 'workspace-write' } = {}) {
  const prefix = [
    process.execPath,
    FAKE_RUNNER,
    '--workspace',
    workspaceRoot,
    '--temp',
    tempDir,
    '--mode',
    mode,
  ]
  if (seamManaged) prefix.push('--write-sid', 'S-1-4-aaaaaaaa', '--temp-write-sid', 'S-1-4-bbbbbbbb')
  return prefix
}

/**
 * The pinned shape template a Host would derive from the first per-call prefix.
 * It pins program/runnerPath/workspace only — the mode is a per-call authority
 * fact now (`modes` is documentation for status output).
 */
function makeTemplate({ workspaceRoot = WORKSPACE } = {}) {
  return {
    program: process.execPath,
    runnerPath: FAKE_RUNNER,
    workspaceRoot,
    enforcement: 'partial',
    modes: ['read-only', 'workspace-write'],
  }
}

/** Make `confine()` look exactly like the real provider: prefix + '--' + placeholder. */
function fakeConfined(prefix, placeholder, enforcement = 'partial') {
  return {
    argv: [...prefix, '--', ...placeholder],
    enforcement,
    denialSignatures: ['access is denied', 'access to the path', 'permission denied', 'operation not permitted'],
    runnerFailureRules: [{ allowedExitCodes: [127], fatalSignatures: ['windows-acl-run: '] }],
  }
}

async function main() {
  fs.mkdirSync(TMP_ROOT, { recursive: true })
  fs.mkdirSync(join(FAKE_RUNNER, '..'), { recursive: true })
  fs.writeFileSync(FAKE_RUNNER, '// fake runner for the static self-test (never executed)\n')
  fs.mkdirSync(join(ALT_RUNNER, '..'), { recursive: true })
  fs.writeFileSync(ALT_RUNNER, '// alternate fake runner (a different DSH-tree path)\n')
  const fakeTempDir = join(TMP_ROOT, 'tmp')
  fs.mkdirSync(fakeTempDir, { recursive: true })
  const PLACEHOLDER = [process.execPath, __internals.constants.PLACEHOLDER_TARGET]

  // -------------------------------------------------------------------------
  // shared.mjs
  // -------------------------------------------------------------------------
  await test('pipe-name：稳定身份（与 DSH_HOME 无关）+ stem 独立', () => {
    const first = resolvePipeName(undefined, { DSH_HOME: 'Z:\\DSH-Data' })
    const second = resolvePipeName(undefined, { DSH_HOME: 'D:\\a\\completely\\different\\home' })
    assertEqual(first, second, 'DSH_HOME 变化不得改变管道名（旧实现会因此把运行中的 pod 变成孤儿）')
    assert(first.startsWith(PIPE_PREFIX + PIPE_STEM), '应带本 bundle 专属 stem：' + first)
    assert(/^\\\\\.\\pipe\\dsh-escape-pod-core-[0-9a-f]{12}$/.test(first), '形状不符：' + first)
    const identity = describePipeIdentity()
    assertEqual(first, PIPE_PREFIX + PIPE_STEM + identity.seedHash, '后缀必须等于稳定身份的哈希')
    assertEqual(identity.seedHash, identitySeedHash(resolveIdentitySeed()), 'seedHash 必须可由种子复算')
    assertEqual(identity.seedHash.length, 12, 'seedHash 长度')
    assert(identity.note.includes('TODO(P2)'), '身份近似必须留下原生 SID 的 TODO：' + identity.note)
    assertEqual(resolvePipeName('abc'), PIPE_PREFIX + 'abc', '裸后缀应补全成完整管道名')
    const full = PIPE_PREFIX + 'explicit-name'
    assertEqual(resolvePipeName(full), full, '完整管道名应原样保留')
  })

  // -------------------------------------------------------------------------
  // 本轮加固：spawn token / 单客户端 / handover
  // -------------------------------------------------------------------------
  const TOKEN_A = generatePodToken()
  const TOKEN_B = generatePodToken()
  const TOKEN_C = generatePodToken()

  /** @param {string} peer */
  function makeConnection(peer) {
    return { peer, connectedAt: new Date().toISOString(), authenticated: false, tokenFingerprint: null }
  }

  await test('spawn token：32 字节 hex、常量时间比较、指纹', () => {
    assert(isPodToken(TOKEN_A), '生成的 token 必须是小写 hex64：' + TOKEN_A)
    assertEqual(TOKEN_A.length, 64, 'token 长度')
    assert(generatePodToken() !== TOKEN_A, '每次生成必须不同')
    assert(!isPodToken('a'.repeat(63)), '短一位应拒绝')
    assert(!isPodToken('A'.repeat(64)), '大写 hex 应拒绝（协议只接受小写）')
    assert(!isPodToken(42), '非字符串应拒绝')
    assert(!isPodToken(undefined), 'undefined 应拒绝')
    assert(tokensEqual(TOKEN_A, TOKEN_A), '相同 token 必须相等')
    assert(!tokensEqual(TOKEN_A, TOKEN_B), '不同 token 必须不等')
    assert(!tokensEqual(undefined, TOKEN_A), '缺 token 必须不等')
    assertEqual(tokenFingerprint(TOKEN_A).length, 12, '指纹长度')
    assert(!tokenFingerprint(TOKEN_A).includes(TOKEN_A.slice(0, 8)), '指纹不得泄露 token 前缀')
  })

  await test('spawn token：stdin 第一行读取；EOF/垃圾/超时一律 fail closed；关闭后不结束', async () => {
    const good = new PassThrough()
    const pendingToken = readTokenFromStdin(good, { timeoutMs: 1000 })
    good.write(TOKEN_A.slice(0, 20))
    good.write(TOKEN_A.slice(20) + '\nignored-second-line\n')
    good.end()
    assertEqual(await pendingToken, TOKEN_A, '跨 chunk 的第一行必须被完整读出')

    // The Host closes stdin right after the token, and the OS closes it if the
    // Host dies. Both are normal: the pod must keep running.
    neutralizePodStdin(good)
    good.destroy(new Error('simulated Host death'))
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 10))
    assertEqual(process.exitCode, undefined, 'stdin 关闭既不能设置退出码，也不能结束 pod')

    const empty = new PassThrough()
    empty.end()
    assertEqual(await readTokenFromStdin(empty, { timeoutMs: 1000 }), null, 'token 前 EOF 必须判失败')

    const garbage = new PassThrough()
    garbage.end('not-a-token\n')
    assertEqual(await readTokenFromStdin(garbage, { timeoutMs: 1000 }), null, '非 hex 行必须判失败')

    const silent = new PassThrough()
    assertEqual(await readTokenFromStdin(silent, { timeoutMs: 50 }), null, '超时必须判失败（pod 不能无限等 token）')
    silent.destroy()

    let noTokenThrew = false
    try {
      createPodAuth({ mode: 'token', token: null })
    } catch {
      noTokenThrew = true
    }
    assertEqual(noTokenThrew, true, '没有 token 的 token 模式必须构造失败（fail closed）')
  })

  await test('单客户端：第二个连接 EBUSY 且不影响第一个；第一个断开后允许新连接', () => {
    const auth = createPodAuth({ token: TOKEN_A, allowHandover: false, handoverGraceMs: 0 })
    const first = makeConnection('peer-1')
    const second = makeConnection('peer-2')
    assertEqual(auth.admitConnection(first).ok, true, '第一个连接应被接纳')
    const busy = auth.admitConnection(second)
    assertEqual(busy.ok, false, '第二个连接必须被拒绝')
    assertEqual(busy.code, 'EBUSY', '错误码必须是 EBUSY')
    assert(busy.message.includes('peer-1'), '拒绝原因应包含现有连接信息：' + busy.message)
    assertEqual(auth.snapshot().rejectedConnections, 1, '拒绝计数')
    assertEqual(auth.snapshot().connected, true, 'status 应显示有连接')
    assertEqual(auth.authorize(first, { token: TOKEN_A }).ok, true, '第一个连接必须仍然可用（拒绝第二个不能影响它）')
    auth.detachConnection(first)
    assertEqual(auth.snapshot().connected, false, '断开后 status 应显示无连接')
    assertEqual(auth.admitConnection(second).ok, true, '第一个断开后应允许新连接')
    auth.detachConnection(second)
  })

  await test('token 鉴权：缺失/错误被拒；每请求校验；handover 后旧 token 立即失效', () => {
    const auth = createPodAuth({ token: TOKEN_A, handoverGraceMs: 60_000 })
    const conn = makeConnection('peer-a')
    auth.admitConnection(conn)
    assertEqual(auth.authorize(conn, {}).code, 'EBADTOKEN', '缺 token 必须 EBADTOKEN')
    assertEqual(auth.authorize(conn, { token: 'e'.repeat(64) }).code, 'EBADTOKEN', '错 token 必须 EBADTOKEN')
    assertEqual(auth.authorize(conn, { token: TOKEN_A }).ok, true, '正确 token 应放行')
    assertEqual(auth.snapshot().ownerAccepted, true, '首个通过认证的连接成为 owner')
    assertEqual(auth.snapshot().tokenFingerprint, tokenFingerprint(TOKEN_A), 'status 里的 token 指纹')
    assert(!JSON.stringify(auth.snapshot()).includes(TOKEN_A), 'status 绝不能包含 token 原文')

    auth.detachConnection(conn)
    const next = makeConnection('peer-b')
    assertEqual(auth.admitConnection(next).ok, true, 'owner 断开后应允许新连接')
    assertEqual(auth.handover(next, { newToken: TOKEN_B }).ok, true, '空闲 pod 应允许 handover')
    assertEqual(auth.snapshot().handoverCount, 1, 'handover 计数')
    assertEqual(auth.snapshot().tokenFingerprint, tokenFingerprint(TOKEN_B), 'handover 后指纹必须更新')
    assertEqual(auth.authorize(next, { token: TOKEN_A }).ok, false, 'handover 后旧 token 必须立即失效')
    assertEqual(auth.authorize(next, { token: TOKEN_B }).ok, true, 'handover 后新 token 必须可用')
    auth.detachConnection(next)
  })

  await test('handover：刚启动/已认证/已禁用/坏 newToken 都拒绝', () => {
    const fresh = createPodAuth({ token: TOKEN_A, handoverGraceMs: 60_000 })
    const freshConn = makeConnection('peer-fresh')
    fresh.admitConnection(freshConn)
    const early = fresh.handover(freshConn, { newToken: TOKEN_B })
    assertEqual(early.code, 'EAUTHREQUIRED', '刚启动的 pod（宽限期内）不得被接管')
    assert(early.retryAfterMs > 0, '拒绝应给出 retryAfterMs')

    const aged = createPodAuth({ token: TOKEN_A, handoverGraceMs: 0 })
    const agedConn = makeConnection('peer-aged')
    aged.admitConnection(agedConn)
    assertEqual(aged.handover(agedConn, { newToken: 'short' }).code, 'EBADTOKEN', '坏 newToken 必须拒绝')
    assertEqual(aged.handover(agedConn, { newToken: TOKEN_B }).ok, true, '宽限期为 0 时应允许接管')
    assertEqual(aged.handover(agedConn, { newToken: TOKEN_C }).code, 'EALREADY', '已认证连接不需要 handover')

    const disabled = createPodAuth({ token: TOKEN_A, allowHandover: false, handoverGraceMs: 0 })
    const disabledConn = makeConnection('peer-disabled')
    disabled.admitConnection(disabledConn)
    assertEqual(disabled.handover(disabledConn, { newToken: TOKEN_B }).code, 'EHANDOVERDISABLED', '--no-handover 必须拒绝接管')
  })

  await test('status 投影：auth/identity 形状稳定、无损、不含 token', () => {
    const auth = createPodAuth({ token: TOKEN_A })
    auth.admitConnection(makeConnection('peer-status'))
    const service = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: join(TMP_ROOT, 'auth-ledger'),
      pipeName: 'dsh-escape-pod-core-static-auth',
      idleExitMs: DEFAULT_IDLE_EXIT_MS,
      ringBytes: DEFAULT_RING_BYTES,
      outputChunkBytes: DEFAULT_OUTPUT_CHUNK_BYTES,
      authSnapshot: () => auth.snapshot(),
      identity: describePipeIdentity(),
    })
    const snap = service.snapshot()
    assertEqual(snap.auth.mode, 'token', 'mode')
    assertEqual(snap.auth.required, true, 'required')
    assertEqual(snap.auth.tokenFingerprint, tokenFingerprint(TOKEN_A), 'token 指纹')
    assertEqual(snap.auth.connected, true, 'connected')
    assertEqual(snap.identity.seedHash, describePipeIdentity().seedHash, 'identity.seedHash')
    assertEqual(snap.identity.seedVersion, 1, 'identity.seedVersion')
    const json = JSON.stringify(snap)
    assertEqual(json.includes(TOKEN_A), false, 'snapshot 不得含 token 原文')
    assertEqual(json.includes('undefined'), false, 'snapshot JSON 不得含 undefined')
  })

  /**
   * Minimal stand-in for a net.Socket: records what the pod writes, lets the
   * test feed request lines, and reports close the way a pipe would.
   */
  class FakeSocket extends EventEmitter {
    /** @param {string} peer */
    constructor(peer) {
      super()
      this.remoteAddress = peer
      this.destroyed = false
      this.writable = true
      this.written = []
      this.ended = false
    }

    setEncoding() {}

    /** @param {string} chunk */
    write(chunk) {
      if (this.destroyed || !this.writable) return false
      this.written.push(String(chunk))
      return true
    }

    /** @param {string} [chunk] */
    end(chunk) {
      if (chunk !== undefined) this.written.push(String(chunk))
      this.ended = true
      this.writable = false
      // A real pipe peer sees EOF and the pod's backstop destroys the socket;
      // model the resulting close so single-client admission is released.
      this.destroy()
    }

    destroy() {
      if (this.destroyed) return
      this.destroyed = true
      this.writable = false
      this.emit('close')
    }

    /** @param {string} text */
    feed(text) {
      this.emit('data', text)
    }

    /** @param {Record<string, unknown>} message */
    request(message) {
      this.feed(JSON.stringify(message) + '\n')
    }

    get responses() {
      const text = this.written.join('')
      return text
        .split('\n')
        .filter((line) => line.trim() !== '')
        .map((line) => JSON.parse(line))
    }
  }

  await test('socket 层：第二个连接 EBUSY、无/错 token EBADTOKEN、handover 后新 token 可用', async () => {
    const auth = createPodAuth({ token: TOKEN_A, handoverGraceMs: 60_000 })
    const clients = new Set()
    const handled = []
    const service = {
      bumpGeneration() {},
      touchActivity() {},
      snapshot: () => ({ ok: true, auth: auth.snapshot() }),
      /** @param {string} op */
      async handle(op, message) {
        handled.push(op)
        return { ok: true, op, echo: message?.echo ?? null }
      },
    }
    const onConnection = createConnectionHandler(service, auth, { clients, log: () => {} })
    const tick = () => new Promise((resolveSleep) => setTimeout(resolveSleep, 20))

    // 1. The first connection is admitted and its authenticated request is served.
    const first = new FakeSocket('peer-first')
    onConnection(first)
    first.request({ op: 'status', id: 1, token: TOKEN_A })
    await tick()
    assertEqual(first.responses.length, 1, '第一个连接应收到响应')
    assertEqual(first.responses[0].ok, true, '正确 token 应被服务：' + JSON.stringify(first.responses[0]))
    assertEqual(first.ended, false, '被接纳的连接不得被关闭')
    assertEqual(handled.join(','), 'status', '请求应进入 service.handle')

    // 2. A second connection is refused with EBUSY, correlated to its request,
    //    and closed; the first connection lives. The refusal must NOT be sent
    //    before the request line: an early uncorrelated frame is dropped by the
    //    client and it only sees ECLOSED (the race that made the remote suite
    //    report "raw pipe closed" instead of EBUSY).
    const busy = new FakeSocket('peer-second')
    onConnection(busy)
    await tick()
    assertEqual(busy.responses.length, 0, '拒绝帧不得早于请求行（否则客户端拿到的是 ECLOSED）')
    assertEqual(busy.ended, false, '收到请求行之前不得关闭第二连接')
    busy.request({ op: 'status', id: 42 })
    await tick()
    assertEqual(busy.responses[0]?.error?.code, 'EBUSY', '第二个连接必须 EBUSY：' + JSON.stringify(busy.responses[0] ?? null))
    assertEqual(busy.responses[0]?.id, 42, '拒绝帧必须带回被拒请求的 id（否则客户端无法关联）')
    assertEqual(busy.ended, true, '第二个连接必须被关闭')
    assertEqual(busy.responses[0]?.error?.message.includes('peer-first'), true, '拒绝原因应指出已有连接')
    first.request({ op: 'ping', id: 2, token: TOKEN_A })
    await tick()
    assertEqual(first.responses[1]?.ok, true, '拒绝第二个连接不得影响第一个')
    assertEqual(first.destroyed, false, '第一个连接必须仍然活着')

    // 3. No token / wrong token: refused, closed, and NO protocol state change.
    first.destroy()
    await tick()
    const handledBefore = handled.length
    const noToken = new FakeSocket('peer-no-token')
    onConnection(noToken)
    noToken.request({ op: 'run', id: 3 })
    await tick()
    assertEqual(noToken.responses[0]?.error?.code, 'EBADTOKEN', '缺 token 应 EBADTOKEN')
    assertEqual(noToken.ended, true, '缺 token 必须关闭连接')
    assertEqual(handled.length, handledBefore, '鉴权失败不得进入 service.handle（不得产生任何副作用）')

    const wrongToken = new FakeSocket('peer-wrong-token')
    onConnection(wrongToken)
    wrongToken.request({ op: 'run', id: 4, token: TOKEN_B })
    await tick()
    assertEqual(wrongToken.responses[0]?.error?.code, 'EBADTOKEN', '错 token 应 EBADTOKEN')
    assertEqual(wrongToken.ended, true, '错 token 必须关闭连接')
    assertEqual(handled.length, handledBefore, '错 token 不得进入 service.handle')

    // 4. The orphaned pod can be claimed; the new token is then required and
    //    the old one is dead.
    const claim = new FakeSocket('peer-claim')
    onConnection(claim)
    claim.request({ op: 'handover', id: 5, newToken: TOKEN_C })
    await tick()
    assertEqual(claim.responses[0]?.ok, true, '空闲 pod 应接受 handover：' + JSON.stringify(claim.responses[0] ?? null))
    assertEqual(auth.snapshot().tokenFingerprint, tokenFingerprint(TOKEN_C), 'handover 后 token 指纹必须更新')
    claim.request({ op: 'status', id: 6, token: TOKEN_A })
    await tick()
    assertEqual(claim.responses[1]?.error?.code, 'EBADTOKEN', 'handover 后旧 token 必须失效')
    // A failed request closes the connection, so the retry is a new one.
    const reauth = new FakeSocket('peer-claim-2')
    onConnection(reauth)
    reauth.request({ op: 'status', id: 7, token: TOKEN_C })
    await tick()
    assertEqual(reauth.responses[0]?.ok, true, 'handover 后新 token 必须可用')
    assertEqual(clients.size, 1, 'admitted 连接集合应只有当前这一个')
    reauth.destroy()
    await tick()
    assertEqual(clients.size, 0, 'close 后必须从 admitted 集合移除')
  })

  await test('DSH 安装树 runner 检查：只接受 node_modules/@deepseek-ai/dsh-sandbox-windows-acl/lib/runner.js', () => {
    assert(isDshInstallRunnerPath(FAKE_RUNNER), '安装树内路径应通过')
    const pnpmShaped = join(TMP_ROOT, 'node_modules', '.pnpm', '@deepseek-ai+dsh-sandbox-windows-acl@1.0.0', 'node_modules', '@deepseek-ai', 'dsh-sandbox-windows-acl', 'lib', 'runner.js')
    assert(isDshInstallRunnerPath(pnpmShaped), 'pnpm 布局应通过')
    assert(!isDshInstallRunnerPath(join(TMP_ROOT, 'evil', 'runner.js')), '安装树外应拒绝')
    assert(!isDshInstallRunnerPath(join(TMP_ROOT, 'node_modules', '@deepseek-ai', 'dsh-sandbox-windows-acl', 'lib', 'not-runner.js')), 'basename 不是 runner.js 应拒绝')
    assert(!isDshInstallRunnerPath('runner.js'), '相对路径应拒绝')
  })

  await test('validatePrefix：接受 per-call 合法形状（seam-managed / agentless）', () => {
    const seam = validatePrefix(makePrefix({ tempDir: fakeTempDir, seamManaged: true }))
    assert(seam.ok === true, 'seam-managed 前缀应通过：' + (seam.ok ? '' : seam.message))
    assertEqual(seam.profile.mode, 'workspace-write', 'mode')
    assertEqual(seam.profile.seamManaged, true, 'seamManaged')
    assertEqual(seam.fingerprint, fingerprintPrefix(seam.prefix), '指纹应可复算')
    const agentless = validatePrefix(makePrefix({ tempDir: fakeTempDir, seamManaged: false }))
    assert(agentless.ok === true, 'agentless 前缀应通过')
    assertEqual(agentless.profile.seamManaged, false, 'agentless seamManaged')
    assert(fingerprintPrefix(seam.prefix) !== fingerprintPrefix(agentless.prefix), '不同前缀指纹应不同')
  })

  await test('validatePrefix：每一种不合法前缀都 fail-closed 并带错误码', () => {
    const good = makePrefix({ tempDir: fakeTempDir })
    /** @type {Array<[string, unknown, string]>} */
    const cases = [
      ['不是数组', 'nope', 'EPREFIXINVALID'],
      ['空数组', [], 'EPREFIXINVALID'],
      ['只有一个元素', ['node.exe'], 'EPREFIXINVALID'],
      ['第二个元素不是 runner.js', [process.execPath, join(TMP_ROOT, 'evil.js'), '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'], 'EPREFIXRUNNER'],
      ['runner 不在 DSH 安装树内', [process.execPath, join(TMP_ROOT, 'evil', 'runner.js'), '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'], 'EPREFIXRUNNERPATH'],
      ['混入 --', [...good.slice(0, 2), '--', ...good.slice(2)], 'EPREFIXINVALID'],
      ['未知标志', [...good.slice(0, 8), '--network', '1'], 'EPREFIXFLAG'],
      ['标志缺值', [process.execPath, FAKE_RUNNER, '--workspace'], 'EPREFIXVALUE'],
      ['重复标志', [...good.slice(0, 4), '--workspace', WORKSPACE, ...good.slice(4)], 'EPREFIXDUP'],
      ['缺 --workspace', [process.execPath, FAKE_RUNNER, '--temp', fakeTempDir, '--mode', 'workspace-write'], 'EPREFIXINVALID'],
      ['缺 --temp', [process.execPath, FAKE_RUNNER, '--workspace', WORKSPACE, '--mode', 'workspace-write'], 'EPREFIXINVALID'],
      ['danger-full-access 前缀（完全访问从不带前缀）', [process.execPath, FAKE_RUNNER, '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'danger-full-access'], 'EPREFIXMODE'],
      ['相对路径', [process.execPath, FAKE_RUNNER, '--workspace', 'relative', '--temp', fakeTempDir, '--mode', 'workspace-write'], 'EPREFIXINVALID'],
      ['temp 不存在（旧前缀）', makePrefix({ tempDir: join(TMP_ROOT, 'gone-tmp'), seamManaged: false }), 'EPREFIXSTALE'],
      ['SID 不成对', [...good.slice(0, 8), '--write-sid', 'S-1-4-aaaaaaaa'], 'EPREFIXGRANT'],
      ['非字符串元素', [process.execPath, 42], 'EPREFIXINVALID'],
      ['位置参数', [...good.slice(0, 2), 'stray', ...good.slice(2)], 'EPREFIXTOKEN'],
    ]
    for (const [label, value, code] of cases) {
      const result = validatePrefix(value)
      assertEqual(result.ok, false, label + ' 应被拒绝')
      assertEqual(result.code, code, label + ' 错误码')
      assert(typeof result.message === 'string' && result.message !== '', label + ' 应带说明')
    }
  })

  await test('validatePrefix + 模板：per-call 前缀必须与钉死模板一致', () => {
    const templateCheck = validateTemplate(makeTemplate())
    assert(templateCheck.ok === true, '模板本身应合法')
    const template = templateCheck.template
    assert(validatePrefix(makePrefix({ tempDir: fakeTempDir }), template).ok === true, '一致的前缀应通过')
    const wrongWorkspace = validatePrefix(makePrefix({ workspaceRoot: TMP_ROOT, tempDir: fakeTempDir }), template)
    assertEqual(wrongWorkspace.ok, false, 'workspace 不一致应拒绝')
    assertEqual(wrongWorkspace.code, 'EPREFIXWORKSPACETEMPLATE', 'workspace 不一致错误码')
    const wrongRunner = validatePrefix([process.execPath, ALT_RUNNER, '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'], template)
    assertEqual(wrongRunner.ok, false, 'runner 路径不一致应拒绝')
    assertEqual(wrongRunner.code, 'EPREFIXRUNNERTEMPLATE', 'runner 不一致错误码')
    const wrongProgram = validatePrefix([join(TMP_ROOT, 'other-node.exe'), FAKE_RUNNER, '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'], template)
    assertEqual(wrongProgram.code, 'EPREFIXPROGRAMTEMPLATE', 'program 不一致错误码')
    assertEqual(wrongProgram.ok, false, 'program 不一致应拒绝')
  })

  await test('validateTemplate：模板本身必须 fail-closed 可判定', () => {
    const base = makeTemplate()
    /** @type {Array<[string, unknown, string]>} */
    const cases = [
      ['不是对象', 'nope', 'EPREFIXTEMPLATE'],
      ['program 不是绝对路径', { ...base, program: 'node.exe' }, 'EPREFIXPROGRAM'],
      ['runnerPath 相对', { ...base, runnerPath: 'runner.js' }, 'EPREFIXRUNNERPATH'],
      ['runnerPath 不在安装树内', { ...base, runnerPath: join(TMP_ROOT, 'evil', 'runner.js') }, 'EPREFIXRUNNERPATH'],
      ['modes 含 danger-full-access', { ...base, modes: ['read-only', 'danger-full-access'] }, 'EPREFIXMODE'],
      ['workspace 不存在', { ...base, workspaceRoot: join(TMP_ROOT, 'no-such-workspace') }, 'EPREFIXWORKSPACE'],
      ['enforcement 非法', { ...base, enforcement: 'none' }, 'EPREFIXENFORCEMENT'],
    ]
    for (const [label, value, code] of cases) {
      const result = validateTemplate(value)
      assertEqual(result.ok, false, label + ' 应被拒绝')
      assertEqual(result.code, code, label + ' 错误码')
    }
    const accepted = validateTemplate(base)
    assertEqual(accepted.ok, true, '合法模板应通过')
    assert(String(describeTemplate(accepted.template).pin).includes('runnerPath'), '模板摘要应说明钉死项')
  })

  await test('UTF-8 偏移：截断不拆分多字节字符', () => {
    const row = Buffer.from('a行', 'utf8') // 61 e8 a1 8c
    assertEqual(trimIncompleteUtf8End(row.subarray(0, 3)), 1, '3 字节处截断应回退到 1')
    assertEqual(trimIncompleteUtf8End(row), 4, '完整字符不裁剪')
    assertEqual(trimIncompleteUtf8End(Buffer.from('ab')), 2, 'ASCII 不裁剪')
    assertEqual(trimIncompleteUtf8End(Buffer.alloc(0)), 0, '空缓冲 0')
    const emoji = Buffer.from('😀', 'utf8') // f0 9f 98 80
    assertEqual(trimIncompleteUtf8End(emoji.subarray(0, 2)), 0, '4 字节序列只剩开头时返回 0（调用方保留原长度）')
  })

  await test('账本位置：默认必须在 workspace 之外，stateDir 可覆盖', () => {
    const localAppData = 'C:\\Users\\tester\\AppData\\Local'
    const defaultDir = resolveStateDir(undefined, { LOCALAPPDATA: localAppData })
    assertEqual(defaultDir, join(localAppData, 'dsh-escape-pod-core'), '默认应在 LOCALAPPDATA 下')
    assert(!isInsideDirectory(WORKSPACE, defaultDir), '默认账本目录不能位于 workspace 内')
    const dshHomeFallback = resolveStateDir(undefined, { LOCALAPPDATA: undefined, DSH_HOME: 'Z:\\DSH-Data' })
    assertEqual(dshHomeFallback, join('Z:\\DSH-Data', '.escape-pod-core'), '无 LOCALAPPDATA 时退到 DSH_HOME')
    assert(!isInsideDirectory(WORKSPACE, dshHomeFallback), 'DSH_HOME 回退也不能位于 workspace 内')
    assertEqual(resolveStateDir('C:\\state\\epc'), 'C:\\state\\epc', '显式 stateDir 应被采用')
    assertEqual(normalizeConfig({ stateDir: 'D:\\epc-state' }).stateDir, 'D:\\epc-state', '配置 stateDir 透传')
    assert(!isInsideDirectory(WORKSPACE, normalizeConfig(null).stateDir), '默认配置的 stateDir 必须在 workspace 之外')
    assertEqual(hashArgv(['a', 'b']).length, 64, 'argvHash 应为 sha256 hex')
    assert(hashArgv(['a', 'b']) !== hashArgv(['a', 'c']), 'argvHash 应随 argv 变化')
  })

  // -------------------------------------------------------------------------
  // Host-side per-call prefix derivation (fake sandbox seam)
  // -------------------------------------------------------------------------
  await test('parseConfinedArgv：只接受「前缀 + -- + 占位目标」', () => {
    const prefix = makePrefix({ tempDir: fakeTempDir })
    const parsed = parseConfinedArgv(fakeConfined(prefix, PLACEHOLDER), PLACEHOLDER)
    assertEqual(parsed.prefix.length, prefix.length, 'prefix 长度')
    assertEqual(parsed.prefix.join('|'), prefix.join('|'), 'prefix 内容应原样')
    assertEqual(parsed.profile.tempDir, fakeTempDir, 'profile.tempDir')
    assertThrowsCode(
      () => parseConfinedArgv({ argv: [...prefix, process.execPath, 'other-placeholder'] }, PLACEHOLDER),
      'EPREFIXINVALID',
      '缺少 -- 分隔符应拒绝',
    )
    assertThrowsCode(
      () => parseConfinedArgv(fakeConfined(prefix, [process.execPath, 'different-placeholder']), PLACEHOLDER),
      'EPREFIXINVALID',
      '目标段与占位目标不一致应拒绝',
    )
    assertThrowsCode(
      () => parseConfinedArgv(fakeConfined([process.execPath, join(TMP_ROOT, 'evil', 'runner.js'), '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'], PLACEHOLDER), PLACEHOLDER),
      'EPREFIXRUNNERPATH',
      '安装树外的 runner 应透传 fail-closed 错误码',
    )
  })

  await test('derivePrefix：session 策略优先，前缀与 enforcement 正确回传', async () => {
    const prefix = makePrefix({ tempDir: fakeTempDir })
    /** @type {any[]} */
    const calls = []
    const sandbox = {
      async confine(argv, policy) {
        calls.push({ argv, policy })
        return fakeConfined(prefix, PLACEHOLDER, 'partial')
      },
    }
    const prepared = await derivePrefix(sandbox, { sessionId: 'sess-1', workspaceRoot: WORKSPACE })
    assertEqual(calls.length, 1, '应只调用一次 confine（session 成功）')
    assertEqual(calls[0].policy.mode, 'workspace-write', 'policy.mode')
    assertEqual(calls[0].policy.sessionId, 'sess-1', 'policy.sessionId')
    assertEqual(calls[0].policy.workspaceRoot, WORKSPACE, 'policy.workspaceRoot')
    assertEqual(prepared.enforcement, 'partial', 'enforcement 透传')
    assertEqual(prepared.policyVariant, 'workspace-write + sessionId', 'variant')
    assertEqual(prepared.fingerprint, fingerprintPrefix(prefix), '指纹')
    assertEqual(prepared.profile.tempDir, fakeTempDir, 'profile.tempDir')
    assertEqual(prepared.denialSignatures.length, 4, 'denialSignatures 透传')
  })

  await test('derivePrefix：每次调用都重新 confine（per-call 前缀，不缓存）', async () => {
    const prefix = makePrefix({ tempDir: fakeTempDir })
    let counter = 0
    const sandbox = {
      async confine(argv) {
        counter += 1
        return fakeConfined(prefix, argv, 'partial')
      },
    }
    const first = await derivePrefix(sandbox, { sessionId: 'sess-2', workspaceRoot: WORKSPACE })
    const second = await derivePrefix(sandbox, { sessionId: 'sess-2', workspaceRoot: WORKSPACE })
    assertEqual(counter, 2, '两次 derivePrefix 必须调用两次 confine（不能缓存）')
    assertEqual(first.fingerprint, second.fingerprint, '同一输入指纹相同')
    assert(typeof first.confinedAt === 'string' && first.confinedAt !== '', '应带签发时间')
  })

  await test('derivePrefix：session 失败后回退 agentless', async () => {
    const prefix = makePrefix({ tempDir: fakeTempDir, seamManaged: false })
    /** @type {any[]} */
    const policies = []
    let attempt = 0
    const sandbox = {
      async confine(_argv, policy) {
        policies.push(policy)
        attempt += 1
        if (attempt === 1) throw Object.assign(new Error('no session grant'), { code: 'EGRANT' })
        return fakeConfined(prefix, PLACEHOLDER, 'partial')
      },
    }
    const prepared = await derivePrefix(sandbox, { sessionId: 'sess-3', workspaceRoot: WORKSPACE })
    assertEqual(policies.length, 2, '应尝试两次')
    assertEqual(policies[1].sessionId, undefined, 'agentless 尝试不应带 sessionId')
    assert(String(prepared.policyVariant).includes('agentless'), 'variant 应标记 agentless')
    assertEqual(prepared.profile.seamManaged, false, 'agentless 前缀')
  })

  await test('derivePrefix：无沙箱 / confine 返回坏 argv 都 fail-closed', async () => {
    let noSandboxCode = null
    try {
      await derivePrefix(null, { workspaceRoot: WORKSPACE })
    } catch (error) {
      noSandboxCode = /** @type {any} */ (error)?.code
    }
    assertEqual(noSandboxCode, 'ENOSANDBOX', '无沙箱应 ENOSANDBOX')
    const broken = { async confine() { return { argv: ['node.exe', 'runner.js'], enforcement: 'partial', denialSignatures: [], runnerFailureRules: [] } } }
    let brokenCode = null
    try {
      await derivePrefix(broken, { workspaceRoot: WORKSPACE })
    } catch (error) {
      brokenCode = /** @type {any} */ (error)?.code
    }
    assertEqual(brokenCode, 'EPREFIXINVALID', '坏 argv 应 EPREFIXINVALID')
  })

  await test('pwsh 解析：PowerShell 7 → PATH → Windows PowerShell → pwsh', () => {
    const fakeProgramFiles = join(TMP_ROOT, 'ProgramFiles')
    const pwsh7 = join(fakeProgramFiles, 'PowerShell', '7', 'pwsh.exe')
    fs.mkdirSync(join(fakeProgramFiles, 'PowerShell', '7'), { recursive: true })
    fs.writeFileSync(pwsh7, '')
    assertEqual(resolvePwshPath(undefined, { ProgramFiles: fakeProgramFiles, PATH: '', SystemRoot: join(TMP_ROOT, 'no-such') }, 'win32'), pwsh7, '应优先 PowerShell 7 安装路径')
    const fakeSystemRoot = join(TMP_ROOT, 'SystemRoot')
    const winPs = join(fakeSystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    fs.mkdirSync(join(fakeSystemRoot, 'System32', 'WindowsPowerShell', 'v1.0'), { recursive: true })
    fs.writeFileSync(winPs, '')
    assertEqual(resolvePwshPath(undefined, { ProgramFiles: join(TMP_ROOT, 'no-such-pf'), PATH: '', SystemRoot: fakeSystemRoot }, 'win32'), winPs, '应回退 Windows PowerShell 5.1')
    assertEqual(resolvePwshPath('C:\\custom\\pwsh.exe', {}, 'win32'), 'C:\\custom\\pwsh.exe', '显式配置应被信任')
    assertEqual(resolvePwshPath(undefined, { ProgramFiles: join(TMP_ROOT, 'no-such-pf'), PATH: '', SystemRoot: join(TMP_ROOT, 'no-such') }, 'win32'), 'pwsh', '都找不到时回退 PATH 解析的 pwsh')
    const argv = buildShellArgv('Write-Output ok', pwsh7)
    assertEqual(argv.length, 6, 'pwsh -NoLogo -NoProfile -NonInteractive -Command <text> 应为 6 个 argv 元素')
    assertEqual(argv[1], '-NoLogo', 'argv[1]')
    // Native `dsh-pwsh-local` guarantees UTF-8 on an OEM/GBK console; without
    // this preamble Chinese and emoji output arrives as mojibake. Each
    // assignment is individually guarded: a read-only session's restricted
    // token puts PowerShell in Constrained Language, where creating the
    // encoding type is a terminating error that must not reach stderr.
    const preamble = "try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }; try { $OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }; "
    assertEqual(argv[5], preamble + 'Write-Output ok', '命令文本前必须带 CLM 安全的 UTF-8 preamble')
    assertEqual(argv[5].startsWith(preamble), true, 'preamble 必须逐字一致（每条赋值各自 try/catch）')
  })

  await test('job cwd 必须落在 policy workspace 内（越界 fail-closed）', () => {
    assertEqual(resolveJobCwd(undefined, WORKSPACE), WORKSPACE, '默认 cwd = workspace')
    assertEqual(resolveJobCwd('pod', WORKSPACE), join(WORKSPACE, 'pod'), '相对路径基于 workspace')
    assertThrowsCode(() => resolveJobCwd('definitely-not-here', WORKSPACE), 'ECWD', '不存在目录应拒绝')
    assertThrowsCode(() => resolveJobCwd('C:\\Windows', WORKSPACE), 'ECWDWORSKSPACE', 'workspace 外的绝对路径应拒绝')
    assertThrowsCode(() => resolveJobCwd('..', WORKSPACE), 'ECWDWORSKSPACE', '用 .. 逃出 workspace 应拒绝')
    assertThrowsCode(() => resolveJobCwd(join(WORKSPACE, '..'), WORKSPACE), 'ECWDWORSKSPACE', '父目录应拒绝')
  })

  await test('配置归一化与默认 stateDir', () => {
    const defaults = normalizeConfig(null)
    assert(String(defaults.pipeName).startsWith(PIPE_PREFIX + PIPE_STEM), '默认管道名带专属 stem')
    assertEqual(defaults.idleExitMs, DEFAULT_IDLE_EXIT_MS, '默认 idleExitMs')
    assertEqual(defaults.ringBytes, DEFAULT_RING_BYTES, '默认 ringBytes')
    assertEqual(defaults.outputChunkBytes, FALLBACK_OUTPUT_CHUNK_BYTES, 'pod 兜底窗口 = 原生默认 64000（不再是写死的 65536）')
    assertEqual(DEFAULT_OUTPUT_CHUNK_BYTES, FALLBACK_OUTPUT_CHUNK_BYTES, '旧常量名保留为同值别名（兼容旧 importer）')
    assertEqual(defaults.modelOutputLimitBytes, 0, '默认不设窗口上限：完全跟随原生 maxOutputBytes')
    assert(!isInsideDirectory(WORKSPACE, defaults.stateDir), '默认 stateDir 必须在 workspace 之外：' + defaults.stateDir)
    const overridden = normalizeConfig({ pipeName: 'my-pipe', idleExitMs: 5000, ringBytes: 1024, outputChunkBytes: 99_999_999, pwshPath: 'C:\\x\\pwsh.exe', stateDir: 'D:\\epc-state' })
    assertEqual(overridden.pipeName, PIPE_PREFIX + 'my-pipe', '覆盖管道名')
    assertEqual(overridden.idleExitMs, 5000, '覆盖 idleExitMs')
    assertEqual(overridden.ringBytes, 4096, 'ringBytes 下限')
    assertEqual(overridden.outputChunkBytes, 1024 * 1024, 'chunk 上限')
    assertEqual(normalizeConfig({ modelOutputLimitBytes: 99_999_999 }).modelOutputLimitBytes, 1024 * 1024, '可选窗口上限 clamp 到 1 MiB')
    assertEqual(normalizeConfig({ modelOutputLimitBytes: 0 }).modelOutputLimitBytes, 0, '0 = 不设上限')
    assertEqual(overridden.pwshPath, 'C:\\x\\pwsh.exe', 'pwshPath 覆盖')
    assertEqual(overridden.stateDir, 'D:\\epc-state', 'stateDir 覆盖')
  })

  await test('执行预算：ctx.shell.resolve 是官方实时途径（每次重读，不缓存）', () => {
    class FakePwshExecutor {
      constructor() {
        this.values = { timeoutMs: 120000, maxOutputBytes: 64000 }
        this.resolveCalls = 0
      }
      resolve(request) {
        this.resolveCalls += 1
        assert(String(request.command).includes('limits-probe'), '探针命令只能是一个永不执行的占位串')
        return { timeoutMs: this.values.timeoutMs, stdoutMaxBytes: this.values.maxOutputBytes }
      }
      get config() {
        return {
          timeoutMs: { get: () => this.values.timeoutMs },
          maxOutputBytes: { get: () => this.values.maxOutputBytes },
        }
      }
    }
    const shell = new FakePwshExecutor()
    const ctx = { get: (name) => (name === 'shell' ? shell : undefined) }
    const first = resolveShellLimits(ctx)
    assertEqual(first.source, 'shell.resolve', 'source 必须是官方 seam')
    assertEqual(first.executor, 'FakePwshExecutor', 'executor 名字如实带出')
    assertEqual(first.timeoutMs, 120000, 'timeoutMs 来自执行器')
    assertEqual(first.maxOutputBytes, 64000, 'maxOutputBytes 来自执行器')
    assertEqual(first.entry, null, 'shell.resolve 路径没有 settings 条目')
    // The whole point: a Settings-page save must be visible to the NEXT call.
    shell.values = { timeoutMs: 5000, maxOutputBytes: 10000 }
    const second = resolveShellLimits(ctx)
    assertEqual(second.timeoutMs, 5000, '设置改了，下一次调用必须跟着变')
    assertEqual(second.maxOutputBytes, 10000, '输出窗口同样实时')
    assert(shell.resolveCalls >= 2, '每次解析都要真的重新问执行器')
    // The optional deployment ceiling can only tighten, never widen.
    const capped = resolveLiveLimits(ctx, { modelOutputLimitBytes: 2000 })
    assertEqual(capped.maxOutputBytes, 2000, '部署上限只能收紧窗口')
    assertEqual(capped.native.maxOutputBytes, 10000, '原生值仍如实保留在 native 里')
    assertEqual(capped.modelCeiling, 2000, 'modelCeiling 如实')
    assertEqual(capped.timeoutMs, 5000, '上限不影响 timeoutMs')
    assertEqual(resolveLiveLimits(ctx, { modelOutputLimitBytes: 0 }).maxOutputBytes, 10000, '0 = 不设上限，跟随原生')
  })

  await test('执行预算：shell.resolve 不可用时退到 shell.config 的 live refs', () => {
    const refs = { timeoutMs: { get: () => 90000 }, maxOutputBytes: { get: () => 80000 } }
    const viaConfig = resolveShellLimits({ get: (name) => (name === 'shell' ? { config: refs } : undefined) })
    assertEqual(viaConfig.source, 'shell.config', '没有 resolve 时退到 config')
    assertEqual(viaConfig.timeoutMs, 90000, 'config.timeoutMs.get()')
    assertEqual(viaConfig.maxOutputBytes, 80000, 'config.maxOutputBytes.get()')
    // A Loader reconcile replaces the refs, not necessarily the object.
    refs.timeoutMs = { get: () => 1234 }
    assertEqual(resolveShellLimits({ get: (name) => (name === 'shell' ? { config: refs } : undefined) }).timeoutMs, 1234, 'config 引用每次都重读')
    // A half-loaded sandbox policy can make resolve() throw; config must still answer.
    const throwing = {
      resolve() {
        throw new Error('sandboxPolicy 尚未就绪')
      },
      config: refs,
    }
    const viaThrowing = resolveShellLimits({ get: (name) => (name === 'shell' ? throwing : undefined) })
    assertEqual(viaThrowing.source, 'shell.config', 'resolve 抛错也要降级到 config，而不是直接兜底')
    assert(viaThrowing.reasons.some((reason) => reason.includes('sandboxPolicy')), '抛错原因必须留档：' + viaThrowing.reasons.join('|'))
    // Invalid refs must not become 0/NaN budgets.
    const invalid = resolveShellLimits({ get: (name) => (name === 'shell' ? { config: { timeoutMs: { get: () => 0 }, maxOutputBytes: { get: () => Number.NaN } } } : undefined) })
    assertEqual(invalid.source, 'fallback:native-defaults', '坏值不能被当成有效设置')
  })

  await test('执行预算：settings.describe 兜底；全都读不到时用原生默认值并如实标注 source', () => {
    const settingsCtx = {
      get: (name) => (name === 'settings'
        ? {
            describe: () => [
              { ns: 'bash-sandbox', value: { timeoutMs: 7000, maxOutputBytes: 70000 } },
              { ns: 'pwsh-sandbox', value: { timeoutMs: 300000, maxOutputBytes: 123456 } },
            ],
          }
        : undefined),
    }
    const viaSettings = resolveShellLimits(settingsCtx, { platform: 'win32' })
    assertEqual(viaSettings.source, 'settings:pwsh-sandbox', 'Windows 优先 pwsh-sandbox 条目')
    assertEqual(viaSettings.entry, 'pwsh-sandbox', 'entry 如实')
    assertEqual(viaSettings.timeoutMs, 300000, 'settings.timeoutMs')
    assertEqual(viaSettings.maxOutputBytes, 123456, 'settings.maxOutputBytes')
    const posix = resolveShellLimits(settingsCtx, { platform: 'linux' })
    assertEqual(posix.source, 'settings:bash-sandbox', 'POSIX 优先 bash-sandbox 条目')
    // Nothing answers: the fallback is the native schema default, labelled.
    const broken = resolveShellLimits({ get: () => { throw new Error('isolate 不匹配') } })
    assertEqual(broken.source, 'fallback:native-defaults', '读不到就必须如实标兜底')
    assertEqual(broken.timeoutMs, 120000, '兜底 timeoutMs = 原生默认 12e4')
    assertEqual(broken.maxOutputBytes, 64000, '兜底 maxOutputBytes = 原生默认 64e3（不是 65536）')
    assertEqual(broken.executor, null, '兜底没有 executor')
    assert(broken.reasons.join('|').includes('isolate'), '兜底原因必须留档：' + broken.reasons.join('|'))
    const noService = resolveShellLimits({ get: () => undefined })
    assertEqual(noService.source, 'fallback:native-defaults', '服务都没有时同样兜底')
    assert(noService.reasons.length >= 2, '每个探测失败都要有原因')
  })

  await test('policyHint：从 tool exec 读 sessionId / workspaceRoot', () => {
    const hint = policyHint({ agent: { id: 'sess-hint', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(hint.sessionId, 'sess-hint', 'sessionId')
    assertEqual(hint.workspaceRoot, WORKSPACE, 'workspaceRoot')
    const empty = policyHint(null)
    assertEqual(empty.sessionId, null, '无 exec 时 sessionId 为 null')
    assert(typeof empty.workspaceRoot === 'string' && empty.workspaceRoot !== '', '无 exec 时仍有可用 workspaceRoot')
  })

  await test('会话归属判定：本会话 / 他会话 / 无主 / adopt 的边界', () => {
    const own = jobOwnership('s1', 's1')
    assertEqual(own.foreign, false, '同一 session 不是 foreign')
    assertEqual(own.allowed, true, '同一 session 默认允许')
    assertEqual(own.adoptedFrom, undefined, '本会话不需要 adoptedFrom')

    const foreign = jobOwnership('s1', 's2')
    assertEqual(foreign.foreign, true, '不同 session 是 foreign')
    assertEqual(foreign.allowed, false, '不同 session 默认拒绝')
    assertEqual(foreign.adoptedFrom, undefined, '没开 adopt 就没有 adoptedFrom')

    const adopted = jobOwnership('s1', 's2', true)
    assertEqual(adopted.allowed, true, 'adopt:true 允许跨会话')
    assertEqual(adopted.adoptedFrom, 's1', 'adopt 成功后带原会话 id')

    const legacyForSession = jobOwnership(null, 's2')
    assertEqual(legacyForSession.foreign, true, '无主 job 对真实会话算 foreign')
    assertEqual(legacyForSession.allowed, false, '无主 job 默认也要 adopt')

    const legacyAdopted = jobOwnership(null, 's2', true)
    assertEqual(legacyAdopted.allowed, true, '无主 job 可 adopt')
    assertEqual(Object.prototype.hasOwnProperty.call(legacyAdopted, 'adoptedFrom'), true, '无主 job 的 adoptedFrom 字段必须存在')
    assertEqual(legacyAdopted.adoptedFrom, null, '无主 job 的 adoptedFrom 是 null（不是 undefined）')

    assertEqual(jobOwnership(null, null).allowed, true, '无主 job + 无会话调用方（Host 级）允许')
    assertEqual(jobOwnership('s1', null).allowed, false, '真实会话的 job 不能被无会话调用方白读')
    assertEqual(jobOwnership('', undefined).allowed, true, '空串归一化为无主')
    assertEqual(jobOwnership('s1', undefined, true).adoptedFrom, 's1', '无会话调用方可 adopt 并记录来源')
  })

  // -------------------------------------------------------------------------
  // Pod protocol over a fake transport (no socket, no child process)
  // -------------------------------------------------------------------------
  const dataRoot = join(TMP_ROOT, 'data')
  const pipeName = PIPE_PREFIX + 'dsh-escape-pod-core-selftest-' + RUN_ID
  const templateCheck = validateTemplate(makeTemplate())
  assert(templateCheck.ok === true, '测试模板应合法')
  const template = templateCheck.template
  const validPrefix = makePrefix({ tempDir: fakeTempDir })
  const validFingerprint = fingerprintPrefix(validPrefix)
  /** @type {any} */
  let service = createPodService({
    workspaceRoot: WORKSPACE,
    dataRoot,
    pipeName,
    idleExitMs: 60_000,
    ringBytes: 65_536,
    outputChunkBytes: 16,
    template,
    // Test seam only: this restricted shell cannot write outside the workspace.
    // The production rule (data root outside the workspace) is asserted below.
    unsafeAllowDataRootInsideWorkspace: true,
    log: () => {},
  })
  service.init()

  await test('pod 启动校验：账本目录在 workspace 内必须拒绝启动（生产默认）', () => {
    const insideLedger = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: join(WORKSPACE, 'local-data', 'escape-pod-core-should-be-rejected'),
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template,
      log: () => {},
    })
    let message = ''
    try {
      insideLedger.init()
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    assert(message.includes('之外'), '账本在 workspace 内时 init 必须抛错，实际：' + (message === '' ? '（没有抛错）' : message))
    assert(message.includes('伪造'), '报错应说明伪造账本的风险，实际：' + message)
    assert(!fs.existsSync(join(WORKSPACE, 'local-data', 'escape-pod-core-should-be-rejected')), '拒绝时不应创建目录')
  })

  await test('pod 协议：模板已钉死、status 可见；无模板的 pod 一律拒绝 run', async () => {
    const status = await service.handle('status', {})
    assertEqual(status.ok, true, 'status 应可用')
    assertEqual(status.podPid, process.pid, 'podPid')
    assertEqual(status.jobs.length, 0, '初始无 job')
    assertEqual(status.template.valid, true, '模板应有效')
    assertEqual(status.template.runnerPath, FAKE_RUNNER, '模板 runnerPath')
    assertEqual(status.template.workspaceRoot, WORKSPACE, '模板 workspace')
    // MODE IS NO LONGER PINNED (a session may be read-only now and widened
    // later); what stays pinned is program + runnerPath + workspaceRoot.
    assertEqual(status.template.modes.join('/'), 'read-only/workspace-write', '模板 modes 只用于展示')
    assertEqual('mode' in status.template, false, '模板不再带单一 mode')
    assertEqual(status.template.pin.includes('runnerPath'), true, '模板应说明钉死项')

    const bare = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    bare.init()
    const noTemplate = await bare.handle('run', { prefix: validPrefix, argv: [process.execPath, '-e', '1'], cwd: WORKSPACE })
    assertEqual(noTemplate.ok, false, '无模板 run 应拒绝')
    assertEqual(noTemplate.error.code, 'EPREFIXTEMPLATE', '无模板错误码')
    await bare.shutdown('selftest done')
  })

  await test('pod 协议：per-call 前缀与 cwd 的 fail-closed 分支', async () => {
    const mismatch = await service.handle('run', {
      prefix: makePrefix({ workspaceRoot: TMP_ROOT, tempDir: fakeTempDir }),
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
    })
    assertEqual(mismatch.ok, false, 'workspace 与模板不一致应拒绝')
    assertEqual(mismatch.error.code, 'EPREFIXWORKSPACETEMPLATE', 'workspace 不一致错误码')
    const notInTree = await service.handle('run', {
      prefix: [process.execPath, join(TMP_ROOT, 'evil', 'runner.js'), '--workspace', WORKSPACE, '--temp', fakeTempDir, '--mode', 'workspace-write'],
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
    })
    assertEqual(notInTree.error.code, 'EPREFIXRUNNERPATH', '安装树外 runner 错误码')
    const badArgs = await service.handle('run', { prefix: validPrefix, argv: [], cwd: WORKSPACE })
    assertEqual(badArgs.error.code, 'EARGS', '空 argv 应拒绝')
    const badCwd = await service.handle('run', { prefix: validPrefix, argv: ['x'], cwd: join(TMP_ROOT, 'nope') })
    assertEqual(badCwd.error.code, 'ECWD', '不存在的 cwd 应拒绝')
    const outsideCwd = await service.handle('run', { prefix: validPrefix, argv: [process.execPath, '-e', '1'], cwd: join(WORKSPACE, '..') })
    assertEqual(outsideCwd.ok, false, 'workspace 外的 cwd 应拒绝')
    assertEqual(outsideCwd.error.code, 'ECWDWORSKSPACE', 'pod 侧也必须拒绝越界 cwd')
    const badJobId = await service.handle('output', { jobId: '../../etc' })
    assertEqual(badJobId.error.code, 'EBADJOBID', '路径穿越形状应拒绝')
    const noJob = await service.handle('output', { jobId: 'podc-none0-abcdef01' })
    assertEqual(noJob.error.code, 'ENOJOB', '不存在的 job 应 ENOJOB')
  })

  await test('pod 协议：per-call 前缀的 temp 目录失效 → EPREFIXSTALE（不让 runner exit 127）', async () => {
    const staleTemp = join(TMP_ROOT, 'stale-tmp')
    fs.mkdirSync(staleTemp, { recursive: true })
    const prefix = makePrefix({ tempDir: staleTemp })
    fs.rmSync(staleTemp, { recursive: true, force: true })
    const run = await service.handle('run', { prefix, argv: [process.execPath, '-e', '1'], cwd: WORKSPACE })
    assertEqual(run.ok, false, 'temp 被收回后 run 应拒绝')
    assertEqual(run.error.code, 'EPREFIXSTALE', '应为 EPREFIXSTALE')
  })

  await test('pod 协议：账本 job 的 unknown 态与绝对偏移续读', async () => {
    // Models a pod that starts AFTER a previous pod instance left a ledger
    // behind: the ledger is scanned at init, a job without exit.json is unknown.
    const dataRoot2 = join(TMP_ROOT, 'data2')
    const jobsRoot = join(dataRoot2, 'jobs')
    const jobId = 'podc-static0-abcdef01'
    const dir = join(jobsRoot, jobId)
    fs.mkdirSync(dir, { recursive: true })
    const content = Buffer.from('行1\nline-2\n终点\n', 'utf8')
    fs.writeFileSync(join(dir, 'out.log'), content)
    jsonWrite(join(dir, 'meta.json'), {
      schema: 1,
      jobId,
      podPid: 4242,
      command: 'fabricated job for offset test',
      argv: ['fabricated'],
      argvHash: hashArgv(['fabricated']),
      cwd: WORKSPACE,
      startedAt: new Date(Date.now() - 60_000).toISOString(),
      prefixFingerprint: 'f'.repeat(64),
      runnerPid: 5555,
    })
    assert(!fs.existsSync(join(dir, 'exit.json')), '先不写 exit.json')
    const ledgerService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: dataRoot2,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 65_536,
      outputChunkBytes: 16,
      template,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    ledgerService.init()

    const status = await ledgerService.handle('status', {})
    const listed = status.jobs.find((job) => job.jobId === jobId)
    assert(listed !== undefined, 'status 应列出账本里的 job')
    assertEqual(listed.status, 'unknown', '无 exit.json 且无句柄应报 unknown')
    assertEqual(listed.bytes, content.length, 'bytes 应为 out.log 大小')

    // Read the whole log in 16-byte chunks using absolute nextOffset.
    const collected = []
    let from = 0
    for (let guard = 0; guard < 100; guard += 1) {
      const chunk = await ledgerService.handle('output', { jobId, from })
      assertEqual(chunk.ok, true, 'output 应成功')
      assertEqual(chunk.from, from, 'from 回显')
      assertEqual(chunk.source, 'disk', '应从磁盘读')
      collected.push(chunk.text)
      if (chunk.eof) {
        assertEqual(chunk.nextOffset, content.length, 'eof 时 nextOffset=total')
        break
      }
      assert(chunk.nextOffset > from, 'nextOffset 必须前进（避免死循环）')
      from = chunk.nextOffset
    }
    assertEqual(collected.join(''), content.toString('utf8'), '分片拼接应等于完整输出')
    const beyond = await ledgerService.handle('output', { jobId, from: content.length + 100 })
    assertEqual(beyond.ok, true, '越界偏移应被 clamp 而不是报错')
    assertEqual(beyond.text, '', '越界偏移无文本')
    assertEqual(beyond.eof, true, '越界偏移 eof')

    const killUnknown = await ledgerService.handle('kill', { jobId })
    assertEqual(killUnknown.ok, true, 'kill 已结束/未知 job 不应报错')
    assertEqual(killUnknown.killed, false, '不应假装杀掉')
    assertEqual(killUnknown.status, 'unknown', '状态应如实')

    jsonWrite(join(dir, 'exit.json'), {
      schema: 1,
      jobId,
      status: 'settled',
      exitCode: 0,
      signal: null,
      startedAt: new Date(Date.now() - 60_000).toISOString(),
      endedAt: new Date(Date.now() - 59_000).toISOString(),
      durationMs: 1000,
      totalBytes: content.length,
      lossy: false,
      writeErrors: 0,
      runnerPid: 5555,
    })
    const rescanned = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: dataRoot2,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    rescanned.init()
    const settledStatus = await rescanned.handle('status', {})
    const settledJob = settledStatus.jobs.find((job) => job.jobId === jobId)
    assertEqual(settledJob.status, 'settled', '写入 exit.json 后应结算为 settled')
    assertEqual(settledJob.exitCode, 0, 'exitCode 应来自 exit.json')
    const settledChunk = await rescanned.handle('output', { jobId, from: 0 })
    assertEqual(settledChunk.running, false, 'settled job running=false')
    assertEqual(settledChunk.exitCode, 0, 'output 也应带 exitCode')
    await rescanned.shutdown('selftest done')
    await ledgerService.shutdown('selftest done')
  })

  await test('pod 协议：spawn 失败也先落 meta（含 argvHash）再写 exit.json', async () => {
    // The runner prefix is real-shaped; in this restricted shell the pipe
    // creation inside `spawn` is EPERM (documented boundary), so the spawn fails
    // closed and must still leave a diagnosable ledger entry.
    const response = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, join(TMP_ROOT, 'no-such-target.mjs')],
      cwd: WORKSPACE,
      command: 'spawn-failure probe',
      enforcement: 'partial',
      host: { pid: process.pid, bootId: 'selftest', startedAt: new Date().toISOString() },
    })
    const jobId = response.jobId
    assert(typeof jobId === 'string' && /^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$/.test(jobId), '应返回 jobId：' + JSON.stringify(response))
    const dir = join(dataRoot, 'jobs', jobId)
    assert(fs.existsSync(join(dir, 'meta.json')), 'meta.json 必须在 spawn 前写入')
    const meta = JSON.parse(fs.readFileSync(join(dir, 'meta.json'), 'utf8'))
    assertEqual(meta.jobId, jobId, 'meta.jobId')
    assertEqual(meta.command, 'spawn-failure probe', 'meta.command')
    assertEqual(meta.prefixFingerprint, validFingerprint, 'meta.prefixFingerprint 应为本次调用前缀的指纹')
    assertEqual(meta.argvHash, hashArgv(meta.argv), 'meta.argvHash 应为目标 argv 的 sha256')
    assertEqual(String(meta.argvHash).length, 64, 'argvHash 长度')
    let status = 'running'
    for (let guard = 0; guard < 100; guard += 1) {
      const chunk = await service.handle('output', { jobId, from: 0 })
      status = chunk.ok ? chunk.status : 'missing'
      if (status !== 'running') break
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 50))
    }
    assert(['spawn-failed', 'settled', 'runner-failed', 'killed'].includes(status), 'spawn 失败必须落成可诊断状态，实际：' + status)
    assert(fs.existsSync(join(dir, 'exit.json')), 'exit.json 必须写出：' + status)
    const exit = JSON.parse(fs.readFileSync(join(dir, 'exit.json'), 'utf8'))
    assertEqual(exit.jobId, jobId, 'exit.jobId')
    assert(['spawn-failed', 'settled', 'runner-failed', 'killed'].includes(exit.status), 'exit.status')
  })

  await test('pod 协议：timeoutMs 可选字段 clamp；超时账本如实投影；output 窗口 clamp 到 1 MiB', async () => {
    // `pod_run` omits the field entirely; that MUST stay "unlimited".
    assertEqual(jobTimeoutOf(null), 0, '缺省 = 不限时（后台语义）')
    assertEqual(jobTimeoutOf({}), 0, '没有 timeoutMs = 不限时')
    assertEqual(jobTimeoutOf({ timeoutMs: -5 }), 0, '负数不产生 deadline')
    assertEqual(jobTimeoutOf({ timeoutMs: Number.NaN }), 0, 'NaN 不产生 deadline')
    assertEqual(jobTimeoutOf({ timeoutMs: 120000 }), 120000, '正常值原样')
    assertEqual(jobTimeoutOf({ timeoutMs: 5_000_000_000 }), MAX_JOB_TIMEOUT_MS, '超过 setTimeout 32 位上限必须 clamp（否则会几乎立刻触发）')
    assert(MAX_JOB_TIMEOUT_MS <= 2 ** 31 - 1, '硬上限必须落在 setTimeout 可表示范围内')

    const host = { pid: process.pid, bootId: 'selftest', startedAt: new Date().toISOString() }
    // The field reaches the ledger exactly once: a foreground deadline is
    // recorded, a background run records null.
    const withTimeout = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      command: 'timeout clamp probe',
      timeoutMs: 5_000_000_000,
      host,
    })
    assert(typeof withTimeout.jobId === 'string', 'run 必须返回 jobId：' + JSON.stringify(withTimeout))
    const timeoutMeta = JSON.parse(fs.readFileSync(join(dataRoot, 'jobs', withTimeout.jobId, 'meta.json'), 'utf8'))
    assertEqual(timeoutMeta.timeoutMs, MAX_JOB_TIMEOUT_MS, 'run.timeoutMs 必须 clamp 后落进 meta.json')
    const background = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      command: 'no timeout probe',
      host,
    })
    assert(typeof background.jobId === 'string', 'run 必须返回 jobId：' + JSON.stringify(background))
    const backgroundMeta = JSON.parse(fs.readFileSync(join(dataRoot, 'jobs', background.jobId, 'meta.json'), 'utf8'))
    assertEqual(backgroundMeta.timeoutMs, null, '没有 timeoutMs 的 run 记 null（后台不限时）')

    // A timeout that already happened: status `killed`, timedOut from exit.json,
    // and the partial output is still readable.
    const timeoutRoot = join(TMP_ROOT, 'timeout-ledger')
    const timeoutJob = 'podc-tout0-abcdef03'
    const timeoutDir = join(timeoutRoot, 'jobs', timeoutJob)
    fs.mkdirSync(timeoutDir, { recursive: true })
    fs.writeFileSync(join(timeoutDir, 'out.log'), Buffer.from('PARTIAL-LINE\n', 'utf8'))
    jsonWrite(join(timeoutDir, 'meta.json'), { schema: 1, jobId: timeoutJob, command: 'timeout probe', startedAt: new Date().toISOString(), timeoutMs: 120000 })
    jsonWrite(join(timeoutDir, 'exit.json'), { schema: 1, jobId: timeoutJob, status: 'killed', exitCode: null, signal: 'SIGTERM', timedOut: true, timeoutMs: 120000, totalBytes: 13 })
    const timeoutService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: timeoutRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    timeoutService.init()
    const read = await timeoutService.handle('output', { jobId: timeoutJob, from: 0 })
    assertEqual(read.status, 'killed', '超时后的账本状态是 killed，不是 settled')
    assertEqual(read.timedOut, true, 'timedOut 从 exit.json 如实投影')
    assertEqual(read.timeoutMs, 120000, 'timeoutMs 如实')
    assertEqual(read.text, 'PARTIAL-LINE\n', '超时也必须保留已经产生的部分输出')
    const timeoutListing = (await timeoutService.handle('status', {})).jobs.find((job) => job.jobId === timeoutJob)
    assertEqual(timeoutListing.timedOut, true, 'status 行同样标 timedOut')
    await timeoutService.shutdown('selftest done')

    // maxBytes clamp: a caller that asks for 4 MiB gets at most 1 MiB.
    const clampRoot = join(TMP_ROOT, 'clamp-ledger')
    const clampJob = 'podc-clmp0-abcdef04'
    const clampDir = join(clampRoot, 'jobs', clampJob)
    fs.mkdirSync(clampDir, { recursive: true })
    const big = Buffer.alloc(MAX_OUTPUT_CHUNK_BYTES + 4096, 0x61)
    fs.writeFileSync(join(clampDir, 'out.log'), big)
    jsonWrite(join(clampDir, 'meta.json'), { schema: 1, jobId: clampJob, command: 'clamp probe', startedAt: new Date().toISOString() })
    const clampService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: clampRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    clampService.init()
    const clamped = await clampService.handle('output', { jobId: clampJob, from: 0, maxBytes: 4 * 1024 * 1024 })
    assertEqual(Buffer.byteLength(clamped.text, 'utf8'), MAX_OUTPUT_CHUNK_BYTES, 'pod 必须把窗口 clamp 到硬上限')
    assertEqual(clamped.truncated, true, '还有更多时必须标 truncated')
    assertEqual(clamped.totalBytes, big.length, '总字节数不受窗口限制')
    await clampService.shutdown('selftest done')
  })

  await test('pod 会话归属：run 写 meta/投影；跨会话 output/kill 拒绝，adopt 可接管', async () => {
    const run = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      command: 'session ownership probe',
      sessionId: 'session-alpha',
      host: { pid: process.pid, bootId: 'selftest', startedAt: new Date().toISOString() },
    })
    assert(run.ok === true || run.error?.code === 'ESPAWNFAILED', 'run 应成功或如实报 spawn 失败（受限 shell 的 EPERM 边界）：' + JSON.stringify(run))
    if (run.ok === true) assertEqual(run.sessionId, 'session-alpha', 'run 回显 sessionId')
    const jobId = run.jobId
    assert(typeof jobId === 'string' && /^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$/.test(jobId), 'run 必须返回 jobId（spawn 失败也先落账本）：' + JSON.stringify(run))
    const meta = JSON.parse(fs.readFileSync(join(dataRoot, 'jobs', jobId, 'meta.json'), 'utf8'))
    assertEqual(meta.sessionId, 'session-alpha', 'meta.json 必须落 sessionId')

    const status = await service.handle('status', {})
    // The standalone package's own version (was 1.7.0 inside the merged
    // restart-bundle, then 1.0.0-hotfix.9 when it split out): POD_VERSION must
    // track package.json. Read it instead of hardcoding so a hotfix bump never
    // turns this into a false failure.
    const pkgVersion = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version
    assertEqual(status.podVersion, pkgVersion, 'POD_VERSION 必须与 package.json 的 version 对齐（' + pkgVersion + '）')
    const row = status.jobs.find((job) => job.jobId === jobId)
    assertEqual(row?.sessionId, 'session-alpha', 'job 投影带 sessionId')

    const own = await service.handle('output', { jobId, from: 0, sessionId: 'session-alpha' })
    assertEqual(own.ok, true, '本会话可读')
    assertEqual(own.sessionId, 'session-alpha', 'output 回显 job 归属')

    const foreign = await service.handle('output', { jobId, from: 0, sessionId: 'session-beta' })
    assertEqual(foreign.ok, false, '他会话默认拒绝读取')
    assertEqual(foreign.error.code, 'EFOREIGNJOB', '错误码必须是 EFOREIGNJOB')
    assert(String(foreign.error.message).includes('adopt: true'), '拒绝消息必须说明 adopt: true：' + foreign.error.message)
    assertEqual(String(foreign.error.message).includes('session-alpha'), false, '拒绝消息不得泄露原会话 id')

    const adopted = await service.handle('output', { jobId, from: 0, sessionId: 'session-beta', adopt: true })
    assertEqual(adopted.ok, true, 'adopt:true 可跨会话读')
    assertEqual(adopted.adoptedFrom, 'session-alpha', 'adoptedFrom 指向原会话')

    const foreignKill = await service.handle('kill', { jobId, sessionId: 'session-beta' })
    assertEqual(foreignKill.error?.code, 'EFOREIGNJOB', '他会话 kill 必须拒绝（哪怕 job 已结束）')
    const foreignCursor = await service.handle('cursor', { jobId, sessionId: 'session-beta' })
    assertEqual(foreignCursor.error?.code, 'EFOREIGNJOB', '他会话 cursor 也必须拒绝（游标也是账本元数据）')
    const foreignAck = await service.handle('ack', { jobId, sessionId: 'session-beta', offset: 0 })
    assertEqual(foreignAck.error?.code, 'EFOREIGNJOB', '他会话 ack 也必须拒绝（写 cursor.json 是账本写）')
    const ownKill = await service.handle('kill', { jobId, sessionId: 'session-alpha' })
    assertEqual(ownKill.ok, true, '本会话 kill 不报归属错')

    // Legacy ledger entries (no sessionId) are unowned: a real session needs
    // adopt, while a Host-level caller with no session still reads them.
    const legacy = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      command: 'legacy unowned probe',
    })
    const legacyMeta = JSON.parse(fs.readFileSync(join(dataRoot, 'jobs', legacy.jobId, 'meta.json'), 'utf8'))
    assertEqual(legacyMeta.sessionId, null, '未传 sessionId 时 meta 记 null')
    const legacyForeign = await service.handle('output', { jobId: legacy.jobId, from: 0, sessionId: 'session-alpha' })
    assertEqual(legacyForeign.error?.code, 'EFOREIGNJOB', '无主历史 job 对真实会话默认拒绝')
    const legacyAdopted = await service.handle('output', { jobId: legacy.jobId, from: 0, sessionId: 'session-alpha', adopt: true })
    assertEqual(legacyAdopted.ok, true, '无主历史 job 可 adopt')
    assertEqual(Object.prototype.hasOwnProperty.call(legacyAdopted, 'adoptedFrom'), true, 'adoptedFrom 字段必须存在（null 不是 undefined）')
    assertEqual(legacyAdopted.adoptedFrom, null, '无主 job 的 adoptedFrom 是 null')
    const hostRead = await service.handle('output', { jobId: legacy.jobId, from: 0 })
    assertEqual(hostRead.ok, true, '无会话调用方仍可读无主 job（Host 级）')

    const noJob = await service.handle('output', { jobId: 'podc-nope0-abcdef01', sessionId: 'session-beta' })
    assertEqual(noJob.error?.code, 'ENOJOB', '不存在的 job 报 ENOJOB')
    assertEqual(String(noJob.error.message).includes(jobId), false, 'ENOJOB 的已知 job 提示不得泄露他会话 jobId：' + noJob.error.message)

    // "重启后"的语义：一个新的 pod 实例从同一份账本重建状态（DSH 重启时 Host 的内存
    // 归属表是空的），同一 sessionId 仍必须能读回自己的 job，其它会话仍被拒。
    const restarted = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    restarted.init()
    const restartedStatus = await restarted.handle('status', {})
    assertEqual(restartedStatus.jobs.find((job) => job.jobId === jobId)?.sessionId, 'session-alpha', '重启后从 meta 读回 sessionId')
    const restartedOwn = await restarted.handle('output', { jobId, from: 0, sessionId: 'session-alpha' })
    assertEqual(restartedOwn.ok, true, '同一 sessionId 在重启语义下仍可读自己的 job')
    const restartedForeign = await restarted.handle('output', { jobId, from: 0, sessionId: 'session-beta' })
    assertEqual(restartedForeign.error?.code, 'EFOREIGNJOB', '重启后他会话仍被拒')
    await restarted.shutdown('selftest done')
  })

  await service.shutdown('selftest done')

  // -------------------------------------------------------------------------
  // ctx.jobs adoption (fake registry + fake pod; the real-pod variant lives in
  // selftest-remote.mjs)
  // -------------------------------------------------------------------------

  /** A duck-typed `ctx.jobs` that records the spec and exposes a fake handle. */
  function createFakeJobs() {
    /** @type {Map<string, any>} */
    const started = new Map()
    /** @type {Map<string, any>} */
    const views = new Map()
    const fake = {
      started,
      views,
      reads: [],
      start(spec) {
        const id = 'registry-' + String(started.size + 1)
        const handle = {
          id,
          appended: [],
          progress: null,
          append(text, opts) {
            this.appended.push({ text, opts })
          },
          updateProgress(text) {
            this.progress = text
          },
        }
        const hooks = spec.run(handle)
        started.set(id, { id, spec, handle, hooks })
        views.set(id, { id, kind: spec.kind, label: spec.label, status: 'running', owner: spec.owner })
        return id
      },
      get(id) {
        return views.get(id) ?? null
      },
      read(id) {
        fake.reads.push(id)
        return { chunks: [], output: { total: 0 } }
      },
    }
    return fake
  }

  /** A duck-typed pod client: output returns queued chunks, kill is recorded. */
  function createFakePod(chunks = [], statusJobs = []) {
    const calls = { output: [], kill: [], status: 0 }
    const queue = chunks.slice()
    return {
      calls,
      mode: () => 'reused',
      stateDir: join(TMP_ROOT, 'adoption-state'),
      async output(_hint, request) {
        calls.output.push(request)
        const next = queue.shift()
        if (next !== undefined) return next
        return {
          ok: true,
          status: 'running',
          running: true,
          text: '',
          from: request.from,
          nextOffset: request.from,
          totalBytes: request.from,
          hasMore: false,
          eof: true,
          exitCode: null,
          signal: null,
        }
      },
      async kill(_hint, request) {
        calls.kill.push(request)
        return { ok: true, killed: true, status: 'killed', exitCode: null, signal: 'SIGTERM' }
      },
      async status() {
        calls.status += 1
        return { response: { jobs: statusJobs, running: statusJobs.filter((job) => job.status === 'running').length } }
      },
    }
  }

  const flush = async () => {
    for (let index = 0; index < 5; index += 1) await Promise.resolve()
  }

  await test('adoption：teardown 哨兵识别与 pod 状态映射', () => {
    assertEqual(TEARDOWN_REASONS.length, 2, '应钉住 dsh-jobs-local 的两个 teardown 原因')
    assertEqual(isTeardownReason('jobs service disposed'), true, 'service teardown 应识别')
    assertEqual(isTeardownReason('owner disposed'), true, 'owner teardown 应识别')
    assertEqual(isTeardownReason(undefined), false, '显式 kill（无 reason）不能当 teardown')
    assertEqual(isTeardownReason('user asked'), false, '用户 reason 不是 teardown')
    assertEqual(isTeardownReason('jobs service disposed', true), true, 'hostDisposing 兜底')
    assertEqual(mapPodOutcome({ status: 'settled', exitCode: 0 }).status, 'completed', 'settled→completed')
    assertEqual(mapPodOutcome({ status: 'settled', exitCode: 0 }).detail, undefined, 'completed 不带 detail（原生 [status: completed]）')
    assertEqual(mapPodOutcome({ status: 'killed', signal: 'SIGTERM' }).status, 'killed', 'killed→killed')
    assertEqual(mapPodOutcome({ status: 'killed', signal: 'SIGTERM' }).detail, 'SIGTERM', 'killed detail = signal')
    assertEqual(mapPodOutcome({ status: 'runner-failed', exitCode: 127 }).status, 'failed', 'runner-failed→failed')
    assertEqual(mapPodOutcome({ status: 'unknown' }).status, 'failed', 'unknown→failed')
    assertEqual(mapPodOutcome({ status: 'settled', exitCode: 3 }).detail, undefined, '非零退出也不进 status detail（原生放文本）')
  })

  await test('adoption：unowned 记录、原生 label、registryInfo 与 job_list 同源', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod()
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-11112222', command: 'echo truncated', startedAt: '2026-10-28T00:00:00.000Z' }, null, 'echo hi')
    assertEqual(registryId, 'registry-1', '应返回 registry id')
    const started = jobs.started.get(registryId)
    assertEqual(started.spec.kind, ADOPT_KIND, 'kind')
    assertEqual(started.spec.owner, undefined, '必须 unowned（无 owner 才会跨会话可见且不随会话销毁）')
    // Native pwsh label is the raw command only; no producer prefix, no jobId.
    assertEqual(started.spec.label, 'echo hi', 'label 必须是纯命令原文（原生形状）')
    assert(!started.spec.label.includes('escape-pod'), 'label 不能带生产者前缀')
    assert(!started.spec.label.includes('podc-abc-11112222'), 'label 不能塞 pod jobId（它只属于 pod_status）')
    const info = manager.registryInfo('podc-abc-11112222')
    assertEqual(info.adopted, true, 'registryInfo.adopted')
    assertEqual(info.id, registryId, 'registryInfo.id')
    assertEqual(info.status, 'running', 'registryInfo 读 registry 状态')
    assertEqual(manager.registryInfo('podc-never-adopted').adopted, false, '未收养的 job 明确说 false')
    manager.dispose()
  })

  await test('adoption 生死线：teardown cancel 绝不调用 pod.kill，且必须结算以免 Host dispose 挂起', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod()
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-33334444', command: 'long job' }, null)
    const record = manager.recordFor('podc-abc-33334444')
    const done = jobs.started.get(registryId).hooks.done
    jobs.started.get(registryId).hooks.cancel('jobs service disposed')
    await flush()
    assertEqual(pod.calls.kill.length, 0, 'Host 退出时不能杀 pod 命令')
    assertEqual(record.detached, true, '应标记 detached')
    const outcome = await done
    assertEqual(outcome.status, 'killed', '记录应结算（cause teardown）')
    assert(String(outcome.detail).includes('left running'), 'detail 必须写明 pod 命令仍在运行')
    // owner disposal is the same teardown class
    const manager2 = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const secondId = manager2.adoptNewJob({ jobId: 'podc-abc-55556666', command: 'x' }, null)
    jobs.started.get(secondId).hooks.cancel('owner disposed')
    await flush()
    assertEqual(pod.calls.kill.length, 0, 'owner teardown 同样不能杀')
    await jobs.started.get(secondId).hooks.done
    manager.dispose()
    manager2.dispose()
  })

  await test('adoption：显式 cancel 真杀，并按 pod 结算映射 done', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod([
      { ok: true, status: 'killed', running: false, text: 'bye\n', from: 0, nextOffset: 4, totalBytes: 4, hasMore: false, eof: true, exitCode: null, signal: 'SIGTERM' },
    ])
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-77778888', command: 'kill me' }, null)
    const hooks = jobs.started.get(registryId).hooks
    hooks.cancel(undefined)
    await flush()
    assertEqual(pod.calls.kill.length, 1, '显式 kill 必须调用 pod.kill')
    assertEqual(pod.calls.kill[0].jobId, 'podc-abc-77778888', 'kill 的目标')
    await manager.pollAllOnce()
    const outcome = await hooks.done
    assertEqual(outcome.status, 'killed', 'done 应映射 pod 的 killed')
    assertEqual(jobs.started.get(registryId).handle.appended[0].text, 'bye\n', '终止前的新字节也应 append')
    assertEqual(manager.registryInfo('podc-abc-77778888').status, 'killed', 'registryInfo 应与结算一致')
    manager.dispose()
  })

  await test('adoption：job_kill 的 pre-execute 标记能压过 teardown 哨兵 reason（真杀）', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod()
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-99990000', command: 'x' }, null)
    manager.noteExplicitKill(registryId)
    jobs.started.get(registryId).hooks.cancel('jobs service disposed')
    await flush()
    assertEqual(pod.calls.kill.length, 1, '显式 job_kill 即使 reason 撞哨兵也必须真杀')
    jobs.started.get(registryId).hooks.cancel('jobs service disposed')
    manager.dispose()
  })

  await test('adoption 模型游标：从收养时偏移开始泵，绝不复读历史', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod([
      { ok: true, status: 'running', running: true, text: 'NEW-ONLY\n', from: 42, nextOffset: 51, totalBytes: 51, hasMore: false, eof: false, exitCode: null, signal: null },
    ])
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-aaaa0000', command: 'resumed' }, null)
    // simulate a restart adoption at the pod's current total
    const resumed = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const resumedId = resumed.adopt({ podJobId: 'podc-abc-bbbb1111', command: 'resumed', baseOffset: 42, hint: null })
    assertEqual(pod.calls.output.length, 0, 'adopt 本身不应读输出')
    await resumed.pollAllOnce()
    assertEqual(pod.calls.output[0].from, 42, '第一次读必须从 baseOffset（已读偏移）开始，不能是 0')
    assertEqual(jobs.started.get(resumedId).handle.appended[0].text, 'NEW-ONLY\n', 'ring 只装收养之后的新字节')
    assertEqual(manager.recordFor('podc-abc-aaaa0000').baseOffset, 0, '本 Host 新起的 job 从 0 开始')
    assertEqual(registryId === null, false, '新 job 也应收养')
    resumed.dispose()
    manager.dispose()
  })

  await test('adoption：ensureAdopted 只收养 running，历史 job 不收养；无 jobs 服务时优雅降级', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod([], [
      { jobId: 'podc-run0-11112222', status: 'running', bytes: 10, command: 'live', startedAt: '2026-10-28T00:00:00.000Z' },
      { jobId: 'podc-done-33334444', status: 'settled', bytes: 99, command: 'old' },
    ])
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const result = await manager.ensureAdopted(null, { force: true })
    assertEqual(result.adopted, 1, '只收养 running 的 job')
    assertEqual(jobs.started.size, 1, 'registry 只多一条')
    assertEqual(manager.registryInfo('podc-done-33334444').adopted, false, '历史 job 明确未收养')
    assertEqual(manager.recordFor('podc-run0-11112222').baseOffset, 10, '收养偏移应为 pod 当前 total')
    manager.dispose()
    const degraded = createAdoptionManager({ getJobs: () => null, pod, autoPoll: false, log: () => {} })
    assertEqual(degraded.adoptNewJob({ jobId: 'podc-x-1' }, null), null, '无 jobs 服务时返回 null 而不是抛错')
    degraded.dispose()
  })

  await test('adoption：插件 dispose（HMR/Host 关闭）解除收养但不杀 pod 命令', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod()
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-abc-cccc2222', command: 'x' }, null)
    const done = jobs.started.get(registryId).hooks.done
    manager.markHostDisposing()
    manager.dispose()
    const outcome = await done
    assertEqual(pod.calls.kill.length, 0, 'dispose 不能杀 pod 命令')
    assertEqual(outcome.status, 'killed', '应结算，避免 registry teardown 等待')
    assert(String(outcome.detail).includes('left running'), 'detail 写明命令仍在跑')
    assertEqual(manager.stats().disposed, true, 'stats.disposed')
  })

  // -------------------------------------------------------------------------
  // Output cursor + prefix hash
  // -------------------------------------------------------------------------

  const prefixHash = (buffer, offset = buffer.length) => createHash('sha256').update(buffer.subarray(0, offset)).digest('hex')

  await test('cursor hash：sha256(0..offset) 正确，checkpoint 可复用（跨块边界）', () => {
    const data = Buffer.from('abcdefghijklmnopqrstuvwxyz-0123456789-世界-END', 'utf8')
    const hasher = createPrefixHasher({
      readRange: (start, length) => data.subarray(start, start + length),
      blockBytes: 8,
    })
    for (const offset of [0, 1, 7, 8, 9, 17, 32, data.length]) {
      assertEqual(hasher.hashAt(offset), prefixHash(data, offset), 'offset=' + String(offset) + ' 的前缀 hash')
    }
    assert(hasher.builtTo === data.length, 'hasher 应已覆盖完整文件')
    assert(hasher.checkpointCount >= 4, '应建立多个 checkpoint，实际=' + String(hasher.checkpointCount))
    assertEqual(hasher.hashAt(0), prefixHash(Buffer.alloc(0)), '空前缀 = sha256(空)')
    let threw = false
    try {
      hasher.extendTo(data.length + 10)
    } catch {
      threw = true
    }
    assertEqual(threw, true, '超出文件长度应抛错（账本被截断）')
  })

  await test('validateCursor：missing/malformed/ahead/mismatch/ok/lossy 六态如实区分', () => {
    const data = Buffer.from('0123456789abcdef', 'utf8')
    const hashAt = (offset) => prefixHash(data, offset)
    const stateOf = (cursor, extra = {}) => validateCursor({ cursor, totalBytes: data.length, windowStart: 0, hashAt, ...extra })
    assertEqual(stateOf(null).state, 'missing', '无 cursor → missing')
    assertEqual(stateOf({ offset: 'x', hash: 'y' }).state, 'malformed', '坏形状 → malformed')
    assertEqual(stateOf({ offset: data.length + 3, hash: 'a'.repeat(64) }).state, 'ahead', '超前 → ahead')
    assertEqual(stateOf({ offset: 5, hash: 'a'.repeat(64) }).state, 'mismatch', 'hash 不符 → mismatch')
    const good = stateOf({ offset: 5, hash: hashAt(5) })
    assertEqual(good.state, 'ok', 'hash 相符 → ok')
    assertEqual(good.valid, true, 'ok 应 valid')
    const lossy = stateOf({ offset: 5, hash: hashAt(5) }, { windowStart: 10 })
    assertEqual(lossy.state, 'lossy', 'offset 早于窗口 → lossy')
    assertEqual(lossy.lossy, true, 'lossy 标志')
    assertEqual(lossy.valid, true, 'lossy 仍可用（显式降级）')
  })

  await test('pod ack：原子写 cursor.json、坏 hash 拒绝、单调、状态可校验、篡改报 mismatch', async () => {
    const cursorRoot = join(TMP_ROOT, 'cursor-data')
    const jobId = 'podc-cursor0-abcdef01'
    const dir = join(cursorRoot, 'jobs', jobId)
    fs.mkdirSync(dir, { recursive: true })
    const content = Buffer.from('hello-世界\nline-2\n', 'utf8')
    fs.writeFileSync(join(dir, 'out.log'), content)
    jsonWrite(join(dir, 'meta.json'), {
      schema: 1,
      jobId,
      podPid: 1,
      command: 'cursor probe',
      argv: ['cursor'],
      cwd: WORKSPACE,
      startedAt: new Date().toISOString(),
    })
    const cursorService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: cursorRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    cursorService.init()
    const fullHash = prefixHash(content)
    assertEqual(fullHash.length, 64, 'sha256 hex')
    const ack = await cursorService.handle('ack', { jobId, offset: content.length, hash: fullHash })
    assertEqual(ack.ok, true, 'ack 应成功：' + JSON.stringify(ack))
    assertEqual(ack.hash, fullHash, 'ack 回显 hash')
    const cursorFile = join(dir, 'cursor.json')
    assert(fs.existsSync(cursorFile), 'cursor.json 应写出')
    const stored = JSON.parse(fs.readFileSync(cursorFile, 'utf8'))
    assertEqual(stored.offset, content.length, 'cursor.offset')
    assertEqual(stored.hash, fullHash, 'cursor.hash')
    assertEqual(stored.algorithm, 'sha256-prefix', 'cursor.algorithm')
    assert(typeof stored.updatedAt === 'string', 'cursor.updatedAt')

    const mismatch = await cursorService.handle('ack', { jobId, offset: content.length, hash: 'f'.repeat(64) })
    assertEqual(mismatch.ok, false, '坏 hash 应拒绝')
    assertEqual(mismatch.error.code, 'EPREFIXHASHMISMATCH', '坏 hash 错误码')
    assertEqual(JSON.parse(fs.readFileSync(cursorFile, 'utf8')).hash, fullHash, '坏 hash 不得覆写 cursor')

    const ahead = await cursorService.handle('ack', { jobId, offset: content.length + 1, hash: fullHash })
    assertEqual(ahead.error.code, 'EACKOFFSET', '超前 offset 应拒绝')

    const behind = await cursorService.handle('ack', { jobId, offset: 0, hash: prefixHash(Buffer.alloc(0)) })
    assertEqual(behind.ok, true, '回读旧偏移不应报错')
    assertEqual(behind.skipped, 'behind-cursor', '应跳过，保持单调')
    assertEqual(JSON.parse(fs.readFileSync(cursorFile, 'utf8')).offset, content.length, 'cursor 不得倒退')

    const status = await cursorService.handle('status', {})
    const listed = status.jobs.find((job) => job.jobId === jobId)
    assertEqual(listed.cursor.state, 'ok', 'status.cursor.state 应为 ok')
    assertEqual(listed.cursor.offset, content.length, 'status.cursor.offset')

    // Tamper the anchor: the pod must report mismatch, not continue silently.
    const tampered = { ...stored, hash: '0'.repeat(64) }
    fs.writeFileSync(cursorFile, JSON.stringify(tampered))
    const status2 = await cursorService.handle('status', {})
    const listed2 = status2.jobs.find((job) => job.jobId === jobId)
    assertEqual(listed2.cursor.state, 'mismatch', '篡改 hash 后应为 mismatch')
    assertEqual(listed2.cursor.valid, false, 'mismatch 不 valid')
    await cursorService.shutdown('selftest done')
  })

  await test('adoption：cursor 优先、缺失回退 total、mismatch 明确告警、lossy 带 gapBefore', async () => {
    const jobs = createFakeJobs()
    const cursorHash = 'a'.repeat(64)
    const statusJobs = [
      { jobId: 'podc-cur0-11112222', status: 'running', bytes: 100, command: 'cursor-ok', cursor: { state: 'ok', offset: 40, hash: cursorHash, lossy: false } },
      { jobId: 'podc-cur1-33334444', status: 'running', bytes: 80, command: 'no-cursor', cursor: { state: 'missing', offset: null } },
      { jobId: 'podc-cur2-55556666', status: 'running', bytes: 70, command: 'bad-cursor', cursor: { state: 'mismatch', offset: 20, hash: 'b'.repeat(64), reason: '前缀 hash 不匹配' } },
      { jobId: 'podc-cur3-77778888', status: 'running', bytes: 60, command: 'lossy-cursor', cursor: { state: 'lossy', offset: 10, hash: cursorHash, reason: '早于保留窗口' } },
    ]
    const basePod = createFakePod([], statusJobs)
    const emptyChunk = (request) => ({
      ok: true, status: 'running', running: true, text: '', from: request.from, nextOffset: request.from,
      totalBytes: 60, hasMore: false, eof: true, exitCode: null, signal: null,
    })
    const pod = {
      ...basePod,
      async output(_hint, request) {
        basePod.calls.output.push(request)
        if (request.jobId === 'podc-cur3-77778888' && request.from === 10) {
          return { ok: true, status: 'running', running: true, text: 'NEW\n', from: 10, nextOffset: 14, totalBytes: 60, hasMore: false, eof: false, exitCode: null, signal: null }
        }
        return emptyChunk(request)
      },
    }
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const result = await manager.ensureAdopted(null, { force: true })
    assertEqual(result.adopted, 4, '应收养 4 个 running job')
    assertEqual(manager.recordFor('podc-cur0-11112222').baseOffset, 40, '有 cursor 时用 cursor.offset')
    assertEqual(manager.recordFor('podc-cur0-11112222').cursorMode, 'ok', 'cursorMode=ok')
    assertEqual(manager.recordFor('podc-cur1-33334444').baseOffset, 80, '无 cursor 回退 totalBytes')
    assertEqual(manager.recordFor('podc-cur1-33334444').cursorMode, 'no-cursor', 'cursorMode=no-cursor')
    assertEqual(manager.recordFor('podc-cur2-55556666').baseOffset, 70, 'hash 不符时不得回退到未验证偏移')
    assertEqual(manager.recordFor('podc-cur2-55556666').cursorMode, 'cursor-mismatch', 'mismatch 明确标记')
    assert(String(manager.recordFor('podc-cur2-55556666').cursorWarning).includes('cursor-mismatch'), '应带 cursor-mismatch 告警')
    assertEqual(manager.recordFor('podc-cur3-77778888').baseOffset, 10, 'lossy 仍从 cursor 续读')
    assertEqual(manager.recordFor('podc-cur3-77778888').lossy, true, 'lossy 标志')
    await manager.pollAllOnce()
    const lossyRecord = manager.recordFor('podc-cur3-77778888')
    const lossyHandle = jobs.started.get(lossyRecord.registryId).handle
    assertEqual(lossyHandle.appended[0]?.opts?.gapBefore, true, 'lossy 的首次 append 必须带 gapBefore')
    const info = manager.registryInfo('podc-cur2-55556666')
    assertEqual(info.cursor, 'cursor-mismatch', 'registryInfo 暴露 cursor 模式')
    manager.dispose()
  })

  // -------------------------------------------------------------------------
  // Model-facing fidelity: no offsets, auto-advancing cursor, UTF-8/line
  // aligned chunks, native-like truncation marker.
  // -------------------------------------------------------------------------

  /** A pod client fake whose cursor advances exactly like the real `ack` op. */
  function createModelPod(content) {
    const buffer = Buffer.from(content, 'utf8')
    let consumed = 0
    const calls = { output: [], ack: [], cursor: 0 }
    return {
      calls,
      mode: () => 'reused',
      stateDir: join(TMP_ROOT, 'model-state'),
      pipeName: 'model-pipe',
      async cursor(_hint, request) {
        calls.cursor += 1
        return { state: 'ok', offset: consumed, hash: 'a'.repeat(64), lossy: false, totalBytes: buffer.length }
      },
      async output(_hint, request) {
        calls.output.push(request)
        const start = request.from
        const maxBytes = request.maxBytes ?? 65536
        if (start >= buffer.length) {
          return {
            ok: true, jobId: request.jobId, text: '', from: start, nextOffset: start, totalBytes: buffer.length,
            hasMore: false, eof: true, running: false, status: 'settled', exitCode: 0, signal: null,
            stalled: false, lossy: false, prefixHash: 'a'.repeat(64),
          }
        }
        const take = Math.min(maxBytes, buffer.length - start)
        let slice = buffer.subarray(start, start + take)
        if (start + take < buffer.length) {
          const safe = trimIncompleteUtf8End(slice)
          slice = safe > 0 ? slice.subarray(0, safe) : Buffer.alloc(0)
        }
        const next = start + slice.length
        const more = next < buffer.length
        return {
          ok: true, jobId: request.jobId, text: slice.toString('utf8'), from: start, nextOffset: next,
          totalBytes: buffer.length, hasMore: more, eof: !more, running: more,
          status: more ? 'running' : 'settled', exitCode: more ? null : 0, signal: null,
          stalled: slice.length === 0 && more, lossy: false, prefixHash: 'a'.repeat(64),
        }
      },
      async ack(_hint, request) {
        calls.ack.push(request)
        consumed = Math.max(consumed, request.offset)
        return { ok: true }
      },
    }
  }

  await test('模型面 pod_output：schema 无 from/maxBytes，自动续读，ack 只记已返回字节', async () => {
    const content = Array.from({ length: 60 }, (_v, index) => 'L' + String(index + 1).padStart(4, '0') + ' 中文😀\n').join('')
    const pod = createModelPod(content)
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    assert(tool !== undefined, 'pod_output 应存在')
    assertEqual(Object.keys(tool.parameters.properties).join(','), 'jobId,adopt', '模型面 schema 只能有 jobId 与 adopt（不得有 from/maxBytes）')
    assert(!/nextOffset|absolute offset/i.test(tool.description), '描述里不应出现偏移术语')
    assert(!/from\b/.test(tool.description), '描述里不应出现 from 参数')
    const exec = { agent: { id: 'model-session', session: { meta: { cwd: WORKSPACE } } } }
    const collected = []
    let calls = 0
    for (;;) {
      calls += 1
      if (calls > 200) throw new Error('模型面读取未收敛')
      const value = await tool.execute({ jobId: 'podc-model0-abcdef01' }, exec)
      for (const forbidden of ['from', 'nextOffset', 'totalBytes', 'prefixHash']) {
        assertEqual(Object.prototype.hasOwnProperty.call(value, forbidden), false, 'model value 不应暴露 ' + forbidden)
      }
      assert(!/offset|nextOffset|\bbytes\b/.test(String(value.message)), 'model 主文本不应出现偏移/字节数：' + value.message.slice(0, 120))
      collected.push(value.text)
      if (value.running === false && value.text === '') break
      if (value.running === false && pod.calls.output.length > 0) {
        const last = pod.calls.output[pod.calls.output.length - 1]
        if (last.from + Buffer.byteLength(value.text) >= Buffer.byteLength(content)) break
      }
    }
    const joined = collected.join('')
    assertEqual(joined, content, '多次模型面读取拼接应等于原文（多字节不丢不坏）')
    assert(!joined.includes('\uFFFD'), '拼接结果不应出现替换字符')
    assertEqual(pod.calls.ack[0].offset, Buffer.byteLength(collected[0]), '首次 ack 应为已返回字节数')
    const lastAck = pod.calls.ack[pod.calls.ack.length - 1]
    assertEqual(lastAck.offset, Buffer.byteLength(content), '最后一次 ack 应到全文末尾')
  })

  await test('alignModelChunk：不拆行、不拆码点，强制截断给 [output truncated]', () => {
    const lineCut = alignModelChunk({ text: 'a\nb\nc', hasMore: true })
    assertEqual(lineCut.text, 'a\nb\n', '有换行时应在最后一个换行后切')
    assertEqual(lineCut.consumedBytes, 4, 'consumedBytes')
    assertEqual(lineCut.droppedPartialLine, true, '应把残行留到下次')
    assertEqual(lineCut.truncated, true, '原生语义：只要还有更多输出就带 [output truncated]')
    const emojiLine = alignModelChunk({ text: '行\n😀', hasMore: true })
    assertEqual(emojiLine.text, '行\n', '多字节残行整体留到下次')
    assertEqual(emojiLine.consumedBytes, 4, 'emoji 不应被切一半')
    const noNewline = alignModelChunk({ text: '连续😀无换行', hasMore: true })
    assertEqual(noNewline.text, '连续😀无换行', '没有换行时整块返回（pod 已按码点对齐）')
    assertEqual(noNewline.truncated, true, '无换行且还有更多 → 截断标记')
    const whole = alignModelChunk({ text: '😀尾', hasMore: false })
    assertEqual(whole.text, '😀尾', 'hasMore=false 时原样返回')
    assertEqual(whole.consumedBytes, 7, '码点字节数（😀=4 + 尾=3）')
  })

  await test('job_output 推进 pod cursor：baseOffset + output.total，去重且忽略错误结果', async () => {
    const acks = []
    const pod = { async ack(_hint, request) { acks.push(request); return { ok: true } } }
    const record = { baseOffset: 100, podJobId: 'podc-ack0-abcdef01', hint: null, settled: false, detached: false }
    const jobs = { get: () => ({ output: { total: 42 } }) }
    const adoptions = { recordForRegistryId: (id) => (id === 'bash-abc' ? record : null) }
    const hook = createJobOutputAckHook({ getJobs: () => jobs, adoptions, pod, log: () => {} })
    const flush = async () => { for (let i = 0; i < 5; i += 1) await Promise.resolve() }
    hook({ name: 'job_output', arguments: { job_id: 'bash-abc' }, agent: { id: 's' } }, { isError: false })
    await flush()
    assertEqual(acks.length, 1, 'job_output 后应发 ack')
    assertEqual(acks[0].offset, 142, 'offset = baseOffset + output.total')
    hook({ name: 'job_output', arguments: { job_id: 'bash-abc' }, agent: { id: 's' } }, { isError: false })
    await flush()
    assertEqual(acks.length, 1, '相同 total 不应重复 ack')
    jobs.get = () => ({ output: { total: 50 } })
    hook({ name: 'job_output', arguments: { job_id: 'bash-abc' }, agent: { id: 's' } }, { isError: false })
    await flush()
    assertEqual(acks.length, 2, '消费更多后应再次 ack')
    assertEqual(acks[1].offset, 150, '新 offset')
    hook({ name: 'job_output', arguments: { job_id: 'bash-abc' }, agent: { id: 's' } }, { isError: true })
    hook({ name: 'job_output', arguments: { job_id: 'bash-nope' }, agent: { id: 's' } }, { isError: false })
    await flush()
    assertEqual(acks.length, 2, '错误结果/非本 pod job 不应 ack')
  })

  await test('pod 字节对齐：极小块也不拆 UTF-8，拼接等于 out.log；cursor op 可读', async () => {
    const alignRoot = join(TMP_ROOT, 'align-data')
    const jobId = 'podc-align0-abcdef01'
    const dir = join(alignRoot, 'jobs', jobId)
    fs.mkdirSync(dir, { recursive: true })
    const content = Buffer.from('中文😀🚀\n尾行✅\n', 'utf8')
    fs.writeFileSync(join(dir, 'out.log'), content)
    jsonWrite(join(dir, 'meta.json'), { schema: 1, jobId, command: 'align probe', startedAt: new Date().toISOString() })
    const alignService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: alignRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    alignService.init()
    const stalled = await alignService.handle('output', { jobId, from: 0, maxBytes: 2 })
    assertEqual(stalled.ok, true, '小块读取不应报错')
    assertEqual(stalled.text, '', '2 字节小于一个中文字符 → 不返回半个码点')
    assertEqual(stalled.stalled, true, '应标记 stalled，提示调用方换大块')
    const pieces = []
    let offset = 0
    for (let guard = 0; guard < 50 && offset < content.length; guard += 1) {
      const chunk = await alignService.handle('output', { jobId, from: offset, maxBytes: 5 })
      assertEqual(chunk.stalled === true, false, '5 字节应总能切出完整码点')
      assert(!chunk.text.includes('\uFFFD'), '不得出现替换字符')
      assert(Buffer.from(chunk.text, 'utf8').length === chunk.nextOffset - chunk.from, 'text 字节数应等于偏移增量')
      pieces.push(Buffer.from(chunk.text, 'utf8'))
      offset = chunk.nextOffset
    }
    assertEqual(Buffer.concat(pieces).equals(content), true, '分片拼接必须与 out.log 逐字节一致')
    const hash = createHash('sha256').update(content).digest('hex')
    const ack = await alignService.handle('ack', { jobId, offset: content.length, hash })
    assertEqual(ack.ok, true, 'ack 全文')
    const cursor = await alignService.handle('cursor', { jobId })
    assertEqual(cursor.ok, true, 'cursor op')
    assertEqual(cursor.cursor.state, 'ok', 'cursor.state')
    assertEqual(cursor.cursor.offset, content.length, 'cursor.offset')
    assertEqual(cursor.cursor.hash, hash, 'cursor.hash')
    await alignService.shutdown('selftest done')
  })

  // -------------------------------------------------------------------------
  // P1 alignment: channel segments, native truncation notice, pure label
  // -------------------------------------------------------------------------

  await test('segments：解析/清洗/覆盖范围不移动偏移，缺口回退 stdout', () => {
    const raw = [
      '{"offset":0,"length":4,"channel":"stdout"}',
      '{"offset":4,"length":4,"channel":"stderr"}',
      'not-json',
      '{"offset":99,"length":5,"channel":"stdout"}',
    ].join('\n')
    const parsed = parseSegments(raw)
    assertEqual(parsed.length, 3, '坏行应被忽略，坏越界条目保留待清洗')
    const kept = sanitizeSegments(parsed, 8)
    assertEqual(kept.length, 2, 'sanitize 应只保留落入 totalBytes 的连续前缀')
    const covered = coverRange(kept, 2, 6)
    assertEqual(covered.length, 2, '跨越两个通道')
    assertEqual(covered[0].offset, 2, '起点偏移不变')
    assertEqual(covered[0].channel, 'stdout', '前两字节属于 stdout')
    assertEqual(covered[1].offset, 4, '第二段从 4 开始')
    assertEqual(covered[1].channel, 'stderr', '后段属于 stderr')
    const gap = coverRange([], 0, 5)
    assertEqual(gap.length, 1, '没有 segment 时给一个兜底段')
    assertEqual(gap[0].channel, 'stdout', '缺口按 stdout 兜底')
    const bytes = Buffer.from('OUT\nERR\n', 'utf8')
    const chunks = buildChunks({ segments: kept, from: 0, to: 8, readBytes: (offset, length) => bytes.subarray(offset, offset + length) })
    assertEqual(chunks.map((chunk) => chunk.channel).join(','), 'stdout,stderr', 'channel 切块')
    assertEqual(chunks.map((chunk) => chunk.text).join(''), bytes.toString('utf8'), '拼接字节不变')
  })

  await test('pod output：segments.jsonl 切出 channel，偏移与 out.log 不变', async () => {
    const channelRoot = join(TMP_ROOT, 'channel-data')
    const jobId = 'podc-chan0-abcdef01'
    const dir = join(channelRoot, 'jobs', jobId)
    fs.mkdirSync(dir, { recursive: true })
    const bytes = Buffer.from('OUT-LINE\nERR-LINE\n尾行\n', 'utf8')
    fs.writeFileSync(join(dir, 'out.log'), bytes)
    fs.writeFileSync(
      join(dir, 'segments.jsonl'),
      [
        JSON.stringify({ offset: 0, length: 9, channel: 'stdout' }),
        JSON.stringify({ offset: 9, length: 9, channel: 'stderr' }),
        JSON.stringify({ offset: 18, length: bytes.length - 18, channel: 'stdout' }),
      ].join('\n') + '\n',
    )
    jsonWrite(join(dir, 'meta.json'), { schema: 1, jobId, command: 'channel probe', startedAt: new Date().toISOString() })
    const channelService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: channelRoot,
      pipeName,
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 65536,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    channelService.init()
    const response = await channelService.handle('output', { jobId, from: 0, maxBytes: bytes.length })
    assertEqual(response.text, bytes.toString('utf8'), 'merged text 仍是 out.log 原字节')
    assertEqual(response.spillPath, join(dir, 'out.log'), 'spillPath 指向 out.log')
    assertEqual(response.chunks.map((chunk) => chunk.channel).join(','), 'stdout,stderr,stdout', 'chunk channel 顺序')
    for (const chunk of response.chunks) {
      assertEqual(Buffer.from(chunk.text, 'utf8').equals(bytes.subarray(chunk.offset, chunk.offset + chunk.length)), true, 'chunk 字节与 out.log 切片一致')
    }
    const fromMiddle = await channelService.handle('output', { jobId, from: 9, maxBytes: 9 })
    assertEqual(fromMiddle.chunks.length, 1, '起点落在 stderr 段')
    assertEqual(fromMiddle.chunks[0].channel, 'stderr', '通道正确')
    await channelService.shutdown('selftest done')
  })

  await test('adoption：按 channel append（stdout/stderr 分开），偏移增量不变', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod()
    pod.output = async (_hint, request) => ({
      ok: true,
      status: 'running',
      running: true,
      text: 'OUT\nERR\n',
      chunks: [
        { offset: request.from, length: 4, channel: 'stdout', text: 'OUT\n' },
        { offset: request.from + 4, length: 4, channel: 'stderr', text: 'ERR\n' },
      ],
      from: request.from,
      nextOffset: request.from + 8,
      totalBytes: request.from + 8,
      hasMore: false,
      eof: false,
      exitCode: null,
      signal: null,
    })
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-chan1-11112222', command: 'x' }, null, 'x')
    await manager.pollAllOnce()
    const rows = jobs.started.get(registryId).handle.appended
    assertEqual(rows.length, 2, '两个 channel 应 append 两次')
    assertEqual(rows[0].opts?.channel, 'stdout', '第一段 stdout')
    assertEqual(rows[1].opts?.channel, 'stderr', '第二段 stderr')
    assertEqual(manager.recordFor('podc-chan1-11112222').podCursor, 8, '偏移按字节前进')
    manager.dispose()
  })

  await test('模型面：stderr 分段渲染 + 原生截断标记', async () => {
    const pod = createModelPod('')
    pod.cursor = async () => ({ state: 'missing' })
    pod.output = async () => ({
      ok: true,
      status: 'running',
      running: true,
      text: 'OUT\nERR\n',
      chunks: [
        { offset: 0, length: 4, channel: 'stdout', text: 'OUT\n' },
        { offset: 4, length: 4, channel: 'stderr', text: 'ERR\n' },
      ],
      spillPath: 'C:\\ledger\\jobs\\podc-x\\out.log',
      from: 0,
      nextOffset: 8,
      totalBytes: 8,
      hasMore: false,
      eof: false,
      exitCode: null,
      signal: null,
    })
    pod.ack = async () => ({ ok: true })
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const value = await tool.execute({ jobId: 'podc-chan2-33334444' }, exec)
    assert(value.message.includes('OUT\n[stderr]\nERR\n'), 'stdout 先、stderr 后并带 [stderr] 标记：' + value.message)
    assert(!/offset|nextOffset/.test(value.message), '模型文本不得出现偏移')

    // Forced truncation (no newline in the window) carries the native spill path.
    pod.cursor = async () => ({ state: 'missing' })
    pod.output = async () => ({
      ok: true,
      status: 'running',
      running: true,
      text: 'no-newline-window',
      chunks: [{ offset: 0, length: 17, channel: 'stdout', text: 'no-newline-window' }],
      spillPath: 'C:\\ledger\\jobs\\podc-x\\out.log',
      from: 0,
      nextOffset: 17,
      totalBytes: 40,
      hasMore: true,
      eof: false,
      exitCode: null,
      signal: null,
    })
    const truncated = await tool.execute({ jobId: 'podc-chan2-33334444' }, exec)
    assert(truncated.message.includes('[output truncated]'), '原生截断标记：' + truncated.message)
    assert(!truncated.message.includes('full output:'), '原生截断标记不带 spill 路径')
    assert(/\[status: running/.test(truncated.message), '截断时仍保留状态行：' + truncated.message)
  })

  await test('env 保鲜：只允许 DSH_*，逐次采集、坏值剔除', () => {
    const picked = sanitizeDshEnv({
      DSH_SESSION_ID: 's-1',
      DSH_HOME: 'Z:\\DSH-Data',
      PATH: 'C:\\Windows',
      DSH_BAD_VALUE: 42,
      DSH_NUL: 'a\u0000b',
      DSH_HUGE: 'x'.repeat(9000),
      not_dsh: 'nope',
    })
    assertEqual(picked.env.DSH_SESSION_ID, 's-1', '合法 DSH_* 保留')
    assertEqual(picked.env.DSH_HOME, 'Z:\\DSH-Data', '合法 DSH_* 保留')
    assertEqual(Object.hasOwn(picked.env, 'PATH'), false, '非 DSH_* 必须丢弃')
    assertEqual(Object.hasOwn(picked.env, 'not_dsh'), false, '非 DSH_* 必须丢弃')
    assertEqual(Object.hasOwn(picked.env, 'DSH_BAD_VALUE'), false, '非字符串值丢弃')
    assertEqual(Object.hasOwn(picked.env, 'DSH_NUL'), false, '含 NUL 丢弃')
    assertEqual(Object.hasOwn(picked.env, 'DSH_HUGE'), false, '超长值丢弃')
    assertEqual(collectDshEnv({ DSH_A: '1', DSH_B: undefined, HOME: 'x' }).DSH_A, '1', '每调用采集当前 env')
  })

  await test('adopted 读路径：pollAdopted 逼泵追平，registry 读由原生 modelCursor 消费', async () => {
    const jobs = createFakeJobs()
    const pod = createFakePod([{
      ok: true, status: 'running', running: true, text: 'X\n', from: 0, nextOffset: 2, totalBytes: 2,
      hasMore: false, eof: false, exitCode: null, signal: null,
    }])
    const manager = createAdoptionManager({ getJobs: () => jobs, pod, autoPoll: false, log: () => {} })
    const registryId = manager.adoptNewJob({ jobId: 'podc-sync0-11112222', command: 'echo hi' }, null, 'echo hi')
    assertEqual(await manager.pollAdopted('podc-sync0-11112222'), true, '收养中的 job 应被 poll')
    assertEqual(jobs.started.get(registryId).handle.appended.length, 1, 'pollAdopted 必须先逼泵追平（append 1 段）')
    assertEqual(await manager.pollAdopted('podc-unknown-33334444'), false, '未收养的 job 返回 false')
    assertEqual(jobs.reads.length, 0, 'poll 本身不消费 registry modelCursor（读只由 pod_output/job_output 发生）')
    manager.dispose()
  })

  await test('description：schema 200、随 run 下发、状态行显示、不进 label', async () => {
    const calls = { run: [], status: 0 }
    const fakePod = {
      stateDir: join(TMP_ROOT, 'desc-state'),
      pipeName: 'desc-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async run(_hint, request) {
        calls.run.push(request)
        return {
          prepared: {
            fingerprint: 'f'.repeat(64),
            enforcement: 'partial',
            policyVariant: 'test',
            profile: { workspaceRoot: WORKSPACE, tempDir: WORKSPACE },
          },
          response: {
            ok: true,
            jobId: 'podc-desc0-11112222',
            status: 'running',
            running: true,
            exitCode: null,
            signal: null,
            totalBytes: 0,
            command: request.command,
            description: request.description ?? null,
            cwd: WORKSPACE,
            startedAt: new Date().toISOString(),
          },
        }
      },
      async status() {
        calls.status += 1
        return {
          response: {
            jobs: [{
              jobId: 'podc-desc0-11112222',
              sessionId: 's',
              status: 'running',
              running: true,
              exitCode: null,
              signal: null,
              totalBytes: 0,
              command: 'echo hi',
              description: '列出工作区',
              cwd: WORKSPACE,
              startedAt: new Date().toISOString(),
            }],
            running: 1,
          },
        }
      },
      async output() {
        return { ok: true, status: 'running', running: true, text: '', from: 0, nextOffset: 0, totalBytes: 0, hasMore: false, eof: false, exitCode: null, signal: null }
      },
      async kill() {
        return { ok: true, killed: true, status: 'killed', exitCode: null, signal: 'SIGTERM' }
      },
    }
    const tools = createTools(fakePod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const runTool = tools.find((candidate) => candidate.name === 'pod_run')
    assertEqual(runTool.parameters.properties.description.maxLength, 200, 'description maxLength=200')
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const started = await runTool.execute({ command: 'echo hi', description: '列出工作区' }, exec)
    assertEqual(started.description, '列出工作区', 'run 返回值带 description')
    assertEqual(calls.run.length, 1, 'pod.run 被调用')
    assertEqual(calls.run[0].description, '列出工作区', 'description 随 run 下发')
    assertEqual(collectDshEnv({ DSH_SESSION_ID: 's-1' }).DSH_SESSION_ID, 's-1', '每次 pod_run 都可重新采集 DSH_*')
    const statusTool = tools.find((candidate) => candidate.name === 'pod_status')
    const status = await statusTool.execute({}, exec)
    assert(status.message.includes('desc=列出工作区'), 'status 行应显示 description：' + status.message)
    assert(!status.message.includes('escape-pod-core/podc-desc0'), 'label 不掺 description')
  })

  await test('adopted pod_output：只走 ctx.jobs.read，不再碰 pod 游标；ack=base+total', async () => {
    const calls = { ack: [], cursor: 0, output: 0, reads: [] }
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'adopted-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async ack(_hint, request) {
        calls.ack.push(request)
        return { ok: true }
      },
      async cursor() {
        calls.cursor += 1
        throw new Error('adopted 读不得再查 pod 游标')
      },
      async output() {
        calls.output += 1
        throw new Error('adopted 读不得再读 pod out.log')
      },
    }
    const readResult = {
      chunks: [
        { at: 0, text: 'OUT\n', channel: 'stdout' },
        { at: 4, text: 'ERR\n', channel: 'stderr' },
      ],
      lossy: false,
      job: { status: 'completed', output: { total: 8 } },
    }
    const jobs = {
      read(id) {
        calls.reads.push(id)
        return readResult
      },
    }
    const adoptions = {
      registryInfo: () => ({ adopted: true, id: 'registry-1', baseOffset: 10, sessionId: 's' }),
      pollAdopted: async () => true,
      getJobsService: () => jobs,
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, adoptions, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const value = await tool.execute({ jobId: 'podc-adopt0-11112222' }, exec)
    assertEqual(calls.reads.join(','), 'registry-1', '必须只走 registry read')
    assertEqual(calls.ack.length, 1, '读后必须 ack pod 游标')
    assertEqual(calls.ack[0].offset, 18, 'ack = baseOffset 10 + registry total 8')
    assertEqual(value.message.includes('OUT\n[stderr]\nERR\n'), true, 'channel 渲染：' + value.message)
    assert(value.message.includes('[status: completed]'), '状态行原生：' + value.message)
    assertEqual(calls.cursor, 0, '不得查询 pod 游标')
    assertEqual(calls.output, 0, '不得读取 pod out.log')
  })

  await test('adopted pod_output：registry lossy 时给原生丢弃提示与 out.log 路径', async () => {
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'adopted-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async ack() {
        return { ok: true }
      },
    }
    const adoptions = {
      registryInfo: () => ({ adopted: true, id: 'registry-2', baseOffset: 0, sessionId: 's' }),
      pollAdopted: async () => true,
      getJobsService: () => ({
        read: () => ({
          chunks: [{ at: 12, text: 'tail\\n', channel: 'stdout', gapBefore: true }],
          lossy: true,
          job: { status: 'running', output: { total: 17 } },
        }),
      }),
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, adoptions, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const value = await tool.execute({ jobId: 'podc-adopt1-22223333' }, exec)
    assert(value.message.includes('[some output was dropped from memory; full output: '), '应带原生丢弃提示：' + value.message)
    assert(value.message.includes('out.log'), '提示应带 out.log 路径：' + value.message)
  })

  await test('pod_status：默认只详细列本会话 job；他会话/无主只给计数且不泄露标识', async () => {
    const MINE = 'podc-mine0-11112222'
    const FOREIGN = 'podc-foreign0-aaaabbbb'
    const LEGACY = 'podc-legacy0-ccccdddd'
    const OLD_POD = 'podc-oldpod0-eeeeffff'
    /** @param {string} jobId @param {string | null} sessionId @param {string} desc */
    const row = (jobId, sessionId, desc) => ({
      jobId,
      sessionId,
      status: 'running',
      running: true,
      exitCode: null,
      signal: null,
      totalBytes: 12,
      cursor: { state: 'missing', offset: null, hash: null, valid: false, lossy: false, reason: null },
      spillPaths: [join(TMP_ROOT, 'spill', jobId, 'out.log')],
      channels: ['stdout'],
      command: desc + ' command',
      description: desc,
      cwd: WORKSPACE,
      runnerPid: 4242,
      startedAt: new Date().toISOString(),
    })
    // A pod that predates the boundary omits `sessionId` entirely; without a
    // local owner the Host must treat it as unowned (not as this session's).
    const oldPodRow = row(OLD_POD, null, 'oldpod')
    delete oldPodRow.sessionId
    const fakePod = {
      stateDir: TMP_ROOT,
      pipeName: 'status-session-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async status() {
        return {
          response: {
            podPid: 99,
            podStartedAt: '2026-01-01T00:00:00.000Z',
            generation: 3,
            podVersion: '1.7.0',
            protocolVersion: 2,
            pipeName: 'status-session-pipe',
            workspaceRoot: WORKSPACE,
            dataRoot: TMP_ROOT,
            identity: null,
            auth: null,
            attestation: { mode: 'warn', available: true, unavailableReason: null, channel: null, deferred: 2, denied: 0 },
            enforcement: 'partial',
            template: { valid: true, runnerPath: FAKE_RUNNER, program: process.execPath, mode: 'workspace-write', workspaceRoot: WORKSPACE, pin: 'a'.repeat(64), lastEnforcement: 'partial' },
            running: 4,
            jobs: [row(MINE, 'me', 'mine'), row(FOREIGN, 'other', 'foreign'), row(LEGACY, null, 'legacy'), oldPodRow],
          },
        }
      },
    }
    const ensured = []
    const fakeAdoptions = {
      async ensureAdopted(_hint, options) {
        ensured.push(options.jobs.map((job) => job.jobId))
        return {
          adopted: 1,
          skipped: 0,
          running: 4,
          jobs: [
            { podJobId: MINE, registryId: 'registry-1', cursorMode: 'fresh', warning: null },
            { podJobId: FOREIGN, registryId: 'registry-2', cursorMode: 'fresh', warning: 'foreign cursor warning' },
            { podJobId: OLD_POD, registryId: 'registry-3', cursorMode: 'fresh', warning: 'old pod cursor warning' },
          ],
        }
      },
      registryInfo: (jobId) => ({ adopted: jobId === MINE, id: 'registry-1', status: 'running', cursor: 'fresh' }),
    }
    const tools = createTools(fakePod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, fakeAdoptions, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_status')
    const value = await tool.execute({}, { agent: { id: 'me', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(value.sessionId, 'me', 'status 回显调用方会话')
    assertEqual(value.jobs.length, 1, '只详细列本会话的 job')
    assertEqual(value.jobs[0].jobId, MINE, '列出的必须是本会话 job')
    assertEqual(value.foreignJobs, 3, 'foreignJobs = 其它会话 + 无主（含旧 pod 缺字段）')
    assertEqual(value.unownedJobs, 2, 'unownedJobs 单独计数（显式 null + 旧 pod 缺字段）')
    assert(value.message.includes('foreignJobs=3'), '文本里给计数：' + value.message)
    assert(value.message.includes('其中无主历史 job 2'), '文本里区分无主历史 job')
    assert(value.message.includes('deferred=2 denied=0'), '管道连接计数必须如实拆开（两次正常 Host 连接不是 denied）：' + value.message)
    assertEqual(ensured[0]?.length, 4, '收养仍使用 pod 全量快照（原生 job_list 行为不变）')
    assertEqual(value.adoptionSync.jobs.length, 1, '收养告警只保留可见 job')
    assertEqual(value.adoptionSync.jobs[0].podJobId, MINE, '可见 job 的收养告警保留')
    const text = JSON.stringify(value)
    for (const secret of [FOREIGN, LEGACY, OLD_POD, 'foreign command', 'legacy command', 'oldpod command', 'foreign cursor warning', 'old pod cursor warning', join(TMP_ROOT, 'spill', FOREIGN, 'out.log'), join(TMP_ROOT, 'spill', LEGACY, 'out.log'), join(TMP_ROOT, 'spill', OLD_POD, 'out.log')]) {
      assertEqual(text.includes(secret), false, 'status 不得泄露他会话标识：' + secret)
    }
  })

  await test('pod_status.limits：当前生效值、来源、pod 兜底/硬上限都如实给出', async () => {
    /** @returns {any} */
    const fakePod = () => ({
      stateDir: TMP_ROOT,
      pipeName: 'limits-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async status() {
        return {
          response: {
            podPid: 77,
            podStartedAt: '2026-10-29T00:00:00.000Z',
            generation: 1,
            podVersion: '1.7.0',
            protocolVersion: 2,
            pipeName: 'limits-pipe',
            enforcement: 'partial',
            template: { valid: false, code: 'ETEMPLATE', reason: 'selftest' },
            workspaceRoot: WORKSPACE,
            dataRoot: TMP_ROOT,
            identity: null,
            auth: null,
            attestation: null,
            running: 0,
            jobs: [],
            // Pod-side fallback window and hard clamp, as a current pod reports them.
            outputChunkBytes: 64000,
            maxOutputChunkBytes: MAX_OUTPUT_CHUNK_BYTES,
          },
          bootstrapError: null,
        }
      },
    })
    const ctx = { get: (name) => (name === 'shell' ? { resolve: () => ({ timeoutMs: 300000, stdoutMaxBytes: 120000 }) } : undefined) }
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const tools = createTools(fakePod(), () => null, { outputChunkBytes: 64000, modelOutputLimitBytes: 0 }, null, () => {}, ctx)
    const value = await tools.find((candidate) => candidate.name === 'pod_status').execute({}, exec)
    assertEqual(value.limits.maxOutputBytes, 120000, '当前生效的输出窗口')
    assertEqual(value.limits.timeoutMs, 300000, '当前生效的命令超时')
    assertEqual(value.limits.source, 'shell.resolve', 'source 必须如实标出读取途径')
    assertEqual(value.limits.executor, null, '对象字面量的执行器名不编造')
    assertEqual(value.limits.modelCeiling, null, '没有部署上限时是 null（无损 JSON）')
    assertEqual(value.limits.native.maxOutputBytes, 120000, 'native 值')
    assertEqual(value.limits.appliesTo.timeout, 'pod_exec', '超时只作用于前台')
    assertEqual(value.limits.appliesTo.backgroundTimeout, 'unlimited', '后台必须写明不限时')
    assertEqual(value.limits.pod.defaultOutputChunkBytes, 64000, 'pod 兜底窗口')
    assertEqual(value.limits.pod.maxOutputChunkBytes, MAX_OUTPUT_CHUNK_BYTES, 'pod 硬上限')
    assert(value.message.includes('执行预算='), '给人看的文本也要有：' + value.message.slice(-200))
    assert(value.message.includes('pod_run（后台）不限时'), '文本必须写清后台不限时')
    const text = JSON.stringify(value)
    assertEqual(JSON.stringify(JSON.parse(text)), text, 'limits 必须是无损 JSON（没有 undefined）')

    // Nothing answers -> the same tool must say "fallback", never pretend native.
    const bareValue = await createTools(fakePod(), () => null, { outputChunkBytes: 64000, modelOutputLimitBytes: 0 }, null, () => {}, null)
      .find((candidate) => candidate.name === 'pod_status')
      .execute({}, exec)
    assertEqual(bareValue.limits.source, 'fallback:native-defaults', '读不到原生值就如实标兜底')
    assertEqual(bareValue.limits.maxOutputBytes, 64000, '兜底窗口 = 原生默认')
    assertEqual(bareValue.limits.timeoutMs, 120000, '兜底超时 = 原生默认')
    assert(bareValue.limits.reasons.length >= 2, '兜底必须留下面每个探测失败的原因')
    assert(bareValue.message.includes('兜底'), '文本要标兜底：' + bareValue.message.slice(-240))
  })

  await test('pod_output：adopt 原样透传到 pod，返回 adoptedFrom；默认调用不接管', async () => {
    const calls = []
    const JOB = 'podc-adopt0-99998888'
    const fakePod = {
      stateDir: TMP_ROOT,
      pipeName: 'adopt-output-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async cursor(_hint, request) {
        calls.push({ op: 'cursor', request })
        return { state: 'missing' }
      },
      async output(_hint, request) {
        calls.push({ op: 'output', request })
        return {
          ok: true, jobId: JOB, sessionId: 'owner-x',
          ...(request.adopt === true ? { adoptedFrom: 'owner-x' } : {}),
          text: 'hello\n', chunks: [], from: 0, nextOffset: 6, totalBytes: 6, hasMore: false, eof: true,
          running: false, status: 'settled', exitCode: 0, signal: null, spillPath: 'x', lossy: false,
          prefixHash: 'a'.repeat(64), stalled: false,
        }
      },
      async ack(_hint, request) {
        calls.push({ op: 'ack', request })
        return { ok: true }
      },
    }
    const tools = createTools(fakePod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    const exec = { agent: { id: 'me', session: { meta: { cwd: WORKSPACE } } } }
    const plain = await tool.execute({ jobId: JOB }, exec)
    assertEqual(calls.find((entry) => entry.op === 'output').request.adopt, false, '默认必须显式发 adopt:false')
    assertEqual(Object.prototype.hasOwnProperty.call(plain, 'adoptedFrom'), false, '没接管就不标注 adoptedFrom')

    calls.length = 0
    const adopted = await tool.execute({ jobId: JOB, adopt: true }, exec)
    for (const op of ['cursor', 'output', 'ack']) {
      assertEqual(calls.find((entry) => entry.op === op)?.request.adopt, true, op + ' 必须带 adopt:true')
    }
    assertEqual(adopted.adoptedFrom, 'owner-x', 'adopt 结果标注原会话')
    assert(adopted.message.includes('原会话：owner-x'), '模型文本要说明接管来源：' + adopted.message)
  })

  await test('adopted pod_output：跨会话默认 EFOREIGNJOB；adopt:true 才读 registry 并标注 adoptedFrom', async () => {
    const reads = []
    const acks = []
    const adoptions = {
      registryInfo: () => ({ adopted: true, id: 'registry-9', baseOffset: 0, sessionId: 'owner-x' }),
      pollAdopted: async () => true,
      getJobsService: () => ({
        read(id) {
          reads.push(id)
          return { chunks: [{ at: 0, text: 'X\n', channel: 'stdout' }], lossy: false, job: { status: 'completed', output: { total: 2 } } }
        },
      }),
    }
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'adopted-boundary-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async ack(_hint, request) {
        acks.push(request)
        return { ok: true }
      },
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, adoptions, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_output')
    const exec = { agent: { id: 'me', session: { meta: { cwd: WORKSPACE } } } }
    let error = null
    try {
      await tool.execute({ jobId: 'podc-adoptown-12345678' }, exec)
    } catch (caught) {
      error = caught
    }
    assert(error !== null, '跨会话 adopted 读必须报错')
    assertEqual(error.code, 'EFOREIGNJOB', '错误码 EFOREIGNJOB：' + String(error.message))
    assertEqual(reads.length, 0, '拒绝时不得调用 ctx.jobs.read')
    const value = await tool.execute({ jobId: 'podc-adoptown-12345678', adopt: true }, exec)
    assertEqual(reads.join(','), 'registry-9', 'adopt 后才读 registry')
    assertEqual(value.adoptedFrom, 'owner-x', '标注 adoptedFrom')
    assertEqual(acks[0]?.adopt, true, '接管读的 pod 游标 ack 也要带 adopt')
  })

  await test('pod_kill：adopt 透传，返回 adoptedFrom，schema 只有 jobId/adopt', async () => {
    const requests = []
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'kill-adopt-pipe',
      async kill(_hint, request) {
        requests.push(request)
        return { ok: true, jobId: request.jobId, killed: true, status: 'killed', exitCode: null, signal: 'SIGTERM', sessionId: 'owner-x', adoptedFrom: 'owner-x' }
      },
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_kill')
    assertEqual(Object.keys(tool.parameters.properties).join(','), 'jobId,adopt', 'kill schema 只有 jobId/adopt')
    const value = await tool.execute({ jobId: 'podc-killown-12345678', adopt: true }, { agent: { id: 'me', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(requests[0].adopt, true, 'adopt 必须透传')
    assertEqual(value.adoptedFrom, 'owner-x', 'kill 结果标注 adoptedFrom')
    assert(value.message.includes('adopt: true'), '模型文本要说明接管：' + value.message)
  })

  // -------------------------------------------------------------------------
  // pod_exec：前台形态 + resumableToolCalls
  // -------------------------------------------------------------------------
  const EXEC_JOB = 'podc-exec0-abcdef01'

  /** A pod client whose `output` answers "running" N times, then settles. */
  function createExecPod({ runningPolls = 1, exitCode = 3, status = 'settled', text = 'OUT\nERR\n' } = {}) {
    const calls = { run: [], output: [] }
    let polls = 0
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'exec-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async run(_hint, request) {
        calls.run.push(request)
        return {
          response: {
            ok: true,
            op: 'run',
            jobId: EXEC_JOB,
            runnerPid: 4321,
            podPid: 9876,
            cwd: request.cwd ?? WORKSPACE,
            command: request.command,
            description: request.description ?? null,
            startedAt: '2026-10-29T00:00:00.000Z',
          },
          prepared: {
            enforcement: 'partial',
            fingerprint: 'f'.repeat(64),
            policyVariant: 'agentless',
            profile: { workspaceRoot: WORKSPACE, tempDir: TMP_ROOT, mode: 'workspace-write' },
          },
        }
      },
      async output(_hint, request) {
        calls.output.push(request)
        polls += 1
        const stillRunning = polls <= runningPolls
        return {
          ok: true,
          op: 'output',
          jobId: EXEC_JOB,
          status: stillRunning ? 'running' : status,
          running: stillRunning,
          exitCode: stillRunning ? null : exitCode,
          signal: null,
          text: stillRunning ? '' : text,
          chunks: stillRunning
            ? []
            : [
                { offset: 0, length: 4, channel: 'stdout', text: 'OUT\n' },
                { offset: 4, length: 4, channel: 'stderr', text: 'ERR\n' },
              ],
          spillPath: join(TMP_ROOT, 'jobs', EXEC_JOB, 'out.log'),
          from: 0,
          nextOffset: stillRunning ? 0 : Buffer.byteLength(text),
          totalBytes: Buffer.byteLength(text),
          hasMore: false,
          eof: true,
          stalled: false,
          lossy: false,
          prefixHash: 'a'.repeat(64),
          cwd: WORKSPACE,
        }
      },
      async ack() {
        return { ok: true }
      },
    }
    return { pod, calls }
  }

  /** A fake `resumableToolCalls` service that records the order of calls. */
  function createFakeResume(events, prefix = '') {
    const service = {
      descriptor: null,
      payload: null,
      reason: null,
      holdCalls: 0,
      statusRows: null,
      status() {
        return { service: 'resumableToolCalls', bootId: 'boot', holds: service.statusRows ?? [] }
      },
      hold(callId, descriptor) {
        service.holdCalls += 1
        events.push(prefix + 'hold:' + callId)
        service.descriptor = descriptor
        return () => events.push(prefix + 'release:' + callId)
      },
      async complete(callId, payload) {
        events.push(prefix + 'complete:' + callId)
        service.payload = payload
        return { applied: false, reason: 'already-in-log', status: 'observed' }
      },
      async fail(callId, reason) {
        events.push(prefix + 'fail:' + callId)
        service.reason = reason
        return { applied: false, reason: 'already-in-log', status: 'observed' }
      },
    }
    return service
  }

  /** A Host context that exposes one service and a manual `session/event` feed. */
  function createFakeHostCtx(service) {
    const listeners = []
    return {
      get(name) {
        return name === 'resumableToolCalls' ? service : undefined
      },
      on(name, handler) {
        if (name !== 'session/event') return () => {}
        listeners.push(handler)
        return () => {
          const at = listeners.indexOf(handler)
          if (at >= 0) listeners.splice(at, 1)
        }
      },
      /** Emit a committed `tool/result` for one call, exactly like the platform. */
      emitResult(callId) {
        for (const handler of [...listeners]) {
          handler(null, { type: 'tool/result', seq: 7, data: { message: { role: 'tool', toolCallId: callId, source: { kind: 'tool', callId } } } })
        }
      },
      listenerCount: () => listeners.length,
    }
  }

  const flushTicks = async (count = 8) => {
    for (let index = 0; index < count; index += 1) await Promise.resolve()
  }

  await test('pod_exec：阻塞到结算、一次调用一条结果，[exit code: 3] + [status: completed]，无 jobId/偏移', async () => {
    const { pod, calls } = createExecPod()
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, null)
    const tool = tools.find((candidate) => candidate.name === 'pod_exec')
    assert(tool !== undefined, 'pod_exec 应注册')
    assertEqual(Object.keys(tool.parameters.properties).join(','), 'command,shell,description,cwd,sandbox_permissions,justification', '参数字段')
    assertEqual(tool.parameters.required.join(','), 'command', '只有 command 必填')
    assert(/退化/.test(tool.description) && /重启/.test(tool.description), '描述里必须写清服务缺失时的退化与重启语义')
    assert(/TOOL_OUTCOME_UNKNOWN/.test(tool.description), '描述里应点名平台合成结果，说明挂起是干什么的')

    const exec = { callId: 'call-exec-1', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const value = await tool.execute({ command: 'exit 3' }, exec)

    // Same spawn path as pod_run: one `run` through the pod client.
    assertEqual(calls.run.length, 1, 'pod_exec 必须复用 pod.run（每条命令一次 run）')
    assertEqual(calls.run[0].command, 'exit 3', '命令原文下发')
    // Poll window vs model window: the poll only needs the status line.
    assertEqual(calls.output[0].maxBytes, 512, '轮询用小窗口（只取状态）')
    assertEqual(calls.output[calls.output.length - 1].maxBytes, 1024, '最后一次读用 modelOutputLimitBytes')
    assertEqual(calls.output[calls.output.length - 1].from, 0, '前台读必须从 0 开始（一次给全量）')

    assert(value.message.includes('OUT\n[stderr]\nERR\n'), 'stdout 在前、[stderr] 段在后：' + value.message)
    assert(value.message.includes('[exit code: 3]'), '非零退出码只走文本：' + value.message)
    assert(value.message.includes('[status: completed]'), '状态行必须映射成原生词汇：' + value.message)
    assert(!value.message.includes(EXEC_JOB), '模型文本不得出现 jobId：' + value.message)
    assert(!/offset|nextOffset|cursor|字节/i.test(value.message), '模型文本不得出现偏移/游标：' + value.message)
    assertEqual(Object.prototype.hasOwnProperty.call(value, 'jobId'), false, '返回结构里不得有 jobId')
    assert(!JSON.stringify(value).includes(EXEC_JOB), '整个返回值里不得出现 jobId')
    assertEqual(value.exitCode, 3, 'exitCode 原样给出')
    assertEqual(value.status, 'completed', 'value.status 使用原生词汇')
    assertEqual(value.resume.available, false, '没有服务时 resume.available=false')
    assert(typeof value.resume.reason === 'string' && value.resume.reason.length > 0, '降级原因必须如实给出')
    assertEqual(value.description, null, '未给 description 时是 null（无损 JSON）')
  })

  await test('pod_exec：hold 必须早于等待，complete 必须晚于平台自己的 tool/result', async () => {
    const events = []
    const service = createFakeResume(events)
    const ctx = createFakeHostCtx(service)
    const { pod } = createExecPod()
    const recordOutput = pod.output
    pod.output = async (hint, request) => {
      events.push('poll')
      return await recordOutput(hint, request)
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, ctx)
    const tool = tools.find((candidate) => candidate.name === 'pod_exec')
    const exec = { callId: 'call-exec-order', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }

    const value = await tool.execute({ command: 'exit 3' }, exec)

    assertEqual(events[0], 'hold:call-exec-order', 'hold 必须是第一个动作（早于任何等待）')
    assertEqual(events[1], 'poll', 'hold 之后才开始等待')
    assertEqual(events.includes('complete:call-exec-order'), false, '平台还没写结果前不得 complete（否则会写第二条 tool/result）')
    assertEqual(value.resume.available, true, '有服务时 resume.available=true')
    assertEqual(value.resume.held, true, '有服务时必须真的挂上')
    assertEqual(value.resume.reason, null, '成功挂起时 reason=null')
    assertEqual(service.descriptor.tool, 'pod_exec', 'hold 声明的工具名')
    assertEqual(service.descriptor.hint.jobId, EXEC_JOB, 'hint 只带 jobId（恢复只需要它）')
    assertEqual(service.descriptor.deadlineMs > 0, true, 'deadlineMs 必须给出')

    ctx.emitResult('call-exec-order')
    await flushTicks()
    assertEqual(events.includes('complete:call-exec-order'), true, '平台写下结果后才 complete')
    assert(service.payload !== null && typeof service.payload === 'object', 'complete 必须带原生形状的结果')
    assertEqual(Array.isArray(service.payload.content), true, 'complete 的 content 是内容块数组')
    assertEqual(service.payload.content[0].type, 'text', 'content[0] 是 text')
    assertEqual(service.payload.isError, false, '成功结果 isError=false')
    assert(service.payload.content[0].text.includes('[status: completed]'), '补写的结果与返回给平台的一致')
    assertEqual(ctx.listenerCount(), 0, '结算后必须解掉 session/event 监听')
  })

  await test('pod_exec：pod 侧查不到（ENOJOB）→ 抛错并 fail(reason)，fail 也在平台结果之后', async () => {
    const events = []
    const service = createFakeResume(events)
    const ctx = createFakeHostCtx(service)
    const { pod } = createExecPod()
    pod.output = async () => {
      const error = new Error('账本里没有这个 job：' + EXEC_JOB)
      error.code = 'ENOJOB'
      throw error
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, ctx)
    const tool = tools.find((candidate) => candidate.name === 'pod_exec')
    const exec = { callId: 'call-exec-lost', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }

    let caught = null
    try {
      await tool.execute({ command: 'exit 0' }, exec)
    } catch (error) {
      caught = error
    }
    assert(caught !== null, '查不到结果时必须抛错，不能假装完成')
    assert(caught.message.includes('ENOJOB') || caught.message.includes('没有这个 job'), '错误文本应保留 pod 侧原因：' + caught.message)
    assert(caught.message.includes('pod_exec'), '错误文本应带上下文：' + caught.message)
    assertEqual(events[0], 'hold:call-exec-lost', 'hold 仍然发生在最前面')
    assertEqual(events.includes('fail:call-exec-lost'), false, '平台结果还没写，不得抢先 fail')

    ctx.emitResult('call-exec-lost')
    await flushTicks()
    assertEqual(events.includes('fail:call-exec-lost'), true, '平台写下错误结果后，才把挂起标成失败')
    assert(typeof service.reason === 'string' && service.reason.includes('没有拿到可用的结果'), 'fail 原因要如实：' + String(service.reason))
  })

  await test('resume：服务缺失 / 形状不全 / ctx.get 抛错都退化为普通阻塞调用', async () => {
    const missing = resolveResumeService({ get: () => undefined })
    assertEqual(missing.service, null, 'undefined 视为不可用')
    assert(missing.reason.includes('没有提供'), '原因说明是谁没提供：' + missing.reason)
    const broken = resolveResumeService({ get: () => ({ hold() {} }) })
    assertEqual(broken.service, null, '缺 complete/fail 的服务不可用')
    assert(broken.reason.includes('complete'), '原因应点名缺什么：' + broken.reason)
    const throwing = resolveResumeService({ get: () => { throw new Error('boom') } })
    assertEqual(throwing.service, null, 'ctx.get 抛错不得冒泡')
    assert(throwing.reason.includes('boom'), '原因应带异常文本：' + throwing.reason)
    assertEqual(resolveResumeService(null).service, null, '没有 ctx 也不可用')

    // A hold that throws must degrade, never fail the tool call.
    const handle = createExecHold({ get: () => ({ hold() { throw new Error('registry full') }, async complete() {}, async fail() {} }) }, {
      callId: 'call-x', jobId: EXEC_JOB, log: () => {},
    })
    assertEqual(handle.available, true, '服务本身可用')
    assertEqual(handle.held, false, 'hold 抛错时 held=false')
    assert(handle.reason.includes('registry full'), 'hold 失败原因必须如实：' + handle.reason)
    assertEqual(typeof handle.release, 'function', 'handle 永远可用（no-op）')
    assertEqual(handle.refresh(), false, '没挂上时刷新是 no-op')
  })

  await test('resume：观察不到平台结果时停等但不补写，挂起与恢复条目都保留', async () => {
    const events = []
    const service = createFakeResume(events, 'svc-')
    // No `on` at all: the bridge must not guess, and it must not discard the
    // proof that this call still owes a result.
    const store = createPendingStore({ file: join(TMP_ROOT, 'recovery', 'nocommit', PENDING_FILE_NAME) })
    const handle = createExecHold({ get: () => service, on: undefined }, {
      callId: 'call-nocommit', jobId: EXEC_JOB, log: () => {}, store,
    })
    assertEqual(handle.held, true, 'hold 仍然登记')
    assertEqual(store.has('call-nocommit'), true, '挂起成功即写恢复条目')
    handle.completeAfterCommit({ content: [] })
    await flushTicks()
    assertEqual(events.includes('svc-complete:call-nocommit'), false, '缺 ctx.on 时不得 complete')
    assertEqual(events.includes('svc-release:call-nocommit'), false, '不得释放服务侧挂起（那是新 Host 补结果的凭据）')
    assertEqual(store.has('call-nocommit'), true, '缺 ctx.on 时条目必须保留（交给下一个 Host）')

    // A listener that never fires: the bounded window also *stops waiting*
    // without writing anything anywhere.
    const silentCtx = { get: () => service, on: () => () => {} }
    const quiet = []
    afterToolResultCommit(silentCtx, 'call-timeout', {
      committed: () => quiet.push('committed'),
      timedOut: () => quiet.push('timedOut'),
    }, { timeoutMs: 5 })
    await new Promise((resolveWait) => setTimeout(resolveWait, 25))
    assertEqual(quiet.join(','), 'timedOut', '窗口内没等到结果事件就走 timedOut')

    // A matching event settles exactly once, even if emitted twice.
    const once = []
    const onceCtx = createFakeHostCtx(service)
    let commits = 0
    afterToolResultCommit(onceCtx, 'call-once', {
      committed: () => { commits += 1; once.push('committed') },
      timedOut: () => once.push('timedOut'),
    }, { timeoutMs: 1000 })
    onceCtx.emitResult('call-once')
    onceCtx.emitResult('call-once')
    await flushTicks()
    assertEqual(commits, 1, '同一条调用只结算一次')
    assertEqual(once.join(','), 'committed', '不得再走 timedOut')
    assertEqual(onceCtx.listenerCount(), 0, '结算后解掉监听')
  })

  await test('恢复清单：release / 关机 / 服务抛错都不得删条目，只有确认结算才删', async () => {
    // 回归（实测踩过）：旧 Host 关机时 release 把 pending-exec.json 清空，
    // 新 Host 启动清单为空 → 恢复扫描无事可做，job 还在跑却没人接。
    const store = createPendingStore({ file: join(TMP_ROOT, 'recovery', 'release-keeps', PENDING_FILE_NAME) })
    const readDisk = () => JSON.parse(fs.readFileSync(store.path, 'utf8')).entries.map((entry) => entry.callId)

    // 1) 普通停等：释放服务侧挂起与删条目都不许发生。
    const events = []
    const service = createFakeResume(events)
    const plain = createExecHold({ get: () => service, on: () => () => {} }, {
      callId: 'call-release-plain', jobId: EXEC_JOB, log: () => {}, store, isDisposing: () => false,
    })
    plain.release()
    plain.release()
    assertEqual(store.has('call-release-plain'), true, 'release 之后条目必须还在')
    assertEqual(readDisk().includes('call-release-plain'), true, '磁盘上也还在（新 Host 读的是磁盘）')
    assertEqual(events.includes('release:call-release-plain'), false, '不得释放服务侧挂起')

    // 2) Host 正在关闭：同样保留（这是恢复半程唯一的凭据）。
    const disposingEvents = []
    const disposingService = createFakeResume(disposingEvents)
    const shuttingDown = createExecHold({ get: () => disposingService, on: undefined }, {
      callId: 'call-release-disposing', jobId: EXEC_JOB, log: () => {}, store, isDisposing: () => true,
    })
    shuttingDown.completeAfterCommit({ content: [] })
    await flushTicks()
    assertEqual(disposingEvents.includes('complete:call-release-disposing'), false, '关机时不得补写结果')
    assertEqual(disposingEvents.includes('release:call-release-disposing'), false, '关机时挂起保留（新 Host 还要靠它）')
    assertEqual(disposingService.holdCalls, 2, '关机时刷新一次挂起，给新 Host 一个完整恢复窗口')
    assertEqual(disposingService.descriptor.hint.jobId, EXEC_JOB, '关机刷新仍只带 jobId')
    assertEqual(store.has('call-release-disposing'), true, '关机时条目必须保留')

    // 3) 服务确认结算（applied）→ 删。
    const appliedEvents = []
    const appliedService = createFakeResume(appliedEvents)
    appliedService.complete = async (callId) => {
      appliedEvents.push('complete:' + callId)
      return { applied: true, status: 'completed' }
    }
    const appliedCtx = createFakeHostCtx(appliedService)
    const applied = createExecHold(appliedCtx, { callId: 'call-settled-applied', jobId: EXEC_JOB, log: () => {}, store })
    applied.completeAfterCommit({ content: [] })
    appliedCtx.emitResult('call-settled-applied')
    await flushTicks()
    assertEqual(appliedEvents.includes('complete:call-settled-applied'), true, '服务确认后 complete 一次')
    assertEqual(store.has('call-settled-applied'), false, '确认结算后删条目')

    // 4) 服务抛错（实测关机时的形态）→ 保留。
    const throwEvents = []
    const throwService = createFakeResume(throwEvents)
    throwService.complete = async () => { throw new Error('the sessionPersistence service is unavailable') }
    const throwCtx = createFakeHostCtx(throwService)
    const throwing = createExecHold(throwCtx, { callId: 'call-settled-throw', jobId: EXEC_JOB, log: () => {}, store })
    throwing.completeAfterCommit({ content: [] })
    throwCtx.emitResult('call-settled-throw')
    await flushTicks()
    assertEqual(store.has('call-settled-throw'), true, '服务没确认就必须留条目（交给下一个 Host 重试）')

    // 5) 服务说日志里已有结果（already-in-log）→ 删。
    const dupEvents = []
    const dupService = createFakeResume(dupEvents)
    dupService.complete = async () => ({ applied: false, reason: 'already-in-log', status: 'observed' })
    const dupCtx = createFakeHostCtx(dupService)
    const duplicate = createExecHold(dupCtx, { callId: 'call-settled-dup', jobId: EXEC_JOB, log: () => {}, store })
    duplicate.completeAfterCommit({ content: [] })
    dupCtx.emitResult('call-settled-dup')
    await flushTicks()
    assertEqual(store.has('call-settled-dup'), false, '日志里已有结果时删条目（不会被下个 boot 重放）')

    // 6) 服务不再持有它（unknown-call）→ 删。
    const unknownEvents = []
    const unknownService = createFakeResume(unknownEvents)
    unknownService.complete = async () => ({ applied: false, reason: 'unknown-call' })
    const unknownCtx = createFakeHostCtx(unknownService)
    const unknown = createExecHold(unknownCtx, { callId: 'call-settled-unknown', jobId: EXEC_JOB, log: () => {}, store })
    unknown.completeAfterCommit({ content: [] })
    unknownCtx.emitResult('call-settled-unknown')
    await flushTicks()
    assertEqual(store.has('call-settled-unknown'), false, '服务不再持有它时删条目')

    // 最终磁盘上只剩"没被确认结算"的那两条。
    const remaining = readDisk().sort()
    assertEqual(remaining.join(','), 'call-release-disposing,call-release-plain,call-settled-throw'.split(',').sort().join(','), '磁盘上只保留未结算的条目：' + remaining.join(','))
  })

  await test('resume：等待期间刷新挂起，已经结算的挂起不复活', async () => {
    const events = []
    const service = createFakeResume(events)
    service.statusRows = [{ callId: 'call-refresh', status: 'held' }]
    const handle = createExecHold({ get: () => service, on: () => () => {} }, {
      callId: 'call-refresh', jobId: EXEC_JOB, log: () => {},
    })
    assertEqual(handle.held, true, '先挂上')
    assertEqual(service.holdCalls, 1, 'hold 只调用一次')
    assertEqual(handle.refresh(), true, '仍 held 时可以刷新')
    assertEqual(service.holdCalls, 2, '刷新会重新 hold（服务据此推进 deadlineAt 并重新落盘）')
    service.statusRows = [{ callId: 'call-refresh', status: 'observed' }]
    assertEqual(handle.refresh(), false, '已经结算的挂起不得被复活')
    assertEqual(service.holdCalls, 2, '不得再调用 hold')
    assertEqual(handle.held, false, 'handle 记为不再持有')
    assertEqual(handle.refresh(), false, '之后不会再刷新')
    assertEqual(service.holdCalls, 2, 'hold 调用次数不变')
  })

  await test('pod_exec：调用被取消时不中止命令，如实返回 running 而不是假装完成', async () => {
    const { pod } = createExecPod({ runningPolls: 99 })
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, null)
    const tool = tools.find((candidate) => candidate.name === 'pod_exec')
    const controller = new AbortController()
    const exec = { callId: 'call-exec-abort', signal: controller.signal, agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const pending = tool.execute({ command: 'Start-Sleep 600' }, exec)
    controller.abort()
    const value = await pending
    assertEqual(value.status, 'running', '取消后必须如实报 running')
    assert(value.message.includes('[status: running]'), '状态行如实：' + value.message)
    assert(value.message.includes('等待被取消'), '要说明等待被取消而命令没被中止：' + value.message)
    assert(!value.message.includes(EXEC_JOB), '取消路径也不得出现 jobId：' + value.message)
  })

  await test('pod_exec：请求带实时 timeoutMs 与实时输出窗口；pod_run 绝不带超时', async () => {
    const { pod, calls } = createExecPod()
    const ctx = { get: (name) => (name === 'shell' ? { resolve: () => ({ timeoutMs: 5000, stdoutMaxBytes: 12345 }) } : undefined) }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 0 }, null, () => {}, ctx)
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const value = await tools.find((candidate) => candidate.name === 'pod_exec').execute({ command: 'exit 3' }, exec)
    assertEqual(calls.run[0].timeoutMs, 5000, 'pod_exec 必须把实时 timeoutMs 随 run 下发')
    assertEqual(calls.output[0].maxBytes, 512, '轮询窗口仍是 512（只取状态）')
    assertEqual(calls.output[calls.output.length - 1].maxBytes, 12345, '最后一次读用实时 maxOutputBytes')
    assertEqual(value.limits.source, 'shell.resolve', '返回值里带本次预算来源')
    assertEqual(value.limits.timeoutMs, 5000, 'value.limits.timeoutMs')
    assertEqual(value.limits.maxOutputBytes, 12345, 'value.limits.maxOutputBytes')
    const before = calls.run.length
    await tools.find((candidate) => candidate.name === 'pod_run').execute({ command: 'exit 0' }, exec)
    assertEqual(calls.run.length, before + 1, 'pod_run 走同一条 run 路径')
    assertEqual(Object.prototype.hasOwnProperty.call(calls.run[before], 'timeoutMs'), false, 'pod_run 请求里绝不能出现 timeoutMs（后台不限时）')
  })

  await test('pod_exec：超时（pod 报告 timedOut）→ 部分输出保留、明确标注、状态 killed 不冒充完成', async () => {
    const { pod } = createExecPod({ runningPolls: 0, exitCode: null, status: 'killed', text: 'PARTIAL\n' })
    const original = pod.output
    pod.output = async (hint, request) => {
      const response = await original(hint, request)
      return { ...response, timedOut: true, timeoutMs: 5000 }
    }
    const ctx = { get: (name) => (name === 'shell' ? { resolve: () => ({ timeoutMs: 5000, stdoutMaxBytes: 20000 }) } : undefined) }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 0 }, null, () => {}, ctx)
    const value = await tools.find((candidate) => candidate.name === 'pod_exec').execute({ command: 'Start-Sleep 600' }, { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(value.timedOut, true, '返回值必须标 timedOut')
    assertEqual(value.timeoutMs, 5000, 'timeoutMs 如实')
    assertEqual(value.status, 'killed', 'status 用原生词汇 killed')
    assert(value.text.includes('PARTIAL'), '部分输出不能丢：' + value.text)
    assert(value.message.startsWith('命令超时：'), '首行必须是超时标注：' + value.message.slice(0, 80))
    assert(value.message.includes('[status: killed, timed out after 5000 ms]'), '状态行带超时细节：' + value.message)
    assert(!value.message.includes('[status: completed]'), '绝不能冒充完成')
    assert(!value.message.includes(EXEC_JOB), '超时文本也不得出现 jobId')
  })

  await test('pod_exec：pod 忽略 timeoutMs（旧 pod）→ Host 在原生 deadline 后 kill 并如实标注超时', async () => {
    const calls = { run: [], output: [], kill: [] }
    let killed = false
    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'timeout-fallback-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async run(_hint, request) {
        calls.run.push(request)
        return {
          response: { ok: true, jobId: EXEC_JOB, runnerPid: 11, podPid: 22, cwd: WORKSPACE, command: request.command, description: null, startedAt: new Date().toISOString() },
          prepared: { enforcement: 'partial', fingerprint: 'f'.repeat(64), policyVariant: 'agentless', profile: { workspaceRoot: WORKSPACE, tempDir: TMP_ROOT, mode: 'workspace-write' } },
        }
      },
      async output(_hint, request) {
        calls.output.push(request)
        if (!killed) {
          return { ok: true, op: 'output', jobId: EXEC_JOB, status: 'running', running: true, exitCode: null, signal: null, text: '', chunks: [], totalBytes: 0, hasMore: false }
        }
        return {
          ok: true,
          op: 'output',
          jobId: EXEC_JOB,
          status: 'killed',
          running: false,
          exitCode: null,
          signal: 'SIGTERM',
          text: 'PARTIAL\n',
          chunks: [{ offset: 0, length: 8, channel: 'stdout', text: 'PARTIAL\n' }],
          totalBytes: 8,
          hasMore: false,
        }
      },
      async kill(_hint, request) {
        calls.kill.push(request)
        killed = true
        return { ok: true, op: 'kill', jobId: EXEC_JOB, killed: true, status: 'killed', exitCode: null, signal: 'SIGTERM', timedOut: true, timeoutMs: request.timeoutMs }
      },
    }
    const ctx = { get: (name) => (name === 'shell' ? { resolve: () => ({ timeoutMs: 20, stdoutMaxBytes: 4096 }) } : undefined) }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 0 }, null, () => {}, ctx)
    const value = await tools.find((candidate) => candidate.name === 'pod_exec').execute({ command: 'Start-Sleep 600' }, { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(calls.run[0].timeoutMs, 20, '仍然先把实时 timeoutMs 下发给 pod')
    assertEqual(calls.kill.length, 1, '旧 pod 不理会 timeoutMs 时，Host 必须兜底终止且只终止一次')
    assertEqual(calls.kill[0].timeoutMs, 20, '兜底 kill 必须带 timeoutMs，账本才能记为超时而不是用户 kill')
    assertEqual(value.timedOut, true, 'Host 兜底同样标 timedOut')
    assertEqual(value.status, 'killed', '最终状态 killed')
    assert(value.message.startsWith('命令超时：'), '仍要明确标注超时：' + value.message.slice(0, 80))
    assert(value.message.includes('PARTIAL'), '部分输出保留：' + value.message)
  })

  // -------------------------------------------------------------------------
  // 恢复半程：DSH 重启后结算被挂起的 pod_exec
  // -------------------------------------------------------------------------
  const RECOVERY_ROOT = join(TMP_ROOT, 'recovery')
  const RECOVERY_JOB = 'podc-recv0-abcdef02'

  /** 与 pod 真实 `output` 投影同形的已结算结果。 */
  function settledOutput(jobId = RECOVERY_JOB) {
    return {
      ok: true,
      op: 'output',
      jobId,
      status: 'settled',
      running: false,
      exitCode: 3,
      signal: null,
      text: 'OUT\nERR\n',
      chunks: [
        { offset: 0, length: 4, channel: 'stdout', text: 'OUT\n' },
        { offset: 4, length: 4, channel: 'stderr', text: 'ERR\n' },
      ],
      spillPath: join(TMP_ROOT, 'jobs', jobId, 'out.log'),
      from: 0,
      nextOffset: 8,
      totalBytes: 8,
      hasMore: false,
      eof: true,
      stalled: false,
      lossy: false,
      prefixHash: 'a'.repeat(64),
      cwd: WORKSPACE,
    }
  }

  /** 同一个 job 还在跑时的投影（running=true）。 */
  function runningOutput(jobId = RECOVERY_JOB) {
    return { ...settledOutput(jobId), status: 'running', running: true, exitCode: null, text: '', chunks: [], nextOffset: 0, totalBytes: 0, eof: false }
  }

  /** 只要 `output` 的 pod 客户端替身；`responses` 逐次消费，最后一项复用。 */
  function createRecoveryPod(responses) {
    const pod = {
      calls: [],
      async output(hint, request) {
        pod.calls.push(request)
        const index = Math.min(pod.calls.length - 1, responses.length - 1)
        const next = responses[index]
        if (typeof next === 'function') return await next(request)
        if (next instanceof Error) throw next
        return next
      },
    }
    return pod
  }

  /** 每条用例一份独立清单（TMP_ROOT 已按 RUN_ID 隔离）。 */
  function newRecoveryStore(name) {
    return createPendingStore({ file: join(RECOVERY_ROOT, name, PENDING_FILE_NAME) })
  }

  /** "上一个 boot"是指另一个进程；清单条目靠 `owner` 区分，测试里给它一个固定值。 */
  const PREVIOUS_BOOT_OWNER = 'previous-boot'

  /** 直接写一份"上一个 boot 留下的"清单，模拟真实重启（走 load 路径）。 */
  function writePendingFile(file, records) {
    fs.mkdirSync(join(file, '..'), { recursive: true })
    const entries = records.map((record) => ({
      tool: 'pod_exec',
      deadlineMs: RECOVERY_DEFAULTS.maxWaitMs,
      recordedAt: Date.now(),
      owner: PREVIOUS_BOOT_OWNER,
      ...record,
    }))
    fs.writeFileSync(
      file,
      JSON.stringify({ version: PENDING_VERSION, bootId: PREVIOUS_BOOT_OWNER, updatedAt: Date.now(), entries }, null, 2) + '\n',
      'utf8',
    )
  }

  function makeRecovery(options) {
    return createExecRecovery({
      hint: () => ({ sessionId: null, workspaceRoot: WORKSPACE }),
      renderExec: (response) => renderExecResult(response, false),
      modelOutputLimitBytes: 1024,
      serviceAttempts: 1,
      serviceRetryMs: 1,
      pollMinMs: 1,
      pollMaxMs: 2,
      log: () => {},
      ...options,
    })
  }

  await test('恢复扫描：重启后 job 已 settled → complete 的内容与 pod_exec 逐字节一致', async () => {
    // 1) 正常前台调用的基线（同一个 pod 客户端、同一个渲染函数）。
    const events = []
    const service = createFakeResume(events)
    const execCtx = createFakeHostCtx(service)
    const { pod: baselinePod } = createExecPod({ runningPolls: 0 })
    const baselineTools = createTools(baselinePod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, execCtx)
    const baseline = await baselineTools
      .find((candidate) => candidate.name === 'pod_exec')
      .execute({ command: 'exit 3' }, { callId: 'call-recover-settled', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } })
    assert(baseline.message.includes('[status: completed]'), '基线是全量结果：' + baseline.message)

    // 2) 模拟重启：上一个 boot 留下了清单条目，账本里这条 job 已结算。
    const store = newRecoveryStore('settled')
    const recorded = store.add({ callId: 'call-recover-settled', jobId: EXEC_JOB, deadlineMs: RECOVERY_DEFAULTS.maxWaitMs })
    assert(recorded !== null, '清单条目应写入')
    // 恢复读的是同一个账本投影（同一个 output 函数），所以差异只能来自渲染/接线。
    const recoveryPod = createRecoveryPod([() => baselinePod.output(null, { jobId: EXEC_JOB, from: 0, maxBytes: 1024 })])
    const recovery = makeRecovery({ store, pod: recoveryPod, resolveService: () => ({ service, reason: null }) })

    const outcome = await recovery.scan()
    assertEqual(outcome.completed, 1, '已结算的 job 必须 complete 一次')
    assertEqual(outcome.failed, 0, '不得走 fail')
    assertEqual(outcome.skipped, false, '服务可用时不跳过')
    assertEqual(events.filter((event) => event === 'complete:call-recover-settled').length, 1, 'complete 只调用一次')
    assertEqual(events.includes('fail:call-recover-settled'), false, '已结算时不得 fail')
    assertEqual(recoveryPod.calls.length, 1, '只查一次账本')
    assertEqual(recoveryPod.calls[0].from, 0, '与 pod_exec 一样从 0 读')
    assertEqual(recoveryPod.calls[0].maxBytes, 1024, '与 pod_exec 的 modelOutputLimitBytes 同窗口')

    assert(service.payload !== null && typeof service.payload === 'object', 'complete 必须带 payload')
    assertEqual(Array.isArray(service.payload.content), true, 'content 是内容块数组')
    assertEqual(service.payload.content[0].type, 'text', 'content[0] 是 text')
    assertEqual(service.payload.isError, false, '恢复出来的成功结果 isError=false')
    assertEqual(service.payload.content[0].text, baseline.message, '恢复文本必须与 pod_exec 的返回完全一致')
    assert(
      Buffer.from(service.payload.content[0].text, 'utf8').equals(Buffer.from(baseline.message, 'utf8')),
      '逐字节一致（含 [stderr] 段、[exit code: 3]、[status: completed]）',
    )
    assertEqual(store.list().length, 0, '结算后清单条目必须删除')
    assertEqual(JSON.parse(fs.readFileSync(store.path, 'utf8')).entries.length, 0, '磁盘上也删掉了')
    // 恢复文本不得泄漏 jobId / 偏移（与前台同一条契约）。
    assert(!service.payload.content[0].text.includes(EXEC_JOB), '恢复文本里不得出现 jobId')
  })

  await test('恢复扫描：job 仍 running → 刷新 hold、不 complete；结算后才 complete', async () => {
    const events = []
    const service = createFakeResume(events)
    service.statusRows = [{ callId: 'call-recover-run', status: 'held' }]
    service.complete = async (callId, payload) => {
      events.push('complete:' + callId)
      service.payload = payload
      return { applied: true, status: 'completed' }
    }
    let settled = false
    const pod = createRecoveryPod([() => (settled ? settledOutput() : runningOutput())])
    const store = newRecoveryStore('running')
    store.add({ callId: 'call-recover-run', jobId: RECOVERY_JOB, deadlineMs: 12 * 60 * 60 * 1000 })
    const recovery = makeRecovery({ store, pod, resolveService: () => ({ service, reason: null }) })

    const first = await recovery.scan()
    assertEqual(first.running, 1, '仍在跑：记一条 running')
    assertEqual(first.completed, 0, '仍在跑时不得 complete')
    assertEqual(events.includes('complete:call-recover-run'), false, '仍在跑时绝不写结果')
    assertEqual(service.holdCalls, 1, '必须刷新挂起（推进 deadlineAt）')
    assertEqual(service.descriptor.tool, 'pod_exec', '刷新时声明的工具名')
    assertEqual(service.descriptor.hint.jobId, RECOVERY_JOB, '刷新时 hint 仍然只带 jobId')
    assertEqual(service.descriptor.deadlineMs, 12 * 60 * 60 * 1000, '刷新用原 deadlineMs')
    assertEqual(store.list().length, 1, '未结算的条目留在清单里')

    settled = true
    const second = await recovery.scan()
    assertEqual(second.completed, 1, '结算后必须 complete')
    assertEqual(events.includes('complete:call-recover-run'), true, '真实结果补回这条调用')
    assert(service.payload.content[0].text.includes('[status: completed]'), '恢复结果用原状态行：' + service.payload.content[0].text)
    assert(service.payload.content[0].text.includes('[exit code: 3]'), '恢复结果保留退出码：' + service.payload.content[0].text)
    assertEqual(store.list().length, 0, '结算后删除')

    // 挂起预算还没花掉一半时不必反复重写服务的 holds 文件（12h 的挂起约 6h 一次）。
    const quietEvents = []
    const quietService = createFakeResume(quietEvents)
    quietService.statusRows = [{ callId: 'call-recover-quiet', status: 'held', deadlineAt: Date.now() + 11 * 60 * 60 * 1000 }]
    const quietStore = newRecoveryStore('quiet')
    quietStore.add({ callId: 'call-recover-quiet', jobId: RECOVERY_JOB, deadlineMs: 12 * 60 * 60 * 1000 })
    const quiet = makeRecovery({
      store: quietStore,
      pod: createRecoveryPod([runningOutput()]),
      resolveService: () => ({ service: quietService, reason: null }),
    })
    const quietOutcome = await quiet.scan()
    assertEqual(quietOutcome.running, 1, '仍在跑')
    assertEqual(quietService.holdCalls, 0, '预算充足时不重写 holds（避免每轮落盘）')
    assertEqual(quietStore.list().length, 1, '不刷新也保留清单条目')

    // 服务已经结算掉的挂起不得被 refresh 复活：宁可放弃清单条目，也不写第二条结果。
    const resurrectEvents = []
    const resurrectService = createFakeResume(resurrectEvents)
    resurrectService.statusRows = [{ callId: 'call-recover-observed', status: 'observed' }]
    const resurrectStore = newRecoveryStore('observed')
    resurrectStore.add({ callId: 'call-recover-observed', jobId: RECOVERY_JOB })
    const resurrect = makeRecovery({
      store: resurrectStore,
      pod: createRecoveryPod([runningOutput()]),
      resolveService: () => ({ service: resurrectService, reason: null }),
    })
    const third = await resurrect.scan()
    assertEqual(resurrectService.holdCalls, 0, '已结算的挂起不得复活')
    assertEqual(resurrectEvents.includes('complete:call-recover-observed'), false, '不得补写第二条结果')
    assertEqual(third.dropped, 1, '没有可回答的调用：放弃清单条目')
    assertEqual(resurrectStore.list().length, 0, '放弃后删除条目')
  })

  await test('恢复扫描：job 不存在 / 账本缺失（ENOJOB）→ fail(reason)，绝不写 complete', async () => {
    const events = []
    const service = createFakeResume(events)
    const lost = new Error('账本里没有这个 job：' + RECOVERY_JOB)
    lost.code = 'ENOJOB'
    const store = newRecoveryStore('lost')
    store.add({ callId: 'call-recover-lost', jobId: RECOVERY_JOB })
    const recovery = makeRecovery({
      store,
      pod: createRecoveryPod([lost]),
      resolveService: () => ({ service, reason: null }),
    })

    const outcome = await recovery.scan()
    assertEqual(outcome.failed, 1, '找不到账本必须如实 fail')
    assertEqual(outcome.completed, 0, '不得假装完成')
    assertEqual(events.includes('complete:call-recover-lost'), false, '绝不用 complete 掩盖缺失')
    assertEqual(events.includes('fail:call-recover-lost'), true, '必须 fail(callId, reason)')
    assert(typeof service.reason === 'string' && service.reason.includes('ENOJOB'), '原因点名 ENOJOB：' + String(service.reason))
    assert(service.reason.includes(RECOVERY_JOB), '原因带上 jobId：' + String(service.reason))
    assertEqual(store.list().length, 0, '失败结算后也删除条目（服务侧已是终局）')
  })

  await test('恢复清单：原子写 / 结算后删除 / 损坏不崩 / 有界', () => {
    const dir = join(RECOVERY_ROOT, 'store')
    const file = join(dir, PENDING_FILE_NAME)
    const store = createPendingStore({ file })
    assertEqual(store.disabled, false, '有 stateDir 时清单可用')
    assertEqual(store.load().entries, 0, '文件不存在时是空清单')
    const entry = store.add({ callId: 'call-store-a', jobId: 'podc-store0-aaaaaaaa' })
    assert(entry !== null, '应写入条目')
    assertEqual(entry.tool, 'pod_exec', '默认工具名')
    assertEqual(entry.deadlineMs, RECOVERY_DEFAULTS.maxWaitMs, '没有 deadlineMs 时取默认上限')
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
    assertEqual(parsed.version, PENDING_VERSION, '磁盘上的 schema 版本')
    assertEqual(parsed.entries.length, 1, '磁盘上一条')
    assertEqual(fs.readdirSync(dir).filter((name) => name.includes('.tmp-')).length, 0, '原子写不得留下临时文件')
    assertEqual(store.has('call-store-a'), true, 'has() 与磁盘一致')

    assertEqual(store.remove('call-store-a'), true, '删除成功')
    assertEqual(JSON.parse(fs.readFileSync(file, 'utf8')).entries.length, 0, '删除后立刻落盘')
    assertEqual(store.remove('call-store-a'), false, '重复删除是 no-op')

    // 损坏 / 版本不符 / 坏条目：都按空清单继续，绝不抛错；下一次写入覆盖成合法清单。
    fs.writeFileSync(file, '{"version": 99, "entries": [', 'utf8')
    const corrupt = createPendingStore({ file })
    const corruptLoad = corrupt.load()
    assertEqual(corruptLoad.corrupt, true, '坏 JSON 被识别为损坏')
    assertEqual(corruptLoad.entries, 0, '损坏时按空清单继续')
    assertEqual(corrupt.list().length, 0, 'list 也不崩')
    corrupt.add({ callId: 'call-store-b', jobId: 'podc-store0-bbbbbbbb' })
    assertEqual(JSON.parse(fs.readFileSync(file, 'utf8')).entries.length, 1, '损坏后下一次写入是合法清单')

    fs.writeFileSync(file, JSON.stringify({ version: PENDING_VERSION, entries: [{ callId: 'call-store-c' }, { callId: 'call-store-d', jobId: 'podc-store0-dddddddd' }] }), 'utf8')
    const mixed = createPendingStore({ file })
    assertEqual(mixed.load().entries, 1, '坏条目被丢弃，好条目保留')
    assertEqual(mixed.list()[0].callId, 'call-store-d', '留下的是形状合法的那条')

    fs.writeFileSync(file, JSON.stringify({ version: PENDING_VERSION + 1, entries: [{ callId: 'x', jobId: 'y' }] }), 'utf8')
    assertEqual(createPendingStore({ file }).load().entries, 0, '版本不符按空清单处理')

    assertEqual(sanitizePendingEntry(null), null, 'null 记录直接丢弃')
    assertEqual(sanitizePendingEntry({ callId: '', jobId: 'x' }), null, '空 callId 丢弃')
    assertEqual(sanitizePendingEntry({ callId: 'c' }), null, '缺 jobId 丢弃')

    // 有界：超过上限就淘汰最旧的，磁盘与内存都不超过 PENDING_LIMITS.entries。
    fs.rmSync(file, { force: true })
    const bounded = createPendingStore({ file })
    for (let index = 0; index < PENDING_LIMITS.entries + 3; index += 1) {
      bounded.add({ callId: 'call-bounded-' + String(index), jobId: RECOVERY_JOB })
    }
    assertEqual(bounded.list().length, PENDING_LIMITS.entries, '内存里有界')
    assertEqual(JSON.parse(fs.readFileSync(file, 'utf8')).entries.length, PENDING_LIMITS.entries, '磁盘上也有界')
    assertEqual(bounded.has('call-bounded-0'), false, '最旧的被淘汰')
    assertEqual(bounded.has('call-bounded-' + String(PENDING_LIMITS.entries + 2)), true, '最新的保留')

    // stateDir 为空：清单禁用，但 add/remove/list 仍然不抛错（pod_exec 不受影响）。
    const disabled = createPendingStore({})
    assertEqual(disabled.disabled, true, '没有路径时禁用')
    assertEqual(disabled.add({ callId: 'c', jobId: 'j' }), null, '禁用时 add 返回 null')
    assertEqual(disabled.remove('c'), false, '禁用时 remove 是 no-op')
    assertEqual(disabled.list().length, 0, '禁用时 list 是空数组')
  })

  await test('恢复扫描：服务不可用 → 直接跳过（降级），清单原样保留', async () => {
    const store = newRecoveryStore('unavailable')
    writePendingFile(store.path, [{ callId: 'call-recover-skip', jobId: RECOVERY_JOB }])
    const pod = createRecoveryPod([settledOutput()])
    const recovery = makeRecovery({
      store,
      pod,
      resolveService: () => ({ service: null, reason: 'Host 没有提供 resumableToolCalls（restart-bundle 早于 1.7.4-hotfix.4）' }),
    })

    const started = recovery.start()
    assertEqual(started.started, true, 'start 同步返回')
    assertEqual(started.pending, 1, 'start 同步读到清单')
    assertEqual(started.carried, 1, '另一个进程留下的条目算"上次 boot"')
    await recovery.done
    assertEqual(store.list().length, 1, '降级时清单必须原样保留（绝不假装结算过）')
    assertEqual(pod.calls.length, 0, '服务不可用时连账本都不读')
    const status = recovery.status()
    assertEqual(status.running, false, '循环已停')
    assertEqual(status.pending, 1, 'status 如实报待恢复')
    assert(typeof status.service === 'string' && status.service.includes('没有提供'), 'status 带降级原因：' + String(status.service))
    assertEqual(status.last, null, '没有扫描过就不编造结果')
    assertEqual(recovery.start().already, true, '重复 start 幂等')
    recovery.dispose()
  })

  await test('恢复扫描：只结算上一次 boot 留下的条目，本 boot 新登记的绝不抢答', async () => {
    const events = []
    const service = createFakeResume(events)
    service.statusRows = [{ callId: 'call-carried', status: 'held' }]
    let settled = false
    const pod = createRecoveryPod([() => (settled ? settledOutput() : runningOutput())])
    const store = newRecoveryStore('carried')
    writePendingFile(store.path, [{ callId: 'call-carried', jobId: RECOVERY_JOB, deadlineMs: 12 * 60 * 60 * 1000 }])
    let addedFresh = false
    const recovery = makeRecovery({
      store,
      pod,
      resolveService: () => ({ service, reason: null }),
      // 循环第一次让出时，模拟"本 boot 又有一次 pod_exec 登记了挂起"。
      sleep: async () => {
        if (addedFresh) return
        addedFresh = true
        store.add({ callId: 'call-fresh', jobId: EXEC_JOB, deadlineMs: 12 * 60 * 60 * 1000 })
        settled = true
      },
    })

    recovery.start()
    await recovery.done
    assertEqual(events.includes('complete:call-carried'), true, '上一个 boot 的调用被结算')
    assertEqual(events.includes('complete:call-fresh'), false, '本 boot 新登记的调用不得被恢复扫描抢答')
    assertEqual(store.has('call-carried'), false, '已结算的条目删除')
    assertEqual(store.has('call-fresh'), true, '新登记的条目留着（由它自己的 completeAfterCommit 负责）')
    recovery.dispose()

    // 同一进程（插件 HMR 重载）刚登记的条目也不算"上一次 boot"：抢答会给同一条调用
    // 写第二条 tool/result。
    const sameBootStore = newRecoveryStore('same-boot')
    sameBootStore.add({ callId: 'call-same-boot', jobId: RECOVERY_JOB, deadlineMs: 12 * 60 * 60 * 1000 })
    const sameBootEvents = []
    const sameBootService = createFakeResume(sameBootEvents)
    const sameBoot = makeRecovery({
      store: sameBootStore,
      pod: createRecoveryPod([settledOutput()]),
      resolveService: () => ({ service: sameBootService, reason: null }),
    })
    const sameBootStart = sameBoot.start()
    await sameBoot.done
    assertEqual(sameBootStart.pending, 1, '清单里确实有一条')
    assertEqual(sameBootStart.carried, 0, '同一进程写的条目不算"上一次 boot"')
    assertEqual(sameBootEvents.includes('complete:call-same-boot'), false, '不得抢答本进程正在跑的调用')
    assertEqual(sameBootStore.has('call-same-boot'), true, '条目原样保留')
    sameBoot.dispose()
  })

  await test('pod_exec：挂起成功即写恢复清单（同步落盘），平台结果写下后删除', async () => {
    // 接线面：插件把这两样东西从 index.js 暴露给恢复模块与自测。
    assertEqual(typeof __internals.createExecRecovery, 'function', 'index.js 应导出恢复扫描器')
    assertEqual(typeof __internals.createPendingStore, 'function', 'index.js 应导出清单')
    assertEqual(__internals.PENDING_FILE_NAME, 'pending-exec.json', '清单文件名与文档一致')
    assertEqual(typeof __internals.renderExecResult, 'function', '渲染函数必须可被恢复路径复用')
    assertEqual(__internals.renderExecResult, renderExecResult, '插件用的就是同一个渲染函数（不是副本）')

    const events = []
    const service = createFakeResume(events)
    const ctx = createFakeHostCtx(service)
    const { pod } = createExecPod()
    const store = newRecoveryStore('exec-wire')
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, ctx, { store })
    const tool = tools.find((candidate) => candidate.name === 'pod_exec')
    const exec = { callId: 'call-wire', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }

    const value = await tool.execute({ command: 'exit 3' }, exec)
    assertEqual(value.resume.held, true, '有服务时必须真的挂上')
    const listed = store.list()
    assertEqual(listed.length, 1, '挂起成功就写清单（hold 返回前已落盘）')
    assertEqual(listed[0].callId, 'call-wire', '清单记的是平台 callId')
    assertEqual(listed[0].jobId, EXEC_JOB, '清单记的是 pod jobId（恢复唯一需要的身份）')
    assertEqual(listed[0].tool, 'pod_exec', '清单记工具名')
    assertEqual(JSON.parse(fs.readFileSync(store.path, 'utf8')).entries.length, 1, '磁盘上确实有一条（重启后能读到）')

    ctx.emitResult('call-wire')
    await flushTicks()
    assertEqual(events.includes('complete:call-wire'), true, '平台写下结果后才 complete')
    assertEqual(store.list().length, 0, '结算后删除清单条目')

    // 没有服务：不挂起，也就不该留清单（否则下一次 boot 会去结算一条它不认识的调用）。
    const bare = newRecoveryStore('exec-nowire')
    const bareTools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, null, { store: bare })
    const bareValue = await bareTools
      .find((candidate) => candidate.name === 'pod_exec')
      .execute({ command: 'exit 0' }, { callId: 'call-bare', agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } })
    assertEqual(bareValue.resume.available, false, '没有服务时降级')
    assertEqual(bare.list().length, 0, '没有挂起就不该留清单')
  })

  await test('pod_status：恢复扫描如实报告，且整个返回值是无损 JSON', async () => {
    const store = newRecoveryStore('status')
    writePendingFile(store.path, [{ callId: 'call-status', jobId: RECOVERY_JOB }])
    const recovery = makeRecovery({
      store,
      pod: createRecoveryPod([settledOutput()]),
      resolveService: () => ({ service: null, reason: 'Host 没有提供 resumableToolCalls' }),
    })
    recovery.start()
    await recovery.done
    assertEqual(recovery.status().pending, 1, '服务不可用时条目保留，status 应如实看到')

    const pod = {
      stateDir: TMP_ROOT,
      pipeName: 'status-pipe',
      mode: () => 'reused',
      template: () => ({ pinned: true }),
      spawnInfo: () => null,
      async status() {
        return {
          response: {
            podPid: 4321,
            podStartedAt: '2026-10-29T00:00:00.000Z',
            generation: 2,
            enforcement: 'partial',
            podVersion: '1.7.0',
            protocolVersion: 2,
            pipeName: 'status-pipe',
            identity: { seedKind: 'user+host', seedVersion: 1, seedHash: 'a'.repeat(64) },
            auth: { mode: 'token', required: true, tokenFingerprint: 'b'.repeat(64), connected: true, tokenSource: 'spawn-stdin', handoverCount: 1, handoverAllowed: true, rejectedConnections: 0 },
            template: { valid: true, runnerPath: FAKE_RUNNER, program: process.execPath, mode: 'workspace-write', workspaceRoot: WORKSPACE, pin: 'c'.repeat(64), lastEnforcement: 'partial' },
            workspaceRoot: WORKSPACE,
            dataRoot: TMP_ROOT,
            running: 0,
            jobs: [],
          },
          bootstrapError: null,
        }
      },
    }
    const tools = createTools(pod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {}, { get: () => undefined }, { store, recovery })
    const tool = tools.find((candidate) => candidate.name === 'pod_status')
    const value = await tool.execute({}, { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } })
    assert(value.message.includes('恢复扫描='), 'status 消息末行应报恢复扫描：' + value.message)
    assert(value.message.includes('待恢复 1 条'), '待恢复条数应如实：' + value.message)
    assert(value.message.includes('resumableToolCalls=unavailable'), '服务不可用也要如实写：' + value.message)
    assertEqual(value.recovery.pending, 1, '返回值里带恢复扫描快照')
    assertEqual(value.recovery.running, false, '循环已停')
    assert(typeof value.recovery.service === 'string', '降级原因在返回值里')
    assertEqual(value.recovery.last, null, '没有扫描过就不编造 last')
    const text = JSON.stringify(value)
    assertEqual(JSON.stringify(JSON.parse(text)), text, 'JSON 往返稳定（没有 undefined / 不可序列化字段）')
    assert(!text.includes('undefined'), '返回值里不得出现 undefined 值：' + text.slice(0, 200))
  })

  // -------------------------------------------------------------------------
  // OS-level client attestation
  // -------------------------------------------------------------------------
  await test('客户端鉴权：受限/低完整性客户端被拒，普通同用户客户端放行', async () => {
    const policy = {
      userSid: 'S-1-5-21-1-2-3-1001',
      sessionId: 1,
      minIntegrityRid: 0x2000,
      allowRestricted: false,
      allowedImages: ['Z:\\nodejs\\node.exe'],
    }
    const sandboxed = evaluateClient({
      ok: true,
      serverPid: 1,
      serverPidMatches: true,
      client: {
        pid: 4242,
        imagePath: 'Z:\\nodejs\\node.exe',
        userSid: 'S-1-5-21-1-2-3-1001',
        sessionId: 1,
        integrityRid: 0x1000,
        restrictedSidCount: 4,
      },
    }, policy)
    assertEqual(sandboxed.allowed, false, 'Low + 受限令牌必须被拒')
    const failedNames = sandboxed.checks.filter((check) => !check.ok).map((check) => check.name).sort()
    assertEqual(failedNames.join(','), 'integrity,token-shape', '应同时指出完整性级别与令牌形态：' + failedNames.join(','))

    const host = evaluateClient({
      ok: true,
      serverPid: 1,
      serverPidMatches: true,
      client: {
        pid: 4243,
        imagePath: 'Z:\\nodejs\\node.exe',
        userSid: 'S-1-5-21-1-2-3-1001',
        sessionId: 1,
        integrityRid: 0x2000,
        restrictedSidCount: 0,
      },
    }, policy)
    assertEqual(host.allowed, true, 'Medium + 非受限 + 同镜像必须放行：' + JSON.stringify(host.checks))

    const otherUser = evaluateClient({
      ok: true,
      serverPid: 1,
      serverPidMatches: true,
      client: {
        pid: 4244,
        imagePath: 'Z:\\nodejs\\node.exe',
        userSid: 'S-1-5-21-9-9-9-1002',
        sessionId: 1,
        integrityRid: 0x2000,
        restrictedSidCount: 0,
      },
    }, policy)
    assertEqual(otherUser.allowed, false, '别的用户必须被拒')

    const foreign = evaluateClient({
      ok: true,
      serverPid: 1,
      serverPidMatches: true,
      client: {
        pid: 4245,
        imagePath: 'C:\\Tools\\evil.exe',
        userSid: 'S-1-5-21-1-2-3-1001',
        sessionId: 1,
        integrityRid: 0x2000,
        restrictedSidCount: 0,
      },
    }, policy)
    assertEqual(foreign.allowed, false, '非白名单镜像必须被拒')

    const unattested = evaluateClient({ ok: false, code: 'ENOHANDLE', message: 'no handle' }, policy)
    assertEqual(unattested.allowed, false, '拿不到身份时必须拒绝（不是默认放行）')
  })

  await test('socket 层：identify 无 token 可读；enforce 下无 nonce 的 handover 被拒，带 nonce 放行', async () => {
    const auth = createPodAuth({ token: TOKEN_A, handoverGraceMs: 60_000 })
    const clients = new Set()
    const ticket = 'a'.repeat(32)
    const tickets = new Map([[ticket, { pid: 4242, at: Date.now(), allowed: true, checks: [] }]])
    const channel = {
      port: () => 45678,
      // Single use, like the real channel: consuming removes the ticket.
      consume: (nonce) => {
        if (!tickets.has(nonce)) return { ok: false, code: 'EUNATTESTED', message: 'nonce 未登记' }
        const ticket = tickets.get(nonce)
        tickets.delete(nonce)
        return { ok: true, ticket }
      },
    }
    const service = {
      bumpGeneration() {},
      touchActivity() {},
      snapshot: () => ({ ok: true, podStartedAt: '2026-01-01T00:00:00.000Z', auth: auth.snapshot() }),
      /** @param {string} op */
      async handle(op) {
        return { ok: true, op }
      },
    }
    const policy = {
      mode: 'enforce',
      userSid: 'S-1-5-21-1-2-3-1001',
      sessionId: 1,
      minIntegrityRid: 0x2000,
      allowRestricted: false,
      allowedImages: ['Z:\\nodejs\\node.exe'],
    }
    const onConnection = createConnectionHandler(service, auth, {
      clients,
      log: () => {},
      attestPolicy: policy,
      identityChannel: channel,
    })
    const tick = () => new Promise((resolveSleep) => setTimeout(resolveSleep, 20))

    // identify carries no token by design: it only publishes a port number.
    const first = new FakeSocket('peer-identify')
    onConnection(first)
    // Accept the spawn owner first: until the pod has seen its spawn token, a
    // handover is refused by policy (EAUTHREQUIRED) regardless of attestation.
    first.request({ op: 'status', id: 0, token: TOKEN_A })
    await tick()
    assertEqual(first.responses[0]?.ok, true, 'spawn token 必须被接受')
    first.request({ op: 'identify', id: 1 })
    await tick()
    assertEqual(first.responses[1]?.ok, true, 'identify 必须无 token 可读：' + JSON.stringify(first.responses[1] ?? null))
    assertEqual(first.responses[1]?.identityChannel?.port, 45678, 'identify 必须给出身份通道端口')
    assertEqual(first.ended, false, 'identify 不得关闭连接')

    // No nonce: the takeover that cannot be attributed is refused.
    first.request({ op: 'handover', id: 2, newToken: TOKEN_B })
    await tick()
    assertEqual(first.responses[2]?.error?.code, 'EUNATTESTED', 'enforce 下无 nonce 的 handover 必须被拒：' + JSON.stringify(first.responses[2] ?? null))
    assertEqual(first.ended, true, '被拒的 handover 必须关闭连接')

    // With a redeemed nonce the takeover proceeds and the new token works.
    const second = new FakeSocket('peer-handover')
    onConnection(second)
    second.request({ op: 'handover', id: 3, newToken: TOKEN_B, nonce: ticket })
    await tick()
    assertEqual(second.responses[0]?.ok, true, '带有效 nonce 的 handover 必须放行：' + JSON.stringify(second.responses[0] ?? null))
    second.request({ op: 'status', id: 4, token: TOKEN_B })
    await tick()
    assertEqual(second.responses[1]?.ok, true, '接管后的新 token 必须可用')
    // Single use: the same nonce cannot be replayed by another connection.
    second.destroy()
    await tick()
    const replay = new FakeSocket('peer-replay')
    onConnection(replay)
    replay.request({ op: 'handover', id: 5, newToken: TOKEN_C, nonce: ticket })
    await tick()
    assertEqual(replay.responses[0]?.error?.code, 'EUNATTESTED', 'nonce 必须一次性：重放应被拒')
  })

  await test('客户端鉴权：TCP 形态没有 serverPid 不得被拒；管道 serverPid 不匹配仍拒', () => {
    const policy = {
      userSid: 'S-1-5-21-1-2-3-1001',
      sessionId: 1,
      minIntegrityRid: 0x2000,
      allowRestricted: false,
      allowedImages: ['Z:/nodejs/node.exe'],
    }
    const client = {
      pid: 4243,
      imagePath: 'Z:/nodejs/node.exe',
      userSid: 'S-1-5-21-1-2-3-1001',
      sessionId: 1,
      integrityRid: 0x2000,
      restrictedSidCount: 0,
    }
    // Identity-channel (TCP) shape: describeTcpPeer returns no serverPid at all.
    const tcp = evaluateClient({ ok: true, pid: 4243, rows: 120, client }, policy)
    assertEqual(tcp.allowed, true, 'TCP 形态不得因缺少管道字段被拒：' + JSON.stringify(tcp.checks))
    assertEqual(tcp.checks.some((check) => check.name === 'server-side'), false,
      'TCP 形态不应产生 server-side 检查（那不是它拿得到的证据）')

    // Pipe shape with a matching server pid: the check exists and passes.
    const pipe = evaluateClient({ ok: true, fd: 7, instances: 1, serverPid: process.pid, serverPidMatches: true, client }, policy)
    assertEqual(pipe.allowed, true, '管道形态 serverPid 匹配必须放行：' + JSON.stringify(pipe.checks))
    assertEqual(pipe.checks.some((check) => check.name === 'server-side' && check.ok === true), true,
      '匹配时必须留下 server-side 证据')

    // Pipe shape pointing at a different server process: still refused.
    const wrongServer = evaluateClient({ ok: true, fd: 7, instances: 1, serverPid: process.pid + 1, serverPidMatches: false, client }, policy)
    assertEqual(wrongServer.allowed, false, '管道 serverPid 不匹配必须拒绝')
    const failed = wrongServer.checks.filter((check) => !check.ok).map((check) => check.name)
    assertEqual(failed.join(','), 'server-side', '唯一失败项应是 server-side：' + failed.join(','))

    // Presence of the number gates the check; a missing flag is not a pass.
    const missingFlag = evaluateClient({ ok: true, fd: 7, instances: 1, serverPid: process.pid, client }, policy)
    assertEqual(missingFlag.allowed, false, 'serverPid 存在但 serverPidMatches 缺失必须拒绝')
  })

  await test('attest-policy.json：合法文件生效、损坏/非法不降级 off、env 逐字段优先', () => {
    const dir = join(TMP_ROOT, 'attest-policy')
    fs.mkdirSync(dir, { recursive: true })
    const file = join(dir, 'attest-policy.json')
    /** @type {string[]} */
    const logs = []
    const selfFacts = { imagePath: 'Z:/nodejs/node.exe', userSid: 'S-1-5-21-1-2-3-1001', sessionId: 1 }
    let stamp = Date.now()
    /** @param {unknown} value */
    const write = (value) => {
      stamp += 5000
      fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value))
      // The source keys the file on mtime+size; two writes in the same clock
      // tick (or same-length payloads) would otherwise look unchanged.
      fs.utimesSync(file, new Date(stamp), new Date(stamp))
    }
    /** @param {string} line */
    const sink = (line) => {
      logs.push(line)
    }
    const source = createAttestPolicySource({ dataRoot: dir, selfFacts, env: {}, log: sink })
    const initial = source.current()
    assertEqual(initial.mode, 'warn', '没有文件时默认 warn（观察，不拦）')
    assertEqual(initial.minIntegrityRid, 0x2000, '默认最低完整性是 Medium')
    assertEqual(initial.allowedImages.join('|'), 'Z:/nodejs/node.exe', '默认白名单是 pod 自己的镜像')

    write({ mode: 'enforce', minIntegrity: 'high', allowRestricted: true, allowedImages: ['Z:/tools/node.exe'] })
    const loaded = source.current()
    assertEqual(loaded.mode, 'enforce', '合法文件的 mode 应生效')
    assertEqual(loaded.minIntegrityRid, 0x3000, 'minIntegrity=high 应解析成 0x3000')
    assertEqual(loaded.allowRestricted, true, 'allowRestricted 应生效')
    assertEqual(loaded.allowedImages.join('|'), 'Z:/tools/node.exe', 'allowedImages 应生效')
    assertEqual(source.describe().error, null, '合法文件不应留下 fileError')
    assert(logs.some((line) => line.includes('已加载')), '加载合法文件必须记日志：' + logs.join(' | '))

    // Corrupt JSON: the last valid policy stays in force; enforce is never relaxed.
    write('{ this is not json')
    const corrupt = source.current()
    assertEqual(corrupt.mode, 'enforce', '损坏文件不得把 enforce 降级')
    assertEqual(corrupt.minIntegrityRid, 0x3000, '损坏文件不得丢掉上一份有效字段')
    assertEqual(corrupt.allowedImages.join('|'), 'Z:/tools/node.exe', '损坏文件不得丢掉上一份白名单')
    assertEqual(source.describe().error?.code, 'EBADATTESTPOLICY', '损坏必须留下 fileError 供诊断')
    assert(logs.some((line) => line.includes('沿用上一份有效策略')), '损坏必须记日志：' + logs.join(' | '))

    // Invalid field: the whole file is rejected, so a stray mode=off cannot win.
    write({ mode: 'off', minIntegrity: 'impossible' })
    const invalid = source.current()
    assertEqual(invalid.mode, 'enforce', '非法字段必须让整份文件失效，不能借 mode=off 放宽')
    assertEqual(invalid.minIntegrityRid, 0x3000, '非法文件同样不得改字段')

    // A valid flip is honoured at once (no restart).
    write({ mode: 'warn' })
    assertEqual(source.current().mode, 'warn', '合法文件应实时生效（按 mtime 重读）')

    // PowerShell 5.1 `Set-Content -Encoding UTF8` writes a BOM; that is not
    // corruption and must still be read.
    stamp += 5000
    fs.writeFileSync(file, '\uFEFF' + JSON.stringify({ mode: 'enforce' }))
    fs.utimesSync(file, new Date(stamp), new Date(stamp))
    assertEqual(source.current().mode, 'enforce', '带 UTF-8 BOM 的合法文件必须被读取')

    // A valid mode=off is honoured (it is the only way the file itself relaxes).
    write({ mode: 'off' })
    assertEqual(source.current().mode, 'off', '合法 mode=off 应生效')

    // Env pins win field by field.
    write({ mode: 'warn', minIntegrity: 'low', allowRestricted: true, allowedImages: ['Z:/from-file.exe'] })
    const pinned = createAttestPolicySource({
      dataRoot: dir,
      selfFacts,
      env: {
        PODC_ATTEST: 'enforce',
        PODC_ATTEST_MIN_INTEGRITY: 'medium',
        PODC_ATTEST_ALLOW_RESTRICTED: '0',
        PODC_ATTEST_IMAGES: 'C:/a.exe;D:/b.exe',
      },
      log: () => {},
    })
    const merged = pinned.current()
    assertEqual(merged.mode, 'enforce', 'env PODC_ATTEST 必须覆盖文件')
    assertEqual(merged.minIntegrityRid, 0x2000, 'env 最低完整性必须覆盖文件')
    assertEqual(merged.allowRestricted, false, 'env ALLOW_RESTRICTED=0 必须覆盖文件里的 true')
    assertEqual(merged.allowedImages.join('|'), 'C:/a.exe|D:/b.exe', 'env 镜像白名单必须覆盖文件')
  })

  await test('socket 层：TCP 身份放行 handover；enforce 下 serverPid 不匹配被拒、无管道句柄不误拒', async () => {
    const tick = () => new Promise((resolveSleep) => setTimeout(resolveSleep, 20))
    // Drive the handler through a LIVE policy source (not a plain object): the
    // point of the file is that the next decision already sees the new mode.
    const policyDir = join(TMP_ROOT, 'attest-policy-live')
    fs.mkdirSync(policyDir, { recursive: true })
    const policyFile = join(policyDir, 'attest-policy.json')
    let policyStamp = Date.now()
    /** @param {Record<string, unknown>} value */
    const writePolicy = (value) => {
      policyStamp += 5000
      fs.writeFileSync(policyFile, JSON.stringify(value))
      fs.utimesSync(policyFile, new Date(policyStamp), new Date(policyStamp))
    }
    writePolicy({ mode: 'enforce' })
    const policy = createAttestPolicySource({
      dataRoot: policyDir,
      selfFacts: { imagePath: 'Z:/nodejs/node.exe', userSid: 'S-1-5-21-1-2-3-1001', sessionId: 1 },
      env: {},
      log: () => {},
    })
    assertEqual(policy.current().mode, 'enforce', '策略文件应被实时读出 enforce')
    const goodClient = {
      pid: 4243,
      imagePath: 'Z:/nodejs/node.exe',
      userSid: 'S-1-5-21-1-2-3-1001',
      sessionId: 1,
      integrityRid: 0x2000,
      restrictedSidCount: 0,
    }
    const ticket = 'b'.repeat(32)
    const tickets = new Map([[ticket, { pid: 4243, at: Date.now(), allowed: true, checks: [] }]])
    const channel = {
      port: () => 45679,
      /** @param {string} nonce */
      consume: (nonce) => {
        if (!tickets.has(nonce)) return { ok: false, code: 'EUNATTESTED', message: 'nonce 未登记' }
        const value = tickets.get(nonce)
        tickets.delete(nonce)
        return { ok: true, ticket: value }
      },
    }
    /** @param {any} attestation */
    const makeHandler = (attestation) => {
      const auth = createPodAuth({ token: TOKEN_A, handoverGraceMs: 60_000 })
      const service = {
        bumpGeneration() {},
        touchActivity() {},
        snapshot: () => ({ ok: true, podStartedAt: '2026-01-01T00:00:00.000Z', auth: auth.snapshot() }),
        /** @param {string} op */
        async handle(op) {
          return { ok: true, op }
        },
      }
      const attestor = {
        describeClient: () => attestation,
      }
      return createConnectionHandler(service, auth, {
        clients: new Set(),
        log: () => {},
        attestor,
        attestPolicy: policy,
        identityChannel: channel,
      })
    }

    // TCP shape: no serverPid. Before the fix this denied every legitimate
    // Host, so this handover is exactly the regression the case pins. The
    // spawn owner must connect once first: until then handover is EAUTHREQUIRED.
    const tcpHandler = makeHandler({ ok: true, pid: 4243, rows: 173, client: goodClient })
    const ownerSocket = new FakeSocket('peer-owner')
    tcpHandler(ownerSocket)
    ownerSocket.request({ op: 'status', id: 0, token: TOKEN_A })
    await tick()
    assertEqual(ownerSocket.responses[0]?.ok, true, 'spawn token 必须被接受')
    ownerSocket.destroy()
    await tick()

    const tcpSocket = new FakeSocket('peer-tcp')
    tcpHandler(tcpSocket)
    tcpSocket.request({ op: 'handover', id: 1, newToken: TOKEN_B, nonce: ticket })
    await tick()
    assertEqual(tcpSocket.responses[0]?.ok, true, 'TCP 形态身份必须放行 handover：' + JSON.stringify(tcpSocket.responses[0] ?? null))

    // Pipe shape whose server pid is not this pod: enforce closes the
    // connection before any request is parsed.
    const pipeSocket = new FakeSocket('peer-pipe')
    makeHandler({ ok: true, fd: 7, instances: 1, serverPid: process.pid + 1, serverPidMatches: false, client: goodClient })(pipeSocket)
    await tick()
    assertEqual(pipeSocket.ended, true, 'enforce 下管道 serverPid 不匹配必须关闭连接')
    assertEqual(pipeSocket.responses[0]?.error?.code, 'ECLIENTDENIED', '拒绝码必须是 ECLIENTDENIED：' + JSON.stringify(pipeSocket.responses[0] ?? null))
    assert(String(pipeSocket.responses[0]?.error?.message ?? '').includes('server-side'), '拒绝原因应指出 server-side 失败')

    // Flip the file back to warn: the SAME handler now admits the same bad
    // connection (observe-only) and `identify` reports the current mode. This
    // is the "ops writes a file, no restart" promise, end to end.
    writePolicy({ mode: 'warn' })
    const warnSocket = new FakeSocket('peer-pipe-warn')
    makeHandler({ ok: true, fd: 7, instances: 1, serverPid: process.pid + 1, serverPidMatches: false, client: goodClient })(warnSocket)
    warnSocket.request({ op: 'identify', id: 2 })
    await tick()
    assertEqual(warnSocket.ended, false, 'warn 模式不得关闭身份不匹配的连接（只记录）')
    assertEqual(warnSocket.responses[0]?.attestationMode, 'warn', 'identify 必须报告文件刚切换到的模式')

    // Node never exposes a pipe HANDLE, so `describeClient` fails with
    // ENOHANDLE on every real Host connection. Enforce must NOT close those
    // connections (that would prevent identify→attest→handover entirely); the
    // handover nonce gate is the enforcement point.
    writePolicy({ mode: 'enforce' })
    const noHandleSocket = new FakeSocket('peer-no-handle')
    makeHandler({ ok: false, code: 'ENOHANDLE', message: 'socket._handle.fd 不是可用的 Win32 HANDLE（值 -1）' })(noHandleSocket)
    noHandleSocket.request({ op: 'identify', id: 3 })
    await tick()
    assertEqual(noHandleSocket.ended, false, 'ENOHANDLE 不得在 enforce 下关闭连接（否则永远拿不到 nonce）')
    assertEqual(noHandleSocket.responses[0]?.attestationMode, 'enforce', 'identify 仍必须可用')
    noHandleSocket.request({ op: 'handover', id: 4, newToken: TOKEN_C })
    await tick()
    assertEqual(noHandleSocket.responses[1]?.error?.code, 'EUNATTESTED',
      '无句柄时 enforce 仍必须拒绝无 nonce 的 handover：' + JSON.stringify(noHandleSocket.responses[1] ?? null))
  })

  await test('attest 计数：deferred（拿不到句柄）不再冒充 denied（真正被策略拒绝）', () => {
    assertEqual(attestationOutcome({ allowed: true }), 'accepted', 'allowed → accepted')
    assertEqual(attestationOutcome({ allowed: false, deferred: true }), 'deferred', 'deferred 的允许=false 不是拒绝')
    assertEqual(attestationOutcome({ allowed: false, deferred: false }), 'denied', '真拒绝 → denied')
    assertEqual(attestationOutcome(null), 'denied', '没有记录也不得算放行')

    const state = { denied: 0, deferred: 0, lastDeniedAt: null, lastDeferredAt: null, lastAcceptedAt: null }
    // Two ordinary Host connections: both deferred (ENOHANDLE), neither denied.
    recordAttestationOutcome(state, { allowed: false, deferred: true, at: 'T1' })
    recordAttestationOutcome(state, { allowed: false, deferred: true, at: 'T2' })
    assertEqual(state.deferred, 2, '两次正常 Host 连接 = deferred:2')
    assertEqual(state.denied, 0, 'deferred 不得计入 denied')
    assertEqual(state.lastDeferredAt, 'T2', 'lastDeferredAt 记最后一次 deferred')
    assertEqual(state.lastDeniedAt, null, '没有真拒绝时 lastDeniedAt 保持 null')

    recordAttestationOutcome(state, { allowed: false, deferred: false, at: 'T3' })
    assertEqual(state.denied, 1, '真拒绝才 += denied')
    assertEqual(state.lastDeniedAt, 'T3', 'lastDeniedAt 记真拒绝')

    recordAttestationOutcome(state, { allowed: true, deferred: false, at: 'T4' })
    assertEqual(state.denied, 1, '放行不影响 denied')
    assertEqual(state.deferred, 2, '放行不影响 deferred')
    assertEqual(state.lastAcceptedAt, 'T4', 'lastAcceptedAt 记最后一次放行')
  })

  await test('身份通道：同一 PID 的 creationTime 变化必须拒绝并记录（防 PID 复用）', () => {
    let clock = 1_000
    const guard = createPidCreationTimeGuard({ ttlMs: 60_000, now: () => clock })
    const attestation = (creationTime) => ({ ok: true, pid: 4242, client: { pid: 4242, creationTime } })

    const first = guard.check(attestation('111'))
    assertEqual(first.ok, true, '第一次见到该 PID 应放行')
    assertEqual(first.check?.name, 'creation-time', '检查项名字固定')
    assert(String(first.check?.detail).includes('首次见到'), '第一次应标注首次：' + String(first.check?.detail))
    const same = guard.check(attestation('111'))
    assertEqual(same.ok, true, '同一创建时间重复 attest 应放行')
    assert(String(same.check?.detail).includes('未变'), '应说明未变')

    clock += 1_000
    const changed = guard.check(attestation('222'))
    assertEqual(changed.ok, false, '同一 PID 的创建时间变化必须拒绝')
    assertEqual(changed.check?.ok, false, '检查项必须标 false')
    assert(String(changed.check?.detail).includes('PID 复用'), '原因应点名 PID 复用：' + String(changed.check?.detail))
    assert(String(changed.check?.detail).includes('111') && String(changed.check?.detail).includes('222'), '应同时给出旧/新创建时间')
    assertEqual(guard.check(attestation('222')).ok, false, '在 TTL 窗口内持续拒绝，不更新为新的创建时间')

    // The nonce TTL is the risk window: once the old observation ages out the
    // current process behind the PID is admitted again (no permanent lockout).
    clock += 61_000
    assertEqual(guard.check(attestation('222')).ok, true, '超过 TTL 后旧观察过期，当前进程重新放行')

    const unreadable = guard.check({ ok: true, pid: 7, client: { pid: 7 } })
    assertEqual(unreadable.ok, true, '拿不到 creationTime 时不能判拒绝')
    assertEqual(unreadable.check, null, '拿不到 creationTime 时不得伪造一个 ok 检查项')
    const notOk = guard.check({ ok: false, code: 'ENOHANDLE' })
    assertEqual(notOk.check, null, '没有身份事实时不做比较')
  })

  // -------------------------------------------------------------------------
  // launcher.mjs + pod_status.relaunch (static wiring only: never creates a
  // real scheduled task — the machine-level probe stays a manual acceptance)
  // -------------------------------------------------------------------------
  await test('launcher.mjs 存在，schtasks 配方是 Create → Run → Change/DISABLE，且不在 /Run 后立刻 /Delete', () => {
    const launcherPath = join(PKG_ROOT, 'launcher.mjs')
    assert(fs.existsSync(launcherPath), 'launcher.mjs 必须存在：' + launcherPath)
    const source = fs.readFileSync(launcherPath, 'utf8')
    const createAt = source.indexOf("['/Create'")
    const runAt = source.indexOf("['/Run', '/TN', taskName]")
    const disableAt = source.indexOf("const disable = await runCommand(exe, ['/Change'")
    assert(createAt > 0, '必须通过 /Create 注册任务')
    assert(runAt > createAt, '/Run 必须在 /Create 之后')
    assert(disableAt > runAt, '/Change /DISABLE 必须在 /Run 之后立刻执行')
    const betweenRunAndDisable = source.slice(runAt, disableAt)
    assert(
      !betweenRunAndDisable.includes('deleteTask('),
      '/Run 与 /Change /DISABLE 之间不得 /Delete：排队中的实例会被一起丢掉（进程从未启动、永远 running）',
    )
    assert(source.includes("'/DISABLE'"), '/Change 必须带 /DISABLE，防 /ST 整分二次触发')
    assert(source.includes('cached: true'), 'probeSchtasks 必须有进程级缓存')
    assert(source.includes('resetSchtasksProbeCache'), '探测缓存必须有强制重探入口（refresh）')
  })

  await test('launcher 纯函数：任务名稳定、env 白名单、launch.cmd 不含秘密且 .vbs 纯 ASCII', () => {
    const name = taskNameFor('Z:/DSH-Data/profiles/web')
    assert(/^dsh-escape-pod-[0-9a-f]{10}$/.test(name), '任务名形状不符：' + name)
    assertEqual(
      taskNameFor('Z:/DSH-Data/profiles/web/'),
      taskNameFor('z:/dsh-data/profiles/web'),
      '大小写/尾斜杠不得改变同一个 dataRoot 的任务名',
    )
    assert(taskNameFor('Z:/DSH-Data/profiles/other') !== name, '不同 dataRoot 必须得到不同任务名')

    const picked = selectPodEnv({ SystemRoot: 'C:/Windows', PATH: 'C:/x', SECRET_TOKEN: 'nope', PODC_ATTEST: 'warn', DSH_HOME: 'Z:/h' })
    assertEqual(picked.env.SECRET_TOKEN, undefined, 'launch.cmd 不得携带无关 Host 秘密')
    assertEqual(picked.env.PODC_ATTEST, 'warn', 'pod 需要的 PODC_* 必须保留')
    assertEqual(picked.env.DSH_HOME, 'Z:/h', 'pod 需要的 DSH_* 必须保留')

    const templateB64 = Buffer.from(
      JSON.stringify({ a: 'b c', nasty: 'x&y|z<q>^%"s"' }),
      'utf8',
    ).toString('base64url')
    const dir = join(TMP_ROOT, 'launcher-cmd')
    const built = buildLaunchFiles({
      nodeExe: process.execPath,
      podScript: join(PKG_ROOT, 'pod.mjs'),
      podArgs: ['--serve', '--pipe', 'pipe:test', '--template-b64', templateB64],
      env: { SystemRoot: 'C:/Windows', PODC_ATTEST: 'warn', SECRET_TOKEN: 'nope' },
      dataRoot: dir,
    })
    const cmd = fs.readFileSync(built.cmdPath, 'utf8')
    const vbs = fs.readFileSync(built.vbsPath, 'utf8')
    assert(cmd.startsWith('@echo off'), 'launch.cmd 必须以 @echo off 开头')
    assert(cmd.includes('set "PODC_ATTEST=warn"'), '必须带上 pod 需要的 env')
    assert(!cmd.includes('SECRET_TOKEN') && !cmd.includes('nope'), 'launch.cmd 不得包含白名单以外的 env/秘密')
    assert(cmd.includes(process.execPath), 'launch.cmd 必须调用 Host 的 node')
    assert(vbs.includes('CreateObject("WScript.Shell")') && vbs.includes(', 0, False'), 'vbs 必须隐藏窗口且不等待')
    assert(/^[\x00-\x7f]*$/.test(vbs), 'launch.vbs 必须是纯 ASCII（wscript 按 ANSI 读取）')
    assert(/^[A-Za-z0-9_-]+$/.test(templateB64), 'base64url token 必须只含 A-Za-z0-9_-')
    assert(cmd.includes('--template-b64 ' + templateB64), 'launch.cmd 必须原样带上 base64url 模板')
    assert(!cmd.includes('--template-json'), 'schtasks 路径不得再使用 --template-json（cmd 会按引号切分）')
    assertEqual(built.dangerous.length, 0, '生成的 launch.cmd 不应命中 cmd 元字符自检')
    // Argument guard: a path with `&` must be refused before a file is written.
    let guardMessage = ''
    try {
      buildLaunchFiles({
        nodeExe: process.execPath,
        podScript: join(PKG_ROOT, 'pod.mjs'),
        podArgs: ['--workspace', 'C:/R&D/x'],
        env: {},
        dataRoot: join(TMP_ROOT, 'launcher-bad'),
      })
    } catch (error) {
      guardMessage = error instanceof Error ? error.message : String(error)
    }
    assert(
      guardMessage.includes('元字符') && guardMessage.includes('podArgs[1]'),
      '含 cmd 元字符的 argv 必须被拒绝并点名参数：' + guardMessage,
    )
    // Generated diagnostics only; no scheduled task was created or run.
    fs.rmSync(dir, { recursive: true, force: true })
  })

  await test('bootstrap 守门：pod.mjs 声明 --bootstrap-handover，Host 只在 schtasks 路径启用', () => {
    const capability = podSupportsStdinlessBootstrap({ podScript: join(PKG_ROOT, 'pod.mjs') })
    assertEqual(capability.ok, true, 'pod.mjs 必须声明支持 --bootstrap-handover：' + String(capability.reason))
    assert(String(capability.reason).includes('bootstrap'), '能力原因必须点名 bootstrap：' + String(capability.reason))
    const podSource = fs.readFileSync(join(PKG_ROOT, 'pod.mjs'), 'utf8')
    assert(podSource.includes("'--bootstrap-handover'"), 'pod.mjs 必须解析 --bootstrap-handover')
    assert(podSource.includes('BOOTSTRAP_CLAIM_TIMEOUT_MS = 120 * 1000'), 'bootstrap 无人认领窗口必须是 120s')
    assert(podSource.includes("'bootstrap-handover-timeout'"), '120s 无人认领必须 shutdown 自退（exit 0）')
    assert(podSource.includes('auth.isBootstrap()'), '计时器必须只在仍是 bootstrap 时才退出')
    const indexSource = fs.readFileSync(join(PKG_ROOT, 'index.js'), 'utf8')
    assert(indexSource.includes("'--bootstrap-handover'"), 'Host 的 schtasks 路径必须传 --bootstrap-handover')
    assert(indexSource.includes('--template-b64'), 'Host 必须用 base64url 传模板（cmd 不再重解析引号）')
    assert(!indexSource.includes("'--template-json'"), 'Host 不得再使用 --template-json（schtasks 下会被 cmd 切分）')
  })

  await test('bootstrap 鉴权：无初始 token，普通 op 一律 EBADTOKEN；handover 立即允许且完成后回到 token 模式', () => {
    const auth = createPodAuth({ token: null, bootstrapHandover: true, startedAtMs: Date.now() })
    const snapshot = auth.snapshot()
    assertEqual(snapshot.mode, 'bootstrap', 'snapshot.mode 必须是 bootstrap')
    assertEqual(snapshot.tokenSource, 'bootstrap', 'snapshot.tokenSource 必须是 bootstrap')
    assertEqual(snapshot.required, true, 'token 仍是必需的（只是尚未建立）')
    assertEqual(auth.isBootstrap(), true, 'isBootstrap 必须为 true')
    const connection = { peer: 'p', connectedAt: 'T', authenticated: false, tokenFingerprint: null }
    const refused = auth.authorize(connection, { token: TOKEN_A })
    assertEqual(refused.ok, false, 'bootstrap 下任何 token 请求都必须被拒')
    assertEqual(refused.code, 'EBADTOKEN', '必须沿用现有未认证错误码 EBADTOKEN')
    const verdict = auth.handover(connection, { newToken: TOKEN_B })
    assertEqual(verdict.ok, true, 'bootstrap handover 不得再等 grace')
    assertEqual(connection.authenticated, true, 'handover 成功后连接即为已认证')
    assertEqual(auth.isBootstrap(), false, 'handover 成功后必须退出 bootstrap')
    assertEqual(auth.snapshot().mode, 'token', '之后 snapshot.mode 回到 token')
    assertEqual(auth.snapshot().tokenSource, 'bootstrap', 'tokenSource 仍须标 bootstrap（pod_status 可见）')
    assertEqual(auth.authorize(connection, { token: TOKEN_B }).ok, true, '新 token 必须可用')
    assertEqual(BOOTSTRAP_CLAIM_TIMEOUT_MS, 120 * 1000, '无人认领窗口必须是 120s')
    const parsed = parseArgs(['--serve', '--bootstrap-handover', '--template-b64', 'abc'])
    assertEqual(parsed.bootstrapHandover, true, '--bootstrap-handover 必须被解析')
    assertEqual(parsed.templateB64, 'abc', '--template-b64 必须被解析')
    assertEqual(parseArgs(['--serve']).bootstrapHandover, false, '默认不得进入 bootstrap')
  })

  await test('socket 层：bootstrap 下 status 被拒；handover 无 nonce 即使 warn 策略也拒绝，enforce+nonce 才放行', async () => {
    const makeService = (auth) => ({
      bumpGeneration() {},
      touchActivity() {},
      snapshot: () => ({ ok: true, podStartedAt: 'T', auth: auth.snapshot() }),
      async handle(op) {
        return { ok: true, op }
      },
    })
    const policyWarn = { mode: 'warn', userSid: 'S-1-5-21-1-2-3-1001', sessionId: 1, minIntegrityRid: 0x2000, allowRestricted: false, allowedImages: ['Z:/node.exe'] }
    const policyEnforce = { ...policyWarn, mode: 'enforce' }
    const tick = () => new Promise((resolveTick) => setTimeout(resolveTick, 20))
    const makeChannel = (ticket) => ({
      port: () => 45679,
      consume: (nonce) => {
        if (nonce !== ticket) return { ok: false, code: 'EUNATTESTED', message: 'nonce 未登记' }
        return { ok: true, ticket: { pid: 4242, at: Date.now(), allowed: true, checks: [] } }
      },
    })

    // 1) bootstrap: a normal op is unauthenticated, and closes the connection.
    const authWarn = createPodAuth({ token: null, bootstrapHandover: true })
    const handlerWarn = createConnectionHandler(makeService(authWarn), authWarn, {
      clients: new Set(),
      log: () => {},
      attestPolicy: policyWarn,
      identityChannel: makeChannel('warn-ticket'),
    })
    const first = new FakeSocket('bootstrap-status')
    handlerWarn(first)
    first.request({ op: 'status', id: 0 })
    await tick()
    assertEqual(first.responses[0]?.error?.code, 'EBADTOKEN', 'bootstrap 下 status 必须被拒：' + JSON.stringify(first.responses[0] ?? null))
    assertEqual(first.ended, true, '未认证请求必须关闭连接')

    // 2) warn policy: even a valid nonce is refused — a nonce issued under warn
    //    proves no integrity, so bootstrap requires enforce.
    const second = new FakeSocket('bootstrap-warn-handover')
    handlerWarn(second)
    second.request({ op: 'handover', id: 1, newToken: TOKEN_B })
    await tick()
    assertEqual(second.responses[0]?.error?.code, 'EUNATTESTED', 'warn 策略下无 nonce 的 bootstrap handover 必须被拒')
    second.destroy()
    await tick()
    const third = new FakeSocket('bootstrap-warn-nonce')
    handlerWarn(third)
    third.request({ op: 'handover', id: 2, newToken: TOKEN_B, nonce: 'warn-ticket' })
    await tick()
    assertEqual(third.responses[0]?.error?.code, 'EUNATTESTED', 'warn 策略下即使有 nonce 也不能 bootstrap')
    assertEqual(authWarn.isBootstrap(), true, 'warn 下的拒绝不得悄悄建立 token')

    // 3) enforce + redeemed nonce: the only path that may establish an owner.
    const authEnforce = createPodAuth({ token: null, bootstrapHandover: true })
    const handlerEnforce = createConnectionHandler(makeService(authEnforce), authEnforce, {
      clients: new Set(),
      log: () => {},
      attestPolicy: policyEnforce,
      identityChannel: makeChannel('enforce-ticket'),
    })
    const fourth = new FakeSocket('bootstrap-enforce')
    handlerEnforce(fourth)
    fourth.request({ op: 'handover', id: 3, newToken: TOKEN_B, nonce: 'enforce-ticket' })
    await tick()
    assertEqual(fourth.responses[0]?.ok, true, 'enforce+nonce 的 bootstrap handover 必须放行：' + JSON.stringify(fourth.responses[0] ?? null))
    assertEqual(authEnforce.isBootstrap(), false, '放行后不再是 bootstrap')
    fourth.request({ op: 'status', id: 4, token: TOKEN_B })
    await tick()
    assertEqual(fourth.responses[1]?.ok, true, 'handover 后新 token 必须可用')
  })

  await test('launcher.json 三态：auto/direct/schtasks + 损坏回落 auto；direct 不探测', () => {
    const dir = join(TMP_ROOT, 'launcher-config')
    fs.mkdirSync(dir, { recursive: true })
    const write = (value) => fs.writeFileSync(join(dir, 'launcher.json'), value, 'utf8')
    write('{"mode":"direct"}')
    const direct = readLauncherMode(dir)
    assertEqual(direct.mode, 'direct', 'direct 必须被解析')
    assertEqual(direct.source, 'file', '来自文件必须标 source=file')
    const directPlan = planLauncher({ config: direct, probe: null, capability: null, dataRoot: dir })
    assertEqual(directPlan.launcher, 'spawn', 'direct 必须走 detached spawn')
    assertEqual(directPlan.forced, false, 'direct 不是强制 schtasks')

    write('{"mode":"schtasks"}')
    const forced = readLauncherMode(dir)
    assertEqual(forced.mode, 'schtasks', 'schtasks 必须被解析')
    const forcedPlan = planLauncher({ config: forced, probe: { status: 'denied' }, capability: { ok: true }, dataRoot: dir })
    assertEqual(forcedPlan.launcher, 'schtasks', 'schtasks 模式即使探测被拒也要尝试')
    assertEqual(forcedPlan.forced, true, 'schtasks 模式必须标记 forced（失败不回落）')
    assert(forcedPlan.warnings.some((warning) => warning.includes('强制')), '强制模式必须给出告警')

    write('{"mode":"nonsense"}')
    const broken = readLauncherMode(dir)
    assertEqual(broken.mode, 'auto', '非法 mode 必须回落 auto')
    assert(String(broken.warning).includes('非法'), '非法 mode 必须给出 warning')
    write('{not-json')
    assertEqual(readLauncherMode(dir).mode, 'auto', '坏 JSON 必须回落 auto')

    fs.rmSync(join(dir, 'launcher.json'))
    assertEqual(readLauncherMode(dir).mode, 'auto', '缺文件默认 auto')
    assertEqual(readLauncherMode(dir).source, 'default', '缺文件 source=default')

    const autoPlan = planLauncher({
      config: { mode: 'auto', source: 'default', path: null, warning: null },
      probe: { status: 'ok' },
      capability: { ok: true },
      dataRoot: dir,
    })
    assertEqual(autoPlan.launcher, 'schtasks', 'auto + probe ok + 能力 ok 必须走 schtasks')
    const indexSource = fs.readFileSync(join(PKG_ROOT, 'index.js'), 'utf8')
    const directGuardAt = indexSource.indexOf("if (config.mode !== 'direct')")
    const probeAt = indexSource.indexOf('probeSchtasks', directGuardAt)
    assert(directGuardAt > 0 && probeAt > directGuardAt, 'direct 模式必须在 probeSchtasks 之前短路：不探测、不建任务')
    fs.rmSync(dir, { recursive: true, force: true })
  })

  await test('自愈：两轮/8s 阈值，最多清 1 次', () => {
    assertEqual(shouldRecoverUnresponsivePod({ rounds: 1, elapsedMs: 1000, recoveries: 0 }), false, '第一轮不足 8s 不得清理')
    assertEqual(shouldRecoverUnresponsivePod({ rounds: 2, elapsedMs: 1000, recoveries: 0 }), true, '第二轮必须触发清理')
    assertEqual(shouldRecoverUnresponsivePod({ rounds: 1, elapsedMs: 8000, recoveries: 0 }), true, '累计 8s 必须触发清理')
    assertEqual(shouldRecoverUnresponsivePod({ rounds: 9, elapsedMs: 90000, recoveries: 1 }), false, '同一 incident 最多清 1 次')
    const indexSource = fs.readFileSync(join(PKG_ROOT, 'index.js'), 'utf8')
    assert(indexSource.includes('recover: killed unresponsive pod pid='), '清理必须留下明确日志')
    assert(indexSource.includes('process.kill(pid, 0)'), '杀前必须用 process.kill(pid, 0) 预检')
    assert(indexSource.includes('process.kill(pid)'), '必须用 process.kill 结束（不要 taskkill）')
    assert(indexSource.includes('podStartedAt 与记录不一致'), '必须做 podStartedAt 交叉核对（pid 复用）')
  })

  await test('pod_status：有 launcher/task/schtasks 字段，relaunch 有 running-job 守卫与 force 逃生口', () => {
    const indexSource = fs.readFileSync(join(PKG_ROOT, 'index.js'), 'utf8')
    for (const needle of ['launcherMode=', 'launcher=', 'task=', 'schtasks=']) {
      assert(indexSource.includes(needle), 'pod_status 普通输出必须含：' + needle)
    }
    assert(
      indexSource.includes('launcher: launcherState === null ? null : launcherState.launcher'),
      'pod_status 的结构化结果必须含 launcher 字段',
    )
    assert(indexSource.includes("action === 'relaunch'"), 'pod_status 必须接受 action:"relaunch"')
    assert(indexSource.includes('force: args?.force === true'), '只有显式 force:true 才能强杀')
    assert(indexSource.includes("'ERELAUNCHBUSY'"), 'relaunch 必须拒绝还有 running job 的 pod')
    assert(indexSource.includes('runningJobs.length > 0 && !force'), 'relaunch 的 running-job/force 守卫必须存在')
    assert(indexSource.includes('process.kill('), 'relaunch 必须用 process.kill（不要 spawn taskkill）')
    assert(!indexSource.includes("'taskkill'") && !indexSource.includes('"taskkill"'), 'index.js 不得 spawn taskkill')
  })

  await test('pod_status：launcher/task/schtasks 来自 Host 状态；action=relaunch 只透传 force', async () => {
    /** @type {any[]} */
    const relaunchCalls = []
    const launcherState = {
      launcher: 'spawn',
      taskName: null,
      schtasksProbe: 'ok',
      mode: 'auto',
      modeSource: 'default',
      forced: false,
      warnings: ['schtasks 可用，但 pod.mjs 仍只从 stdin 读 token'],
      at: '2026-10-30T00:00:00.000Z',
      taskDeleted: false,
    }
    /** @returns {any} */
    const fakePod = () => ({
      stateDir: TMP_ROOT,
      pipeName: 'launcher-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      launcher: () => launcherState,
      /** @param {any} _hint @param {{ force?: boolean }} options */
      async relaunch(_hint, options) {
        relaunchCalls.push(options)
        return { ok: true, killedPid: 4242, forced: options?.force === true, runningBefore: 0, launcher: launcherState }
      },
      async status() {
        return {
          response: {
            podPid: 77,
            podStartedAt: '2026-10-29T00:00:00.000Z',
            generation: 1,
            podVersion: '1.7.0',
            protocolVersion: 2,
            pipeName: 'launcher-pipe',
            enforcement: 'partial',
            template: { valid: false, code: 'ETEMPLATE', reason: 'selftest' },
            workspaceRoot: WORKSPACE,
            dataRoot: TMP_ROOT,
            identity: null,
            auth: null,
            attestation: null,
            running: 0,
            jobs: [],
            outputChunkBytes: 64000,
            maxOutputChunkBytes: MAX_OUTPUT_CHUNK_BYTES,
          },
          bootstrapError: null,
        }
      },
    })
    const ctx = { get: () => undefined }
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const tools = createTools(fakePod(), () => null, { outputChunkBytes: 64000, modelOutputLimitBytes: 0 }, null, () => {}, ctx)
    const statusTool = tools.find((candidate) => candidate.name === 'pod_status')
    const value = await statusTool.execute({}, exec)
    assertEqual(value.launcher, 'spawn', '结构化结果必须带 launcher')
    assertEqual(value.task, null, 'spawn 路径没有计划任务')
    assertEqual(value.schtasksProbe, 'ok', 'probe 结果必须透传')
    assertEqual(value.launcherMode, 'auto', '结构化结果必须带 launcherMode')
    assert(value.message.includes('launcherMode=auto（默认）'), '普通输出必须有 launcherMode= 行')
    assert(value.message.includes('launcher=spawn'), '普通输出必须有 launcher= 行')
    assert(value.message.includes('task=（无；launcher=spawn'), '普通输出必须有 task= 行')
    assert(value.message.includes('schtasks=ok（schtasks 可用'), '普通输出必须有 schtasks= 行与警告')
    assertEqual(relaunchCalls.length, 0, '只读 status 不得触发 relaunch')

    const restarted = await statusTool.execute({ action: 'relaunch', force: true }, exec)
    assertEqual(relaunchCalls.length, 1, 'action=relaunch 必须调用 pod.relaunch')
    assertEqual(relaunchCalls[0].force, true, 'force:true 必须透传')
    assertEqual(restarted.relaunch.killedPid, 4242, 'relaunch 结果必须带回被杀 pid')
    assert(restarted.message.includes('relaunch=已重启'), '普通输出必须说明发生过 relaunch')
  })

  // -------------------------------------------------------------------------
  // Freeze / thaw (design: pod/research/逃生舱-冻结方案.md, decisions in §7)
  // -------------------------------------------------------------------------
  const freezeJobId = 'podc-frz0-abcdef01'

  /**
   * A fake Win32 freeze surface: drives the controller's real state machine
   * (timers, watchdog, ledger records) without a process or a job object.
   * @param {Record<string, any>} [overrides]
   */
  function makeFreezeApi(overrides = {}) {
    const calls = { freeze: [], suspend: [], resume: [], close: [] }
    return {
      calls,
      createJob: () => 'job-handle',
      getLastError: () => 0,
      setFreeze: (_job, value) => {
        calls.freeze.push(value)
        return { ok: true, win32: 0 }
      },
      queryFreeze: () => ({ ok: true, win32: 0, frozen: true, flags: 7 }),
      assignRunner: () => ({ ok: true, stage: 'Assigned', win32: 0 }),
      pidInJob: () => false,
      descendantsOf: () => [],
      suspendProcess: (pid) => {
        calls.suspend.push(pid)
        return { ok: true, pid, handle: 'h-' + String(pid) }
      },
      resumeProcess: (handle) => {
        calls.resume.push(handle)
        return 0
      },
      close: (handle) => {
        calls.close.push(handle)
        return true
      },
      ...overrides,
    }
  }

  /** @param {Record<string, any>} [overrides] */
  function makeFreezeRec(overrides = {}) {
    return {
      jobId: freezeJobId,
      diskOnly: false,
      finalized: false,
      child: {},
      runnerPid: 111,
      jobHandle: null,
      status: 'running',
      timeoutMs: null,
      timeoutTimer: null,
      deadlineAtMs: null,
      deadlineRemainingMs: null,
      freezeState: 'none',
      frozenAt: null,
      frozenAtMs: null,
      freezeBy: null,
      freezeCount: 0,
      freezeMaxMs: null,
      freezePodGeneration: 'pg-freeze',
      frozenMsTotal: 0,
      freezeWatchdogTimer: null,
      suspendedProcs: [],
      killedWhileFrozen: false,
      ...overrides,
    }
  }

  await test('冻结探测：注入失败不阻止启动，status 如实标 unsupported（含原因）', async () => {
    const probeRoot = join(TMP_ROOT, 'freeze-probe-ledger')
    const service = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: probeRoot,
      pipeName: pipeName + '-freeze-probe',
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template,
      unsafeAllowDataRootInsideWorkspace: true,
      // Test seam: the real probe reads koffi and the OS. The requirement is
      // that a FAILED probe is inert, so inject one.
      freezeProbe: () => ({ supported: false, reason: 'injected probe failure' }),
      log: () => {},
    })
    service.init()
    const status = await service.handle('status', {})
    assertEqual(status.ok, true, '探测失败不得影响 status')
    assertEqual(status.freeze.supported, false, 'status.freeze.supported 必须如实')
    assertEqual(status.freeze.state, 'unsupported', 'state=unsupported')
    assert(String(status.freeze.reason).includes('injected probe failure'), '必须带原因：' + JSON.stringify(status.freeze))
    assertEqual(status.freeze.defaultMaxFreezeMs, FREEZE_DEFAULT_MAX_MS, '默认看门狗 30 分钟（1800000ms）')
    assertEqual(typeof status.podGeneration, 'string', 'podGeneration 是进程实例 id（字符串）')
    // The execution path is untouched: a run fails only the way this restricted
    // shell always fails spawn (EPERM), never because freeze is unavailable.
    const run = await service.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      sessionId: 'session-alpha',
    })
    assertEqual(run.ok, false, '受限 shell 里 spawn 应失败')
    assertEqual(run.error.code, 'ESPAWNFAILED', '失败原因仍是 spawn 失败，不是冻结探测')
    assert(typeof run.jobId === 'string', '失败也要先落账本 jobId')
    const after = await service.handle('status', {})
    assertEqual(after.freeze.supported, false, '失败的 run 不得改变探测结果')
    // The freeze op must not pretend: a ledger-only/never-handled job is ENOTHANDLE.
    const refused = await service.handle('freeze', { jobId: run.jobId, action: 'freeze', sessionId: 'session-alpha' })
    assertEqual(refused.ok, false, '没有句柄时 freeze 必须失败')
    assert(FREEZE_ERROR_CODES.includes(refused.error.code), '错误码必须属于冻结错误词汇：' + refused.error.code)
    await service.shutdown('selftest done')
  })

  await test('meta.json.freeze：六字段白名单；handle / suspendedProcs 永不入账本', () => {
    // `meta.json.freeze` has EXACTLY these six keys. Exported whitelist, so the
    // assertion here is on the same function the pod writes with.
    const record = freezeLedgerFields({
      state: 'frozen',
      since: '2026-10-30T00:00:00.000Z',
      by: 'session-a',
      podPid: 4242,
      podGeneration: 'pod-1-abc',
      count: 3,
    })
    assertEqual(
      JSON.stringify(Object.keys(record)),
      JSON.stringify(['state', 'since', 'by', 'podPid', 'podGeneration', 'count']),
      'meta.json.freeze 的键必须正好是这六个',
    )
    assertEqual(record.state, 'frozen', 'state 原样')
    assertEqual(record.count, 3, 'count 原样')
    assertEqual(freezeLedgerFields({ state: 'none', since: 'x', by: '' }).since, null, '非 frozen 时 since 必须归 null')
    assertEqual(freezeLedgerFields({ state: 'none', by: '' }).by, null, '空 by 归 null')
    assertEqual(freezeLedgerFields({}).count, 0, '缺省 count=0')
    // The pod must never persist a handle; JSON-serializable is the cheap proof
    // that no BigInt handle leaked into the record.
    const text = JSON.stringify(record)
    assertEqual(/#|handle|suspended/i.test(text), false, 'freeze 记录不得含句柄字样：' + text)
    assertEqual(text.includes('undefined'), false, 'freeze 记录必须是无损 JSON')
    // A hand-edited ledger may contain junk; the projection drops it instead of
    // passing it through to the status row.
    const readBack = metaFreezeOf({ freeze: { ...record, jobHandle: 1234, suspendedProcs: [1] } })
    assertEqual(
      JSON.stringify(Object.keys(readBack)),
      JSON.stringify(['state', 'since', 'by', 'podPid', 'podGeneration', 'count']),
      'metaFreezeOf 必须只保留白名单字段',
    )
    assertEqual(readBack.jobHandle, undefined, '读回时不得保留 jobHandle')
    assertEqual(readBack.suspendedProcs, undefined, '读回时不得保留 suspendedProcs')
    assertEqual(metaFreezeOf({}), null, '没有 freeze 字段时返回 null')
    // The controller hands this exact record to the pod (the only meta writer).
    const metaRecords = []
    const controller = createFreezeController({
      log: () => {},
      api: makeFreezeApi(),
      podGeneration: 'pod-1-abc',
      probe: () => ({ supported: true }),
      onStateChange: (_rec, value) => metaRecords.push(value),
    })
    const rec = makeFreezeRec()
    controller.createJob(rec)
    controller.freeze(rec, { by: 'session-a', maxFreezeMs: 60_000 })
    assertEqual(
      JSON.stringify(Object.keys(metaRecords[0])),
      JSON.stringify(['state', 'since', 'by', 'podPid', 'podGeneration', 'count']),
      '控制器写账本的记录必须是同一套六字段',
    )
    const exitScan = (value, path = '') => {
      if (value === null || typeof value !== 'object') return []
      return Object.entries(value).flatMap(([key, child]) => [
        ...(/handle|suspended/i.test(key) ? [path + key] : []),
        ...exitScan(child, path + key + '.'),
      ])
    }
    assertEqual(exitScan(record).length, 0, 'freeze 记录里不得出现任何句柄键')
    controller.settle(rec)
  })

  await test('maxFreezeMs：默认 30 分钟，0/NaN/负数取默认，超大值 clamp', () => {
    assertEqual(FREEZE_DEFAULT_MAX_MS, 30 * 60 * 1000, '默认看门狗必须是 30 分钟')
    assertEqual(freezeMaxOf({}), FREEZE_DEFAULT_MAX_MS, '缺省 = 30 分钟')
    assertEqual(freezeMaxOf({ maxFreezeMs: 0 }), FREEZE_DEFAULT_MAX_MS, '0 = 用 pod 默认（不是"无限"）')
    assertEqual(freezeMaxOf({ maxFreezeMs: Number.NaN }), FREEZE_DEFAULT_MAX_MS, 'NaN = 默认')
    assertEqual(freezeMaxOf({ maxFreezeMs: -1 }), FREEZE_DEFAULT_MAX_MS, '负数 = 默认')
    assertEqual(freezeMaxOf({ maxFreezeMs: '60000' }), FREEZE_DEFAULT_MAX_MS, '字符串 = 默认')
    assertEqual(freezeMaxOf({ maxFreezeMs: 5000 }), 5000, '正常值原样')
    assertEqual(freezeMaxOf({ maxFreezeMs: 1e12 }), FREEZE_MAX_MS, '超过 setTimeout 32 位上限必须 clamp')
    assert(FREEZE_MAX_MS <= 2 ** 31 - 1, 'clamp 上限必须落在 setTimeout 可表示范围内')
    assertEqual(FREEZE_ERROR_CODES.includes('EFREEZEUNSUPPORTED'), true, '错误码词汇必须含 EFREEZEUNSUPPORTED')
    assertEqual(FREEZE_ERROR_CODES.includes('EOSFAIL'), true, '错误码词汇必须含 EOSFAIL')
    // The controller applies the same normalization (single source of truth).
    const controller = createFreezeController({
      log: () => {},
      api: makeFreezeApi(),
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
    })
    const rec = makeFreezeRec()
    controller.createJob(rec)
    const outcome = controller.freeze(rec, { maxFreezeMs: 0 })
    assertEqual(outcome.maxFreezeMs, FREEZE_DEFAULT_MAX_MS, 'pod 侧同样按默认值执行')
    assertEqual(controller.view(rec).remainingFreezeMs <= FREEZE_DEFAULT_MAX_MS, true, '剩余时间不得超过上限')
    controller.settle(rec)
  })

  await test('冻结暂停超时计时器；解冻后按剩余量重挂（不会被立刻杀掉）', async () => {
    /** @type {string[]} */
    const deadlines = []
    const api = makeFreezeApi()
    const controller = createFreezeController({
      log: () => {},
      api,
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
      onDeadline: (rec) => deadlines.push(rec.jobId),
    })
    const rec = makeFreezeRec({ timeoutMs: 120 })
    controller.createJob(rec)
    assertEqual(controller.armDeadline(rec, 120), true, '应先挂上 120ms 超时')
    const frozen = controller.freeze(rec, { by: 'session-a', maxFreezeMs: 60_000 })
    assertEqual(frozen.ok, true, '冻结应成功')
    assertEqual(rec.timeoutTimer, null, '冻结必须 clearTimeout 计时器')
    assert(rec.deadlineRemainingMs > 0 && rec.deadlineRemainingMs <= 120, '必须记下剩余预算：' + String(rec.deadlineRemainingMs))
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 260))
    assertEqual(deadlines.length, 0, '冻结期间超时计时器不得触发（否则解冻瞬间就被杀）')
    assertEqual(rec.freezeState, 'frozen', '期间应保持冻结')
    const thawed = controller.thaw(rec, 'manual')
    assertEqual(thawed.ok, true, '解冻应成功')
    assertEqual(rec.timeoutTimer === null, false, '解冻必须按剩余量重挂计时器')
    assert(rec.deadlineRemainingMs > 0 && rec.deadlineRemainingMs <= 120, '重挂后剩余量必须还是原来剩下的预算：' + String(rec.deadlineRemainingMs))
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 260))
    assertEqual(deadlines.length, 1, '解冻后剩余预算应该继续走完并触发一次超时')
    rec.finalized = true
    controller.settle(rec)
  })

  await test('maxFreezeMs 看门狗：到点自动解冻并记日志，不杀命令', async () => {
    /** @type {string[]} */
    const logs = []
    /** @type {string[]} */
    const deadlines = []
    const api = makeFreezeApi()
    const controller = createFreezeController({
      log: (message) => logs.push(message),
      api,
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
      onDeadline: (rec) => deadlines.push(rec.jobId),
    })
    const rec = makeFreezeRec({ timeoutMs: 60_000 })
    controller.createJob(rec)
    const frozen = controller.freeze(rec, { by: 'session-a', maxFreezeMs: 60 })
    assertEqual(frozen.ok, true, '冻结应成功')
    assertEqual(rec.freezeState, 'frozen', '先冻结')
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 280))
    assertEqual(rec.freezeState, 'none', '看门狗到点必须自动解冻')
    assertEqual(typeof rec.autoThawedAt, 'string', '必须记下自动解冻时刻')
    assert(logs.some((line) => line.includes('看门狗') && line.includes('自动解冻')), '必须留一条看门狗日志：' + JSON.stringify(logs))
    assertEqual(deadlines.length, 0, '看门狗只解冻，不杀命令')
    assertEqual(api.calls.freeze.join(','), 'true,false', '内核调用必须是 freeze 后 thaw')
    assertEqual(controller.view(rec).state, 'none', '投影状态回到 none')
    rec.finalized = true
    controller.settle(rec)
  })

  await test('pod_exec 的 Host 兜底超时：冻结期间按 pod 剩余预算重锚，不杀被冻结的命令', () => {
    const before = Date.now()
    assertEqual(hostFallbackDeadline(1234, { frozen: false }), 1234, '未冻结：兜底截止时刻不变')
    assertEqual(hostFallbackDeadline(1234, {}), 1234, '旧 pod（没有 frozen 字段）：不变')
    assertEqual(hostFallbackDeadline(1234, { frozen: true, remainingTimeoutMs: null }), 1234, '冻结但没有剩余预算：不猜，保持原截止时刻')
    assertEqual(hostFallbackDeadline(1234, { frozen: true, remainingTimeoutMs: -1 }), 1234, '负数剩余预算无效')
    assertEqual(hostFallbackDeadline(0, { frozen: true, remainingTimeoutMs: 50_000 }), 0, '本来没有兜底期限（0）时不得凭空造一个')
    const extended = hostFallbackDeadline(1, { frozen: true, remainingTimeoutMs: 50_000 })
    assert(extended > before + 49_000 && extended < before + 52_000, '冻结时应重锚到 now+剩余预算+grace：' + String(extended - before))
  })

  await test('冻结原语：EOSFAIL 不改变状态；thaw 失败保持冻结并留看门狗；settle 记账', async () => {
    const failingFreeze = makeFreezeApi({ setFreeze: () => ({ ok: false, win32: 87 }) })
    const controller = createFreezeController({
      log: () => {},
      api: failingFreeze,
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
    })
    const rec = makeFreezeRec()
    controller.createJob(rec)
    const failed = controller.freeze(rec, { maxFreezeMs: 60_000 })
    assertEqual(failed.ok, false, '内核拒绝必须如实失败')
    assertEqual(failed.code, 'EOSFAIL', 'Win32 失败必须是 EOSFAIL')
    assertEqual(failed.win32, 87, '必须带回 Win32 码')
    assertEqual(rec.freezeState, 'none', '失败即完全没冻（内核语义）')
    assertEqual(rec.freezeCount, 0, '失败不计入冻结次数')

    // Thaw failure: stay frozen and keep the watchdog armed, so it can retry.
    let allowFreeze = true
    const flaky = makeFreezeApi({ setFreeze: () => (allowFreeze ? { ok: true, win32: 0 } : { ok: false, win32: 5 }) })
    const controller2 = createFreezeController({
      log: () => {},
      api: flaky,
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
    })
    const rec2 = makeFreezeRec({ jobId: 'podc-frz1-abcdef02' })
    controller2.createJob(rec2)
    controller2.freeze(rec2, { maxFreezeMs: 60_000 })
    allowFreeze = false
    const thawFailed = controller2.thaw(rec2, 'manual')
    assertEqual(thawFailed.ok, false, '解冻失败必须如实失败')
    assertEqual(thawFailed.code, 'EOSFAIL', '解冻失败也是 EOSFAIL')
    assertEqual(rec2.freezeState, 'frozen', '解冻失败必须保持冻结（半解冻更糟）')
    assertEqual(rec2.freezeWatchdogTimer === null, false, '看门狗必须仍挂着')
    allowFreeze = true
    assertEqual(controller2.thaw(rec2, 'manual').ok, true, '恢复后应能解冻')

    // settle: an open episode is counted, the handle is closed, the meta record
    // is reset to state none (a finished job must not look frozen forever).
    const records = []
    const controller3 = createFreezeController({
      log: () => {},
      api: makeFreezeApi(),
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
      onStateChange: (_rec, value) => records.push(value),
    })
    const rec3 = makeFreezeRec({ jobId: 'podc-frz2-abcdef03', killedWhileFrozen: true })
    controller3.createJob(rec3)
    controller3.freeze(rec3, { by: 'session-a', maxFreezeMs: 60_000 })
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 80))
    const stats = controller3.settle(rec3)
    assert(stats.frozenMs >= 50, '结算必须计入仍在进行的冻结时长：' + String(stats.frozenMs))
    assertEqual(stats.freezeCount, 1, 'freezeCount=1')
    assertEqual(stats.killedWhileFrozen, true, 'killedWhileFrozen 必须透传')
    assertEqual(rec3.jobHandle, null, 'settle 必须关闭并清空句柄')
    assertEqual(rec3.freezeState, 'none', 'settle 后状态归 none')
    assertEqual(records.at(-1).state, 'none', '结算必须把 meta.freeze 重置为 none')

    // A runner that cannot be put into the pod's job must be visible in status:
    // this is the "supported but every freeze returns ENOTHANDLE" case.
    const failingAssign = makeFreezeApi({ assignRunner: () => ({ ok: false, stage: 'AssignProcessToJobObject', win32: 5 }) })
    const controller4 = createFreezeController({
      log: () => {},
      api: failingAssign,
      podGeneration: 'pg-freeze',
      probe: () => ({ supported: true }),
    })
    const rec4 = makeFreezeRec({ jobId: 'podc-frz8-abcdef09' })
    controller4.createJob(rec4)
    assertEqual(controller4.attachRunner(rec4, 111), false, '赋值失败必须返回 false')
    assertEqual(rec4.jobHandle, null, '赋值失败必须丢弃句柄（不能假装能冻）')
    assertEqual(controller4.lastAttachFailure().win32, 5, '必须记下赋值失败的 Win32 码，供 pod_status 显示')
    assertEqual(controller4.lastAttachFailure().stage, 'AssignProcessToJobObject', '必须记下失败阶段')
    assertEqual(controller4.lastAttachFailure().runnerPid, 111, '必须记下失败时的 runnerPid')
    controller4.settle(rec4)
  })

  await test('frozen-orphan：账本标 frozen 且没有本 pod 的句柄 → thawable=false，只能 kill', async () => {
    const orphanRoot = join(TMP_ROOT, 'freeze-orphan-ledger')
    const orphanJob = 'podc-frz3-abcdef04'
    const orphanDir = join(orphanRoot, 'jobs', orphanJob)
    fs.mkdirSync(orphanDir, { recursive: true })
    fs.writeFileSync(join(orphanDir, 'out.log'), Buffer.from('partial\\n', 'utf8'))
    jsonWrite(join(orphanDir, 'meta.json'), {
      schema: 1,
      jobId: orphanJob,
      sessionId: 'session-alpha',
      command: 'frozen orphan probe',
      startedAt: new Date().toISOString(),
      freeze: freezeLedgerFields({
        state: 'frozen',
        since: new Date(Date.now() - 60_000).toISOString(),
        by: 'session-alpha',
        podPid: 9999,
        podGeneration: 'dead-pod-instance',
        count: 2,
      }),
    })
    const orphanService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: orphanRoot,
      pipeName: pipeName + '-freeze-orphan',
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    orphanService.init()
    const status = await orphanService.handle('status', {})
    const row = status.jobs.find((job) => job.jobId === orphanJob)
    assertEqual(row.status, 'frozen-orphan', '没有 exit.json 的冻结账本必须标 frozen-orphan')
    assertEqual(row.freeze.state, 'frozen', 'freeze.state=frozen')
    assertEqual(row.freeze.thawable, false, 'pod 重启后不可解冻')
    assertEqual(row.freeze.orphan, true, '必须是 orphan')
    assertEqual(row.freeze.count, 2, '冻结次数从账本读回')
    assertEqual(row.freeze.podGeneration, 'dead-pod-instance', '账本记录的 podGeneration 如实投影')

    const freezeRefused = await orphanService.handle('freeze', { jobId: orphanJob, action: 'freeze', sessionId: 'session-alpha' })
    assertEqual(freezeRefused.ok, false, '孤儿冻结必须失败')
    assertEqual(freezeRefused.error.code, 'ENOTHANDLE', 'pod 重启后只有账本 → ENOTHANDLE')
    const thawRefused = await orphanService.handle('thaw', { jobId: orphanJob, sessionId: 'session-alpha' })
    assertEqual(thawRefused.error?.code, 'ENOTHANDLE', 'thaw 别名同样 ENOTHANDLE')
    // `output` must expose the freeze facts: the foreground watcher re-anchors
    // its fallback deadline from them, and pod_output renders nothing else.
    const orphanOutput = await orphanService.handle('output', { jobId: orphanJob, from: 0, sessionId: 'session-alpha' })
    assertEqual(orphanOutput.frozen, true, 'output 必须带 frozen 布尔')
    assertEqual(orphanOutput.freeze.state, 'frozen', 'output 必须带 freeze 投影')
    assertEqual(orphanOutput.remainingTimeoutMs, null, '账本记录没有暂停中的预算 → null（Host 不重锚）')
    const killAllowed = await orphanService.handle('kill', { jobId: orphanJob, sessionId: 'session-alpha' })
    assertEqual(killAllowed.ok, true, '唯一的清理途径 pod_kill 必须允许（对已结束/未知 job 如实返回 killed=false）')
    assertEqual(killAllowed.killed, false, '不得假装杀掉')
    await orphanService.shutdown('selftest done')

    // A FINISHED job with a stale `frozen` in meta is not an orphan: exit.json
    // is authoritative, and a settled job cannot be "stuck".
    jsonWrite(join(orphanDir, 'exit.json'), {
      schema: 1,
      jobId: orphanJob,
      status: 'settled',
      exitCode: 0,
      signal: null,
      startedAt: new Date(Date.now() - 120_000).toISOString(),
      endedAt: new Date(Date.now() - 60_000).toISOString(),
      durationMs: 60_000,
      totalBytes: 8,
      lossy: false,
      writeErrors: 0,
      frozenMs: 1000,
      freezeCount: 2,
      killedWhileFrozen: false,
    })
    const settledService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: orphanRoot,
      pipeName: pipeName + '-freeze-orphan-settled',
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template: null,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    settledService.init()
    const settledStatus = await settledService.handle('status', {})
    const settledRow = settledStatus.jobs.find((job) => job.jobId === orphanJob)
    assertEqual(settledRow.status, 'settled', '有 exit.json 时状态以 exit.json 为准，不标 orphan')
    assertEqual(settledRow.freeze.state, 'none', '已结束的 job 不得仍报 frozen')
    assertEqual(settledRow.freeze.thawable, false, '已结束的 job 不可冻结/解冻')
    await settledService.shutdown('selftest done')

    // Same pod generation, but still a disk-only record: the handle is the real
    // proof of thawability, not the generation string.
    const samePodRow = freezeRowOf(
      { diskOnly: true, freezeState: 'frozen', freezePodGeneration: 'pg-freeze', freezeCount: 1 },
      { podGeneration: 'pg-freeze' },
    )
    assertEqual(samePodRow.thawable, false, '没有活句柄就绝不可解冻（哪怕 generation 相同）')
    assertEqual(samePodRow.orphan, true, '同样是 orphan')
    // A live record with a handle in the same pod IS thawable.
    const liveRow = freezeRowOf(
      { diskOnly: false, finalized: false, freezeState: 'frozen', freezePodGeneration: 'pg-freeze', jobHandle: 123n, freezeMaxMs: 60_000, frozenAtMs: Date.now() },
      { podGeneration: 'pg-freeze' },
    )
    assertEqual(liveRow.thawable, true, '本 pod 持有句柄时可解冻')
    assertEqual(liveRow.orphan, false, '不是 orphan')
  })

  await test('pod freeze op：EBADJOBID/ENOJOB/EFOREIGNJOB/adopt/ENOTRUNNING 与 owner 不泄露', async () => {
    const opRoot = join(TMP_ROOT, 'freeze-op-ledger')
    const opService = createPodService({
      workspaceRoot: WORKSPACE,
      dataRoot: opRoot,
      pipeName: pipeName + '-freeze-op',
      idleExitMs: 60_000,
      ringBytes: 4096,
      outputChunkBytes: 16,
      template,
      unsafeAllowDataRootInsideWorkspace: true,
      log: () => {},
    })
    opService.init()
    // In this restricted shell spawn fails, which is enough: the record is live
    // (diskOnly=false) and finalized, so the op reaches ENOTRUNNING.
    const run = await opService.handle('run', {
      prefix: validPrefix,
      argv: [process.execPath, '-e', '1'],
      cwd: WORKSPACE,
      sessionId: 'session-alpha',
    })
    const jobId = run.jobId
    assert(typeof jobId === 'string', 'run 必须先落 jobId')
    const badId = await opService.handle('freeze', { jobId: '../../etc', action: 'freeze', sessionId: 'session-alpha' })
    assertEqual(badId.error.code, 'EBADJOBID', '形状不合法 → EBADJOBID')
    const missing = await opService.handle('freeze', { jobId: 'podc-none0-abcdef01', action: 'freeze', sessionId: 'session-alpha' })
    assertEqual(missing.error.code, 'ENOJOB', '账本里没有 → ENOJOB')
    const foreign = await opService.handle('freeze', { jobId, action: 'freeze', sessionId: 'session-beta' })
    assertEqual(foreign.error.code, 'EFOREIGNJOB', '跨会话默认拒绝')
    assertEqual(String(foreign.error.message).includes('adopt: true'), true, '拒绝消息必须说明 adopt: true')
    assertEqual(String(foreign.error.message).includes('session-alpha'), false, '拒绝消息不得泄露原会话 id')
    const foreignThaw = await opService.handle('thaw', { jobId, sessionId: 'session-beta' })
    assertEqual(foreignThaw.error.code, 'EFOREIGNJOB', 'thaw 别名同样受会话边界约束')
    const adopted = await opService.handle('freeze', { jobId, action: 'freeze', sessionId: 'session-beta', adopt: true })
    assertEqual(adopted.error.code, 'ENOTRUNNING', 'adopt:true 越过归属后到达真实状态：job 已结束')
    const own = await opService.handle('freeze', { jobId, action: 'freeze', sessionId: 'session-alpha' })
    assertEqual(own.error.code, 'ENOTRUNNING', '本会话对已结束 job 也是 ENOTRUNNING')
    const thaw = await opService.handle('freeze', { jobId, action: 'thaw', sessionId: 'session-alpha' })
    assertEqual(thaw.error.code, 'ENOTRUNNING', 'action=thaw 对已结束 job 同样是 ENOTRUNNING')
    await opService.shutdown('selftest done')
  })

  await test('pod_freeze 工具：schema、adopt/maxFreezeMs 透传、错误码不伪造', async () => {
    const calls = []
    const JOB = 'podc-frz4-abcdef05'
    const { PodError } = __internals
    const fakePod = {
      stateDir: TMP_ROOT,
      pipeName: 'freeze-tool-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async freeze(_hint, request) {
        calls.push(request)
        if (request.jobId === 'podc-frz5-abcdef06') throw new PodError('冻结被拒绝（测试）', 'EFOREIGNJOB')
        return {
          ok: true,
          op: 'freeze',
          jobId: request.jobId,
          action: request.action,
          frozen: request.action === 'freeze',
          frozenAt: request.action === 'freeze' ? '2026-10-30T00:00:00.000Z' : null,
          frozenForMs: request.action === 'freeze' ? 0 : 5000,
          remainingFreezeMs: request.action === 'freeze' ? 1_800_000 : null,
          maxFreezeMs: request.action === 'freeze' ? 1_800_000 : null,
          freezeCount: 1,
          thawable: request.action === 'freeze',
          alreadyFrozen: false,
          alreadyThawed: request.action !== 'freeze',
          sessionId: 'me',
          ...(request.adopt === true ? { adoptedFrom: 'owner-x' } : {}),
        }
      },
    }
    const tools = createTools(fakePod, () => null, { outputChunkBytes: 65536, modelOutputLimitBytes: 1024 }, null, () => {})
    const tool = tools.find((candidate) => candidate.name === 'pod_freeze')
    assert(tool !== undefined, 'pod_freeze 必须注册')
    assertEqual(tool.parameters.required.join(','), 'jobId,action', 'jobId 与 action 必填')
    assertEqual(JSON.stringify(tool.parameters.properties.action.enum), JSON.stringify(['freeze', 'thaw']), 'action 只有 freeze/thaw')
    assertEqual(tool.parameters.properties.adopt.type, 'boolean', 'adopt 是 boolean')
    assertEqual(tool.parameters.properties.maxFreezeMs.type, 'number', 'maxFreezeMs 是 number')
    assertEqual(tool.parameters.additionalProperties, false, '不接受未声明参数')
    const exec = { agent: { id: 'me', session: { meta: { cwd: WORKSPACE } } } }
    let badIdCode = null
    try {
      await tool.execute({ jobId: '../x', action: 'freeze' }, exec)
    } catch (error) {
      badIdCode = error?.code ?? null
    }
    assertEqual(badIdCode, 'EBADJOBID', '非法 jobId 必须在 Host 侧就 EBADJOBID')
    let badActionCode = null
    try {
      await tool.execute({ jobId: JOB, action: 'pause' }, exec)
    } catch (error) {
      badActionCode = error?.code ?? null
    }
    assertEqual(badActionCode, 'EBADACTION', '未知 action 必须拒绝')
    const frozen = await tool.execute({ jobId: JOB, action: 'freeze' }, exec)
    assertEqual(calls[0].action, 'freeze', 'action 透传')
    assertEqual(calls[0].adopt, false, '默认显式 adopt:false')
    assertEqual(Object.prototype.hasOwnProperty.call(calls[0], 'maxFreezeMs'), false, '未传 maxFreezeMs 时不下发（pod 用默认值）')
    assertEqual(frozen.frozen, true, '结果 frozen=true')
    assertEqual(frozen.remainingFreezeMs, 1_800_000, '看门狗剩余时间透传')
    assert(frozen.message.includes('看门狗剩余='), '模型文本要显示剩余时间：' + frozen.message)
    assertEqual(Object.prototype.hasOwnProperty.call(frozen, 'adoptedFrom'), false, '没接管就不标 adoptedFrom')
    const thawed = await tool.execute({ jobId: JOB, action: 'thaw', maxFreezeMs: 5000 }, exec)
    assertEqual(calls[1].action, 'thaw', 'thaw 透传')
    assertEqual(calls[1].maxFreezeMs, 5000, 'maxFreezeMs 透传')
    assertEqual(thawed.frozen, false, '解冻后 frozen=false')
    const adopted = await tool.execute({ jobId: JOB, action: 'freeze', adopt: true }, exec)
    assertEqual(calls[2].adopt, true, 'adopt 透传')
    assertEqual(adopted.adoptedFrom, 'owner-x', '结果标注接管来源')
    let foreignCode = null
    try {
      await tool.execute({ jobId: 'podc-frz5-abcdef06', action: 'freeze' }, exec)
    } catch (error) {
      foreignCode = error?.code ?? null
    }
    assertEqual(foreignCode, 'EFOREIGNJOB', 'pod 的结构化错误码必须原样抛出（不被包成 EPODCERROR）')
  })

  await test('pod_status：freeze= 行与 job 行 frozen（剩余时间）/frozen-orphan', async () => {
    const row = (jobId, freeze) => ({
      jobId,
      sessionId: 's',
      status: freeze?.state === 'frozen' && freeze.thawable !== true ? 'frozen-orphan' : 'running',
      running: freeze?.state !== 'frozen',
      exitCode: null,
      signal: null,
      timedOut: false,
      timeoutMs: null,
      runnerPid: 4242,
      startedAt: '2026-10-30T00:00:00.000Z',
      endedAt: null,
      durationMs: null,
      bytes: 10,
      lossy: false,
      cursor: { state: 'valid', offset: 10, lossy: false },
      spillPaths: [join(TMP_ROOT, 'out.log')],
      channels: ['stdout'],
      command: 'node -e setInterval',
      description: null,
      cwd: WORKSPACE,
      prefixFingerprint: 'f'.repeat(64),
      freeze,
    })
    const makePod = (freezeInfo, jobs) => ({
      stateDir: TMP_ROOT,
      pipeName: 'freeze-status-pipe',
      mode: () => 'reused',
      template: () => null,
      spawnInfo: () => null,
      async status() {
        return {
          response: {
            podPid: 1,
            podStartedAt: 'T',
            generation: 1,
            podGeneration: 'pg-freeze',
            podVersion: '1.7.0',
            protocolVersion: 2,
            pipeName: 'freeze-status-pipe',
            enforcement: 'partial',
            template: { valid: false, code: 'E', reason: 'selftest' },
            workspaceRoot: WORKSPACE,
            dataRoot: TMP_ROOT,
            identity: null,
            auth: null,
            attestation: null,
            running: jobs.filter((job) => job.running).length,
            jobs,
            outputChunkBytes: 64000,
            maxOutputChunkBytes: MAX_OUTPUT_CHUNK_BYTES,
            freeze: freezeInfo,
          },
          bootstrapError: null,
        }
      },
    })
    const exec = { agent: { id: 's', session: { meta: { cwd: WORKSPACE } } } }
    const supportedInfo = {
      supported: true,
      state: 'supported',
      reason: null,
      checkedAt: '2026-10-30T00:00:00.000Z',
      defaultMaxFreezeMs: FREEZE_DEFAULT_MAX_MS,
    }
    const frozenRow = row('podc-frz6-abcdef07', {
      state: 'frozen',
      since: '2026-10-30T00:00:00.000Z',
      by: 's',
      count: 1,
      frozenForMs: 60_000,
      maxFreezeMs: 1_800_000,
      remainingFreezeMs: 1_740_000,
      podGeneration: 'pg-freeze',
      thawable: true,
      orphan: false,
    })
    const orphanRow = row('podc-frz7-abcdef08', {
      state: 'frozen',
      since: '2026-10-30T00:00:00.000Z',
      by: 's',
      count: 2,
      frozenForMs: 60_000,
      maxFreezeMs: null,
      remainingFreezeMs: null,
      podGeneration: 'dead',
      thawable: false,
      orphan: true,
    })
    const supported = await createTools(makePod(supportedInfo, [frozenRow, orphanRow]), () => null, { outputChunkBytes: 64000, modelOutputLimitBytes: 0 }, null, () => {})
      .find((candidate) => candidate.name === 'pod_status')
      .execute({}, exec)
    assertEqual(supported.freeze.supported, true, '结构化结果必须带 freeze')
    assertEqual(supported.podGeneration, 'pg-freeze', 'podGeneration 透传')
    assert(supported.message.includes('freeze=supported'), '文本必须有 freeze=supported：' + supported.message.slice(0, 400))
    assert(supported.message.includes('frozen=剩29m00s'), 'job 行必须显示剩余时间：' + supported.message)
    assert(supported.message.includes('frozen-orphan=不可解冻'), '孤儿行必须说清不可解冻：' + supported.message)
    assert(supported.message.includes('killed=false'), '孤儿行必须如实说明 pod_kill 拿不到句柄（不承诺真的能清理）')
    const unsupported = await createTools(
      makePod({ supported: false, state: 'unsupported', reason: '这台机器没有 job 冻结', checkedAt: null, defaultMaxFreezeMs: FREEZE_DEFAULT_MAX_MS }, []),
      () => null,
      { outputChunkBytes: 64000, modelOutputLimitBytes: 0 },
      null,
      () => {},
    ).find((candidate) => candidate.name === 'pod_status').execute({}, exec)
    assertEqual(unsupported.freeze.supported, false, 'unsupported 如实投影')
    assert(unsupported.message.includes('freeze=unsupported（这台机器没有 job 冻结）'), '文本必须有原因：' + unsupported.message.slice(0, 400))
    const attachWarn = await createTools(
      makePod({ ...supportedInfo, lastAttachError: { at: '2026-10-30T00:00:00.000Z', stage: 'AssignProcessToJobObject', win32: 5, runnerPid: 4242 } }, []),
      () => null,
      { outputChunkBytes: 64000, modelOutputLimitBytes: 0 },
      null,
      () => {},
    ).find((candidate) => candidate.name === 'pod_status').execute({}, exec)
    assert(attachWarn.message.includes('runner 入 job 失败'), 'supported 但赋值失败必须显示在 freeze= 行：' + attachWarn.message.slice(0, 500))
    assert(attachWarn.message.includes('Win32 5'), '必须带上 Win32 码')
    const legacyPod = await createTools(makePod(undefined, []), () => null, { outputChunkBytes: 64000, modelOutputLimitBytes: 0 }, null, () => {})
      .find((candidate) => candidate.name === 'pod_status')
      .execute({}, exec)
    assertEqual(legacyPod.freeze, null, '旧 pod（没有该字段）必须投影为 null')
    assert(legacyPod.message.includes('freeze=unknown'), '旧 pod 必须说 unknown，不能假装 supported：' + legacyPod.message.slice(0, 400))
  })

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  const passed = results.filter((row) => row.ok).length
  const failed = results.length - passed
  const summary = { ok: failed === 0, passed, failed, workspace: WORKSPACE, tmpRoot: TMP_ROOT, cases: results }
  fs.writeFileSync(join(TMP_ROOT, 'static-result.json'), JSON.stringify(summary, null, 2) + '\n')
  process.stdout.write('\n静态自测：' + passed + ' 通过 / ' + failed + ' 失败\n')
  process.stdout.write(JSON.stringify({ ok: summary.ok, passed, failed }) + '\n')
  process.exitCode = failed === 0 ? 0 : 1
}

await main()
