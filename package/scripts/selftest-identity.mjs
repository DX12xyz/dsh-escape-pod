#!/usr/bin/env node
/**
 * Loopback identity-channel self-test for @local/dsh-escape-pod.
 *
 * The identity channel is a real TCP listener on 127.0.0.1, and its whole point
 * is the reverse 4-tuple lookup, so this suite does **not** mock the transport:
 * every case opens a real `net.connect` to the ephemeral port the channel bound
 * and sends one real request line. What it covers:
 *
 *   1. a legal attest is answered `allowed:true` and `consume()` redeems a
 *      one-shot ticket holding the attested pid/facts/checks;
 *   2. the same nonce cannot be redeemed twice (`EUNATTESTED`);
 *   3. a ticket past its TTL is refused (`EEXPIRED`, or `EUNATTESTED` when a
 *      `prune()` already removed it) while exact-TTL is still valid;
 *   4. the 65th issuance evicts the oldest ticket (MAX_TICKETS = 64), the
 *      newest still redeems, and only one entry is evicted;
 *   5. a denied attestation (restricted token / low integrity) replies
 *      `allowed:false` and issues no nonce;
 *   6. a policy source that throws, or an attestor that crashes / returns no
 *      facts, can never admit: the nonce is not issued and the channel keeps
 *      serving afterwards;
 *   7. the PID-reuse guard refuses a changed creationTime within the ticket TTL,
 *      keeps admitting an unchanged one, and lets the pid through again after
 *      the observation ages out;
 *   8. `mode=off` admits with exactly one `policy` check and still issues a
 *      redeemable ticket (behaviour read from identity.mjs before asserting);
 *   9. malformed lines (bad JSON, missing/ill-shaped nonce, unknown op, a
 *      >MAX_LINE_BYTES line) all answer `ok:false` with a named code, and the
 *      listener still serves valid requests afterwards.
 *
 * Deliberately out of scope: the real `GetExtendedTcpTable` lookup (this suite
 * uses a fake attestor and therefore proves wiring/verdict/ticket semantics,
 * not the OS query), named pipes, spawning children, and talking to a live pod.
 * `ETIMEOUT` (a silent 3s connection) and empty lines are not exercised so the
 * suite stays fast and the "one request line per connection" contract stays
 * untouched; see TECHDOC.md §7.5 for the same list.
 *
 * Runs inside a restricted shell. Every channel is stopped before the process
 * exits; a watchdog only fires if something leaked.
 *
 * Usage: node scripts/selftest-identity.mjs
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import { join, resolve } from 'node:path'
import { randomBytes } from 'node:crypto'

import { createIdentityChannel } from '../identity.mjs'

const HOST = '127.0.0.1'
const REQUEST_TIMEOUT_MS = 5000
const WORKSPACE = resolve('Z:\\Project\\DSHproject')
const RUN_ID = String(process.pid) + '-' + randomBytes(3).toString('hex')
const TMP_ROOT = join(WORKSPACE, '.tmp', 'escape-pod-core-selftest-identity', RUN_ID)

/** Facts that pass `evaluateClient` under `makePolicy()`. */
const USER_SID = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
const IMAGE = 'C:\\Windows\\System32\\node.exe'
const PID = 4242

/** @type {Set<any>} every channel this run started, closed before exit */
const liveChannels = new Set()
/** @type {Array<{ name: string, ok: boolean, detail?: string }>} */
const results = []

/** @param {string} name @param {() => (void | Promise<void>)} fn */
async function test(name, fn) {
  try {
    await fn()
    results.push({ name, ok: true })
    process.stdout.write('[PASS] ' + name + '\n')
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    results.push({ name, ok: false, detail })
    process.stdout.write('[FAIL] ' + name + ' — ' + detail + '\n')
  } finally {
    // A failing assertion must not leave a listener behind and hang the run.
    for (const channel of liveChannels) channel.stop()
    liveChannels.clear()
  }
}

/** @param {Record<string, unknown>} [overrides] */
function makeClient(overrides = {}) {
  return {
    pid: PID,
    userSid: USER_SID,
    sessionId: 7,
    integrityRid: 0x3000, // SECURITY_MANDATORY_MEDIUM_RID
    restrictedSidCount: 0,
    imagePath: IMAGE,
    ...overrides,
  }
}

/** @param {Record<string, unknown>} [overrides] */
function makePolicy(overrides = {}) {
  return {
    mode: 'enforce',
    userSid: USER_SID,
    sessionId: 7,
    minIntegrityRid: 0x3000,
    allowRestricted: false,
    allowedImages: [IMAGE],
    allowedImagesExact: true,
    ...overrides,
  }
}

/**
 * A fake attestor is legitimate here only because the transport is real: the
 * channel must hand it the *accepted socket*, which is exactly the object whose
 * localPort/remotePort the real `GetExtendedTcpTable` lookup consumes. The
 * state below lets a test also make it throw or return `{ok:false}`.
 *
 * @param {any} peer `{ok:true,pid,client}` / `{ok:false,code,message}` / Error
 */
function createFakeAttestor(peer) {
  const state = {
    /** @type {any} */
    peer,
    calls: 0,
    /** @type {number | null} */
    lastLocalPort: null,
    /** @type {number | null} */
    lastRemotePort: null,
  }
  return {
    state,
    /** @param {any} socket */
    describeTcpPeer(socket) {
      state.calls += 1
      state.lastLocalPort = Number(socket?.localPort)
      state.lastRemotePort = Number(socket?.remotePort)
      if (state.peer instanceof Error) throw state.peer
      return state.peer
    },
  }
}

/** @param {any} options @returns {Promise<{ channel: any, port: number }>} */
async function startChannel(options) {
  const channel = createIdentityChannel(options)
  liveChannels.add(channel)
  const port = await channel.start()
  assert.ok(Number.isInteger(port) && port > 0, '身份通道必须绑定到一个真实的临时端口，实际 ' + String(port))
  return { channel, port }
}

/**
 * One real loopback request/response. The server replies with exactly one
 * newline-terminated JSON line and ends the socket.
 *
 * @param {number} port
 * @param {string} payload
 * @returns {Promise<any>}
 */
function request(port, payload) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = net.connect({ host: HOST, port })
    let buffer = ''
    let settled = false
    const timer = setTimeout(
      () => finish(new Error('身份通道 ' + String(REQUEST_TIMEOUT_MS) + 'ms 内没有回复：' + JSON.stringify(payload.slice(0, 120)))),
      REQUEST_TIMEOUT_MS,
    )
    timer.unref?.()

    /** @param {Error | null} error @param {any} [reply] */
    function finish(error, reply) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error !== null) rejectPromise(error)
      else resolvePromise(reply)
    }

    socket.setEncoding('utf8')
    socket.once('connect', () => socket.write(payload))
    socket.on('data', (chunk) => {
      buffer += chunk
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      const line = buffer.slice(0, newline).trim()
      try {
        finish(null, JSON.parse(line))
      } catch {
        finish(new Error('身份通道回复不是 JSON：' + JSON.stringify(line.slice(0, 200))))
      }
    })
    socket.on('end', () => finish(new Error('身份通道在回复前结束了连接：' + JSON.stringify(buffer.slice(0, 200)))))
    socket.on('close', () => finish(new Error('身份通道在回复前关闭了连接：' + JSON.stringify(buffer.slice(0, 200)))))
    socket.on('error', (error) => finish(error))
  })
}

/** @param {number} port @param {string} nonce */
function attest(port, nonce) {
  return request(port, JSON.stringify({ op: 'attest', nonce }) + '\n')
}

/** The last verdict recorded by `snapshot()`; `snapshot()` also prunes. */
function lastChecks(channel) {
  return channel.snapshot().last?.checks ?? []
}

/** @param {any} channel @param {string} name */
function checkNamed(channel, name) {
  return lastChecks(channel).find((entry) => entry.name === name) ?? null
}

/**
 * A refused nonce that was never issued must say so: EUNATTESTED. (EEXPIRED is
 * only reachable for a ticket that WAS issued and later aged out; see case 3.)
 *
 * @param {{ ok: boolean, code?: string }} result
 * @param {string} message
 */
function assertNotIssued(result, message) {
  assert.equal(result.ok, false, message + '：不能兑换到票据')
  assert.equal(result.code, 'EUNATTESTED', message + '：期望 EUNATTESTED，实际 ' + String(result.code))
}

async function main() {
  fs.mkdirSync(TMP_ROOT, { recursive: true })
  const watchdog = setTimeout(() => {
    process.stdout.write('身份通道自测：超过 60s 仍未结束，强制退出（可能有连接未关闭）\n')
    process.exit(2)
  }, 60_000)

  try {
    // -----------------------------------------------------------------------
    // 1. A legal attestation issues a redeemable one-shot ticket.
    // -----------------------------------------------------------------------
    await test('身份通道：合法 attest 回复 allowed:true，consume 兑换到一次性票据', async () => {
      const client = makeClient()
      const attestor = createFakeAttestor({ ok: true, pid: client.pid, client })
      const logs = []
      const nonce = '0123456789abcdef0123456789abcdef'
      const { channel, port } = await startChannel({
        attestor,
        policy: makePolicy(),
        log: (line) => logs.push(line),
      })

      const reply = await attest(port, nonce)
      assert.deepEqual(reply, { ok: true, allowed: true, pid: client.pid, failed: [] })

      // The transport really is TCP: the fake attestor received the accepted
      // socket, whose localPort is the channel's port and whose remotePort is
      // the client's ephemeral port. That pair is what the real lookup uses.
      assert.equal(attestor.state.calls, 1, 'attestor 必须恰好被调用一次')
      assert.equal(attestor.state.lastLocalPort, port, 'attestor 应拿到真实服务端 socket（localPort=通道端口）')
      assert.ok(attestor.state.lastRemotePort > 0, 'attestor 应拿到真实客户端端口（remotePort>0）')

      const before = channel.snapshot()
      assert.equal(before.listening, true, '通道应处于 listening')
      assert.equal(before.port, port, 'snapshot.port 应是真实绑定端口')
      assert.equal(before.requests, 1, 'requests 计数一次合法请求')
      assert.equal(before.allowed, 1, 'allowed 计数一次放行')
      assert.equal(before.denied, 0, '放行不计入 denied')
      assert.equal(before.outstandingTickets, 1, '放行后应有一张未兑换票据')
      assert.equal(before.ttlMs, 60_000, '默认 TTL 是 60s')
      assert.equal(before.last.allowed, true, 'snapshot.last 记录本次判定')
      assert.equal(before.last.pid, client.pid, 'snapshot.last 记录对端 pid')

      const redeemed = channel.consume(nonce)
      assert.equal(redeemed.ok, true, '合法签发的 nonce 必须能兑换，实际 ' + JSON.stringify(redeemed))
      assert.equal(redeemed.ticket.nonce, nonce, '票据应携带原 nonce')
      assert.equal(redeemed.ticket.pid, client.pid, '票据应携带被归属的 pid')
      assert.equal(redeemed.ticket.allowed, true, '票据应标记 allowed')
      assert.deepEqual(redeemed.ticket.checks.map((entry) => entry.name), ['user', 'session', 'integrity', 'token-shape', 'image'], 'TCP 路径不应产生 server-side 检查项')
      assert.ok(redeemed.ticket.checks.every((entry) => entry.ok === true), '全部检查项应通过')
      assert.deepEqual(redeemed.ticket.facts, client, '票据携带 attestor 给出的进程事实')
      assert.equal(channel.snapshot().outstandingTickets, 0, '兑换后票据表应为空')
      assert.ok(logs.some((line) => line.includes('identity ok') && line.includes('mode=enforce')), '应记录 identity ok 日志')
    })

    // -----------------------------------------------------------------------
    // 2. Single use: the second redemption fails.
    // -----------------------------------------------------------------------
    await test('身份通道：同一 nonce 只能兑换一次（重放得 EUNATTESTED）', async () => {
      const client = makeClient()
      const nonce = 'fedcba9876543210fedcba9876543210'
      const { channel, port } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: client.pid, client }),
        policy: makePolicy(),
      })

      const reply = await attest(port, nonce)
      assert.equal(reply.allowed, true, '第一次 attest 应放行')

      const first = channel.consume(nonce)
      assert.equal(first.ok, true, '第一次兑换应成功')
      assert.equal(first.ticket.nonce, nonce, '第一次兑换应返回对应票据')

      const second = channel.consume(nonce)
      assertNotIssued(second, '同一 nonce 的第二次兑换')
      assert.equal(channel.snapshot().outstandingTickets, 0, '重放不能复活票据')
    })

    // -----------------------------------------------------------------------
    // 3. TTL expiry, both with the stale entry still present and pruned away.
    // -----------------------------------------------------------------------
    await test('身份通道：票据过期后 consume 拒绝；恰好 TTL 仍有效', async () => {
      let clock = 1_700_000_000_000
      const ttlMs = 5_000
      const client = makeClient()
      const { channel, port } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: client.pid, client }),
        policy: makePolicy(),
        ttlMs,
        now: () => clock,
      })
      assert.equal(channel.snapshot().ttlMs, ttlMs, '注入的 ttlMs 应生效')

      // (a) No prune() ran between issuance and this consume, so the entry is
      // still in the table and consume() itself must report EEXPIRED. A future
      // implementation that prunes inside consume() would legitimately answer
      // EUNATTESTED instead (the suite spec accepts either: both mean "this
      // nonce can no longer be redeemed"), so accept both and say which one.
      const staleNonce = 'a1'.repeat(16)
      assert.equal((await attest(port, staleNonce)).allowed, true, '过期用例的前置签发应放行')
      clock += ttlMs + 1
      const expired = channel.consume(staleNonce)
      assert.equal(expired.ok, false, '超过 TTL 的票据不能兑换')
      assert.ok(expired.code === 'EEXPIRED' || expired.code === 'EUNATTESTED', '过期必须被拒：EEXPIRED，或已被 prune 删除时的 EUNATTESTED；实际 ' + String(expired.code) + '（本次没有触发 prune，按代码应为 EEXPIRED）')
      assert.equal(channel.consume(staleNonce).code, 'EUNATTESTED', '过期票据一旦被处理，再兑换只剩 EUNATTESTED')

      // (b) snapshot() calls prune(), which must actually delete expired
      // entries — not merely hide them from consume().
      const prunedNonce = 'b2'.repeat(16)
      assert.equal((await attest(port, prunedNonce)).allowed, true, 'prune 用例的前置签发应放行')
      clock += ttlMs + 1
      assert.equal(channel.snapshot().outstandingTickets, 0, 'prune 应删除过期票据')
      assert.equal(channel.consume(prunedNonce).code, 'EUNATTESTED', '被 prune 删除后兑换应得 EUNATTESTED')

      // (c) Boundary: the code uses `now - at > ttlMs`, so exactly the TTL is
      // still valid. Pinned here because "expired" must not become ">= TTL".
      const boundaryNonce = 'c3'.repeat(16)
      assert.equal((await attest(port, boundaryNonce)).allowed, true, '边界用例的前置签发应放行')
      clock += ttlMs
      assert.equal(channel.consume(boundaryNonce).ok, true, '恰好等于 TTL 时票据仍有效（代码判定为严格大于）')
    })

    // -----------------------------------------------------------------------
    // 4. The ticket cap: the 65th issuance evicts the oldest.
    // -----------------------------------------------------------------------
    await test('身份通道：第 65 张票据淘汰最旧的，最新的仍可兑换', async () => {
      const client = makeClient()
      const { channel, port } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: client.pid, client }),
        policy: makePolicy(),
      })

      /** 16-hex distinct nonces, in issuance order. */
      const nonces = Array.from({ length: 65 }, (_, index) => index.toString(16).padStart(16, '0'))
      for (let index = 0; index < nonces.length; index += 1) {
        const reply = await attest(port, nonces[index])
        assert.equal(reply.allowed, true, '第 ' + String(index + 1) + ' 张票据的签发应放行')
        assert.equal(reply.pid, client.pid, '第 ' + String(index + 1) + ' 张票据应带上 pid')
      }

      // Do NOT call snapshot() here: snapshot() prunes, which would itself
      // evict the oldest ticket and mask exactly what this case is about
      // (eviction at issuance time, MAX_TICKETS = 64).
      const oldest = channel.consume(nonces[0])
      assert.equal(oldest.ok, false, '第 65 张签发后，最旧的 nonce 必须已被上限淘汰（MAX_TICKETS=64）')
      assert.equal(oldest.code, 'EUNATTESTED', '被淘汰的 nonce 应表现为从未登记')

      const newest = channel.consume(nonces[64])
      assert.equal(newest.ok, true, '最新一张必须仍可兑换')

      const secondOldest = channel.consume(nonces[1])
      assert.equal(secondOldest.ok, true, '只应淘汰最旧一张，不能整表清空')

      assert.equal(channel.snapshot().outstandingTickets, 62, '65 张 - 淘汰 1 张 - 兑换 2 张 = 62 张未兑换')
    })

    // -----------------------------------------------------------------------
    // 5. A denied verdict issues no nonce (restricted token / low integrity).
    // -----------------------------------------------------------------------
    await test('身份通道：attestor 判定拒绝时不签发 nonce（受限令牌 / 低完整性）', async () => {
      const restricted = makeClient({ restrictedSidCount: 2 })
      const lowIntegrity = makeClient({ integrityRid: 0x1000 })
      const attestor = createFakeAttestor({ ok: true, pid: restricted.pid, client: restricted })
      const logs = []
      const { channel, port } = await startChannel({ attestor, policy: makePolicy(), log: (line) => logs.push(line) })

      const restrictedReply = await attest(port, 'd4'.repeat(16))
      assert.equal(restrictedReply.ok, true, '协议层仍应正常回复（判定在 allowed 字段里）')
      assert.equal(restrictedReply.allowed, false, '受限令牌必须被拒')
      assert.deepEqual(restrictedReply.failed, ['token-shape'], '失败项应点名 token-shape')
      assertNotIssued(channel.consume('d4'.repeat(16)), '受限令牌的 nonce')
      const restrictedCheck = checkNamed(channel, 'token-shape')
      assert.equal(restrictedCheck?.ok, false, 'token-shape 检查项必须是 false')
      assert.ok(String(restrictedCheck?.detail).includes('受限令牌'), '检查项应说明这是受限令牌：' + String(restrictedCheck?.detail))

      attestor.state.peer = { ok: true, pid: lowIntegrity.pid, client: lowIntegrity }
      const lowReply = await attest(port, 'e5'.repeat(16))
      assert.equal(lowReply.allowed, false, '低完整性必须被拒')
      assert.deepEqual(lowReply.failed, ['integrity'], '失败项应点名 integrity')
      assertNotIssued(channel.consume('e5'.repeat(16)), '低完整性的 nonce')

      const snapshot = channel.snapshot()
      assert.equal(snapshot.allowed, 0, '两次拒绝不得计入 allowed')
      assert.equal(snapshot.denied, 2, '两次真拒绝应计入 denied')
      assert.equal(snapshot.outstandingTickets, 0, '拒绝不得留下任何票据')
      assert.equal(snapshot.last.allowed, false, 'snapshot.last 应记录最后一次拒绝')
      assert.ok(logs.some((line) => line.includes('identity DENIED') && line.includes('failed=integrity')), '应记录 DENIED 与失败项')
    })

    // -----------------------------------------------------------------------
    // 6. Unavailable policy / crashed attestor must refuse, not admit.
    // -----------------------------------------------------------------------
    await test('身份通道：策略不可用 / attestor 崩溃时拒发 nonce，且通道继续服务', async () => {
      const client = makeClient()

      // (a) The policy source itself throws: resolvePolicy() must degrade to
      // null, and null is a refusal (not a licence to admit).
      let policyBroken = true
      const attestor = createFakeAttestor({ ok: true, pid: client.pid, client })
      const policy = () => {
        if (policyBroken) throw new Error('attestation 策略源不可用')
        return makePolicy()
      }
      const { channel, port } = await startChannel({ attestor, policy })

      const denied = await attest(port, 'f6'.repeat(16))
      assert.equal(denied.ok, true, '协议层仍应正常回复')
      assert.equal(denied.allowed, false, '拿不到策略时必须拒绝，不能放行')
      assert.deepEqual(denied.failed, ['policy'], '失败项应点名 policy')
      assertNotIssued(channel.consume('f6'.repeat(16)), '策略不可用时的 nonce')
      const policyCheck = checkNamed(channel, 'policy')
      assert.equal(policyCheck?.ok, false, 'policy 检查项必须是 false')
      assert.ok(String(policyCheck?.detail).includes('策略源不可用'), '检查项应说明策略源不可用：' + String(policyCheck?.detail))

      // The same channel recovers once the policy resolves again: the policy is
      // resolved per request, so a transient failure must not brick the channel.
      policyBroken = false
      assert.equal((await attest(port, '07'.repeat(16))).allowed, true, '策略恢复后同一通道应立刻恢复放行')

      // (b) The production policy shape is an object with current(); a throwing
      // current() must be just as unavailable as a throwing function.
      const brokenSource = {
        current() {
          throw new Error('current 崩了')
        },
      }
      const { channel: sourceChannel, port: sourcePort } = await startChannel({ attestor, policy: brokenSource })
      const sourceDenied = await attest(sourcePort, '18'.repeat(16))
      assert.equal(sourceDenied.allowed, false, 'policy.current() 抛错时必须拒绝')
      assert.deepEqual(sourceDenied.failed, ['policy'], '失败项应点名 policy')
      assertNotIssued(sourceChannel.consume('18'.repeat(16)), 'current() 抛错时的 nonce')

      // (c) The attestor throws (GetExtendedTcpTable unavailable): no identity
      // facts means no admission, but the channel must answer and keep serving.
      const crashing = createFakeAttestor(new Error('GetExtendedTcpTable 崩了'))
      const { channel: crashChannel, port: crashPort } = await startChannel({ attestor: crashing, policy: makePolicy() })
      const crashed = await attest(crashPort, '29'.repeat(16))
      assert.equal(crashed.ok, true, '协议层仍应正常回复')
      assert.equal(crashed.allowed, false, 'attestor 崩溃时必须拒绝')
      assert.deepEqual(crashed.failed, ['identity'], '失败项应点名 identity')
      assertNotIssued(crashChannel.consume('29'.repeat(16)), 'attestor 崩溃时的 nonce')
      const identityCheck = checkNamed(crashChannel, 'identity')
      assert.equal(identityCheck?.ok, false, 'identity 检查项必须是 false')
      assert.ok(String(identityCheck?.detail).includes('EATTESTCRASH'), '检查项应带上 EATTESTCRASH：' + String(identityCheck?.detail))

      crashing.state.peer = { ok: true, pid: client.pid, client }
      assert.equal((await attest(crashPort, '3a'.repeat(16))).allowed, true, 'attestor 恢复后同一通道应恢复放行')

      // (d) The attestor explicitly reports "no facts" ({ok:false}) — the same
      // refusal, without an exception.
      crashing.state.peer = { ok: false, code: 'ENOHANDLE', message: 'no 4-tuple on the pipe path' }
      const noFacts = await attest(crashPort, '4b'.repeat(16))
      assert.equal(noFacts.allowed, false, '拿不到身份事实时必须拒绝')
      assert.deepEqual(noFacts.failed, ['identity'], '失败项应点名 identity')
      assertNotIssued(crashChannel.consume('4b'.repeat(16)), '拿不到事实时的 nonce')
    })

    // -----------------------------------------------------------------------
    // 7. PID reuse: same pid, changed creationTime is refused.
    // -----------------------------------------------------------------------
    await test('身份通道：同一 PID 在 TTL 内 creationTime 变化被拒发（PID 复用守卫）', async () => {
      let clock = 1_800_000_000_000
      const ttlMs = 5_000
      const creationTime = '133700000000000001'
      const client = makeClient({ creationTime })
      const attestor = createFakeAttestor({ ok: true, pid: client.pid, client })
      const logs = []
      const { channel, port } = await startChannel({
        attestor,
        policy: makePolicy(),
        ttlMs,
        now: () => clock,
        log: (line) => logs.push(line),
      })

      assert.equal((await attest(port, '5c'.repeat(16))).allowed, true, '首次见到该 PID 应放行')
      const firstCheck = checkNamed(channel, 'creation-time')
      assert.equal(firstCheck?.ok, true, '首次检查项应为 true')
      assert.ok(String(firstCheck?.detail).includes('首次见到'), '首次应标注“首次见到”：' + String(firstCheck?.detail))

      assert.equal((await attest(port, '6d'.repeat(16))).allowed, true, 'creationTime 不变应继续放行')
      assert.ok(String(checkNamed(channel, 'creation-time')?.detail).includes('未变'), '应说明 creationTime 未变')

      // Same pid, a different process behind it: only creationTime can tell
      // them apart, so the next attestation must be denied.
      attestor.state.peer = { ok: true, pid: client.pid, client: makeClient({ creationTime: '133700000000000002' }) }
      const changed = await attest(port, '7e'.repeat(16))
      assert.equal(changed.allowed, false, '同一 PID 的 creationTime 变化必须拒绝')
      assert.deepEqual(changed.failed, ['creation-time'], '失败项应点名 creation-time')
      assert.equal(checkNamed(channel, 'creation-time')?.ok, false, '检查项必须标 false')
      assert.ok(String(checkNamed(channel, 'creation-time')?.detail).includes('PID 复用'), '原因应点名 PID 复用')
      assertNotIssued(channel.consume('7e'.repeat(16)), 'PID 复用时的 nonce')
      assert.ok(logs.some((line) => line.includes('identity PID 复用被拒')), '应记录 PID 复用拒绝日志')

      // A mismatch does not overwrite the remembered value: the original
      // process behind the pid is still admitted.
      attestor.state.peer = { ok: true, pid: client.pid, client }
      assert.equal((await attest(port, '8f'.repeat(16))).allowed, true, '创建时间回到原值时应放行（守卫不覆盖旧值）')

      // The guard window is the ticket TTL: after it ages out, the process now
      // behind the pid is admitted again (no permanent lockout).
      clock += ttlMs + 1
      attestor.state.peer = { ok: true, pid: client.pid, client: makeClient({ creationTime: '133700000000000003' }) }
      assert.equal((await attest(port, '90'.repeat(16))).allowed, true, '超过 TTL 后新进程应重新放行，不永久锁死')
      assert.ok(String(checkNamed(channel, 'creation-time')?.detail).includes('首次见到'), 'TTL 过后应重新按首次见到处理')
    })

    // -----------------------------------------------------------------------
    // 8. mode=off: admit with exactly one policy check, still issue the ticket.
    // -----------------------------------------------------------------------
    await test('身份通道：mode=off 时放行且只有一条 policy 检查（仍签发可兑换票据）', async () => {
      const client = makeClient()
      const { channel, port } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: client.pid, client }),
        policy: makePolicy({ mode: 'off' }),
      })

      const reply = await attest(port, 'a0'.repeat(16))
      assert.deepEqual(reply, { ok: true, allowed: true, pid: client.pid, failed: [] }, 'mode=off 应放行且无失败项')

      const snapshot = channel.snapshot()
      assert.equal(snapshot.last.mode, 'off', '记录里的 mode 应为 off')
      assert.deepEqual(snapshot.last.checks.map((entry) => entry.name), ['policy'], 'mode=off 只应留下一条 policy 检查（evaluateClient 被跳过）')
      assert.equal(snapshot.last.checks[0].ok, true, 'policy 检查项应为 true')
      assert.ok(String(snapshot.last.checks[0].detail).includes('mode=off'), '检查项应说明 mode=off：' + String(snapshot.last.checks[0].detail))

      const redeemed = channel.consume('a0'.repeat(16))
      assert.equal(redeemed.ok, true, 'mode=off 仍会签发可兑换票据（handover 需要它）')
      assert.equal(channel.snapshot().outstandingTickets, 0, '兑换后票据表应为空')

      // Behaviour read from the code: off returns before evaluateClient, so a
      // client that enforce would refuse is admitted too. Asserted explicitly so
      // a future tightening of off is a visible test change, not a silent one.
      const hostile = makeClient({
        restrictedSidCount: 3,
        integrityRid: 0x1000,
        userSid: 'S-1-5-21-9999999999-8888888888-7777777777-1002',
        sessionId: 99,
        imagePath: 'C:\\Windows\\System32\\cmd.exe',
      })
      const { channel: hostileChannel, port: hostilePort } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: hostile.pid, client: hostile }),
        policy: makePolicy({ mode: 'off' }),
      })
      const hostileReply = await attest(hostilePort, 'b1'.repeat(16))
      assert.equal(hostileReply.allowed, true, 'mode=off 完全跳过身份校验，用户/session/完整性/镜像都不参与判定')
      assert.deepEqual(hostileChannel.snapshot().last.checks.map((entry) => entry.name), ['policy'], 'mode=off 不得产生任何 evaluateClient 检查项')
      assert.equal(hostileChannel.consume('b1'.repeat(16)).ok, true, 'mode=off 对任意客户端都签发票据')
    })

    // -----------------------------------------------------------------------
    // 9. Protocol robustness: every malformed line is a clean ok:false, and the
    //    listener keeps serving.
    // -----------------------------------------------------------------------
    await test('身份通道：非法 JSON / 缺 nonce / 格式错 / 超长行都回 ok:false 且通道不崩', async () => {
      const client = makeClient()
      const { channel, port } = await startChannel({
        attestor: createFakeAttestor({ ok: true, pid: client.pid, client }),
        policy: makePolicy(),
      })

      /** @type {Array<{ name: string, line: string, code: string }>} */
      const malformed = [
        { name: '非法 JSON', line: 'this is not json', code: 'EBADJSON' },
        { name: '缺 nonce', line: JSON.stringify({ op: 'attest' }), code: 'EBADNONCE' },
        { name: 'nonce 不是十六进制', line: JSON.stringify({ op: 'attest', nonce: 'zzzz-not-hex' }), code: 'EBADNONCE' },
        { name: 'nonce 不是字符串', line: JSON.stringify({ op: 'attest', nonce: 12345 }), code: 'EBADNONCE' },
        { name: '缺 op', line: JSON.stringify({ nonce: 'deadbeefdeadbeef' }), code: 'EBADOP' },
        { name: '未知 op', line: JSON.stringify({ op: 'status' }), code: 'EBADOP' },
      ]

      let served = 0
      for (let index = 0; index < malformed.length; index += 1) {
        const item = malformed[index]
        const reply = await request(port, item.line + '\n')
        assert.equal(reply.ok, false, item.name + ' 必须是 ok:false')
        assert.equal(reply.error?.code, item.code, item.name + ' 应回 ' + item.code + '，实际 ' + String(reply.error?.code))
        assert.ok(typeof reply.error?.message === 'string' && reply.error.message.length > 0, item.name + ' 应带可读的错误消息')

        // 通道不崩：每条坏请求之后，同一监听端口仍必须正常签发。
        const nonce = (0xc0 + index).toString(16).padStart(2, '0').repeat(16)
        const good = await attest(port, nonce)
        assert.equal(good.allowed, true, item.name + ' 之后通道必须仍能正常服务')
        assert.equal(channel.consume(nonce).ok, true, item.name + ' 之后的正常票据应可兑换')
        served += 1
      }

      // 缺 op 的那条里带了一个合法格式的 nonce：它必须没有被登记。
      assertNotIssued(channel.consume('deadbeefdeadbeef'), '缺 op 请求里的 nonce')

      // A single line above MAX_LINE_BYTES is refused without ever reaching
      // handleLine, so it must not issue the nonce embedded in it either.
      const longNonce = '0d'.repeat(16)
      const overlong = JSON.stringify({ op: 'attest', nonce: longNonce, pad: 'x'.repeat(5000) })
      assert.ok(overlong.length > 4096, '用例自身必须真的超过 4096 字节')
      const overlongReply = await request(port, overlong + '\n')
      assert.equal(overlongReply.ok, false, '超长行必须是 ok:false')
      assert.equal(overlongReply.error?.code, 'ETOOLONG', '超长行应回 ETOOLONG')
      assertNotIssued(channel.consume(longNonce), '超长行里的 nonce')

      // 超长行之后仍能服务。
      const afterLong = await attest(port, '1e'.repeat(16))
      assert.equal(afterLong.allowed, true, '超长行之后通道必须仍能正常服务')
      assert.equal(channel.consume('1e'.repeat(16)).ok, true, '超长行之后的正常票据应可兑换')
      served += 1

      // 半行请求后直接断开：没有换行就没有请求，通道不能因此崩。
      await new Promise((resolvePromise, rejectPromise) => {
        const socket = net.connect({ host: HOST, port })
        socket.once('connect', () => {
          socket.write('{"op":"attest","nonce":"')
          setTimeout(() => {
            socket.destroy()
            resolvePromise(undefined)
          }, 30)
        })
        socket.once('error', rejectPromise)
      })
      const afterAbort = await attest(port, '2f'.repeat(16))
      assert.equal(afterAbort.allowed, true, '半行断开后通道必须仍能正常服务')
      assert.equal(channel.consume('2f'.repeat(16)).ok, true, '半行断开之后的正常票据应可兑换')
      served += 1

      const snapshot = channel.snapshot()
      assert.equal(snapshot.listening, true, '整套坏请求之后通道仍在 listening')
      assert.equal(snapshot.denied, 0, '协议错误不计入 denied（它们没有走到判定）')
      assert.equal(snapshot.allowed, served, 'allowed 应只统计真正的放行：' + String(served))
      assert.equal(snapshot.outstandingTickets, 0, '所有正常票据都被兑换，表应为空')
      assert.equal(snapshot.requests, malformed.length + served, 'requests 统计每条进入 handleLine 的行（超长行/半行不计）')
    })
  } finally {
    for (const channel of liveChannels) channel.stop()
    liveChannels.clear()
    clearTimeout(watchdog)
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  fs.mkdirSync(TMP_ROOT, { recursive: true })
  const passed = results.filter((row) => row.ok).length
  const failed = results.length - passed
  const summary = { ok: failed === 0, passed, failed, workspace: WORKSPACE, tmpRoot: TMP_ROOT, cases: results }
  fs.writeFileSync(join(TMP_ROOT, 'identity-result.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8')
  process.stdout.write('\n身份通道自测：' + passed + ' 通过 / ' + failed + ' 失败\n')
  process.stdout.write(JSON.stringify({ ok: summary.ok, passed, failed }) + '\n')
  process.exitCode = failed === 0 ? 0 : 1
}

await main()
