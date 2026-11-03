/**
 * The pod's identity channel: a loopback TCP listener whose only job is to tell
 * the pod *which process* is asking.
 *
 * Why a second channel at all: the protocol rides a named pipe, and Node never
 * exposes the Win32 handle of a pipe socket (`_handle.fd` is -1 for both the
 * listener and an accepted connection), so the pod cannot call
 * GetNamedPipeClientProcessId on its own clients. TCP does expose the 4-tuple,
 * and Windows maps a 4-tuple to the owning pid, so a loopback connection gives
 * an exact answer with no handle and no shared secret.
 *
 * The channel is not a transport and carries no protocol: a client connects,
 * sends one line `{op:"attest", nonce}`, and gets back `{allowed, pid}`. The
 * nonce is then presented on the pipe (the `handover` request) to bind that
 * connection to the attested identity. Nothing secret crosses this channel — the
 * port is public, and the reply only says whether the caller's own process
 * passed the policy.
 *
 * PID reuse: the OS answers "pid N", but Windows reuses pids. Every attestation
 * therefore also records the process creation time, and a second attestation
 * from the same pid with a different creation time is refused for the nonce TTL
 * (see `createPidCreationTimeGuard` in attest.mjs) and logged.
 */

import net from 'node:net'
import { randomBytes } from 'node:crypto'

import { createPidCreationTimeGuard, evaluateClient } from './attest.mjs'

/** One request line is a few dozen bytes; refuse anything that is not. */
const MAX_LINE_BYTES = 4096
/** How long an issued nonce stays usable on the pipe. */
const DEFAULT_TICKET_TTL_MS = 60 * 1000
/** Bounded ticket table: this channel is reachable by any local process. */
const MAX_TICKETS = 64
/** A client that connects and says nothing must not hold a slot. */
const REQUEST_TIMEOUT_MS = 3000

/**
 * @param {{ attestor: any, policy: any, log?: (message: string) => void, ttlMs?: number, now?: () => number }} options
 */
export function createIdentityChannel(options) {
  const attestor = options.attestor
  const policy = options.policy
  const log = typeof options.log === 'function' ? options.log : () => {}
  const ttlMs = Number.isInteger(options.ttlMs) && options.ttlMs > 0 ? options.ttlMs : DEFAULT_TICKET_TTL_MS
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  // PID reuse is only dangerous while a nonce issued to that pid can still be
  // redeemed, so the guard uses the same TTL as the ticket table.
  const creationGuard = createPidCreationTimeGuard({ ttlMs, now, maxPids: MAX_TICKETS * 4 })

  /** @type {Map<string, { nonce: string, pid: number, at: number, allowed: boolean, checks: any[], facts: any }>} */
  const tickets = new Map()
  /** @type {net.Server | null} */
  let server = null
  /** @type {number | null} */
  let boundPort = null
  let requests = 0
  let allowedCount = 0
  let deniedCount = 0
  /** @type {any} */
  let last = null

  /**
   * Resolve the policy for THIS request.
   *
   * `policy` is usually a live source (`createAttestPolicySource`), not a frozen
   * object: the operator edits `<dataRoot>/attest-policy.json` and the next
   * identity request must already see the new mode. Accepting a plain object
   * keeps the unit tests and older callers working.
   *
   * @returns {any}
   */
  function resolvePolicy() {
    try {
      if (typeof policy === 'function') return policy()
      if (policy !== null && typeof policy === 'object' && typeof policy.current === 'function') return policy.current()
      return policy
    } catch (error) {
      log('identity policy 解析失败：' + (error instanceof Error ? error.message : String(error)))
      return null
    }
  }

  function prune() {
    const cutoff = now() - ttlMs
    for (const [nonce, ticket] of tickets) {
      if (ticket.at < cutoff) tickets.delete(nonce)
    }
    // Oldest first: Map preserves insertion order.
    while (tickets.size > MAX_TICKETS) {
      const oldest = tickets.keys().next()
      if (oldest.done === true) break
      tickets.delete(oldest.value)
    }
  }

  /**
   * Handle one request line.
   *
   * @param {any} socket
   * @param {string} line
   */
  function handleLine(socket, line) {
    requests += 1
    /** @type {any} */
    let message = null
    try {
      message = JSON.parse(line)
    } catch {
      return reply(socket, { ok: false, error: { code: 'EBADJSON', message: 'request is not valid JSON' } })
    }
    if (message?.op !== 'attest') {
      return reply(socket, { ok: false, error: { code: 'EBADOP', message: 'only op=attest is served on the identity channel' } })
    }
    const nonce = typeof message?.nonce === 'string' ? message.nonce.trim() : ''
    if (!/^[0-9a-f]{16,128}$/i.test(nonce)) {
      return reply(socket, { ok: false, error: { code: 'EBADNONCE', message: 'nonce 必须是 16-128 位十六进制' } })
    }

    /** @type {any} */
    let peer = null
    try {
      peer = attestor.describeTcpPeer(socket)
    } catch (error) {
      peer = { ok: false, code: 'EATTESTCRASH', message: error instanceof Error ? error.message : String(error) }
    }
    const activePolicy = resolvePolicy()
    const verdict = peer?.ok === true
      ? evaluate(peer, activePolicy)
      : { allowed: false, checks: [{ name: 'identity', ok: false, detail: String(peer?.code) + ': ' + String(peer?.message) }] }
    // Same pid, different process: GetProcessTimes is the only fact that tells
    // those apart, and it is checked over the nonce TTL. A mismatch denies the
    // request outright (no nonce is issued) and is logged below.
    const stable = peer?.ok === true ? creationGuard.check(peer) : { ok: true, check: null }
    if (stable.check !== null) verdict.checks.push(stable.check)
    if (stable.ok === false) verdict.allowed = false
    const mode = activePolicy === null || activePolicy === undefined ? 'off' : String(activePolicy.mode ?? 'warn')
    const record = {
      at: new Date(now()).toISOString(),
      nonce: nonce.slice(0, 8) + '…',
      pid: typeof peer?.pid === 'number' ? peer.pid : null,
      mode,
      allowed: verdict.allowed === true,
      checks: verdict.checks,
      facts: peer?.client ?? null,
    }
    last = record
    if (verdict.allowed) allowedCount += 1
    else deniedCount += 1

    if (verdict.allowed === true) {
      // Insert first, then prune. Pruning *before* the insert never counts the
      // ticket being issued, so the table settled at MAX_TICKETS + 1 and the
      // oldest nonce stayed redeemable one issuance past the documented cap.
      tickets.set(nonce, {
        nonce,
        pid: record.pid,
        at: now(),
        allowed: true,
        checks: verdict.checks,
        facts: record.facts,
      })
      prune()
    }

    const failed = verdict.checks.filter((check) => !check.ok).map((check) => check.name)
    log(
      'identity ' + (verdict.allowed ? 'ok' : 'DENIED') + ' mode=' + mode + ' pid=' + String(record.pid) +
      ' image=' + String(record.facts?.imagePath) + ' integrity=' + String(record.facts?.integrity) +
      ' restricted=' + String(record.facts?.restrictedSidCount) +
      (failed.length > 0 ? ' failed=' + failed.join(',') : ''),
    )
    if (stable.check !== null && stable.check.ok === false) {
      log('identity PID 复用被拒：' + stable.check.detail)
    }
    // The reply is deliberately minimal: the caller learns only its own verdict.
    return reply(socket, {
      ok: true,
      allowed: verdict.allowed === true,
      pid: record.pid,
      failed,
    })
  }

  /**
   * @param {any} peer
   * @param {any} activePolicy resolved fresh for this request
   */
  function evaluate(peer, activePolicy) {
    // No policy at all is not a licence to admit anyone: the identity channel
    // exists only when attestation is configured, so a missing policy means
    // something is broken and the requested nonce must not be issued.
    if (activePolicy === null || activePolicy === undefined) {
      return { allowed: false, checks: [{ name: 'policy', ok: false, detail: '拿不到 attestation 策略（策略源不可用）' }] }
    }
    if (activePolicy.mode === 'off') {
      return { allowed: true, checks: [{ name: 'policy', ok: true, detail: 'mode=off：本次不做身份校验' }] }
    }
    return evaluateClient(peer, activePolicy)
  }

  /** @param {any} socket @param {any} payload */
  function reply(socket, payload) {
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
  }

  /** @param {any} socket */
  function onConnection(socket) {
    try {
      socket.setEncoding('utf8')
    } catch {
      // a socket that cannot be decoded cannot be attested either
    }
    socket.on('error', () => {})
    /** @type {string} */
    let buffer = ''
    const timer = setTimeout(() => {
      reply(socket, { ok: false, error: { code: 'ETIMEOUT', message: 'identity request timed out' } })
    }, REQUEST_TIMEOUT_MS)
    timer.unref?.()
    socket.on('data', (chunk) => {
      buffer += chunk
      if (buffer.length > MAX_LINE_BYTES) {
        clearTimeout(timer)
        reply(socket, { ok: false, error: { code: 'ETOOLONG', message: 'identity request too long' } })
        return
      }
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      clearTimeout(timer)
      const line = buffer.slice(0, newline).trim()
      buffer = ''
      if (line === '') return
      handleLine(socket, line)
    })
    socket.on('close', () => clearTimeout(timer))
  }

  return {
    /**
     * Bind the channel on 127.0.0.1 with an ephemeral port.
     * @returns {Promise<number>}
     */
    start() {
      if (server !== null) return Promise.resolve(boundPort ?? 0)
      server = net.createServer(onConnection)
      return new Promise((resolve, reject) => {
        const onError = (error) => {
          server?.removeListener('listening', onListening)
          reject(error)
        }
        const onListening = () => {
          server?.removeListener('error', onError)
          const address = server?.address()
          boundPort = address !== null && typeof address === 'object' && typeof address.port === 'number' ? address.port : 0
          log('identity channel listening on 127.0.0.1:' + String(boundPort))
          resolve(boundPort)
        }
        server.once('error', onError)
        server.once('listening', onListening)
        server.listen(0, '127.0.0.1')
      })
    },
    /** @returns {number | null} */
    port() {
      return boundPort
    },
    /**
     * Redeem one attested nonce. Single use: the pipe handshake consumes it.
     * @param {string} nonce
     */
    consume(nonce) {
      const key = typeof nonce === 'string' ? nonce.trim() : ''
      if (key === '') return { ok: false, code: 'ENONONCE', message: '请求没有携带 nonce' }
      const ticket = tickets.get(key)
      if (ticket === undefined) return { ok: false, code: 'EUNATTESTED', message: 'nonce 未在身份通道上登记（或已被使用）' }
      tickets.delete(key)
      if (now() - ticket.at > ttlMs) return { ok: false, code: 'EEXPIRED', message: 'nonce 已过期' }
      return { ok: true, ticket }
    },
    snapshot() {
      prune()
      return {
        listening: boundPort !== null,
        port: boundPort,
        requests,
        allowed: allowedCount,
        denied: deniedCount,
        outstandingTickets: tickets.size,
        ttlMs,
        last,
      }
    },
    stop() {
      if (server === null) return
      const closing = server
      server = null
      try {
        closing.close()
      } catch {
        // already closed
      }
    },
    /** Test seam: the nonce generator lives here so tests can pin its shape. */
    newNonce() {
      return randomBytes(16).toString('hex')
    },
  }
}
