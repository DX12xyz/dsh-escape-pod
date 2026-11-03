#!/usr/bin/env node
/**
 * Non-model raw output reader ("supervisor CLI"). The model-facing `pod_output`
 * has no offsets; this script is the escape hatch for a human/maintainer who
 * needs an absolute read (debugging, forensics, verifying a chunk boundary).
 *
 * It is deliberately NOT registered as a tool: it never appears in the model's
 * tool table, and it does NOT write a cursor (a raw re-read must not move the
 * model's consumed anchor).
 *
 * Usage:
 *   node pod-raw.mjs --job <jobId> --from 0 [--max-bytes 65536] [--json] [--token <hex>] [--adopt]
 *   node pod-raw.mjs --job <jobId> --cursor [--json] [--adopt]
 *   node pod-raw.mjs --handover --job <jobId> --cursor        # claim an orphaned pod
 *   # --pipe defaults to the identity-derived name (user + hostname), not DSH_HOME
 *
 * The pod now requires the spawn-time token on every request, and that token
 * lives only in the Host's memory. A running DSH cannot hand it out, so:
 *   - `--token <hex>` / `--token-stdin`  use a token you already know (e.g. you
 *     spawned the pod yourself with `--auth open`... which needs none);
 *   - `--handover`  rotate the token of an ORPHANED pod (no live Host client)
 *     and use the new one for this invocation. It is rejected with EBUSY while a
 *     DSH still holds the pod, so it cannot steal a live pod.
 *
 * Exit codes: 0 ok, 2 usage/pipe/protocol/auth error.
 */

import net from 'node:net'
import { generatePodToken, isPodToken, resolvePipeName } from '../shared.mjs'

const USAGE = `pod-raw — non-model absolute reader for @local/dsh-escape-pod

  node pod-raw.mjs --job <jobId> --from <bytes> [--max-bytes <n>] [--json] [--adopt]
  node pod-raw.mjs --job <jobId> --cursor [--json] [--adopt]
  node pod-raw.mjs --handover --job <jobId> --cursor

  --pipe <name>   override the pipe (default: identity-derived)
  --token <hex>   the pod's current spawn token (64 hex chars)
  --token-stdin   read that token from the first stdin line
  --handover      rotate an ORPHANED pod's token first, then read with it
  --adopt         read a job owned by another DSH session (explicit takeover;
                  without it the pod answers EFOREIGNJOB)
  --json          print the raw protocol response
This script reads bytes only; it never advances the model-visible cursor.`

/** @param {string[]} argv */
function parseArgs(argv) {
  /** @type {Record<string, string | boolean>} */
  const options = { json: false, cursor: false, handover: false, adopt: false }
  const valueFlags = new Set(['--pipe', '--job', '--from', '--max-bytes', '--token'])
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    if (token === '--json') options.json = true
    else if (token === '--cursor') options.cursor = true
    else if (token === '--handover') options.handover = true
    else if (token === '--adopt') options.adopt = true
    else if (token === '--token-stdin') options['token-stdin'] = true
    else if (token === '--help' || token === '-h') options.help = true
    else if (valueFlags.has(token)) {
      const value = argv[index + 1]
      if (value === undefined) throw new Error('缺少参数值：' + token)
      options[token.slice(2)] = value
      index += 1
    } else {
      throw new Error('未知参数：' + token)
    }
  }
  return options
}

/** @param {Record<string, string | boolean>} options */
function resolvePipe(options) {
  return resolvePipeName(typeof options.pipe === 'string' && options.pipe !== '' ? options.pipe : undefined)
}

/** First line of stdin (the token), or null. */
async function readTokenLine() {
  let text = ''
  for await (const chunk of process.stdin) {
    text += String(chunk)
    const newline = text.indexOf('\n')
    if (newline >= 0) return text.slice(0, newline).trim()
    if (text.length > 4096) return null
  }
  return text.trim() === '' ? null : text.trim()
}

/** One NDJSON request against the pod's maintenance pipe. */
function request(pipeName, op, payload, token, timeoutMs = 15000) {
  return new Promise((resolvePromise, reject) => {
    const socket = net.connect(pipeName)
    let buffer = ''
    let settled = false
    /** @param {Error} error */
    const fail = (error) => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(error)
    }
    const timer = setTimeout(() => fail(new Error('请求超时：' + op)), timeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
    socket.setEncoding('utf8')
    socket.on('connect', () => {
      /** @type {Record<string, unknown>} */
      const body = { id: 'raw-' + String(Date.now()), op, ...payload }
      if (typeof token === 'string' && token !== '') body.token = token
      socket.write(JSON.stringify(body) + '\n')
    })
    socket.on('data', (chunk) => {
      buffer += chunk
      let newline = buffer.indexOf('\n')
      while (newline >= 0) {
        const line = buffer.slice(0, newline)
        buffer = buffer.slice(newline + 1)
        try {
          const response = JSON.parse(line)
          if (!settled) {
            settled = true
            clearTimeout(timer)
            socket.end()
            resolvePromise(response)
          }
        } catch {
          // keep reading; a partial line is normal
        }
        newline = buffer.indexOf('\n')
      }
    })
    socket.on('error', (error) => fail(error))
    socket.on('close', () => {
      if (!settled) fail(new Error('管道提前关闭：' + pipeName))
    })
  })
}

async function main() {
  /** @type {Record<string, string | boolean>} */
  let options
  try {
    options = parseArgs(process.argv.slice(2))
  } catch (error) {
    process.stderr.write(String(error instanceof Error ? error.message : error) + '\n\n' + USAGE + '\n')
    return 2
  }
  if (options.help === true) {
    process.stdout.write(USAGE + '\n')
    return 0
  }
  const jobId = typeof options.job === 'string' ? options.job : ''
  if (!/^podc-[0-9a-z]{1,12}-[0-9a-f]{8}$/.test(jobId)) {
    process.stderr.write('缺少或非法 --job（应形如 podc-<stamp>-<hex8>）\n\n' + USAGE + '\n')
    return 2
  }
  let pipeName
  try {
    pipeName = resolvePipe(options)
  } catch (error) {
    process.stderr.write(String(error instanceof Error ? error.message : error) + '\n')
    return 2
  }
  const json = options.json === true
  /** @type {string | null} */
  let token = typeof options.token === 'string' ? options.token : null
  if (token !== null && !isPodToken(token)) {
    process.stderr.write('--token 必须是 32 字节 hex（64 个小写十六进制字符）\n')
    return 2
  }
  if (token === null && options['token-stdin'] === true) {
    token = await readTokenLine()
    if (!isPodToken(token)) {
      process.stderr.write('--token-stdin：标准输入第一行不是合法的 32 字节 hex token\n')
      return 2
    }
  }
  const authHint = '（pod 现在要求 spawn 期 token，且它只在 Host 内存里；用 --token/--token-stdin 传入已知 token，或对一个空闲 pod 用 --handover 轮换）'
  try {
    if (token === null && options.handover === true) {
      const newToken = generatePodToken()
      const claimed = await request(pipeName, 'handover', { newToken }, null)
      if (claimed.ok !== true) {
        process.stderr.write(
          'handover 被拒绝（' + String(claimed?.error?.code ?? 'unknown') + '）：' + String(claimed?.error?.message ?? '') + '\n',
        )
        return 2
      }
      token = newToken
      process.stderr.write('[raw] handover accepted：pod token 已轮换，本次调用使用新 token（handoverCount=' + String(claimed?.auth?.handoverCount ?? '?') + '）\n')
    }
    if (options.cursor === true) {
      const response = await request(pipeName, 'cursor', { jobId, adopt: options.adopt === true }, token)
      if (json) process.stdout.write(JSON.stringify(response) + '\n')
      else if (response.ok === true) process.stdout.write(JSON.stringify(response.cursor, null, 2) + '\n')
      else if (response?.error?.code === 'EBADTOKEN') process.stderr.write(String(response?.error?.message ?? '') + authHint + '\n')
      else process.stderr.write(String(response?.error?.message ?? 'cursor 读取失败') + '\n')
      return response.ok === true ? 0 : 2
    }
    const from = options.from === undefined ? 0 : Number(options.from)
    const maxBytes = options['max-bytes'] === undefined ? undefined : Number(options['max-bytes'])
    if (!Number.isInteger(from) || from < 0) throw new Error('--from 必须是非负整数')
    /** @type {Record<string, unknown>} */
    const payload = { jobId, from, adopt: options.adopt === true }
    if (Number.isInteger(maxBytes)) payload.maxBytes = maxBytes
    const response = await request(pipeName, 'output', payload, token)
    if (response.ok !== true) {
      if (response?.error?.code === 'EBADTOKEN') process.stderr.write(String(response?.error?.message ?? '') + authHint + '\n')
      else process.stderr.write(String(response?.error?.message ?? '读取失败') + '\n')
      return 2
    }
    if (json) {
      process.stdout.write(JSON.stringify(response) + '\n')
    } else {
      process.stdout.write(response.text)
      process.stderr.write(
        '\n[raw] job=' + jobId + ' from=' + String(response.from) + ' next=' + String(response.nextOffset) +
        ' total=' + String(response.totalBytes) + ' status=' + String(response.status) + '\n',
      )
    }
    return 0
  } catch (error) {
    process.stderr.write('pod-raw 失败：' + String(error instanceof Error ? error.message : error) + '\n')
    return 2
  }
}

process.exitCode = await main()
