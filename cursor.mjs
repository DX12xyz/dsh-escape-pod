/**
 * Output-cursor and prefix-hash primitives.
 *
 * The adoption fix needs two things the pod can prove about its own ledger:
 *
 *   1. a HOST-READ CURSOR (`jobs/<jobId>/cursor.json`) saying "the Host had
 *      consumed exactly these `offset` bytes", so a new Host adopts at that
 *      offset instead of at the pod's current total — otherwise output produced
 *      while DSH was down never reaches `job_output`;
 *   2. a PREFIX HASH over bytes [0, offset), so that cursor can be checked
 *      against the current `out.log`. If the retained prefix changed (partial
 *      overwrite, foreign job id, corrupted file), the hash differs and the
 *      cursor must be reported as a mismatch instead of silently continuing.
 *
 * The hash is a plain sha256 of the exact prefix bytes. Computing it naively on
 * every ack would be O(n) per ack, so the hasher snapshots a `Hash.copy()` at
 * every checkpoint (64 KiB by default) while it streams the file once. An ack at
 * an arbitrary offset then costs at most one checkpoint interval of hashing,
 * while the mathematical meaning stays "sha256 of bytes 0..offset".
 *
 * This module has no Cordis and no pod dependencies: the pod passes a
 * `readRange(start, length)` reader, and the tests pass either a fake reader or
 * a real file reader.
 */

import { createHash } from 'node:crypto'

export const CURSOR_SCHEMA = 1
export const CURSOR_ALGORITHM = 'sha256-prefix'
export const CHECKPOINT_BYTES = 64 * 1024

/** @param {unknown} value */
function isOffset(value) {
  return Number.isInteger(value) && /** @type {number} */ (value) >= 0
}

/**
 * Incremental sha256 over a growing byte prefix, with checkpoints.
 * @param {{ readRange: (start: number, length: number) => Buffer, blockBytes?: number }} options
 */
export function createPrefixHasher(options) {
  const readRange = options.readRange
  const blockBytes = Number.isInteger(options.blockBytes) && options.blockBytes >= 1 ? options.blockBytes : CHECKPOINT_BYTES
  const liveHash = createHash('sha256')
  /** @type {{ offset: number, state: import('node:crypto').Hash }[]} */
  const checkpoints = []
  let builtTo = 0

  /** @param {Buffer} buffer */
  function feed(buffer) {
    let consumed = 0
    while (consumed < buffer.length) {
      const boundary = Math.floor(builtTo / blockBytes) * blockBytes + blockBytes
      const take = Math.min(boundary - builtTo, buffer.length - consumed)
      liveHash.update(buffer.subarray(consumed, consumed + take))
      builtTo += take
      consumed += take
      if (builtTo === boundary) checkpoints.push({ offset: builtTo, state: liveHash.copy() })
      if (take === 0) break
    }
  }

  /** @param {number} target */
  function extendTo(target) {
    if (!isOffset(target)) throw new Error('prefix hash 目标偏移非法：' + String(target))
    if (target <= builtTo) return
    const needed = target - builtTo
    const bytes = readRange(builtTo, needed)
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
      throw new Error('无法读取前缀字节：需要 ' + String(needed) + ' 字节 @ ' + String(builtTo))
    }
    feed(bytes)
    if (builtTo < target) {
      throw new Error('前缀不完整：只读到 ' + String(builtTo) + ' / ' + String(target) + ' 字节（账本可能被截断）')
    }
  }

  /**
   * sha256 over bytes [0, offset). Extends the stream first when needed.
   * @param {number} offset
   */
  function hashAt(offset) {
    extendTo(offset)
    /** @type {{ offset: number, state: import('node:crypto').Hash } | null} */
    let best = null
    for (const checkpoint of checkpoints) {
      if (checkpoint.offset <= offset) best = checkpoint
      else break
    }
    const state = best === null ? createHash('sha256') : best.state.copy()
    const base = best === null ? 0 : best.offset
    if (offset > base) {
      const bytes = readRange(base, offset - base)
      if (!Buffer.isBuffer(bytes) || bytes.length < offset - base) {
        throw new Error('前缀校验读取失败：' + String(base) + '..' + String(offset))
      }
      state.update(bytes)
    }
    return state.digest('hex')
  }

  return {
    feed,
    extendTo,
    hashAt,
    get builtTo() {
      return builtTo
    },
    get checkpointCount() {
      return checkpoints.length
    },
  }
}

/**
 * Validate a stored cursor against the current log.
 *
 * States:
 *   - `missing`     no cursor file (fall back to the pod total; new jobs adopt at 0)
 *   - `malformed`   cursor exists but has no usable offset/hash
 *   - `ahead`       offset > current total (truncated/foreign ledger) → invalid
 *   - `unreadable`  the prefix bytes could not be hashed → invalid
 *   - `mismatch`    hash differs → invalid; the reader must NOT silently continue
 *   - `lossy`       hash matches, but offset is before the live retention window,
 *                   so completeness is not claimed
 *   - `ok`          hash matches inside the window
 *
 * @param {{
 *   cursor: any,
 *   totalBytes: number,
 *   windowStart?: number,
 *   hashAt: (offset: number) => string,
 * }} input
 */
export function validateCursor(input) {
  const cursor = input.cursor
  const totalBytes = Number.isFinite(input.totalBytes) ? input.totalBytes : 0
  const windowStart = Number.isFinite(input.windowStart) ? input.windowStart : 0
  if (cursor === null || cursor === undefined) {
    return { state: 'missing', valid: false, lossy: false, offset: null, hash: null, reason: '账本里没有 cursor.json（从未 ack 过）' }
  }
  if (typeof cursor !== 'object') {
    return { state: 'malformed', valid: false, lossy: false, offset: null, hash: null, reason: 'cursor.json 不是对象' }
  }
  const offset = cursor.offset
  if (!isOffset(offset)) {
    return { state: 'malformed', valid: false, lossy: false, offset: null, hash: null, reason: 'cursor.offset 不是非负整数：' + String(offset) }
  }
  if (typeof cursor.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(cursor.hash)) {
    return { state: 'malformed', valid: false, lossy: false, offset, hash: null, reason: 'cursor.hash 不是 sha256 hex' }
  }
  if (offset > totalBytes) {
    return {
      state: 'ahead',
      valid: false,
      lossy: false,
      offset,
      hash: cursor.hash.toLowerCase(),
      reason: 'cursor.offset=' + String(offset) + ' 超过当前 totalBytes=' + String(totalBytes) + '（账本被截断或是别的 job 的游标）',
    }
  }
  let actual
  try {
    actual = input.hashAt(offset)
  } catch (error) {
    return {
      state: 'unreadable',
      valid: false,
      lossy: false,
      offset,
      hash: cursor.hash.toLowerCase(),
      reason: '无法校验前缀哈希：' + (error instanceof Error ? error.message : String(error)),
    }
  }
  if (actual.toLowerCase() !== cursor.hash.toLowerCase()) {
    return {
      state: 'mismatch',
      valid: false,
      lossy: false,
      offset,
      hash: actual,
      expected: cursor.hash.toLowerCase(),
      reason: '前缀 hash 不匹配：cursor=' + cursor.hash.slice(0, 12) + '… 实际=' + actual.slice(0, 12) + '…（保留的日志前缀变了）',
    }
  }
  const lossy = offset < windowStart
  return {
    state: lossy ? 'lossy' : 'ok',
    valid: true,
    lossy,
    offset,
    hash: actual,
    windowStart,
    reason: lossy
      ? 'cursor.offset=' + String(offset) + ' 早于保留窗口起点 ' + String(windowStart) + '（内存环已丢弃；out.log 可能仍可读，但不保证完整补全）'
      : null,
  }
}
