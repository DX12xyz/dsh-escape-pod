/**
 * Channel segments for the escape-pod ledger.
 *
 * `out.log` stays the one byte-continuous authoritative stream (absolute offsets,
 * append-only). `segments.jsonl` sits beside it and records, for each written
 * run of bytes, which stream produced it: `{ offset, length, channel }`.
 * Readers split a byte range with {@link coverRange} and decode each piece, which
 * is how the Host rebuilds native `JobChunk.channel` information without moving
 * a single offset.
 *
 * Segment boundaries are written only at decoded-text boundaries (the pod uses a
 * per-channel `StringDecoder` before writing), so a chunk never splits a UTF-8
 * code point and `Buffer.concat(chunks.map(c => Buffer.from(c.text)))` equals the
 * bytes in `out.log`.
 *
 * This module is dependency-free so both the pod and the self-tests can use it.
 */

export const SEGMENTS_FILE = 'segments.jsonl'
export const CHANNELS = Object.freeze(['stdout', 'stderr', 'log'])

/** @param {unknown} channel */
export function normalizeChannel(channel) {
  return channel === 'stderr' || channel === 'log' ? channel : 'stdout'
}

/**
 * Parse `segments.jsonl` text, ignoring malformed lines.
 * @param {string} text
 */
export function parseSegments(text) {
  /** @type {{ offset: number, length: number, channel: string }[]} */
  const entries = []
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (line.trim() === '') continue
    try {
      const raw = JSON.parse(line)
      if (!Number.isInteger(raw?.offset) || raw.offset < 0) continue
      if (!Number.isInteger(raw?.length) || raw.length <= 0) continue
      entries.push({ offset: raw.offset, length: raw.length, channel: normalizeChannel(raw.channel) })
    } catch {
      // a partially written trailing line is not a segment
    }
  }
  return entries
}

/**
 * Keep the contiguous prefix that fits inside `totalBytes`. A crash between the
 * `out.log` write and the segment append can leave a gap; readers fall back to
 * `stdout` for uncovered bytes instead of trusting a shifted segment.
 * @param {{ offset: number, length: number, channel: string }[]} entries
 * @param {number} totalBytes
 */
export function sanitizeSegments(entries, totalBytes) {
  const sorted = entries
    .filter((entry) => entry.offset + entry.length <= totalBytes)
    .sort((left, right) => left.offset - right.offset)
  /** @type {{ offset: number, length: number, channel: string }[]} */
  const kept = []
  let expected = 0
  for (const entry of sorted) {
    if (entry.offset < expected) continue // overlap: later entries lose
    if (entry.offset > expected) break // gap: drop the rest
    kept.push({ offset: entry.offset, length: entry.length, channel: normalizeChannel(entry.channel) })
    expected = entry.offset + entry.length
  }
  return kept
}

/**
 * Split `[from, to)` into channel pieces, filling any uncovered byte range with
 * `fallbackChannel`. Offsets stay absolute; lengths are positive.
 * @param {{ offset: number, length: number, channel: string }[]} segments
 * @param {number} from
 * @param {number} to
 * @param {string} [fallbackChannel]
 */
export function coverRange(segments, from, to, fallbackChannel = 'stdout') {
  const start = Math.max(0, Math.trunc(from))
  const end = Math.max(start, Math.trunc(to))
  /** @type {{ offset: number, length: number, channel: string }[]} */
  const pieces = []
  let cursor = start
  for (const segment of segments) {
    const segStart = segment.offset
    const segEnd = segment.offset + segment.length
    if (segEnd <= cursor) continue
    if (segStart >= end) break
    if (segStart > cursor) {
      pieces.push({ offset: cursor, length: Math.min(segStart, end) - cursor, channel: normalizeChannel(fallbackChannel) })
      cursor = Math.min(segStart, end)
      if (cursor >= end) break
    }
    const pieceStart = Math.max(segStart, cursor)
    const pieceEnd = Math.min(segEnd, end)
    if (pieceEnd > pieceStart) {
      pieces.push({ offset: pieceStart, length: pieceEnd - pieceStart, channel: normalizeChannel(segment.channel) })
      cursor = pieceEnd
    }
    if (cursor >= end) break
  }
  if (cursor < end) pieces.push({ offset: cursor, length: end - cursor, channel: normalizeChannel(fallbackChannel) })
  return pieces
}

/**
 * Build decoded chunks for `[from, to)`.
 * @param {{
 *   segments: { offset: number, length: number, channel: string }[],
 *   from: number, to: number,
 *   readBytes: (offset: number, length: number) => Buffer,
 *   fallbackChannel?: string,
 * }} input
 */
export function buildChunks(input) {
  return coverRange(input.segments, input.from, input.to, input.fallbackChannel)
    .map((piece) => ({
      offset: piece.offset,
      length: piece.length,
      channel: piece.channel,
      text: input.readBytes(piece.offset, piece.length).toString('utf8'),
    }))
    .filter((chunk) => chunk.text.length > 0)
}
