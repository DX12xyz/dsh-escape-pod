/**
 * OS-level client attestation for the escape pod's named pipe.
 *
 * The pod's pipe is the only control surface of a process that outlives DSH.
 * A token alone cannot protect it: the token must survive a restart, so it has
 * to exist somewhere a later Host can read, and anything a later Host can read
 * a same-user attacker can read too. This module adds the part the OS *can*
 * answer without any shared secret — "which process is on the other end of this
 * pipe, and what is it?":
 *
 *   GetNamedPipeClientProcessId   → the connecting process id, from the kernel
 *   OpenProcess/QueryFullProcess… → its image path
 *   GetProcessTimes               → its creation time (defeats PID reuse)
 *   OpenProcessToken/GetToken…    → its user SID, integrity level, and whether
 *                                   it is a restricted (sandboxed) token
 *   ProcessIdToSessionId          → its logon session
 *
 * The first row only works when we have a Win32 HANDLE for the pipe socket, and
 * Node does not expose one (`_handle.fd` is -1 for a pod's listening pipe and
 * for accepted connections alike). `describeClient` is therefore kept for
 * transports that do expose a handle, while the pod's real path is the loopback
 * identity channel: a TCP 4-tuple is looked up in GetExtendedTcpTable to get the
 * exact peer pid, then the same token facts are read (`describeTcpPeer`). See
 * identity.mjs for the nonce handshake that binds that answer to a pipe request.
 *
 * All of it is read through Koffi (prebuilt FFI), so the pod needs no native
 * addon and no compiler. Koffi is resolved from the DSH install the pod was
 * spawned by (DSH_HOME/profiles/node_modules), not from a hard-coded path.
 *
 * Honest limit: this is a *policy* boundary, not a cryptographic one. A
 * same-user process that deliberately starts a matching image can still pass.
 * See research/逃生舱-接入鉴权.md for why, and for the deployment shapes that
 * do give a real boundary.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'

/** Access rights and token classes used below. */
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
const TOKEN_QUERY = 0x0008
const TOKEN_USER = 1
const TOKEN_RESTRICTED_SIDS = 11
const TOKEN_INTEGRITY_LEVEL = 25
const ERROR_INSUFFICIENT_BUFFER = 122
/** GetExtendedTcpTable: IPv4, all TCP rows with owning pid. */
const AF_INET = 2
const TCP_TABLE_OWNER_PID_ALL = 5

/** Windows integrity levels, as the RID of S-1-16-<rid>. */
export const INTEGRITY_RID = Object.freeze({
  untrusted: 0x0000,
  low: 0x1000,
  medium: 0x2000,
  mediumPlus: 0x2100,
  high: 0x3000,
  system: 0x4000,
  protected: 0x5000,
})

/**
 * Human-readable integrity level for logs.
 * @param {number} rid
 */
export function integrityName(rid) {
  if (rid >= INTEGRITY_RID.protected) return 'protected'
  if (rid >= INTEGRITY_RID.system) return 'system'
  if (rid >= INTEGRITY_RID.high) return 'high'
  if (rid >= INTEGRITY_RID.mediumPlus) return 'medium-plus'
  if (rid >= INTEGRITY_RID.medium) return 'medium'
  if (rid >= INTEGRITY_RID.low) return 'low'
  return 'untrusted'
}

/**
 * `off` / `warn` / `enforce`, from an environment variable or a policy file.
 * Anything unrecognised is `warn`: observing is the safe default, and a typo
 * must never silently disable the check (`off`).
 *
 * @param {string | undefined} raw
 * @returns {'off' | 'warn' | 'enforce'}
 */
export function normalizeAttestMode(raw) {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : ''
  if (value === 'off' || value === 'enforce' || value === 'warn') return value
  return 'warn'
}

/** Integrity keywords accepted by both `PODC_ATTEST_MIN_INTEGRITY` and the policy file. */
const ATTEST_INTEGRITY_KEYWORDS = Object.freeze({
  untrusted: INTEGRITY_RID.untrusted,
  low: INTEGRITY_RID.low,
  medium: INTEGRITY_RID.medium,
  'medium-plus': INTEGRITY_RID.mediumPlus,
  high: INTEGRITY_RID.high,
  system: INTEGRITY_RID.system,
})

/** A policy file is a few hundred bytes; anything bigger is not a policy. */
const ATTEST_POLICY_MAX_BYTES = 64 * 1024

/**
 * Validate the optional fields of `attest-policy.json`.
 *
 * Every field is optional, but a field that is present and wrong invalidates
 * the WHOLE file. Silently ignoring a typo (`"mode": "enforce "` is fine after
 * trimming, but `"mode": "enforse"` or `"enforce": true` is not) could leave an
 * operator believing they tightened policy while the previous, looser one is
 * still in force — and, worse, a stray `"mode": "off"` next to a bad field
 * would relax it.
 *
 * @param {unknown} raw parsed JSON
 * @returns {{ ok: true, value: { mode?: 'off' | 'warn' | 'enforce', minIntegrityRid?: number, allowRestricted?: boolean, allowedImages?: string[] } } | { ok: false, message: string }}
 */
export function parseAttestPolicyFile(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, message: '顶层必须是 JSON 对象' }
  }
  const record = /** @type {Record<string, unknown>} */ (raw)
  /** @type {{ mode?: 'off' | 'warn' | 'enforce', minIntegrityRid?: number, allowRestricted?: boolean, allowedImages?: string[] }} */
  const value = {}
  if (record.mode !== undefined) {
    const mode = typeof record.mode === 'string' ? record.mode.trim().toLowerCase() : ''
    if (mode !== 'off' && mode !== 'warn' && mode !== 'enforce') {
      return { ok: false, message: 'mode 必须是 "off" | "warn" | "enforce"（实际 ' + JSON.stringify(record.mode) + '）' }
    }
    value.mode = mode
  }
  if (record.minIntegrity !== undefined) {
    const name = typeof record.minIntegrity === 'string' ? record.minIntegrity.trim().toLowerCase() : ''
    const rid = ATTEST_INTEGRITY_KEYWORDS[name]
    if (typeof rid !== 'number') {
      return {
        ok: false,
        message: 'minIntegrity 必须是 untrusted|low|medium|medium-plus|high|system（实际 ' + JSON.stringify(record.minIntegrity) + '）',
      }
    }
    value.minIntegrityRid = rid
  }
  if (record.allowRestricted !== undefined) {
    if (typeof record.allowRestricted !== 'boolean') {
      return { ok: false, message: 'allowRestricted 必须是布尔值（实际 ' + JSON.stringify(record.allowRestricted) + '）' }
    }
    value.allowRestricted = record.allowRestricted
  }
  if (record.allowedImages !== undefined) {
    if (!Array.isArray(record.allowedImages) || record.allowedImages.length === 0) {
      return { ok: false, message: 'allowedImages 必须是非空字符串数组' }
    }
    /** @type {string[]} */
    const images = []
    for (const entry of record.allowedImages) {
      if (typeof entry !== 'string' || entry.trim() === '') {
        return { ok: false, message: 'allowedImages 的每一项都必须是非空字符串（实际 ' + JSON.stringify(entry) + '）' }
      }
      images.push(entry.trim())
    }
    value.allowedImages = images
  }
  return { ok: true, value }
}

/**
 * The live attestation policy: environment pins first, `<dataRoot>/attest-policy.json`
 * second, built-in defaults last.
 *
 * Why a file at all: the environment a pod was spawned with is fixed for its
 * lifetime, and the pod outlives DSH — changing `PODC_ATTEST` would require
 * restarting DSH (and, worse, killing the pod). The file is re-`stat()`ed on
 * every `current()` call (one per identity request), so writing it switches
 * warn→enforce without a restart.
 *
 * Corruption policy: a file that cannot be read, parsed or validated never
 * changes the active policy. The last valid file stays in force (or, before the
 * first valid file, the env/default policy does), and the failure is logged once
 * per changed file plus exposed through `describe().fileError`. In particular a
 * damaged file can never move the pod to `off`.
 *
 * Priority is per field, so `PODC_ATTEST_MIN_INTEGRITY=high` still wins while
 * the file supplies `mode`.
 *
 * @param {{ dataRoot?: string, selfFacts?: any, env?: Record<string, string | undefined>, log?: (message: string) => void, now?: () => number }} [options]
 */
export function createAttestPolicySource(options = {}) {
  const env = options.env ?? process.env
  const log = typeof options.log === 'function' ? options.log : () => {}
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const selfFacts = options.selfFacts ?? null
  const filePath = typeof options.dataRoot === 'string' && options.dataRoot !== ''
    ? join(options.dataRoot, 'attest-policy.json')
    : ''

  /** @param {string} name @returns {string | null} */
  const envText = (name) => {
    const raw = env[name]
    return typeof raw === 'string' && raw.trim() !== '' ? raw.trim() : null
  }

  // Env pins: null means "not pinned, the file (or the default) decides".
  const rawMode = envText('PODC_ATTEST')
  const envMode = rawMode === null ? null : normalizeAttestMode(rawMode)
  const rawIntegrity = envText('PODC_ATTEST_MIN_INTEGRITY')
  const envMinIntegrityRid = rawIntegrity === null
    ? null
    : ATTEST_INTEGRITY_KEYWORDS[rawIntegrity.toLowerCase()] ?? INTEGRITY_RID.medium
  const rawAllowRestricted = envText('PODC_ATTEST_ALLOW_RESTRICTED')
  const envAllowRestricted = rawAllowRestricted === null ? null : rawAllowRestricted === '1'
  const rawImages = envText('PODC_ATTEST_IMAGES')
  const envImages = rawImages === null
    ? null
    : (() => {
      const images = rawImages.split(';').map((entry) => entry.trim()).filter((entry) => entry !== '')
      return images.length > 0 ? images : null
    })()

  /** @type {{ mode?: 'off' | 'warn' | 'enforce', minIntegrityRid?: number, allowRestricted?: boolean, allowedImages?: string[] } | null} */
  let filePolicy = null
  /** @type {string | null} identity of the last file state we looked at */
  let fileSignature = null
  /** @type {{ code: string, message: string, at: string, path: string } | null} */
  let fileError = null
  /** @type {string | null} */
  let fileLoadedAt = null

  /** @returns {string[]} */
  function defaultImages() {
    const image = typeof selfFacts?.imagePath === 'string' && selfFacts.imagePath !== '' ? selfFacts.imagePath : process.execPath
    return [image]
  }

  /** @param {{ mode?: string, minIntegrityRid?: number, allowRestricted?: boolean, allowedImages?: string[] }} value */
  function describeFilePolicy(value) {
    /** @type {string[]} */
    const parts = []
    if (value.mode !== undefined) parts.push('mode=' + value.mode)
    if (value.minIntegrityRid !== undefined) parts.push('minIntegrity=' + integrityName(value.minIntegrityRid))
    if (value.allowRestricted !== undefined) parts.push('allowRestricted=' + String(value.allowRestricted))
    if (value.allowedImages !== undefined) parts.push('allowedImages=' + value.allowedImages.join('|'))
    return parts.length === 0 ? '空策略（全部沿用环境/默认）' : parts.join(' ')
  }

  /**
   * Merge the three layers into the object `evaluateClient` consumes.
   * @returns {{ mode: 'off' | 'warn' | 'enforce', userSid: string | null, sessionId: number | null, minIntegrityRid: number, allowRestricted: boolean, allowedImages: string[], allowedImagesExact: boolean }}
   */
  function merged() {
    const file = filePolicy ?? {}
    const images = envImages ?? file.allowedImages ?? null
    return {
      mode: envMode ?? file.mode ?? 'warn',
      userSid: typeof selfFacts?.userSid === 'string' ? selfFacts.userSid : null,
      sessionId: typeof selfFacts?.sessionId === 'number' ? selfFacts.sessionId : null,
      minIntegrityRid: envMinIntegrityRid ?? file.minIntegrityRid ?? INTEGRITY_RID.medium,
      allowRestricted: envAllowRestricted ?? file.allowRestricted ?? false,
      allowedImages: images === null || images.length === 0 ? defaultImages() : images.slice(),
      allowedImagesExact: true,
    }
  }

  /**
   * Remember a failed read/parse without touching the active policy.
   * @param {string} message
   */
  function noteFileError(message) {
    fileError = { code: 'EBADATTESTPOLICY', message, at: new Date(now()).toISOString(), path: filePath }
    log('attest-policy: ' + message + '；沿用上一份有效策略（mode=' + merged().mode + '）')
  }

  /** Re-read the file only when mtime/size changed; a no-op otherwise. */
  function refresh() {
    if (filePath === '') return
    /** @type {import('node:fs').Stats | null} */
    let stat = null
    try {
      stat = statSync(filePath)
    } catch (error) {
      const code = String(/** @type {any} */ (error)?.code ?? 'EUNKNOWN')
      if (code !== 'ENOENT') {
        const signature = 'error:' + code
        if (signature !== fileSignature) {
          fileSignature = signature
          noteFileError('无法读取 ' + filePath + '（' + code + '）')
        }
        return
      }
      // Missing file: keep the last valid file policy if we ever had one, so
      // deleting it cannot silently relax an already-enforced policy.
      if (filePolicy !== null && fileSignature !== 'missing') {
        fileSignature = 'missing'
        noteFileError('文件已不存在（' + filePath + '）')
      }
      return
    }
    const signature = String(stat.mtimeMs) + ':' + String(stat.size)
    if (signature === fileSignature) return
    // Set it before parsing: a file that stays broken must log once, not once
    // per identity request.
    fileSignature = signature
    let text = ''
    try {
      text = readFileSync(filePath, 'utf8')
    } catch (error) {
      noteFileError('读取 ' + filePath + ' 失败：' + messageOf(error))
      return
    }
    if (text.length > ATTEST_POLICY_MAX_BYTES) {
      noteFileError('策略文件过大（' + String(text.length) + ' 字节，上限 ' + String(ATTEST_POLICY_MAX_BYTES) + '）')
      return
    }
    /** @type {unknown} */
    let raw = null
    try {
      // Windows editors (and PowerShell 5.1 `Set-Content -Encoding UTF8`) add a
      // UTF-8 BOM; JSON.parse rejects it. Strip it so an operator's perfectly
      // valid file is not reported as corrupt.
      raw = JSON.parse(text.replace(/^\uFEFF/, ''))
    } catch (error) {
      noteFileError('JSON 解析失败：' + messageOf(error))
      return
    }
    const parsed = parseAttestPolicyFile(raw)
    if (parsed.ok !== true) {
      noteFileError('非法策略：' + parsed.message)
      return
    }
    filePolicy = parsed.value
    fileError = null
    fileLoadedAt = new Date(now()).toISOString()
    log('attest-policy: 已加载 ' + filePath + '（' + describeFilePolicy(filePolicy) + '）')
  }

  return {
    /** @returns {string} */
    path() {
      return filePath
    },
    /**
     * The policy to apply right now. Re-reads the file when it changed, so this
     * is what both the identity channel and the pipe handshake must call.
     */
    current() {
      refresh()
      return merged()
    },
    /** Diagnostics for `attest-probe.json`; contains no secrets. */
    describe() {
      refresh()
      const active = merged()
      return {
        path: filePath,
        loadedAt: fileLoadedAt,
        error: fileError,
        file: filePolicy,
        active: {
          mode: active.mode,
          minIntegrity: integrityName(active.minIntegrityRid),
          minIntegrityRid: active.minIntegrityRid,
          allowRestricted: active.allowRestricted,
          allowedImages: active.allowedImages,
        },
        pinnedByEnv: {
          mode: envMode,
          minIntegrityRid: envMinIntegrityRid,
          allowRestricted: envAllowRestricted,
          allowedImages: envImages,
        },
      }
    },
  }
}

/**
 * Locate a loadable `koffi` from the DSH install this pod belongs to.
 *
 * Order matters: the profile's own node_modules is the install the Host is
 * running from, so its ABI always matches the node that spawned the pod. The
 * npx cache is only a fallback for a pod started by hand.
 *
 * @param {{ dshHome?: string | undefined, env?: Record<string, string | undefined> }} [options]
 * @returns {{ ok: true, koffi: any, root: string } | { ok: false, tried: string[] }}
 */
export function resolveKoffi(options = {}) {
  const env = options.env ?? process.env
  /** @type {string[]} */
  const roots = []
  const dshHome = options.dshHome ?? env.DSH_HOME
  if (typeof dshHome === 'string' && dshHome !== '') roots.push(join(dshHome, 'profiles', 'node_modules'))
  const localAppData = env.LOCALAPPDATA
  if (typeof localAppData === 'string' && localAppData !== '') {
    const npxRoot = join(localAppData, 'npm-cache', '_npx')
    try {
      for (const entry of readdirSync(npxRoot)) roots.push(join(npxRoot, entry, 'node_modules'))
    } catch {
      // No npx cache: not an error, just one fewer fallback.
    }
  }
  /** @type {string[]} */
  const tried = []
  for (const root of roots) {
    if (!existsSync(join(root, 'koffi', 'package.json'))) continue
    try {
      const require = createRequire(join(root, '__podc_koffi_probe.cjs'))
      return { ok: true, koffi: require('koffi'), root }
    } catch (error) {
      tried.push(root + ': ' + messageOf(error))
    }
  }
  return { ok: false, tried: tried.length > 0 ? tried : roots.map((root) => root + ': koffi/package.json missing') }
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function messageOf(error) {
  if (error instanceof Error) return error.message
  return String(error)
}

/**
 * Decode a SID that Win32 wrote into a buffer we own.
 *
 * GetTokenInformation returns TOKEN_USER / TOKEN_MANDATORY_LABEL whose first
 * field is a PSID pointing *into that same buffer*. Koffi can decode the
 * pointer but decoding the string it points at is a native call we do not need:
 * the address arithmetic is enough and cannot fault.
 *
 * @param {any} koffi
 * @param {Buffer} buffer
 * @returns {string}
 */
function sidFromOwnedBuffer(koffi, buffer) {
  const base = koffi.address(buffer)
  const offset = Number(buffer.readBigUInt64LE(0) - base)
  if (offset < 0 || offset + 8 > buffer.length) {
    throw new Error('SID pointer is outside the token buffer (offset ' + String(offset) + ')')
  }
  const revision = buffer[offset]
  const count = buffer[offset + 1]
  if (count > 15 || offset + 8 + count * 4 > buffer.length) {
    throw new Error('SID is malformed (sub-authority count ' + String(count) + ')')
  }
  let authority = 0n
  for (let index = 0; index < 6; index += 1) authority = (authority << 8n) | BigInt(buffer[offset + 2 + index])
  /** @type {number[]} */
  const subAuthorities = []
  for (let index = 0; index < count; index += 1) subAuthorities.push(buffer.readUInt32LE(offset + 8 + index * 4))
  return 'S-' + String(revision) + '-' + authority.toString() + (subAuthorities.length > 0 ? '-' + subAuthorities.join('-') : '')
}

/**
 * @param {string} sid
 * @returns {number}
 */
function sidLastRid(sid) {
  const parts = sid.split('-')
  const last = Number(parts[parts.length - 1])
  return Number.isFinite(last) ? last : -1
}

/**
 * Bind the Win32 calls attestation needs, plus the small helpers that keep the
 * pointer handling in one place.
 *
 * @param {any} koffi
 */
function createBindings(koffi) {
  const PVOID = koffi.pointer('void')
  const PUINT32 = koffi.pointer('uint32')
  const kernel32 = koffi.load('kernel32.dll')
  const advapi32 = koffi.load('advapi32.dll')
  const ntdll = koffi.load('ntdll.dll')
  const iphlpapi = koffi.load('iphlpapi.dll')
  /** @param {any} library @param {string} name @param {any} result @param {any[]} args */
  const bind = (library, name, result, args) => library.func('__stdcall', name, result, args)

  const api = {
    getNamedPipeInfo: bind(kernel32, 'GetNamedPipeInfo', 'int', [PVOID, PUINT32, PUINT32, PUINT32, PUINT32]),
    getNamedPipeClientProcessId: bind(kernel32, 'GetNamedPipeClientProcessId', 'int', [PVOID, PUINT32]),
    getNamedPipeServerProcessId: bind(kernel32, 'GetNamedPipeServerProcessId', 'int', [PVOID, PUINT32]),
    openProcess: bind(kernel32, 'OpenProcess', PVOID, ['uint32', 'int', 'uint32']),
    queryFullProcessImageNameW: bind(kernel32, 'QueryFullProcessImageNameW', 'int', [PVOID, 'uint32', PVOID, PUINT32]),
    getProcessTimes: bind(kernel32, 'GetProcessTimes', 'int', [PVOID, PVOID, PVOID, PVOID, PVOID]),
    closeHandle: bind(kernel32, 'CloseHandle', 'int', [PVOID]),
    getLastError: bind(kernel32, 'GetLastError', 'uint32', []),
    processIdToSessionId: bind(kernel32, 'ProcessIdToSessionId', 'int', ['uint32', PUINT32]),
    openProcessToken: bind(advapi32, 'OpenProcessToken', 'int', [PVOID, 'uint32', PVOID]),
    getTokenInformation: bind(advapi32, 'GetTokenInformation', 'int', [PVOID, 'int', PVOID, 'uint32', PUINT32]),
    ntQueryInformationProcess: bind(ntdll, 'NtQueryInformationProcess', 'int', [PVOID, 'int', PVOID, 'uint32', PUINT32]),
    getExtendedTcpTable: bind(iphlpapi, 'GetExtendedTcpTable', 'uint32', [PVOID, PUINT32, 'int', 'uint32', 'uint32', 'uint32']),
  }

  const allocU32 = () => koffi.alloc('uint32', 1)
  const readU32 = (/** @type {any} */ slot) => koffi.decode(slot, 'uint32')
  const allocPtr = () => koffi.alloc(PVOID, 1)
  const readPtr = (/** @type {any} */ slot) => koffi.decode(slot, PVOID)

  /**
   * @param {boolean} ok
   * @param {string} where
   */
  const must = (ok, where) => {
    if (!ok) throw new Error(where + ' failed (Win32 ' + String(api.getLastError()) + ')')
  }

  return { api, PVOID, allocU32, readU32, allocPtr, readPtr, must, koffi }
}

/**
 * Create the attestor. Loading is lazy and failure is not fatal: a pod without
 * attestation still runs (and says so), which is what keeps a koffi problem
 * from taking down the only thing that survived the restart.
 *
 * @param {{ log?: (message: string) => void, env?: Record<string, string | undefined>, dshHome?: string | undefined }} [options]
 */
export function createAttestor(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  /** @type {any} */
  let bindings = null
  /** @type {string | null} */
  let unavailableReason = null
  let attempted = false

  function ensure() {
    if (attempted) return bindings
    attempted = true
    const resolved = resolveKoffi({ dshHome: options.dshHome, env: options.env })
    if (resolved.ok !== true) {
      unavailableReason = 'koffi 不可用：' + resolved.tried.join('; ')
      log('attestation unavailable: ' + unavailableReason)
      return null
    }
    try {
      bindings = createBindings(resolved.koffi)
      log('attestation ready (koffi from ' + resolved.root + ')')
      return bindings
    } catch (error) {
      unavailableReason = 'Win32 绑定失败：' + messageOf(error)
      log('attestation unavailable: ' + unavailableReason)
      return null
    }
  }

  /**
   * Read the Win32 HANDLE behind an accepted Node pipe socket.
   *
   * In practice this transport never provides one: Node/libuv reports
   * `_handle.fd === -1` for both the listening socket and an accepted named-pipe
   * connection on Windows, so `ENOHANDLE` is the normal, expected answer — not
   * evidence against the client. If some future Node version does expose a
   * usable value, it is validated with GetNamedPipeInfo before use. Identity on
   * the pipe therefore rests on the handover nonce from the loopback identity
   * channel (see identity.mjs), not on this handle.
   *
   * @param {any} socket
   */
  function resolveHandle(socket) {
    const bound = ensure()
    if (bound === null) return { ok: false, code: 'EUNAVAILABLE', message: unavailableReason ?? 'attestation unavailable' }
    const raw = socket?._handle?.fd
    if (typeof raw !== 'number' || raw <= 0) {
      return { ok: false, code: 'ENOHANDLE', message: 'socket._handle.fd 不是可用的 Win32 HANDLE（值 ' + String(raw) + '）' }
    }
    const flags = bound.allocU32()
    const outSize = bound.allocU32()
    const inSize = bound.allocU32()
    const instances = bound.allocU32()
    if (!bound.api.getNamedPipeInfo(raw, flags, outSize, inSize, instances)) {
      const win32 = bound.api.getLastError()
      return { ok: false, code: 'ENOTHANDLE', message: 'GetNamedPipeInfo 拒绝了 fd ' + String(raw) + '（Win32 ' + String(win32) + '）', fd: raw, win32 }
    }
    return { ok: true, handle: raw, instances: bound.readU32(instances), flags: bound.readU32(flags) }
  }

  /**
   * Everything the OS will tell us about a pid we can already name.
   *
   * @param {number} pid
   */
  function describePid(pid) {
    const bound = ensure()
    if (bound === null) return { pid, error: unavailableReason ?? 'attestation unavailable' }
    /** @type {any} */
    const facts = { pid }
    const process = bound.api.openProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if (!process) {
      facts.error = 'OpenProcess failed (Win32 ' + String(bound.api.getLastError()) + ')'
      return facts
    }
    try {
      const pathBuffer = Buffer.alloc(32768)
      const pathSize = bound.allocU32()
      bound.koffi.encode(pathSize, 'uint32', pathBuffer.length / 2)
      if (bound.api.queryFullProcessImageNameW(process, 0, pathBuffer, pathSize)) {
        facts.imagePath = pathBuffer.toString('utf16le', 0, bound.readU32(pathSize) * 2)
      } else {
        facts.imagePathError = 'Win32 ' + String(bound.api.getLastError())
      }

      const created = bound.koffi.alloc('uint64', 1)
      const exited = bound.koffi.alloc('uint64', 1)
      const kernel = bound.koffi.alloc('uint64', 1)
      const user = bound.koffi.alloc('uint64', 1)
      if (bound.api.getProcessTimes(process, created, exited, kernel, user)) {
        facts.creationTime = String(bound.koffi.decode(created, 'uint64'))
      } else {
        facts.creationTimeError = 'Win32 ' + String(bound.api.getLastError())
      }

      const basic = Buffer.alloc(48)
      const returned = bound.allocU32()
      if (bound.api.ntQueryInformationProcess(process, 0, basic, basic.length, returned) === 0) {
        facts.parentPid = Number(basic.readBigUInt64LE(24))
      }

      const tokenSlot = bound.allocPtr()
      if (bound.api.openProcessToken(process, TOKEN_QUERY, tokenSlot)) {
        const token = bound.readPtr(tokenSlot)
        try {
          facts.userSid = sidFromOwnedBuffer(bound.koffi, readTokenInfo(bound, token, TOKEN_USER))
          const integritySid = sidFromOwnedBuffer(bound.koffi, readTokenInfo(bound, token, TOKEN_INTEGRITY_LEVEL))
          facts.integritySid = integritySid
          facts.integrityRid = sidLastRid(integritySid)
          facts.integrity = integrityName(facts.integrityRid)
          facts.restrictedSidCount = readTokenInfo(bound, token, TOKEN_RESTRICTED_SIDS).readUInt32LE(0)
        } finally {
          bound.api.closeHandle(token)
        }
      } else {
        facts.tokenError = 'OpenProcessToken failed (Win32 ' + String(bound.api.getLastError()) + ')'
      }

      const session = bound.allocU32()
      if (bound.api.processIdToSessionId(pid, session)) facts.sessionId = bound.readU32(session)
    } finally {
      bound.api.closeHandle(process)
    }
    return facts
  }

  /**
   * @param {any} bound
   * @param {any} token
   * @param {number} infoClass
   * @returns {Buffer}
   */
  function readTokenInfo(bound, token, infoClass) {
    const needed = bound.allocU32()
    bound.api.getTokenInformation(token, infoClass, null, 0, needed)
    const size = bound.readU32(needed)
    if (size === 0) throw new Error('GetTokenInformation(' + String(infoClass) + ') reported no size')
    const buffer = Buffer.alloc(size)
    if (!bound.api.getTokenInformation(token, infoClass, buffer, buffer.length, needed)) {
      const win32 = bound.api.getLastError()
      if (win32 !== ERROR_INSUFFICIENT_BUFFER) throw new Error('GetTokenInformation(' + String(infoClass) + ') failed (Win32 ' + String(win32) + ')')
    }
    return buffer
  }

  /**
   * Identify the process on the other end of an accepted pipe socket.
   *
   * @param {any} socket
   */
  function describeClient(socket) {
    const handle = resolveHandle(socket)
    if (handle.ok !== true) return handle
    const bound = ensure()
    const pidSlot = bound.allocU32()
    if (!bound.api.getNamedPipeClientProcessId(handle.handle, pidSlot)) {
      return {
        ok: false,
        code: 'ENOCLIENTPID',
        message: 'GetNamedPipeClientProcessId failed (Win32 ' + String(bound.api.getLastError()) + ')',
        fd: handle.handle,
      }
    }
    const clientPid = bound.readU32(pidSlot)
    const serverSlot = bound.allocU32()
    const serverPid = bound.api.getNamedPipeServerProcessId(handle.handle, serverSlot) ? bound.readU32(serverSlot) : null
    return {
      ok: true,
      fd: handle.handle,
      instances: handle.instances,
      serverPid,
      serverPidMatches: serverPid === process.pid,
      client: describePid(clientPid),
    }
  }

  /**
   * Owning pid of one TCP connection, from the OS table.
   *
   * Node exposes `localPort`/`remotePort` for TCP, and Windows maps a 4-tuple to
   * the owning pid. The client's row is the *reversed* tuple: its local port is
   * our remote port. This is the only peer-identity primitive available without
   * a Win32 handle, and it is exact — a TCP 4-tuple has exactly one owner per
   * side.
   *
   * @param {number} localPort our port (server side)
   * @param {number} remotePort the peer's port (client side)
   * @returns {{ ok: true, pid: number, rows: number } | { ok: false, code: string, message: string, matches?: number }}
   */
  function ownerPidOf(localPort, remotePort) {
    const bound = ensure()
    if (bound === null) return { ok: false, code: 'EUNAVAILABLE', message: unavailableReason ?? 'attestation unavailable' }
    if (!Number.isInteger(localPort) || !Number.isInteger(remotePort) || localPort <= 0 || remotePort <= 0) {
      return { ok: false, code: 'EBADTUPLE', message: 'invalid ports ' + String(localPort) + '/' + String(remotePort) }
    }
    const api = bound.api
    const size = bound.allocU32()
    let status = api.getExtendedTcpTable(null, size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if (status !== ERROR_INSUFFICIENT_BUFFER && status !== 0) {
      return { ok: false, code: 'ETABLE', message: 'GetExtendedTcpTable size query failed (' + String(status) + ')' }
    }
    const buffer = Buffer.alloc(Math.max(bound.readU32(size), 4))
    bound.koffi.encode(size, 'uint32', buffer.length)
    status = api.getExtendedTcpTable(buffer, size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if (status !== 0) return { ok: false, code: 'ETABLE', message: 'GetExtendedTcpTable failed (' + String(status) + ')' }
    const count = buffer.readUInt32LE(0)
    /** @type {number[]} */
    const matches = []
    for (let index = 0; index < count; index += 1) {
      const offset = 4 + index * 24
      // Ports are stored network-order in the low 16 bits of a DWORD.
      if (buffer.readUInt16BE(offset + 8) !== remotePort) continue
      if (buffer.readUInt16BE(offset + 16) !== localPort) continue
      matches.push(buffer.readUInt32LE(offset + 20))
    }
    if (matches.length === 0) return { ok: false, code: 'ENOOWNER', message: 'TCP 表里没有 ' + String(remotePort) + '→' + String(localPort) + ' 这一行', matches: 0 }
    const unique = [...new Set(matches)]
    if (unique.length > 1) return { ok: false, code: 'EAMBIGUOUS', message: '同一四元组对应多个 pid：' + unique.join(','), matches: unique.length }
    return { ok: true, pid: unique[0], rows: count }
  }

  /**
   * Identify a TCP peer: OS pid lookup plus that process's token facts.
   *
   * @param {{ localPort?: number, remotePort?: number }} socket
   */
  function describeTcpPeer(socket) {
    const lookup = ownerPidOf(Number(socket?.localPort), Number(socket?.remotePort))
    if (lookup.ok !== true) return lookup
    return {
      ok: true,
      pid: lookup.pid,
      rows: lookup.rows,
      client: describePid(lookup.pid),
    }
  }

  return {
    describePid,
    describeClient,
    describeTcpPeer,
    ownerPidOf,
    resolveHandle,
    /** @returns {string | null} */
    unavailableReason() {
      ensure()
      return unavailableReason
    },
    /** Force a load attempt now (used to log readiness at pod start). */
    warmUp() {
      ensure()
      return unavailableReason
    },
  }
}

/**
 * Decide whether an attested client may drive this pod.
 *
 * Every check is reported, not just the first failure: an operator reading the
 * log needs to see *which* property the client violated.
 *
 * @param {any} attestation `describeClient` (pipe) or `describeTcpPeer` (identity channel) result
 * @param {{ userSid: string | null, sessionId: number | null, minIntegrityRid: number, allowRestricted: boolean, allowedImages: string[], allowedImagesExact?: boolean }} policy
 * @returns {{ allowed: boolean, checks: Array<{ name: string, ok: boolean, detail: string }> }}
 */
export function evaluateClient(attestation, policy) {
  /** @type {Array<{ name: string, ok: boolean, detail: string }>} */
  const checks = []
  const add = (/** @type {string} */ name, /** @type {boolean} */ ok, /** @type {string} */ detail) => {
    checks.push({ name, ok, detail })
  }

  if (attestation?.ok !== true) {
    add('identity', false, String(attestation?.code ?? 'unknown') + ': ' + String(attestation?.message ?? 'no attestation'))
    return { allowed: false, checks }
  }

  const client = attestation.client ?? {}
  if (typeof client.pid !== 'number' || client.pid <= 0) {
    add('identity', false, 'client pid unavailable: ' + String(client.error ?? 'unknown'))
    return { allowed: false, checks }
  }

  // Only the named-pipe path can tell us the server side: `describeClient`
  // reads it with GetNamedPipeServerProcessId. The loopback identity channel
  // (describeTcpPeer) answers from the TCP table and has no pipe handle, so it
  // produces no `serverPid` — and must not be failed for a field the OS was
  // never asked for. Gating on the field's presence keeps this check honest
  // evidence instead of inventing a pass for the TCP path.
  if (typeof attestation.serverPid === 'number') {
    add('server-side', attestation.serverPidMatches === true, 'GetNamedPipeServerProcessId=' + String(attestation.serverPid) + ' self=' + String(process.pid))
  }

  if (typeof client.userSid !== 'string') {
    add('user', false, 'client SID unreadable: ' + String(client.tokenError ?? client.error ?? 'unknown'))
  } else if (typeof policy.userSid !== 'string') {
    add('user', false, 'pod could not read its own SID; refusing to compare')
  } else {
    add('user', client.userSid === policy.userSid, 'client=' + client.userSid + ' pod=' + policy.userSid)
  }

  if (typeof policy.sessionId !== 'number') {
    add('session', false, 'pod could not read its own session id')
  } else {
    add('session', client.sessionId === policy.sessionId, 'client=' + String(client.sessionId) + ' pod=' + String(policy.sessionId))
  }

  const rid = typeof client.integrityRid === 'number' ? client.integrityRid : -1
  add('integrity', rid >= policy.minIntegrityRid, 'client=' + integrityName(rid) + ' (0x' + rid.toString(16) + ') required>=' + integrityName(policy.minIntegrityRid))

  const restricted = typeof client.restrictedSidCount === 'number' ? client.restrictedSidCount : -1
  add('token-shape', policy.allowRestricted ? true : restricted === 0, 'restrictedSidCount=' + String(restricted) + (restricted > 0 ? '（受限令牌：这是 DSH 沙箱里的进程，不是 Host）' : ''))

  const images = Array.isArray(policy.allowedImages) ? policy.allowedImages.filter((entry) => typeof entry === 'string' && entry !== '') : []
  if (images.length === 0) {
    add('image', false, 'no allowed client image configured')
  } else {
    const image = typeof client.imagePath === 'string' ? client.imagePath : ''
    const match = images.some((allowed) => (policy.allowedImagesExact === false
      ? image.toLowerCase().endsWith(allowed.toLowerCase())
      : image.toLowerCase() === allowed.toLowerCase()))
    add('image', match, 'client=' + (image === '' ? '<unreadable>' : image) + ' allowed=' + images.join('|'))
  }

  return { allowed: checks.every((check) => check.ok), checks }
}

/**
 * Minimal, real PID-reuse check for the identity channel.
 *
 * The OS answer ("pid N is asking") is only as good as the pid→process binding.
 * Windows reuses PIDs, so a nonce issued to pid N must not be trusted if the
 * process now behind N was created at a different time. This guard remembers
 * the last creation time seen for each pid inside a window (the nonce TTL, so
 * the check covers exactly the period a nonce can still be redeemed) and
 * refuses a *different* creation time for the same pid.
 *
 * It is deliberately not part of the pure `evaluateClient`: it is stateful and
 * only meaningful across repeated attestations. A missing/unreadable
 * creationTime cannot be compared, so it produces no check at all — it never
 * invents a pass. A mismatch does not overwrite the remembered value; the pid
 * stays suspect until the entry ages out.
 *
 * @param {{ ttlMs?: number, now?: () => number, maxPids?: number }} [options]
 * @returns {{
 *   check: (attestation: any) => {
 *     ok: boolean,
 *     check: { name: string, ok: boolean, detail: string } | null,
 *   },
 * }}
 */
export function createPidCreationTimeGuard(options = {}) {
  const ttlMs = Number.isInteger(options.ttlMs) && options.ttlMs > 0 ? options.ttlMs : 60 * 1000
  const maxPids = Number.isInteger(options.maxPids) && options.maxPids > 0 ? options.maxPids : 256
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  /** @type {Map<number, { creationTime: string, at: number }>} */
  const seen = new Map()

  function prune(at) {
    for (const [pid, entry] of seen) {
      if (at - entry.at > ttlMs) seen.delete(pid)
    }
    // Map preserves insertion order; drop the oldest observations first.
    while (seen.size > maxPids) {
      const oldest = seen.keys().next()
      if (oldest.done === true) break
      seen.delete(oldest.value)
    }
  }

  return {
    check(attestation) {
      if (attestation?.ok !== true) return { ok: true, check: null }
      const client = attestation.client ?? {}
      const pid = client.pid
      const creationTime = typeof client.creationTime === 'string' && client.creationTime !== '' ? client.creationTime : null
      if (!Number.isInteger(pid) || pid <= 0 || creationTime === null) {
        // Nothing the OS gave us can be compared; do not fabricate a pass.
        return { ok: true, check: null }
      }
      const at = now()
      prune(at)
      const previous = seen.get(pid)
      if (previous === undefined) {
        seen.set(pid, { creationTime, at })
        return {
          ok: true,
          check: { name: 'creation-time', ok: true, detail: '首次见到 pid=' + String(pid) + ' creationTime=' + creationTime },
        }
      }
      if (previous.creationTime !== creationTime) {
        return {
          ok: false,
          check: {
            name: 'creation-time',
            ok: false,
            detail: 'pid=' + String(pid) + ' 的 creationTime 变了（上次 ' + previous.creationTime +
              '，本次 ' + creationTime + '）：疑似 PID 复用，拒绝本次身份校验且不签发 nonce',
          },
        }
      }
      previous.at = at
      return {
        ok: true,
        check: { name: 'creation-time', ok: true, detail: 'pid=' + String(pid) + ' creationTime 未变' },
      }
    },
  }
}
