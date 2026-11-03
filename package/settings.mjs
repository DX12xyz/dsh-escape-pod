/**
 * Escape pod settings, shared by the Host plugin (settings page API) and the
 * pod process (freeze mode). The file lives in the pod's state directory so the
 * two components never depend on each other: the plugin may be reloaded or
 * disabled and the pod still honours this file.
 *
 * Schema (version 3):
 *   freezeMode     boolean  true = freeze running jobs when DSH disappears
 *   freezeMinutes  integer  1..1440, default 30 (watchdog episode length)
 *   regenerations  integer  0..3, default 1 (thaw+refreeze episodes before self-destruct)
 *   shells         { powershell: 'auto'|candidate id, bash: 'auto'|candidate id }
 *
 * Version 3 only adds `shells`. A version-2 (or older) file simply has no such
 * key, so it reads as the defaults and is written back complete on the next
 * save: no migration step, exactly like the `enabled` removal below. The shell
 * normalization is shared with shells.mjs so the settings page, the detection
 * and this file can never disagree about what a valid choice is; the import is
 * one-way (settings -> shells) to keep the module graph acyclic.
 *
 * There is no `enabled` switch any more: the pod always serves commands. A
 * settings file written by an older build still carries `enabled`; it is
 * ignored on read and dropped on the next write, so an existing file keeps
 * working without a migration step.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { SHELL_SETTINGS_DEFAULTS, normalizeShellDefaults } from './shells.mjs';

export const POD_SETTINGS_FILE = 'settings.json';
export const POD_SETTINGS_VERSION = 3;
export const FREEZE_MINUTES_MIN = 1;
export const FREEZE_MINUTES_MAX = 1440;
export const REGENERATIONS_MIN = 0;
export const REGENERATIONS_MAX = 3;

/**
 * @type {{
 *   freezeMode: boolean,
 *   freezeMinutes: number,
 *   regenerations: number,
 *   shells: { powershell: string, bash: string },
 * }}
 */
export const POD_SETTINGS_DEFAULTS = Object.freeze({
  freezeMode: false,
  freezeMinutes: 30,
  regenerations: 1,
  // A copy: defaults are frozen and shared by every reader, but a caller may
  // legitimately edit the object it got from normalizePodSettings().
  shells: Object.freeze({ ...SHELL_SETTINGS_DEFAULTS }),
});

/**
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clampInt(value, fallback, min, max) {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

/**
 * Normalize any stored/user input into the one shape every reader understands.
 * A legacy `enabled` field is deliberately ignored (there is no disable switch
 * any more), which is exactly the documented "old file keeps working" rule.
 * `shells` is always a fresh object: callers may keep and edit the result.
 * @param {unknown} raw
 * @returns {{
 *   freezeMode: boolean,
 *   freezeMinutes: number,
 *   regenerations: number,
 *   shells: { powershell: string, bash: string },
 * }}
 */
export function normalizePodSettings(raw) {
  const value = raw !== null && typeof raw === 'object' ? /** @type {Record<string, unknown>} */ (raw) : {};
  return {
    freezeMode: value.freezeMode === true,
    freezeMinutes: clampInt(value.freezeMinutes, POD_SETTINGS_DEFAULTS.freezeMinutes, FREEZE_MINUTES_MIN, FREEZE_MINUTES_MAX),
    regenerations: clampInt(value.regenerations, POD_SETTINGS_DEFAULTS.regenerations, REGENERATIONS_MIN, REGENERATIONS_MAX),
    shells: normalizeShellDefaults(value.shells),
  };
}

/** @param {string} stateDir */
export function podSettingsPath(stateDir) {
  return join(stateDir, POD_SETTINGS_FILE);
}

/**
 * Read + normalize the settings file. A missing or unreadable file answers the
 * defaults (never throws: a broken settings file must not stop the pod).
 * @param {string} stateDir
 * @returns {{
 *   freezeMode: boolean,
 *   freezeMinutes: number,
 *   regenerations: number,
 *   shells: { powershell: string, bash: string },
 * }}
 */
export function readPodSettings(stateDir) {
  try {
    const file = podSettingsPath(stateDir);
    // normalizePodSettings(undefined) rather than a spread of the defaults:
    // every reader gets its own `shells` object, never the shared frozen one.
    if (!existsSync(file)) return normalizePodSettings(undefined);
    return normalizePodSettings(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return normalizePodSettings(undefined);
  }
}

/**
 * Atomically persist normalized settings. `enabled` (and any other unknown
 * field) is never written: the file on disk is exactly the new schema.
 * @param {string} stateDir
 * @param {unknown} next
 * @returns {boolean} true when the file was written
 */
export function writePodSettings(stateDir, next) {
  const value = normalizePodSettings(next);
  try {
    mkdirSync(stateDir, { recursive: true });
    const file = podSettingsPath(stateDir);
    const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(temp, `${JSON.stringify({ version: POD_SETTINGS_VERSION, ...value }, null, 2)}\n`, 'utf8');
    renameSync(temp, file);
    return true;
  } catch {
    return false;
  }
}
