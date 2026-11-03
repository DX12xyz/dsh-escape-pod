/**
 * @local/dsh-escape-pod — Client half.
 *
 * One surface: this bundle's settings page (`plugins.bundle.config`), which
 * renders the escape pod's own switches and its emergency stop.
 *
 *   GET  /api/dsh-escape-pod/settings  -> { ok, freezeMode, freezeMinutes, regenerations, shells, writable }
 *   POST /api/dsh-escape-pod/settings  { freezeMode?, freezeMinutes?, regenerations?, shells? }
 *   GET  /api/dsh-escape-pod/shells    -> { ok, generatedAt, groups, defaults, error? }
 *   POST /api/dsh-escape-pod/shutdown  (human-only; a 5-second hold is the guard)
 *
 * The pod is a separate process: saving here writes its `settings.json` and the
 * pod re-reads it on the next disconnect/grace/watchdog tick, so nothing is
 * reloaded and no agent/session is touched. The red button borrows the visual
 * language of the DSH power page's forced long-press: it only fires after a
 * full 5 seconds, releasing anywhere cancels, and the answer reports how many
 * jobs the pod killed (`killed`) before it exited.
 */
window.__ModuleLoader__.load({
  id: '@local/dsh-escape-pod',
  factory: (require) => {
    const React = require('react');
    const h = React.createElement;

    const NS = 'dshEscapePod';
    const API_SETTINGS = '/api/dsh-escape-pod/settings';
    const API_SHELLS = '/api/dsh-escape-pod/shells';
    const API_SHUTDOWN = '/api/dsh-escape-pod/shutdown';
    const REQUEST_TIMEOUT_MS = 8000;
    const HOLD_MS = 5000;
    const HOLD_TICK_MS = 50;
    const FREEZE_MINUTES = Object.freeze({ min: 1, max: 1440 });
    const REGENERATIONS = Object.freeze({ min: 0, max: 3 });
    // Must match `POD_SETTINGS_DEFAULTS` in settings.mjs: the pod reads the very
    // same file, so the UI fallback describes the pod's own defaults.
    const DEFAULTS = Object.freeze({
      freezeMode: false,
      freezeMinutes: 30,
      regenerations: 1,
      // Must match SHELL_SETTINGS_DEFAULTS in shells.mjs (settings schema v3).
      shells: Object.freeze({ powershell: 'auto', bash: 'auto' }),
    });
    const STYLE_ID = 'dshpod-settings-css';

    /* ------------------------------------------------------------- locales -- */

    const zh = {
      'settings.title': '逃生舱',
      'settings.desc':
        '命令由脱离 DSH 的 pod 进程托管：DSH 重启或崩溃后命令继续运行，输出写入账本；前台调用在新 Host 启动后回填真实结果，后台任务可按需续读。',
      'settings.freeze': '冻结模式',
      'settings.freezeDesc':
        '检测到 DSH 消失 10 秒后冻结所有运行中的命令；DSH 回来后自动解冻。每冻结 30 分钟（可配）会尝试“解冻再冻结”并消耗一次再生机会，机会耗尽后自毁并终止任务。',
      'settings.minutes': '冻结时长（分钟）',
      'settings.regenerations': '再生次数',
      'settings.ranges': '冻结时长 1–1440 分钟；再生次数 0–3 次。',
      'settings.invalid': '冻结时长需为 1–1440 的整数，再生次数需为 0–3 的整数。',
      'settings.save': '保存',
      'settings.saving': '保存中…',
      'settings.saved': '已保存，立即生效（不会重载插件）',
      'settings.saveFailed': '保存失败：{message}',
      'settings.loadFailed': '读取设置失败：{message}',
      'settings.loading': '读取中…',
      'settings.readOnly': '逃生舱设置目录不可写，无法保存；请检查其状态目录的权限。',
      'settings.note': '保存写入逃生舱自己的 settings.json 并立即生效（pod 在断开、宽限到点与看门狗到点时重读），不会触发插件热重载。',
      'settings.summary': '冻结模式：{state} · {minutes} 分钟 / {regenerations} 次',
      'settings.stateOn': '开',
      'settings.stateOff': '关',
      'shells.title': '命令行',
      'shells.desc':
        '探测本机可用的 PowerShell / bash / cmd。这里选的是默认值；AI 也可以在会话里用 pod_shell 临时切换。',
      'shells.optional':
        '命令行是可选覆盖，不会强制替换 DSH/系统原装的解释器：选「自动」时沿用默认探测，行为与以前一致。建议先用原装默认，只有它不可用、启动失败或版本不满足时才切换；所选路径运行期不可用时按“会话选择 → 设置默认 → 自动探测”逐级回落。',
      'shells.auto': '自动（探测）',
      'shells.unavailable': '不可用',
      'shells.stale': '已失效，运行时会回落到自动',
      'shells.cmdFixed': 'cmd.exe（固定，不可选）',
      'shells.detectFailed': '探测失败：{message}',
      'shells.loading': '正在探测本机命令行…',
      'shells.powershell': 'PowerShell',
      'shells.bash': 'bash',
      'shutdown.title': '关闭逃生舱',
      'shutdown.desc': '立即终止逃生舱托管的所有任务并关闭逃生舱进程；DSH 本身不受影响。需要长按 5 秒确认。',
      'shutdown.hold': '长按 5 秒关闭逃生舱',
      'shutdown.holding': '继续按住… {seconds} 秒',
      'shutdown.busy': '正在关闭逃生舱…',
      'shutdown.done': '已关闭逃生舱（终止 {count} 个任务）',
      'shutdown.doneUnknown': '已关闭逃生舱（未收到确认：任务可能已被终止）',
      'shutdown.failed': '关闭逃生舱失败：{message}',
    };

    const en = {
      'settings.title': 'Escape pod',
      'settings.desc':
        'Commands are owned by a pod process outside DSH: they keep running across a DSH restart or crash and their output goes to the ledger. A foreground call gets its real result backfilled on the next boot; background jobs stay readable.',
      'settings.freeze': 'Freeze mode',
      'settings.freezeDesc':
        'Freezes every running command 10 seconds after DSH disappears and thaws them when DSH comes back. Every 30 minutes of freeze (configurable) it attempts a thaw + refreeze, spending one regeneration; once the regenerations are exhausted it self-destructs and terminates the jobs.',
      'settings.minutes': 'Freeze duration (minutes)',
      'settings.regenerations': 'Regenerations',
      'settings.ranges': 'Freeze duration 1–1440 minutes; regenerations 0–3.',
      'settings.invalid': 'Freeze duration must be an integer from 1 to 1440 and regenerations an integer from 0 to 3.',
      'settings.save': 'Save',
      'settings.saving': 'Saving…',
      'settings.saved': 'Saved. Effective immediately (no plugin reload).',
      'settings.saveFailed': 'Save failed: {message}',
      'settings.loadFailed': 'Cannot read the settings: {message}',
      'settings.loading': 'Reading…',
      'settings.readOnly': 'The escape pod settings directory is not writable, so nothing can be saved; check the permissions of its state directory.',
      'settings.note': "Saved into the escape pod's own settings.json and effective immediately (the pod re-reads it on disconnect, at grace expiry and on every watchdog tick). No plugin reload.",
      'settings.summary': 'Freeze mode: {state} · {minutes} minutes / {regenerations} regeneration(s)',
      'settings.stateOn': 'on',
      'settings.stateOff': 'off',
      'shells.title': 'Command line',
      'shells.desc':
        'Detected PowerShell / bash / cmd on this machine. These are defaults; the AI can override them per session with pod_shell.',
      'shells.optional':
        'A shell choice is an optional override, never a forced replacement for the DSH/system interpreter: with Auto the defaults are used and behaviour is unchanged. Prefer the stock default first and switch only when it is unavailable, fails to start, or is the wrong version; if the chosen path disappears at run time the selection falls back step by step (session override → settings default → auto detection).',
      'shells.auto': 'Auto (detected)',
      'shells.unavailable': 'Unavailable',
      'shells.stale': 'No longer available; falls back to auto at run time',
      'shells.cmdFixed': 'cmd.exe (fixed, not selectable)',
      'shells.detectFailed': 'Detection failed: {message}',
      'shells.loading': 'Detecting shells…',
      'shells.powershell': 'PowerShell',
      'shells.bash': 'bash',
      'shutdown.title': 'Shut the escape pod down',
      'shutdown.desc': 'Terminates every job the escape pod owns and closes the pod process; DSH itself is unaffected. Requires a 5-second hold.',
      'shutdown.hold': 'Hold 5 seconds to shut the escape pod down',
      'shutdown.holding': 'Keep holding… {seconds}s',
      'shutdown.busy': 'Shutting the escape pod down…',
      'shutdown.done': 'Escape pod closed ({count} job(s) terminated)',
      'shutdown.doneUnknown': 'Escape pod closed (no confirmation received; jobs may have been terminated)',
      'shutdown.failed': 'Shutting the escape pod down failed: {message}',
    };

    /* ------------------------------------------------------------- helpers -- */

    const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

    function formatText(template, values) {
      if (typeof template !== 'string') return '';
      if (values === undefined || values === null) return template;
      return template.replace(/\{(\w+)\}/g, (match, key) =>
        values !== null && values !== undefined && hasOwn(values, key) ? String(values[key]) : match,
      );
    }

    /**
     * The bundle-config page can render outside this bundle's own locale
     * wrappers, so resolve the inlined dictionaries when no `t` seat exists.
     */
    function fallbackTranslate(key, values) {
      let dict = en;
      try {
        const language =
          typeof navigator !== 'undefined' && typeof navigator.language === 'string' ? navigator.language : '';
        if (language.toLowerCase().indexOf('zh') === 0) dict = zh;
      } catch {
        dict = en;
      }
      const template = hasOwn(dict, key) ? dict[key] : en[key];
      if (typeof template !== 'string') return String(key);
      return values === undefined ? template : formatText(template, values);
    }

    function settingsTranslate(props) {
      return props !== null && props !== undefined && typeof props.t === 'function' ? props.t : fallbackTranslate;
    }

    function errorText(error) {
      if (error === null || error === undefined) return 'unknown error';
      if (typeof error === 'string') return error;
      if (typeof error.message === 'string' && error.message.length > 0) return error.message;
      return String(error);
    }

    /** JSON request with a hard timeout; non-2xx becomes an Error carrying `status`. */
    async function apiRequest(url, init) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        const response = await fetch(
          url,
          Object.assign({ credentials: 'same-origin', signal: controller.signal }, init),
        );
        const text = await response.text();
        let data = {};
        try {
          data = text.length > 0 ? JSON.parse(text) : {};
        } catch {
          data = {};
        }
        if (!response.ok) {
          const error = new Error(data.error ?? 'HTTP ' + String(response.status));
          error.status = response.status;
          throw error;
        }
        return data;
      } finally {
        clearTimeout(timer);
      }
    }

    /** One integer inside `range`, or null. Accepts a numeric string. */
    function configInt(value, min, max) {
      const parsed = typeof value === 'number' ? value : Number(typeof value === 'string' ? value.trim() : value);
      if (!Number.isFinite(parsed) || Math.trunc(parsed) !== parsed) return null;
      if (parsed < min || parsed > max) return null;
      return parsed;
    }

    function settingsFrom(data) {
      const fallback = { ...DEFAULTS, shells: { ...DEFAULTS.shells } };
      if (data === null || typeof data !== 'object' || data.ok === false) return fallback;
      return {
        freezeMode: data.freezeMode === true,
        freezeMinutes: configInt(data.freezeMinutes, FREEZE_MINUTES.min, FREEZE_MINUTES.max) ?? fallback.freezeMinutes,
        regenerations: configInt(data.regenerations, REGENERATIONS.min, REGENERATIONS.max) ?? fallback.regenerations,
        shells: settingsShells(data.shells),
      };
    }

    /**
     * `{powershell, bash}` exactly as stored ('auto' or a candidate id). The
     * server already normalizes this; the UI only needs the same shape so a
     * missing/old `shells` field cannot turn into an `undefined` select value.
     */
    function settingsShells(raw) {
      const value = raw !== null && typeof raw === 'object' ? raw : {};
      const choice = (candidate) =>
        typeof candidate === 'string' && candidate.trim() !== '' ? candidate.trim() : 'auto';
      return { powershell: choice(value.powershell), bash: choice(value.bash) };
    }

    /** Candidate groups from GET /shells; a broken answer means "no candidates". */
    function shellGroupsFrom(data) {
      if (data === null || typeof data !== 'object' || !Array.isArray(data.groups)) return [];
      return data.groups.filter(
        (group) => group !== null && typeof group === 'object' && typeof group.kind === 'string',
      );
    }

    /* -------------------------------------------------------------- styles -- */

    const CSS = `
.dshpod-cfg{box-sizing:border-box;display:flex;flex-direction:column;gap:8px;max-width:640px;font-family:inherit;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}
.dshpod-cfg-summary{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.dshpod-cfg-title{font-size:14px;line-height:20px;font-weight:600}
.dshpod-cfg-desc{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}
.dshpod-cfg-subtitle{font-size:13px;line-height:20px;font-weight:600;margin-top:6px}
.dshpod-cfg-row{display:flex;align-items:center;flex-wrap:wrap;gap:8px}
.dshpod-cfg-label{flex:none;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary)}
.dshpod-input.dshpod-cfg-input{flex:0 0 110px;width:110px}
.dshpod-select{flex:0 1 320px;width:320px;min-width:160px;max-width:100%}
.dshpod-select option:disabled{color:var(--dsw-alias-label-secondary)}
.dshpod-input{box-sizing:border-box;height:32px;padding:0 10px;border-radius:8px;border:.5px solid var(--dsw-alias-border-l1);background:color-mix(in srgb, var(--dsw-alias-bg-layer-1) 70%, transparent);color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;outline:none}
.dshpod-input:disabled{opacity:.6}
.dshpod-input:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}
.dshpod-cfg-check{display:flex;align-items:center;gap:8px;font-size:13px;line-height:20px}
.dshpod-cfg-check input{margin:0;width:14px;height:14px;accent-color:var(--dsw-alias-brand-primary)}
.dshpod-cfg-check:disabled,.dshpod-cfg-check-locked{opacity:.6}
.dshpod-cfg-note{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}
.dshpod-cfg-ok{font-size:12px;line-height:18px;color:var(--dsw-alias-state-success-primary);overflow-wrap:anywhere}
.dshpod-cfg-error{font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary);overflow-wrap:anywhere}
.dshpod-cfg-save{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-top:4px}
.dshpod-button{display:inline-flex;align-items:center;justify-content:center;gap:6px;flex:none;height:32px;padding:0 14px;border-radius:8px;border:.5px solid var(--dsw-alias-brand-primary);background:transparent;color:var(--dsw-alias-brand-primary);font-size:13px;line-height:1;cursor:pointer;font-family:inherit;transition:background .12s ease,color .12s ease}
.dshpod-button:hover:not(:disabled){background:color-mix(in srgb, var(--dsw-alias-brand-primary) 12%, transparent)}
.dshpod-button:disabled{opacity:.55;cursor:default}
.dshpod-danger-zone{margin-top:8px;padding:10px 12px;border-radius:8px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);background:color-mix(in srgb, var(--dsw-alias-state-error-primary) 8%, transparent);border:.5px dashed color-mix(in srgb, var(--dsw-alias-state-error-primary) 45%, transparent)}
.dshpod-danger-zone .dshpod-cfg-label{margin-bottom:8px;display:block}
.dshpod-hold{position:relative;overflow:hidden;border-color:var(--dsw-alias-state-error-primary);color:var(--dsw-alias-state-error-primary);animation-duration:700ms;animation-iteration-count:infinite;animation-timing-function:ease-in-out}
.dshpod-hold:hover:not(:disabled){background:color-mix(in srgb, var(--dsw-alias-state-error-primary) 12%, transparent)}
.dshpod-hold::after{content:'';position:absolute;left:0;bottom:0;height:2px;width:var(--dshpod-hold-progress,0%);background:var(--dsw-alias-state-error-primary);transition:width .06s linear}
.dshpod-hold-active{animation-name:dshpod-hold-pulse}
@keyframes dshpod-hold-pulse{0%,100%{box-shadow:0 0 0 0 color-mix(in srgb, var(--dsw-alias-state-error-primary) 0%, transparent)}50%{box-shadow:0 0 0 4px color-mix(in srgb, var(--dsw-alias-state-error-primary) 28%, transparent)}}
@media (prefers-reduced-motion: reduce){.dshpod-hold{animation:none!important}.dshpod-hold::after{transition:none}}
`;

    let styleElement = null;
    function ensureStyles() {
      if (typeof document === 'undefined') return () => {};
      if (styleElement !== null && styleElement.isConnected) return () => {};
      styleElement = document.createElement('style');
      styleElement.dataset.plugin = '@local/dsh-escape-pod';
      styleElement.dataset.pluginCss = STYLE_ID;
      styleElement.textContent = CSS;
      document.head.appendChild(styleElement);
      return () => {
        try {
          styleElement?.remove();
        } catch {
          /* ignore */
        }
        styleElement = null;
      };
    }

    /* ----------------------------------------------------------- components -- */

    /** A broken config panel must never take the plugins page down with it. */
    class SettingsBoundary extends React.Component {
      constructor(props) {
        super(props);
        this.state = { failed: false };
      }
      static getDerivedStateFromError() {
        return { failed: true };
      }
      componentDidCatch() {
        /* the panel is optional */
      }
      render() {
        return this.state.failed ? null : this.props.children;
      }
    }

    /**
     * Red 5-second hold, same interaction contract as the DSH power page's
     * forced tier: a full 5s press confirms; releasing anywhere, losing focus,
     * a hidden tab or a pointer cancellation stops it with nothing sent.
     */
    function LongPressButton(props) {
      const { t, label, busy, onConfirm } = props;
      const idleLabel = typeof label === 'string' && label.length > 0 ? label : t('shutdown.hold');
      const [holding, setHolding] = React.useState(false);
      const [elapsed, setElapsed] = React.useState(0);
      const startAt = React.useRef(0);
      const timer = React.useRef(null);
      const holdRef = React.useRef(false);

      const stop = React.useCallback(() => {
        holdRef.current = false;
        if (timer.current !== null) {
          clearInterval(timer.current);
          timer.current = null;
        }
        setHolding(false);
        setElapsed(0);
      }, []);

      const start = React.useCallback(() => {
        if (holdRef.current || busy === true) return;
        holdRef.current = true;
        startAt.current = Date.now();
        setHolding(true);
        setElapsed(0);
        timer.current = setInterval(() => {
          const value = Date.now() - startAt.current;
          if (value >= HOLD_MS) {
            stop();
            onConfirm();
            return;
          }
          setElapsed(value);
        }, HOLD_TICK_MS);
      }, [busy, onConfirm, stop]);

      React.useEffect(() => () => stop(), [stop]);

      React.useEffect(() => {
        if (!holding) return undefined;
        if (typeof window === 'undefined' || typeof document === 'undefined') return undefined;
        const onWindowBlur = () => stop();
        const onVisibilityChange = () => {
          if (document.visibilityState === 'hidden') stop();
        };
        const onPointerEnd = () => stop();
        window.addEventListener('blur', onWindowBlur);
        window.addEventListener('pointerup', onPointerEnd, true);
        window.addEventListener('pointercancel', onPointerEnd, true);
        document.addEventListener('visibilitychange', onVisibilityChange);
        return () => {
          window.removeEventListener('blur', onWindowBlur);
          window.removeEventListener('pointerup', onPointerEnd, true);
          window.removeEventListener('pointercancel', onPointerEnd, true);
          document.removeEventListener('visibilitychange', onVisibilityChange);
        };
      }, [holding, stop]);

      const remaining = Math.max(0, (HOLD_MS - elapsed) / 1000).toFixed(1);
      const progress = Math.min(100, Math.round((elapsed / HOLD_MS) * 100));
      const flashMs = Math.max(120, Math.round(700 - (elapsed / HOLD_MS) * 560));
      const valueText = holding ? formatText(t('shutdown.holding'), { seconds: remaining }) : idleLabel;
      return h(
        'button',
        {
          type: 'button',
          className: 'dshpod-button dshpod-hold' + (holding ? ' dshpod-hold-active' : ''),
          style: { '--dshpod-hold-progress': String(progress) + '%', animationDuration: String(flashMs) + 'ms' },
          disabled: busy === true,
          'aria-label': idleLabel,
          'aria-valuemin': 0,
          'aria-valuemax': HOLD_MS,
          'aria-valuenow': Math.min(HOLD_MS, Math.round(elapsed)),
          'aria-valuetext': valueText,
          onPointerDown: (event) => {
            if (event.button !== 0) return;
            event.preventDefault();
            try {
              event.currentTarget.setPointerCapture?.(event.pointerId);
            } catch {
              /* not supported */
            }
            start();
          },
          onPointerUp: stop,
          onPointerCancel: stop,
          onPointerLeave: stop,
          onLostPointerCapture: stop,
          onPointerMove: (event) => {
            if (!holdRef.current) return;
            const rect = event.currentTarget.getBoundingClientRect();
            const inside =
              event.clientX >= rect.left &&
              event.clientX <= rect.right &&
              event.clientY >= rect.top &&
              event.clientY <= rect.bottom;
            if (!inside) stop();
          },
          onClick: (event) => {
            // A click is not a confirmation: stop propagation so nothing treats
            // the button as an ordinary toggle.
            event.preventDefault();
          },
          // Keyboard parity with the DSH power page's forced tier: holding
          // Enter/Space is the same gesture as holding the pointer.
          onKeyDown: (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            if (event.repeat) return;
            start();
          },
          onKeyUp: (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            stop();
          },
          onBlur: stop,
        },
        busy === true ? t('shutdown.busy') : valueText,
      );
    }

    function EscapePodPanel(props) {
      const t = settingsTranslate(props);
      // The bundle list may render this component in "summary" mode; the panel
      // still fetches the live values first, so the one-liner describes the pod
      // rather than the UI defaults.
      const view = props !== null && props !== undefined && props.view === 'summary' ? 'summary' : 'page';
      const [freezeMode, setFreezeMode] = React.useState(DEFAULTS.freezeMode);
      const [freezeMinutes, setFreezeMinutes] = React.useState(String(DEFAULTS.freezeMinutes));
      const [regenerations, setRegenerations] = React.useState(String(DEFAULTS.regenerations));
      // Shell pickers. Filled from GET /settings (the saved values) and
      // GET /shells (the live candidates); a failed detection only blanks the
      // option list, it never blocks saving the other settings.
      const [shells, setShells] = React.useState({ ...DEFAULTS.shells });
      const [shellsLoaded, setShellsLoaded] = React.useState(false);
      const [shellGroups, setShellGroups] = React.useState([]);
      const [shellError, setShellError] = React.useState(null);
      const [writable, setWritable] = React.useState(true);
      const [loaded, setLoaded] = React.useState(false);
      const [busy, setBusy] = React.useState(false);
      const [message, setMessage] = React.useState(null);
      const [shutdown, setShutdown] = React.useState({ stage: 'idle', killed: 0, timedOut: false, error: null });
      const aliveRef = React.useRef(true);
      const baseId = typeof React.useId === 'function' ? React.useId() : 'dshpod-cfg';
      const freezeId = baseId + '-freeze';
      const minutesId = baseId + '-minutes';
      const regenerationsId = baseId + '-regenerations';

      const applyConfig = (data) => {
        const value = settingsFrom(data);
        setFreezeMode(value.freezeMode);
        setFreezeMinutes(String(value.freezeMinutes));
        setRegenerations(String(value.regenerations));
        setShells(value.shells);
        setShellsLoaded(true);
        setWritable(data !== null && typeof data === 'object' ? data.writable !== false : true);
      };

      React.useEffect(() => {
        aliveRef.current = true;
        return () => {
          aliveRef.current = false;
        };
      }, []);

      React.useEffect(() => {
        let cancelled = false;
        apiRequest(API_SETTINGS, { method: 'GET' }).then(
          (data) => {
            if (cancelled || !aliveRef.current) return;
            setLoaded(true);
            applyConfig(data);
          },
          (error) => {
            if (cancelled || !aliveRef.current) return;
            setLoaded(true);
            setMessage({ kind: 'error', text: formatText(t('settings.loadFailed'), { message: errorText(error) }) });
          },
        );
        return () => {
          cancelled = true;
        };
      }, [view]);

      /**
       * Candidate discovery is a separate request on purpose: it runs a probe
       * on the Host (never a pod connection), and its failure must leave the
       * freeze settings fully editable.
       */
      React.useEffect(() => {
        // The one-line summary never shows shell choices, and detection may
        // spawn interpreters: do not probe the machine for a summary render.
        if (view === 'summary') return undefined;
        let cancelled = false;
        apiRequest(API_SHELLS, { method: 'GET' }).then(
          (data) => {
            if (cancelled || !aliveRef.current) return;
            setShellGroups(shellGroupsFrom(data));
            setShellError(
              data !== null && typeof data === 'object' && typeof data.error === 'string' && data.error !== ''
                ? data.error
                : null,
            );
          },
          (error) => {
            if (cancelled || !aliveRef.current) return;
            setShellGroups([]);
            setShellError(errorText(error));
          },
        );
        return () => {
          cancelled = true;
        };
      }, [view]);

      if (view === 'summary') {
        return h(
          'div',
          { className: 'dshpod-cfg' },
          h(
            'span',
            { className: 'dshpod-cfg-summary' },
            formatText(t('settings.summary'), {
              state: freezeMode === true ? t('settings.stateOn') : t('settings.stateOff'),
              minutes: loaded ? freezeMinutes : DEFAULTS.freezeMinutes,
              regenerations: loaded ? regenerations : DEFAULTS.regenerations,
            }),
          ),
          message !== null && message.kind === 'error'
            ? h('span', { className: 'dshpod-cfg-error' }, message.text)
            : null,
        );
      }

      const save = () => {
        if (busy || !loaded || writable !== true) return;
        // While freeze mode is OFF the two numbers are hidden; a half-typed
        // value there must not block the save, so fall back to the pod defaults
        // instead of rejecting a switch the user can actually see.
        const minutes = configInt(freezeMinutes, FREEZE_MINUTES.min, FREEZE_MINUTES.max) ?? (freezeMode === true ? null : DEFAULTS.freezeMinutes);
        const regenerationCount = configInt(regenerations, REGENERATIONS.min, REGENERATIONS.max) ?? (freezeMode === true ? null : DEFAULTS.regenerations);
        if (minutes === null || regenerationCount === null) {
          setMessage({ kind: 'error', text: t('settings.invalid') });
          return;
        }
        setBusy(true);
        setMessage(null);
        // ONE payload for every field: the route replaces what it is given and
        // keeps omitted fields. `shells` is only sent once the saved values
        // actually loaded — after a failed GET the pickers still hold the UI
        // defaults, and sending them would wipe the stored choice.
        const payload = { freezeMode: freezeMode === true, freezeMinutes: minutes, regenerations: regenerationCount };
        if (shellsLoaded) payload.shells = { powershell: shells.powershell, bash: shells.bash };
        apiRequest(API_SETTINGS, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        }).then(
          (data) => {
            if (!aliveRef.current) return;
            setBusy(false);
            applyConfig(data);
            setMessage({ kind: 'ok', text: t('settings.saved') });
          },
          (error) => {
            if (!aliveRef.current) return;
            setBusy(false);
            setMessage({ kind: 'error', text: formatText(t('settings.saveFailed'), { message: errorText(error) }) });
          },
        );
      };

      const shutdownPod = () => {
        if (shutdown.stage === 'running') return;
        setShutdown({ stage: 'running', killed: 0, timedOut: false, error: null });
        apiRequest(API_SHUTDOWN, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ reason: 'settings page hold-to-confirm' }),
        }).then(
          (data) => {
            if (!aliveRef.current) return;
            const killed = typeof data.killed === 'number' && Number.isFinite(data.killed) ? data.killed : 0;
            setShutdown({
              stage: 'done',
              killed,
              timedOut: data.timedOut === true || data.status === 'timeout' || data.status === 'unknown',
              error: null,
            });
          },
          (error) => {
            if (!aliveRef.current) return;
            setShutdown({ stage: 'error', killed: 0, timedOut: false, error: errorText(error) });
          },
        );
      };

      const disabled = busy || !loaded || writable !== true;
      const numbersDisabled = disabled;

      /* ---- command line: PowerShell / bash pickers, cmd is fixed ---- */
      const groupOf = (kind) => shellGroups.find((group) => group.kind === kind) ?? null;
      const candidatesOf = (kind) => {
        const group = groupOf(kind);
        if (group === null || !Array.isArray(group.candidates)) return [];
        return group.candidates.filter(
          (candidate) => candidate !== null && typeof candidate === 'object' && typeof candidate.id === 'string',
        );
      };
      // A saved id can only be judged against a working detection: when the probe
      // itself failed, "not in the list" says nothing about the path.
      const shellsDetected = shellError === null && shellGroups.length > 0;
      const staleShells = ['powershell', 'bash'].filter((kind) => {
        if (!shellsDetected) return false;
        const chosen = shells[kind];
        if (typeof chosen !== 'string' || chosen === 'auto') return false;
        const candidate = candidatesOf(kind).find((entry) => entry.id === chosen) ?? null;
        return candidate === null || candidate.available !== true;
      });
      const cmdPath = candidatesOf('cmd')[0]?.path ?? null;

      const renderShellSelect = (kind, label) => {
        const id = baseId + '-shell-' + kind;
        const candidates = candidatesOf(kind);
        const chosen = shells[kind];
        const known = candidates.some((candidate) => candidate.id === chosen);
        const options = [
          h('option', { key: 'auto', value: 'auto' }, t('shells.auto')),
          ...candidates.map((candidate) => {
            // Two dsh-ops PortableGit instances share the same label, so the
            // absolute path (and the probed version) is the only way to tell
            // them apart in a native <select>.
            const detail = [candidate.version, candidate.path].filter(
              (value) => typeof value === 'string' && value !== '',
            ).join(' · ');
            return h(
              'option',
              { key: candidate.id, value: candidate.id, disabled: candidate.available !== true },
              (candidate.label || candidate.id) +
                (detail === '' ? '' : ' — ' + detail) +
                (candidate.available === true ? '' : '（' + t('shells.unavailable') + '）'),
            );
          }),
        ];
        // An id that is no longer detected must stay visible: silently showing
        // the first option would look like the saved choice had been kept.
        if (!known && chosen !== 'auto') {
          options.push(
            h('option', { key: 'stale', value: chosen, disabled: true }, chosen + '（' + t('shells.unavailable') + '）'),
          );
        }
        return h(
          'div',
          { className: 'dshpod-cfg-row', key: kind },
          h('label', { className: 'dshpod-cfg-label', htmlFor: id }, label),
          h(
            'select',
            {
              id,
              className: 'dshpod-input dshpod-select',
              value: chosen,
              disabled,
              onChange: (event) => {
                const next = event.target.value;
                setShells((previous) => ({ ...previous, [kind]: next }));
              },
            },
            options,
          ),
        );
      };

      const shutdownLine =
        shutdown.stage === 'done'
          ? shutdown.timedOut === true
            ? t('shutdown.doneUnknown')
            : formatText(t('shutdown.done'), { count: shutdown.killed })
          : shutdown.stage === 'error'
            ? formatText(t('shutdown.failed'), { message: shutdown.error })
            : shutdown.stage === 'running'
              ? t('shutdown.busy')
              : null;

      return h(
        'div',
        { className: 'dshpod-cfg' },
        h('div', { className: 'dshpod-cfg-title' }, t('settings.title')),
        h('div', { className: 'dshpod-cfg-desc' }, t('settings.desc')),
        h(
          'label',
          { className: 'dshpod-cfg-check', htmlFor: freezeId },
          h('input', {
            id: freezeId,
            type: 'checkbox',
            checked: freezeMode === true,
            disabled,
            onChange: (event) => setFreezeMode(event.target.checked === true),
          }),
          h('span', null, t('settings.freeze')),
        ),
        freezeMode === true
          ? h(
              React.Fragment,
              null,
              h(
                'div',
                { className: 'dshpod-cfg-row' },
                h('label', { className: 'dshpod-cfg-label', htmlFor: minutesId }, t('settings.minutes')),
                h('input', {
                  id: minutesId,
                  className: 'dshpod-input dshpod-cfg-input',
                  type: 'number',
                  min: FREEZE_MINUTES.min,
                  max: FREEZE_MINUTES.max,
                  step: 1,
                  inputMode: 'numeric',
                  value: freezeMinutes,
                  disabled: numbersDisabled,
                  onChange: (event) => setFreezeMinutes(event.target.value),
                  onKeyDown: (event) => {
                    if (event.key !== 'Enter' && event.key !== 'NumpadEnter') return;
                    event.preventDefault();
                    save();
                  },
                }),
              ),
              h(
                'div',
                { className: 'dshpod-cfg-row' },
                h('label', { className: 'dshpod-cfg-label', htmlFor: regenerationsId }, t('settings.regenerations')),
                h('input', {
                  id: regenerationsId,
                  className: 'dshpod-input dshpod-cfg-input',
                  type: 'number',
                  min: REGENERATIONS.min,
                  max: REGENERATIONS.max,
                  step: 1,
                  inputMode: 'numeric',
                  value: regenerations,
                  disabled: numbersDisabled,
                  onChange: (event) => setRegenerations(event.target.value),
                  onKeyDown: (event) => {
                    if (event.key !== 'Enter' && event.key !== 'NumpadEnter') return;
                    event.preventDefault();
                    save();
                  },
                }),
              ),
              h('div', { className: 'dshpod-cfg-desc' }, t('settings.freezeDesc')),
            )
          : null,
        h('div', { className: 'dshpod-cfg-note' }, t('settings.ranges')),
        h('div', { className: 'dshpod-cfg-subtitle' }, t('shells.title')),
        h('div', { className: 'dshpod-cfg-desc' }, t('shells.desc')),
        renderShellSelect('powershell', t('shells.powershell')),
        renderShellSelect('bash', t('shells.bash')),
        staleShells.length === 0
          ? null
          : h('div', { className: 'dshpod-cfg-error' }, t('shells.stale') + '（' + staleShells.join(' / ') + '）'),
        h('div', { className: 'dshpod-cfg-note' }, t('shells.cmdFixed') + (cmdPath === null ? '' : '：' + cmdPath)),
        shellError !== null
          ? h('div', { className: 'dshpod-cfg-error' }, formatText(t('shells.detectFailed'), { message: shellError }))
          : shellGroups.length === 0
            ? h('div', { className: 'dshpod-cfg-note' }, t('shells.loading'))
            : null,
        // Deliberately last and secondary: a choice is an override, never a
        // requirement, and the stock interpreter stays the recommendation.
        h('div', { className: 'dshpod-cfg-note' }, t('shells.optional')),
        writable === true ? null : h('div', { className: 'dshpod-cfg-error' }, t('settings.readOnly')),
        h(
          'div',
          { className: 'dshpod-cfg-save' },
          h(
            'button',
            { type: 'button', className: 'dshpod-button', disabled, onClick: save },
            busy ? t('settings.saving') : loaded ? t('settings.save') : t('settings.loading'),
          ),
          message === null
            ? null
            : h('span', { className: message.kind === 'ok' ? 'dshpod-cfg-ok' : 'dshpod-cfg-error', role: 'status' }, message.text),
        ),
        h('div', { className: 'dshpod-cfg-note' }, t('settings.note')),
        h(
          'div',
          { className: 'dshpod-danger-zone' },
          h('span', { className: 'dshpod-cfg-label' }, t('shutdown.title')),
          h('div', { className: 'dshpod-cfg-desc' }, t('shutdown.desc')),
          h(
            'div',
            { className: 'dshpod-cfg-save' },
            h(LongPressButton, { t, label: t('shutdown.hold'), busy: shutdown.stage === 'running', onConfirm: shutdownPod }),
            shutdownLine === null
              ? null
              : h(
                  'span',
                  {
                    className: shutdown.stage === 'error' ? 'dshpod-cfg-error' : 'dshpod-cfg-ok',
                    role: 'status',
                  },
                  shutdownLine,
                ),
          ),
        ),
      );
    }

    /** Registered bundle-config component; a crash stays on this page. */
    function EscapePodSettings(props) {
      return h(SettingsBoundary, null, h(EscapePodPanel, props));
    }

    /* ---------------------------------------------------------------- app ---- */

    const inject = ['slots', 'locale'];

    function apply(ctx) {
      ctx.effect(
        () =>
          ctx.locale.register(NS, {
            zh,
            en,
          }),
        'dsh-escape-pod: locale dictionaries',
      );
      ctx.effect(() => ensureStyles(), 'dsh-escape-pod: styles');
      // Plugins page -> this bundle's detail page. Contained so a config-page
      // failure can never affect anything else this plugin owns.
      try {
        ctx.slots.inject('plugins.bundle.config', () =>
          ctx.slots.register(
            {
              name: 'plugins.bundle.config',
              key: '@local/dsh-escape-pod',
              locale: NS,
            },
            EscapePodSettings,
          ),
        );
      } catch {
        /* optional surface */
      }
    }

    return { inject, apply };
  },
});
