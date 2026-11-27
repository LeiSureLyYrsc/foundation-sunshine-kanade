// The online mode of the host, contract version 1: a pure read of the one optional object the host may publish in the
// answer it already sends to a page of this origin, GET /api/tray/state. Nothing in this file calls the host, starts a
// program, opens a socket or holds a secret: the shell runs the intents and this file only reads, projects and names.
//
// ---- the wire contract (what the Core producer must send) ------------------------------------------------
//
// GET /api/tray/state -> an object that already holds protocol_version, capabilities, status, sessions, vdd …
//
//   "capabilities": ["state-v1", "events-v1", …, "kanade-v1"]     // the feature is advertised here, on its own
//   "kanade": {                                                   // the optional state, version 1
//     "version": 1,                                               // strict; any other number, or none, is not read
//     "updated_at_ms": 1764153600123,                             // strict positive safe integer, epoch ms, never a string
//     "component": "available",                                   // available | disabled | missing | incompatible | unavailable
//     "registration": "registered",                               // registered | unregistered
//     "control": "online",                                        // online | offline | unreachable
//     "pending_count": 2,                                         // strict non-negative safe integer; no list, no ids
//     "transport": "protected",                                   // standby | protected
//     "connection_authorized": true,                              // boolean
//     "native_paired": true,                                      // boolean
//     "streaming": false                                          // boolean, about the connection this state describes
//   }
//
// Two independent gates, both required: `capabilities` must contain `kanade-v1`, and `kanade.version` must be 1. Either
// one missing is `unsupported` with its own reason, so a host that is too old (`no_capability`) reads differently from a
// host that promises the feature and sends something else (`capability_missing`, `state_missing`, `invalid`, `version`).
//
// `connection_authorized`, `native_paired` and `streaming` describe ONE connection — the Kanade connection this state is
// about. They are never derived from the host's native client list or its running sessions: a host that does not report
// them leaves them `unknown`, and an unknown is drawn as unknown.
//
// ---- freshness while the page stays open ----------------------------------------------------------------
//
// `updated_at_ms` is the host's own moment for the values. A read is kept for at most KANADE_ONLINE_MAX_AGE_MS; past that
// the values are dropped rather than shown as current (a stale row would look like a live one). While the panel is open the
// view re-reads on a bounded interval (KANADE_ONLINE_REFRESH_MS) and calls expireKanadeOnlineState() between reads, so a
// page left open for an hour cannot show an hour-old "online". A failed read is `unavailable`, which is a different
// sentence from `unsupported`.

export const KANADE_ONLINE_VERSION = 1
export const KANADE_ONLINE_CAPABILITY = 'kanade-v1'
/** The one property of the tray state that carries this contract. */
export const KANADE_ONLINE_STATE_KEY = 'kanade'
/** A read older than this is not shown as current. */
export const KANADE_ONLINE_MAX_AGE_MS = 120_000
/** How often an open panel re-reads, so the freshness above is checked with something to re-check. */
export const KANADE_ONLINE_REFRESH_MS = 30_000

/** The rows of the panel, in reading order; a tray port draws the same ones. */
export const KANADE_ONLINE_ROW_IDS = Object.freeze(['component', 'registration', 'control', 'pending', 'transport', 'connection', 'pairing', 'streaming'])
/** The intents the panel can emit; a tray port wires the same names to its own handlers. */
export const KANADE_ONLINE_ACTION_IDS = Object.freeze(['refresh', 'companion', 'user_center', 'native_pin'])

const COMPONENT_LEVELS = new Set(['available', 'disabled', 'missing', 'incompatible', 'unavailable'])
const REGISTRATION_LEVELS = new Set(['registered', 'unregistered'])
const CONTROL_LEVELS = new Set(['online', 'offline', 'unreachable'])
const TRANSPORT_LEVELS = new Set(['standby', 'protected'])

const TONE_OF = Object.freeze({
  available: 'ok',
  registered: 'ok',
  online: 'ok',
  authorized: 'ok',
  paired: 'ok',
  active: 'ok',
  protected: 'ok',
  none: 'ok',
  count: 'info',
  disabled: 'tertiary',
  standby: 'tertiary',
  unregistered: 'tertiary',
  not_authorized: 'tertiary',
  unpaired: 'tertiary',
  idle: 'tertiary',
  unknown: 'tertiary',
  missing: 'warn',
  incompatible: 'warn',
  offline: 'warn',
  unreachable: 'warn',
  unavailable: 'warn',
  unsupported: 'warn',
  stale: 'warn',
})

/** Only a warning or an error needs a glyph beside its chip: the tone already carries the rest. */
const ICON_OF_TONE = Object.freeze({ warn: 'warning', error: 'error' })

const isRecord = (value) => !!value && typeof value === 'object' && !Array.isArray(value)

/** One level of a closed set, or `unknown`: a word this build does not know is not turned into a state. */
const levelOf = (value, allowed) => (typeof value === 'string' && allowed.has(value) ? value : 'unknown')

/** A proof carried only by an actual boolean: `true`/`false` prove, anything else is unknown. */
const proofOf = (value, whenTrue, whenFalse) => (value === true ? whenTrue : value === false ? whenFalse : 'unknown')

/** The exact numeric field of the pending requests: a count, never a list of ids. */
const pendingCountOf = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : null)

/** The host's moment for the values: a positive safe integer, with no coercion — a string or a bool is not a time. */
const timestampOf = (value) => (Number.isSafeInteger(value) && value > 0 ? value : null)

const toneOf = (level) => TONE_OF[level] || 'tertiary'
const iconOf = (tone) => ICON_OF_TONE[tone]

/** The state that has no readable data, only a reason. */
const absentState = (presence, reason, readAtMs) => ({ presence, reason, version: 0, updatedAtMs: null, readAtMs, data: null })

/**
 * Reads the online-mode state out of a tray state answer. Pure: the same arguments give the same result.
 *
 * @param {unknown} trayState the object GET /api/tray/state returned, or null once the call failed
 * @param {object} [options]
 * @param {number} [options.now] the moment of the read, for the age check
 * @param {number} [options.maxAgeMs] how old the host's values may be and still be shown
 * @param {string} [options.failure] why there is no answer (`read`, `timeout`, `status`); it only names the reason
 * @returns {{presence:'supported'|'unsupported'|'unavailable'|'stale', reason:string, version:number,
 *            updatedAtMs:number|null, readAtMs:number, data:object|null}}
 */
export function readKanadeOnlineState(trayState, options = {}) {
  const now = Number.isFinite(options.now) ? options.now : Date.now()
  const maxAgeMs = Number.isFinite(options.maxAgeMs) ? options.maxAgeMs : KANADE_ONLINE_MAX_AGE_MS

  if (options.failure) return absentState('unavailable', String(options.failure), now)
  if (!isRecord(trayState)) return absentState('unavailable', 'read', now)

  const advertised = Array.isArray(trayState.capabilities) && trayState.capabilities.includes(KANADE_ONLINE_CAPABILITY)
  const raw = trayState[KANADE_ONLINE_STATE_KEY]
  const present = raw !== undefined && raw !== null

  // The two gates are independent, so each failure keeps its own name.
  if (!advertised && !present) return absentState('unsupported', 'no_capability', now)
  if (present && !advertised) return absentState('unsupported', 'capability_missing', now)
  if (!present) return absentState('unsupported', 'state_missing', now)
  if (!isRecord(raw)) return absentState('unsupported', 'invalid', now)
  if (raw.version !== KANADE_ONLINE_VERSION) return absentState('unsupported', 'version', now)

  const updatedAtMs = timestampOf(raw.updated_at_ms)
  if (updatedAtMs === null) return absentState('unsupported', 'invalid_timestamp', now)
  // A clock that runs the other way is as untrustworthy as a late answer; both leave the age unproven.
  if (Math.abs(now - updatedAtMs) > maxAgeMs) return absentState('stale', 'stale', now)

  const data = Object.freeze({
    component: levelOf(raw.component, COMPONENT_LEVELS),
    registration: levelOf(raw.registration, REGISTRATION_LEVELS),
    control: levelOf(raw.control, CONTROL_LEVELS),
    pendingCount: pendingCountOf(raw.pending_count),
    transport: levelOf(raw.transport, TRANSPORT_LEVELS),
    connectionAuthorized: proofOf(raw.connection_authorized, 'authorized', 'not_authorized'),
    nativePaired: proofOf(raw.native_paired, 'paired', 'unpaired'),
    streaming: proofOf(raw.streaming, 'active', 'idle'),
  })

  return { presence: 'supported', reason: 'ok', version: KANADE_ONLINE_VERSION, updatedAtMs, readAtMs: now, data }
}

/**
 * The same state as it stands at `now`: a supported state whose values have aged past the limit becomes `stale`, and its
 * values are dropped with it. The view calls this between reads so a panel left open cannot keep showing old values.
 */
export function expireKanadeOnlineState(state, now, maxAgeMs = KANADE_ONLINE_MAX_AGE_MS) {
  if (state?.presence !== 'supported' || !state.data) return state
  const moment = Number.isFinite(now) ? now : Date.now()
  const ageOfRead = moment - Number(state.readAtMs)
  const ageOfValues = state.updatedAtMs === null ? Infinity : moment - Number(state.updatedAtMs)
  if (ageOfRead <= maxAgeMs && ageOfValues <= maxAgeMs) return state
  return absentState('stale', 'aged_out', moment)
}

/** The row of one level: its id, the level itself, the chip tone and, for a tone that needs one, the icon. */
function rowOf(id, level, extra = {}) {
  const tone = toneOf(level)
  return { id, level, tone, icon: iconOf(tone), ...extra }
}

/**
 * What the panel lists. A state that could not be read is one row saying so: the eight fields of an unreadable payload
 * are not drawn as eight unknowns, which would look like eight answers.
 */
export function kanadeOnlineRows(state) {
  const presence = state?.presence
  if (presence !== 'supported' || !state?.data) return [rowOf('presence', presence || 'unavailable')]
  const data = state.data
  return [
    rowOf('component', data.component),
    rowOf('registration', data.registration),
    rowOf('control', data.control),
    data.pendingCount === null
      ? rowOf('pending', 'unknown')
      : rowOf('pending', data.pendingCount > 0 ? 'count' : 'none', { count: data.pendingCount }),
    rowOf('transport', data.transport),
    rowOf('connection', data.connectionAuthorized),
    rowOf('pairing', data.nativePaired),
    rowOf('streaming', data.streaming),
  ]
}

/**
 * Why an entry is not usable, as one reason code per entry. The distinctions are the point: a host with no online mode at
 * all, a host whose answer cannot be read, an answer that has aged out, a component that is installed but disabled, and a
 * program this product has no trusted way to open are five different situations and read as five.
 */
function blockedReason(state) {
  const presence = state?.presence
  if (presence === 'unsupported') return 'unsupported_host'
  if (presence === 'unavailable') return 'state_unreadable'
  if (presence === 'stale') return 'state_stale'
  const component = state?.data?.component
  if (component && component !== 'available' && component !== 'unknown') return 'component_unavailable'
  const control = state?.data?.control
  if (control === 'offline' || control === 'unreachable') return 'control_offline'
  return ''
}

/**
 * What the panel offers. Refresh always works, because the state it re-reads is the one thing this panel can do alone. The
 * companion and the User Center are separate programs: their entries are enabled only when the shell passes a trusted
 * handler, and otherwise say why they cannot be pressed. The native PIN stays enabled whatever the online state is.
 *
 * @param {object} [options]
 * @param {object|null} [options.state] what readKanadeOnlineState (or expireKanadeOnlineState) returned
 * @param {boolean} [options.busy] a read is in flight
 * @param {{companion?: Function, userCenter?: Function}} [options.handlers] what the shell can actually open
 */
export function kanadeOnlineActions(options = {}) {
  const handlers = options.handlers || {}
  const blocked = blockedReason(options.state)
  const program = (name) => {
    if (blocked) return { enabled: false, reason: blocked }
    if (typeof handlers[name] !== 'function') return { enabled: false, reason: 'no_handler' }
    return { enabled: true, reason: '' }
  }
  return [
    { id: 'refresh', enabled: options.busy !== true, reason: options.busy === true ? 'busy' : '' },
    { id: 'companion', ...program('companion') },
    { id: 'user_center', ...program('userCenter') },
    { id: 'native_pin', enabled: true, reason: '' },
  ]
}

// ---- the labels: EN and zh-CN, here, so no shared locale file has to carry them ----

const EN = {
  panel: {
    title: 'Online mode',
    description: 'Kanade authorization does not replace the native Sunshine PIN.',
  },
  presence: {
    supported: 'The host reports an online state.',
    unsupported: 'This host does not offer an online state this panel can read.',
    unavailable: 'The online state cannot be read right now.',
    stale: 'The last online state has aged out, so none of its values are shown.',
  },
  field: {
    component: 'Kanade component',
    registration: 'Registration',
    control: 'Control plane',
    pending: 'Pending requests',
    transport: 'Transport',
    connection: 'Kanade connection',
    pairing: 'Native pairing',
    streaming: 'Streaming',
  },
  component: {
    available: 'Ready',
    disabled: 'Disabled',
    missing: 'Not installed',
    incompatible: 'Incompatible version',
    unavailable: 'Not usable',
    unknown: 'Unknown',
  },
  registration: { registered: 'Registered', unregistered: 'Not registered', unknown: 'Unknown' },
  control: { online: 'Online', offline: 'Offline', unreachable: 'Unreachable', unknown: 'Unknown' },
  pending: { none: 'None', count: '{count}', unknown: 'Unknown' },
  transport: { standby: 'Standby', protected: 'Protected path ready', unknown: 'Unknown' },
  connection: { authorized: 'Authorized', not_authorized: 'Not authorized', unknown: 'Unknown' },
  pairing: { paired: 'Paired', unpaired: 'Not paired', unknown: 'Not reported' },
  streaming: { active: 'Streaming now', idle: 'Not streaming', unknown: 'Not reported' },
  action: {
    refresh: 'Refresh',
    companion: 'Open companion',
    user_center: 'Open User Center',
    native_pin: 'Enter native PIN',
  },
  action_reason: {
    busy: 'Reading the state from the host.',
    no_handler: 'This host offers no trusted way to open it yet.',
    unsupported_host: 'The host has no online mode to open.',
    state_unreadable: 'The online state cannot be read right now.',
    state_stale: 'The online state has aged out; refresh to read it again.',
    component_unavailable: 'The Kanade component is not usable on this host.',
    control_offline: 'The control plane is not reachable.',
  },
  note: {
    per_connection: 'The Kanade connection, native pairing and streaming above describe this connection only; they are not taken from the host’s client list or its running sessions.',
    scope: 'The companion and the User Center are separate programs. This panel shows what the host reports and offers the way in; it does not approve requests, sign anything in, or replace the native PIN.',
    absence: 'You can still use the native PIN and connect over your local network.',
  },
}

const ZH = {
  panel: {
    title: '在线模式',
    description: 'Kanade 授权不能代替 Sunshine 原生 PIN。',
  },
  presence: {
    supported: '主机报告了在线状态。',
    unsupported: '当前主机没有提供本面板能读取的在线状态。',
    unavailable: '暂时读不到在线状态。',
    stale: '上一次在线状态已经过期，因此不显示它的任何一项数值。',
  },
  field: {
    component: 'Kanade 组件',
    registration: '登记',
    control: '控制面',
    pending: '待处理请求',
    transport: '传输',
    connection: 'Kanade 连接',
    pairing: '原生配对',
    streaming: '串流',
  },
  component: {
    available: '正常',
    disabled: '已禁用',
    missing: '未安装',
    incompatible: '版本不兼容',
    unavailable: '不可用',
    unknown: '未知',
  },
  registration: { registered: '已登记', unregistered: '未登记', unknown: '未知' },
  control: { online: '在线', offline: '离线', unreachable: '不可达', unknown: '未知' },
  pending: { none: '没有', count: '{count} 项', unknown: '未知' },
  transport: { standby: '待命', protected: '受保护路径已就绪', unknown: '未知' },
  connection: { authorized: '已获授权', not_authorized: '未获授权', unknown: '未知' },
  pairing: { paired: '已配对', unpaired: '未配对', unknown: '主机未报告' },
  streaming: { active: '正在串流', idle: '没有串流', unknown: '主机未报告' },
  action: {
    refresh: '刷新',
    companion: '打开 companion',
    user_center: '打开 User Center',
    native_pin: '输入原生 PIN',
  },
  action_reason: {
    busy: '正在从主机读取状态。',
    no_handler: '这台主机还没有提供可信的打开方式。',
    unsupported_host: '主机没有可打开的在线模式。',
    state_unreadable: '暂时读不到在线状态。',
    state_stale: '在线状态已过期，刷新可重新读取。',
    component_unavailable: 'Kanade 组件在这台主机上不可用。',
    control_offline: '控制面不可达。',
  },
  note: {
    per_connection: '上面的 Kanade 连接、原生配对和串流只描述这一个连接，不取自主机的客户端列表或正在运行的会话。',
    scope: 'companion 和 User Center 是独立程序。此面板只显示主机报告的状态并提供入口，不代为批准请求，也不代替原生 PIN。',
    absence: '你仍可使用原生 PIN，在局域网内连接。',
  },
}

/** The labels of the panel in the language the panel shows: Chinese for a Chinese locale, English for every other one. */
export function kanadeOnlineTexts(locale) {
  return /^zh/i.test(String(locale || 'en')) ? ZH : EN
}

/**
 * One label by its dotted key (`field.component`, `component.missing`, `action.native_pin`), with `{name}` placeholders
 * filled from `params`. A key that is not there comes back as the key itself, which is visible without throwing.
 */
export function kanadeOnlineText(texts, key, params = {}) {
  const value = String(key || '').split('.').reduce((node, part) => (node && typeof node === 'object' ? node[part] : undefined), texts)
  if (typeof value !== 'string') return String(key || '')
  return value.replace(/\{(\w+)\}/g, (match, name) => (params[name] === undefined || params[name] === null ? match : String(params[name])))
}

/** The value text of one row: a count row reads its number, every other one its level. */
export function kanadeOnlineRowText(texts, row) {
  if (!row) return ''
  if (row.id === 'presence') return kanadeOnlineText(texts, `presence.${row.level}`)
  if (row.id === 'pending') return kanadeOnlineText(texts, `pending.${row.level === 'count' ? 'count' : row.level}`, { count: row.count ?? 0 })
  return kanadeOnlineText(texts, `${row.id}.${row.level}`)
}
