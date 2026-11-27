import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  KANADE_ONLINE_MAX_AGE_MS,
  expireKanadeOnlineState,
  kanadeOnlineActions,
  kanadeOnlineRows,
  kanadeOnlineTexts,
  readKanadeOnlineState,
} from '../utils/kanadeOnlineMode.js'

const now = 1_764_153_600_123
const tray = (patch = {}) => ({ capabilities: ['state-v1', 'kanade-v1'], kanade: { version: 1, updated_at_ms: now, ...patch } })
const read = (snapshot) => readKanadeOnlineState(snapshot, { now })
const levels = (state) => Object.fromEntries(kanadeOnlineRows(state).map(({ id, level }) => [id, level]))

test('old Core, unreadable response and wrong contract version are distinguishable', () => {
  assert.equal(read({ capabilities: ['state-v1'] }).reason, 'no_capability')
  assert.equal(read({ kanade: tray().kanade }).reason, 'capability_missing')
  assert.equal(read({ capabilities: ['kanade-v1'] }).reason, 'state_missing')
  assert.equal(read(tray({ version: 2, control: 'online' })).data, null)
  assert.equal(read(null).presence, 'unavailable')
})

test('freshness and counts do not coerce non-numeric values', () => {
  for (const invalid of [null, 0, false, String(now), Infinity]) {
    assert.equal(read(tray({ updated_at_ms: invalid })).data, null)
  }
  for (const invalid of [null, false, '1', -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(levels(read(tray({ pending_count: invalid }))).pending, 'unknown')
  }
  const sample = read(tray({ control: 'online' }))
  const expired = expireKanadeOnlineState(sample, now + KANADE_ONLINE_MAX_AGE_MS + 1)
  assert.equal(expired.presence, 'stale')
  assert.equal(expired.data, null)
})

test('online, grant, native pairing, and streaming remain independent', () => {
  const observed = tray({ component: 'available', registration: 'registered', control: 'online', pending_count: 3,
    transport: 'standby', connection_authorized: true, native_paired: false, streaming: 'false', ignored: 'extra' })
  observed.sessions = [{ id: 1 }]
  const state = read(observed)
  assert.deepEqual(levels(state), { component: 'available', registration: 'registered', control: 'online', pending: 'count',
    transport: 'standby', connection: 'authorized', pairing: 'unpaired', streaming: 'unknown' })
  assert.deepEqual(Object.keys(state.data).sort(), [
    'component', 'connectionAuthorized', 'control', 'nativePaired', 'pendingCount', 'registration', 'streaming', 'transport',
  ])
})

test('refresh and native PIN remain available even when integration is missing or disabled', () => {
  const stateCases = [read(null), read({}), ...['disabled', 'missing', 'incompatible', 'unavailable'].map((component) => read(tray({ component }))),
    read(tray({ control: 'offline' })), read(tray({ control: 'online', transport: 'protected' }))]
  for (const state of stateCases) {
    assert.deepEqual(kanadeOnlineActions({ state }).filter((action) => action.enabled).map((action) => action.id),
      ['refresh', 'native_pin'])
  }
  assert.equal(kanadeOnlineActions({ busy: true }).find((action) => action.id === 'refresh').enabled, false)
  assert.equal(kanadeOnlineTexts('zh-CN').panel.title, '在线模式')
})

test('the authenticated Web shell embeds the view and uses the existing PIN flow', () => {
  const shell = readFileSync(new URL('../views/WebShell.vue', import.meta.url), 'utf8')
  const view = readFileSync(new URL('../views/OnlineMode.vue', import.meta.url), 'utf8')
  assert.match(shell, /hash: 'online-mode'/)
  assert.match(view, /apiJson\('\/api\/tray\/state'/)
  assert.match(view, /shell\.nav\.go\('pin'\)/)
  assert.doesNotMatch(view, /local-auth\.token|X-Sunshine-Local-Token|http:\/\/|shell\.open/)
})
