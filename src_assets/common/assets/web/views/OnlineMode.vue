<template>
  <div class="m-app m-root online-mode-page">
    <MPage :title="T.panel.title">
      <KanadeOnlinePanel :state="state" :busy="busy" :locale="String(locale)" @action="onAction" />
    </MPage>
  </div>
</template>

<script setup>
import { computed, inject, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { MPage } from 'foundation-ui/vue'
import KanadeOnlinePanel from '../components/kanade/KanadeOnlinePanel.vue'
import { KANADE_ONLINE_MAX_AGE_MS, KANADE_ONLINE_REFRESH_MS, expireKanadeOnlineState, kanadeOnlineTexts, readKanadeOnlineState } from '../utils/kanadeOnlineMode.js'
import { apiJson } from '../utils/apiFetch.js'

// 在线模式 (stream): the host's optional online state, read from the one place the host already publishes it to a page of
// this origin, GET /api/tray/state, through the session this page already has. Nothing else is asked of the network and no
// address is guessed: the companion and the User Center are separate programs with no trusted way in from here yet, so
// their entries stay disabled and the panel says why. The native PIN is the page 连接设备 of this shell.
const TIMEOUT_MS = 6000

const { locale } = useI18n()
const shell = inject('webShell', null)
const T = computed(() => kanadeOnlineTexts(String(locale.value)))
const state = ref(readKanadeOnlineState(null, { failure: 'read' }))
const busy = ref(false)
let request = null
let poll = null
let expiration = null

function expire() {
  clearTimeout(expiration)
  const now = Date.now()
  state.value = expireKanadeOnlineState(state.value, now)
  if (state.value.presence === 'supported') {
    const deadline = Math.min(state.value.updatedAtMs, state.value.readAtMs) + KANADE_ONLINE_MAX_AGE_MS
    expiration = setTimeout(expire, Math.max(1, deadline - now + 1))
  }
}

async function refresh() {
  if (busy.value) return
  busy.value = true
  const controller = new AbortController()
  request = controller
  try {
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(TIMEOUT_MS)])
    const trayState = await apiJson('/api/tray/state', { signal, cache: 'no-store' })
    if (!controller.signal.aborted) state.value = readKanadeOnlineState(trayState)
  } catch (error) {
    if (!controller.signal.aborted) state.value = readKanadeOnlineState(null, { failure: error?.name === 'TimeoutError' ? 'timeout' : 'read' })
  } finally {
    request = null
    busy.value = false
    if (!controller.signal.aborted) expire()
  }
}

function onAction(id) {
  if (id === 'refresh') { void refresh(); return }
  // the native PIN is this shell's own page, opened with the request its pair button uses
  if (id === 'native_pin') {
    if (shell?.nav) {
      shell.nav.go('pin')
      shell.pending.value = 'pair'
    }
  }
}

onMounted(() => {
  void refresh()
  poll = setInterval(() => { expire(); void refresh() }, KANADE_ONLINE_REFRESH_MS)
})
onBeforeUnmount(() => {
  clearInterval(poll)
  clearTimeout(expiration)
  request?.abort()
})
</script>
