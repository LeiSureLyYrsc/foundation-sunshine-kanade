<template>
  <div class="kanade-online" role="group" :aria-label="T.panel.title" :aria-busy="busy ? 'true' : 'false'" :data-kanade-presence="presence">
    <!-- A state that could not be read is said in one line, not drawn as eight unknowns that would look like eight answers. -->
    <MBanner v-if="!supported" class="kanade-online__absent" tone="warn" icon="warning">
      <strong>{{ T.panel.title }}</strong>
      <div>{{ presenceText }}</div>
    </MBanner>
    <!-- Each row is the host's word on one thing: ready does not follow from online, and none of them follows from pairing. -->
    <MGroup v-else class="kanade-online__states">
      <MItem v-for="row in rows" :key="row.id" :title="T.field[row.id]" :data-kanade-row="row.id" :data-kanade-level="row.level">
        <template #trail><MChip :tone="row.tone" :icon="row.icon">{{ rowText(row) }}</MChip></template>
      </MItem>
    </MGroup>
    <!-- Intents only: the page that shows this panel runs what it can; the companion and the User Center are separate
         programs, so their rows stay disabled until the shell gives a trusted handler for them. -->
    <MGroup class="kanade-online__actions">
      <MItem
        v-for="action in actions"
        :key="action.id"
        action
        :icon="ACTION_ICONS[action.id]"
        :title="T.action[action.id]"
        :text="action.reason ? T.action_reason[action.reason] : ''"
        :disabled="!action.enabled"
        :data-kanade-action="action.id"
        :data-kanade-enabled="action.enabled ? 'true' : 'false'"
        @click="emitAction(action)"
      />
    </MGroup>
    <MFooter>{{ T.panel.description }} {{ supported ? T.note.per_connection : T.note.absence }}</MFooter>
    <p class="kanade-online__live" role="status" aria-live="polite" aria-atomic="true">{{ liveText }}</p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { MBanner, MChip, MFooter, MGroup, MItem } from 'foundation-ui/vue'
import { kanadeOnlineActions, kanadeOnlineRowText, kanadeOnlineRows, kanadeOnlineText, kanadeOnlineTexts } from '../../utils/kanadeOnlineMode.js'

// The online-mode panel of the Web UI, and the same rows a tray port draws: the labels and the row ids come from
// utils/kanadeOnlineMode.js, the reading of the host's answer comes from there too. This component asks nothing of the host
// and starts nothing; it draws the state it was given and emits the id of the action that was pressed.
const props = defineProps({
  /** What readKanadeOnlineState returned. */
  state: { type: Object, default: null },
  /** A read is in flight: the rows stay, the refresh row says so and does not repeat the call. */
  busy: { type: Boolean, default: false },
  /** The language the panel speaks: Chinese for a Chinese locale, English for every other one. */
  locale: { type: String, default: 'en' },
  /** What the shell can actually open (`companion`, `userCenter`); an entry without one is disabled, never faked. */
  handlers: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['action'])

const ACTION_ICONS = Object.freeze({ refresh: 'refresh', companion: 'terminal', user_center: 'public', native_pin: 'dialpad' })

const T = computed(() => kanadeOnlineTexts(props.locale))
const presence = computed(() => String(props.state?.presence || 'unavailable'))
const supported = computed(() => presence.value === 'supported')
const rows = computed(() => kanadeOnlineRows(props.state))
const actions = computed(() => kanadeOnlineActions({ state: props.state, busy: props.busy, handlers: props.handlers }))
const presenceText = computed(() => kanadeOnlineText(T.value, `presence.${presence.value}`))
const rowText = (row) => kanadeOnlineRowText(T.value, row)
// What changes is announced once: the presence of the state, or the in-flight read.
const liveText = computed(() => (props.busy ? T.value.action_reason.busy : presenceText.value))

function emitAction(action) {
  if (!action?.enabled) return
  emit('action', action.id)
}
</script>

<style scoped>
/* the one announcement of a change, read by a screen reader and not drawn */
.kanade-online__live { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }
.kanade-online__absent :deep(.m-banner__text) { display: grid; gap: 2px; }
</style>
