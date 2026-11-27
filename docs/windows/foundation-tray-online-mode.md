# Foundation tray online mode: paired source handoff

The Windows tray popup (all three WebView variants, including the default
right-click popup) shows Online mode in the menu itself. It consumes the same
`kanade-v1` wire contract as the WebUI and uses the existing authenticated
Core tray polling/SSE. Refresh requests a bounded read through Panel's local
Core tray client. Native PIN opens the existing local pairing page, not a
new PIN flow or a cloud approval. The native system-menu fallback is unchanged.
Companion and User Center remain disabled: this package has no trusted
host action for either one.

## Review and apply the source changes

The cross-repository patches are attached to this Core branch, not merged into
its uninitialized submodule. Apply them in **separate, clean checkouts** at the
exact bases below; do not apply them over the installed GUI or advance pins
without the matching artifacts.

1. In `AlkaidLab/foundation-ui` at
   `f059aa4c5777b011a2788477d2c9e9fda253908c`, check and apply
   [`foundation-ui-tray-start-page.patch`](tray-online-mode/foundation-ui-tray-start-page.patch)
   using `git apply --check` then `git apply`. Use an LF checkout on Windows
   (`git -c core.autocrlf=false` when checking out the base). It adds a generic
   optional `start-page` slot to `MTrayPopup`/`MTrayMenu`. Without the slot,
   existing consumers keep the same content and menu behavior.
2. In `AlkaidLab/foundation-panel` at
   `462c3853699f6b0078afd15f29b5a7bbc7ad0a8d`, check and apply
   [`foundation-panel-tray-online-mode.patch`](tray-online-mode/foundation-panel-tray-online-mode.patch)
   the same way. Run the contract fixture in the Panel checkout, with
   `FOUNDATION_ONLINE_WEB_CONTRACT` set to the absolute Core checkout path for
   `src_assets/common/assets/web/utils/kanadeOnlineMode.js`:
   `node --test src/renderer/ctxmenu/trayOnlineMode.test.js`. This compares
   the independently implemented readers against the same inputs without
   importing GPL Core source into the MIT Panel bundle.
3. After cross-repo source/push approval, make the new foundation-ui commit
   available to Panel, update Panel's `package.json` **and** `package-lock.json`
   to the exact new foundation-ui commit with the matching integrity value,
   and run Panel's renderer tests and its Windows artifact-only workflow
   (`create_release=false`). Verify the GUI executable and native plugin are
   paired. Merely applying the Panel patch without the new dependency will not
   render the slot. Do not move Core's own unchanged WebUI UI dependency pin
   just to build Panel.
4. Record the new Panel commit as Core's Panel gitlink after the bundle exists.
   Follow [the paired build procedure](../paired-gui-build.md) for `gui_run_id`
   and authorized artifact read access. If Panel builds from a fork, review
   both the repository URL and artifact-source checks. Use `publish=false`
   for the isolated Core run. Do not loosen the release pin or make the
   workflow fall back to the old bundle on a mismatch. To back out, stop
   selecting the paired candidate; do not overwrite a running installation.

## Remaining status and runtime gates

Core implements an optional `kanade-v1` serializer and an in-process publisher
for a typed, minimal observation. The locked Kanade components do not expose
a separately trusted read-only feed to Core; the REM-2 pipe and companion
output are not feeds. Until a separate vetted provider is wired, neither
surface claims Kanade is online or shows a live count. A source must provide
its observation time and separate evidence for Authorization, native pairing
and streaming; absent fields are unknown. Do not publish IDs, credentials,
launch URLs, or commands. When the provider is withdrawn, clear the snapshot;
both surfaces age out unrefreshed observations.

Run Core's `tray_state_unit_tests` and the existing auth/pairing checks in
authorized Windows CI. On one matching isolated portable package, check the
actual tray popup and WebUI for old Core, missing/disabled component, stale and
disconnected state, offline/reconnect, a pending count and protected-path
readiness; use approved fixtures until a trusted feed is available. Verify
refresh stays in the popup and PIN reaches the local `/pin#pairing` flow even
without Kanade. Record the foundation-ui, Panel, and Core SHAs together with
run/attempt and SHA-256 evidence. Native WebView sizing, focus and interaction
are not proven by source tests; do not count them or live media/streaming as
passed without an authorized runtime window.
