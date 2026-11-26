# Optional Windows GUI package pairing

The Windows Actions packaging job uses the release bundle pinned by commit,
tag and SHA-256 in `scripts/installer-inputs.json`. The commit must match the
Panel gitlink. The job passes the verified bundle to CMake with `FETCH_GUI=OFF`;
it does not use the `FetchGUI.cmake` fallback for local development builds.

For an explicit paired development test, supply `gui_run_id` when dispatching
`main.yml`. Only this opt-in path uses `scripts/fetch-paired-gui.ps1`: the run
must be a successful Panel `build.yml` run at the committed
`src_assets/common/sunshine-control-panel` gitlink and contain a non-expired
`sunshine-gui-windows-x64` artifact. It keeps the GUI executable and native
plugin together and writes `paired-build.json` with the repository, run and
commit used. The two bundle sources are mutually exclusive in that workflow;
a missing or mismatched paired artifact fails the run instead of falling back
to the release bundle. Only those manual download steps read the
`PANEL_READ_TOKEN` Actions secret, which must be separately provisioned with
read access to the Panel repository's Actions artifacts. The current paired
fetch and gitlink both refer to `AlkaidLab/foundation-panel`; a fork needs an
explicit reviewed source change in both places, not merely a different run ID.
If building the Panel by manual dispatch, set `create_release=false`.

For local paired staging, run `scripts/fetch-paired-gui.ps1 -Destination <fresh-path>`
from the Sunshine checkout. Omit `RunId` to discover a matching build, or pass
`-RunId <id>` to validate a specific build. Configure with `FETCH_GUI=OFF` and
`GUI_DIR=<fresh-path>` to use the verified bundle. GitHub artifact access requires
an authenticated `gh` session or an appropriate `GH_TOKEN`.
