# Isolated Kanade HTTPS and Foundation online-mode validation

This procedure is for an approved Windows test environment, not the existing
User Center or a running Foundation install. Keep the User Center, companion,
host orchestrator, and Foundation Core separate. Use staging paths on `D:` and
an explicitly provisioned disposable database; do not reuse the live service's
environment or identity directories.

## User Center: one direct HTTPS origin

Choose one hostname (for example `localhost`), a free port (for example `8443`),
and a certificate whose subject alternative name matches that hostname. Its
issuer must already be trusted by the test browser and clients, or provisioned
through the test host's approved trust process. Keep the key in an existing
restricted test location, outside the repository. Do not bypass verification.

With an already provisioned test environment and valid certificate/key paths,
run Uvicorn directly in the test environment. The following is an example for
an administrative site on the same test machine, not a public listener:

```powershell
$env:PYTHONPATH = (Join-Path $PWD 'src')
.\.venv\Scripts\python.exe -m uvicorn kanade.main:app `
  --host 127.0.0.1 --port 8443 --no-proxy-headers `
  --ssl-certfile '<approved test certificate path>' `
  --ssl-keyfile '<approved test private key path>'
```

Open `https://localhost:8443/` in the browser. Do not use the existing
`http://127.0.0.1:8000/` endpoint for administrative login. Direct TLS avoids
trusting loopback `X-Forwarded-*` headers as proof of HTTPS. Do not enable a
reverse-proxy path without separately verifying the transport trust boundary.

With disposable test accounts, check these outcomes independently:

- A trusted HTTPS browser session can log in as admin and perform an exact
  same-origin write with its own session CSRF token. Verify the cookie flags
  (`Secure`, `HttpOnly`, `SameSite=Strict`) without recording its value.
- A direct HTTP admin login (including forwarded-header variants), an incorrect
  origin, a missing or wrong CSRF token, and a non-admin account are rejected.
  The direct-HTTP check uses an explicitly isolated test fixture, not the
  running HTTP service.
- The admin web session does not satisfy device-bound session operations.

## Companion and host sidecar

- Use the supported `python -m kanade.companion` entry point with the test
  HTTPS URL and a protected test identity store; see `Kanade/docs/companion.md`
  for configuration. Start with the intended identity already selected. Do not
  force enrollment or share a writable identity store with another process
  until its ownership and concurrency contract are verified. Verify pending,
  approval, rejection, and expiry in the companion, not in Foundation.
- Use the existing `python -m kanade.windows_host_lab --config <manifest.json>`
  orchestration with a verified, matching REM-2 Windows artifact and an isolated
  portable Foundation instance. See `Kanade/docs/m2a-rem2-sidecar-ipc.md` and
  `Kanade/docs/m2a-windows-acceptance.md`. Verify manifest and runtime
  provenance, private IPC, peer and lease checks, and native media encryption.
  The lab command can start its own processes if its preflight passes; it is
  not a read-only probe. The User Center launcher is not a sidecar launcher.
  The locked lab config requires `system_tray=disabled`; a passing lab run
  alone therefore cannot establish popup parity. Test the tray separately on
  the same candidate package, without relaxing the lab's isolation policy.
- Confirm there is no port conflict before starting the isolated instance. If
  there is a conflict or no trusted artifact, stop the test setup, not the
  existing service. Check the sidecar mapping and rejection cases for TCP
  `47990` and `48001`; do not disable the Foundation WebUI to get a clean result.

Verify the two UI surfaces on one candidate package, including disabled or
missing Kanade, stale status, pending work, and native PIN independently.
Record separate evidence for control-plane login, cloud authorization, native
pairing, and actual streaming. A ready sidecar or a successful native PIN is
not evidence of a working audio/video stream. Retain redacted outcomes and
artifact identifiers only; no credentials, identity blobs, or request contents.

## Artifact-only Windows CI

After separate push and run authorization, dispatch `Build and Release` on the
isolated validation branch with `publish=false`. For a new Panel build, set
`gui_run_id` only to a verified successful build for the committed Panel
gitlink. GitHub Actions needs read access to that artifact. With no run ID,
the GUI release pin must match the gitlink. Do not dispatch from `master`.

The locked Panel `462c3853` / GUI `1.0.5` does not have a dynamic popup
registration hook. A true dual-UI candidate needs the smallest Panel source
change, a new explicit gitlink and a matching GUI bundle; a package with the
old tray is not such a candidate. The REM-2 pipe is private to its parent and
child and carries credentials; it is not a status feed. Do not attach a UI
client to it or scrape companion output. Until there is a trusted, separate
read-only status source, the panel cannot assert online mode or display a
live cloud request count.

Compare `portable-build-inputs.json`, `SHA256SUMS.txt`, and the portable archive
under the same Actions run and attempt. Record the separate REM-2 Windows
workflow run, source commit and archive/executable hashes before a runtime
check. The CI package listing establishes that the WebUI and GUI were both
shipped; neither that listing nor a green test run establishes runtime parity
or working streaming.
