# Foundation portable v2026.1119: driver preflight

Use this checklist with the portable package associated with Core commit
`83438ebc1b4c3ba5a57ee91f5bd57c83d0822cdb`. A matching script is not proof of
the provenance of its driver binaries: verify the portable archive against
the trusted release record before any maintenance.
Keep any test staging and diagnostic logs on `D:`.

## Read-only checks

| Component | Paths relative to the portable `Sunshine` directory | Bundled INF versions |
| --- | --- | --- |
| ZakoVDD | `scripts\install-vdd.bat`, `scripts\vdd-device-helper.ps1`, `scripts\driver\latest\ZakoVDD.inf`, `scripts\driver\win10\ZakoVDD.inf` | `latest`: `100.0.18.2`; `win10`: `15.0.15.10` |
| Zako Virtual Mouse | `scripts\vmouse\install-vmouse.bat`, `scripts\vmouse\driver\ZakoVirtualMouse.inf` | `10.17.39.409` |

Inspect the actual package layout rather than assuming `install-vmouse.bat`
is directly under `scripts`. Record the OS build, selected VDD payload, and
the detected devices' provider, version and problem code. The VDD helper
selects a compatible payload; do not force a payload based solely on its
version number. `Get-PnpDevice -PresentOnly` and `Get-PnpDeviceProperty`
can inventory devices without installing anything. A GameViewer adapter is
not ZakoVDD and must not be removed. A present Zako adapter, even with PnP
status `OK`, does not prove that Sunshine can open its control interface.

## Approved maintenance window only

Use an isolated Windows test host with no active Sunshine session. Record
baseline device and display state and agree on rollback first. Run the
package's `scripts\install-vdd.bat` under explicitly authorized administrator
access only if VDD is absent or a repair is justified. Do not bypass driver
signature checks. Verify the Zako control interface registers, opens under
the normal Core identity, and accepts the expected ioctl. Test tray create,
keep and destroy, and verify Core cleans up a rejected or timed-out request.
Record interface registration, handle-open and ioctl results separately;
a successful installer exit is not sufficient.

Verify vmouse separately *after* VDD. If vmouse is absent or needs authorized
repair, run `scripts\vmouse\install-vmouse.bat` only after confirming the
window allows service interruption: its cleanup path can stop the Sunshine
service. Confirm the expected input backend really is active and exercise
basic input; working SendInput is not proof of vmouse. Either install may
prompt for UAC. Defer any required restart until specifically authorized.

Use only the matching package's documented rollback for the component changed;
do not remove unrelated display or input devices. Keep the actual device and
ioctl checks pending if no isolated test host/window is available.
