# Local Web UI token: Windows publication failure

When the Core cannot publish its protected local token, the previous value is
not accepted. Keep browser account login and HTTPS as the independent route
for local management. An anonymous `401` is expected; do not bypass it.

Record `stage` and `win32_error` from Core in an isolated candidate run. For
`MoveFileExW`, code `32` is a sharing violation and code `5` is access denied.
The latter can have several causes. The additional warning about possible
administrator ownership is based on read-only metadata and is not proof of
the cause, of installation ownership, or of permission to perform a repair.
Record any separate `DeleteFileW(temp)` error; it does not change the original
failure. Failed publication can leave a file that was never a valid token.
Do not inspect its contents or sweep for temporary files. A running Core
spaces out retries after a failed interactive-user rotation and keeps its
previous credential disabled between attempts.

**Approved maintenance window only:** have an operator use trusted installation
maintenance to verify the exact configured file named `local-auth.token`, the
installation it belongs to, resolved parent and target, single link, owner and
DACL. Stop if any path component is a reparse point, the target is not a
regular file, the metadata cannot be verified, or this is not the approved
isolated instance. If the operator approves an exact-file recovery, handle only
that verified leftover in the maintenance window and let normal-identity Core
publish a new token. Do not change directory ACLs, copy the old credential,
move the token to a different path, or leave Core or the GUI elevated. A Core
whose token initialization failed needs an approved restart after recovery.

In the Windows fixture, verify ordinary rotation, a replacement obstruction,
rejection of the old credential and subsequent publication. In a separate
authorized run, reproduce the actual administrator-owned case. Confirm an
already running tray reconnects after the isolated Core restarts, authenticates
state and event requests with the new token and continues to reject anonymous,
old and unauthorized credentials. Keep logs on `D:` and report only stages,
codes, and access assertions; do not collect token values.
