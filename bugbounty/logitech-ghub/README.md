# Logitech G HUB — bug bounty working notes

HackerOne, asset "G Hub / Executable / High / Eligible". Only the latest G HUB version is in
scope — **re-verify the installed version is current before submitting anything.**

Read in this order:

| File | What it is |
|---|---|
| `windows-pending-testing.md` | Session 0 — static analysis of the installer, on Linux. |
| `WHAT-DO-I-DO.md` | Session 0's instructions for the first Windows run. |
| `windows-session-1-results.md` | Session 1 — Windows recon. Killed the privesc-by-ACL thesis; found the Overwolf 45654 origin issue. |
| `FEDORA-SESSION-RESULTS.md` | Session 2 — recovered the SYSTEM updater's full IPC protocol and found the accept-time security check. **Its §2 lead is now closed — read session 3 before acting on it.** |
| `WHAT-DO-I-DO-windows.md` | Session 2's instructions for the second Windows run. Executed; superseded. |
| **`windows-session-2-results.md`** | **Session 3 — current state.** Identified the updater's real IPC transport and closed the §2 lead. |
| **`WHAT-DO-I-DO-fedora.md`** | **Do this next**, on Fedora. Static analysis only. |

## Current status

**The §2 lead is closed. No finding.**

`lghub_updater.exe` (SYSTEM) **does** own a named pipe — `\\.\pipe\<GUID>`, e.g.
`a62ed1c1-e1a9-5495-9038-16bd49ec7341`. Session 2 concluded no Logitech pipe existed and inferred
that the IPC therefore ran over TCP 9180, hitting the unconditional-allow branch of
`FUN_140c243e0`. That was a false negative: the pipe name is a bare GUID, so a name grep misses it.
Because a pipe transport is in use, the **enforced** branch applies — the peer's real PID is
resolved from the kernel, pinned against PID reuse, and signature-verified against `Logitech Inc`.

Independently confirmed: **TCP 9180 is not the IPC.** It returned a byte-identical `HTTP/1.0 404`
to plain GETs *and* to six WebSocket upgrades across four paths and both recovered subprotocols.
A websocketpp endpoint answers `400`/`426` to an upgrade it rejects; a constant 404 with no
path- or header-dependent variation means no route matched and no upgrade handler was consulted.

**What survives:** a low-priv, unsigned process **can open** the updater's pipe — the DACL admits
ordinary users, so the entire defence is the post-accept signature check. One experiment remains:
send a `HelloRequest` over that pipe and see whether the connection is dropped. Static analysis
says it will be. That test has **not** been run; question 6 of the gate (working PoC) is still
unmet, and no report should be written until it returns a positive result.

`WHAT-DO-I-DO-fedora.md` is the next step — it recovers the pipe framing and `content_type` so
that test is a single write rather than a blind sweep.

## Layout

```
protos/                    69 .proto files reconstructed from lghub_updater.exe  <- the IPC protocol
protos_agent/              same, recovered from lghub_agent.exe
windows/                   find-logi-endpoint.ps1 (v2), ipc_probe.py  <- run these on Windows
tools/                     extract_protos.py, DumpDepot.java, TraceAuth.java
analysis/                  Ghidra output backing the claims in FEDORA-SESSION-RESULTS.md §2
evidence/windows-session-2/ raw output backing windows-session-2-results.md
```

## Tooling notes

- `windows/find-logi-endpoint.ps1` **v1 was broken** — it printed an empty section 1 on every
  machine and would have led to the opposite (wrong) conclusion. Four defects, all fixed in v2;
  see `windows-session-2-results.md` §5. The failure was silent, which is how the dead lead
  survived a session.
- `windows/ipc_probe.py` has never been run — `python` on the Windows box is the Microsoft Store
  alias stub, not a real interpreter. Its WebSocket half is superseded by the PowerShell probes in
  v2 of the endpoint script; its raw-framing half is moot now that 9180 is not the IPC.

## Closed — do not re-chase

Install-dir ACLs, DLL hijacking, unquoted service paths, unsigned binaries, updater MITM,
`ProgramData\LGHUB` write access, and the depot path-traversal check (correctly implemented).
The Overwolf 45654 origin issue is downgraded — React escapes the injected data and the affected
UI only renders when Overwolf is actually installed.

Added by session 3:

- **TCP 9180 and the "transport-dependent security check" thesis.** Closed. 9180 is a routeless
  stub listener.
- **"No Logitech named pipe exists."** That was a false negative. Three exist — two owned by
  `lghub_agent`, one by `lghub_updater`. Never conclude "no pipe" from a name grep; enumerate
  `\\.\pipe\` and resolve owners with `GetNamedPipeServerProcessId`.
