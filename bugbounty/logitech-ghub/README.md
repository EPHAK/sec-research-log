# Logitech G HUB — bug bounty working notes

HackerOne, asset "G Hub / Executable / High / Eligible". Only the latest G HUB version is in
scope — **re-verify the installed version is current before submitting anything.**

Read in this order:

| File | What it is |
|---|---|
| `windows-pending-testing.md` | Session 0 — static analysis of the installer, on Linux. |
| `WHAT-DO-I-DO.md` | Session 0's instructions for the first Windows run. |
| `windows-session-1-results.md` | Session 1 — Windows recon. Killed the privesc-by-ACL thesis; found the Overwolf 45654 origin issue. |
| **`FEDORA-SESSION-RESULTS.md`** | **Session 2 — current state.** Recovered the SYSTEM updater's full IPC protocol and found the accept-time security check. |
| **`WHAT-DO-I-DO-windows.md`** | **Do this next**, on Windows, as a normal user. |

## Current status

**One open lead, not yet a finding.** `lghub_updater.exe` runs as SYSTEM and exposes an IPC
protocol that can run executables (`RunLaunchableByAliasRequest`) and repoint the update server
(`SetChannelRequest`). Static analysis indicates the accept-time client check is
transport-dependent and returns "allow" unconditionally on the non-named-pipe path — and the
updater's listener on 127.0.0.1:9180 is TCP.

If an unsigned, non-elevated process can complete the handshake, that is local privilege
escalation to SYSTEM. **This has not been tested even once.** Question 6 of the gate (working PoC)
is unmet. `WHAT-DO-I-DO-windows.md` is the test.

## Layout

```
protos/        69 .proto files reconstructed from lghub_updater.exe  <- the IPC protocol
protos_agent/  same, recovered from lghub_agent.exe
windows/       find-logi-endpoint.ps1, ipc_probe.py  <- run these on Windows
tools/         extract_protos.py, DumpDepot.java, TraceAuth.java
analysis/      Ghidra output backing the claims in FEDORA-SESSION-RESULTS.md §2
```

## Closed — do not re-chase

Install-dir ACLs, DLL hijacking, unquoted service paths, unsigned binaries, updater MITM,
`ProgramData\LGHUB` write access, and the depot path-traversal check (correctly implemented).
The Overwolf 45654 origin issue is downgraded — React escapes the injected data and the affected
UI only renders when Overwolf is actually installed.
