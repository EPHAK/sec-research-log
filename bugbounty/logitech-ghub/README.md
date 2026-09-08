# Logitech G HUB — bug bounty working notes

HackerOne, asset "G Hub / Executable / High / Eligible". Only the latest G HUB version is in
scope — **re-verify the installed version is current before submitting anything.**

Read in this order:

| File | What it is |
|---|---|
| `windows-pending-testing.md` | Session 0 — static analysis of the installer, on Linux. |
| `WHAT-DO-I-DO.md` | Session 0's instructions for the first Windows run. |
| `windows-session-1-results.md` | Session 1 — Windows recon. Killed the privesc-by-ACL thesis; found the Overwolf 45654 origin issue. |
| `FEDORA-SESSION-RESULTS.md` | Session 2 — recovered the SYSTEM updater's IPC protocol and the accept-time security check. Its §2 lead was closed by session 3; its §2 *caveat 1* was resolved by session 4, and the resolution reopened a related lead. |
| `WHAT-DO-I-DO-windows.md` | Session 2's instructions for the second Windows run. Executed; superseded. |
| `windows-session-2-results.md` | Session 3 — identified the real IPC transport (a GUID-named pipe) and closed the TCP 9180 lead. |
| `WHAT-DO-I-DO-fedora.md` | Session 3's instructions for the second Fedora run. Executed; superseded. |
| `pipe-framing.md` | Session 4. Framing, `content_type` table, the pipe-name literal, and the `llc_check` feature flag. Every claim cites an address, and §10 shows how each one was independently re-checked. |
| **`acl-evidence.md`** | **Session 4.** Real ACL evidence, read directly off the target disk, closing the `llc_check` lead. |
| `WHAT-DO-I-DO-windows-3.md` | Session 4's instructions for the third Windows run. Executed; superseded. |
| **`windows-session-3-results.md`** | **Session 5 — the live handshake test. The last open question, answered. ENGAGEMENT CLOSED, no finding.** |

## Current status

**CLOSED — no vulnerability, no report.** Session 5 ran the live test on the target
(non-elevated, PowerShell 5.1, G HUB `2026.5.939708`) and got the predicted result:
**the SYSTEM updater's pipe drops an unsigned, non-elevated peer at the default flag value.**

It drops harder than predicted. Connecting and then reading *without sending anything* gets
clean EOF after 0 bytes, 3/3 runs within ~16ms — **the server closes the connection itself
before the client writes a byte**, exactly as `asyncAccept` says it should. The peer is
refused on inspection; the `HelloRequest` is never read. Details and the trial that
distinguishes this from a race: `windows-session-3-results.md` §3.

The `llc_check` route is confirmed closed from the live system too: the file exists nowhere
in the search path, and an actual non-admin file-creation attempt is denied in all three
directories plus `C:\ProgramData\LGHUB`. `C:\` allows folder-create only — the stock Windows
default, and not a file-write primitive.

Session 5 also found and fixed **four defects in the session scripts**, three of which would
have voided or inverted the result — including an unguarded `$pipe.Write()` that turned the
expected outcome into an uncaught terminating error, discarding a correct finding as a crash.
The recurring root cause, worth remembering: **on PowerShell 5.1 `Write-Host` goes to the
information stream, so `2>&1` captures none of it.**

Everything below is retained as the record of how each route was closed.

**Settled — the handshake test is now one write.** The updater's IPC is a byte-mode named
pipe with a **`uint32` little-endian length prefix + serialized `Envelope`**;
`HelloRequest.content_type` is **`0x1100001`**; `SupportedProtocols` is **`[1]`**; and the
pipe name is a **hardcoded string literal** — `a62ed1c1-e1a9-5495-9038-16bd49ec7341`, the
same on every machine running this build, not derived and not per-install. The blind 0–64
sweep is unnecessary. `windows/hello-probe.ps1` sends the frame and self-tests its own
encoder first.

**Settled — the signature check is not bypassable on its own terms.** The publisher compare
is *exact*, not `strstr`: length check then `memcmp` against `"Logitech Inc"` and
`"Logitech Inc."`. `WinVerifyTrust` runs first and short-circuits. Nothing is reachable
before the check — on failure `asyncAccept` closes the connection without registering it or
starting a read.

**Closed by session 4, with real evidence — mode 0's flag is not attacker-settable here.**
Session 2 flagged "which argument is the mode selector" as an unresolved inference, and
session 3 let that inference carry the conclusion "enforced, no finding". The selector was
resolved: it is **not a compile-time constant**, it is the feature flag **`llc_check`**
(default `1`), read from a plain-text `logi_features.cfg` searched **upward from the
executable's directory, ending at `C:\`**. That reopened the lead.

It is now closed again — this time on evidence read directly off the actual analysed
machine's disk (`acl-evidence.md`), not on an assumption about "the Windows default":
`logi_features.cfg` does not exist anywhere in the search path, and **no non-admin trustee
has `FILE_ADD_FILE` on any of the three search-path directories.** `C:\` grants
`Authenticated Users` `FILE_ADD_SUBDIRECTORY` only — folders, not files; `Program Files` and
`Program Files\LGHUB` grant non-admins nothing but read. Every static-analysis-reachable
route to disabling the accept-time check is closed.

**Confirmed live by session 5**, from the running system as the unprivileged user, by
actually attempting the file creation rather than reading the ACL: denied in all three
directories, and in `C:\ProgramData\LGHUB` as well.

**The last open item — answered by session 5.** Does the pipe actually drop an unsigned peer
at the default flag value? **Yes**, deterministically, and before the client can send a byte.
`windows-session-3-results.md` has the run. The engagement closes with a documented negative
rather than an assumption, which was the point.

## Layout

```
pipe-framing.md            session 4's deliverable: framing, content types, llc_check,
                           and §10 - how every claim in it was independently verified
protos/                    69 .proto files reconstructed from lghub_updater.exe
protos_agent/              same, recovered from lghub_agent.exe
windows/  run-session.ps1     <- RUN THIS. the whole Windows session, one command
          hello-probe.ps1     the handshake test on its own (run-session.ps1 calls it)
          characterise-drop.ps1  session 5: separates "server closed us at accept time"
                              from "we raced the write" - the test that settled it
          find-logi-endpoint.ps1, ipc_probe.py   superseded, kept for the record
tools/    build_hello.py      generates the envelope (source of the known-good hex)
          mock-updater.ps1    fake updater speaking the recovered framing, for testing
                              hello-probe.ps1 off-target
          roundtrip_check.py  parses a generated frame with descriptors pulled out of
                              lghub_updater.exe itself
          Query.java, Wrappers.java   the Ghidra headless scripts used this session
          extract_protos.py, DumpDepot.java, TraceAuth.java
analysis/                  Ghidra output backing FEDORA-SESSION-RESULTS.md §2
evidence/windows-session-2/ raw output backing windows-session-2-results.md
evidence/windows-session-3/ raw output backing windows-session-3-results.md - the full
                           session transcript and the drop characterisation
```

## Tooling notes

- **Both Windows scripts were actually executed before being handed over**, not just written.
  PowerShell 7.4.6 was installed on the Fedora box; `hello-probe.ps1` was driven end to end
  against `tools/mock-updater.ps1` (reply / drop / timeout / no-server / tampered self-test),
  and `run-session.ps1` was run in an environment where nearly every Windows call fails.
  **Four real defects were found that way**, including a write test that reported a false
  `WRITABLE` into its own verdict. See `pipe-framing.md` §10.4. Session 2's experience —
  a script that failed silently and nearly inverted the finding — is why this is now the rule.
- `windows/hello-probe.ps1` **self-tests its protobuf encoder against a known-good frame and
  aborts if it does not match**, before opening the pipe.
- `windows/find-logi-endpoint.ps1` v1 was broken — four defects, all fixed in v2; see
  `windows-session-2-results.md` §5.
- `windows/ipc_probe.py` has never been run and is now superseded — `python` on the Windows
  box is the Microsoft Store alias stub, and its framing guesses are moot now that the
  framing is known.
- `tools/Query.java` / `tools/Wrappers.java` drive Ghidra headless against the existing
  project. Env-var driven: `GH_DEC`, `GH_XREF`, `GH_REFTO`, `GH_STR`, `GH_SYM`, `GH_DIS`,
  `GH_RANGE`, `GH_VTABLE`, `GH_OUTFILE`. `GH_RANGE` decompiles a whole address range, which
  is how the `logi::ipc` and `logi::local_connection` modules were mapped.

## Closed — do not re-chase

Install-dir ACLs *as a DLL-hijack / binary-replacement path*, DLL hijacking, unquoted service
paths, unsigned binaries, updater MITM, `ProgramData\LGHUB` write access, and the depot
path-traversal check (correctly implemented). The Overwolf 45654 origin issue is downgraded —
React escapes the injected data and the affected UI only renders when Overwolf is installed.

Added by session 3:

- **TCP 9180 and the "transport-dependent security check" thesis.** Closed.
- **"No Logitech named pipe exists."** A false negative. Never conclude "no pipe" from a name
  grep; enumerate `\\.\pipe\` and resolve owners with `GetNamedPipeServerProcessId`.

Added by session 4:

- **What 9180 actually is.** `logi::api::http_server(9180, 9189)` — the HTTP half of
  `logi::pipeline::api_server<named_pipes::Server, http_server>`, with no routes registered in
  this binary, which is why every path and every WebSocket upgrade gets a byte-identical 404.
  Not crashpad (that pipe is `\\.\pipe\crashpad_%lu_`, a separate wrapper), not Sentry, not
  dead code. **Do not re-probe it.**
- **Substring publisher compare.** Closed — the compare is exact against two literals.
- **"A PoC must enumerate the pipe and resolve owners, never hard-code the GUID"** (session 3
  §1). Wrong. The GUID is a literal in `.rdata`; hard-coding it is correct.
- **`CreateNamedPipeW`-only searches.** The IPC pipe is created through **`CreateNamedPipeA`**.
  Search both.
