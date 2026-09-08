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
| **`pipe-framing.md`** | **Session 4 — current state.** Framing, `content_type` table, the pipe-name literal, and the `llc_check` feature flag. Every claim cites an address. |
| **`WHAT-DO-I-DO-windows-3.md`** | **Do this next**, on Windows. It is one command: `windows\run-session.ps1`. |

## Current status

Two things are settled and one is open.

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

**Open — mode 0 is reachable in shipped builds.** Session 2 flagged "which argument is the
mode selector" as an unresolved inference, and session 3 let that inference carry the
conclusion "enforced, no finding". Resolved: the selector is **not a compile-time constant**.
It is the feature flag **`llc_check`** (default `1`), read at startup from a plain-text file
`logi_features.cfg` that is searched **upward from the executable's directory, ending at
`C:\`**. With `llc_check = 0`, `FUN_140c243e0` returns 1 unconditionally and the SYSTEM
updater accepts every peer on a pipe whose DACL is `Everyone: 0x1FFFFF` by design.

Whether that is a *finding* now depends on one thing this box cannot answer: whether an
unprivileged user can create a file in `C:\Program Files\LGHUB\`, `C:\Program Files\`, or
`C:\`. On a stock Windows the answer is no — the default `C:\` DACL grants
`Authenticated Users:(AD)` (create *folders*), not `WD` (create *files*). **Do not report
this until `icacls` and an actual write attempt from a non-admin shell say otherwise.**
See `WHAT-DO-I-DO-windows-3.md` §2.

## Layout

```
pipe-framing.md            session 4's deliverable: framing, content types, llc_check,
                           and §10 - how every claim in it was independently verified
protos/                    69 .proto files reconstructed from lghub_updater.exe
protos_agent/              same, recovered from lghub_agent.exe
windows/  run-session.ps1     <- RUN THIS. the whole Windows session, one command
          hello-probe.ps1     the handshake test on its own (run-session.ps1 calls it)
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
