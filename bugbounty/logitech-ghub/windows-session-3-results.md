# Session 5 — third Windows run. The live handshake test.

Executed 2026-09-08 on the target machine, **non-elevated**, as `EPHAK\swaga`, under
**Windows PowerShell 5.1.26100.9278 (Desktop)** on Windows 11 26200.

This session existed to answer the one question static analysis could not:
**does the SYSTEM updater's pipe actually drop an unsigned, non-elevated peer at the default
`llc_check` value?**

**It does. Deterministically, and earlier in the sequence than predicted.** The engagement
closes with a documented negative.

## 1. Environment

G HUB build installed — **`2026.5.939708`** (`lghub_updater.exe`, `lghub_agent.exe`,
`lghub_sso_handler.exe`; `lghub_software_manager.exe` 2026.5.9708, `lghub_gl.exe`
2.4.17.922017). Running: `lghub_agent` (16436), `lghub_updater` (6260), `lghub_system_tray`
(15944), `logi_lamparray_service.AMD64` (6168).

Scope is latest-version-only. Nothing is being submitted, so version currency is moot here —
but if that changes, re-verify before filing.

## 2. The pipe is there and a non-admin can open it

```
\\.\pipe\a62ed1c1-e1a9-5495-9038-16bd49ec7341     FOUND  (157-161 pipes visible)
opened from a non-elevated process                 OK
```

The hardcoded GUID from `FUN_140e04ef0` is correct on this build — session 4's call to
hard-code it rather than enumerate was right. The DACL admits an ordinary user, matching the
`Everyone:0x1FFFFF` descriptor read out of the binary. **Opening the pipe is not the boundary.**

## 3. The handshake — DROPPED

The encoder self-test passed on PowerShell 5.1, byte for byte against the frame generated on
Fedora, so the PS5.1-vs-PS7 caveat is closed:

```
self-test expected : 1500000008011802208180c0082a0a1205656e2d55531a0101
self-test produced : 1500000008011802208180c0082a0a1205656e2d55531a0101
```

The real probe connects and is then torn down. `RESULT: DROPPED`.

### 3.1 Characterised properly, not inferred from one exception

The first run died with `Pipe is broken` on `Write`. That alone is weak evidence — it could
be a race, or our own bug. `windows/characterise-drop.ps1` (checked in) separates the cases;
raw output in `evidence/windows-session-3/drop-characterisation.txt`:

**Trial A — connect, then write (5 runs).** Inconsistent, and therefore uninformative on its
own: run 1 failed with `Pipe is broken` after 8ms, runs 2-5 "succeeded". A successful `Write`
here means nothing — the bytes land in the local pipe buffer of a handle the server has
already abandoned.

**Trial B — connect, write *nothing*, and see who closes first (3 runs).** This is the
decisive test:

```
run 1: connect=0ms -> read returned 0 bytes after 16ms   (0 = SERVER CLOSED US)
run 2: connect=0ms -> read returned 0 bytes after  0ms   (0 = SERVER CLOSED US)
run 3: connect=0ms -> read returned 0 bytes after  0ms   (0 = SERVER CLOSED US)
```

**The server closes the connection itself, returning clean EOF, before the client sends a
single byte.** Three for three, within ~16ms.

This matches `asyncAccept` exactly: on signature-check failure it calls the connection's
close slot and never registers the connection or starts a read. The peer is refused **on
inspection**, not on the content of its handshake — the `HelloRequest` is never even read.
The accept-time check is enforced at the default flag value.

### 3.2 What this test does and does not prove

It proves an unprivileged, unsigned local peer cannot complete — cannot even begin — the
updater IPC handshake. That is the claim that mattered.

It does not, by itself, prove the close is caused by the *signature* check specifically; a
live test cannot distinguish that from, say, a server that admits only one client. The
attribution rests on session 4's static analysis (`pipe-framing.md` §6), and the two agree.
Either way the conclusion for the engagement is identical: **no unprivileged path through
this IPC.**

## 4. `llc_check` — confirmed not attacker-settable, live

Confirms `acl-evidence.md`, which was read off the disk from Fedora. Now from the running
system, as the actual unprivileged user:

**The file does not exist** anywhere in the search path:

```
absent : C:\Program Files\LGHUB\logi_features.cfg
absent : C:\Program Files\logi_features.cfg
absent : C:\logi_features.cfg
```

**No non-admin can create one.** Empirical, not read off an ACL — create a real file, confirm
it exists, delete it:

| Directory | create FILE | create FOLDER |
|---|---|---|
| `C:\Program Files\LGHUB\` | **denied** | denied |
| `C:\Program Files\` | **denied** | denied |
| `C:\` | **denied** | yes |
| `C:\ProgramData\LGHUB` | **denied** | — |

`C:\` is the textbook stock result the handoff warned about: `Authenticated Users:(AD)` —
create folders — with no `WD`. **A folder-create is not a file-write primitive and is not
reportable.** `icacls` agrees: `Program Files` and `Program Files\LGHUB` give `BUILTIN\Users`
only `(RX)`/`(GR,GE)`; `C:\ProgramData\LGHUB` gives `Everyone:(RX)` and nothing more,
confirming session 2's reading and closing the FeatureCanary cache route from the live side
too.

The only `*.cfg` files under `ProgramData\LGHUB` are two game-integration files in depot
directories (`gamestate_integration_logitech.cfg`, CSGO and Dota 2) — unrelated to
`logi_features.cfg`, and not writable by us.

## 5. Four defects found in the session scripts, all fixed

Three of them would have inverted or silently voided the finding. The pattern is the one that
already cost session 2, and it is worth stating as a rule: **on PowerShell 5.1 `Write-Host`
goes to the information stream (6), so `2>&1` captures none of it.**

1. **`hello-probe.ps1` — unguarded `$pipe.Write()` under `$ErrorActionPreference='Stop'`.**
   The broken pipe — *the expected outcome* — was a terminating error. The script died before
   printing any verdict, and the exception escaped the caller's redirect entirely. **This is
   the important one:** a conclusive, correct result was being thrown away as a crash. Now
   caught and reported as `DROPPED`, with the accept-time reasoning spelled out.
2. **`run-session.ps1` — `$out = & $probe ... 2>&1`.** Could never work: the probe reports via
   `Write-Host`. `$out` only ever held stray error records, so every `-match` test failed and
   the VERDICT block printed `(nothing recorded)` after a perfectly good run. Now `*>&1`.
3. **`run-session.ps1` — `icacls` with a trailing backslash.** PowerShell quotes native
   arguments, and the trailing `\` escaped the closing quote, so `icacls` received
   `C:\Program Files\LGHUB"` and failed — on the two directories that matter most. Silently,
   into a step-failed line. Now trimmed (keeping `C:\` a root).
4. **`run-session.ps1` — no branch for a probe that dies on write.** Added, so this can never
   again produce a blank verdict after a decisive run.

Post-fix the script runs end to end and prints
`Handshake DROPPED - accept-time signature check is enforced (expected)`.

## 6. Verdict — no finding, and the engagement closes

```
Handshake DROPPED  +  all three search-path directories deny file creation
```

Per the decision table in the handoff, that is the closing condition. Every route to
disabling the updater IPC's accept-time signature check is now closed **with evidence**:

- the check is **enforced live**, at the default flag value, verified against the running
  SYSTEM service (§3);
- the flag file **does not exist** and **cannot be created** by an unprivileged account, on
  the real machine, tested by actually trying (§4);
- the publisher compare is **exact**, not `strstr` (session 4);
- `FeatureCanary` **cannot** reach the same flag map (session 4 addendum), and its cache
  directory is not writable anyway (§4);
- TCP 9180 is a **routeless HTTP server** (session 4).

**No report is filed.** There is nothing here to report: the boundary this engagement set out
to test holds. This is a negative result backed by evidence rather than assumption, which was
the point of running it.

Do **not** re-chase any of the above. If a future build is revisited, the two things worth
re-reading are the pipe-name literal in `FUN_140e04ef0` and whether `asyncAccept` still
closes before registering the connection.

## 7. Evidence

```
evidence/windows-session-3/transcript.txt              full run-session.ps1 transcript
evidence/windows-session-3/drop-characterisation.txt   trials A and B, plus the two ACLs
evidence/windows-session-3/icacls_C__.txt              C:\ ACL as saved by the script
windows/characterise-drop.ps1                          the tool that settled §3.1
```
