# WHAT DO I DO — Logitech G HUB, Windows session #3

Paste this into a fresh assistant session on the Windows box, together with `pipe-framing.md`.

Fedora session #4 answered every open question that static analysis can answer. Two results
changed the picture:

- The pipe framing and `content_type` are now known exactly, so **the handshake test is one
  write, not a 0–64 sweep.**
- **Mode 0 is reachable in shipped builds.** The accept-time signature check is gated on a
  feature flag (`llc_check`, default on) read from a text file whose search path ends at
  `C:\`. Whether that is *exploitable* comes down to three directory ACLs — which only this
  box can answer.

---

## Just run this

```powershell
cd <repo>\bugbounty\logitech-ghub\windows
powershell -ExecutionPolicy Bypass -File .\run-session.ps1
```

**Non-elevated, as an ordinary user.** That is the threat model; the script says so loudly
and flags the run as invalid if you are elevated.

`run-session.ps1` does the whole session and writes a transcript to
`%USERPROFILE%\Desktop\logi-session4\transcript.txt`:

| | |
|---|---|
| **A** | context — user, elevation, PowerShell version, G HUB build, running processes |
| **B** | confirm the updater's pipe exists and this process can open it |
| **C** | **the handshake test** — one `HelloRequest` to the SYSTEM updater (runs `hello-probe.ps1`, self-test first) |
| **D** | does `logi_features.cfg` already exist anywhere in the search path? if so, print it |
| **E** | `icacls` on the three directories in that search path |
| **F** | **empirical write test** — can a non-admin create a *file* (not just a folder) there? |
| **G** | `C:\ProgramData\LGHUB` feature-cache check |

Then it prints a **VERDICT** block telling you what the combination means.

### What it will not do

It never writes `logi_features.cfg`. It never sends an installer, pipeline or launchable
command. Step F uses a scratch filename (`zz_logi_write_probe.tmp`) and deletes it, so
nothing about the service changes either way. The one step that *would* modify the system is
gated behind an explicit decision — see "If F says writable" below.

### It has been tested

Not just written. PowerShell 7.4.6 was installed on the Fedora box and both scripts were run:
`hello-probe.ps1` end to end against a mock server speaking the recovered framing (reply,
drop, timeout, no-server, and a deliberately-corrupted self-test that must abort without
opening the pipe), and `run-session.ps1` against a hostile environment where nearly every
Windows call fails. Four real defects were found and fixed that way, including a write test
that **reported a false WRITABLE into the verdict**. See `pipe-framing.md` §10.4.

Caveat: those runs were PowerShell **7** on Linux. This box may be Windows PowerShell **5.1**.
Both scripts parse clean and avoid 7-only syntax, and section C runs `hello-probe.ps1
-SelfTestOnly` first — which exercises the whole protobuf encoder on whatever PowerShell you
actually have, in seconds, without touching the pipe. If that passes, the encoder is right.

---

## Reading the result

### C says `DROPPED` (this is what static analysis predicts)

The accept-time signature check is enforced at the default flag value. That is not a wasted
step: it is the evidence that settles question 6 of the gate in the negative, which no amount
of further code reading can do. Move to F.

### C says `REPLIED`

A SYSTEM service completed a handshake with an unsigned, non-elevated peer. **Stop there.**
That is the report on its own. Do not send `RunLaunchableByAliasRequest` or anything else —
executing something as SYSTEM adds nothing to the report and a great deal to the blast
radius. Check section D: if it replied, `llc_check` is probably already `0` on this machine
and D should show why.

### F says all three directories deny file creation

`llc_check` is not attacker-settable here. The lead closes honestly, with evidence. Say so
plainly and write it up as *no finding*. That is the expected outcome — see the ACL note
below.

### F says some directory allows a non-admin to create a *file*

The lead is live. The next step modifies a SYSTEM service's configuration and needs a reboot
to take effect, so **ask the operator before doing it.** If it goes ahead:

1. `Set-Content <thatdir>\logi_features.cfg 'llc_check = 0'`
2. reboot — a non-admin cannot restart `LGHUBUpdaterService`, and "survives a reboot" is the
   honest way to state the attack anyway
3. re-run `run-session.ps1` non-elevated
4. a reply now demonstrates the full chain: unprivileged file write → the SYSTEM IPC accepts
   an arbitrary peer → `RunLaunchableByAliasRequest` is SYSTEM code execution
5. **delete the file** and confirm the probe returns to `DROPPED`

### The ACL note that decides this

The Windows default on `C:\` grants `Authenticated Users:(AD)` — **create folders** — but not
`WD` — **create files**. So `create folder: yes / create file: denied` is the expected stock
result and means **not exploitable**. Section F tests both separately for exactly this reason.
Do not report a folder-create as a file-write primitive.

---

## Background, if you need it

The chain, with addresses in `pipe-framing.md` §6:

```
logi_features.cfg["llc_check"]   default 1
  -> ConnectionConfig+0x34
  -> FUN_140c243e0 arg1
       1 -> resolve peer PID from the kernel, WinVerifyTrust vs "Logitech Inc"
       0 -> return 1        // accept every peer, no check at all
```

Search order (walking **up** from the executable's directory, first match wins):

```
1.  C:\Program Files\LGHUB\logi_features.cfg
2.  C:\Program Files\logi_features.cfg
3.  C:\logi_features.cfg
```

File format — one flag per line, matched against
`([a-z0-9]+[a-z0-9 ._]*[a-z0-9]+)\s*=\s*(0|1|false|true|off|on|yes|no)\s*`.

## Already answered — do not re-derive

- **Framing.** `uint32` little-endian length prefix + serialized `Envelope`. Byte-mode pipe
  (`dwPipeMode = 0x8`), not message mode.
- **`HelloRequest.content_type` = `0x1100001`.** `HelloResponse` = `0x1400001`.
- **`SupportedProtocols = [1]`, `Language = "en-US"`.**
- **The pipe GUID is a hardcoded literal** `a62ed1c1-e1a9-5495-9038-16bd49ec7341`
  (`FUN_140e04ef0`), and `lghub_agent.exe` carries the identical literal. Hard-code it. If a
  future build stops answering, re-read that one function.
- **The publisher compare is exact**, not `strstr`: `cmp rbx,0xc` then `memcmp` 12, else
  `cmp rbx,13` then `memcmp` 13. A `Logitech Incorporated Evil Ltd` certificate would not
  pass. `WinVerifyTrust` runs first and short-circuits. Closed.
- **Nothing is reachable before the check.** On failure `asyncAccept` calls the connection's
  close slot and never registers the connection or starts a read.
- **9180 is `logi::api::http_server(9180, 9189)`** — the HTTP half of
  `api_server<named_pipes::Server, http_server>`, with no routes registered in this binary.
  Not crashpad, not Sentry, not dead code. That is why every path returns a constant 404.
  **Do not re-probe it.**

## One loose end from the Fedora side

`GetFeatureFlag`'s map was traced to exactly one populate path (`logi_features.cfg`, loaded in
`FUN_14002a8a0`). The binary also contains a `FeatureCanary` subsystem with its own
`get_flag`, a `features_cache.json`, and a downloadable features config depot. **I did not
prove FeatureCanary never writes into the same map.** If it does, and its cache is writable,
that is a second route to `llc_check = 0`. Section G collects the evidence; session 2
recorded `C:\ProgramData\LGHUB` as `Everyone:(RX)`, so this is probably another closed door —
confirm rather than assume.

## Reporting rules — unchanged

- 7-question gate. Question 6 (working PoC) is the one that decides this.
- No theoretical bugs. "`C:\` is *usually* writable" is not evidence; `icacls` output plus a
  successful file creation from a non-admin shell is.
- Check the Logitech program's own Hacktivity tab before submitting, not global H1 search.
- Distinguish explicitly from the 2018 Ormandy / Logitech Options bug: different product,
  transport, protocol and impact.
- Local-only. `PIPE_REJECT_REMOTE_CLIENTS` is set on the pipe. The attacker already has code
  execution as a normal user; the gain is SYSTEM. Do not claim browser reachability.
