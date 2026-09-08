# WHAT DO I DO — Logitech G HUB, Windows session #3

Paste this into a fresh assistant session on the Windows box, together with
`pipe-framing.md`. Read `pipe-framing.md` first — it has the bytes and the addresses.

Fedora session #3 answered all four tasks. Two of them changed the picture:

- The pipe framing and `content_type` are now known exactly, so **the handshake test is one
  write, not a 0–64 sweep.** `windows/hello-probe.ps1` does it.
- **Mode 0 is reachable in shipped builds.** The security check is gated on a feature flag
  (`llc_check`, default on) read from a text file whose search path ends at `C:\`. Whether
  that is *exploitable* comes down to three directory ACLs — which only this box can answer.

---

## Step 1 — the handshake test (5 minutes, do this first)

```powershell
cd <repo>\bugbounty\logitech-ghub\windows
powershell -ExecutionPolicy Bypass -File .\hello-probe.ps1 -SelfTestOnly   # sanity check, no pipe
powershell -ExecutionPolicy Bypass -File .\hello-probe.ps1                 # the real test
```

Run it **non-elevated**, as an ordinary user. It writes one `HelloRequest` envelope and
nothing else — no installer, pipeline or launchable command.

The script self-tests its own protobuf encoder against a known-good frame before it touches
the pipe, and aborts loudly if it does not match. (Session 2's script failed silently and
nearly inverted the conclusion. If this one fails, it says so.)

**It has actually been run**, not just written. PowerShell 7.4.6 was installed on the Fedora
box and the script was exercised end to end against a mock server that speaks the recovered
framing (`mock-updater.ps1`, checked in): reply path, drop path, timeout path, no-server
path, and a deliberately-corrupted self-test that must abort without opening the pipe. Two
real defects were found and fixed that way — `WindowsIdentity::GetCurrent()` throwing, and
`PipeStream.ReadTimeout` being unsupported — either of which would have killed the run on
your box. See `pipe-framing.md` §10.4.

Those tests ran on PowerShell **7** on Linux. Your box may be Windows PowerShell **5.1**.
The script parses clean and avoids 7-only syntax, but run `-SelfTestOnly` first anyway — it
exercises the whole encoder on whatever PowerShell you actually have, in seconds, without
touching the pipe. If the self-test passes there, the encoder is right.

**Interpreting it:**

| Result | Meaning | Next |
|---|---|---|
| `DROPPED` | The accept-time signature check is enforced with `llc_check` at its default. Expected. | Go to step 2 |
| Reply, `in_response_to_id = 1` | A SYSTEM service completed a handshake with an unsigned, non-elevated peer. | **Stop. That is the report.** Do not send further commands; the handshake is proof enough |
| `CONNECT FAILED / access denied` | Contradicts the `Everyone:0x1FFFFF` descriptor read out of the binary. Record it — the DACL would then be the boundary and the whole thesis changes | Record and report back |

`DROPPED` is what static analysis predicts. Getting it is not a wasted step: it is the
evidence that closes question 6 of the gate in the negative, which is the thing three
sessions of reading code cannot do.

---

## Step 2 — the `llc_check` question (this is the live lead)

`pipe-framing.md` §6 has the full chain with addresses. Short version:

```
logi_features.cfg["llc_check"]   default 1
  -> ConnectionConfig+0x34
  -> FUN_140c243e0 arg1
       1 -> resolve peer PID from kernel, WinVerifyTrust vs "Logitech Inc"
       0 -> return 1        // accept every peer, no check at all
```

The file is found by walking **up** from the executable's directory:

```
1.  C:\Program Files\LGHUB\logi_features.cfg
2.  C:\Program Files\logi_features.cfg
3.  C:\logi_features.cfg
```

first match wins, and the format is one line:

```
llc_check = 0
```

### 2a. Does the file already exist? (read-only)

```powershell
'C:\Program Files\LGHUB\logi_features.cfg','C:\Program Files\logi_features.cfg','C:\logi_features.cfg' |
  ForEach-Object { [pscustomobject]@{ Path=$_; Exists=(Test-Path $_) } } | Format-Table -Auto
Get-Content 'C:\logi_features.cfg' -ErrorAction SilentlyContinue
```

If one exists and already contains `llc_check`, read it — that alone is interesting.

### 2b. The ACLs — this is the whole question (read-only)

```powershell
icacls C:\
icacls "C:\Program Files"
icacls "C:\Program Files\LGHUB"
```

What matters is whether `Users`, `Authenticated Users`, `INTERACTIVE` or your own account has
**`(W)`, `(M)`, `(F)` or the specific `WD` (create files / write data)** on any of the three.

**Be precise about `AD` vs `WD`.** The Windows default on `C:\` grants
`Authenticated Users:(AD)` — that is *create folders*, `FILE_ADD_SUBDIRECTORY`. Creating a
**file** needs `WD` / `FILE_ADD_FILE`, which the default `C:\` DACL does **not** grant to
non-admins. So on a stock, unmodified Windows this is **not** exploitable, and saying
otherwise would be exactly the "theoretical bug" the gate exists to stop.

Sessions 0–1 already reported the install-dir ACLs as clean. That was recorded when it looked
like a dead end; it is load-bearing now, so re-run it rather than trusting the note.

### 2c. Empirical write test (creates and deletes one file)

ACL output is easy to misread. Test it directly, with a name that is **not** the real one so
nothing changes behaviour:

```powershell
foreach ($d in 'C:\','C:\Program Files\','C:\Program Files\LGHUB\') {
  $p = Join-Path $d 'zz_write_probe.tmp'
  try   { Set-Content -Path $p -Value 'probe' -ErrorAction Stop
          Write-Host "WRITABLE: $d" -ForegroundColor Red
          Remove-Item $p -Force }
  catch { Write-Host "denied:   $d  ($($_.Exception.GetType().Name))" }
}
```

- **All three denied** → `llc_check` is not attacker-settable on this machine. The lead is
  closed honestly, with evidence, and the engagement ends. Say so plainly.
- **Any one writable by a non-admin** → the lead is live and step 3 applies.

### 2d. Only if 2c says writable — and only with the operator's explicit say-so

Placing a real `logi_features.cfg` changes the configuration of a SYSTEM service and needs a
service restart or reboot to take effect. That is a system modification, not a read-only
probe. **Ask before doing it.** If it goes ahead:

1. `Set-Content 'C:\logi_features.cfg' 'llc_check = 0'` (or whichever directory 2c found)
2. reboot (a non-admin cannot restart `LGHUBUpdaterService`; a reboot is the realistic path,
   and "survives a reboot" is the honest way to state the attack anyway)
3. re-run `hello-probe.ps1` non-elevated
4. a reply now = the full chain demonstrated: unprivileged file write → SYSTEM IPC accepts
   an arbitrary peer → `RunLaunchableByAliasRequest` is SYSTEM code execution
5. **remove the file afterwards** and confirm the probe goes back to DROPPED

Do not run `RunLaunchableByAliasRequest` or any other installer/pipeline command. The
completed handshake is the finding; executing something as SYSTEM adds nothing to the report
and a lot to the blast radius.

---

## Step 3 — one loose end from the Fedora side

I traced `GetFeatureFlag`'s map to exactly one populate path: `logi_features.cfg`, loaded at
startup in `FUN_14002a8a0`. The binary also contains a `FeatureCanary` subsystem
(`feature_canary.cpp`, `features_cache.json`, `features.json`, a downloadable "features config
depot") with its own `FeatureCanary::get_flag`. **I did not prove that FeatureCanary never
writes into the same map.** If it does, and if its cache lives somewhere writable, that is a
second route to `llc_check = 0`.

Cheap check on your side:

```powershell
Get-ChildItem C:\ProgramData\LGHUB -Recurse -Include features*.json,*.cfg -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
icacls C:\ProgramData\LGHUB
```

Session 2 recorded `C:\ProgramData\LGHUB` as `Everyone:(RX)` — not writable — so this is
probably another closed door. Confirm rather than assume.

---

## Already answered — do not re-derive

- **Framing.** `uint32` little-endian length prefix + serialized `Envelope`. Byte-mode pipe
  (`dwPipeMode = 0x8`), not message mode.
- **`HelloRequest.content_type` = `0x1100001`.** `HelloResponse` = `0x1400001`.
- **`SupportedProtocols = [1]`, `Language = "en-US"`.**
- **The pipe GUID is a hardcoded literal** `a62ed1c1-e1a9-5495-9038-16bd49ec7341`
  (`FUN_140e04ef0`). Hard-code it; no enumeration needed. If a future build stops answering,
  re-read that one function.
- **The publisher compare is exact**, not `strstr`: length check then `memcmp` against
  `"Logitech Inc"` and `"Logitech Inc."`. A `Logitech Incorporated Evil Ltd` certificate
  would not pass. `WinVerifyTrust` runs first and short-circuits. Closed.
- **Nothing is reachable before the check.** On failure `asyncAccept` calls the connection's
  close slot and never registers the connection or starts a read.
- **9180 is `logi::api::http_server(9180, 9189)`** — the HTTP half of
  `api_server<named_pipes::Server, http_server>`, with no routes registered in this binary.
  Not crashpad, not Sentry, not dead code. That is why every path returns a constant 404.
  **Do not re-probe it.**

## Reporting rules — unchanged

- 7-question gate. Question 6 (working PoC) is still the one that decides this.
- No theoretical bugs. "`C:\` is *usually* writable" is not evidence; `icacls` output and a
  successful write from a non-admin shell is.
- Check the Logitech program's own Hacktivity tab before submitting.
- Distinguish explicitly from the 2018 Ormandy / Logitech Options bug: different product,
  transport, protocol and impact.
- Local-only. `PIPE_REJECT_REMOTE_CLIENTS` is set on the pipe. Attacker already has code
  execution as a normal user; the gain is SYSTEM. Do not claim browser reachability.
