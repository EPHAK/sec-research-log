# Logitech G HUB — Windows session results → continue on Fedora

**Session date:** 2026-09-08 (Windows box `EPHAK`, user `swaga`, non-elevated)
**Target:** Logitech G HUB — H1 asset "G Hub / Executable / High / **Eligible** / only latest version in scope"
**Installed version tested:** G HUB **39.1.2**, updater package version **2026.5.939708**
**All binaries:** validly Authenticode-signed, `CN=Logitech Inc, O=Logitech Inc, L=Newark, S=California, C=US`
**Everything below was read-only.** Nothing was installed, stopped, modified, or reconfigured.

> Scope note: G HUB is explicitly bounty-eligible ("Only the latest version of GHub is in scope").
> **Confirm 39.1.2 is still latest before submitting** — if a newer build shipped, re-verify there first.

---

## 0. TL;DR

One live, reproducible finding; the entire local-privesc thesis from the previous handoff is **dead** and should not be re-chased.

| | |
|---|---|
| **LIVE** | `lghub_agent` listens on `127.0.0.1:45654` (Overwolf integration endpoint) and performs **no `Origin` validation**, while its sibling endpoint on `127.0.0.1:9010` in the **same process** correctly returns `403 unable to connect from remote origin`. |
| **DEAD** | DLL hijack / binary planting / unquoted service path / weak service ACL / unsigned binaries — all checked, all clean. |
| **OPEN** | (a) is port 45654 deterministic? (b) can a real browser reach it (mixed-content + Chrome PNA)? (c) symlink race on user-writable elevated log dirs. |

---

## 1. Machine state / topology (established facts)

### Processes
| PID | Process | Runs as |
|---|---|---|
| 16748 | `lghub_agent.exe` | `EPHAK\swaga` (**logged-in user**) |
| 16568 | `lghub_system_tray.exe` | `EPHAK\swaga` |
| 6408 | `lghub_updater.exe` | **SYSTEM** (owner unreadable from low-priv = confirms SYSTEM) |
| 6416 | `logi_lamparray_service.AMD64.exe` | **SYSTEM** |

### Services
```
Name        : LGHUBUpdaterService
State       : Running    StartMode : Auto    StartName : LocalSystem
PathName    : "C:\Program Files\LGHUB\lghub_updater.exe" --run-as-service     <-- quoted, fine

Name        : logi_lamparray_service
State       : Running    StartMode : Auto    StartName : LocalSystem
PathName    : C:\Windows\System32\DriverStore\FileRepository\logi_lamparray_usb.inf_amd64_.../logi_lamparray_service.AMD64.exe
```

### Localhost listeners (the whole local attack surface)
```
127.0.0.1:9010     lghub_agent (PID 16748)            websocketpp 0.8.2  -- ORIGIN ENFORCED
127.0.0.1:45654    lghub_agent (PID 16748)            websocketpp 0.8.2  -- NO ORIGIN CHECK  <== FINDING
127.0.0.1:9180     lghub_updater (PID 6408, SYSTEM)   plain HTTP/1.0, 404 to everything tried
```
All three bind **127.0.0.1 only** — not remotely reachable. Confirmed via `Get-NetTCPConnection`.

### Named pipes
Only one Logitech pipe exists: `\\.\pipe\logi.trueforce.connect`
- ACL: `Everyone : 2032127 (FULL CONTROL)`
- **Owner: `EPHAK\swaga`** → hosted by a *user-level* process (Trueforce wheel SDK, `C:\Program Files\Logi\Trueforce`).
- **No privilege boundary is crossed** → not privesc on a single-user box. Only interesting on a multi-user host (another low-priv user could hijack it). Left as a low-priority note, not a finding.

---

## 2. THE LIVE FINDING — cross-site WebSocket hijacking of the Overwolf integration endpoint

### 2.1 What it is
`lghub_agent.exe` runs **two** WebSocket servers. One validates `Origin`; the other does not.

Evidence matrix (raw handshakes, captured in `ghub-recon/FINDING_origin_matrix.txt`):

```
Origin                    Port 9010                                          Port 45654
------                    ---------                                          ----------
(none)                    HTTP/1.1 400 Bad Request                           HTTP/1.1 101 Switching Protocols
https://evil.example      HTTP/1.1 403 unable to connect from remote origin  HTTP/1.1 101 Switching Protocols
http://attacker.test      HTTP/1.1 403 unable to connect from remote origin  HTTP/1.1 101 Switching Protocols
null                      HTTP/1.1 403 unable to connect from remote origin  HTTP/1.1 101 Switching Protocols
https://www.google.com    HTTP/1.1 403 unable to connect from remote origin  HTTP/1.1 101 Switching Protocols
file://                   HTTP/1.1 400 Bad Request                           HTTP/1.1 101 Switching Protocols
```

**Same process. Same library (websocketpp 0.8.2). Opposite behaviour.**
That is the whole report in one table: Logitech demonstrably treats `Origin` as a security boundary here
(9010 rejects it with a purpose-written message) and simply did not apply it to the 45654 listener.

### 2.2 What 45654 is
It is the **Overwolf integration endpoint**. From `lghub_agent.exe` strings:
```
logi::overwolf::overwolf_endpoint_impl::on_websocket_message
logi::overwolf::overwolf_endpoint_impl::on_websocket_connection_open
logi::overwolf::overwolf_endpoint_impl::on_websocket_connection_close
C:\builds\kragle\lego\logi\provider\overwolf\src\overwolf_endpoint_impl.cpp
"Overwolf Endpoint WebSocket"
"Overwolf server now listening on port %d..."
"Overwolf listening failed, retrying on port %d..."
```
Command vocabulary recovered from the same string region:
```
get-extensions   install-extension   update-commands-list
capture          screenshot          show-replay
start-streaming  stop-streaming      toggle-streaming
turn-on          turn-off
```
Error strings (useful as a protocol oracle):
```
"Invalid argument within json. Check your json."  "Invalid integration"  "Empty parameters"
"Invalid command"  "Invalid app"  "Invalid invocation"  "Invalid extension id"
"Overwolf connection not established"
```

### 2.3 Reproduction (verified, repeatable)
Connect a WebSocket to `ws://127.0.0.1:45654/` with **any** `Origin` header. It upgrades, and the
server **immediately pushes a command to the client unprompted**:
```
<- {"command":"get-extensions","extensionId":"overwolf","id":"0"}
```
Verified with `Origin: https://evil.example`. Sending a malformed reply causes the server to drop
the connection (matches the `Invalid argument within json` path).

**Overwolf is NOT installed on this machine** — yet the endpoint listens and actively solicits.
So this surface is present on **every** G HUB install, not just Overwolf users. That materially
widens the affected population and is worth stating in the report.

### 2.4 Honest impact assessment (do not overclaim)
**Proven:** any origin can open the socket, impersonate the Overwolf integration, receive commands
G HUB issues, and feed a crafted extension list back into the G HUB UI. Also denies the socket to
the legitimate Overwolf client (feature DoS).

**Explicitly NOT proven — do not claim these:**
- No keystroke injection demonstrated (this is *not* a re-run of the 2018 Options bug).
- No code execution demonstrated.
- No privilege escalation — `lghub_agent` runs as the logged-in user, so a same-user local
  process crossing this boundary gains nothing.
- **XSS→RCE is closed off**: `app.asar` sets `nodeIntegration:!1` and `contextIsolation:!0`,
  and the UI is React (auto-escaping). So injecting HTML in an extension name will not pop.

Realistic severity: **low-to-medium**, carried mainly by the "you fixed 9010 and missed 45654"
argument. Strengthen it or drop it based on §2.5.

### 2.5 The two questions that decide whether this is worth submitting
**(a) Is port 45654 deterministic?**
Not resolved. Not stored in `settings.db`, not in the registry, not a hardcoded `mov reg,imm32`
in the binary (searched for immediate `0xB256`; only two data-region hits at offsets 29457819 /
29457829). The `"retrying on port %d"` string implies base-port + increment on bind failure.
- **Test:** restart `lghub_agent.exe` and see whether it returns on 45654.
  *(Not done this session — the user declined killing the process. Do it in the VM instead.)*
- If deterministic → clean drive-by, severity up. If random → attacker must port-scan from the
  browser, which is still practical (WebSocket scanning is fast and the handshake is a unique
  fingerprint) but weakens the report.

**(b) Can a real browser actually reach it?** This is the make-or-break question.
- `ws://` from an **`https://`** page = blocked as mixed content. So an https attacker site cannot do it.
- `ws://` from an **`http://`** page = allowed, but subject to **Chrome Private Network Access**
  (public → loopback is increasingly blocked/preflighted). Test current Chrome + Firefox.
- A ready PoC is written: **`ghub-recon/poc_ghub_origin.html`**. Serve it over http from a
  **non-loopback** host so the page origin is genuinely cross-origin, then open it. It tests 9010
  (control, expect refused) and 45654 (expect CONNECTED + the `get-extensions` push).
- **If no current browser can reach it, this collapses to a local-only, same-user issue and should
  be dropped** — a same-user local process gains nothing. Run the gate honestly here.

---

## 3. CLOSED LEADS — do not re-chase (this kills the previous handoff's primary thesis)

The prior handoff's **"Primary: elevated updater service → DLL hijacking, binary planting,
writable service paths"** is **dead**. All verified this session:

| Check | Result |
|---|---|
| `C:\Program Files\LGHUB` ACL | `BUILTIN\Users : ReadAndExecute, Synchronize` only. Correct. |
| `lghub_updater.exe` ACL | Users read-only. Correct. |
| **File-level** write test, every file in `Program Files\LGHUB` + `ProgramData\LGHUB` | **zero writable files** |
| `C:\ProgramData\LGHUB` | Deliberately hardened — explicit **non-inherited** `Everyone : ReadAndExecute`. Logitech broke inheritance on purpose here. |
| Unquoted service path (Logitech) | None. `LGHUBUpdaterService` path is properly quoted. |
| Unsigned binaries in privileged dirs | **None.** All `.exe`/`.dll`/`.sys` under `Program Files\LGHUB` are Valid-signed by Logitech. |
| Scheduled tasks (Logitech) | None. |
| Named pipes | Only `logi.trueforce.connect`, owned by the low-priv user → no boundary. |

Also dead from the earlier Linux session and re-confirmed: **updater MITM** — no plaintext HTTP
update endpoint.

Out-of-scope bycatch (noted, not ours, do not report to Logitech):
unquoted service paths in `UpcElevationService` (Ubisoft) and `vgc` (Riot Vanguard), both LocalSystem.

### 3.1 `127.0.0.1:9180` — the SYSTEM updater HTTP server (unresolved, low prospects)
`lghub_updater.exe` (SYSTEM) serves plain `HTTP/1.0` on 9180 (note: *not* websocketpp — no
`Server:` header, unlike 9010/45654). **Every path tried returned 404**, including WebSocket
upgrades with the correct subprotocol.

The IPC subprotocol name is `logi.updater_ipc.protocol.v1.protobuf` (also
`logi.updater_ipc.protocol.protobuf`) and the payload is protobuf, so the router path lives inside
the message envelope, not the URL — which is why URL probing 404s.

The updater binary embeds the shared `logi::router` table (722 paths, exported to
`ghub-recon/updater_router_paths.txt`; agent has 1038 in `agent_router_paths.txt`). The
high-value-looking ones, **none of which were reachable**:
```
/updates/host_address     /updates/run_launchable   /updates/remote
/updates/install          /updates/download         /updates/depot/reinstall
/updates/updater_service/install                    /updates/pipeline
/installer/install_depot_extension
/lps/install_plugin_from_file    /lps/action/execute    /lps/install_lps
```
**Caveat before getting excited:** these strings are from a shared static router library linked
into both binaries — their presence does **not** prove the updater registers them. The device
routes (`/audio/%s/...`, `/analog/%s/...`) are in the updater binary too and obviously belong to
the agent. Do not build a report on this string list alone.

To actually settle 9180 you need the real client half: capture `lghub_agent` → `lghub_updater`
traffic during an update check (no connection was live during this session), or reverse
`endpoint_websocket_proxy` in `logi::router`. **This is the highest-ceiling remaining lead**
(anything reachable here is SYSTEM), but it is also the most expensive.

---

## 4. REMAINING LEAD — symlink / TOCTOU against elevated log writes

Genuinely promising, unproven, and the right thing to do in the `win11` VM.

**Ingredients (all verified):**
1. These directories are **created by an elevated process** (`Owner: BUILTIN\Administrators`) but
   are **writable by a normal user**:
   ```
   C:\ProgramData\Logi\GHUB\Logs
   C:\ProgramData\Logi\GHUB\Logs\shared_installer
   C:\ProgramData\Logi\GHUB\Logs\software_manager
   C:\ProgramData\LGHUBData\applications
   C:\ProgramData\Logishrd\LGHUB\analytics\...
   ```
   (`Logi`, `Logishrd`, `LGHUBData` all carry the default inherited `BUILTIN\Users : Write`.
   Only `ProgramData\LGHUB` was hardened — the others were missed.)
2. The log filename format string is `%s-%s-%ld.log` — predictable enough to pre-place a
   reparse point.
3. **A low-priv user can start the SYSTEM updater service on demand.** SDDL for
   `LGHUBUpdaterService`:
   ```
   D:(A;;RP;;;WD)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
   ```
   `(A;;RP;;;WD)` = **`Everyone` : `SERVICE_START`**. Config change (`DC`) is Administrators-only,
   so this is not privesc by itself — but it hands an attacker a **trigger** to fire the elevated
   code path at will, which is exactly what you need to win a symlink race.

**The chain to attempt:** low-priv user junctions `...\Logs\software_manager` (or pre-creates the
predictable log filename as a symlink) → starts `LGHUBUpdaterService` via `Everyone:RP` →
elevated `lghub_software_manager` writes its log through the reparse point → arbitrary file
write as SYSTEM → SYSTEM.

**Only worth reporting if you land the full low-priv → SYSTEM transition.** Per the standing
rules, an unproven writable-path claim gets closed as informative.

---

## 5. Files brought back — `D:\research\ghub-recon\`

Zip this directory and move it to Fedora.

| File | What it is |
|---|---|
| `app.asar` | **14.6 MB Electron frontend.** Extract on Linux (JSON header + concatenated files). Confirmed `nodeIntegration:!1`, `contextIsolation:!0`. Contains the UI side of the integration flow: `v$.send(rD.SET,"/overwolf/extensions/install",...)` then `GET /overwolf/extensions`; payload shape `t.payload.extensions`. |
| `lghub_software_manager.exe` | **19 MB, and it is .NET (ILRepack)** — `lghub_software_manager, Version=2026.5.9708.0`, PDB path `C:\builds\kragle\lego\build\x64\logi\frontend_zero\lghub_software_manager\...`. Decompile with ilspycmd/dnSpy — by far the cheapest reversing win available, and it is the component that writes into the user-writable log dir in §4. |
| `FINDING_origin_matrix.txt` | The §2.1 evidence table. |
| `poc_ghub_origin.html` | Browser PoC for §2.5(b). |
| `updater_router_paths.txt` / `agent_router_paths.txt` | 722 / 1038 extracted `logi::router` paths. |
| `services.txt`, `service_sddl.txt`, `listeners.txt` | §1 raw output. |
| `version.json`, `next.json`, `periodic_check.json`, `groups.json` | Updater state from `C:\ProgramData\LGHUB`. |
| `01_*`–`11_*` | Output of the earlier `ghub-recon.ps1` run. **Note its `05_WRITABLE...` only scanned `%LOCALAPPDATA%`** (the user's own dir — everything there is FullControl by definition and is *not* a finding). The ProgramData results in §4 came from this session's scan, not that script. |

---

## 6. Gate check on the live finding (§2), run honestly

1. **Actually a vulnerability?** Yes — missing `Origin` validation on a localhost WebSocket (CWE-1385, cross-site WebSocket hijacking) + no authentication on the channel.
2. **In scope?** Yes — "G Hub / Executable / Eligible", latest version. Re-verify 39.1.2 is current.
3. **Duplicate?** Distinct from the 2018 Ormandy/Options bug — different product, different codebase, different port, different protocol, and no keystroke injection. No public G HUB WebSocket vuln was found in the 2026-09-07 searches. **Still check the Logitech program's own Hacktivity tab before submitting** (not global H1 search — it is useless for these terms).
4. **Reproduces reliably?** Yes — deterministic, captured in the matrix above.
5. **Actual impact?** Modest and honestly bounded: integration impersonation, UI data injection, feature DoS. **Not** RCE, **not** privesc, **not** keystroke injection.
6. **Exploitable with a working PoC?** From a raw socket, yes. **From a browser — UNVERIFIED.** This is the gate item that is not yet satisfied. §2.5(b) settles it.
7. **Would the platform accept it?** Borderline. It clears the bar only if §2.5(b) shows a real browser can connect. **If no current browser can reach it, drop this and put the time into §4 (symlink→SYSTEM) or §3.1 (the 9180 SYSTEM router) instead.**

---

## 7. Do this next, in order

1. **Run `poc_ghub_origin.html` from a non-loopback http origin in current Chrome and Firefox.**
   This single test decides whether §2 is submittable. Do it first — it is 5 minutes.
2. If it connects: restart `lghub_agent` and confirm whether 45654 is stable, then write §2 up
   with the 9010-vs-45654 table as the centrepiece.
3. If it does not connect: **drop §2** and move to the `win11` VM for §4 (symlink race to SYSTEM),
   which has a far higher ceiling and clears the "no theoretical bugs" bar if it lands.
4. On Fedora meanwhile (free, parallel, no VM needed): decompile `lghub_software_manager.exe`
   (.NET — easy) and extract `app.asar`. Both feed §3.1 and §4.
5. Do **not** re-run: install-dir ACLs, DLL-hijack hunting, unquoted paths, signature checks,
   updater MITM. All closed in §3.

**Still do NOT do natively on the Windows box:** driver IOCTL fuzzing (will BSOD) — `win11` VM only.
