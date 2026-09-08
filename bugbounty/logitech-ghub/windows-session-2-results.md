# Logitech G HUB — Windows session #2 results (2026-09-08)

**Continues:** `FEDORA-SESSION-RESULTS.md` (Fedora static analysis, same day) and
`WHAT-DO-I-DO-windows.md` (the plan this session executed).

**Everything here is step 1 only.** Read-only enumeration plus HTTP/WebSocket probes of an already
listening loopback port. No G HUB process was started, stopped, written to, or injected into. No
`HelloRequest` was sent to any Logitech IPC endpoint — step 3 was **not** run.

Host: `EPHAK`, user `ephak\swaga`, **non-elevated** (`IsInRole(Administrator) = False`), probing
PID 19816. G HUB build **2026.5.939708** (all `lghub_*.exe` agree).

---

## 0. TL;DR — what changed

1. **`lghub_updater.exe` (SYSTEM) owns a named pipe.** It is GUID-named, which is why the previous
   session's name-grep missed it and concluded "no Logitech pipe".
2. That means `FUN_140c243e0` takes the **mode 1 (enforced)** branch, not the `return 1` branch.
   **The §2 Fedora lead is dead.**
3. **TCP 9180 does not speak WebSocket.** Six upgrade attempts across four paths and both
   recovered subprotocols all returned a *byte-identical* `HTTP/1.0 404`. It is a routeless stub
   listener, not the IPC transport. This independently confirms (1).
4. `find-logi-endpoint.ps1` as shipped **could not produce this result** — four defects made
   section 1 print empty on every machine. Fixed; see §5.
5. One thing survives: a **low-priv, unsigned process can open the SYSTEM updater's pipe**. The
   DACL admits us; the entire defence is the post-accept signature check. See §4.

---

## 1. THE ANSWER — the updater's IPC transport is a named pipe

`pipes_logi.txt`, resolved via `CreateFileW` → `GetNamedPipeServerProcessId`:

| Pipe | OwnerPID | Owner | Path |
|---|---|---|---|
| `a62ed1c1-e1a9-5495-9038-16bd49ec7341` | 6180 | **`lghub_updater`** | *unreadable = SYSTEM* |
| `e0c10619-60c9-5414-a4e8-5d9e19d4dedc` | 15556 | `lghub_agent` | `C:\Program Files\LGHUB\lghub_agent.exe` |
| `logi.trueforce.connect` | 15556 | `lghub_agent` | `C:\Program Files\LGHUB\lghub_agent.exe` |

Logitech processes at probe time: `lghub_agent` (15556), `lghub_system_tray` (15536),
`lghub_updater` (6180), `logi_lamparray_service.AMD64` (5304).

Of 213 pipe entries, 74 owners resolved. The 139 that did not are all Chromium `mojo.*`,
`Winsock2\CatalogChangeListener-*`, `Sessions\1\AppContainerNamedObjects\*` and Alienware
`AlienEyeShortcutNamedPipe_*` — none plausibly Logitech. Failure tally:
`ERROR_PIPE_BUSY (231) ×112`, `ERROR_ACCESS_DENIED (5) ×27`.

**Why the previous session missed it:** the pipe name is a bare GUID. It is not a literal in the
binary and does not match `logi|lghub|ghub`. The only way to find it is to enumerate `\\.\pipe\`
and resolve owners by PID. It is stable across runs within a boot, so it is per-install or
per-boot — **a PoC must enumerate and resolve owners, never hard-code the GUID.**

### What this does to the §2 lead

`FUN_140c243e0` selects between:

```c
if (param_1 == 0) return 1;            // allow unconditionally  <-- the hoped-for path
if (param_1 != 1) return 0;
FUN_140c1b1f0(local_48);               // GetNamedPipeClientProcessId -> OpenProcess
                                       // -> GetProcessTimes -> QueryFullProcessImageNameA
if ((local_18 == '\0') || (local_28 == 0)) return 0;   // fails closed if peer unknown
return FUN_140c1b480(local_38);        // WinVerifyTrust vs "Logitech Inc[.]"
```

The Fedora argument was: *9180 is TCP, `GetNamedPipeClientProcessId` cannot identify a TCP peer,
the updater imports no `GetExtendedTcpTable`/`GetTcpTable2`, therefore the TCP path must be the
`return 1` branch.* Every step of that reasoning still holds — but its **premise** was that 9180
is the IPC transport. It is not. The updater has a real pipe, so the peer *is* resolved from the
kernel and signature-verified. **Close the lead.**

---

## 2. Listeners

`listeners.txt` — 127.0.0.1 only:

| Port | OwnerPID | Proc | Path |
|---|---|---|---|
| 8884 | 4 | `System` | |
| 9010 | 15556 | `lghub_agent` | `C:\Program Files\LGHUB\lghub_agent.exe` |
| **9180** | **6180** | **`lghub_updater`** | *unreadable = SYSTEM* |
| 45654 | 15556 | `lghub_agent` | `C:\Program Files\LGHUB\lghub_agent.exe` |

The updater owns **both** the pipe and 9180. That ambiguity is what §3 resolves.

---

## 3. 9180 is not a WebSocket endpoint — theory tested, NEGATIVE

The Fedora handoff flagged this explicitly as the signal pointing the other way: the updater links
**websocketpp** (68 string hits), and a websocketpp server answers a non-WebSocket request with a
well-formed `HTTP/1.0 404`. So 9180 might have been a WebSocket IPC endpoint.

Eight probes from the low-priv process — plain `GET /`, plain `POST /`, and six RFC-6455 upgrades:

| Probe | Response |
|---|---|
| `GET / HTTP/1.1` | `HTTP/1.0 404 Not Found` |
| `POST / HTTP/1.1` | `HTTP/1.0 404 Not Found` |
| WS upgrade `path=/` | `HTTP/1.0 404 Not Found` |
| WS upgrade `path=/ipc` | `HTTP/1.0 404 Not Found` |
| WS upgrade `path=/updater` | `HTTP/1.0 404 Not Found` |
| WS upgrade `path=/v1` | `HTTP/1.0 404 Not Found` |
| WS upgrade `subprotocol=logi.updater_ipc.protocol.v1.protobuf` | `HTTP/1.0 404 Not Found` |
| WS upgrade `subprotocol=logi.updater_ipc.protocol.protobuf` | `HTTP/1.0 404 Not Found` |

Every response was byte-identical:

```
HTTP/1.0 404 Not Found
Content-Length: 85
Content-Type: text/html

<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>
```

**This is the diagnostic part.** A websocketpp endpoint that received a well-formed upgrade on the
right path with the wrong subprotocol answers **`400`**; on an unsupported version, **`426`**. A
constant 404 with no path-dependent and no header-dependent variation means **no route matched and
no upgrade handler was consulted** — consistent with the Fedora finding that the updater registers
no URL paths outside the shared `logi::router` string table.

Conclusion: 9180 is a routeless stub/health listener. It is not the IPC.

---

## 4. What survives — the pipe DACL admits ordinary users

Resolving the updater's owning PID required successfully `CreateFileW`-ing
`\\.\pipe\a62ed1c1-…` from this **unsigned, non-elevated** process. `FILE_READ_ATTRIBUTES`
succeeded. So the pipe's DACL is not the boundary; the *entire* defence is the post-accept
signature check in `FUN_140c243e0`.

That makes exactly one experiment decisive, and it is cheap:

> Connect to the updater's pipe from an unsigned low-priv process, send a `HelloRequest`
> envelope, observe whether the connection survives.

- **Dropped / no reply** → check is enforced. Engagement over; write it up as "no finding".
- **Reply carrying `in_response_to_id`** → a SYSTEM service completed a handshake with a peer
  whose identity was entirely self-declared. **That is the report.**

Static analysis says it will be dropped. Run it anyway — it is the difference between "the code
looks right" and "the check is enforced", and the gate rules do not accept the former.

---

## 5. `find-logi-endpoint.ps1` was broken — four defects, all fixed

The shipped v1 printed an **empty section 1 on every machine**. It never produced pipe data, so
running it as-is would have led to the *opposite* conclusion ("no Logitech pipe → the allow-all
branch is live → go to step 3"). Worth recording, because that near-miss is how a dead lead
survives a session.

| # | Defect | Effect |
|---|---|---|
| 1 | `$pid = 0` | `$PID` is a read-only automatic variable; assignment throws, and `[ref]$pid` then fails. |
| 2 | `foreach (...) { } \| Tee-Object` | A `foreach` **statement** cannot be piped — `EmptyPipeElement` **parse** error, so the whole script refused to run. |
| 3 | `$GENERIC_READ = 0x80000000` | Parses as `Int32` `-2147483648`; the `uint` marshal throws. `[uint32]0x80000000` fails too — needs `[uint32]2147483648`. |
| 4 | `Split-Path -Leaf` | Returns **empty** for pipe names containing `\` (`Sessions\1\AppContainerNamedObjects\…`, `LOCAL\mojo…`) — ~100 of ~158 names. The script then opened the pipe **directory** repeatedly and got `ERROR_INVALID_PARAMETER (87)`. |

Defect 4 is the one that actually hid the finding, and it is silent — the loop `continue`s past
every failure, so a fully broken run looks like a clean "no pipes found".

v2 also adds: a `FILE_READ_ATTRIBUTES` → `GENERIC_READ` fallback (`GENERIC_READ` alone is denied
on most pipes), the WebSocket probes from §3, UTF-8 output instead of UTF-16, and a `context.txt`
recording `whoami` / elevation / build, so the low-priv claim is evidenced rather than asserted.

**`ipc_probe.py` was not run** — `python` on this box is the Microsoft Store alias stub, not a real
interpreter. Its WebSocket half is superseded by §3; its raw-framing half is moot now that 9180 is
not the IPC.

---

## 6. Files produced

```
%USERPROFILE%\Desktop\logi-endpoint\
  pipes_logi.txt           Logitech-owned / unresolvable / logi-named pipes  (§1)
  pipes_with_owners.txt    all 213 pipes with resolved owners
  listeners.txt            127.0.0.1 listeners with owning process + path    (§2)
  port9180.txt             all 8 probes and their raw responses              (§3)
  context.txt              whoami, elevation, probing PID, G HUB versions
  SUMMARY.md               condensed version of this document
```

---

## 7. Gate check — re-run on the §2 lead

1. **Actually a vulnerability?** **No.** The premise (9180 is the IPC) is disproven. The transport
   in use takes the enforced branch.
2. **In scope?** Moot.
3. **Duplicate?** Moot.
4. **Reproduces?** N/A — there is nothing to reproduce.
5. **Impact?** None demonstrated.
6. **Exploitable with a working PoC?** No, and there is no longer a reason to expect one on this
   path.
7. **Would the platform accept it?** No. Submitting "the updater has an unauthenticated TCP port"
   on the strength of a 404-only stub listener would be closed as informative, correctly.

**Status: §2 lead CLOSED. Do not re-chase 9180.** The only remaining item is the pipe handshake in
§4, which is expected to fail closed but has not been run.

---

## 8. Do NOT re-do (cumulative, across all three sessions)

- Install-dir ACLs, DLL hijacking, unquoted service paths, signature checks — clean.
- Updater MITM — no plaintext HTTP update endpoint.
- `ProgramData\LGHUB` write access — hardened, `Everyone:(RX)`.
- Depot path-traversal check — correctly implemented (canonicalises first, checks the separator
  boundary).
- Overwolf 45654 origin issue — downgraded; React escapes injected names and the list renders only
  when Overwolf is actually installed.
- **TCP 9180 / the transport-dependent security check — closed by this session.**
- **"No Logitech named pipe exists" — that was a false negative. Three exist.** Never conclude
  "no pipe" from a name grep.
