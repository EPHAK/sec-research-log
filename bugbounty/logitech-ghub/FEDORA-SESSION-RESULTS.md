# Logitech G HUB — Fedora session results (2026-09-08)

**Continues:** `logitech session continued on fedora.md` (Windows session, same day).
**Everything here is static analysis on Fedora.** No G HUB process was contacted, started or modified.

Binaries analysed (copied from the mounted Windows volume, `C:\Program Files\LGHUB`):

| File | Size | Notes |
|---|---|---|
| `lghub_updater.exe` | 22 MB | **runs as SYSTEM** (`LGHUBUpdaterService`). Main subject below. |
| `lghub_agent.exe` | 86 MB | runs as the logged-in user; owns 9010 / 45654 |
| `lghub_software_manager.exe` | 19 MB | mixed .NET (WPF installer UI) + native |
| `app.asar` | 14.6 MB | Electron frontend, extracted (250 files) |

Tooling installed this session (all user-local, no root): .NET SDK 8 + runtime 6 (`~/.dotnet`),
`ilspycmd` 8.2, python `protobuf`. Ghidra 12.1.2 was already present.

---

## 0. TL;DR — what changed

1. **The updater's full IPC protocol has been recovered** (69 protobuf descriptors, reconstructed
   into readable `.proto` files). §3.1 of the previous handoff called this "the highest-ceiling
   remaining lead, and also the most expensive". It is now done, and it was cheap.
2. That protocol exposes **SYSTEM-level operations to whatever can talk to it** — including
   running executables and repointing the update server.
3. **The accept-time security check appears to be transport-dependent**, and returns *allow*
   unconditionally on the non-named-pipe path. Port 9180 is TCP. **This is the lead.**
4. **§2 (Overwolf 45654 origin) is weaker than the previous handoff assumed** and should be
   deprioritised — see §4.
5. **§4 of the old handoff (depot symlink / path traversal) is largely dead** — the traversal
   check is correctly implemented. See §5.

---

## 1. Recovered IPC protocol (new capability)

Protobuf `FileDescriptorProto` blobs are embedded in the binaries. `extract_protos.py` locates
each descriptor's `name` field and then walks the wire format field-by-field to find its exact
end, then renders readable `.proto` source.

- 69 descriptors from `lghub_updater.exe` → `protos/`
- same set from `lghub_agent.exe` → `protos_agent/`

The updater IPC is fully described by six files:

```
logi/updater_ipc/protocol/messages/envelope.proto
logi/updater_ipc/protocol/messages/error.proto
logi/updater_ipc/protocol/messages/v1/connections.proto
logi/updater_ipc/protocol/messages/v1/installer.proto
logi/updater_ipc/protocol/messages/v1/pipeline.proto
logi/updater_ipc/protocol/messages/v1/package.proto
```

### 1.1 The envelope — routing is numeric, which explains the previous session's 404s

```protobuf
message Envelope {
  enum FlagValues { NONE = 0; ERROR = 1; EXPECTS_REPLY = 2; }
  uint32 message_id = 1;
  uint32 in_response_to_id = 2;
  Envelope.FlagValues flags = 3;
  uint32 content_type = 4;      // <-- the router key
  bytes  content_data = 5;      // <-- serialised inner message
}
```

The previous session URL-probed 9180 and got 404 on everything. That is expected: **there is no
URL routing.** Dispatch is on the numeric `content_type` inside the envelope. Confirmed
independently — the updater binary contains **no URL paths that aren't in the shared
`logi::router` string table**, i.e. it registers no HTTP routes of its own.

### 1.2 The handshake carries no credential

```protobuf
message EndpointInformation {
  string Name = 1; string Identifier = 2; string Version = 3;
  uint64 ProcessID = 4;          // <-- client-declared
  string ExecutablePath = 5;     // <-- client-declared
  uint64 start_time = 6;
}
message HelloRequest {
  EndpointInformation Endpoint = 1;
  string Language = 2;
  repeated uint32 SupportedProtocols = 3;
}
```

There is **no token, key, nonce or signature field anywhere in the handshake**. The only identity
a client presents is self-declared. Any authentication must therefore be out-of-band — see §2.

Note `ConnectionStatusChangeBroadcast.Flags` includes `LogitechSigned = 4`, so the product does
have a notion of "this peer is a signed Logitech binary".

### 1.3 What the IPC can be told to do (all of this is SYSTEM)

From `installer.proto`:

```protobuf
message RunLaunchableByAliasRequest {          // SYSTEM executes something
  string app_tag = 1; string depot_name = 2;
  string launchable_alias = 3; bool wait = 4;
}
message InstallDepotRequest { ... map<string,string> custom_tags = 5; repeated string file_groups = 6; }
message InstallDepotExtensionRequest   { string app_tag; string depot_name; string extension_name; }
message UninstallDepotExtensionRequest { ... }
message StartProcessesRequest { string app_tag = 1; LaunchableOperation op = 2; bool frontend_only = 3; }

message DepotExtensions.DepotExecutable {      // what an extension actually runs
  string pipeline_uri = 1;
  repeated string arguments = 2;
}
```

From `pipeline.proto` / `package.proto`:

```protobuf
message Channel {                 // repoint the update server
  string pipeline_host = 1; string name = 2; string password = 3;
  repeated string access_groups = 4;
}
message SetChannelRequest    { string app_tag = 1; Channel channel = 2; }
message SetChannelInfoRequest{ string app_tag = 1; Channel channel = 2; string transaction_id = 3; }
message SaveCommandLineRequest { repeated CommandLineEntry entries = 1; string transaction_id = 2; }
message ExecuteActionsRequest  { string transaction_id = 1; }
message DownloadDepotRequest / RemoveDepotRequest / ModifyStateRequest / DirectUninstallRequest
```

If an arbitrary local process can drive this, that is **local privilege escalation to SYSTEM** —
directly, via `RunLaunchableByAliasRequest` / `InstallDepotExtensionRequest`, without needing any
memory-corruption or file-race bug.

---

## 2. THE LEAD — accept-time security check looks transport-dependent

`logi::local_connection::impl::LocalServerImpl::asyncAccept` logs:

```
LocalServerImpl::asyncAccept: Connected client: 0x%p
LocalServerImpl::asyncAccept: Connected client: 0x%p failed security check
```

Call site (`FUN_140c25970`, Ghidra):

```c
uVar14 = param_1[0xc];                    // server object field (+0x60)
uVar12 = FUN_140c1b630(*param_1 + 8);     // returns *(int*)(conn + 0x34)
cVar11 = FUN_140c243e0(uVar12, uVar14, 0);
if (cVar11 == '\0') { /* ... "failed security check" ... */ }
```

The policy function `FUN_140c243e0`:

```c
undefined1 FUN_140c243e0(int param_1)
{
  if (param_1 == 0) return 1;            // <-- allow unconditionally, no check at all
  if (param_1 != 1) return 0;
  FUN_140c1b1f0(local_48);               // resolve peer process (named-pipe only, see below)
  if ((local_18 == '\0') || (local_28 == 0)) return 0;   // fails closed if peer unknown
  return FUN_140c1b480(local_38);        // verify peer signature
}
```

And the peer resolver `FUN_140c1b1f0` is **named-pipe-only**:

```c
if (param_3 == 0) GetNamedPipeClientProcessId(param_2, &pid);
else if (param_3 == 1) GetNamedPipeServerProcessId(param_2, &pid);
else return invalid;
OpenProcess(0x1000, 0, pid);             // PROCESS_QUERY_LIMITED_INFORMATION
GetProcessTimes(...);                    // start time (anti-PID-reuse)
QueryFullProcessImageNameA(...);         // real image path
```

`FUN_140c1b480` (the verifier) chains to `FUN_140a5e960`, which compares the publisher against
the literals **`Logitech Inc` / `Logitech Inc.`**, which in turn calls `FUN_140a5ea70` =
`logi::platform::security::FileCertificate::FileCertificateImpl::isTrustedByOS` → `WinVerifyTrust`.

**So the design is sound for named pipes and absent for the other transport.** One branch resolves
the peer's *real* PID from the kernel (not the client-declared one), pins it with the process start
time, resolves the true image path and verifies it is Logitech-signed. The other branch returns 1.

### Why this matters
- `lghub_updater.exe` (SYSTEM) listens on **TCP `127.0.0.1:9180`** — confirmed in the previous
  session via `Get-NetTCPConnection`.
- `GetNamedPipeClientProcessId` **cannot** identify the peer of a TCP socket. On a socket the
  mode-1 branch would fail closed and reject *every* client, including the legitimate agent.
- The updater imports **no** socket-peer-identification API — `GetExtendedTcpTable` and
  `GetTcpTable2` are both **absent** from the binary. There is no other way for it to learn who
  connected over TCP.
- Therefore, if 9180 is the IPC transport, the check on that path is necessarily the `return 1`
  branch.

### Honest caveats — read these before acting
1. **Decompiler argument recovery is unreliable here.** The call site passes three arguments;
   Ghidra rendered the body with one. Which of `conn+0x34` / `server+0x60` is the selector is an
   *inference*. What is solid: the function selects between "allow unconditionally" and
   "resolve-peer-and-verify", on a value supplied by the connection/server object.
2. **It is not yet proven that 9180 is the IPC endpoint at all.** It might be a status/health
   listener, with the real IPC on a named pipe. The pipe list from the previous session shows no
   `logi`-named pipe — but it does contain ~30 GUID-named pipes, any of which could be it, and
   the owning process was never checked.
3. `CreateNamedPipeW` in the updater belongs to **crashpad** (`\\.\pipe\crashpad_%lu_`), not to
   the IPC. I checked this specifically; it does not tell us the IPC transport either way.

**All three are settled by one cheap dynamic test on Windows — see the companion
`WHAT-DO-I-DO-windows.md`.**

---

## 3. Depot / update-channel integrity (context, not a finding)

- `C:\ProgramData\LGHUB` is `Everyone:(RX)` — deliberately hardened, **not** user-writable. Local
  depot injection there is not possible. Confirmed against `06_icacls_roots.txt`.
- `keys.json` (world-readable) holds **83 keys, every one exactly 16 bytes** (AES-128-sized
  symmetric material), not public keys.
- `updates.Depot` carries `cipher_suite`, `iv`, `key`, `mac` **and** a separate `Signatures`
  message, so depot authenticity is not resting on those symmetric keys alone.
- Update host strings: `https://updates.ghub.logitechg.com`, `https://pipeline.logitech.io`,
  `https://stg-pipeline.np.logitech.io`. No plaintext HTTP update endpoint — consistent with the
  earlier finding that updater-MITM is dead.

Not chased further: without a delivery path, a depot-parsing bug is unreachable, and the IPC lead
above is a shorter route to the same impact.

---

## 4. §2 Overwolf endpoint (45654) — downgrade, deprioritise

Reading the extracted Electron bundle (`asar-x/app.min.js`) narrows the impact *below* what the
previous handoff estimated:

- Injected extension names render through `KEY_STRING(t.name)` inside React → **auto-escaped, no XSS**
  (the previous handoff already ruled out XSS→RCE via `nodeIntegration:!1`; this is an additional
  independent barrier).
- The extension list is only rendered when `this.props.integrationInstalled` is true and the
  integration guid passes `Qbe(...)` — i.e. **only if the Overwolf integration is actually
  installed.** The previous handoff argued the bug was interesting *because* it affects every
  install even without Overwolf; the UI code contradicts that for the rendering path.

Combined with the still-unanswered browser-reachability question (mixed content + Chrome PNA),
this does not look submittable. Recommend dropping unless the browser test happens to succeed.

---

## 5. Depot symlink / path traversal — mostly dead

The previous session flagged `CreateSymbolicLinkW` + `Path traversal detected:` + `Broken symlink
in depot` as a promising combination. Decompiling the check (`FUN_14020e7e0`) shows it is
**correctly implemented**:

- both the base directory and the candidate path are **canonicalised first**
  (`logi::filesystem::weakly_canonical` / `canonical`), so symlinks are resolved *before* comparison;
- containment is a prefix compare **plus** a check that the following character is `/` or `\`,
  so the classic `/base` vs `/basefoo` prefix bug is not present;
- on failure it throws `Path traversal detected: '%s' resolves outside base directory '%s'`.

That is a textbook-correct containment check. Not worth further time.

---

## 6. Files produced

```
logitech/
  bin/                     lghub_{updater,agent,software_manager,sso_handler,gl,system_tray}.exe + data/ sdks/
  asar-x/                  extracted Electron frontend (250 files)
  analysis/
    protos/                69 reconstructed .proto files (updater)
    protos_agent/          same, from the agent binary
    sm_cs/                 decompiled .NET: Logi.{Engine,Installer,Core,Bootstrap,DownloadMonitor}
    lghub_updater.exe.map.txt        string/import -> function map
    lghub_updater.exe.decomp.c       174 decompiled functions
    updater_seccheck.txt             the asyncAccept security-check chain (§2)
    updater_logisig_callers.txt      callers of the Logitech-signature check
    updater_pipe_callers.txt         named-pipe API callers (crashpad attribution)
  extract_protos.py        protobuf descriptor recovery tool
  ghidra_scripts/          DumpDepot.java, TraceAuth.java
```

## 7. Gate check (7 questions) — run honestly on the §2 lead

1. **Actually a vulnerability?** *Unproven.* If 9180 is the IPC and the check is the allow-all
   branch: yes, missing authentication on a privileged local service (CWE-306).
2. **In scope?** Yes — G HUB executable, bounty-eligible. Re-verify 39.1.2 is still latest.
3. **Duplicate?** No public G HUB updater-IPC vulnerability found. Distinct from the 2018
   Ormandy/Options WebSocket bug (different product, transport and protocol).
4. **Reproduces?** Unknown — not yet executed once.
5. **Impact?** If confirmed: **local privilege escalation to SYSTEM**, via a documented API call,
   no memory corruption required. High.
6. **Exploitable with a working PoC?** **NOT YET.** This is the unmet gate item and the only thing
   that matters next.
7. **Would the platform accept it?** Only with a demonstrated low-priv → SYSTEM transition.
   An unauthenticated-endpoint claim without that will be closed as informative.

**Status: promising lead, not a finding. Do not write a report until step 3 of the Windows plan
returns a positive result.**
