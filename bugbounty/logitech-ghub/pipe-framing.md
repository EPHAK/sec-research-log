# Logitech G HUB updater IPC — pipe framing, content types, and the `llc_check` flag

**Fedora session #3, 2026-09-08. Static analysis only** — Ghidra headless on
`lghub_updater.exe` (build 2026.5.939708, 22 MB), no running system touched.

Every claim below cites the address it was read at. Nothing here is inferred from a
function name.

---

## 0. TL;DR

1. **The pipe name is a hardcoded string literal**, not derived and not per-install:
   `a62ed1c1-e1a9-5495-9038-16bd49ec7341`. It is the same on every machine running this
   build. (`FUN_140e04ef0` returns the literal.) Session 3's note "a PoC must enumerate and
   resolve owners, never hard-code the GUID" is **wrong** — hard-coding is correct.
2. **The pipe is byte mode** (`dwPipeMode = 0x8`), so there *is* framing:
   **`uint32 little-endian length` + that many bytes of serialized `Envelope`.**
3. **`HelloRequest.content_type = 0x1100001`** (17825793). Read off the send site.
   No 0–64 sweep needed.
4. **`SupportedProtocols = [1]`**, `Language = "en-US"`.
5. **Mode 0 is reachable in a shipped build.** The mode selector is not a constant — it is
   the feature flag **`llc_check`** (default `1`), read at startup from a plain-text file
   `logi_features.cfg` that is searched **upward from the executable's directory, ending at
   `C:\`**. See §6 — this is the live question the session opened.

---

## 1. The transport

`logi::api::named_pipes::Server::Impl::start()` (`FUN_1401a1ef0`) builds a
`logi::local_connection::ConnectionConfig` and hands it to
`logi::ipc::ServerNode::Start()` (`FUN_140c09030`), which drives
`logi::local_connection::impl::LocalServerImpl`.

`LocalServerImpl::asyncAccept` (`FUN_140c264c0`) creates each pipe instance at
`140c267c9`. Disassembly of the call site:

```
140c26776  LEA  RCX,[R13 + 0x8]        ; &ConnectionConfig
140c2677a  CALL FUN_140c1b580          ; -> cfg+0x30   (publicAccess bool)
140c26782  LEA  RDX,[RBP + 0x120]
140c26789  LEA  RCX,[R13 + 0x8]
140c2678d  CALL FUN_140c1b5b0          ; -> "\\.\pipe\" + cfg.name
140c2679c  MOV  byte  ptr [RSP + 0x38],SIL     ; arg8 = publicAccess
140c267a1  MOV  dword ptr [RSP + 0x30],EDI     ; arg7 nDefaultTimeOut = 0
140c267a5  MOV  dword ptr [RSP + 0x28],0x400   ; arg6 nInBufferSize   = 1024
140c267ad  MOV  dword ptr [RSP + 0x20],0x400   ; arg5 nOutBufferSize  = 1024
140c267b5  MOV  EDX,0x40000003                 ; arg2 dwOpenMode
140c267ba  MOV  R9D,0xff                       ; arg4 nMaxInstances   = 255
140c267c0  MOV  R8D,0x8                        ; arg3 dwPipeMode      <<<<
140c267c6  MOV  RCX,RAX                        ; arg1 lpName
140c267c9  CALL FUN_140c26fd0                  ; CreateNamedPipeA wrapper
```

- `dwOpenMode = 0x40000003` = `FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX`
- **`dwPipeMode = 0x8`** = `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`

**Byte mode.** Not message mode. So the length prefix question is live, and §2 answers it.

`PIPE_REJECT_REMOTE_CLIENTS` means local-only — consistent with "attacker already has code
execution as a normal user", not remotely reachable.

### The DACL, in the binary

`FUN_140c26fd0` is a `CreateNamedPipeA` wrapper whose 8th argument selects a hand-built
security descriptor:

```c
AllocateAndInitializeSid({0,0,0,0,0,1}, 1, 0,...)   // S-1-1-0  = Everyone
ea.grfAccessPermissions = 0x1fffff;                 // full access
ea.grfAccessMode        = SET_ACCESS;
SetEntriesInAclA(1,&ea,NULL,&acl); SetSecurityDescriptorDacl(sd,TRUE,acl,FALSE);
```

and `Server::Impl::start` passes **`publicAccess = 1` unconditionally** (`local_d8 = 1` at
`140c26776`'s caller, see §6 listing). So the pipe grants **Everyone `0x1FFFFF`** by design.
This confirms, from the binary, the Windows session's observation that a low-priv process
can open it. The DACL is not the boundary; the accept-time check is the whole defence.

---

## 2. Framing — `uint32 LE length` + payload

### Read side

`ConnectionImpl::AsyncRead` (`FUN_140c201a0`, logs `"AsyncRead start..."`):

```c
local_278 = param_1 + 0x98;    // buffer  = &conn->m_incomingSize   (uint32 at conn+0x98)
uStack_270 = 4;                // length  = 4
...
FUN_140c1f4c0(local_c8, local_268, 0, 1);   // asio async_read(handle, buffer(&size,4), transfer_all)
```

The completion handler (`FUN_140c1e8a0`) then:

```c
if (*(u64*)(conn+0x90) < (u64)*(u32*)(conn+0x98))
    log("ConnectionImpl::async_read: Buffer size (%ld) exceeds maximum buffer size (%ld)"), abort;
else
    log("ConnectionImpl::async_read: read of %ld bytes pending...", *(u32*)(conn+0x98));
    resize(conn->buffer /*conn+0xa0*/, *(u32*)(conn+0x98));
    async_read(handle, buffer(conn->buffer, size), transfer_all);   // -> FUN_140c1f2c0
```

and on completion `FUN_140c1e650` (`"async_read: Complete: Bytes:%ld"`) invokes the
upper-layer callback with the raw buffer at `conn+0xa0`.

The 4 bytes are read **directly into a `uint32_t` in memory** and used as a `uint` with no
byte swap anywhere on the path. x86-64 ⇒ **little-endian**.

### Write side

`ConnectionImpl::Write` (`FUN_140c20480`) copies the payload and queues it; the queue drain
(`FUN_140c229c0`) does:

```c
*(u8  *)(conn+0xb8) = 1;                                  // writing flag
*(int *)(conn+0xbc) = queue.front().end - queue.front().begin;   // payload byte count
...
local_d8 = param_1 + 0xbc;  local_d0 = 4;                 // async_write(&size, 4)
...
if (*(uint*)(conn+0xbc) <= avail) len = *(uint*)(conn+0xbc);      // then async_write(payload, len)
```

Symmetric. **4-byte little-endian length prefix, then exactly that many bytes.**

### Maximum message size

`ConnectionImpl` ctor (`FUN_140c1d2e0`) sets `conn+0x90 = param_3` (the max). `asyncAccept`
supplies it via `FUN_140c1b590(cfg)`:

```c
longlong FUN_140c1b590(cfg) { v = *(u64*)(cfg+0x28); return v ? v : 0xfffffffe; }
```

`Server::Impl::start` leaves `cfg+0x28 = 0`, so the maximum is the fallback
**`0xFFFFFFFE` (~4 GiB)** — i.e. effectively unbounded, and the server will `resize()` a
`std::vector<unsigned char>` to whatever a peer's length prefix says. (Noted, not chased:
that is a memory-amplification DoS, but only for a peer that already passed the accept-time
check, so it is not independently interesting.)

---

## 3. The router table — `content_type` is numeric, and here are the numbers

Dispatch reads `content_type` from the parsed message at `+0x18`
(`FUN_1403c2190`); `message_id` is at `+0x14`, `in_response_to_id` at `+0x10`.

`ConnectionManagementActor::OnMessage` (`FUN_14034fa70`) and the corresponding send sites
(`FUN_14034f1f0`, and `14034ed2f` / `140350???`) give the connections-protocol table:

| content_type | message | where read |
|---|---|---|
| **`0x1100001`** | **`HelloRequest`** | `140c34f36f` — `SendWithResponse(conn, out, 0x1100001, payload)` in `FUN_14034f1f0`, the function that returns a `std::future<HelloResponse>` |
| `0x1400001` | `HelloResponse` | `FUN_14034fa70` |
| `0x1600002` | `PingRequest` | `FUN_14034fa70` |
| `0x1700002` | `PingResponse` | `FUN_14034fa70` |
| `0x1100003` | `GoodbyeRequest` | `FUN_14034fa70` + send site |
| `0x1100004` | `GetConnectedClientsRequest` | send site at `14034ed2f` |
| `0x1400004` | `GetConnectedClientsResponse` | `FUN_14034fa70` |
| `0x1500005` | `ConnectionStatusChangeBroadcast` | `FUN_14034fa70` |

Shape: `(fileId << 24) | (role << 20) | messageIndex`. Connections is file `1`; the message
index is the pair id (Hello=1, Ping=2, Goodbye=3, GetConnectedClients=4,
ConnectionStatusChange=5); the role nibble distinguishes request/response/broadcast.
**Do not extrapolate the role nibble** — it is not consistent across pairs (Hello uses
1→4, Ping uses 6→7). The eight values above were each read from the binary.

The other four dispatchers (`FUN_1402bff90`, `FUN_1402d41b0`, `FUN_1402aaf30`,
`FUN_1402a0960`) cover the pipeline / installer / package / shared-settings protocols; the
constants recovered from them, for reference, are `0x2200027 0x220002f 0x240000b 0x250000c
0x2500033 0x3500032 0x3500033 0x4400081 0x4400083 0x4400085 0x4500090 0x5400001 0x5400005
0x5500010`. Those are **not** needed for the handshake test and were not individually mapped
to message types.

---

## 4. `HelloRequest` contents

The one construction site is `FUN_140356c40` @ `140356ea?`:

```c
local_3b0 = "en-US"; local_3a0 = 5;              // Language
local_528 = malloc(4); *local_528 = 1;           // SupportedProtocols = { 1 }
FUN_1403c38f0(helloReq, endpointInfo, &language, &supportedProtocols);
FUN_14034f1f0(conn, &future, helloReq);          // -> content_type 0x1100001
```

**`SupportedProtocols = [1]`. `Language = "en-US"`.** That is the only version the shipped
client offers, so `[1]` is the value to send.

`EndpointInformation` is entirely client-declared (`Name`, `Identifier`, `Version`,
`ProcessID`, `ExecutablePath`, `start_time`) and carries no credential — as session 2 found.
The server never uses it for identity; it resolves the peer from the kernel.

---

## 5. The wire bytes

Generated by `handoff/build_hello.py` (checked in; re-run it to change fields).

**Minimal — no `EndpointInformation` sub-message (25 bytes on the wire):**

```
15000000 08 01 18 02 20 81 80 c0 08 2a 0a 12 05 65 6e 2d 55 53 1a 01 01
```
```
15 00 00 00        uint32 LE length = 21
08 01              field 1 message_id        = 1
18 02              field 3 flags             = 2  (EXPECTS_REPLY)
20 81 80 c0 08     field 4 content_type      = 0x1100001   <-- HelloRequest
2a 0a              field 5 content_data, len 10
   12 05 "en-US"     HelloRequest.Language = "en-US"
   1a 01 01          HelloRequest.SupportedProtocols = [1]  (packed)
```

**Realistic — full `EndpointInformation` (71 bytes on the wire):**

```
43000000 08 01 18 02 20 81 80 c0 08 2a 38 0a 2c 0a 05 70 72 6f 62 65 12 05 70 72 6f
62 65 1a 05 31 2e 30 2e 30 20 d2 09 2a 12 43 3a 5c 70 72 6f 62 65 5c 70 72 6f 62 65
2e 65 78 65 12 05 65 6e 2d 55 53 1a 01 01
```

with `Endpoint = {Name:"probe", Identifier:"probe", Version:"1.0.0", ProcessID:1234,
ExecutablePath:"C:\probe\probe.exe"}`.

A `HelloResponse` reply is an `Envelope` with `field 2 in_response_to_id = 1` and
`content_type = 0x1400001` — envelope bytes `10 01` and `20 81 80 80 0a` respectively.

**`handoff/windows/hello-probe.ps1` builds and sends this from PowerShell** (no Python
needed on the Windows box) and prints DROPPED vs REPLIED. Run it non-elevated.

---

## 6. The mode selector — **it is a feature flag, and mode 0 is reachable**

Session 2 flagged "which argument is the selector" as an unresolved inference. It is
resolved, and the answer changes the picture.

### 6.1 The call site, retyped

`FUN_140c243e0` really takes three arguments; Ghidra rendered one. The two it dropped are
passed straight through to `FUN_140c1b1f0(&out, HANDLE, int)`:

```c
// LocalServerImpl::ServerCallback, FUN_140c25970 @ 140c25b37
uVar12 = param_1[0xc];                    // ctx+0x60  = the pipe HANDLE
uVar10 = FUN_140c1b630(*param_1 + 8);     // = *(int*)(LocalServerImpl+8+0x34)
cVar9  = FUN_140c243e0(uVar10, uVar12, 0);
```

so the true signature is

```c
bool FUN_140c243e0(int mode, HANDLE pipe, int direction /*0 = resolve client*/);
```

**arg1 is the selector; `server+0x60` is the HANDLE, not the selector.** The selector is
`ConnectionConfig+0x34` (the config is stored at `LocalServerImpl+8`; the config move-ctor
`FUN_140c1b4b0` copies `+0x34` explicitly).

### 6.2 What writes it

`logi::api::named_pipes::Server::Impl::start()`, `FUN_1401a1ef0` @ `140a2245`:

```c
local_108 = 0; ... uStack_f0 = 0xf;                    // cfg+0x00..0x1F : std::string name
local_e8  = 0;                                         // cfg+0x20
local_e0  = 0;                                         // cfg+0x28  (max msg size; 0 -> 0xfffffffe)
local_d8  = 0;                                         // cfg+0x30
local_d4  = 1;                                         // cfg+0x34
FUN_14002d700(&local_108, srv+0x38, srv+0x48);         // cfg.name = the pipe name
local_d8  = 1;                                         // cfg+0x30 = publicAccess  = TRUE (always)
local_d4  = (uint)(*(char*)(param_1 + 0x58) != '\0');  // cfg+0x34 = securityMode  <<<<
FUN_140c09030(srv->node, &local_108);                  // ServerNode::Start(cfg)
```

`Server::Impl+0x58` is set once, in the ctor (`FUN_14019cef0`):

```c
FUN_140024fe0(param_1 + 7, param_2);                        // Impl+0x38 = config.name
*(u8*)(param_1 + 0xb) = *(u8*)(param_2 + 0x20);             // Impl+0x58 = config.secure
```

and the one and only `Server` construction site is `FUN_140076160` (`updater_core::startup`)
@ `14007778a`:

```c
puVar12 = FUN_140e04ef0(...);                     // the pipe name, see 6.4
FUN_14002d700(&local_1b8, *puVar12, puVar12[1]);

local_a08 = 0x40f1dfd0; uStack_a00 = 9;           // string_view{ "llc_check", 9 }
local_198 = FUN_1400277d0(&local_a08, 1);         // GetFeatureFlag("llc_check", default = true)

FUN_140024fe0(local_ba8, &local_1b8);             // config.name   = pipe name
local_b88 = local_198;                            // config+0x20   = llc_check     <<<<
FUN_14019a430(new Server(0x20), local_ba8);
```

**Full chain:**

```
logi_features.cfg["llc_check"]  (default 1)
  -> Server config +0x20
  -> Server::Impl +0x58
  -> ConnectionConfig +0x34
  -> FUN_140c243e0 arg1
       0 -> return 1                      (accept every peer, no check at all)
       1 -> GetNamedPipeClientProcessId -> OpenProcess -> GetProcessTimes
            -> QueryFullProcessImageNameA -> WinVerifyTrust vs "Logitech Inc[.]"
```

### 6.3 Where `llc_check` comes from

`FUN_1400277d0` = `logi::util::feature_decisions::GetFeatureFlag(string_view, bool default)`
(`logi/util/feature_decisions.hpp`). It looks the name up in a hash map and **returns the
caller's default unchanged if the key is absent** (`FUN_14014b160`, `LAB_14014b2bd`).

The map is populated once at startup (`FUN_14002a8a0`) from the file **`logi_features.cfg`**:

```c
FUN_14014b700(local_178, &DAT_14131d100);   // filename = "logi_features.cfg"
FUN_14014b8f0(local_178);                   // load it
```

`FUN_14014b8f0` resolves the path with

```c
local_180 = logi::util::process::WinExecutablePathProvider::vftable;
uVar2 = FUN_140157520(&local_38, &local_180);    // = parent_path(GetModuleFileName())
FUN_14015dbb0(local_150, filename, /*walkUp=*/1, uVar2);
```

and `FUN_14015dbb0(out, name, walkUp, dir)` is: *test `dir/name`; if it does not exist and
`walkUp`, recurse on `dir.parent_path()` until the parent equals the dir.* So the search
order on a stock install is

```
1.  C:\Program Files\LGHUB\logi_features.cfg
2.  C:\Program Files\logi_features.cfg
3.  C:\logi_features.cfg          <-- last stop; parent_path("C:\") == "C:\"
```

**File format** — one flag per line, matched against this regex (built at
`FUN_140015640`, applied in `logi::util::feature_flags::list_loader::load_stream`,
`FUN_14014bb60`):

```
([a-z0-9]+[a-z0-9 ._]*[a-z0-9]+)\s*=\s*(0|1|false|true|off|on|yes|no)\s*
```

so the disabling line is literally:

```
llc_check = 0
```

### 6.4 The pipe name is a hardcoded literal

```c
undefined8 * FUN_140e04ef0(undefined8 *param_1) {
  param_1[1] = 0x24;
  *param_1 = "a62ed1c1-e1a9-5495-9038-16bd49ec7341";
  return param_1;
}
```

Not `CoCreateGuid`, not the machine GUID, not read from `ProgramData`. A compile-time
constant. It matches the GUID the Windows session observed. It will change only when
Logitech changes it in a future build — so **hard-code it, and re-read this function if a
new build stops answering.**

---

## 7. The publisher compare is exact, not `strstr` (task 4)

`FUN_140c1b480` -> `FUN_140c24560` -> `FUN_140a5e960`:

```c
if (!FUN_140a5ea70(...)) return 0;                    // isTrustedByOS / WinVerifyTrust FIRST
name = GetSubjectName(cert);
if (name.size() == 0xc  && memcmp(name, "Logitech Inc",  0xc) == 0) return 1;
if (name.size() == g_len && memcmp(name, "Logitech Inc.", g_len) == 0) return 1;
return 0;
```

Length is compared **before** `memcmp`, and `memcmp` covers the whole string. Two exact
literals. `Logitech Incorporated Evil Ltd` would fail on the length test. The
`Logitech Inc` / `Logitech Inc.` pair is two spellings of the same subject, not a substring
match. **That sub-lead is closed.**

`WinVerifyTrust` runs first and short-circuits, so nothing after it is reachable with an
untrusted signature. The `LogitechSigned = 4` flag in
`ConnectionStatusChangeBroadcast.Flags` is set *from* this result and broadcast to peers; no
privileged operation was found gated on the flag separately, and nothing in
`LocalServerImpl::asyncAccept` runs a message handler before `FUN_140c243e0` returns — on
`false` it calls the connection's close vtable slot and never registers the connection or
starts a read.

---

## 8. What 9180 is (task 2)

`logi::pipeline::api_server<logi::api::named_pipes::Server, logi::api::http_server>` — the
updater's API surface is a template over **two** transports. The named-pipe half is the IPC
above. The HTTP half is constructed in `updater_core::startup` as

```c
uVar7 = FUN_140e02c90();     // returns 0x23e5 = 9189
uVar8 = FUN_140e02c70();     // returns 0x23dc = 9180
new logi::api::http_server(uVar8, uVar7);     // FUN_1401ab800(obj, 9180, 9189)
```

so **9180 is the start of a 9180–9189 port range** for the `logi::api` HTTP/router transport.
It is **not** crashpad (crashpad's pipe is `\\.\pipe\crashpad_%lu_`, created by a completely
separate wrapper `FUN_1401f7660` with `dwPipeMode = 6`), not Sentry, and not dead code — it
is a live listener that simply has **no routes registered in this binary**, which is exactly
why session 3 got a byte-identical `HTTP/1.0 404` to every path and every WebSocket upgrade.

**Do not re-probe 9180.** It answers 404 because the router table is empty, not because the
right path was not found.

---

## 9. Corrections to earlier sessions

- Session 2 §2 caveat 1 ("which of `conn+0x34` / `server+0x60` is the selector is an
  inference"): resolved. `conn+0x34` — i.e. `ConnectionConfig+0x34` reached via
  `FUN_140c1b630(LocalServerImpl+8)` — is the selector; `server+0x60` is the pipe HANDLE.
- Session 2 §2 caveat 3 ("`CreateNamedPipeW` in the updater belongs to crashpad"): true but
  incomplete. The IPC pipe is created through **`CreateNamedPipeA`** (`FUN_140c26fd0`), which
  a `CreateNamedPipeW`-only search misses. Search both.
- Session 3 §1 ("a PoC must enumerate and resolve owners, never hard-code the GUID"):
  wrong. The GUID is a literal in `.rdata`.
- Session 3 §4 ("the entire defence is the post-accept signature check"): correct, and now
  stronger — the `Everyone: 0x1FFFFF` DACL is explicit in the code, not incidental.

---

## 10. Verification — how each claim above was checked

Everything in §1–§8 was first read out of Ghidra's decompiler. Decompiler output is an
interpretation, so each load-bearing constant was then re-checked by a **second, independent
method**: raw bytes lifted from the PE and disassembled with `objdump` (not Ghidra), a
cross-check against a different binary, and an executable round-trip.

### 10.1 Raw disassembly (objdump, independent of Ghidra)

| Claim | Bytes | Disassembly |
|---|---|---|
| `dwPipeMode = 8` | `41 b8 08 00 00 00` @ `140c267c0` | `mov r8d,0x8` — 3rd arg to `FUN_140c26fd0` |
| 4-byte length prefix | `48 8d 87 98 00 00 00` / `48 c7 44 24 28 04 00 00 00` @ `140c2031f` | `lea rax,[rdi+0x98]` then `mov QWORD PTR [rsp+0x28],0x4` — an `asio::mutable_buffer{&conn+0x98, 4}` |
| `content_type = 0x1100001` | `41 b8 01 00 10 01` @ `14034f36d` | `mov r8d,0x1100001`, 3rd arg to the send call at `14034f37b` |
| pipe name is a literal | `48 8d 05 89 ff 2d 00` / `48 c7 41 08 24 00 00 00` @ `140e04ef0` | `lea rax,[rip+0x2dff89]` → `0x1410e4e80`, `mov [rcx+8],0x24`. Bytes at `0x1410e4e80` are exactly `a62ed1c1-e1a9-5495-9038-16bd49ec7341` |
| 9180 / 9189 | `b8 dc 23 00 00 c3` / `b8 e5 23 00 00 c3` | `mov eax,0x23dc; ret` and `mov eax,0x23e5; ret` |
| publisher compare is exact | `48 83 fb 0c` / `75 16` @ `140a5e9b7` | `cmp rbx,0xc; jne` then `memcmp(...,0xc)`; else `cmp rbx,[0x14133b508]` (that qword = **13**) then `memcmp(...,13)`. Length first, full-length memcmp. No substring search anywhere |

The `llc_check` chain, instruction by instruction, at `140077715`:

```
movups xmm0,[rip+0xea639c]   # 0x140f1dab8 -> string_view{ptr=0x140f1dfd0, len=9}
movaps [rsp+0x580],xmm0      #   bytes at 0x140f1dfd0 = "llc_check"
mov    dl,0x1                # 2nd arg: default = true
lea    rcx,[rsp+0x580]
call   0x1400277d0           # GetFeatureFlag(name, default)
mov    [rsp+0xdf0],al        # save the result
lea    rdx,[rsp+0xdd0]
lea    rcx,[rsp+0x3e0]       # <- the ServerConfig lives at rsp+0x3e0
call   0x140024fe0           #    config.name = pipe name
movzx  eax,BYTE PTR [rsp+0xdf0]
mov    [rsp+0x400],al        # <- rsp+0x400 = config + 0x20   *** the flag lands here ***
mov    ecx,0x20
call   0x140dff73c           # operator new(0x20)
lea    rdx,[rsp+0x3e0]       #    the config
call   0x14019a430           # Server::Server(config)
```

`config+0x20` is exactly the byte `Server::Impl`'s constructor copies to `Impl+0x58`, which
`Impl::start` turns into `ConnectionConfig+0x34`. The chain in §6.2 is confirmed in raw bytes,
not inferred from the decompiler.

### 10.2 Cross-binary check

Counting the literals across five shipped binaries:

| | updater | agent | system_tray | software_manager | gl |
|---|---|---|---|---|---|
| `a62ed1c1-…7341` | 1 | **1** | 0 | 0 | 0 |
| `llc_check` | 1 | 0 | 1 | 0 | 1 |
| `logi_features.cfg` | 1 | 1 | 2 | 1 | 1 |
| imm `0x1100001` | 1 | **1** | 0 | 0 | 0 |

**`lghub_agent.exe` — the legitimate client — carries the identical GUID literal and the
identical `0x1100001` immediate.** In the agent's `.rdata` the two pipe GUIDs sit adjacent:

```
… "e0c10619-60c9-5414-a4e8-5d9e19d4dedc"  "a62ed1c1-e1a9-5495-9038-16bd49ec7341" "public" "ghub13" …
```

i.e. the pipe the agent *hosts* and the pipe it *connects to*, both compile-time constants,
and both matching the runtime table in `windows-session-2-results.md` §1. That is a second
binary, independently agreeing. Neither side derives the name at runtime.

`llc_check` appears only in the three binaries that host a `named_pipes::Server`; the agent,
which is a client here, does not read it. Consistent.

### 10.3 Round-trip against the shipped schema

`tools/roundtrip_check.py` pulls the `FileDescriptorProto` blobs for `envelope.proto` and
`v1/connections.proto **out of `lghub_updater.exe` itself**, builds message classes from them
with `google.protobuf`, and parses the generated frame:

```
recovered logi/updater_ipc/protocol/messages/envelope.proto: messages = ['Envelope']
recovered .../v1/connections.proto: ['EndpointInformation','HelloRequest','HelloResponse', …]
frame = 71 bytes; prefix says 67, body is 67  -> OK
  message_id: 1
  flags: EXPECTS_REPLY
  content_type: 17825793          (= 0x1100001)
  Endpoint { Name:"probe" Identifier:"probe" Version:"1.0.0" ProcessID:1234
             ExecutablePath:"C:\\probe\\probe.exe" }
  Language: "en-US"
  SupportedProtocols: 1
ALL ASSERTIONS PASSED
```

The frame is well-formed against the descriptors the product itself ships. Field numbers and
the packed encoding of `repeated uint32` are not guesses.

### 10.4 The probe script was actually executed

PowerShell 7.4.6 was installed locally and `windows/hello-probe.ps1` was run against a mock
server (`tools/mock-updater.ps1`) that speaks the recovered framing. All four paths were
exercised:

| Scenario | Result |
|---|---|
| encoder self-test | produced hex byte-identical to `build_hello.py` |
| self-test with the expected hex deliberately corrupted | **aborts, exit 4, never opens the pipe** |
| mock replies with a `HelloResponse` | frame accepted; mock decoded `content_type = 0x1100001`; probe read the reply and printed the finding path. Reply carried `10 01` and `20 81 80 80 0a`, the exact marker bytes the script tells the operator to look for |
| mock reads then closes | `RESULT: DROPPED - server closed the pipe without replying`, exit 0 |
| server accepts but never replies | `RESULT: DROPPED - no reply within the timeout`, exit 0 |
| no server at all | `CONNECT FAILED`, exit 2 |

`windows/run-session.ps1` — the one-shot session driver — was run the same way, in an
environment where nearly every Windows call fails, to check that a single broken step can
never abort the run or corrupt the verdict. **Two further defects surfaced there:**

3. Non-terminating errors (`Join-Path` on a missing drive, a missing `icacls`) sprayed past
   `try`/`catch` and the run continued in an unknown state. `Step` now sets
   `$ErrorActionPreference = 'Stop'` inside the step body so they are caught and reported as
   one labelled line.
4. **The write test reported a false `WRITABLE` into the VERDICT.** `WriteAllText` on a
   non-existent directory silently succeeded against a relative path, and that became a red
   finding. This is the single most dangerous failure this script could have — a false
   writable would send the next session down a wrong path and toward a bogus report. Now it
   requires the path to be rooted, requires the directory to exist, re-checks
   `File.Exists` at the intended path before believing the write, and refuses to run the
   filesystem checks at all off Windows.

**Two defects in `hello-probe.ps1` were found and fixed the same way**, both of which would
have aborted the test on the Windows box:

1. `[Security.Principal.WindowsIdentity]::GetCurrent()` threw and killed the script. Now
   wrapped in try/catch — context reporting can never abort the probe.
2. `$pipe.ReadTimeout = …` throws `"Timeouts are not supported on this stream"` —
   `PipeStream` does not support it. Replaced with a `ReadAsync` + `Task.Wait(timeout)`
   helper.

This is the class of failure that made `find-logi-endpoint.ps1` v1 useless for a whole
session. The script now parses clean and behaves correctly on every path.

**Caveat:** the tests ran on PowerShell 7.4.6 on Linux. The Windows box may use Windows
PowerShell 5.1. The script avoids 7-only syntax and parses clean, but **run
`-SelfTestOnly` first on the target** — it exercises the entire encoder on whatever
PowerShell is actually there, in a few seconds, without touching the pipe.

### 10.5 What is *not* verified

- Nothing has been sent to a live G HUB process. The whole handshake question is still
  question 6 of the gate, unmet.
- The `C:\` / `C:\Program Files` ACLs are not knowable from here. §6.3 establishes that
  `C:\logi_features.cfg` is *in the search path*; whether an unprivileged user can create it
  is a Windows-side check and is where the remaining lead lives or dies.
- I traced `GetFeatureFlag`'s map to one populate path (`logi_features.cfg`). The binary also
  contains a `FeatureCanary` subsystem with its own `get_flag`; I did **not** prove it never
  writes into the same map. If it does, and its cache is writable, that is a second route.
