# WHAT DO I DO — Logitech G HUB, Windows session #2

Paste this file into a fresh assistant session on the Windows box, together with
`FEDORA-SESSION-RESULTS.md`.

**One question decides this whole engagement:**

> Can an ordinary, unsigned, non-elevated process talk to `lghub_updater.exe` (which runs as
> **SYSTEM**) and get it to act?

If **yes** → local privilege escalation to SYSTEM via a documented API call. High severity, and
the protocol is already fully reverse-engineered, so the PoC is short.
If **no** → the lead is dead; say so plainly and move on. Do not try to rescue it.

Everything in steps 1–2 is **read-only**. Step 3 sends a handshake only. Step 4 is the only
state-changing step and has its own warning.

---

## Before you start

- Confirm the installed G HUB version is still the latest (scope says "only the latest version
  of GHub is in scope"). Previous session tested **39.1.2 / updater 2026.5.939708**.
- You need `python.exe` on PATH. Nothing else. No Sysinternals, no admin.
- **Run everything as your normal user.** Running elevated invalidates the entire test.

---

## Step 1 — What is the IPC transport? (2 minutes, decisive)

```powershell
powershell -ExecutionPolicy Bypass -File .\find-logi-endpoint.ps1
```

It enumerates every named pipe, resolves each pipe's **owning process** via
`GetNamedPipeServerProcessId`, lists the loopback listeners, and pokes 9180.

Read the result like this:

| Outcome | Meaning | Next |
|---|---|---|
| A pipe is owned by **`lghub_updater.exe`** | IPC is pipe-based → the peer **is** identified by real PID and signature-verified (`FUN_140c243e0` mode 1, fails closed) | The 9180 lead is probably **dead**. Still do step 2 to see what 9180 is, then stop. |
| **No** Logitech-owned pipe, and 9180 belongs to `lghub_updater` | The allow-all branch is the live path | Go to step 2 and 3. This is the good case. |
| Owner shows `<unreadable = likely SYSTEM>` | You can't read a SYSTEM process from a low-priv token — that is expected and is itself informative | Treat as "possibly the updater"; step 3 settles it. |

## Step 2 — What does 9180 actually speak? (5 minutes)

The previous session got `HTTP/1.0 404` on every URL. That is now **explained**: the updater
registers no URL routes at all — dispatch is on the numeric `content_type` field *inside* the
protobuf envelope. So URL probing was always going to 404.

```powershell
python ipc_probe.py --port 9180
```

`ipc_probe.py` is stdlib-only (no pip). It builds a real `HelloRequest` envelope — the encoder
was verified against `google.protobuf` on the Linux box — and tries it two ways:

1. **Raw framings** over the TCP socket: raw / 4-byte BE / 4-byte LE / varint-prefixed / HTTP POST.
2. **WebSocket**, which is the more likely one. The updater links **websocketpp** (68 string hits),
   and session 1 saw 9180 answer a well-formed `HTTP/1.0 404` — that is how a websocketpp server
   replies to a non-WebSocket request. The prober attempts an upgrade across paths
   `/`, `/ipc`, `/updater`, `/v1` and the two subprotocol names recovered from the binary
   (`logi.updater_ipc.protocol.v1.protobuf`, `logi.updater_ipc.protocol.protobuf`), plus no
   subprotocol. It validates `Sec-WebSocket-Accept`, captures anything the server pushes
   unprompted, then speaks `Envelope` over binary frames.

If the raw framings return nothing it falls through to the WebSocket attempt automatically. To run
only the WebSocket probe:

```powershell
python ipc_probe.py --port 9180 --ws
```

If nothing lands, widen the `content_type` sweep:

```powershell
python ipc_probe.py --port 9180 --scan-types 0 64
```

**Record the non-101 handshake responses too** — they are diagnostic. A `400` means the server
speaks WebSocket but rejected your subprotocol; a `404` means wrong path; a connection reset means
it is not an HTTP server at all. Do not treat "no 101" as "authenticated".

## Step 3 — THE TEST

If step 2 returns a protobuf response containing an `in_response_to_id` or an
`EndpointInformation` block, then a **SYSTEM service just completed a handshake with an
unsigned, non-elevated process whose identity was entirely self-declared.**

Capture, verbatim:
- the exact request bytes (hex) and framing that worked
- the full response bytes and the decoded fields
- `whoami`, `whoami /priv`, and the PID/path of your python process, to prove it was low-priv
- the PID/user of `lghub_updater.exe` from `Get-Process`, to prove the other end was SYSTEM

That pairing — low-priv client, SYSTEM server, successful handshake — **is the report.**

### If it does not respond
Do not conclude "authenticated" yet. Watch the legitimate client first: restart G HUB and observe
what `lghub_agent.exe` connects to. If the agent uses a pipe you missed, step 1's table will show
it once the agent is running. Re-run step 1 *while G HUB is actively updating*.

## Step 4 — Only if step 3 succeeded: prove impact

**Stop and think before running this.** Step 3 proves missing authentication; that alone is
usually enough for a report and is much safer. Step 4 proves code execution as SYSTEM, which is
what turns it from medium into high — but it changes system state.

Do it **in the `win11` VM, on a snapshot**, never on the daily-driver Windows install.

The relevant calls, all recovered in `protos/`:

```protobuf
RunLaunchableByAliasRequest { app_tag; depot_name; launchable_alias; wait }
InstallDepotExtensionRequest{ app_tag; depot_name; extension_name }
DepotExtensions.DepotExecutable { pipeline_uri; repeated arguments }   // what actually runs
SetChannelRequest { app_tag; Channel{ pipeline_host; name; password; access_groups } }
```

Benign proof-of-execution only: get it to launch something inert that leaves a timestamped
artifact you can point at. **Do not** repoint `pipeline_host` at anything you do not control, and
do not touch the real update channel on a machine you care about.

---

## Reporting rules — do not skip

Run the 7-question gate (it is in `FEDORA-SESSION-RESULTS.md` §7, already filled in for this lead;
question 6 is the one currently failing).

- **No theoretical bugs.** "The endpoint looks unauthenticated" is not a finding. A completed
  handshake from a low-priv process is.
- Check the **Logitech program's own Hacktivity tab** before submitting (not global H1 search —
  it is useless for these terms).
- This is **distinct from the 2018 Ormandy / Logitech Options bug**: different product, different
  transport (not a browser-reachable WebSocket), different protocol, and the impact is local
  privesc rather than keystroke injection. Say so explicitly in the report so triage doesn't
  reflexively dupe it.
- Do **not** claim browser reachability. This is a local-process attack. An attacker needs
  existing code execution as a normal user; the gain is SYSTEM. That is a legitimate and
  well-understood impact — state it precisely and do not inflate it.

## Do NOT re-do (settled, see FEDORA-SESSION-RESULTS.md)

- Install-dir ACLs, DLL hijacking, unquoted service paths, signature checks — all clean.
- Updater MITM — no plaintext HTTP endpoint.
- `ProgramData\LGHUB` write access — hardened, `Everyone:(RX)`.
- Depot path-traversal check — correctly implemented (canonicalises first, checks the separator
  boundary).
- The Overwolf 45654 origin issue — downgraded; React escapes the injected names and the list only
  renders when Overwolf is actually installed.
