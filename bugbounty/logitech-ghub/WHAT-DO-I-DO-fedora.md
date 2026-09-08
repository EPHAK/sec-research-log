# WHAT DO I DO — Logitech G HUB, Fedora session #2

Paste this file into a fresh assistant session on the Fedora box, together with
`FEDORA-SESSION-RESULTS.md` and `WINDOWS-SESSION-2-RESULTS.md`.

**Read `WINDOWS-SESSION-2-RESULTS.md` first.** The lead you were chasing is dead. `lghub_updater.exe`
owns a GUID-named pipe (`\\.\pipe\a62ed1c1-…`), so `FUN_140c243e0` takes the **enforced** mode-1
branch, and TCP 9180 returned a byte-identical 404 to six WebSocket upgrades — it is a routeless
stub, not the IPC.

**Do not re-derive the 9180 argument. Do not re-open §2, §4 or §5 of the old handoff.**

There is exactly one live question left, and it is now a *Windows* experiment:

> Does the SYSTEM updater's pipe drop an unsigned, non-elevated peer?

Static analysis says yes (it should fail closed). This session's only job is to make that Windows
test **one shot instead of ten** — and to honestly try to break the "it fails closed" conclusion
before we accept it. Everything below is static analysis. Nothing here touches a running system.

---

## Task 1 — Resolve the decompiler ambiguity (highest value, do this first)

`FEDORA-SESSION-RESULTS.md` §2 flagged this caveat and never settled it:

> Decompiler argument recovery is unreliable here. The call site passes three arguments; Ghidra
> rendered the body with one. Which of `conn+0x34` / `server+0x60` is the selector is an *inference*.

That inference is now load-bearing in the opposite direction — we are about to conclude "enforced"
on the strength of it. Settle it properly.

In Ghidra, on `lghub_updater.exe`:

1. Retype `FUN_140c243e0` by hand to the three-argument signature the call site actually passes.
   Ghidra's auto-analysis collapsed it; fix the prototype and re-decompile.
2. Answer: **which parameter is the mode selector**, and **what writes it**. Trace back from
   `LocalServerImpl` construction (`FUN_140c25970` reads `param_1[0xc]`, i.e. `server+0x60`).
3. Answer: **can that selector ever be 0 in a shipped configuration?** If the enum is
   `{0 = local/trusted, 1 = verify}`, find every construction site and record the literal passed.
   If *any* reachable site passes 0, the allow-all branch is live on some transport and the lead
   is back — on the pipe this time, not on 9180.

**Record the answer either way.** "Mode 0 is unreachable in shipped builds" is the sentence that
actually closes this engagement; we do not have it yet.

## Task 2 — What is 9180, and does anything else listen?

We know 9180 answers a constant 404 and registers no routes. Close the loop cheaply:

- Find what constructs the HTTP server bound to 9180 in `lghub_updater.exe`. Is it crashpad, a
  Sentry/telemetry handler, a health endpoint, or dead code from a removed feature?
- Confirm there is no second, route-carrying HTTP server in the binary.
- If 9180 turns out to be a *crash-report upload receiver*, say so — that is a different (and
  much less interesting) attack surface, and it should be written down so nobody re-probes it.

Low value, but it is 20 minutes and it prevents a fourth session rediscovering port 9180.

## Task 3 — Recover the pipe framing, so the Windows PoC is one shot

This is the deliverable the Windows box actually needs.

We have the `Envelope` message and all 69 descriptors. What we do **not** have is how an envelope
is delimited on the wire over a named pipe. `ipc_probe.py` guessed five framings for TCP; over a
pipe the answer is knowable statically.

From `logi::local_connection::impl::LocalServerImpl` and its client-side counterpart, recover:

1. **Pipe mode.** Is the pipe created with `PIPE_TYPE_MESSAGE` or `PIPE_TYPE_BYTE`? Message mode
   means one envelope per `WriteFile` and **no length prefix at all** — that single fact decides
   the framing. Find the `CreateNamedPipeW` call that is *not* crashpad's
   (`\\.\pipe\crashpad_%lu_`) and read its `dwPipeMode`.
2. **Length prefix, if byte mode.** Width and endianness: 4-byte BE, 4-byte LE, or protobuf varint.
3. **Where the pipe name comes from.** It is a GUID, stable across runs within a boot. Is it
   derived (machine GUID? install id? a registry value? a `CoCreateGuid` at service start?) or
   read from a file under `C:\ProgramData\LGHUB`? This tells the PoC whether to enumerate or to
   compute — and if it is *derived from something predictable*, that is independently interesting.
4. **Protocol negotiation.** `HelloRequest.SupportedProtocols` is `repeated uint32`. Find the
   accepted values so the handshake is not rejected for a trivially wrong version.
5. **The `content_type` value for `HelloRequest`.** Dispatch is numeric. Find the router table that
   maps `content_type` → message type and dump it. Without this the Windows PoC is guessing across
   a 0–64 sweep; with it, the test is a single write.

**Deliverable:** a short `pipe-framing.md` plus the exact byte sequence for a minimal
`HelloRequest` envelope, hex, ready to paste. Include the `content_type` value and the framing.

## Task 4 — Is the signature check bypassable on its own terms?

Only after tasks 1 and 3. This is the one way the engagement comes back to life.

`FUN_140c1b1f0` resolves the peer as: `GetNamedPipeClientProcessId` → `OpenProcess(0x1000)` →
`GetProcessTimes` (anti-PID-reuse) → `QueryFullProcessImageNameA` → `WinVerifyTrust` against
`Logitech Inc[.]`. That is a well-built check. Look specifically for:

- **Does it verify the image on disk, or the running image?** If it path-resolves and then
  re-opens the file, there is a window between the path resolution and `WinVerifyTrust`.
  A Logitech-signed binary we can start ourselves and then... no — we cannot modify a file under
  `Program Files` (ACLs are clean). So this only matters if the resolved path can be made to point
  somewhere writable. Check whether the path is canonicalised, and whether a symlink/junction or a
  `\\?\`-prefixed or 8.3 short-name path could redirect it.
- **Is `WinVerifyTrust` called with revocation checking and a policy that rejects expired certs?**
  Note what `FUN_140a5ea70` (`FileCertificate::isTrustedByOS`) passes — a lax policy is a finding
  only if it lets a *non-Logitech* signer through, which the `Logitech Inc` string compare should
  prevent independently.
- **Is the publisher compared as a substring?** `Logitech Inc` vs `Logitech Inc.` are both accepted.
  If the compare is `strstr`-style rather than exact, a certificate with subject
  `Logitech Incorporated Evil Ltd` would pass. Read `FUN_140a5e960` carefully and say which it is.
- **What happens on the `LogitechSigned = 4` flag path?** `ConnectionStatusChangeBroadcast.Flags`
  has it. Is any privileged operation gated on that flag *separately*, and is any operation
  reachable **before** the flag is evaluated?

Read the actual bytes for each of these; do not infer from the function names. The publisher
compare in particular is worth reading instruction by instruction — `Logitech Inc` and
`Logitech Inc.` both being accepted is consistent with an exact compare against two literals *and*
with a substring match, and those two have very different consequences.

---

## What to send back

1. `pipe-framing.md` — task 3's deliverable, with the hex envelope.
2. The answer to task 1, stated as a sentence: *"mode 0 is / is not reachable in shipped builds,
   because …"*.
3. A one-line verdict on task 4.

I will run the pipe handshake on Windows with that in hand.

---

## Reporting rules — unchanged, do not skip

- Run the 7-question gate. Question 6 (working PoC) is still the one that fails, and no amount of
  further static analysis can satisfy it.
- **No theoretical bugs.** "The check looks bypassable" is not a finding.
- Check the **Logitech program's own Hacktivity tab** before submitting, not global H1 search.
- If this is distinct from the 2018 Ormandy / Logitech Options bug, say so explicitly in any
  report — different product, transport, protocol, and impact.
- Do **not** claim browser reachability. This is a local-process attack: attacker already has code
  execution as a normal user; the gain is SYSTEM. State it precisely; do not inflate it.

## Report what you find — in both directions

Do not predict the outcome before reading the code, and do not let the last three sessions'
closed leads set the expectation for this one. Several of those closures were correct; one
(`"no Logitech named pipe exists"`) was a false negative that survived a whole session and nearly
sent the Windows box chasing a dead lead. Priors are not evidence.

Two failure modes, equally bad:

- **Manufacturing.** Writing up "the check looks bypassable" without the bytes to prove it. The
  7-question gate exists to catch this; question 6 is not negotiable.
- **Rubber-stamping.** Concluding "correctly implemented" because the function names look right
  and the previous checks held up. The depot path-traversal check *was* correct — that says
  nothing about this one. Read the instructions.

If a task genuinely resolves clean, say so in one line and move to the next. If any of the four
opens a door — a reachable mode 0, a substring publisher compare, a derivable pipe name, an
operation reachable before the `LogitechSigned` flag — that is the finding, and it is worth the
whole engagement. Chase it.
