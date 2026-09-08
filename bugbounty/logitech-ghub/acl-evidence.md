# ACL evidence — read directly off the target disk, not assumed

**This machine dual-boots into the same Windows install this engagement has been analysing.**
The Windows volume is mounted read-write at `/run/media/ephak/OS` via ntfs-3g. Confirmed
same install, not a lookalike:

```
sha256sum "OS:\Program Files\LGHUB\lghub_updater.exe"  ==  bin/lghub_updater.exe
```

ntfs-3g exposes each file's raw self-relative `SECURITY_DESCRIPTOR` as the
`system.ntfs_acl` extended attribute. `sd_decode.py` (checked in) parses it — owner SID,
DACL, every ACE's trustee, inheritance flags, and access mask — without going through any
Windows API. This is the same bytes `icacls` would read; it does not depend on being logged
into Windows.

## The question this answers

Task 1 (`pipe-framing.md` §6) found that the pipe's accept-time signature check is gated on
the feature flag `llc_check` (default 1), read from `logi_features.cfg`, searched:

```
1.  C:\Program Files\LGHUB\logi_features.cfg
2.  C:\Program Files\logi_features.cfg
3.  C:\logi_features.cfg
```

Two things decide whether that is exploitable: does the file already exist, and can an
unprivileged principal *create* one (not just a folder) in any of the three directories.

## 1. The file does not exist

```
absent: C:\Program Files\LGHUB\logi_features.cfg
absent: C:\Program Files\logi_features.cfg
absent: C:\logi_features.cfg
```

`llc_check` is at its compiled-in default (1 = enforced) on this machine right now.

## 2. No non-admin principal can create a file in any of the three directories

### `C:` — DACL (`sd_root.hex`, checked in)

| Trustee | Mask | Flags | Grants |
|---|---|---|---|
| BUILTIN\Administrators | `0x001f01ff` | OI CI | full control |
| SYSTEM | `0x001f01ff` | OI CI | full control |
| BUILTIN\Users | `0x001200a9` | OI CI | **read-only** — list, read, traverse, read attrs |
| Authenticated Users | `0xe0010000` | OI CI **InheritOnly** | applies only to *new children*, not to `C:\` itself |
| **Authenticated Users** | **`0x00000004`** | **not inherited** | **`FILE_ADD_SUBDIRECTORY` only — create folders** |
| AppContainer (S-1-15-3-…) | `0x001000a1` | — | read-only |

The one non-admin write grant on `C:\` itself is bit `0x4`, `FILE_ADD_SUBDIRECTORY`.
**Bit `0x2`, `FILE_ADD_FILE`, is not set in any ACE for any non-admin trustee.** A
non-admin account can create `C:\SomeFolder\`; it cannot create `C:\logi_features.cfg`.

### `C:\Program Files` and `C:\Program Files\LGHUB` (`sd_pf.hex`, `sd_lghub.hex`)

Both carry the same shape: TrustedInstaller / SYSTEM / Administrators get full control;
`BUILTIN\Users`, `ALL APPLICATION PACKAGES` and `ALL RESTRICTED APPLICATION PACKAGES` get
the identical read-only mask `0x001200a9`; `CREATOR OWNER` only matters for objects a
non-admin already owns. **There is no ACE anywhere on either directory that grants a
non-admin principal any write bit, inherited or not.** Stricter than `C:\` — not even folder
creation.

## Verdict

**On this machine,  is not attacker-settable by any unprivileged account.** No
directory in the search path admits a non-admin file write; the file doesn't currently exist
to abuse anyway. Combined with the exact-match publisher compare and the closed 9180 lead
(both in `pipe-framing.md`), **every static-analysis-reachable route to disabling the pipe's
accept-time signature check is closed, with evidence, not inference.**

This does not by itself prove the pipe drops an unsigned peer at the *default* flag value —
that is still the one thing that needs a live handshake, because it is the only claim in this
whole engagement that static analysis (now including live ACL reads) cannot settle. Run
`windows/run-session.ps1` once for that; expect `DROPPED`, and if you get it, this
engagement is done — write it up as no finding.

## Caveat

This is the DACL Windows will enforce, read from disk. It does not model Mandatory Integrity
Control labels (none are set on any of these three objects — no SACL entries with the
mandatory-label ACE type were present) or third-party filter drivers/AV that might further
restrict access. It is stronger evidence than "the Windows default is usually X", and it is
the real machine, not a guess — but the live `icacls` run in `run-session.ps1` §E is still
worth doing as final confirmation, and it's the one open item.

## Reproduce

```bash
python3 handoff/sd_decode.py ""
python3 handoff/sd_decode.py ""
python3 handoff/sd_decode.py ""
```
