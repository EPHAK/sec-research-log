# WHAT DO I DO — Logitech G HUB, Windows session

You are on Windows. **No tools installed. None needed** — everything below is built into Windows.
Everything here is **read-only**. Nothing gets installed, started, stopped, or modified.

---

## THE ONE THING TO DO

1. Open **PowerShell as Administrator** (Start → type `powershell` → right-click → Run as administrator)
2. Run this — it fetches nothing, it's all local:

```powershell
cd $env:USERPROFILE
# if you have the repo cloned:
#   powershell -ExecutionPolicy Bypass -File .\sec-research-log\bugbounty\logitech-ghub\ghub-recon.ps1
```

**If you don't have the repo on Windows** (likely), just open `ghub-recon.ps1` from GitHub in a
browser, click **Raw**, select-all, copy, and **paste the whole thing into the admin PowerShell
window**. Pasting sidesteps execution-policy problems entirely.

3. It writes everything to **`C:\ghub-recon\`** and copies `app.asar` in there too.
4. **Zip `C:\ghub-recon` and get it back to the Linux box.** That's the deliverable.

That's it. ~2 minutes.

---

## What it collects (and why)

| File | What it answers |
|---|---|
| `05_WRITABLE_IN_PRIVILEGED_PATHS.txt` | **The money check.** Any file/dir under a SYSTEM service's path that `Users`/`Authenticated Users`/`Everyone` can write to. That's a privesc candidate — DLL planting or binary replacement against a service running as SYSTEM. |
| `02b_listening_logi.txt` | The **WebSocket port** and which process owns it. Historically ~9010. |
| `07b_signatures_UNSIGNED.txt` | Unsigned `.exe`/`.dll`/`.sys` shipped in a privileged directory — loadable without integrity checks. |
| `04_unquoted_service_paths.txt` | Unquoted service paths with spaces (any vendor, cheap win). |
| `08b_named_pipes_logi.txt` | The IPC surface between the UI and the elevated service. |
| `03_services.txt` | Service account (`LocalSystem`?), start mode, binary path. |
| **`app.asar`** | **Bring this back.** It's the Electron frontend. The WebSocket protocol and any `Origin` validation live in here as readable JS. I'll extract and read it on the Linux box. |

---

## Reading the output yourself (if you want a fast signal)

- **`05_...WRITABLE...`** — if this file is **not empty**, that's the most interesting result of
  the whole run. Any hit where `IsDir=True` under `C:\Program Files\LGHUB` is a strong lead.
- **`07b_...UNSIGNED`** — non-empty means unsigned binaries in a privileged path.
- **`02b_listening_logi`** — note the port. If you want the 15-second WebSocket check, open any
  website, hit F12, and in the console run:
  ```js
  new WebSocket("ws://127.0.0.1:PORT")
  ```
  If it **connects** from a foreign origin, that's the Origin-validation question answered.
  (See the duplicate-check note before getting excited — §5 of `windows-pending-testing.md`.)

---

## Do NOT do these natively

- Driver IOCTL fuzzing → **will bluescreen you**. That belongs in the `win11` VM on the Linux box.
- Updater MITM → needs a CA cert in your system trust store. Also already ruled out: static
  analysis found **no plaintext HTTP update endpoint**, so don't spend time on it.
- Any actual privesc PoC execution → do that in the VM, after recon says there's something there.

---

## Optional, only if you want more later

Sysinternals (Procmon for DLL-hijack hunting) is a single zip, no install:
`https://download.sysinternals.com/files/SysinternalsSuite.zip`
Not needed for the run above.

---

## Before writing anything up

Run the 7-Question Gate: (1) actually a vulnerability, (2) in scope, (3) duplicate,
(4) reproduces reliably, (5) actual impact, (6) exploitable with a working PoC,
(7) would the platform accept it.

**Do not submit unquoted-service-path or DLL-hijack findings without demonstrating actual
elevation** — both get closed as informative when unproven. A writable path is the *trigger to
build a PoC in the VM*, not a finding on its own.

Duplicate-check context (2018 Ormandy / Logitech Options) is in `windows-pending-testing.md` §5.
Read it before submitting anything WebSocket-related.
