# Logitech G HUB — Windows pending testing

**Status:** static analysis done on Linux, runtime testing PENDING on Windows.
**Program:** Logitech (HackerOne) — 9 downloadable executables, 6 bounty-eligible,
paid high/critical, ~1h median first response, Safe Harbor explicit.
**Machine:** test on native Windows (Logitech mice attached — G HUB with no device
attached exposes far less surface: macros and device config need real hardware).

> Re-verify current scope on the H1 program page before testing. Scope data is from a
> 2026-09-07 `bounty-targets-data` snapshot.

---

## 1. What's already established (done on Linux, don't redo)

Analysed `lghub_installer.exe`, 68 MB, PE32+ x86-64, built 2026-08-18
`sha256 4b2f9903b27c8434afcd52fe65845632fcae47cc50432fb6b3b1637144e811e1`
Source: `https://download01.logi.com/web/ftp/pub/techsupport/gaming/lghub_installer.exe`

| Finding | Consequence |
|---|---|
| **No plaintext HTTP update/download endpoint.** Every `http://` string is DigiCert/Microsoft CRL+OCSP (HTTP by design), XML schema namespaces, or font copyright text. | **Updater-MITM hypothesis is dead. Don't spend a session on it.** |
| Installer is a .NET bootstrapper `2026.4.9028.0`, DigiCert code-signed | Real artifacts only exist post-install; the bootstrapper is a dead end |
| **libcurl bundled** (`curl.se/docs/hsts.html`, `alt-svc`, `http-cookies`) | Downloads go via curl → open question is whether `SSL_VERIFYPEER` is disabled. Needs binary analysis of the installed updater, not strings. |
| **Chromium Crashpad bundled** | Electron frontend confirmed → `app.asar` exists post-install |
| One S3 reference `https://2pipeline.s3.amazonaws.com` | Noted only. Unverified, may not be Logitech's. No claim made. |

---

## 2. Bug-class priority (one at a time — go deep, don't spray)

**Primary: the elevated updater service.** Repeatedly flagged in public discussion as a
concern (elevated, persistent, DLL-hijack / MITM potential) with **zero published research**.
Least saturated. MITM half is already ruled out above, so focus on **DLL hijacking, binary
planting, and writable service paths**.

**Secondary (15 min, high payoff): the local WebSocket server.**
The obvious angle *because* of history — see §5 — so expect competition. Worth checking
purely because G HUB is a **different codebase** from Options, and a fix applied to one
product line and missed in another is a genuine non-duplicate finding.

**Do NOT do natively:** driver IOCTL fuzzing (will BSOD). Needs the `win11` VM.

---

## 3. Commands to run, in order

### 3a. Locate the install and the listening socket
```
netstat -anob | findstr LISTENING
dir /s /b "%LOCALAPPDATA%\LGHUB" 2>nul | findstr /i "asar exe dll"
dir /s /b "C:\Program Files\LGHUB" 2>nul | findstr /i "asar exe dll"
```
**Looking for:** a localhost listener owned by an lghub process (historically ~9010), and
the path to `resources\app.asar`.

### 3b. Service configuration
```
sc queryex type=service state=all | findstr /i "lghub logi"
sc qc <ServiceName>
wmic service where "name like '%%lghub%%'" get name,pathname,startmode,startname
```
**Looking for:** `START_NAME: LocalSystem`, and any **unquoted path containing spaces**.

### 3c. Writable paths = binary planting / DLL hijack
```
accesschk.exe -uwdqs "Authenticated Users" "C:\Program Files\LGHUB"
accesschk.exe -uwqs  "Authenticated Users" "C:\Program Files\LGHUB\*"
accesschk.exe -uwdqs "Users" "%LOCALAPPDATA%\LGHUB"
accesschk.exe -uwcqv "Authenticated Users" *
```
**Looking for:** any dir in a SYSTEM service's path that a normal user can write to.
That is the finding — a service running as SYSTEM loading a DLL from a user-writable dir.

### 3d. DLL hijack candidates (Procmon)
Filter: `Process Name` contains `lghub` **AND** `Result` is `NAME NOT FOUND` **AND**
`Path` ends with `.dll`. Restart the service / trigger an update check while capturing.
**Looking for:** probed DLL paths that don't exist and sit in a writable dir.

### 3e. Signature check
```
sigcheck.exe -e -u -s "C:\Program Files\LGHUB"
```
**Looking for:** unsigned executables/DLLs shipped in a privileged directory.

### 3f. WebSocket (secondary)
```
:: from 3a, get the port. Then from a browser console on ANY http(s) page:
::   new WebSocket("ws://127.0.0.1:<PORT>")
:: -> does it connect? Is Origin rejected?
```
**Looking for:** connection accepted with a foreign `Origin`. If accepted, check whether
auth is the same brute-forceable PID scheme from 2018 (see §5) before writing it up.

---

## 4. Bring back to the Linux box

- [ ] `app.asar` — I can parse it here (JSON header + concatenated files, Python extractor)
      and read the WebSocket handler to answer the Origin-validation question definitively
- [ ] Output of 3b and 3c (paste as text)
- [ ] The updater service binary, if you want it reversed
- [ ] Procmon export from 3d (CSV)

---

## 5. Duplicate check — READ BEFORE WRITING ANYTHING UP

**Logitech Options, 2018, Tavis Ormandy / Project Zero.** Options opened a WebSocket server
reachable from **any website**. The only "authentication" was supplying a **PID owned by your
user**, with **unlimited guesses** — brute-forceable in microseconds. Allowed changing settings
and **injecting arbitrary keystrokes**. Ormandy met Logitech 2018-09-18; they promised **Origin
checks and type checking**; the Oct 1 release didn't fix it; he **publicly disclosed 2018-12-11**.

Searches run 2026-09-07 found **no public G HUB WebSocket vulnerability** and no CVE with
technical detail for 2024–2025.

Implications:
- A naive "no Origin validation" report is likely **known-issue** territory. If you find it,
  frame it as *"the 2018 Options fix was never applied to G HUB's separate codebase."*
- Before submitting, check the **Logitech program's own Hacktivity tab** (not global search —
  global full-text matches "hub"/"websocket" everywhere and is useless), and confirm whether
  Logitech discloses at all. If they don't, hacktivity proves nothing either way.

Sources: Threatpost `threatpost.com/logitech-keystroke-injection-flaw/139928/`,
TechTarget `searchsecurity/news/252454414`, SC Media, CVEdetails vendor_id-944.

---

## 6. Gate before writing a report

1. Actually a security vulnerability?  2. In scope?  3. Duplicate?  4. Reproduces reliably?
5. Actual impact?  6. Exploitable (working PoC)?  7. Would the platform accept it?

**Do not submit unquoted-service-path or DLL-hijack without demonstrating actual elevation.**
Both are routinely closed as informative when unproven. If 3c/3d turn up a writable path,
that's the trigger to spin up Hyper-V (or the `win11` VM here) and build the real
low-priv → SYSTEM PoC.
