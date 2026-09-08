<#
  run-session.ps1 - Logitech G HUB, Windows session #3. One script, the whole session.

  Produced by the Fedora static-analysis session #4. Background: pipe-framing.md.

  WHAT IT DOES  (all read-only except step D, which creates and deletes scratch files)
    A. context - user, elevation, PowerShell version, G HUB build
    B. confirm the updater's pipe exists and we can open it
    C. the handshake test - one HelloRequest to the SYSTEM updater  (hello-probe.ps1)
    D. does logi_features.cfg already exist anywhere in the search path?
    E. icacls on the three directories in that search path
    F. empirical write test - can a non-admin create a FILE (not just a folder) there?
    G. ProgramData\LGHUB feature-cache check

  WHAT IT DOES NOT DO
    It never writes logi_features.cfg. It never sends an installer, pipeline or
    launchable command. Those need an explicit decision - see the VERDICT block.

  RUN IT NON-ELEVATED, as an ordinary user. That is the threat model.

      powershell -ExecutionPolicy Bypass -File .\run-session.ps1

  Everything is also written to  %USERPROFILE%\Desktop\logi-session4\transcript.txt
#>

[CmdletBinding()]
param(
    [string]$PipeName = 'a62ed1c1-e1a9-5495-9038-16bd49ec7341',
    [switch]$SkipHandshake
)

# NOTE: deliberately NOT using Set-StrictMode or $ErrorActionPreference='Stop' here.
# Every step is individually guarded; one failing check must never abort the session.
# (find-logi-endpoint.ps1 v1 died silently and cost a whole session.)

$OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'logi-session4'
try { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null } catch { $OutDir = $PWD.Path }
$Transcript = Join-Path $OutDir 'transcript.txt'
$script:Findings = New-Object System.Collections.Generic.List[string]

function Say {
    param([string]$Text, [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    try { Add-Content -Path $Transcript -Value $Text -Encoding UTF8 } catch { }
}
function Head { param([string]$T) Say ''; Say ("=" * 78) 'Cyan'; Say $T 'Cyan'; Say ("=" * 78) 'Cyan' }
function Step {
    param([string]$Name, [scriptblock]$Body)
    # Promote non-terminating errors to terminating INSIDE the step, so a cmdlet that
    # merely writes to the error stream (Join-Path on a missing drive, icacls, ...) is
    # caught here instead of spraying red text and continuing in an unknown state.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try { & $Body }
    catch { Say ("  [step '{0}' failed: {1}]" -f $Name, $_.Exception.Message) 'DarkYellow' }
    finally { $ErrorActionPreference = $prev }
}

Say "logi-session4  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Say "output dir: $OutDir"

# This script is Windows-only. Off Windows, paths like C:\ are ordinary relative names and
# the write tests would "succeed" for the wrong reason - a false WRITABLE in the verdict.
$IsWin = $true
try { if ($PSVersionTable.PSVersion.Major -ge 6) { $IsWin = $IsWindows } } catch { }
if (-not $IsWin) {
    Say ''
    Say 'THIS IS NOT WINDOWS. The filesystem checks below are meaningless here and are' 'Red'
    Say 'DISABLED so they cannot produce a false WRITABLE result. Run this on the target.' 'Red'
}

# ------------------------------------------------------------------ A. context
Head 'A. CONTEXT'
Step 'identity' {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $elev = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Say "user       : $($id.Name)"
    Say "elevated   : $elev"
    if ($elev) {
        Say '  !! You are ELEVATED. Every result below is meaningless for the threat model.' 'Red'
        Say '  !! Re-run from a normal, non-elevated PowerShell.' 'Red'
        $script:Findings.Add('RUN WAS ELEVATED - results invalid, re-run non-elevated')
    }
}
Step 'psversion' { Say "powershell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" }
Step 'os'        { Say "os         : $((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version)" }
Step 'ghubver'   {
    $v = Get-ChildItem 'C:\Program Files\LGHUB\lghub_*.exe' -ErrorAction Stop |
         ForEach-Object { '{0} {1}' -f $_.Name, $_.VersionInfo.FileVersion }
    $v | ForEach-Object { Say "  $_" }
    Say '  (scope is LATEST version only - confirm this is current before submitting anything)' 'DarkGray'
}
Step 'procs' {
    Get-Process lghub_*, logi_* -ErrorAction SilentlyContinue |
      Select-Object Id, ProcessName | ForEach-Object { Say ("  pid {0,-8} {1}" -f $_.Id, $_.ProcessName) }
}

# --------------------------------------------------------------- B. the pipe
Head 'B. THE UPDATER PIPE'
Say "expected name (hardcoded literal in lghub_updater.exe and lghub_agent.exe):"
Say "  \\.\pipe\$PipeName"
$pipePresent = $false
Step 'enumerate' {
    $all = @([System.IO.Directory]::GetFiles('\\.\pipe\'))
    Say "  $($all.Count) named pipes visible"
    $hit = $all | Where-Object { $_ -like "*$PipeName*" }
    if ($hit) { $script:pipePresent = $true; Say "  FOUND: $hit" 'Green' }
    else {
        Say "  NOT FOUND - the GUID may have changed in this build." 'Yellow'
        Say "  GUID-shaped pipes present:" 'Yellow'
        $all | Where-Object { $_ -match '[0-9a-f]{8}-[0-9a-f]{4}-' } | ForEach-Object { Say "    $_" }
        $script:Findings.Add('Updater pipe GUID not found - re-read FUN_140e04ef0 in the new build')
    }
}
Step 'open' {
    $p = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $p.Connect(3000)
    Say "  opened it from this non-elevated process -> the DACL admits us" 'Green'
    Say "  (matches the Everyone:0x1FFFFF descriptor read out of the binary)"
    $p.Dispose()
}

# ------------------------------------------------------------ C. the handshake
Head 'C. THE HANDSHAKE TEST'
if ($SkipHandshake) { Say '  skipped (-SkipHandshake)' }
else {
    $probe = Join-Path $PSScriptRoot 'hello-probe.ps1'
    if (-not (Test-Path $probe)) {
        Say "  hello-probe.ps1 not found next to this script ($probe)" 'Red'
    } else {
        Say '  running hello-probe.ps1 -SelfTestOnly first (validates the encoder on THIS PowerShell)...'
        & $probe -SelfTestOnly 2>&1 | ForEach-Object { Say "    $_" }
        if ($LASTEXITCODE -ne 0) {
            Say '  SELF-TEST FAILED - not running the real probe. Report this; do not trust a result.' 'Red'
            $script:Findings.Add('hello-probe.ps1 self-test FAILED on this PowerShell - encoder bug')
        } else {
            Say ''
            Say '  running the real handshake...'
            $out = & $probe -PipeName $PipeName 2>&1
            $out | ForEach-Object { Say "    $_" }
            if ($out -match 'REPLIED TO AN UNSIGNED') {
                $script:Findings.Add('*** SYSTEM updater COMPLETED A HANDSHAKE with an unsigned non-elevated peer ***')
            } elseif ($out -match 'DROPPED') {
                $script:Findings.Add('Handshake DROPPED - accept-time signature check is enforced (expected)')
            } elseif ($out -match 'CONNECT FAILED') {
                $script:Findings.Add('Could not connect to the pipe - DACL may be the boundary after all')
            }
        }
    }
}

# ------------------------------------------- D. does logi_features.cfg exist?
Head 'D. logi_features.cfg - DOES IT ALREADY EXIST?'
Say 'Search path (resolved by walking UP from the exe directory; first match wins):'
$SearchDirs = @('C:\Program Files\LGHUB\', 'C:\Program Files\', 'C:\')
foreach ($d in $SearchDirs) {
    Step "exists $d" {
        $f = [System.IO.Path]::Combine($d, 'logi_features.cfg')
        if (Test-Path $f) {
            Say "  EXISTS: $f" 'Yellow'
            Say '  ---- contents ----'
            Get-Content $f -ErrorAction SilentlyContinue | ForEach-Object { Say "  | $_" }
            Say '  ------------------'
            $script:Findings.Add("logi_features.cfg already present at $f - read it")
        } else { Say "  absent : ${d}logi_features.cfg" }
    }
}
Say ''
Say 'Reminder - the line that disables the check is exactly:   llc_check = 0'
Say 'accepted values: 0|1|false|true|off|on|yes|no   (key must be lowercase a-z0-9 . _ and spaces)'

# ------------------------------------------------------------------ E. icacls
Head 'E. ACLs ON THE SEARCH PATH'
Say 'What matters: does Users / Authenticated Users / INTERACTIVE / your account have'
Say '(W), (M), (F) or specifically WD (create files) - NOT just AD (create folders).'
Say ''
foreach ($d in $SearchDirs) {
    Step "icacls $d" {
        Say "---- icacls `"$d`" ----" 'White'
        $r = & icacls $d 2>&1 | Out-String -Stream
        $r | ForEach-Object { Say "  $_" }
        try { $r | Out-File -FilePath (Join-Path $OutDir ('icacls_' + ($d -replace '[:\\ ]','_') + '.txt')) -Encoding UTF8 } catch {}
    }
}

# ----------------------------------------------------- F. empirical write test
Head 'F. EMPIRICAL WRITE TEST (creates and deletes scratch entries)'
Say 'ACL output is easy to misread. This tests it directly. It uses a scratch name, NOT'
Say 'logi_features.cfg, so nothing about the service changes either way.'
Say ''
foreach ($d in $SearchDirs) {
    Step "write $d" {
        if (-not $IsWin) { Say "  $d  -- skipped, not Windows"; return }
        if (-not [System.IO.Path]::IsPathRooted($d) -or -not [System.IO.Directory]::Exists($d)) {
            Say "  $d  -- directory does not exist; test skipped (a result here would be meaningless)" 'Yellow'
            return
        }
        $fileOk = $false; $dirOk = $false; $fileErr = ''; $dirErr = ''
        $tf = [System.IO.Path]::Combine($d, 'zz_logi_write_probe.tmp')
        try {
            [System.IO.File]::WriteAllText($tf, 'probe')
            # Only believe it if the file is actually there, at the path we intended.
            if ([System.IO.File]::Exists($tf)) { $fileOk = $true } else { $fileErr = 'write reported success but the file is not there' }
            [System.IO.File]::Delete($tf)
        } catch { $fileErr = $_.Exception.Message }
        $td = [System.IO.Path]::Combine($d, 'zz_logi_dir_probe')
        try {
            [System.IO.Directory]::CreateDirectory($td) | Out-Null
            if ([System.IO.Directory]::Exists($td)) { $dirOk = $true }
            [System.IO.Directory]::Delete($td)
        } catch { $dirErr = $_.Exception.Message }

        if ($fileOk) {
            Say "  $d" 'Red'
            Say "     CREATE FILE   : YES  <-- logi_features.cfg can be planted here" 'Red'
            $script:Findings.Add("*** WRITABLE: a non-admin can create a FILE in $d - llc_check is settable ***")
        } else {
            Say "  $d"
            Say "     create file   : denied  ($fileErr)"
        }
        if ($dirOk) { Say "     create folder : yes  (this is the normal Windows default on C:\ - folders only, not files)" }
        else        { Say "     create folder : denied" }
    }
}

# ------------------------------------------------------------- G. ProgramData
Head 'G. ProgramData\LGHUB - THE OTHER POSSIBLE FLAG SOURCE'
Say 'Loose end from the Fedora side: GetFeatureFlag''s map was traced to one populate path'
Say '(logi_features.cfg). The binary also has a FeatureCanary subsystem with its own'
Say 'get_flag and a downloadable features config depot. If that feeds the same map and its'
Say 'cache is writable, that is a second route to llc_check = 0.'
Say ''
Step 'features files' {
    $f = Get-ChildItem 'C:\ProgramData\LGHUB' -Recurse -Include features*.json,*.cfg -ErrorAction SilentlyContinue
    if ($f) { $f | ForEach-Object { Say ("  {0,-70} {1,8} bytes  {2}" -f $_.FullName, $_.Length, $_.LastWriteTime) } }
    else    { Say '  no features*.json / *.cfg found under C:\ProgramData\LGHUB' }
}
Step 'icacls programdata' {
    Say '---- icacls "C:\ProgramData\LGHUB" ----' 'White'
    (& icacls 'C:\ProgramData\LGHUB' 2>&1 | Out-String -Stream) | ForEach-Object { Say "  $_" }
}
Step 'write programdata' {
    if (-not $IsWin) { Say '  skipped, not Windows'; return }
    if (-not [System.IO.Directory]::Exists('C:\ProgramData\LGHUB')) {
        Say '  C:\ProgramData\LGHUB does not exist; test skipped' 'Yellow'; return
    }
    $tf = 'C:\ProgramData\LGHUB\zz_logi_write_probe.tmp'
    try {
        [System.IO.File]::WriteAllText($tf,'probe')
        if ([System.IO.File]::Exists($tf)) {
            Say '  CREATE FILE in C:\ProgramData\LGHUB : YES' 'Red'
            $script:Findings.Add('*** WRITABLE: non-admin can create files in C:\ProgramData\LGHUB ***')
        } else { Say '  create file in C:\ProgramData\LGHUB : reported success but file absent - ignore' 'Yellow' }
        [System.IO.File]::Delete($tf)
    } catch { Say "  create file in C:\ProgramData\LGHUB : denied  ($($_.Exception.Message))" }
}

# ------------------------------------------------------------------- VERDICT
Head 'VERDICT'
if ($script:Findings.Count -eq 0) { Say '  (nothing recorded - check the sections above for errors)' 'Yellow' }
foreach ($f in $script:Findings) {
    if ($f.StartsWith('***')) { Say "  $f" 'Red' } else { Say "  $f" }
}
Say ''
Say 'HOW TO READ THIS:'
Say ''
Say '  Handshake DROPPED  +  all three dirs deny file creation'
Say '      -> The check is enforced and the flag is not attacker-settable on this machine.'
Say '         The engagement closes, honestly, with evidence. Say so plainly. No report.'
Say ''
Say '  Handshake DROPPED  +  some dir allows a non-admin to create a FILE'
Say '      -> The lead is live. Next step needs an explicit decision, because it modifies a'
Say '         SYSTEM service config and needs a reboot to take effect:'
Say '             Set-Content <thatdir>\logi_features.cfg ''llc_check = 0''   ; reboot ; re-run'
Say '         A reply after that is the full chain: unprivileged file write -> SYSTEM IPC'
Say '         accepts any peer -> RunLaunchableByAliasRequest is SYSTEM code execution.'
Say '         DELETE the file afterwards and confirm the probe returns to DROPPED.'
Say '         Do NOT send RunLaunchableByAliasRequest. The handshake is proof enough.'
Say ''
Say '  Handshake REPLIED right now'
Say '      -> Stop. That is the report on its own, and it means llc_check is already 0 on'
Say '         this machine - section D should show why.'
Say ''
Say 'Note on ACLs: the Windows default on C:\ grants Authenticated Users (AD) - create'
Say 'FOLDERS - but not WD - create FILES. So "create folder: yes / create file: denied" is'
Say 'the expected stock result and means NOT exploitable. Do not report a folder-create as a'
Say 'file-write primitive.'
Say ''
Say "transcript: $Transcript"
