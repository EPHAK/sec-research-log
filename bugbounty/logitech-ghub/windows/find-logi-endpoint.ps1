<#
  Identifies the real IPC transport of the SYSTEM updater (lghub_updater.exe).
  Read-only. No tools to install - uses only built-in Windows APIs.
  Run as a NORMAL (non-elevated) user - that is the whole point of the test.

  Answers:
    1. Which named pipes exist, and which process owns each one.
    2. Whether lghub_updater.exe (SYSTEM) owns a pipe -> pipe transport, peer is verified.
    3. What is actually listening on TCP 9180, and whether it speaks WebSocket.

  Fixed 2026-09-08 (v2). The v1 script printed an EMPTY section 1 on every machine. Four defects:
    1. `$pid = 0`                   - $PID is a read-only automatic variable; assignment throws.
    2. `foreach (...) {} | Tee`     - a foreach STATEMENT cannot be piped (EmptyPipeElement).
    3. `$GENERIC_READ = 0x80000000` - parses as Int32 -2147483648; the uint marshal throws.
                                      [uint32]0x80000000 fails too. Must be [uint32]2147483648.
    4. `Split-Path -Leaf`           - returns EMPTY for pipe names containing '\', e.g.
                                      "Sessions\1\AppContainerNamedObjects\...", "LOCAL\mojo...".
                                      That is ~100 of ~158 pipes. The script then opened the pipe
                                      DIRECTORY repeatedly and got ERROR_INVALID_PARAMETER (87).
  Also added: FILE_READ_ATTRIBUTES fallback (GENERIC_READ alone is denied on most pipes), and a
  WebSocket-upgrade probe of 9180 (3.2), which is what actually kills the 9180 lead.
#>

$ErrorActionPreference = 'Continue'
$out = "$env:USERPROFILE\Desktop\logi-endpoint"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Add-Type -Namespace Win32 -Name Pipe -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share,
    IntPtr sec, uint disp, uint flags, IntPtr templ);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetNamedPipeServerProcessId(IntPtr h, ref uint pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
'@

$INVALID       = [IntPtr](-1)
$FILE_SHARE    = [uint32]3
$OPEN_EXISTING = [uint32]3
# fix 3: 0x80000000 is a negative Int32 in PowerShell; use the decimal form
$modes = @(
  @{ n = 'FILE_READ_ATTRIBUTES'; v = [uint32]128 },
  @{ n = 'GENERIC_READ';         v = [uint32]2147483648 }
)

# fix 4: build the prefix without embedding backslashes, and strip it by LENGTH, not Split-Path
$BS   = [string][char]92
$ROOT = $BS + $BS + '.' + $BS + 'pipe' + $BS

Write-Host "`n=== 1. Named pipes and their owning processes ===" -ForegroundColor Cyan

$raw   = @([System.IO.Directory]::GetFiles($ROOT))
$names = @($raw | ForEach-Object {
             if ($_.StartsWith($ROOT)) { $_.Substring($ROOT.Length) } else { $_ }
           } | Where-Object { $_ -ne '' })
Write-Host ("pipe entries: {0}   usable names: {1}" -f $raw.Count, $names.Count)

$rows = @()
$errs = @{}
function Bump([string]$k) { if ($script:errs.ContainsKey($k)) { $script:errs[$k]++ } else { $script:errs[$k] = 1 } }

foreach ($name in $names) {
    $done = $false
    foreach ($m in $modes) {
        if ($done) { break }
        $h = [Win32.Pipe]::CreateFileW(($ROOT + $name), $m.v, $FILE_SHARE,
                                       [IntPtr]::Zero, $OPEN_EXISTING, [uint32]0, [IntPtr]::Zero)
        if ($h -eq $INVALID) { Bump "open/$($m.n):$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"; continue }
        $opid = [uint32]0
        if ([Win32.Pipe]::GetNamedPipeServerProcessId($h, [ref]$opid)) {
            $proc  = Get-Process -Id $opid -ErrorAction SilentlyContinue
            $ppath = ''
            if ($proc) { try { $ppath = $proc.Path } catch { $ppath = '<path denied = elevated/SYSTEM>' } }
            $rows += [pscustomobject]@{
                Pipe = $name; OwnerPID = [int]$opid
                Owner = if ($proc) { $proc.ProcessName } else { "<unreadable = likely SYSTEM>" }
                Path  = $ppath
            }
            $done = $true
        } else { Bump "GetNamedPipeServerProcessId:$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
        [void][Win32.Pipe]::CloseHandle($h)
    }
    if (-not $done) {
        $rows += [pscustomobject]@{ Pipe = $name; OwnerPID = -1; Owner = '<could not open / query>'; Path = '' }
    }
}

Write-Host ("resolved owners: {0} / {1}" -f @($rows | Where-Object { $_.OwnerPID -ge 0 }).Count, $names.Count)
Write-Host "failure tally (expected: 231=ERROR_PIPE_BUSY, 5=ERROR_ACCESS_DENIED):"
$errs.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { Write-Host "  $($_.Key) x$($_.Value)" }

($rows | Sort-Object Owner, Pipe | Format-Table -AutoSize Pipe, OwnerPID, Owner, Path |
    Out-String -Width 300) | Set-Content -Encoding utf8 "$out\pipes_with_owners.txt"

Write-Host "`n>>> Pipes owned by a Logitech process (THE ANSWER):" -ForegroundColor Yellow
$logi     = @(Get-Process | Where-Object { $_.ProcessName -match 'lghub|logi' } | Select-Object Id, ProcessName)
$logiPids = @($logi | Select-Object -Expand Id)
$logi | ForEach-Object { Write-Host "  PID $($_.Id)  $($_.ProcessName)" }

$hit = @($rows | Where-Object {
            $logiPids -contains $_.OwnerPID -or
            $_.Owner -like '*unreadable*'   -or
            $_.Pipe  -match 'logi|lghub|ghub'
        })
$hitTxt = ($hit | Sort-Object Owner, Pipe | Format-Table -AutoSize Pipe, OwnerPID, Owner, Path | Out-String -Width 300)
if ($hit.Count -eq 0) { $hitTxt = "(no Logitech-owned pipe, no unreadable-owner pipe, no logi-named pipe)" }
Set-Content -Encoding utf8 "$out\pipes_logi.txt" -Value $hitTxt
Write-Host $hitTxt

Write-Host "`n=== 2. Logitech listeners ===" -ForegroundColor Cyan
$lisTxt = (Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalAddress -eq '127.0.0.1' } |
  ForEach-Object {
     $pr = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
     $pp = ''
     if ($pr) { try { $pp = $pr.Path } catch { $pp = '<path denied = elevated/SYSTEM>' } }
     [pscustomobject]@{ Port = $_.LocalPort; OwnerPID = $_.OwningProcess
                        Proc = if ($pr) { $pr.ProcessName } else { '<unreadable = SYSTEM>' }
                        Path = $pp }
  } | Sort-Object Port | Format-Table -AutoSize | Out-String -Width 220)
Set-Content -Encoding utf8 "$out\listeners.txt" -Value $lisTxt
Write-Host $lisTxt

Write-Host "`n=== 3. What does 9180 answer? ===" -ForegroundColor Cyan

function Probe([string]$label, [string]$req) {
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine("--- $label ---")
    try {
        $c = New-Object Net.Sockets.TcpClient
        $c.ReceiveTimeout = 1500
        $c.Connect('127.0.0.1', 9180)
        $s = $c.GetStream()
        $b = [Text.Encoding]::ASCII.GetBytes($req)
        $s.Write($b, 0, $b.Length); $s.Flush()
        Start-Sleep -Milliseconds 500
        $buf = New-Object byte[] 4096
        $n = 0
        try { $n = $s.Read($buf, 0, $buf.Length) } catch { [void]$sb.AppendLine("(read timeout / no data)") }
        if ($n -gt 0) { [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
        $c.Close()
    } catch { [void]$sb.AppendLine("ERROR: $_") }
    [void]$sb.AppendLine("")
    return $sb.ToString()
}

$nl  = "`r`n"
$key = [Convert]::ToBase64String((1..16 | ForEach-Object { Get-Random -Max 256 }))
$all = New-Object Text.StringBuilder

# 3.1 plain HTTP
[void]$all.Append((Probe "GET / HTTP/1.1"  ("GET / HTTP/1.1$nl"  + "Host: 127.0.0.1:9180$nl$nl")))
[void]$all.Append((Probe "POST / HTTP/1.1" ("POST / HTTP/1.1$nl" + "Host: 127.0.0.1:9180${nl}Content-Length: 0$nl$nl")))

# 3.2 WebSocket upgrade - the updater links websocketpp, so this is the theory to kill
foreach ($p in @('/', '/ipc', '/updater', '/v1')) {
    [void]$all.Append((Probe "WS upgrade path=$p (no subprotocol)" (
        "GET $p HTTP/1.1$nl" + "Host: 127.0.0.1:9180$nl" +
        "Upgrade: websocket$nl" + "Connection: Upgrade$nl" +
        "Sec-WebSocket-Key: $key$nl" + "Sec-WebSocket-Version: 13$nl$nl")))
}
foreach ($sp in @('logi.updater_ipc.protocol.v1.protobuf', 'logi.updater_ipc.protocol.protobuf')) {
    [void]$all.Append((Probe "WS upgrade path=/ subprotocol=$sp" (
        "GET / HTTP/1.1$nl" + "Host: 127.0.0.1:9180$nl" +
        "Upgrade: websocket$nl" + "Connection: Upgrade$nl" +
        "Sec-WebSocket-Key: $key$nl" + "Sec-WebSocket-Protocol: $sp$nl" +
        "Sec-WebSocket-Version: 13$nl$nl")))
}
Set-Content -Encoding utf8 "$out\port9180.txt" -Value $all.ToString()
Write-Host $all.ToString()

# --- caller identity, so the low-priv claim is evidenced ---
$id  = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$ctx = "whoami: $(whoami)`nelevated(admin): $($id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))`nprobing PID: $PID`n`nG HUB versions:`n"
$ctx += (Get-ChildItem 'C:\Program Files\LGHUB\lghub_*.exe' -ErrorAction SilentlyContinue |
         ForEach-Object { "  {0}  {1}" -f $_.Name, $_.VersionInfo.ProductVersion } | Out-String)
Set-Content -Encoding utf8 "$out\context.txt" -Value $ctx
Write-Host $ctx

Write-Host "`nSaved to $out" -ForegroundColor Green
Write-Host @"

INTERPRETATION
  * A pipe owned by lghub_updater.exe  -> IPC is pipe-based; the peer IS signature-verified
                                          (FUN_140c243e0 mode 1, fails closed).
                                          The 9180 lead is dead. Report that and stop.
  * NO Logitech pipe, and 9180 is the  -> the allow-all branch is the live path.
    updater                               Go to step 3: capture the agent's traffic.
  * 9180 returning a BYTE-IDENTICAL 404 to plain GETs and to all six WebSocket upgrades means
    it is a routeless stub listener, not the IPC. A websocketpp endpoint answers 400/426.
"@ -ForegroundColor Gray
