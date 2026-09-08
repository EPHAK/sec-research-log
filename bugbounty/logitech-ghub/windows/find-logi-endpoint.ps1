<#
  Identifies the real IPC transport of the SYSTEM updater (lghub_updater.exe).
  Read-only. No tools to install - uses only built-in Windows APIs.
  Run as a NORMAL (non-elevated) user - that is the whole point of the test.

  Answers:
    1. Which named pipes exist, and which process owns each one.
    2. Whether lghub_updater.exe (SYSTEM) owns a pipe -> pipe transport, peer is verified.
    3. What is actually listening on TCP 9180.
#>

$ErrorActionPreference = 'Continue'
$out = "$env:USERPROFILE\Desktop\logi-endpoint"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Add-Type -Namespace Win32 -Name Pipe -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share,
    IntPtr sec, uint disp, uint flags, IntPtr templ);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetNamedPipeServerProcessId(IntPtr h, out uint pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
'@

$GENERIC_READ = 0x80000000
$FILE_SHARE   = 3
$OPEN_EXISTING= 3

Write-Host "`n=== 1. Named pipes and their owning processes ===" -ForegroundColor Cyan
$rows = @()
foreach ($p in [System.IO.Directory]::GetFiles("\\.\pipe\")) {
    $name = Split-Path $p -Leaf
    $h = [Win32.Pipe]::CreateFileW("\\.\pipe\$name", $GENERIC_READ, $FILE_SHARE,
                                   [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::new(-1)) { continue }
    $pid = 0
    if ([Win32.Pipe]::GetNamedPipeServerProcessId($h, [ref]$pid)) {
        $proc = (Get-Process -Id $pid -ErrorAction SilentlyContinue)
        $rows += [pscustomobject]@{
            Pipe = $name; OwnerPID = $pid
            Owner = if ($proc) { $proc.ProcessName } else { "<unreadable = likely SYSTEM>" }
        }
    }
    [void][Win32.Pipe]::CloseHandle($h)
}
$rows | Sort-Object Owner, Pipe | Format-Table -AutoSize | Out-String -Width 200 |
    Tee-Object "$out\pipes_with_owners.txt"

Write-Host "`n>>> Pipes owned by a Logitech process (THE ANSWER):" -ForegroundColor Yellow
$logiPids = (Get-Process | Where-Object { $_.ProcessName -match 'lghub|logi' }).Id
$rows | Where-Object { $logiPids -contains $_.OwnerPID -or $_.Owner -like '*unreadable*' } |
    Format-Table -AutoSize | Out-String -Width 200 | Tee-Object "$out\pipes_logi.txt"

Write-Host "`n=== 2. Logitech listeners ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalAddress -eq '127.0.0.1' } |
  ForEach-Object {
     $pr = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
     [pscustomobject]@{ Port=$_.LocalPort; PID=$_.OwningProcess
                        Proc= if($pr){$pr.ProcessName}else{"<SYSTEM>"} }
  } | Sort-Object Port | Format-Table -AutoSize | Out-String |
      Tee-Object "$out\listeners.txt"

Write-Host "`n=== 3. What does 9180 answer? ===" -ForegroundColor Cyan
foreach ($req in @("GET / HTTP/1.1`r`nHost: 127.0.0.1`r`n`r`n",
                   "POST / HTTP/1.1`r`nHost: 127.0.0.1`r`nContent-Length: 0`r`n`r`n")) {
    try {
        $c = New-Object Net.Sockets.TcpClient('127.0.0.1', 9180)
        $s = $c.GetStream()
        $b = [Text.Encoding]::ASCII.GetBytes($req)
        $s.Write($b, 0, $b.Length); $s.Flush()
        Start-Sleep -Milliseconds 400
        $buf = New-Object byte[] 2048
        $n = $s.Read($buf, 0, $buf.Length)
        "--- request: $($req.Split("`r")[0]) ---"
        [Text.Encoding]::ASCII.GetString($buf, 0, $n)
        $c.Close()
    } catch { "9180 error: $_" }
} | Tee-Object "$out\port9180.txt"

Write-Host "`nSaved to $out" -ForegroundColor Green
Write-Host @"

INTERPRETATION
  * A pipe owned by lghub_updater.exe  -> IPC is pipe-based; the peer IS signature-verified.
                                          The 9180 lead is probably dead. Report that and stop.
  * NO Logitech pipe, and 9180 is the  -> the allow-all branch is the live path.
    updater                               Go to step 3: capture the agent's traffic.
"@ -ForegroundColor Gray
