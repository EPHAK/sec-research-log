# Characterise HOW the updater pipe drops an unsigned, non-elevated peer.
$ErrorActionPreference = 'Continue'
$PipeName = 'a62ed1c1-e1a9-5495-9038-16bd49ec7341'

function Connect-Probe {
    $p = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p.Connect(3000)
    $sw.Stop()
    return @{ Pipe = $p; ConnectMs = $sw.ElapsedMilliseconds }
}

Write-Host '=== TRIAL A: connect, then write the HelloRequest (5 runs) ==='
for ($i = 1; $i -le 5; $i++) {
    $r = $null
    try { $r = Connect-Probe } catch { Write-Host ("  run {0}: CONNECT FAILED: {1}" -f $i, $_.Exception.Message); continue }
    $p = $r.Pipe
    $buf = New-Object byte[] 111
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $res = ''
    try { $p.Write($buf, 0, $buf.Length); $p.Flush(); $res = 'write SUCCEEDED' }
    catch { $res = 'write FAILED: ' + $_.Exception.InnerException.Message }
    $sw.Stop()
    Write-Host ("  run {0}: connected={1} connect={2}ms  isConnected={3}  {4}  (after {5}ms)" -f `
        $i, $true, $r.ConnectMs, $p.IsConnected, $res, $sw.ElapsedMilliseconds)
    try { $p.Dispose() } catch {}
    Start-Sleep -Milliseconds 300
}

Write-Host ''
Write-Host '=== TRIAL B: connect, write NOTHING, wait for the server to close us (3 runs) ==='
Write-Host '    0 bytes read = server closed the connection itself (accept-time reject).'
Write-Host '    timeout      = server kept us and was waiting for data.'
for ($i = 1; $i -le 3; $i++) {
    $r = $null
    try { $r = Connect-Probe } catch { Write-Host ("  run {0}: CONNECT FAILED: {1}" -f $i, $_.Exception.Message); continue }
    $p = $r.Pipe
    $buf = New-Object byte[] 16
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $t = $p.ReadAsync($buf, 0, 16)
    $done = $t.Wait(4000)
    $sw.Stop()
    if (-not $done) {
        Write-Host ("  run {0}: connect={1}ms  -> still open after 4000ms (server is WAITING for data)" -f $i, $r.ConnectMs)
    } else {
        $n = -1; $err = ''
        try { $n = $t.Result } catch { $err = $_.Exception.InnerException.Message }
        if ($err) { Write-Host ("  run {0}: connect={1}ms  -> read threw after {2}ms: {3}" -f $i, $r.ConnectMs, $sw.ElapsedMilliseconds, $err) }
        else      { Write-Host ("  run {0}: connect={1}ms  -> read returned {2} bytes after {3}ms  (0 = SERVER CLOSED US)" -f $i, $r.ConnectMs, $n, $sw.ElapsedMilliseconds) }
    }
    try { $p.Dispose() } catch {}
    Start-Sleep -Milliseconds 300
}

Write-Host ''
Write-Host '=== ACLs the session script failed to read (trailing-backslash quoting bug) ==='
foreach ($d in @('C:\Program Files\LGHUB', 'C:\Program Files')) {
    Write-Host ("---- icacls {0} ----" -f $d)
    & icacls $d 2>&1 | ForEach-Object { Write-Host "  $_" }
}
