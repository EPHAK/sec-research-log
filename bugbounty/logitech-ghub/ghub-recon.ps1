<#
    ghub-recon.ps1 - Logitech G HUB recon using ONLY built-in Windows tools.
    No Sysinternals, no third-party downloads required.

    Run in an ADMIN PowerShell:
        powershell -ExecutionPolicy Bypass -File .\ghub-recon.ps1
    Or just paste the whole file into an admin PowerShell window.

    Everything is read-only. Nothing is installed, started, stopped, or modified.
    Output lands in C:\ghub-recon\
#>

$out = 'C:\ghub-recon'
New-Item -ItemType Directory -Force -Path $out | Out-Null
function Log($name, $data) {
    $p = Join-Path $out $name
    $data | Out-String -Width 4096 | Set-Content -Path $p -Encoding UTF8
    Write-Host "  [+] $name"
}
Write-Host "`n=== G HUB recon -> $out ===`n"

# ---------------------------------------------------------------- 1. install paths
$roots = @(
    "$env:ProgramFiles\LGHUB",
    "${env:ProgramFiles(x86)}\LGHUB",
    "$env:LOCALAPPDATA\LGHUB",
    "$env:ProgramData\LGHUB"
) | Where-Object { Test-Path $_ }
Log '01_install_roots.txt' $roots
Write-Host "  install roots found: $($roots.Count)"

# ---------------------------------------------------------------- 2. listening sockets + owner
$conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Local = "$($_.LocalAddress):$($_.LocalPort)"
        PID   = $_.OwningProcess
        Proc  = $proc.ProcessName
        Path  = $proc.Path
    }
} | Sort-Object Local
Log '02_listening_all.txt' ($conns | Format-Table -AutoSize)
Log '02b_listening_logi.txt' ($conns | Where-Object { $_.Proc -match 'lghub|logi' } | Format-Table -AutoSize)

# ---------------------------------------------------------------- 3. services
$svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'lghub|logi' -or $_.PathName -match 'lghub|logi' } |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName
Log '03_services.txt' ($svc | Format-List)

# unquoted service paths (any service, not just Logitech - cheap win)
$unq = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $p = $_.PathName
    $p -and $p -notmatch '^\s*"' -and $p -match '^\s*\S+\s+\S' -and $p -match '^[A-Za-z]:\\.*\s.*\\'
} | Select-Object Name, StartName, PathName
Log '04_unquoted_service_paths.txt' ($unq | Format-List)

# ---------------------------------------------------------------- 5. WRITABLE PATHS (the money check)
# A SYSTEM service loading from a dir a normal user can write to = privesc candidate.
$idents = 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'Everyone', "$env:USERNAME"
$writeRights = 'Write', 'Modify', 'FullControl', 'CreateFiles', 'AppendData', 'WriteData'
$hits = foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $item = $_
        try { $acl = Get-Acl $item.FullName -ErrorAction Stop } catch { return }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $idMatch = $idents | Where-Object { $ace.IdentityReference.Value -like "*$_*" }
            if (-not $idMatch) { continue }
            $r = $ace.FileSystemRights.ToString()
            if ($writeRights | Where-Object { $r -like "*$_*" }) {
                [PSCustomObject]@{
                    Path     = $item.FullName
                    IsDir    = $item.PSIsContainer
                    Identity = $ace.IdentityReference.Value
                    Rights   = $r
                }
            }
        }
    }
}
Log '05_WRITABLE_IN_PRIVILEGED_PATHS.txt' ($hits | Format-Table -AutoSize -Wrap)
Write-Host "  [!] writable-path hits: $(($hits | Measure-Object).Count)"

# also: is the install root itself writable?
$rootAcl = foreach ($root in $roots) {
    "=== $root ==="
    icacls $root 2>&1
}
Log '06_icacls_roots.txt' $rootAcl

# ---------------------------------------------------------------- 7. signatures
$bins = foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue
}
$sigs = $bins | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Status = $s.Status
        Signer = $s.SignerCertificate.Subject
        Path   = $_.FullName
    }
}
Log '07_signatures_all.txt' ($sigs | Format-Table -AutoSize -Wrap)
Log '07b_signatures_UNSIGNED.txt' ($sigs | Where-Object { $_.Status -ne 'Valid' } | Format-Table -AutoSize -Wrap)
Write-Host "  [!] non-Valid signatures: $(($sigs | Where-Object { $_.Status -ne 'Valid' } | Measure-Object).Count)"

# ---------------------------------------------------------------- 8. named pipes
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | Sort-Object
Log '08_named_pipes_all.txt' $pipes
Log '08b_named_pipes_logi.txt' ($pipes | Where-Object { $_ -match 'lghub|logi' })

# ---------------------------------------------------------------- 9. running processes
Log '09_processes.txt' (Get-Process | Where-Object { $_.ProcessName -match 'lghub|logi' } |
    Select-Object Id, ProcessName, Path, StartTime | Format-Table -AutoSize -Wrap)

# ---------------------------------------------------------------- 10. app.asar - THE key artifact
$asar = foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -Filter 'app.asar' -ErrorAction SilentlyContinue
}
Log '10_asar_location.txt' ($asar | Select-Object FullName, Length, LastWriteTime | Format-List)
foreach ($a in $asar) {
    $dest = Join-Path $out $a.Name
    try {
        Copy-Item $a.FullName $dest -Force -ErrorAction Stop
        Write-Host "  [+] copied $($a.Name) ($([math]::Round($a.Length/1MB,1)) MB)"
    } catch { Write-Host "  [-] could not copy $($a.FullName): $_" }
}

# ---------------------------------------------------------------- 11. version
Log '11_versions.txt' ($bins | ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.Name
        Version = $_.VersionInfo.FileVersion
        Product = $_.VersionInfo.ProductName
        Path    = $_.FullName
    }
} | Format-Table -AutoSize -Wrap)

Write-Host "`n=== done. Zip C:\ghub-recon and bring it back. ===`n"
Write-Host "Priority files to look at:"
Write-Host "  05_WRITABLE_IN_PRIVILEGED_PATHS.txt  <- privesc candidates"
Write-Host "  02b_listening_logi.txt               <- the WebSocket port"
Write-Host "  07b_signatures_UNSIGNED.txt          <- unsigned bins in privileged dirs"
Write-Host "  app.asar                             <- bring this back, it has the WS handler"
