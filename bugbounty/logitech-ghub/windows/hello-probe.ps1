<#
  hello-probe.ps1 - Logitech G HUB updater IPC handshake probe
  Produced by the Fedora static-analysis session #3. See handoff/pipe-framing.md.

  WHAT IT DOES
    Opens \\.\pipe\<updater GUID>, writes ONE HelloRequest envelope, and reports
    whether the SYSTEM service replies or drops us.

  SAFETY
    Run NON-ELEVATED as an ordinary user. It sends only the handshake. It sends no
    installer, pipeline or launchable command. It writes nothing to disk.

  SELF-TEST
    Before touching the pipe it rebuilds the minimal envelope and compares it byte for
    byte against the hex recovered on Fedora. If PowerShell's byte handling misbehaves
    the script ABORTS with a loud error instead of producing a wrong conclusion.
    (Session 2's probe script failed silently and nearly inverted the finding. Not again.)

  OUTCOMES
    DROPPED / no reply -> accept-time signature check is ENFORCED. No finding. Done.
    Reply (in_response_to_id = 1) -> a SYSTEM service completed a handshake with an
                                     unsigned, non-elevated peer. That is the report.
#>

[CmdletBinding()]
param(
    [string]$PipeName = 'a62ed1c1-e1a9-5495-9038-16bd49ec7341',
    [int]$TimeoutMs   = 5000,
    [switch]$Minimal,
    [switch]$SelfTestOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================ protobuf encoders
# Every one of these returns a real [byte[]]. The leading comma in `return ,$x`
# stops PowerShell unrolling the array into the pipeline (which would silently
# turn it into Object[] and break Stream.Write later).

function New-Varint {
    param([Parameter(Mandatory)][UInt64]$Value)
    $out = New-Object System.Collections.Generic.List[byte]
    $n = $Value
    do {
        $b = [byte]($n -band 0x7F)
        $n = $n -shr 7
        if ($n -ne 0) { $b = [byte]($b -bor 0x80) }
        [void]$out.Add($b)
    } while ($n -ne 0)
    return ,([byte[]]$out.ToArray())
}

function New-Tag {
    param([Parameter(Mandatory)][int]$Field, [Parameter(Mandatory)][int]$WireType)
    return ,([byte[]](New-Varint ([UInt64](($Field -shl 3) -bor $WireType))))
}

function New-VarintField {          # wire type 0
    param([Parameter(Mandatory)][int]$Field, [Parameter(Mandatory)][UInt64]$Value)
    $t = [byte[]](New-Tag $Field 0)
    $v = [byte[]](New-Varint $Value)
    return ,([byte[]]($t + $v))
}

function New-BytesField {           # wire type 2: string / bytes / embedded message
    param([Parameter(Mandatory)][int]$Field, [byte[]]$Value = @())
    $t = [byte[]](New-Tag $Field 2)
    $l = [byte[]](New-Varint ([UInt64]$Value.Length))
    return ,([byte[]]($t + $l + $Value))
}

function New-StringField {
    param([Parameter(Mandatory)][int]$Field, [Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return ,([byte[]](New-BytesField $Field ([System.Text.Encoding]::UTF8.GetBytes($Value))))
}

function New-PackedUInt32Field {    # proto3 `repeated uint32` defaults to packed
    param([Parameter(Mandatory)][int]$Field, [Parameter(Mandatory)][UInt32[]]$Values)
    $body = [byte[]]@()
    foreach ($v in $Values) { $body = [byte[]]($body + [byte[]](New-Varint ([UInt64]$v))) }
    return ,([byte[]](New-BytesField $Field $body))
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { '{0:x2}' -f $_ }) -join '')
}

# ============================================================ message assembly
$CONTENT_TYPE_HELLO_REQUEST = [UInt64]0x1100001   # FUN_14034f1f0 @ 14034f36f
$FLAG_EXPECTS_REPLY         = [UInt64]2

function New-EndpointInformation {
    param([string]$Name, [string]$Identifier, [string]$Version,
          [UInt64]$ProcessId, [string]$ExecutablePath, [UInt64]$StartTime)
    $b = [byte[]]@()
    if ($Name)           { $b = [byte[]]($b + [byte[]](New-StringField 1 $Name)) }
    if ($Identifier)     { $b = [byte[]]($b + [byte[]](New-StringField 2 $Identifier)) }
    if ($Version)        { $b = [byte[]]($b + [byte[]](New-StringField 3 $Version)) }
    if ($ProcessId)      { $b = [byte[]]($b + [byte[]](New-VarintField 4 $ProcessId)) }
    if ($ExecutablePath) { $b = [byte[]]($b + [byte[]](New-StringField 5 $ExecutablePath)) }
    if ($StartTime)      { $b = [byte[]]($b + [byte[]](New-VarintField 6 $StartTime)) }
    return ,$b
}

function New-HelloRequest {
    param([byte[]]$Endpoint = @(), [string]$Language = 'en-US', [UInt32[]]$Protocols = @(1))
    $b = [byte[]]@()
    if ($Endpoint.Length) { $b = [byte[]]($b + [byte[]](New-BytesField 1 $Endpoint)) }
    if ($Language)        { $b = [byte[]]($b + [byte[]](New-StringField 2 $Language)) }
    if ($Protocols.Count) { $b = [byte[]]($b + [byte[]](New-PackedUInt32Field 3 $Protocols)) }
    return ,$b
}

function New-Envelope {
    param([UInt64]$MessageId, [UInt64]$ContentType, [byte[]]$ContentData,
          [UInt64]$InResponseToId = 0, [UInt64]$Flags = 0)
    $b = [byte[]]@()
    if ($MessageId)      { $b = [byte[]]($b + [byte[]](New-VarintField 1 $MessageId)) }
    if ($InResponseToId) { $b = [byte[]]($b + [byte[]](New-VarintField 2 $InResponseToId)) }
    if ($Flags)          { $b = [byte[]]($b + [byte[]](New-VarintField 3 $Flags)) }
    if ($ContentType)    { $b = [byte[]]($b + [byte[]](New-VarintField 4 $ContentType)) }
    if ($ContentData.Length) { $b = [byte[]]($b + [byte[]](New-BytesField 5 $ContentData)) }
    return ,$b
}

function New-Frame {   # uint32 little-endian length prefix + envelope
    param([byte[]]$Envelope)
    return ,([byte[]]([BitConverter]::GetBytes([UInt32]$Envelope.Length) + $Envelope))
}

# ==================================================================== self-test
# Known-good, produced by handoff/build_hello.py on the analysis box.
$EXPECTED_MINIMAL_FRAME = '1500000008011802208180c0082a0a1205656e2d55531a0101'

$testHello = [byte[]](New-HelloRequest -Endpoint @() -Language 'en-US' -Protocols @(1))
$testEnv   = [byte[]](New-Envelope -MessageId 1 -ContentType $CONTENT_TYPE_HELLO_REQUEST `
                                   -ContentData $testHello -Flags $FLAG_EXPECTS_REPLY)
$testFrame = [byte[]](New-Frame $testEnv)
$testHex   = ConvertTo-HexString $testFrame

Write-Host "self-test expected : $EXPECTED_MINIMAL_FRAME"
Write-Host "self-test produced : $testHex"
if ($testHex -ne $EXPECTED_MINIMAL_FRAME) {
    Write-Host ''
    Write-Host 'SELF-TEST FAILED - the encoder does not reproduce the known-good frame.' -ForegroundColor Red
    Write-Host 'Do NOT trust any result from this script. Fix the encoder first.'        -ForegroundColor Red
    exit 4
}
Write-Host 'self-test OK.' -ForegroundColor Green
Write-Host ''
if ($SelfTestOnly) { exit 0 }

# ============================================================== build the frame
if ($Minimal) {
    $frame = $testFrame
} else {
    $exe = try { [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
           catch { 'C:\probe\probe.exe' }
    $ep = [byte[]](New-EndpointInformation -Name 'probe' -Identifier 'probe' -Version '1.0.0' `
                                           -ProcessId ([UInt64]$PID) -ExecutablePath $exe -StartTime 0)
    $hello = [byte[]](New-HelloRequest -Endpoint $ep -Language 'en-US' -Protocols @(1))
    $envl  = [byte[]](New-Envelope -MessageId 1 -ContentType $CONTENT_TYPE_HELLO_REQUEST `
                                   -ContentData $hello -Flags $FLAG_EXPECTS_REPLY)
    $frame = [byte[]](New-Frame $envl)
}

# Context, best-effort. Never let this abort the probe.
try {
    $idn = [Security.Principal.WindowsIdentity]::GetCurrent()
    $prn = New-Object Security.Principal.WindowsPrincipal($idn)
    Write-Host "user         : $($idn.Name)"
    Write-Host "elevated     : $($prn.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
} catch {
    Write-Host "user         : <identity API unavailable: $($_.Exception.Message)>"
}
Write-Host "pid          : $PID"
Write-Host "pipe         : \\.\pipe\$PipeName"
Write-Host ("content_type : 0x{0:X}" -f $CONTENT_TYPE_HELLO_REQUEST)
Write-Host "frame        : $($frame.Length) bytes"
Write-Host "frame hex    : $(ConvertTo-HexString $frame)"
Write-Host ''

# ==================================================================== the probe
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeName,
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None)
try {
    $pipe.Connect($TimeoutMs)
} catch {
    Write-Host "CONNECT FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host 'If this is access-denied, the DACL is the boundary after all - record that;'
    Write-Host 'it contradicts the Everyone:0x1FFFFF descriptor read out of the binary.'
    exit 2
}
Write-Host 'connected.' -ForegroundColor Green

# Session 5: this was an unguarded Write. With $ErrorActionPreference='Stop' a broken pipe
# here is a TERMINATING error - the script died before printing any verdict, the exception
# escaped the caller's redirect, and run-session.ps1's VERDICT read "(nothing recorded)"
# after a conclusive run. The server rejecting us at accept time IS the expected outcome,
# so it has to be reported, not thrown.
#
# Measured on the target (5x connect+write, 3x connect and read without writing): the
# server closes the connection itself, returning EOF with 0 bytes, before we send anything.
# Whether our Write lands in the local pipe buffer first is a race, so both paths below
# mean the same thing.
try {
    $pipe.Write($frame, 0, $frame.Length)
    $pipe.Flush()
    Write-Host "wrote $($frame.Length) bytes."
} catch {
    Write-Host ''
    Write-Host 'RESULT: DROPPED - the server closed the pipe before it would accept our bytes.' -ForegroundColor Yellow
    Write-Host "  ($($_.Exception.InnerException.Message))"
    Write-Host 'This is the accept-time rejection in its strongest form: the connection was torn'
    Write-Host 'down between connect() and write(), i.e. the peer was refused on inspection, not'
    Write-Host 'on the content of the handshake. The signature check is ENFORCED.'
    Write-Host 'Write it up as "no finding" for the pipe handshake.'
    try { $pipe.Dispose() } catch { }
    exit 0
}

# PipeStream does not support ReadTimeout, so bound each read with ReadAsync + Wait.
function Read-WithTimeout {
    param([System.IO.Stream]$Stream, [byte[]]$Buffer, [int]$Want, [int]$TimeoutMs)
    $got = 0; $timedOut = $false; $eof = $false
    while ($got -lt $Want) {
        $task = $Stream.ReadAsync($Buffer, $got, $Want - $got)
        if (-not $task.Wait($TimeoutMs)) { $timedOut = $true; break }
        $n = $task.Result
        if ($n -le 0) { $eof = $true; break }
        $got += $n
    }
    return [pscustomobject]@{ Got = $got; TimedOut = $timedOut; Eof = $eof }
}

$hdr = [byte[]]::new(4)
$eof = $false
$got = 0
try {
    $r   = Read-WithTimeout -Stream $pipe -Buffer $hdr -Want 4 -TimeoutMs $TimeoutMs
    $got = $r.Got
    $eof = $r.Eof
} catch {
    Write-Host "read ended: $($_.Exception.Message)"
}

if ($got -lt 4) {
    Write-Host ''
    if ($eof) { Write-Host 'RESULT: DROPPED - server closed the pipe without replying.' -ForegroundColor Yellow }
    else      { Write-Host 'RESULT: DROPPED - no reply within the timeout.'             -ForegroundColor Yellow }
    Write-Host 'The accept-time signature check is ENFORCED. This is the expected outcome.'
    Write-Host 'Write it up as "no finding" for the pipe handshake and move to the llc_check question.'
    $pipe.Dispose()
    exit 0
}

$len = [BitConverter]::ToUInt32($hdr, 0)
Write-Host "reply length prefix: $len"
if ($len -gt 1MB) { Write-Host 'implausible reply length - aborting.' -ForegroundColor Red; $pipe.Dispose(); exit 3 }

$body = [byte[]]::new($len)
$got = 0
try {
    $r = Read-WithTimeout -Stream $pipe -Buffer $body -Want ([int]$len) -TimeoutMs $TimeoutMs
    $got = $r.Got
} catch { Write-Host "read ended: $($_.Exception.Message)" }

$show = [Math]::Min($got, 256)
if ($show -gt 0) { Write-Host "reply body ($got bytes): $(ConvertTo-HexString $body[0..($show-1)])" }
Write-Host ''
Write-Host 'RESULT: THE SYSTEM SERVICE REPLIED TO AN UNSIGNED, NON-ELEVATED PEER.' -ForegroundColor Red
Write-Host 'Expect content_type 0x1400001 (HelloResponse) and field 2 in_response_to_id = 1'
Write-Host '  -> look for the bytes  20 81 80 80 0a  (content_type) and  10 01  (in_response_to_id).'
Write-Host 'That is the finding. Stop here - do NOT send any installer or pipeline command.'
$pipe.Dispose()
