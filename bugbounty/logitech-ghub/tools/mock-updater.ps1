param([string]$PipeName='mocklogi', [ValidateSet('reply','drop')][string]$Mode='reply')
$ErrorActionPreference='Stop'
function New-Varint([UInt64]$n){ $o=New-Object System.Collections.Generic.List[byte]
  do{$b=[byte]($n -band 0x7F);$n=$n -shr 7;if($n -ne 0){$b=[byte]($b -bor 0x80)};[void]$o.Add($b)}while($n -ne 0)
  return ,([byte[]]$o.ToArray()) }
function Rd-Varint([byte[]]$b,[ref]$i){ $r=[UInt64]0;$s=0
  while($true){$c=$b[$i.Value];$i.Value++;$r=$r -bor ([UInt64]($c -band 0x7F) -shl $s);if(($c -band 0x80) -eq 0){break};$s+=7}
  return $r }

$srv = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName,[System.IO.Pipes.PipeDirection]::InOut,1)
Write-Host "[mock] listening on $PipeName (mode=$Mode)"
$srv.WaitForConnection()
Write-Host "[mock] client connected"

$hdr=[byte[]]::new(4); $g=0
while($g -lt 4){ $n=$srv.Read($hdr,$g,4-$g); if($n -le 0){break}; $g+=$n }
if($g -lt 4){ Write-Host "[mock] no header"; exit 1 }
$len=[BitConverter]::ToUInt32($hdr,0)
Write-Host "[mock] length prefix = $len"
$body=[byte[]]::new($len); $g=0
while($g -lt $len){ $n=$srv.Read($body,$g,$len-$g); if($n -le 0){break}; $g+=$n }
Write-Host "[mock] body ($g bytes): $((($body|ForEach-Object{'{0:x2}' -f $_}) -join ''))"

# decode the envelope top-level fields
$i=0; $ct=0; $mid=0; $flags=0; $inner=$null
while($i -lt $body.Length){
  $ref=[ref]$i; $tag=Rd-Varint $body $ref; $i=$ref.Value
  $f=[int]($tag -shr 3); $wt=[int]($tag -band 7)
  if($wt -eq 0){ $ref=[ref]$i; $v=Rd-Varint $body $ref; $i=$ref.Value
                 switch($f){1{$mid=$v}3{$flags=$v}4{$ct=$v}} }
  elseif($wt -eq 2){ $ref=[ref]$i; $l=Rd-Varint $body $ref; $i=$ref.Value
                     if($f -eq 5){$inner=$body[$i..($i+$l-1)]}; $i+=[int]$l }
  else { Write-Host "[mock] unexpected wiretype $wt"; break }
}
Write-Host ("[mock] message_id={0} flags={1} content_type=0x{2:X}" -f $mid,$flags,$ct)
if($inner){ Write-Host "[mock] content_data: $((($inner|ForEach-Object{'{0:x2}' -f $_}) -join ''))" }

if($ct -ne 0x1100001){ Write-Host "[mock] FAIL: content_type is not HelloRequest" -ForegroundColor Red; exit 2 }
Write-Host "[mock] content_type == 0x1100001 (HelloRequest) OK" -ForegroundColor Green

if($Mode -eq 'drop'){ Write-Host "[mock] dropping (simulating enforced check)"; $srv.Dispose(); exit 0 }

# build a HelloResponse envelope: message_id=2, in_response_to_id=1, content_type=0x1400001
$env=[byte[]]@()
$env += [byte[]](New-Varint 8)  + [byte[]](New-Varint 2)          # f1 message_id=2
$env += [byte[]](New-Varint 16) + [byte[]](New-Varint 1)          # f2 in_response_to_id=1
$env += [byte[]](New-Varint 32) + [byte[]](New-Varint 0x1400001)  # f4 content_type
$hr = [byte[]]((New-Varint 16) + (New-Varint 1))                  # HelloResponse.ProtocolVersion=1
$env += [byte[]](New-Varint 42) + [byte[]](New-Varint $hr.Length) + $hr
$frame=[byte[]]([BitConverter]::GetBytes([UInt32]$env.Length)+$env)
Write-Host "[mock] replying $($frame.Length) bytes: $((($frame|ForEach-Object{'{0:x2}' -f $_}) -join ''))"
$srv.Write($frame,0,$frame.Length); $srv.Flush()
Start-Sleep -Milliseconds 300
$srv.Dispose()
