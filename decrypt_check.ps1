$path = "C:\Users\dELL\Desktop\allbutterfact.x64\allbutterfact.x64.bin"
$b = [IO.File]::ReadAllBytes($path)
$stub = 1888
$dll = New-Object byte[] ($b.Length - $stub)
[Array]::Copy($b, $stub, $dll, 0, $dll.Length)

$mask = [uint64]"4294967295"
$State = [uint64]"2166136261"
$key = [System.Text.Encoding]::ASCII.GetBytes("HAVOC_CRYPT_KEY_MARKER")
foreach ($k in $key) {
    $State = (($State -bxor [uint64]$k) * [uint64]"16777619") -band $mask
}
for ($i = 0; $i -lt $dll.Length; $i++) {
    $State = ($State + [uint64]"1831565813") -band $mask
    $s = $State
    $s = (($s -bxor ($s -shr 15)) * ($s -bor 1)) -band $mask
    $t = (($s -bxor ($s -shr 7)) * ($s -bor 61)) -band $mask
    $s = ($s -bxor (($s + $t) -band $mask)) -band $mask
    $ks = ($s -bxor ($s -shr 14)) -band 0xFF
    $dll[$i] = [byte]($dll[$i] -bxor [byte]$ks)
}
Write-Host ("decrypted first 4 bytes: {0:X2} {1:X2} {2:X2} {3:X2}  ascii: {4}{5}" -f $dll[0],$dll[1],$dll[2],$dll[3],[char]$dll[0],[char]$dll[1])
$pe = [BitConverter]::ToInt32($dll, 0x3C)
Write-Host ("e_lfanew=0x{0:X}  PE sig: {1}{2}" -f $pe, [char]$dll[$pe], [char]$dll[$pe+1])
