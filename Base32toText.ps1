# Decode Base32 (RFC 4648) in PowerShell 5

$base32 = @"
I5XW6ZBAO5XXE2ZBEBKGQYLUEB3WC4ZAIJQXGZJAGMZCYIDPMZ2GK3RAOVZWKZBA
NFXCAR3PN5TWYZJAIF2XI2DFNZ2GSY3BORXXEIDLMV4XGLRAJF2CA5LTMVZSAQJN
LIQGC3TEEAZC2NZOEBEWMIDZN52SA43FMUQGY33UOMQG6ZRAOVYHAZLSMNQXGZJA
NRSXI5DFOJZSAYLOMQQGI2LHNF2HGLBAORUGS3TLEBBGC43FGMZC4ICHMV2CA5DI
MF2CAZTMMFTSCIDGNRQWO6ZZMJRDKYTCHBSWCNJQHBRGGZTCMM2TCYTEGVSTCMLF
MZRDEOLDMN6Q====
"@

# RFC 4648 alphabet
$alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
$map = @{}
for($i=0;$i -lt $alph.Length;$i++){ $map[$alph[$i]] = [byte]$i }

# Normalize
$s = ($base32 -replace '\s','').ToUpper().TrimEnd('=')

# Decode 5-bit symbols into bytes
$bits = 0; $bitsLeft = 0
$bytes = New-Object System.Collections.Generic.List[byte]
foreach($ch in $s.ToCharArray()){
    if(-not $map.ContainsKey($ch)){ continue }
    $val = [int]$map[$ch]
    $bits = ($bits -shl 5) -bor $val
    $bitsLeft += 5
    while($bitsLeft -ge 8){
        $bitsLeft -= 8
        $byte = ($bits -shr $bitsLeft) -band 0xFF
        $bytes.Add([byte]$byte) | Out-Null
        if($bitsLeft -gt 0){
            $mask = (1 -shl $bitsLeft) - 1
            $bits = $bits -band $mask
        } else {
            $bits = 0
        }
    }
}

$text = [Text.Encoding]::UTF8.GetString($bytes.ToArray())
$text
if($text -match 'flag\{[0-9a-f]{32}\}'){ "FLAG: $($Matches[0])" }
