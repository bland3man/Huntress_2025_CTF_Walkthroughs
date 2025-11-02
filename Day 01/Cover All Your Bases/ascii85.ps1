# Ascii85 / Base85 decoder (PowerShell 5.x, ASCII only)

$ErrorActionPreference = 'Stop'

# ==== INPUT ====
$raw = @'
@D_<sB5GVmj-;A[GD:PIptd9#KgRoG![3\gx4mcIUAiYA8M=E_=UOU5S$HqE$p<KHnvkV66}Q?tqB]P)
Dy\4O\cT$^qE;BG\LX&pVXaZ$Tq0,'1:I3jzOY4Rs}8iY(1.GjE2RDb#yuj-*n10I1S\d:W-#pm0',!e
D:H4sK'c@^jAiC%1K}1^V65i/Upa*U(mEU'(Va'b/nt_*vgYH.^_V_Td5AgNoIWlD9jvOZ3oKhm/WwX+
-GHriuce$TlHB+#)E]kGisTc:ehwoA<RF;gx-ld->om0iC&$I3SXV_'bF.gOk[#-H,1kv93JUpCu&I-r
4c^^pu+!?9iXkKdk6,1cPeWN.@E?CO
'@

# ==== PREP ====
# Remove whitespace
$data = ($raw -replace '\s','')

# If Adobe-style wrappers exist (<~ ... ~>), extract the inside
if($data -match '<~' -and $data -match '~>'){
    $data = ($data.Split('<~')[1]).Split('~>')[0]
}

# ==== DECODER ====
function Decode-Ascii85 {
    param([string]$s)

    # Valid Ascii85 chars are '!' (33) through 'u' (117). 'z' is a special case (0x00000000)
    $bytes = New-Object System.Collections.Generic.List[byte]
    $i = 0
    $len = $s.Length

    while($i -lt $len){
        # Handle 'z' (represents 4 zero bytes) if it appears as a standalone token
        if($s[$i] -eq 'z'){
            # 'z' is only valid when not in the middle of a 5-char block; we enforce by treating it alone.
            $bytes.Add(0) ; $bytes.Add(0) ; $bytes.Add(0) ; $bytes.Add(0)
            $i++
            continue
        }

        # Gather up to 5 chars for a block
        $remain = [Math]::Min(5, $len - $i)
        $block = $s.Substring($i, $remain).ToCharArray()

        # Validate and pad with 'u' (117) if short
        $vals = New-Object System.Collections.Generic.List[int]
        foreach($ch in $block){
            $code = [int][char]$ch
            if($code -lt 33 -or $code -gt 117){
                throw "Invalid Ascii85 character: '$ch' (code $code) at position $i."
            }
            $vals.Add($code - 33)
        }
        $padCount = 0
        if($vals.Count -lt 5){
            $padCount = 5 - $vals.Count
            for($p=0;$p -lt $padCount;$p++){ $vals.Add(117 - 33) } # pad with 'u'
        }

        # Compute 32-bit value: sum(vals[k] * 85^(4-k))
        [uint64]$value = 0
        for($k=0;$k -lt 5;$k++){
            $value = ($value * 85) + [uint64]$vals[$k]
        }

        # Now emit bytes (big-endian): normally 4 bytes; if padded, emit (count-1) bytes
        $emitCount = 4
        if($padCount -gt 0){
            # When there were N pads, original chars were (5 - N), and we emit (5 - N - 1) bytes
            $emitCount = (5 - $padCount - 1)
            if($emitCount -lt 0){ $emitCount = 0 }
        }

        # Break into 4 big-endian bytes
        $b3 = [byte](($value -shr 24) -band 0xFF)
        $b2 = [byte](($value -shr 16) -band 0xFF)
        $b1 = [byte](($value -shr 8)  -band 0xFF)
        $b0 = [byte]( $value          -band 0xFF)

        if($emitCount -ge 1){ $bytes.Add($b3) }
        if($emitCount -ge 2){ $bytes.Add($b2) }
        if($emitCount -ge 3){ $bytes.Add($b1) }
        if($emitCount -ge 4){ $bytes.Add($b0) }

        $i += $remain
    }

    return ,([byte[]]$bytes.ToArray())
}

# ==== RUN ====
[byte[]]$out = Decode-Ascii85 -s $data

# Save raw bytes for forensics
$null = New-Item -ItemType Directory -Path 'C:\LOGS' -Force
$outPath = 'C:\LOGS\payload.bin'
[System.IO.File]::WriteAllBytes($outPath, $out)

# Try UTF-8 preview (non-fatal if it's binary)
try {
    $text = [System.Text.Encoding]::UTF8.GetString($out)
    # Heuristic: if it has many control chars, don't spam the console
    $ctrl = ($text.ToCharArray() | Where-Object { [int]$_ -lt 9 -or ([int]$_ -ge 14 -and [int]$_ -lt 32) }).Count
    if($ctrl -gt 0){
        Write-Host "Decoded $($out.Length) bytes -> likely binary. Saved to $outPath"
    } else {
        Write-Host "Decoded UTF-8 text ($($out.Length) bytes):"
        Write-Host $text
    }
} catch {
    Write-Host "Decoded $($out.Length) bytes (non-text). Saved to $outPath"
}
