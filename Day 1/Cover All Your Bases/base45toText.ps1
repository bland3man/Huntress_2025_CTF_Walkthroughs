# base45-run.ps1  (PowerShell 5.x)
# Input : C:\Users\BlandWallace\Documents\Huntress-CTF\Binary\base45.txt
# Output: C:\Users\BlandWallace\Documents\Huntress-CTF\Binary\decoded.txt

$InPath  = 'C:\Users\BlandWallace\Documents\Huntress-CTF\Binary\base45-inputFile.txt'
$OutPath = 'C:\Users\BlandWallace\Documents\Huntress-CTF\Binary\decoded.txt'

if (-not (Test-Path $InPath)) { throw "Input file not found: $InPath" }

# RFC 9285 Base45 alphabet (includes a literal space)
$Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
$Map = @{}
for ($i=0; $i -lt $Alphabet.Length; $i++) { $Map[$Alphabet[$i]] = $i }

function Normalize([string]$s) {
    $s = $s -replace "[`r`n`t]", ''              # remove CR/LF/TAB
    $s = $s -replace ([char]0x00A0), ' '         # NBSP -> SPACE
    $s = $s -replace [char]0x2010, '-'           # unicode dashes -> '-'
    $s = $s -replace [char]0x2011, '-'
    $s = $s -replace [char]0x2012, '-'
    $s = $s -replace [char]0x2013, '-'
    $s = $s -replace [char]0x2014, '-'
    $s = $s -replace [char]0x2212, '-'
    return $s
}

function Decode-Base45([string]$s, [bool]$TreatSpaceAsDigit) {
    if (-not $TreatSpaceAsDigit) { $s = $s -replace ' ', '' }
    if ([string]::IsNullOrWhiteSpace($s)) { throw "Empty after normalization." }

    # Validate characters
    for ($k=0; $k -lt $s.Length; $k++) {
        if (-not $Map.ContainsKey($s[$k])) { throw "Invalid Base45 char '$($s[$k])' at pos $k" }
    }

    $out = New-Object System.Collections.Generic.List[byte]
    $i = 0
    while ($i -lt $s.Length) {
        $remain = $s.Length - $i
        if ($remain -ge 3) {
            $v0 = [int]$Map[$s[$i]]
            $v1 = [int]$Map[$s[$i+1]]
            $v2 = [int]$Map[$s[$i+2]]
            $x  = $v0 + 45*$v1 + 2025*$v2
            if ($x -ge 65536) { throw "Invalid Base45 triple value ($x) at pos $i" }
            $out.Add([byte](($x -shr 8) -band 0xFF)) | Out-Null
            $out.Add([byte]($x -band 0xFF))          | Out-Null
            $i += 3
        }
        elseif ($remain -eq 2) {
            $v0 = [int]$Map[$s[$i]]
            $v1 = [int]$Map[$s[$i+1]]
            $x  = $v0 + 45*$v1
            if ($x -ge 256) { throw "Invalid Base45 pair value ($x) at pos $i" }
            $out.Add([byte]$x) | Out-Null
            $i += 2
        }
        else {
            throw "Invalid Base45 length (dangling single character at end)."
        }
    }
    ,$out.ToArray()
}

function Try-InflateUtf8([byte[]]$buf) {
    try {
        # If zlib header present (0x78 0x01/5E/9C/DA), skip 2 bytes
        $offset = 0
        if ($buf.Length -ge 2 -and $buf[0] -eq 0x78 -and ($buf[1] -in 0x01,0x5E,0x9C,0xDA)) { $offset = 2 }
        $msIn  = New-Object IO.MemoryStream(,$buf[$offset..($buf.Length-1)])
        $msOut = New-Object IO.MemoryStream
        $ds = New-Object IO.Compression.DeflateStream($msIn, [IO.Compression.CompressionMode]::Decompress)
        $ds.CopyTo($msOut); $ds.Dispose()
        [Text.Encoding]::UTF8.GetString($msOut.ToArray())
    } catch { $null }
}

# Run
$raw  = Get-Content -Raw -Path $InPath
$norm = Normalize $raw

$decodedBytes = $null
# Try mode 1: spaces are Base45 digits
try { $decodedBytes = Decode-Base45 $norm $true } catch { }

# Try mode 2: spaces are separators
if (-not $decodedBytes) {
    try { $decodedBytes = Decode-Base45 $norm $false } catch { }
}

if (-not $decodedBytes) { throw "Base45 decode failed in both modes." }

# Try deflate; if not compressed, treat as UTF-8
$text = Try-InflateUtf8 $decodedBytes
if (-not $text) { $text = [Text.Encoding]::UTF8.GetString($decodedBytes) }

# Write result to file as UTF-8 (no BOM)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutPath, $text, $utf8NoBom)

# Also print to console
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$text

# If a flag is present, show it clearly
if ($text -match 'flag\{[0-9a-f]{32}\}') { "FLAG: $($Matches[0])" }
