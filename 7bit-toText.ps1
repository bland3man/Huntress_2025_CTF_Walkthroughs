# Decode-This.ps1  (PowerShell 5.x) — hardcoded 7-bit lines

$bits = @'
11001101101100110000111001111111011011001011000110110011011001111000110110001011011001110011100001
11001011100010110010011001100110010110010111001010110011011000111001010110011011100001110010110101
1100100011010101110010110110011011011001000111001011001111001101111101
'@

# keep only 0/1 per line
$lines = $bits -split "`r?`n" | ForEach-Object {
  ($_ -replace '\s','') -replace '[^01]', ''
} | Where-Object { $_ -ne '' }

# decode each line as 7-bit ASCII
$sb = New-Object System.Text.StringBuilder
foreach ($ln in $lines) {
  if ($ln.Length % 7 -ne 0) {
    Write-Error "Line length not divisible by 7. Fix the bits." ; exit 1
  }
  for ($i = 0; $i -lt $ln.Length; $i += 7) {
    $chunk = $ln.Substring($i, 7)
    $val = [Convert]::ToInt32($chunk, 2)
    [void]$sb.Append([char]$val)
  }
}

$result = $sb.ToString()
Write-Output $result
