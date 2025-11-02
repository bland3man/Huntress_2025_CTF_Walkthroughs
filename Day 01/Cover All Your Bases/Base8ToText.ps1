# tripletsToText.ps1  (PowerShell 5.x)
# These numbers are OCTAL (base 8), not decimal. Decode each token as base-8.

$numbers = @"
116 151 143 145 154 171 040 144 157 156 145 041 040 124 150 141 164 040 167 141 163 040 102 141 163 
145 040 070 054 040 157 162 040 157 143 164 141 154 056 040 111 164 040 165 163 145 163 040 144 151 
147 151 164 163 040 060 055 067 054 040 141 156 144 040 157 146 164 145 156 040 163 150 157 167 163 
040 165 160 040 151 156 040 146 151 154 145 040 160 145 162 155 151 163 163 151 157 156 163 040 157 
156 040 114 151 156 165 170 056 040 123 160 157 164 040 151 164 040 167 150 145 156 040 156 165 155 
142 145 162 163 040 150 141 166 145 040 154 145 141 144 151 156 147 040 060 163 056 040 110 145 162 
145 047 163 040 171 157 165 162 040 146 154 141 147 072 040 146 154 141 147 173 146 145 065 070 060 
145 060 065 145 065 062 067 146 062 060 064 062 061 062 071 060 066 060 065 070 060 071 143 141 145 
143 071 175
"@

# Normalize -> keep only octal tokens (digits 0-7), drop anything else
$octets = $numbers -split '\s+' | Where-Object { $_ -match '^[0-7]+$' -and $_.Length -gt 0 }

# Convert each octal token to a character
$chars = foreach ($o in $octets) {
    [char]([Convert]::ToInt32($o, 8))
}

# Join and output
$result = -join $chars
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$result

# Also write to a file next to the script (avoids console codepage issues)
$outFile = 'C:\Users\BlandWallace\Documents\Huntress-CTF\Binary\decoded.txt'
[System.IO.File]::WriteAllText($outFile, $result, [System.Text.Encoding]::UTF8)
