# Paste your hex byte pairs below exactly as given
$hex = @"
41 77 65 73 6f 6d 65 20 6a 6f 62 21 20 54 68 61 74 20 77 61 73 20 42 61 73 65 20 31 36 2c 20 6f 72 
20 68 65 78 61 64 65 63 69 6d 61 6c 2e 20 49 74 20 75 73 65 73 20 30 2d 39 20 61 6e 64 20 41 2d 46 
2c 20 6f 66 74 65 6e 20 77 69 74 68 20 70 72 65 66 69 78 65 73 20 6c 69 6b 65 20 30 78 2e 20 43 6f 
6d 6d 6f 6e 20 69 6e 20 6d 65 6d 6f 72 79 20 64 75 6d 70 73 20 61 6e 64 20 63 6f 6c 6f 72 20 63 6f 
64 65 73 2e 20 48 65 72 65 20 69 73 20 79 6f 75 72 20 66 6c 61 67 3a 20 66 6c 61 67 7b 64 33 63 62 
32 62 65 33 65 34 65 34 61 38 66 35 31 37 64 39 63 35 63 65 34 33 37 32 62 30 62 37 7d
"@

# Normalize, convert each token from hex to a byte, then to ASCII
$bytes = foreach($t in ($hex -split '\s+' | Where-Object { $_ -ne '' })) { [Convert]::ToByte($t,16) }
[Text.Encoding]::ASCII.GetString($bytes)
