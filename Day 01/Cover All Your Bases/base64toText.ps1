$b64 = @"
V2VsbCBkb25lISBUaGF0IHdhcyBCYXNlIDY0LCBzdXBlciBjb21tb24gZm9yIGVuY29kaW5nIGRh
dGEgaW4gZW1haWwgYW5kIHdlYiB0cmFmZmljLiBMb29rIGZvciBBLVosIGEteiwgMC05LCBwbHVz
ICsgYW5kIC8sIGFuZCBzb21ldGltZXMgdGhlIHBhZGRpbmcgPSBzaWducyBhdCB0aGUgZW5kLiBG
bGFnOiBmbGFne2NkMDE2NGZmNjQ3MjZmMjk3MmIyZDhmMmFjMDExOWRifQ==
"@
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($b64 -replace '\s','')))
