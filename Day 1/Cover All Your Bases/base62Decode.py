# PowerShell (single command) - copy/paste into PS
import sys
s="VJGSuERc6qYAYPdRc556JTHqxqWwLbPwzABc0XgIhgwYEWdQji1"
AL="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
n=0
for c in s: n = n*62 + AL.index(c)
b = n.to_bytes((n.bit_length()+7)//8, 'big') or b'\x00'
print("hex:", b.hex())
try:
    print("utf8:", b.decode())
except:
    print("utf8: <non-utf8>")
