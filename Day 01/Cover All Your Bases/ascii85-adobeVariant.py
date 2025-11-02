#!/usr/bin/env python3
# Ascii85 (Adobe/Ascii85) decoder that works with or without <~ ~> wrapper

import base64, re

PAYLOAD = r"""
<~:2+3L+EqaECEXg"BOQ!*G@>P86=FqH+?250+EqL5@qZupDf'',+DG^9A8,XfATD@"F<Ga8EbSs"FE9
&W<+ohc6"FnCAM6>j@qfX:2'@'NEbSs"F<G^IF^]*&Gp%0M@<-I2+EqOABHTEd+CT.u+D#G$F!,[@FD)
eG4t[sWBOr;a7RJ:Q3ANE6G%#E*@;^00F`V,8+CQC%Ec5AsATAo%CiF&r@V'X(.!]`R+DkP4+EM+*+Cf
(nEa`I"ATDi7Ch[Zr+FYja?n<FI/0JkO+FP[k+A$/fH#IhG+Co%nDe*F"+Cf>,E,8rsDK?q/@W-C2+DG
_:@;KXg+EMgF@W-((/0K"XBlmiu+EV:.+@9LXAN2OiG%#E*@;^0>+@^0UB0%/ICggt'@5K\q@:_,Q2D[
<IA2uM-1h/C&AN)S+@P_LS2.U<.I/~>
""".strip()

def decode_ascii85(s: str) -> bytes:
    # remove all whitespace
    b = re.sub(rb"\s+", b"", s.encode("utf-8"))
    # if wrapped with <~ ~>, extract inside; otherwise use as-is
    if b.startswith(b"<~") and b.endswith(b"~>"):
        b = b[2:-2]
    elif b.find(b"<~") != -1 and b.find(b"~>") != -1:
        b = b.split(b"<~", 1)[1].rsplit(b"~>", 1)[0]
    # decode with adobe=False (works on the raw inner stream)
    return base64.a85decode(b, adobe=False)

if __name__ == "__main__":
    out = decode_ascii85(PAYLOAD)
    text = out.decode("utf-8", "replace")
    print(text)
    import re as _re
    m = _re.search(r"flag\{[0-9a-f]{32}\}", text)
    if m:
        print("FLAG:", m.group(0))
