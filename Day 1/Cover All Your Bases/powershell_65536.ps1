$u = @'
𖡅驣ꍬ𐙥啴𒁪噢褠陨啴陷啳陂驳欠樵欳唬鵷顩啨陣啮陭啰𒁴𐘠陥ꍲ啹𔑥𓁥啹𐙕顩饯啥鵣𓁡顡驴捲縠啦𒁹啵驳啥鹷饬ꔠ𖡩𓅥𒀠啦饯啤ꍧ𒅹𓅨
阠饮𓄠ꕹ𒁢𓅬唬𒁹啵𓁡啥𓁰靯靡𖥬ꌠ𒁯鹫鱮阠啴鵴𓅩售驈驲鸠啳𒁹𓁵鬠𐙩ꍡ鬠陬潧鬠陬𠅧樴昷椷餵饣餴欱浦此敦污饦魡昷朵頸ᕽ
'@

$py = @'
import sys, re, base65536
data = sys.stdin.read()
data = re.sub(r"\s+", "", data)  # remove ALL whitespace (fixes code point 10)
b = base65536.decode(data)
try:
    sys.stdout.write(b.decode("utf-8"))
except UnicodeDecodeError:
    open("out.bin","wb").write(b)
    print("\nBinary payload written to out.bin")
'@

$u | py -c $py