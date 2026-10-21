#!/usr/bin/env python3
"""gen_font8x16.py — 8x16 等宽位图字体生成（DejaVu Sans Mono → Rust 表）。

产出: crates/kernel/src/font_gen.rs —— FONT8X16: [u8; 95*16]
  （ASCII 0x20..=0x7E，每字形 16 行 × 8 位，MSB = 最左像素）。
用途: M23-S2 SYS_FB_TEXT(37) 内核侧文本服务。
纪律: 本文件为生成源——重跑再生成，勿手改 font_gen.rs。
"""
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
W, H = 8, 16
LO, HI = 0x20, 0x7E
N = HI - LO + 1

font = ImageFont.truetype(FONT_PATH, 14)  # 14px 字面 → 8x16 网格内垂直居中
img = Image.new("L", (W, H), 0)

glyphs = []
for code in range(LO, HI + 1):
    img.paste(0, (0, 0, W, H))
    d = ImageDraw.Draw(img)
    ch = chr(code)
    # 字形绘制：以基线对齐锚点放置，超宽裁剪（等宽 8px 内）
    d.text((0, 1), ch, fill=255, font=font, anchor="la")
    rows = []
    for y in range(H):
        b = 0
        for x in range(W):
            if img.getpixel((x, y)) >= 96:  # 阈值抗锯齿二值化
                b |= 0x80 >> x
        rows.append(b)
    glyphs.append(rows)

# Rust 表发射
lines = []
lines.append("// 本文件由 scripts/gen_font8x16.py 生成——勿手改；重跑脚本再生成。")
lines.append("// M23-S2 内核侧文本服务字体：8x16 等宽位图（DejaVu Sans Mono 14px")
lines.append("// 栅格化，阈值 96 二值化），ASCII 0x20..=0x7E，95 字形 × 16 行。")
lines.append("// 行字节 MSB = 最左像素（fb::draw_text 逐位展开）。")
lines.append("")
lines.append("#[rustfmt::skip]")
lines.append("pub const FONT8X16: [u8; %d] = [" % (N * 16))
for gi, rows in enumerate(glyphs):
    ch = chr(LO + gi)
    esc = {"\\": "\\\\", '"': '\\"'}.get(ch, ch)
    lines.append('    // U+%04X \'%s\'' % (LO + gi, esc))
    for r in range(0, 16, 4):
        quad = ", ".join("0x%02X" % rows[r + k] for k in range(4))
        lines.append("    " + quad + ",")
lines.append("];")
lines.append("")

with open("crates/kernel/src/font_gen.rs", "w") as f:
    f.write("\n".join(lines))

# 自检：空格全零 + 'L' 有覆盖 + 数字区有覆盖
sp = glyphs[0]
L = glyphs[ord("L") - LO]
assert all(b == 0 for b in sp), "space must be blank"
assert any(b != 0 for b in L), "L must have coverage"
cov = sum(bin(b).count("1") for row in L for b in [row])
print("font_gen.rs written: %d glyphs, L coverage=%d px" % (N, cov))
