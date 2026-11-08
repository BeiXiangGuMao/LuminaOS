#!/usr/bin/env python3
"""gen_m42_fbdev_image.py — M42-FBDEV1 用户态 fb 驱动进程映像生成器（阶段一首笔）。

产物：crates/kernel/src/exec_images_gen_m42.rs（user.rs 经 include! 引入）
  - FBDEV_LXE：LXE1 双段映像（代码 RX @FBDEV_ENTRY + 数据 RW @FBDEV_DATA_VA）

fbdev 驱动进程车道（M42 阶段一「用户态 fb 驱动进程」首笔）：
  1. SYS_FB_MAP(0x40000000) —— LFB 映射移交（映射进本进程用户根，
     SURFACE_OWNER 单面 CAS 首认领者 = 驱动进程——直写车道承接）；
  2. SYS_DEV_PIO dispi 探测 —— OUT16 0x1CE←0（索引=ID 寄存器）+
     IN16 0x1CF 读版本（≥0xB0C0）——端口访问面活体（ERR_CAP 重试
     64 拍窗口：spawn→grant 登记窗免疫，t100 先例同款）；
  3. 直写成像 —— LFB 行 0 x=0..63 共 64 px 写 FBDEV_PAINT 常量
     （内核侧 VRAM 物理读回对账——映射移交端到端证据）；
  4. SYS_LOG 取证（LUMINA-T101-FBDEV 行）→ EXIT(0)。
  bail 码：70 = FB_MAP 失败；71 = PIO 裁量预算耗尽；72 = dispi 版本
  下限未过。全数 fail-visible（装置不静默）。

交叉锚点常量（与 kernel::user / kernel::dev 文档双向对账，漂移即红）：
  FBDEV_ENTRY     = 0x1_8000_0000   （PDPT[6] 全新分支段区——FRESH_BASE）
  FBDEV_DATA_VA   = 0x1_8000_1000   （数据段——PROG_DATA_VA 同域）
  FBDEV_PAINT     = 0x2B7F_1E00     （直写成像常量）
  bail 码         = 70/71/72        （fail-visible 退出码族）

寄存器约定 = bedrock abi v0/v0.19：rax = 系统调用号；rdi/rsi/rdx =
参数；callee-saved（rbx/rbp/r12-r15）跨 syscall 保留（M33-P1 帧快照
域——r12 重试预算跨 syscall 存续依赖本契约）。
验证：脚本自检走 objdump -D -b binary 反汇编逐段锚定（工作区根运行
python3 scripts/gen_m42_fbdev_image.py --check 可复验）。
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ---- 交叉锚点常量 ----
FBDEV_ENTRY = 0x1_8000_0000
FBDEV_DATA_VA = 0x1_8000_1000
FBDEV_PAINT = 0x2B7F_1E00
FBDEV_BAIL_MAP = 70
FBDEV_BAIL_PIO = 71
FBDEV_BAIL_DISPI = 72
PAGE = 0x1000
FB_VA_BASE = 0x4000_0000

SYS_LOG, SYS_EXIT, SYS_YIELD = 0, 1, 2
SYS_FB_MAP, SYS_DEV_PIO = 35, 41
PIO_IN16, PIO_OUT16 = 2, 3
DISPI_INDEX, DISPI_DATA = 0x1CE, 0x1CF
DISPI_ID_MIN = 0xB0C0
PIO_RETRY_BUDGET = 64

FLAG_W, FLAG_X = 1 << 0, 1 << 1

EVIDENCE = b"LUMINA-T101-FBDEV px=64 map=0 pio=ok"
assert len(EVIDENCE) <= 64

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_gen_m42.rs"


# ---- 微型两遍汇编器（rel8/rel32 前向/后向标号裁决，越域即断言失败） ----
class Asm:
    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (pos, label, kind, prefix_len)

    def here(self):
        return len(self.buf)

    def label(self, name):
        assert name not in self.labels, f"重复标号 {name}"
        self.labels[name] = self.here()

    def db(self, *parts):
        for p in parts:
            if isinstance(p, int):
                self.buf.append(p)
            else:
                self.buf.extend(p)

    def jmp8(self, opc, target):
        self.db(opc)
        self.fixups.append((self.here(), target, 8, 1))
        self.db(0)

    def jmp32(self, target):
        self.db(0x0F, 0x85)  # jne rel32（本映像唯一 rel32 点：entry bail）
        self.fixups.append((self.here(), target, 32, 0))
        self.db(0, 0, 0, 0)

    def resolve(self):
        for pos, target, kind, prefix in self.fixups:
            rel = self.labels[target] - (pos + (4 if kind == 32 else 1))
            if kind == 8:
                assert -128 <= rel <= 127, f"rel8 越域：{target} = {rel}"
                self.buf[pos] = rel & 0xFF
            else:
                assert -(1 << 31) <= rel < (1 << 31), f"rel32 越域：{target}"
                self.buf[pos : pos + 4] = struct.pack("<i", rel)


def build_code():
    a = Asm()
    # ---- 1) SYS_FB_MAP：rsi = FB_VA_BASE（a1 槽——parse 域契约） ----
    a.db(0xBE, struct.pack("<I", FB_VA_BASE))          # mov esi, imm32
    a.db(0xB8, struct.pack("<I", SYS_FB_MAP))          # mov eax, 35
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x85, 0xC0)                             # test rax, rax
    a.jmp32("bail_map")                                # jne rel32 bail_map
    # ---- 2) SYS_DEV_PIO dispi 探测（登记窗重试域） ----
    a.label("retry")
    a.db(0x41, 0xBC, struct.pack("<I", PIO_RETRY_BUDGET))  # mov r12d, budget
    a.label("retry_head")
    a.db(0xBF, struct.pack("<I", PIO_OUT16))           # mov edi, op OUT16
    a.db(0xBE, struct.pack("<I", DISPI_INDEX))         # mov esi, 0x1CE
    a.db(0x31, 0xD2)                                   # xor edx, edx
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jmp8(0x74, "denied")                             # je denied
    a.db(0xBF, struct.pack("<I", PIO_IN16))            # mov edi, op IN16
    a.db(0xBE, struct.pack("<I", DISPI_DATA))          # mov esi, 0x1CF
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jmp8(0x74, "denied")                             # je denied
    a.db(0x3D, struct.pack("<I", DISPI_ID_MIN))        # cmp eax, 0xB0C0
    a.jmp8(0x72, "bail_dispi")                         # jb bail_dispi
    # ---- 3) 直写成像：行 0 x=0..63 ← FBDEV_PAINT ----
    a.label("paint")
    a.db(0xBF, struct.pack("<I", FB_VA_BASE))          # mov edi, LFB va
    a.db(0xBE, struct.pack("<I", FBDEV_PAINT))         # mov esi, paint
    a.db(0x31, 0xC9)                                   # xor ecx, ecx
    a.label("p1")
    a.db(0x89, 0x34, 0x8F)                             # mov [rdi+rcx*4], esi
    a.db(0xFF, 0xC1)                                   # inc ecx
    a.db(0x83, 0xF9, 64)                               # cmp ecx, 64
    a.jmp8(0x72, "p1")                                 # jb p1
    # ---- 4) SYS_LOG 取证 + EXIT(0) ----
    a.db(0x48, 0xBF, struct.pack("<Q", FBDEV_DATA_VA))  # movabs rdi, DATA_VA
    a.db(0xBE, struct.pack("<I", len(EVIDENCE)))        # mov esi, len
    a.db(0x31, 0xC0)                                   # xor eax, eax (SYS_LOG)
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x31, 0xFF)                                   # xor edi, edi
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $（EXIT 失效停机）
    # ---- denied：裁量窗重试（YIELD 让权——登记窗免疫） ----
    a.label("denied")
    a.db(0x49, 0xFF, 0xCC)                             # dec r12d
    a.jmp8(0x74, "bail_pio")                           # jz bail_pio
    a.db(0xB8, struct.pack("<I", SYS_YIELD))           # mov eax, 2
    a.db(0x0F, 0x05)                                   # syscall
    a.jmp8(0xEB, "retry_head")                         # jmp retry_head
    # ---- bail 族（fail-visible：装置不静默） ----
    a.label("bail_map")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_MAP))      # mov edi, 70
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_pio")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_PIO))      # mov edi, 71
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_dispi")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_DISPI))    # mov edi, 72
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.resolve()
    return bytes(a.buf)


def lxe1(entry, stack_top, segs):
    """LXE1 编码（bedrock::exec::encode 同构：64B 头 + 32B 段头 × n + 载荷）。"""
    payload_off = 64 + 32 * len(segs)
    out = bytearray()
    out += struct.pack("<I", 0x3145_584C)  # magic "LXE1"
    out += struct.pack("<I", 1)            # version
    out += struct.pack("<I", len(segs))
    out += struct.pack("<I", 0)            # 保留
    out += struct.pack("<Q", entry)
    out += struct.pack("<Q", stack_top)
    out += struct.pack("<Q", payload_off)
    out += bytes(24)                       # 0x28..0x40 保留
    for seg in segs:
        out += struct.pack("<QQQQ", seg[0], seg[1], seg[2], seg[3])
    for seg in segs:
        assert len(seg[4]) == seg[2]
        out += seg[4]
    return bytes(out)


def objdump_check(code):
    """独立验证通道：objdump 反汇编锚定关键指令序（机器码形态守恒）。"""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        dis = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "--no-show-raw-insn", path],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        Path(path).unlink(missing_ok=True)
    # 关键锚（偏移敏感序——重排即生成器缺陷显形；空白归一单空格）
    anchors = [
        ("mov $0x40000000,%esi", "FB_MAP 参数"),
        ("mov $0x23,%eax", "SYS_FB_MAP 号"),
        ("syscall", "FB_MAP 入口"),
        ("mov $0x1ce,%esi", "dispi 索引口"),
        ("mov $0x1cf,%esi", "dispi 数据口"),
        ("mov $0x29,%eax", "SYS_DEV_PIO 号"),
        ("cmp $0xb0c0,%eax", "dispi 版本下限"),
        ("movabs $0x180001000,%rdi", "取证串指针"),
        ("mov %esi,(%rdi,%rcx,4)", "LFB 直写成像"),
        ("dec %r12", "重试预算域"),
    ]
    flat = " ".join(dis.split())
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    # syscall 次数锚：FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + EXIT×4 = 9
    n_sys = flat.count("syscall")
    assert n_sys == 9, f"syscall 计数锚失配：{n_sys} ≠ 9"
    return n_sys


def rs_array(blob, per_line=16):
    rows = []
    for i in range(0, len(blob), per_line):
        chunk = blob[i : i + per_line]
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    return "\n".join(rows).rstrip(",")


def main():
    check_only = "--check" in sys.argv
    code = build_code()
    n_sys = objdump_check(code)
    data = EVIDENCE
    blob = lxe1(
        FBDEV_ENTRY,
        0,
        [
            (FBDEV_ENTRY, PAGE, len(code), FLAG_X, code),
            (FBDEV_DATA_VA, PAGE, len(data), FLAG_W, data),
        ],
    )
    if check_only:
        print(f"[check] code={len(code)}B data={len(data)}B blob={len(blob)}B syscall={n_sys}")
        return
    doc = f"""// 本文件由 scripts/gen_m42_fbdev_image.py 生成——勿手改；重跑脚本再生成。
// M42-FBDEV1 用户态 fb 驱动进程映像（阶段一首笔）；交叉锚点常量与
// kernel::user / kernel::dev 文档双向对账。机器码经 objdump 反汇编
// 锚定自检（syscall ×{n_sys}：FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + EXIT 4）。

/// fbdev 映像入口虚地址（PDPT[6] 全新分支段区首槽——[`FRESH_BASE`]
/// 同域；gen 脚本 FBDEV_ENTRY 对账）。
#[allow(dead_code)] // 文档锚点：LXE1 头 entry 字段内嵌同值（gen 脚本对账）
pub const FBDEV_ENTRY: u64 = 0x1_8000_0000;
/// fbdev 映像数据段虚地址（FRESH_BASE + 0x1000——PROG_DATA_VA 同域）。
#[allow(dead_code)] // 文档锚点：LXE1 段表 vaddr 字段内嵌同值
pub const FBDEV_DATA_VA: u64 = 0x1_8000_1000;
/// fbdev 直写成像常量（LFB 行 0 x=0..63 共 64 px；内核侧 VRAM 物理
/// 读回对账锚——t101 (g) 相位。与文本前景 0x00F0_F0F0 / 黑底 0x0 可区分）。
pub const FBDEV_PAINT: u32 = 0x2B7F_1E00;
/// bail 退出码：SYS_FB_MAP 失败（LFB 移交面 ERR）。
#[allow(dead_code)] // 文档锚点：机器码 bail_map 臂 imm32 内嵌同值
pub const FBDEV_BAIL_MAP: i32 = {FBDEV_BAIL_MAP};
/// bail 退出码：SYS_DEV_PIO 裁量预算耗尽（64 拍重试窗仍 ERR_CAP）。
#[allow(dead_code)] // 文档锚点：机器码 bail_pio 臂 imm32 内嵌同值
pub const FBDEV_BAIL_PIO: i32 = {FBDEV_BAIL_PIO};
/// bail 退出码：dispi 版本下限未过（< 0xB0C0）。
#[allow(dead_code)] // 文档锚点：机器码 bail_dispi 臂 imm32 内嵌同值
pub const FBDEV_BAIL_DISPI: i32 = {FBDEV_BAIL_DISPI};

/// fbdev 驱动进程映像（M42-FBDEV1 阶段一首笔；LXE1 双段：代码 RX
/// @FBDEV_ENTRY + 数据 RW @FBDEV_DATA_VA，栈 = 遗留单帧 0x403000）。
/// 车道序：(1) SYS_FB_MAP({FB_VA_BASE:#x}) LFB 映射移交（SURFACE_OWNER
/// 单面 CAS 首认领者 = 驱动进程）；(2) SYS_DEV_PIO dispi 探测——OUT16
/// 0x1CE←0 + IN16 0x1CF 读版本（≥0xB0C0），ERR_CAP 重试 64 拍
/// （spawn→grant 登记窗免疫——t100 先例同款；r12 重试预算跨 syscall
/// 存续 = M33-P1 callee-saved 帧快照契约）；(3) LFB 行 0 ×64 px 直写
/// FBDEV_PAINT（内核 VRAM 物理读回对账）；(4) SYS_LOG 取证 + EXIT(0)。
/// bail 码 70/71/72 fail-visible（映像不静默）。寄存器约定 = bedrock
/// abi v0/v0.19（rax = 号，rdi/rsi/rdx = 参数）。
pub const FBDEV_LXE: [u8; {len(blob)}] = [
{rs_array(blob)}
];
"""
    OUT.write_text(doc, encoding="utf-8")
    print(f"[gen] {OUT} code={len(code)}B data={len(data)}B blob={len(blob)}B syscall={n_sys}")


if __name__ == "__main__":
    main()
