#!/usr/bin/env python3
"""gen_m16_images.py — M16 探针包装与 Weave 源映像生成器。

产物：crates/kernel/src/exec_images_m16_gen.rs（user.rs 经 include! 引入；
与 M14 的 exec_images_gen.rs 分文件共存——各里程碑生成器只增不改）
  - EXEC3_PROGRAM：t54 探针包装（EXEC(9) 负探针 → EXEC(3) → prog.lwp Weave 包源映像）
  - EXEC4_PROGRAM：t55 探针包装（EXEC(4) → deep.lxe 增长栈动态扩容）
  - DEEP_LXE：单段映像 + 增长栈；程序触达静态 32 页窗口之外的第 40/70 页
    （各触发一次窗口动态扩容 32→64→96），写读回校验后 EXIT(93)

交叉锚点常量（与 kernel::user / vmm 双向对账，漂移即 t54/t55 红）：
  FRESH_BASE      = 0x1_8000_0000   （PDPT[6] 全新分支段区）
  STACK_TOP_GROW  = 0x1_8040_0000   （增长栈顶；pt_stack[511] 预映射）
  GROW_PAGE_A     = 40              （首触页：静态窗（33 页下界）之外 → 扩容 1）
  GROW_PAGE_B     = 70              （次触页：64 页窗下界之外 → 扩容 2）
  DEEP_MAGIC_A    = 0x00E1_0001     （页 A 写读回校验值）
  DEEP_MAGIC_B    = 0x00E2_0002     （页 B 写读回校验值）

寄存器约定 = bedrock abi v0：rax = 系统调用号；rdi/rsi/rdx = 参数。
用法：python3 scripts/gen_m16_images.py（工作区根运行）
"""

import struct
from pathlib import Path

# ---- 交叉锚点常量（与 kernel::user / vmm 双向对账） ----
FRESH_BASE = 0x1_8000_0000
STACK_TOP_GROW = 0x1_8040_0000
GROW_PAGE_A = 40
GROW_PAGE_B = 70
DEEP_MAGIC_A = 0x00E1_0001
DEEP_MAGIC_B = 0x00E2_0002
PAGE = 0x1000

SYS_EXIT, SYS_EXEC = 1, 17

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_m16_gen.rs"


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def le64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def disp32(v):
    """有符号 32 位位移（小端补码）。"""
    return struct.pack("<i", v)


# ---- 指令发射助手（手汇编核算，gen_m14 同款纪律） ----
def mov_edi_imm32(imm):
    return b"\xbf" + le32(imm)


def mov_eax_imm32(imm):
    return b"\xb8" + le32(imm)


def movabs_rax_imm64(imm):
    return b"\x48\xb8" + le64(imm)


def movabs_r15_imm64(imm):
    return b"\x49\xbf" + le64(imm)


def mov_r15disp_rax(disp):
    """mov [r15 + disp32], rax —— 49 89 87（REX.WB，mod=10 disp32，rm=r15，reg=rax）"""
    return b"\x49\x89\x87" + disp32(disp)


def mov_rax_r15disp(disp):
    """mov rdx, [r15 + disp32] —— 49 8B 97（reg=rdx=010）"""
    return b"\x49\x8b\x97" + disp32(disp)


def cmp_rax_rdx():
    return b"\x48\x39\xd0"


def jne_rel8(rel):
    assert 0 < rel < 0x80
    return b"\x75" + bytes([rel])


def syscall():
    return b"\x0f\x05"


def jmp_self():
    return b"\xeb\xfe"


# ---- EXEC 包装程序（t54/t55） ----
def build_exec3_program():
    """EXEC(9) → 期望 ERR_IMAGE(10)；EXEC(3) 成功即不返回（prog.lwp）；回落 EXIT(76)。"""
    code = b""
    code += mov_edi_imm32(9) + mov_eax_imm32(SYS_EXEC) + syscall()
    code += b"\x48\x83\xf8\x0a"  # cmp rax, 10
    # jne EXIT76（0x10 处，next=0x12，target=0x1E，rel=0x0C）
    code += b"\x75\x0c"
    code += mov_edi_imm32(3) + mov_eax_imm32(SYS_EXEC) + syscall()  # 0x12..0x1D
    code += mov_edi_imm32(76) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x1E..0x2A
    code += jmp_self()  # 0x2B
    assert len(code) == 0x2C, hex(len(code))
    return code


def build_exec4_program():
    """EXEC(4) 成功即不返回（deep.lxe 增长栈动态扩容）；回落 EXIT(76)。"""
    code = b""
    code += mov_edi_imm32(4) + mov_eax_imm32(SYS_EXEC) + syscall()  # 0x00..0x0B
    code += mov_edi_imm32(76) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x0C..0x18
    code += jmp_self()  # 0x19
    assert len(code) == 0x1A, hex(len(code))
    return code


# ---- LXE1 容器（与 bedrock::exec encode 同布局；双侧漂移即宿主/裸机测试红） ----
def lxe_encode(entry, stack_top, segs):
    """segs = [(vaddr, flags, data, mem_len)]；布局见 bedrock/src/exec.rs 模块文档。"""
    assert 1 <= len(segs) <= 8
    assert stack_top % PAGE == 0
    hdr = b"LXE1" + le32(1) + le32(len(segs)) + le32(0)
    hdr += le64(entry) + le64(stack_top)
    payload_off = 64 + 32 * len(segs)
    hdr += le64(payload_off) + b"\x00" * 24
    segtab = b""
    for vaddr, flags, data, mem_len in segs:
        assert vaddr % PAGE == 0 and len(data) <= mem_len and flags in (1, 2, 3)
        segtab += le64(vaddr) + le64(mem_len) + le64(len(data)) + le64(flags)
    payload = b"".join(s[2] for s in segs)
    return hdr + segtab + payload


FLAG_W, FLAG_X = 1, 2


def build_deep_lxe():
    """增长栈动态扩容映像：触页 A（第 40 页，静态窗外）→ 扩容 1 → 触页 B
    （第 70 页，64 页窗外）→ 扩容 2 → 写读回各校验 → EXIT(93)；错则 EXIT(96)。"""
    disp_a = -GROW_PAGE_A * PAGE
    disp_b = -GROW_PAGE_B * PAGE
    code = b""
    # 0x00: movabs r15, STACK_TOP_GROW
    code += movabs_r15_imm64(STACK_TOP_GROW)
    # 0x0A: movabs rax, MAGIC_A；写页 A（扩容 1：#PF → 窗口 32→64）
    code += movabs_rax_imm64(DEEP_MAGIC_A)          # 0x0A..0x13
    code += mov_r15disp_rax(disp_a)                  # 0x14..0x1A
    code += mov_rax_r15disp(disp_a)                  # 0x1B..0x21
    code += cmp_rax_rdx()                            # 0x22..0x24
    # 0x25: jne fail（next=0x27，target=0x52，rel=0x2B）
    code += jne_rel8(0x2B)
    # 0x27: movabs rax, MAGIC_B；写页 B（扩容 2：#PF → 窗口 64→96）
    code += movabs_rax_imm64(DEEP_MAGIC_B)          # 0x27..0x30
    code += mov_r15disp_rax(disp_b)                  # 0x31..0x37
    code += mov_rax_r15disp(disp_b)                  # 0x38..0x3E
    code += cmp_rax_rdx()                            # 0x3F..0x41
    # 0x42: jne fail（next=0x44，target=0x52，rel=0x0E）
    code += jne_rel8(0x0E)
    # 0x44: EXIT(93)
    code += mov_edi_imm32(93) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x44..0x4F
    code += jmp_self()                               # 0x50
    # fail @0x52
    code += mov_edi_imm32(96) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x52..0x5D
    code += jmp_self()                               # 0x5E
    assert len(code) == 0x60, hex(len(code))
    return lxe_encode(FRESH_BASE, STACK_TOP_GROW, [(FRESH_BASE, FLAG_X, code, PAGE)])


def rust_array(name, blob, doc):
    lines = [f"/// {doc}", f"pub const {name}: [u8; {len(blob)}] = ["]
    for i in range(0, len(blob), 16):
        chunk = ", ".join(f"0x{b:02X}" for b in blob[i:i + 16])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def main():
    exec3 = build_exec3_program()
    exec4 = build_exec4_program()
    deep = build_deep_lxe()
    parts = [
        "// 本文件由 scripts/gen_m16_images.py 生成——勿手改；重跑脚本再生成。",
        "// 交叉锚点常量见脚本头注释与 kernel::user / vmm 文档（双向对账）。",
        "",
        rust_array("EXEC3_PROGRAM", exec3,
                   "EXEC 包装程序（t54；EXEC(9) 负探针 → EXEC(3) → prog.lwp Weave 包源映像；回落 EXIT(76)）"),
        "",
        rust_array("EXEC4_PROGRAM", exec4,
                   "EXEC 包装程序（t55；EXEC(4) → deep.lxe 增长栈动态扩容；回落 EXIT(76)）"),
        "",
        rust_array("DEEP_LXE", deep,
                   "单段 LXE1 映像 + 增长栈动态扩容（t55；stack_top = 0x1_8040_0000，触页 40/70 各触发扩容）"),
        "",
    ]
    OUT.write_text("\n".join(parts))
    print(f"written {OUT} ({OUT.stat().st_size} bytes)")
    print(f"EXEC3={len(exec3)}B EXEC4={len(exec4)}B DEEP_LXE={len(deep)}B")
    print(f"anchors: FRESH={FRESH_BASE:#x} TOP={STACK_TOP_GROW:#x} "
          f"pages=({GROW_PAGE_A},{GROW_PAGE_B}) magic=({DEEP_MAGIC_A:#x},{DEEP_MAGIC_B:#x})")


if __name__ == "__main__":
    main()
