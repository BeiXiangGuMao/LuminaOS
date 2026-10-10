#!/usr/bin/env python3
"""gen_m14_images.py — M14-① LXE1 多段映像与 EXEC 包装程序生成器。

产物：crates/kernel/src/exec_images_gen.rs（user.rs 经 include! 引入）
  - EXEC1_PROGRAM：t47 探针包装（EXEC(9) 负探针 → EXEC(1) → prog.lxe）
  - EXEC2_PROGRAM：t48 探针包装（EXEC(2) → grow.lxe 增长栈）
  - PROG_LXE：双段映像（代码 RX @0x1_8000_0000 + 数据 RW @0x1_8000_1000）
  - GROW_LXE：单段映像 + 增长栈（stack_top = 0x1_8040_0000）

交叉锚点常量（与 kernel::user 文档锚点双向对账，漂移即 t47/t48 红）：
  FRESH_BASE      = 0x1_8000_0000   （PDPT[6] 全新分支段区）
  STACK_TOP_GROW  = 0x1_8040_0000   （增长栈顶；pt_stack[511] 预映射）
  PROG_DATA_VA    = 0x1_8000_1000   （prog.lxe 数据段）
  SEED_MAGIC      = 0x00B0_0001     （prog.lxe 数据段预置值）
  RESULT_MAGIC    = 0x00B0_0091     （prog.lxe 成功哨兵；低 16 位 = 退出码）
  GROW_MAGIC      = 0x00A5_A5A5     （grow.lxe 写读回校验值）

寄存器约定 = bedrock abi v0：rax = 系统调用号；rdi/rsi/rdx = 参数。
用法：python3 scripts/gen_m14_images.py（工作区根运行）
"""

import struct
from pathlib import Path

# ---- 交叉锚点常量（与 kernel::user 双向对账） ----
FRESH_BASE = 0x1_8000_0000
STACK_TOP_GROW = 0x1_8040_0000
PROG_DATA_VA = 0x1_8000_1000
SEED_MAGIC = 0x00B0_0001
RESULT_MAGIC = 0x00B0_0091
GROW_MAGIC = 0x00A5_A5A5
PAGE = 0x1000

SYS_EXIT, SYS_EXEC = 1, 17

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_gen.rs"


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def le64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


# ---- 指令发射助手（手汇编核算，gen_t45.py 同款纪律） ----
def mov_edi_imm32(imm):
    return b"\xbf" + le32(imm)


def mov_eax_imm32(imm):
    return b"\xb8" + le32(imm)


def syscall():
    return b"\x0f\x05"


def jmp_self():
    return b"\xeb\xfe"


# ---- EXEC 包装程序 ----
def build_exec1_program():
    """EXEC(9) → 期望 ERR_IMAGE(10)；EXEC(1) 成功即不返回；回落 EXIT(76)。"""
    code = b""
    code += mov_edi_imm32(9) + mov_eax_imm32(SYS_EXEC) + syscall()
    code += b"\x48\x83\xf8\x0a"  # cmp rax, 10
    # jne EXIT76（0x10 处，next=0x12，target=0x1E，rel=0x0C）
    code += b"\x75\x0c"
    code += mov_edi_imm32(1) + mov_eax_imm32(SYS_EXEC) + syscall()  # 0x12..0x1D
    code += mov_edi_imm32(76) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x1E..0x2A
    code += jmp_self()  # 0x2B
    assert len(code) == 0x2C, hex(len(code))
    return code


def build_exec2_program():
    """EXEC(2) 成功即不返回（grow.lxe）；回落 EXIT(76)。"""
    code = b""
    code += mov_edi_imm32(2) + mov_eax_imm32(SYS_EXEC) + syscall()  # 0x00..0x0B
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


def build_prog_lxe():
    """双段映像：读数据段种子 → 校验 → 写结果哨兵 → EXIT(91)；错则 EXIT(94)。"""
    code = b""
    # movabs r15, PROG_DATA_VA（0x0A 起）
    code += b"\x49\xbf" + le64(PROG_DATA_VA)
    code += b"\x49\x8b\x07"  # 0x0A: mov rax, [r15]
    code += b"\x48\x3d" + le32(SEED_MAGIC)  # 0x0D: cmp rax, SEED_MAGIC（6B）
    # 0x13: jne fail（next=0x15，target=0x2B，rel=0x16）
    code += b"\x75\x16"
    code += b"\x49\xc7\x47\x08" + le32(RESULT_MAGIC)  # 0x15: mov qword [r15+8], RESULT（8B；REX.WB —— rm=r15）
    code += mov_edi_imm32(91) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x1D..0x29
    code += jmp_self()  # 0x29
    # fail @0x2B
    code += mov_edi_imm32(94) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x2B..0x37
    code += jmp_self()  # 0x37
    assert len(code) == 0x39, hex(len(code))
    data = le64(SEED_MAGIC)  # 数据段载荷：种子魔数（8 字节，尾部清零至整页）
    return lxe_encode(
        FRESH_BASE, 0,
        [(FRESH_BASE, FLAG_X, code, PAGE), (PROG_DATA_VA, FLAG_W, data, PAGE)],
    )


def build_grow_lxe():
    """单段映像 + 增长栈：sub rsp 0x1800 → #PF（内核扩栈）→ 写读回 → EXIT(92)。"""
    code = b""
    code += b"\x48\x81\xec" + le32(0x1800)  # sub rsp, 0x1800
    code += b"\x48\xc7\xc0" + le32(GROW_MAGIC)  # mov rax, GROW_MAGIC
    code += b"\x48\x89\x04\x24"  # mov [rsp], rax
    code += b"\x48\x8b\x14\x24"  # mov rdx, [rsp]
    code += b"\x48\x39\xd0"  # cmp rax, rdx
    # jne fail（0x19 处，next=0x1B，target=0x29，rel=0x0E）
    code += b"\x75\x0e"
    code += mov_edi_imm32(92) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x1B..0x27
    code += jmp_self()  # 0x27
    # fail @0x29
    code += mov_edi_imm32(95) + mov_eax_imm32(SYS_EXIT) + syscall()  # 0x29..0x35
    code += jmp_self()  # 0x35
    assert len(code) == 0x37, hex(len(code))
    return lxe_encode(FRESH_BASE, STACK_TOP_GROW, [(FRESH_BASE, FLAG_X, code, PAGE)])


def rust_array(name, blob, doc):
    lines = [f"/// {doc}", f"pub const {name}: [u8; {len(blob)}] = ["]
    for i in range(0, len(blob), 16):
        chunk = ", ".join(f"0x{b:02X}" for b in blob[i:i + 16])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def main():
    exec1 = build_exec1_program()
    exec2 = build_exec2_program()
    prog = build_prog_lxe()
    grow = build_grow_lxe()
    parts = [
        "// 本文件由 scripts/gen_m14_images.py 生成——勿手改；重跑脚本再生成。",
        "// 交叉锚点常量见脚本头注释与 kernel::user 文档（双向对账）。",
        "",
        rust_array("EXEC1_PROGRAM", exec1,
                   "EXEC 包装程序（t47；EXEC(9) 负探针 → EXEC(1) → prog.lxe；回落 EXIT(76)）"),
        "",
        rust_array("EXEC2_PROGRAM", exec2,
                   "EXEC 包装程序（t48；EXEC(2) → grow.lxe 增长栈；回落 EXIT(76)）"),
        "",
        rust_array("PROG_LXE", prog,
                   "双段 LXE1 映像（t47；代码 RX + 数据 RW @0x1_8000_1000，哨兵 RESULT_MAGIC）"),
        "",
        rust_array("GROW_LXE", grow,
                   "单段 LXE1 映像 + 增长栈（t48；stack_top = 0x1_8040_0000，#PF 驱动扩栈）"),
        "",
    ]
    OUT.write_text("\n".join(parts))
    print(f"written {OUT} ({OUT.stat().st_size} bytes)")
    print(f"EXEC1={len(exec1)}B EXEC2={len(exec2)}B PROG_LXE={len(prog)}B GROW_LXE={len(grow)}B")
    print(f"anchors: FRESH={FRESH_BASE:#x} TOP={STACK_TOP_GROW:#x} "
          f"SEED={SEED_MAGIC:#x} RESULT={RESULT_MAGIC:#x} GROW={GROW_MAGIC:#x}")


if __name__ == "__main__":
    main()
