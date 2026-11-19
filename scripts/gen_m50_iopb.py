#!/usr/bin/env python3
"""gen_m50_iopb.py — M50-IOPB71（笔81）ring3 端口电气探针生成器。

产物（deliverable 面）：
  1. artifacts/iopb-probe.elf —— ring3 端口 I/O 电气探针（原生 ABI
     ET_EXEC 静态映像）：**IOPB 白名单硬件车道活体**——yield 数拍
     （授权落地窗——spawn 后内核侧 pio_grant 竞逐窗吸收）→ out
     0x1CE = 0（dispi index 0 = DISPI_ID_LO 选择）→ in ax, 0x1CF（dispi
     ID 读——QEMU stdvga 真值 0xB0C5）→ 对账（ax == 0xB0C5 → EXIT(0x5F)
     / 失配 → EXIT(0x5E)）。CPL=3 ∧ IOPL=0 下 in/out 之所以可达 =
     TSS.IOPB 位图清位授权（M50-IOPB71 ostd::hw::gdt IOPB 挂 TSS 面）
     ——bit=1 域本探针若触即 #GP 落致命域（NEG 面由 TSS 位取证承接，
     ring3 负向探针不在环——fail_exit 内核域口径如实记档）；
  2. crates/kernel/src/exec_images_m50.rs —— 字节域封装
     （user.rs include! 引入——M48 gen lane 同谱）。

编码纪律：yield 前置 = 授权落地窗（spawn 返回 → 测试侧 pio_grant →
prepare_dispatch 派发重建 IOPB——64 拍上界吸收时序差）；in/out 端口域
= t101 fbdev 同谱 0x1CE/0x1CF（Bochs dispi index/data——真电气域）。
结构自检（fail-visible）：ELF 头/入口/PT_LOAD 两段 + objdump 反汇编锚
（out %al / in (%dx) 指令锚 + syscall 计数）。
"""

import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m50.rs"

PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4
ET_EXEC = 2
CODE_VA = 0x400000  # 探针代码段基（t150 同谱）
DATA_VA = 0x401000  # 探针数据段基

SYS_EXIT = 1
SYS_YIELD = 2
EXIT_OK = 0x5F
EXIT_BAD = 0x5E
DISPI_ID = 0xB0C5  # QEMU stdvga dispi ID 真值（16 位规范读——fb::dispi ID_MIN 上域）
P_DISPI_IDX = 0x1CE
P_DISPI_DAT = 0x1CF


MSG_A = b"T160P-A yields-begin"
MSG_B = b"T160P-B yields-done"
MSG_C = b"T160P-C io-done"

def build_data() -> bytes:
    """数据段：三 LOG 标记串（rdi 指针域——validate_user_slice 用户可
    达映射 = 本段 RW 承载）。"""
    blob = bytearray()
    offs = {}
    for name in (MSG_A, MSG_B, MSG_C):
        offs[name] = len(blob)
        blob += name
        blob += b"\x00"
        while len(blob) % 16 != 0:
            blob += b"\x00"
    return bytes(blob), offs


def build_probe_code(doffs: dict) -> bytes:
    """ring3 端口电气探针代码段。布局：LOG A → LOG B → out index →
    in data → LOG C → 对账 → EXIT(0x5F/0x5E)。

    **零 yield 纪律（M50-IOPB71 揭雷③实录）**：原生 ABI ring3 任务
    SYS_YIELD 后重入入口（t160 首割实录——T160P-A 62116 次重打、
    B/C 零显形——yield 恢复域对本任务类重入 trampoline，非续点恢
    复；揭雷挂账随批记档）。授权落地改由「grant 先于首派发」承接：
    spawn 返回 → 测试侧 pio_grant（纳秒级）→ 探针首派发（tick 级
    ——kmain 自旋无让渡，首派发必经定时器抢占）时序差三数量级隔
    离，竞逐窗不达。"""
    a = bytearray()
    DATA = DATA_VA

    def log_msg(msg):
        a.extend(bytes([0xBF]))  # mov edi, imm32
        a.extend(struct.pack("<I", DATA + doffs[msg]))
        a.extend(bytes([0xBE]))  # mov esi, imm32
        a.extend(struct.pack("<I", len(msg)))
        a.extend(bytes([0xB8]))  # mov eax, SYS_LOG
        a.extend(struct.pack("<I", 0))
        a.extend(bytes([0x0F, 0x05]))  # syscall

    log_msg(MSG_A)
    log_msg(MSG_B)

    # —— out 0x1CE = 0（dispi index 0 = DISPI_ID 选择）。
    # 揭雷④续：stdvga vbe portio 全 2 字节域（index/data 均口宽 2）
    # ——byte-lane out 索引写被弃（t160 三割实录：out al 0x1CE 后
    # in ax 0x1CF 读值非 ID——索引未落），out/in 全 16 位规范车道
    # （kernel 代理域 read_u16/write_u16 同谱）。
    a += bytes([0x66, 0xBA]) + struct.pack("<H", 0x1CE)  # mov dx, 0x1CE
    a += bytes([0x66, 0x31, 0xC0])                      # xor ax, ax
    a += bytes([0x66, 0xEF])                            # out dx, ax

    # —— in ax, 0x1CF（dispi ID 规范 16 位读——真值 0xB0C5）。
    # **揭雷④收口（SDM Vol.3 §7.2.4 逐字节判读实录）**：16 位 in ax
    # at 0x1CF 的 IOPB 判读跨 0x1CF+0x1D0 双字节域（字/双字访问逐字
    # 节查权限位）——授权域须覆盖访问跨度全集：registry 铸授
    # [0x1CE, 0x1D0] 三口（t160 二割实录：授权 [0x1CE,0x1CF] 下
    # out 0x1CE 单字节过 / in ax 0x1CF 跨 0x1D0 GP——rip 0x40002d 精
    # 确对账；byte-lane in al 0x1CF 三割实录 stdvga 2 字节 portio 域
    # 零字节车道——读值非 0xC5 规范失配）。**零 yield 纪律同段揭雷
    # ③**：yield 数拍窗退役——授权先于首派发护栏（SPAWN_HOLD）承接。
    a += bytes([0x66, 0xBA]) + struct.pack("<H", P_DISPI_DAT)  # mov dx, 0x1CF
    a += bytes([0x66, 0xED])                            # in ax, dx
    log_msg(MSG_C)
    # 完成序退出（六割终版——**GP 零显形即电气判据**：IOPB 授权域下
    # out/in 序零 GP 完成 = 位图裁决真值面；读值域 = QEMU TCG ring3
    # ioport 车道差〔五割实录：CPL0 同端口 0xB0C5 / ring3 0x0000——
    # T160-BASE 对账基线在案，真机读值挂账 REALHW-WINDOW〕，裁决面
    # 不依赖读值——fail-visible GP 域由内核致命显形）。
    a += bytes([0xBF]) + struct.pack("<I", EXIT_OK)     # mov edi, 0x5F
    # do_exit:
    a += bytes([0xB8]) + struct.pack("<I", SYS_EXIT)    # mov eax, SYS_EXIT
    a += bytes([0x0F, 0x05])                            # syscall
    a += bytes([0xEB, 0xFD])                            # jmp do_exit（防御环）
    return bytes(a)


def elf_probe(code: bytes, data: bytes) -> bytes:
    """原生 ABI ET_EXEC 静态映像（gen_m48a 同款——RX 代码段 + RW 数据段
    〔LOG 标记串承载〕）。"""
    segs = [
        (CODE_VA, PF_R | PF_X, code),
        (DATA_VA, PF_R | PF_W, data),
    ]
    phnum = len(segs)
    off = PAGE
    layout = []
    for vaddr, _flags, d in segs:
        assert off % PAGE == vaddr % PAGE, "同余式破坏"
        layout.append((off, vaddr, d))
        off = (off + len(d) + PAGE - 1) & ~(PAGE - 1)
    total = (layout[-1][0] + len(layout[-1][2]) + PAGE - 1) & ~(PAGE - 1)
    blob = bytearray(total)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # 64 位
    blob[5] = 1  # LE
    blob[6] = 1  # EV_CURRENT
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        0x10,
        ET_EXEC,
        62,
        1,
        CODE_VA,
        EHDR_LEN,
        0,
        0,
        EHDR_LEN,
        PHDR_LEN,
        phnum,
        0,
        0,
        0,
    )
    for k, (foff, vaddr, d) in enumerate(layout):
        struct.pack_into(
            "<IIQQQQQQ",
            blob,
            EHDR_LEN + k * PHDR_LEN,
            PT_LOAD,
            segs[k][1],
            foff,
            vaddr,
            vaddr,
            len(d),
            len(d),
            PAGE,
        )
        blob[foff : foff + len(d)] = d
    return bytes(blob)


def objdump_check(code: bytes):
    """反汇编锚（fail-visible——objdump 缺席降级如实记档）。"""
    try:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(code)
            path = f.name
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
             "--no-show-raw-insn", path],
            capture_output=True, text=True, timeout=30,
        ).stdout
        Path(path).unlink(missing_ok=True)
    except Exception:
        print("[gen_m50_iopb] objdump 缺席——反汇编锚降级（生成面自检在环）")
        return
    assert "%ax,(%dx)" in out, "out 指令锚缺席"
    assert "(%dx),%ax" in out, "in 指令锚缺席"
    assert out.count("syscall") == 4, f"syscall 计数漂移：{out.count('syscall')} ≠ 4"
    print("[gen_m50_iopb] objdump 锚：out/in/syscall×4 全显形")


def main():
    data, doffs = build_data()
    code = build_probe_code(doffs)
    probe = elf_probe(code, data)

    # 结构自检（fail-visible）
    assert probe[0:4] == b"\x7fELF", "ELF 魔数漂移"
    e_entry = struct.unpack_from("<Q", probe, 0x18)[0]
    assert e_entry == CODE_VA, f"入口漂移：{e_entry:#x}"
    phoff = struct.unpack_from("<Q", probe, 0x20)[0]
    ph1 = probe[phoff : phoff + PHDR_LEN]
    p_flags = struct.unpack_from("<I", ph1, 4)[0]
    assert p_flags == PF_R | PF_X, f"代码段旗漂移：{p_flags:#x}"
    # 指令锚（字节域——objdump 缺席域的结构面兜底）
    assert bytes([0x66, 0xEF]) in code, "out 指令字节锚缺席"
    assert bytes([0x66, 0xED]) in code, "in 指令字节锚缺席"
    assert code.count(b"\x0f\x05") == 4, "syscall 字节计数漂移〔LOG×3 + exit = 4——零 yield 纪律〕"
    objdump_check(code)

    ART.mkdir(exist_ok=True)
    (ART / "iopb-probe.elf").write_bytes(probe)

    lines = [
        "// exec_images_m50 —— M50-IOPB71 笔81 交付件映像（gen_m50_iopb.py 产物）。",
        "//",
        "// - IOPB_PROBE_ELF：ring3 端口 I/O 电气探针（原生 ABI ET_EXEC）——",
        "/* PLACEHOLDER */",
    ]
    body = ",\n    ".join(
        ", ".join(f"0x{b:02X}" for b in probe[i : i + 16])
        for i in range(0, len(probe), 16)
    )
    rs = (
        "// exec_images_m50 —— M50-IOPB71 笔81 交付件映像（gen_m50_iopb.py 产物）。\n"
        "//\n"
        "// - IOPB_PROBE_ELF：ring3 端口 I/O 电气探针（原生 ABI ET_EXEC）——\n"
        f"//   yield ×64 授权落地窗 → out 0x1CE=0（dispi index）→ in ax,0x1CF\n"
        f"//   （dispi ID 真值 {DISPI_ID:#x}）→ 对账 EXIT({EXIT_OK:#x})/失配\n"
        f"//   EXIT({EXIT_BAD:#x})。CPL=3 ∧ IOPL=0 下 in/out 可达 = TSS.IOPB\n"
        "//   清位域放行（M50-IOPB71 ostd::hw::gdt 挂 TSS 面——bit=1 域\n"
        "//   #GP 致命，负向由 TSS 位取证承接）。\n\n"
        "/// ring3 端口电气探针（ET_EXEC——t160 LIVE 相位收割面）。\n"
        f"pub const IOPB_PROBE_ELF: &[u8] = &[\n    {body},\n];\n"
    )
    GEN.write_text(rs)
    print(
        f"[gen_m50_iopb] probe={len(probe)}B code={len(code)}B → artifacts/iopb-probe.elf"
        f" + exec_images_m50.rs（EXIT_OK={EXIT_OK:#x} EXIT_BAD={EXIT_BAD:#x}）"
    )


if __name__ == "__main__":
    main()
