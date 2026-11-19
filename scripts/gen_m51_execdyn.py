#!/usr/bin/env python3
"""gen_m51_execdyn.py — M51-EXECDYN73（笔84）ring3 SYS_EXEC 动态分流探针生成器。

产物（deliverable 面）：
  1. artifacts/execdyn-probe.elf —— ring3 SYS_EXEC 动态分流电气探针
     （原生 ABI ET_EXEC 静态映像）：LOG("T162P-A exec-pre") →
     SYS_EXEC(5)〔rdi=映像号 5 = EXEC_IMAGES 新尾槽 /bin/busybox-dyn〕
     → 成功即不返回（同任务 CR3 替换 → 动态分流臂 → musl ldso ring3
     真执行 → busybox-dyn usage 退出——父收割对账）；失败路径
     LOG("T162P-B exec-fail") → EXIT(97) fail-visible。
  2. artifacts/execdyn-miss.elf —— 迷你 ET_DYN + PT_INTERP 动态件
     （PT_INTERP = "/lib/ld-musl-miss.so"——VFS 缺位路径）：仅供
     exec_load_switch 直呼 NEG 相位（解释器缺位 → BadImage 提前返回
     ——装载前置闸零 CR3 写，kmain 任务态零污染）。件体最小合法
     （probe 魔数 + parse ET_DYN/PT_INTERP 判定通过即可——不装载）。
  3. crates/kernel/src/exec_images_m51.rs —— 字节域封装
     （user.rs include! 引入——M48/M50 gen lane 同谱）。

编码纪律：SYS_EXEC(17) ABI = rax=17 / rdi=映像号（bedrock abi v0
寄存器约定）；成功路径 syscall 不返回（sys_exec → exec_load_switch
改写 SyscallFrame → SYSRET 即入新映像）；同任务 exec 替换语义 =
Linux execve(2) 同谱（t47/t51 LXE 车道先例 + t161 fork 桩面互证）。
结构自检（fail-visible）：ELF 头/入口/PT_LOAD 两段 + objdump 反汇编
锚（syscall 计数）。
"""

import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m51.rs"

PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56
PT_LOAD = 1
PT_INTERP = 3
PF_X = 1
PF_W = 2
PF_R = 4
ET_EXEC = 2
ET_DYN = 3
CODE_VA = 0x400000  # 探针代码段基（t150/t160 同谱）
DATA_VA = 0x401000  # 探针数据段基
MISS_VA = 0x402000  # miss 件段基（仅 parse 判定承载——不装载）

SYS_EXIT = 1
SYS_LOG = 0
SYS_EXEC = 17
IMAGE_BUSYBOX_DYN = 5  # EXEC_IMAGES 尾槽（M51-EXECDYN73 笔84）
EXIT_FAIL = 97

MSG_A = b"T162P-A exec-pre"
MSG_B = b"T162P-B exec-fail"
INTERP_MISS = b"/lib/ld-musl-miss.so\x00"


def build_data() -> tuple[bytes, dict]:
    """数据段：两 LOG 标记串（rdi 指针域——validate_user_slice 用户
    可达映射 = 本段 RW 承载）。"""
    blob = bytearray()
    offs = {}
    for name in (MSG_A, MSG_B):
        offs[name] = len(blob)
        blob += name
        blob += b"\x00"
        while len(blob) % 16 != 0:
            blob += b"\x00"
    return bytes(blob), offs


def build_probe_code(doffs: dict) -> bytes:
    """ring3 SYS_EXEC 动态分流探针代码段。布局：LOG A → SYS_EXEC(5)
    （成功不返回——同任务替换）→ 失败路径 LOG B → EXIT(97)。

    exec 摸路纪律（t161 同谱）：探针零 SYS_YIELD（yield 恢复域对本
    任务类重入 trampoline 非续点恢复——M50-IOPB71 揭雷③实录随批
    记档）；spawn 首派发经定时器抢占窗自然推进。
    """
    a = bytearray()
    # LOG A：rdi = DATA_VA + off(A)（EDData 段 VA 直算），rsi = len
    a += bytes([0xBF]) + struct.pack("<I", DATA_VA + doffs[MSG_A])
    a += bytes([0xBE]) + struct.pack("<I", len(MSG_A))
    a += bytes([0x31, 0xC0])  # xor eax, eax（SYS_LOG=0）
    a += bytes([0x0F, 0x05])  # syscall
    # SYS_EXEC(image=5)：rdi=5, rax=17——成功即不返回
    a += bytes([0xBF]) + struct.pack("<I", IMAGE_BUSYBOX_DYN)
    a += bytes([0xB8]) + struct.pack("<I", SYS_EXEC)
    a += bytes([0x0F, 0x05])  # syscall
    # 失败路径（fail-visible）：LOG B → EXIT(97)
    a += bytes([0xBF]) + struct.pack("<I", DATA_VA + doffs[MSG_B])
    a += bytes([0xBE]) + struct.pack("<I", len(MSG_B))
    a += bytes([0x31, 0xC0])  # xor eax, eax（SYS_LOG=0）
    a += bytes([0x0F, 0x05])  # syscall
    a += bytes([0xBF]) + struct.pack("<I", EXIT_FAIL)  # mov edi, 97
    a += bytes([0xB8]) + struct.pack("<I", SYS_EXIT)   # mov eax, SYS_EXIT
    a += bytes([0x0F, 0x05])                           # syscall
    a += bytes([0xEB, 0xFD])                           # jmp 防御环（回 exit）
    return bytes(a)


def elf_static_exec(code: bytes, data: bytes) -> bytes:
    """原生 ABI ET_EXEC 静态映像（gen_m50_iopb 同款——RX 代码段 + RW
    数据段〔LOG 标记串承载〕）。"""
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


def elf_dyn_miss() -> bytes:
    """迷你 ET_DYN + PT_INTERP 动态件（NEG 相位——解释器缺位车道
    拒收面）。仅 parse 判定承载（probe 魔数 + ET_DYN + PT_INTERP 串
    ——exec_load_switch 分流臂 parse 后 vfs MISS → BadImage 提前
    返回；零段装载零 CR3 写）。"""
    phnum = 2
    phoff = EHDR_LEN
    interp_off = PAGE  # PT_INTERP 串载荷页
    # 小 RX 段（4 B NOP——parse 段域合法性承载；entry 落段内）
    code = b"\x90\x90\x90\x90"
    code_off = 2 * PAGE
    total = 3 * PAGE
    blob = bytearray(total)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2
    blob[5] = 1
    blob[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        0x10,
        ET_DYN,
        62,
        1,
        MISS_VA,  # e_entry（PIE 基式 vaddr）
        phoff,
        0,
        0,
        EHDR_LEN,
        PHDR_LEN,
        phnum,
        0,
        0,
        0,
    )
    # phdr[0] = PT_LOAD RX（代码段）
    struct.pack_into(
        "<IIQQQQQQ",
        blob,
        phoff,
        PT_LOAD,
        PF_R | PF_X,
        code_off,
        MISS_VA,
        MISS_VA,
        len(code),
        len(code),
        PAGE,
    )
    blob[code_off : code_off + len(code)] = code
    # phdr[1] = PT_INTERP（解释器路径串——VFS 缺位路径）
    struct.pack_into(
        "<IIQQQQQQ",
        blob,
        phoff + PHDR_LEN,
        PT_INTERP,
        PF_R,
        interp_off,
        MISS_VA,
        MISS_VA,
        len(INTERP_MISS),
        len(INTERP_MISS),
        PAGE,
    )
    blob[interp_off : interp_off + len(INTERP_MISS)] = INTERP_MISS
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
        print("[gen_m51_execdyn] objdump 缺席——反汇编锚降级（生成面自检在环）")
        return
    n = out.count("syscall")
    assert n == 4, f"syscall 计数漂移：{n} ≠ 4"
    print("[gen_m51_execdyn] objdump 锚：syscall×4 全显形")


def main():
    data, doffs = build_data()
    code = build_probe_code(doffs)
    probe = elf_static_exec(code, data)
    miss = elf_dyn_miss()

    # 结构自检（fail-visible）
    assert probe[0:4] == b"\x7fELF", "探针 ELF 魔数漂移"
    e_entry = struct.unpack_from("<Q", probe, 0x18)[0]
    assert e_entry == CODE_VA, f"探针入口漂移：{e_entry:#x}"
    assert code.count(b"\x0f\x05") == 4, "探针 syscall 计数漂移〔LOG×2 + exec + exit = 4〕"
    assert miss[0:4] == b"\x7fELF", "miss 件魔数漂移"
    m_type = struct.unpack_from("<H", miss, 0x10)[0]
    assert m_type == ET_DYN, f"miss 件 e_type 漂移：{m_type}"
    assert miss[interp_off_pos(miss) : interp_off_pos(miss) + len(INTERP_MISS)] == INTERP_MISS, \
        "miss 件 PT_INTERP 串漂移"
    objdump_check(code)

    ART.mkdir(exist_ok=True)
    (ART / "execdyn-probe.elf").write_bytes(probe)
    (ART / "execdyn-miss.elf").write_bytes(miss)

    body = ",\n    ".join(
        ", ".join(f"0x{b:02X}" for b in probe[i : i + 16])
        for i in range(0, len(probe), 16)
    )
    mbody = ",\n    ".join(
        ", ".join(f"0x{b:02X}" for b in miss[i : i + 16])
        for i in range(0, len(miss), 16)
    )
    rs = (
        "// exec_images_m51 —— M51-EXECDYN73 笔84 交付件映像（gen_m51_execdyn.py 产物）。\n"
        "//\n"
        "// - EXEC_DYN_PROBE_ELF：ring3 SYS_EXEC 动态分流电气探针（原生 ABI\n"
        "//   ET_EXEC）——LOG(\"T162P-A exec-pre\") → SYS_EXEC(5)〔映像号 5 =\n"
        "//   EXEC_IMAGES 尾槽 /bin/busybox-dyn〕成功即不返回（同任务 CR3\n"
        "//   替换 → exec_load_switch PT_INTERP 动态分流臂 → musl ldso ring3\n"
        "//   真执行 → busybox-dyn usage 退出——父收割对账）；失败路径\n"
        f"//   LOG(\"T162P-B exec-fail\") → EXIT({EXIT_FAIL}) fail-visible。\n"
        "// - EXEC_DYN_MISS_ELF：迷你 ET_DYN + PT_INTERP 动态件\n"
        "//   （PT_INTERP = /lib/ld-musl-miss.so——VFS 缺位路径）——仅供\n"
        "//   exec_load_switch 直呼 NEG 相位（解释器缺位 → BadImage 提前\n"
        "//   返回——装载前置闸零 CR3 写，kmain 任务态零污染）。\n\n"
        "/// ring3 SYS_EXEC 动态分流电气探针（ET_EXEC——t162 LIVE 相位）。\n"
        f"pub const EXEC_DYN_PROBE_ELF: &[u8] = &[\n    {body},\n];\n\n"
        "/// 迷你动态件（ET_DYN + PT_INTERP 缺位路径——t162 NEG 相位）。\n"
        f"pub const EXEC_DYN_MISS_ELF: &[u8] = &[\n    {mbody},\n];\n"
    )
    GEN.write_text(rs)
    print(
        f"[gen_m51_execdyn] probe={len(probe)}B miss={len(miss)}B → artifacts/execdyn-probe.elf"
        f" + artifacts/execdyn-miss.elf + exec_images_m51.rs"
    )


def interp_off_pos(miss: bytes) -> int:
    """miss 件 PT_INTERP 载荷偏移（结构自检读取面）。"""
    return 0x1000


if __name__ == "__main__":
    main()
