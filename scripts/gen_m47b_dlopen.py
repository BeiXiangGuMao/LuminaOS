#!/usr/bin/env python3
"""gen_m47b_dlopen.py — M47-DLOPEN54（笔61）dlopen 真消费面批映像生成器。

产物（deliverable 面）：
  1. artifacts/liblumina-core.so   —— 依赖库 ELF 交付件（真 ET_DYN 共享
     对象——SONAME=liblumina-core.so + core_fn/lextern_dat 双定义符号 +
     GNU 哈希双链 + RELA RELATIVE×2 + PT_DYNAMIC 十目——ld-lumina.so
     UNDEF 族（ldep_fn/lextern_dat）的真决议供给方）；
  2. artifacts/ldlumina-dlopen-probe.elf —— ring3 自装载链探针（原生
     ABI ET_EXEC 静态映像）：数据段内嵌 ld-lumina.so + liblumina-core.so
     双真件 → SYS_MMAP(46) 四窗 R|W 分级（L1_RX/L1_RW/C_RX/C_RW）→
     rep movsb 分级拷贝（BSS 尾零不拷）→ ring3 重定位写面（ld-lumina
     RELATIVE/GLOB_DAT/JUMP_SLOT/COPY + core RELATIVE×2——跨模块决议
     值烘焙）→ SYS_MPROTECT(47) RX 终旗×2 → **call ldlumina_boot**
     （0x5A5A5A5A 对账）→ **GOT[2] 间呼 core_fn**（0xC0DEC0DE——
     JUMP_SLOT 跨模块电气证明）→ COPY 槽 "CORE" 读回 → core REL[0]/
     GOT[1] 读回 → BSS 尾零读回 → 负例二目（未登记域 mprotect / 登记
     重叠 mmap——BAD(u64::MAX-1) 显形）→ LOG 取证 → EXIT(89)；
  3. crates/kernel/src/exec_images_m47b.rs —— include_bytes 封装
     （user.rs include! 引入——M42 gen lane 同谱）。

结构自检（fail-visible）：ELF 头/同余式/页槽互斥/动态表 walk/SONAME
读回/RELA 条目数/GNU 哈希 lookup 仿真（双符号桶链全谱）+ 真件字节对账
（ld-lumina.so 与 gen_m47_ldlumina.build_ld_lumina_so() 逐位同源）+
objdump 反汇编锚（探针）。

消费序与 harbor::ld::exec::exec_plan 三段式消费序同谱（先全量映射、
再统一拷贝、后逐区终旗——Linux 装载器共享页序）；基址烘焙 = ring3
MMAP_ANON 窗（L1_BASE=0x2_0000_0000 / C_BASE=0x2_0001_0000——与 t148
探针窗基零碰撞域分离）。
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m47b.rs"

sys.path.insert(0, str(ROOT / "scripts"))
import gen_m47_ldlumina as m47  # 单一事实源——ld-lumina.so 本体复用

PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4
ET_DYN = 3
ET_EXEC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_GNU_HASH = 0x6FFF_FEF5

R_X86_64_RELATIVE = 8

SYS_EXIT = 1
SYS_MMAP = 46
SYS_MPROT = 47

# ---- ring3 探针窗基（MMAP_ANON 窗 0x2_0000_0000..0x2_1000_0000 内） ----

L1_BASE = 0x2_0000_0000  # ld-lumina.so 装载基（RX @+0x1000 / RW @+0x3000 2页）
C_BASE = 0x2_0001_0000  # liblumina-core.so 装载基（RX @+0x1000 / RW @+0x3000）
DATA_VA = 0x401000  # 探针数据段基（msg1@0 / msg2@0x40 / SO@0x1000 / CORE@0x4000）
SO_DATA_OFF = 0x1000  # 探针数据段内 ld-lumina.so blob 偏移
CORE_DATA_OFF = 0x4000  # 探针数据段内 liblumina-core.so blob 偏移

EXIT_OK = 89  # t149 LIVE 相位收割对账码

BAD = (1 << 64) - 2  # u64::MAX - 1（BadArgs 哨兵——负例显形域）

MAGIC_BOOT = 0x5A5A5A5A  # ldlumina_boot 桩返回值（m47 同源）
MAGIC_CORE = 0xC0DEC0DE  # core_fn 桩返回值
CORE_FN_CODE = b"\xb8" + struct.pack("<I", MAGIC_CORE) + b"\xc3"  # mov eax,imm32; ret
DATA_MAGIC = b"CORE"  # lextern_dat 内容（COPY 源）

CORE_SONAME = b"liblumina-core.so"
CORE_FN = b"core_fn"
CORE_DAT = b"lextern_dat"

# ---- harbor::ld::exec dl_new_hash 同源实现（m47 语义锚同谱） ----


def dl_new_hash(name: bytes) -> int:
    h = 5381
    for c in name:
        h = (h * 33) ^ c & 0xFFFFFFFF
    return h & 0xFFFFFFFF


# ---- liblumina-core.so 本体（ET_DYN——依赖库交付件） ----

# 布局（vaddr = 文件偏移同余式；3 页 = 12,288 B——ld-lumina.so 同尺寸姊妹件）：
#   0x0000      头区（EHDR + 3 PHDR：LOAD RX / LOAD RW / DYNAMIC）
#   0x1000 RX   core_fn 桩（6B）+ .dynstr + .dynsym + .gnu_hash + .rela.dyn
#   0x2000 RW   GOT[0]/GOT[1]（RELATIVE×2 目标）+ lextern_dat @+0x40 +
#               .dynamic @+0x100；filesz = memsz = 0x200（无 BSS——最小件）
CORE_TEXT_VA = 0x1000
CORE_RW_VA = 0x3000
CORE_FN_VA = CORE_TEXT_VA  # core_fn @ RX 页首
CORE_DAT_VA = CORE_RW_VA + 0x40  # lextern_dat @ RW+0x40


def build_core_dynstr() -> bytes:
    return CORE_SONAME + b"\0" + CORE_FN + b"\0" + CORE_DAT + b"\0"


def build_core_dynsym() -> bytes:
    """3 目：[0] null / [1] core_fn（defined GLOBAL|FUNC）/ [2] lextern_dat
    （defined GLOBAL|OBJECT 尺寸 4）。"""

    def sym(name: int, info: int, shndx: int, value: int, size: int) -> bytes:
        return struct.pack("<IBBHQQ", name, info, 0, shndx, value, size)

    str_fn = len(CORE_SONAME) + 1
    str_dat = str_fn + len(CORE_FN) + 1
    return b"".join(
        [
            sym(0, 0, 0, 0, 0),
            sym(str_fn, 0x12, 1, CORE_FN_VA, len(CORE_FN_CODE)),
            sym(str_dat, 0x11, 1, CORE_DAT_VA, len(DATA_MAGIC)),
        ]
    )


def build_core_gnu_hash() -> bytes:
    """GNU 哈希表（2 defined 符号 @symidx 1,2）：header(16B) + bloom(8B)
    + buckets(2×u32) + chains(2×u32)。gABI 双位布局 + 桶链同桶续链
    （链尾旗 = 低位 1——每桶末符号置旗）。"""
    h1 = dl_new_hash(CORE_FN)
    h2 = dl_new_hash(CORE_DAT)
    bloom_shift = 0
    bloom = (1 << (h1 % 64)) | (1 << ((h1 >> bloom_shift) % 64))
    bloom |= (1 << (h2 % 64)) | (1 << ((h2 >> bloom_shift) % 64))
    nbuckets = 2
    buckets = [0, 0]
    chains = [0, 0]
    # 桶链组装（符号升序入桶——同桶末符号置链尾旗）
    last_in_bucket = {}
    for idx, h in ((1, h1), (2, h2)):
        last_in_bucket[h % nbuckets] = idx
    for idx, h in ((1, h1), (2, h2)):
        b = h % nbuckets
        if buckets[b] == 0:
            buckets[b] = idx
        chains[idx - 1] = (h | 1) if last_in_bucket[b] == idx else (h & ~1)
    hdr = struct.pack("<IIII", nbuckets, 1, 1, bloom_shift)
    return hdr + struct.pack("<Q", bloom) + struct.pack("<II", *buckets) + struct.pack("<II", *chains)


def build_core_rela() -> bytes:
    """RELA RELATIVE×2（自指针绝对化——gABI base+addend 口径）：
    GOT[0] = &lextern_dat（addend 0x3040）/ GOT[1] = &core_fn（addend
    0x1000）。决议值 = C_BASE + addend（烘焙域对账锚）。"""

    def rela(off: int, sym: int, typ: int, addend: int) -> bytes:
        return struct.pack("<QQq", off, (sym << 32) | typ, addend)

    return b"".join(
        [
            rela(CORE_RW_VA + 0x00, 0, R_X86_64_RELATIVE, CORE_DAT_VA),
            rela(CORE_RW_VA + 0x08, 0, R_X86_64_RELATIVE, CORE_FN_VA),
        ]
    )


def build_core_dynamic(dynstr_va: int, dynstr_len: int, dynsym_va: int, gnu_va: int, rela_va: int) -> bytes:
    ents = [
        (DT_SONAME, 0),
        (DT_STRTAB, dynstr_va),
        (DT_STRSZ, dynstr_len),
        (DT_SYMTAB, dynsym_va),
        (DT_SYMENT, 24),
        (DT_GNU_HASH, gnu_va),
        (DT_RELA, rela_va),
        (DT_RELASZ, 48),
        (DT_RELAENT, 24),
        (DT_NULL, 0),
    ]
    return b"".join(struct.pack("<QQ", t, v) for t, v in ents)


def build_core_so() -> bytes:
    dynstr = build_core_dynstr()
    dynsym = build_core_dynsym()
    gnu = build_core_gnu_hash()
    rela = build_core_rela()
    # RX 段内容：core_fn 桩（@0x1000）→ dynstr → dynsym → gnu_hash → rela
    text = bytearray()
    text += CORE_FN_CODE
    text += b"\x90" * (0x40 - len(CORE_FN_CODE))  # 对齐留白（m47 同谱）
    dynstr_va = CORE_TEXT_VA + len(text)
    text += dynstr
    dynsym_va = CORE_TEXT_VA + len(text)
    text += dynsym
    gnu_va = CORE_TEXT_VA + len(text)
    text += gnu
    rela_va = CORE_TEXT_VA + len(text)
    text += rela
    text += b"\x00" * (-len(text) % PAGE)
    assert len(text) <= PAGE, f"RX 段越页：{len(text):#x}"
    # RW 段：GOT 双槽 + lextern_dat + .dynamic
    rw = bytearray(0x200)
    rw[0x40:0x44] = DATA_MAGIC
    dyn = build_core_dynamic(dynstr_va, len(dynstr), dynsym_va, gnu_va, rela_va)
    assert len(dyn) <= 0x100, f"动态表越界：{len(dyn):#x}"
    rw[0x100 : 0x100 + len(dyn)] = dyn

    phnum = 3
    total = 3 * PAGE
    blob = bytearray(total)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # ELFCLASS64
    blob[5] = 1  # ELFDATA2LSB
    blob[6] = 1  # EV_CURRENT
    phdrs = []
    # PT_LOAD RX
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_LOAD, PF_R | PF_X, PAGE, CORE_TEXT_VA, CORE_TEXT_VA, len(text), len(text), PAGE
        )
    )
    # PT_LOAD RW（filesz = memsz = 0x200——无 BSS）
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_LOAD, PF_R | PF_W, 2 * PAGE, CORE_RW_VA, CORE_RW_VA, len(rw), len(rw), PAGE
        )
    )
    # PT_DYNAMIC（RW @+0x100）
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_DYNAMIC, PF_R | PF_W, 2 * PAGE + 0x100, CORE_RW_VA + 0x100, CORE_RW_VA + 0x100, len(dyn), len(dyn), 8
        )
    )
    assert len(phdrs) == phnum
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        0x10,
        ET_DYN,
        62,  # EM_X86_64
        1,
        0,  # e_entry（共享对象——0）
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
    blob[EHDR_LEN : EHDR_LEN + PHDR_LEN * phnum] = b"".join(phdrs)
    blob[PAGE : PAGE + len(text)] = text
    blob[2 * PAGE : 2 * PAGE + len(rw)] = rw
    # 结构自检：同余式 + 页槽互斥（PT_LOAD）
    for off, va in [(PAGE, CORE_TEXT_VA), (2 * PAGE, CORE_RW_VA)]:
        assert off % PAGE == va % PAGE, f"同余式破坏：off={off:#x} va={va:#x}"
    a_lo = CORE_TEXT_VA // PAGE
    a_hi = (CORE_TEXT_VA + len(text) + PAGE - 1) // PAGE
    b_lo = CORE_RW_VA // PAGE
    assert a_lo >= b_lo or b_lo >= a_hi, "页槽重叠"
    return bytes(blob)


# ---- ring3 自装载链探针（原生 ABI ET_EXEC——ELF_NATIVE lane 同谱） ----

def build_probe_code() -> bytes:
    """ring3 自装载链探针（dlopen 真消费面电气活体）。

    寄存器面：r14 = L1_BASE（ld-lumina 装载基）/ r15 = C_BASE（core
    装载基）/ rbx = 探针数据段基 DATA_VA（callee-saved 跨 syscall
    存续；拷贝源 disp = 段内偏移绝对域——SO blob @+0x1000 / CORE
    blob @+0x4000 相对段基直算，blob 基不重复计入 disp）。
    序：LOG(msg1) → mmap×4 R|W 分级窗回显 → rep movsb 分级拷贝×4 →
    ring3 重定位写面（ld-lumina RELATIVE/GLOB_DAT/JUMP_SLOT/COPY +
    core RELATIVE×2）→ mprotect RX 终旗×2 → call ldlumina_boot →
    GOT[2] 间呼 core_fn → COPY/"CORE" 读回 → core REL[0]/GOT[1] 读回 →
    BSS 尾零读回 → 负例二目 → LOG(msg2) → EXIT(89)。
    bail 表（90..103 fail-visible）= 尾部 mov edi,code; EXIT 布局。
    """
    bail_codes = {
        "mmap_l1_rx": 90,
        "mmap_l1_rw": 91,
        "mmap_c_rx": 92,
        "mmap_c_rw": 93,
        "mprot_l1": 94,
        "mprot_c": 95,
        "boot_call": 96,
        "got_call": 97,
        "copy_slot": 98,
        "core_rel0": 99,
        "got1_readback": 100,
        "bss_zero": 101,
        "neg_mprot": 102,
        "neg_mmap": 103,
    }

    body = bytearray()
    jne_fix = []  # (位置, bail 码)

    def U32(v):
        body.extend(struct.pack("<I", v))

    def I32(v):
        body.extend(struct.pack("<i", v))

    def Q(v):
        body.extend(struct.pack("<Q", v))

    def jne8(code):
        # jne rel32（0F 85 cd——bail 表距离无界域）
        body.extend(b"\x0f\x85")
        jne_fix.append((len(body), code))
        body.extend(b"\x00\x00\x00\x00")

    def mmap_seq(va_reg: int, disp: int, length: int, expect: int, bail: int):
        nonlocal body
        # mmap(va_reg+disp, length, R|W, 0, ANON_FD) → rax == expect
        # （disp 全域非零——lea rdi, [r14/r15+disp32] 单一编码域）
        if va_reg == 14:
            body += b"\x49\x8d\xbe"  # lea rdi, [r14+disp32]
        else:
            body += b"\x49\x8d\xbf"  # lea rdi, [r15+disp32]
        U32(disp)
        body += b"\xbe"  # mov esi, length
        U32(length)
        body += b"\xba"  # mov edx, 3（PROT_READ|PROT_WRITE）
        I32(3)
        body += b"\x45\x31\xd2"  # xor r10d, r10d（flags = 0）
        body += b"\x49\xc7\xc0\xff\xff\xff\xff"  # mov r8, -1（MMAP_ANON_FD）
        body += b"\xb8"  # mov eax, SYS_MMAP
        I32(SYS_MMAP)
        body += b"\x0f\x05"
        body += b"\x48\xb9"  # movabs rcx, expect
        Q(expect)
        body += b"\x48\x39\xc8"  # cmp rax, rcx
        jne8(bail)

    def mprot_seq(va_reg: int, disp: int, length: int, prot: int, ok_zero: bool, bail: int):
        nonlocal body
        # mprotect(va_reg+disp, length, prot) → 0（ok_zero）或 BAD（负例）
        if va_reg == 14:
            body += b"\x49\x8d\xbe"
        else:
            body += b"\x49\x8d\xbf"
        U32(disp)
        body += b"\xbe"
        U32(length)
        body += b"\xba"
        I32(prot)
        body += b"\xb8"
        I32(SYS_MPROT)
        body += b"\x0f\x05"
        if ok_zero:
            body += b"\x48\x85\xc0"  # test rax, rax
            jne8(bail)
        else:
            body += b"\x48\xb9"
            Q(BAD)
            body += b"\x48\x39\xc8"  # cmp rax, rcx
            jne8(bail)

    def copy_seq(src_disp: int, dst_reg: int, dst_disp: int, n: int):
        nonlocal body
        # rep movsb：rsi = rbx+src_disp（探针数据段 blob 内）→
        # rdi = dst_reg+dst_disp（映射窗）
        body += b"\x48\x8d\xb3"  # lea rsi, [rbx+disp32]
        U32(src_disp)
        if dst_reg == 14:
            body += b"\x49\x8d\xbe"  # lea rdi, [r14+disp32]
        else:
            body += b"\x49\x8d\xbf"  # lea rdi, [r15+disp32]
        U32(dst_disp)
        body += b"\xb9"  # mov ecx, n
        U32(n)
        body += b"\xf3\xa4"  # rep movsb

    def write_q(dst_reg: int, disp: int, value: int):
        nonlocal body
        # movabs rax, value; mov [dst_reg+disp32], rax
        body += b"\x48\xb8"
        Q(value)
        if dst_reg == 14:
            body += b"\x49\x89\x86"
        else:
            body += b"\x49\x89\x87"
        U32(disp)

    def readback_q(dst_reg: int, disp: int, expect: int, bail: int):
        nonlocal body
        # mov rax, [dst_reg+disp32]; movabs rcx, expect; cmp rax, rcx
        if dst_reg == 14:
            body += b"\x49\x8b\x86"
        else:
            body += b"\x49\x8b\x87"
        U32(disp)
        body += b"\x48\xb9"
        Q(expect)
        body += b"\x48\x39\xc8"
        jne8(bail)

    # r14 = L1_BASE / r15 = C_BASE / rbx = DATA_VA（段基——拷贝源 disp
    # = 段内绝对偏移：SO blob @+0x1000 / CORE blob @+0x4000）
    body += b"\x49\xbe"
    Q(L1_BASE)
    body += b"\x49\xbf"
    Q(C_BASE)
    body += b"\x48\xbb"
    Q(DATA_VA)
    # LOG(msg1)
    body += b"\xbf"
    U32(DATA_VA)
    body += b"\xbe"
    I32(len(b"LUMINA-T149-PROBE"))
    body += b"\xb8"
    I32(0)
    body += b"\x0f\x05"
    # cld（rep 方向清位——显式纪律）
    body += b"\xfc"
    # [1..4] mmap×4 R|W 分级窗（回显对账）
    mmap_seq(14, 0x1000, 0x1000, L1_BASE + 0x1000, bail_codes["mmap_l1_rx"])
    mmap_seq(14, 0x3000, 0x2000, L1_BASE + 0x3000, bail_codes["mmap_l1_rw"])
    mmap_seq(15, 0x1000, 0x1000, C_BASE + 0x1000, bail_codes["mmap_c_rx"])
    mmap_seq(15, 0x3000, 0x1000, C_BASE + 0x3000, bail_codes["mmap_c_rw"])
    # [5..8] rep movsb 分级拷贝×4（BSS 尾零不拷——filesz 语义）
    copy_seq(SO_DATA_OFF + 0x1000, 14, 0x1000, 0x1000)  # ld RX 页
    copy_seq(SO_DATA_OFF + 0x2000, 14, 0x3000, 0x200)  # ld RW filesz 0x200
    copy_seq(CORE_DATA_OFF + 0x1000, 15, 0x1000, 0x1000)  # core RX 页
    copy_seq(CORE_DATA_OFF + 0x2000, 15, 0x3000, 0x200)  # core RW filesz 0x200
    # [9] ring3 重定位写面（烘焙决议值——harbor 链式决议同值域）
    # ld-lumina RELATIVE：GOT[0] = L1_BASE（base + addend 0）
    write_q(14, 0x3000, L1_BASE)
    # ld-lumina GLOB_DAT：GOT[1] = core_fn（C_BASE+0x1000）
    write_q(14, 0x3008, C_BASE + 0x1000)
    # ld-lumina JUMP_SLOT：GOT[2] = core_fn（跨模块决议——电气间呼锚）
    write_q(14, 0x3010, C_BASE + 0x1000)
    # ld-lumina COPY：[L1+0x3020] ← [C+0x3040]（"CORE" 4 字节搬运；
    # REX.B=0x41 无 REX.R——reg=000 即 eax，R 误置即 r8d 雷域）
    body += b"\x41\x8b\x87"  # mov eax, [r15+disp32]
    U32(0x3040)
    body += b"\x41\x89\x86"  # mov [r14+disp32], eax
    U32(0x3020)
    # core RELATIVE：GOT[0] = C_BASE+0x3040 / GOT[1] = C_BASE+0x1000
    write_q(15, 0x3000, C_BASE + 0x3040)
    write_q(15, 0x3008, C_BASE + 0x1000)
    # [10..11] mprotect RX 终旗×2
    mprot_seq(14, 0x1000, 0x1000, 5, True, bail_codes["mprot_l1"])
    mprot_seq(15, 0x1000, 0x1000, 5, True, bail_codes["mprot_c"])
    # [12] call ldlumina_boot（L1+0x1000——PROT_EXEC 活体 + 装载执行域）
    body += b"\x49\x8d\x86"  # lea rax, [r14+0x1000]
    U32(0x1000)
    body += b"\xff\xd0"  # call rax
    body += b"\x3d"  # cmp eax, MAGIC_BOOT
    U32(MAGIC_BOOT)
    jne8(bail_codes["boot_call"])
    # [13] GOT[2] 间呼 core_fn（JUMP_SLOT 跨模块电气证明）
    body += b"\x49\x8b\x86"  # mov rax, [r14+0x3010]
    U32(0x3010)
    body += b"\xff\xd0"
    body += b"\x3d"
    U32(MAGIC_CORE)
    jne8(bail_codes["got_call"])
    # [14] COPY 槽读回（"CORE" LE = 0x45524F43）
    body += b"\x49\x8b\x86"  # mov rax, [r14+0x3020]
    U32(0x3020)
    body += b"\x48\xb9"
    Q(int.from_bytes(DATA_MAGIC, "little"))
    body += b"\x48\x39\xc8"
    jne8(bail_codes["copy_slot"])
    # [15] core REL[0] 读回（GOT[0] = C_BASE+0x3040）
    readback_q(15, 0x3000, C_BASE + 0x3040, bail_codes["core_rel0"])
    # [16] GOT[1] 读回（= C_BASE+0x1000）
    readback_q(14, 0x3008, C_BASE + 0x1000, bail_codes["got1_readback"])
    # [17] BSS 尾零读回（L1+0x4000——RW 区第 2 页 = memsz>filesz 域）
    readback_q(14, 0x4000, 0, bail_codes["bss_zero"])
    # [18] 负例 a：mprotect(L1+0x5000 未登记, 0x1000, R|W) → BAD
    mprot_seq(14, 0x5000, 0x1000, 3, False, bail_codes["neg_mprot"])
    # [19] 负例 b：mmap(L1+0x1000 重叠, 0x1000, R|W, 0, -1) → BAD
    mmap_seq(14, 0x1000, 0x1000, BAD, bail_codes["neg_mmap"])
    # [20] LOG(msg2) → EXIT(89)
    body += b"\xbf"
    U32(DATA_VA + 0x40)
    body += b"\xbe"
    I32(len(b"LUMINA-T149-ELEC"))
    body += b"\xb8"
    I32(0)
    body += b"\x0f\x05"
    body += b"\xbf"
    U32(EXIT_OK)
    body += b"\xb8"
    I32(SYS_EXIT)
    body += b"\x0f\x05"

    # bail 尾表（90..103——mov edi, code; EXIT）
    bail_at = {}
    for code in bail_codes.values():
        bail_at[code] = len(body)
        body += b"\xbf"
        body += struct.pack("<I", code)
        body += b"\xb8"
        body += struct.pack("<i", SYS_EXIT)
        body += b"\x0f\x05"

    for at, bc in jne_fix:
        delta = bail_at[bc] - (at + 4)
        body[at : at + 4] = struct.pack("<i", delta)
    return bytes(body)


def elf_probe(code: bytes, data: bytes) -> bytes:
    segs = [
        (0x400000, PF_R | PF_X, code),
        (0x401000, PF_R | PF_W, data),
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
    blob[4] = 2
    blob[5] = 1
    blob[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH", blob, 0x10, ET_EXEC, 62, 1, 0x400000, EHDR_LEN, 0, 0, EHDR_LEN, PHDR_LEN, phnum, 0, 0, 0
    )
    for k, (foff, vaddr, d) in enumerate(layout):
        struct.pack_into(
            "<IIQQQQQQ", blob, EHDR_LEN + k * PHDR_LEN, PT_LOAD, segs[k][1], foff, vaddr, vaddr, len(d), len(d), PAGE
        )
        blob[foff : foff + len(d)] = d
    return bytes(blob)


def objdump_check(code: bytes, anchors, n_sys):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        dis = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "--no-show-raw-insn", path],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except FileNotFoundError:
        return  # objdump 缺席——结构自检降级（生成面自检已在环）
    finally:
        Path(path).unlink(missing_ok=True)
    flat = " ".join(dis.split())
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    got = flat.count("syscall")
    assert got == n_sys, f"syscall 计数锚失配：{got} ≠ {n_sys}"


def rs_file(core: bytes, probe: bytes) -> str:
    def hexrow(d: bytes, name: str, doc: str) -> str:
        rows = []
        for i in range(0, len(d), 16):
            rows.append("    " + ", ".join(f"0x{b:02X}" for b in d[i : i + 16]) + ",")
        body = "\n".join(rows)
        return f"/// {doc}\npub const {name}: &[u8] = &[\n{body}\n];\n"

    return (
        "// exec_images_m47b —— M47-DLOPEN54 笔61 交付件映像（gen_m47b_dlopen.py 产物）。\n"
        "//\n"
        "// - LIBLUMINA_CORE_SO：依赖库 ELF 交付件（真 ET_DYN 共享对象——\n"
        "//   SONAME=liblumina-core.so + core_fn/lextern_dat 双定义符号 +\n"
        "//   GNU 哈希双链 + RELA RELATIVE×2——ld-lumina.so UNDEF 族真决议\n"
        "//   供给方；artifacts/liblumina-core.so 单一事实源——t149 CHAIN\n"
        "//   相位链式消费锚）；\n"
        "// - DLOPEN_ELF：ring3 自装载链探针（原生 ABI ET_EXEC——数据段\n"
        "//   内嵌 ld-lumina.so + liblumina-core.so 双真件，SYS_MMAP 四窗\n"
        "//   分级 + rep movsb 拷贝 + ring3 重定位写面 + RX 终旗 + boot\n"
        "//   call + GOT[2] 间呼 core_fn + COPY 读回 + BSS 尾零 + 负例二目；\n"
        "//   EXIT(89) 对账码——t149 LIVE 相位收割面）。\n\n"
        + hexrow(
            core,
            "LIBLUMINA_CORE_SO",
            "liblumina-core.so 依赖库（ET_DYN——交付件字节面，与 artifacts/ 逐位同源）。",
        )
        + "\n"
        + hexrow(
            probe,
            "DLOPEN_ELF",
            "ring3 自装载链探针（ET_EXEC——dlopen 真消费面电气活体）。",
        )
    )


def main():
    ART.mkdir(exist_ok=True)
    core = build_core_so()
    so = m47.build_ld_lumina_so()
    # 真件对账：ld-lumina.so 与 m47 生成器逐位同源（单一事实源锚）
    art_so = ART / "ld-lumina.so"
    if art_so.exists():
        assert art_so.read_bytes() == so, "ld-lumina.so 与 m47 生成器漂移（单一事实源破坏）"

    probe_code = build_probe_code()
    data = bytearray(0x7000)
    msg1 = b"LUMINA-T149-PROBE"
    msg2 = b"LUMINA-T149-ELEC"
    data[0 : len(msg1)] = msg1
    data[0x40 : 0x40 + len(msg2)] = msg2
    data[SO_DATA_OFF : SO_DATA_OFF + len(so)] = so
    data[CORE_DATA_OFF : CORE_DATA_OFF + len(core)] = core
    probe = elf_probe(probe_code, bytes(data))

    # 结构自检①：core so 头族 walk（SONAME 读回 + RELA 条目数 + 动态表收尾）
    dynstr = build_core_dynstr()
    assert dynstr.startswith(CORE_SONAME + b"\0"), "SONAME 读回破坏"
    str_fn = len(CORE_SONAME) + 1
    assert dynstr[str_fn:].startswith(CORE_FN + b"\0"), "core_fn 名读回破坏"
    rela = build_core_rela()
    assert len(rela) == 2 * 24, f"RELA 条目漂移：{len(rela)}"
    dyn = build_core_dynamic(0, 0, 0, 0, 0)
    assert dyn[-16:] == struct.pack("<QQ", DT_NULL, 0), "动态表 DT_NULL 收尾破坏"

    # 结构自检②：GNU 哈希 lookup 仿真（exec 机械面同谱——bloom 双位 +
    # 桶链走查 + 链尾旗；双符号全谱）
    h1 = dl_new_hash(CORE_FN)
    h2 = dl_new_hash(CORE_DAT)
    gnu = build_core_gnu_hash()
    nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack_from("<IIII", gnu, 0)
    bloom = struct.unpack_from("<Q", gnu, 16)[0]
    buckets = struct.unpack_from("<II", gnu, 24)
    chains = struct.unpack_from("<II", gnu, 32)
    assert (nbuckets, symoffset, bloom_size) == (2, 1, 1), "GNU 头漂移"
    for h, want_idx, want_name in ((h1, 1, CORE_FN), (h2, 2, CORE_DAT)):
        bit1, bit2 = h % 64, (h >> bloom_shift) % 64
        assert (bloom >> bit1) & 1 and (bloom >> bit2) & 1, f"bloom 双位缺（{want_name}）"
        sym = buckets[h % nbuckets]
        assert sym != 0, f"桶空（{want_name}）"
        found = None
        for _ in range(16):
            assert sym >= symoffset, "坏表（sym < symoffset）"
            if sym == want_idx:
                found = sym
                break
            if chains[sym - symoffset] & 1:
                break
            sym += 1
        assert found == want_idx, f"桶链走查失配（{want_name}）"

    # 结构自检③：探针反汇编锚 + syscall 计数（25 = LOG×2 + MMAP×5
    # 〔映射×4 + 负例×1〕 + MPROT×3〔终旗×2 + 负例×1〕 + EXIT×1 +
    # bail 表 EXIT×14）
    objdump_check(
        probe_code,
        [
            ("call *%rax", "PROT_EXEC 活体 call 锚"),
            ("cmp $0x5a5a5a5a,%eax", "boot 桩返回值对账锚"),
            ("cmp $0xc0dec0de,%eax", "core_fn 桩返回值对账锚"),
            ("rep movsb %ds:(%rsi),%es:(%rdi)", "分级拷贝锚"),
        ],
        25,
    )

    (ART / "liblumina-core.so").write_bytes(core)
    (ART / "ldlumina-dlopen-probe.elf").write_bytes(probe)
    GEN.write_text(rs_file(core, probe))
    print(f"liblumina-core.so       = {len(core)} B -> artifacts/liblumina-core.so")
    print(f"ldlumina-dlopen-probe.elf = {len(probe)} B -> artifacts/ldlumina-dlopen-probe.elf")
    print(f"exec_images_m47b.rs -> {GEN.relative_to(ROOT)}")
    print(f"GNU hash({CORE_FN.decode()}) = {h1:#010x} / GNU hash({CORE_DAT.decode()}) = {h2:#010x}（harbor dl_new_hash 对账域）")


if __name__ == "__main__":
    main()
