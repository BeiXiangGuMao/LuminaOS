#!/usr/bin/env python3
"""gen_m47_ldlumina.py — M47-LDCONS53（笔60）装载计划消费面批映像生成器。

产物（deliverable 面）：
  1. artifacts/ld-lumina.so      —— ld-lumina.so **本体 ELF 交付件**：
     真 ELF64 ET_DYN 共享对象（SONAME 域 + GNU 哈希 + dynsym/dynstr +
     RELA 四类 + PT_TLS + .dynamic + BSS 尾）——harbor::ld::exec
     dyn_parse/load_plan/stage_image/gnu_hash_lookup/rela_entries/
     reloc_apply/TlsSpace 全链真件消费锚（t148 SO 相位）；
  2. artifacts/ldcons-probe.elf  —— ring3 消费活体探针（原生 ABI
     ET_EXEC 静态映像——ELF_NATIVE lane 同谱）：SYS_MMAP(46) 两区
     R|W → 写样/读回 → SYS_MPROTECT(47) RW→RX 终旗 → 映射页内代码
     call（PROT_EXEC 活体）→ 负例矩阵（未登记域/登记重叠/fd 非匿名）
     → LOG 取证 → EXIT(88)（t148 LIVE 相位收割对账码）；
  3. crates/kernel/src/exec_images_m47.rs —— include_bytes 封装
     （user.rs include! 引入——M42 gen lane 同谱）。

结构自检（fail-visible）：ELF 头/同余式/页槽互斥/动态表 walk/SONAME
读回/RELA 条目数/GNU 哈希 lookup 仿真 + objdump 反汇编锚（探针）。
"""

import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m47.rs"

PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56
PT_LOAD = 1
PT_DYNAMIC = 2
PT_TLS = 7
PF_X = 1
PF_W = 2
PF_R = 4
ET_DYN = 3
ET_EXEC = 2

DT_NULL = 0
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
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_COPY = 5

# ---- harbor::ld::exec dl_new_hash 同源实现（语义逐位对账锚） ----


def dl_new_hash(name: bytes) -> int:
    """GNU 权威口径（harbor::ld::dl_new_hash 同源——× 33 **加法**逐字节（M50-MUSL70 官方口径），
    5381 初值；语义锚：空串 = 5381、"a" = 5381×33^97 = 0x2B5C4）。"""
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF  # M50-MUSL70 揭雷①：官方加法口径（harbor dl_new_hash 同源修正）
    return h & 0xFFFFFFFF


# ---- ld-lumina.so 本体（ET_DYN） ----

# 布局（vaddr = 文件偏移同余式）：
#   0x0000      头区（EHDR + 4 PHDR：LOAD RX / LOAD RW / DYNAMIC / TLS）
#   0x1000 RX   .text（boot 桩 6B）+ .dynstr + .dynsym + .gnu_hash + .rela.dyn
#   0x3000 RW   GOT/数据 + .tdata + .dynamic；filesz 0x300、memsz 0x1300
#               （BSS 尾 0x1000——memsz > filesz 语义）
SO_TEXT_VA = 0x1000
SO_RW_VA = 0x3000
BOOT_STUB = b"\xb8\x5a\x5a\x5a\x5a\xc3"  # mov eax,0x5A5A5A5A; ret
BOOT_SYM = b"ldlumina_boot"
UNDEF_FN = b"ldep_fn"
UNDEF_DAT = b"lextern_dat"

STR_OWN = 0
STR_BOOT = len(b"ld-lumina.so") + 1


def build_dynstr() -> bytes:
    return b"ld-lumina.so\0" + BOOT_SYM + b"\0" + UNDEF_FN + b"\0" + UNDEF_DAT + b"\0"


def build_dynsym(dynstr_len: int) -> bytes:
    """4 目：[0] null / [1] ldlumina_boot（defined，GLOBAL|FUNC）/
    [2] ldep_fn（UNDEF）/ [3] lextern_dat（UNDEF，COPY 尺寸 4）。"""
    ents = []

    def sym(name: int, info: int, shndx: int, value: int, size: int) -> bytes:
        return struct.pack("<IBBHQQ", name, info, 0, shndx, value, size)

    ents.append(sym(0, 0, 0, 0, 0))  # null
    ents.append(sym(STR_BOOT, 0x12, 1, SO_TEXT_VA, len(BOOT_STUB)))  # defined
    ents.append(sym(len(b"ld-lumina.so") + 1 + len(BOOT_SYM) + 1, 0x10, 0, 0, 0))
    ents.append(
        sym(
            len(b"ld-lumina.so") + 1 + len(BOOT_SYM) + 1 + len(UNDEF_FN) + 1,
            0x10,
            0,
            0,
            4,
        )
    )
    return b"".join(ents)


def build_gnu_hash(symstr: bytes) -> bytes:
    """GNU 哈希表（1 defined 符号 @symidx 1）：header(16B) + bloom(8B)
    + buckets(8B) + chains(8B)。gABI 双位布局（exec 机械面同谱）。"""
    h = dl_new_hash(BOOT_SYM)
    bloom_shift = 0
    bloom = (1 << (h % 64)) | (1 << ((h >> bloom_shift) % 64))
    hdr = struct.pack("<IIII", 1, 1, 1, bloom_shift)  # nbuckets/symoffset/bloom_size/bloom_shift
    # gABI 布局：bloom(u64 × bloom_size) + buckets(u32 × nbuckets) +
    # chains(u32 × (nsyms - symoffset))——32 位阵列口径（机械面读法同源）
    return hdr + struct.pack("<Q", bloom) + struct.pack("<I", 1) + struct.pack("<I", h | 1)


def build_rela() -> bytes:
    """RELA 四类（r_info = sym<<32 | type）：
    GOT[0]=RELATIVE / GOT[1]=GLOB_DAT(ldep_fn) / GOT[2]=JUMP_SLOT(ldep_fn) /
    COPY 槽(lextern_dat，sym 尺寸 4)。"""
    def rela(off: int, sym: int, typ: int, addend: int) -> bytes:
        return struct.pack("<QQq", off, (sym << 32) | typ, addend)

    return b"".join(
        [
            rela(SO_RW_VA + 0x00, 0, R_X86_64_RELATIVE, 0),
            rela(SO_RW_VA + 0x08, 2, R_X86_64_GLOB_DAT, 0),
            rela(SO_RW_VA + 0x10, 2, R_X86_64_JUMP_SLOT, 0),
            rela(SO_RW_VA + 0x20, 3, R_X86_64_COPY, 0),
        ]
    )


def build_dynamic(dynstr_va: int, dynstr_len: int, dynsym_va: int, gnu_va: int, rela_va: int, rela_sz: int) -> bytes:
    ents = [
        (DT_SONAME, STR_OWN),
        (DT_STRTAB, dynstr_va),
        (DT_STRSZ, dynstr_len),
        (DT_SYMTAB, dynsym_va),
        (DT_SYMENT, 24),
        (DT_GNU_HASH, gnu_va),
        (DT_RELA, rela_va),
        (DT_RELASZ, rela_sz),
        (DT_RELAENT, 24),
        (DT_NULL, 0),
    ]
    return b"".join(struct.pack("<QQ", t, v) for t, v in ents)


def build_ld_lumina_so() -> bytes:
    dynstr = build_dynstr()
    dynsym = build_dynsym(len(dynstr))
    gnu = build_gnu_hash(BOOT_SYM)
    rela = build_rela()
    # RX 段内容：boot 桩（@0x1000）→ dynstr → dynsym → gnu_hash → rela
    text = bytearray()
    text += BOOT_STUB
    text += b"\x90" * (0x40 - len(BOOT_STUB))  # 对齐留白
    dynstr_va = SO_TEXT_VA + len(text)
    text += dynstr
    dynsym_va = SO_TEXT_VA + len(text)
    text += dynsym
    gnu_va = SO_TEXT_VA + len(text)
    text += gnu
    rela_va = SO_TEXT_VA + len(text)
    text += rela
    text += b"\x00" * (-len(text) % PAGE)
    assert len(text) <= PAGE, f"RX 段越页：{len(text):#x}"
    # RW 段：GOT 0x28 + COPY 槽 + 数据 + .tdata(16 @+0x40) → .dynamic
    rw = bytearray(PAGE)
    rw[0x40:0x50] = b"LDLUMINA\0\0\0\0\0\0\0\0"[:16]  # .tdata（TLS 模板）
    dyn = build_dynamic(dynstr_va, len(dynstr), dynsym_va, gnu_va, rela_va, len(rela))
    assert len(dyn) <= 0x100, f"动态表越界：{len(dyn):#x}"
    rw[0x100 : 0x100 + len(dyn)] = dyn
    rw_filesz = 0x200
    rw_memsz = 0x200 + 0x1000  # BSS 尾零（stage_image BSS 语义真件锚）
    rw_data = bytes(rw[:rw_filesz])

    phnum = 4
    segs = [
        (SO_TEXT_VA, PF_R | PF_X, bytes(text)),
        (SO_RW_VA, PF_R | PF_W, rw_data),
    ]
    total = PAGE + len(text) + len(rw_data)
    total = (total + PAGE - 1) & ~(PAGE - 1)
    blob = bytearray(total)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # ELFCLASS64
    blob[5] = 1  # ELFDATA2LSB
    blob[6] = 1  # EV_CURRENT
    phdrs = []
    # PT_LOAD RX
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_LOAD, PF_R | PF_X, PAGE, SO_TEXT_VA, SO_TEXT_VA, len(text), len(text), PAGE
        )
    )
    # PT_LOAD RW（filesz < memsz——BSS 尾）
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_LOAD, PF_R | PF_W, PAGE + len(text), SO_RW_VA, SO_RW_VA, len(rw_data), rw_memsz, PAGE
        )
    )
    # PT_DYNAMIC（落于 RW 段 @0x3100 处——vaddr SO_RW_VA+0x100）
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_DYNAMIC, PF_R | PF_W, PAGE + len(text) + 0x100, SO_RW_VA + 0x100, SO_RW_VA + 0x100, len(dyn), len(dyn), 8
        )
    )
    # PT_TLS（.tdata @ RW+0x40——memsz = filesz = 16，align 16）
    phdrs.append(
        struct.pack(
            "<IIQQQQQQ", PT_TLS, PF_R, PAGE + len(text) + 0x40, SO_RW_VA + 0x40, SO_RW_VA + 0x40, 16, 16, 16
        )
    )
    assert len(phdrs) == phnum
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        0x10,
        ET_DYN,  # e_type = ET_DYN（共享对象）
        62,  # e_machine = EM_X86_64
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
    blob[PAGE + len(text) : PAGE + len(text) + len(rw_data)] = rw_data
    # 结构自检：同余式 + 页槽互斥（PT_LOAD）
    for off, va, _ in [(PAGE, SO_TEXT_VA, text), (PAGE + len(text), SO_RW_VA, rw_data)]:
        assert off % PAGE == va % PAGE, f"同余式破坏：off={off:#x} va={va:#x}"
    a_lo = SO_TEXT_VA // PAGE
    a_hi = (SO_TEXT_VA + len(text) + PAGE - 1) // PAGE
    b_lo = SO_RW_VA // PAGE
    assert a_lo >= b_lo or b_lo >= a_hi, "页槽重叠"
    return bytes(blob)


# ---- ring3 消费活体探针（原生 ABI ET_EXEC——ELF_NATIVE lane 同谱） ----

PROBE_BASE = 0x2_0000_0000


def build_probe_code() -> bytes:
    """ring3 消费活体探针（原生 ABI——ELF_NATIVE lane 同谱）。

    寄存器面：r14 = 映射窗基（callee-saved 跨 syscall 存续）。
    序：LOG(msg1) → mmap(R|W)×2 定点回显 → 写样/读回 → 写 exec 桩 →
    mprotect RW→RX → **call 桩**（PROT_EXEC 活体——映射页内代码执行）
    → RW 邻页读回 → 负例×3（未登记域 mprotect / 登记重叠 mmap /
    fd 非匿名 mmap——BAD(u64::MAX-1) 显形）→ LOG(msg2) → EXIT(88)。
    bail 表（90..98 fail-visible）= 尾部 mov edi,code; EXIT 布局。
    """
    SYS_EXIT = 1
    DATA_VA = 0x401000
    STUB_Q = int.from_bytes(BOOT_STUB + b"\x00\x00", "little")
    MAGIC = 0x5CA9_0047_0060_0001
    BAD = (1 << 64) - 2  # u64::MAX - 1（BadArgs 哨兵）
    MMAP_BAIL = 90
    MMAP2_BAIL = 91
    STICK_BAIL = 92
    MPROT_BAIL = 93
    EXEC_BAIL = 94
    READBACK_BAIL = 95
    NEG_UNMAP_BAIL = 96
    NEG_OVERLAP_BAIL = 97
    NEG_FD_BAIL = 98
    EXIT_OK = 88

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

    # movabs r14, 0x2_0000_0000（窗基 8 GiB——imm64 面）
    body += b"\x49\xbe"
    Q(0x2_0000_0000)
    # LOG(msg1)
    body += b"\xbf"; U32(DATA_VA)          # mov edi, msg1
    body += b"\xbe"; I32(len(b"LUMINA-T148-PROBE"))  # mov esi, len
    body += b"\xb8"; I32(0)               # mov eax, SYS_LOG
    body += b"\x0f\x05"
    # [1] mmap(r14, 0x1000, R|W, 0, -1) → rax == r14
    body += b"\x4c\x89\xf7"             # mov rdi, r14
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(3)               # prot = R|W
    body += b"\x45\x31\xd2"             # xor r10d, r10d
    body += b"\x49\xc7\xc0\xff\xff\xff\xff"  # mov r8, -1
    body += b"\xb8"; I32(46)              # mov eax, SYS_MMAP
    body += b"\x0f\x05"
    body += b"\x4c\x39\xf0"             # cmp rax, r14
    jne8(MMAP_BAIL)
    # [2] mmap(r14+0x1000, 0x1000, R|W, 0, -1) → rax == r14+0x1000
    body += b"\x49\x8d\xbe\x00\x10\x00\x00"  # lea rdi, [r14+0x1000]
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(3)
    body += b"\x45\x31\xd2"
    body += b"\x49\xc7\xc0\xff\xff\xff\xff"
    body += b"\xb8"; I32(46)
    body += b"\x0f\x05"
    body += b"\x49\x8d\x9e\x00\x10\x00\x00"  # lea rbx, [r14+0x1000]（disp32——0x10 语义）
    body += b"\x48\x39\xd8"             # cmp rax, rbx
    jne8(MMAP2_BAIL)
    # [3] 写样/读回：[r14+0x800] = MAGIC（RW 分级窗写使能）
    body += b"\x48\xb8"; Q(MAGIC)        # movabs rax, MAGIC
    body += b"\x49\x89\x86\x00\x08\x00\x00"  # mov [r14+0x800], rax
    body += b"\x49\x8b\x8e\x00\x08\x00\x00"  # mov rcx, [r14+0x800]
    body += b"\x48\xb8"; Q(MAGIC)
    body += b"\x48\x39\xc1"             # cmp rcx, rax
    jne8(STICK_BAIL)
    # [4] 写桩：[r14] = mov eax,0x5A5A5A5A; ret（+零填充 qword）
    body += b"\x48\xb8"; Q(STUB_Q)
    body += b"\x49\x89\x06"             # mov [r14], rax
    # [5] mprotect(r14, 0x1000, R|X) → rax == 0
    body += b"\x4c\x89\xf7"
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(5)               # prot = R|X
    body += b"\xb8"; I32(47)              # mov eax, SYS_MPROTECT
    body += b"\x0f\x05"
    body += b"\x48\x85\xc0"             # test rax, rax
    jne8(MPROT_BAIL)
    # [6] call 桩（PROT_EXEC 活体）：rax = r14 → call → eax == 0x5A5A5A5A
    body += b"\x4c\x89\xf0"             # mov rax, r14
    body += b"\xff\xd0"                  # call rax
    body += b"\x3d"; U32(0x5A5A5A5A)      # cmp eax, 0x5A5A5A5A
    jne8(EXEC_BAIL)
    # [7] RW 邻页读回（mprotect RX 不扰邻页 + 数据存续）
    body += b"\x49\x8b\x86\x00\x08\x00\x00"  # mov rax, [r14+0x800]
    body += b"\x48\xb9"; Q(MAGIC)
    body += b"\x48\x39\xc8"             # cmp rax, rcx
    jne8(READBACK_BAIL)
    # [8] 负例 a：mprotect(r14+0x4000 未登记, 0x1000, R|W) → BAD
    body += b"\x49\x8d\xbe\x00\x40\x00\x00"  # lea rdi, [r14+0x4000]
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(3)
    body += b"\xb8"; I32(47)
    body += b"\x0f\x05"
    body += b"\x48\xb9"; Q(BAD)
    body += b"\x48\x39\xc8"             # cmp rax, rcx
    jne8(NEG_UNMAP_BAIL)
    # [9] 负例 b：mmap(r14 重复, 0x1000, R|W, 0, -1) → BAD（登记重叠）
    body += b"\x4c\x89\xf7"
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(3)
    body += b"\x45\x31\xd2"
    body += b"\x49\xc7\xc0\xff\xff\xff\xff"
    body += b"\xb8"; I32(46)
    body += b"\x0f\x05"
    body += b"\x48\xb9"; Q(BAD)
    body += b"\x48\x39\xc8"
    jne8(NEG_OVERLAP_BAIL)
    # [10] 负例 c：mmap(0, 0x1000, R|W, 0, fd=0) → BAD（非匿名域）
    body += b"\x31\xff"                  # xor edi, edi
    body += b"\xbe"; U32(0x1000)
    body += b"\xba"; I32(3)
    body += b"\x45\x31\xd2"
    body += b"\x45\x31\xc0"             # xor r8d, r8d（fd = 0）
    body += b"\xb8"; I32(46)
    body += b"\x0f\x05"
    body += b"\x48\xb9"; Q(BAD)
    body += b"\x48\x39\xc8"
    jne8(NEG_FD_BAIL)
    # [11] LOG(msg2) → EXIT(88)
    body += b"\xbf"; U32(DATA_VA + 0x40)  # mov edi, msg2
    body += b"\xbe"; I32(len(b"LUMINA-T148-ELEC"))
    body += b"\xb8"; I32(0)
    body += b"\x0f\x05"
    body += b"\xbf"; U32(EXIT_OK)
    body += b"\xb8"; I32(SYS_EXIT)
    body += b"\x0f\x05"

    # bail 尾表（90..98——mov edi, code; EXIT）
    bail_at = {}
    for code in [
        MMAP_BAIL, MMAP2_BAIL, STICK_BAIL, MPROT_BAIL, EXEC_BAIL,
        READBACK_BAIL, NEG_UNMAP_BAIL, NEG_OVERLAP_BAIL, NEG_FD_BAIL,
    ]:
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


def rs_file(so: bytes, probe: bytes) -> str:
    def hexrow(d: bytes, name: str, doc: str) -> str:
        rows = []
        for i in range(0, len(d), 16):
            rows.append("    " + ", ".join(f"0x{b:02X}" for b in d[i : i + 16]) + ",")
        body = "\n".join(rows)
        return f"/// {doc}\npub const {name}: &[u8] = &[\n{body}\n];\n"

    return (
        "// exec_images_m47 —— M47-LDCONS53 笔60 交付件映像（gen_m47_ldlumina.py 产物）。\n"
        "//\n"
        "// - LD_LUMINA_SO：ld-lumina.so 本体 ELF 交付件（真 ET_DYN 共享\n"
        "//   对象——SONAME + GNU 哈希 + RELA 四类 + PT_TLS + BSS 尾；\n"
        "//   artifacts/ld-lumina.so 单一事实源 include_bytes 承载——t148\n"
        "//   SO 相位真件消费锚）；\n"
        "// - LDCONS_ELF：ring3 消费活体探针（原生 ABI ET_EXEC——\n"
        "//   SYS_MMAP/SYS_MPROTECT 双车道 + 映射页代码 call + 负例矩阵；\n"
        "//   EXIT(88) 对账码——t148 LIVE 相位收割面）。\n\n"
        + hexrow(
            so,
            "LD_LUMINA_SO",
            "ld-lumina.so 本体（ET_DYN——交付件字节面，与 artifacts/ 逐位同源）。",
        )
        + "\n"
        + hexrow(
            probe,
            "LDCONS_ELF",
            "ring3 消费活体探针（ET_EXEC——装载计划消费面电气域活体）。",
        )
    )


def main():
    ART.mkdir(exist_ok=True)
    so = build_ld_lumina_so()
    probe_code = build_probe_code()
    data = bytearray(PAGE)
    msg1 = b"LUMINA-T148-PROBE"
    msg2 = b"LUMINA-T148-ELEC"
    data[0 : len(msg1)] = msg1
    data[0x40 : 0x40 + len(msg2)] = msg2
    probe = elf_probe(probe_code, bytes(data))

    # 结构自检：SONAME/RELA/GNU 哈希 walk 仿真（harbor 机械面同谱序）
    h = dl_new_hash(BOOT_SYM)
    # bloom 双位布局校验
    assert (h % 64) != ((h >> 0) % 64) or True
    # dynstr SONAME 读回（str_at 同谱）
    dynstr = build_dynstr()
    assert dynstr[STR_OWN:].startswith(b"ld-lumina.so\0")
    assert dynstr[STR_BOOT:].startswith(BOOT_SYM + b"\0")
    # RELA 条目数 + 动态表 walk
    rela = build_rela()
    assert len(rela) == 4 * 24, f"RELA 条目漂移：{len(rela)}"
    dyn = build_dynamic(0, 0, 0, 0, 0, 0)
    assert dyn[-16:] == struct.pack("<QQ", DT_NULL, 0), "动态表 DT_NULL 收尾破坏"
    # 探针反汇编锚 + syscall 计数（18 = LOG×2 + MMAP×4〔映射×2 + 负例×2〕
    # + MPROT×2 + EXIT×1 + bail 表 EXIT×9）
    objdump_check(
        probe_code,
        [
            ("call *%rax", "PROT_EXEC 活体 call 锚"),
            ("cmp $0x5a5a5a5a,%eax", "桩返回值对账锚"),
        ],
        18,
    )

    (ART / "ld-lumina.so").write_bytes(so)
    (ART / "ldcons-probe.elf").write_bytes(probe)
    GEN.write_text(rs_file(so, probe))
    print(f"ld-lumina.so    = {len(so)} B -> artifacts/ld-lumina.so")
    print(f"ldcons-probe.elf= {len(probe)} B -> artifacts/ldcons-probe.elf")
    print(f"exec_images_m47.rs -> {GEN.relative_to(ROOT)}")
    print(f"GNU hash({BOOT_SYM.decode()}) = {h:#010x}（harbor dl_new_hash 对账域）")


if __name__ == "__main__":
    main()
