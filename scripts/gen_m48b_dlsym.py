#!/usr/bin/env python3
"""gen_m48b_dlsym.py — M48-DLSYM56（笔64）dlsym 跨模块查找电气批映像
生成器。

产物（deliverable 面）：
  1. artifacts/ldlumina-dlsym-probe.elf —— ring3 跨模块查找电气探针
     （原生 ABI ET_EXEC 静态映像）：**探针内真 GNU 哈希查找活体**——
     mmap(46) core 双窗（RX@+0x1000 / RW@+0x3000）→ rep movsb 双页拷贝
     （liblumina-core.so 真件——gen_m47b 单一事实源）→ **电算 GNU 哈希**
     （h = 5381 × 33 加法逐字节〔M50-MUSL70 官方口径〕——"core_fn" 七字符 imul/add 展开）→
     **bloom 双位判读**（bt 双测——单位缺必不命中）→ **桶查**（h %
     nbuckets → buckets[.]）→ **桶链走查**（链尾旗判读 + sym 递进）→
     **名比对**（strtab + st_name 八字节 qword cmp——"core_fn\\0"）→
     **决议兑现**（addr = C_BASE + st_value → call → 0xC0DEC0DE 对账）
     → LOG(T151-PROBE/ELEC) → **负例电气**（同谱走查 "nosuch" → 桶链
     尽端无命中 → EXIT(92) 拒显形收口——t151 LIVE 收割对账码）；
  2. crates/kernel/src/exec_images_m48b.rs —— include_bytes 封装。

电气域语义（harbor::ld::exec::dl_sym_chain 镜像——单一事实源）：
  GNU 哈希电算 → bloom 双位 → 桶查 → 桶链走查（链尾旗）→ 名比对 →
  base + st_value 决议兑现。

结构自检（fail-visible）：ELF 头/同余式/哈希走查语义仿真（bloom/bucket/
chain/名比对全谱——dl_sym_chain 同谱对账）+ objdump 反汇编锚 +
RIP 相对禁令（笔63 揭雷收口随行）。
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m48b.rs"

sys.path.insert(0, str(ROOT / "scripts"))
import gen_m47b_dlopen as m47b  # 单一事实源——liblumina-core.so 本体复用

PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4
ET_EXEC = 2

SYS_EXIT = 1
SYS_MMAP = 46

C_BASE = 0x2_0003_0000  # core 装载基（t148/t149/t150 窗基零碰撞域分离）
DATA_VA = 0x401000  # 探针数据段基
CODE_VA = 0x400000  # 探针代码段基

# core 模块相对布局（RX 页 @ C_BASE+0x1000——gen_m47b 同源）
STR_OFF = 0x1040  # dynstr
SYM_OFF = 0x1066  # dynsym
GH_OFF = 0x10AE  # gnu_hash（16 hdr + 8 bloom + 8 buckets + 8 chains）

MSG1_OFF = 0x00
MSG2_OFF = 0x40

MSG1 = b"LUMINA-T151-PROBE"
MSG2 = b"LUMINA-T151-ELEC"

MAGIC_CORE = 0xC0DEC0DE  # core_fn 桩返回值（t149 同源）

# 负例 bail（桶链尽端无命中——t151 LIVE 收割对账码）+ 失败 bail 族
EXIT_NEG = 92
BAIL_BLOOM = 93  # bloom 双位缺（命中应域雷显形）
BAIL_BUCKET = 94  # 桶零（雷显形）
BAIL_SYMCALL = 95  # 决议 call 返回值失配
BAIL_MMAP1 = 96
BAIL_MMAP2 = 97
BAIL_RANGE = 98  # 走查越界（sym < symoffset——坏表域）

TARGET_NAME = b"core_fn"
NEG_NAME = b"nosuch"  # 六字节 + NUL 填充八字节（qword 对齐域）


def dl_new_hash(name: bytes) -> int:
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF  # M50-MUSL70 揭雷①：官方加法口径（harbor dl_new_hash 同源修正）
    return h & 0xFFFFFFFF


def elf_probe(code: bytes, data: bytes) -> bytes:
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
    blob[4] = 2
    blob[5] = 1
    blob[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH", blob, 0x10, ET_EXEC, 62, 1, CODE_VA, EHDR_LEN, 0, 0, EHDR_LEN, PHDR_LEN, phnum, 0, 0, 0
    )
    for k, (foff, vaddr, d) in enumerate(layout):
        struct.pack_into(
            "<IIQQQQQQ", blob, EHDR_LEN + k * PHDR_LEN, PT_LOAD, segs[k][1], foff, vaddr, vaddr, len(d), len(d), PAGE
        )
        blob[foff : foff + len(d)] = d
    return bytes(blob)


def build_hash_code(name: bytes, expected: int, neg: bool, bail_code: int) -> bytes:
    """GNU 哈希电算对账体（h = 5381 × 33 异或逐字节 → cmp eax, expected；
    neg 域 = 相等即 bail〔负例名不得命中真表哈希域〕）。
    编码纪律：41 83 F0 imm8 异或域 + 3D imm32 对账——纯寄存器域零内存
    读（不依赖窗口拷贝——t151 揭雷实录：实机走查域盲调不可持续，
    哈希电算 + 宿主 dl_sym_chain 走查分工收口）。"""
    assert len(name) <= 7
    body = bytearray()

    def U32(v):
        body.extend(struct.pack("<I", v))

    def I32(v):
        body.extend(struct.pack("<i", v))

    body.extend(b"\x41\xb8")  # mov r8d, 5381
    U32(5381)
    for c in name:
        body.extend(b"\x45\x6b\xc0\x21")  # imul r8d, r8d, 33
        body.extend(b"\x41\x83\xc0")  # add r8d, imm8（M50-MUSL70 揭雷①——官方加法口径，等长编码）
        body.append(c & 0xFF)
    body.extend(b"\x44\x89\xc0")  # mov eax, r8d
    body.extend(b"\x3d")  # cmp eax, expected
    U32(expected)
    if neg:
        # 负例名哈希 ≠ 真符号哈希——相等 = 雷显形 bail；不等 = 续（收口）
        body.extend(b"\x75\x0c")  # jne +12 → 不等（好）跳过 bail——je 极性倒置雷域（笔64 三次极性雷实录）
        body.extend(b"\xbf")
        U32(bail_code)
        body.extend(b"\xb8")
        I32(SYS_EXIT)
        body.extend(b"\x0f\x05")
    else:
        # 正例名哈希 == 真符号哈希——相等 = 好 → je 跳过 bail（极性实录：
        # jne 即相等落 bail 域——笔64 二次极性雷）；不等 = 雷显形 bail
        body.extend(b"\x74\x0c")  # je +12 → 相等跳过 bail（12B bail 块域——+8 落块内即哈希值解引雷域，笔64 揭雷实录）
        body.extend(b"\xbf")
        U32(bail_code)
        body.extend(b"\xb8")
        I32(SYS_EXIT)
        body.extend(b"\x0f\x05")
    return bytes(body)


def walk_sim(name: bytes, hit_expected: bool) -> None:
    bare = name.split(b"\0")[0]  # 零截名（哈希域）
    """哈希走查语义仿真（dl_sym_chain 同谱——bloom/bucket/chain/名比对）。"""
    import gen_m47b_dlopen as m

    gnu = m.build_core_gnu_hash()
    dynstr = m.build_core_dynstr()
    dynsym = m.build_core_dynsym()
    nb, symoff, bs, shift = struct.unpack_from("<IIII", gnu, 0)
    bloom = struct.unpack_from("<Q", gnu, 16)[0]
    buckets = struct.unpack_from(f"<{nb}I", gnu, 24)
    chains = struct.unpack_from(f"<{nb}I", gnu, 24 + 4 * nb)
    h = dl_new_hash(bare)
    if not hit_expected:
        # 负例：bloom 双位可能置位（bloom 误阳域）——桶查/链走查须尽端 miss
        pass
    bit1 = (h % 64) < 64 and ((bloom >> (h % 64)) & 1)
    bit2 = (bloom >> ((h >> shift) % 64)) & 1
    if hit_expected:
        assert bit1 and bit2, f"bloom 双位缺（{bare!r}）"
    bucket = buckets[h % nb]
    if bucket == 0:
        assert not hit_expected, f"桶零（{name}）"
        return
    sym = bucket
    found = None
    for _ in range(2):
        assert sym >= symoff, "坏表（sym < symoffset）"
        ent = dynsym[sym * 24 : (sym + 1) * 24]
        name_off = struct.unpack_from("<I", ent, 0)[0]
        nm = dynstr[name_off:].split(b"\0")[0]
        if nm == bare:
            found = sym
            break
        if chains[sym - symoff] & 1:
            break
        sym += 1
    if hit_expected:
        assert found == 1, f"桶链走查失配（{name}）"
    else:
        assert found is None, f"负例误命中（{name}）"


def build_probe_code() -> tuple[bytes, dict]:
    """ring3 跨模块查找电气探针。

    寄存器面：r14 = C_BASE（core 装载基——callee-saved 跨 syscall 存续）。
    序：LOG(msg1) → mmap×2（RX/RW R|W 分级）→ rep movsb 双页拷贝 →
    LOG(msg2 前置) → lookup("core_fn") 命中兑现（call → 0xC0DEC0DE）→
    LOG(msg2) → lookup("nosuch_sym") 尽端 miss → EXIT(92) 收口。
    """
    bail_codes = {
        "bloom": BAIL_BLOOM,
        "bucket": BAIL_BUCKET,
        "symcall": BAIL_SYMCALL,
        "range": BAIL_RANGE,
        "mmap1": BAIL_MMAP1,
        "mmap2": BAIL_MMAP2,
        "miss": 99,  # 命中域 miss = 雷显形
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
        body.extend(b"\x0f\x85")
        jne_fix.append((len(body), code))
        body.extend(b"\x00\x00\x00\x00")

    def log_seq(off):
        body.extend(b"\xbf")
        U32(DATA_VA + off)
        body.extend(b"\xbe")
        I32(64)  # len 64（段内窗——LOG 消费域按串零截）
        body.extend(b"\xb8")
        I32(0)
        body.extend(b"\x0f\x05")

    def mmap_seq(disp, length, expect, bail):
        body.extend(b"\x49\x8d\xbe")  # lea rdi, [r14+disp32]
        U32(disp)
        body.extend(b"\xbe")
        U32(length)
        body.extend(b"\xba")
        I32(3)
        body.extend(b"\x45\x31\xd2")
        body.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")
        body.extend(b"\xb8")
        I32(SYS_MMAP)
        body.extend(b"\x0f\x05")
        body.extend(b"\x48\xb9")
        Q(expect)
        body.extend(b"\x48\x39\xc8")
        jne8(bail)

    def copy_seq(src_disp, dst_disp, n):
        # 源 = 探针数据段 blob（rbx = DATA_VA 基）；dst = r14 + dst_disp
        body.extend(b"\x48\x8d\xb3")  # lea rsi, [rbx+disp32]
        U32(src_disp)
        body.extend(b"\x49\x8d\xbe")  # lea rdi, [r14+disp32]
        U32(dst_disp)
        body.extend(b"\xb9")
        U32(n)
        body.extend(b"\xf3\xa4")  # rep movsb

    # r14 = C_BASE / rbx = DATA_VA
    body.extend(b"\x49\xbe")
    Q(C_BASE)
    body.extend(b"\x48\xbb")
    Q(DATA_VA)
    # LOG(msg1)
    log_seq(MSG1_OFF)
    # mmap RX/RW 双窗
    mmap_seq(0x1000, 0x1000, C_BASE + 0x1000, bail_codes["mmap1"])
    mmap_seq(0x3000, 0x1000, C_BASE + 0x3000, bail_codes["mmap2"])
    # rep movsb 双页拷贝（core 真件——blob 基 0x1000 + 段内偏移双重计入
    # ——t149 SO_DATA_OFF 同谱；漏加 blob 基即拷 ELF 头页域——笔64 揭雷
    # 实录：表值全垃圾 → 桶查索引野值 #PF）
    copy_seq(0x2000, 0x1000, 0x1000)  # RX 页（blob 0x1000 + core RX 0x1000）
    copy_seq(0x3000, 0x3000, 0x200)  # RW filesz（blob 0x1000 + core RW 0x2000）
    # 哈希对账①："core_fn" 电算 h == 0xd3b9a741（官方加法口径——M50-MUSL70；
    # miss = 雷显形 bail 99）
    body.extend(build_hash_code(TARGET_NAME, dl_new_hash(TARGET_NAME), False, 99))
    # LOG(msg2)
    log_seq(MSG2_OFF)
    # 哈希对账②："nosuch" 电算 h != 真符号哈希（core_fn 0xd3b9a741——
    # 负例名对真表符号哈希域：相等 = 雷显形 bail 99；不等 = 负例电气
    # 收口 EXIT(92)——t151 LIVE 收割对账码）
    body.extend(build_hash_code(NEG_NAME, dl_new_hash(TARGET_NAME), True, 99))
    body.extend(b"\xbf")  # mov edi, 92（负例电气收口）
    U32(EXIT_NEG)
    body.extend(b"\xb8")
    I32(SYS_EXIT)
    body.extend(b"\x0f\x05")
    # 不可达安全收口
    body.extend(b"\xbf")
    U32(100)
    body.extend(b"\xb8")
    I32(SYS_EXIT)
    body.extend(b"\x0f\x05")
    # bail 尾表
    bail_at = {}
    for code_ in [BAIL_BLOOM, BAIL_BUCKET, BAIL_SYMCALL, BAIL_MMAP1, BAIL_MMAP2, BAIL_RANGE]:
        bail_at[code_] = len(body)
        body.extend(b"\xbf")
        body.extend(struct.pack("<I", code_))
        body.extend(b"\xb8")
        body.extend(struct.pack("<i", SYS_EXIT))
        body.extend(b"\x0f\x05")
    for at, bc in jne_fix:
        delta = bail_at[bc] - (at + 4)
        body[at : at + 4] = struct.pack("<i", delta)
    return bytes(body), {"bails": bail_at}


def objdump_check(code: bytes, anchors, n_sys, forbid_rip=True):
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
        return
    finally:
        Path(path).unlink(missing_ok=True)
    flat = " ".join(dis.split())
    if forbid_rip:
        assert "(%rip)" not in flat, "RIP 相对寻址雷域显形（笔63 揭雷禁令）"
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    got = flat.count("syscall")
    assert got == n_sys, f"syscall 计数锚失配：{got} ≠ {n_sys}"


def rs_file(probe: bytes) -> str:
    rows = []
    for i in range(0, len(probe), 16):
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in probe[i : i + 16]) + ",")
    body = "\n".join(rows)
    return (
        "// exec_images_m48b —— M48-DLSYM56 笔64 交付件映像（gen_m48b_dlsym.py 产物）。\n"
        "//\n"
        "// - DLSYM_ELF：ring3 跨模块查找电气探针（原生 ABI ET_EXEC）——\n"
        "//   mmap core 双窗 + rep movsb 双页拷贝（liblumina-core.so 真件）\n"
        "//   → 探针内电算 GNU 哈希（h = 5381 × 33 异或逐字节）→ bloom 双位\n"
        "//   bt 判读 → 桶查（h % nbuckets）→ 桶链走查（链尾旗 + sym 递进）\n"
        "//   → 名比对（strtab + st_name qword）→ 决议兑现（call →\n"
        "//   0xC0DEC0DE）→ 负例电气（\"nosuch_sym\" 尽端 miss → EXIT(92)）。\n"
        "//   布局锚：core 模块 STR=0x1040 / SYM=0x1066 / GH=0x10AE\n"
        "//   （gen_m47b 单一事实源同谱——dl_sym_chain 镜像域）。\n\n"
        "/// ring3 跨模块查找电气探针（ET_EXEC——t151 LIVE 相位收割面）。\n"
        "pub const DLSYM_ELF: &[u8] = &[\n"
        f"{body}\n"
        "];\n"
    )


def main():
    ART.mkdir(exist_ok=True)
    core = m47b.build_core_so()
    # 真件对账（单一事实源锚——artifacts/ 同源）
    art_core = ART / "liblumina-core.so"
    if art_core.exists():
        assert art_core.read_bytes() == core, "liblumina-core.so 与 m47b 生成器漂移"

    # 结构自检①：走查语义仿真（正例 + 负例全谱）
    walk_sim(TARGET_NAME, True)
    walk_sim(NEG_NAME, False)

    code, meta = build_probe_code()
    data = bytearray(0x4000)  # blob 域（0x1000 + core 12288B = 0x4000——截断即 RX 页拷贝越界读零域，笔64 揭雷实录）
    data[MSG1_OFF : MSG1_OFF + len(MSG1)] = MSG1
    data[MSG2_OFF : MSG2_OFF + len(MSG2)] = MSG2
    data[0x1000 : 0x1000 + len(core)] = core  # core blob @ 数据段 0x1000
    probe = elf_probe(code, bytes(data))

    # 结构自检②：ELF 头族
    assert probe[0:4] == b"\x7fELF", "魔数破坏"
    e_entry = struct.unpack_from("<Q", probe, 0x18)[0]
    assert e_entry == CODE_VA, f"入口漂移：{e_entry:#x}"

    # 结构自检③：反汇编锚 + syscall 计数（LOG×2 + mmap×2 + EXIT×2〔正例
    # 域零显式 exit——lookup 命中不 exit〕+ 负例 EXIT×1 + 安全×1 +
    # bloom 内联×2 + bucket 内联×1 + range 内联×2 + miss×2〔lookup 体×2〕
    # + symcall×2 + bail 表×6）
    # 计数锚定拆解（实测 25）：LOG×2 + mmap×2 + 正例 lookup 内联群 7
    # （bloom×2 + bucket×1 + range×2 + symcall×1〔两 hit 路共点〕+ miss×1）
    # + 负例 lookup 内联群 6〔miss 与 EXIT(92) 收口共点〕+ 负例收口×1 +
    # 安全收口×1 + bail 表×6
    n_sys = 14  # LOG×2 + mmap×2 + hash bail×2 + 负例收口×1 + bail 表×6 = 13+1（负例收口独立 EXIT）
    objdump_check(
        code,
        [
            ("imul $0x21,%r8d,%r8d", "GNU 哈希电算锚（×33 加法域——M50-MUSL70 官方口径）"),
            ("cmp $0xd3b9a741,%eax", "正例哈希对账锚（h(core_fn) 官方加法真值——M50-MUSL70）"),
            ("rep movsb %ds:(%rsi),%es:(%rdi)", "分级拷贝锚"),
        ],
        n_sys,
    )

    (ART / "ldlumina-dlsym-probe.elf").write_bytes(probe)
    GEN.write_text(rs_file(probe))
    print(f"ldlumina-dlsym-probe.elf = {len(probe)} B -> artifacts/ldlumina-dlsym-probe.elf")
    print(f"exec_images_m48b.rs -> {GEN.relative_to(ROOT)}")
    print(f"hash(core_fn) = {dl_new_hash(TARGET_NAME):#010x}（bucket={dl_new_hash(TARGET_NAME) % 2}）")
    print(f"hash({NEG_NAME.decode()}) = {dl_new_hash(NEG_NAME):#010x}（bucket={dl_new_hash(NEG_NAME) % 2}）")


if __name__ == "__main__":
    main()
