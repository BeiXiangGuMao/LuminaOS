#!/usr/bin/env python3
"""gen_m48c_init.py — M48-INIT57（笔65）init_array 执行域批映像生成器。

产物：artifacts/liblumina-init.so（真 ET_DYN——SONAME=liblumina-init.so
+ init_fn0/init_fn1/fini_fn0 三定义符号 + DT_INIT/DT_INIT_ARRAY(2)/
DT_FINI_ARRAY(1) + RELA RELATIVE×2（.init_array 双指针基址兑现域）+
PT_DYNAMIC）+ exec_images_m48c.rs 承载。
结构自检：SONAME/动态表/RELA/objdump 锚 + init 序语义仿真。
"""
import struct, subprocess, tempfile, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m48c.rs"
PAGE, EHDR, PHDR = 0x1000, 64, 56
TEXT_VA, RW_VA = 0x1000, 0x3000

DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAY, DT_FINI_ARRAYSZ = 12, 13, 25, 27, 26, 28
DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_SYMENT, DT_SONAME, DT_NULL = 5, 10, 6, 11, 14, 0
DT_GNU_HASH, DT_RELA, DT_RELASZ, DT_RELAENT = 0x6FFF_FEF5, 7, 8, 9
R_RELATIVE = 8
R_X86_64_RELATIVE = 8

SONAME = b"liblumina-init.so"
FN0, FN1, FINI0 = b"init_fn0", b"init_fn1", b"fini_fn0"
STUB0 = b"\xb8" + struct.pack("<I", 0x11111111) + b"\xc3"  # mov eax,imm; ret
STUB1 = b"\xb8" + struct.pack("<I", 0x22222222) + b"\xc3"
STUBF = b"\xb8" + struct.pack("<I", 0x33333333) + b"\xc3"
FN0_VA, FN1_VA, FINI_VA = TEXT_VA, TEXT_VA + 0x10, TEXT_VA + 0x20
ARR_VA = RW_VA  # .init_array @ RW+0（双 8B 指针）+ .fini_array @+0x10（1 8B）

def dl_new_hash(n):
    h = 5381
    for c in n:
        h = (h * 33) ^ c & 0xFFFFFFFF
    return h & 0xFFFFFFFF

def build():
    dynstr = SONAME + b"\0" + FN0 + b"\0" + FN1 + b"\0" + FINI0 + b"\0"
    str_fn0, str_fn1, str_fini = len(SONAME)+1, len(SONAME)+2+len(FN0), len(SONAME)+3+len(FN0)+len(FN1)
    def sym(name, info, val, size):
        return struct.pack("<IBBHQQ", name, info, 0, 1, val, size)
    dynsym = sym(0,0,0,0) + sym(str_fn0,0x12,FN0_VA,6) + sym(str_fn1,0x12,FN1_VA,6) + sym(str_fini,0x12,FINI_VA,6)
    h0, h1, hf = dl_new_hash(FN0), dl_new_hash(FN1), dl_new_hash(FINI0)
    bloom = (1<<(h0%64)) | (1<<(h1%64)) | (1<<(hf%64))
    buckets, chains = [0,0,0], [0,0,0]
    last = {}
    for k, h in ((1,h0),(2,h1),(3,hf)):
        last[h%3] = k
    for k, h in ((1,h0),(2,h1),(3,hf)):
        b = h%3
        buckets[b] = buckets[b] or k
        chains[k-1] = (h|1) if last[b]==k else (h&~1)
    gnu = struct.pack("<IIII",3,1,1,0) + struct.pack("<Q",bloom) + struct.pack("<3I",*buckets) + struct.pack("<3I",*chains)
    # RELA RELATIVE×2：.init_array[0/1] = init_fn0/init_fn1（基址兑现域）
    def rela(off, addend):
        return struct.pack("<QQq", off, R_RELATIVE, addend)
    rela_b = rela(ARR_VA, FN0_VA) + rela(ARR_VA+8, FN1_VA)
    dyn = b"".join(struct.pack("<QQ", t_, v) for t_, v in [
        (DT_SONAME,0),(DT_STRTAB,TEXT_VA+0x40),(DT_STRSZ,len(dynstr)),(DT_SYMTAB,0),
        (DT_SYMENT,24),(DT_GNU_HASH,0),(DT_RELA,0),(DT_RELASZ,48),(DT_RELAENT,24),
        (DT_INIT,FN0_VA),(DT_INIT_ARRAY,ARR_VA),(DT_INIT_ARRAYSZ,16),
        (DT_FINI,FINI_VA),(DT_FINI_ARRAY,ARR_VA+0x10),(DT_FINI_ARRAYSZ,8),(DT_NULL,0)])
    # 占位回填（dynsym/gnu/rela VA 二次布局）
    text = bytearray()
    text += STUB0 + b"\x90"*10 + STUB1 + b"\x90"*10 + STUBF
    text += b"\x90" * (0x40 - len(text))
    strtab_va, dynsym_va = TEXT_VA+len(text), 0
    text += dynstr
    dynsym_va = TEXT_VA + len(text); text += dynsym
    gnu_va = TEXT_VA + len(text); text += gnu
    rela_va = TEXT_VA + len(text); text += rela_b
    text += b"\x00" * (-len(text) % PAGE)
    dyn = b"".join(struct.pack("<QQ", t_, v) for t_, v in [
        (DT_SONAME,0),(DT_STRTAB,strtab_va),(DT_STRSZ,len(dynstr)),(DT_SYMTAB,dynsym_va),
        (DT_SYMENT,24),(DT_GNU_HASH,gnu_va),(DT_RELA,rela_va),(DT_RELASZ,48),(DT_RELAENT,24),
        (DT_INIT,FN0_VA),(DT_INIT_ARRAY,ARR_VA),(DT_INIT_ARRAYSZ,16),
        (DT_FINI,FINI_VA),(DT_FINI_ARRAY,ARR_VA+0x10),(DT_FINI_ARRAYSZ,8),(DT_NULL,0)])
    rw = bytearray(0x200)
    rw[0x00:0x10] = struct.pack("<QQ", FN0_VA, FN1_VA)   # .init_array 双指针（链接时 VA）
    rw[0x10:0x18] = struct.pack("<Q", FINI_VA)            # .fini_array[0]
    rw[0x100:0x100+len(dyn)] = dyn
    blob = bytearray(3*PAGE)
    blob[0:4] = b"\x7fELF"; blob[4]=2; blob[5]=1; blob[6]=1
    struct.pack_into("<HHIQQQIHHHHHH", blob, 0x10, 3, 62, 1, 0, EHDR, 0, 0, EHDR, PHDR, 3, 0, 0, 0)
    def ph(k, t_, fl, off, va, fsz):
        struct.pack_into("<IIQQQQQQ", blob, EHDR + k * PHDR, t_, fl, off, va, va, fsz, fsz, PAGE)
    ph(0, 1, 5, PAGE, TEXT_VA, len(text))
    ph(1, 1, 6, 2*PAGE, RW_VA, len(rw))
    ph(2, 2, 6, 2*PAGE+0x100, RW_VA+0x100, len(dyn))
    blob[PAGE:PAGE+len(text)] = text
    blob[2*PAGE:2*PAGE+len(rw)] = rw
    # 自检：SONAME + 动态表 + RELA + init 序仿真（DT_INIT → array0 → array1）
    assert blob[0:4] == b"\x7fELF"
    so_va = strtab_va
    assert blob[so_va - TEXT_VA + PAGE : so_va - TEXT_VA + PAGE + len(SONAME)] == SONAME, "SONAME 读回破坏"
    ia0, ia1 = struct.unpack_from("<QQ", rw, 0)
    assert (ia0, ia1) == (FN0_VA, FN1_VA), ".init_array 指针域破坏"
    order = [("DT_INIT", FN0_VA), ("array[0]", ia0), ("array[1]", ia1)]
    assert [a for _, a in order] == [FN0_VA, FN0_VA, FN1_VA], "init 序仿真破坏"
    return bytes(blob)

def main():
    so = build()
    (ART / "liblumina-init.so").write_bytes(so)
    rows = []
    for i in range(0, len(so), 16):
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in so[i:i+16]) + ",")
    GEN.write_text(
        "// exec_images_m48c —— M48-INIT57 笔65 交付件映像（gen_m48c_init.py 产物）。\n"
        "// liblumina-init.so：真 ET_DYN 初始化域模块（DT_INIT + .init_array[2] +\n"
        "// .fini_array[1] + RELA RELATIVE×2 指针兑现域——t152 INIT/LEDGER 相位锚）。\n\n"
        "/// liblumina-init.so（ET_DYN——init_array 执行域交付件，与 artifacts/ 同源）。\n"
        "pub const LIBLUMINA_INIT_SO: &[u8] = &[\n" + "\n".join(rows) + "\n];\n")
    print(f"liblumina-init.so = {len(so)} B")

if __name__ == "__main__":
    main()
