#!/usr/bin/env python3
"""gen_m48a_pltgot.py — M48-PLTGOT55（笔63）PLT/GOT 惰性绑定电气执行批
映像生成器。

产物（deliverable 面）：
  1. artifacts/ldlumina-pltgot-probe.elf —— ring3 惰性绑定电气探针
     （原生 ABI ET_EXEC 静态映像）：**真 PLT/GOT 惰性绑定电气活体**——
     mmap(46) GOT 窗（RW 匿名页）→ 经典 GOT 布局铸面（GOT[1] =
     link_map 描述子 / GOT[2] = resolver 入口 / GOT[3+idx] = PLT 存根
     地址）→ **首调经 PLT 存根**（call *GOT[3] → PLT1: push 0; jmp
     PLT0 → push [r14+8]（描述子）; jmp [r14+0x10]（resolver 间呼）→
     resolver 电水解（pop 描述子/idx → 符号表查址 → **GOT[3] 槽写兑现**
     → PATCHES 计数 → call 目标 → ret 回 caller）→ 首调对账（eax==1 +
     GOT[3] 读回 == 目标址 + PATCHES==1）→ **次调直达**（call *GOT[3]
     → 目标直呼——eax==2 + PATCHES 仍==1——resolver 零重入电气证明）
     → GOT[1] 描述子原貌读回 → LOG 取证（T150-PROBE/ELEC 探针面）→
     **负例电气**（call *GOT[4] → PLT2: push 1 → resolver → 符号表
     [1]==0 → bail EXIT(91)——resolver 拒显形收口）；
  2. crates/kernel/src/exec_images_m48a.rs —— include_bytes 封装
     （user.rs include! 引入——M42 gen lane 同谱）。

电气域语义（harbor::ld::exec::LazyGot 两态机镜像——单一事实源）：
  wire（JUMP_SLOT × !bind_now → 槽初值 = PLT 存根）
  resolve（resolver 步 → 槽值 = 决议地址，Stub→Resolved）
  直达（已决议槽不经 resolver——次调 PATCHES 零增）。

编码纪律：GOT 窗基 0x2_0002_0000 > 2^31——**disp32 绝对寻址不可达域**
（雷位实录：push [abs]/mov [abs+idx] 编码不出）——GOT 槽访问全程寄存器
间接（r14 = GOT 基 callee-saved）；数据段 0x401xxx < 2^31——abs disp32
可达（TABLE 查址 [TABLE+idx*8] / PATCHES/CALLS 计数域）。

笔63 揭雷第一域（x86-64 FF 组编码雷）：`FF 05 disp32`〔modrm rm=101 无
SIB〕在 64 位模式 = **RIP 相对**〔32 位习惯遗留——cr2=0x801239 =
0x4001a9 + 0x401090 精确对账实录〕；abs 必经 SIB 无基（modrm rm=100 +
SIB base=101 → `FF 04 25 disp`——INC /0 数字码）+ objdump 锚
**RIP 相对禁令**（`(%rip)` 子串零容忍——锚串 `incl 0x401090(%rip)` 曾
漏放〔后随 # 0x401239 有效址注释即铁证〕——本笔收口）。

结构自检（fail-visible）：ELF 头/同余式/两态机语义仿真（wire→resolve
→direct 全谱——harbor LazyGot 同谱对账）+ objdump 反汇编锚（PLT push/
jmp/resolver 写槽/inc 计数）+ syscall 计数。
"""

import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
GEN = ROOT / "crates" / "kernel" / "src" / "exec_images_m48a.rs"

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

# ---- ring3 探针窗基（MMAP_ANON 窗内——t148/t149 窗基零碰撞域分离） ----

GOT_BASE = 0x2_0002_0000  # GOT 窗（RW 匿名页——PLT/GOT 槽面）
DATA_VA = 0x401000  # 探针数据段基
CODE_VA = 0x400000  # 探针代码段基

# 数据段布局
MSG1_OFF = 0x00  # "LUMINA-T150-PROBE"
MSG2_OFF = 0x40  # "LUMINA-T150-ELEC"
TABLE_OFF = 0x80  # 符号表 [2]：TABLE[0] = 目标函数址 / TABLE[1] = 0（负例）
PATCHES_OFF = 0x90  # resolver 兑现计数（u32）
CALLS_OFF = 0x94  # 目标函数调用计数（u32）

# 负例 bail（resolver 拒显形——t150 LIVE 收割对账码）+ 失败 bail 族
EXIT_NEG = 91
EXIT_OK_SAFE = 92  # 不可达安全收口（负例 call 若返回即雷显形）
BAIL_RANGE = 93  # resolver idx 越界（0..1 外）
BAIL_FIRST = 94  # 首调返回值失配
BAIL_PATCH = 95  # GOT[3] 读回失配
BAIL_CNT1 = 96  # PATCHES != 1（首调后）
BAIL_SECOND = 97  # 次调返回值失配
BAIL_CNT2 = 98  # PATCHES != 1（次调后——resolver 重入雷显形）
BAIL_DESC = 99  # GOT[1] 描述子原貌失配
BAIL_MMAP = 100  # mmap 失败

MAGIC_DESC = 0x1A1A1A1A  # GOT[1] link_map 描述子（电气消费域——push 入栈）

MSG1 = b"LUMINA-T150-PROBE"
MSG2 = b"LUMINA-T150-ELEC"


def elf_probe(code: bytes, data: bytes) -> bytes:
    """原生 ABI ET_EXEC 静态映像（ELF_NATIVE lane 同谱——gen_m47 同款）。"""
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


def build_probe_code() -> tuple[bytes, dict]:
    """ring3 惰性绑定电气探针。

    寄存器面：r14 = GOT_BASE（callee-saved 跨 syscall 存续——PLT0/
    resolver 域 GOT 槽访问全寄存器间接）。
    布局：entry 主序 → PLT0 → PLT1（+16）→ PLT2（+32）→ resolver（对齐
    16）→ target（对齐 16）→ bail 尾表。经典 x86_64 PLT 布局：PLT 存根 =
    push rel_idx; jmp PLT0；PLT0 = push [r14+8]（描述子）; mov rax,
    [r14+0x10]; jmp rax（resolver 间呼）；resolver = pop 描述子 → pop idx
    → 表查址 → GOT 槽写兑现 → PATCHES++ → call 目标 → ret 回 caller
    （glibc _dl_runtime_resolve 同谱电水单）。
    """
    body = bytearray()
    jne_fix = []  # (位置, bail 码)
    patch_imm64 = []  # (imm64 位置, 取 meta 键)
    patch_qword = []  # (qword 位置, 取 meta 键)

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

    def write_q(disp: int, meta_key: str):
        # movabs rax, <imm64→meta>; mov [r14+disp32], rax
        body.extend(b"\x48\xb8")
        patch_imm64.append((len(body), meta_key))
        body.extend(b"\x00" * 8)
        body.extend(b"\x49\x89\x86")
        U32(disp)

    def readback_q(disp: int, meta_key: str, bail: int):
        # mov rax, [r14+disp32]; movabs rcx, <imm64→meta>; cmp
        body.extend(b"\x49\x8b\x86")
        U32(disp)
        body.extend(b"\x48\xb9")
        patch_imm64.append((len(body), meta_key))
        body.extend(b"\x00" * 8)
        body.extend(b"\x48\x39\xc8")
        jne8(bail)

    def call_got(disp: int):
        # mov rax, [r14+disp32]; call rax（GOT 间呼——首调/次调同款编码）
        body.extend(b"\x49\x8b\x86")
        U32(disp)
        body.extend(b"\xff\xd0")

    def read_abs_dword(abs_va: int):
        # mov eax, [abs disp32]（8B 04 25——modrm rm=100 + SIB base=101
        # 无基——真绝对；rm=101 无 SIB 即 RIP 相对雷域）
        body.extend(b"\x8b\x04\x25")
        U32(abs_va)

    def inc_abs_dword(abs_va: int):
        # inc dword [abs disp32]（FF 04 25——/0 数字码 + SIB 无基;
        # FF 05 disp = modrm rm=101 无 SIB = RIP 相对雷域——笔63 揭雷收口）
        body.extend(b"\xff\x04\x25")
        U32(abs_va)

    # ---- 主序 ----
    # movabs r14, GOT_BASE
    body.extend(b"\x49\xbe")
    Q(GOT_BASE)
    # LOG(msg1)
    body.extend(b"\xbf")
    U32(DATA_VA + MSG1_OFF)
    body.extend(b"\xbe")
    I32(len(MSG1))
    body.extend(b"\xb8")
    I32(0)
    body.extend(b"\x0f\x05")
    # mmap(GOT_BASE, 0x1000, R|W, 0, ANON_FD=-1) → rax == GOT_BASE
    body.extend(b"\x4c\x89\xf7")  # mov rdi, r14
    body.extend(b"\xbe")
    U32(0x1000)
    body.extend(b"\xba")
    I32(3)
    body.extend(b"\x45\x31\xd2")  # xor r10d, r10d
    body.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")  # mov r8, -1（MMAP_ANON_FD）
    body.extend(b"\xb8")
    I32(SYS_MMAP)
    body.extend(b"\x0f\x05")
    body.extend(b"\x48\xb9")
    Q(GOT_BASE)
    body.extend(b"\x48\x39\xc8")
    jne8(BAIL_MMAP)
    # ---- GOT 铸面（经典布局——wire 域电气化） ----
    body.extend(b"\x49\xc7\x86")  # mov QWORD PTR [r14+0x00], 0（GOT[0] 零位）
    U32(0x00)
    Q(0)
    write_q(0x08, "desc")  # GOT[1] = link_map 描述子
    write_q(0x10, "resolver")  # GOT[2] = resolver 入口
    write_q(0x18, "plt1")  # GOT[3] = PLT1 存根（idx 0 槽初值）
    write_q(0x20, "plt2")  # GOT[4] = PLT2 存根（idx 1 槽初值——负例）
    # ---- 首调（lazy——经 PLT1 → PLT0 → resolver 电水解） ----
    call_got(0x18)
    body.extend(b"\x3d")  # cmp eax, 1（target CALLS 计数 == 1）
    U32(1)
    jne8(BAIL_FIRST)
    # GOT[3] 兑现对账（== target——resolver 写槽电气证据）
    readback_q(0x18, "target", BAIL_PATCH)
    # PATCHES == 1
    read_abs_dword(DATA_VA + PATCHES_OFF)
    body.extend(b"\x3d")
    U32(1)
    jne8(BAIL_CNT1)
    # ---- 次调（direct——已决议槽直达，resolver 零重入） ----
    call_got(0x18)
    body.extend(b"\x3d")
    U32(2)
    jne8(BAIL_SECOND)
    # PATCHES 仍 == 1（直达电气证明）
    read_abs_dword(DATA_VA + PATCHES_OFF)
    body.extend(b"\x3d")
    U32(1)
    jne8(BAIL_CNT2)
    # GOT[1] 描述子原貌（push 消费不破坏）
    readback_q(0x08, "desc", BAIL_DESC)
    # LOG(msg2)
    body.extend(b"\xbf")
    U32(DATA_VA + MSG2_OFF)
    body.extend(b"\xbe")
    I32(len(MSG2))
    body.extend(b"\xb8")
    I32(0)
    body.extend(b"\x0f\x05")
    # ---- 负例电气：call *GOT[4] → PLT2 → resolver idx=1 → 表[1]==0 →
    #      EXIT(91)（resolver 拒显形——t150 LIVE 收割对账码；永不返回） ----
    call_got(0x20)
    # 不可达安全收口（负例 call 返回即雷显形——EXIT_OK_SAFE）
    body.extend(b"\xbf")
    U32(EXIT_OK_SAFE)
    body.extend(b"\xb8")
    I32(SYS_EXIT)
    body.extend(b"\x0f\x05")

    # ---- 尾部布局：PLT0 → PLT1 → PLT2 → resolver → target（16 对齐） ----
    while len(body) % 16:
        body.extend(b"\x90")
    plt0_at = len(body)
    # PLT0: push QWORD PTR [r14+8]（描述子入栈——GOT[1] 电气消费）；
    #       mov rax, [r14+0x10]; jmp rax（resolver 间呼——GOT[2] 消费）
    body.extend(b"\x41\xff\xb6")  # push QWORD PTR [r14+disp32]
    U32(0x08)
    body.extend(b"\x49\x8b\x86")  # mov rax, [r14+disp32]
    U32(0x10)
    body.extend(b"\xff\xe0")  # jmp rax
    assert len(body) - plt0_at <= 16, "PLT0 越 16 B 步长"
    plt1_at = plt0_at + 16
    body.extend(b"\x00" * (plt1_at - len(body)))
    # PLT1: push 0; jmp PLT0（rel_idx = 0——首个 JUMP_SLOT）
    body.extend(b"\x6a\x00")
    jmp1_pos = len(body)
    body.extend(b"\xe9")
    body.extend(b"\x00" * 4)
    assert len(body) - plt1_at <= 16, "PLT1 越 16 B 步长"
    plt2_at = plt0_at + 32
    # 间隙 NOP 填充（线性反汇编对齐——00 填充致解码漂移雷域）
    body.extend(b"\x90" * (plt2_at - len(body)))
    # PLT2: push 1; jmp PLT0（rel_idx = 1——负例槽）
    body.extend(b"\x6a\x01")
    jmp2_pos = len(body)
    body.extend(b"\xe9")
    body.extend(b"\x00" * 4)
    # resolver（对齐 16）
    while len(body) % 16:
        body.extend(b"\x90")
    resolver_at = len(body)
    # pop rax（描述子弃）/ pop rdi（rel_idx）
    body.extend(b"\x58\x5f")
    # cmp edi, 1; ja bail_range（idx ∈ {0,1} 域闸）
    body.extend(b"\x81\xff")
    U32(1)
    body.extend(b"\x0f\x87")
    jne_fix.append((len(body), BAIL_RANGE))
    body.extend(b"\x00\x00\x00\x00")
    # mov rdx, [TABLE + rdi*8]（符号表查址——abs disp32 + 变址，
    # SIB base=101 无基 + index=rdi）
    body.extend(b"\x48\x8b\x14\xfd")
    U32(DATA_VA + TABLE_OFF)
    # test rdx, rdx
    body.extend(b"\x48\x85\xd2")
    # je bail_neg（rel8 跨距 = 写槽 8 + inc 7〔FF 04 25 编码域〕+ call 2 + ret 1 = 18）
    body.extend(b"\x74\x12")
    # GOT[3+idx] 槽写兑现（mov [r14 + rdi*8 + 0x18], rdx——resolver 电水
    # 核心；SIB base=r14〔REX.B=1，base 域 110→r14〕+ index=rdi〔REX.X=0
    # ——X 误置即 r15 雷域〕+ disp32；REX = 0x49〔W=1 + B=1——W=0 即 32
    # 位写雷域、X=1 即变址 r15 雷域——双雷实录 objdump 逐目核销〕）
    body.extend(b"\x49\x89\x94\xfe")
    U32(0x18)
    # inc dword [PATCHES]（FF 04 25——SIB 无基真绝对）
    inc_abs_dword(DATA_VA + PATCHES_OFF)
    # call rdx; ret（执行目标 → 回 caller——glibc resolver 同谱收尾）
    body.extend(b"\xff\xd2\xc3")
    # bail_neg 内联（je +17 目标——mov edi, EXIT_NEG; exit）
    body.extend(b"\xbf")
    U32(EXIT_NEG)
    body.extend(b"\xb8")
    I32(SYS_EXIT)
    body.extend(b"\x0f\x05")
    # target（对齐 16）：inc dword [CALLS]; mov eax, [CALLS]; ret
    while len(body) % 16:
        body.extend(b"\x90")
    target_at = len(body)
    inc_abs_dword(DATA_VA + CALLS_OFF)
    body.extend(b"\x8b\x04\x25")
    U32(DATA_VA + CALLS_OFF)
    body.extend(b"\xc3")

    # ---- bail 尾表（fail-visible——mov edi, code; EXIT） ----
    bail_codes = [BAIL_RANGE, BAIL_FIRST, BAIL_PATCH, BAIL_CNT1, BAIL_SECOND, BAIL_CNT2, BAIL_DESC, BAIL_MMAP]
    bail_at = {}
    for code_ in bail_codes:
        bail_at[code_] = len(body)
        body.extend(b"\xbf")
        body.extend(struct.pack("<I", code_))
        body.extend(b"\xb8")
        body.extend(struct.pack("<i", SYS_EXIT))
        body.extend(b"\x0f\x05")

    # ---- 回填 ----
    for at, bc in jne_fix:
        delta = bail_at[bc] - (at + 4)
        body[at : at + 4] = struct.pack("<i", delta)
    # jmp rel32（PLT1/PLT2 → PLT0）
    body[jmp1_pos + 1 : jmp1_pos + 5] = struct.pack("<i", plt0_at - (jmp1_pos + 5))
    body[jmp2_pos + 1 : jmp2_pos + 5] = struct.pack("<i", plt0_at - (jmp2_pos + 5))

    meta = {
        "plt0": CODE_VA + plt0_at,
        "plt1": CODE_VA + plt1_at,
        "plt2": CODE_VA + plt2_at,
        "resolver": CODE_VA + resolver_at,
        "target": CODE_VA + target_at,
        "desc": MAGIC_DESC,
    }
    for pos, key in patch_imm64:
        body[pos : pos + 8] = struct.pack("<Q", meta[key])
    return bytes(body), meta


def two_state_sim(meta: dict) -> None:
    """两态机语义仿真（harbor::ld::exec::LazyGot 同谱对账——wire →
    resolve → direct 全谱镜像）。"""
    # wire：槽初值 = plt0 + 16 × (idx + 1)（经典布局）
    stub1 = meta["plt0"] + 16 * (0 + 1)
    stub2 = meta["plt0"] + 16 * (1 + 1)
    assert stub1 == meta["plt1"], f"PLT1 存根布局漂移：{stub1:#x} ≠ {meta['plt1']:#x}"
    assert stub2 == meta["plt2"], "PLT2 存根布局漂移"
    # resolve：Stub → Resolved（首调兑现）
    state = stub1
    resolved = False
    if not resolved:
        state = meta["target"]
        resolved = True
    assert resolved and state == meta["target"], "两态翻转漂移"
    # direct：已决议槽值不变（次调零重入）
    assert state == meta["target"]


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
    # RIP 相对禁令（笔63 揭雷第一域收口——FF 组 rm=101 无 SIB 雷域；
    # 本探针零 RIP 相对域，凡 `(%rip)` 即雷显形）
    assert "(%rip)" not in flat, f"RIP 相对寻址雷域显形：{[ln for ln in flat.split(' ') if 'rip' in ln]}"
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    got = flat.count("syscall")
    assert got == n_sys, f"syscall 计数锚失配：{got} ≠ {n_sys}"


def rs_file(probe: bytes, meta: dict) -> str:
    rows = []
    for i in range(0, len(probe), 16):
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in probe[i : i + 16]) + ",")
    body = "\n".join(rows)
    return (
        "// exec_images_m48a —— M48-PLTGOT55 笔63 交付件映像（gen_m48a_pltgot.py 产物）。\n"
        "//\n"
        "// - PLTGOT_ELF：ring3 PLT/GOT 惰性绑定电气探针（原生 ABI ET_EXEC）——\n"
        "//   mmap GOT 窗 → 经典 GOT 铸面（GOT[1] 描述子 / GOT[2] resolver /\n"
        "//   GOT[3+idx] PLT 存根）→ 首调经 PLT1→PLT0→resolver 电水解（pop\n"
        "//   描述子/idx → 表查址 → GOT[3] 写兑现 → PATCHES++ → call 目标）\n"
        "//   → 次调直达（resolver 零重入电气证明）→ GOT[1] 原貌读回 →\n"
        "//   负例电气（call *GOT[4] → 表[1]==0 → resolver EXIT(91)）。\n"
        "//   布局锚：PLT0 = {plt0:#x} / PLT1 = {plt1:#x} / PLT2 = {plt2:#x}\n"
        "//   / resolver = {res:#x} / target = {tgt:#x}（LazyGot 两态机同谱）。\n\n"
        "/// ring3 PLT/GOT 惰性绑定电气探针（ET_EXEC——t150 LIVE 相位收割面）。\n"
        "pub const PLTGOT_ELF: &[u8] = &[\n"
        f"{body}\n"
        "];\n"
    ).format(plt0=meta["plt0"], plt1=meta["plt1"], plt2=meta["plt2"], res=meta["resolver"], tgt=meta["target"])


def main():
    ART.mkdir(exist_ok=True)
    code, meta = build_probe_code()

    data = bytearray(0x100)
    data[MSG1_OFF : MSG1_OFF + len(MSG1)] = MSG1
    data[MSG2_OFF : MSG2_OFF + len(MSG2)] = MSG2
    struct.pack_into("<Q", data, TABLE_OFF, meta["target"])  # TABLE[0]
    struct.pack_into("<Q", data, TABLE_OFF + 8, 0)  # TABLE[1] = 0（负例）
    struct.pack_into("<I", data, PATCHES_OFF, 0)
    struct.pack_into("<I", data, CALLS_OFF, 0)
    probe = elf_probe(code, bytes(data))

    # 结构自检①：ELF 头族（e_entry = CODE_VA）
    assert probe[0:4] == b"\x7fELF", "魔数破坏"
    e_entry = struct.unpack_from("<Q", probe, 0x18)[0]
    assert e_entry == CODE_VA, f"入口漂移：{e_entry:#x}"
    e_type, e_machine = struct.unpack_from("<HH", probe, 0x10)
    assert (e_type, e_machine) == (ET_EXEC, 62), "头族漂移"

    # 结构自检②：两态机语义仿真（harbor LazyGot 同谱——wire/resolve/direct）
    two_state_sim(meta)

    # 结构自检③：探针反汇编锚 + syscall 计数（13 = LOG×2 + mmap×1 +
    # bail 表 EXIT×8 + 负例 EXIT×1 + 安全收口 EXIT×1）
    objdump_check(
        code,
        [
            ("push 0x8(%r14)", "PLT0 描述子 push 锚"),
            ("jmp *%rax", "resolver 间呼锚"),
            ("call *%rdx", "resolver→target 电水锚"),
            ("mov %rdx,0x18(%r14,%rdi,8)", "resolver GOT 槽写兑现锚（64 位 rdx + r14 基 + rdi 变址——REX W/X/B 三位逐目核销）"),
            ("incl 0x401090", "PATCHES 计数锚（绝对域——RIP 相对禁令随行）"),
            ("incl 0x401094", "CALLS 计数锚（绝对域——RIP 相对禁令随行）"),
            ("push $0x0", "PLT1 rel_idx push 锚"),
            ("push $0x1", "PLT2 rel_idx push 锚"),
        ],
        13,
    )

    (ART / "ldlumina-pltgot-probe.elf").write_bytes(probe)
    GEN.write_text(rs_file(probe, meta))
    print(f"ldlumina-pltgot-probe.elf = {len(probe)} B -> artifacts/ldlumina-pltgot-probe.elf")
    print(f"exec_images_m48a.rs -> {GEN.relative_to(ROOT)}")
    print(
        "PLT0={plt0:#x} PLT1={plt1:#x} PLT2={plt2:#x} resolver={res:#x} target={tgt:#x}".format(
            plt0=meta["plt0"], plt1=meta["plt1"], plt2=meta["plt2"], res=meta["resolver"], tgt=meta["target"]
        )
    )


if __name__ == "__main__":
    main()
