#!/usr/bin/env python3
"""gen_m42_elf_lane.py — M42 次笔「ring3 编译进程承接（用户态 ELF 播种 lane）」映像生成器。

产物：crates/kernel/src/exec_images_gen_m42_elf.rs（user.rs 经 include! 引入）
  - ELF_NATIVE：原生 ABI ELF64 静态映像（t105 消费——播种 lane 活体）
  - SHM_CLIENT：桌面链 wl_shm 客户端 ELF64 静态映像（t106 消费——
    ring3 编译进程承接的桌面链消费者）

【域①】ELF_NATIVE 车道（真 ELF64 容器 = ELF 头 64B + PT_LOAD ×2）：
  1. SYS_LOG 取证（LUMINA-T105-ELF ring3-native——进程内取证显形）;
  2. r12d 累加 1..=10（编译域计算面——环内算术活体）;
  3. EXIT(77)（WAITPID 收割对账码——t105 断言面）。

【域②】SHM_CLIENT 车道（桌面链 wl_shm / fd 传递客户端）：
  1. SYS_SHM(43) op0 CREATE(POOL_BYTES) → r12d = 池句柄
     （返回 (1<<32)|handle 高位装载形——错误码域无交叠）;
  2. SYS_SHM op1 MAP(handle, SHM_VA_BASE) → r14 = 池窗口虚地址
     （回显 == SHM_VA_BASE 契约）;
  3. 客户端像素面：320×200 ARGB 渐变棋盘直写池窗口
     （px = 0xFF000000 | ((lx&0x3F)<<16) | ((ly&0x3F)<<8) | 0x5A
     ——与内核 t106 期望值函数逐位对账）;
  4. SYS_UNIXSOCK(42) op2 CONNECT("wayland-comp") → r13d = 连接句柄;
  5. SYS_UNIXSOCK op8 SEND_FD(conn, pool_handle) —— **fd 附带数据
     传递面（SCM_RIGHTS 语义）**：ptr 域承载待传递句柄值;
  6. SYS_UNIXSOCK op4 SEND(conn, wire_blob) —— Wayland wire 批
     （get_registry + bind compositor/shm + create_surface +
     create_pool〔fd 占位〕+ create_buffer + attach + damage +
     commit——9 消息 200 B 单发）;
  7. SYS_UNIXSOCK op5 RECV —— 帧回调 done 事件（wl_callback.done
     12 B）阻塞等待——官方帧提交握手语义;
  8. SYS_LOG 取证（LUMINA-T106-CLIENT）→ YIELD×32（teardown 前
     窗——kmain VRAM 断言窗）→ EXIT(0)。
  bail 码：80 = CREATE / 81 = MAP / 82 = CONNECT / 83 = SEND_FD /
  84 = SEND / 85 = RECV（fail-visible——装置不静默）。

交叉锚点常量（与 kernel::shm / kernel::unixsock / kernel::waycomp /
kernel::main(t105/t106) 双向对账，漂移即红）：
  ELF_ENTRY       = 0x40_0000   （PD[2] 槽域——build_user_space_elf 放置域）
  ELF_DATA_VA     = 0x40_1000
  POOL_W×H        = 320×200     （池像素域——t106 断言窗口）
  POOL_BYTES      = 320*200*4 = 256000（CREATE 尺寸域）
  SHM_VA_BASE     = 0x7000_0000（bedrock::abi 同源——PDPT[1] 上半窗）
  PX_COLOR(lx,ly) = 0xFF000000 | ((lx&0x3F)<<16) | ((ly&0x3F)<<8) | 0x5A
  数据段布局：+0x00 套接字名 / +0x10 取证串 / +0x40 wire 批 / +0x200 回执缓冲
寄存器约定 = bedrock abi v0/v0.22：rax = 系统调用号；rdi/rsi/rdx/r10 =
参数；callee-saved（r12–r15）跨 syscall 存续（M33-P1 帧快照契约）：
r12 = 池句柄 / r13 = 连接句柄 / r14 = 池窗口虚地址 / r15 = 回执累加·让权预算。
验证：ELF 容器断言（同余式/页槽互斥/头自洽）+ objdump 反汇编锚定 +
syscall 计数锚（工作区根运行 python3 scripts/gen_m42_elf_lane.py 可复验）。
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ---- 交叉锚点常量 ----
ELF_ENTRY = 0x40_0000
ELF_DATA_VA = 0x40_1000
PAGE = 0x1000
EHDR_LEN = 64
PHDR_LEN = 56

SYS_LOG, SYS_EXIT, SYS_YIELD = 0, 1, 2
SYS_UNIXSOCK, SYS_SHM = 42, 43
USOCK_CONNECT, USOCK_SEND, USOCK_RECV, USOCK_SEND_FD = 2, 4, 5, 8
SHM_CREATE, SHM_MAP = 0, 1

SHM_VA_BASE = 0x7000_0000
POOL_W, POOL_H = 320, 200
POOL_STRIDE = POOL_W * 4
POOL_BYTES = POOL_W * POOL_H * 4
PX_BASE = 0x5A
SOCK_NAME = b"wayland-comp"
CLIENT_EVIDENCE = b"LUMINA-T106-CLIENT shm-pool fd-pass"
NATIVE_EVIDENCE = b"LUMINA-T105-ELF lane=ring3-native"

BAIL_CREATE, BAIL_MAP, BAIL_CONNECT, BAIL_SENDFD, BAIL_SEND, BAIL_RECV = 80, 81, 82, 83, 84, 85

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_gen_m42_elf.rs"


def px_color(lx: int, ly: int) -> int:
    """客户端像素函数（与 kernel t106 期望值函数逐位对账）。"""
    return 0xFF00_0000 | ((lx & 0x3F) << 16) | ((ly & 0x3F) << 8) | PX_BASE


# ---- 微型两遍汇编器（rel8/rel32 前向/后向标号裁决，越域即断言失败） ----
class Asm:
    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (pos, target, kind, insn_len)

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

    def imm32(self, v):
        self.db(struct.pack("<I", v & 0xFFFFFFFF))

    def imm64(self, v):
        self.db(struct.pack("<Q", v))

    def jmp8(self, opc, target):
        self.db(opc)
        self.fixups.append((self.here(), target, 8, 1))
        self.db(0)

    def jcc32(self, cc, target):
        self.db(0x0F, cc)
        self.fixups.append((self.here(), target, 32, 2))
        self.db(0, 0, 0, 0)

    def jmp32u(self, target):
        self.db(0xE9)
        self.fixups.append((self.here(), target, 32, 1))
        self.db(0, 0, 0, 0)

    def resolve(self):
        for pos, target, kind, ilen in self.fixups:
            rel = self.labels[target] - (pos + (4 if kind == 32 else 1))
            if kind == 8:
                assert -128 <= rel <= 127, f"rel8 越域：{target} = {rel}"
                self.buf[pos] = rel & 0xFF
            else:
                assert -(1 << 31) <= rel < (1 << 31), f"rel32 越域：{target}"
                self.buf[pos:pos + 4] = struct.pack("<i", rel)


# ---- 指令编码助手 ----
def mov_eax_i(a, v):    a.db(0xB8); a.imm32(v)            # mov eax, imm32
def mov_edi_i(a, v):    a.db(0xBF); a.imm32(v)            # mov edi, imm32
def mov_esi_i(a, v):    a.db(0xBE); a.imm32(v)            # mov esi, imm32
def mov_edx_i(a, v):    a.db(0xBA); a.imm32(v)            # mov edx, imm32
def mov_r10d_i(a, v):   a.db(0x41, 0xBA); a.imm32(v)      # mov r10d, imm32
def mov_r15d_i(a, v):   a.db(0x41, 0xBF); a.imm32(v)      # mov r15d, imm32
def syscall(a):         a.db(0x0F, 0x05)                  # syscall


# ---- wire 批编组（官方 wayland.xml 核心子集——与 prism::wayland 对账） ----
def w_u32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def w_str(s):
    raw = s + b"\0"
    pad = (-len(raw)) % 4
    return w_u32(len(raw)) + raw + b"\0" * pad


def w_msg(obj, opcode, args):
    size = 8 + len(args)
    return w_u32(obj) + w_u32((size << 16) | opcode) + args


def build_wire_blob():
    """9 消息 wire 批：registry → bind compositor/shm → surface →
    create_pool（fd 占位）→ create_buffer → attach → damage → commit。"""
    blob = b""
    blob += w_msg(1, 1, w_u32(2))                                    # get_registry → registry=2
    blob += w_msg(2, 0, w_u32(1) + w_str(b"wl_compositor") + w_u32(4) + w_u32(3))   # bind → compositor=3
    blob += w_msg(2, 0, w_u32(3) + w_str(b"wl_shm") + w_u32(1) + w_u32(4))          # bind → shm=4
    blob += w_msg(3, 0, w_u32(0x21))                                 # create_surface → surface=0x21
    blob += w_msg(4, 0, w_u32(5) + w_u32(0) + w_u32(POOL_BYTES))     # create_pool → pool=5 + fd 占位 + size
    blob += w_msg(5, 0, w_u32(6) + w_u32(0) + w_u32(POOL_W) + w_u32(POOL_H) +
                  w_u32(POOL_STRIDE) + w_u32(1))                     # create_buffer → buffer=6（XRGB8888）
    blob += w_msg(0x21, 1, w_u32(6) + w_u32(0) + w_u32(0))           # attach(buffer=6)
    blob += w_msg(0x21, 2, w_u32(0) + w_u32(0) + w_u32(POOL_W) + w_u32(POOL_H))     # damage 全 buffer
    blob += w_msg(0x21, 6, b"")                                      # commit
    return blob


# ---- 域①：ELF_NATIVE 代码段 ----
def build_native_code():
    a = Asm()
    # 1) SYS_LOG 取证
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA)     # movabs rdi, DATA_VA
    a.db(0xBE); a.imm32(len(NATIVE_EVIDENCE))  # mov esi, len
    mov_eax_i(a, SYS_LOG)
    syscall(a)
    # 2) r12d 累加 1..=10（编译域计算面）
    a.db(0x45, 0x31, 0xE4)                     # xor r12d, r12d
    a.db(0x41, 0xBD); a.imm32(1)               # mov r13d, 1
    a.label("sum")
    a.db(0x45, 0x01, 0xEC)                     # add r12d, r13d
    a.db(0x41, 0xFF, 0xC5)                     # inc r13d
    a.db(0x41, 0x83, 0xFD, 10)                 # cmp r13d, 10
    a.jmp8(0x76, "sum")                        # jbe sum
    # 3) EXIT(77)（WAITPID 收割对账码）
    mov_edi_i(a, 77)
    mov_eax_i(a, SYS_EXIT)
    syscall(a)
    a.db(0xEB, 0xFE)                           # jmp $（EXIT 失效停机）
    a.resolve()
    return bytes(a.buf)


# ---- 域②：SHM_CLIENT 代码段 ----
def build_client_code():
    a = Asm()
    WIRE = build_wire_blob()
    NAME_OFF, EVID_OFF, WIRE_OFF, RECV_OFF = 0x00, 0x10, 0x40, 0x200

    # 1) SYS_SHM CREATE(POOL_BYTES) → r12d = 池句柄
    mov_edi_i(a, SHM_CREATE)
    a.db(0xBE); a.imm32(POOL_BYTES)            # mov esi, POOL_BYTES
    mov_eax_i(a, SYS_SHM)
    syscall(a)
    a.db(0x49, 0x89, 0xC4)                     # mov r12, rax
    a.db(0x49, 0xC1, 0xEC, 32)                 # shr r12, 32
    a.db(0x41, 0x83, 0xFC, 1)                  # cmp r12d, 1
    a.jcc32(0x85, "bail_create")               # jne rel32 bail_create
    a.db(0x41, 0x89, 0xC4)                     # mov r12d, eax（低 32 = 句柄）

    # 2) SYS_SHM MAP(handle, SHM_VA_BASE) → r14 = 池窗口虚地址
    mov_edi_i(a, SHM_MAP)
    a.db(0x44, 0x89, 0xE6)                     # mov esi, r12d（GNU as 权威核验：44 89 E6）
    mov_edx_i(a, SHM_VA_BASE)
    mov_eax_i(a, SYS_SHM)
    syscall(a)
    a.db(0x49, 0x89, 0xC6)                     # mov r14, rax
    a.db(0x49, 0x81, 0xFE); a.imm32(SHM_VA_BASE)  # cmp r14, SHM_VA_BASE
    a.jcc32(0x85, "bail_map")                  # jne rel32 bail_map（回显契约）

    # 3) 客户端像素面：320×200 渐变直写池窗口（r14 基址）
    a.db(0x4C, 0x89, 0xF6)                     # mov rsi, r14（行指针）
    a.db(0x45, 0x31, 0xED)                     # xor r13d, r13d（ly）
    a.label("row")
    a.db(0x45, 0x31, 0xD2)                     # xor r10d, r10d（lx）
    a.db(0x48, 0x89, 0xF7)                     # mov rdi, rsi（像素指针）
    a.label("px")
    a.db(0x44, 0x89, 0xD0)                     # mov eax, r10d
    a.db(0x83, 0xE0, 0x3F)                     # and eax, 0x3F
    a.db(0xC1, 0xE0, 16)                       # shl eax, 16
    a.db(0x44, 0x89, 0xE9)                     # mov ecx, r13d
    a.db(0x83, 0xE1, 0x3F)                     # and ecx, 0x3F
    a.db(0xC1, 0xE1, 8)                        # shl ecx, 8
    a.db(0x09, 0xC8)                           # or eax, ecx
    a.db(0x0D); a.imm32(0xFF00_0000 | PX_BASE) # or eax, 0xFF00005A
    a.db(0x89, 0x07)                           # mov [rdi], eax
    a.db(0x48, 0x83, 0xC7, 4)                  # add rdi, 4
    a.db(0x41, 0xFF, 0xC2)                     # inc r10d
    a.db(0x41, 0x81, 0xFA); a.imm32(POOL_W)    # cmp r10d, 320
    a.jmp8(0x72, "px")                         # jb px
    a.db(0x48, 0x81, 0xC6); a.imm32(POOL_STRIDE)  # add rsi, 1280
    a.db(0x41, 0xFF, 0xC5)                     # inc r13d
    a.db(0x41, 0x81, 0xFD); a.imm32(POOL_H)    # cmp r13d, 200
    a.jmp8(0x72, "row")                        # jb row

    # 4) SYS_UNIXSOCK CONNECT("wayland-comp")
    mov_edi_i(a, USOCK_CONNECT)
    a.db(0x31, 0xF6)                           # xor esi, esi
    a.db(0xBA); a.imm32(ELF_DATA_VA + NAME_OFF)  # mov edx, name ptr
    a.db(0x41, 0xBA); a.imm32(len(SOCK_NAME))  # mov r10d, 12
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x41, 0x89, 0xC5)                     # mov r13d, eax（连接句柄）
    a.db(0x45, 0x85, 0xED)                     # test r13d, r13d
    a.jcc32(0x84, "bail_connect")              # jz rel32 bail_connect
    a.db(0x41, 0x83, 0xFD, 15)                 # cmp r13d, 15
    a.jcc32(0x87, "bail_connect")              # ja rel32 bail_connect

    # 5) SYS_UNIXSOCK SEND_FD(conn, pool_handle)——fd 附带数据传递
    mov_edi_i(a, USOCK_SEND_FD)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0x44, 0x89, 0xE2)                     # mov edx, r12d
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x85, 0xC0)                     # test rax, rax
    a.jcc32(0x85, "bail_sendfd")               # jnz rel32 bail_sendfd

    # 6) SYS_UNIXSOCK SEND(conn, wire 批)
    mov_edi_i(a, USOCK_SEND)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0xBA); a.imm32(ELF_DATA_VA + WIRE_OFF)  # mov edx, wire ptr
    a.db(0x41, 0xBA); a.imm32(len(WIRE))       # mov r10d, WIRE_LEN
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x3D); a.imm32(len(WIRE))       # cmp rax, WIRE_LEN
    a.jcc32(0x85, "bail_send")                 # jne rel32 bail_send

    # 7) 帧回调 done 等待（RECV 累计 ≥12 B——wl_callback.done 域）
    a.db(0x45, 0x31, 0xFF)                     # xor r15d, r15d（got）
    a.label("recv")
    mov_edi_i(a, USOCK_RECV)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0xBA); a.imm32(ELF_DATA_VA + RECV_OFF)  # mov edx, recv buf
    a.db(0x41, 0xBA); a.imm32(128)             # mov r10d, 128
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x85, 0xC0)                     # test rax, rax
    a.jcc32(0x84, "bail_recv")                 # jz rel32 bail_recv（0 = EOF）
    a.db(0x41, 0x01, 0xC7)                     # add r15d, eax
    a.db(0x41, 0x83, 0xFF, 12)                 # cmp r15d, 12
    a.jmp8(0x72, "recv")                       # jb recv

    # 8) SYS_LOG 取证 → SHUT（EOF 对端终结——teardown 链）→ YIELD×32 → EXIT(0)
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA + EVID_OFF)  # movabs rdi, evidence
    a.db(0xBE); a.imm32(len(CLIENT_EVIDENCE))  # mov esi, len
    mov_eax_i(a, SYS_LOG)
    syscall(a)
    mov_edi_i(a, 7)                            # USOCK_SHUT
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)                                 # EOF 对端终结（teardown 链）——错误忽略
    mov_r15d_i(a, 32)
    a.label("yld")
    mov_eax_i(a, SYS_YIELD)
    syscall(a)
    a.db(0x41, 0xFF, 0xCF)                     # dec r15d
    a.jmp8(0x75, "yld")                        # jnz yld
    a.db(0x31, 0xFF)                           # xor edi, edi
    mov_eax_i(a, SYS_EXIT)
    syscall(a)
    a.db(0xEB, 0xFE)                           # jmp $

    # bail 族（fail-visible）
    a.label("bail_create")
    mov_edi_i(a, BAIL_CREATE); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_map")
    mov_edi_i(a, BAIL_MAP); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_connect")
    mov_edi_i(a, BAIL_CONNECT); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_sendfd")
    mov_edi_i(a, BAIL_SENDFD); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_send")
    mov_edi_i(a, BAIL_SEND); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_recv")
    mov_edi_i(a, BAIL_RECV); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.resolve()
    return bytes(a.buf), WIRE


# ---- ELF64 容器编码（ET_EXEC 静态双段——bedrock::elf::parse 对账口径） ----
def elf64(entry, segs):
    """segs = [(vaddr, flags, data)]；载荷页对齐、p_offset ≡ p_vaddr (mod PAGE)。"""
    phnum = len(segs)
    layout = []
    off = PAGE  # 头区占首页（EHDR + PHDR），载荷自 0x1000 起
    for vaddr, _flags, data in segs:
        assert (off % PAGE) == (vaddr % PAGE), f"同余式破坏：off={off:#x} vaddr={vaddr:#x}"
        layout.append((off, vaddr, data))
        off = (off + len(data) + PAGE - 1) & ~(PAGE - 1)
    total = layout[-1][0] + len(layout[-1][2])
    total = (total + PAGE - 1) & ~(PAGE - 1)
    blob = bytearray(total)
    # ELF 头
    blob[0:4] = b"\x7fELF"
    blob[4] = 2   # ELFCLASS64
    blob[5] = 1   # ELFDATA2LSB
    blob[6] = 1   # EV_CURRENT
    struct.pack_into("<HHIQQQIHHHHHH", blob, 0x10,
                     2,            # e_type = ET_EXEC
                     62,           # e_machine = EM_X86_64
                     1,            # e_version
                     entry,        # e_entry
                     EHDR_LEN,     # e_phoff
                     0,            # e_shoff
                     0,            # e_flags
                     EHDR_LEN,     # e_ehsize
                     PHDR_LEN,     # e_phentsize
                     phnum,        # e_phnum
                     0, 0, 0)      # e_shentsize/e_shnum/e_shstrndx
    # 程序头
    for k, (foff, vaddr, data) in enumerate(layout):
        base = EHDR_LEN + k * PHDR_LEN
        struct.pack_into("<IIQQQQQQ", blob, base,
                         1,               # p_type = PT_LOAD
                         segs[k][1],      # p_flags
                         foff,            # p_offset
                         vaddr,           # p_vaddr
                         vaddr,           # p_paddr
                         len(data),       # p_filesz
                         len(data),       # p_memsz
                         PAGE)            # p_align
        blob[foff:foff + len(data)] = data
    # 结构自检：页槽互斥（PT_LOAD 页区间两两无交）
    for i in range(phnum):
        for j in range(i):
            a_lo = layout[i][1] // PAGE
            a_hi = (layout[i][1] + len(layout[i][2]) + PAGE - 1) // PAGE
            b_lo = layout[j][1] // PAGE
            b_hi = (layout[j][1] + len(layout[j][2]) + PAGE - 1) // PAGE
            assert a_lo >= b_hi or b_lo >= a_hi, f"页槽重叠：段{i}×段{j}"
    return bytes(blob)


def objdump_check(code, anchors, n_sys):
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
    flat = " ".join(dis.split())
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    got = flat.count("syscall")
    assert got == n_sys, f"syscall 计数锚失配：{got} ≠ {n_sys}"


def rs_hex(data, indent="    "):
    rows = []
    for i in range(0, len(data), 16):
        rows.append(indent + ", ".join(f"0x{b:02X}" for b in data[i:i + 16]) + ",")
    return "\n".join(rows)


def main():
    native_code = build_native_code()
    client_code, wire = build_client_code()

    # 数据段
    native_data = bytearray(0x40)
    native_data[0:len(NATIVE_EVIDENCE)] = NATIVE_EVIDENCE
    client_data = bytearray(0x280)
    client_data[0x00:0x00 + len(SOCK_NAME)] = SOCK_NAME
    client_data[0x10:0x10 + len(CLIENT_EVIDENCE)] = CLIENT_EVIDENCE
    client_data[0x40:0x40 + len(wire)] = wire
    assert len(wire) <= 0x1C0

    elf_native = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, native_code),            # PF_R|PF_X
        (ELF_DATA_VA, 6, bytes(native_data)),   # PF_R|PF_W
    ])
    elf_client = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, client_code),
        (ELF_DATA_VA, 6, bytes(client_data)),
    ])

    # objdump 反汇编锚定 + syscall 计数
    objdump_check(native_code, [
        ("movabs $0x401000,%rdi", "取证串指针"),
        ("syscall", "LOG 入口"),
        ("add %r13d,%r12d", "累加域"),
        ("mov $0x4d,%edi", "EXIT(77)"),
    ], n_sys=2)
    objdump_check(client_code, [
        ("mov $0x3e800,%esi", "POOL_BYTES"),
        ("mov $0x70000000,%edx", "SHM_VA_BASE"),
        ("mov $0x401000,%edx", "套接字名指针"),
        ("mov %r12d,%esi", "句柄传递"),
        ("mov %r12d,%edx", "SEND_FD 句柄域"),
        ("mov $0x401040,%edx", "wire 批指针"),
        ("mov %eax,(%rdi)", "池直写"),
    ], n_sys=16)  # 主道 10（CREATE/MAP/CONNECT/SEND_FD/SEND/RECV/LOG/SHUT/YIELD/EXIT）+ bail EXIT ×6

    # Rust 生成物
    out = f"""// 本文件由 scripts/gen_m42_elf_lane.py 生成——勿手改；重跑脚本再生成。
// M42 次笔「ring3 编译进程承接（用户态 ELF 播种 lane）+ 桌面链批次
//（wl_shm/fd 传递）」映像；真 ELF64 ET_EXEC 静态容器（ELF 头 64B +
// PT_LOAD ×2——bedrock::elf::parse 逐字段对账口径）。两映像机器码均经
// objdump 反汇编锚定自检 + syscall 计数锚。
//
//   ELF_NATIVE  syscall ×2（LOG 1 + EXIT 1）——t105 播种 lane 活体
//   SHM_CLIENT  CREATE 1 + MAP 1 + CONNECT 1 + SEND_FD 1 + SEND 1 +
//               RECV n（帧回调 done 到达即出环）+ LOG 1 + SHUT 1 +
//               YIELD 32 + EXIT 1——t106 桌面链客户端活体

/// ELF 播种 lane 映像入口虚地址（PD[2] 槽域——[`crate::user::ELF_USER_BASE`]
/// 同域；gen 脚本 ELF_ENTRY 对账）。
#[allow(dead_code)] // 文档锚点：ELF 头 e_entry 字段内嵌同值（gen 脚本对账）
pub const ELF_LANE_ENTRY: u64 = 0x40_0000;
/// ELF 播种 lane 数据段虚地址（ELF_USER_BASE + 0x1000）。
#[allow(dead_code)] // 文档锚点：PT_LOAD② vaddr 字段内嵌同值
pub const ELF_LANE_DATA_VA: u64 = 0x40_1000;
/// t105 收割对账退出码（ELF_NATIVE EXIT——WAITPID 断言面）。
#[allow(dead_code)] // 文档锚点：EXIT imm32 内嵌同值
pub const ELF_NATIVE_EXIT: i32 = 77;
/// t106 池像素域宽（gen 脚本 POOL_W 对账——客户端像素面断言窗）。
#[allow(dead_code)] // 文档锚点：create_buffer width 域内嵌同值（gen 脚本对账）
pub const CLIENT_POOL_W: u32 = {POOL_W};
/// t106 池像素域高（gen 脚本 POOL_H 对账）。
#[allow(dead_code)] // 文档锚点：create_buffer height 域内嵌同值
pub const CLIENT_POOL_H: u32 = {POOL_H};
/// t106 池字节域（CREATE 尺寸域——320×200×4）。
pub const CLIENT_POOL_BYTES: u32 = {POOL_BYTES};
/// t106 池行距（stride = W×4——create_buffer stride 域同源）。
#[allow(dead_code)] // 文档锚点：create_buffer stride 域内嵌同值
pub const CLIENT_POOL_STRIDE: u32 = {POOL_STRIDE};
/// t106 客户端像素函数低位（0xFF000000 | ((lx&0x3F)<<16) |
/// ((ly&0x3F)<<8) | PX_BASE——与 kernel t106 期望值函数逐位对账）。
pub const CLIENT_PX_BASE: u32 = {PX_BASE:#x};
/// t106 wire 批长度（9 消息 = {len(wire)} B——单发域 ≤ USOCK_BUF）。
pub const CLIENT_WIRE_LEN: usize = {len(wire)};
/// bail 退出码：SYS_SHM CREATE 失败（高位装载形未过）。
#[allow(dead_code)] // 文档锚点：bail_create EXIT imm32 内嵌同值
pub const CLIENT_BAIL_CREATE: i32 = {BAIL_CREATE};
/// bail 退出码：SYS_SHM MAP 失败（回显契约未过）。
#[allow(dead_code)] // 文档锚点：bail_map EXIT imm32 内嵌同值
pub const CLIENT_BAIL_MAP: i32 = {BAIL_MAP};
/// bail 退出码：SYS_UNIXSOCK CONNECT 失败。
#[allow(dead_code)] // 文档锚点：bail_connect EXIT imm32 内嵌同值
pub const CLIENT_BAIL_CONNECT: i32 = {BAIL_CONNECT};
/// bail 退出码：SYS_UNIXSOCK SEND_FD 失败（fd 附带数据传递域）。
#[allow(dead_code)] // 文档锚点：bail_sendfd EXIT imm32 内嵌同值
pub const CLIENT_BAIL_SENDFD: i32 = {BAIL_SENDFD};
/// bail 退出码：SYS_UNIXSOCK SEND 短写/失败。
#[allow(dead_code)] // 文档锚点：bail_send EXIT imm32 内嵌同值
pub const CLIENT_BAIL_SEND: i32 = {BAIL_SEND};
/// bail 退出码：SYS_UNIXSOCK RECV EOF（帧回调未达即对端终结）。
#[allow(dead_code)] // 文档锚点：bail_recv EXIT imm32 内嵌同值
pub const CLIENT_BAIL_RECV: i32 = {BAIL_RECV};

/// 域① 映像：ELF_NATIVE（原生 ABI ELF64 静态——真 ELF 容器，播种
/// lane `spawn_elf_seed` 消费；lin_abi = false 原生派发）。车道：LOG
/// 取证 → r12d 累加 1..=10 → EXIT({77})。t105 消费。
pub static ELF_NATIVE: [u8; {len(elf_native)}] = [
{rs_hex(elf_native)}
];

/// 域② 映像：SHM_CLIENT（桌面链 wl_shm/fd 传递客户端——真 ELF 容器，
/// 播种 lane 消费者）。车道：SYS_SHM CREATE+MAP → 池像素面渐变直写 →
/// CONNECT(wayland-comp) → SEND_FD → wire 批 9 消息（create_pool fd 占位、
/// create_buffer、attach、damage、commit）→ RECV 帧回调 done →
/// LOG → YIELD×32 → EXIT(0)。t106 消费。
pub static SHM_CLIENT: [u8; {len(elf_client)}] = [
{rs_hex(elf_client)}
];
"""
    OUT.write_text(out)
    print(f"[gen_m42_elf_lane] ELF_NATIVE={len(elf_native)}B SHM_CLIENT={len(elf_client)}B wire={len(wire)}B → {OUT}")


if __name__ == "__main__":
    main()
