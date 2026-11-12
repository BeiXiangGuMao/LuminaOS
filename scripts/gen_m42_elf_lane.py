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

# ---- 域③常量（M42-GEOM6——fbdev 驱动进程 ELF 化迁移 + resident × ELF lane）----
SYS_FB_MAP, SYS_DEV_PIO = 35, 41
SYS_IPC_SEND, SYS_IPC_RECV = 3, 4
PIO_IN16, PIO_OUT16 = 2, 3
DISPI_INDEX, DISPI_DATA = 0x1CE, 0x1CF
DISPI_ID_MIN = 0xB0C0
FB_VA_BASE = 0x4000_0000  # bedrock::abi FB_VA_BASE 同源（PDPT[1] 显示专用分支）
FB_W, FB_H = 1920, 1080
FBDEV_PAINT = 0x2B7F_1E00  # exec_images_gen_m42::FBDEV_PAINT 同源（boot 身份漆）
FB_SVC_EVIDENCE = b"LUMINA-T108-ELFSVC boot map=0 pio=ok"
FB_SVC_BAIL_MAP, FB_SVC_BAIL_PIO, FB_SVC_BAIL_DISPI = 70, 71, 72
FB_SVC_H1, FB_SVC_H2 = 1, 2  # 服务环句柄约定（spawn_elf_seed_wired 接线域同源）
FB_SVC_REQ_LEN = 32
FB_SVC_EVID_OFF, FB_SVC_REQ_OFF, FB_SVC_RESP_OFF = 0x00, 0x40, 0x60
RESIDENT_EVIDENCE = b"LUMINA-T108-RESIDENT resident-elf lane"
RESIDENT_YIELDS = 64

# ---- 域④常量（M42-INPUT7——waycomp 主体迁移前置：native 编译进程链）----
INPUT_EVIDENCE = b"LUMINA-T109-CLIENT input-chain ok"
INPUT_BAIL_CONNECT, INPUT_BAIL_SEND, INPUT_BAIL_RECV, INPUT_BAIL_BUDGET = 90, 91, 92, 93
INPUT_ACC_CAP = 512
INPUT_RECV_BUDGET = 64
INPUT_TOTAL_TARGET = 272  # 事件流累计目标（globals+caps+keymap+enter+key×2+ptr enter+button×2 = 272B——客户端存活至指针域事件到达）
# 客户端对象 id 域（wire 批内静态分配——与 prism::wayland 对账）
INPUT_REGISTRY, INPUT_SEAT, INPUT_COMP, INPUT_SURF, INPUT_PTR, INPUT_KBD = 2, 3, 4, 5, 6, 7
# wl 事件 opcode（官方 XML 声明序——与 SIG_KEYBOARD_KEY 对账）
WL_EV_KEY, WL_EV_CAPS = 3, 0

# ---- 域⑤常量（M42-WAYCOMP8——waycomp 主体 ELF 化迁移本体：常驻合成器
# 服务会话环/合流电气面 ring3 化）----
SYS_FB_SURFACE, SYS_FB_SYNC = 40, 36
USOCK_BIND, USOCK_ACCEPT_B = 1, 6
SURF_VA_BASE = 0x6000_0000  # bedrock::abi SURF_VA_BASE 同源（槽写窗基域）
WC_NAME = b"wayland-1"      # 名域正交登记（wayland-0 = t103 / wayland-comp = 内核 waycomp 双轨回归锚）
WC_SURF = 0x21              # 会话 surface id（= fb surface id——v0 跨会话复用，teardown 摘除后重登记）
WC_CB = 0x31                # 帧回调对象 id（服务端固定分配——客户端解析对账域）
WC_X, WC_Y, WC_W, WC_H = 32, 32, 320, 200  # v0 策略几何（单窗定形——cascade tiling 单窗全盒缩编面）
WC_Z = 20                   # POLICY_Z_BASE 同源（master 顶层）
WC_TINT = WC_SURF & 0xFF    # pane_pattern 色相域（fb id & 0xFF——waycomp::pane_pattern 同源）
WC_C0 = 0xFF00_0000 | (WC_TINT << 16) | 0x3030  # checker 0（r=tint / g=0x30 / b=0x30）
WC_C1 = 0xFF00_0000 | 0x30C0 | WC_TINT          # checker 1（r=tint / g=0x30 / b=0xC0）
WC_REGISTRY, WC_COMP = 2, 3  # 客户端批对象 id 域（registry=2 / compositor=3——t104 车道同源）
WC_BOOT_EVID = b"LUMINA-WAYCOMPELF-BOOT bind=wayland-1 ring3"
WC_BAIL_BIND, WC_BAIL_ACCEPT, WC_BAIL_REG = 100, 101, 104
# 数据段布局：+0x00 套接字名 / +0x10 boot 取证串 / +0x40 globals 公告批 /
# +0x100 done 事件 blob / +0x140 接收窗（r15 = 高 32 位累计游标 ‖ 低 32
# 位 done 串号——跨会话存续域，双槽寄存器打包）
WC_EVID_OFF, WC_GLOB_OFF, WC_DONE_OFF, WC_BUF_OFF = 0x10, 0x40, 0x100, 0x140
WC_BUF_CAP = 512
WC_EV_TARGET = 136  # globals 124 + done 12（客户端字节计数车道——t106 已验证模式）

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


# ---- 域③：FBDEV_SVC_ELF 代码段（M42-GEOM6 域②——常驻 fbdev 服务
# ELF 化迁移：FBDEV_SVC_LXE 车道序的真 ELF64 容器重编码——语义逐拍对
# 齐：FB_MAP → dispi 探测 64 拍重试 → 行 0 身份漆 → LOG → 服务环
# [RECV h1 → 帧解码 → PAINT_RECT 域闸 LFB 直写 / QUIT / 未知 op →
# SEND h2 回帧] → QUIT EXIT(0)。寄存器面 = LXE 同谱：r13 = 服务序号 /
# r14 = 请求帧缓冲 / r15 = 应答帧缓冲 / rbx = 收帧 tag（callee-saved
# 跨 syscall 存续契约）。数据段：+0x00 取证串 / +0x40 请求帧缓冲 /
# +0x60 应答帧缓冲。bail 码 70/71/72 fail-visible——LXE 同码域。）----
def build_wc_globals_blob():
    """globals 公告批（124 B——encode_registry_global_event 同源字节：
    registry=2 客户端域 + 四 global 声明序〔compositor v4 / seat v1 /
    shm v1 / output v2〕——waycomp::GLOBALS 与 prism 编码器逐字节对账）。"""
    blob = b""
    for name, iface, ver in [(1, b"wl_compositor", 4), (2, b"wl_seat", 1),
                             (3, b"wl_shm", 1), (4, b"wl_output", 2)]:
        blob += w_msg(WC_REGISTRY, 0, w_u32(name) + w_str(iface) + w_u32(ver))
    assert len(blob) == 124, f"globals 批长漂移：{len(blob)} ≠ 124"
    return blob


def build_wc_client_batch():
    """客户端 wire 批（96 B——内核侧 t110 经 prism 编码器同源构建）：
    get_registry → bind compositor → create_surface → damage → commit。
    定形匹配器锚域断言：A@0（get_registry 头）/ C@88（commit 头）。"""
    blob = b""
    blob += w_msg(1, 1, w_u32(WC_REGISTRY))                                     # get_registry → registry=2
    blob += w_msg(WC_REGISTRY, 0, w_u32(1) + w_str(b"wl_compositor") + w_u32(4) + w_u32(WC_COMP))  # bind → comp=3
    blob += w_msg(WC_COMP, 0, w_u32(WC_SURF))                                   # create_surface → 0x21
    blob += w_msg(WC_SURF, 2, w_u32(0) + w_u32(0) + w_u32(WC_W) + w_u32(WC_H))  # damage 全 buffer
    blob += w_msg(WC_SURF, 6, b"")                                              # commit
    assert len(blob) == 96, f"客户端批长漂移：{len(blob)} ≠ 96"
    assert blob[0:8] == w_u32(1) + w_u32((12 << 16) | 1), "A 锚域漂移（get_registry 头）"
    assert blob[88:92] == w_u32(WC_SURF) and blob[92:96] == w_u32((8 << 16) | 6), "C 锚域漂移（commit 头）"
    return blob


def build_input_wire_blob():
    """7 消息 wire 批（M42-INPUT7 输入链客户端）：registry → bind
    wl_seat/wl_compositor → surface → seat.get_pointer/get_keyboard →
    commit（首映射窗 = 焦点策略面输入——键盘 enter 前随域）。"""
    blob = b""
    blob += w_msg(1, 1, w_u32(INPUT_REGISTRY))                                          # get_registry
    blob += w_msg(INPUT_REGISTRY, 0, w_u32(2) + w_str(b"wl_seat") + w_u32(1) + w_u32(INPUT_SEAT))
    blob += w_msg(INPUT_REGISTRY, 0, w_u32(1) + w_str(b"wl_compositor") + w_u32(4) + w_u32(INPUT_COMP))
    blob += w_msg(INPUT_COMP, 0, w_u32(INPUT_SURF))                                      # create_surface
    blob += w_msg(INPUT_SEAT, 0, w_u32(INPUT_PTR))                                       # get_pointer
    blob += w_msg(INPUT_SEAT, 1, w_u32(INPUT_KBD))                                       # get_keyboard
    blob += w_msg(INPUT_SURF, 6, b"")                                                    # commit
    return blob


def build_input_client_code():
    """域④：INPUT_CLIENT 代码段（M42-INPUT7——native 编译进程链成熟
    首割：桌面链输入客户端真 wire 协议消费者）。车道：CONNECT →
    wire 批 7 消息单发 → RECV 字节计数等待（t106 车道——事件流累计
    ≥ 272B = 键盘+指针事件字节域全部到达）→ LOG 取证 →
    SHUT（EOF teardown 链）→ YIELD×16 → EXIT(0)。寄存器契约：r13d =
    连接句柄 / r14 = ACC 窗基址 / r12 = 累计字节数 / r15d = 预算
    （callee-saved 跨 syscall 存续域）。"""
    a = Asm()
    WIRE = build_input_wire_blob()
    NAME_OFF, EVID_OFF, WIRE_OFF, ACC_OFF = 0x00, 0x10, 0x40, 0x200

    # 1) SYS_UNIXSOCK CONNECT("wayland-comp") → r13d = 连接句柄
    mov_edi_i(a, USOCK_CONNECT)
    a.db(0x31, 0xF6)                           # xor esi, esi
    a.db(0xBA); a.imm32(ELF_DATA_VA + NAME_OFF)  # mov edx, name ptr
    a.db(0x41, 0xBA); a.imm32(len(SOCK_NAME))    # mov r10d, 12
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x41, 0x89, 0xC5)                     # mov r13d, eax
    a.db(0x45, 0x85, 0xED)                     # test r13d, r13d
    a.jcc32(0x84, "bail_connect")
    a.db(0x41, 0x83, 0xFD, 15)                 # cmp r13d, 15
    a.jcc32(0x87, "bail_connect")

    # 2) SYS_UNIXSOCK SEND(conn, wire 批 7 消息)
    mov_edi_i(a, USOCK_SEND)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0xBA); a.imm32(ELF_DATA_VA + WIRE_OFF)  # mov edx, wire ptr
    a.db(0x41, 0xBA); a.imm32(len(WIRE))         # mov r10d, WIRE_LEN
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x3D); a.imm32(len(WIRE))         # cmp rax, WIRE_LEN
    a.jcc32(0x85, "bail_send")

    # 3) RECV 字节计数等待（t106 车道——纯字节域）：事件流累计 ≥
    #    INPUT_TOTAL_TARGET（272B = globals 124 + caps 12 + keymap 20 +
    #    enter 20 + key ×2 48 + ptr enter 24 + button ×2 48——客户端存活
    #    至指针域事件到达，t109 键盘+指针双相位对账窗）。
    #    事件语义证明 = 服务端 stamps（WLCOMP_KEYS/INPUT_KEYS）+ 本计
    #    数对账；窗内容解析挂账（用户态读路径诊断域随批摘除）。
    mov_r15d_i(a, INPUT_RECV_BUDGET)
    a.db(0x49, 0xBE); a.imm64(ELF_DATA_VA + ACC_OFF)                  # movabs r14, ACC base
    a.db(0x45, 0x31, 0xE4)                     # xor r12d, r12d（累计 = 0）
    a.label("recv")
    mov_edi_i(a, USOCK_RECV)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0x4C, 0x89, 0xF2)                     # mov rdx, r14（固定窗基址）
    mov_r10d_i(a, INPUT_ACC_CAP)               # mov r10d, 512（窗容量）
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x85, 0xC0)                     # test rax, rax
    a.jcc32(0x84, "bail_recv")                 # 0 = EOF
    a.db(0x4C, 0x01, 0xE0)                     # add rax, r12（累计 += n）
    a.db(0x49, 0x89, 0xC4)                     # mov r12, rax
    a.db(0x49, 0x81, 0xFC); a.imm32(INPUT_TOTAL_TARGET)   # cmp r12, TARGET
    a.jcc32(0x83, "hit")                       # jae → 事件域到达
    a.db(0x41, 0xFF, 0xCF)                     # dec r15d
    a.jcc32(0x84, "bail_budget")
    a.jmp32u("recv")

    # 4) hit：LOG 取证 → SHUT（EOF teardown 链）→ YIELD×16 → EXIT(0)
    a.label("hit")
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA + EVID_OFF)  # movabs rdi, evidence
    a.db(0xBE); a.imm32(len(INPUT_EVIDENCE))    # mov esi, len
    mov_eax_i(a, SYS_LOG)
    syscall(a)
    mov_edi_i(a, 7)                            # USOCK_SHUT
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)                                 # EOF 对端终结（错误忽略）
    mov_r15d_i(a, 16)
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
    a.label("bail_connect")
    mov_edi_i(a, INPUT_BAIL_CONNECT); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_send")
    mov_edi_i(a, INPUT_BAIL_SEND); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_recv")
    mov_edi_i(a, INPUT_BAIL_RECV); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_budget")
    mov_edi_i(a, INPUT_BAIL_BUDGET); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.resolve()
    return bytes(a.buf), WIRE


def build_fbdev_svc_code():
    a = Asm()
    # 1) SYS_FB_MAP(FB_VA_BASE)——va 走 rsi（abi 契约：rsi = 用户虚地址）
    mov_esi_i(a, FB_VA_BASE)
    mov_eax_i(a, SYS_FB_MAP)
    syscall(a)
    a.db(0x48, 0x85, 0xC0)                 # test rax, rax
    a.jcc32(0x85, "bail_map")              # jne rel32 bail_map
    # 2) dispi 探测（64 拍重试窗——spawn→grant 登记窗免疫，LXE 同谱）
    a.db(0x41, 0xBC); a.imm32(64)          # mov r12d, 64
    a.label("probe")
    mov_edi_i(a, PIO_OUT16)
    mov_esi_i(a, DISPI_INDEX)
    a.db(0x31, 0xD2)                       # xor edx, edx
    mov_eax_i(a, SYS_DEV_PIO)
    syscall(a)
    a.db(0x48, 0x83, 0xF8, 1)              # cmp rax, 1（ERR_CAP）
    a.jmp8(0x74, "probe_retry")            # je probe_retry
    mov_edi_i(a, PIO_IN16)
    mov_esi_i(a, DISPI_DATA)
    mov_eax_i(a, SYS_DEV_PIO)
    syscall(a)
    a.db(0x48, 0x83, 0xF8, 1)              # cmp rax, 1
    a.jmp8(0x74, "probe_retry")            # je probe_retry
    a.db(0x3D); a.imm32(DISPI_ID_MIN)      # cmp eax, 0xB0C0
    a.jcc32(0x82, "bail_dispi")            # jb rel32 bail_dispi
    a.jmp8(0xEB, "boot_paint")             # jmp 探测过 → 身份漆
    a.label("probe_retry")
    a.db(0x49, 0xFF, 0xCC)                 # dec r12
    a.jcc32(0x84, "bail_pio")              # je rel32 bail_pio（预算耗尽）
    mov_eax_i(a, SYS_YIELD)
    syscall(a)
    a.jmp32u("probe")                      # jmp rel32 回探测（重试臂远跳）
    # 3) 行 0 身份漆 ×64 px（boot 身份域——t108 读回对账）
    a.label("boot_paint")
    mov_edi_i(a, FB_VA_BASE)
    mov_esi_i(a, FBDEV_PAINT)
    a.db(0x31, 0xC9)                       # xor ecx, ecx
    a.label("prow")
    a.db(0x89, 0x34, 0x8F)                 # mov [rdi+rcx*4], esi
    a.db(0xFF, 0xC1)                       # inc ecx
    a.db(0x83, 0xF9, 0x40)                 # cmp ecx, 64
    a.jmp8(0x72, "prow")                   # jb prow
    # 4) SYS_LOG boot 取证
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA + FB_SVC_EVID_OFF)
    mov_esi_i(a, len(FB_SVC_EVIDENCE))
    mov_eax_i(a, SYS_LOG)
    syscall(a)
    # 5) 服务环：RECV(h1) 阻塞收帧 → 帧解码 → PAINT/QUIT/未知 → SEND(h2)
    a.db(0x49, 0xBE); a.imm64(ELF_DATA_VA + FB_SVC_REQ_OFF)   # movabs r14, req
    a.db(0x49, 0xBF); a.imm64(ELF_DATA_VA + FB_SVC_RESP_OFF)  # movabs r15, resp
    a.db(0x45, 0x31, 0xED)                 # xor r13d, r13d（seq）
    a.label("recv")
    mov_edi_i(a, FB_SVC_H1)
    mov_esi_i(a, FB_SVC_REQ_LEN)
    a.db(0x4C, 0x89, 0xF2)                 # mov rdx, r14
    mov_eax_i(a, SYS_IPC_RECV)
    syscall(a)
    a.db(0x48, 0x89, 0xC3)                 # mov rbx, rax
    a.db(0x48, 0xC1, 0xEB, 32)             # shr rbx, 32（tag 域）
    a.db(0x83, 0xF8, 4)                    # cmp eax, 4（短帧重收）
    a.jmp8(0x72, "recv")                   # jb recv
    a.db(0x41, 0x8B, 0x46, 0x00)           # mov eax, [r14]（op）
    a.db(0x83, 0xF8, 1)                    # cmp eax, 1（PAINT）
    a.jmp8(0x74, "paint_arm")
    a.db(0x83, 0xF8, 2)                    # cmp eax, 2（QUIT）
    a.jmp8(0x74, "do_quit")
    a.db(0x41, 0xC7, 0x47, 0x00); a.imm32(3)  # mov dword [r15], 3（EOP）
    a.jmp8(0xEB, "reply")
    a.label("paint_arm")
    a.db(0x41, 0x8B, 0x46, 0x08)           # mov eax, [r14+8]（y）
    a.db(0x3D); a.imm32(FB_H)              # cmp eax, 1080
    a.jcc32(0x83, "status_edom")           # jae rel32 status_edom
    a.db(0x41, 0x8B, 0x46, 0x04)           # mov eax, [r14+4]（x）
    a.db(0x41, 0x03, 0x46, 0x0C)           # add eax, [r14+12]（w）
    a.db(0x3D); a.imm32(FB_W)              # cmp eax, 1920
    a.jcc32(0x87, "status_edom")           # ja rel32 status_edom
    a.db(0x41, 0x8B, 0x46, 0x08)           # mov eax, [r14+8]（y）
    a.db(0x69, 0xC0); a.imm32(FB_W)        # imul eax, eax, 1920
    a.db(0x41, 0x03, 0x46, 0x04)           # add eax, [r14+4]（x）
    a.db(0xC1, 0xE0, 2)                    # shl eax, 2
    a.db(0x05); a.imm32(FB_VA_BASE)        # add eax, FB_VA_BASE
    a.db(0x89, 0xC7)                       # mov edi, eax
    a.db(0x41, 0x8B, 0x76, 0x10)           # mov esi, [r14+16]（value）
    a.db(0x41, 0x8B, 0x4E, 0x0C)           # mov ecx, [r14+12]（w）
    a.db(0x31, 0xD2)                       # xor edx, edx
    a.label("pxw")
    a.db(0x89, 0x34, 0x97)                 # mov [rdi+rdx*4], esi
    a.db(0xFF, 0xC2)                       # inc edx
    a.db(0x39, 0xCA)                       # cmp edx, ecx
    a.jmp8(0x72, "pxw")                    # jb pxw
    a.db(0x41, 0xC7, 0x47, 0x00); a.imm32(0)  # status = 0
    a.jmp8(0xEB, "reply")
    a.label("do_quit")
    a.db(0x41, 0xC7, 0x47, 0x00); a.imm32(0)  # status = 0
    a.jmp8(0xEB, "reply")
    a.label("status_edom")
    a.db(0x41, 0xC7, 0x47, 0x00); a.imm32(2)  # status = 2（EDOM）
    a.label("reply")
    a.db(0x44, 0x89, 0xE8)                 # mov eax, r13d
    a.db(0xFF, 0xC0)                       # inc eax
    a.db(0x41, 0x89, 0x47, 0x04)           # mov [r15+4], eax（seq+1）
    mov_edi_i(a, FB_SVC_H2)
    mov_esi_i(a, 8)
    a.db(0x4C, 0x89, 0xFA)                 # mov rdx, r15
    a.db(0x41, 0x89, 0xDA)                 # mov r10d, ebx（收帧 tag）
    a.db(0x41, 0x81, 0xCA); a.imm32(0x80)  # or r10d, 0x80（应答 tag 域）
    mov_eax_i(a, SYS_IPC_SEND)
    syscall(a)
    a.db(0x41, 0xFF, 0xC5)                 # inc r13d
    a.db(0x41, 0x83, 0x7E, 0x00, 2)        # cmp dword [r14], 2（QUIT?）
    a.jmp8(0x74, "do_exit")
    a.jmp32u("recv")                       # jmp rel32 回收帧环
    a.label("do_exit")
    a.db(0x31, 0xFF)                       # xor edi, edi
    mov_eax_i(a, SYS_EXIT)
    syscall(a)
    a.db(0xEB, 0xFE)                       # jmp $（EXIT 失效停机）
    # bail 族（fail-visible——LXE 同码域 70/71/72）
    a.label("bail_map")
    mov_edi_i(a, FB_SVC_BAIL_MAP); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_pio")
    mov_edi_i(a, FB_SVC_BAIL_PIO); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_dispi")
    mov_edi_i(a, FB_SVC_BAIL_DISPI); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.resolve()
    return bytes(a.buf)


# ---- 域⑤：WAYCOMP_SVC_ELF 代码段（M42-WAYCOMP8——waycomp 主体 ELF
# 化迁移本体：常驻合成器服务会话环/合流电气面 ring3 化。车道：BIND
# ("wayland-1") → LOG boot 取证 → 真常驻环〔ACCEPT_B 阻塞收连接 → 会
# 话环：RECV 游标累计 ≥ 96B → 定形匹配器〔A@0 = get_registry →
# globals 124B 单发；C@88 = commit → SYS_FB_SURFACE op0 REGISTER（返
# 回槽写窗 VA）→ pane_pattern 320×200 直写 → SYS_FB_SYNC 损伤记账 →
# done 事件 12B（串号递增）〕→ RECV 0 = EOF → teardown〔op2 REMOVE +
# SYNC〕→ 回 ACCEPT_B——真常驻不退出形，RESIDENT_SEED v0 有界退出形
# 挂账摘牌〕。寄存器契约：r12d = 监听者 / r13d = 连接 / r14 = 接收窗
# 基址 / rbx = 会话旗标〔bit0 = globals 已发 / bit1 = commit 已处理〕
# / r15 = 高 32 位累计游标 ‖ 低 32 位 done 串号（跨会话存续——双槽寄
# 存器打包）；done blob / globals 批 / 名字 / 取证串落数据段。错误码
# 大值域（u64::MAX-1 等）→ cmp cap ja teardown fail-visible 收场回环。
# bail 100/101 fail-visible。）----
def build_wc_svc_code():
    a = Asm()
    BATCH_LEN = 96

    # 1) SYS_UNIXSOCK BIND("wayland-1") → r12d = 监听者句柄
    mov_edi_i(a, USOCK_BIND)
    a.db(0x31, 0xF6)                           # xor esi, esi
    a.db(0xBA); a.imm32(ELF_DATA_VA + 0x00)    # mov edx, name ptr
    a.db(0x41, 0xBA); a.imm32(len(WC_NAME))    # mov r10d, 9
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x41, 0x89, 0xC4)                     # mov r12d, eax
    a.db(0x45, 0x85, 0xE4)                     # test r12d, r12d
    a.jcc32(0x84, "bail_bind")                 # jz bail_bind
    a.db(0x41, 0x83, 0xFC, 15)                 # cmp r12d, 15
    a.jcc32(0x87, "bail_bind")                 # ja bail_bind

    # 2) SYS_LOG boot 取证
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA + WC_EVID_OFF)   # movabs rdi, evid
    mov_esi_i(a, len(WC_BOOT_EVID))
    mov_eax_i(a, SYS_LOG)
    syscall(a)

    # 3) 真常驻环：ACCEPT_B 阻塞收连接
    a.label("accept")
    mov_edi_i(a, USOCK_ACCEPT_B)
    a.db(0x44, 0x89, 0xE6)                     # mov esi, r12d
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x41, 0x89, 0xC5)                     # mov r13d, eax
    a.db(0x45, 0x85, 0xED)                     # test r13d, r13d
    a.jcc32(0x84, "bail_accept")               # jz bail_accept
    a.db(0x41, 0x83, 0xFD, 15)                 # cmp r13d, 15
    a.jcc32(0x87, "bail_accept")               # ja bail_accept
    a.db(0xBB); a.imm32(0)                     # mov ebx, 0（会话旗标清零）
    a.db(0x49, 0x81, 0xE7); a.imm32(0xFFFF_FFFF)  # and r15, 0xFFFFFFFF（游标清零——串号存续）

    # 4) 会话环：RECV 游标累计 ≥ 96B → 定形匹配器
    a.db(0x49, 0xBE); a.imm64(ELF_DATA_VA + WC_BUF_OFF)    # movabs r14, buf
    a.label("recv")
    mov_edi_i(a, USOCK_RECV)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0x4D, 0x89, 0xFB)                     # mov r11, r15
    a.db(0x49, 0xC1, 0xEB, 32)                 # shr r11, 32（累计游标）
    a.db(0x4C, 0x89, 0xF2)                     # mov rdx, r14
    a.db(0x4C, 0x01, 0xDA)                     # add rdx, r11（游标域接收）
    a.db(0x41, 0xBA); a.imm32(WC_BUF_CAP)      # mov r10d, 512
    a.db(0x45, 0x29, 0xDA)                     # sub r10d, r11d（余量域）
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x48, 0x85, 0xC0)                     # test rax, rax
    a.jcc32(0x84, "teardown")                  # jz teardown（EOF——会话收场回环）
    a.db(0x48, 0x81, 0xF8); a.imm32(WC_BUF_CAP)   # cmp rax, 512（错误码大值域闸）
    a.jcc32(0x87, "teardown")                  # ja teardown（fail-visible 收场回环）
    a.db(0x48, 0xC1, 0xE0, 32)                 # shl rax, 32
    a.db(0x49, 0x01, 0xC7)                     # add r15, rax（累计游标 += n）
    a.db(0x4D, 0x89, 0xFB)                     # mov r11, r15
    a.db(0x49, 0xC1, 0xEB, 32)                 # shr r11, 32
    a.db(0x41, 0x81, 0xFB); a.imm32(BATCH_LEN) # cmp r11d, 96
    a.jcc32(0x82, "recv")                      # jb recv（未满续收）

    # 5) 定形匹配器 A@0（get_registry 头 → globals 124B 单发）
    a.db(0xF7, 0xC3, 0x01, 0x00, 0x00, 0x00)   # test rbx, 1
    a.jcc32(0x85, "match_c")                   # jnz match_c
    a.db(0x41, 0x83, 0x3E, 0x01)               # cmp dword [r14], 1
    a.jcc32(0x85, "match_c")                   # jne match_c
    a.db(0x41, 0x81, 0x7E, 0x04); a.imm32(0x000C_0001)  # cmp dword [r14+4], 0x000C0001
    a.jcc32(0x85, "match_c")                   # jne match_c
    mov_edi_i(a, USOCK_SEND)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    mov_edx_i(a, ELF_DATA_VA + WC_GLOB_OFF)    # mov edx, globals 批指针
    a.db(0x41, 0xBA); a.imm32(124)             # mov r10d, 124
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x83, 0xCB, 0x01)                     # or rbx, 1（globals 已发）

    # 6) 定形匹配器 C@88（commit 头 → REGISTER + 漆面 + SYNC + done）
    a.label("match_c")
    a.db(0xF7, 0xC3, 0x02, 0x00, 0x00, 0x00)   # test rbx, 2
    a.jcc32(0x85, "after_scan")                # jnz after_scan
    a.db(0x41, 0x83, 0x7E, 0x58, 0x21)         # cmp dword [r14+88], 0x21
    a.jcc32(0x85, "after_scan")                # jne after_scan
    a.db(0x41, 0x81, 0x7E, 0x5C); a.imm32((8 << 16) | 6)  # cmp dword [r14+92], 0x00080006
    a.jcc32(0x85, "after_scan")                # jne after_scan
    # REGISTER：op0 → 槽写窗 VA（域闸 0x60000000）
    a.db(0x31, 0xFF)                           # xor edi, edi
    mov_esi_i(a, WC_SURF)
    a.db(0x48, 0xBA); a.imm64((WC_Y << 32) | WC_X)        # movabs rdx, xy
    a.db(0x49, 0xBA); a.imm64((WC_H << 32) | WC_W)        # movabs r10, wh
    a.db(0x41, 0xB8); a.imm32(WC_Z)            # mov r8d, 20
    mov_eax_i(a, SYS_FB_SURFACE)
    syscall(a)
    a.db(0x48, 0x3D); a.imm32(SURF_VA_BASE)    # cmp rax, 0x60000000
    a.jcc32(0x82, "send_done")                 # jb send_done（VA 域外 fail-visible——漆面跳过，done 照发）
    # 漆面：pane_pattern 320×200 直写（rbp = ly / rsi = rowpar / r10d = lx）
    a.db(0x48, 0x89, 0xC7)                     # mov rdi, rax（写窗游标）
    a.db(0x31, 0xED)                           # xor ebp, ebp（ly）
    a.label("row")
    a.db(0x89, 0xEE)                           # mov esi, ebp
    a.db(0xC1, 0xEE, 3)                        # shr esi, 3
    a.db(0x83, 0xE6, 1)                        # and esi, 1（rowpar）
    a.db(0x45, 0x31, 0xD2)                     # xor r10d, r10d（lx）
    a.label("px")
    a.db(0x44, 0x89, 0xD0)                     # mov eax, r10d
    a.db(0xC1, 0xE8, 3)                        # shr eax, 3
    a.db(0x83, 0xE0, 1)                        # and eax, 1
    a.db(0x31, 0xF0)                           # xor eax, esi（parity = (lx>>3)+(ly>>3) 低位 XOR）
    mov_edx_i(a, WC_C1)
    a.db(0x85, 0xC0)                           # test eax, eax
    mov_eax_i(a, WC_C0)
    a.db(0x0F, 0x44, 0xD0)                     # cmove edx, eax（Intel cmovz edx,eax——parity=0 → C0）
    a.db(0x89, 0x17)                           # mov [rdi], edx
    a.db(0x48, 0x83, 0xC7, 4)                  # add rdi, 4
    a.db(0x41, 0xFF, 0xC2)                     # inc r10d
    a.db(0x41, 0x81, 0xFA); a.imm32(WC_W)      # cmp r10d, 320
    a.jmp8(0x72, "px")                         # jb px
    a.db(0xFF, 0xC5)                           # inc ebp
    a.db(0x81, 0xFD); a.imm32(WC_H)            # cmp ebp, 200
    a.jmp8(0x72, "row")                        # jb row
    # SYNC 损伤记账（唯一入口——ADR-0004 双轨语义同源）
    mov_edi_i(a, WC_X)
    mov_esi_i(a, WC_Y)
    mov_edx_i(a, WC_W)
    a.db(0x41, 0xBA); a.imm32(WC_H)            # mov r10d, 200
    mov_eax_i(a, SYS_FB_SYNC)
    syscall(a)
    # done 事件 12B（串号递增——跨会话存续域）
    a.label("send_done")
    a.db(0x41, 0xFF, 0xC7)                     # inc r15d（串号低 32 位）
    a.db(0x49, 0xBB); a.imm64(ELF_DATA_VA + WC_DONE_OFF)  # movabs r11, done blob
    a.db(0x45, 0x89, 0x7B, 0x08)               # mov [r11+8], r15d（串号域改写）
    mov_edi_i(a, USOCK_SEND)
    a.db(0x44, 0x89, 0xEE)                     # mov esi, r13d
    a.db(0x48, 0xBA); a.imm64(ELF_DATA_VA + WC_DONE_OFF)  # movabs rdx, done blob
    a.db(0x41, 0xBA); a.imm32(12)              # mov r10d, 12
    mov_eax_i(a, SYS_UNIXSOCK)
    syscall(a)
    a.db(0x83, 0xCB, 0x02)                     # or rbx, 2（commit 已处理）
    a.label("after_scan")
    a.db(0x49, 0x81, 0xE7); a.imm32(0xFFFF_FFFF)  # and r15, 0xFFFFFFFF（游标清零——串号存续）
    a.jmp32u("recv")

    # 7) teardown：REMOVE + SYNC → 回 ACCEPT_B（真常驻回环）
    a.label("teardown")
    mov_edi_i(a, 2)                            # op2 REMOVE
    mov_esi_i(a, WC_SURF)
    a.db(0x48, 0xBA); a.imm64((WC_Y << 32) | WC_X)
    a.db(0x49, 0xBA); a.imm64((WC_H << 32) | WC_W)
    a.db(0x45, 0x31, 0xC0)                     # xor r8d, r8d
    mov_eax_i(a, SYS_FB_SURFACE)
    syscall(a)
    mov_edi_i(a, WC_X)
    mov_esi_i(a, WC_Y)
    mov_edx_i(a, WC_W)
    a.db(0x41, 0xBA); a.imm32(WC_H)
    mov_eax_i(a, SYS_FB_SYNC)
    syscall(a)
    a.jmp32u("accept")

    # bail 族（fail-visible）
    a.label("bail_bind")
    mov_edi_i(a, WC_BAIL_BIND); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.label("bail_accept")
    mov_edi_i(a, WC_BAIL_ACCEPT); mov_eax_i(a, SYS_EXIT); syscall(a); a.db(0xEB, 0xFE)
    a.resolve()
    return bytes(a.buf)


def build_resident_code():
    a = Asm()
    a.db(0x48, 0xBF); a.imm64(ELF_DATA_VA)    # movabs rdi, DATA_VA
    mov_esi_i(a, len(RESIDENT_EVIDENCE))
    mov_eax_i(a, SYS_LOG)
    syscall(a)
    mov_r15d_i(a, RESIDENT_YIELDS)
    a.label("yld")
    mov_eax_i(a, SYS_YIELD)
    syscall(a)
    a.db(0x41, 0xFF, 0xCF)                 # dec r15d
    a.jmp8(0x75, "yld")                    # jnz yld
    a.db(0x31, 0xFF)                       # xor edi, edi
    mov_eax_i(a, SYS_EXIT)
    syscall(a)
    a.db(0xEB, 0xFE)                       # jmp $（EXIT 失效停机）
    a.resolve()
    return bytes(a.buf)


def main():
    native_code = build_native_code()
    client_code, wire = build_client_code()
    fbsvc_code = build_fbdev_svc_code()
    resident_code = build_resident_code()
    input_code, input_wire = build_input_client_code()
    wc_code = build_wc_svc_code()
    wc_globals = build_wc_globals_blob()
    wc_batch = build_wc_client_batch()

    # 数据段
    native_data = bytearray(0x40)
    native_data[0:len(NATIVE_EVIDENCE)] = NATIVE_EVIDENCE
    client_data = bytearray(0x280)
    client_data[0x00:0x00 + len(SOCK_NAME)] = SOCK_NAME
    client_data[0x10:0x10 + len(CLIENT_EVIDENCE)] = CLIENT_EVIDENCE
    client_data[0x40:0x40 + len(wire)] = wire
    assert len(wire) <= 0x1C0
    fbsvc_data = bytearray(0x80)
    fbsvc_data[FB_SVC_EVID_OFF:FB_SVC_EVID_OFF + len(FB_SVC_EVIDENCE)] = FB_SVC_EVIDENCE
    resident_data = bytearray(0x40)
    resident_data[0:len(RESIDENT_EVIDENCE)] = RESIDENT_EVIDENCE
    input_data = bytearray(0x400)
    input_data[0x00:0x00 + len(SOCK_NAME)] = SOCK_NAME
    input_data[0x10:0x10 + len(INPUT_EVIDENCE)] = INPUT_EVIDENCE
    input_data[0x40:0x40 + len(input_wire)] = input_wire
    input_data[0x380:0x382] = b"CL"
    assert len(input_wire) <= 0x1C0
    wc_data = bytearray(0x340)
    wc_data[0x00:0x00 + len(WC_NAME)] = WC_NAME
    wc_data[WC_EVID_OFF:WC_EVID_OFF + len(WC_BOOT_EVID)] = WC_BOOT_EVID
    wc_data[WC_GLOB_OFF:WC_GLOB_OFF + len(wc_globals)] = wc_globals
    # done 事件 blob：obj = WC_CB / header = (12<<16)|0 / serial = 0（运行期改写）
    struct.pack_into("<III", wc_data, WC_DONE_OFF, WC_CB, (12 << 16) | 0, 0)

    elf_native = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, native_code),            # PF_R|PF_X
        (ELF_DATA_VA, 6, bytes(native_data)),   # PF_R|PF_W
    ])
    elf_client = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, client_code),
        (ELF_DATA_VA, 6, bytes(client_data)),
    ])
    elf_fbsvc = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, fbsvc_code),
        (ELF_DATA_VA, 6, bytes(fbsvc_data)),
    ])
    elf_resident = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, resident_code),
        (ELF_DATA_VA, 6, bytes(resident_data)),
    ])
    elf_input = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, input_code),
        (ELF_DATA_VA, 6, bytes(input_data)),
    ])
    elf_wc = elf64(ELF_ENTRY, [
        (ELF_ENTRY, 5, wc_code),
        (ELF_DATA_VA, 6, bytes(wc_data)),
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
    objdump_check(fbsvc_code, [
        ("mov $0x40000000,%esi", "FB_VA_BASE（abi 契约 rsi = 用户虚地址）"),
        ("mov $0x23,%eax", "SYS_FB_MAP"),
        ("mov $0x1ce,%esi", "dispi 索引口"),
        ("mov $0x1cf,%esi", "dispi 数据口"),
        ("cmp $0xb0c0,%eax", "dispi 版本域闸"),
        ("movabs $0x401040,%r14", "请求帧缓冲"),
        ("movabs $0x401060,%r15", "应答帧缓冲"),
        ("or $0x80,%r10d", "应答 tag 域"),
        ("imul $0x780,%eax,%eax", "行寻址（先像素偏移后 ×4）"),
        ("mov %esi,(%rdi,%rcx,4)", "LFB 身份漆"),
        ("mov %esi,(%rdi,%rdx,4)", "PAINT_RECT 行写"),
    ], n_sys=11)  # FB_MAP 1 + probe 2（OUT16/IN16）+ 重试 YIELD 1 + LOG 1 + RECV 1 + SEND 1 + EXIT 1 + bail EXIT ×3
    objdump_check(resident_code, [
        ("movabs $0x401000,%rdi", "取证串指针"),
    ], n_sys=3)  # LOG 1 + YIELD 1 + EXIT 1
    objdump_check(input_code, [
        ("mov $0x401000,%edx", "套接字名指针"),
        ("mov $0x401040,%edx", "wire 批指针"),
        ("movabs $0x401200,%r14", "ACC 固定窗基址"),
        ("movabs $0x401010,%rdi", "取证串指针"),
    ], n_sys=11)  # 主道 7（CONNECT/SEND/RECV/LOG/SHUT/YIELD/EXIT）+ bail EXIT ×4
    objdump_check(wc_code, [
        ("mov $0x401000,%edx", "套接字名指针"),
        ("movabs $0x401010,%rdi", "boot 取证串指针"),
        ("mov $0x401040,%edx", "globals 批指针"),
        ("movabs $0x401100,%r11", "done blob 指针"),
        ("movabs $0x401140,%r14", "接收窗基址"),
        ("cmp $0x60000000,%rax", "槽写窗 VA 域闸"),
        ("mov $0x21,%esi", "surface id 域"),
        ("movabs $0x2000000020,%rdx", "xy 打包域"),
        ("movabs $0xc800000140,%r10", "wh 打包域"),
        ("mov $0x28,%eax", "SYS_FB_SURFACE"),
        ("mov $0x24,%eax", "SYS_FB_SYNC"),
    ], n_sys=12)  # BIND 1 + LOG 1 + ACCEPT 1 + RECV 1 + SEND(globals) 1 + REGISTER 1 + SYNC 1 + SEND(done) 1 + REMOVE 1 + SYNC(td) 1 + bail EXIT ×2

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

/// 域③ bail 退出码：SYS_FB_MAP 失败（fbsvc-elf——ELF 化服务）。
#[allow(dead_code)] // 文档锚点：bail_map EXIT imm32 内嵌同值
pub const FB_SVC_ELF_BAIL_MAP: i32 = {FB_SVC_BAIL_MAP};
/// 域③ bail 退出码：dispi 探测重试预算耗尽（PIO ERR_CAP 持续）。
#[allow(dead_code)] // 文档锚点：bail_pio EXIT imm32 内嵌同值
pub const FB_SVC_ELF_BAIL_PIO: i32 = {FB_SVC_BAIL_PIO};
/// 域③ bail 退出码：dispi 版本域闸未过（< 0xB0C0）。
#[allow(dead_code)] // 文档锚点：bail_dispi EXIT imm32 内嵌同值
pub const FB_SVC_ELF_BAIL_DISPI: i32 = {FB_SVC_BAIL_DISPI};
/// 域③ 服务环句柄约定（spawn_elf_seed_wired 接线域同源——子 h1/h2）。
#[allow(dead_code)] // 文档锚点：RECV/SEND edi imm32 内嵌同值
pub const FB_SVC_ELF_H1: usize = {FB_SVC_H1};
#[allow(dead_code)]
pub const FB_SVC_ELF_H2: usize = {FB_SVC_H2};
/// 域③ 常驻种子让权拍数（RESIDENT_SEED YIELD × N——t108 有界活体窗）。
#[allow(dead_code)] // 文档锚点：mov r15d, imm32 内嵌同值
pub const RESIDENT_SEED_YIELDS: u32 = {RESIDENT_YIELDS};

/// 域④ wire 批长度（M42-INPUT7——INPUT_CLIENT 7 消息 =
/// {len(input_wire)} B，单发域 ≤ USOCK_BUF）。
#[allow(dead_code)] // 文档锚点：SEND r10d imm32 内嵌同值（gen 脚本对账）
pub const INPUT_CLIENT_WIRE_LEN: usize = {len(input_wire)};
/// 域④ bail 退出码：CONNECT 失败（input-client——输入链客户端）。
#[allow(dead_code)] // 文档锚点：bail_connect EXIT imm32 内嵌同值
pub const INPUT_CLIENT_BAIL_CONNECT: i32 = {INPUT_BAIL_CONNECT};
/// 域④ bail 退出码：SEND 短写/失败。
#[allow(dead_code)] // 文档锚点：bail_send EXIT imm32 内嵌同值
pub const INPUT_CLIENT_BAIL_SEND: i32 = {INPUT_BAIL_SEND};
/// 域④ bail 退出码：RECV EOF（key 事件未达即对端终结）。
#[allow(dead_code)] // 文档锚点：bail_recv EXIT imm32 内嵌同值
pub const INPUT_CLIENT_BAIL_RECV: i32 = {INPUT_BAIL_RECV};
/// 域④ bail 退出码：预算耗尽（key 事件未达）。
#[allow(dead_code)] // 文档锚点：bail_budget EXIT imm32 内嵌同值
pub const INPUT_CLIENT_BAIL_BUDGET: i32 = {INPUT_BAIL_BUDGET};
/// 域④ 客户端 wl_keyboard 对象 id（wire 批内静态分配——扫描器对账
/// 域；与 kernel 侧 t109 断言同源）。
#[allow(dead_code)] // 文档锚点：扫描器 cmp edi imm8 内嵌同值
pub const INPUT_CLIENT_KBD_OBJ: u32 = {INPUT_KBD};

/// 域⑤ 客户端 wire 批长（M42-WAYCOMP8——t110 内核侧客户端经 prism
/// 编码器同源构建，96 B 单发域）。
pub const WC_SVC_WIRE_LEN: usize = {len(wc_batch)};
/// 域⑤ 合成器套接字名（内核侧 t110 客户端 connect 域——映像数据段
/// 内嵌同值）。
pub const WC_SVC_SOCK_NAME: &[u8] = b"wayland-1";
/// 域⑤ 客户端 registry 对象 id（批内静态分配——gen 批对账）。
pub const WC_SVC_REGISTRY_ID: u32 = {WC_REGISTRY};
/// 域⑤ 客户端 compositor 对象 id（批内静态分配）。
pub const WC_SVC_COMP_ID: u32 = {WC_COMP};
/// 域⑤ 客户端字节计数目标（globals 124 + done 12 = {WC_EV_TARGET} B
/// ——t106 字节计数车道同源）。
pub const WC_SVC_EV_TARGET: usize = {WC_EV_TARGET};
/// 域⑤ 会话 surface id（= fb surface id——v0 跨会话复用）。
#[allow(dead_code)] // 文档锚点：REGISTER esi imm32 内嵌同值
pub const WC_SVC_SURF: u32 = {WC_SURF};
/// 域⑤ 帧回调对象 id（服务端固定分配——客户端解析对账域）。
#[allow(dead_code)] // 文档锚点：done blob obj 字段内嵌同值
pub const WC_SVC_CB: u32 = {WC_CB};
/// 域⑤ v0 策略几何（单窗定形——REGISTER xy/wh 打包域对账）。
pub const WC_SVC_X: u32 = {WC_X};
pub const WC_SVC_Y: u32 = {WC_Y};
pub const WC_SVC_W: u32 = {WC_W};
pub const WC_SVC_H: u32 = {WC_H};
/// 域⑤ z 序（POLICY_Z_BASE 同源——master 顶层）。
pub const WC_SVC_Z: i32 = {WC_Z};
/// 域⑤ pane_pattern 双色（fb id 色相域 0x{WC_TINT:X}——waycomp::
/// pane_pattern 同源逐位对账；t110 断言面走 waycomp::pane_pattern
/// 同源函数，本常量为文档锚点）。
#[allow(dead_code)] // 文档锚点：漆面 mov edx/eax imm32 内嵌同值
pub const WC_SVC_C0: u32 = {WC_C0:#x};
#[allow(dead_code)] // 文档锚点：cmove edx 备选色 imm32 内嵌同值
pub const WC_SVC_C1: u32 = {WC_C1:#x};
/// 域⑤ bail 退出码：BIND 失败（waycomp-svc-elf——主体迁移服务）。
#[allow(dead_code)] // 文档锚点：bail_bind EXIT imm32 内嵌同值
pub const WC_SVC_BAIL_BIND: i32 = {WC_BAIL_BIND};
/// 域⑤ bail 退出码：ACCEPT_B 失败。
#[allow(dead_code)] // 文档锚点：bail_accept EXIT imm32 内嵌同值
pub const WC_SVC_BAIL_ACCEPT: i32 = {WC_BAIL_ACCEPT};

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

/// 域③ 映像：FBDEV_SVC_ELF（M42-GEOM6 域②——**常驻 fbdev 服务 ELF
/// 化迁移**：FBDEV_SVC_LXE 车道序的真 ELF64 容器重编码，播种 lane
/// `spawn_elf_seed_wired` 消费——h1/h2 服务环接线域预装）。车道：
/// SYS_FB_MAP(FB_VA_BASE) → dispi 探测（OUT16 0x1CE←0 + IN16 0x1CF
/// 读版本 ≥ 0xB0C0，ERR_CAP 64 拍 YIELD 重试窗——spawn→grant 登记
/// 窗免疫）→ LFB 行 0 ×64 px 直写 boot 身份漆 → SYS_LOG 取证 → 服务
/// 环：SYS_IPC_RECV(h1) 阻塞收帧 → 帧解码 [op][x][y][w][value]——
/// op 1 = PAINT_RECT（域闸 y<1080 ∧ x+w≤1920，越域 status=2 拒不写）
/// LFB 直写 / op 2 = QUIT / 未知 op = status 3 → SYS_IPC_SEND(h2) 回
/// 帧 [status][seq]（tag|0x80）→ QUIT 即 EXIT(0)。寄存器面 = LXE 同
/// 谱：r13 = 服务序号 / r14 = 请求帧缓冲 / r15 = 应答帧缓冲 / rbx =
/// 收帧 tag。t108 消费（LXE 双轨 t102 回归锚保持——迁移对账面）。
pub static FBDEV_SVC_ELF: [u8; {len(elf_fbsvc)}] = [
{rs_hex(elf_fbsvc)}
];

/// 域③ 映像：RESIDENT_SEED（resident × ELF lane 结构活体——
/// `spawn_elf_seed_resident` 消费：常驻旗标 × 真 ELF64 原生 ABI 复
/// 合显形）。车道：SYS_LOG 取证 → YIELD×{RESIDENT_YIELDS} →
/// EXIT(0)。v0 结构活体为有界退出形（常驻旗标语义 = 批跑收敛谓词
/// 豁免域旗标面断言；真常驻不退出形服务随 waycomp 主体迁移批次挂
/// 账）。t108 消费。
pub static RESIDENT_SEED: [u8; {len(elf_resident)}] = [
{rs_hex(elf_resident)}
];

/// 域④ 映像：INPUT_CLIENT（M42-INPUT7——**waycomp 主体迁移前置：
/// native 编译进程链成熟首割**，桌面链输入客户端真 wire 协议消费
/// 者，播种 lane `spawn_elf_seed` 消费）。车道：SYS_UNIXSOCK
/// CONNECT(wayland-comp) → wire 批 7 消息单发（get_registry → bind
/// wl_seat/wl_compositor → create_surface → seat.get_pointer/
/// get_keyboard → commit——首映射窗 = 焦点策略面输入）→ RECV 固定
/// 窗加逐消息游标扫描（客户端 wire 解析器——键盘 key 事件检测域
/// obj == wl_keyboard(0x{INPUT_KBD:X}) 且 opcode == EV_KEY(3)）→
/// LOG 取证 → SHUT（EOF teardown 链）→ YIELD×16 → EXIT(0)。t109
/// 消费（编译进程链四形齐备：协议形/shm 形/服务环形/常驻形）。
pub static INPUT_CLIENT: [u8; {len(elf_input)}] = [
{rs_hex(elf_input)}
];

/// 域⑤ 映像：WAYCOMP_SVC_ELF（M42-WAYCOMP8——**waycomp 主体 ELF 化
/// 迁移本体：常驻合成器服务会话环/合流电气面 ring3 化**，真常驻不退
/// 出形服务，播种 lane `spawn_elf_seed_resident` 消费）。车道：
/// SYS_UNIXSOCK BIND("wayland-1")〔名域正交——wayland-0 = t103 /
/// wayland-comp = 内核 waycomp 双轨回归锚〕→ SYS_LOG boot 取证 → 真
/// 常驻环：ACCEPT_B 阻塞收连接 → 会话环〔RECV 游标累计 ≥ 96B → 定
/// 形匹配器：A@0 = get_registry 头 → globals 124B 公告单发〔
/// encode_registry_global_event 同源字节——registry=2 + 四 global
/// 声明序〕；C@88 = commit 头 → SYS_FB_SURFACE op0 REGISTER（v0 策
/// 略几何 32,32,320,200 z=20——返回槽写窗 VA）→ pane_pattern 320×200
/// 直写〔双色 0x{WC_C0:X}/0x{WC_C1:X}——fb id 色相 0x{WC_TINT:X}〕→
/// SYS_FB_SYNC 损伤记账 → wl_callback.done 12B（串号递增——跨会话
/// 存续）〕→ RECV 0 = EOF → teardown〔op2 REMOVE + SYNC〕→ 回
/// ACCEPT_B。错误码大值域 → teardown 收场回环（fail-visible）。bail
/// 100/101。t110 消费（RESIDENT_SEED v0 有界退出形挂账摘牌——真常驻
/// 不退出形在环；窗内容解析域挂账随 ring3 车道重验批次）。
pub static WAYCOMP_SVC_ELF: [u8; {len(elf_wc)}] = [
{rs_hex(elf_wc)}
];
"""
    OUT.write_text(out)
    print(
        f"[gen_m42_elf_lane] ELF_NATIVE={len(elf_native)}B SHM_CLIENT={len(elf_client)}B "
        f"FBDEV_SVC_ELF={len(elf_fbsvc)}B RESIDENT_SEED={len(elf_resident)}B "
        f"INPUT_CLIENT={len(elf_input)}B WAYCOMP_SVC_ELF={len(elf_wc)}B "
        f"wire={len(wire)}B input_wire={len(input_wire)}B wc_batch={len(wc_batch)}B "
        f"wc_globals={len(wc_globals)}B → {OUT}"
    )


if __name__ == "__main__":
    main()
