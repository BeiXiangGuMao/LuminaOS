#!/usr/bin/env python3
"""gen_m42_fbdev_image.py — M42 用户态 fb 驱动进程映像生成器（阶段一笔① + 笔②）。

产物：crates/kernel/src/exec_images_gen_m42.rs（user.rs 经 include! 引入）
  - FBDEV_LXE：一次性移交链映像（笔① M42-FBDEV1，t101 消费）
  - FBDEV_SVC_LXE：常驻 fbdev 服务映像（笔② M42-FBSVC2，t102 消费）

【笔①】一次性映像车道：
  1. SYS_FB_MAP(0x40000000) —— LFB 映射移交（SURFACE_OWNER 单面 CAS 首认领者）;
  2. SYS_DEV_PIO dispi 探测 —— OUT16 0x1CE←0（索引=ID 寄存器）+
     IN16 0x1CF 读版本（≥0xB0C0）——端口访问面活体（ERR_CAP 重试
     64 拍窗口：spawn→grant 登记窗免疫，t100 先例同款）；
  3. 直写成像 —— LFB 行 0 x=0..63 共 64 px 写 FBDEV_PAINT 常量；
  4. SYS_LOG 取证（LUMINA-T101-FBDEV 行）→ EXIT(0)。

【笔②】常驻服务映像车道（驱动进程常驻面——服务环/IPC 通道 + 常驻
fbdev 服务化）：
  1. SYS_FB_MAP —— LFB 映射移交（同笔①；t101 fbdev 退出已由
     Surface 生命周期释放面归还单面——笔② 揭雷修复前置）；
  2. SYS_DEV_PIO dispi 探测（同笔① 64 拍重试窗）；
  3. boot 成像 —— LFB 行 0 x=0..63 = FBDEV_PAINT（身份锚——t102
     内核侧 VRAM 读回对账「boot 漆存续」面）；
  4. SYS_LOG boot 取证（LUMINA-T102-FBSVC boot 行）→ 进服务环：
     SYS_IPC_RECV(h1=FB 请求通道) 阻塞收帧 → 帧解码
     [op][x][y][w][value] —— op 1 = PAINT_RECT（域闸 y<1080 ∧
     x+w≤1920，越域 status=2 拒不写——fail-visible）→ LFB 直写；
     op 2 = QUIT；未知 op = status 3 → SYS_IPC_SEND(h2=FB 应答通道)
     回帧 [status][seq]（tag = 请求 tag|0x80）→ QUIT 即 EXIT(0)。
     服务序号 seq 由 r13 累计（callee-saved 跨 syscall 存续）。
  bail 码：70 = FB_MAP 失败；71 = PIO 裁量预算耗尽；72 = dispi 版本
  下限未过。全数 fail-visible（装置不静默）。

交叉锚点常量（与 kernel::user / kernel::dev / kernel::main(t102) 双向
对账，漂移即红）：
  FBDEV_ENTRY     = 0x1_8000_0000   （PDPT[6] 全新分支段区——FRESH_BASE）
  FBDEV_DATA_VA   = 0x1_8000_1000   （数据段——PROG_DATA_VA 同域）
  FBDEV_PAINT     = 0x2B7F_1E00     （笔① 直写成像常量 / 笔② boot 身份锚）
  FB_SVC_PAINT    = 0x5E1F_2A00     （笔② 服务域成像常量——与身份锚可区分）
  数据段布局：+0x00 boot 取证串 / +0x40 请求帧缓冲 / +0x60 应答帧缓冲
  帧协议：请求 [op u32][x u32][y u32][w u32][value u32]（op 1/2）；
          应答 [status u32][seq u32]，tag = 请求 tag|0x80。
  bail 码         = 70/71/72        （fail-visible 退出码族）

寄存器约定 = bedrock abi v0/v0.19：rax = 系统调用号；rdi/rsi/rdx =
参数；SYS_IPC_SEND 载荷指针 = rdx、tag = r10（慢路径语义）；callee-saved
（rbx/rbp/r12-r15）跨 syscall 保留（M33-P1 帧快照域——r12 重试预算 /
r14 收帧缓冲指针 / r15 应答缓冲指针 / r13 服务序号跨 syscall 存续依赖
本契约）。
验证：脚本自检走 objdump -D -b binary 反汇编逐段锚定（工作区根运行
python3 scripts/gen_m42_fbdev_image.py --check 可复验）。
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ---- 交叉锚点常量 ----
FBDEV_ENTRY = 0x1_8000_0000
FBDEV_DATA_VA = 0x1_8000_1000
FBDEV_PAINT = 0x2B7F_1E00
FBDEV_BAIL_MAP = 70
FBDEV_BAIL_PIO = 71
FBDEV_BAIL_DISPI = 72
PAGE = 0x1000
FB_VA_BASE = 0x4000_0000

SYS_LOG, SYS_EXIT, SYS_YIELD = 0, 1, 2
SYS_FB_MAP, SYS_DEV_PIO = 35, 41
SYS_IPC_SEND, SYS_IPC_RECV = 3, 4
PIO_IN16, PIO_OUT16 = 2, 3
DISPI_INDEX, DISPI_DATA = 0x1CE, 0x1CF
DISPI_ID_MIN = 0xB0C0
PIO_RETRY_BUDGET = 64

# ---- 笔② 常驻服务协议常量（与 t102 客户端帧构造双向对账） ----
FB_SVC_OP_PAINT, FB_SVC_OP_QUIT = 1, 2
FB_SVC_STATUS_OK, FB_SVC_STATUS_EDOM, FB_SVC_STATUS_EOP = 0, 2, 3
FB_SVC_PAINT = 0x5E1F_2A00
FB_SVC_REPLY_TAG = 0x80
FB_SVC_RECV_OFF, FB_SVC_REPLY_OFF = 0x40, 0x60
FB_W, FB_H = 1920, 1080

FLAG_W, FLAG_X = 1 << 0, 1 << 1

EVIDENCE = b"LUMINA-T101-FBDEV px=64 map=0 pio=ok"
assert len(EVIDENCE) <= 64
SVC_EVIDENCE = b"LUMINA-T102-FBSVC boot map=0 pio=ok"
assert len(SVC_EVIDENCE) <= 64

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_gen_m42.rs"


# ---- 微型两遍汇编器（rel8/rel32 前向/后向标号裁决，越域即断言失败） ----
class Asm:
    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (pos, label, kind, prefix_len)

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

    def jmp8(self, opc, target):
        self.db(opc)
        self.fixups.append((self.here(), target, 8, 1))
        self.db(0)

    def jmp32(self, target):
        self.db(0x0F, 0x85)  # jne rel32（本映像唯一 rel32 点：entry bail）
        self.fixups.append((self.here(), target, 32, 0))
        self.db(0, 0, 0, 0)

    def je32(self, target):
        self.db(0x0F, 0x84)  # je rel32（条件远跳：op 分派 / QUIT 判定）
        self.fixups.append((self.here(), target, 32, 0))
        self.db(0, 0, 0, 0)

    def jcc32(self, cc, target):
        """通用 0F cc rel32 条件远跳（cc = 第二操作码：JB=0x82 / JE=0x84 等）。"""
        self.db(0x0F, cc)
        self.fixups.append((self.here(), target, 32, 0))
        self.db(0, 0, 0, 0)

    def jmp32u(self, target):
        self.db(0xE9)  # jmp rel32（无条件远跳：服务环回边——距离无 rel8 界）
        self.fixups.append((self.here(), target, 32, 0))
        self.db(0, 0, 0, 0)

    def resolve(self):
        for pos, target, kind, prefix in self.fixups:
            rel = self.labels[target] - (pos + (4 if kind == 32 else 1))
            if kind == 8:
                assert -128 <= rel <= 127, f"rel8 越域：{target} = {rel}"
                self.buf[pos] = rel & 0xFF
            else:
                assert -(1 << 31) <= rel < (1 << 31), f"rel32 越域：{target}"
                self.buf[pos : pos + 4] = struct.pack("<i", rel)


def build_code():
    a = Asm()
    # ---- 1) SYS_FB_MAP：rsi = FB_VA_BASE（a1 槽——parse 域契约） ----
    a.db(0xBE, struct.pack("<I", FB_VA_BASE))          # mov esi, imm32
    a.db(0xB8, struct.pack("<I", SYS_FB_MAP))          # mov eax, 35
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x85, 0xC0)                             # test rax, rax
    a.jmp32("bail_map")                                # jne rel32 bail_map
    # ---- 2) SYS_DEV_PIO dispi 探测（登记窗重试域） ----
    a.label("retry")
    a.db(0x41, 0xBC, struct.pack("<I", PIO_RETRY_BUDGET))  # mov r12d, budget
    a.label("retry_head")
    a.db(0xBF, struct.pack("<I", PIO_OUT16))           # mov edi, op OUT16
    a.db(0xBE, struct.pack("<I", DISPI_INDEX))         # mov esi, 0x1CE
    a.db(0x31, 0xD2)                                   # xor edx, edx
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jmp8(0x74, "denied")                             # je denied
    a.db(0xBF, struct.pack("<I", PIO_IN16))            # mov edi, op IN16
    a.db(0xBE, struct.pack("<I", DISPI_DATA))          # mov esi, 0x1CF
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jmp8(0x74, "denied")                             # je denied
    a.db(0x3D, struct.pack("<I", DISPI_ID_MIN))        # cmp eax, 0xB0C0
    a.jmp8(0x72, "bail_dispi")                         # jb bail_dispi
    # ---- 3) 直写成像：行 0 x=0..63 ← FBDEV_PAINT ----
    a.label("paint")
    a.db(0xBF, struct.pack("<I", FB_VA_BASE))          # mov edi, LFB va
    a.db(0xBE, struct.pack("<I", FBDEV_PAINT))         # mov esi, paint
    a.db(0x31, 0xC9)                                   # xor ecx, ecx
    a.label("p1")
    a.db(0x89, 0x34, 0x8F)                             # mov [rdi+rcx*4], esi
    a.db(0xFF, 0xC1)                                   # inc ecx
    a.db(0x83, 0xF9, 64)                               # cmp ecx, 64
    a.jmp8(0x72, "p1")                                 # jb p1
    # ---- 4) SYS_LOG 取证 + EXIT(0) ----
    a.db(0x48, 0xBF, struct.pack("<Q", FBDEV_DATA_VA))  # movabs rdi, DATA_VA
    a.db(0xBE, struct.pack("<I", len(EVIDENCE)))        # mov esi, len
    a.db(0x31, 0xC0)                                   # xor eax, eax (SYS_LOG)
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x31, 0xFF)                                   # xor edi, edi
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $（EXIT 失效停机）
    # ---- denied：裁量窗重试（YIELD 让权——登记窗免疫） ----
    a.label("denied")
    a.db(0x49, 0xFF, 0xCC)                             # dec r12d
    a.jmp8(0x74, "bail_pio")                           # jz bail_pio
    a.db(0xB8, struct.pack("<I", SYS_YIELD))           # mov eax, 2
    a.db(0x0F, 0x05)                                   # syscall
    a.jmp8(0xEB, "retry_head")                         # jmp retry_head
    # ---- bail 族（fail-visible：装置不静默） ----
    a.label("bail_map")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_MAP))      # mov edi, 70
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_pio")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_PIO))      # mov edi, 71
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_dispi")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_DISPI))    # mov edi, 72
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.resolve()
    return bytes(a.buf)


def lxe1(entry, stack_top, segs):
    """LXE1 编码（bedrock::exec::encode 同构：64B 头 + 32B 段头 × n + 载荷）。"""
    payload_off = 64 + 32 * len(segs)
    out = bytearray()
    out += struct.pack("<I", 0x3145_584C)  # magic "LXE1"
    out += struct.pack("<I", 1)            # version
    out += struct.pack("<I", len(segs))
    out += struct.pack("<I", 0)            # 保留
    out += struct.pack("<Q", entry)
    out += struct.pack("<Q", stack_top)
    out += struct.pack("<Q", payload_off)
    out += bytes(24)                       # 0x28..0x40 保留
    for seg in segs:
        out += struct.pack("<QQQQ", seg[0], seg[1], seg[2], seg[3])
    for seg in segs:
        assert len(seg[4]) == seg[2]
        out += seg[4]
    return bytes(out)


def objdump_check(code):
    """独立验证通道：objdump 反汇编锚定关键指令序（机器码形态守恒）。"""
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
    # 关键锚（偏移敏感序——重排即生成器缺陷显形；空白归一单空格）
    anchors = [
        ("mov $0x40000000,%esi", "FB_MAP 参数"),
        ("mov $0x23,%eax", "SYS_FB_MAP 号"),
        ("syscall", "FB_MAP 入口"),
        ("mov $0x1ce,%esi", "dispi 索引口"),
        ("mov $0x1cf,%esi", "dispi 数据口"),
        ("mov $0x29,%eax", "SYS_DEV_PIO 号"),
        ("cmp $0xb0c0,%eax", "dispi 版本下限"),
        ("movabs $0x180001000,%rdi", "取证串指针"),
        ("mov %esi,(%rdi,%rcx,4)", "LFB 直写成像"),
        ("dec %r12", "重试预算域"),
    ]
    flat = " ".join(dis.split())
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    # syscall 次数锚：FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + EXIT×4 = 9
    n_sys = flat.count("syscall")
    assert n_sys == 9, f"syscall 计数锚失配：{n_sys} ≠ 9"
    return n_sys


def build_code_svc():
    """笔② 常驻 fbdev 服务映像代码段：boot 面（FB_MAP → dispi 探测 →
    行 0 身份漆 → LOG）→ 服务环（RECV → 解码 → 域闸/直写 → SEND 应答
    → QUIT 判定）。寄存器面：r12 = PIO 重试预算（boot 后退役）、r13 =
    服务序号、r14 = 请求帧缓冲指针、r15 = 应答帧缓冲指针（全 callee-saved
    ——M33-P1 跨 syscall 存续契约）。"""
    a = Asm()
    # ---- 1) SYS_FB_MAP：rsi = FB_VA_BASE（a1 槽——parse 域契约） ----
    a.db(0xBE, struct.pack("<I", FB_VA_BASE))          # mov esi, imm32
    a.db(0xB8, struct.pack("<I", SYS_FB_MAP))          # mov eax, 35
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x85, 0xC0)                             # test rax, rax
    a.jmp32("bail_map")                                # jne rel32 bail_map
    # ---- 2) SYS_DEV_PIO dispi 探测（登记窗重试域，笔① 同款；
    #     denied/bail_dispi 远跳 rel32——boot 漆块隔距超 rel8 界） ----
    a.label("retry")
    a.db(0x41, 0xBC, struct.pack("<I", PIO_RETRY_BUDGET))  # mov r12d, budget
    a.label("retry_head")
    a.db(0xBF, struct.pack("<I", PIO_OUT16))           # mov edi, op OUT16
    a.db(0xBE, struct.pack("<I", DISPI_INDEX))         # mov esi, 0x1CE
    a.db(0x31, 0xD2)                                   # xor edx, edx
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jcc32(0x84, "denied")                            # je rel32 denied
    a.db(0xBF, struct.pack("<I", PIO_IN16))            # mov edi, op IN16
    a.db(0xBE, struct.pack("<I", DISPI_DATA))          # mov esi, 0x1CF
    a.db(0xB8, struct.pack("<I", SYS_DEV_PIO))         # mov eax, 41
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x48, 0x83, 0xF8, 0x01)                       # cmp rax, 1 (ERR_CAP)
    a.jcc32(0x84, "denied")                            # je rel32 denied
    a.db(0x3D, struct.pack("<I", DISPI_ID_MIN))        # cmp eax, 0xB0C0
    a.jcc32(0x82, "bail_dispi")                        # jb rel32 bail_dispi
    # ---- 3) boot 成像：行 0 x=0..64 ← FBDEV_PAINT（身份锚——t102 boot 漆存续对账） ----
    a.label("paint0")
    a.db(0xBF, struct.pack("<I", FB_VA_BASE))          # mov edi, LFB va
    a.db(0xBE, struct.pack("<I", FBDEV_PAINT))         # mov esi, paint
    a.db(0x31, 0xC9)                                   # xor ecx, ecx
    a.label("p0")
    a.db(0x89, 0x34, 0x8F)                             # mov [rdi+rcx*4], esi
    a.db(0xFF, 0xC1)                                   # inc ecx
    a.db(0x83, 0xF9, 64)                               # cmp ecx, 64
    a.jmp8(0x72, "p0")                                 # jb p0
    # ---- 4) boot 取证 LOG + 服务环指针初始化 ----
    a.db(0x48, 0xBF, struct.pack("<Q", FBDEV_DATA_VA))  # movabs rdi, DATA_VA
    a.db(0xBE, struct.pack("<I", len(SVC_EVIDENCE)))   # mov esi, len
    a.db(0x31, 0xC0)                                   # xor eax, eax (SYS_LOG)
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x49, 0xBE, struct.pack("<Q", FBDEV_DATA_VA + FB_SVC_RECV_OFF))   # movabs r14, recv buf
    a.db(0x49, 0xBF, struct.pack("<Q", FBDEV_DATA_VA + FB_SVC_REPLY_OFF))  # movabs r15, reply buf
    a.db(0x45, 0x31, 0xED)                             # xor r13d, r13d (served = 0；REX R|B 无 W——32 位域)
    # ---- 5) 服务环：RECV(h1, 32, r14) → 解码 → 域闸/直写 → REPLY(h2) → QUIT 判定 ----
    a.label("svc_loop")
    a.db(0xBF, struct.pack("<I", 1))                   # mov edi, 1（h1 = FB 请求通道）
    a.db(0xBE, struct.pack("<I", 32))                  # mov esi, 32（buf_len）
    a.db(0x4C, 0x89, 0xF2)                             # mov rdx, r14（载荷指针——慢路径语义）
    a.db(0xB8, struct.pack("<I", SYS_IPC_RECV))        # mov eax, 4
    a.db(0x0F, 0x05)                                   # syscall（阻塞——IpcRecv 等待对象）
    a.db(0x48, 0x89, 0xC3)                             # mov rbx, rax（tag = rax>>32）
    a.db(0x48, 0xC1, 0xEB, 0x20)                       # shr rbx, 32
    a.db(0x83, 0xF8, 0x04)                             # cmp eax, 4（len ≥ 4：错误码 1..4 与坏帧同拒）
    a.jmp8(0x72, "svc_loop")                           # jb svc_loop（重收）
    a.db(0x41, 0x8B, 0x46, 0x00)                       # mov eax, [r14+0]（op）
    a.db(0x83, 0xF8, FB_SVC_OP_PAINT)                  # cmp eax, 1
    a.jmp8(0x74, "do_paint")                           # je do_paint
    a.db(0x83, 0xF8, FB_SVC_OP_QUIT)                   # cmp eax, 2
    a.jmp8(0x74, "do_quit")                            # je do_quit
    a.db(0x41, 0xC7, 0x47, 0x00)                       # mov dword [r15+0], imm32（REX.B——rm=111+r15）
    a.db(struct.pack("<I", FB_SVC_STATUS_EOP))         #   status = 3（未知 op）
    a.jmp8(0xEB, "reply")                              # jmp reply
    # ---- PAINT_RECT：域闸（y<1080 ∧ x+w≤1920）→ LFB 直写 ----
    a.label("do_paint")
    a.db(0x41, 0x8B, 0x46, 0x08)                       # mov eax, [r14+8]（y）
    a.db(0x3D, struct.pack("<I", FB_H))                # cmp eax, 1080
    a.jmp8(0x73, "bad_req")                            # jae bad_req（越域拒不写）
    a.db(0x41, 0x8B, 0x46, 0x04)                       # mov eax, [r14+4]（x）
    a.db(0x41, 0x03, 0x46, 0x0C)                       # add eax, [r14+12]（+w）
    a.db(0x3D, struct.pack("<I", FB_W))                # cmp eax, 1920
    a.jmp8(0x77, "bad_req")                            # ja bad_req
    a.db(0x41, 0x8B, 0x46, 0x08)                       # mov eax, [r14+8]（y）
    a.db(0x69, 0xC0, struct.pack("<I", FB_W))           # imul eax, eax, 1920（像素行宽——先像素偏移后 ×4）
    a.db(0x41, 0x03, 0x46, 0x04)                       # add eax, [r14+4]（+x，像素域）
    a.db(0xC1, 0xE0, 0x02)                             # shl eax, 2（×4 字节/px）
    a.db(0x05, struct.pack("<I", FB_VA_BASE))          # add eax, FB_VA_BASE
    a.db(0x89, 0xC7)                                   # mov edi, eax（目的行址）
    a.db(0x41, 0x8B, 0x76, 0x10)                       # mov esi, [r14+16]（value）
    a.db(0x41, 0x8B, 0x4E, 0x0C)                       # mov ecx, [r14+12]（w）
    a.db(0x31, 0xD2)                                   # xor edx, edx
    a.label("p2")
    a.db(0x89, 0x34, 0x97)                             # mov [rdi+rdx*4], esi（SIB scale=10 → ×4）
    a.db(0xFF, 0xC2)                                   # inc edx
    a.db(0x39, 0xCA)                                   # cmp edx, ecx
    a.jmp8(0x72, "p2")                                 # jb p2
    a.db(0x41, 0xC7, 0x47, 0x00)                       # mov dword [r15+0], imm32（REX.B）
    a.db(struct.pack("<I", FB_SVC_STATUS_OK))          #   status = 0
    a.jmp8(0xEB, "reply")                              # jmp reply
    # ---- QUIT：status 0 应答后 EXIT(0)（常驻面有界终结——收割契约） ----
    a.label("do_quit")
    a.db(0x41, 0xC7, 0x47, 0x00)                       # mov dword [r15+0], imm32（REX.B）
    a.db(struct.pack("<I", FB_SVC_STATUS_OK))          #   status = 0
    a.jmp8(0xEB, "reply")                              # jmp reply（不直落 bad_req——status 覆写防线）
    # ---- 越域拒绝：status = 2（fail-visible 不写显形） ----
    a.label("bad_req")
    a.db(0x41, 0xC7, 0x47, 0x00)                       # mov dword [r15+0], imm32（REX.B）
    a.db(struct.pack("<I", FB_SVC_STATUS_EDOM))        #   status = 2
    # ---- 应答：SEND(h2, 8, r15, tag|0x80) → served++ → QUIT 判定 ----
    a.label("reply")
    a.db(0x44, 0x89, 0xE8)                             # mov eax, r13d（seq = served+1）
    a.db(0xFF, 0xC0)                                   # inc eax
    a.db(0x41, 0x89, 0x47, 0x04)                       # mov [r15+4], eax
    a.db(0xBF, struct.pack("<I", 2))                   # mov edi, 2（h2 = FB 应答通道）
    a.db(0xBE, struct.pack("<I", 8))                   # mov esi, 8（应答帧长）
    a.db(0x4C, 0x89, 0xFA)                             # mov rdx, r15（载荷指针）
    a.db(0x41, 0x89, 0xDA)                             # mov r10d, ebx（REX.B——零扩展入 r10）
    a.db(0x41, 0x81, 0xCA, struct.pack("<I", FB_SVC_REPLY_TAG))  # or r10d, 0x80（imm32——imm8 符号扩展会污高位）
    a.db(0xB8, struct.pack("<I", SYS_IPC_SEND))        # mov eax, 3
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0x41, 0xFF, 0xC5)                             # inc r13d（served++）
    a.db(0x41, 0x83, 0x7E, 0x00, FB_SVC_OP_QUIT)       # cmp dword [r14+0], 2（QUIT?）
    a.je32("svc_exit")                                 # je rel32 svc_exit
    a.jmp32u("svc_loop")                               # jmp rel32 svc_loop（回边）
    a.label("svc_exit")
    a.db(0x31, 0xFF)                                   # xor edi, edi
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $（EXIT 失效停机）
    # ---- denied：裁量窗重试（YIELD 让权——登记窗免疫；retry_head 回跳
    #     rel32——boot 漆块隔距超 rel8 界） ----
    a.label("denied")
    a.db(0x49, 0xFF, 0xCC)                             # dec r12d
    a.jmp8(0x74, "bail_pio")                           # jz bail_pio
    a.db(0xB8, struct.pack("<I", SYS_YIELD))           # mov eax, 2
    a.db(0x0F, 0x05)                                   # syscall
    a.jmp32u("retry_head")                             # jmp rel32 retry_head
    # ---- bail 族（fail-visible：装置不静默） ----
    a.label("bail_map")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_MAP))      # mov edi, 70
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_pio")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_PIO))      # mov edi, 71
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.label("bail_dispi")
    a.db(0xBF, struct.pack("<I", FBDEV_BAIL_DISPI))    # mov edi, 72
    a.db(0xB8, struct.pack("<I", SYS_EXIT))            # mov eax, 1
    a.db(0x0F, 0x05)                                   # syscall
    a.db(0xEB, 0xFE)                                   # jmp $
    a.resolve()
    return bytes(a.buf)


def objdump_check_svc(code):
    """笔② 服务映像独立验证通道：objdump 反汇编锚定关键指令序
    （帧解码/域闸/行跨距/应答标签/服务序号——机器码形态守恒）。"""
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
    anchors = [
        ("mov $0x40000000,%esi", "FB_MAP 参数"),
        ("mov $0x23,%eax", "SYS_FB_MAP 号"),
        ("cmp $0xb0c0,%eax", "dispi 版本下限"),
        ("movabs $0x180001040,%r14", "请求帧缓冲指针"),
        ("movabs $0x180001060,%r15", "应答帧缓冲指针"),
        ("mov $0x4,%eax", "SYS_IPC_RECV 号"),
        ("shr $0x20,%rbx", "tag 提取"),
        ("imul $0x780,%eax,%eax", "像素行宽 1920"),
        ("mov %esi,(%rdi,%rdx,4)", "LFB 直写成像"),
        ("mov %eax,0x4(%r15)", "应答 seq 落帧"),
        ("or $0x80,%r10d", "应答标签"),
        ("mov $0x3,%eax", "SYS_IPC_SEND 号"),
        ("inc %r13", "服务序号累计"),
        ("dec %r12", "重试预算域"),
    ]
    flat = " ".join(dis.split())
    for needle, why in anchors:
        assert needle in flat, f"objdump 锚缺失（{why}）：{needle}"
    # syscall 次数锚：FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + RECV 1
    # + SEND 1 + EXIT(QUIT) 1 + bail EXIT×3 = 11
    n_sys = flat.count("syscall")
    assert n_sys == 11, f"syscall 计数锚失配：{n_sys} ≠ 11"
    return n_sys


def rs_array(blob, per_line=16):
    rows = []
    for i in range(0, len(blob), per_line):
        chunk = blob[i : i + per_line]
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    return "\n".join(rows).rstrip(",")


def main():
    check_only = "--check" in sys.argv
    # ---- 笔① 一次性移交链映像 ----
    code = build_code()
    n_sys = objdump_check(code)
    data = EVIDENCE
    blob = lxe1(
        FBDEV_ENTRY,
        0,
        [
            (FBDEV_ENTRY, PAGE, len(code), FLAG_X, code),
            (FBDEV_DATA_VA, PAGE, len(data), FLAG_W, data),
        ],
    )
    # ---- 笔② 常驻 fbdev 服务映像 ----
    svc_code = build_code_svc()
    svc_n_sys = objdump_check_svc(svc_code)
    svc_data = SVC_EVIDENCE
    svc_blob = lxe1(
        FBDEV_ENTRY,
        0,
        [
            (FBDEV_ENTRY, PAGE, len(svc_code), FLAG_X, svc_code),
            (FBDEV_DATA_VA, PAGE, len(svc_data), FLAG_W, svc_data),
        ],
    )
    if check_only:
        print(f"[check] one-shot code={len(code)}B blob={len(blob)}B syscall={n_sys}")
        print(f"[check] resident svc code={len(svc_code)}B blob={len(svc_blob)}B syscall={svc_n_sys}")
        return
    doc = f"""// 本文件由 scripts/gen_m42_fbdev_image.py 生成——勿手改；重跑脚本再生成。
// M42 用户态 fb 驱动进程映像（阶段一笔① + 笔②）；交叉锚点常量与
// kernel::user / kernel::dev / kernel::main(t102) 双向对账。两映像
// 机器码均经 objdump 反汇编锚定自检：
//   FBDEV_LXE     syscall ×{n_sys}（FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + EXIT 4）
//   FBDEV_SVC_LXE syscall ×{svc_n_sys}（FB_MAP 1 + PIO 2 + YIELD 1 + LOG 1 + RECV 1 + SEND 1 + EXIT 1 + bail EXIT 3）

/// fbdev 映像入口虚地址（PDPT[6] 全新分支段区首槽——[`FRESH_BASE`]
/// 同域；gen 脚本 FBDEV_ENTRY 对账）。
#[allow(dead_code)] // 文档锚点：LXE1 头 entry 字段内嵌同值（gen 脚本对账）
pub const FBDEV_ENTRY: u64 = 0x1_8000_0000;
/// fbdev 映像数据段虚地址（FRESH_BASE + 0x1000——PROG_DATA_VA 同域）。
#[allow(dead_code)] // 文档锚点：LXE1 段表 vaddr 字段内嵌同值
pub const FBDEV_DATA_VA: u64 = 0x1_8000_1000;
/// fbdev 直写成像常量（LFB 行 0 x=0..63 共 64 px；内核侧 VRAM 物理
/// 读回对账锚——t101 (g) 相位 / t102 boot 漆存续对账面。与文本前景
/// 0x00F0_F0F0 / 黑底 0x0 / [`FB_SVC_PAINT`] 可区分）。
pub const FBDEV_PAINT: u32 = 0x2B7F_1E00;
/// bail 退出码：SYS_FB_MAP 失败（LFB 移交面 ERR）。
#[allow(dead_code)] // 文档锚点：机器码 bail_map 臂 imm32 内嵌同值
pub const FBDEV_BAIL_MAP: i32 = {FBDEV_BAIL_MAP};
/// bail 退出码：SYS_DEV_PIO 裁量预算耗尽（64 拍重试窗仍 ERR_CAP）。
#[allow(dead_code)] // 文档锚点：机器码 bail_pio 臂 imm32 内嵌同值
pub const FBDEV_BAIL_PIO: i32 = {FBDEV_BAIL_PIO};
/// bail 退出码：dispi 版本下限未过（< 0xB0C0）。
#[allow(dead_code)] // 文档锚点：机器码 bail_dispi 臂 imm32 内嵌同值
pub const FBDEV_BAIL_DISPI: i32 = {FBDEV_BAIL_DISPI};

/// fb 驱动进程映像（M42-FBDEV1 阶段一首笔；LXE1 双段：代码 RX
/// @FBDEV_ENTRY + 数据 RW @FBDEV_DATA_VA，栈 = 遗留单帧 0x403000）。
/// 车道序：(1) SYS_FB_MAP({FB_VA_BASE:#x}) LFB 映射移交（SURFACE_OWNER
/// 单面 CAS 首认领者 = 驱动进程）；(2) SYS_DEV_PIO dispi 探测——OUT16
/// 0x1CE←0 + IN16 0x1CF 读版本（≥0xB0C0），ERR_CAP 重试 64 拍
/// （spawn→grant 登记窗免疫——t100 先例同款；r12 重试预算跨 syscall
/// 存续 = M33-P1 callee-saved 帧快照契约）；(3) LFB 行 0 ×64 px 直写
/// FBDEV_PAINT（内核 VRAM 物理读回对账）；(4) SYS_LOG 取证 + EXIT(0)。
/// bail 码 70/71/72 fail-visible（映像不静默）。寄存器约定 = bedrock
/// abi v0/v0.19（rax = 号，rdi/rsi/rdx = 参数）。
pub const FBDEV_LXE: [u8; {len(blob)}] = [
{rs_array(blob)}
];

// ================= 笔② M42-FBSVC2：常驻 fbdev 服务映像 =================

/// fb 服务请求帧 op：PAINT_RECT（帧 [op][x][y][w][value]，直写 LFB）。
pub const FB_SVC_OP_PAINT: u32 = {FB_SVC_OP_PAINT};
/// fb 服务请求帧 op：QUIT（应答后 EXIT(0)——常驻面有界终结）。
pub const FB_SVC_OP_QUIT: u32 = {FB_SVC_OP_QUIT};
/// fb 服务应答 status：成功。
pub const FB_SVC_STATUS_OK: u32 = {FB_SVC_STATUS_OK};
/// fb 服务应答 status：越域拒绝（y≥1080 ∨ x+w>1920——fail-visible 不写）。
pub const FB_SVC_STATUS_EDOM: u32 = {FB_SVC_STATUS_EDOM};
/// fb 服务应答 status：未知 op（协议域外——fail-visible 不写；映像侧
/// 文档锚点——t102 未消费，dead_code 豁免）。
#[allow(dead_code)]
pub const FB_SVC_STATUS_EOP: u32 = {FB_SVC_STATUS_EOP};
/// fb 服务域成像常量（t102 请求 PAINT_RECT(8, 1, 64, FB_SVC_PAINT)
/// ——内核侧 VRAM 行 1 读回对账锚；与 [`FBDEV_PAINT`] 身份锚可区分）。
pub const FB_SVC_PAINT: u32 = 0x5E1F_2A00;
/// fb 服务应答标签位（应答 tag = 请求 tag | 0x80——回声服务同款）。
pub const FB_SVC_REPLY_TAG: u32 = {FB_SVC_REPLY_TAG:#x};

/// 常驻 fbdev 服务映像（M42-FBSVC2 阶段一笔②「驱动进程常驻面——服务
/// 环/IPC 通道 + 常驻 fbdev 服务化」；LXE1 双段同 FBDEV_LXE 布局）。
/// 车道序：(1) SYS_FB_MAP LFB 映射移交（Surface 单面——t101 fbdev 退出
/// 已由生命周期释放面归还，笔② 揭雷修复前置）；(2) SYS_DEV_PIO dispi
/// 探测（64 拍重试窗同笔①）；(3) LFB 行 0 ×64 px 直写 FBDEV_PAINT
/// （boot 身份漆）；(4) SYS_LOG boot 取证 → **服务环**：SYS_IPC_RECV
/// (h1 = FB 请求通道) 阻塞收帧 → 帧解码 [op][x][y][w][value]——op 1 =
/// PAINT_RECT（域闸 y<1080 ∧ x+w≤1920，越域 status=2 拒不写）LFB 直
/// 写；op 2 = QUIT；未知 op = status 3 → SYS_IPC_SEND(h2 = FB 应答通
/// 道) 回帧 [status][seq]（tag|0x80）→ QUIT 即 EXIT(0)。寄存器面：
/// r13 = 服务序号 / r14 = 请求帧缓冲 / r15 = 应答帧缓冲（callee-saved
/// 跨 syscall 存续）。数据段：+0x00 boot 取证串 / +0x40 请求帧缓冲 /
/// +0x60 应答帧缓冲。bail 码 70/71/72 fail-visible。句柄约定：h1 =
/// FB 请求通道 / h2 = FB 应答通道（t102 spawn_stage_wired 接线域同源）。
pub const FBDEV_SVC_LXE: [u8; {len(svc_blob)}] = [
{rs_array(svc_blob)}
];
"""
    OUT.write_text(doc, encoding="utf-8")
    print(
        f"[gen] {OUT} one-shot code={len(code)}B blob={len(blob)}B syscall={n_sys}"
        f" | svc code={len(svc_code)}B blob={len(svc_blob)}B syscall={svc_n_sys}"
    )


if __name__ == "__main__":
    main()
