#!/usr/bin/env python3
"""gen_m23_images.py — M23-②③ init（PID 1 ring3 shell）映像生成器。

产物：crates/kernel/src/exec_images_gen_m23.rs（user.rs 经 include! 引入）
  - INIT_IMAGE：init shell 映像（位置固定 0x400000，单帧 RX + 栈帧）

协议（与 kernel::user / exec_images_gen_m23.rs 文档双向对账）：
  入口 r14 分向：r14 = 0（内核 spawn_user 无父派生）→ shell 主循环；
  r14 != 0（sys_spawn COW 子代，r14 = 父 pid）→ 子代分支。

  shell 主循环：prompt("ok> ") → GETCH 轮询（0 → YIELD 重试）→ 行积累
  @LINE_BUF（每 prompt 清首 qword，短行比较安全）→ '\n' 提交后按首
  双字分派：
    halt  → SYS_EXIT(0x10)（kmain interactive 尾读 INIT_EXIT 透传 →
            kernel_exit(0x10) → QEMU 码 33 = 批跑成功域同源）
    st    → 信箱 1 → spawn 子代 → 子代 EXEC(0) selftest.lxe → exit 42
    prog  → 信箱 2 → EXEC(1) prog.lxe  → exit 91
    grow  → 信箱 3 → EXEC(2) grow.lxe  → exit 92
    deep  → 信箱 5 → EXEC(4) deep.lxe
    ping  → 直答 "pong\r\n"（不派生）
    help  → 直答命令清单（A2 深化：自省面）
    ver   → 直答 "LuminaOS v0.23.0+dev"（A2 深化：版本面）
    echo  → 参数域原样回显（A2 深化：参数面首次引入；r12 = 行长自
            parse 透传，r12 < 5 或参数域空 → "(void)" 占位——
            validate_user_slice 拒 len=0，空回显不可达，占位即负探针）
    fb    → S1 显示面：SYS_FB_MAP(0x40000000) → 底部 64 行三色带
            直画（y 704..724 红 / 725..745 绿 / 746..767 蓝，行带
            分色——字节码最短路径）→ SYS_FB_SYNC(0,704,1024,64) →
            "fb-ok"；MAP 失败（非零返码）→ "fb-err"
    其余  → "err?\r\n"
  派生命令共用臂：信箱写 1 基映像号 → SYS_SPAWN → WAITPID 阻塞收割 →
  itoa 倒写 @NUM 区 → "exit=" + <dec> + "\r\n" 三段 SYS_LOG → 重打提示。
  spawn 失败（OK 位缺失）→ "spawn-err\r\n"。

  子代分支：读信箱（COW 遗传——父写早于 SPAWN，子副本可见）→ 0 =
  异常回落 EXIT(76)（gen_m14 EXEC 回落同码域）；非 0 → EXEC(信箱-1)
  成功不返回。

交叉锚点常量：
  LINE_BUF   = 0x402E00   （行积累缓冲；栈帧内，COW 拷贝可见）
  MAILBOX    = 0x402F00   （命令信箱，1 基；0 = 无命令）
  NUM_END    = 0x402C20   （itoa 数字区尾；0x402C1F 起倒写，u64 上限 20 位）
  HALT_CODE  = 0x10       （halt 终结码 = EXIT_SUCCESS）
  EXEC_BAIL  = 76         （子代信箱空回落码）

寄存器纪律（syscall 桩契约）：rax = 返回值；rcx/r11/rbp 出入破坏；
rbx/r12–r15 与五参数寄存器全量往返。本映像跨 syscall 持有：
r12（行游标）/ r13（子 pid）/ r15（数字游标）；rbx 仅 itoa 内部
（窗口内无 syscall）；rcx/r11/rbp 全程不用。无 push/call——栈页
零侵扰，LINE_BUF/MAILBOX 静置栈页底部不受 rsp 下压影响。

用法：python3 scripts/gen_m23_images.py（工作区根运行）
"""

import struct
from pathlib import Path

# ---- 交叉锚点常量（与 kernel::user 文档双向对账） ----
LINE_BUF = 0x40_2E00
MAILBOX = 0x40_2F00
NUM_END = 0x40_2C20
HALT_CODE = 0x10
EXEC_BAIL = 76

# bedrock abi v0.20 系统调用号
SYS_LOG, SYS_EXIT, SYS_YIELD = 0, 1, 2
SYS_WAIT_PID, SYS_SPAWN, SYS_EXEC, SYS_TTY_GETCH = 12, 13, 17, 34

# A2/S1 直答文本（长度由 len() 现算——免手数错）
HELP_TEXT = b"cmds: halt st prog grow deep ping echo ver help fb text"
VER_TEXT = b"LuminaOS v0.23.0+dev"
EVOID_TEXT = b"(void)"
FBOK_TEXT = b"fb-ok"
FBERR_TEXT = b"fb-err"
BANNER_TEXT = b"LUMINA OS v0.23"
TEXTOK_TEXT = b"text-ok"
TEXTERR_TEXT = b"text-err"

# S1/S2 显示面常量（与 bedrock abi FB_VA_BASE/SYS_FB_* 双向对账）
FB_VA = 0x40_000000
SYS_FB_MAP, SYS_FB_SYNC, SYS_FB_TEXT = 35, 36, 37

OUT = Path(__file__).resolve().parent.parent / "crates/kernel/src/exec_images_gen_m23.rs"


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def cmd_word(s):
    """命令首双字小端立即数（'halt' → 0x746C6168）。"""
    assert len(s) == 4
    return struct.unpack("<I", s)[0]


class Asm:
    """微型 fixup 汇编器：标签 + rel32 跳转 + abs32 数据引用。

    跳转统一 rel32（jmp E9 / jcc 0F 8x）——免弛缓两遍（代码 < 0.5KB，
    尺寸代价 ~30B，远小于 4KB 页预算）；字符串引用统一 abs32。
    """

    def __init__(self, base):
        self.base = base
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (pos, label, kind) kind: 'rel' | 'abs'

    @property
    def off(self):
        return len(self.buf)

    def label(self, name):
        assert name not in self.labels, f"duplicate label {name}"
        self.labels[name] = self.off

    def va(self, name):
        return self.base + self.labels[name]

    def db(self, *chunks):
        for c in chunks:
            self.buf += bytes(c)

    def jmp(self, target):
        self.db(b"\xE9")
        self.fixups.append((self.off, target, "rel"))
        self.db(le32(0))

    def jcc(self, cc, target):
        self.db(b"\x0F", bytes([cc]))
        self.fixups.append((self.off, target, "rel"))
        self.db(le32(0))

    def abs32(self, label):
        self.fixups.append((self.off, label, "abs"))
        self.db(le32(0))

    def resolve(self):
        for pos, target, kind in self.fixups:
            if kind == "rel":
                rel = self.labels[target] - (pos + 4)
                self.buf[pos:pos + 4] = struct.pack("<i", rel)
            else:
                self.buf[pos:pos + 4] = le32(self.base + self.labels[target])
        return bytes(self.buf)


# ---- 字符串常量（页尾 abs32 引用；exit 行经 itoa 区组合，单调用交付） ----
STRINGS = [
    ("s_prompt", b"ok> "),
    ("s_pong", b"pong\r\n"),
    ("s_err", b"err?\r\n"),
    ("s_sperr", b"spawn-err\r\n"),
    ("s_help", HELP_TEXT),
    ("s_ver", VER_TEXT),
    ("s_evoid", EVOID_TEXT),
    ("s_fbok", FBOK_TEXT),
    ("s_fberr", FBERR_TEXT),
    ("s_banner", BANNER_TEXT),
    ("s_textok", TEXTOK_TEXT),
    ("s_texterr", TEXTERR_TEXT),
]

JE, JNE, JNZ = 0x84, 0x85, 0x85


def log_call(a, str_label, ln):
    """SYS_LOG(str_label, ln)：rdi=ptr rsi=len rax=0。"""
    a.db(b"\xBF")            # mov edi, imm32
    a.abs32(str_label)
    a.db(b"\xBE", le32(ln))  # mov esi, ln
    a.db(b"\x31\xC0")        # xor eax, eax
    a.db(b"\x0F\x05")        # syscall


def mailbox_set(a, n):
    """mov qword [MAILBOX], n（信箱写早于 SPAWN——COW 遗传面）。"""
    a.db(b"\x48\xC7\x04\x25", le32(MAILBOX), le32(n))


def build_init_image():
    a = Asm(0x400000)

    # ---- 入口：r14 细胞分向（0 = 根 shell / 非 0 = 派生子代）----
    a.db(b"\x4D\x85\xF6")  # test r14, r14
    a.jcc(JNE, "child")

    # ---- shell 主循环 ----
    a.label("prompt")
    # 清行缓冲首 qword（短行双字比较的零域安全性）
    a.db(b"\x48\xC7\x04\x25", le32(LINE_BUF), le32(0))
    log_call(a, "s_prompt", 4)
    a.db(b"\x41\xBC", le32(LINE_BUF))  # mov r12d, LINE_BUF（零扩展）

    a.label("getch_loop")
    a.db(b"\xB8", le32(SYS_TTY_GETCH))  # mov eax, SYS_TTY_GETCH
    a.db(b"\x0F\x05")                   # syscall
    a.db(b"\x48\x85\xC0")               # test rax, rax
    a.jcc(JE, "do_yield")               # 0 = 暂无数据 → yield 重试
    a.db(b"\x3C\x0A")                   # cmp al, 0x0A
    a.jcc(JE, "parse")                  # 行终结 → 解析
    a.db(b"\x41\x88\x04\x24")           # mov [r12], al
    a.db(b"\x49\xFF\xC4")               # inc r12
    a.jmp("getch_loop")

    a.label("do_yield")
    a.db(b"\xB8", le32(SYS_YIELD))  # mov eax, SYS_YIELD
    a.db(b"\x0F\x05")
    a.jmp("getch_loop")

    # ---- 行解析：首双字分派（行长 0 → 静默重打提示）----
    a.label("parse")
    a.db(b"\x49\x81\xEC", le32(LINE_BUF))  # sub r12, LINE_BUF（r12 = 行长）
    a.db(b"\x4D\x85\xE4")                  # test r12, r12
    a.jcc(JE, "prompt")                    # 空行 → 静默重提示
    a.db(b"\x8B\x04\x25", le32(LINE_BUF))  # mov eax, [LINE_BUF]
    for cmd, target in [
        (b"halt", "do_halt"),
        (b"st\x00\x00", "do_st"),
        (b"prog", "do_prog"),
        (b"grow", "do_grow"),
        (b"deep", "do_deep"),
        (b"ping", "do_ping"),
        (b"echo", "do_echo"),
        (b"ver\x00", "do_ver"),
        (b"help", "do_help"),
        (b"fb\x00\x00", "do_fb"),
        (b"text", "do_text"),
    ]:
        a.db(b"\x3D", le32(cmd_word(cmd)))  # cmp eax, imm32
        a.jcc(JE, target)
    a.jmp("do_unknown")

    # ---- halt：SYS_EXIT(0x10)——kmain interactive 尾读 INIT_EXIT 透传 ----
    a.label("do_halt")
    a.db(b"\xBF", le32(HALT_CODE))       # mov edi, HALT_CODE
    a.db(b"\xB8", le32(SYS_EXIT))        # mov eax, SYS_EXIT
    a.db(b"\x0F\x05")
    a.db(b"\xEB\xFE")                    # jmp $（EXIT 失效则原地停）

    # ---- 派生命令：信箱写 1 基映像号（+1 使 0 保持「无命令」哨兵语义）----
    for label, n in [("do_st", 1), ("do_prog", 2), ("do_grow", 3), ("do_deep", 5)]:
        a.label(label)
        mailbox_set(a, n)
        a.jmp("do_spawn")

    a.label("do_ping")
    log_call(a, "s_pong", 6)
    a.jmp("prompt")

    a.label("do_unknown")
    log_call(a, "s_err", 6)
    a.jmp("prompt")

    # ---- A2 深化直答：help / ver ----
    a.label("do_help")
    log_call(a, "s_help", len(HELP_TEXT))
    a.jmp("prompt")

    a.label("do_ver")
    log_call(a, "s_ver", len(VER_TEXT))
    a.jmp("prompt")

    # ---- A2 参数面：echo（r12 = 行长自 parse 透传；首双字已证 "echo"）----
    # 行长 < 5（裸 "echo"）或参数域空（"echo " 尾随空格）→ "(void)" 占位
    # （validate_user_slice 拒 len=0——零长 SYS_LOG 静默无 CRLF，占位即
    # 可断言负探针）；有参 → 自 LINE_BUF+5 起按 r12-5 字节原样回显，
    # 尾随 CRLF 由内核 serial_log_bytes 补齐。
    a.label("do_echo")
    a.db(b"\x49\x83\xFC\x05")   # cmp r12, 5
    a.jcc(0x82, "echo_void")     # jb → 裸 echo → (void)
    a.db(b"\x48\xC7\xC7", le32(LINE_BUF + 5))  # mov rdi, LINE_BUF+5
    a.db(b"\x4C\x89\xE6")        # mov rsi, r12
    a.db(b"\x48\x83\xEE\x05")    # sub rsi, 5
    a.jcc(JE, "echo_void")       # 参数域零字节 → (void)
    a.db(b"\x31\xC0")            # xor eax, eax
    a.db(b"\x0F\x05")            # SYS_LOG(args)——回显参数行
    a.jmp("prompt")
    a.label("echo_void")
    log_call(a, "s_evoid", len(EVOID_TEXT))
    a.jmp("prompt")

    # ---- S1 显示面：fb（映射 → 直画三色带 → 损伤屏障）----
    # 寄存器窗口（无 syscall 持有态）：r12 = 行 y 游标 / r13 = 列 x 游标 /
    # r14 = LFB 用户基址 / r15 = 当前写指针；rbx = 当前色。行带分色
    # （y<725 红 / y<746 绿 / 余蓝）——逐行选色一次，内环纯写。
    a.label("do_fb")
    # SYS_FB_MAP(rdi=0, rsi=FB_VA, rdx=0)
    a.db(b"\x31\xFF")                    # xor edi, edi
    a.db(b"\xBE", le32(FB_VA))            # mov esi, 0x40000000
    a.db(b"\x31\xD2")                    # xor edx, edx
    a.db(b"\xB8", le32(SYS_FB_MAP))       # mov eax, 35
    a.db(b"\x0F\x05")                    # syscall
    a.db(b"\x85\xC0")                    # test eax, eax
    a.jcc(JNE, "fb_fail")                 # 非零返码 → fb-err
    a.db(b"\x41\xBE", le32(FB_VA))        # mov r14d, 0x40000000（基址）
    a.db(b"\x41\xBC", le32(704))          # mov r12d, 704（首行）
    a.label("fb_row")
    a.db(b"\x41\x81\xFC", le32(725))      # cmp r12d, 725
    a.jcc(0x82, "fb_red")                 # jb → 红带
    a.db(b"\x41\x81\xFC", le32(746))      # cmp r12d, 746
    a.jcc(0x82, "fb_green")               # jb → 绿带
    a.db(b"\xBB", le32(0x000000FF))       # mov ebx, 蓝
    a.jmp("fb_have_color")
    a.label("fb_red")
    a.db(b"\xBB", le32(0x00FF0000))       # mov ebx, 红
    a.jmp("fb_have_color")
    a.label("fb_green")
    a.db(b"\xBB", le32(0x0000FF00))       # mov ebx, 绿
    a.label("fb_have_color")
    # r15 = r14 + (r12 << 12)（stride = 1024*4 = 0x1000 = 页粒度）
    a.db(b"\x45\x89\xE7")                 # mov r15d, r12d
    a.db(b"\x41\xC1\xE7\x0C")             # shl r15d, 12
    a.db(b"\x45\x01\xF7")                 # add r15d, r14d
    a.db(b"\x45\x31\xED")                 # xor r13d, r13d（x = 0）
    a.label("fb_px")
    a.db(b"\x41\x89\x1F")                 # mov [r15], ebx
    a.db(b"\x49\x83\xC7\x04")             # add r15, 4
    a.db(b"\x41\xFF\xC5")                 # inc r13d
    a.db(b"\x41\x81\xFD", le32(1024))     # cmp r13d, 1024
    a.jcc(0x82, "fb_px")                  # jb → 内环
    a.db(b"\x41\xFF\xC4")                 # inc r12d
    a.db(b"\x41\x81\xFC", le32(768))      # cmp r12d, 768
    a.jcc(0x82, "fb_row")                 # jb → 外环
    # SYS_FB_SYNC(rdi=0, rsi=704, rdx=1024, r10=64)——返回交盒字节数
    #（demo 断言锚点 LUMINA-FB-SYNC 落串口，返码不校验）
    a.db(b"\x31\xFF")                    # xor edi, edi
    a.db(b"\xBE", le32(704))              # mov esi, 704
    a.db(b"\xBA", le32(1024))             # mov edx, 1024
    a.db(b"\x41\xBA", le32(64))           # mov r10d, 64
    a.db(b"\xB8", le32(SYS_FB_SYNC))      # mov eax, 36
    a.db(b"\x0F\x05")                    # syscall
    log_call(a, "s_fbok", len(FBOK_TEXT))
    a.jmp("prompt")
    a.label("fb_fail")
    log_call(a, "s_fberr", len(FBERR_TEXT))
    a.jmp("prompt")

    # ---- S2 文本面：text（SYS_FB_TEXT 内核侧 8x16 字体直画横幅）----
    # SYS_FB_TEXT(a0=x=rdi, a1=y=rsi, a2=buf=rdx, a3=len=r10)；返回实渲染
    # 字符数（== len 即成功；ENODEV/EFAULT/EINVAL 皆 ≠ len → text-err）。
    # 无需先 MAP——内核侧经 FB_* 服务句柄直写 LFB（S1 Surface 为用户侧
    # 直画面；两者并存互不依赖）。y=560 落于三色带上方空白域。
    a.label("do_text")
    a.db(b"\xBF", le32(32))              # mov edi, 32（x）
    a.db(b"\xBE", le32(560))             # mov esi, 560（y）
    a.db(b"\xBA")                        # mov edx, s_banner（buf）
    a.abs32("s_banner")
    a.db(b"\x41\xBA", le32(len(BANNER_TEXT)))  # mov r10d, 15（len）
    a.db(b"\xB8", le32(SYS_FB_TEXT))     # mov eax, 37
    a.db(b"\x0F\x05")                    # syscall
    a.db(b"\x3D", le32(len(BANNER_TEXT)))  # cmp eax, 15
    a.jcc(JNE, "text_fail")              # 返码 ≠ 字符数 → text-err
    log_call(a, "s_textok", len(TEXTOK_TEXT))
    a.jmp("prompt")
    a.label("text_fail")
    log_call(a, "s_texterr", len(TEXTERR_TEXT))
    a.jmp("prompt")

    # ---- 派生共用臂：SPAWN → OK 位校验 → WAITPID 收割 → itoa 打印 ----
    a.label("do_spawn")
    a.db(b"\x31\xFF")                    # xor edi, edi（reserved = 0）
    a.db(b"\xB8", le32(SYS_SPAWN))       # mov eax, SYS_SPAWN
    a.db(b"\x0F\x05")
    a.db(b"\x41\x89\xC5")                # mov r13d, eax（pid 低 32 位）
    a.db(b"\x48\xC1\xE8\x20")            # shr rax, 32（OK 位域）
    a.db(b"\x48\x83\xF8\x01")            # cmp rax, 1
    a.jcc(JNE, "spawn_fail")

    a.label("wait")
    a.db(b"\x44\x89\xEF")               # mov edi, r13d（rdi = pid）
    a.db(b"\xB8", le32(SYS_WAIT_PID))   # mov eax, SYS_WAIT_PID
    a.db(b"\x0F\x05")                   # rax = OK_BIT|slot<<16|code&0xFFFF（打包面）
    a.db(b"\x25", le32(0xFFFF))         # and eax, 0xFFFF（低 16 位 = 退出码域）

    # itoa + 单调用组合打印：数字倒写至 0x402C1D 起首位（终结位固定），
    # 后补 CRLF @0x402C1E 与 "exit=" @r15-5，整行 "exit=<dec>\r\n" 一次
    # SYS_LOG 交付——serial_log_bytes 每调用追加 CRLF（console.rs:136），
    # 分次调用会把整行撒成多行（demo 断言与终端可读性双杀），必须组合。
    # 初版两败（LG=ptr/len 侦察行定案）：① r15 起点低一字 → 预减环下
    # 0x402C1D 成漏写缝，零页陈旧字节（'.'）混入内容；② imm16 字节序
    # 写反 → CRLF 变 LFCR。现起点 = NUM_END-2（首位数字落 0x402C1D 含），
    # CRLF @0x402C1E..1F，无缝隙全自写。
    a.db(b"\x41\xBF", le32(NUM_END - 2))  # mov r15d, 0x402C1E（预减后首写 0x402C1D）
    a.db(b"\xBB", le32(10))               # mov ebx, 10（零扩展至 rbx）
    a.label("itoa_loop")
    a.db(b"\x31\xD2")              # xor edx, edx
    a.db(b"\x48\xF7\xF3")          # div rbx
    a.db(b"\x80\xC2\x30")          # add dl, 0x30
    a.db(b"\x49\xFF\xCF")          # dec r15
    a.db(b"\x41\x88\x17")          # mov [r15], dl
    a.db(b"\x48\x85\xC0")          # test rax, rax
    a.jcc(JNZ, "itoa_loop")

    # 组合：mov dword [r15-5], 'exit'；mov byte [r15-1], '='；
    #       mov word [0x402C1E], 0x0A0D（CRLF 固定尾）
    a.db(b"\x41\xC7\x47\xFB", le32(0x74697865))  # 'exit' LE
    a.db(b"\x41\xC6\x47\xFF\x3D")                # '=' @ r15-1
    a.db(b"\x66\xC7\x04\x25", le32(NUM_END - 2), b"\x0D\x0A")  # imm16=0x0A0D LE → [1E]=\r [1F]=\n
    a.db(b"\x49\x8D\x7F\xFB")      # lea rdi, [r15-5]（rm=111+REX.B → r15；GNU as 对账）
    a.db(b"\xBE", le32(NUM_END))   # mov esi, NUM_END
    a.db(b"\x48\x29\xFE")          # sub rsi, rdi（整行长 = 5 + 数字位 + 2）
    a.db(b"\x31\xC0")              # xor eax, eax
    a.db(b"\x0F\x05")
    a.jmp("prompt")

    a.label("spawn_fail")
    log_call(a, "s_sperr", 11)
    a.jmp("prompt")

    # ---- 子代分支：信箱 → EXEC（成功不返回；信箱空回落 76）----
    a.label("child")
    a.db(b"\x8B\x04\x25", le32(MAILBOX))  # mov eax, [MAILBOX]
    a.db(b"\x85\xC0")                     # test eax, eax
    a.jcc(JE, "child_bail")
    a.db(b"\xFF\xC8")                     # dec eax（1 基 → 表索引）
    a.db(b"\x89\xC7")                     # mov edi, eax
    a.db(b"\xB8", le32(SYS_EXEC))         # mov eax, SYS_EXEC
    a.db(b"\x0F\x05")                     # 成功即不返回
    a.label("child_bail")
    a.db(b"\xBF", le32(EXEC_BAIL))        # mov edi, 76
    a.db(b"\xB8", le32(SYS_EXIT))
    a.db(b"\x0F\x05")
    a.db(b"\xEB\xFE")                     # jmp $

    # ---- 字符串区（页尾；abs32 引用）----
    for name, data in STRINGS:
        a.label(name)
        a.db(data)

    assert a.off <= 4096, f"image exceeds code page: {a.off}"
    return a.resolve()


def rust_array(name, blob, doc, attrs=""):
    lines = []
    if attrs:
        lines.append(attrs)
    lines += [f"/// {doc}", f"pub const {name}: [u8; {len(blob)}] = ["]
    for i in range(0, len(blob), 16):
        chunk = ", ".join(f"0x{b:02X}" for b in blob[i:i + 16])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def anchor(name, value, note):
    """文档锚点常量（双构建均不直接引用——dead_code 豁免，USER_IPC_PAYLOAD_VA 同款）。"""
    return f"#[allow(dead_code)] // {note}\npub const {name}: u64 = {value:#x};"


def main():
    init = build_init_image()
    parts = [
        "// 本文件由 scripts/gen_m23_images.py 生成——勿手改；重跑脚本再生成。",
        "// M23-②③ init（PID 1 ring3 shell）映像；交叉锚点常量与脚本头双向对账。",
        "",
        f"/// init shell 协议锚点（与 scripts/gen_m23_images.py 双向对账）：",
        "/// - 行缓冲 0x402E00 / 命令信箱 0x402F00（1 基映像号，0 = 无命令）",
        "/// - itoa 数字区尾 0x402C20（倒写）/ halt 终结码 0x10 / EXEC 回落码 76",
        anchor("INIT_LINE_BUF", LINE_BUF, "文档锚点：字节码内嵌 0x402E00 的常量定义源"),
        anchor("INIT_MAILBOX", MAILBOX, "文档锚点：字节码内嵌 0x402F00 的常量定义源"),
        anchor("INIT_NUM_END", NUM_END, "文档锚点：字节码内嵌 0x402C20 的常量定义源"),
        anchor("INIT_HALT_CODE", HALT_CODE, "文档锚点：halt 终结码（EXIT_SUCCESS 同源）"),
        anchor("INIT_EXEC_BAIL", EXEC_BAIL, "文档锚点：子代信箱空回落码"),
        "",
        rust_array(
            "INIT_IMAGE",
            init,
            "init shell 映像（M23-②③；位置固定 0x400000，单帧 RX + 栈帧）。\n"
            "/// 入口 r14 分向（0 = shell 主循环 / 非 0 = 派生子代 EXEC 信箱映像）。\n"
            "/// shell：prompt → GETCH 轮询（0 → YIELD）→ 首双字分派 halt/st/prog/\n"
            "/// grow/deep/ping/echo/ver/help/fb/err?；派生命令 = 信箱 + SPAWN + WAITPID\n"
            "/// 及 itoa 打印 exit=<dec>；echo 参数面（r12-5 字节原样回显，空域→(void)）；\n"
            "/// fb 显示面（SYS_FB_MAP 映射 → 64 行三色带直画 → SYS_FB_SYNC 损伤屏障）。\n"
            "/// 子代：读信箱 → EXEC(映像号) 成功不返回 → 回落 76。\n"
            "/// 字节码由 scripts/gen_m23_images.py 生成（objdump 已收口）。\n"
            "/// 默认批跑构建未引用（interactive 面专用）——dead_code 豁免。",
            attrs="#[cfg_attr(not(feature = \"interactive\"), allow(dead_code))]",
        ),
        "",
    ]
    OUT.write_text("\n".join(parts))
    print(f"INIT_IMAGE = {len(init)} bytes -> {OUT}")


if __name__ == "__main__":
    main()
