//! PS/2 键盘驱动（M23-①）——scancode set 1 翻译 + 无锁按键环形缓冲。
//!
//! 分层纪律：IRQ1 桩（ostd）读 scancode 后转交本模块钩子；翻译、
//! 环形缓冲、与 tty 的衔接全部在本模块。缓冲 = [`SpscRing`]（单生产
//! 者 = BSP IRQ1 桩体，单消费者 = tty 读侧），生产侧仅在 ISR 语境、
//! 消费侧仅在任务语境，各自单线程推进——SPSC 契约成立。
//!
//! **双车道分域**（M42-WAYCOMP17 笔⑰——kbd→waycomp 转接臂落域）：
//! IRQ1 桩体转交点双投递——〔tty 车道 [`feed`]：scancode → 翻译 →
//! ASCII 控制面 → [`KBD_RING`]（既有，行规程读侧消费）〕+〔waycomp
//! 车道 [`forward_waycomp`]：键态语义直传（释放位剥离 → state 0/1
//! 编码）→ [`crate::waycomp::input_key_isr`] ISR 臂（会话环 drain
//! 消费）。两车道独立消费互不相扰；ISR 语境纪律由臂面承载（内核语
//! 境旗随批 + try_lock 有界退避随批——waycomp 模块文档同源）。
//!
//! 驱动旁路缩编首割（M31-N1）：scancode set 1 翻译面 crate 化外移至
//! `morse`（纯函数零依赖零 IO——ADR-0004 混合态渐进第一块可移动物）；
//! 本模块保留电气/机制面（IRQ1 钩子、环形缓冲、Shift 态寄存、注入面）。
//!
//! 自检注入面 [`inject`]：与 ISR 钩子走同一入环函数（差异仅触发源），
//! t64 据此对「scancode → 翻译 → 行规程 → 读侧」全链做活体断言，
//! 不依赖批跑环境的真实键入。**ISR 臂面 [`inject_isr`]**（笔⑰）：与
//! IRQ1 桩体全谱同路径（on_scancode 双车道——feed + 转接臂，差异仅
//! 触发源），t118 据此对 ISR 臂全链做活体断言。
//!
//! **PS/2 aux（IRQ12）电气源接线域**（M42-AUX25 笔㉕）：IRQ12 桩体
//! （ostd，源位判读 + 级联双 EOI）→ [`on_aux_byte`] → [`AUX_RING`]
//! 原始字节环（驱动车道——未来 aux 驱动进程消费域）。**双车道扩谱**
//! （笔㉔挂账「kbd.rs 双车道接线随 aux 驱动批次」兑现任务面）：
//! 〔电气车道 [`on_aux_byte`]：IRQ12 桩体 → 原始字节入环〕+
//! 〔指针生产车道 [`aux_pump`]：三字节包状态机（标准 PS/2 兼容鼠
//! 标包：字节 0 bit3 恒 1 + 按钮位 + 溢出位，字节 1/2 = dx/dy 9 位
//! 二补）→ 增量累积光标绝对坐标（屏域钳制）→
//! [`crate::waycomp::input_pointer_motion`] / [`input_pointer_button`]
//! 任务语境生产出线——waycomp 会话环 drain 消费〕。包状态机 = 任务
//! 语境消费域（[`aux_pump`]——waycomp drain 前置泵 + 测试直调双
//! 入口；ISR 语境零重活纪律保持——桩体只做源位判读 + 入环）。溢出
//! 包（bit6/7）整包丢弃 fail-visible（[`AUX_OVF`]）；中包杂码重同
//! 步（[`AUX_RESYNC`]）；注入面 [`inject_aux`] 与 IRQ12 桩体全谱同
//! 路径（t125 活体承载——批跑无鼠标输入无副作用）。

use morse::{is_release, shift_event, translate};
use ostd::sync::spsc::SpscRing;

/// 按键环形缓冲深度（64 键 = 行编辑充足余量；溢出静默丢弃并计数）。
const KBD_CAP: usize = 64;

/// 无锁按键环（元素 = 翻译后的 ASCII 控制面字节）。
static KBD_RING: SpscRing<u8, KBD_CAP> = SpscRing::new();

/// 环满丢弃计数（取证面：消费者侧读取，溢出可观测）。
pub static KBD_DROP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 当前 Shift 按下态（0x2A 左 / 0x36 右；释放位 bit7=1 清除）。
static SHIFT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// t64 取证：中断驱动入环计数（IRQ1 活体触发面，批跑环境通常为 0）。
pub static KBD_IRQ_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 初始化：注册 IRQ1 桩钩子（PIC 解 mask 由 interrupts 初始化序负责）。
/// M42-AUX25 笔㉕随批：IRQ12 aux 钩子同序注册（电气源接线就位）。
pub fn init() {
    ostd::interrupt::stubs::set_kbd_hook(on_scancode);
    ostd::interrupt::stubs::set_aux_hook(on_aux_byte);
}

/// IRQ1 桩体转交点（ostd 钩子）：原始 scancode 入口。
fn on_scancode(sc: u8) {
    KBD_IRQ_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    feed(sc); // tty 车道（既有——scancode → 翻译 → ASCII 控制面）
    forward_waycomp(sc); // waycomp 转接臂车道（笔⑰——键态语义直传）
}

/// waycomp 转接臂出线（M42-WAYCOMP17 笔⑰）：IRQ1 桩体 → waycomp 输
/// 入队列 ISR 臂——键态语义直传（释放位 bit7 剥离 → state 0/1 编码
/// ——waycomp 会话域 modifiers 语义核自带修饰键态机〔笔⑮〕，kbd
/// SHIFT 寄存面为 tty 车道域不跨车道；0xE0 前缀扩展域字节原样直传
/// ——evdev 域外拒收 UNMAPPED 取证 fail-visible，扩展域挂账既录维
/// 持）。ISR 语境纪律由臂面承载（内核语境旗随批 + try_lock 有界退
/// 避随批——[`crate::waycomp::input_key_isr`]）。返回臂受理值（入环
/// 成功 = true；退避耗尽/队满 = false——丢弃域 fail-visible 可辨）。
fn forward_waycomp(sc: u8) -> bool {
    let (code, state) = if sc & 0x80 != 0 {
        (sc & 0x7F, 0u32) // 释放域：bit7 剥离 → state=0
    } else {
        (sc, 1u32) // 按下域：state=1
    };
    crate::waycomp::input_key_isr(code, state)
}

/// 自检/测试注入入口：与 ISR 同路径（feed → 翻译 → 入环）。
pub fn inject(sc: u8) {
    feed(sc);
}

/// 自检/测试注入入口（M42-WAYCOMP17 笔⑰——ISR 臂面）：与 IRQ1 桩体
/// 全谱同路径（on_scancode 三步同序——IRQ 计数随行 + feed + 转接臂，
/// 差异仅触发源；t64 inject 先例同谱扩展——v0 inject 仅 tty 单车道）。
/// 返回臂受理值（t118 据此对 ISR 臂全链做活体断言——(c) 争用域
/// accepted=false 断言消费）。钩子签名约束：on_scancode 保持 fn(u8)
/// 桩体形态——本入口为三步同序展开，路径等价。
pub fn inject_isr(sc: u8) -> bool {
    KBD_IRQ_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    feed(sc);
    forward_waycomp(sc)
}

/// 统一入口：scancode set 1 翻译 → ASCII 控制面 → 入环。
///
/// 只处理按下事件（bit7=1 的释放事件仅维护 Shift 态）；非映射键
/// 静默忽略。控制面：`\n`（0x1C Enter）、`\x08`（0x0E Backspace）、
/// 可打印 ASCII（字母大小写随 Shift、数字行符号随 Shift 最小集）。
/// 翻译表与事件分类在 `morse`（M31-N1 外移）；Shift 态寄存留本模块
/// （电气侧相邻状态——ISR 语境单写，任务语境单读，AtomicBool 契约）。
fn feed(sc: u8) {
    if let Some(down) = shift_event(sc) {
        SHIFT.store(down, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    if is_release(sc) {
        return; // 其余释放事件忽略
    }
    let shift = SHIFT.load(core::sync::atomic::Ordering::Relaxed);
    if let Some(b) = translate(sc, shift) {
        if KBD_RING.send(b).is_err() {
            KBD_DROP.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// 非阻塞单键读取（tty 消费侧）。
pub fn pop() -> Option<u8> {
    KBD_RING.recv()
}

/// 键环非空判定（M41-笔④ tty 阻塞读探针消费面）。
pub fn avail() -> bool {
    !KBD_RING.is_empty()
}

/// 字节直注入（M41-笔④ t100 装置面）：绕过 scancode 翻译直入键环
/// （ASCII 控制面字节——与 feed 出口同域；SPSC 生产者侧 = 注入方
/// 任务语境，批跑无真实键入 = 事实单生产者，契约保持如实登记）。
/// 入环后唤醒 tty 阻塞读等待者（任务语境 wake——先注入后读者时序
/// 由登记窗探针免疫兜底，先读者后注入时序由本唤醒承载）。
pub fn inject_raw(b: u8) {
    if KBD_RING.send(b).is_err() {
        KBD_DROP.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    crate::task::wake_tasks(|w| matches!(w, crate::task::WaitWhat::TtyRead));
}

// ---- M42-AUX25 笔㉕：PS/2 aux（IRQ12）电气源接线域 ----

/// aux 原始字节环深度（64 字节 = 包流缓冲余量；溢出丢弃计数显形）。
const AUX_CAP: usize = 64;

/// aux 原始字节环（驱动车道——IRQ12 桩体单生产 ISR 语境 / [`aux_pump`]
/// 单消费任务语境，SPSC 契约成立；注入面批跑域事实单生产者纪律同
/// [`inject_raw`] 先例如实登记）。
static AUX_RING: SpscRing<u8, AUX_CAP> = SpscRing::new();

/// IRQ12 电气源触发计数（t125 静态对账面；批跑环境通常为 0——无鼠
/// 标输入，t64 [`KBD_IRQ_COUNT`] 同口径）。
pub static AUX_IRQ_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// aux 环满丢弃计数（消费域停滞窗溢出显形——fail-visible）。
pub static AUX_DROP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 解码包产出计数（指针生产车道活体取证——t125 断言面）。
pub static AUX_PACKETS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 溢出整包丢弃计数（字节 0 bit6/7 溢出位在场——fail-visible）。
pub static AUX_OVF: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 中包杂码重同步计数（包流对齐失步——bit3 恒 1 契约面）。
pub static AUX_RESYNC: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// aux 光标绝对坐标 x（增量累积 + 屏域钳制——[`crate::fb::WIDTH`]）。
static AUX_CUR_X: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// aux 光标绝对坐标 y（增量累积 + 屏域钳制——[`crate::fb::HEIGHT`]；
/// PS/2 dy 正值 = 向上 = 屏 y 递减方向，极性反转在包出口）。
static AUX_CUR_Y: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

/// 上包按钮位（bit0 left / bit1 right / bit2 middle——沿检测寄存面）。
static AUX_BTN_PREV: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 包状态机态（0 = 等包头 / 1 = 已收包头 / 2 = 已收 dx / 3 = 溢出吞字节）。
static AUX_ST: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// 包头暂存（按钮位 + 符号位——出包域消费）。
static AUX_HEAD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// dx 暂存。
static AUX_DX: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// 溢出包待吞字节计数（包头后 dx/dy 两字节——整包丢弃域）。
static AUX_SKIP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 包状态机互斥（[`aux_pump`] 双入口串行化——waycomp drain 前置泵 +
/// 测试直调并发窗；锁窗 = 状态机步进 + 指针生产即放，零嵌套持有：
/// [`crate::waycomp::input_pointer_motion`] 内 IN_MU → SCHED 单向序
/// 在本锁窗内展开，锁序 AUX_ST_MU → IN_MU → SCHED 单向不回环）。
static AUX_ST_MU: ostd::sync::SpinLock<u32> = ostd::sync::SpinLock::new(0);

/// IRQ12 桩体转交点（ostd 钩子）：原始 aux 字节入口（电气车道）。
fn on_aux_byte(b: u8) {
    AUX_IRQ_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if AUX_RING.send(b).is_err() {
        AUX_DROP.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    // AuxRead 阻塞唤醒（M42-AUXR3——IRQ12 出字域；接管态下唯一消费
    // 者 = ring3 驱动，ISR 语境 wake_tasks 可达〔CompIn 同谱先例〕）。
    crate::task::wake_tasks(|w| matches!(w, crate::task::WaitWhat::AuxRead));
}

/// 自检/测试注入入口（M42-AUX25 笔㉕）：与 IRQ12 桩体全谱同路径
/// （IRQ 计数随行 + 入环，差异仅触发源；t125 活体承载——v0 批跑无
/// 鼠标输入，事实单生产者纪律同 [`inject_raw`] 先例如实登记）。
pub fn inject_aux(b: u8) {
    on_aux_byte(b);
}

/// aux 光标绝对坐标读面（增量累积域对账——t125 断言面）。
pub fn aux_cursor() -> (i32, i32) {
    (
        AUX_CUR_X.load(core::sync::atomic::Ordering::Acquire),
        AUX_CUR_Y.load(core::sync::atomic::Ordering::Acquire),
    )
}

/// aux 计数读面（packets, ovf, resync, drop, irq——t125 全谱对账）。
pub fn aux_counts() -> (usize, usize, usize, usize, usize) {
    (
        AUX_PACKETS.load(core::sync::atomic::Ordering::Acquire),
        AUX_OVF.load(core::sync::atomic::Ordering::Acquire),
        AUX_RESYNC.load(core::sync::atomic::Ordering::Acquire),
        AUX_DROP.load(core::sync::atomic::Ordering::Acquire),
        AUX_IRQ_COUNT.load(core::sync::atomic::Ordering::Acquire),
    )
}

// ---- M42-AUXR3 笔㉚：ring3 aux 驱动消费车道（接管态仲裁域）----

/// 环属主旗（boot 双轨回归锚纪律——默认 false = 内核 aux_pump 车道
/// 持有〔t125 断言面原貌〕；显式声明才移交 ring3 aux-svc-elf 驱动。
/// 声明面 = 内核内部仲裁 [`aux_elf_claim`]——ABI 面不设接管臂，ring3
/// 不可改写环属主）。
static AUX_ELF_OWNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 接管声明/释放（内核内部仲裁面——t130 活体显式切换； wahr 冪等）。
pub fn aux_elf_claim(on: bool) {
    AUX_ELF_OWNED.store(on, core::sync::atomic::Ordering::Release);
    // AuxRead 阻塞唤醒（claim 双向——接管放行消费域 / 释放回收哨兵
    // 让步域；wake_tasks 自带 IntWindow，任务语境可达）。
    crate::task::wake_tasks(|w| matches!(w, crate::task::WaitWhat::AuxRead));
}

/// 接管态读面（t130 对账域）。
pub fn aux_elf_owned() -> bool {
    AUX_ELF_OWNED.load(core::sync::atomic::Ordering::Acquire)
}

/// [`SYS_AUX_READ`](bedrock::abi::SYS_AUX_READ) 承接面：ring3 aux 驱
/// 动单字节读出（**阻塞式**——M42-AUXR3 揭雷收口）。三态语义：接管
/// 未声明 → `AUX_RET_NOT_OWNER` 立返后**登记阻塞**（AuxRead 等待——
/// claim 唤醒；v0 轮询口径退役——boot 忙式 idle 环 ~37k polls/s 调度
/// 洪水拉宽 exit_current→Zombie 竞窗〔t95 早退实录〕+ t124 短收）；
/// 接管声明 → 环出单字节 / 环空登记阻塞（on_aux_byte/inject_aux 唤
/// 醒）。探针 = 接管态与环空双读零锁（CompIn 探针同款纪律——SCHED 锁
/// 窗内零 AUX_ST_MU 取锁，锁序 AUX_ST_MU → SCHED 单向保持）。SPSC 单
/// 消费者契约：接管态下唯一消费者 = ring3 驱动（内核 aux_pump 同期零
/// 消费）。返回：字节 0..=255 / AUX_RET_NOT_OWNER / AUX_RET_EMPTY
/// （唤醒后竞窗域——驱动侧让步重试承载）。
pub fn sys_aux_read() -> u64 {
    use bedrock::abi::{AUX_RET_EMPTY, AUX_RET_NOT_OWNER};
    if !AUX_ELF_OWNED.load(core::sync::atomic::Ordering::Acquire) {
        // 未接管：立返哨兵 + 登记 AuxRead 阻塞（claim 唤醒——idle 零
        // CPU 零扰动，RESIDENT/ACCEPT_B 同族形态）。
        crate::task::block_current_unless(crate::task::WaitWhat::AuxRead, true, || {
            !AUX_ELF_OWNED.load(core::sync::atomic::Ordering::Acquire)
        });
        return AUX_RET_NOT_OWNER;
    }
    match AUX_RING.recv() {
        Some(b) => u64::from(b),
        None => {
            // 接管但环空：登记阻塞（on_aux_byte/inject_aux 唤醒）。
            crate::task::block_current_unless(crate::task::WaitWhat::AuxRead, true, || {
                AUX_ELF_OWNED.load(core::sync::atomic::Ordering::Acquire) && AUX_RING.is_empty()
            });
            AUX_RET_EMPTY
        }
    }
}

/// aux 环深度读面（驱动车道待消费字节——t125 排空对账）。
pub fn aux_pending() -> usize {
    AUX_RING.len()
}

/// 指针生产车道（M42-AUX25 笔㉕双车道扩谱任务面）：排空 [`AUX_RING`]
/// → 三字节包状态机 → 增量累积光标绝对坐标（屏域钳制）→
/// [`crate::waycomp::input_pointer_motion`] / [`input_pointer_button`]
/// 任务语境生产出线。返回本轮解码包数。
///
/// 包格式（标准 PS/2 兼容鼠标流——QEMU i8042 第二通道默认形）：
/// 字节 0 = bit3 恒 1 + bit6/7 溢出位 + bit4/5 dx/dy 符号位 +
/// bit0/1/2 左/右/中按钮；字节 1 = dx（9 位二补低 8 位）；字节 2 =
/// dy。正 dy = 向上（屏 y 递减）——极性反转在包出口。
///
/// 调用域 = 任务语境（waycomp drain 前置泵 + t125 直调——ISR 语境
/// 零重活纪律：桩体只做源位判读 + 入环，状态机全谱在此）。互斥 =
/// [`AUX_ST_MU`]（双入口串行化——锁窗内指针生产 IN_MU 单向序展开）。
pub fn aux_pump() -> usize {
    // M42-AUXR3 笔㉚接管态让步门（boot 双轨回归锚纪律——ring3 驱动
    // 持有期内核车道零消费零争抢：单消费者契约以属主旗承载；显形计
    // 数域 fail-visible，零静默）。
    if AUX_ELF_OWNED.load(core::sync::atomic::Ordering::Acquire) {
        return 0;
    }
    let _g = AUX_ST_MU.lock();
    let mut produced = 0usize;
    while let Some(b) = AUX_RING.recv() {
        match AUX_ST.load(core::sync::atomic::Ordering::Acquire) {
            0 => {
                if b & 0x08 == 0 {
                    // 包流对齐失步（bit3 恒 1 契约面）——fail-visible
                    // 重同步（字节丢弃，态不变）。
                    AUX_RESYNC.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                } else if b & 0xC0 != 0 {
                    // 溢出包（bit6/7）整包丢弃——包头后 dx/dy 两字节
                    // 吞没域（流对齐保持）。
                    AUX_OVF.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    AUX_SKIP.store(2, core::sync::atomic::Ordering::Relaxed);
                    AUX_ST.store(3, core::sync::atomic::Ordering::Release);
                } else {
                    AUX_HEAD.store(b, core::sync::atomic::Ordering::Relaxed);
                    AUX_ST.store(1, core::sync::atomic::Ordering::Release);
                }
            }
            1 => {
                AUX_DX.store(b, core::sync::atomic::Ordering::Relaxed);
                AUX_ST.store(2, core::sync::atomic::Ordering::Release);
            }
            2 => {
                // 出包域：符号扩展 + 极性反转 + 屏域钳制 + 指针生产。
                let head = AUX_HEAD.load(core::sync::atomic::Ordering::Relaxed);
                let dx_raw = AUX_DX.load(core::sync::atomic::Ordering::Relaxed);
                let dxi = if head & 0x10 != 0 {
                    i32::from(dx_raw) - 256
                } else {
                    i32::from(dx_raw)
                };
                let dyi = if head & 0x20 != 0 {
                    i32::from(b) - 256
                } else {
                    i32::from(b)
                };
                let w = crate::fb::WIDTH as i32;
                let h = crate::fb::HEIGHT as i32;
                let nx =
                    (AUX_CUR_X.load(core::sync::atomic::Ordering::Acquire) + dxi).clamp(0, w - 1);
                // 正 dy = 向上 = 屏 y 递减（PS/2 极性反转在包出口）。
                let ny =
                    (AUX_CUR_Y.load(core::sync::atomic::Ordering::Acquire) - dyi).clamp(0, h - 1);
                AUX_CUR_X.store(nx, core::sync::atomic::Ordering::Release);
                AUX_CUR_Y.store(ny, core::sync::atomic::Ordering::Release);
                // 指针生产出线（受理域 fail-visible 由 waycomp 计数戳
                // 承载——队满丢弃可辨）。
                let _ = crate::waycomp::input_pointer_motion(nx, ny);
                // 按钮沿检测（bit0/1/2 → evdev BTN_LEFT/RIGHT/MIDDLE）。
                let btns = usize::from(head & 0x07);
                let prev = AUX_BTN_PREV.load(core::sync::atomic::Ordering::Acquire);
                for bit in 0..3u32 {
                    let mask = 1usize << bit;
                    if btns & mask != prev & mask {
                        let code = match bit {
                            0 => 0x110u32, // BTN_LEFT
                            1 => 0x111u32, // BTN_RIGHT
                            _ => 0x112u32, // BTN_MIDDLE
                        };
                        let state = if btns & mask != 0 { 1 } else { 0 };
                        let _ = crate::waycomp::input_pointer_button(code, state);
                    }
                }
                AUX_BTN_PREV.store(btns, core::sync::atomic::Ordering::Release);
                AUX_PACKETS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                produced += 1;
                AUX_ST.store(0, core::sync::atomic::Ordering::Release);
            }
            _ => {
                // 溢出吞字节域（3）：dx/dy 两字节静默吞没——流对齐保持。
                let left = AUX_SKIP.load(core::sync::atomic::Ordering::Acquire);
                if left <= 1 {
                    AUX_SKIP.store(0, core::sync::atomic::Ordering::Relaxed);
                    AUX_ST.store(0, core::sync::atomic::Ordering::Release);
                } else {
                    AUX_SKIP.store(left - 1, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }
    produced
}
