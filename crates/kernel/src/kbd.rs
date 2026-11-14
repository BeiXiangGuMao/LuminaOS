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
pub fn init() {
    ostd::interrupt::stubs::set_kbd_hook(on_scancode);
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
