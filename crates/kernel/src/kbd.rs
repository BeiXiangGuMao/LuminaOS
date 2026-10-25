//! PS/2 键盘驱动（M23-①）——scancode set 1 翻译 + 无锁按键环形缓冲。
//!
//! 分层纪律：IRQ1 桩（ostd）读 scancode 后转交本模块钩子；翻译、
//! 环形缓冲、与 tty 的衔接全部在本模块。缓冲 = [`SpscRing`]（单生产
//! 者 = BSP IRQ1 桩体，单消费者 = tty 读侧），生产侧仅在 ISR 语境、
//! 消费侧仅在任务语境，各自单线程推进——SPSC 契约成立。
//!
//! 驱动旁路缩编首割（M31-N1）：scancode set 1 翻译面 crate 化外移至
//! `morse`（纯函数零依赖零 IO——ADR-0004 混合态渐进第一块可移动物）；
//! 本模块保留电气/机制面（IRQ1 钩子、环形缓冲、Shift 态寄存、注入面）。
//!
//! 自检注入面 [`inject`]：与 ISR 钩子走同一入环函数（差异仅触发源），
//! t64 据此对「scancode → 翻译 → 行规程 → 读侧」全链做活体断言，
//! 不依赖批跑环境的真实键入。

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
    feed(sc);
}

/// 自检/测试注入入口：与 ISR 同路径（feed → 翻译 → 入环）。
pub fn inject(sc: u8) {
    feed(sc);
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
