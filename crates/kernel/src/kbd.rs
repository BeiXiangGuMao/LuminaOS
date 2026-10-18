//! PS/2 键盘驱动（M23-①）——scancode set 1 翻译 + 无锁按键环形缓冲。
//!
//! 分层纪律：IRQ1 桩（ostd）读 scancode 后转交本模块钩子；翻译、
//! 环形缓冲、与 tty 的衔接全部在本模块。缓冲 = [`SpscRing`]（单生产
//! 者 = BSP IRQ1 桩体，单消费者 = tty 读侧），生产侧仅在 ISR 语境、
//! 消费侧仅在任务语境，各自单线程推进——SPSC 契约成立。
//!
//! 自检注入面 [`inject`]：与 ISR 钩子走同一入环函数（差异仅触发源），
//! t64 据此对「scancode → 翻译 → 行规程 → 读侧」全链做活体断言，
//! 不依赖批跑环境的真实键入。

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
fn feed(sc: u8) {
    const RELEASE: u8 = 0x80;
    match sc {
        0x2A | 0x36 => {
            SHIFT.store(true, core::sync::atomic::Ordering::Relaxed);
            return;
        }
        // 释放码 = 按下码 | 0x80：左 Shift 0xAA / 右 Shift 0xB6。
        0xAA | 0xB6 => {
            SHIFT.store(false, core::sync::atomic::Ordering::Relaxed);
            return;
        }
        _ if sc & RELEASE != 0 => return, // 其余释放事件忽略
        _ => {}
    }
    let shift = SHIFT.load(core::sync::atomic::Ordering::Relaxed);
    let ch = translate(sc, shift);
    if let Some(b) = ch {
        if KBD_RING.send(b).is_err() {
            KBD_DROP.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// 非阻塞单键读取（tty 消费侧）。
pub fn pop() -> Option<u8> {
    KBD_RING.recv()
}

/// scancode set 1 → ASCII 最小翻译表（按下态；Shift 影响字母与数字行）。
fn translate(sc: u8, shift: bool) -> Option<u8> {
    let c = match sc {
        // 数字行（Shift = 符号最小集）
        0x02 => {
            if shift {
                b'!'
            } else {
                b'1'
            }
        }
        0x03 => {
            if shift {
                b'@'
            } else {
                b'2'
            }
        }
        0x04 => {
            if shift {
                b'#'
            } else {
                b'3'
            }
        }
        0x05 => {
            if shift {
                b'$'
            } else {
                b'4'
            }
        }
        0x06 => {
            if shift {
                b'%'
            } else {
                b'5'
            }
        }
        0x07 => {
            if shift {
                b'^'
            } else {
                b'6'
            }
        }
        0x08 => {
            if shift {
                b'&'
            } else {
                b'7'
            }
        }
        0x09 => {
            if shift {
                b'*'
            } else {
                b'8'
            }
        }
        0x0A => {
            if shift {
                b'('
            } else {
                b'9'
            }
        }
        0x0B => {
            if shift {
                b')'
            } else {
                b'0'
            }
        }
        0x0C => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
        0x0D => {
            if shift {
                b'+'
            } else {
                b'='
            }
        }
        0x0E => 0x08,  // Backspace
        0x0F => b'\t', // Tab
        0x1C => b'\n', // Enter
        0x39 => b' ',  // Space
        0x33 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        0x34 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        0x35 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        0x27 => {
            if shift {
                b':'
            } else {
                b';'
            }
        }
        0x28 => {
            if shift {
                b'"'
            } else {
                b'\''
            }
        }
        0x29 => {
            if shift {
                b'~'
            } else {
                b'`'
            }
        }
        0x2B => {
            if shift {
                b'|'
            } else {
                b'\\'
            }
        }
        0x1A => {
            if shift {
                b'{'
            } else {
                b'['
            }
        }
        0x1B => {
            if shift {
                b'}'
            } else {
                b']'
            }
        }
        // QWERTY 三行（Shift = 大写；0x27/0x28/0x29 已在符号行先匹配）
        0x10..=0x19 | 0x1E..=0x26 | 0x2C..=0x32 => {
            let base = match sc {
                0x10..=0x19 => b"qwertyuiop"[(sc - 0x10) as usize],
                0x1E..=0x26 => b"asdfghjkl"[(sc - 0x1E) as usize],
                _ => b"zxcvbnm"[(sc - 0x2C) as usize],
            };
            if shift {
                base - 32
            } else {
                base
            }
        }
        _ => return None,
    };
    Some(c)
}
