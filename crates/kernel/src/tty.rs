//! TTY 行规程（M23-①）——键盘控制面字节 → 行编辑 → 行提交。
//!
//! 最小行规程：回显（可打印直写串口）、退格编辑（`\b \b` 抹迹）、
//! 回车行提交（`\n` 提交至就绪行缓冲，读侧 [`read_line`] 取走）。
//! 单行就绪面（一次一行）：shell 交互与 t64 断言均按「敲一行读一行」
//! 使用；双缓冲（编辑态 / 就绪态）分离使读侧与编辑态无共享。
//!
//! 消费链：`kbd::pop()`（SPSC 单消费者 = 本模块轮询方）→ [`feed`] →
//! 行缓冲；读侧与喂侧同在任务语境（t64 自检 / M23-② syscall 臂），
//! 单线程契约由调用序保证。

/// 行缓冲容量（shell 命令行上限；超出丢弃并响铃占位）。
const LINE_CAP: usize = 128;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// 编辑态行缓冲 + 长度。
static mut LINE_BUF: [u8; LINE_CAP] = [0; LINE_CAP];
static LINE_LEN: AtomicUsize = AtomicUsize::new(0);

/// 就绪行缓冲 + 长度 + 就绪旗（行提交 ↔ 读侧取走的握手面）。
static mut READY_BUF: [u8; LINE_CAP] = [0; LINE_CAP];
static READY_LEN: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);

/// t64 取证：行提交计数。
pub static LINES_SUBMITTED: AtomicUsize = AtomicUsize::new(0);

/// 串口回显（免分配逐字节；控制字节过滤复用 serial_log_bytes 语义）。
fn echo(bytes: &[u8]) {
    crate::console::serial_log_bytes(bytes);
}

/// 行规程喂入口：单字节处理（编辑态推进 + 回显）。
pub fn feed(b: u8) {
    match b {
        b'\n' => submit(),
        0x08 => {
            let len = LINE_LEN.load(Ordering::Acquire);
            if len > 0 {
                LINE_LEN.store(len - 1, Ordering::Release);
                echo(b"\x08 \x08");
            }
        }
        0x20..=0x7E => {
            let len = LINE_LEN.load(Ordering::Acquire);
            if len < LINE_CAP {
                // SAFETY: 单写者（喂侧任务语境）；读侧只见就绪面。
                // 裸指针 add 偏移（避开 static_mut_refs 语义）。
                unsafe { *(&raw mut LINE_BUF as *mut u8).add(len) = b };
                LINE_LEN.store(len + 1, Ordering::Release);
                echo(&[b]);
            }
        }
        _ => {} // 其余控制字节忽略（Tab 等后续版本按需扩展）
    }
}

/// 行提交：编辑态 → 就绪面（旗后置——读侧以 READY 为准）。
fn submit() {
    echo(b"\r\n");
    let len = LINE_LEN.load(Ordering::Acquire);
    // SAFETY: 喂侧单写者；提交与读取由 READY 旗互斥推进。
    unsafe {
        core::ptr::copy_nonoverlapping(
            (&raw const LINE_BUF) as *const u8,
            (&raw mut READY_BUF) as *mut u8,
            len,
        );
    }
    READY_LEN.store(len, Ordering::Release);
    READY.store(true, Ordering::Release);
    LINE_LEN.store(0, Ordering::Release);
    LINES_SUBMITTED.fetch_add(1, Ordering::Relaxed);
}

/// 非阻塞取就绪行：`READY` 时取走（清旗）返回 Some(len)，否则 None。
pub fn read_line(buf: &mut [u8]) -> Option<usize> {
    if !READY.swap(false, Ordering::AcqRel) {
        return None;
    }
    let len = READY_LEN.load(Ordering::Acquire).min(buf.len());
    // SAFETY: READY 旗握手保证读侧独占（提交面已写毕）。
    let src = unsafe { core::slice::from_raw_parts((&raw const READY_BUF) as *const u8, len) };
    buf[..len].copy_from_slice(src);
    Some(len)
}

/// 泵一轮：kbd 环 → 行规程（喂侧主循环；M23-② 起 syscall 臂同构复用）。
pub fn pump() {
    while let Some(b) = crate::kbd::pop() {
        feed(b);
    }
}
