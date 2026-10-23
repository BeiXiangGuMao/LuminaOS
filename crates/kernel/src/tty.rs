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

use ostd::sync::spsc::SpscRing;

/// 编辑态行缓冲 + 长度。
static mut LINE_BUF: [u8; LINE_CAP] = [0; LINE_CAP];
static LINE_LEN: AtomicUsize = AtomicUsize::new(0);

/// 就绪行缓冲 + 长度 + 就绪旗（行提交 ↔ 读侧取走的握手面）。
static mut READY_BUF: [u8; LINE_CAP] = [0; LINE_CAP];
static READY_LEN: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);

/// t64 取证：行提交计数。
pub static LINES_SUBMITTED: AtomicUsize = AtomicUsize::new(0);

/// GETCH 消费缓冲容量（= 行缓冲容量；就绪行整体接管后逐字节消费）。
const GETCH_CAP: usize = LINE_CAP;

/// GETCH 消费态：活动行缓冲 + 行长 + 消费游标。
///
/// 游标语义 = [`SYS_TTY_GETCH`]（abi v0.20）：`usize::MAX` = 无活动行；
/// `0..=len` = 消费位（`cur == len` 为 `\n` 终结虚位——消费即复位）。
/// 单消费者契约：init shell（M23-②）为唯一长期消费方，t65 自检在
/// init 派生前完成（串行无并发；多消费者竞争面属后续里程碑）。
static mut GETCH_BUF: [u8; GETCH_CAP] = [0; GETCH_CAP];
static GETCH_LEN: AtomicUsize = AtomicUsize::new(0);
static GETCH_CURSOR: AtomicUsize = AtomicUsize::new(usize::MAX);

/// 串口回显（M23-② 改 raw 直写：serial_log_bytes 每调用追加 CRLF +
/// 控制字节换 '.'，会把逐键回显撕成多行并抹掉退格三连——终端可读性
/// 与行编辑体验双杀；serial_send_raw 零翻译逐字节保真，TLV 同款路径）。
fn echo(bytes: &[u8]) {
    crate::console::serial_send_raw(bytes);
}

/// 行规程喂入口：单字节处理（编辑态推进 + 回显）。
///
/// M24-A1 行规程扩展：**分页态**优先——武装旗置位期间，键不入行编辑
/// 也不回显，改投分页键队列（`more` 键面：任意键翻页、q 族键中止）。
/// 生产侧 = [`pump`]（键盘环消费点，任务语境），消费侧 = shell 分页
/// 等键环（[`crate::shell::pager_replay`]，同任务串行）——单任务
/// 契约与 [`getch`] 消费面同源（M23-② 纪律）。
pub fn feed(b: u8) {
    if PAGER_ARMED.load(Ordering::Acquire) {
        if PAGER_KEYS.send(b).is_err() {
            PAGER_DROP.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
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

/// SYS_TTY_GETCH 主体（M23-②）：泵一轮后按消费游标取下一字节。
///
/// 返回域见 abi [`bedrock::abi::SYS_TTY_GETCH`] 文档：`0` = 暂无数据；
/// `0x01..=0xFF` = 行内字节或行终结 `\n`（虚位）。行提交由 IRQ1 异步
/// 推进，本函数全非阻塞——交互方（init shell）以 `0 → SYS_YIELD →
/// 重试` 轮询推进。
pub fn getch() -> u64 {
    // 先泵：键盘环残余字节入行规程（IRQ1 与消费方异步，泵点收敛）。
    pump();
    // 无活动行 → 尝试接管新就绪行（READY 旗握手，与 read_line 同纪律）。
    if GETCH_CURSOR.load(Ordering::Acquire) == usize::MAX {
        if !READY.swap(false, Ordering::AcqRel) {
            return 0; // 暂无数据（非阻塞轮询语义）
        }
        let len = READY_LEN.load(Ordering::Acquire);
        // SAFETY: READY 旗握手保证提交面写毕且本侧独占（单消费者契约：
        // init shell / t65 串行消费，与 read_line 的单线程契约同源）。
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&raw const READY_BUF) as *const u8,
                (&raw mut GETCH_BUF) as *mut u8,
                len,
            );
        }
        GETCH_LEN.store(len, Ordering::Release);
        GETCH_CURSOR.store(0, Ordering::Release);
        if len == 0 {
            // 空行（裸回车）：行体零字节，本取即终结符。
            GETCH_CURSOR.store(usize::MAX, Ordering::Release);
            return u64::from(b'\n');
        }
    }
    // 活动行消费位域 [0, len]：cur < len 取缓冲字节；cur == len 取
    // `\n` 终结虚位（消费即复位游标——下一取重走接管面）。
    let cur = GETCH_CURSOR.load(Ordering::Acquire);
    let len = GETCH_LEN.load(Ordering::Acquire);
    let b = if cur < len {
        // SAFETY: cur < len ≤ GETCH_CAP；游标由本函数单消费者推进。
        unsafe { *(&raw const GETCH_BUF as *const u8).add(cur) }
    } else {
        b'\n'
    };
    let next = if cur < len { cur + 1 } else { usize::MAX };
    GETCH_CURSOR.store(next, Ordering::Release);
    u64::from(b)
}

// ---- M24-A1 行规程扩展：分页态（`more` 键面） ----
//
// 武装旗 + 分页键队列：`more` 重放期间键入不入行编辑（无回显无编辑
// 态推进——raw 语义，real more 同款），改入 16 深键队列；shell 重放
// 环在页界处取键裁决（任意键翻页 / q 族键中止）。队列生产者 = pump
// 消费点（feed），消费者 = 分页等键环——同任务串行（init shell 的
// SYS_PIPE op2 调用栈内），SPSC 契约成立。武装/卸臂皆 shell 单发
// 语义（pager_replay 入口武装、出口卸臂），窗口外行规程原貌。

/// 分页键队列容量（页界间连击余量；满则丢弃并计数——fail-visible）。
const PAGER_KEY_CAP: usize = 16;

/// 分页态武装旗（shell::pager_replay 窗口内置位）。
static PAGER_ARMED: AtomicBool = AtomicBool::new(false);

/// 分页键队列（元素 = 翻译后的 ASCII 键面字节）。
static PAGER_KEYS: SpscRing<u8, PAGER_KEY_CAP> = SpscRing::new();

/// 队列满丢弃计数（取证面：页界间连击溢出可观测）。
pub static PAGER_DROP: AtomicUsize = AtomicUsize::new(0);

/// 分页态武装：先卸臂排残（防御上一窗口残留键窜入本窗），再清队列、
/// 置旗——窗口内 feed 改道分页键队列。
pub fn pager_arm() {
    PAGER_ARMED.store(false, Ordering::Release);
    while PAGER_KEYS.recv().is_some() {}
    PAGER_ARMED.store(true, Ordering::Release);
}

/// 分页态卸臂：行规程回原貌（行编辑 + 回显）。
pub fn pager_disarm() {
    PAGER_ARMED.store(false, Ordering::Release);
}

/// 分页键非阻塞取一（shell 页界裁决点）。
pub fn pager_take_key() -> Option<u8> {
    PAGER_KEYS.recv()
}
