//! shell 管道/分页承接面（M24-A1）——单级 `|` 雏形 + `more` 内核主体。
//!
//! 雏形架构（与 bedrock abi [`SYS_PIPE`] 文档双向对账）：
//!
//! ```text
//! ring3 init shell                    kernel::shell
//! ─────────────────                  ──────────────────────────
//! parse 扫 '|'（左截断右暂存）
//!   → SYS_PIPE(0) 捕获武装    ──────► capture_arm（log_sink 改道入捕）
//!   → 左命令派发（直答经 SYS_LOG）
//!   → SYS_PIPE(2) 分页重放    ──────► pager_replay：逐行落串口 +
//!       （阻塞至分页完结）              页界 `--more--` 等键
//!   → prompt                           （键面 = tty 分页态队列）
//! ```
//!
//! - **捕获面**：全局单缓冲（1 KiB），arm..drain/replay 窗口内所有
//!   `SYS_LOG` 按调用序入捕，每次调用尾补 `\n` 行界（载荷不含换行、
//!   串口路径每调用补 CRLF——行语义同源）。缓冲满整行丢弃 + 计数
//!   （fail-visible，不截半行）。
//! - **分页面**：[`pager_replay`] 逐行重落串口，每满
//!   [`PAGE_LINES`]（4 行）停顿打 `--more--` 等键——任意键翻页、
//!   `q`/`Q`/ESC/Ctrl-C 中止（残余行舍弃）。键经 tty 分页态队列投递
//!   （[`crate::tty::pager_arm`] 行规程扩展：窗口内键不入行编辑）。
//! - **单消费者契约**：init shell（M23-②）串行调用为唯一长期用户，
//!   t74 自检在自检段同线程注入/断言（无并发窗口）——与 tty 消费面
//!   纪律同源。多级管道/双缓冲/多消费者属后续里程碑。
//!
//! 等键环为忙等（pump + 取键 + spin）：中断投递键入（IRQ1 → 键盘环），
//! tick 抢占保其余任务不被饿死；雏形不做让步面（如实记档）。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::console;
use crate::tty;

/// 捕获缓冲容量（1 KiB；`SYS_LOG` 单载荷 ≤ 512 + 行界，两行满载余量）。
const CAP_CAP: usize = 1024;

/// 捕获缓冲（行界成帧流；单消费者 = 排水/重放取走即清）。
static mut CAP_BUF: [u8; CAP_CAP] = [0; CAP_CAP];

/// 捕获有效字节数。
static CAP_LEN: AtomicUsize = AtomicUsize::new(0);

/// 捕获武装旗（arm..drain/replay 窗口内置位；窗口外 `SYS_LOG` 落串口）。
static CAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// 累计入捕行数（含被丢弃行——对账面）。
static CAP_LINES: AtomicUsize = AtomicUsize::new(0);

/// 缓冲满整行丢弃计数（fail-visible；不截半行保行完整性）。
static CAP_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// `more` 页界（每页行数；雏形定值——终端尺寸协商面属后续里程碑）。
pub const PAGE_LINES: usize = 4;

/// 分页重放累计实显行数（跨调用累加；t74 对账面）。
static REPLAY_LINES: AtomicUsize = AtomicUsize::new(0);

/// 分页停顿累计（页界 `--more--` 次数）。
static REPLAY_PAUSES: AtomicUsize = AtomicUsize::new(0);

/// 分页中止累计（q 族键裁决次数）。
static REPLAY_ABORTS: AtomicUsize = AtomicUsize::new(0);

/// 捕获面快照（t74 断言面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeStat {
    /// 捕获武装态。
    pub active: bool,
    /// 捕获有效字节数。
    pub len: usize,
    /// 累计入捕行数。
    pub lines: usize,
    /// 缓冲满整行丢弃数。
    pub dropped: usize,
}

/// 分页面快照（t74 断言面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagerStat {
    /// 累计实显行数。
    pub lines: usize,
    /// 累计页界停顿数。
    pub pauses: usize,
    /// 累计中止数。
    pub aborts: usize,
}

/// 捕获面快照读出。
pub fn pipe_snapshot() -> PipeStat {
    PipeStat {
        active: CAP_ACTIVE.load(Ordering::Acquire),
        len: CAP_LEN.load(Ordering::Acquire),
        lines: CAP_LINES.load(Ordering::Relaxed),
        dropped: CAP_DROPPED.load(Ordering::Relaxed),
    }
}

/// 分页面快照读出。
pub fn pager_snapshot() -> PagerStat {
    PagerStat {
        lines: REPLAY_LINES.load(Ordering::Relaxed),
        pauses: REPLAY_PAUSES.load(Ordering::Relaxed),
        aborts: REPLAY_ABORTS.load(Ordering::Relaxed),
    }
}

/// `SYS_LOG` 唯一去向面（syscall 派发器调用 + t74 产线注入同源）：
/// 捕获武装期入捕（调用序 + 行界成帧），否则落串口。
pub fn log_sink(text: &[u8]) {
    if CAP_ACTIVE.load(Ordering::Acquire) {
        capture_append(text);
        return;
    }
    console::serial_log_bytes(text);
}

/// 捕获追加一行（载荷 + `\n` 行界；满则整行弃 + 计数）。
fn capture_append(text: &[u8]) {
    CAP_LINES.fetch_add(1, Ordering::Relaxed);
    let need = text.len() + 1;
    let len = CAP_LEN.load(Ordering::Acquire);
    if len + need > CAP_CAP {
        CAP_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: 单写者（捕获窗口内调用方任务语境）；读侧仅在
    // drain/replay（同任务串行，arm..取走握手与 tty READY 面同纪律）。
    unsafe {
        let base = (&raw mut CAP_BUF) as *mut u8;
        core::ptr::copy_nonoverlapping(text.as_ptr(), base.add(len), text.len());
        *base.add(len + text.len()) = b'\n';
    }
    CAP_LEN.store(len + need, Ordering::Release);
}

/// 捕获武装（幂等：已武装则保持；缓冲由 drain/replay/drop 清账面归零）。
pub fn capture_arm() {
    CAP_ACTIVE.store(true, Ordering::Release);
}

/// 捕获排水：内容拷出（min(捕获长, 缓冲长)）→ 返回实拷字节数 →
/// 清账 + 卸臂（单发语义；二次排水得 0 = 零泄漏对账锚）。
pub fn capture_drain(buf: &mut [u8]) -> usize {
    let len = CAP_LEN.load(Ordering::Acquire);
    let n = len.min(buf.len());
    if n > 0 {
        // SAFETY: 捕获窗口已写毕（CAP_LEN 握手）；同任务串行读。
        let src = unsafe { core::slice::from_raw_parts((&raw const CAP_BUF) as *const u8, n) };
        buf[..n].copy_from_slice(src);
    }
    CAP_LEN.store(0, Ordering::Release);
    CAP_ACTIVE.store(false, Ordering::Release);
    n
}

/// 捕获弃置：清账 + 卸臂（右命令非 `more` 的 shell 侧清场）。
pub fn capture_drop() {
    CAP_LEN.store(0, Ordering::Release);
    CAP_ACTIVE.store(false, Ordering::Release);
}

/// 分页等键环：泵一轮（键盘环 → 行规程——分页态下入分页键队列）+
/// 非阻塞取键；无键则 spin（中断投递键入，tick 抢占保其余任务）。
fn pager_wait_key() -> Option<u8> {
    loop {
        tty::pump();
        if let Some(k) = tty::pager_take_key() {
            return Some(k);
        }
        core::hint::spin_loop();
    }
}

/// `more` 分页重放主体：`content` 逐行（`\n` 界，尾段无界亦为行）重落
/// 串口，每满 [`PAGE_LINES`] 行且尚有余行 → `--more--` 等键（任意键
/// 翻页 / q 族键中止）。返实显行数；出口统一卸臂（行规程回原貌）。
///
/// 不经武装旗直调面（t74）/ `SYS_PIPE(2)` 派发面共用本函数——分页
/// 语义单一事实源。调用方负责内容清账（syscall 面就地清，t74 面自
/// 持缓冲）；本函数只读不改 `content`。
pub fn pager_replay(content: &[u8]) -> usize {
    tty::pager_arm();
    let mut shown = 0usize;
    let mut start = 0usize;
    let total = content.len();
    while start < total {
        let end = match content[start..].iter().position(|&b| b == b'\n') {
            Some(p) => start + p,
            None => total,
        };
        console::serial_log_bytes(&content[start..end]);
        shown += 1;
        REPLAY_LINES.fetch_add(1, Ordering::Relaxed);
        start = if end < total { end + 1 } else { total };
        // 页界停顿：整页已显且尚有余行（尾页不满无停顿——more 语义）
        if shown.is_multiple_of(PAGE_LINES) && start < total {
            REPLAY_PAUSES.fetch_add(1, Ordering::Relaxed);
            console::serial_send_raw(b"--more--");
            match pager_wait_key() {
                Some(b'q' | b'Q' | 0x1B | 0x03) => {
                    REPLAY_ABORTS.fetch_add(1, Ordering::Relaxed);
                    console::serial_send_raw(b"\r\n"); // 键收讫显形（证据行整洁）
                    break;
                }
                _ => console::serial_send_raw(b"\r\n"),
            }
        }
    }
    tty::pager_disarm();
    shown
}

/// `SYS_PIPE` 派发主体（慢路径：rsi/rdx = 慢路径语义的用户缓冲指针/长）。
///
/// 返回域见 abi [`SYS_PIPE`] 文档；坏指针按 BadArgs 域返码（与 abi
/// 解析错误同面，雏形不细分 errno）。
pub fn sys_pipe(op: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    const BAD: u64 = u64::MAX - 1;
    match op {
        // 0 = 捕获武装
        0 => {
            capture_arm();
            0
        }
        // 1 = 排水（用户缓冲拷出 + 清账卸臂）
        1 => {
            let Some(slice) = crate::syscall::validate_user_slice_mut(buf_ptr, buf_len) else {
                return BAD;
            };
            capture_drain(slice) as u64
        }
        // 2 = 分页重放（more 主体；重放毕清账卸臂——单发零泄漏）
        2 => {
            let len = CAP_LEN.load(Ordering::Acquire);
            // SAFETY: 捕获窗口写毕（CAP_LEN 握手）；同任务串行读。
            let content =
                unsafe { core::slice::from_raw_parts((&raw const CAP_BUF) as *const u8, len) };
            let lines = pager_replay(content);
            CAP_LEN.store(0, Ordering::Release);
            CAP_ACTIVE.store(false, Ordering::Release);
            lines as u64
        }
        // 3 = 弃置
        3 => {
            capture_drop();
            0
        }
        _ => BAD,
    }
}
