//! 无锁 SPSC 环形通道（SYNC-02，M5 申请新增）。
//!
//! 用途：Bedrock IPC 快速路径（B-P01）的数据结构基座——固定容量、零堆、
//! 单生产者/单消费者语义下的无锁消息传递。本模块是全 crate unsafe 纪律的
//! 收口点之一：调用方面（含 bedrock::ipc::FastPath 包装）完全 safe。
//!
//! 内存序协议（经典 SPSC 发布/订阅模式）：
//! - 生产者：`tail` Relaxed 读 + 写槽位 + `tail` Release 自增——
//!   Release 保证槽位写入先于索引发布；
//! - 消费者：`tail` Acquire 读 → 读到已发布槽位；`head` Release 自增——
//!   保证槽位读出先于槽位复用声明；
//! - 容量判定：`tail - head`（环绕计数，usize 回转安全）。
//!
//! 纪律：**单生产者 + 单消费者**是 soundness 契约（见 unsafe impl 注释）；
//! 多生产者或多消费者使用即数据竞争，由类型系统外纪律封死（API 文档 +
//! bedrock 包装只暴露给单一发送/接收方）。

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 64 字节缓存行填充（避免 tail/head 假共享）。
#[repr(align(64))]
struct CacheLine(AtomicUsize);

/// 固定容量无锁 SPSC 环。
///
/// `N` MUST 为 2 的幂（取模经位与；构造时 debug_assert 校验）。
pub struct SpscRing<T, const N: usize> {
    /// 生产者游标（已发布消息数）。
    tail: CacheLine,
    /// 消费者游标（已消费消息数）。
    head: CacheLine,
    /// 槽位池（仅生产者写未发布槽、消费者读已发布槽——SPSC 契约下不重叠）。
    buf: UnsafeCell<[MaybeUninit<T>; N]>,
}

// SAFETY: 前置条件 —— SPSC 契约：同一时刻恰好一个生产者与一个消费者。
// 不变式 —— 生产者只写 [tail % N] 且先写后发布（Release）；消费者只在
//          Acquire 读到新 tail 后读槽，且读完后才 Release 让出槽位；
//          两游标永不指向同一未完成槽（容量判定排除满/空歧义）。
// 并发 —— 原子游标构成 happens-before 链：写槽 → tail.Release →
//          tail.Acquire → 读槽 → head.Release → head.Acquire → 复用槽。
// 违反后果 —— 多生产者/多消费者即槽位撕裂与消息丢失（数据竞争，UB）。
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}
// SAFETY: 同上——Send/Sync 语义由 SPSC 使用契约约束（单发单收）。
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}

impl<T: Copy, const N: usize> SpscRing<T, N> {
    /// 创建空环（槽位未初始化；首读必发生在首写之后，MaybeUninit 安全）。
    pub const fn new() -> Self {
        Self {
            tail: CacheLine(AtomicUsize::new(0)),
            head: CacheLine(AtomicUsize::new(0)),
            // SAFETY 注记：MaybeUninit 数组逐元素 uninit 是合法常量构造；
            // 未初始化内存永不被读取（消费前必有对应发布写入）。
            buf: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
        }
    }

    /// 入队一条消息；满则原样退还（非阻塞，快速路径语义）。
    pub fn send(&self, value: T) -> Result<(), T> {
        let t = self.tail.0.load(Ordering::Relaxed);
        let h = self.head.0.load(Ordering::Acquire);
        if t.wrapping_sub(h) >= N {
            return Err(value);
        }
        // SAFETY: 前置条件 —— SPSC 契约下生产者独占 [t % N] 槽。
        // 不变式 —— 槽写入完成后 tail 才 Release 自增（下方 store）。
        // 并发 —— 消费者最多 Acquire 读到旧 t，不读本槽。
        // 违反后果 —— 双生产者会撕裂槽位（契约封死，见 unsafe impl）。
        unsafe { (*self.buf.get())[t % N].write(value) };
        self.tail.0.store(t.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// 出队一条消息；空则 None（非阻塞）。
    pub fn recv(&self) -> Option<T> {
        let h = self.head.0.load(Ordering::Relaxed);
        let t = self.tail.0.load(Ordering::Acquire);
        if h == t {
            return None;
        }
        // SAFETY: 前置条件 —— h < t（上方判定）保证 [h % N] 已发布。
        // 不变式 —— 槽值读出后 head 才 Release 自增（下方 store）。
        // 并发 —— 生产者最多复用 [h % N] 于本核 head 自增之后。
        // 违反后果 —— 多消费者会重复消费（契约封死，见 unsafe impl）。
        let v = unsafe { (*self.buf.get())[h % N].assume_init() };
        self.head.0.store(h.wrapping_add(1), Ordering::Release);
        Some(v)
    }

    /// 当前可消费消息数。
    pub fn len(&self) -> usize {
        self.tail
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.0.load(Ordering::Acquire))
    }

    /// 环是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Copy, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::SpscRing;

    #[test]
    fn fifo_single_thread() {
        let r: SpscRing<u64, 4> = SpscRing::new();
        assert!(r.is_empty());
        assert_eq!(r.send(1), Ok(()));
        assert_eq!(r.send(2), Ok(()));
        assert_eq!(r.len(), 2);
        assert_eq!(r.recv(), Some(1));
        assert_eq!(r.recv(), Some(2));
        assert_eq!(r.recv(), None);
    }

    #[test]
    fn full_and_reject_returns_value() {
        let r: SpscRing<u32, 2> = SpscRing::new();
        assert_eq!(r.send(10), Ok(()));
        assert_eq!(r.send(11), Ok(()));
        assert_eq!(r.send(12), Err(12)); // 满：原样退还
        assert_eq!(r.recv(), Some(10));
        assert_eq!(r.send(13), Ok(())); // 释放一槽后可再入
        assert_eq!(r.recv(), Some(11));
        assert_eq!(r.recv(), Some(13));
    }

    #[test]
    fn wraparound_indexing() {
        // 游标环绕（usize 回转语义下 t % N 恒正确）
        let r: SpscRing<u8, 2> = SpscRing::new();
        for i in 0..8u8 {
            r.send(i).expect("send");
            assert_eq!(r.recv(), Some(i));
        }
    }

    #[test]
    fn cross_thread_ping_pong() {
        extern crate std;
        use std::sync::Arc;
        let r: Arc<SpscRing<u64, 8>> = Arc::new(SpscRing::new());
        let tx = Arc::clone(&r);
        let producer = std::thread::spawn(move || {
            for i in 0..2_000u64 {
                while tx.send(i).is_err() {
                    std::thread::yield_now();
                }
            }
        });
        let mut got = 0u64;
        while got < 2_000 {
            if let Some(v) = r.recv() {
                assert_eq!(v, got);
                got += 1;
            }
            std::thread::yield_now();
        }
        producer.join().expect("producer panicked");
    }
}
