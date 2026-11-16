//! 无锁 MPMC 环形通道（SYNC-03，M45-MPMC46 笔51 申请新增）。
//!
//! 用途：waycomp 输入生产域零锁直推基座——固定容量、零堆、多生产者/
//! 多消费者语义下的无锁消息传递（Dmitry Vyukov 有界 MPMC 队列算法，
//! 1024b.org 同谱经典实现）。本模块是全 crate unsafe 纪律的收口点
//! 之一：调用方面完全 safe，unsafe 全部封装于环内部原子协议。
//!
//! 内存序协议（Vyukov 逐槽序列号发布模式）：
//! - 槽位契约：每槽 `seq` 三态——`seq == pos`（槽空闲待接管）/
//!   `seq == pos+1`（槽已装满待消费）/ `seq == pos+N`（槽已腾空，
//!   下一轮可复用）；游标 `tail`/`head` 经 CAS 接管推进；
//! - 生产者：`tail` Relaxed 读 → 槽 `seq` Acquire 读（判定空闲）→
//!   `tail` CAS 接管（Relaxed——接管序由槽 seq 发布）→ 写槽 →
//!   `seq = pos+1` Release 发布（写槽先于发布）；
//! - 消费者：`head` Relaxed 读 → 槽 `seq` Acquire 读（判定已装满）
//!   → `head` CAS 接管 → 读槽 → `seq = pos+N` Release 发布（腾空
//!   声明先于槽复用）；
//! - happens-before 链：写槽 → seq.Release → seq.Acquire → 读槽 →
//!   seq.Release（腾空）→ seq.Acquire（复用者）→ 复写槽；
//! - 容量判定：`seq - pos` 符号差（isize——负 = 满〔生产侧〕/ 空
//!   〔消费侧〕；usize 回转同余安全——N 为 2 的幂，`pos & (N-1)`
//!   槽位与环绕游标同余对齐）。
//!
//! 纪律：多生产者/多消费者均为 soundness 契约内合法域（CAS 接管 +
//! 逐槽 seq 双重排他——同槽并发接管恰一胜者）；`N` MUST 为 2 的幂
//! （位与槽位，构造契约同 [`super::spsc::SpscRing`] 先例）。

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 64 字节缓存行填充（避免 tail/head 假共享）。
#[repr(align(64))]
struct CacheLine(AtomicUsize);

/// 环槽位：序列号（三态契约见模块头）+ 数据槽。
struct Cell<T> {
    /// 槽位序列号（三态发布契约——Vyukov 算法排他核）。
    seq: AtomicUsize,
    /// 数据槽（仅接管胜者写/消费胜者读——seq 契约下不重叠）。
    data: UnsafeCell<MaybeUninit<T>>,
}

/// 固定容量无锁 MPMC 环。
///
/// `N` MUST 为 2 的幂（槽位经位与；契约同 [`super::spsc::SpscRing`]）。
pub struct MpmcRing<T, const N: usize> {
    /// 生产者游标（CAS 接管推进——接管数 = 发布数上界）。
    tail: CacheLine,
    /// 消费者游标（CAS 接管推进——接管数 = 消费数上界）。
    head: CacheLine,
    /// 槽位池（seq 三态契约下接管胜者独占读写）。
    buf: [Cell<T>; N],
}

// SAFETY: 前置条件 —— Vyukov 协议双排他：游标 CAS 接管 + 槽 seq 三态
//          发布（同槽并发接管恰一胜者——CAS 唯一性）。
// 不变式 —— 生产者只在 `seq == pos` 接管后写槽（此刻槽既非待消费亦
//          非复用窗），写毕 seq.Release(pos+1) 发布；消费者只在
//          `seq == pos+1`（Acquire 见发布）后读槽，读毕
//          seq.Release(pos+N) 腾空——腾空前复用者 Acquire 读 seq
//          ≠ pos+N 不复写。
// 并发 —— happens-before 链全谱封闭：写槽 → seq.Rel → seq.Acq →
//          读槽 → seq.Rel → seq.Acq → 复写槽（无窗）。
// 违反后果 —— 协议外触碰槽位（绕过 CAS/seq）即数据竞争（UB）；
//          协议内多产多消恰为设计域（本环 soundness 主张）。
unsafe impl<T: Send, const N: usize> Sync for MpmcRing<T, N> {}
// SAFETY: 同上——T 所有权可跨执行流转移（send 交出 / recv 取回）。
unsafe impl<T: Send, const N: usize> Send for MpmcRing<T, N> {}

impl<T: Copy, const N: usize> MpmcRing<T, N> {
    /// 创建空环（逐槽 seq 初始化为槽号——Vyukov 初态契约）。
    pub const fn new() -> Self {
        // 槽池常量化：全槽同构初值（seq=0 + 数据槽 uninit）后逐槽改写
        // seq = 槽号（Vyukov 初态：槽 s 首轮可填充于 pos = s；数据槽
        // 未初始化永不读——消费前必有对应发布写入，契约同 SPSC 环）。
        let mut cells: [Cell<T>; N] = [const {
            Cell {
                seq: AtomicUsize::new(0),
                data: UnsafeCell::new(MaybeUninit::uninit()),
            }
        }; N];
        let mut i = 0usize;
        while i < N {
            cells[i].seq = AtomicUsize::new(i);
            i += 1;
        }
        Self {
            tail: CacheLine(AtomicUsize::new(0)),
            head: CacheLine(AtomicUsize::new(0)),
            buf: cells,
        }
    }

    /// 入队一条消息；满则原样退还（非阻塞，快速路径语义——SPSC 环
    /// send 同谱面）。
    pub fn send(&self, value: T) -> Result<(), T> {
        let mut pos = self.tail.0.load(Ordering::Relaxed);
        loop {
            let cell = &self.buf[pos & (N - 1)];
            let seq = cell.seq.load(Ordering::Acquire);
            // 差值符号：0 = 槽空闲可接管 / 负 = 环满退还 / 正 = 落后
            // 追赶（他产者已推进 pos——重读游标再判）。
            match (seq.wrapping_sub(pos)) as isize {
                0 => {
                    // CAS 接管：胜者独占 [pos & (N-1)] 槽写窗。
                    if self
                        .tail
                        .0
                        .compare_exchange_weak(
                            pos,
                            pos.wrapping_add(1),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        // SAFETY: 前置条件 —— CAS 胜者独占本槽写窗（seq
                        //          契约：接管期无读者无复用者）。
                        // 不变式 —— 写毕 seq Release(pos+1) 发布后槽
                        //          才进入待消费态。
                        // 并发 —— 复用者须 Acquire 读到 pos+N 才复写
                        //          （腾空发布后）——happens-before 封闭。
                        // 违反后果 —— 协议外第二写者即数据竞争（UB，
                        //          CAS 唯一性 + seq 三态契约封死）。
                        unsafe { (*cell.data.get()).write(value) };
                        cell.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    // CAS 败（compare_exchange_weak 已把 pos 刷新为观
                    // 察值）——循环重判新 pos。
                }
                d if d < 0 => return Err(value), // 环满：原样退还
                _ => pos = self.tail.0.load(Ordering::Relaxed), // 追赶
            }
        }
    }

    /// 出队一条消息；空则 None（非阻塞）。
    pub fn recv(&self) -> Option<T> {
        let mut pos = self.head.0.load(Ordering::Relaxed);
        loop {
            let cell = &self.buf[pos & (N - 1)];
            let seq = cell.seq.load(Ordering::Acquire);
            // 差值符号：0 = 槽已装满可接管 / 负 = 环空返回 / 正 = 落
            // 后追赶（他消费者已推进 pos——重读游标再判）。
            match (seq.wrapping_sub(pos.wrapping_add(1))) as isize {
                0 => {
                    // CAS 接管：胜者独占本槽读窗（他消费者接管的是
                    // 后续槽）。
                    if self
                        .head
                        .0
                        .compare_exchange_weak(
                            pos,
                            pos.wrapping_add(1),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        // SAFETY: 前置条件 —— seq == pos+1（Acquire
                        //          见发布）保证槽已完整写入。
                        // 不变式 —— 读毕 seq Release(pos+N) 腾空声明
                        //          后槽才可复用。
                        // 并发 —— 复用者（生产者）须 Acquire 读到
                        //          pos+N 才复写——读窗与复写窗无交叠。
                        // 违反后果 —— 协议外触碰即数据竞争（UB，
                        //          CAS 唯一性 + seq 契约封死）。
                        let v = unsafe { (*cell.data.get()).assume_init_read() };
                        cell.seq.store(pos.wrapping_add(N), Ordering::Release);
                        return Some(v);
                    }
                }
                d if d < 0 => return None,                      // 环空
                _ => pos = self.head.0.load(Ordering::Relaxed), // 追赶
            }
        }
    }

    /// 当前可消费消息数（上界近似——并发窗内瞬时快照，取证面用）。
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

impl<T: Copy, const N: usize> Default for MpmcRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::MpmcRing;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn fifo_full_and_reject_single_thread() {
        let r: MpmcRing<u64, 4> = MpmcRing::new();
        assert!(r.is_empty());
        assert_eq!(r.send(1), Ok(()));
        assert_eq!(r.send(2), Ok(()));
        assert_eq!(r.len(), 2);
        assert_eq!(r.recv(), Some(1));
        assert_eq!(r.recv(), Some(2));
        assert_eq!(r.recv(), None);
        // 满退还 + 腾一格再入（SPSC 环 full/reject 同谱语义）
        let r2: MpmcRing<u32, 2> = MpmcRing::new();
        assert_eq!(r2.send(10), Ok(()));
        assert_eq!(r2.send(11), Ok(()));
        assert_eq!(r2.send(12), Err(12));
        assert_eq!(r2.recv(), Some(10));
        assert_eq!(r2.send(13), Ok(()));
        assert_eq!(r2.recv(), Some(11));
        assert_eq!(r2.recv(), Some(13));
    }

    #[test]
    fn wraparound_indexing() {
        // 游标环绕（usize 回转语义下 pos & (N-1) 恒正确）
        let r: MpmcRing<u8, 2> = MpmcRing::new();
        for i in 0..64u8 {
            r.send(i).expect("send");
            assert_eq!(r.recv(), Some(i));
        }
    }

    #[test]
    fn multi_producer_multi_consumer_exactly_once() {
        // 4 产者 × 2500 + 4 消费者 @ N=8——全谱恰一次交付（MPMC
        // soundness 主张活体：零丢失零重复）
        const PRODS: usize = 4;
        const CONS: usize = 4;
        const PER_PROD: u64 = 2_500;
        const TOTAL: u64 = (PRODS as u64) * PER_PROD;
        let r: Arc<MpmcRing<u64, 8>> = Arc::new(MpmcRing::new());
        let mut handles = Vec::new();
        for p in 0..PRODS {
            let r = Arc::clone(&r);
            handles.push(std::thread::spawn(move || {
                for i in 0..PER_PROD {
                    let v = ((p as u64) << 32) | i;
                    while r.send(v).is_err() {
                        std::thread::yield_now();
                    }
                }
            }));
        }
        let received: Arc<std::sync::Mutex<Vec<u64>>> = Arc::default();
        for _ in 0..CONS {
            let r = Arc::clone(&r);
            let sink = Arc::clone(&received);
            handles.push(std::thread::spawn(move || loop {
                if let Some(v) = r.recv() {
                    sink.lock().expect("sink").push(v);
                    continue;
                }
                // 空转窗：交付总数达账即收工（TOTAL 达账 = 全谱出环）
                if sink.lock().expect("sink").len() == TOTAL as usize {
                    return;
                }
                std::thread::yield_now();
            }));
        }
        for h in handles.drain(..PRODS) {
            h.join().expect("producer panicked");
        }
        for h in handles {
            h.join().expect("consumer panicked");
        }
        let got = received.lock().expect("sink");
        assert_eq!(got.len(), TOTAL as usize, "交付总数对账");
        let uniq: HashSet<u64> = got.iter().copied().collect();
        assert_eq!(uniq.len(), TOTAL as usize, "恰一次交付——零重复");
        for p in 0..PRODS {
            for i in 0..PER_PROD {
                assert!(uniq.contains(&(((p as u64) << 32) | i)), "零丢失");
            }
        }
    }

    #[test]
    fn small_capacity_concurrent_stress() {
        // N=2 极小容量并发压力——满窗退还路径 + 产消推进活性
        let r: Arc<MpmcRing<u64, 2>> = Arc::new(MpmcRing::new());
        let tx = Arc::clone(&r);
        let producer = std::thread::spawn(move || {
            for i in 0..4_000u64 {
                while tx.send(i).is_err() {
                    std::thread::yield_now();
                }
            }
        });
        let rx = Arc::clone(&r);
        let consumer = std::thread::spawn(move || {
            let mut got = 0u64;
            let mut last = 0u64;
            while got < 4_000 {
                if let Some(v) = rx.recv() {
                    // 单消费者域：FIFO 单调性锚（同产者序列无重复乱序）
                    assert_eq!(v, last);
                    last += 1;
                    got += 1;
                }
                std::thread::yield_now();
            }
            got
        });
        producer.join().expect("producer panicked");
        assert_eq!(consumer.join().expect("consumer panicked"), 4_000);
    }
}
