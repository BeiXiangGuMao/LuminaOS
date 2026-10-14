//! Pulse 脉冲 —— 网络栈基础件。
//!
//! 依据《指标与规范手册》第 7 章：Pulse 的零拷贝收发按三条路径组织，本 crate 提供
//! 其中路径二的数据结构面——固定容量 SPSC（单生产者单消费者）无锁环形队列，用于
//! 网卡驱动与协议栈线程之间的包描述符交接；另附 [`SocketAddr`] 地址类型。
//!
//! 安全性说明：环内未初始化内存的管理是本 crate 唯一的 unsafe 集中区，
//! 逐处携带 SAFETY 四行注释。
#![no_std]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 网络地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketAddr {
    /// IPv4 + 端口。
    V4 {
        /// 四段地址，按 a.b.c.d。
        octets: [u8; 4],
        /// 端口（主机字节序）。
        port: u16,
    },
}

impl SocketAddr {
    /// 解析 "a.b.c.d:port" 形式的地址字符串（无堆实现，适配 no_std）。
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, port) = s.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let mut octets = [0u8; 4];
        let mut it = ip.split('.');
        for slot in octets.iter_mut() {
            *slot = it.next()?.parse().ok()?;
        }
        if it.next().is_some() {
            return None;
        }
        Some(SocketAddr::V4 { octets, port })
    }
}

impl core::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            SocketAddr::V4 {
                octets: [a, b, c, d],
                port,
            } => {
                write!(f, "{a}.{b}.{c}.{d}:{port}")
            }
        }
    }
}

/// 固定容量 SPSC 环。容量在编译期确定，无堆分配。
pub struct SpscRing<T, const N: usize> {
    head: AtomicUsize, // 生产者写
    tail: AtomicUsize, // 消费者写
    slots: [UnsafeCell<MaybeUninit<T>>; N],
}

impl<T, const N: usize> SpscRing<T, N> {
    /// 创建空环。N 建议 2 的幂。
    pub fn new() -> Self {
        let slots = core::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit()));
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            slots,
        }
    }

    /// 生产者投递一个元素；环满时归还所有权（`Err(value)`）。
    pub fn push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= N {
            return Err(value);
        }
        let slot = &self.slots[head % N];
        // SAFETY: 前置条件 —— head-tail < N 保证槽位空闲且只有生产者触碰该槽。
        // SAFETY: 不变式 —— 每个槽位只在 head 推进到它时写入一次，随后才可读。
        // SAFETY: 并发 —— SPSC 约定：写槽与发布 head 之间的顺序由下方 Release 保证。
        // SAFETY: 违反后果 —— 违反 SPSC 约定（多生产者）会写穿未发布槽位，未定义行为。
        unsafe {
            (*slot.get()).write(value);
        }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// 消费者取走一个元素；空则返回 None。
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot = &self.slots[tail % N];
        // SAFETY: 前置条件 —— tail != head 保证槽位已写入且只有消费者读取。
        // SAFETY: 不变式 —— 读取后立即以 tail+1 发布，生产者重写需等下一次绕行。
        // SAFETY: 并发 —— Acquire 读 head 已与生产者 Release 配对。
        // SAFETY: 违反后果 —— 多消费者会重复读取同一槽位，未定义行为。
        let value = unsafe { (*slot.get()).assume_init_read() };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(value)
    }

    /// 当前元素数（近似值，仅供诊断）。
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// 是否为空（近似值）。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: 前置条件 —— T: Send 且严格 SPSC 使用（单生产者单消费者各一线程）。
// SAFETY: 不变式 —— 槽位写入/读取由 head/tail 原子变量编排，互不交叠。
// SAFETY: 并发 —— Acquire/Release 配对构成 happens-before 链。
// SAFETY: 违反后果 —— 违反 SPSC 约定时本 unsafe impl 不再成立。
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::{SocketAddr, SpscRing};
    use std::string::ToString;
    use std::sync::Arc;

    #[test]
    fn addr_parse_and_display() {
        let a = SocketAddr::parse("192.168.7.9:8080").expect("parse");
        assert_eq!(
            a,
            SocketAddr::V4 {
                octets: [192, 168, 7, 9],
                port: 8080
            }
        );
        assert_eq!(a.to_string(), "192.168.7.9:8080");
        assert!(SocketAddr::parse("999.1.1.1:1").is_none());
        assert!(SocketAddr::parse("1.2.3.4").is_none());
    }

    #[test]
    fn ring_full_returns_value_back() {
        let ring: SpscRing<u32, 2> = SpscRing::new();
        ring.push(1).expect("1");
        ring.push(2).expect("2");
        assert_eq!(ring.push(3), Err(3), "full");
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.push(3), Ok(()));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert!(ring.is_empty());
    }

    #[test]
    fn spsc_threads_transfer_10k() {
        let ring: Arc<SpscRing<u64, 1024>> = Arc::new(SpscRing::new());
        let rx = Arc::clone(&ring);
        let producer = std::thread::spawn(move || {
            for i in 0..10_000u64 {
                while ring.push(i).is_err() {
                    core::hint::spin_loop();
                }
            }
        });
        let consumer = std::thread::spawn(move || {
            let mut expect = 0u64;
            while expect < 10_000 {
                if let Some(v) = rx.pop() {
                    assert_eq!(v, expect);
                    expect += 1;
                } else {
                    core::hint::spin_loop();
                }
            }
            expect
        });
        producer.join().expect("producer");
        assert_eq!(consumer.join().expect("consumer"), 10_000);
    }
}
