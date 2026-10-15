//! IPC 端点信箱：快速路径的数据结构面。
//!
//! 快速路径（B-P01 预算内）必须无锁化前的第一步是正确的锁语义：此处用 OSTD
//! 自旋锁保护 `VecDeque`，M2 阶段按 SPEC 2 章升级为无锁环形通道并保留本实现
//! 作为语义参考。载荷为 TLV 帧字节（见 [`crate::tlv`]）。
//!
//! M5：无锁环形通道以 [`FastPath`] 落地——底层为 `ostd::sync::spsc::SpscRing`
//! （unsafe 收口在 OSTD，本 crate 保持零 unsafe），定槽、零堆、缓存行隔离。

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ostd::sync::spsc::SpscRing;
use ostd::sync::SpinLock;

/// 单端点信箱：发送入队、接收出队。
pub struct Endpoint {
    mailbox: SpinLock<VecDeque<Vec<u8>>>,
    capacity: usize,
}

/// 信箱已满错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// 队列已达到容量上限。
    MailboxFull,
    /// 端点无数据（非阻塞接收）。
    Empty,
}

/// 端点默认容量（条数）。
pub const DEFAULT_CAPACITY: usize = 64;

impl Endpoint {
    /// 创建指定容量的端点。
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            mailbox: SpinLock::new(VecDeque::new()),
            capacity,
        }
    }

    /// 创建默认容量端点。
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// 发送一段载荷；满则拒绝（快速路径不做阻塞等待）。
    pub fn send(&self, payload: Vec<u8>) -> Result<(), EndpointError> {
        let mut q = self.mailbox.lock();
        if q.len() >= self.capacity {
            return Err(EndpointError::MailboxFull);
        }
        q.push_back(payload);
        Ok(())
    }

    /// 非阻塞接收。
    pub fn recv(&self) -> Result<Vec<u8>, EndpointError> {
        let mut q = self.mailbox.lock();
        q.pop_front().ok_or(EndpointError::Empty)
    }

    /// 当前积压条数。
    pub fn pending(&self) -> usize {
        self.mailbox.lock().len()
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// FastPath 单槽载荷：tag + 定长缓冲 + 实际长度（B-P01 快速路径帧格式）。
///
/// 128 字节定长槽（4 + 4 + 120），Copy 语义保证 SPSC 槽位搬运无堆参与。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastSlot {
    /// 帧标签（TLV tag 同义复用）。
    pub tag: u32,
    /// 载荷有效字节数（≤ [`FastPath::PAYLOAD`]）。
    pub len: u32,
    /// 定长载荷缓冲（有效区 `payload[..len]`，其余未定义）。
    pub payload: [u8; FastPath::PAYLOAD],
}

/// FastPath 错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathError {
    /// 环已满（非阻塞退还）。
    Full,
    /// 载荷超长（上限 [`FastPath::PAYLOAD`]）。
    TooLong,
}

/// 无锁快速路径通道：单发送方 → 单接收方（SPSC）。
///
/// 底层 [`SpscRing`]（OSTD SYNC-02）；本类型全部 safe Rust。
/// 典型用法：BSP↔AP 各持一条单向通道（双向 = 两条实例）。
pub struct FastPath {
    ring: SpscRing<FastSlot, { FastPath::CAP }>,
}

impl FastPath {
    /// 环容量（槽数，2 的幂）。
    pub const CAP: usize = 64;
    /// 单槽载荷上限（字节）。
    pub const PAYLOAD: usize = 120;

    /// 创建空通道。
    pub const fn new() -> Self {
        Self {
            ring: SpscRing::new(),
        }
    }

    /// 发送一帧（非阻塞）。
    pub fn send_frame(&self, tag: u32, value: &[u8]) -> Result<(), FastPathError> {
        if value.len() > Self::PAYLOAD {
            return Err(FastPathError::TooLong);
        }
        let mut slot = FastSlot {
            tag,
            len: value.len() as u32,
            payload: [0u8; Self::PAYLOAD],
        };
        slot.payload[..value.len()].copy_from_slice(value);
        self.ring.send(slot).map_err(|_| FastPathError::Full)
    }

    /// 接收一帧；写入 `out` 并返回 (tag, 有效长度)。空环返回 None。
    pub fn recv_frame(&self, out: &mut [u8; Self::PAYLOAD]) -> Option<(u32, usize)> {
        let slot = self.ring.recv()?;
        let n = slot.len as usize;
        out[..n].copy_from_slice(&slot.payload[..n]);
        Some((slot.tag, n))
    }

    /// 当前积压帧数。
    pub fn pending(&self) -> usize {
        self.ring.len()
    }
}

impl Default for FastPath {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::Endpoint;
    use super::EndpointError::*;
    use std::sync::Arc;

    #[test]
    fn fifo_and_errors() {
        let ep = Endpoint::with_capacity(2);
        assert_eq!(ep.recv(), Err(Empty));
        ep.send(alloc::vec::Vec::from(b"one" as &[u8]))
            .expect("1st");
        ep.send(alloc::vec::Vec::from(b"two" as &[u8]))
            .expect("2nd");
        assert_eq!(
            ep.send(alloc::vec::Vec::from(b"three" as &[u8])),
            Err(MailboxFull)
        );
        assert_eq!(ep.pending(), 2);
        assert_eq!(ep.recv().expect("r1"), b"one");
        assert_eq!(ep.recv().expect("r2"), b"two");
        assert_eq!(ep.pending(), 0);
    }

    #[test]
    fn cross_thread_ping_pong() {
        let ep = Arc::new(Endpoint::with_capacity(16));
        let tx = Arc::clone(&ep);
        let producer = std::thread::spawn(move || {
            for i in 0..100u32 {
                // 有界信箱：满则让步重试（生产端 panic 会让消费端永挂）
                while tx
                    .send(alloc::vec::Vec::from(i.to_le_bytes().as_slice()))
                    .is_err()
                {
                    std::thread::yield_now();
                }
            }
        });
        let mut got = 0u32;
        while got < 100 {
            if let Ok(msg) = ep.recv() {
                let mut b = [0u8; 4];
                b.copy_from_slice(&msg);
                assert_eq!(u32::from_le_bytes(b), got);
                got += 1;
            }
            // 让步而非自旋：2 核 CI 环境下 spin 等待可能活锁
            std::thread::yield_now();
        }
        producer.join().expect("producer panicked");
    }

    #[test]
    fn fastpath_fifo_and_too_long() {
        use super::{FastPath, FastPathError::*};
        let fp = FastPath::new();
        let long = [7u8; FastPath::PAYLOAD + 1];
        assert_eq!(fp.send_frame(0x10, &long), Err(TooLong));
        assert_eq!(fp.send_frame(0x10, b"alpha"), Ok(()));
        assert_eq!(fp.send_frame(0x11, b"beta"), Ok(()));
        assert_eq!(fp.pending(), 2);
        let mut out = [0u8; FastPath::PAYLOAD];
        assert_eq!(fp.recv_frame(&mut out), Some((0x10, 5)));
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(fp.recv_frame(&mut out), Some((0x11, 4)));
        assert_eq!(&out[..4], b"beta");
        assert_eq!(fp.recv_frame(&mut out), None);
    }

    #[test]
    fn fastpath_cross_thread_roundtrip() {
        use super::FastPath;
        const PAYLOAD: usize = FastPath::PAYLOAD;
        let req = Arc::new(FastPath::new());
        let resp = Arc::new(FastPath::new());
        let rq = Arc::clone(&req);
        let rs = Arc::clone(&resp);
        let server = std::thread::spawn(move || {
            let mut out = [0u8; PAYLOAD];
            for i in 0..500u32 {
                let frame = loop {
                    if let Some(f) = rq.recv_frame(&mut out) {
                        break f;
                    }
                    std::thread::yield_now();
                };
                assert_eq!(frame.0, 0x20);
                assert_eq!(frame.1, 4);
                assert_eq!(u32::from_le_bytes(out[..4].try_into().expect("4B")), i);
                while rs.send_frame(0xA0, &i.to_le_bytes()).is_err() {
                    std::thread::yield_now();
                }
            }
        });
        let mut out = [0u8; PAYLOAD];
        for i in 0..500u32 {
            while req.send_frame(0x20, &i.to_le_bytes()).is_err() {
                std::thread::yield_now();
            }
            loop {
                match resp.recv_frame(&mut out) {
                    Some((0xA0, 4)) => {
                        assert_eq!(u32::from_le_bytes(out[..4].try_into().expect("4B")), i);
                        break;
                    }
                    _ => std::thread::yield_now(),
                }
            }
        }
        server.join().expect("server panicked");
    }
}
