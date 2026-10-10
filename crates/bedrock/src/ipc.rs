//! IPC 端点信箱：快速路径的数据结构面。
//!
//! 快速路径（B-P01 预算内）必须无锁化前的第一步是正确的锁语义：此处用 OSTD
//! 自旋锁保护 `VecDeque`，M2 阶段按 SPEC 2 章升级为无锁环形通道并保留本实现
//! 作为语义参考。载荷为 TLV 帧字节（见 [`crate::tlv`]）。

use alloc::collections::VecDeque;
use alloc::vec::Vec;
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

#[cfg(test)]
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
                // 背压重试：信箱满是可重试错误（对端仍在消费），MUST NOT 升级
                // 为 panic——否则对端将永久等不足条数，用例假死（M1 遗留竞态，
                // 多核调度下可复现）。重试前重建载荷，语义与首次发送一致。
                while tx
                    .send(alloc::vec::Vec::from(i.to_le_bytes().as_slice()))
                    .is_err()
                {
                    core::hint::spin_loop();
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
            core::hint::spin_loop();
        }
        producer.join().expect("producer panicked");
    }
}
