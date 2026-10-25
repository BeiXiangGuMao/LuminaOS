//! Pulse 脉冲 —— 网络栈协议数据面。
//!
//! 依据《指标与规范手册》第 7 章：Pulse 的零拷贝收发按三条路径组织，本 crate
//! 承载其中的**协议数据面**——网络地址类型与协议结构（M27 起扩展 UDP/TCP 报文
//! 面与端口管理），供内核 `kernel::vnet` 消费。环机制不在此处：[`SpscRing`]
//! 式无锁环的单一事实源为 `ostd::sync::spsc`（SYNC-02 本体，ADR-0005 裁决
//! 「环归 ostd::sync 白名单、pulse 纯协议面」——M27-N1 执行步兑现，原生环
//! 面退役；`bedrock::sync` 等价内联为 M26-V1-c 登记例外，见该登记注记）。
//!
//! 安全性说明：本 crate `forbid(unsafe_code)` 全域生效——协议面为纯数据
//! 结构与纯函数，零 unsafe 集中区（ADR-0005 终态密度 0）。
#![no_std]
#![forbid(unsafe_code)]

pub mod udp;

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

    /// 回环地址 127.0.0.1 + `port`（内核内回环通路寻址用，t78 同源）。
    pub fn loopback(port: u16) -> Self {
        SocketAddr::V4 {
            octets: [127, 0, 0, 1],
            port,
        }
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

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::SocketAddr;
    use std::string::ToString;

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
    fn loopback_helper() {
        let a = SocketAddr::loopback(7777);
        assert_eq!(
            a,
            SocketAddr::V4 {
                octets: [127, 0, 0, 1],
                port: 7777
            }
        );
        assert_eq!(a.to_string(), "127.0.0.1:7777");
    }
}
