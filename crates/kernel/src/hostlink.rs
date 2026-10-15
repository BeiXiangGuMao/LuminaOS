//! 宿主-客户机 TLV 联测通道（M4）：COM1 双向 TLV 帧交换。
//!
//! 协议（与 xtask S8 配对）：
//! 1. 客户机输出 `LUMINA-HOSTLINK-READY`；
//! 2. 宿主经 QEMU stdin 写入请求帧 `[tag:u16le][len:u16le][value]`；
//! 3. 客户机校验后回送 `LUMINA-TLV-RESP:` + 应答帧（tag|0x8000，
//!    value = 请求 value + b"-ACK"）+ `LUMINA-TLV-OK`；
//! 4. 超时（150 节拍 @100 Hz）即联测失败，冒烟以非 33 退出码暴露。
//!
//! 本模块零 unsafe：串口读写经 `crate::console` 的 HW-01 收口原语。

use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::console::{serial_send_raw, serial_try_read};

/// 联测超时（节拍数）：1.5 s @100 Hz。
const READ_TIMEOUT_TICKS: u64 = 150;
/// 请求 value 上限（与 TLV 协议上限保持距离）。
const MAX_REQ_VALUE: u64 = 512;

/// 读取直到凑齐一帧 TLV（头 4 字节 + value）；超时返回 None。
fn read_frame(timeout_at: u64) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    while ostd::time::now() < timeout_at {
        match serial_try_read() {
            Some(b) => {
                buf.push(b);
                if buf.len() >= 4 {
                    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                    if buf.len() >= 4 + len {
                        return Some(buf);
                    }
                }
            }
            None => ostd::hw::intr::halt(), // 等下一个节拍唤醒后继续轮询
        }
    }
    None
}

/// 执行一次请求-应答交换；返回是否成功（自检 15 判定）。
pub fn run_exchange(log: &mut crate::console::DualLog) -> bool {
    let _ = writeln!(log, "LUMINA-HOSTLINK-READY");

    let deadline = ostd::time::now() + READ_TIMEOUT_TICKS;
    let Some(req) = read_frame(deadline) else {
        let _ = writeln!(log, "LUMINA-TLV-TIMEOUT");
        return false;
    };
    let tag = u16::from_le_bytes([req[0], req[1]]);
    let len = u16::from_le_bytes([req[2], req[3]]) as u64;
    if len as usize != req.len() - 4 || len > MAX_REQ_VALUE {
        let _ = writeln!(log, "LUMINA-TLV-BADREQ len={len}");
        return false;
    }
    let value = &req[4..];

    // 应答：tag | 0x8000，value = 请求 value + b"-ACK"
    let mut reply: Vec<u8> = Vec::with_capacity(4 + value.len() + 4);
    reply.extend_from_slice(&(tag | 0x8000).to_le_bytes());
    let rlen = (value.len() + 4) as u16;
    reply.extend_from_slice(&rlen.to_le_bytes());
    reply.extend_from_slice(value);
    reply.extend_from_slice(b"-ACK");

    let _ = writeln!(log, "LUMINA-TLV-RESP:");
    serial_send_raw(&reply);
    let _ = writeln!(log, "LUMINA-TLV-OK");
    true
}
