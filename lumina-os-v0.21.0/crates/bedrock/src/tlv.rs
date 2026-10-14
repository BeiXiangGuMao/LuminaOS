//! TLV 编帧：内核测试协议与 IPC 载荷的统一格式。
//!
//! 依据《系统开发指南》第六章：QEMU 宿主-客户机测试走 TLV（Tag-Length-Value）
//! 帧。帧头 4 字节：`tag: u16`（小端）+ `len: u16`（小端，仅指 value 长度），
//! 紧随 value。本模块提供零拷贝解析（借用输入切片）与分配式编码两条路径。

/// 最大 value 长度：65535 字节（len 字段 u16 上限）。
pub const MAX_VALUE_LEN: usize = u16::MAX as usize;

/// TLV 解析错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// 输入不足 4 字节帧头。
    TruncatedHeader,
    /// 帧头声明的 value 长度超出实际剩余字节。
    TruncatedValue,
    /// value 长度超出协议上限。
    ValueTooLong,
}

/// 一帧 TLV 的借用视图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// 标签。
    pub tag: u16,
    /// 载荷。
    pub value: &'a [u8],
}

/// 从输入缓冲解析第一帧；返回（帧，剩余输入）。
pub fn decode_one(input: &[u8]) -> Result<(Frame<'_>, &[u8]), TlvError> {
    let [t0, t1, l0, l1, rest @ ..] = input else {
        return Err(TlvError::TruncatedHeader);
    };
    let tag = u16::from_le_bytes([*t0, *t1]);
    let len = u16::from_le_bytes([*l0, *l1]) as usize;
    if len > MAX_VALUE_LEN {
        return Err(TlvError::ValueTooLong);
    }
    if rest.len() < len {
        return Err(TlvError::TruncatedValue);
    }
    let (value, rest) = rest.split_at(len);
    Ok((Frame { tag, value }, rest))
}

/// 解析全部帧；遇到任何截断即报错（严格模式）。
pub fn decode_all(mut input: &[u8]) -> Result<alloc::vec::Vec<Frame<'_>>, TlvError> {
    let mut out = alloc::vec::Vec::new();
    while !input.is_empty() {
        let (f, rest) = decode_one(input)?;
        out.push(f);
        input = rest;
    }
    Ok(out)
}

/// 编码一帧到 `out` 尾部（分配式，测试与慢路径用）。
pub fn encode(out: &mut alloc::vec::Vec<u8>, tag: u16, value: &[u8]) -> Result<(), TlvError> {
    if value.len() > MAX_VALUE_LEN {
        return Err(TlvError::ValueTooLong);
    }
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{decode_all, decode_one, encode, Frame, TlvError};

    #[test]
    fn roundtrip_multi_frame() {
        let mut buf = alloc::vec::Vec::new();
        encode(&mut buf, 0x0001, b"ping").expect("small value");
        encode(&mut buf, 0x0002, b"").expect("empty value");
        encode(&mut buf, 0xFFFF, &[0xAB; 300]).expect("300B value");
        let frames = decode_all(&buf).expect("decode");
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames[0],
            Frame {
                tag: 1,
                value: b"ping"
            }
        );
        assert_eq!(frames[1], Frame { tag: 2, value: b"" });
        assert_eq!(frames[2].tag, 0xFFFF);
        assert_eq!(frames[2].value, &[0xAB; 300]);
    }

    #[test]
    fn rejects_truncation() {
        assert_eq!(decode_one(&[1, 2]), Err(TlvError::TruncatedHeader));
        assert_eq!(
            decode_one(&[1, 0, 9, 0, b'x']),
            Err(TlvError::TruncatedValue)
        );
    }

    #[test]
    fn rejects_overlong_value() {
        let mut buf = alloc::vec::Vec::new();
        let too_big = [0u8; 0] as [u8; 0];
        let _ = too_big;
        // 构造 len 声明 0xFFFF 但实际只有 3 字节：TruncatedValue 优先于 TooLong 不可达，
        // 因此 ValueTooLong 只能由 encode 侧触发。
        assert_eq!(
            encode(&mut buf, 1, &[0u8; 70_000]),
            Err(TlvError::ValueTooLong)
        );
    }
}
