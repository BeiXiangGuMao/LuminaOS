//! 早期控制台抽象。
//!
//! 启动早期没有日志子系统，Bedrock 通过本 trait 把字符写到串口或内存缓冲。
//! 输出通道按 DEV-002 第四章日志通道约定分级，此处仅提供无格式化的底层写入。

/// 早期控制台写入接口。
pub trait Console {
    /// 写入一段 UTF-8 文本；实现方 MUST 逐字节落盘且不缓冲超过一行。
    fn write_str(&mut self, s: &str);
}

/// 空实现：用于测试与「关闭输出」的编译期选择。
#[derive(Debug, Default, Clone, Copy)]
pub struct NullConsole;

impl Console for NullConsole {
    fn write_str(&mut self, _s: &str) {}
}

/// 内存环形缓冲控制台：QEMU 测试期把输出留在内存供宿主侧断言（TLV 协议约定）。
pub struct MemConsole {
    buf: [u8; MEM_CAP],
    len: usize,
}

/// 内存缓冲容量（字节）。
pub const MEM_CAP: usize = 4096;

impl MemConsole {
    /// 创建空缓冲。
    pub const fn new() -> Self {
        Self {
            buf: [0; MEM_CAP],
            len: 0,
        }
    }

    /// 已缓冲字节数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 缓冲是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 读取已缓冲内容（按写入顺序）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for MemConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl Console for MemConsole {
    fn write_str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if self.len < MEM_CAP {
                self.buf[self.len] = b;
                self.len += 1;
            }
            // 超出容量即丢弃：早期控制台 MUST NOT 阻塞或 panic。
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Console, MemConsole, NullConsole};

    #[test]
    fn mem_console_records_and_caps() {
        let mut c = MemConsole::new();
        c.write_str("lumina: boot\n");
        assert_eq!(c.as_bytes(), b"lumina: boot\n");

        let big = "x".repeat(super::MEM_CAP + 64);
        c.write_str(&big);
        assert_eq!(c.len(), super::MEM_CAP);
    }

    #[test]
    fn null_console_accepts_anything() {
        let mut c = NullConsole;
        c.write_str("ignored");
    }
}
