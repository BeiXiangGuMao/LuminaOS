//! console 串口日志字节翻译纯函数面（M34-D2 外移自 kernel::console::
//! serial_log_bytes 内联逻辑——电气发送以 emit 闭包下发，本面零 I/O）。

/// 串口日志字节翻译（流式 emit，零分配）：`\n` → CRLF 展开（串口侧
/// 换行规范）、`0x20..0x7F` 可打印直通、其余控制字节 → `'.'` 占位、
/// 尾部 CRLF 追加（每调用一日志行的帧界语义——宿主 wait_log 子串
/// 断言安全域）。翻译规则与 M13-② 原核逐字节同构（golden 对账）。
pub fn translate_log_bytes<E: FnMut(u8)>(bytes: &[u8], mut emit: E) {
    for &b in bytes {
        if b == b'\n' {
            emit(b'\r');
            emit(b'\n');
        } else if (0x20..0x7F).contains(&b) {
            emit(b);
        } else {
            emit(b'.');
        }
    }
    emit(b'\r');
    emit(b'\n');
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate alloc;
    use super::translate_log_bytes;

    fn tr(bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        translate_log_bytes(bytes, |b| out.push(b));
        out
    }

    #[test]
    fn translate_golden() {
        // M34-D2 宿主对账：翻译核 golden 九目（与 M13-② 原核同构）
        assert_eq!(tr(b"hi"), b"hi\r\n"); // 直通 + 尾 CRLF
        assert_eq!(tr(b"a\nb"), b"a\r\nb\r\n"); // CRLF 展开
        assert_eq!(tr(b"\x01\x02"), b"..\r\n"); // 控制字节 → '.'
        assert_eq!(tr(b"\x1f\x7f"), b"..\r\n"); // 0x1F/0x7F 边界皆占位
        assert_eq!(tr(b"\x20\x7e"), b" \x7e\r\n"); // 0x20/0x7E 边界直通
        assert_eq!(tr(b""), b"\r\n"); // 空输入 = 纯尾 CRLF（帧界语义）
        assert_eq!(tr(b"\r"), b".\r\n"); // 裸 CR 亦占位（仅 \n 展开）
        assert_eq!(tr(b"ab\x00cd"), b"ab.cd\r\n"); // NUL 占位（TLV 域隔离）
        assert_eq!(tr(b"ok\n"), b"ok\r\n\r\n"); // 输入自带 \n + 尾 CRLF
    }
}
