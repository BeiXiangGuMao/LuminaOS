//! tty 行编辑分类纯函数面（M34-D2 外移自 kernel::tty::feed 分类核——
//! 行缓冲 static 域与回显电气面留 kernel，分类器无状态纯函数）。

/// 行编辑动作（分类产物；执行面归 kernel::tty——电气/缓冲域不动）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineAction {
    /// 可打印字节入缓冲（len < cap）。
    Append,
    /// 退格抹迹（len > 0）。
    Backspace,
    /// 回车行提交。
    Submit,
    /// 忽略（控制字节 / 空退格 / 满容）。
    Ignore,
}

/// 回车行提交字节（行规程语义锚）。
pub const SUBMIT_BYTE: u8 = b'\n';
/// 退格抹迹三连（`\b \b`——终端抹迹序列，M23-① 原核同构）。
pub const BACKSPACE_TRACE: [u8; 3] = *b"\x08 \x08";
/// 行提交回显（CRLF）。
pub const SUBMIT_ECHO: [u8; 2] = *b"\r\n";

/// 行编辑分类（M23-① 最小行规程语义纯函数化）：`\n` → Submit；
/// `\b`(0x08) → Backspace（len > 0，零长度退格 Ignore）；`0x20..=0x7E`
/// 可打印 → Append（len < cap，满容 Ignore）；余者 Ignore（Tab 等
/// 后续版本按需扩展——M23-① 口径）。
pub fn classify(b: u8, len: usize, cap: usize) -> LineAction {
    match b {
        b'\n' => LineAction::Submit,
        0x08 if len > 0 => LineAction::Backspace,
        0x20..=0x7E if len < cap => LineAction::Append,
        _ => LineAction::Ignore,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{classify, LineAction};

    #[test]
    fn classify_golden() {
        // M34-D2 宿主对账：分类器 golden 十二目
        assert_eq!(classify(b'a', 0, 128), LineAction::Append);
        assert_eq!(classify(b'~', 5, 128), LineAction::Append); // 0x7E 边界
        assert_eq!(classify(b' ', 5, 128), LineAction::Append); // 0x20 边界
        assert_eq!(classify(b'\n', 0, 128), LineAction::Submit); // 空行亦提交
        assert_eq!(classify(b'\n', 42, 128), LineAction::Submit);
        assert_eq!(classify(0x08, 1, 128), LineAction::Backspace);
        assert_eq!(classify(0x08, 0, 128), LineAction::Ignore); // 空退格
        assert_eq!(classify(b'a', 128, 128), LineAction::Ignore); // 满容
        assert_eq!(classify(b'\t', 0, 128), LineAction::Ignore); // 控制域
        assert_eq!(classify(0x7F, 0, 128), LineAction::Ignore); // DEL 拒收
        assert_eq!(classify(0x00, 0, 128), LineAction::Ignore); // NUL 拒收
        assert_eq!(classify(0x1F, 3, 128), LineAction::Ignore); // 域下界外
    }
}
