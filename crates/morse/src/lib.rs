//! Morse 电键 —— scancode set 1 翻译面（键盘语义域，驱动旁路缩编首割）。
//!
//! 意象：Morse 电键——物理击键信号到语义字符的翻译器。本 crate 是
//! `kernel::kbd` 旁路缩编的首割（M31-N1，ROADMAP M31；ADR-0004 混合态
//! 渐进——机制留 kernel，旁路面分批外移）：把 PS/2 scancode set 1 的纯
//! 翻译逻辑从内核驱动电气面剥离为零依赖纯函数库——无 IO、无锁、无状态
//! 副作用（Shift 事件分类为纯判定函数，状态寄存由消费方持有），可同时
//! 用于内核态与用户态，宿主测试得以全谱覆盖。
//!
//! 分层纪律：电气面（IRQ1 桩钩子 / i8042 / 环形缓冲 / 注入面）留
//! `kernel::kbd` 本体；本 crate 只承载「scancode → ASCII 控制面字节」
//! 翻译表与事件分类判定——驱动用户态化批次的第一块可移动物。
//! 命名登记：细则 PDF 介质失联（ROADMAP §七 5），命名按在库意象序列
//! 自定（Morse 电键），重取后对账。
#![no_std]
#![forbid(unsafe_code)]

/// 释放事件判定（scancode set 1 纪律：bit7=1 为释放码）。
#[inline]
pub fn is_release(sc: u8) -> bool {
    sc & 0x80 != 0
}

/// Shift 事件分类（纯判定，无副作用）：
/// `Some(true)` = Shift 按下（0x2A 左 / 0x36 右），
/// `Some(false)` = Shift 释放（0xAA / 0xB6，按下码 | 0x80），
/// `None` = 非 Shift 事件（交回 [`translate`] 裁量）。
#[inline]
pub fn shift_event(sc: u8) -> Option<bool> {
    match sc {
        0x2A | 0x36 => Some(true),
        0xAA | 0xB6 => Some(false),
        _ => None,
    }
}

/// scancode set 1 → ASCII 最小翻译表（按下态；Shift 影响字母与数字行）。
///
/// 非映射键返回 `None`（静默忽略语义由消费方裁量）。控制面：
/// `\n`（0x1C Enter）、`\x08`（0x0E Backspace）、`\t`（0x0F Tab）、
/// 可打印 ASCII（字母大小写随 Shift、数字行符号随 Shift 最小集）。
pub fn translate(sc: u8, shift: bool) -> Option<u8> {
    let c = match sc {
        // 数字行（Shift = 符号最小集）
        0x02 => {
            if shift {
                b'!'
            } else {
                b'1'
            }
        }
        0x03 => {
            if shift {
                b'@'
            } else {
                b'2'
            }
        }
        0x04 => {
            if shift {
                b'#'
            } else {
                b'3'
            }
        }
        0x05 => {
            if shift {
                b'$'
            } else {
                b'4'
            }
        }
        0x06 => {
            if shift {
                b'%'
            } else {
                b'5'
            }
        }
        0x07 => {
            if shift {
                b'^'
            } else {
                b'6'
            }
        }
        0x08 => {
            if shift {
                b'&'
            } else {
                b'7'
            }
        }
        0x09 => {
            if shift {
                b'*'
            } else {
                b'8'
            }
        }
        0x0A => {
            if shift {
                b'('
            } else {
                b'9'
            }
        }
        0x0B => {
            if shift {
                b')'
            } else {
                b'0'
            }
        }
        0x0C => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
        0x0D => {
            if shift {
                b'+'
            } else {
                b'='
            }
        }
        0x0E => 0x08,  // Backspace
        0x0F => b'\t', // Tab
        0x1C => b'\n', // Enter
        0x39 => b' ',  // Space
        0x33 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        0x34 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        0x35 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        0x27 => {
            if shift {
                b':'
            } else {
                b';'
            }
        }
        0x28 => {
            if shift {
                b'"'
            } else {
                b'\''
            }
        }
        0x29 => {
            if shift {
                b'~'
            } else {
                b'`'
            }
        }
        0x2B => {
            if shift {
                b'|'
            } else {
                b'\\'
            }
        }
        0x1A => {
            if shift {
                b'{'
            } else {
                b'['
            }
        }
        0x1B => {
            if shift {
                b'}'
            } else {
                b']'
            }
        }
        // QWERTY 三行（Shift = 大写；0x27/0x28/0x29 已在符号行先匹配）
        0x10..=0x19 | 0x1E..=0x26 | 0x2C..=0x32 => {
            let base = match sc {
                0x10..=0x19 => b"qwertyuiop"[(sc - 0x10) as usize],
                0x1E..=0x26 => b"asdfghjkl"[(sc - 0x1E) as usize],
                _ => b"zxcvbnm"[(sc - 0x2C) as usize],
            };
            if shift {
                base - 32
            } else {
                base
            }
        }
        _ => return None,
    };
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 数字行全谱：非 Shift = 数字 1..0；Shift = 符号 !@#$%^&*()。
    #[test]
    fn number_row_digits_and_symbols() {
        const DIGITS: [u8; 10] = *b"1234567890";
        const SYMBOLS: [u8; 10] = *b"!@#$%^&*()";
        for (i, sc) in (0x02..=0x0B).enumerate() {
            assert_eq!(translate(sc, false), Some(DIGITS[i]), "sc={sc:#04x}");
            assert_eq!(translate(sc, true), Some(SYMBOLS[i]), "sc={sc:#04x}");
        }
    }

    /// 控制面四键：Backspace / Tab / Enter / Space（Shift 不影响）。
    #[test]
    fn control_keys_shift_invariant() {
        for shift in [false, true] {
            assert_eq!(translate(0x0E, shift), Some(0x08));
            assert_eq!(translate(0x0F, shift), Some(b'\t'));
            assert_eq!(translate(0x1C, shift), Some(b'\n'));
            assert_eq!(translate(0x39, shift), Some(b' '));
        }
    }

    /// 符号行双态全谱（- = , . / ; ' ` \ [ ] 与 Shift 上档）。
    #[test]
    fn symbol_row_both_states() {
        const PAIRS: [(u8, u8, u8); 13] = [
            (0x0C, b'-', b'_'),
            (0x0D, b'=', b'+'),
            (0x33, b',', b'<'),
            (0x34, b'.', b'>'),
            (0x35, b'/', b'?'),
            (0x27, b';', b':'),
            (0x28, b'\'', b'"'),
            (0x29, b'`', b'~'),
            (0x2B, b'\\', b'|'),
            (0x1A, b'[', b'{'),
            (0x1B, b']', b'}'),
            (0x02, b'1', b'!'),
            (0x0B, b'0', b')'),
        ];
        for (sc, base, shifted) in PAIRS {
            assert_eq!(translate(sc, false), Some(base), "sc={sc:#04x}");
            assert_eq!(translate(sc, true), Some(shifted), "sc={sc:#04x}");
        }
    }

    /// QWERTY 三行全字母：非 Shift 小写 = Shift 大写（26 键同源对账）。
    #[test]
    fn qwerty_rows_lowercase_and_uppercase() {
        const ROWS: [(u8, u8, &str); 3] = [
            (0x10, 0x19, "qwertyuiop"),
            (0x1E, 0x26, "asdfghjkl"),
            (0x2C, 0x32, "zxcvbnm"),
        ];
        for (lo, hi, letters) in ROWS {
            for (i, sc) in (lo..=hi).enumerate() {
                let base = letters.as_bytes()[i];
                assert_eq!(translate(sc, false), Some(base), "sc={sc:#04x}");
                assert_eq!(translate(sc, true), Some(base - 32), "sc={sc:#04x}");
            }
        }
    }

    /// 非映射键与释放态数字键全拒（fail-visible：None = 消费方静默裁量面）。
    #[test]
    fn unmapped_and_release_rejected() {
        for sc in [0x00u8, 0x01, 0x1D, 0x38, 0x5B, 0x5C, 0x5D, 0xE0] {
            assert_eq!(translate(sc, false), None, "sc={sc:#04x}");
            assert_eq!(translate(sc, true), None, "sc={sc:#04x}");
        }
        // 释放态数字键（按下码 | 0x80）不可作为按下事件翻译。
        for sc in [0x82u8, 0x9C, 0xAA] {
            assert_eq!(translate(sc, false), None, "sc={sc:#04x}");
        }
    }

    /// Shift 事件矩阵：按下双码 / 释放双码 / 非 Shift 事件全 None
    /// （含释放态数字键与控制键——均非 Shift 事件）。
    #[test]
    fn shift_event_matrix() {
        assert_eq!(shift_event(0x2A), Some(true)); // 左 Shift 按下
        assert_eq!(shift_event(0x36), Some(true)); // 右 Shift 按下
        assert_eq!(shift_event(0xAA), Some(false)); // 左 Shift 释放
        assert_eq!(shift_event(0xB6), Some(false)); // 右 Shift 释放
        for sc in [0x02u8, 0x82, 0x0E, 0x8E, 0x39, 0x1C] {
            assert_eq!(shift_event(sc), None, "sc={sc:#04x}");
        }
    }

    /// 释放码判定：bit7=1 全真 / 常用按下码全假。
    #[test]
    fn release_detection() {
        for sc in [0x82u8, 0xAA, 0xB6, 0x9C, 0xF0] {
            assert!(is_release(sc), "sc={sc:#04x}");
        }
        for sc in [0x02u8, 0x2A, 0x36, 0x39, 0x1C] {
            assert!(!is_release(sc), "sc={sc:#04x}");
        }
    }
}
