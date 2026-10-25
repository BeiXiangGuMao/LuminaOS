//! ctype 域——字符分类与大小写转换（值语义 `extern "C"`）。
//!
//! 承接 POSIX `<ctype.h>`："C" locale 语义（仅 ASCII 域判定，locale 面
//! 挂账见 crate 文档）。libc 惯例：分类函数接收 `c_int`（值域须为
//! `unsigned char` 或 EOF），返回 `c_int`（0 = 假 / 非零 = 真）。v0 safe
//! 面：值域超界（负且非 EOF-哨兵、或 > 255）一律返回 0（fail-visible
//! 化——C 为 UB，此处为确定性行为，见各函数文档）。
//!
//! EOF 哨兵：`EOF = -1`（与 stdio 惯例一致）；EOF 输入对所有分类函数
//! 返回 0（非字符类）。

use crate::c_int;

/// 文件结束哨兵（`<stdio.h>` 惯例值 -1；ctype 值域判定随行）。
pub const EOF: c_int = -1;

/// ASCII 判定内部基元：仅 0..=255 参与分类（超界返回 0）。
#[inline]
fn in_domain(c: c_int) -> bool {
    (0..=255).contains(&c)
}

/// 是否字母或数字（`isalnum`）。
#[must_use]
pub extern "C" fn isalnum(c: c_int) -> c_int {
    i32::from(in_domain(c) && (is_ascii_alpha(c) || (c as u8).is_ascii_digit()))
}

/// 是否字母（`isalpha`）。
#[must_use]
pub extern "C" fn isalpha(c: c_int) -> c_int {
    i32::from(in_domain(c) && is_ascii_alpha(c))
}

/// 是否空白（水平制表或空格，`isblank`）。
#[must_use]
pub extern "C" fn isblank(c: c_int) -> c_int {
    i32::from(in_domain(c) && matches!(c as u8, b'\t' | b' '))
}

/// 是否控制字符（`iscntrl`）。
#[must_use]
pub extern "C" fn iscntrl(c: c_int) -> c_int {
    i32::from(in_domain(c) && ((c as u8) < 0x20 || c as u8 == 0x7F))
}

/// 是否十进制数字（`isdigit`）。
#[must_use]
pub extern "C" fn isdigit(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_digit())
}

/// 是否图形字符（可打印且非空格，`isgraph`）。
#[must_use]
pub extern "C" fn isgraph(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_graphic())
}

/// 是否小写字母（`islower`）。
#[must_use]
pub extern "C" fn islower(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_lowercase())
}

/// 是否可打印字符（含空格，`isprint`）。
#[must_use]
pub extern "C" fn isprint(c: c_int) -> c_int {
    i32::from(in_domain(c) && (0x20..0x7F).contains(&(c as u8)))
}

/// 是否标点（可打印且非字母数字空格，`ispunct`）。
#[must_use]
pub extern "C" fn ispunct(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_punctuation())
}

/// 是否空白字符（`isspace`：空格/换页/换行/回车/水平与垂直制表）。
#[must_use]
pub extern "C" fn isspace(c: c_int) -> c_int {
    i32::from(in_domain(c) && matches!(c as u8, b' ' | b'\t' | b'\n' | 0x0B | b'\r' | 0x0C))
}

/// 是否大写字母（`isupper`）。
#[must_use]
pub extern "C" fn isupper(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_uppercase())
}

/// 是否十六进制数字（`isxdigit`：0-9 a-f A-F）。
#[must_use]
pub extern "C" fn isxdigit(c: c_int) -> c_int {
    i32::from(in_domain(c) && (c as u8).is_ascii_hexdigit())
}

/// 是否 ASCII（0..=127，`isascii`——POSIX 扩展符号）。
#[must_use]
pub extern "C" fn isascii(c: c_int) -> c_int {
    i32::from((0..=127).contains(&c))
}

/// 转 ASCII 低 7 位（`toascii`——POSIX 扩展符号：`c & 0x7F`）。
#[must_use]
pub extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7F
}

/// 大写转小写（`tolower`；非大写原样返回）。
#[must_use]
pub extern "C" fn tolower(c: c_int) -> c_int {
    if in_domain(c) && (c as u8).is_ascii_uppercase() {
        c + 32
    } else {
        c
    }
}

/// 小写转大写（`toupper`；非小写原样返回）。
#[must_use]
pub extern "C" fn toupper(c: c_int) -> c_int {
    if in_domain(c) && (c as u8).is_ascii_lowercase() {
        c - 32
    } else {
        c
    }
}

#[inline]
fn is_ascii_alpha(c: c_int) -> bool {
    (c as u8).is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_domains() {
        assert_eq!(isdigit(b'0' as c_int), 1);
        assert_eq!(isdigit(b'9' as c_int), 1);
        assert_eq!(isdigit(b'a' as c_int), 0);
        assert_eq!(isdigit(b'/' as c_int), 0);
        assert_eq!(isalpha(b'Z' as c_int), 1);
        assert_eq!(isalpha(b'z' as c_int), 1);
        assert_eq!(isalpha(b'0' as c_int), 0);
        assert_eq!(isalnum(b'5' as c_int), 1);
        assert_eq!(isalnum(b'k' as c_int), 1);
        assert_eq!(isalnum(b'!' as c_int), 0);
        assert_eq!(isblank(b' ' as c_int), 1);
        assert_eq!(isblank(b'\t' as c_int), 1);
        assert_eq!(isblank(b'\n' as c_int), 0);
        assert_eq!(isspace(b'\n' as c_int), 1);
        assert_eq!(isspace(0x0B as c_int), 1);
        assert_eq!(isspace(b'a' as c_int), 0);
        assert_eq!(iscntrl(0x01), 1);
        assert_eq!(iscntrl(0x7F), 1);
        assert_eq!(iscntrl(b'a' as c_int), 0);
        assert_eq!(isgraph(b'a' as c_int), 1);
        assert_eq!(isgraph(b' ' as c_int), 0);
        assert_eq!(isprint(b' ' as c_int), 1);
        assert_eq!(isprint(0x7F), 0);
        assert_eq!(ispunct(b'!' as c_int), 1);
        assert_eq!(ispunct(b'a' as c_int), 0);
        assert_eq!(isupper(b'A' as c_int), 1);
        assert_eq!(isupper(b'a' as c_int), 0);
        assert_eq!(islower(b'a' as c_int), 1);
        assert_eq!(isxdigit(b'f' as c_int), 1);
        assert_eq!(isxdigit(b'F' as c_int), 1);
        assert_eq!(isxdigit(b'g' as c_int), 0);
    }

    #[test]
    fn conversions_and_sentinels() {
        assert_eq!(tolower(b'Q' as c_int), b'q' as c_int);
        assert_eq!(tolower(b'q' as c_int), b'q' as c_int);
        assert_eq!(tolower(b'1' as c_int), b'1' as c_int);
        assert_eq!(toupper(b'q' as c_int), b'Q' as c_int);
        assert_eq!(toupper(b'!' as c_int), b'!' as c_int);
        assert_eq!(isascii(0), 1);
        assert_eq!(isascii(127), 1);
        assert_eq!(isascii(128), 0);
        assert_eq!(toascii(0xFF), 0x7F);
        // EOF 哨兵与超界值域：全部判假（fail-visible 化，C 为 UB）
        let classifiers: [(&str, extern "C" fn(c_int) -> c_int); 12] = [
            ("isalnum", isalnum),
            ("isalpha", isalpha),
            ("isblank", isblank),
            ("iscntrl", iscntrl),
            ("isdigit", isdigit),
            ("isgraph", isgraph),
            ("islower", islower),
            ("isprint", isprint),
            ("ispunct", ispunct),
            ("isspace", isspace),
            ("isupper", isupper),
            ("isxdigit", isxdigit),
        ];
        for (name, f) in classifiers {
            assert_eq!(f(EOF), 0, "{name} must reject EOF");
            assert_eq!(f(-42), 0, "{name} must reject -42");
            assert_eq!(f(256), 0, "{name} must reject 256");
        }
        assert_eq!(isascii(EOF), 0);
        // 转换函数对非转换域原样返回
        assert_eq!(tolower(EOF), EOF);
        assert_eq!(toupper(256), 256);
    }
}
