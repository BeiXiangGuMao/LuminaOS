//! wchar 域——宽字符分类与宽串语义（"C" locale 单字节映射面）。
//!
//! 承接 POSIX `<wctype.h>` + `<wchar.h>` 37 符号（M35-H1d，121 → 158）：
//! isw 族 12 + towlower/towupper + wctype/wctrans/towctrans（17）+
//! wcs 族 15 + wmem 族 5（20）。
//!
//! # safe 面承载形式（M29/M35 纪律）
//!
//! - **宽串 = `&[wchar_t]` 切片**（NUL 终止串以 `0` 宽字符承载，越界即
//!   `None`/界限值——string 域同款 fail-visible 化）；`wmem` 族为「缓冲区
//!   + 偏移对」承载（string mem 族同款：重叠拒绝/方向感知）。
//! - **"C" locale 纪律**：宽分类域收敛于 ASCII 0..=0x7F（越域宽字符一律
//!   判假/原样返回——C locale 惯例，多字节 locale 面挂账）；负值域
//!   （C UB）→ 判假 0（fail-visible）。
//! - **wctype/wctrans 句柄**：C `wctype_t`/`wctrans_t` 不透明句柄 →
//!   非零 `u32` 描述符（0 = 无效名——C 返 0 照办）；`iswctype`/
//!   `towctrans` 按描述符分发至同域分类/转换面。

use crate::c_int;
use crate::wchar_t;

/// 宽 EOF 哨兵（`WEOF`——与 ctype `EOF = -1` 惯例同源）。
pub const WEOF: c_int = -1;

/// ASCII 域判定内部基元（"C" locale 宽分类域；负值/超域一律域外）。
#[inline]
fn w_in_domain(wc: wchar_t) -> bool {
    (0..=0x7F).contains(&wc)
}

// ───────────────────────── isw 族（12）─────────────────────────

/// 宽字符是否字母或数字（`iswalnum`）。
#[must_use]
pub extern "C" fn iswalnum(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_alphanumeric())
}

/// 宽字符是否字母（`iswalpha`）。
#[must_use]
pub extern "C" fn iswalpha(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_alphabetic())
}

/// 宽字符是否空白·水平域（`iswblank`）。
#[must_use]
pub extern "C" fn iswblank(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && matches!(wc as u8, b'\t' | b' '))
}

/// 宽字符是否控制（`iswcntrl`）。
#[must_use]
pub extern "C" fn iswcntrl(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && ((wc as u8) < 0x20 || wc as u8 == 0x7F))
}

/// 宽字符是否十进制数字（`iswdigit`）。
#[must_use]
pub extern "C" fn iswdigit(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_digit())
}

/// 宽字符是否图形（`iswgraph`）。
#[must_use]
pub extern "C" fn iswgraph(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_graphic())
}

/// 宽字符是否小写（`iswlower`）。
#[must_use]
pub extern "C" fn iswlower(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_lowercase())
}

/// 宽字符是否可打印（`iswprint`）。
#[must_use]
pub extern "C" fn iswprint(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (0x20..0x7F).contains(&(wc as u8)))
}

/// 宽字符是否标点（`iswpunct`）。
#[must_use]
pub extern "C" fn iswpunct(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_punctuation())
}

/// 宽字符是否空白（`iswspace`）。
#[must_use]
pub extern "C" fn iswspace(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && matches!(wc as u8, b' ' | b'\t' | b'\n' | 0x0B | b'\r' | 0x0C))
}

/// 宽字符是否大写（`iswupper`）。
#[must_use]
pub extern "C" fn iswupper(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_uppercase())
}

/// 宽字符是否十六进制位（`iswxdigit`）。
#[must_use]
pub extern "C" fn iswxdigit(wc: wchar_t) -> c_int {
    c_int::from(w_in_domain(wc) && (wc as u8).is_ascii_hexdigit())
}

/// 宽大写转小写（`towlower`；非大写原样返回）。
#[must_use]
pub extern "C" fn towlower(wc: wchar_t) -> wchar_t {
    if w_in_domain(wc) && (wc as u8).is_ascii_uppercase() {
        wchar_t::from((wc as u8).to_ascii_lowercase())
    } else {
        wc
    }
}

/// 宽小写转大写（`towupper`；非小写原样返回）。
#[must_use]
pub extern "C" fn towupper(wc: wchar_t) -> wchar_t {
    if w_in_domain(wc) && (wc as u8).is_ascii_lowercase() {
        wchar_t::from((wc as u8).to_ascii_uppercase())
    } else {
        wc
    }
}

// ───────────────────── wctype / wctrans 句柄族 ─────────────────────

/// 分类描述符位面（bit i = 第 i 类——[`wctype`] 名表序）。
const CLASS_NAMES: [&str; 12] = [
    "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space",
    "upper", "xdigit",
];

/// 分类名 → 描述符（`wctype`）：无效名返 0（C 照办）。
#[must_use]
pub fn wctype(name: &[u8]) -> u32 {
    CLASS_NAMES
        .iter()
        .position(|n| n.as_bytes() == name)
        .map_or(0, |i| 1 << i)
}

/// 按描述符宽分类（`iswctype`）：无效描述符 → 0（fail-visible）。
#[must_use]
pub extern "C" fn iswctype(wc: wchar_t, desc: u32) -> c_int {
    match desc {
        d if d == wctype(b"alnum") => iswalnum(wc),
        d if d == wctype(b"alpha") => iswalpha(wc),
        d if d == wctype(b"blank") => iswblank(wc),
        d if d == wctype(b"cntrl") => iswcntrl(wc),
        d if d == wctype(b"digit") => iswdigit(wc),
        d if d == wctype(b"graph") => iswgraph(wc),
        d if d == wctype(b"lower") => iswlower(wc),
        d if d == wctype(b"print") => iswprint(wc),
        d if d == wctype(b"punct") => iswpunct(wc),
        d if d == wctype(b"space") => iswspace(wc),
        d if d == wctype(b"upper") => iswupper(wc),
        d if d == wctype(b"xdigit") => iswxdigit(wc),
        _ => 0,
    }
}

/// 转换名 → 描述符（`wctrans`）：`tolower` = 1 / `toupper` = 2 /
/// 无效名 = 0（C 照办）。
#[must_use]
pub fn wctrans(name: &[u8]) -> u32 {
    match name {
        b"tolower" => 1,
        b"toupper" => 2,
        _ => 0,
    }
}

/// 按描述符宽转换（`towctrans`）：无效描述符 → 原样（fail-visible）。
#[must_use]
pub extern "C" fn towctrans(wc: wchar_t, desc: u32) -> wchar_t {
    match desc {
        1 => towlower(wc),
        2 => towupper(wc),
        _ => wc,
    }
}

// ───────────────────────── wcs 族（15）─────────────────────────

/// 宽 NUL 串扫描界（片内无 `0` 终止 → `None`——string `strlen` 同款）。
fn wcs_span(s: &[wchar_t]) -> Option<usize> {
    s.iter().position(|&w| w == 0)
}

/// 宽串长度（`wcslen`）：片内无 NUL 宽字符 → `None`（fail-visible）。
#[must_use]
pub fn wcslen(s: &[wchar_t]) -> Option<usize> {
    wcs_span(s)
}

/// 有界宽串长度（`wcsnlen`）：无 NUL 时以 `max`/片界为界。
#[must_use]
pub fn wcsnlen(s: &[wchar_t], max: usize) -> usize {
    wcs_span(s).unwrap_or(s.len()).min(max)
}

/// 宽串复制（`wcscpy`）：`dst` 容量须 ≥ len+1，补 `0` 终止；返回长度。
pub fn wcscpy(dst: &mut [wchar_t], src: &[wchar_t]) -> Option<usize> {
    let len = wcslen(src)?;
    if dst.len() < len + 1 {
        return None;
    }
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
    Some(len)
}

/// 有界宽串复制（`wcsncpy`）：短源以 `0` 补足至 `n`（C 语义照办）。
pub fn wcsncpy(dst: &mut [wchar_t], src: &[wchar_t], n: usize) -> Option<usize> {
    if dst.len() < n {
        return None;
    }
    let len = wcsnlen(src, n);
    dst[..len].copy_from_slice(&src[..len]);
    for w in &mut dst[len..n] {
        *w = 0;
    }
    Some(n)
}

/// 宽串追加（`wcscat`）：`dst` 须已含 `0`（追加点）；返回追加后总长。
pub fn wcscat(dst: &mut [wchar_t], src: &[wchar_t]) -> Option<usize> {
    let at = wcslen(dst)?;
    let slen = wcslen(src)?;
    if dst.len() < at + slen + 1 {
        return None;
    }
    dst[at..at + slen].copy_from_slice(&src[..slen]);
    dst[at + slen] = 0;
    Some(at + slen)
}

/// 有界宽串追加（`wcsncat`）：至多 `n` 宽字符 + 终止 `0`。
pub fn wcsncat(dst: &mut [wchar_t], src: &[wchar_t], n: usize) -> Option<usize> {
    let at = wcslen(dst)?;
    let slen = wcsnlen(src, n);
    if dst.len() < at + slen + 1 {
        return None;
    }
    dst[at..at + slen].copy_from_slice(&src[..slen]);
    dst[at + slen] = 0;
    Some(at + slen)
}

/// 宽串比较（`wcscmp`）：任一片无 NUL → `None`。
#[must_use]
pub fn wcscmp(a: &[wchar_t], b: &[wchar_t]) -> Option<c_int> {
    let sa = a.get(..wcslen(a)?)?;
    let sb = b.get(..wcslen(b)?)?;
    Some(wmemcmp(sa, sb))
}

/// 有界宽串比较（`wcsncmp`）：至多 `n` 宽字符（`0` 亦参与）。
#[must_use]
pub fn wcsncmp(a: &[wchar_t], b: &[wchar_t], n: usize) -> Option<c_int> {
    let sa = a.get(..wcslen(a)?)?;
    let sb = b.get(..wcslen(b)?)?;
    let na = sa.get(..n.min(sa.len())).unwrap_or(&[]);
    let nb = sb.get(..n.min(sb.len())).unwrap_or(&[]);
    Some(wmemcmp(na, nb))
}

/// 宽串内宽字符首现（`wcschr`）：含 `0` 终止符可寻；未命中 → `None`。
#[must_use]
pub fn wcschr(s: &[wchar_t], wc: wchar_t) -> Option<usize> {
    match s.iter().position(|&w| w == wc) {
        Some(at) => Some(at),
        None if wc == 0 => wcslen(s),
        None => None,
    }
}

/// 宽串内宽字符末现（`wcsrchr`）：语义同 [`wcschr`]，取末次。
#[must_use]
pub fn wcsrchr(s: &[wchar_t], wc: wchar_t) -> Option<usize> {
    match s.iter().rposition(|&w| w == wc) {
        Some(at) => Some(at),
        None if wc == 0 => wcslen(s),
        None => None,
    }
}

/// 宽子串首现（`wcsstr`）：空针 → `Some(0)`；返回干内下标。
#[must_use]
pub fn wcsstr(haystack: &[wchar_t], needle: &[wchar_t]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// 初始跨度（`wcsspn`）：自首起连续命中 `accept` 集的宽字符数。
#[must_use]
pub fn wcsspn(s: &[wchar_t], accept: &[wchar_t]) -> usize {
    let end = wcslen(s).unwrap_or(s.len());
    s[..end].iter().take_while(|w| accept.contains(w)).count()
}

/// 初始反跨度（`wcscspn`）：首个 reject 或终止符下标。
#[must_use]
pub fn wcscspn(s: &[wchar_t], reject: &[wchar_t]) -> usize {
    let end = wcslen(s).unwrap_or(s.len());
    s[..end]
        .iter()
        .position(|w| reject.contains(w))
        .unwrap_or(end)
}

/// 集内任意宽字符首现（`wcspbrk`）：无命中 → `None`。
#[must_use]
pub fn wcspbrk(s: &[wchar_t], accept: &[wchar_t]) -> Option<usize> {
    let end = wcslen(s).unwrap_or(s.len());
    s[..end].iter().position(|w| accept.contains(w))
}

/// 宽串复制·所有权（`wcsdup`）：`0` 前内容复制（不含 `0`）。
pub fn wcsdup(s: &[wchar_t]) -> Option<alloc::vec::Vec<wchar_t>> {
    Some(s[..wcslen(s)?].to_vec())
}

// ───────────────────────── wmem 族（5）─────────────────────────

/// 宽域查找（`wmemchr`）：mem 语义（无 NUL 要求）。
#[must_use]
pub fn wmemchr(s: &[wchar_t], wc: wchar_t) -> Option<usize> {
    s.iter().position(|&w| w == wc)
}

/// 宽域比较（`wmemcmp`）：字典序（负/零/正）。
#[must_use]
pub fn wmemcmp(a: &[wchar_t], b: &[wchar_t]) -> c_int {
    let n = a.len().min(b.len());
    for i in 0..n {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => continue,
            core::cmp::Ordering::Less => return -1,
            core::cmp::Ordering::Greater => return 1,
        }
    }
    match a.len().cmp(&b.len()) {
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Greater => 1,
    }
}

/// 宽域复制（`wmemcpy`）：同缓冲区两域复制——重叠拒绝（string `memcpy`
/// 同款 fail-visible）。
pub fn wmemcpy(buf: &mut [wchar_t], dst: usize, src: usize, n: usize) -> Option<usize> {
    bounds(buf, dst, n)?;
    bounds(buf, src, n)?;
    let (ds, de) = (dst, dst + n);
    let (ss, se) = (src, src + n);
    if ds < se && ss < de {
        return None; // 重叠拒绝
    }
    if n > 0 {
        buf.copy_within(src..src + n, dst);
    }
    Some(n)
}

/// 宽域移动（`wmemmove`）：允许重叠（`copy_within` 方向感知）。
pub fn wmemmove(buf: &mut [wchar_t], dst: usize, src: usize, n: usize) -> Option<usize> {
    bounds(buf, dst, n)?;
    bounds(buf, src, n)?;
    if n > 0 {
        buf.copy_within(src..src + n, dst);
    }
    Some(n)
}

/// 宽域填充（`wmemset`）：返回处理宽字符数。
pub fn wmemset(dst: &mut [wchar_t], wc: wchar_t) -> usize {
    dst.fill(wc);
    dst.len()
}

/// 域界基元（string 域同款：off+n ≤ len）。
fn bounds(buf: &[wchar_t], off: usize, n: usize) -> Option<()> {
    if off.checked_add(n)? <= buf.len() {
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// 宽 C 串基元（+`0` 终止）。
    fn wstr(s: &str) -> Vec<wchar_t> {
        let mut v: Vec<wchar_t> = s.chars().map(|c| c as u32 as wchar_t).collect();
        v.push(0);
        v
    }

    /// isw/tow 全谱（ASCII 域 + 越域判假）。
    #[test]
    fn isw_family_ascii_domain() {
        assert_eq!(iswalnum(b'7' as wchar_t), 1);
        assert_eq!(iswalnum(b'a' as wchar_t), 1);
        assert_eq!(iswalnum(b'!' as wchar_t), 0);
        assert_eq!(iswalpha(b'A' as wchar_t), 1);
        assert_eq!(iswalpha(b'7' as wchar_t), 0);
        assert_eq!(iswblank(b'\t' as wchar_t), 1);
        assert_eq!(iswblank(b'\n' as wchar_t), 0);
        assert_eq!(iswcntrl(0x01), 1);
        assert_eq!(iswcntrl(0x7F), 1);
        assert_eq!(iswdigit(b'9' as wchar_t), 1);
        assert_eq!(iswgraph(b'~' as wchar_t), 1);
        assert_eq!(iswgraph(b' ' as wchar_t), 0);
        assert_eq!(iswlower(b'c' as wchar_t), 1);
        assert_eq!(iswprint(b' ' as wchar_t), 1);
        assert_eq!(iswprint(0x1F), 0);
        assert_eq!(iswpunct(b'*' as wchar_t), 1);
        assert_eq!(iswpunct(b'a' as wchar_t), 0);
        assert_eq!(iswspace(0x0C), 1);
        assert_eq!(iswupper(b'Z' as wchar_t), 1);
        assert_eq!(iswxdigit(b'F' as wchar_t), 1);
        assert_eq!(iswxdigit(b'g' as wchar_t), 0);
        // "C" locale：越 ASCII 域一律判假（登记面）
        assert_eq!(iswalpha(0x4E2D), 0, "CJK beyond C-locale domain");
        assert_eq!(iswprint(0x263A), 0);
        // 负值域（C UB → fail-visible 判假；WEOF 哨兵同行）
        assert_eq!(iswalpha(WEOF as wchar_t), 0);
        assert_eq!(iswdigit(-5), 0);
        // tow 转换 + 恒等回环
        assert_eq!(towlower(b'Q' as wchar_t), b'q' as wchar_t);
        assert_eq!(towlower(b'q' as wchar_t), b'q' as wchar_t);
        assert_eq!(towupper(b'q' as wchar_t), b'Q' as wchar_t);
        assert_eq!(towlower(0x4E2D), 0x4E2D, "identity beyond domain");
    }

    /// wctype/wctrans 描述符面 + iswctype/towctrans 分发。
    #[test]
    fn wctype_wctrans_dispatch() {
        let d_alnum = wctype(b"alnum");
        assert_ne!(d_alnum, 0);
        assert_eq!(wctype(b"bogus"), 0, "invalid name -> 0 (C 照办)");
        assert_eq!(iswctype(b'x' as wchar_t, d_alnum), 1);
        assert_eq!(iswctype(b'*' as wchar_t, d_alnum), 0);
        assert_eq!(iswctype(b'x' as wchar_t, 0xDEAD), 0, "invalid desc");
        let d_upper = wctype(b"upper");
        assert_eq!(iswctype(b'Q' as wchar_t, d_upper), 1);
        assert_eq!(iswctype(b'q' as wchar_t, d_upper), 0);
        // 转换描述符
        assert_eq!(wctrans(b"tolower"), 1);
        assert_eq!(wctrans(b"toupper"), 2);
        assert_eq!(wctrans(b"flip"), 0);
        assert_eq!(
            towctrans(b'M' as wchar_t, wctrans(b"tolower")),
            b'm' as wchar_t
        );
        assert_eq!(
            towctrans(b'm' as wchar_t, wctrans(b"toupper")),
            b'M' as wchar_t
        );
        assert_eq!(
            towctrans(b'm' as wchar_t, 0xBEEF),
            b'm' as wchar_t,
            "invalid desc identity"
        );
    }

    /// wcs 族：长度/复制/追加/比较/搜索/跨度/dup。
    #[test]
    fn wcs_family_full() {
        let s = wstr("hello");
        assert_eq!(wcslen(&s), Some(5));
        assert_eq!(wcslen(&[]), None, "empty slice no NUL");
        assert_eq!(wcsnlen(&s, 3), 3);
        assert_eq!(
            wcsnlen(
                &b"unterminated"
                    .iter()
                    .map(|&b| wchar_t::from(b))
                    .collect::<Vec<_>>(),
                4
            ),
            4
        );
        // 复制
        let mut d = [0i32; 8];
        assert_eq!(wcscpy(&mut d, &wstr("hey")), Some(3));
        assert_eq!(&d[..4], &[b'h' as i32, b'e' as i32, b'y' as i32, 0]);
        assert_eq!(wcscpy(&mut [0i32; 3], &wstr("abcd")), None, "dst too small");
        let mut d = [0x7F7F_i32; 6];
        assert_eq!(wcsncpy(&mut d, &wstr("ab"), 5), Some(5));
        assert_eq!(&d, &[b'a' as i32, b'b' as i32, 0, 0, 0, 0x7F7F]);
        // 追加
        let mut d = [0i32; 10];
        assert_eq!(wcscpy(&mut d, &wstr("ab")), Some(2));
        assert_eq!(wcscat(&mut d, &wstr("cd")), Some(4));
        assert_eq!(
            &d[..5],
            &[b'a' as i32, b'b' as i32, b'c' as i32, b'd' as i32, 0]
        );
        let mut d = [0i32; 8];
        assert_eq!(wcscpy(&mut d, &wstr("ab")), Some(2));
        assert_eq!(wcsncat(&mut d, &wstr("cdef"), 2), Some(4));
        // 比较
        let a = wstr("abc");
        let b = wstr("abd");
        let unterminated: Vec<wchar_t> = b"abc".iter().map(|&b| wchar_t::from(b)).collect();
        assert_eq!(wcscmp(&a, &a), Some(0));
        assert_eq!(wcscmp(&a, &b), Some(-1));
        assert_eq!(wcscmp(&unterminated, &unterminated), None, "unterminated");
        assert_eq!(wcsncmp(&a, &b, 2), Some(0));
        assert_eq!(wcsncmp(&a, &b, 3), Some(-1));
        // 搜索（含终止符可寻）
        assert_eq!(wcschr(&s, b'l' as wchar_t), Some(2));
        assert_eq!(wcsrchr(&s, b'l' as wchar_t), Some(3));
        assert_eq!(wcschr(&s, 0), Some(5));
        assert_eq!(wcschr(&s, b'z' as wchar_t), None);
        let h = wstr("haystack");
        assert_eq!(wcsstr(&h, &wstr("stack")), Some(3));
        assert_eq!(wcsstr(&h, &wstr("needle")), None);
        // 跨度
        let x = wstr("abcabc");
        assert_eq!(wcsspn(&x, &[b'a' as i32, b'b' as i32]), 2);
        assert_eq!(wcscspn(&x, &[b'c' as i32]), 2);
        assert_eq!(wcspbrk(&x, &[b'c' as i32, b'b' as i32]), Some(1));
        assert_eq!(wcspbrk(&x, &[b'z' as i32]), None);
        // dup
        assert_eq!(
            wcsdup(&wstr("dup")).as_deref(),
            Some(&[b'd' as i32, b'u' as i32, b'p' as i32][..])
        );
    }

    /// wmem 族：查找/比较/复制重叠语义/填充。
    #[test]
    fn wmem_family_full() {
        let w: Vec<wchar_t> = [3, 1, 4, 1, 5].iter().map(|&x| x as wchar_t).collect();
        assert_eq!(wmemchr(&w, 4), Some(2));
        assert_eq!(wmemchr(&w, 9), None);
        assert_eq!(wmemcmp(&[1, 2, 3], &[1, 2, 3]), 0);
        assert_eq!(wmemcmp(&[1, 2, 3], &[1, 2, 4]), -1);
        assert_eq!(wmemcmp(&[1, 2], &[1, 2, 3]), -1, "prefix shorter");
        // wmemcpy：重叠拒绝 + 越界
        let mut d = [1i32, 2, 3, 4, 0, 0, 0, 0];
        assert_eq!(wmemcpy(&mut d, 4, 0, 4), Some(4));
        assert_eq!(d, [1, 2, 3, 4, 1, 2, 3, 4]);
        assert_eq!(wmemcpy(&mut d, 6, 0, 4), None, "out of bounds");
        assert_eq!(wmemcpy(&mut d, 2, 0, 4), None, "overlap rejected");
        // wmemmove：重叠方向感知
        let mut m = [1i32, 2, 3, 4, 0];
        assert_eq!(wmemmove(&mut m, 1, 0, 4), Some(4));
        assert_eq!(m, [1, 1, 2, 3, 4]);
        let mut m2 = [0i32, 1, 2, 3, 4];
        assert_eq!(wmemmove(&mut m2, 0, 1, 4), Some(4));
        assert_eq!(m2, [1, 2, 3, 4, 4]);
        // wmemset
        let mut z = [0i32; 3];
        assert_eq!(wmemset(&mut z, 0x58), 3);
        assert_eq!(z, [0x58, 0x58, 0x58]);
    }
}
