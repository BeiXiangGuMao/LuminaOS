//! string 域——mem/str 语义（切片语义 safe 面）。
//!
//! 承接 POSIX `<string.h>` 内存与字符串族。v0 承载形式：
//!
//! - **mem 族双指针以「缓冲区 + 偏移对」承载**：safe Rust 无法构造别名
//!   `&mut`/`&` 视图，偏移对才是 C 双指针（可重叠）语义的诚实 safe 面；
//!   `memcpy` 重叠拒绝 / `memmove` 方向感知（`copy_within` = `ptr::copy`）；
//! - **NUL 终止串以 `&[u8]` 切片承载**——越界访问在 C 为 UB，本面一律
//!   fail-visible 化：容量不足 / 契约违反 → `None` 或 0（静默截断禁令
//!   纪律，pulse 先例）；搜索类返回字节偏移（`Option<usize>`）。
//!
//! C ABI 指针层（raw ptr 签名）挂账见 crate 文档——本面为语义层，
//! 符号名与 C 族一一对应。

use crate::c_int;
use alloc::vec::Vec;

/// 内存复制（`memcpy`）：同缓冲区内两指针域复制——`buf[dst..dst+n]`
/// ⟵ `buf[src..src+n]`。
///
/// 指针对以「缓冲区 + 偏移对」承载（safe Rust 无法构造别名 `&mut`/`&`
/// 视图，偏移对才是 C 双指针语义的诚实 safe 面）。域界越界或二域重叠
/// → `None`（C：重叠为 UB → 契约违反 fail-visible）；成功返回 `Some(n)`。
pub fn memcpy(buf: &mut [u8], dst: usize, src: usize, n: usize) -> Option<usize> {
    bounds(buf, dst, n)?;
    bounds(buf, src, n)?;
    let (ds, de) = (dst, dst + n);
    let (ss, se) = (src, src + n);
    if ds < se && ss < de {
        return None; // 重叠拒绝（C UB → fail-visible）
    }
    if n > 0 {
        buf.copy_within(src..src + n, dst);
    }
    Some(n)
}

/// 内存移动（`memmove`）：允许重叠的同缓冲区复制。
///
/// 语义与 C 完全对齐（`copy_within` = `ptr::copy` = 方向感知移动）。
/// 域界越界 → `None`；成功返回 `Some(n)`。
pub fn memmove(buf: &mut [u8], dst: usize, src: usize, n: usize) -> Option<usize> {
    bounds(buf, dst, n)?;
    bounds(buf, src, n)?;
    if n > 0 {
        buf.copy_within(src..src + n, dst);
    }
    Some(n)
}

/// 域界检查：`[off, off+n)` 必须落在 `buf` 界内，越界返回 `None`。
fn bounds(buf: &[u8], off: usize, n: usize) -> Option<()> {
    off.checked_add(n)
        .and_then(|end| if end <= buf.len() { Some(()) } else { None })
}

/// 内存填充（`memset`）：全片填 `v`，返回填充字节数。
pub fn memset(dst: &mut [u8], v: u8) -> usize {
    let n = dst.len();
    dst.fill(v);
    n
}

/// 内存比较（`memcmp`）：全片字典序，返回 -1/0/1。
///
/// 与 C 的 n 字节比较对齐：公共前缀相同时，较短片视为更小
/// （等价 `memcmp(a, b, min)` 后接长度收尾——C 实践中 n 内相等即 0，
/// 本面为全片字典序的 fail-visible 全量版，见文档）。
#[must_use]
pub fn memcmp(a: &[u8], b: &[u8]) -> c_int {
    match a.cmp(b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// 字节首次出现（`memchr`）：返回片内偏移。
#[must_use]
pub fn memchr(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&x| x == c)
}

/// 字节末次出现（`memrchr`）：返回片内偏移。
#[must_use]
pub fn memrchr(s: &[u8], c: u8) -> Option<usize> {
    s.iter().rposition(|&x| x == c)
}

/// C 串长度（`strlen`）：扫描 NUL 终止符，返回串长（不含 NUL）。
///
/// 片内无 NUL → `None`（C 为越界 UB → fail-visible）。
#[must_use]
pub fn strlen(s: &[u8]) -> Option<usize> {
    memchr(s, 0)
}

/// 有界 C 串长度（`strnlen`）：至多扫描 `max` 字节。
///
/// 找到 NUL 返回串长，未找到返回 `max`（POSIX strnlen 语义，无失败态）。
#[must_use]
pub fn strnlen(s: &[u8], max: usize) -> usize {
    let bound = max.min(s.len());
    memchr(&s[..bound], 0).unwrap_or(bound)
}

/// C 串比较（`strcmp`）：按 NUL 前内容逐字节比较，返回 -1/0/1。
///
/// 任一片无 NUL → `None`（fail-visible）。
#[must_use]
pub fn strcmp(a: &[u8], b: &[u8]) -> Option<c_int> {
    let sa = a.get(..strlen(a)?)?;
    let sb = b.get(..strlen(b)?)?;
    Some(memcmp(sa, sb))
}

/// 有界 C 串比较（`strncmp`）：至多比较 `n` 字节（NUL 亦参与比较）。
///
/// 任一片无 NUL → `None`。
#[must_use]
pub fn strncmp(a: &[u8], b: &[u8], n: usize) -> Option<c_int> {
    let sa = a.get(..strlen(a)?)?;
    let sb = b.get(..strlen(b)?)?;
    let na = sa.get(..n.min(sa.len())).unwrap_or(&[]);
    let nb = sb.get(..n.min(sb.len())).unwrap_or(&[]);
    Some(memcmp(na, nb))
}

/// C 串内字符首次出现（`strchr`）：含 NUL 终止符可寻（`c == 0` 返回
/// 终止符偏移，libc 语义）；片内无 NUL 且未命中 → `None`。
#[must_use]
pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    match memchr(s, c) {
        Some(at) => Some(at),
        // c == 0 时 strlen 即终止符偏移；c != 0 且无 NUL → None
        None if c == 0 => strlen(s),
        None => None,
    }
}

/// C 串内字符末次出现（`strrchr`）：语义同 [`strchr`]，取末次。
#[must_use]
pub fn strrchr(s: &[u8], c: u8) -> Option<usize> {
    match memrchr(s, c) {
        Some(at) => Some(at),
        None if c == 0 => strlen(s),
        None => None,
    }
}

/// 子串首次出现（`strstr`）：干与针均为字节片（有界扫描）。
///
/// 空针 → `Some(0)`（libc 前缀语义）。返回干内偏移。
#[must_use]
pub fn strstr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// 初始跨度（`strspn`）：自首起连续命中 `accept` 集的字符数。
///
/// NUL 终止符终止扫描（C 语义）；无 NUL 时以片界为界。
#[must_use]
pub fn strspn(s: &[u8], accept: &[u8]) -> usize {
    let end = strlen(s).unwrap_or(s.len());
    s[..end].iter().take_while(|c| accept.contains(c)).count()
}

/// 初始反跨度（`strcspn`）：自首起连续**不**命中 `reject` 集的字符数
/// （NUL 终止符终止扫描——故返回值 = 首个 reject 字符或终止符的偏移）。
#[must_use]
pub fn strcspn(s: &[u8], reject: &[u8]) -> usize {
    let end = strlen(s).unwrap_or(s.len());
    s[..end]
        .iter()
        .position(|c| reject.contains(c))
        .unwrap_or(end)
}

/// 集内任意字符首次出现（`strpbrk`）：返回偏移；无命中 → `None`
/// （NUL 终止扫描，C 语义）。
#[must_use]
pub fn strpbrk(s: &[u8], accept: &[u8]) -> Option<usize> {
    let end = strlen(s).unwrap_or(s.len());
    s[..end].iter().position(|c| accept.contains(c))
}

/// 复制 C 串（`strdup`）：NUL 前内容复制为新 `Vec<u8>`（不含 NUL）。
///
/// 片内无 NUL → `None`（fail-visible）。
pub fn strdup(s: &[u8]) -> Option<Vec<u8>> {
    Some(s[..strlen(s)?].to_vec())
}

/// 有界复制 C 串（`strndup`）：至多 `n` 字节（NUL 终止优先）。
///
/// 片内 `n` 界内无 NUL 亦可行（取前 n 字节）；片长不足取全长。
pub fn strndup(s: &[u8], n: usize) -> Option<Vec<u8>> {
    let end = strlen(s).unwrap_or(s.len()).min(n);
    Some(s[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    #[test]
    fn memcpy_and_memmove() {
        // memcpy：常规 / 域界越界 / 重叠拒绝
        let mut d = [1u8, 2, 3, 4, 0, 0, 0, 0];
        assert_eq!(memcpy(&mut d, 4, 0, 4), Some(4));
        assert_eq!(d, [1, 2, 3, 4, 1, 2, 3, 4]);
        assert_eq!(memcpy(&mut d, 6, 0, 4), None, "dst range out of bounds");
        assert_eq!(memcpy(&mut d, 0, 2, 4), None, "overlap must be rejected");
        assert_eq!(memcpy(&mut d, 2, 0, 4), None);
        assert_eq!(memcpy(&mut d, 0, 0, 0), Some(0), "n=0 no-op");
        // memmove：高位重叠方向感知（dst > src，自尾向首）
        let mut m = [1u8, 2, 3, 4, 0];
        assert_eq!(memmove(&mut m, 1, 0, 4), Some(4));
        assert_eq!(m, [1, 1, 2, 3, 4]);
        // memmove：低位重叠（dst < src，自首向尾）
        let mut m2 = [0u8, 1, 2, 3, 4];
        assert_eq!(memmove(&mut m2, 0, 1, 4), Some(4));
        assert_eq!(m2, [1, 2, 3, 4, 4]);
        assert_eq!(memmove(&mut m2, 3, 0, 2), Some(2), "disjoint ranges");
        assert_eq!(memmove(&mut m2, 2, 0, 9), None, "out of bounds");
        assert_eq!(memmove(&mut m2, 1, 1, 2), Some(2), "dst==src no-op");
    }

    #[test]
    fn memset_memcmp_memchr() {
        let mut d = [0u8; 5];
        assert_eq!(memset(&mut d, 0xA5), 5);
        assert!(d.iter().all(|&x| x == 0xA5));
        assert_eq!(memcmp(b"abc", b"abc"), 0);
        assert_eq!(memcmp(b"abc", b"abd"), -1);
        assert_eq!(memcmp(b"ab", b"abc"), -1, "shorter prefix < longer");
        assert_eq!(memcmp(b"b", b"a"), 1);
        assert_eq!(memchr(b"hello", b'l'), Some(2));
        assert_eq!(memrchr(b"hello", b'l'), Some(3));
        assert_eq!(memchr(b"hello", b'z'), None);
    }

    #[test]
    fn strlen_strnlen_fail_visible() {
        assert_eq!(strlen(&cstr("hello")), Some(5));
        assert_eq!(strlen(b""), None, "empty slice has no NUL byte");
        assert_eq!(strlen(b"abc"), None, "unterminated must be None");
        assert_eq!(strnlen(b"abc\0xyz", 100), 3);
        assert_eq!(strnlen(b"abcdef", 3), 3, "no NUL within max -> max");
        assert_eq!(strnlen(b"abcdef", 100), 6, "no NUL, bound by slice end");
    }

    #[test]
    fn strcmp_strncmp() {
        let a = cstr("abc");
        let b = cstr("abd");
        let c = cstr("abc");
        assert_eq!(strcmp(&a, &c), Some(0));
        assert_eq!(strcmp(&a, &b), Some(-1));
        assert_eq!(strcmp(&b, &a), Some(1));
        assert_eq!(strcmp(b"abc", b"abc"), None, "unterminated -> None");
        assert_eq!(strncmp(&a, &b, 2), Some(0), "ab == ab within n=2");
        assert_eq!(strncmp(&a, &b, 3), Some(-1));
        assert_eq!(strncmp(&a, &b, 0), Some(0));
    }

    #[test]
    fn strchr_strrchr_including_terminator() {
        let s = cstr("hello");
        assert_eq!(strchr(&s, b'l'), Some(2));
        assert_eq!(strrchr(&s, b'l'), Some(3));
        assert_eq!(strchr(&s, 0), Some(5), "NUL is addressable");
        assert_eq!(strchr(&s, b'z'), None);
        assert_eq!(strrchr(b"unterminated", 0), None);
        let dup = cstr("aaa");
        assert_eq!(strrchr(&dup, b'a'), Some(2));
    }

    #[test]
    fn strstr_spans_pbrk() {
        let h = cstr("haystack");
        assert_eq!(strstr(&h, b"stack"), Some(3));
        assert_eq!(strstr(&h, b""), Some(0));
        assert_eq!(strstr(&h, b"needle"), None);
        assert_eq!(strstr(b"short", b"shorter-than"), None);
        let s = cstr("abcabc");
        assert_eq!(strspn(&s, b"ab"), 2);
        assert_eq!(strcspn(&s, b"c"), 2);
        assert_eq!(strcspn(&s, b"z"), 6, "stop at terminator");
        assert_eq!(strpbrk(&s, b"cb"), Some(1), "first hit is b@1");
        assert_eq!(strpbrk(&s, b"z"), None);
    }

    #[test]
    fn strdup_strndup() {
        let s = cstr("dup me");
        assert_eq!(strdup(&s).as_deref(), Some(&b"dup me"[..]));
        assert_eq!(strdup(b"no-nul"), None);
        assert_eq!(strndup(&s, 3).as_deref(), Some(&b"dup"[..]));
        assert_eq!(strndup(&s, 100).as_deref(), Some(&b"dup me"[..]));
        assert_eq!(strndup(b"unterminated", 4).as_deref(), Some(&b"unte"[..]));
    }
}
