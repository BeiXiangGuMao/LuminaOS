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

/// C 串复制（`strcpy`）：`src`（须含 NUL）复制入 `dst` 并补 NUL；
/// `dst` 容量须 ≥ len+1，否则 `None`（C 溢出 UB → fail-visible）。
/// 返回复制长度（= NUL 写位下标——[`stpcpy`] 语义同行）。
pub fn strcpy(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let len = strlen(src)?;
    if dst.len() < len + 1 {
        return None;
    }
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
    Some(len)
}

/// 有界 C 串复制（`strncpy`）：至多 `n` 字节；`src` 短于 `n` 时以 NUL
/// 补足至 `n`（C 语义照办）；返回写入字节数（恒 `n`，`dst` 须容 `n`）。
///
/// `src` 片内无 NUL 且片长 < `n` → 以片界为界（C 越界读 UB → 界内化）。
pub fn strncpy(dst: &mut [u8], src: &[u8], n: usize) -> Option<usize> {
    if dst.len() < n {
        return None;
    }
    let len = strnlen(src, n);
    dst[..len].copy_from_slice(&src[..len]);
    for b in &mut dst[len..n] {
        *b = 0;
    }
    Some(n)
}

/// C 串追加（`strcat`）：`dst` 须已含 NUL（追加点）；`dst` 容量须 ≥
/// len+srclen+1。返回追加后总长。
pub fn strcat(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let at = strlen(dst)?;
    let slen = strlen(src)?;
    if dst.len() < at + slen + 1 {
        return None;
    }
    dst[at..at + slen].copy_from_slice(&src[..slen]);
    dst[at + slen] = 0;
    Some(at + slen)
}

/// 有界 C 串追加（`strncat`）：至多追加 `n` 字节（NUL 终止优先）+
/// 终止 NUL。返回追加后总长。
pub fn strncat(dst: &mut [u8], src: &[u8], n: usize) -> Option<usize> {
    let at = strlen(dst)?;
    let slen = strnlen(src, n);
    if dst.len() < at + slen + 1 {
        return None;
    }
    dst[at..at + slen].copy_from_slice(&src[..slen]);
    dst[at + slen] = 0;
    Some(at + slen)
}

/// C 串复制·尾指针语义（`stpcpy`）：返回 NUL 写位下标（C 返回指向
/// 终止 NUL 的指针——偏移映射）。
pub fn stpcpy(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    strcpy(dst, src)
}

/// 有界 C 串复制·尾指针语义（`stpncpy`）：`src` 短于 `n` → 返回 NUL
/// 写位；`src` ≥ `n` → 返回 `n`（无 NUL 写入，C 照办）。
pub fn stpncpy(dst: &mut [u8], src: &[u8], n: usize) -> Option<usize> {
    if dst.len() < n {
        return None;
    }
    let len = strnlen(src, n);
    dst[..len].copy_from_slice(&src[..len]);
    if len < n {
        for b in &mut dst[len..n] {
            *b = 0;
        }
        Some(len)
    } else {
        Some(n)
    }
}

/// 分词（`strtok`）：进程级游标全局面（C 内部 saveptr——指针同一性
/// 承载：续扫须重传**同一**基串，本面无 NULL 续扫——偏差登记）。
///
/// 首调（游标未指同串）= 自 0 起扫；续调 = 自上次游标续扫。返回 token
/// （所有权克隆）；耗尽 → `None`（游标复位）。
///
/// 偏差登记：C 允许两次调用间改传不同串/NULL——本面以指针同一性判定
/// 续扫，异串 = 全新分词（C saveptr 误用同域险情，登记）。
pub fn strtok(s: &[u8], delim: &[u8]) -> Option<Vec<u8>> {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    static BASE: AtomicUsize = AtomicUsize::new(0);
    static OFF: AtomicUsize = AtomicUsize::new(0);
    static LIVE: AtomicBool = AtomicBool::new(false);
    let base = s.as_ptr() as usize;
    let start = if LIVE.load(Ordering::Relaxed) && BASE.load(Ordering::Relaxed) == base {
        OFF.load(Ordering::Relaxed).min(s.len())
    } else {
        0
    };
    let (token, next) = strtok_scan(s, start, delim)?;
    LIVE.store(true, Ordering::Relaxed);
    BASE.store(base, Ordering::Relaxed);
    OFF.store(next, Ordering::Relaxed);
    Some(token)
}

/// 分词·显式游标（`strtok_r`）：`saveptr` 承载**剩余串**（C `char **`
/// 的所有权面映射）；首调传 `Some(s)`，续调传 `None`。
pub fn strtok_r(s: Option<&[u8]>, delim: &[u8], saveptr: &mut Option<Vec<u8>>) -> Option<Vec<u8>> {
    let rest: Vec<u8> = match (s, saveptr.as_ref()) {
        (Some(x), _) => x.to_vec(),
        (None, Some(r)) => r.clone(),
        (None, None) => return None,
    };
    let (token, consumed) = strtok_scan(&rest, 0, delim)?;
    let remaining: Vec<u8> = rest[consumed.min(rest.len())..].to_vec();
    *saveptr = Some(remaining);
    Some(token)
}

/// 分词扫描内核：`start` 起跳过前导分隔符 → token 终界；返回
/// `(token, 下一扫描位)`。无 token → `None`。
fn strtok_scan(s: &[u8], start: usize, delim: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut i = start;
    while i < s.len() && s[i] != 0 && delim.contains(&s[i]) {
        i += 1;
    }
    if i >= s.len() || s[i] == 0 {
        return None;
    }
    let tok_start = i;
    while i < s.len() && s[i] != 0 && !delim.contains(&s[i]) {
        i += 1;
    }
    Some((s[tok_start..i].to_vec(), i))
}

/// "C" locale 串比较（`strcoll`）：恒等 [`strcmp`]（collation 面 = 字节
/// 序——"C" locale 纪律，locale 面挂账）。
pub fn strcoll(a: &[u8], b: &[u8]) -> Option<c_int> {
    strcmp(a, b)
}

/// 变换（`strxfrm`）："C" locale 下恒等复制（C 语义照办——返回**全变换
/// 长度**（不含 NUL）；`dst` 足容则全拷 + NUL，否则截断拷 + NUL）。
pub fn strxfrm(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let full = strlen(src)?;
    let write = full.min(dst.len().saturating_sub(1));
    dst[..write].copy_from_slice(&src[..write]);
    dst[write] = 0;
    Some(full)
}

/// 错误串·线程安全面（`strerror_r`）：名称表查得 [`crate::errno::strerror`]
/// 写入 `buf`（含 NUL）；XSI 返回值域照办——0 = 成功 / `ERANGE` = 缓冲
/// 不足（内容截断 + NUL）/ `EINVAL` = 未知错误码。
pub fn strerror_r(errnum: c_int, buf: &mut [u8]) -> c_int {
    let name = crate::errno::strerror(errnum);
    if buf.is_empty() {
        return crate::errno::ERANGE;
    }
    if name == "EUNKNOWN" {
        // 未知码（含 0）：XSI EINVAL 面（名称表 miss）
        buf[0] = 0;
        return crate::errno::EINVAL;
    }
    let name = name.as_bytes();
    let write = name.len().min(buf.len() - 1);
    buf[..write].copy_from_slice(&name[..write]);
    buf[write] = 0;
    if write < name.len() {
        return crate::errno::ERANGE;
    }
    0
}

/// 限量复制至遇字符（`memccpy`）：`src` 前域复制至 `c` 首现（含）或
/// `n` 尽；命中返回 dst 内**止点后偏移**（C 返回指针的偏移映射），
/// 未命中 → `None`。
pub fn memccpy(dst: &mut [u8], src: &[u8], c: u8, n: usize) -> Option<usize> {
    let n = n.min(src.len()).min(dst.len());
    for i in 0..n {
        dst[i] = src[i];
        if src[i] == c {
            return Some(i + 1);
        }
    }
    None
}

/// 位翻转域（`memfrob`）：前 `n` 字节逐位 XOR `0x2A`（越界钳位——C 为
/// 无界 UB → 确定行为登记）；返回处理字节数。
pub fn memfrob(buf: &mut [u8], n: usize) -> usize {
    let n = n.min(buf.len());
    for b in &mut buf[..n] {
        *b ^= 0x2A;
    }
    n
}

/// 域移动复制（`bcopy`）：语义同 [`memmove`]（允许重叠，方向感知）；
/// 返回 `Some(n)` / 域界越界 `None`。
pub fn bcopy(buf: &mut [u8], dst: usize, src: usize, n: usize) -> Option<usize> {
    memmove(buf, dst, src, n)
}

/// 域清零（`bzero`）：前 `n` 字节清零（越界钳位——C UB → 确定行为）；
/// 返回处理字节数。
pub fn bzero(buf: &mut [u8], n: usize) -> usize {
    let n = n.min(buf.len());
    buf[..n].fill(0);
    n
}

/// 域比较（`bcmp`）：0 = 全等 / 1 = 有异（C 历史返回值域 0/非零）。
#[must_use]
pub fn bcmp(a: &[u8], b: &[u8]) -> c_int {
    c_int::from(a != b)
}

/// 字符首现·历史名（`index`）= [`strchr`]。
pub fn index(s: &[u8], c: u8) -> Option<usize> {
    strchr(s, c)
}

/// 字符末现·历史名（`rindex`）= [`strrchr`]。
pub fn rindex(s: &[u8], c: u8) -> Option<usize> {
    strrchr(s, c)
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

    /// 扩容批：strcpy/strncpy/stpcpy/stpncpy 复制族。
    #[test]
    fn copy_family_extended() {
        let mut d = [0u8; 8];
        assert_eq!(strcpy(&mut d, &cstr("hey")), Some(3));
        assert_eq!(&d[..4], b"hey\0");
        assert_eq!(strcpy(&mut d, b"no-nul"), None, "src unterminated");
        assert_eq!(strcpy(&mut [0u8; 3], &cstr("abcd")), None, "dst too small");
        // stpcpy 尾指针 = NUL 位
        let mut d = [0u8; 8];
        assert_eq!(stpcpy(&mut d, &cstr("ab")), Some(2));
        assert_eq!(d[2], 0);
        // strncpy：短源补 NUL 至 n
        let mut d = [0xFFu8; 6];
        assert_eq!(strncpy(&mut d, &cstr("ab"), 5), Some(5));
        assert_eq!(&d, b"ab\0\0\0\xFF");
        // strncpy：长源截断（无 NUL 写入）
        let mut d = [0u8; 3];
        assert_eq!(strncpy(&mut d, b"abcdef", 3), Some(3));
        assert_eq!(&d, b"abc");
        // strncpy：dst 不够
        assert_eq!(strncpy(&mut [0u8; 2], &cstr("ab"), 5), None);
        // stpncpy：短源 → NUL 位；长源 → n
        let mut d = [0u8; 6];
        assert_eq!(stpncpy(&mut d, &cstr("ab"), 4), Some(2));
        assert_eq!(&d[..4], b"ab\0\0");
        let mut d = [0u8; 3];
        assert_eq!(stpncpy(&mut d, b"abcdef", 3), Some(3));
    }

    /// 扩容批：strcat/strncat 追加族。
    #[test]
    fn append_family_extended() {
        let mut d = [0u8; 10];
        assert_eq!(strcpy(&mut d, &cstr("ab")), Some(2));
        assert_eq!(strcat(&mut d, &cstr("cd")), Some(4));
        assert_eq!(&d[..5], b"abcd\0");
        // dst 无 NUL → None
        let mut raw = *b"ab";
        assert_eq!(strcat(&mut raw, &cstr("x")), None);
        // 容量不足
        let mut d = [0u8; 4];
        assert_eq!(strcpy(&mut d, &cstr("abc")), Some(3));
        assert_eq!(strcat(&mut d, &cstr("de")), None);
        // strncat：n 界（NUL 终止优先）
        let mut d = [0u8; 8];
        assert_eq!(strcpy(&mut d, &cstr("ab")), Some(2));
        assert_eq!(strncat(&mut d, &cstr("cdef"), 2), Some(4));
        assert_eq!(&d[..5], b"abcd\0");
    }

    /// 扩容批：strtok 全局游标 / strtok_r 显式游标。
    #[test]
    fn strtok_family() {
        // strtok：指针同一性续扫（同串重传）
        let s = cstr("a,b,,c");
        assert_eq!(strtok(&s, b",").as_deref(), Some(&b"a"[..]));
        assert_eq!(strtok(&s, b",").as_deref(), Some(&b"b"[..]));
        assert_eq!(strtok(&s, b",").as_deref(), Some(&b"c"[..]));
        assert_eq!(strtok(&s, b","), None, "exhausted");
        // 异串 = 全新分词（指针同一性判定，登记面）
        let t = cstr("x;y");
        assert_eq!(strtok(&t, b";").as_deref(), Some(&b"x"[..]));
        // strtok_r：显式 saveptr
        let mut save = None;
        let s = cstr("one two three");
        assert_eq!(
            strtok_r(Some(&s), b" ", &mut save).as_deref(),
            Some(&b"one"[..])
        );
        assert_eq!(
            strtok_r(None, b" ", &mut save).as_deref(),
            Some(&b"two"[..])
        );
        assert_eq!(
            strtok_r(None, b" ", &mut save).as_deref(),
            Some(&b"three"[..])
        );
        assert_eq!(strtok_r(None, b" ", &mut save), None, "exhausted");
        // strtok_r：(None, None) → None
        let mut empty = None;
        assert_eq!(strtok_r(None, b" ", &mut empty), None);
        // 分隔符前导/尾随
        let mut save = None;
        let s = cstr(",,a,,");
        assert_eq!(
            strtok_r(Some(&s), b",", &mut save).as_deref(),
            Some(&b"a"[..])
        );
        assert_eq!(strtok_r(None, b",", &mut save), None);
    }

    /// 扩容批：strcoll/strxfrm/strerror_r（"C" locale 面）。
    #[test]
    fn locale_and_strerror_r() {
        let a = cstr("abc");
        let b = cstr("abd");
        assert_eq!(strcoll(&a, &a), Some(0));
        assert_eq!(strcoll(&a, &b), Some(-1));
        // strxfrm：足容全拷 + 返回全长
        let mut d = [0u8; 8];
        assert_eq!(strxfrm(&mut d, &cstr("xyz")), Some(3));
        assert_eq!(&d[..4], b"xyz\0");
        // 截断仍返全长（C 语义照办）
        let mut d = [0u8; 3];
        assert_eq!(strxfrm(&mut d, &cstr("xyzw")), Some(4));
        assert_eq!(&d, b"xy\0");
        // strerror_r：已知/未知/小缓冲
        let mut buf = [0u8; 16];
        assert_eq!(strerror_r(crate::errno::EINVAL, &mut buf), 0);
        assert_eq!(&buf[..7], b"EINVAL\0");
        let mut small = [0u8; 3];
        assert_eq!(
            strerror_r(crate::errno::EINVAL, &mut small),
            crate::errno::ERANGE
        );
        assert_eq!(&small[..2], b"EI", "truncated + NUL");
        assert_eq!(small[2], 0);
        let mut buf = [0u8; 16];
        assert_eq!(strerror_r(99999, &mut buf), crate::errno::EINVAL);
        assert_eq!(buf[0], 0);
        let mut empty: [u8; 0] = [];
        assert_eq!(strerror_r(1, &mut empty), crate::errno::ERANGE);
    }

    /// 扩容批：memccpy/memfrob/bcopy/bzero/bcmp/index/rindex。
    #[test]
    fn mem_legacy_family() {
        // memccpy：命中止点 / 未命中
        let mut d = [0u8; 8];
        assert_eq!(memccpy(&mut d, b"aXbXc", b'b', 5), Some(3));
        assert_eq!(&d[..3], b"aXb");
        let mut d = [0u8; 8];
        assert_eq!(memccpy(&mut d, b"aXbXc", b'z', 5), None);
        // memfrob：XOR 0x2A（frob("Hello") = "bOFFE"—— involutive：再 frob 复原）
        let mut buf = *b"Hello";
        assert_eq!(memfrob(&mut buf, 5), 5);
        assert_eq!(&buf, b"bOFFE");
        assert_eq!(memfrob(&mut buf, 5), 5);
        assert_eq!(&buf, b"Hello", "frob is involutive");
        // bcopy：重叠方向感知（同 memmove）
        let mut m = [1u8, 2, 3, 4, 0];
        assert_eq!(bcopy(&mut m, 1, 0, 4), Some(4));
        assert_eq!(m, [1, 1, 2, 3, 4]);
        assert_eq!(bcopy(&mut m, 5, 0, 2), None, "out of bounds");
        // bzero
        let mut z = [0xAAu8; 4];
        assert_eq!(bzero(&mut z, 2), 2);
        assert_eq!(z, [0, 0, 0xAA, 0xAA]);
        // bcmp：0/1 值域（非符号）
        assert_eq!(bcmp(b"ab", b"ab"), 0);
        assert_eq!(bcmp(b"ab", b"ac"), 1);
        assert_eq!(bcmp(b"ab", b"ab\0"), 1, "length participates");
        // index/rindex = strchr/strrchr
        let s = cstr("hello");
        assert_eq!(index(&s, b'l'), Some(2));
        assert_eq!(rindex(&s, b'l'), Some(3));
        assert_eq!(index(&s, b'z'), None);
    }
}
