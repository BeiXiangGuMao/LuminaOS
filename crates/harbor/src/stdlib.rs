//! stdlib 域——数值转换、排序与伪随机。
//!
//! 承接 POSIX `<stdlib.h>` 符号面（M29 首批 20 项 + M35-H1c 扩容 10 项）：
//! abs/div 族为值语义 `extern "C"`；strto* 为切片语义 safe 面（返回
//! `(值, 消耗字节数)` 对，等价 C 的 `endptr` 惯用法）；qsort/bsearch/
//! qsort_r 为 Rust 泛型切片面；rand/srand/rand_r 为 LCG 伪随机（数值
//! recipes 风格，v0 决定论实现）；mbr/wcs 转换族为 "C" locale ASCII 单
//! 字节面（多字节编码面挂账）。
//!
//! **C UB 的 fail-visible 化**：
//! - div 族除零 / `i32::MIN / -1` 溢出：C 为 UB，本面返回 `{0, 0}` 哨兵
//!   （文档化确定行为，零 panic 载体纪律）；
//! - strto* 溢出：POSIX defined（钳位 + `errno = ERANGE`）——照办；
//! - `atoi` = `(int)strtol(s, 10)` 截断语义（POSIX 等式照办）；
//! - mbstowcs/wcstombs 非法序列：C 返 `(size_t)-1`——照办（哨兵值登记）。
//!
//! # M35-H1c 扩容批（10 符号）承载形式
//!
//! - **strtoimax/strtoumax**：LP64 下 `intmax_t`/`uintmax_t` 与 long 同宽
//!   ——strtol/strtoull 引擎复用（双符号齐备纪律）；
//! - **mblen/mbtowc/wctomb**："C" locale 单字节编码（ASCII 0..=0x7F，
//!   越域 → `-1` + `errno = EILSEQ`；C 多字节状态机面挂账）；
//! - **mbstowcs/wcstombs**：逐元素 ASCII 往返（非法 → `usize::MAX` 哨兵
//!   = C `(size_t)-1` 照办；目标容量尽即停 = C `n` 界语义）；
//! - **qsort_r**：C `compar(a, b, arg)` 上下文指针 → 闭包捕获等价化
//!   （登记）；**rand_r**：调用方持种子（可重入，全局态面不触及）；
//!   **atof** = `strtod(s).0` 等式照办。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::c_int;
use crate::ctype;
use crate::errno::{self, ERANGE};
use crate::{c_intmax, c_long, c_ulong};

/// `div` 结果（POSIX `div_t`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DivT {
    /// 商。
    pub quot: c_int,
    /// 余。
    pub rem: c_int,
}

/// `ldiv` 结果（POSIX `ldiv_t`；LP64 下与 `lldiv_t` 同构但符号独立）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LdivT {
    /// 商。
    pub quot: c_long,
    /// 余。
    pub rem: c_long,
}

/// 绝对值（`abs`）。`i32::MIN` 的绝对值 C 为 UB，本面为 wrapping
/// （返回 `i32::MIN`）——文档化确定行为。
#[must_use]
pub extern "C" fn abs(x: c_int) -> c_int {
    x.wrapping_abs()
}

/// 绝对值（`labs`，`long` 域；`i64::MIN` wrapping 语义同 [`abs`]）。
#[must_use]
pub extern "C" fn labs(x: c_long) -> c_long {
    x.wrapping_abs()
}

/// 绝对值（`llabs`，`long long` 域）。
#[must_use]
pub extern "C" fn llabs(x: i64) -> i64 {
    x.wrapping_abs()
}

/// 绝对值（`imaxabs`，`intmax_t` 域）。
#[must_use]
pub extern "C" fn imaxabs(x: c_intmax) -> c_intmax {
    x.wrapping_abs()
}

/// 整除（`div`）。除零 / 溢出（`i32::MIN / -1`）→ `{0, 0}` 哨兵。
#[must_use]
pub extern "C" fn div(numer: c_int, denom: c_int) -> DivT {
    match numer.checked_div(denom) {
        Some(q) => DivT {
            quot: q,
            rem: numer - q * denom,
        },
        None => DivT { quot: 0, rem: 0 },
    }
}

/// 整除（`ldiv`，`long` 域；哨兵语义同 [`div`]）。
#[must_use]
pub extern "C" fn ldiv(numer: c_long, denom: c_long) -> LdivT {
    match numer.checked_div(denom) {
        Some(q) => LdivT {
            quot: q,
            rem: numer - q * denom,
        },
        None => LdivT { quot: 0, rem: 0 },
    }
}

/// 整除（`lldiv`，`long long` 域）。
#[must_use]
pub extern "C" fn lldiv(numer: i64, denom: i64) -> LdivT {
    let r = ldiv(numer, denom);
    LdivT {
        quot: r.quot,
        rem: r.rem,
    }
}

/// 整除（`imaxdiv`，`intmax_t` 域）。
#[must_use]
pub extern "C" fn imaxdiv(numer: c_intmax, denom: c_intmax) -> LdivT {
    ldiv(numer, denom)
}

/// LCG 伪随机状态（进程级；初值 1 = POSIX「启动即 srand(1)」语义）。
static RAND_STATE: AtomicU32 = AtomicU32::new(1);

/// 设置伪随机种子（`srand`）。
pub extern "C" fn srand(seed: crate::c_uint) {
    RAND_STATE.store(seed, Ordering::Relaxed);
}

/// 伪随机数（`rand`）：返回 0..=32767（LCG：state = state*1664525 + 1013904223，
/// 取高 15 位——数值 recipes 风格，v0 决定论实现，非密码学面）。
#[must_use]
pub extern "C" fn rand() -> c_int {
    let next = RAND_STATE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |s| {
            Some(s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223))
        })
        .unwrap_or(1_013_904_223);
    ((next >> 16) & 0x7FFF) as c_int
}

/// 十进制整数转换（`atoi`）：等式 `(int)strtol(s, 10)` 截断语义。
#[must_use]
pub fn atoi(s: &[u8]) -> c_int {
    let (v, _) = strtol(s, 10);
    v as c_int
}

/// 十进制整数转换（`atol`，`long` 域）。
#[must_use]
pub fn atol(s: &[u8]) -> c_long {
    let (v, _) = strtol(s, 10);
    v
}

/// 十进制整数转换（`atoll`，`long long` 域）。
#[must_use]
pub fn atoll(s: &[u8]) -> i64 {
    let (v, _) = strtol(s, 10);
    v
}

/// 有基整数转换（`strtol`）：`(值, 消耗字节数)`。
///
/// - `base = 0` 自检测（`0x`/`0X` 十六进制、`0` 八进制、余为十进制）；
/// - `base ∈ 2..=36` 显式基（字母不区分大小写）；
/// - 溢出钳位 + `errno = ERANGE`（POSIX defined 语义）；
/// - 无可转换数字 → `(0, 0)`（endptr = nptr 惯用法）；
/// - `"0x"` 后无十六进制位 → 按单字符 `"0"` 转换（POSIX 最长前缀规则）。
pub fn strtol(s: &[u8], base: c_int) -> (c_long, usize) {
    let (acc, consumed, neg, overflow) = scan_signed(s, base);
    let v = if overflow {
        // POSIX 溢出钳位（errno 已由扫描核置 ERANGE）
        if neg {
            i64::MIN
        } else {
            i64::MAX
        }
    } else if neg {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    };
    (v, consumed)
}

/// 有基整数转换（`strtoll`）：LP64 下与 [`strtol`] 同宽，符号齐备。
pub fn strtoll(s: &[u8], base: c_int) -> (i64, usize) {
    strtol(s, base)
}

/// 有基无符号转换（`strtoul`）：`long` 域。
pub fn strtoul(s: &[u8], base: c_int) -> (c_ulong, usize) {
    strtoull(s, base)
}

/// 有基无符号转换（`strtoull`）：`(值, 消耗字节数)`。
///
/// POSIX 语义照办：接受 `-` 前缀（按 2^64 模取负）；溢出 → `u64::MAX`
/// + `errno = ERANGE`。
pub fn strtoull(s: &[u8], base: c_int) -> (c_ulong, usize) {
    let (acc, consumed, neg, overflow) = scan_magnitude(s, base, u64::MAX as u128);
    if overflow {
        errno::set_errno(ERANGE);
        return (u64::MAX, consumed);
    }
    let v = acc as u64;
    (if neg { v.wrapping_neg() } else { v }, consumed)
}

/// 十进制浮点转换（`strtod`）：`(值, 消耗字节数)`。
///
/// 文法：`[ws][±]digits[.digits][(e|E)[±]digits]`（小数与指数至少一侧
/// 有位）。溢出（±∞）→ `errno = ERANGE`（POSIX HUGE_VAL 语义）。
pub fn strtod(s: &[u8]) -> (f64, usize) {
    let mut i = 0;
    while i < s.len() && ctype::isspace(s[i] as c_int) != 0 {
        i += 1;
    }
    let start = i;
    let mut j = i;
    if j < s.len() && (s[j] == b'+' || s[j] == b'-') {
        j += 1;
    }
    let int_digits = count_digits(s, j);
    j += int_digits;
    let mut frac_digits = 0;
    if j < s.len() && s[j] == b'.' {
        frac_digits = count_digits(s, j + 1);
        if int_digits > 0 || frac_digits > 0 {
            j += 1 + frac_digits;
        }
    }
    if int_digits == 0 && frac_digits == 0 {
        return (0.0, 0);
    }
    // 指数段：仅当 e 后至少一位数字才计入
    let mut end = j;
    if j < s.len() && (s[j] == b'e' || s[j] == b'E') {
        let mut k = j + 1;
        if k < s.len() && (s[k] == b'+' || s[k] == b'-') {
            k += 1;
        }
        if count_digits(s, k) > 0 {
            end = k + count_digits(s, k);
        }
    }
    let consumed = end;
    let text = core::str::from_utf8(&s[start..end]).unwrap_or("0");
    let v: f64 = text.parse().unwrap_or(0.0);
    if v.is_infinite() {
        errno::set_errno(ERANGE);
    }
    (v, consumed)
}

/// 排序（`qsort`）：确定性稳定排序（Rust 泛型切片面；libc 比较器形态
/// 由 `Ord` 承接——多匹配场景 libc 未定义序，稳定序为文档化超集）。
pub fn qsort<T: Ord>(v: &mut [T]) {
    v.sort();
}

/// 二分查找（`bsearch`）：有序片内查找 `key`，命中返回任一下标
/// （libc 未定义重键命中位次），未命中返回 `None`。
#[must_use]
pub fn bsearch<T: Ord>(key: &T, base: &[T]) -> Option<usize> {
    base.binary_search(key).ok()
}

// -------------------------------------------------------- 内部扫描基元

fn count_digits(s: &[u8], from: usize) -> usize {
    s[from..]
        .iter()
        .take_while(|&&c| ctype::isdigit(c as c_int) != 0)
        .count()
}

/// 符号整数扫描共享核：返回 `(幅值 u128, 消耗字节数, 负号, 溢出旗)`。
/// 幅值上限 `limit` 供溢出判定（正域 i64::MAX，负域 i64::MIN 幅值，
/// 无符号域 u64::MAX）。溢出时置 `errno = ERANGE`（signed/unsigned
/// 共用 POSIX 语义）。
fn scan_magnitude(s: &[u8], base: c_int, limit: u128) -> (u128, usize, bool, bool) {
    let mut i = 0;
    while i < s.len() && ctype::isspace(s[i] as c_int) != 0 {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if neg || (i < s.len() && s[i] == b'+') {
        i += 1;
    }
    // 基解析
    let (base, prefix_len) = if base == 0 {
        if i + 1 < s.len() && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' {
            (16, 2)
        } else if i < s.len() && s[i] == b'0' {
            (8, 0)
        } else {
            (10, 0)
        }
    } else if base == 16 && i + 1 < s.len() && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' {
        (16, 2)
    } else {
        (base as u32, 0)
    };
    let digits_from = i + prefix_len;
    let mut d = digits_from;
    while d < s.len() {
        let c = s[d];
        let v = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'z' => u32::from(c - b'a') + 10,
            b'A'..=b'Z' => u32::from(c - b'A') + 10,
            _ => break,
        };
        if v >= base {
            break;
        }
        d += 1;
    }
    let digit_count = d - digits_from;
    if digit_count == 0 {
        if prefix_len > 0 {
            // "0x" 无十六进制位 → 按单字符 "0" 转换（POSIX 最长前缀规则）
            return (0, i + 1, neg, false);
        }
        return (0, 0, neg, false);
    }
    let mut acc: u128 = 0;
    let mut overflow = false;
    for &c in &s[digits_from..d] {
        let v = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'z' => u32::from(c - b'a') + 10,
            _ => u32::from(c - b'A') + 10,
        };
        let next = acc
            .checked_mul(u128::from(base))
            .and_then(|m| m.checked_add(u128::from(v)));
        match next {
            Some(x) if x <= limit => acc = x,
            _ => {
                overflow = true;
                break;
            }
        }
    }
    if overflow {
        errno::set_errno(ERANGE);
    }
    (acc, d, neg, overflow)
}

/// 符号整数扫描：幅值核 + 符号域钳位判定（正 i64::MAX / 负 i64::MIN 幅值）。
/// 溢出/超域时 errno 已置 ERANGE（幅值核管 overflow，本层管 over 超域）。
fn scan_signed(s: &[u8], base: c_int) -> (u128, usize, bool, bool) {
    let neg_limit_mag = 0x8000_0000_0000_0000u128; // |i64::MIN|
    let pos_limit = 0x7FFF_FFFF_FFFF_FFFFu128; // i64::MAX
    let (acc, consumed, neg, overflow) = scan_magnitude(s, base, neg_limit_mag);
    if overflow {
        return (0, consumed, neg, true);
    }
    let over = if neg {
        acc > neg_limit_mag
    } else {
        acc > pos_limit
    };
    if over {
        errno::set_errno(ERANGE);
        return (0, consumed, neg, true);
    }
    (acc, consumed, neg, false)
}

// ───── M35-H1c 扩容批（10 符号）─────

/// 有基整数转换（`strtoimax`，`intmax_t` 域）：LP64 下与 [`strtol`] 同宽。
pub fn strtoimax(s: &[u8], base: c_int) -> (c_intmax, usize) {
    strtol(s, base)
}

/// 有基无符号转换（`strtoumax`，`uintmax_t` 域）：LP64 下与
/// [`strtoull`] 同宽（负号模取负语义随行）。
pub fn strtoumax(s: &[u8], base: c_int) -> (crate::c_uintmax, usize) {
    strtoull(s, base)
}

/// ASCII 单字节判定基元（"C" locale mb 面）。
fn ascii_ok(b: u8) -> bool {
    b < 0x80
}

/// 多字节字符长度（`mblen`）：`None` = 复位（返 0）；空片 = `n = 0`
/// （返 0）；NUL 首字节 = 0；ASCII = 1；非 ASCII = `-1` +
/// `errno = EILSEQ`（"C" locale 单字节纪律，状态机面挂账）。
pub fn mblen(s: Option<&[u8]>) -> c_int {
    match s {
        None => 0,
        Some([]) => 0,
        Some(x) if x[0] == 0 => 0,
        Some(x) if ascii_ok(x[0]) => 1,
        Some(_) => {
            errno::set_errno(crate::errno::EILSEQ);
            -1
        }
    }
}

/// 多字节转宽字符（`mbtowc`）：语义同 [`mblen`]，ASCII 时写 `out`。
pub fn mbtowc(out: &mut crate::wchar_t, s: Option<&[u8]>) -> c_int {
    match s {
        None => 0,
        Some([]) => 0,
        Some(x) if x[0] == 0 => 0,
        Some(x) if ascii_ok(x[0]) => {
            *out = crate::wchar_t::from(x[0]);
            1
        }
        Some(_) => {
            errno::set_errno(crate::errno::EILSEQ);
            -1
        }
    }
}

/// 宽字符转多字节（`wctomb`）：ASCII 0..=0x7F 写 `buf[0]` 返 1；NUL 宽
/// 字符照写（C 语义）；越域 → `-1` + `errno = EILSEQ`（"C" locale；
/// 复位面随 `buf` 缺省承载——C `s = NULL` 复位态挂账）。
pub fn wctomb(buf: &mut [u8], wc: crate::wchar_t) -> c_int {
    if buf.is_empty() {
        errno::set_errno(crate::errno::EILSEQ);
        return -1;
    }
    if (0..=0x7F).contains(&wc) {
        buf[0] = wc as u8;
        1
    } else {
        errno::set_errno(crate::errno::EILSEQ);
        -1
    }
}

/// 多字节串转宽串（`mbstowcs`）：逐字节 ASCII 往返，NUL 止（NUL 不计数；
/// 目标容量尽即停返已转数——C `n` 界语义）；非法字节 → `usize::MAX`
/// （C `(size_t)-1` 照办）。
pub fn mbstowcs(dst: &mut [crate::wchar_t], src: &[u8]) -> usize {
    for (i, &b) in src.iter().enumerate() {
        if b == 0 {
            return i;
        }
        if i >= dst.len() {
            return dst.len();
        }
        if !ascii_ok(b) {
            return usize::MAX;
        }
        dst[i] = crate::wchar_t::from(b);
    }
    src.len()
}

/// 宽串转多字节串（`wcstombs`）：逐宽字符 ASCII 往返，NUL 宽字符止
/// （不计数；目标容量尽即停返已转数——C `n` 界语义；有容则补 NUL 不
/// 计数——C 语义照办）；越域宽字符 → `usize::MAX`。
pub fn wcstombs(dst: &mut [u8], src: &[crate::wchar_t]) -> usize {
    for (i, &w) in src.iter().enumerate() {
        if w == 0 {
            if i < dst.len() {
                dst[i] = 0;
            }
            return i;
        }
        if i >= dst.len() {
            return dst.len();
        }
        if !(0..=0x7F).contains(&w) {
            return usize::MAX;
        }
        dst[i] = w as u8;
    }
    src.len()
}

/// 排序·比较器面（`qsort_r`）：C `compar(a, b, arg)` 上下文指针 → 闭包
/// 捕获等价化（登记）；确定性稳定排序（qsort 同纪律）。
pub fn qsort_r<T>(v: &mut [T], compar: impl Fn(&T, &T) -> c_int) {
    v.sort_by(|a, b| compar(a, b).cmp(&0));
}

/// 伪随机·可重入（`rand_r`）：调用方持种子（LCG 常数与 [`rand`] 同源；
/// 取高 15 位——0..=32767）。
#[must_use]
pub fn rand_r(seed: &mut crate::c_uint) -> c_int {
    let next = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *seed = next;
    ((next >> 16) & 0x7FFF) as c_int
}

/// 十进制浮点转换（`atof`）= `strtod(s).0` 等式照办。
#[must_use]
pub fn atof(s: &[u8]) -> f64 {
    let (v, _) = strtod(s);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::errno;

    #[test]
    fn abs_family() {
        assert_eq!(abs(-5), 5);
        assert_eq!(abs(5), 5);
        assert_eq!(abs(0), 0);
        assert_eq!(labs(-7), 7);
        assert_eq!(llabs(-9), 9);
        assert_eq!(imaxabs(-7), 7);
        // i32::MIN / i64::MIN：C 为 UB → wrapping 文档化行为
        assert_eq!(abs(i32::MIN), i32::MIN);
        assert_eq!(labs(i64::MIN), i64::MIN);
    }

    #[test]
    fn div_family_and_sentinels() {
        assert_eq!(div(7, 2), DivT { quot: 3, rem: 1 });
        assert_eq!(
            div(-7, 2),
            DivT { quot: -3, rem: -1 },
            "C truncation semantics"
        );
        assert_eq!(div(7, -2), DivT { quot: -3, rem: 1 });
        assert_eq!(div(9, 3), DivT { quot: 3, rem: 0 });
        assert_eq!(div(1, 0), DivT { quot: 0, rem: 0 }, "zero divisor sentinel");
        assert_eq!(
            div(i32::MIN, -1),
            DivT { quot: 0, rem: 0 },
            "overflow sentinel"
        );
        assert_eq!(ldiv(7, 2), LdivT { quot: 3, rem: 1 });
        assert_eq!(lldiv(-7, 2), LdivT { quot: -3, rem: -1 });
        assert_eq!(imaxdiv(9, 4), LdivT { quot: 2, rem: 1 });
    }

    #[test]
    fn rand_srand_determinism() {
        srand(42);
        let a: [c_int; 8] = core::array::from_fn(|_| rand());
        assert!(a.iter().all(|&x| (0..=32767).contains(&x)));
        srand(42);
        let b: [c_int; 8] = core::array::from_fn(|_| rand());
        assert_eq!(a, b, "same seed must replay");
        srand(43);
        let c: [c_int; 8] = core::array::from_fn(|_| rand());
        assert_ne!(a, c, "different seed must diverge");
    }

    #[test]
    fn atoi_family() {
        assert_eq!(atoi(b"42"), 42);
        assert_eq!(atoi(b"  -17abc"), -17);
        assert_eq!(atoi(b"+5"), 5);
        assert_eq!(atoi(b"xyz"), 0, "no conversion -> 0");
        assert_eq!(atoi(b""), 0);
        assert_eq!(atol(b"9999999999"), 9_999_999_999);
        assert_eq!(atoll(b"123456789012345"), 123_456_789_012_345);
    }

    #[test]
    fn strtol_bases_and_consumed() {
        assert_eq!(strtol(b"ff", 16), (255, 2));
        assert_eq!(strtol(b"0x1F", 0), (31, 4));
        assert_eq!(strtol(b"017", 0), (15, 3), "leading zero = octal");
        assert_eq!(strtol(b"10", 0), (10, 2));
        assert_eq!(strtol(b"101", 2), (5, 3));
        assert_eq!(strtol(b"z", 36), (35, 1));
        assert_eq!(strtol(b"Z", 36), (35, 1), "case-insensitive digits");
        assert_eq!(strtol(b"12abc", 10), (12, 2), "stop at first invalid");
        assert_eq!(strtol(b"  42", 10), (42, 4), "leading ws consumed");
        assert_eq!(strtol(b"xyz", 10), (0, 0), "no conversion");
        // "0x" 无十六进制位 → 按单字符 "0"
        assert_eq!(strtol(b"0x", 16), (0, 1));
        assert_eq!(strtol(b"0xg", 0), (0, 1));
    }

    #[test]
    fn strtol_overflow_erange() {
        errno::set_errno(0);
        assert_eq!(strtol(b"9223372036854775807", 10), (i64::MAX, 19));
        assert_eq!(errno(), 0, "boundary value is not overflow");
        assert_eq!(strtol(b"9223372036854775808", 10), (i64::MAX, 19));
        assert_eq!(errno(), ERANGE, "clamp + ERANGE");
        // i64::MIN 精确边界：合法值，无 ERANGE
        errno::set_errno(0);
        assert_eq!(strtol(b"-9223372036854775808", 10), (i64::MIN, 20));
        assert_eq!(errno(), 0, "MIN boundary is exact, not overflow");
        assert_eq!(strtol(b"-9223372036854775809", 10), (i64::MIN, 20));
        assert_eq!(errno(), ERANGE, "beyond MIN -> clamp + ERANGE");
        errno::set_errno(0);
    }

    #[test]
    fn strtoull_family() {
        assert_eq!(strtoull(b"18446744073709551615", 10), (u64::MAX, 20));
        assert_eq!(strtoull(b"42", 10), (42, 2));
        assert_eq!(strtoul(b"ff", 16), (255, 2));
        // POSIX：负号按模取负
        assert_eq!(strtoull(b"-1", 10), (u64::MAX, 2));
        // 溢出 → u64::MAX + ERANGE
        errno::set_errno(0);
        assert_eq!(strtoull(b"18446744073709551616", 10), (u64::MAX, 20));
        assert_eq!(errno(), ERANGE);
        errno::set_errno(0);
    }

    #[test]
    fn strtod_faces() {
        assert_eq!(strtod(b"3.5"), (3.5, 3));
        assert_eq!(strtod(b"  -2.5e2 rest"), (-250.0, 8));
        assert_eq!(strtod(b".5"), (0.5, 2), "fraction-only form");
        assert_eq!(strtod(b"42."), (42.0, 3));
        assert_eq!(strtod(b"1e3"), (1000.0, 3));
        assert_eq!(strtod(b"E5"), (0.0, 0), "no digits -> no conversion");
        assert_eq!(
            strtod(b"1e"),
            (1.0, 1),
            "bare e is not exponent, '1' converts"
        );
        errno::set_errno(0);
        let (v, n) = strtod(b"1e999");
        assert!(v.is_infinite());
        assert_eq!(n, 5);
        assert_eq!(errno(), ERANGE, "overflow -> HUGE_VAL + ERANGE");
        errno::set_errno(0);
    }

    #[test]
    fn qsort_bsearch() {
        let mut v = [5u64, 3, 9, 1, 7, 3];
        qsort(&mut v);
        assert_eq!(v, [1, 3, 3, 5, 7, 9]);
        assert_eq!(bsearch(&7u64, &v), Some(4));
        assert_eq!(bsearch(&4u64, &v), None);
        let empty: [u64; 0] = [];
        assert_eq!(bsearch(&1u64, &empty), None);
        let mut words = ["pear", "apple", "fig"];
        qsort(&mut words);
        assert_eq!(words, ["apple", "fig", "pear"]);
    }

    /// H1c 扩容批：strtoimax/strtoumax（LP64 同宽 + 负号模取负）。
    #[test]
    fn strtoimax_strtoumax() {
        assert_eq!(strtoimax(b"-42xyz", 10), (-42, 3));
        assert_eq!(strtoimax(b"0x1F", 0), (31, 4));
        assert_eq!(strtoumax(b"18446744073709551615", 10), (u64::MAX, 20));
        assert_eq!(strtoumax(b"-1", 10), (u64::MAX, 2), "negation modulo 2^64");
        assert_eq!(strtoumax(b"42", 10), (42, 2));
    }

    /// H1c 扩容批：mblen/mbtowc/wctomb（"C" locale ASCII 单字节面）。
    #[test]
    fn mb_char_family() {
        // mblen：复位/空/NUL/ASCII/非法
        assert_eq!(mblen(None), 0);
        assert_eq!(mblen(Some(b"")), 0);
        assert_eq!(mblen(Some(b"\0rest")), 0);
        assert_eq!(mblen(Some(b"A")), 1);
        errno::set_errno(0);
        assert_eq!(mblen(Some(b"\xC3")), -1);
        assert_eq!(errno(), crate::errno::EILSEQ);
        // mbtowc：写值语义
        let mut wc: crate::wchar_t = 0;
        assert_eq!(mbtowc(&mut wc, None), 0);
        assert_eq!(mbtowc(&mut wc, Some(b"Q")), 1);
        assert_eq!(wc, 0x51);
        assert_eq!(mbtowc(&mut wc, Some(b"\0")), 0);
        assert_eq!(mbtowc(&mut wc, Some(b"\xFF")), -1);
        // wctomb：ASCII 往返 + 越域
        let mut buf = [0u8; 4];
        assert_eq!(wctomb(&mut buf, 0x51), 1);
        assert_eq!(buf[0], b'Q');
        assert_eq!(wctomb(&mut buf, 0), 1, "NUL wide char writes \\0");
        assert_eq!(buf[0], 0);
        assert_eq!(wctomb(&mut buf, 0x263A), -1);
    }

    /// H1c 扩容批：mbstowcs/wcstombs 往返（NUL 界/容量界/非法哨兵）。
    #[test]
    fn mb_string_roundtrip() {
        let mut wide = [0i32; 8];
        assert_eq!(mbstowcs(&mut wide, b"abc\0more"), 3);
        assert_eq!(&wide[..4], &[b'a' as i32, b'b' as i32, b'c' as i32, 0]);
        // 容量界即停
        let mut wide = [0i32; 2];
        assert_eq!(mbstowcs(&mut wide, b"abcd"), 2);
        // 非法哨兵
        let mut wide = [0i32; 8];
        assert_eq!(mbstowcs(&mut wide, b"ab\xFF"), usize::MAX);
        // wcstombs 往返
        let src: [crate::wchar_t; 4] = [b'x' as i32, b'y' as i32, b'z' as i32, 0];
        let mut narrow = [0u8; 8];
        assert_eq!(wcstombs(&mut narrow, &src), 3);
        assert_eq!(&narrow[..4], b"xyz\0");
        // 越域宽字符哨兵
        let bad: [crate::wchar_t; 2] = [b'x' as i32, 0x2026];
        assert_eq!(wcstombs(&mut narrow, &bad), usize::MAX);
        // 容量界
        let src: [crate::wchar_t; 3] = [b'a' as i32, b'b' as i32, b'c' as i32];
        let mut tiny = [0u8; 2];
        assert_eq!(wcstombs(&mut tiny, &src), 2);
    }

    /// H1c 扩容批：qsort_r 比较器面 + rand_r 可重入 + atof 等式。
    #[test]
    fn qsort_r_rand_r_atof() {
        // qsort_r：闭包捕获上下文（C arg 指针等价化）+ 降序
        let mut v = [3i32, 1, 4, 1, 5];
        qsort_r(&mut v, |a: &i32, b: &i32| b.cmp(a) as c_int);
        assert_eq!(v, [5, 4, 3, 1, 1]);
        // rand_r：确定性序列（种子同值 → 序列同值）
        let mut s1: crate::c_uint = 7;
        let mut s2: crate::c_uint = 7;
        for _ in 0..8 {
            let a = rand_r(&mut s1);
            let b = rand_r(&mut s2);
            assert_eq!(a, b);
            assert!((0..=32767).contains(&a));
        }
        assert_ne!(s1, 7, "seed advanced");
        // atof 等式 + 负数/指数
        assert_eq!(atof(b"2.5"), 2.5);
        assert_eq!(atof(b"-3.25e2"), -325.0);
        assert_eq!(atof(b"junk"), 0.0);
    }
}
