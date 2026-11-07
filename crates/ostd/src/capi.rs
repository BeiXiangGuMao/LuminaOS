//! ostd::capi —— C ABI 指针基元层（M39-HBI：harbor::abi 薄壳的基元面）。
//!
//! 依据 harbor lib.rs 既登记挂账转正方案（「ostd 出指针基元 + harbor
//! 薄壳」）：指针解引用 unsafe 收口于本层（ostd 全 crate 允许层——
//! ROADMAP §1.2 / ADR-0005 同构裁决），harbor 侧保持 crate 级
//! `forbid(unsafe_code)` 零 unsafe 承诺不破。
//!
//! # 纪律
//!
//! - **volatile 块步进**：复制/置值走 volatile 读写字节/u64 步进——
//!   防 LLVM 把安全复制循环替换为内建 `memcpy` 调用（本层导出同名片
//!   时 = 自递归，relibc/compiler-builtins 同款规避纪律）；
//! - **fail-visible**：null 指针 / 重叠域 / 越界一律显形（bool/Option
//!   返回，零静默）；
//! - **有界扫描**：strlen 型扫描带 max 界（C 无界契约的防御化——越界
//!   前必停，调用方以 `usize::MAX` 表 C 全域口径）；
//! - **clippy::not_unsafe_ptr_arg_deref 模块级豁免**：本层 API 形态 =
//!   checked 基元（null 判定 + fail-visible 返回 + C 契约域文档化——
//!   指针有效性随 C 调用契约，与 libc FFI 绑定同构），lint 的
//!   「safe 包装即应标 unsafe」口径与本层 fail-visible 设计冲突，
//!   豁免随 M39-HBI 落账（unreachable 域由宿主对账测试全谱覆盖）。

// 豁免理由见模块头注（checked 基元形态——C 契约域文档化 + fail-visible）。
#![allow(clippy::not_unsafe_ptr_arg_deref)]

/// 原子步进块宽（u64 主步 + 字节尾段）。
const CHUNK: usize = core::mem::size_of::<u64>();

/// 非重叠复制基元（`memcpy` 语义）：null/重叠域显形拒绝。
/// volatile 步进防内建替换自递归。
pub fn raw_copy(dst: *mut u8, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true; // C 零长域（null 亦合法——memcpy(p,q,0) 口径）
    }
    if dst.is_null() || src.is_null() {
        return false;
    }
    let (d, s) = (dst as usize, src as usize);
    if d < s + len && s < d + len {
        return false; // 重叠域 = raw_move 契约，本基元显形拒绝
    }
    // SAFETY：调用方保证 dst/src 各自可写/可读 len 字节（C 契约域）；
    // volatile 步进 = 逐块显式访存，无内建替换面。
    unsafe {
        let mut i = 0;
        while i + CHUNK <= len {
            let v = src.add(i) as *const u64;
            let w = dst.add(i) as *mut u64;
            w.write_volatile(v.read_volatile());
            i += CHUNK;
        }
        while i < len {
            dst.add(i).write_volatile(src.add(i).read_volatile());
            i += 1;
        }
    }
    true
}

/// 重叠安全移动基元（`memmove` 语义）：方向判定（前向/逆向）后步进。
pub fn raw_move(dst: *mut u8, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true; // C 零长域（null 亦合法）
    }
    if dst.is_null() || src.is_null() {
        return false;
    }
    let (d, s) = (dst as usize, src as usize);
    // SAFETY：C memmove 契约域（d..d+len 与 s..s+len 可写/可读）；
    // 方向化 volatile 步进保证重叠域语义正确。
    unsafe {
        let overlap = d < s + len && s < d + len;
        let backward = overlap && d > s;
        let mut i = if backward { len } else { 0 };
        while backward && i >= CHUNK {
            i -= CHUNK;
            let v = src.add(i) as *const u64;
            let w = dst.add(i) as *mut u64;
            w.write_volatile(v.read_volatile());
        }
        if backward {
            while i > 0 {
                i -= 1;
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        } else {
            while i + CHUNK <= len {
                let v = src.add(i) as *const u64;
                let w = dst.add(i) as *mut u64;
                w.write_volatile(v.read_volatile());
                i += CHUNK;
            }
            while i < len {
                dst.add(i).write_volatile(src.add(i).read_volatile());
                i += 1;
            }
        }
    }
    true
}

/// 置值基元（`memset` 语义）：null 显形拒绝。
pub fn raw_set(dst: *mut u8, val: u8, len: usize) -> bool {
    if dst.is_null() {
        return false;
    }
    // SAFETY：C memset 契约域（dst 可写 len 字节）；volatile 步进。
    unsafe {
        let wide = (val as u64) * 0x0101_0101_0101_0101;
        let mut i = 0;
        while i + CHUNK <= len {
            (dst.add(i) as *mut u64).write_volatile(wide);
            i += CHUNK;
        }
        while i < len {
            dst.add(i).write_volatile(val);
            i += 1;
        }
    }
    true
}

/// 比较基元（`memcmp` 语义）：None = null 显形；Some(±1/0) = 字典序
/// 差符号（首个差异字节 a<b → -1）。
pub fn raw_cmp(a: *const u8, b: *const u8, len: usize) -> Option<i32> {
    if a.is_null() || b.is_null() {
        return None;
    }
    // SAFETY：C memcmp 契约域（双区各可读 len 字节）。
    unsafe {
        for i in 0..len {
            let x = a.add(i).read_volatile();
            let y = b.add(i).read_volatile();
            if x != y {
                return Some(if x < y { -1 } else { 1 });
            }
        }
    }
    Some(0)
}

/// 有界查找基元（`memchr` 语义）：None = null 或未命中。
pub fn raw_chr(p: *const u8, len: usize, byte: u8) -> Option<usize> {
    if p.is_null() {
        return None;
    }
    // SAFETY：C memchr 契约域（p 可读 len 字节）。
    unsafe {
        for i in 0..len {
            if p.add(i).read_volatile() == byte {
                return Some(i);
            }
        }
    }
    None
}

/// 有界 NUL 扫描基元（`strlen` 语义的防御化）：返回 NUL 偏移；
/// max 内未遇 NUL → None（越界前必停）。
pub fn raw_strlen(p: *const u8, max: usize) -> Option<usize> {
    if p.is_null() {
        return None;
    }
    // SAFETY：C strlen 契约域（NUL 终止串；max 界防御化）。
    unsafe {
        let mut i = 0usize;
        while i < max {
            if p.add(i).read_volatile() == 0 {
                return Some(i);
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn copy_set_cmp_roundtrip() {
        let mut buf = [0u8; 32];
        assert!(raw_set(buf.as_mut_ptr(), 0xA5, 32));
        assert!(buf.iter().all(|&b| b == 0xA5));
        let src = [7u8; 16];
        assert!(raw_copy(buf.as_mut_ptr(), src.as_ptr(), 16));
        assert_eq!(&buf[..16], &[7u8; 16]);
        assert_eq!(raw_cmp(buf.as_ptr(), src.as_ptr(), 16), Some(0));
        assert_eq!(raw_cmp(buf.as_ptr(), [8u8; 16].as_ptr(), 16), Some(-1));
        // 零长域：null 亦合法（C 语义）
        assert!(raw_copy(core::ptr::null_mut(), core::ptr::null(), 0));
    }

    #[test]
    fn fail_visible_domains() {
        let mut buf = [0u8; 8];
        assert!(!raw_copy(buf.as_mut_ptr(), core::ptr::null(), 4));
        assert!(!raw_copy(core::ptr::null_mut(), buf.as_ptr(), 4));
        assert!(!raw_set(core::ptr::null_mut(), 1, 4));
        assert_eq!(raw_cmp(core::ptr::null(), buf.as_ptr(), 4), None);
        assert_eq!(raw_chr(core::ptr::null(), 4, b'x'), None);
        assert_eq!(raw_strlen(core::ptr::null(), 8), None);
        // 重叠域 = move 契约，copy 显形拒绝
        assert!(!raw_copy(buf.as_mut_ptr().wrapping_add(1), buf.as_ptr(), 4));
        // move 契约：重叠前向/逆向全谱
        let mut m = *b"abcdef";
        assert!(raw_move(m.as_mut_ptr().wrapping_add(2), m.as_ptr(), 4));
        assert_eq!(&m, b"ababcd");
        let mut m2 = *b"abcdef";
        assert!(raw_move(m2.as_mut_ptr(), m2.as_ptr().wrapping_add(2), 4));
        assert_eq!(&m2, b"cdefef"); // memmove(dst=s-2) = 源域前移覆写本义
    }

    #[test]
    fn chr_strlen_bounded() {
        let s = b"hello\0world";
        assert_eq!(raw_chr(s.as_ptr(), 11, b'l'), Some(2));
        assert_eq!(raw_chr(s.as_ptr(), 11, b'z'), None);
        assert_eq!(raw_strlen(s.as_ptr(), 11), Some(5));
        assert_eq!(raw_strlen(s.as_ptr(), 3), None); // 界内未遇 NUL → None
    }
}
