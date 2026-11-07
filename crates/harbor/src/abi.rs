//! harbor::abi —— C ABI 指针/链接层（M39-HBI：lib.rs v0 范围界定既登记
//! 挂账转正——「C ABI 链接层（#[no_mangle] 导出 + raw ptr 指针层）暂缓」
//! 随本批摘牌）。
//!
//! # 形态（薄壳纪律）
//!
//! - **指针解引用 unsafe 全数收口 `ostd::capi`**（checked 原语——volatile
//!   块步进防 LLVM 内建替换自递归 + fail-visible null/重叠/越界显形）；
//!   本层 crate 级 `forbid(unsafe_code)` 承诺不破——薄壳零 unsafe 块；
//! - **签名 = C ABI 指针形**（`extern "C"` + `*mut/*const c_void/u8`）；
//! - **导出面**：`target_os = "none"`（内核目标）`#[no_mangle]` 导出——
//!   用户态链接面成形后的 C 工具链对接位；宿主测试面 cfg 隔离（无导出，
//!   与宿主 libc 零符号冲突——S4 测试车道不受扰）；
//! - **fail-visible 语义**：C 契约中 UB 域（null dst、重叠 memcpy）以
//!   显形返回值表达（NULL 返回 / false / 负码），偏差即测试对账。
//!
//! # v0 导出族（mem/str 核心 12 符号——H-P01 清点随族扩记 158→170）
//!
//! memcpy / memmove / memset / memcmp / memchr / strlen / strcpy /
//! strncpy / strcat / strncat / strcmp / strncmp。

use core::ffi::c_void;

use ostd::capi;

/// C strlen 全域口径哨兵（有界扫描的 C 全域表达）。
pub const STRLEN_UNBOUNDED: usize = usize::MAX;

/// memcpy：非重叠复制（重叠域显形拒绝——返回 NULL，偏差即对账）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if capi::raw_copy(dst.cast(), src.cast(), n) {
        dst
    } else {
        core::ptr::null_mut()
    }
}

/// memmove：重叠安全移动。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if capi::raw_move(dst.cast(), src.cast(), n) {
        dst
    } else {
        core::ptr::null_mut()
    }
}

/// memset：置值（null → NULL）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn memset(dst: *mut c_void, val: i32, n: usize) -> *mut c_void {
    if capi::raw_set(dst.cast(), val as u8, n) {
        dst
    } else {
        core::ptr::null_mut()
    }
}

/// memcmp：字典序差符号（null → 显形非零码；C 契约 UB 域防御化）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    capi::raw_cmp(a.cast(), b.cast(), n).unwrap_or(i32::MIN)
}

/// memchr：有界查找（未命中 → NULL）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn memchr(p: *const c_void, byte: i32, n: usize) -> *mut c_void {
    match capi::raw_chr(p.cast(), n, byte as u8) {
        // safe 指针偏移（wrapping_add——界内偏移，off < n 契约域）
        Some(off) => (p as *mut u8).wrapping_add(off).cast(),
        None => core::ptr::null_mut(),
    }
}

/// strlen：有界 NUL 扫描（C 全域口径 = [`STRLEN_UNBOUNDED`] 界；
/// 界内未遇 NUL → 0 显形，偏差即对账）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strlen(p: *const core::ffi::c_char) -> usize {
    capi::raw_strlen(p as *const u8, STRLEN_UNBOUNDED).unwrap_or(0)
}

/// strcpy：复制 NUL 终止串（null/无界 → dst 原样返回显形，偏差即对账）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strcpy(
    dst: *mut core::ffi::c_char,
    src: *const core::ffi::c_char,
) -> *mut core::ffi::c_char {
    // fail-visible 形态：复制域失败 = dst 原样返回（偏差登记于模块头注
    // ——C 契约无错误通道，v0 以恒等返回显形不吞不崩）
    match capi::raw_strlen(src as *const u8, STRLEN_UNBOUNDED) {
        Some(n) => {
            let _ = capi::raw_copy(dst as *mut u8, src as *const u8, n + 1);
            dst
        }
        None => dst,
    }
}

/// strncpy：定界复制（n 界内不足补 NUL——C 语义；null → dst 原样）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strncpy(
    dst: *mut core::ffi::c_char,
    src: *const core::ffi::c_char,
    n: usize,
) -> *mut core::ffi::c_char {
    if dst.is_null() {
        return dst;
    }
    let slen = capi::raw_strlen(src as *const u8, n).unwrap_or(n);
    let copy_n = slen.min(n);
    if !capi::raw_copy(dst as *mut u8, src as *const u8, copy_n) {
        return dst;
    }
    if copy_n < n {
        capi::raw_set((dst as *mut u8).wrapping_add(copy_n), 0, n - copy_n);
    }
    dst
}

/// strcat：追加（null → dst 原样显形）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strcat(
    dst: *mut core::ffi::c_char,
    src: *const core::ffi::c_char,
) -> *mut core::ffi::c_char {
    let dlen = capi::raw_strlen(dst as *const u8, STRLEN_UNBOUNDED).unwrap_or(0);
    let _ = capi::raw_strlen(src as *const u8, STRLEN_UNBOUNDED)
        .map(|n| capi::raw_copy((dst as *mut u8).wrapping_add(dlen), src as *const u8, n + 1));
    dst
}

/// strncat：定界追加（追加 n 内字符 + 终 NUL）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strncat(
    dst: *mut core::ffi::c_char,
    src: *const core::ffi::c_char,
    n: usize,
) -> *mut core::ffi::c_char {
    let dlen = capi::raw_strlen(dst as *const u8, STRLEN_UNBOUNDED).unwrap_or(0);
    let slen = capi::raw_strlen(src as *const u8, n).unwrap_or(n);
    if !capi::raw_copy((dst as *mut u8).wrapping_add(dlen), src as *const u8, slen) {
        return dst;
    }
    capi::raw_set((dst as *mut u8).wrapping_add(dlen + slen), 0, 1);
    dst
}

/// strcmp：字典序比较（null → i32::MIN 显形）。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strcmp(a: *const core::ffi::c_char, b: *const core::ffi::c_char) -> i32 {
    let alen = capi::raw_strlen(a as *const u8, STRLEN_UNBOUNDED).unwrap_or(0);
    let blen = capi::raw_strlen(b as *const u8, STRLEN_UNBOUNDED).unwrap_or(0);
    let n = alen.max(blen) + 1; // 含 NUL 终止域
    capi::raw_cmp(a as *const u8, b as *const u8, n).unwrap_or(i32::MIN)
}

/// strncmp：定界字典序比较。
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn strncmp(
    a: *const core::ffi::c_char,
    b: *const core::ffi::c_char,
    n: usize,
) -> i32 {
    capi::raw_cmp(a as *const u8, b as *const u8, n).unwrap_or(i32::MIN)
}

/// H-P01 清点扩记面（M39-HBI）：abi 导出符号名清单（机检对账 +
/// METRICS H-P01 行口径——158 符号面 + abi 12 = 170）。
pub const ABI_SYMBOLS: &[&str] = &[
    "memcpy", "memmove", "memset", "memcmp", "memchr", "strlen", "strcpy", "strncpy", "strcat",
    "strncat", "strcmp", "strncmp",
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mem_family_roundtrip() {
        let mut buf = [0u8; 24];
        let r = memset(buf.as_mut_ptr().cast(), 0x5A, 24);
        assert_eq!(r, buf.as_mut_ptr().cast::<c_void>());
        assert!(buf.iter().all(|&b| b == 0x5A));
        let src = *b"abcdef";
        let r2 = memcpy(buf.as_mut_ptr().cast(), src.as_ptr().cast(), src.len());
        assert_eq!(r2, buf.as_mut_ptr().cast::<c_void>());
        assert_eq!(&buf[..6], b"abcdef");
        assert_eq!(memcmp(buf.as_ptr().cast(), src.as_ptr().cast(), 6), 0);
        assert_eq!(
            memchr(buf.as_ptr().cast(), b'd' as i32, 6),
            buf.as_ptr().wrapping_add(3) as *mut c_void
        );
        // 负例：null 显形 NULL
        assert!(memcpy(core::ptr::null_mut(), src.as_ptr().cast(), 4).is_null());
        assert!(memset(core::ptr::null_mut(), 1, 4).is_null());
    }

    #[test]
    fn move_overlap_domain() {
        let mut m = *b"abcdef";
        let r = memmove(
            m.as_mut_ptr().wrapping_add(2) as *mut c_void,
            m.as_ptr() as *const c_void,
            4,
        );
        assert_eq!(r, m.as_mut_ptr().wrapping_add(2) as *mut c_void);
        assert_eq!(&m, b"ababcd");
    }

    #[test]
    fn str_family_roundtrip() {
        // c_char = u8（LuminaOS LP64 面板）——缓冲以 u8 承载
        let mut buf = [0u8; 32];
        let dst = buf.as_mut_ptr().cast::<core::ffi::c_char>();
        let hello = c"hello";
        let world = c"world";
        assert!(core::ptr::eq(strcpy(dst, hello.as_ptr().cast()), dst));
        assert_eq!(strlen(dst), 5);
        assert!(core::ptr::eq(strcat(dst, world.as_ptr().cast()), dst));
        assert_eq!(strlen(dst), 10);
        assert_eq!(strcmp(dst, c"helloworld".as_ptr()), 0);
        assert_eq!(strncmp(dst, c"helloxyz".as_ptr(), 5), 0);
        assert_eq!(strncmp(dst, c"helloxyz".as_ptr(), 6), -1);
        // strncpy 补 NUL 域
        let mut b2 = [0x7Fu8; 8];
        strncpy(b2.as_mut_ptr().cast(), hello.as_ptr().cast(), 8);
        assert_eq!(&b2[..5], b"hello");
        assert_eq!(&b2[5..], &[0, 0, 0]);
        // strncat 定界追加
        let mut b3 = *b"abc\0....";
        strncat(b3.as_mut_ptr().cast(), c"xyz".as_ptr(), 2);
        assert_eq!(&b3[..6], b"abcxy\0");
        // null 域显形（dst 原样返回——偏差登记于模块头注）
        assert!(core::ptr::eq(
            strcpy(core::ptr::null_mut(), hello.as_ptr().cast()),
            core::ptr::null_mut()
        ));
    }

    #[test]
    fn abi_symbol_inventory_m39() {
        // H-P01 清点扩记面：abi 族 12 符号机检（158 + 12 = 170 全域口径
        // 对账随 lib.rs h_p01_symbol_inventory 双面在环）
        assert_eq!(ABI_SYMBOLS.len(), 12);
        assert_eq!(
            ABI_SYMBOLS,
            &[
                "memcpy", "memmove", "memset", "memcmp", "memchr", "strlen", "strcpy", "strncpy",
                "strcat", "strncat", "strcmp", "strncmp"
            ]
        );
    }
}
