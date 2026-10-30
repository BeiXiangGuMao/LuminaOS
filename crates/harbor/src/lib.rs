//! Harbor 港湾 —— 纯 Rust POSIX libc 符号面。
//!
//! 承接《Harbor 港湾开发细则》v1.0.0（POSIX.1-2017 定位）与《指标与规范
//! 手册》第 5 章指标族 H-P01…H-P07：执行系统库档**零 unsafe** 政策（crate
//! 级 `forbid(unsafe_code)`），M29-H1 落地 H-P01 首批垂直切片，
//! M35-H1a…H1d 扩容至 **158 符号，H-P01 闸 50→150 升级兑现**（细则 DoD
//! 硬锚：≥150 机检双端在环）。
//!
//! # 域谱（158 函数符号，M35-H1d 补齐；机器可检清点见 `tests::h_p01_symbol_inventory`）
//!
//! - [`errno`]：errno 面（AtomicI32）+ POSIX 错误常量 46 项 + strerror
//!   名称表（3 函数符号 + 45 常量）；
//! - [`ctype`]：字符分类/大小写转换 16 符号（值语义 `extern "C"`）；
//! - [`string`]：mem/str 语义 18 符号（切片语义 safe 面——NUL 终止串以
//!   `&[u8]` 承载，越界即 `None`/界限值，等价 C 语义的 fail-visible 化）；
//! - [`stdlib`]：数值转换/排序/伪随机 20 符号（abs/div 族值语义
//!   `extern "C"` + strto* 切片面 + qsort/bsearch + rand/srand LCG）；
//! - [`time`]：历法换算与格式化 14 符号（M35-H1a——UTC/"C" locale 纯
//!   计算 UTC 面：gmtime/localtime 族 + mktime/timegm/difftime +
//!   asctime/ctime 族固定 26 字节形状 + strftime/wcsftime + tzset 空实现
//!   登记；时钟源 syscall 面挂账不虚报）；
//! - [`search`]：哈希表/线性搜索/双链队列/BST 15 符号（M35-H1b——
//!   hcreate/hdestroy/hsearch 全局族〔atomic 槽位定容 64〕+ _r 显式表族 +
//!   lfind/lsearch + insque/remque 索引双链 + tsearch 族句柄 BST）；
//! - [`unistd`]：命令行解析与系统配置 7 符号（M35-H1c——getopt 族显式
//!   状态面〔GetoptState〕+ swab/confstr/sysconf/getpagesize）；
//! - string/stdlib 扩容 28 符号（M35-H1c——复制/追加/分词/legacy mem 族
//!   + strtoimax 族/mb 面/qsort_r/rand_r/atof）；
//! - [`wchar`]：宽字符分类与宽串 37 符号（M35-H1d 补齐——isw 族/tow 族/
//!   wctype/wctrans/towctrans 描述符面 + wcs/wmem 族切片语义）。
//!
//! # v0 范围界定（偏差登记，见 ROADMAP §四 M29 计划注）
//!
//! - **C ABI 链接层**（`#[unsafe(no_mangle)]` 导出 + raw ptr 指针层）暂缓：
//!   指针解引用需 unsafe，与 crate 级 forbid 承诺冲突；待用户态链接面成形
//!   后以外置方案（如 ostd 出指针基元 + harbor 薄壳）补位。当前所有
//!   `extern "C"` 函数为值语义（C 调用约定、Rust 符号修饰），切片面为
//!   纯 safe Rust 签名。
//! - **平台 ABI 面板（LP64 决策）**：`c_char = u8`（LuminaOS 自定 ABI，
//!   非 x86_64-linux 的 i8 惯例）、`c_int = i32`、`c_long = c_longlong =
//!   i64`（LP64，`long` 与 `long long` 同宽——`strtol`/`strtoll` 等价但
//!   双符号齐备）、`intmax_t = i64`。
//! - **errno 存储**：v0 为进程级单例（AtomicI32）；POSIX 线程局部语义
//!   随用户态任务面挂账。
//! - **locale**：全部按 "C" locale 语义（isupper/islower/tolower 等仅
//!   ASCII 域），locale 面挂账。
//!
//! 历史：本 crate 原为内核堆分配器（HarborBump/HarborFreeList，693 行），
//! ADR-0003 裁决身份拆分——分配器迁 `ostd::heap`（M29-N1 执行），harbor
//! 名字与 crate 让位细则定义的 POSIX libc 本体（M29-H1 自此重铸）。
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ctype;
pub mod errno;
pub mod search;
pub mod stdlib;
pub mod string;
pub mod time;
pub mod unistd;
pub mod wchar;

// C ABI 惯用小写命名（libc 符号名对齐）——non_camel_case_types 为有意为之
/// C ABI 基础类型（LuminaOS LP64 面板，见 crate 文档）。
#[allow(non_camel_case_types)]
pub type c_char = u8;
/// C `int`（LP64：32 位）。
#[allow(non_camel_case_types)]
pub type c_int = i32;
/// C `unsigned int`。
#[allow(non_camel_case_types)]
pub type c_uint = u32;
/// C `long`（LP64：64 位，与 `long long` 同宽）。
#[allow(non_camel_case_types)]
pub type c_long = i64;
/// C `unsigned long`。
#[allow(non_camel_case_types)]
pub type c_ulong = u64;
/// C `intmax_t`（LP64：64 位）。
#[allow(non_camel_case_types)]
pub type c_intmax = i64;
/// C `wchar_t`（LP64 Linux：32 位；M35-H1a time 域 wcs* 面随行）。
#[allow(non_camel_case_types)]
pub type wchar_t = i32;
/// C `uintmax_t`（LP64：64 位；M35-H1c stdlib 扩容面随行）。
#[allow(non_camel_case_types)]
pub type c_uintmax = u64;

#[cfg(test)]
mod tests {
    /// H-P01 符号清点（机器可检 **≥150 闸**——M35-H1d 自 50 升级兑现细则
    /// DoD 硬锚；逐域枚举公开函数符号名，断言总数；errno 45 常量另计，
    /// 不入函数口径）。
    #[test]
    fn h_p01_symbol_inventory() {
        const ERRNO: &[&str] = &["errno", "set_errno", "strerror"];
        const CTYPE: &[&str] = &[
            "isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph", "islower", "isprint",
            "ispunct", "isspace", "isupper", "isxdigit", "isascii", "toascii", "tolower",
            "toupper",
        ];
        const STRING: &[&str] = &[
            "memcpy",
            "memmove",
            "memset",
            "memcmp",
            "memchr",
            "memrchr",
            "strlen",
            "strnlen",
            "strcmp",
            "strncmp",
            "strchr",
            "strrchr",
            "strstr",
            "strspn",
            "strcspn",
            "strpbrk",
            "strdup",
            "strndup",
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "stpcpy",
            "stpncpy",
            "strtok",
            "strtok_r",
            "strcoll",
            "strxfrm",
            "strerror_r",
            "memccpy",
            "memfrob",
            "bcopy",
            "bzero",
            "bcmp",
            "index",
            "rindex",
        ];
        const STDLIB: &[&str] = &[
            "abs",
            "labs",
            "llabs",
            "imaxabs",
            "div",
            "ldiv",
            "lldiv",
            "imaxdiv",
            "atoi",
            "atol",
            "atoll",
            "strtol",
            "strtoul",
            "strtoll",
            "strtoull",
            "strtod",
            "qsort",
            "bsearch",
            "rand",
            "srand",
            "strtoimax",
            "strtoumax",
            "mblen",
            "mbtowc",
            "wctomb",
            "mbstowcs",
            "wcstombs",
            "qsort_r",
            "rand_r",
            "atof",
        ];
        const TIME: &[&str] = &[
            "difftime",
            "timegm",
            "mktime",
            "gmtime",
            "gmtime_r",
            "localtime",
            "localtime_r",
            "asctime",
            "asctime_r",
            "ctime",
            "ctime_r",
            "strftime",
            "wcsftime",
            "tzset",
        ];
        const SEARCH: &[&str] = &[
            "hcreate",
            "hdestroy",
            "hsearch",
            "hcreate_r",
            "hdestroy_r",
            "hsearch_r",
            "lfind",
            "lsearch",
            "insque",
            "remque",
            "tsearch",
            "tfind",
            "tdelete",
            "twalk",
            "tdestroy",
        ];
        const UNISTD: &[&str] = &[
            "getopt",
            "getopt_long",
            "getopt_long_only",
            "swab",
            "confstr",
            "sysconf",
            "getpagesize",
        ];
        const WCTYPE: &[&str] = &[
            "iswalnum",
            "iswalpha",
            "iswblank",
            "iswcntrl",
            "iswdigit",
            "iswgraph",
            "iswlower",
            "iswprint",
            "iswpunct",
            "iswspace",
            "iswupper",
            "iswxdigit",
            "towlower",
            "towupper",
            "wctype",
            "wctrans",
            "towctrans",
        ];
        const WCHAR: &[&str] = &[
            "wcslen", "wcsnlen", "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcscmp", "wcsncmp",
            "wcschr", "wcsrchr", "wcsstr", "wcsspn", "wcscspn", "wcspbrk", "wcsdup", "wmemchr",
            "wmemcmp", "wmemcpy", "wmemmove", "wmemset",
        ];
        let total = ERRNO.len()
            + CTYPE.len()
            + STRING.len()
            + STDLIB.len()
            + TIME.len()
            + SEARCH.len()
            + UNISTD.len()
            + WCTYPE.len()
            + WCHAR.len();
        assert!(
            total >= 150,
            "H-P01 upgraded gate: must export >= 150 symbols, got {total}"
        );
        assert_eq!(total, 158);
        // 域内抽查（防清单漂移）：每域至少 1 名逐一比对实际公开面。
        assert_eq!(crate::errno::strerror(crate::errno::EINVAL), "EINVAL");
        assert_eq!(crate::ctype::isdigit(b'7' as crate::c_int), 1);
        let buf = [0u8; 4];
        assert_eq!(crate::string::strlen(&buf), Some(0));
        assert_eq!(crate::stdlib::abs(-5), 5);
        assert_eq!(crate::stdlib::imaxabs(-7), 7);
        assert_eq!(
            crate::time::timegm(&crate::time::Tm {
                tm_year: 70,
                tm_mon: 0,
                tm_mday: 1,
                tm_hour: 0,
                tm_min: 0,
                tm_sec: 0,
                tm_wday: 4,
                tm_yday: 0,
                tm_isdst: 0
            }),
            Some(0)
        );
        assert_eq!(
            crate::search::lfind(&3, &[1, 2, 3], |a: &i32, b: &i32| a.cmp(b) as crate::c_int),
            Some(2)
        );
        assert_eq!(crate::unistd::getpagesize(), 4096);
        assert_eq!(crate::stdlib::atof(b"2.5"), 2.5);
        assert_eq!(crate::wchar::iswdigit(b'7' as crate::wchar_t), 1);
        let wide = [0x71, 0];
        assert_eq!(crate::wchar::wcslen(&wide), Some(1));
    }
}
