//! unistd 域——命令行解析与系统配置查询（值/切片语义 safe 面）。
//!
//! 承接 POSIX `<unistd.h>` 7 符号（M35-H1c，86 → 121 增量路径之一）：
//! getopt 族（getopt/getopt_long/getopt_long_only）+ swab + confstr +
//! sysconf + getpagesize。
//!
//! # safe 面承载形式（M29/M35 纪律）
//!
//! - **getopt 全局游标**：C 的 optind/optarg/optopt 为进程级全局——本面
//!   以 [`GetoptState`] 显式状态承载（可重入，偏差登记：全局游标面挂账）；
//!   opterr 报错打印（stderr 面）v0 静默化（返回 '?' 已足 fail-visible，
//!   登记）；非选项参数即停（C `+` 模式语义——无 argv 重排，登记）；
//!   长选项 v0 **精确匹配**（C 前缀缩写面挂账）。
//! - **swab**：C `ssize_t n` 交换域 → 片界 min 承载（奇数尾不交换照办）。
//! - **confstr/sysconf**：C 出参缓冲 → 所有权返回；号域取 **Linux glibc
//!   号域对齐**（conduit 绑定表同构纪律）；未支持名 → `None`/`-1` +
//!   `errno = EINVAL`（C 照办）。
//! - **数值口径**：PAGESIZE/CLK_TCK/ARG_MAX/OPEN_MAX 为 v0 静态承载
//!   （OPEN_MAX 与 kernel 句柄表定容对账——随 M35-BBa 批次实证对齐，挂账）。

use alloc::vec::Vec;

use crate::c_int;
use crate::c_long;
use crate::errno::{self, EINVAL};

// ───────────────────────── getopt 族 ─────────────────────────

/// getopt 迭代状态（C optind/optarg/optopt 全局游标的显式化重铸）。
#[derive(Debug, Clone)]
pub struct GetoptState {
    /// 下一个待解析 argv 下标（C `optind`；初值 1——argv[0] 为程序名惯例，
    /// 调用方须传入含程序名的完整 argv）。
    pub optind: usize,
    /// 最近一次未匹配/缺参的选项字符（C `optopt`）。
    pub optopt: c_int,
    /// 最近一次选项的参数（C `optarg`——所有权面；`None` = 无参/可选未附）。
    pub optarg: Option<Vec<u8>>,
    /// 簇内游标（C `nextchar` 内部态的外显——重入所需）。
    nextchar: usize,
}

impl Default for GetoptState {
    fn default() -> Self {
        Self {
            optind: 1, // C optind 初值：argv[0] 跳过
            optopt: 0,
            optarg: None,
            nextchar: 0,
        }
    }
}

/// 长选项定义（C `struct option` 的切片面重铸）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongOpt<'a> {
    /// 长选项名（如 `b"verbose"`——调用方传 `--name` 双横线剥离后比对）。
    pub name: &'a [u8],
    /// 参数需求（[`NO_ARGUMENT`]/[`REQUIRED_ARGUMENT`]/[`OPTIONAL_ARGUMENT`]）。
    pub has_arg: c_int,
    /// 返回值（`val`；0 = 仅报告 longidx——C 照办）。
    pub val: c_int,
}

/// 无参数（C `no_argument` = 0）。
pub const NO_ARGUMENT: c_int = 0;
/// 必需参数（C `required_argument` = 1）。
pub const REQUIRED_ARGUMENT: c_int = 1;
/// 可选参数（C `optional_argument` = 2）。
pub const OPTIONAL_ARGUMENT: c_int = 2;

/// 短选项解析（`getopt`）。
///
/// 返回：选项字符（`c_int`）/ `b':'`（缺参——optstring 前导 `:` 模式）/
/// `b'?'`（未知选项或缺参默认模式）/ `-1`（解析完毕）。
///
/// 语义锚：簇 `"abc"` 逐字符交付；带参选项吃簇余部或下一 argv；
/// `--` 终止符；非选项即停（登记见模块文档）。
pub fn getopt(argv: &[&[u8]], optstring: &[u8], st: &mut GetoptState) -> c_int {
    getopt_engine(argv, optstring, &[], st, &mut None, false)
}

/// 长选项解析（`getopt_long`）：`--name`/`--name=value`/`--name value`。
///
/// 命中长选项时 `longidx` 置 `Some(下标)`；返回 `val`（`val = 0` 时返回
/// 0，C 照办）。未知长选项 → `b'?'`（`optopt` = 名首字符）。
pub fn getopt_long(
    argv: &[&[u8]],
    optstring: &[u8],
    longopts: &[LongOpt<'_>],
    st: &mut GetoptState,
    longidx: &mut Option<usize>,
) -> c_int {
    getopt_engine(argv, optstring, longopts, st, longidx, false)
}

/// 长选项解析·单横线同权（`getopt_long_only`）：`-name` 亦先按长选项
/// 匹配（未命中回落短选项引擎）。
pub fn getopt_long_only(
    argv: &[&[u8]],
    optstring: &[u8],
    longopts: &[LongOpt<'_>],
    st: &mut GetoptState,
    longidx: &mut Option<usize>,
) -> c_int {
    getopt_engine(argv, optstring, longopts, st, longidx, true)
}

/// getopt 引擎（三符号共用；`long_only` = getopt_long_only 旗标）。
fn getopt_engine(
    argv: &[&[u8]],
    optstring: &[u8],
    longopts: &[LongOpt<'_>],
    st: &mut GetoptState,
    longidx: &mut Option<usize>,
    long_only: bool,
) -> c_int {
    *longidx = None;
    let missing = if optstring.first() == Some(&b':') {
        b':'
    } else {
        b'?'
    };
    if st.optind >= argv.len() {
        return -1;
    }
    let cur = argv[st.optind];
    // 长选项匹配（-- 双横线恒；- 单横线仅 long_only 且簇内待解析位为 0）
    let long_cand: Option<&[u8]> = if cur.starts_with(b"--") && cur.len() > 2 {
        Some(&cur[2..])
    } else if long_only && st.nextchar == 0 && cur.starts_with(b"-") && cur.len() > 2 {
        Some(&cur[1..])
    } else {
        None
    };
    if let Some(body) = long_cand {
        let (name, inline) = match body.iter().position(|&b| b == b'=') {
            Some(at) => (&body[..at], Some(&body[at + 1..])),
            None => (body, None),
        };
        let hit = longopts.iter().position(|lo| lo.name == name);
        let Some(hit) = hit else {
            st.optopt = name.first().copied().unwrap_or(b'?') as c_int;
            st.optarg = Some(name.to_vec()); // C：未知长选项 optarg = 名
            st.optind += 1;
            st.nextchar = 0;
            return b'?' as c_int;
        };
        let lo = longopts[hit];
        *longidx = Some(hit);
        match lo.has_arg {
            REQUIRED_ARGUMENT => {
                if let Some(v) = inline {
                    st.optarg = Some(v.to_vec());
                    st.optind += 1;
                    st.nextchar = 0;
                } else {
                    st.optind += 1;
                    if st.optind >= argv.len() {
                        st.optopt = lo.val;
                        return missing as c_int;
                    }
                    st.optarg = Some(argv[st.optind].to_vec());
                    st.optind += 1;
                }
            }
            OPTIONAL_ARGUMENT => {
                st.optarg = inline.map(|v| v.to_vec());
                st.optind += 1;
                st.nextchar = 0;
            }
            _ => {
                st.optarg = None;
                st.optind += 1;
                st.nextchar = 0;
            }
        }
        return lo.val;
    }
    if st.nextchar == 0 {
        // 新参数起手：短选项须 "-x"（len ≥ 2）；`--` = 终止符
        if cur.len() < 2 || cur[0] != b'-' {
            return -1; // 非选项即停（登记：无重排）
        }
        if cur == b"--" {
            st.optind += 1;
            return -1;
        }
        st.nextchar = 1;
    }
    let Some(&c) = cur.get(st.nextchar) else {
        st.optind += 1;
        st.nextchar = 0;
        return -1;
    };
    st.nextchar += 1;
    let Some(pos) = optstring.iter().position(|&o| o == c) else {
        st.optopt = c as c_int;
        if st.nextchar >= cur.len() {
            st.optind += 1;
            st.nextchar = 0;
        }
        return b'?' as c_int;
    };
    if optstring.get(pos + 1) == Some(&b':') {
        let optional = optstring.get(pos + 2) == Some(&b':');
        if st.nextchar < cur.len() {
            st.optarg = Some(cur[st.nextchar..].to_vec());
            st.optind += 1;
            st.nextchar = 0;
            return c as c_int;
        }
        if optional {
            st.optarg = None;
            st.optind += 1;
            st.nextchar = 0;
            return c as c_int;
        }
        st.optind += 1;
        if st.optind >= argv.len() {
            st.optopt = c as c_int;
            st.nextchar = 0;
            return missing as c_int;
        }
        st.optarg = Some(argv[st.optind].to_vec());
        st.optind += 1;
        st.nextchar = 0;
        return c as c_int;
    }
    if st.nextchar >= cur.len() {
        st.optind += 1;
        st.nextchar = 0;
    }
    c as c_int
}

// ───────────────────────── swab ─────────────────────────

/// 相邻字节交换（`swab`）：`src` 偶对两两交换写入 `dst`；处理域 =
/// `min(src.len(), dst.len())` 向下取偶（C `ssize_t n` 的片界承载，奇数
/// 尾不交换照办）；返回处理字节数。
pub fn swab(src: &[u8], dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len()) & !1;
    for i in (0..n).step_by(2) {
        dst[i] = src[i + 1];
        dst[i + 1] = src[i];
    }
    n
}

// ───────────────────────── confstr / sysconf / getpagesize ─────────────────────────

/// `confstr` 名：路径默认值（glibc 号域 `_CS_PATH` = 0）。
pub const _CS_PATH: c_int = 0;
/// `confstr` 名：libc 版本串（glibc 号域 = 2）。
pub const _CS_GNU_LIBC_VERSION: c_int = 2;

/// `sysconf` 名：参数上限（glibc 号域 = 0）。
pub const _SC_ARG_MAX: c_int = 0;
/// `sysconf` 名：时钟嘀嗒（glibc 号域 = 2）。
pub const _SC_CLK_TCK: c_int = 2;
/// `sysconf` 名：进程打开文件上限（glibc 号域 = 4）。
pub const _SC_OPEN_MAX: c_int = 4;
/// `sysconf` 名：作业控制（glibc 号域 = 7）。
pub const _SC_JOB_CONTROL: c_int = 7;
/// `sysconf` 名：保存 UID/GID 语义（glibc 号域 = 8）。
pub const _SC_SAVED_IDS: c_int = 8;
/// `sysconf` 名：页大小（glibc 号域 = 30）。
pub const _SC_PAGESIZE: c_int = 30;

/// 配置串（`confstr`）：已知名返回值（所有权面——C 出参缓冲的等价化）；
/// 未支持名 → `None`（v0 面：_CS_PATH + _CS_GNU_LIBC_VERSION，登记）。
#[must_use]
pub fn confstr(name: c_int) -> Option<Vec<u8>> {
    match name {
        _CS_PATH => Some(b"/bin:/usr/bin".to_vec()),
        _CS_GNU_LIBC_VERSION => {
            Some(alloc::format!("harbor {}", env!("CARGO_PKG_VERSION")).into_bytes())
        }
        _ => None,
    }
}

/// 系统配置（`sysconf`）：已知名返回值；未支持名 → `-1` 且
/// `errno = EINVAL`（C 照办）。
///
/// v0 数值口径见模块文档（OPEN_MAX 与 kernel 句柄表对账挂账）。
pub fn sysconf(name: c_int) -> c_long {
    match name {
        _SC_ARG_MAX => 131_072,
        _SC_CLK_TCK => 100,
        _SC_OPEN_MAX => 64,
        _SC_JOB_CONTROL | _SC_SAVED_IDS => 1,
        _SC_PAGESIZE => 4096,
        _ => {
            errno::set_errno(EINVAL);
            -1
        }
    }
}

/// 页大小（`getpagesize`）——与 [`sysconf`] 的 `_SC_PAGESIZE` 同源。
#[must_use]
pub extern "C" fn getpagesize() -> c_int {
    4096
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 短选项引擎：簇交付/带参/缺参两模式/未知/`--`/非选项即停。
    #[test]
    fn getopt_short_engine() {
        // 簇 "abc"（无参选项）逐字符交付
        let argv: [&[u8]; 2] = [b"prog", b"-abc"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"abc", &mut st), b'a' as c_int);
        assert_eq!(getopt(&argv, b"abc", &mut st), b'b' as c_int);
        assert_eq!(getopt(&argv, b"abc", &mut st), b'c' as c_int);
        assert_eq!(getopt(&argv, b"abc", &mut st), -1);
        assert_eq!(st.optind, 2);
        // 带参：簇内余部（"-oVALUE"）
        let argv: [&[u8]; 2] = [b"prog", b"-o42"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"o:", &mut st), b'o' as c_int);
        assert_eq!(st.optarg.as_deref(), Some(&b"42"[..]));
        // 带参：下一 argv（"-o 42"）
        let argv: [&[u8]; 3] = [b"prog", b"-o", b"42"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"o:", &mut st), b'o' as c_int);
        assert_eq!(st.optarg.as_deref(), Some(&b"42"[..]));
        assert_eq!(getopt(&argv, b"o:", &mut st), -1);
        assert_eq!(st.optind, 3);
        // 缺参默认模式：'?' + optopt
        let argv: [&[u8]; 2] = [b"prog", b"-o"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"o:", &mut st), b'?' as c_int);
        assert_eq!(st.optopt, b'o' as c_int);
        // 缺参前导 ':' 模式：':' + optopt
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b":o:", &mut st), b':' as c_int);
        assert_eq!(st.optopt, b'o' as c_int);
        // 未知选项：'?' + optopt + 簇内后续继续
        let argv: [&[u8]; 2] = [b"prog", b"-az"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"a", &mut st), b'a' as c_int);
        assert_eq!(getopt(&argv, b"a", &mut st), b'?' as c_int);
        assert_eq!(st.optopt, b'z' as c_int);
        // `--` 终止符 + 非选项即停
        let argv: [&[u8]; 4] = [b"prog", b"--", b"-a", b"file"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"a", &mut st), -1);
        assert_eq!(st.optind, 2, "past --");
        let argv: [&[u8]; 3] = [b"prog", b"file", b"-a"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"a", &mut st), -1, "non-option stop");
        assert_eq!(st.optind, 1, "stops at non-option");
        // 可选参数 "::"：簇内附参 / 无参
        let argv: [&[u8]; 2] = [b"prog", b"-x9"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"x::", &mut st), b'x' as c_int);
        assert_eq!(st.optarg.as_deref(), Some(&b"9"[..]));
        let argv: [&[u8]; 2] = [b"prog", b"-x"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"x::", &mut st), b'x' as c_int);
        assert_eq!(st.optarg, None);
        // 空 argv 即 -1
        let argv: [&[u8]; 1] = [b"prog"];
        let mut st = GetoptState::default();
        assert_eq!(getopt(&argv, b"a", &mut st), -1);
    }

    /// 长选项引擎：精确匹配/=取参/下一 argv 取参/缺参/未知/val=0/long_only。
    #[test]
    fn getopt_long_engine() {
        let longs = [
            LongOpt {
                name: b"verbose",
                has_arg: NO_ARGUMENT,
                val: b'v' as c_int,
            },
            LongOpt {
                name: b"output",
                has_arg: REQUIRED_ARGUMENT,
                val: b'o' as c_int,
            },
            LongOpt {
                name: b"level",
                has_arg: OPTIONAL_ARGUMENT,
                val: 0,
            },
        ];
        // 无参长选项 + longidx
        let argv: [&[u8]; 2] = [b"prog", b"--verbose"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long(&argv, b"", &longs, &mut st, &mut idx),
            b'v' as c_int
        );
        assert_eq!(idx, Some(0));
        assert_eq!(st.optarg, None);
        // =取参
        let argv: [&[u8]; 2] = [b"prog", b"--output=f.txt"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long(&argv, b"", &longs, &mut st, &mut idx),
            b'o' as c_int
        );
        assert_eq!(idx, Some(1));
        assert_eq!(st.optarg.as_deref(), Some(&b"f.txt"[..]));
        // 下一 argv 取参
        let argv: [&[u8]; 3] = [b"prog", b"--output", b"g.txt"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long(&argv, b"", &longs, &mut st, &mut idx),
            b'o' as c_int
        );
        assert_eq!(st.optarg.as_deref(), Some(&b"g.txt"[..]));
        assert_eq!(getopt_long(&argv, b"", &longs, &mut st, &mut idx), -1);
        // 可选参：=附 / 未附
        let argv: [&[u8]; 2] = [b"prog", b"--level=3"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(getopt_long(&argv, b"", &longs, &mut st, &mut idx), 0);
        assert_eq!(st.optarg.as_deref(), Some(&b"3"[..]));
        let argv: [&[u8]; 2] = [b"prog", b"--level"];
        let mut st = GetoptState::default();
        assert_eq!(getopt_long(&argv, b"", &longs, &mut st, &mut idx), 0);
        assert_eq!(st.optarg, None);
        // 必需参缺失
        let argv: [&[u8]; 2] = [b"prog", b"--output"];
        let mut st = GetoptState::default();
        assert_eq!(
            getopt_long(&argv, b"", &longs, &mut st, &mut idx),
            b'?' as c_int
        );
        // 未知长选项：'?' + optarg = 名（C 照办）
        let argv: [&[u8]; 2] = [b"prog", b"--bogus"];
        let mut st = GetoptState::default();
        assert_eq!(
            getopt_long(&argv, b"", &longs, &mut st, &mut idx),
            b'?' as c_int
        );
        assert_eq!(st.optarg.as_deref(), Some(&b"bogus"[..]));
        // getopt_long_only：单横线长匹配 + 未命中回落短选项
        let argv: [&[u8]; 2] = [b"prog", b"-verbose"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long_only(&argv, b"v", &longs, &mut st, &mut idx),
            b'v' as c_int
        );
        assert_eq!(idx, Some(0));
        let argv: [&[u8]; 2] = [b"prog", b"-x"];
        let mut st = GetoptState::default();
        assert_eq!(
            getopt_long_only(&argv, b"x", &longs, &mut st, &mut idx),
            b'x' as c_int
        );
        // 普通 getopt 不吃单横线长名（回落短选项引擎）
        let argv: [&[u8]; 2] = [b"prog", b"-verbose"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long(&argv, b"v", &longs, &mut st, &mut idx),
            b'v' as c_int
        );
        assert_eq!(idx, None, "plain getopt_long keeps short engine");
        // 混排：长/短交错推进
        let argv: [&[u8]; 4] = [b"prog", b"--verbose", b"-o", b"out.bin"];
        let mut st = GetoptState::default();
        let mut idx = None;
        assert_eq!(
            getopt_long(&argv, b"o:", &longs, &mut st, &mut idx),
            b'v' as c_int
        );
        assert_eq!(
            getopt_long(&argv, b"o:", &longs, &mut st, &mut idx),
            b'o' as c_int
        );
        assert_eq!(st.optarg.as_deref(), Some(&b"out.bin"[..]));
        assert_eq!(getopt_long(&argv, b"o:", &longs, &mut st, &mut idx), -1);
    }

    /// swab：偶对交换/奇尾/片界承载。
    #[test]
    fn swab_pair_exchange() {
        let mut dst = [0u8; 4];
        assert_eq!(swab(b"abcd", &mut dst), 4);
        assert_eq!(dst, [b'b', b'a', b'd', b'c']);
        // 奇数尾不交换
        let mut dst = [0u8; 5];
        assert_eq!(swab(b"abcde", &mut dst), 4);
        assert_eq!(dst, [b'b', b'a', b'd', b'c', 0]);
        // dst 界承载
        let mut dst = [0u8; 2];
        assert_eq!(swab(b"abcdef", &mut dst), 2);
        assert_eq!(dst, [b'b', b'a']);
    }

    /// confstr/sysconf/getpagesize：已知名/未知名 EINVAL。
    #[test]
    fn conf_sys_pagesize() {
        assert_eq!(confstr(_CS_PATH).as_deref(), Some(&b"/bin:/usr/bin"[..]));
        let ver = confstr(_CS_GNU_LIBC_VERSION).unwrap_or_default();
        assert!(ver.starts_with(b"harbor "), "version prefix");
        assert_eq!(confstr(99), None, "unsupported name");
        assert_eq!(sysconf(_SC_PAGESIZE), 4096);
        assert_eq!(sysconf(_SC_CLK_TCK), 100);
        assert_eq!(sysconf(_SC_ARG_MAX), 131_072);
        assert_eq!(sysconf(_SC_OPEN_MAX), 64);
        assert_eq!(sysconf(_SC_JOB_CONTROL), 1);
        errno::set_errno(0);
        assert_eq!(sysconf(9999), -1);
        assert_eq!(errno::errno(), EINVAL);
        assert_eq!(getpagesize(), 4096);
    }
}
