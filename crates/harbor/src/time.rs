//! time 域——历法换算与格式化（纯计算 UTC/"C" locale 面）。
//!
//! 承接 POSIX `<time.h>` 14 符号（M35-H1a，57 → 71）：gmtime 族 +
//! localtime 族 + mktime/timegm/difftime + asctime 族 + ctime 族 +
//! strftime/wcsftime + tzset。
//!
//! # 纪律（M35 口径裁决注 ③）
//!
//! - **UTC/"C" locale 固定**：TZ 环境面挂账，`localtime` 族在 UTC 纪律下
//!   与 gmtime 族恒等（显式登记而非静默省略）；`tzset` 为空实现登记。
//! - **时钟源 syscall 面**（`time`/`clock`/`clock_gettime`）需内核时钟源
//!   读点，挂账不虚报——本域全部为纯计算历法面。
//! - **proleptic Gregorian**：civil-days 算法（Hinnant 元素法），负纪元秒
//!   全域数学一致（1969-12-31 亦精确分解）；闰年/世纪年（2100 非闰）随
//!   算法天然正确。
//!
//! # fail-visible 映射（C UB → 确定行为）
//!
//! - `mktime` 不可表示（算术溢出/越域）→ `None`（C 返 `-1` 哨兵的
//!   fail-visible 化映射）；成功时**就地规范化**（C 语义照办）。
//! - `asctime`/`ctime` 固定 26 字节形状（25 字符 + NUL）：年份域收敛于
//!   1000..=9999（4 位十进制惯例；C 为 `%d` 变长 + 越界 UB，此处定形
//!   fail-visible）；`tm_wday`/`tm_mon`/`tm_mday`/时..秒域越界 → `None`。
//! - `strftime` 缓冲不足 → `None`（C 返 0 的映射；空输出 = `Some(0)`）；
//!   未知转换说明符 → 字面复制（glibc 惯例，非 UB 化，偏差登记）；
//!   `E`/`O` 修饰符在 "C" locale 下与基本转换同义（POSIX §C locale 照办）。
//! - 支持的转换说明符集：`%a %A %b %B %h %c %C %d %D %e %F %H %I %j %m
//!   %M %n %p %r %R %S %t %T %u %U %w %W %x %X %y %Y %z %Z %%`。

use alloc::vec::Vec;

use crate::c_int;
use crate::c_long;
use crate::wchar_t;

/// `time_t`（LP64：`c_long` = i64，纪元秒）。
#[allow(non_camel_case_types)]
pub type time_t = c_long;

/// 分解时间结构（POSIX `struct tm`，`repr(C)` 字段序照办）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Tm {
    /// 秒（0..=60，60 为闰秒域）。
    pub tm_sec: c_int,
    /// 分（0..=59）。
    pub tm_min: c_int,
    /// 时（0..=23）。
    pub tm_hour: c_int,
    /// 月内日（1..=31）。
    pub tm_mday: c_int,
    /// 月（0..=11，1 月 = 0——POSIX 惯例）。
    pub tm_mon: c_int,
    /// 年 − 1900（如 2026 年 = 126）。
    pub tm_year: c_int,
    /// 星期（0..=6，星期日 = 0）。
    pub tm_wday: c_int,
    /// 年内日（0..=365）。
    pub tm_yday: c_int,
    /// 夏令时旗（UTC 纪律下恒 0；TZ 面挂账）。
    pub tm_isdst: c_int,
}

/// 星期缩写表（"C" locale）。
const WDAY3: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
/// 星期全名表（"C" locale）。
const WDAY_FULL: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
/// 月缩写表（"C" locale）。
const MON3: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// 月全名表（"C" locale）。
const MON_FULL: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// 每秒日商（civil-days 基元）。
const SECS_PER_DAY: i64 = 86_400;

/// 天数自公历日期（Hinnant civil_from_days 逆算子——proleptic Gregorian）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 公历日期自天数（Hinnant civil_from_days）——返回 `(年, 月1..=12, 日)`。
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}

/// 纪元秒自 `Tm` 字段（算术恒等式承载完整规范化：mon/mday/h..s 任意整
/// 数域皆线性承载，与 C mktime 逐级进位规范化数学等价）。溢出 → `None`。
fn epoch_from_tm(y: i64, mon: i64, mday: i64, hour: i64, min: i64, sec: i64) -> Option<i64> {
    // 年域防 civil 算术漂移（i64 安全带；真实历法面远小于此界）。
    if !(-100_000..=100_000).contains(&y) {
        return None;
    }
    let y2 = y.checked_add(mon.div_euclid(12))?;
    let m2 = mon.rem_euclid(12) + 1; // days_from_civil 取 1..=12
    let days = days_from_civil(y2, m2, 1);
    let secs = days
        .checked_mul(SECS_PER_DAY)?
        .checked_add((mday - 1).checked_mul(SECS_PER_DAY)?)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)?;
    Some(secs)
}

/// 纪元秒分解为规范化 `Tm`（任意 i64 全域，含负秒——rem_euclid 语义）。
fn decompose(t: time_t) -> Option<Tm> {
    let days = t.div_euclid(SECS_PER_DAY);
    let secs = t.rem_euclid(SECS_PER_DAY);
    let (y, mo, d) = civil_from_days(days);
    let yday = days - days_from_civil(y, 1, 1);
    Some(Tm {
        tm_sec: c_int::try_from(secs % 60).ok()?,
        tm_min: c_int::try_from((secs / 60) % 60).ok()?,
        tm_hour: c_int::try_from(secs / 3600).ok()?,
        tm_mday: c_int::try_from(d).ok()?,
        tm_mon: c_int::try_from(mo - 1).ok()?,
        tm_year: c_int::try_from(y - 1900).ok()?,
        tm_wday: c_int::try_from((days + 4).rem_euclid(7)).ok()?,
        tm_yday: c_int::try_from(yday).ok()?,
        tm_isdst: 0,
    })
}

/// 差值秒（`difftime`）：`t1 - t0` 双精度承载（值语义 `extern "C"`）。
#[must_use]
pub extern "C" fn difftime(t1: time_t, t0: time_t) -> f64 {
    (i128::from(t1) - i128::from(t0)) as f64
}

/// 纪元秒自分解时间（`timegm`——UTC 解释，不改写字段；POSIX 语义）。
///
/// 任意越域字段（mon = 13、mday = 0、sec = -1 …）按算术恒等式规范化
/// 承载；不可表示 → `None`。
#[must_use]
pub fn timegm(tm: &Tm) -> Option<time_t> {
    epoch_from_tm(
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon),
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
    )
}

/// 纪元秒自分解时间（`mktime`——UTC/"C" 纪律下与 [`timegm`] 同语义），
/// **成功时就地规范化**（C 语义照办：全字段重写为规范值，`tm_isdst`
/// 保留）。不可表示 → `None`（C 返 -1 哨兵的 fail-visible 映射）。
pub fn mktime(tm: &mut Tm) -> Option<time_t> {
    let t = timegm(tm)?;
    let norm = decompose(t)?;
    tm.tm_sec = norm.tm_sec;
    tm.tm_min = norm.tm_min;
    tm.tm_hour = norm.tm_hour;
    tm.tm_mday = norm.tm_mday;
    tm.tm_mon = norm.tm_mon;
    tm.tm_year = norm.tm_year;
    tm.tm_wday = norm.tm_wday;
    tm.tm_yday = norm.tm_yday;
    Some(t)
}

/// 纪元秒分解（`gmtime`）：值语义返回。
#[must_use]
pub fn gmtime(t: time_t) -> Option<Tm> {
    decompose(t)
}

/// 纪元秒分解（`gmtime_r`）：写入调用方缓冲（C `_r` 惯例的引用映射）。
pub fn gmtime_r(t: time_t, out: &mut Tm) -> Option<&mut Tm> {
    *out = decompose(t)?;
    Some(out)
}

/// 纪元秒分解（`localtime`）：UTC/"C" locale 固定纪律下与 [`gmtime`]
/// 恒等（TZ 环境面挂账，显式登记——裁决注 ③）。
#[must_use]
pub fn localtime(t: time_t) -> Option<Tm> {
    decompose(t)
}

/// 纪元秒分解（`localtime_r`）：UTC 纪律下与 [`gmtime_r`] 恒同。
pub fn localtime_r(t: time_t, out: &mut Tm) -> Option<&mut Tm> {
    *out = decompose(t)?;
    Some(out)
}

/// ASCII 时间串（`asctime`）：固定 26 字节形状
/// `"Www Mmm dd hh:mm:ss yyyy\n\0"`（域界越出固定形状 → `None`，
/// 见模块文档 fail-visible 映射）。
#[must_use]
pub fn asctime(tm: &Tm) -> Option<[u8; 26]> {
    let mut out = [0u8; 26];
    asctime_into(tm, &mut out)?;
    Some(out)
}

/// ASCII 时间串（`asctime_r`）：写入调用方缓冲（须 ≥ 26 字节），返回
/// 写入长度 26。
pub fn asctime_r(tm: &Tm, buf: &mut [u8]) -> Option<usize> {
    asctime_into(tm, buf)?;
    Some(26)
}

/// `asctime` 内核：域界验证 + 固定布局写位。
fn asctime_into(tm: &Tm, out: &mut [u8]) -> Option<()> {
    if out.len() < 26 {
        return None;
    }
    let w = usize::try_from(tm.tm_wday).ok().filter(|&w| w <= 6)?;
    let mon = usize::try_from(tm.tm_mon).ok().filter(|&m| m <= 11)?;
    let mday = usize::try_from(tm.tm_mday)
        .ok()
        .filter(|&d| (1..=31).contains(&d))?;
    let (h, mi, s) = (tm.tm_hour, tm.tm_min, tm.tm_sec);
    if !(0..=23).contains(&h) || !(0..=59).contains(&mi) || !(0..=60).contains(&s) {
        return None;
    }
    let y = i64::from(tm.tm_year) + 1900;
    // 固定 26 字节形状 = 4 位年惯例（1000..=9999；C 为变长 %d + 越界 UB）。
    if !(1000..=9999).contains(&y) {
        return None;
    }
    let y4 = y as u32;
    out[0..3].copy_from_slice(WDAY3[w].as_bytes());
    out[3] = b' ';
    out[4..7].copy_from_slice(MON3[mon].as_bytes());
    // 日域 %3d（空格右对齐 3 位：mday=1 → "  1"，mday=31 → " 31"）。
    out[7] = b' ';
    if mday >= 10 {
        out[8] = b'0' + (mday / 10) as u8;
    } else {
        out[8] = b' ';
    }
    out[9] = b'0' + (mday % 10) as u8;
    out[10] = b' ';
    put2(out, 11, h as u32);
    out[13] = b':';
    put2(out, 14, mi as u32);
    out[16] = b':';
    put2(out, 17, s as u32);
    out[19] = b' ';
    put2(out, 20, y4 / 100);
    put2(out, 22, y4 % 100);
    out[24] = b'\n';
    out[25] = 0;
    Some(())
}

/// 两位零填充写位基元。
fn put2(buf: &mut [u8], at: usize, v: u32) {
    buf[at] = b'0' + ((v / 10) % 10) as u8;
    buf[at + 1] = b'0' + (v % 10) as u8;
}

/// 纪元秒 ASCII 时间串（`ctime`）＝ [`asctime`]∘[`localtime`]（UTC 纪律）。
#[must_use]
pub fn ctime(t: time_t) -> Option<[u8; 26]> {
    asctime(&decompose(t)?)
}

/// 纪元秒 ASCII 时间串（`ctime_r`）＝ [`asctime_r`]∘[`localtime`]。
pub fn ctime_r(t: time_t, buf: &mut [u8]) -> Option<usize> {
    asctime_r(&decompose(t)?, buf)
}

/// 格式化时间（`strftime`）：字节面（"C" locale 全 ASCII 输出）。
///
/// 输出超缓冲 → `None`（C 返 0 的映射）；空输出 = `Some(0)`。支持集与
/// 偏差登记见模块文档。
pub fn strftime(buf: &mut [u8], format: &[u8], tm: &Tm) -> Option<usize> {
    let mut tmp: Vec<u8> = Vec::new();
    fmt_into(&mut tmp, format, tm)?;
    if tmp.len() > buf.len() {
        return None;
    }
    buf[..tmp.len()].copy_from_slice(&tmp);
    Some(tmp.len())
}

/// 宽字符格式化时间（`wcsftime`）：宽格式/宽缓冲（"C" locale 下全部
/// 输出为 ASCII，逐元素 `u8 → wchar_t` 承载；宽域非 ASCII → `None`
/// fail-visible 登记）。
pub fn wcsftime(buf: &mut [wchar_t], format: &[wchar_t], tm: &Tm) -> Option<usize> {
    let mut fbytes = Vec::with_capacity(format.len());
    for &w in format {
        fbytes.push(u8::try_from(w).ok()?);
    }
    let mut tmp: Vec<u8> = Vec::new();
    fmt_into(&mut tmp, &fbytes, tm)?;
    if tmp.len() > buf.len() {
        return None;
    }
    for (d, &b) in buf[..tmp.len()].iter_mut().zip(tmp.iter()) {
        *d = wchar_t::from(b);
    }
    Some(tmp.len())
}

/// 时区设定（`tzset`）：UTC/"C" locale 固定纪律下为空实现（裁决注 ③
/// 登记——TZ 环境面挂账）。
pub extern "C" fn tzset() {}

/// 年内第几周（`%U` 周日首 / `%W` 周一首——首周前计第 0 周，POSIX 惯例；
/// `first` = 年首日所在周的周日/周一锚偏移）。
fn week_of(yday: i64, first: i64) -> i64 {
    (yday + 7 - first) / 7
}

/// `strftime` 展开内核（递归承载组合说明符 `%c/%D/%F/%r/%R/%T/%x/%X`）。
fn fmt_into(out: &mut Vec<u8>, fmt: &[u8], tm: &Tm) -> Option<()> {
    let y = i64::from(tm.tm_year) + 1900;
    let mut i = 0;
    while i < fmt.len() {
        let b = fmt[i];
        if b != b'%' {
            out.push(b);
            i += 1;
            continue;
        }
        i += 1;
        // E/O 修饰符："C" locale 下与基本转换同义（POSIX 照办）。
        if i < fmt.len() && matches!(fmt[i], b'E' | b'O') {
            i += 1;
        }
        let Some(&spec) = fmt.get(i) else {
            // 悬空 '%'：字面复制（glibc 惯例）。
            out.push(b'%');
            break;
        };
        i += 1;
        match spec {
            b'%' => out.push(b'%'),
            b'a' => out.extend_from_slice(WDAY3[idx(tm.tm_wday, 7)?].as_bytes()),
            b'A' => out.extend_from_slice(WDAY_FULL[idx(tm.tm_wday, 7)?].as_bytes()),
            b'b' | b'h' => out.extend_from_slice(MON3[idx(tm.tm_mon, 12)?].as_bytes()),
            b'B' => out.extend_from_slice(MON_FULL[idx(tm.tm_mon, 12)?].as_bytes()),
            b'C' => {
                if y < 0 {
                    return None;
                }
                put2_push(out, (y / 100) as u64);
            }
            b'd' => put2_push(out, u64::try_from(tm.tm_mday).ok()?),
            b'e' => {
                let d = u64::try_from(tm.tm_mday).ok()?;
                if d > 99 {
                    return None;
                }
                if d < 10 {
                    out.push(b' ');
                }
                push_dec(out, d);
            }
            b'H' => put2_push(out, u64::try_from(tm.tm_hour).ok()?),
            b'I' => {
                let h = i64::from(tm.tm_hour);
                if !(0..=23).contains(&h) {
                    return None;
                }
                put2_push(out, (if h % 12 == 0 { 12 } else { h % 12 }) as u64);
            }
            b'j' => {
                let d = i64::from(tm.tm_yday) + 1;
                if !(1..=999).contains(&d) {
                    return None;
                }
                if d < 100 {
                    out.push(b'0');
                }
                if d < 10 {
                    out.push(b'0');
                }
                push_dec(out, d as u64);
            }
            b'm' => put2_push(out, u64::try_from(tm.tm_mon + 1).ok()?),
            b'M' => put2_push(out, u64::try_from(tm.tm_min).ok()?),
            b'n' => out.push(b'\n'),
            b'p' => out.extend_from_slice(if tm.tm_hour < 12 { b"AM" } else { b"PM" }),
            b'S' => put2_push(out, u64::try_from(tm.tm_sec).ok()?),
            b't' => out.push(b'\t'),
            b'u' => {
                let w = idx(tm.tm_wday, 7)?;
                push_dec(out, if w == 0 { 7 } else { w as u64 });
            }
            b'U' => {
                let yd = i64::from(tm.tm_yday);
                let wd = i64::from(tm.tm_wday);
                put2_push(out, week_of(yd, wd).max(0) as u64);
            }
            b'W' => {
                let yd = i64::from(tm.tm_yday);
                let wd = i64::from(tm.tm_wday);
                put2_push(out, week_of(yd, (wd + 6) % 7).max(0) as u64);
            }
            b'w' => push_dec(out, idx(tm.tm_wday, 7)? as u64),
            b'y' => {
                if y < 0 {
                    return None;
                }
                put2_push(out, (y % 100) as u64);
            }
            b'Y' => {
                if y < 0 {
                    return None;
                }
                push_dec(out, y as u64);
            }
            b'z' => out.extend_from_slice(b"+0000"),
            b'Z' => out.extend_from_slice(b"UTC"),
            // 组合说明符（"C" locale 惯例展开）。
            b'c' => fmt_into(out, b"%a %b %e %H:%M:%S %Y", tm)?,
            b'D' => fmt_into(out, b"%m/%d/%y", tm)?,
            b'F' => fmt_into(out, b"%Y-%m-%d", tm)?,
            b'r' => fmt_into(out, b"%I:%M:%S %p", tm)?,
            b'R' => fmt_into(out, b"%H:%M", tm)?,
            b'T' => fmt_into(out, b"%H:%M:%S", tm)?,
            b'x' => fmt_into(out, b"%m/%d/%y", tm)?,
            b'X' => fmt_into(out, b"%H:%M:%S", tm)?,
            // 未知说明符：字面复制（glibc 惯例，非 UB 化——偏差登记）。
            _ => {
                out.push(b'%');
                out.push(spec);
            }
        }
    }
    Some(())
}

/// 域界索引基元（越界 → `None`——C UB 的 fail-visible 化）。
fn idx(v: c_int, len: usize) -> Option<usize> {
    usize::try_from(v).ok().filter(|&i| i < len)
}

/// 两位零填充推送（≥100 自然扩展宽度——C 最小宽度语义）。
fn put2_push(out: &mut Vec<u8>, v: u64) {
    if v < 10 {
        out.push(b'0');
    }
    push_dec(out, v);
}

/// 十进制推送。
fn push_dec(out: &mut Vec<u8>, v: u64) {
    let mut buf = [0u8; 20];
    let mut n = 0;
    let mut v = v;
    loop {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
        if v == 0 {
            break;
        }
    }
    for j in (0..n).rev() {
        out.push(buf[j]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// 对账测试基线向量（Python `datetime` 同源实证，M35-H1a 取证）。
    #[test]
    fn known_epochs_decompose() {
        // t=0：1970-01-01 周四（wday=4，yday=0）
        let Some(tm) = gmtime(0) else {
            panic!("t=0 must decompose")
        };
        assert_eq!(tm.tm_year, 70);
        assert_eq!(tm.tm_mon, 0);
        assert_eq!(tm.tm_mday, 1);
        assert_eq!(tm.tm_wday, 4);
        assert_eq!(tm.tm_yday, 0);
        // t=-1：1969-12-31 23:59:59 周三（负秒域 rem_euclid 语义）
        let Some(tm) = gmtime(-1) else {
            panic!("t=-1 must decompose")
        };
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday), (69, 11, 31));
        assert_eq!((tm.tm_hour, tm.tm_min, tm.tm_sec), (23, 59, 59));
        assert_eq!(tm.tm_wday, 3);
        assert_eq!(tm.tm_yday, 364);
        // 2000-02-29 00:00:00 周二（闰日）
        let Some(tm) = gmtime(951_782_400) else {
            panic!("leap day")
        };
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday), (100, 1, 29));
        assert_eq!(tm.tm_wday, 2);
        assert_eq!(tm.tm_yday, 59);
        // 2009-02-13 23:31:30 周五（著名常量向量）
        let Some(tm) = gmtime(1_234_567_890) else {
            panic!("famous vector")
        };
        assert_eq!((tm.tm_hour, tm.tm_min, tm.tm_sec), (23, 31, 30));
        assert_eq!(tm.tm_mday, 13);
        assert_eq!(tm.tm_wday, 5);
        // 9999-12-31 23:59:59（asctime 年域上界锚）
        let Some(tm) = gmtime(253_402_300_799) else {
            panic!("year 9999")
        };
        assert_eq!(tm.tm_year, 8099);
        assert_eq!(tm.tm_mon, 11);
        assert_eq!(tm.tm_mday, 31);
        // 2100-03-01：世纪非闰年锚（2100 非闰 → 3 月 1 日 yday=59）
        let Some(tm) = gmtime(4_107_542_400) else {
            panic!("century non-leap")
        };
        assert_eq!((tm.tm_mon, tm.tm_mday), (2, 1));
        assert_eq!(tm.tm_yday, 59);
        // 1972-07-01 周六
        let Some(tm) = gmtime(78_796_800) else {
            panic!("1972-07-01")
        };
        assert_eq!(tm.tm_wday, 6);
        assert_eq!(tm.tm_yday, 182);
    }

    /// roundtrip + 就地规范化（C mktime 语义照办）。
    #[test]
    fn mktime_timegm_roundtrip_and_normalization() {
        for t in [-1_i64, 0, 86_399, 951_782_400, 1_234_567_890, 4_107_542_400] {
            let Some(tm) = gmtime(t) else {
                panic!("decompose {t}")
            };
            assert_eq!(timegm(&tm), Some(t), "timegm roundtrip {t}");
            let mut m = tm;
            assert_eq!(mktime(&mut m), Some(t), "mktime roundtrip {t}");
            assert_eq!(m, tm, "mktime rewrite must be identity on canonical input");
        }
        // 越域字段算术恒等规范化：(2000, mon=0, mday=32) == 2000-02-01
        let mut m = Tm {
            tm_year: 100,
            tm_mon: 0,
            tm_mday: 32,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(timegm(&m), Some(949_363_200));
        assert_eq!(mktime(&mut m), Some(949_363_200));
        assert_eq!(
            (m.tm_mon, m.tm_mday, m.tm_wday),
            (1, 1, 2),
            "normalized in place"
        );
        // mon=12 进位到次年 1 月；sec=86400 进位到日
        let mut m2 = Tm {
            tm_year: 99,
            tm_mon: 12,
            tm_mday: 1,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 86_400,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(
            mktime(&mut m2),
            Some(946_771_200),
            "mon=12 & sec=86400 carry: 2000-01-01 +1d"
        );
        assert_eq!((m2.tm_year, m2.tm_mon, m2.tm_mday), (100, 0, 2));
        // localtime 族恒等 gmtime 族（UTC 纪律显式登记）
        assert_eq!(localtime(1_234_567_890), gmtime(1_234_567_890));
        let mut slot = Tm::default();
        let got = localtime_r(1_234_567_890, &mut slot);
        assert!(got.is_some(), "localtime_r must succeed");
        let mut slot2 = Tm::default();
        assert!(gmtime_r(1_234_567_890, &mut slot2).is_some());
        assert_eq!(slot, slot2, "localtime_r == gmtime_r under UTC");
    }

    /// 固定 26 字节形状 + 域界 fail-visible。
    #[test]
    fn asctime_ctime_fixed_shape() {
        let Some(tm) = gmtime(0) else { panic!("t=0") };
        let Some(bytes) = asctime(&tm) else {
            panic!("t=0 asctime")
        };
        assert_eq!(&bytes[..], b"Thu Jan  1 00:00:00 1970\n\0");
        let Some(tm) = gmtime(951_782_400) else {
            panic!("leap")
        };
        let Some(bytes) = ctime(951_782_400) else {
            panic!("leap ctime")
        };
        assert_eq!(&bytes[..], b"Tue Feb 29 00:00:00 2000\n\0");
        // asctime_r：缓冲过小 → None；恰好 26 → Some(26) 且带 NUL
        let mut small = [0u8; 25];
        assert_eq!(asctime_r(&tm, &mut small), None);
        let mut exact = [0u8; 26];
        assert_eq!(asctime_r(&tm, &mut exact), Some(26));
        assert_eq!(exact[25], 0);
        // 域界越出固定形状：年份 999（< 1000）与 10000（> 9999）
        let bad = Tm {
            tm_year: 999 - 1900,
            tm_wday: 4,
            tm_mon: 0,
            tm_mday: 1,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(asctime(&bad), None, "year 999 breaks fixed shape");
        let bad = Tm {
            tm_year: 10_000 - 1900,
            tm_wday: 4,
            tm_mon: 0,
            tm_mday: 1,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(asctime(&bad), None, "year 10000 breaks fixed shape");
        // wday/mon 越界（C UB → None）
        let bad = Tm {
            tm_year: 70,
            tm_wday: 9,
            tm_mon: 0,
            tm_mday: 1,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(asctime(&bad), None);
        let bad = Tm {
            tm_year: 70,
            tm_wday: 4,
            tm_mon: 13,
            tm_mday: 1,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        assert_eq!(asctime(&bad), None);
    }

    /// strftime 支持集 + 组合说明符 + 偏差登记面。
    #[test]
    fn strftime_supported_set() {
        let Some(tm) = gmtime(1_234_567_890) else {
            panic!("famous")
        };
        let mut buf = [0u8; 64];
        // 标量族
        let n = strftime(&mut buf, b"%Y-%m-%d %H:%M:%S", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"2009-02-13 23:31:30");
        // 名字族 + 最小宽度族
        let n = strftime(&mut buf, b"%a %A %b %B %j %p", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"Fri Friday Feb February 044 PM");
        // %I/%e/%C/%y/%u/%w/%U/%W（1970-01-01 周四锚：U=W=0）
        let Some(tm0) = gmtime(0) else { panic!("t=0") };
        let n = strftime(&mut buf, b"%I %e %C %y %u %w %U %W", &tm0).unwrap_or(0);
        assert_eq!(&buf[..n], b"12  1 19 70 4 4 00 00");
        // 1999-12-31 周五（yday=364）：U=W=52
        let Some(tm) = gmtime(946_598_400) else {
            panic!("1999-12-31")
        };
        let n = strftime(&mut buf, b"%U %W", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"52 52");
        // 组合说明符
        let n = strftime(&mut buf, b"%F %T %D %R", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"1999-12-31 00:00:00 12/31/99 00:00");
        let n = strftime(&mut buf, b"%c", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"Fri Dec 31 00:00:00 1999");
        let n = strftime(&mut buf, b"%x %X %r", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"12/31/99 00:00:00 12:00:00 AM");
        // UTC 面字面量 + E/O 修饰符同义 + %% 与未知说明符字面复制
        let n = strftime(&mut buf, b"%z %Z %EY %Oy %Q %%", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"+0000 UTC 1999 99 %Q %");
        // 悬空 %
        let n = strftime(&mut buf, b"abc%", &tm).unwrap_or(0);
        assert_eq!(&buf[..n], b"abc%");
        // 空格式 = Some(0)
        assert_eq!(strftime(&mut buf, b"", &tm), Some(0));
        // 缓冲不足 → None
        let mut tiny = [0u8; 3];
        assert_eq!(strftime(&mut tiny, b"%Y", &tm), None);
    }

    /// wcsftime 宽面（ASCII 逐元素承载 + 越宽域 fail-visible）。
    #[test]
    fn wcsftime_wide_domain() {
        let Some(tm) = gmtime(1_234_567_890) else {
            panic!("famous")
        };
        let fmt: Vec<wchar_t> = b"%Y/%m/%d %H:%M"
            .iter()
            .map(|&b| wchar_t::from(b))
            .collect();
        let mut buf = [0i32; 32];
        let n = wcsftime(&mut buf, &fmt, &tm).unwrap_or(0);
        let got: Vec<u8> = buf[..n]
            .iter()
            .map(|&w| u8::try_from(w).unwrap_or(0))
            .collect();
        assert_eq!(&got[..], b"2009/02/13 23:31");
        // 缓冲不足
        let mut tiny = [0i32; 3];
        assert_eq!(wcsftime(&mut tiny, &fmt, &tm), None);
        // 非 ASCII 宽字符格式 → None（fail-visible 登记）
        let fmt_bad: Vec<wchar_t> = vec![0x4E2D, wchar_t::from(b'%'), wchar_t::from(b'Y')];
        let mut buf = [0i32; 16];
        assert_eq!(wcsftime(&mut buf, &fmt_bad, &tm), None);
    }

    /// difftime 值语义。
    #[test]
    fn difftime_value_semantics() {
        assert_eq!(difftime(100, 40), 60.0);
        assert_eq!(difftime(40, 100), -60.0);
        assert_eq!(difftime(0, 0), 0.0);
        assert_eq!(difftime(-1, 0), -1.0);
        // i64 边界差值经 i128 承载（C UB → 确定行为）：2^64-1 圆整到最近 f64 = 2^64
        assert_eq!(difftime(i64::MAX, i64::MIN), 2.0_f64.powi(64));
    }

    /// tzset 空实现登记（可调用不崩溃）。
    #[test]
    fn tzset_noop() {
        tzset();
    }
}
