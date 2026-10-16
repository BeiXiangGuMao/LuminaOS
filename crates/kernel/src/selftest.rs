//! 自检结果报告：统一打点格式，供宿主 smoke 阶段按行断言。

use crate::console::DualLog;

/// 记录一项自检结果：打印 `[PASS|FAIL] 名称` 并累计通过数。
/// M22-①：判定同时入 census 记账，每 8 项发射一行单行 census
/// （败点名内化进内核计数行——批杀/串口交叠丢行后，最近 census 行
/// 把败点夹逼到 ≤8 项窗内）。
pub fn report(log: &mut DualLog, pass: &mut usize, ok: bool, name: &str) {
    let n = crate::census::record(ok);
    let tag = if ok { "PASS" } else { "FAIL" };
    let _ = core::fmt::Write::write_fmt(log, format_args!("  [{tag}] {name}\n"));
    if ok {
        *pass += 1;
    }
    if crate::census::periodic(n) {
        crate::census::write_to(log);
    }
}
