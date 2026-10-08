//! 自检结果报告：统一打点格式，供宿主 smoke 阶段按行断言。

use crate::console::DualLog;

/// 记录一项自检结果：打印 `[PASS|FAIL] 名称` 并累计通过数。
pub fn report(log: &mut DualLog, pass: &mut usize, ok: bool, name: &str) {
    let tag = if ok { "PASS" } else { "FAIL" };
    let _ = core::fmt::Write::write_fmt(log, format_args!("  [{tag}] {name}\n"));
    if ok {
        *pass += 1;
    }
}
