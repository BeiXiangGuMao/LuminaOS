//! 内核时间基线：PIT 节拍计数（M3）。
//!
//! IRQ0 处理程序调用 [`tick`]；其余代码经 [`now`] 读取、[`sleep_ticks`]
//! 低功耗等待。M3 节拍源为 PIT 通道 0（100 Hz，见 [`crate::hw::pit`]）；
//! TSC/APV 计时随 M4+ SMP 一并引入。

use core::sync::atomic::{AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);

/// 中断处理程序打点（IRQ0 专用；每次节拍 +1）。
pub fn tick() {
    let _ = TICKS.fetch_add(1, Ordering::Relaxed);
}

/// 当前节拍数（单调递增，回绕在 u64 尽头——584 万年 @100 Hz）。
pub fn now() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// 低功耗等待 `n` 个节拍：hlt 直至计数达标。
///
/// # PANIC（防挂死）
/// `budget` 次唤醒后仍未达标即终止调用方（裸机自检防挂死护栏，
/// 正常情况下 100 Hz 时钟远快于此预算）。
pub fn sleep_ticks(n: u64, budget: u32) -> bool {
    let target = now().saturating_add(n);
    let mut woken: u32 = 0;
    while now() < target {
        crate::hw::intr::halt();
        woken += 1;
        if woken > budget {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{now, tick};

    #[test]
    fn ticks_monotonic() {
        // 宿主测试与裸机共享同一静态：只验证相对单调性
        let a = now();
        tick();
        tick();
        let b = now();
        assert!(b >= a + 2 || b >= 2);
        for _ in 0..5 {
            tick();
        }
        assert!(now() >= b + 5);
    }
}

/// TSC 单调时钟：经 PIT 节拍校准的纳秒基线（M4）。
///
/// 校准原理：取 TSC 快照后睡眠 `n` 个 PIT 节拍，再取快照——
/// `tsc_hz = ΔTSC × pit_hz / n`。纯计算部分拆为 [`measure`]
/// （宿主可测）；裸机路径 [`calibrate_after`] 负责采样。
/// 64 位防溢出：中间乘法一律走 u128。
pub mod tsc_clock {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// 校准出的 TSC 频率（Hz）；0 = 尚未校准。
    static TSC_HZ: AtomicU64 = AtomicU64::new(0);

    /// 校准数学核心：由「节拍计数差 + TSC 差」推 TSC 频率（Hz）。
    /// 宿主可测；裸机与宿主共用同一公式。
    pub fn measure(ticks_elapsed: u64, tsc_elapsed: u64, pit_hz: u64) -> u64 {
        if ticks_elapsed == 0 || tsc_elapsed == 0 || pit_hz == 0 {
            return 0;
        }
        // tsc_hz = Δtsc / Δ秒 = Δtsc × pit_hz / Δticks（u128 防溢出）
        ((tsc_elapsed as u128 * pit_hz as u128) / ticks_elapsed as u128) as u64
    }

    /// 提交校准结果（裸机路径调用）。
    pub fn commit(hz: u64) {
        TSC_HZ.store(hz, Ordering::Relaxed);
    }

    /// 已校准的 TSC 频率；未校准返回 0。
    pub fn hz() -> u64 {
        TSC_HZ.load(Ordering::Relaxed)
    }

    /// 由 TSC 差计算纳秒跨度（u128 中间量防溢出）；未校准返回 None。
    pub fn elapsed_ns(tsc_delta: u64) -> Option<u64> {
        let hz = TSC_HZ.load(Ordering::Relaxed);
        if hz == 0 || tsc_delta == 0 {
            return None;
        }
        Some(((tsc_delta as u128 * 1_000_000_000u128) / hz as u128) as u64)
    }

    /// 纳秒基线（TSC 起点的单调纳秒时刻）——供绝对时间戳拼接。
    static BASE_TSC: AtomicU64 = AtomicU64::new(0);

    /// 设定纳秒基线（校准完成时以当时 TSC 读数调用）。
    pub fn set_base(tsc_at_zero: u64) {
        BASE_TSC.store(tsc_at_zero, Ordering::Relaxed);
    }

    /// 自基线起的单调纳秒时间戳；未校准返回 None。
    pub fn now_ns() -> Option<u64> {
        let base = BASE_TSC.load(Ordering::Relaxed);
        let now = crate::hw::tsc::read();
        if base == 0 {
            return None;
        }
        elapsed_ns(now.saturating_sub(base))
    }
}

use crate::hw::tsc;

/// 校准 TSC 频率：睡眠 `ticks` 个 PIT 节拍并采样（阻塞）。
/// 返回校准出的 TSC 频率（Hz）；采样或数学异常返回 0。
pub fn calibrate_tsc(ticks: u64, pit_hz: u64) -> u64 {
    let t0 = tsc::read();
    let k0 = now();
    if !sleep_ticks(ticks, (ticks as u32).saturating_mul(60) + 600) {
        return 0;
    }
    let (t1, k1) = (tsc::read(), now());
    let delta_k = k1.saturating_sub(k0);
    let delta_t = t1.saturating_sub(t0);
    let hz = tsc_clock::measure(delta_k, delta_t, pit_hz);
    if hz > 0 {
        tsc_clock::commit(hz);
        tsc_clock::set_base(t1);
    }
    hz
}

/// 读 TSC 原始计数（基准测试用）。
pub fn tsc_now() -> u64 {
    tsc::read()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tsc_tests {
    use super::tsc_clock::measure;

    #[test]
    fn measure_scales_ticks_to_hz() {
        // 100 个节拍（1 秒 @100Hz）内 TSC 走了 3e9 → 3 GHz
        assert_eq!(measure(100, 3_000_000_000, 100), 3_000_000_000);
        // 半秒：50 拍 1.5e9 tick → 3 GHz
        assert_eq!(measure(50, 1_500_000_000, 100), 3_000_000_000);
    }

    #[test]
    fn measure_rejects_zero_inputs() {
        assert_eq!(measure(0, 1000, 100), 0);
        assert_eq!(measure(10, 0, 100), 0);
        assert_eq!(measure(10, 1000, 0), 0);
    }

    #[test]
    fn measure_no_overflow_with_large_tsc() {
        // 2.9e9 Hz × 100 tick / 100 tick — 大数不溢出（u128 中间量）
        let hz = measure(100, u64::MAX / 8, 100);
        assert!(hz > 0);
    }
}
