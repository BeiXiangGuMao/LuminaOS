//! Ripple 涟漪 —— 弹簧物理求解器。
//!
//! 依据《美术设计指南》第六章与《指标与规范手册》Ripple 章：动效参数是物理常量
//! 而非时长表。参数库两枚标准弹簧与美术指南逐项一致：
//!
//! - `STANDARD`：刚度 170、阻尼 26（默认过渡）；
//! - `SNAPPY`：刚度 300、阻尼 30（快速反馈）。
//!
//! 求解采用半隐式欧拉（semi-implicit Euler），步长由调用方固定传入——GPU 确定性
//! 要求同一参数与初值在任何机器上得到逐位一致的结果（SPEC Ripple 章）。
#![no_std]

/// 弹簧参数：`f = k·(target - x) − c·v`（质量归一为 1）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    /// 刚度 k（N/m，量纲约定值）。
    pub stiffness: f64,
    /// 阻尼系数 c。
    pub damping: f64,
}

/// 默认过渡弹簧（170/26）。
pub const STANDARD: Spring = Spring {
    stiffness: 170.0,
    damping: 26.0,
};
/// 快速反馈弹簧（300/30）。
pub const SNAPPY: Spring = Spring {
    stiffness: 300.0,
    damping: 30.0,
};

/// 判定精度：位移与速度同时低于该阈值视为静止。
pub const SETTLE_EPS: f64 = 0.01;

impl Spring {
    /// 半隐式欧拉推进一步：先更新速度，再更新位移。
    pub fn step(&self, pos: f64, vel: f64, target: f64, dt: f64) -> (f64, f64) {
        debug_assert!(dt > 0.0, "dt must be positive");
        let force = self.stiffness * (target - pos) - self.damping * vel;
        let vel = vel + force * dt;
        let pos = pos + vel * dt;
        (pos, vel)
    }

    /// 是否已静止在目标附近。
    pub fn settled(pos: f64, vel: f64, target: f64) -> bool {
        (target - pos).abs() < SETTLE_EPS && vel.abs() < SETTLE_EPS
    }

    /// 从当前状态推进到静止（上限 `max_steps` 步），返回 (位移, 速度, 实际步数)。
    pub fn run_until_settled(
        &self,
        pos: f64,
        vel: f64,
        target: f64,
        dt: f64,
        max_steps: u32,
    ) -> (f64, f64, u32) {
        let (mut pos, mut vel) = (pos, vel);
        let mut steps = 0u32;
        while steps < max_steps && !Self::settled(pos, vel, target) {
            let (p, v) = self.step(pos, vel, target, dt);
            pos = p;
            vel = v;
            steps += 1;
        }
        (pos, vel, steps)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{SNAPPY, STANDARD};

    const DT: f64 = 1.0 / 120.0;

    #[test]
    fn converges_without_nan() {
        for (name, s) in [("standard", STANDARD), ("snappy", SNAPPY)] {
            let (pos, vel, steps) = s.run_until_settled(0.0, 0.0, 300.0, DT, 20_000);
            assert!((pos - 300.0).abs() < 0.01, "{name} pos={pos}");
            assert!(vel.abs() < 0.01, "{name} vel={vel}");
            assert!(steps < 20_000, "{name} did not settle");
            assert!(pos.is_finite() && vel.is_finite());
        }
    }

    #[test]
    fn snappy_is_faster_than_standard() {
        let (_, _, a) = STANDARD.run_until_settled(0.0, 0.0, 100.0, DT, 20_000);
        let (_, _, b) = SNAPPY.run_until_settled(0.0, 0.0, 100.0, DT, 20_000);
        assert!(b < a, "snappy {b} steps should beat standard {a}");
    }

    #[test]
    fn interrupt_is_reversible() {
        // 中途改目标：从 0 → 300，走到一半改成 0，必须收敛回 0。
        let s = STANDARD;
        let (mut pos, mut vel) = (0.0f64, 0.0f64);
        for i in 0..120 {
            let target = if i < 60 { 300.0 } else { 0.0 };
            (pos, vel) = s.step(pos, vel, target, DT);
        }
        let (pos, vel, _) = s.run_until_settled(pos, vel, 0.0, DT, 20_000);
        assert!(
            (pos - 0.0).abs() < 0.01 && vel.abs() < 0.01,
            "pos={pos} vel={vel}"
        );
    }
}
