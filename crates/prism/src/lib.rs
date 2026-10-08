//! Prism 棱镜 —— 电源管理策略核心。
//!
//! 依据《指标与规范手册》第 9 章：电源策略分三阶段执行——策略（决定目标状态）、
//! 回退（低电量降级目标）、验证（迁移后自检）。本 crate 实现无副作用策略函数，
//! 供服务进程调用；迁移的实际执行（驱动协商）不在本 crate。
#![no_std]

/// 系统电源状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// 全速活跃。
    Active,
    /// 短暂空闲（保留内存与显示）。
    Idle,
    /// 挂起到内存。
    Suspend,
    /// 休眠到盘。
    Hibernate,
}

/// 策略输入观测值。
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// 用户空闲时长（毫秒）。
    pub user_idle_ms: u64,
    /// 电量百分比 0-100。
    pub battery_pct: u8,
    /// 是否外接电源。
    pub on_ac: bool,
}

/// 策略动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 维持现状。
    Stay,
    /// 进入指定状态。
    Transition(PowerState),
}

/// 阈值配置（默认值来自 SPEC 9 章策略表）。
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// 进入 Idle 的用户空闲时长（毫秒）。
    pub idle_after_ms: u64,
    /// 进入 Suspend 的用户空闲时长（毫秒）。
    pub suspend_after_ms: u64,
    /// 低电量阈值（百分比）。
    pub low_battery_pct: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            idle_after_ms: 180_000,
            suspend_after_ms: 1_800_000,
            low_battery_pct: 15,
        }
    }
}

/// 策略阶段一：根据观测决定目标状态（含阶段二低电量回退）。
pub fn decide(obs: &Observation, th: &Thresholds) -> Action {
    // 阶段二回退：低电量且未接电源时，跳过 Idle 直接压向 Suspend。
    let low = obs.battery_pct <= th.low_battery_pct && !obs.on_ac;
    if low || obs.user_idle_ms >= th.suspend_after_ms {
        return Action::Transition(PowerState::Suspend);
    }
    if obs.user_idle_ms >= th.idle_after_ms {
        return Action::Transition(PowerState::Idle);
    }
    Action::Stay
}

/// 合法状态迁移表（阶段三验证依据）。同状态视为允许（无操作）。
pub fn can_transition(from: PowerState, to: PowerState) -> bool {
    use PowerState::*;
    match (from, to) {
        (a, b) if a == b => true,
        (Active, Idle) | (Idle, Active) => true,
        (Active, Suspend) | (Idle, Suspend) => true,
        (Suspend, Active) => true,
        (Active, Hibernate) | (Idle, Hibernate) => true,
        (Hibernate, Active) => true,
        // Suspend → Hibernate 属深度降级，允许；反向 MUST 先唤醒。
        (Suspend, Hibernate) => true,
        (Hibernate, Suspend) => false,
        // 其余组合（如 Suspend → Idle）一律不允许。
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Action, Observation, PowerState, Thresholds};

    #[test]
    fn idle_then_suspend_timeline() {
        let th = Thresholds::default();
        let obs = |idle: u64| Observation {
            user_idle_ms: idle,
            battery_pct: 90,
            on_ac: true,
        };
        assert_eq!(super::decide(&obs(60_000), &th), Action::Stay);
        assert_eq!(
            super::decide(&obs(200_000), &th),
            Action::Transition(PowerState::Idle)
        );
        assert_eq!(
            super::decide(&obs(2_000_000), &th),
            Action::Transition(PowerState::Suspend)
        );
    }

    #[test]
    fn low_battery_fallback_skips_idle() {
        let th = Thresholds::default();
        let obs = Observation {
            user_idle_ms: 1_000,
            battery_pct: 10,
            on_ac: false,
        };
        assert_eq!(
            super::decide(&obs, &th),
            Action::Transition(PowerState::Suspend)
        );
        // 同样电量但接着电源：不降级
        let obs = Observation {
            user_idle_ms: 1_000,
            battery_pct: 10,
            on_ac: true,
        };
        assert_eq!(super::decide(&obs, &th), Action::Stay);
    }

    #[test]
    fn transition_table_rejects_illegal() {
        assert!(super::can_transition(PowerState::Idle, PowerState::Active));
        assert!(super::can_transition(
            PowerState::Suspend,
            PowerState::Hibernate
        ));
        assert!(!super::can_transition(
            PowerState::Hibernate,
            PowerState::Suspend
        ));
    }
}
