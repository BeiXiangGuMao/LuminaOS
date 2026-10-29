//! 电源协同显示侧语义面（M34-P4：PR-P04 首割）。
//!
//! 依据《指标与规范手册》PR-P04 口径：电源策略与显示侧的协同语义面——
//! 电源状态目标映射为显示侧指令（Restore/DimTo/Blank），显示状态机
//! 三态（On/Dim/Blank）单入口迁移 + fail-visible 错误显形 + 亮度档位
//! 契约（On=100 / Blank=0 / Dim 仅收 [`DIM_STEPS`] 档位表内值）。
//!
//! 口径裁决（M34-计划注 ②）：本模块为纯语义面，零电气改动——物理屏
//! DPMS 读写与背光调光执行面挂账真机窗口；kernel 侧挂接登记面见
//! `kernel::fb`（M34-P4 小节）。与电源三阶段（[`crate::decide`]）的
//! 协同经 [`directive_for`] 闭集映射 + [`crate::can_transition`] 迁移闸
//! 上游把关：`Active→Restore / Idle→DimTo(25) / Suspend|Hibernate→Blank`。

use crate::PowerState;

/// 亮度档位契约表：Dim 态仅收表内档位（fail-visible，档位外拒绝）。
///
/// 档位 = 显示协同语义面固定闭集（不虚设连续调光——背光调光电气面
/// 挂账真机窗口后，物理档位随驱动协商批次对账）。
pub const DIM_STEPS: [u8; 4] = [10, 25, 50, 75];

/// 显示电源状态（三态闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayState {
    /// 全亮活跃（亮度契约 = 100）。
    On,
    /// 调暗（亮度契约 = 档位表值 1..=99）。
    Dim,
    /// 熄屏（亮度契约 = 0）。
    Blank,
}

/// 电源策略 → 显示侧协同指令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directive {
    /// 恢复全亮（目标 On + 亮度 100——电源 Active 全速活跃协同口径）。
    Restore,
    /// 调暗到指定档位（须 ∈ [`DIM_STEPS`]）。
    DimTo(u8),
    /// 熄屏（目标 Blank + 亮度 0）。
    Blank,
}

/// 显示协同错误集（fail-visible 显形，不静默吞错）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    /// 非法迁移（如 Blank → Dim：MUST 先唤醒，同电源表
    /// Hibernate→Suspend 反向禁止风格）。
    IllegalTransition {
        /// 迁移源态。
        from: DisplayState,
        /// 迁移目标态。
        to: DisplayState,
    },
    /// 目标态与当前态相同（幂等请求显形拒绝——不静默当成功）。
    AlreadyInState(DisplayState),
    /// 档位外值（DimTo 非 [`DIM_STEPS`] 档位）。
    OutOfRange(u8),
}

/// 显示电源状态机：状态 + 当前亮度，迁移唯一入口 [`DisplayPower::apply`]。
///
/// 亮度契约不变式（每笔迁移后成立，宿主对账断言）：On ⇒ 100 /
/// Blank ⇒ 0 / Dim ⇒ ∈ [`DIM_STEPS`]。
#[derive(Debug, Clone, Copy)]
pub struct DisplayPower {
    state: DisplayState,
    brightness: u8,
}

impl DisplayPower {
    /// 初始态：On + 100（全亮活跃）。
    pub fn new() -> Self {
        DisplayPower {
            state: DisplayState::On,
            brightness: 100,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> DisplayState {
        self.state
    }

    /// 当前亮度登记值（0-100）。
    pub fn brightness(&self) -> u8 {
        self.brightness
    }

    /// 迁移唯一入口（AF-P06 唯一入口同构纪律）：合法迁移改写状态与
    /// 亮度并返回 Ok；非法迁移/同态/档位外一律 Err 显形，零静默。
    pub fn apply(&mut self, d: Directive) -> Result<(), DisplayError> {
        let (to, nb) = match d {
            Directive::Restore => {
                if self.state == DisplayState::On {
                    return Err(DisplayError::AlreadyInState(DisplayState::On));
                }
                (DisplayState::On, 100)
            }
            Directive::DimTo(v) => {
                if !DIM_STEPS.contains(&v) {
                    return Err(DisplayError::OutOfRange(v));
                }
                if self.state == DisplayState::Dim && self.brightness == v {
                    return Err(DisplayError::AlreadyInState(DisplayState::Dim));
                }
                if self.state == DisplayState::Blank {
                    return Err(DisplayError::IllegalTransition {
                        from: self.state,
                        to: DisplayState::Dim,
                    });
                }
                (DisplayState::Dim, v)
            }
            Directive::Blank => {
                if self.state == DisplayState::Blank {
                    return Err(DisplayError::AlreadyInState(DisplayState::Blank));
                }
                (DisplayState::Blank, 0)
            }
        };
        self.state = to;
        self.brightness = nb;
        Ok(())
    }
}

impl Default for DisplayPower {
    fn default() -> Self {
        Self::new()
    }
}

/// 显示侧合法迁移表（阶段三验证依据风格，与 [`crate::can_transition`]
/// 电源表同构）：Blank → Dim 禁止（MUST 先唤醒恢复 On）；同态不由本表
/// 判定（[`DisplayPower::apply`] 以 AlreadyInState 显形）。
pub fn can_transition_display(from: DisplayState, to: DisplayState) -> bool {
    use DisplayState::*;
    match (from, to) {
        (On, Dim) | (On, Blank) => true,
        (Dim, On) | (Dim, Blank) => true,
        (Blank, On) => true,
        (Blank, Dim) => false,
        (On, On) | (Dim, Dim) | (Blank, Blank) => false,
    }
}

/// 电源状态 → 显示协同指令闭集映射（协同语义核心）。
///
/// 恒返回 `Some`（四态映射闭集齐全）；以 `Option` 收口防未来电源态
/// 扩容漏映射——漏项即 `None` 显形，宿主对账逐态断言兜底。
pub fn directive_for(state: PowerState) -> Option<Directive> {
    match state {
        PowerState::Active => Some(Directive::Restore),
        PowerState::Idle => Some(Directive::DimTo(25)),
        PowerState::Suspend | PowerState::Hibernate => Some(Directive::Blank),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        can_transition_display, directive_for, Directive, DisplayError, DisplayPower, DisplayState,
        DIM_STEPS,
    };
    use crate::{can_transition, decide, Action, Observation, PowerState, Thresholds};

    #[test]
    fn dim_blank_restore_timeline() {
        let mut dp = DisplayPower::new();
        assert_eq!(dp.state(), DisplayState::On);
        assert_eq!(dp.brightness(), 100);
        // On → Dim(25)：调暗
        dp.apply(Directive::DimTo(25)).unwrap();
        assert_eq!(dp.state(), DisplayState::Dim);
        assert_eq!(dp.brightness(), 25);
        // Dim(25) → Dim(50)：换档合法（同态不同档）
        dp.apply(Directive::DimTo(50)).unwrap();
        assert_eq!(dp.brightness(), 50);
        // Dim → Blank：深降
        dp.apply(Directive::Blank).unwrap();
        assert_eq!(dp.state(), DisplayState::Blank);
        assert_eq!(dp.brightness(), 0);
        // Blank → On：唤醒恢复全亮（Restore 协同口径）
        dp.apply(Directive::Restore).unwrap();
        assert_eq!(dp.state(), DisplayState::On);
        assert_eq!(dp.brightness(), 100);
    }

    #[test]
    fn illegal_matrix_fail_visible() {
        let mut dp = DisplayPower::new();
        // 同态三目显形拒绝（不静默当成功）
        assert_eq!(
            dp.apply(Directive::Restore),
            Err(DisplayError::AlreadyInState(DisplayState::On))
        );
        dp.apply(Directive::Blank).unwrap();
        assert_eq!(
            dp.apply(Directive::Blank),
            Err(DisplayError::AlreadyInState(DisplayState::Blank))
        );
        // Blank → Dim 禁止（MUST 先唤醒）
        assert_eq!(
            dp.apply(Directive::DimTo(25)),
            Err(DisplayError::IllegalTransition {
                from: DisplayState::Blank,
                to: DisplayState::Dim,
            })
        );
        // 拒绝后状态机零扰动（fail-visible 不半迁移）
        assert_eq!(dp.state(), DisplayState::Blank);
        assert_eq!(dp.brightness(), 0);
    }

    #[test]
    fn dim_steps_gate() {
        let mut dp = DisplayPower::new();
        // 档位外四目：0（Blank 域）/ 100（On 域）/ 30（非档位）/ 贴界 99
        assert_eq!(
            dp.apply(Directive::DimTo(0)),
            Err(DisplayError::OutOfRange(0))
        );
        assert_eq!(
            dp.apply(Directive::DimTo(100)),
            Err(DisplayError::OutOfRange(100))
        );
        assert_eq!(
            dp.apply(Directive::DimTo(30)),
            Err(DisplayError::OutOfRange(30))
        );
        assert_eq!(
            dp.apply(Directive::DimTo(99)),
            Err(DisplayError::OutOfRange(99))
        );
        // 档位表内四档全过
        for v in DIM_STEPS {
            dp.apply(Directive::DimTo(v)).unwrap();
            assert_eq!(dp.brightness(), v);
        }
    }

    #[test]
    fn transition_table_parity() {
        use DisplayState::*;
        // 表内合法三目 + 反向禁目与 apply 实路径对账
        assert!(can_transition_display(On, Dim));
        assert!(can_transition_display(Dim, Blank));
        assert!(can_transition_display(Blank, On));
        assert!(!can_transition_display(Blank, Dim));
        assert!(!can_transition_display(On, On));
        // 电源表同构风格复验（既有面零回归哨兵）
        assert!(can_transition(PowerState::Idle, PowerState::Active));
        assert!(!can_transition(PowerState::Hibernate, PowerState::Suspend));
    }

    #[test]
    fn directive_map_closed_set() {
        // 四态映射闭集全 Some（漏项即 None 显形）
        assert_eq!(directive_for(PowerState::Active), Some(Directive::Restore));
        assert_eq!(directive_for(PowerState::Idle), Some(Directive::DimTo(25)));
        assert_eq!(directive_for(PowerState::Suspend), Some(Directive::Blank));
        assert_eq!(directive_for(PowerState::Hibernate), Some(Directive::Blank));
    }

    #[test]
    fn power_display_coop_chain() {
        // 端到端协同链：电源三阶段 decide → 迁移闸 → directive_for → apply
        let th = Thresholds::default();
        let obs = |idle: u64, bat: u8, ac: bool| Observation {
            user_idle_ms: idle,
            battery_pct: bat,
            on_ac: ac,
        };
        let mut dp = DisplayPower::new();
        // 活跃期：Stay → 显示不动（On）
        let a = decide(&obs(60_000, 90, true), &th);
        assert_eq!(a, Action::Stay);
        // 空闲达阈：Idle → DimTo(25)
        let a = decide(&obs(200_000, 90, true), &th);
        assert_eq!(a, Action::Transition(PowerState::Idle));
        if let Action::Transition(s) = a {
            dp.apply(directive_for(s).unwrap()).unwrap();
        }
        assert_eq!(dp.state(), DisplayState::Dim);
        assert_eq!(dp.brightness(), 25);
        // 低电量回退：Suspend → Blank
        let a = decide(&obs(1_000, 10, false), &th);
        assert_eq!(a, Action::Transition(PowerState::Suspend));
        if let Action::Transition(s) = a {
            dp.apply(directive_for(s).unwrap()).unwrap();
        }
        assert_eq!(dp.state(), DisplayState::Blank);
        assert_eq!(dp.brightness(), 0);
        // 回插电源唤醒：Active → Restore 全亮
        let a = decide(&obs(0, 90, true), &th);
        assert_eq!(a, Action::Stay);
        dp.apply(Directive::Restore).unwrap();
        assert_eq!(dp.state(), DisplayState::On);
        assert_eq!(dp.brightness(), 100);
    }
}
