//! Aurora 极光 —— 原生应用框架核心。
//!
//! 依据《指标与规范手册》第 16 章（Aurora 规范，AF 指标族）：AF-P01 要求框架冷
//! 启动开销 ≤120 ms（P0 硬门禁），生命周期迁移 MUST 全部经过框架校验。本 crate
//! 实现两个策略面：
//!
//! - [`LuappManifest`]：`.luapp` 清单的最小校验（应用 id 反向域名、能力声明）；
//! - [`AppRuntime`]：六态生命周期状态机（Registered → Launching → Foreground →
//!   Background → Suspended → Terminated），拦截率 100%（AF-P03，P0）。
//!
//! 能力权限的派生规则由 Vanguard 能力模型执行；意图路由与后台任务在 SDK 服务侧。

/// 应用生命周期六态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// 已注册（清单已装载）。
    Registered,
    /// 启动中。
    Launching,
    /// 前台运行。
    Foreground,
    /// 后台驻留。
    Background,
    /// 已挂起（冻结内存）。
    Suspended,
    /// 已终止（终态）。
    Terminated,
}

/// 应用运行时：生命周期状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppRuntime {
    state: Lifecycle,
}

impl AppRuntime {
    /// 创建应用实例（初始 Registered）。
    pub fn new() -> Self {
        Self {
            state: Lifecycle::Registered,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> Lifecycle {
        self.state
    }

    /// 迁移生命周期；非法迁移被拦截并返回 Err（迁移必须可审计）。
    pub fn transition(&mut self, to: Lifecycle) -> Result<(), String> {
        let ok = matches!(
            (self.state, to),
            (Lifecycle::Registered, Lifecycle::Launching)
                | (Lifecycle::Launching, Lifecycle::Foreground)
                | (Lifecycle::Launching, Lifecycle::Terminated)
                | (Lifecycle::Foreground, Lifecycle::Background)
                | (Lifecycle::Background, Lifecycle::Foreground)
                | (Lifecycle::Background, Lifecycle::Suspended)
                | (Lifecycle::Background, Lifecycle::Terminated)
                | (Lifecycle::Suspended, Lifecycle::Terminated)
                | (Lifecycle::Suspended, Lifecycle::Background)
        );
        if ok {
            self.state = to;
            Ok(())
        } else {
            Err(format!(
                "illegal lifecycle transition {:?} -> {:?}",
                self.state, to
            ))
        }
    }
}

impl Default for AppRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// 清单校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// 应用 id 不符合反向域名格式（≥3 段、段非空、全小写字母数字点）。
    BadAppId,
    /// 能力声明为空（应用 MUST 显式声明所需能力，哪怕为只读最小集）。
    NoCapabilities,
}

/// `.luapp` 应用清单（最小面；完整字段表见 LUM-DEV-AUR-001 附录）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuappManifest {
    /// 应用 id，如 `org.lumina.notes`。
    pub app_id: String,
    /// 显示名。
    pub display_name: String,
    /// 版本（Weave 语义化版本）。
    pub version: String,
    /// 声明的能力（如 `cap.fs.documents.read`）。
    pub capabilities: Vec<String>,
}

impl LuappManifest {
    /// 校验清单的结构约束。
    pub fn validate(&self) -> Result<(), ManifestError> {
        let segs: Vec<&str> = self.app_id.split('.').collect();
        let ok_shape = segs.len() >= 3
            && segs.iter().all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            });
        if !ok_shape {
            return Err(ManifestError::BadAppId);
        }
        if self.capabilities.is_empty() {
            return Err(ManifestError::NoCapabilities);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{AppRuntime, Lifecycle, LuappManifest};

    #[test]
    fn full_lifecycle_walk() {
        let mut a = AppRuntime::new();
        assert_eq!(a.state(), Lifecycle::Registered);
        for to in [
            Lifecycle::Launching,
            Lifecycle::Foreground,
            Lifecycle::Background,
            Lifecycle::Suspended,
            Lifecycle::Terminated,
        ] {
            a.transition(to).expect("legal step");
        }
        assert_eq!(a.state(), Lifecycle::Terminated);
    }

    #[test]
    fn foreground_only_via_launching() {
        let mut a = AppRuntime::new();
        assert!(
            a.transition(Lifecycle::Foreground).is_err(),
            "registered -> foreground illegal"
        );
        a.transition(Lifecycle::Launching).expect("launch");
        a.transition(Lifecycle::Background)
            .expect_err("launching -> background illegal");
        a.transition(Lifecycle::Foreground).expect("launch -> fg");
        assert!(
            a.transition(Lifecycle::Suspended).is_err(),
            "fg -> suspended illegal"
        );
    }

    #[test]
    fn terminated_is_sink() {
        let mut a = AppRuntime::new();
        a.transition(Lifecycle::Launching).expect("launch");
        a.transition(Lifecycle::Terminated).expect("abort");
        for to in [
            Lifecycle::Registered,
            Lifecycle::Launching,
            Lifecycle::Foreground,
        ] {
            assert!(a.transition(to).is_err(), "terminated must be sink");
        }
    }

    #[test]
    fn manifest_validation() {
        let good = LuappManifest {
            app_id: "org.lumina.notes".into(),
            display_name: "Notes".into(),
            version: "0.3.1".into(),
            capabilities: vec!["cap.fs.documents.read".into()],
        };
        assert_eq!(good.validate(), Ok(()));

        let bad_id = LuappManifest {
            app_id: "Notes".into(),
            ..good.clone()
        };
        assert!(matches!(
            bad_id.validate(),
            Err(super::ManifestError::BadAppId)
        ));

        let no_cap = LuappManifest {
            capabilities: vec![],
            ..good
        };
        assert_eq!(no_cap.validate(), Err(super::ManifestError::NoCapabilities));
    }
}
