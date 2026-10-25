//! Aurora 极光 —— 原生应用框架核心。
//!
//! 依据《指标与规范手册》第 16 章（Aurora 规范，AF 指标族）：AF-P01 要求框架冷
//! 启动开销 ≤120 ms（P0 硬门禁）；AF-P06 要求生命周期全迁移 MUST 经框架校验；
//! AF-P03 要求生命周期拦截率 100%（P0）。本 crate 实现三个策略面：
//!
//! - [`LuappManifest`]：`.luapp` 清单的最小校验（应用 id 反向域名、能力声明
//!   逐条 schema 闸——M32-A1 能力域扩容）；
//! - [`AppRuntime`]：六态生命周期状态机（Registered → Launching → Foreground →
//!   Background → Suspended → Terminated），拦截率 100%（AF-P03，P0）；
//! - [`perm`]：权限中心首割四相面（声明 schema 闸 → 安装时授予〔vanguard
//!   CapabilityTable 承接桥〕→ 运行时检查拒绝显形 → 撤销后访问显形）；
//! - [`sdk`]：SDK 最小服务面（App 声明式注册折叠〔清单 + 生命周期回调单环
//!   折叠，loom Elm fold 纪律同构〕+ 意图路由骨架〔intent 命名域 + 定容
//!   路由表 + 未注册意图显形拒收〕——M32-S1）。
//!
//! 能力权限的派生规则由 Vanguard 能力模型执行（单一事实源——vanguard 本体
//! 零改动，M32-A1 政策边 aurora→vanguard）；意图路由随 M32-S1 落 [`sdk`]
//! 面，后台任务仍居 SDK 服务侧后续批次。
//!
//! M32-A1 起 no_std + alloc（crystal/cascade 先例）：内核自检段（t81）直接
//! 消费本 crate 的语义面；宿主测试经 test 模块照常运行。
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;

use alloc::{format, string::String, vec::Vec};

pub mod perm;
pub mod sdk;

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

    /// 迁移生命周期；非法迁移被拦截并返回 Err（迁移必须可审计，AF-P03 拦截 100%）。
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
    /// 能力声明 schema 非法（`cap.<域>.<资源>.<动作>` 四段闸——M32-A1 能力域
    /// 扩容；格式规则单一事实源在 [`perm::check_schema`]）。
    BadCapability,
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
        // M32-A1 能力域扩容：逐条 schema 闸（格式规则单一事实源 perm::check_schema）
        for cap in &self.capabilities {
            perm::check_schema(cap).map_err(|_| ManifestError::BadCapability)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{AppRuntime, Lifecycle, LuappManifest, ManifestError};
    use alloc::vec;

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
        assert!(matches!(bad_id.validate(), Err(ManifestError::BadAppId)));

        // M32-A1 能力域扩容：schema 非法声明逐条闸显形（三段缺资源段）
        let bad_cap = LuappManifest {
            capabilities: vec!["fs.documents.read".into()],
            ..good.clone()
        };
        assert_eq!(bad_cap.validate(), Err(ManifestError::BadCapability));

        let no_cap = LuappManifest {
            capabilities: vec![],
            ..good
        };
        assert_eq!(no_cap.validate(), Err(ManifestError::NoCapabilities));
    }
}
