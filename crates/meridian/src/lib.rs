//! Meridian 经纬 —— OS 服务监管者。
//!
//! 依据《指标与规范手册》第 3 章：Meridian 是最大的 safe Rust 组件，负责服务
//! 注册、启动序编排与故障恢复。本 crate 实现监管者的策略核心：
//!
//! - 注册表：服务名 → 状态机；
//! - 恢复策略：指数退避重启，封顶 30 s，`Always` 策略不受失败计数影响；
//! - 幂等恢复：对已运行服务重复 `start` 必须是无操作（幂等恢复的监管面保证）。
//!
//! 与 Bedrock 的交互（系统调用分发）在服务进程中实现；本 crate 不做 IO。
//!
//! M24-M1 起新增分发器首割 [`dispatcher`]：号 + 版本位解码、能力校验
//! 入口与三层错误模型（细则 §3.2/§3.3；M-P01 打点骨架在位）。

pub mod dispatcher;

/// M24-M2 生成物落位：IDL 契约（`crates/meridian/idl/`）经 `xtask idl-gen`
/// 生成 —— 禁止手编；漂移由 `xtask idl-check`（ci S5b-idl 阶段）以字节级
/// 比对拒绝。契约变更流程：改 toml → idl-gen → 生成物随契约同批提交。
pub mod idl_gen;

use std::collections::HashMap;

/// 重启策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// 失败不重启。
    Never,
    /// 失败后按退避重启，最多 `max_retries` 次。
    OnFailure {
        /// 最大重启次数。
        max_retries: u32,
    },
    /// 总是重启（守护服务默认）。
    Always,
}

/// 服务运行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// 已注册未启动。
    Stopped,
    /// 启动中（握手未完成）。
    Starting,
    /// 正常运行。
    Running,
    /// 失败后退避等待第 `attempt` 次重启。
    Backoff(u32),
    /// 重启次数耗尽，判定失败。
    Failed,
}

/// 服务规格。
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// 服务唯一名（反向域名约定）。
    pub name: String,
    /// 重启策略。
    pub policy: RestartPolicy,
    /// 初始退避时长（毫秒）。
    pub base_backoff_ms: u64,
}

/// 监管者注册表。
#[derive(Debug, Default)]
pub struct Supervisor {
    services: HashMap<String, (ServiceSpec, ServiceState)>,
}

/// 退避封顶（毫秒）。
pub const BACKOFF_CAP_MS: u64 = 30_000;

impl Supervisor {
    /// 注册服务；重名覆盖既有注册（启动序编排方负责唯一性）。
    pub fn register(&mut self, spec: ServiceSpec) {
        self.services
            .insert(spec.name.clone(), (spec, ServiceState::Stopped));
    }

    /// 启动服务。幂等：`Starting`/`Running` 状态下重复启动为无操作。
    pub fn start(&mut self, name: &str) -> Result<ServiceState, String> {
        let Some((_, state)) = self.services.get_mut(name) else {
            return Err(format!("unknown service: {name}"));
        };
        match state {
            ServiceState::Starting | ServiceState::Running => Ok(*state),
            ServiceState::Stopped | ServiceState::Backoff(_) => {
                *state = ServiceState::Starting;
                Ok(ServiceState::Starting)
            }
            ServiceState::Failed => Err(format!("service {name} exhausted retries")),
        }
    }

    /// 通知服务就绪。
    pub fn mark_running(&mut self, name: &str) -> Result<(), String> {
        match self.services.get_mut(name) {
            None => Err(format!("unknown service: {name}")),
            Some((_, state)) => {
                *state = ServiceState::Running;
                Ok(())
            }
        }
    }

    /// 服务退出：按策略决定重启或判死。返回下次重启的退避毫秒数（None = 不重启）。
    pub fn on_exit(&mut self, name: &str, failed: bool) -> Result<Option<u64>, String> {
        let Some((spec, state)) = self.services.get_mut(name) else {
            return Err(format!("unknown service: {name}"));
        };
        if !failed {
            *state = ServiceState::Stopped;
            return Ok(None);
        }
        let attempt = match *state {
            ServiceState::Backoff(n) => n + 1,
            _ => 1,
        };
        match spec.policy {
            RestartPolicy::Never => {
                *state = ServiceState::Failed;
                Ok(None)
            }
            RestartPolicy::OnFailure { max_retries } if attempt > max_retries => {
                *state = ServiceState::Failed;
                Ok(None)
            }
            _ => {
                let backoff =
                    (spec.base_backoff_ms.saturating_mul(attempt as u64)).min(BACKOFF_CAP_MS);
                *state = ServiceState::Backoff(attempt);
                Ok(Some(backoff))
            }
        }
    }

    /// 查询状态。
    pub fn state(&self, name: &str) -> Option<ServiceState> {
        self.services.get(name).map(|(_, s)| *s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{RestartPolicy, ServiceSpec, ServiceState, Supervisor};

    fn spec(name: &str, policy: RestartPolicy) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            policy,
            base_backoff_ms: 100,
        }
    }

    #[test]
    fn idempotent_start_is_noop() {
        let mut s = Supervisor::default();
        s.register(spec("org.lumina.weave", RestartPolicy::Always));
        assert_eq!(s.start("org.lumina.weave"), Ok(ServiceState::Starting));
        assert_eq!(s.start("org.lumina.weave"), Ok(ServiceState::Starting));
        s.mark_running("org.lumina.weave").expect("running");
        assert_eq!(s.start("org.lumina.weave"), Ok(ServiceState::Running));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut s = Supervisor::default();
        s.register(spec("org.lumina.crystal", RestartPolicy::Always));
        s.start("org.lumina.crystal").expect("start");
        assert_eq!(s.on_exit("org.lumina.crystal", true), Ok(Some(100)));
        assert_eq!(s.on_exit("org.lumina.crystal", true), Ok(Some(200)));
        assert_eq!(s.on_exit("org.lumina.crystal", true), Ok(Some(300)));
        for _ in 0..400 {
            s.on_exit("org.lumina.crystal", true).expect("always");
        }
        assert_eq!(
            s.on_exit("org.lumina.crystal", true),
            Ok(Some(30_000)),
            "cap"
        );
    }

    #[test]
    fn retry_budget_exhausts() {
        let mut s = Supervisor::default();
        s.register(spec(
            "org.lumina.fragile",
            RestartPolicy::OnFailure { max_retries: 2 },
        ));
        s.start("org.lumina.fragile").expect("start");
        assert!(s.on_exit("org.lumina.fragile", true).expect("1").is_some());
        assert!(s.on_exit("org.lumina.fragile", true).expect("2").is_some());
        assert_eq!(s.on_exit("org.lumina.fragile", true), Ok(None));
        assert_eq!(s.state("org.lumina.fragile"), Some(ServiceState::Failed));
        assert!(s.start("org.lumina.fragile").is_err());
    }

    #[test]
    fn clean_exit_stops_retrying() {
        let mut s = Supervisor::default();
        s.register(spec("org.lumina.tools", RestartPolicy::Always));
        s.start("org.lumina.tools").expect("start");
        s.mark_running("org.lumina.tools").expect("running");
        assert_eq!(s.on_exit("org.lumina.tools", false), Ok(None));
        assert_eq!(s.state("org.lumina.tools"), Some(ServiceState::Stopped));
    }
}
