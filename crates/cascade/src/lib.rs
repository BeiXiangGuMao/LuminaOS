//! Cascade 流域 —— 桌面环境外壳语义。
//!
//! 依据《指标与规范手册》第 13 章：Cascade 管理桌面骨架（Panel/Dock/窗口栈）。
//! 本 crate 实现外壳状态机与窗口焦点序两个策略面；布局的双态引擎在服务侧，
//! 视觉规格由《美术设计指南》第四章与第七章定义。
//!
//! M30-C1 起 shell 语义四面归位（CA-P05 结构面，ROADMAP M30）：
//!
//! - [`ShellState`]/[`Shell`]：四态外壳状态机（Boot/LockScreen/Session/Overview）；
//! - [`FocusList`]：窗口焦点序（LRU 前置）；
//! - [`workspace::Workspaces`]：定容工作区表（窗口归属/切换/跨区定位）；
//! - [`tiling::tiling_plan`]：master-stack 平铺计划（产出 [`mirror::Rect`]
//!   几何单一事实源，保留域消费 `loom` 骨架常量）；
//! - [`dock::Dock`]：定容 Dock 登记面（图标档位校验消费 `glyph::scale_factor`）。
//!
//! M30-C1 起 no_std + alloc（crystal/mirror 先例）：内核自检段（t79）直接
//! 消费本 crate 的语义面；宿主测试经 test 模块照常运行。
#![no_std]
extern crate alloc;

use alloc::{format, string::String, vec::Vec};

pub mod dock;
pub mod tiling;
pub mod workspace;

/// 外壳语义面错误集（fail-visible，无静默吞并）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellError {
    /// 工作区索引越界。
    WorkspaceRange,
    /// 窗口已存在于任一工作区（重复打开拒收）。
    AlreadyOpen,
    /// 窗口未在指定工作区打开。
    NotOpen,
    /// 应用已在 Dock 登记。
    DuplicateApp,
    /// Dock 容量满。
    DockFull,
    /// 图标尺寸不在 24/48/96 档位（glyph::scale_factor 闸）。
    IllegalIcon,
    /// 视口不可承载桌面骨架（零维或小于 Panel+Dock+双倍网格保留域）。
    Viewport,
}

/// 外壳全局状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellState {
    /// 启动中。
    Boot,
    /// 锁屏。
    LockScreen,
    /// 用户会话。
    Session,
    /// 多任务概览。
    Overview,
}

/// 外壳状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shell {
    state: ShellState,
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

impl Shell {
    /// 创建外壳（初始 Boot）。
    pub fn new() -> Self {
        Self {
            state: ShellState::Boot,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> ShellState {
        self.state
    }

    /// 尝试迁移状态；非法迁移返回 Err 并保持原状。
    pub fn transition(&mut self, to: ShellState) -> Result<(), String> {
        let ok = matches!(
            (self.state, to),
            (ShellState::Boot, ShellState::LockScreen)
                | (ShellState::LockScreen, ShellState::Session)
                | (ShellState::Session, ShellState::LockScreen)
                | (ShellState::Session, ShellState::Overview)
                | (ShellState::Overview, ShellState::Session)
                | (ShellState::Overview, ShellState::LockScreen)
        );
        if ok {
            self.state = to;
            Ok(())
        } else {
            Err(format!(
                "illegal shell transition {:?} -> {:?}",
                self.state, to
            ))
        }
    }

    /// 外壳是否处于可操作工作区的状态（Session/Overview 语义面）。
    ///
    /// Boot/LockScreen 不暴露工作区操作——组合契约：`Workspaces` 自身不感知
    /// 外壳状态，由调用方（组合层/自检段）以本谓词把门。
    pub fn workspace_available(&self) -> bool {
        matches!(self.state, ShellState::Session | ShellState::Overview)
    }
}

/// 窗口焦点序：最后激活的窗口在最前。
#[derive(Debug, Default)]
pub struct FocusList {
    order: Vec<u64>,
}

impl FocusList {
    /// 创建空焦点序（const，供工作区表定容初始化）。
    pub const fn new() -> Self {
        Self { order: Vec::new() }
    }

    /// 激活窗口（不存在则加入）。
    pub fn activate(&mut self, id: u64) {
        if let Some(pos) = self.order.iter().position(|&x| x == id) {
            self.order.remove(pos);
        }
        self.order.insert(0, id);
    }

    /// 关闭窗口。
    pub fn close(&mut self, id: u64) -> bool {
        let before = self.order.len();
        self.order.retain(|&x| x != id);
        self.order.len() != before
    }

    /// 当前焦点窗口。
    pub fn focused(&self) -> Option<u64> {
        self.order.first().copied()
    }

    /// 栈序（从焦点到底部）。
    pub fn stack(&self) -> &[u64] {
        &self.order
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FocusList, Shell, ShellState};

    #[test]
    fn shell_boot_to_session_via_lock() {
        let mut sh = Shell::new();
        assert_eq!(sh.state(), ShellState::Boot);
        assert!(
            sh.transition(ShellState::Session).is_err(),
            "boot -> session illegal"
        );
        sh.transition(ShellState::LockScreen).expect("boot -> lock");
        sh.transition(ShellState::Session).expect("lock -> session");
        sh.transition(ShellState::Overview)
            .expect("session -> overview");
        sh.transition(ShellState::LockScreen)
            .expect("overview -> lock");
    }

    #[test]
    fn workspace_gate_follows_shell_state() {
        // 组合契约谓词：Boot/LockScreen 不暴露工作区
        let mut sh = Shell::new();
        assert!(!sh.workspace_available());
        sh.transition(ShellState::LockScreen).expect("boot -> lock");
        assert!(!sh.workspace_available());
        sh.transition(ShellState::Session).expect("lock -> session");
        assert!(sh.workspace_available());
        sh.transition(ShellState::Overview).expect("-> overview");
        assert!(sh.workspace_available());
    }

    #[test]
    fn focus_order_is_lru_front() {
        let mut f = FocusList::new();
        f.activate(1);
        f.activate(2);
        f.activate(3);
        assert_eq!(f.focused(), Some(3));
        f.activate(1);
        assert_eq!(f.focused(), Some(1));
        assert_eq!(f.stack(), &[1, 3, 2]);
        assert!(f.close(3));
        assert_eq!(f.stack(), &[1, 2]);
    }
}
