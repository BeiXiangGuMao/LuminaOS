//! Cascade 流域 —— 桌面环境外壳状态。
//!
//! 依据《指标与规范手册》第 13 章：Cascade 管理桌面骨架（Panel/Dock/窗口栈）。
//! 本 crate 实现外壳状态机与窗口焦点序两个策略面；布局的双态引擎在服务侧，
//! 视觉规格由《美术设计指南》第四章与第七章定义。

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
}

/// 窗口焦点序：最后激活的窗口在最前。
#[derive(Debug, Default)]
pub struct FocusList {
    order: Vec<u64>,
}

impl FocusList {
    /// 创建空焦点序。
    pub fn new() -> Self {
        Self::default()
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
