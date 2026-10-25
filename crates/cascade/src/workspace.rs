//! 工作区语义面 —— 定容工作区表与窗口归属。
//!
//! 桌面骨架 CA-P05 结构面之一：固定数量工作区（[`WORKSPACE_COUNT`]），
//! 每区独立 [`FocusList`] 焦点序；窗口全局唯一归属（跨区重复打开拒收），
//! 切换/定位/关闭全闸 fail-visible。
//!
//! 组合契约：本面不感知外壳状态（Boot/LockScreen 不暴露工作区操作），
//! 调用方以 [`crate::Shell::workspace_available`] 把门——语义分层面
//! 不做隐藏耦合，t79 活体按此契约对账。

use crate::{FocusList, ShellError};

/// 工作区数量（v0 固定四面）。
pub const WORKSPACE_COUNT: usize = 4;

/// 工作区表（定容，const new——内核 static 可用）。
#[derive(Debug)]
pub struct Workspaces {
    current: usize,
    lists: [FocusList; WORKSPACE_COUNT],
}

impl Default for Workspaces {
    fn default() -> Self {
        Self::new()
    }
}

impl Workspaces {
    /// 空表（const：初始 0 号区）。
    pub const fn new() -> Self {
        Self {
            current: 0,
            lists: [const { FocusList::new() }; WORKSPACE_COUNT],
        }
    }

    /// 当前工作区号。
    pub fn current(&self) -> usize {
        self.current
    }

    /// 切换当前工作区（越界拒收，状态保持）。
    pub fn switch(&mut self, ws: usize) -> Result<(), ShellError> {
        if ws >= WORKSPACE_COUNT {
            return Err(ShellError::WorkspaceRange);
        }
        self.current = ws;
        Ok(())
    }

    /// 在指定工作区打开窗口（全局唯一归属——已存在于任一区则拒收）。
    pub fn open(&mut self, id: u64, ws: usize) -> Result<(), ShellError> {
        if ws >= WORKSPACE_COUNT {
            return Err(ShellError::WorkspaceRange);
        }
        if self.locate(id).is_some() {
            return Err(ShellError::AlreadyOpen);
        }
        self.lists[ws].activate(id);
        Ok(())
    }

    /// 关闭窗口（任意区；返回是否确有删除）。
    pub fn close(&mut self, id: u64) -> bool {
        let mut closed = false;
        for f in &mut self.lists {
            if f.close(id) {
                closed = true;
            }
        }
        closed
    }

    /// 激活指定工作区中的既有窗口（置顶；窗口不在该区拒收）。
    pub fn activate_in(&mut self, ws: usize, id: u64) -> Result<(), ShellError> {
        if ws >= WORKSPACE_COUNT {
            return Err(ShellError::WorkspaceRange);
        }
        if !self.lists[ws].stack().contains(&id) {
            return Err(ShellError::NotOpen);
        }
        self.lists[ws].activate(id);
        Ok(())
    }

    /// 跨区定位窗口归属（返回区号）。
    pub fn locate(&self, id: u64) -> Option<usize> {
        self.lists.iter().position(|f| f.stack().contains(&id))
    }

    /// 指定工作区焦点窗口。
    pub fn focused_in(&self, ws: usize) -> Result<Option<u64>, ShellError> {
        if ws >= WORKSPACE_COUNT {
            return Err(ShellError::WorkspaceRange);
        }
        Ok(self.lists[ws].focused())
    }

    /// 指定工作区栈序（焦点 → 底部）。
    pub fn stack_in(&self, ws: usize) -> Result<&[u64], ShellError> {
        if ws >= WORKSPACE_COUNT {
            return Err(ShellError::WorkspaceRange);
        }
        Ok(self.lists[ws].stack())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Workspaces, WORKSPACE_COUNT};
    use crate::ShellError;

    #[test]
    fn open_switch_focus_per_workspace() {
        let mut ws = Workspaces::new();
        assert_eq!(ws.current(), 0);
        ws.open(1, 0).unwrap();
        ws.open(2, 0).unwrap();
        ws.open(3, 1).unwrap();
        // 每区独立焦点序：0 区最近激活 2；1 区 3
        assert_eq!(ws.focused_in(0).unwrap(), Some(2));
        assert_eq!(ws.focused_in(1).unwrap(), Some(3));
        assert_eq!(ws.stack_in(0).unwrap(), &[2, 1]);
        // 切换 + 当前区焦点
        ws.switch(1).unwrap();
        assert_eq!(ws.focused_in(1).unwrap(), Some(3));
        // 跨区定位
        assert_eq!(ws.locate(1), Some(0));
        assert_eq!(ws.locate(3), Some(1));
        assert_eq!(ws.locate(9), None);
    }

    #[test]
    fn duplicate_open_rejected_globally() {
        let mut ws = Workspaces::new();
        ws.open(1, 0).unwrap();
        // 同区重复
        assert_eq!(ws.open(1, 0), Err(ShellError::AlreadyOpen));
        // 跨区重复（全局唯一归属）
        assert_eq!(ws.open(1, 2), Err(ShellError::AlreadyOpen));
        // 拒收后状态不变
        assert_eq!(ws.locate(1), Some(0));
    }

    #[test]
    fn range_gates_are_visible() {
        let mut ws = Workspaces::new();
        let oob = WORKSPACE_COUNT; // 4 越界
        assert_eq!(ws.switch(oob), Err(ShellError::WorkspaceRange));
        assert_eq!(ws.open(1, oob), Err(ShellError::WorkspaceRange));
        assert_eq!(ws.focused_in(oob), Err(ShellError::WorkspaceRange));
        assert!(ws.stack_in(oob).is_err());
        // 拒收后当前区不变
        assert_eq!(ws.current(), 0);
    }

    #[test]
    fn close_removes_from_any_workspace() {
        let mut ws = Workspaces::new();
        ws.open(1, 0).unwrap();
        ws.open(2, 3).unwrap();
        assert!(ws.close(2));
        assert_eq!(ws.locate(2), None);
        assert!(!ws.close(2), "二次关闭 false");
        assert!(ws.close(1));
        assert_eq!(ws.focused_in(0).unwrap(), None);
    }

    #[test]
    fn activate_in_requires_membership() {
        let mut ws = Workspaces::new();
        ws.open(1, 0).unwrap();
        ws.open(2, 1).unwrap();
        // 未在本区
        assert_eq!(ws.activate_in(0, 2), Err(ShellError::NotOpen));
        ws.activate_in(0, 1).unwrap();
        assert_eq!(ws.focused_in(0).unwrap(), Some(1));
    }
}
