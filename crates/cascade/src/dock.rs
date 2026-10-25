//! Dock 登记面 —— 定容启动器栏语义（零堆）。
//!
//! 桌面骨架 CA-P05 结构面之三：Dock 以固定槽位承载启动器项
//! （应用 + 图标档位）。图标档位校验消费 [`glyph::scale_factor`]
//! 单一事实源（24/48/96 三档；非档位拒收 fail-visible——非法档位
//! 在登记面即显形，不留到渲染面才失败）。
//!
//! 视觉常量纪律：悬停/间距/图标本体渲染归 glyph/loom/ripple 各自
//! 单一事实源；Dock 只承载「谁在栏上、用什么档位」的登记语义。

use crate::ShellError;
use glyph::scale_factor;

/// Dock 项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DockItem {
    /// 应用身份。
    pub app: u64,
    /// 图标档位（24/48/96，glyph::scale_factor 校验过）。
    pub icon: u32,
}

/// 定容 Dock（const new，内核 static 可用）。
#[derive(Debug)]
pub struct Dock<const N: usize> {
    items: [Option<DockItem>; N],
    len: usize,
}

impl<const N: usize> Dock<N> {
    /// 空 Dock（const）。
    pub const fn new() -> Self {
        Self {
            items: [const { None }; N],
            len: 0,
        }
    }

    /// 登记启动器项（档位闸 + 重复应用闸 + 容量闸，全 fail-visible）。
    pub fn register(&mut self, app: u64, icon: u32) -> Result<(), ShellError> {
        if scale_factor(icon).is_err() {
            return Err(ShellError::IllegalIcon);
        }
        if self.find(app).is_some() {
            return Err(ShellError::DuplicateApp);
        }
        if self.len >= N {
            return Err(ShellError::DockFull);
        }
        self.items[self.len] = Some(DockItem { app, icon });
        self.len += 1;
        Ok(())
    }

    /// 注销启动器项（保序左移；返回是否确有删除）。
    pub fn unregister(&mut self, app: u64) -> bool {
        let Some(pos) = self.find(app) else {
            return false;
        };
        for i in pos..self.len - 1 {
            self.items[i] = self.items[i + 1];
        }
        self.items[self.len - 1] = None;
        self.len -= 1;
        true
    }

    /// 已登记项（保序切片）。
    pub fn items(&self) -> &[Option<DockItem>] {
        &self.items[..self.len]
    }

    /// 登记数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn find(&self, app: u64) -> Option<usize> {
        self.items[..self.len]
            .iter()
            .position(|it| it.is_some_and(|i| i.app == app))
    }
}

impl<const N: usize> Default for Dock<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::Dock;
    use crate::ShellError;

    #[test]
    fn register_validates_icon_against_glyph_scale() {
        let mut d = Dock::<4>::new();
        assert!(d.register(1, 24).is_ok());
        assert!(d.register(2, 48).is_ok());
        assert!(d.register(3, 96).is_ok());
        // 非档位（glyph::scale_factor 闸拒收）
        assert_eq!(d.register(4, 32), Err(ShellError::IllegalIcon));
        assert_eq!(d.register(4, 0), Err(ShellError::IllegalIcon));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn duplicate_app_rejected() {
        let mut d = Dock::<4>::new();
        d.register(1, 24).unwrap();
        assert_eq!(d.register(1, 48), Err(ShellError::DuplicateApp));
        assert_eq!(d.len(), 1);
        assert_eq!(d.items()[0].map(|i| i.icon), Some(24));
    }

    #[test]
    fn capacity_gate_and_unregister_keeps_order() {
        let mut d = Dock::<2>::new();
        d.register(1, 24).unwrap();
        d.register(2, 48).unwrap();
        assert_eq!(d.register(3, 24), Err(ShellError::DockFull));
        // 注销首项 → 保序左移
        assert!(d.unregister(1));
        assert!(!d.unregister(1));
        assert_eq!(d.items()[0].map(|i| i.app), Some(2));
        assert_eq!(d.len(), 1);
        d.register(3, 96).unwrap();
        assert_eq!(d.items()[1].map(|i| i.app), Some(3));
    }
}
