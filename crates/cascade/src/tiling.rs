//! 平铺策略面 —— master-stack 布局计划（纯函数，几何单一事实源）。
//!
//! 桌面骨架 CA-P05 结构面之二：动态平铺 v0 承接 master-stack 形态——
//! 首窗（焦点窗）居左半为 master，余窗右列均分纵排。产出
//! [`mirror::Rect`] 几何单一事实源（prism::Stack 直接可消费；
//! 与 loom 布局产出同源对账——两套面同一几何）。
//!
//! 保留域消费 `loom` 骨架常量（单一事实源纪律）：Panel 顶保留
//! [`loom::PANEL_HEIGHT`]、Dock 底保留 [`loom::DOCK_HEIGHT`]；间距统一
//! [`loom::GRID`]（内容域四周边距 + master/stack 中缝 + 纵排缝同值），
//! 全值天然落 8px 网格（ART-003 纪律由常量构造保证）。
//!
//! 窗口序契约：调用方传入顺序即 z 序——index 0 为 master（通常是焦点窗）。

use crate::ShellError;
use alloc::vec::Vec;
use loom::{DOCK_HEIGHT, GRID, PANEL_HEIGHT};
use mirror::Rect;

/// 平铺计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TilingPlan {
    /// 平铺内容域（Panel/Dock 保留域之间的桌面区）。
    pub content: Rect,
    /// 窗矩形序列（index 0 = master；空窗表为空序列）。
    pub panes: Vec<(u64, Rect)>,
}

/// master-stack 平铺计划。
///
/// - 内容域 = 视口挖去 Panel 顶带与 Dock 底带；
/// - 内容域内四周边距 8px 得铺排盒；
/// - 0 窗 → 空窗序列（计划仍有效，content 可用）；
/// - 1 窗 → master 独占铺排盒；
/// - ≥2 窗 → master 居左半（中缝 8px），余窗右列纵排均分
///   （纵排余数归首块——与 loom Fill 余数纪律同构，确定性分配）；
/// - 视口不可承载骨架（小于 Panel+Dock+双倍网格）→ [`ShellError::Viewport`]。
pub fn tiling_plan(windows: &[u64], viewport: (u32, u32)) -> Result<TilingPlan, ShellError> {
    let g = GRID;
    let min_h = PANEL_HEIGHT + DOCK_HEIGHT + 2 * g;
    if viewport.0 < 2 * g + 1 || viewport.1 < min_h {
        return Err(ShellError::Viewport);
    }
    let content = Rect {
        x: 0,
        y: PANEL_HEIGHT as i32,
        w: viewport.0,
        h: viewport.1 - PANEL_HEIGHT - DOCK_HEIGHT,
    };
    // 铺排盒（内容域内缩一周网格）
    let box_x = content.x + g as i32;
    let box_y = content.y + g as i32;
    let box_w = content.w - 2 * g;
    let box_h = content.h - 2 * g;

    let mut panes = Vec::new();
    match windows.len() {
        0 => {}
        1 => {
            panes.push((
                windows[0],
                Rect {
                    x: box_x,
                    y: box_y,
                    w: box_w,
                    h: box_h,
                },
            ));
        }
        n => {
            let mid = g as i32;
            let master_w = (box_w - g) / 2;
            panes.push((
                windows[0],
                Rect {
                    x: box_x,
                    y: box_y,
                    w: master_w,
                    h: box_h,
                },
            ));
            // 右列纵排：k 块均分，余数归首块
            let k = n - 1;
            let stack_x = box_x + master_w as i32 + mid;
            let stack_w = box_w - g - master_w;
            let base = (box_h - (k as u32 - 1) * g) / k as u32;
            let leftover = (box_h - (k as u32 - 1) * g) % k as u32;
            let mut y = box_y;
            for (i, &id) in windows[1..].iter().enumerate() {
                let h = base + if i == 0 { leftover } else { 0 };
                panes.push((
                    id,
                    Rect {
                        x: stack_x,
                        y,
                        w: stack_w,
                        h,
                    },
                ));
                y += h as i32 + g as i32;
            }
        }
    }
    Ok(TilingPlan { content, panes })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::tiling_plan;
    use crate::ShellError;
    use loom::{DOCK_HEIGHT, GRID, PANEL_HEIGHT};

    fn rect(x: i32, y: i32, w: u32, h: u32) -> mirror::Rect {
        mirror::Rect { x, y, w, h }
    }

    #[test]
    fn content_reserves_panel_and_dock() {
        let p = tiling_plan(&[], (1920, 1080)).unwrap();
        assert_eq!(p.content, rect(0, 48, 1920, 960));
        assert!(p.panes.is_empty());
        // 保留域常量同源对账
        assert_eq!(p.content.y, PANEL_HEIGHT as i32);
        assert_eq!(p.content.h, 1080 - PANEL_HEIGHT - DOCK_HEIGHT);
    }

    #[test]
    fn single_window_takes_box() {
        let p = tiling_plan(&[7], (1920, 1080)).unwrap();
        assert_eq!(p.panes.len(), 1);
        // 铺排盒 = 内容域内缩 8：(8,56,1904,944)
        assert_eq!(
            p.panes[0].1,
            rect(GRID as i32, (PANEL_HEIGHT + GRID) as i32, 1904, 944)
        );
        assert_eq!(p.panes[0].0, 7);
    }

    #[test]
    fn master_stack_golden_two_windows() {
        let p = tiling_plan(&[1, 2], (1920, 1080)).unwrap();
        assert_eq!(p.panes.len(), 2);
        // master 左半：(8,56,948,944)
        assert_eq!(p.panes[0].1, rect(8, 56, 948, 944));
        // stack 右半：(964,56,948,944)
        assert_eq!(p.panes[1].1, rect(964, 56, 948, 944));
        // 中缝恰 8px：964 - (8+948) = 8
    }

    #[test]
    fn stack_column_even_split_three_windows() {
        let p = tiling_plan(&[1, 2, 3], (1920, 1080)).unwrap();
        // 纵排 2 块均分：(944-8)/2 = 468 each
        assert_eq!(p.panes[1].1, rect(964, 56, 948, 468));
        assert_eq!(p.panes[2].1, rect(964, 532, 948, 468));
        // 缝 8：532 - (56+468) = 8
    }

    #[test]
    fn stack_remainder_goes_to_first_block() {
        // 视口高 1081：content h=961、铺排盒 h=945；2 块：(945-8)/2=468 余 1 → 首 469
        let p = tiling_plan(&[1, 2, 3], (1920, 1081)).unwrap();
        assert_eq!(p.panes[1].1, rect(964, 56, 948, 469));
        assert_eq!(p.panes[2].1, rect(964, 533, 948, 468));
    }

    #[test]
    fn order_follows_caller_z_contract() {
        // 焦点序传入：index 0 = master（调用方先把焦点窗排首位）
        let p = tiling_plan(&[42, 7, 9], (1920, 1080)).unwrap();
        assert_eq!(p.panes[0].0, 42);
        assert_eq!(p.panes[1].0, 7);
        assert_eq!(p.panes[2].0, 9);
    }

    #[test]
    fn viewport_too_small_rejected() {
        assert_eq!(tiling_plan(&[], (100, 100)), Err(ShellError::Viewport));
        assert_eq!(tiling_plan(&[], (0, 1080)), Err(ShellError::Viewport));
        // 恰好最小可承载：2*8+1 宽 × Panel+Dock+16 高
        let min_w = 2 * GRID + 1;
        let min_h = PANEL_HEIGHT + DOCK_HEIGHT + 2 * GRID;
        assert!(tiling_plan(&[], (min_w, min_h)).is_ok());
    }
}
