//! 约束求解布局 —— 平面元素树 → 视口内 Frame 骨架矩形。
//!
//! 单轴约束求解（v0 承接面，ROADMAP M30-L1）：容器沿 [`crate::elm::Dir`]
//! 主轴排布子元素，`Fixed` 取确定值、`Fill` 按权重瓜分内容盒剩余主轴
//! 空间（余数全归首个 Fill 子——确定性分配）；横轴 v0 恒拉伸语义
//! （子元素横轴尺寸 = 内容盒横轴尺寸）。产出 [`mirror::Rect`] 几何
//! 单一事实源（loom 只产出坐标，不运算几何代数——交/并独占归 mirror）。
//!
//! ## 网格闸（ART-003 间距刻度纪律）
//!
//! `pad` 与 `gap` 必须落在 8px 网格（[`crate::GRID`] 整数倍），违者
//! [`LayoutError::OffGrid`] fail-visible——设计稿偏离网格按指南视为缺陷，
//! 布局面拒绝承载而非静默吸附。
//!
//! ## 溢出闸
//!
//! 固定尺寸之和加间距超出内容盒主轴 → [`LayoutError::Overflow`]；
//! 布局宁可拒绝也不裁剪（静默截断禁令，与 pulse 编码面同一纪律）。
//!
//! 零堆：子链三遍走（计数闸 → 余数核算 → 游标摊派），结果写入调用方
//! [`Layout`]（const new，内核 static 可用）。

use crate::elm::{Dir, Id, Main, ViewBuf};
use crate::GRID;
use mirror::Rect;

/// 布局错误集（fail-visible）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// 视口零维。
    Viewport,
    /// view 树未声明根。
    NoRoot,
    /// 句柄越界（树契约破坏）。
    BadId,
    /// 间距偏离 8px 网格（ART-003 纪律闸）。
    OffGrid {
        /// 违规节点。
        id: Id,
        /// 违规域（"pad"/"gap"）。
        field: &'static str,
        /// 违规值。
        value: u32,
    },
    /// Fill 权重为 0（权重域 ≥1）。
    FillWeight {
        /// 违规节点。
        id: Id,
    },
    /// 固定尺寸之和超出内容盒主轴。
    Overflow {
        /// 违规容器。
        id: Id,
    },
}

/// 布局结果槽（定容，const new，内核 static 可用）。
///
/// 矩形按节点 [`Id`] 索引；未求解/清空后槽位为 `None`。
#[derive(Debug)]
pub struct Layout<const N: usize> {
    rects: [Option<Rect>; N],
}

impl<const N: usize> Layout<N> {
    /// 空槽表（const）。
    pub const fn new() -> Self {
        Layout {
            rects: [const { None }; N],
        }
    }

    /// 清空（复用槽表解下一帧）。
    pub fn clear(&mut self) {
        self.rects = [const { None }; N];
    }

    /// 取节点求解矩形。
    pub fn rect(&self, id: Id) -> Option<Rect> {
        self.rects.get(id.0 as usize).copied().flatten()
    }
}

impl<const N: usize> Default for Layout<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// 网格闸：间距值必须是 8px 网格整数倍。
fn on_grid(v: u32) -> bool {
    v.is_multiple_of(GRID)
}

/// 求解入口：以 `viewport` 为根内容框，递归求解整棵 view 树。
///
/// 结果写入 `out`（先 clear）；任何闸失败即整体失败（调用方丢弃 `out`
/// 即可，fail-visible 不做半程产物）。
pub fn solve<const N: usize>(
    buf: &ViewBuf<N>,
    viewport: (u32, u32),
    out: &mut Layout<N>,
) -> Result<(), LayoutError> {
    if viewport.0 == 0 || viewport.1 == 0 {
        return Err(LayoutError::Viewport);
    }
    let Some(root) = buf.root() else {
        return Err(LayoutError::NoRoot);
    };
    out.clear();
    let root_rect = Rect {
        x: 0,
        y: 0,
        w: viewport.0,
        h: viewport.1,
    };
    solve_node(buf, root, root_rect, out)
}

/// 递归求解单节点：网格闸 → 落自身矩形 → 内容盒摊派子元素。
fn solve_node<const N: usize>(
    buf: &ViewBuf<N>,
    id: Id,
    rect: Rect,
    out: &mut Layout<N>,
) -> Result<(), LayoutError> {
    let Some(node) = buf.node(id) else {
        return Err(LayoutError::BadId);
    };
    for &p in &node.pad {
        if !on_grid(p) {
            return Err(LayoutError::OffGrid {
                id,
                field: "pad",
                value: p,
            });
        }
    }
    if !on_grid(node.gap) {
        return Err(LayoutError::OffGrid {
            id,
            field: "gap",
            value: node.gap,
        });
    }
    out.rects[id.0 as usize] = Some(rect);

    // 内容盒（pad 内缩；饱和到 0——过度 pad 得空内容盒而非负数域）。
    let inner_x = rect.x + node.pad[3] as i32;
    let inner_y = rect.y + node.pad[0] as i32;
    let inner_w = rect
        .w
        .saturating_sub(node.pad[1])
        .saturating_sub(node.pad[3]);
    let inner_h = rect
        .h
        .saturating_sub(node.pad[0])
        .saturating_sub(node.pad[2]);
    let inner_main: u64 = match node.dir {
        Dir::Row => inner_w,
        Dir::Column => inner_h,
    } as u64;

    // 走一遍：子链计数 + 固定和 + 权重和（权重 ≥1 闸）。
    let mut n: u64 = 0;
    let mut fixed_sum: u64 = 0;
    let mut weight_sum: u64 = 0;
    let mut cur = buf.first_child(id);
    while let Some(c) = cur {
        let Some(cn) = buf.node(c) else {
            return Err(LayoutError::BadId);
        };
        match cn.main {
            Main::Fixed(v) => fixed_sum += v as u64,
            Main::Fill(w) => {
                if w == 0 {
                    return Err(LayoutError::FillWeight { id: c });
                }
                weight_sum += w as u64;
            }
        }
        n += 1;
        cur = buf.next_sibling(c);
    }
    if n == 0 {
        return Ok(());
    }

    let gaps = (n - 1) * node.gap as u64;
    if fixed_sum + gaps > inner_main {
        return Err(LayoutError::Overflow { id });
    }
    let free = inner_main - gaps - fixed_sum;

    // 走二遍：Fill 基础份额之和 → 余数核算（余数全归首个 Fill 子）。
    let mut fill_base_sum: u64 = 0;
    let mut cur = buf.first_child(id);
    while let Some(c) = cur {
        if let Some(cn) = buf.node(c) {
            if let Main::Fill(w) = cn.main {
                fill_base_sum += free * w as u64 / weight_sum;
            }
        }
        cur = buf.next_sibling(c);
    }
    let leftover = free - fill_base_sum;

    // 走三遍：游标摊派 + 递归。
    let mut cursor = match node.dir {
        Dir::Row => inner_x,
        Dir::Column => inner_y,
    };
    let mut first_fill = true;
    let mut cur = buf.first_child(id);
    while let Some(c) = cur {
        let Some(cn) = buf.node(c) else {
            return Err(LayoutError::BadId);
        };
        let main_sz: u64 = match cn.main {
            Main::Fixed(v) => v as u64,
            Main::Fill(w) => {
                let base = free * w as u64 / weight_sum;
                if first_fill {
                    first_fill = false;
                    base + leftover
                } else {
                    base
                }
            }
        };
        let child_rect = match node.dir {
            Dir::Row => Rect {
                x: cursor,
                y: inner_y,
                w: main_sz as u32,
                h: inner_h,
            },
            Dir::Column => Rect {
                x: inner_x,
                y: cursor,
                w: inner_w,
                h: main_sz as u32,
            },
        };
        solve_node(buf, c, child_rect, out)?;
        cursor += main_sz as i32 + node.gap as i32;
        cur = buf.next_sibling(c);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{solve, Layout, LayoutError};
    use crate::elm::{Dir, Kind, Main, Node, ViewBuf};
    use crate::{DOCK_HEIGHT, PANEL_HEIGHT};
    use mirror::Rect;

    fn node(dir: Dir, pad: [u32; 4], gap: u32, main: Main) -> Node {
        Node {
            kind: Kind::Node,
            dir,
            pad,
            gap,
            main,
        }
    }

    fn r(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn column_fixed_then_fill_golden() {
        // 根纵排 pad 8 gap 8；三子 Fixed(48) / Fixed(72) / Fill(1)
        // 内容盒 (8,8,1904,1064)：free = 1064-16-120 = 928
        let mut buf = ViewBuf::<8>::new();
        let root = buf
            .push(node(Dir::Column, [8, 8, 8, 8], 8, Main::Fill(1)))
            .unwrap();
        let c1 = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fixed(48)))
            .unwrap();
        let c2 = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fixed(72)))
            .unwrap();
        let c3 = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fill(1)))
            .unwrap();
        buf.attach(root, c1).unwrap();
        buf.attach(root, c2).unwrap();
        buf.attach(root, c3).unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<8>::new();
        solve(&buf, (1920, 1080), &mut out).unwrap();
        assert_eq!(out.rect(root), Some(r(0, 0, 1920, 1080)));
        assert_eq!(out.rect(c1), Some(r(8, 8, 1904, 48)));
        assert_eq!(out.rect(c2), Some(r(8, 64, 1904, 72)));
        assert_eq!(out.rect(c3), Some(r(8, 144, 1904, 928)));
    }

    #[test]
    fn row_fill_split_and_remainder_rule() {
        // 权重 1:1、gap 8、视口宽 1904：free=1896 → 各 948
        let mut buf = ViewBuf::<8>::new();
        let root = buf.push(node(Dir::Row, [0; 4], 8, Main::Fill(1))).unwrap();
        let a = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let b = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        buf.attach(root, a).unwrap();
        buf.attach(root, b).unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<8>::new();
        solve(&buf, (1904, 100), &mut out).unwrap();
        assert_eq!(out.rect(a), Some(r(0, 0, 948, 100)));
        assert_eq!(out.rect(b), Some(r(956, 0, 948, 100)));

        // 余数纪律：视口宽 1905 → free=1897，base 948+948=1896，余 1 归首个 Fill
        let mut buf2 = ViewBuf::<8>::new();
        let root2 = buf2.push(node(Dir::Row, [0; 4], 8, Main::Fill(1))).unwrap();
        let a2 = buf2.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let b2 = buf2.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        buf2.attach(root2, a2).unwrap();
        buf2.attach(root2, b2).unwrap();
        buf2.set_root(root2).unwrap();
        let mut out2 = Layout::<8>::new();
        solve(&buf2, (1905, 100), &mut out2).unwrap();
        assert_eq!(out2.rect(a2), Some(r(0, 0, 949, 100)));
        assert_eq!(out2.rect(b2), Some(r(957, 0, 948, 100)));
    }

    #[test]
    fn desktop_skeleton_golden_panel_content_dock() {
        // 桌面骨架（t79 消费面）：根纵排 pad [48,0,72,0]——Panel/Dock 保留域；
        // 内容行横排两窗 Fill(1) gap 8。骨架常量与 loom 恒等面板同源。
        let mut buf = ViewBuf::<8>::new();
        let root = buf
            .push(node(
                Dir::Column,
                [PANEL_HEIGHT, 0, DOCK_HEIGHT, 0],
                0,
                Main::Fill(1),
            ))
            .unwrap();
        let content = buf.push(node(Dir::Row, [0; 4], 8, Main::Fill(1))).unwrap();
        let w1 = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let w2 = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        buf.attach(root, content).unwrap();
        buf.attach(content, w1).unwrap();
        buf.attach(content, w2).unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<8>::new();
        solve(&buf, (1920, 1080), &mut out).unwrap();
        assert_eq!(out.rect(root), Some(r(0, 0, 1920, 1080)));
        assert_eq!(out.rect(content), Some(r(0, 48, 1920, 960)));
        // free = 1920-8 = 1912 → 各 956
        assert_eq!(out.rect(w1), Some(r(0, 48, 956, 960)));
        assert_eq!(out.rect(w2), Some(r(964, 48, 956, 960)));
    }

    #[test]
    fn nested_row_in_column() {
        // 深度 2：纵排根 pad 0 gap 0，子1 Fixed(100)、子2 横排 Fill(1)（内含 Fill(1):Fill(3)）
        let mut buf = ViewBuf::<8>::new();
        let root = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fill(1)))
            .unwrap();
        let top = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fixed(100)))
            .unwrap();
        let row = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let l = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let rr = buf.push(node(Dir::Row, [0; 4], 0, Main::Fill(3))).unwrap();
        buf.attach(root, top).unwrap();
        buf.attach(root, row).unwrap();
        buf.attach(row, l).unwrap();
        buf.attach(row, rr).unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<8>::new();
        solve(&buf, (400, 500), &mut out).unwrap();
        assert_eq!(out.rect(top), Some(r(0, 0, 400, 100)));
        assert_eq!(out.rect(row), Some(r(0, 100, 400, 400)));
        // free=400：1:3 → 100/300
        assert_eq!(out.rect(l), Some(r(0, 100, 100, 400)));
        assert_eq!(out.rect(rr), Some(r(100, 100, 300, 400)));
    }

    #[test]
    fn off_grid_spacing_rejected() {
        // pad 10 违网格
        let mut buf = ViewBuf::<4>::new();
        let root = buf
            .push(node(Dir::Column, [0, 10, 0, 0], 0, Main::Fill(1)))
            .unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<4>::new();
        assert_eq!(
            solve(&buf, (100, 100), &mut out),
            Err(LayoutError::OffGrid {
                id: root,
                field: "pad",
                value: 10
            })
        );
        // gap 12 违网格
        let mut buf2 = ViewBuf::<4>::new();
        let root2 = buf2
            .push(node(Dir::Column, [0; 4], 12, Main::Fill(1)))
            .unwrap();
        buf2.set_root(root2).unwrap();
        assert_eq!(
            solve(&buf2, (100, 100), &mut out),
            Err(LayoutError::OffGrid {
                id: root2,
                field: "gap",
                value: 12
            })
        );
    }

    #[test]
    fn overflow_and_weight_gates() {
        // 固定和 2000 > 内容盒 100
        let mut buf = ViewBuf::<4>::new();
        let root = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fill(1)))
            .unwrap();
        let a = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fixed(1000)))
            .unwrap();
        let b = buf
            .push(node(Dir::Column, [0; 4], 0, Main::Fixed(1000)))
            .unwrap();
        buf.attach(root, a).unwrap();
        buf.attach(root, b).unwrap();
        buf.set_root(root).unwrap();
        let mut out = Layout::<4>::new();
        assert_eq!(
            solve(&buf, (100, 100), &mut out),
            Err(LayoutError::Overflow { id: root })
        );
        // Fill(0) 权重闸
        let mut buf2 = ViewBuf::<4>::new();
        let root2 = buf2.push(node(Dir::Row, [0; 4], 0, Main::Fill(1))).unwrap();
        let z = buf2.push(node(Dir::Row, [0; 4], 0, Main::Fill(0))).unwrap();
        buf2.attach(root2, z).unwrap();
        buf2.set_root(root2).unwrap();
        assert_eq!(
            solve(&buf2, (100, 100), &mut out),
            Err(LayoutError::FillWeight { id: z })
        );
    }

    #[test]
    fn viewport_and_root_gates() {
        let buf = ViewBuf::<4>::new();
        let mut out = Layout::<4>::new();
        assert_eq!(solve(&buf, (0, 100), &mut out), Err(LayoutError::Viewport));
        assert_eq!(solve(&buf, (100, 0), &mut out), Err(LayoutError::Viewport));
        assert_eq!(solve(&buf, (100, 100), &mut out), Err(LayoutError::NoRoot));
    }
}
