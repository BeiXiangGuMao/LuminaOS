//! 光栅化器 —— 图标注册表与同源缩放渲染（渲染库本体，M30-G1）。
//!
//! 依据《美术设计指南》第五章同源缩放纪律的渲染面兑现：图标以 24px 源
//! 网格的几何基元声明（[`Prim`]），**非同源重绘禁令**在工程面兑现为
//! 「基元坐标只能经 [`crate::map_point`] 变换到目标画布」——任何档位
//! 的像素都是同一源几何的确定性投影，不存在第二份图形事实。
//!
//! 渲染语义：
//! - 描边宽度 = 档位倍率（×1/×2/×4 → 1/2/4 px 粗细），线宽随源缩放；
//! - 线段走 Bresenham 整数光栅化，圆走中点圆（八分对称），矩形走四边
//!   线段轮廓；
//! - 像素写入有界（越界裁剪不 panic——图标在画布边缘按光栅器惯例
//!   裁剪；fail-visible 闸在档位校验面 [`crate::scale_factor`]）；
//! - 零堆、`forbid(unsafe_code)`，目标画布由调用方提供
//!   （`&mut [u32]` + stride，内核 static 域可用）。

/// 几何基元（24 源网格坐标，f32 逻辑像素）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Prim {
    /// 线段（Bresenham）。
    Line {
        /// 起 x。
        x1: f32,
        /// 起 y。
        y1: f32,
        /// 终 x。
        x2: f32,
        /// 终 y。
        y2: f32,
    },
    /// 矩形轮廓。
    Rect {
        /// 左上 x。
        x: f32,
        /// 左上 y。
        y: f32,
        /// 宽。
        w: f32,
        /// 高。
        h: f32,
    },
    /// 圆轮廓（中点圆）。
    Circle {
        /// 圆心 x。
        cx: f32,
        /// 圆心 y。
        cy: f32,
        /// 半径。
        r: f32,
    },
}

/// 图标定义：24 源网格基元列表（同源缩放的唯一图形事实）。
#[derive(Debug)]
pub struct IconDef {
    /// 图标名（注册键）。
    pub name: &'static str,
    /// 基元列表。
    pub prims: &'static [Prim],
}

/// 内置图标注册表（24 源网格声明式图标集，v0 四枚）。
pub const ICONS: &[IconDef] = &[
    // close：对角叉
    IconDef {
        name: "close",
        prims: &[
            Prim::Line {
                x1: 6.0,
                y1: 6.0,
                x2: 18.0,
                y2: 18.0,
            },
            Prim::Line {
                x1: 18.0,
                y1: 6.0,
                x2: 6.0,
                y2: 18.0,
            },
        ],
    },
    // terminal：外框 + 提示符「>_」
    IconDef {
        name: "terminal",
        prims: &[
            Prim::Rect {
                x: 3.0,
                y: 4.0,
                w: 18.0,
                h: 16.0,
            },
            Prim::Line {
                x1: 7.0,
                y1: 9.0,
                x2: 11.0,
                y2: 13.0,
            },
            Prim::Line {
                x1: 11.0,
                y1: 13.0,
                x2: 16.0,
                y2: 13.0,
            },
        ],
    },
    // folder：袋身 + 斜肩标签
    IconDef {
        name: "folder",
        prims: &[
            Prim::Rect {
                x: 3.0,
                y: 6.0,
                w: 18.0,
                h: 13.0,
            },
            Prim::Line {
                x1: 3.0,
                y1: 6.0,
                x2: 6.0,
                y2: 3.0,
            },
            Prim::Line {
                x1: 6.0,
                y1: 3.0,
                x2: 11.0,
                y2: 3.0,
            },
        ],
    },
    // record：双同心圆
    IconDef {
        name: "record",
        prims: &[
            Prim::Circle {
                cx: 12.0,
                cy: 12.0,
                r: 7.0,
            },
            Prim::Circle {
                cx: 12.0,
                cy: 12.0,
                r: 3.0,
            },
        ],
    },
];

/// 查注册表。
pub fn find(name: &str) -> Option<&'static IconDef> {
    ICONS.iter().find(|i| i.name == name)
}

/// 画布光栅上下文（行距/描边宽/颜色绑定——收敛参数面）。
struct Canvas<'a> {
    buf: &'a mut [u32],
    stride: usize,
    sw: usize,
    color: u32,
}

impl Canvas<'_> {
    /// 有界像素写入（越界静默裁剪——光栅器惯例，不 panic）。
    fn px(&mut self, x: i32, y: i32) {
        if x < 0 || y < 0 {
            return;
        }
        let (ux, uy) = (x as usize, y as usize);
        if ux >= self.stride {
            return;
        }
        let Some(idx) = uy.checked_mul(self.stride).and_then(|v| v.checked_add(ux)) else {
            return;
        };
        if idx < self.buf.len() {
            self.buf[idx] = self.color;
        }
    }

    /// 描边块写入（sw×sw，随倍率加粗）。
    fn block(&mut self, x: i32, y: i32) {
        for dy in 0..self.sw {
            for dx in 0..self.sw {
                self.px(x + dx as i32, y + dy as i32);
            }
        }
    }

    /// Bresenham 线段（含描边块）。
    fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut x = x0;
        let mut y = y0;
        let mut err = dx + dy;
        loop {
            self.block(x, y);
            if x == x1 && y == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// 中点圆轮廓（八分对称，含描边块）。
    fn circle(&mut self, cx: i32, cy: i32, r: i32) {
        let mut x = r;
        let mut y = 0i32;
        let mut err = 1 - r;
        while x >= y {
            for (px, py) in [
                (cx + x, cy + y),
                (cx + y, cy + x),
                (cx - y, cy + x),
                (cx - x, cy + y),
                (cx - x, cy - y),
                (cx - y, cy - x),
                (cx + y, cy - x),
                (cx + x, cy - y),
            ] {
                self.block(px, py);
            }
            y += 1;
            if err < 0 {
                err += 2 * y + 1;
            } else {
                x -= 1;
                err += 2 * (y - x) + 1;
            }
        }
    }
}

/// 渲染图标到画布（同源缩放唯一合法路径）。
///
/// - `size` 必须 ∈ {24,48,96}（[`crate::scale_factor`] 闸）；
/// - 坐标经 [`crate::map_point`] 变换，标量域（宽高/半径）乘同源倍率；
/// - `stride` 为行距（画布宽），越界像素裁剪；
/// - `color` 为 ABGR packed u32（直写面，色彩合成不归本 crate）。
pub fn render(
    icon: &IconDef,
    size: u32,
    color: u32,
    buf: &mut [u32],
    stride: usize,
) -> Result<(), crate::GlyphError> {
    let f = crate::scale_factor(size)? as f32;
    let sw = f as usize;
    let mut c = Canvas {
        buf,
        stride,
        sw,
        color,
    };
    for prim in icon.prims {
        match *prim {
            Prim::Line { x1, y1, x2, y2 } => {
                let (ax, ay) = crate::map_point(x1, y1, size)?;
                let (bx, by) = crate::map_point(x2, y2, size)?;
                c.line(ax as i32, ay as i32, bx as i32, by as i32);
            }
            Prim::Rect { x, y, w, h } => {
                let (ax, ay) = crate::map_point(x, y, size)?;
                let (bx, by) = crate::map_point(x + w, y + h, size)?;
                c.line(ax as i32, ay as i32, bx as i32, ay as i32);
                c.line(bx as i32, ay as i32, bx as i32, by as i32);
                c.line(bx as i32, by as i32, ax as i32, by as i32);
                c.line(ax as i32, by as i32, ax as i32, ay as i32);
            }
            Prim::Circle { cx, cy, r } => {
                let (ccx, ccy) = crate::map_point(cx, cy, size)?;
                // no_std 无 f32::round：正数域 +0.5 截断等价四舍五入
                let rad = (r * f + 0.5) as i32;
                c.circle(ccx as i32, ccy as i32, rad);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::{find, render, IconDef, Prim, ICONS};
    use crate::GlyphError;
    use std::vec::Vec;

    fn canvas(n: usize) -> (Vec<u32>, usize) {
        (std::vec![0u32; n * n], n)
    }

    const INK: u32 = 0xFFFF_FFFF;

    #[test]
    fn registry_has_unique_names() {
        assert!(ICONS.len() >= 4);
        for (i, a) in ICONS.iter().enumerate() {
            assert!(find(a.name).is_some(), "{} 可查", a.name);
            for b in &ICONS[i + 1..] {
                assert_ne!(a.name, b.name, "注册名唯一");
            }
        }
        assert!(find("no-such-icon").is_none());
    }

    #[test]
    fn close_icon_24_pixels_on_diagonals() {
        let icon = find("close").unwrap();
        let (mut buf, stride) = canvas(24);
        render(icon, 24, INK, &mut buf, stride).unwrap();
        // 四端点 + 中心全亮（Bresenham 对角线含两端）
        for (x, y) in [(6, 6), (18, 18), (18, 6), (6, 18), (12, 12)] {
            assert_eq!(buf[y * 24 + x], INK, "({x},{y}) 应亮");
        }
        // 叉外角未触
        assert_eq!(buf[0], 0);
        assert_eq!(buf[23], 0);
    }

    #[test]
    fn same_source_anchor_points_lit_at_all_sizes() {
        // 同源缩放不变式（诚实面）：源几何上的采样点在每一档位的目标画布
        // 上必亮（几何线投影成立；描边块不构成逐像素折半不变式——48 档
        // sw=2 的块状描边是源对角线的合法投影而非其像素倍增）
        let icon = find("close").unwrap();
        for size in crate::SIZES {
            let mut buf = std::vec![0u32; (size * size) as usize];
            render(icon, size, INK, &mut buf, size as usize).unwrap();
            for t in 0..=12u32 {
                let (x, y) = crate::map_point(6.0 + t as f32, 6.0 + t as f32, size).unwrap();
                let (ux, uy) = (x as u32, y as u32);
                assert_eq!(buf[(uy * size + ux) as usize], INK, "size={size} 源点({t})");
            }
        }
    }

    #[test]
    fn terminal_rect_outline_center_hollow() {
        let icon = find("terminal").unwrap();
        let (mut buf, stride) = canvas(24);
        render(icon, 24, INK, &mut buf, stride).unwrap();
        // 框角亮：左上 (3,4) 与右下 (21,20)
        assert_eq!(buf[4 * 24 + 3], INK);
        assert_eq!(buf[20 * 24 + 21], INK);
        // 框内中心空心（提示符线不经过）
        assert_eq!(buf[12 * 24 + 12], 0);
        // 提示符下划线亮
        assert_eq!(buf[13 * 24 + 14], INK);
    }

    #[test]
    fn illegal_size_rejected_before_any_pixel() {
        let icon = find("close").unwrap();
        let (mut buf, stride) = canvas(24);
        assert_eq!(
            render(icon, 32, INK, &mut buf, stride),
            Err(GlyphError::IllegalSize)
        );
        assert!(buf.iter().all(|&p| p == 0), "拒绝时零像素写入");
    }

    #[test]
    fn edge_clip_never_panics() {
        // 圆心贴角、半径溢出画布——越界象限静默裁剪不 panic
        let edge = IconDef {
            name: "edge-case",
            prims: &[Prim::Circle {
                cx: 2.0,
                cy: 2.0,
                r: 6.0,
            }],
        };
        let (mut buf, stride) = canvas(24);
        assert!(render(&edge, 24, INK, &mut buf, stride).is_ok());
        // 圆右极点 (8,2) 在场
        assert_eq!(buf[2 * 24 + 8], INK);
        // 角 (0,0) 在圆内（轮廓不填充）且不触——裁剪与空心双证据
        assert_eq!(buf[0], 0);
        // 远角 (23,23) 在圆可达域外未触
        assert_eq!(buf[23 * 24 + 23], 0);
    }

    #[test]
    fn record_concentric_circles_lit() {
        let icon = find("record").unwrap();
        let (mut buf, stride) = canvas(24);
        render(icon, 24, INK, &mut buf, stride).unwrap();
        // 外圆顶点 (12,5)、内圆顶点 (12,9) 亮；双圆之间空心 (12,7)
        assert_eq!(buf[5 * 24 + 12], INK);
        assert_eq!(buf[9 * 24 + 12], INK);
        assert_eq!(buf[7 * 24 + 12], 0);
        // 圆心空心（轮廓非填充）
        assert_eq!(buf[12 * 24 + 12], 0);
    }
}
