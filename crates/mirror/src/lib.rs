//! Mirror 映境 —— 合成器的表面表与损伤跟踪。
//!
//! 依据《指标与规范手册》第 10 章：Mirror 按帧预算执行三级玻璃材质的模糊与合成，
//! 损伤（damage）跟踪是把合成开销压进预算的第一手段——只重绘变化的区域。
//! 本 crate 提供矩形几何与损伤聚合的纯算法面；Vulkan 互操作边界不在本 crate。
//!
//! Surface 表在服务进程内使用 Crystal 的代际槽表实现（句柄外泄安全），此处
//! 提供几何原语。
//!
//! M23-B 起 no_std + alloc（对照 Crystal 惯例）：内核首帧合成面直接依赖本
//! crate 的几何与损伤跟踪；宿主测试经 test 模块 `extern crate std` 照常运行。
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

/// 轴对齐矩形（逻辑像素；y 向下为正）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// 左上角 x。
    pub x: i32,
    /// 左上角 y。
    pub y: i32,
    /// 宽。
    pub w: u32,
    /// 高。
    pub h: u32,
}

impl Rect {
    /// 与另一矩形的交集；不相交返回 None。
    pub fn intersection(&self, other: &Rect) -> Option<Rect> {
        let x1 = self.x.max(other.x);
        let y1 = self.y.max(other.y);
        let x2 = (self.x + self.w as i32).min(other.x + other.w as i32);
        let y2 = (self.y + self.h as i32).min(other.y + other.h as i32);
        if x2 > x1 && y2 > y1 {
            Some(Rect {
                x: x1,
                y: y1,
                w: (x2 - x1) as u32,
                h: (y2 - y1) as u32,
            })
        } else {
            None
        }
    }

    /// 面积（平方像素）。
    pub fn area(&self) -> u64 {
        self.w as u64 * self.h as u64
    }

    /// 是否包含点。
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.x + self.w as i32 && py < self.y + self.h as i32
    }
}

/// 损伤跟踪器：聚合本帧全部脏区并给出包围盒。
#[derive(Debug, Default)]
pub struct DamageTracker {
    rects: Vec<Rect>,
}

impl DamageTracker {
    /// 记录一块脏区。
    pub fn mark(&mut self, r: Rect) {
        self.rects.push(r);
    }

    /// 本帧脏区列表。
    pub fn rects(&self) -> &[Rect] {
        &self.rects
    }

    /// 包围盒；无损伤返回 None（本帧可跳过合成——预算面最重要的快速通道）。
    pub fn bounding_box(&self) -> Option<Rect> {
        // 生产路径零 expect：以首元素 + 折叠展开，空列表自然返回 None。
        let mut rects = self.rects.iter();
        let first = *rects.next()?;
        let mut x1 = first.x;
        let mut y1 = first.y;
        let mut x2 = first.x + first.w as i32;
        let mut y2 = first.y + first.h as i32;
        for r in rects {
            x1 = x1.min(r.x);
            y1 = y1.min(r.y);
            x2 = x2.max(r.x + r.w as i32);
            y2 = y2.max(r.y + r.h as i32);
        }
        Some(Rect {
            x: x1,
            y: y1,
            w: (x2 - x1) as u32,
            h: (y2 - y1) as u32,
        })
    }

    /// 清空跟踪（帧提交后调用）。
    pub fn clear(&mut self) {
        self.rects.clear();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::{DamageTracker, Rect};

    #[test]
    fn intersection_and_contains() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let b = Rect {
            x: 50,
            y: 50,
            w: 100,
            h: 100,
        };
        let c = a.intersection(&b).expect("overlap");
        assert_eq!((c.x, c.y, c.w, c.h), (50, 50, 50, 50));
        assert_eq!(c.area(), 2500);

        let d = Rect {
            x: 200,
            y: 0,
            w: 10,
            h: 10,
        };
        assert!(a.intersection(&d).is_none());
        assert!(a.contains(0, 0));
        assert!(!a.contains(100, 50));
    }

    #[test]
    fn damage_bbox_and_skip_frame() {
        let mut t = DamageTracker::default();
        assert!(t.bounding_box().is_none(), "no damage -> skip compose");
        t.mark(Rect {
            x: 10,
            y: 10,
            w: 20,
            h: 20,
        });
        t.mark(Rect {
            x: 60,
            y: 40,
            w: 30,
            h: 10,
        });
        let bb = t.bounding_box().expect("bbox");
        assert_eq!((bb.x, bb.y, bb.w, bb.h), (10, 10, 80, 40));
        t.clear();
        assert!(t.bounding_box().is_none());
    }
}
