//! 物理帧分配器：区间裁剪 + 顺序分配 + LIFO 空闲表。
//!
//! 设计（承接 SPEC 第 2/17 章「OSTD 提供物理内存基元」）：
//! 1. 构造时以「可用区域 − 保留区域」做区间裁剪，得到干净的帧段（run）；
//!    裁剪是纯逻辑函数 [`subtract_ranges`]，宿主可测。
//! 2. 分配优先弹 LIFO 空闲表（复用刚释放的帧，局部性好），否则沿帧段
//!    顺序推进（bump）。释放压回空闲表。
//! 3. 统计完备（total/allocs/deallocs/free_list/held），供门禁取证
//!    （Harbor 统计族同款纪律）。
//!
//! 全模块零 unsafe：帧是纯数字物理地址；把帧当作内存访问是调用方的事
//! （经由 [`crate::hw::phys`] 的恒等映射收口）。

/// 帧大小：4 KiB。
pub const FRAME_SIZE: u64 = 4096;

/// M3 恒等映射上限：帧分配器只服务低于 1 GiB 的物理内存。
pub const IDENT_MAP_LIMIT: u64 = 0x4000_0000;

/// 一段物理内存区间（字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// 起始物理地址。
    pub start: u64,
    /// 长度（字节）。
    pub len: u64,
}

impl Region {
    /// 区间末尾（不含）。
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// 帧分配器构造错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// 可用与保留区域完全重叠，无帧可分配。
    NoFramesAvailable,
}

/// 分配统计快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameStats {
    /// 可分配帧总数（裁剪后）。
    pub total: u64,
    /// 累计成功分配次数。
    pub allocs: u64,
    /// 累计释放次数。
    pub deallocs: u64,
    /// 当前在空闲表中的帧数。
    pub free_list: u64,
    /// 当前被调用方持有的帧数（= allocs − deallocs）。
    pub held: u64,
}

/// 单个帧段（run）：顺序分配游标。
struct Run {
    next: u64,
    end: u64,
}

/// 物理帧分配器。
///
/// 线程安全：内部为 OSTD 自旋锁；`alloc`/`dealloc` 可在任意上下文调用
/// （不得在中断处理中调用阻塞路径——M3 调度点固定，无此风险）。
pub struct FrameAllocator {
    inner: crate::sync::SpinLock<Inner>,
}

struct Inner {
    runs: alloc::vec::Vec<Run>,
    run_pos: usize,
    free: alloc::vec::Vec<u64>,
    stats: FrameStats,
}

impl FrameAllocator {
    /// 以「可用区域 − 保留区域」构造分配器。
    ///
    /// 区域裁剪规则：
    /// - 高于 [`IDENT_MAP_LIMIT`] 的部分直接截去（M3 恒等映射边界）；
    /// - 帧段起点向上对齐 4 KiB、终点向下对齐 4 KiB；
    /// - 与任何保留区间重叠的帧永不下发。
    pub fn new(usable: &[Region], reserved: &[Region]) -> Result<Self, FrameError> {
        let mut runs = alloc::vec::Vec::new();
        let mut total: u64 = 0;
        for r in subtract_ranges(usable, reserved) {
            let start = r.start.next_multiple_of(FRAME_SIZE);
            let end = r.end() - (r.end() % FRAME_SIZE);
            if start < end && start < IDENT_MAP_LIMIT {
                let end = end.min(IDENT_MAP_LIMIT);
                total += (end - start) / FRAME_SIZE;
                runs.push(Run { next: start, end });
            }
        }
        if total == 0 {
            return Err(FrameError::NoFramesAvailable);
        }
        Ok(Self {
            inner: crate::sync::SpinLock::new(Inner {
                runs,
                run_pos: 0,
                free: alloc::vec::Vec::new(),
                stats: FrameStats {
                    total,
                    ..FrameStats::default()
                },
            }),
        })
    }

    /// 分配一个 4 KiB 物理帧；耗尽返回 `None`。
    pub fn alloc(&self) -> Option<u64> {
        let mut g = self.inner.lock();
        let h = &mut *g;
        let frame = if let Some(f) = h.free.pop() {
            f
        } else {
            // 沿帧段推进；跳过已耗尽的段
            loop {
                if h.run_pos >= h.runs.len() {
                    return None;
                }
                let run = &mut h.runs[h.run_pos];
                if run.next + FRAME_SIZE <= run.end {
                    let f = run.next;
                    run.next += FRAME_SIZE;
                    break f;
                }
                h.run_pos += 1;
            }
        };
        h.stats.allocs += 1;
        h.stats.held = h.stats.allocs - h.stats.deallocs;
        Some(frame)
    }

    /// 归还一个此前分配的帧（LIFO 空闲表）。
    pub fn dealloc(&self, frame: u64) {
        debug_assert_eq!(frame % FRAME_SIZE, 0, "frame must be 4 KiB aligned");
        let mut g = self.inner.lock();
        let h = &mut *g;
        h.free.push(frame);
        h.stats.deallocs += 1;
        h.stats.free_list = h.free.len() as u64;
        h.stats.held = h.stats.allocs - h.stats.deallocs;
    }

    /// 统计快照。
    pub fn stats(&self) -> FrameStats {
        // free_list 字段在 alloc（弹出）路径之外还要反映弹空后的长度
        let mut g = self.inner.lock();
        let h = &mut *g;
        h.stats.free_list = h.free.len() as u64;
        h.stats
    }
}

/// 区间减法：`base` 中挖去 `cut` 覆盖的部分，返回剩余区间列表。
///
/// 经典扫描线：按起点排序两端事件，线性合并。输出保持有序且两两不交。
pub fn subtract_ranges(base: &[Region], cut: &[Region]) -> alloc::vec::Vec<Region> {
    let mut cuts: alloc::vec::Vec<(u64, u64)> = cut
        .iter()
        .map(|r| (r.start, r.end()))
        .filter(|(s, e)| s < e)
        .collect();
    cuts.sort_unstable();
    let mut out = alloc::vec::Vec::new();
    for r in base {
        let (mut cur, end) = (r.start, r.end());
        if cur >= end {
            continue;
        }
        for (cs, ce) in &cuts {
            if *ce <= cur || *cs >= end {
                continue;
            }
            if *cs > cur {
                out.push(Region {
                    start: cur,
                    len: *cs - cur,
                });
            }
            cur = cur.max(*ce);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            out.push(Region {
                start: cur,
                len: end - cur,
            });
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{subtract_ranges, FrameAllocator, FrameError, Region, FRAME_SIZE};

    fn r(start: u64, len: u64) -> Region {
        Region { start, len }
    }

    #[test]
    fn subtract_removes_and_keeps_order() {
        // 可用 [0, 0x10000)，挖去中间 [0x3000, 0x5000) 与头部 [0, 0x1000)
        let got = subtract_ranges(&[r(0, 0x1_0000)], &[r(0, 0x1000), r(0x3000, 0x2000)]);
        assert_eq!(got, alloc::vec![r(0x1000, 0x2000), r(0x5000, 0xB000)]);
    }

    #[test]
    fn subtract_handles_multiple_bases_and_empties() {
        let got = subtract_ranges(&[r(0x1000, 0x1000), r(0, 0)], &[r(0x1800, 0x400)]);
        assert_eq!(got, alloc::vec![r(0x1000, 0x800), r(0x1C00, 0x400)]);
    }

    #[test]
    fn alloc_is_aligned_and_sequential() {
        let fa = FrameAllocator::new(&[r(0x1000, 0x3000)], &[]).unwrap();
        let a = fa.alloc().unwrap();
        let b = fa.alloc().unwrap();
        let c = fa.alloc().unwrap();
        assert_eq!((a, b, c), (0x1000, 0x2000, 0x3000));
        assert_eq!(a % FRAME_SIZE, 0);
        assert!(fa.alloc().is_none());
        let s = fa.stats();
        assert_eq!(
            s,
            super::FrameStats {
                total: 3,
                allocs: 3, // 失败分配不计入成功次数
                deallocs: 0,
                free_list: 0,
                held: 3,
            }
        );
    }

    #[test]
    fn lifo_reuse_returns_last_freed() {
        let fa = FrameAllocator::new(&[r(0x2000, 0x4000)], &[]).unwrap();
        let a = fa.alloc().unwrap();
        let b = fa.alloc().unwrap();
        fa.dealloc(a);
        fa.dealloc(b);
        // LIFO：后释放的 b 先回来
        assert_eq!(fa.alloc().unwrap(), b);
        assert_eq!(fa.alloc().unwrap(), a);
        let s = fa.stats();
        assert_eq!(s.free_list, 0);
        assert_eq!(s.held, 2);
    }

    #[test]
    fn reservation_carves_kernel_hole() {
        // 可用 [0x100000, 0x200000)，内核占 [0x110000, 0x180000)
        let fa =
            FrameAllocator::new(&[r(0x10_0000, 0x10_0000)], &[r(0x11_0000, 0x7_0000)]).unwrap();
        let mut seen = alloc::vec::Vec::new();
        while let Some(f) = fa.alloc() {
            seen.push(f);
        }
        // 起点向上对齐后从 0x100000 起；洞两侧合计 0x100000/0x1000 + 0x80000/0x1000
        assert_eq!(seen.len(), 0x10 + 0x80);
        assert_eq!(seen[0], 0x10_0000);
        assert_eq!(seen[0x10 - 1], 0x10_F000);
        assert_eq!(seen[0x10], 0x18_0000);
        for f in &seen {
            // 任何帧都不得落入保留洞
            assert!(*f < 0x11_0000 || *f >= 0x18_0000);
        }
    }

    #[test]
    fn clamps_above_identity_limit_and_rejects_empty() {
        // 全部高于 1 GiB → 无帧
        assert!(matches!(
            FrameAllocator::new(&[r(0x1_0000_0000, 0x1000)], &[]),
            Err(FrameError::NoFramesAvailable)
        ));
        // 跨界区域被截到 1 GiB
        let fa = FrameAllocator::new(&[r(0x3FFF_F000, 0x2000)], &[]).unwrap();
        let f = fa.alloc().unwrap();
        assert_eq!(f, 0x3FFF_F000);
        assert!(fa.alloc().is_none());
    }

    #[test]
    fn exhaust_then_free_restores_full_capacity() {
        let fa = FrameAllocator::new(&[r(0x1000, 0x10_000)], &[]).unwrap();
        let total = fa.stats().total;
        // [0x1000, 0x11000) → 16 帧
        assert_eq!(total, 16);
        let mut all = alloc::vec::Vec::new();
        while let Some(f) = fa.alloc() {
            all.push(f);
        }
        assert_eq!(all.len() as u64, total);
        assert_eq!(fa.stats().held, total);
        for f in &all {
            fa.dealloc(*f);
        }
        let s = fa.stats();
        assert_eq!(s.free_list, total);
        assert_eq!(s.held, 0);
        assert_eq!(s.deallocs, total);
        // 复用后仍可全量再分配
        let mut again = 0;
        while fa.alloc().is_some() {
            again += 1;
        }
        assert_eq!(again as u64, total);
    }
}
