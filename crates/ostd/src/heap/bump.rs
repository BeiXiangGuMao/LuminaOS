//! 区域式（bump）分配器。
//!
//! 原 `harbor::HarborBump`（ADR-0003 执行步，M29-N1 迁入）：GlobalAlloc
//! 契约 + 统计 + 启动期 rebind。dealloc 只做统计回收，不做单块归还
//! （区域式策略的预期行为，见「非目标」）。

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

use super::AllocStats;
use crate::sync::SpinLock;

struct BumpInner {
    base: *mut u8,
    size: usize,
    cursor: usize,
    stats: AllocStats,
}

/// 区域式分配器。线程安全（内部为 OSTD 自旋锁）；可作为 `#[global_allocator]`。
pub struct Bump {
    inner: SpinLock<UnsafeCell<BumpInner>>,
}

// SAFETY: 前置条件 —— base 指向调用方保证的一块 `size` 字节、独占、对齐 ≥ 8 的内存区域。
// SAFETY: 不变式 —— cursor 永不越过 size；全部指针运算在锁内进行且先做溢出检查。
// SAFETY: 并发 —— inner 为 SpinLock，互斥访问 inner；Bump 本身不缓存指针。
// SAFETY: 违反后果 —— 若 region 生命期短于分配器或调用方伪造 base/size，将产生悬垂指针。
unsafe impl Sync for Bump {}
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 持锁期间独占 inner；layout 已由调用方保证非零。
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        let align = layout.align().max(8);
        // 以绝对地址求对齐：base + cursor 向上取整到 align，再折回偏移量。
        // （仅当 base 恰为 align 对齐时，对 cursor 取整才等价——不能假设。）
        let base_addr = h.base as usize;
        let Some(aligned_addr) = base_addr
            .checked_add(h.cursor)
            .map(|cur| cur.next_multiple_of(align))
        else {
            return ptr::null_mut();
        };
        let Some(start) = aligned_addr.checked_sub(base_addr) else {
            return ptr::null_mut();
        };
        let end = match start.checked_add(layout.size()) {
            Some(e) => e,
            None => return ptr::null_mut(),
        };
        if end > h.size {
            return ptr::null_mut();
        }
        h.cursor = end;
        h.stats.allocs += 1;
        h.stats.bytes_in_use = end;
        if h.stats.bytes_in_use > h.stats.peak_bytes {
            h.stats.peak_bytes = h.stats.bytes_in_use;
        }
        // SAFETY: start+size ≤ h.size（上方检查），指针落在调用方提供的区域之内。
        unsafe { h.base.add(start) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // SAFETY: 仅触碰自有统计字段；bump 策略下不做单块回收（见模块文档「非目标」）。
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        h.stats.deallocs += 1;
    }
}

impl Bump {
    /// 用一块外部提供的区域构造分配器（空测试惯用法见 `new_unbacked`）。
    pub const fn new(base: *mut u8, size: usize) -> Self {
        Self {
            inner: SpinLock::new(UnsafeCell::new(BumpInner {
                base,
                size,
                cursor: 0,
                stats: AllocStats {
                    allocs: 0,
                    deallocs: 0,
                    bytes_in_use: 0,
                    peak_bytes: 0,
                },
            })),
        }
    }

    /// 无后备区域构造：内核启动期惯用法——先创建全局分配器，
    /// 再在 `kmain` 早期用 [`Bump::rebind`] 绑定后备区域。
    pub const fn new_unbacked() -> Self {
        Self::new(core::ptr::null_mut(), 0)
    }

    /// 启动期绑定后备区域：cursor 清零、统计归零。
    ///
    /// 返回 `false` 表示拒绝重绑：分配器已有在用分配（cursor ≠ 0），
    /// 此时换区域会令既有指针悬垂；调用方 MUST 仅在启动期、首次分配
    /// 之前调用一次。
    ///
    /// # SAFETY（调用方义务）
    /// `base` 指向调用方保证的 `size` 字节、独占、对齐 ≥ 8 的内存区域，
    /// 其生命期必须覆盖分配器自本调用起的全部使用期（静态区域天然满足）。
    pub fn rebind(&self, base: *mut u8, size: usize) -> bool {
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        if h.cursor != 0 {
            return false;
        }
        h.base = base;
        h.size = size;
        h.cursor = 0;
        h.stats = AllocStats::default();
        true
    }

    /// 当前统计快照。
    pub fn stats(&self) -> AllocStats {
        // SAFETY: 仅在锁内读取。
        let g = self.inner.lock();
        unsafe { (*g.get()).stats }
    }
}

#[cfg(test)]
mod tests {
    use super::{AllocStats, Bump};
    use core::alloc::{GlobalAlloc, Layout};

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    const ARENA: usize = 64 * 1024;
    // SAFETY: GlobalAlloc 契约要求基址 ≥ 8 对齐；u8 数组本身只有 1 对齐，
    // 故用 #[repr(align(16))] 包装后取内部数组地址。
    #[repr(align(16))]
    struct Aligned([u8; ARENA]);
    static ARENA_BYTES: Aligned = Aligned([0; ARENA]);

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn make() -> Bump {
        Bump::new(ARENA_BYTES.0.as_ptr() as *mut u8, ARENA)
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn honors_alignment() {
        let h = make();
        for align in [1usize, 2, 4, 8, 16, 64, 256] {
            let p = unsafe { h.alloc(Layout::from_size_align(17, align).unwrap()) };
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "ptr not aligned to {align}");
        }
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn returns_null_when_exhausted() {
        let h = make();
        let big = Layout::from_size_align(ARENA + 1, 8).unwrap();
        assert!(unsafe { h.alloc(big) }.is_null());
        // 先取 ARENA-8 字节，再用 8 字节恰好填满区域
        let exact = Layout::from_size_align(ARENA - 8, 8).unwrap();
        assert!(!unsafe { h.alloc(exact) }.is_null());
        let fill = Layout::from_size_align(8, 8).unwrap();
        assert!(!unsafe { h.alloc(fill) }.is_null());
        assert!(unsafe { h.alloc(Layout::from_size_align(1, 1).unwrap()) }.is_null());
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn stats_track_allocs_and_peak() {
        let h = make();
        let a = unsafe { h.alloc(Layout::from_size_align(100, 8).unwrap()) };
        assert!(!a.is_null());
        let s1 = h.stats();
        assert_eq!(s1.allocs, 1);
        assert_eq!(s1.bytes_in_use, 100); // 起始对齐内含，分配本体 100 字节
        unsafe { h.dealloc(a, Layout::from_size_align(100, 8).unwrap()) };
        let s2 = h.stats();
        assert_eq!(s2.deallocs, 1);
        assert_eq!(
            s2,
            AllocStats {
                allocs: 1,
                deallocs: 1,
                bytes_in_use: 100,
                peak_bytes: 100
            }
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn rebind_after_unbacked_and_rejects_when_busy() {
        let h = Bump::new_unbacked();
        // 未绑定区域时分配失败（返回 null），不 panic。
        let p = unsafe { h.alloc(Layout::from_size_align(8, 8).unwrap()) };
        assert!(p.is_null());
        // 绑定后可正常分配。
        assert!(h.rebind(ARENA_BYTES.0.as_ptr() as *mut u8, ARENA));
        let p = unsafe { h.alloc(Layout::from_size_align(8, 8).unwrap()) };
        assert!(!p.is_null());
        // 已有在用分配（cursor ≠ 0）时拒绝重绑，避免悬垂指针。
        assert!(!h.rebind(ARENA_BYTES.0.as_ptr() as *mut u8, ARENA));
    }
}
