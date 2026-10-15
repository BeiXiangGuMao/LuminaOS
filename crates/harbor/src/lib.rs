//! Harbor 港湾 —— 分配器与 libc 边界。
//!
//! 承接《指标与规范手册》第 5 章（Harbor）的指标族 H-P01…H-P07：分配热路径
//! 预算、碎片率上限与统计完备性。本 crate 提供：
//!
//! - [`HarborBump`]：区域式（bump）分配器，作为内核启动期与测试环境的
//!   `GlobalAlloc` 实现； dealloc 只做统计回收，属预期行为并有文档。
//! - [`HarborFreeList`]：first-fit + 地址序合并 + bump 晋升的通用
//!   free-list 分配器（M21-③：SPEC 5 章承诺的单块回收复用面），
//!   内核堆现行挂载实现。
//! - [`AllocStats`]：分配统计（次数、在用字节、峰值），供基准与门禁取证；
//!   free-list 扩展取证经 [`HarborFreeList::free_stamps`]。
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use ostd::sync::SpinLock;

/// 分配统计快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocStats {
    /// 成功分配次数。
    pub allocs: u64,
    /// 成功释放次数（bump 区域整体回收时按区域计一次）。
    pub deallocs: u64,
    /// 当前在用字节（含对齐填充）。
    pub bytes_in_use: usize,
    /// 历史峰值在用字节。
    pub peak_bytes: usize,
}

struct HarborInner {
    base: *mut u8,
    size: usize,
    cursor: usize,
    stats: AllocStats,
}

/// 区域式分配器。线程安全（内部为 OSTD 自旋锁）；可作为 `#[global_allocator]`。
pub struct HarborBump {
    inner: SpinLock<UnsafeCell<HarborInner>>,
}

// SAFETY: 前置条件 —— base 指向调用方保证的一块 `size` 字节、独占、对齐 ≥ 8 的内存区域。
// SAFETY: 不变式 —— cursor 永不越过 size；全部指针运算在锁内进行且先做溢出检查。
// SAFETY: 并发 —— inner 为 SpinLock，互斥访问 inner；HarborBump 本身不缓存指针。
// SAFETY: 违反后果 —— 若 region 生命期短于分配器或调用方伪造 base/size，将产生悬垂指针。
unsafe impl Sync for HarborBump {}
unsafe impl GlobalAlloc for HarborBump {
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
        // SAFETY: 仅触碰自有统计字段；bump 策略下不做单块回收（见 crate 文档「非目标」）。
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        h.stats.deallocs += 1;
    }
}

impl HarborBump {
    /// 用一块外部提供的区域构造分配器（空测试惯用法见 `new_unbacked`）。
    pub const fn new(base: *mut u8, size: usize) -> Self {
        Self {
            inner: SpinLock::new(UnsafeCell::new(HarborInner {
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
    /// 再在 `kmain` 早期用 [`HarborBump::rebind`] 绑定后备区域。
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

/// 空闲块最小字节数：16 B 头（size+next）+ 16 B 最小载荷。
const MIN_BLOCK: usize = 32;

/// 空闲块内部分割阈值：余量低于此值整块划入分配（内部碎片 ≤ 31 B）。
const MIN_SPLIT: usize = 32;

/// M21-③ Harbor free-list（first-fit + 地址序合并 + bump 晋升）。
///
/// 承接 crate 文档承诺的 SPEC 5 章「通用 free-list」补齐：在 bump 之上
/// 增加单块回收复用面——
///
/// - **块模型**：分配块 = `[block, block+block_size)`，16 字节对齐；
///   用户载荷前紧贴 16 字节头 `{block_start, block_size}`（dealloc 恢复
///   块界的全部根据）；载荷对齐由 `align_up(block+16, align)` 前垫实现
///   （前垫计入分配块，对齐 > 16 时至多浪费 align-16 字节）。
/// - **空闲块**：侵入式单链（size+next 存于块首 16 字节），**地址序**
///   维护——合并判定退化为 O(1) 邻接检查（prev_end == block 或
///   block_end == next_start），free 即合并无碎片积累面。
/// - **分配路径**：free-list first-fit（可整块或尾部 16 对齐分割，余量
///   < MIN_SPLIT 整块划入）→ 无_fit 则 bump 推进（永不回收 bump 已
///   划出界外的对齐缝隙，统计面如实计为在用）。
/// - **ZST**：size=0 返回对齐悬挂指针（= align 值，恒异于真实堆指针
///   ——内核堆基址 ≥ 0x600000），dealloc 无操作。
/// - **统计**：[`AllocStats`] 四字段语义保持（bytes_in_use = bump 已推进
///   字节数 − 空闲块字节和）；free-list 扩展面（free_blocks 空闲块数 /
///   reuse_allocs 复用分配次数——bump 不回收故递增即复用铁证）经
///   [`HarborFreeList::free_stamps`] 取证。
pub struct HarborFreeList {
    inner: SpinLock<UnsafeCell<FreeListInner>>,
}

struct FreeListInner {
    base: *mut u8,
    size: usize,
    /// bump 推进位（相对 base 的字节偏移；16 对齐推进）。
    cursor: usize,
    /// 空闲链首（块绝对地址；0 = 空）。地址序单链。
    head: usize,
    free_blocks: u64,
    reuse_allocs: u64,
    free_bytes: usize,
    stats: AllocStats,
}

// SAFETY: 前置条件 —— base 指向调用方保证的一块 `size` 字节、独占、对齐 ≥ 16 的内存区域。
// SAFETY: 不变式 —— 全部块 16 字节对齐且界内（cursor ≤ size、块界互叠为零）；指针运算全在锁内 usize 域完成并先做溢出检查。
// SAFETY: 并发 —— inner 为 SpinLock，互斥访问；HarborFreeList 本身不缓存指针。
// SAFETY: 违反后果 —— region 生命期短于分配器或调用方伪造 base/size，将产生悬垂指针。
unsafe impl Sync for HarborFreeList {}
// SAFETY: GlobalAlloc 契约由块模型承载——alloc 返回的指针在 dealloc 时
// 经 16 字节头精确恢复块界；realloc 默认实现 = alloc+copy+dealloc 安全。
unsafe impl GlobalAlloc for HarborFreeList {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 持锁期间独占 inner；layout 已由调用方保证非零。
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        let align = layout.align().max(8);
        let want = layout.size();
        if h.base.is_null() || h.size == 0 {
            return ptr::null_mut();
        }
        if want == 0 {
            // ZST：对齐悬挂指针（= align 值；真实堆指针 ≥ base ≥ 0x600000，
            // 二者域恒不相交）。
            return align as *mut u8;
        }
        let base_addr = h.base as usize;
        // ① free-list first-fit（地址序扫描，首个可容块）
        let mut prev: usize = 0;
        let mut cur = h.head;
        while cur != 0 {
            // SAFETY: cur 为锁内维护的空闲块地址（界内 16 对齐），头部
            //         16 字节属分配器自有内存。
            let bsize = unsafe { (cur as *const usize).read() };
            let next = unsafe { ((cur + 8) as *const usize).read() };
            let payload = cur.checked_add(16).map(|p| p.next_multiple_of(align));
            let Some(payload) = payload else {
                return ptr::null_mut();
            };
            let Some(end) = payload.checked_add(want) else {
                return ptr::null_mut();
            };
            let r = end.next_multiple_of(16);
            let block_end = cur + bsize;
            if payload >= cur + 16 && r <= block_end {
                // 命中：摘链（或原地收缩为余块）
                let rem = block_end - r;
                let new_next = if rem >= MIN_SPLIT {
                    // 尾部余块自 r 起（16 对齐），继承后继
                    // SAFETY: r..block_end ≥ MIN_SPLIT，写入自有空闲内存头部。
                    unsafe {
                        (r as *mut usize).write(rem);
                        ((r + 8) as *mut usize).write(next);
                    }
                    r
                } else {
                    next
                };
                if prev == 0 {
                    h.head = new_next;
                } else {
                    // SAFETY: prev 为空闲链上有效块地址，next 槽属其头部。
                    unsafe { ((prev + 8) as *mut usize).write(new_next) };
                }
                if rem >= MIN_SPLIT {
                    // 一分为二：块数不变（原块 → 占用段 + 余块）；
                    // free_bytes 只减被占用段（bsize − rem）
                    h.free_bytes -= bsize - rem;
                } else {
                    // 整块划入：块数 -1，free_bytes 减全块
                    h.free_blocks -= 1;
                    h.free_bytes -= bsize;
                }
                // 载荷头：{block_start, 消耗块界}（含尾垫）
                // SAFETY: payload-16 ≥ cur，写入分配块内部自有头槽。
                unsafe {
                    ((payload - 16) as *mut usize).write(cur);
                    ((payload - 8) as *mut usize).write(r - cur);
                }
                h.stats.allocs += 1;
                h.reuse_allocs += 1;
                h.stats.bytes_in_use = h.cursor - h.free_bytes;
                return payload as *mut u8;
            }
            prev = cur;
            cur = next;
        }
        // ② bump 晋升：16 对齐推进，载荷前垫对齐
        let block_off = h.cursor.next_multiple_of(16);
        let Some(payload_off) = base_addr
            .checked_add(block_off + 16)
            .map(|a| a.next_multiple_of(align))
            .map(|a| a - base_addr)
        else {
            return ptr::null_mut();
        };
        let Some(end_off) = payload_off
            .checked_add(want)
            .map(|e| e.next_multiple_of(16))
        else {
            return ptr::null_mut();
        };
        if end_off > h.size {
            return ptr::null_mut();
        }
        // 载荷头：{block_start, 消耗块界}
        // SAFETY: payload_off ≥ block_off + 16，头槽在 bump 新划区域内。
        unsafe {
            ((base_addr + payload_off - 16) as *mut usize).write(base_addr + block_off);
            ((base_addr + payload_off - 8) as *mut usize).write(end_off - block_off);
        }
        h.cursor = end_off;
        h.stats.allocs += 1;
        h.stats.bytes_in_use = h.cursor - h.free_bytes;
        if h.stats.bytes_in_use > h.stats.peak_bytes {
            h.stats.peak_bytes = h.stats.bytes_in_use;
        }
        // SAFETY: payload_off + want ≤ end_off ≤ size，指针界内。
        unsafe { h.base.add(payload_off) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: 持锁期间独占 inner；块界由载荷头精确恢复。
        let g = self.inner.lock();
        let h = unsafe { &mut *g.get() };
        h.stats.deallocs += 1;
        if layout.size() == 0 {
            return; // ZST：无块可还
        }
        if h.base.is_null() {
            return;
        }
        let base_addr = h.base as usize;
        let p = ptr as usize;
        if p < base_addr + 16 || p > base_addr + h.size {
            return; // 契约外指针（含 ZST 悬挂）：仅计 deallocs，不动块面
        }
        // SAFETY: p 为本分配器签出的载荷指针，头槽（p-16..p）属自有块。
        let block = unsafe { ((p - 16) as *const usize).read() };
        let bsize = unsafe { ((p - 8) as *const usize).read() };
        if block < base_addr || block + bsize > base_addr + h.cursor || bsize < MIN_BLOCK {
            return; // 头部完整性防线：界外/退化块拒绝入链
        }
        h.free_bytes += bsize; // 释放总量一次入账；合并只改块数不改字节和
                               // 地址序插入 + O(1) 邻接合并
        let block_end = block + bsize;
        let mut prev: usize = 0;
        let mut cur = h.head;
        while cur != 0 && cur < block {
            // SAFETY: cur 为空闲链有效块，next 槽属其头部。
            let next = unsafe { ((cur + 8) as *const usize).read() };
            prev = cur;
            cur = next;
        }
        // 后邻合并：block_end == cur → 吞并 cur
        let inserted = block;
        let mut inserted_size = bsize;
        if cur == block_end {
            // SAFETY: cur 空闲块头部读（size 槽）。
            let csize = unsafe { (cur as *const usize).read() };
            let cnext = unsafe { ((cur + 8) as *const usize).read() };
            inserted_size = bsize + csize;
            // SAFETY: inserted（=block）头槽写入合并后界。
            unsafe {
                (inserted as *mut usize).write(inserted_size);
                ((inserted + 8) as *mut usize).write(cnext);
            }
            // 块数不变：inserted 尚未入账，cur 已在链上——二者合一后
            // 计数面维持原值（free_bytes 和不变，已由入口一次性加账）。
        } else {
            // SAFETY: inserted 头槽写入（块内存此时已归分配器）。
            unsafe {
                (inserted as *mut usize).write(inserted_size);
                ((inserted + 8) as *mut usize).write(cur);
            }
            h.free_blocks += 1;
        }
        // 前邻合并：prev_end == block → 扩 prev
        if prev != 0 {
            // SAFETY: prev 空闲块头部读。
            let psize = unsafe { (prev as *const usize).read() };
            if prev + psize == inserted {
                // 前邻合并：prev 吞并 inserted——后继必须接 inserted 的
                // next（后邻合并时 inserted.next = cnext ≠ cur，直接接
                // cur 会把已吞区域重新当块遍历 → 链腐坏）
                // SAFETY: inserted 头槽 next 读 + prev 双槽改写，均为
                //         分配器自有空闲内存。
                let inext = unsafe { ((inserted + 8) as *const usize).read() };
                unsafe {
                    (prev as *mut usize).write(psize + inserted_size);
                    ((prev + 8) as *mut usize).write(inext);
                }
                h.free_blocks -= 1;
                h.stats.bytes_in_use = h.cursor - h.free_bytes;
                return;
            }
            // SAFETY: prev next 槽指向 inserted。
            unsafe {
                ((prev + 8) as *mut usize).write(inserted);
            }
        } else {
            h.head = inserted;
        }
        h.stats.bytes_in_use = h.cursor - h.free_bytes;
    }
}

impl HarborFreeList {
    /// 用一块外部提供的区域构造分配器。
    pub const fn new(base: *mut u8, size: usize) -> Self {
        Self {
            inner: SpinLock::new(UnsafeCell::new(FreeListInner {
                base,
                size,
                cursor: 0,
                head: 0,
                free_blocks: 0,
                reuse_allocs: 0,
                free_bytes: 0,
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
    /// 再在 `kmain` 早期用 [`HarborFreeList::rebind`] 绑定后备区域。
    pub const fn new_unbacked() -> Self {
        Self::new(core::ptr::null_mut(), 0)
    }

    /// 启动期绑定后备区域：游标/空闲链/统计全量清零。
    ///
    /// 返回 `false` 表示拒绝重绑：分配器已有在用分配（cursor ≠ 0），
    /// 此时换区域会令既有指针悬垂；调用方 MUST 仅在启动期、首次分配
    /// 之前调用一次。
    ///
    /// # SAFETY（调用方义务）
    /// `base` 指向调用方保证的 `size` 字节、独占、对齐 ≥ 16 的内存区域，
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
        h.head = 0;
        h.free_blocks = 0;
        h.reuse_allocs = 0;
        h.free_bytes = 0;
        h.stats = AllocStats::default();
        true
    }

    /// 当前统计快照（含 free-list 扩展面）。
    pub fn stats(&self) -> AllocStats {
        // SAFETY: 仅在锁内读取。
        let g = self.inner.lock();
        unsafe { (*g.get()).stats }
    }

    /// free-list 扩展取证：(空闲块数, 复用分配次数)。
    pub fn free_stamps(&self) -> (u64, u64) {
        // SAFETY: 仅在锁内读取。
        let g = self.inner.lock();
        let h = unsafe { &*g.get() };
        (h.free_blocks, h.reuse_allocs)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{AllocStats, HarborBump};
    use core::alloc::{GlobalAlloc, Layout};

    const ARENA: usize = 64 * 1024;
    // SAFETY: GlobalAlloc 契约要求基址 ≥ 8 对齐；u8 数组本身只有 1 对齐，
    // 故用 #[repr(align(16))] 包装后取内部数组地址。
    #[repr(align(16))]
    struct Aligned([u8; ARENA]);
    static ARENA_BYTES: Aligned = Aligned([0; ARENA]);

    fn make() -> HarborBump {
        HarborBump::new(ARENA_BYTES.0.as_ptr() as *mut u8, ARENA)
    }

    #[test]
    fn honors_alignment() {
        let h = make();
        for align in [1usize, 2, 4, 8, 16, 64, 256] {
            let p = unsafe { h.alloc(Layout::from_size_align(17, align).unwrap()) };
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "ptr not aligned to {align}");
        }
    }

    #[test]
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
    fn rebind_after_unbacked_and_rejects_when_busy() {
        let h = HarborBump::new_unbacked();
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

/// M21-③ HarborFreeList 宿主测试（每例独立 arena——cargo test 默认
/// 并行执行，共享 arena 会互踩内存；模式完整性断言必须有独占区域）。
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod free_list_tests {
    use super::HarborFreeList;
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    const ARENA: usize = 64 * 1024;

    // 关键：arena 必须 UnsafeCell 包裹——无内部可变性的 static 会被放进
    // .rodata（只读段），free-list 写块头即写只读内存 SIGSEGV（bump 不
    // 写 arena 故旧测试从未暴露）。UnsafeCell 强制落入可写段。
    #[repr(align(16))]
    struct ArenaA(UnsafeCell<[u8; ARENA]>);
    #[repr(align(16))]
    struct ArenaB(UnsafeCell<[u8; ARENA]>);
    #[repr(align(16))]
    struct ArenaC(UnsafeCell<[u8; ARENA]>);
    #[repr(align(16))]
    struct ArenaD(UnsafeCell<[u8; ARENA]>);
    #[repr(align(16))]
    struct ArenaE(UnsafeCell<[u8; ARENA]>);

    // SAFETY: 每个 arena 恰被一个测试独占使用（测试间无共享）。
    unsafe impl Sync for ArenaA {}
    unsafe impl Sync for ArenaB {}
    unsafe impl Sync for ArenaC {}
    unsafe impl Sync for ArenaD {}
    unsafe impl Sync for ArenaE {}

    static ARENA_A: ArenaA = ArenaA(UnsafeCell::new([0; ARENA]));
    static ARENA_B: ArenaB = ArenaB(UnsafeCell::new([0; ARENA]));
    static ARENA_C: ArenaC = ArenaC(UnsafeCell::new([0; ARENA]));
    static ARENA_D: ArenaD = ArenaD(UnsafeCell::new([0; ARENA]));
    static ARENA_E: ArenaE = ArenaE(UnsafeCell::new([0; ARENA]));

    fn l(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn freelist_reuses_freed_block() {
        let h = HarborFreeList::new(ARENA_A.0.get() as *mut u8, ARENA);
        let a = unsafe { h.alloc(l(4096, 8)) };
        assert!(!a.is_null());
        unsafe { h.dealloc(a, l(4096, 8)) };
        let (fb0, ru0) = h.free_stamps();
        assert!(fb0 >= 1);
        let b = unsafe { h.alloc(l(4096, 8)) };
        assert_eq!(b, a, "first-fit must reuse the just-freed block");
        let (_, ru1) = h.free_stamps();
        assert_eq!(
            ru1,
            ru0 + 1,
            "reuse_allocs must increment (bump never recycles)"
        );
    }

    #[test]
    fn freelist_coalesces_neighbors() {
        let h = HarborFreeList::new(ARENA_B.0.get() as *mut u8, ARENA);
        let lay = l(1024, 8);
        let a = unsafe { h.alloc(lay) };
        let b = unsafe { h.alloc(lay) };
        let c = unsafe { h.alloc(lay) };
        assert!(!a.is_null() && !b.is_null() && !c.is_null());
        // 三块相邻（同布局顺排无垫），逆序释放 → 两次合并 → 恰一空闲大块
        unsafe { h.dealloc(c, lay) };
        unsafe { h.dealloc(b, lay) };
        unsafe { h.dealloc(a, lay) };
        let (fb, _) = h.free_stamps();
        assert_eq!(fb, 1, "three adjacent blocks must coalesce into one");
        let big = unsafe { h.alloc(l(3 * 1024, 8)) };
        assert!(!big.is_null(), "coalesced block must fit 3 KiB");
    }

    #[test]
    fn freelist_honors_alignment() {
        let h = HarborFreeList::new(ARENA_C.0.get() as *mut u8, ARENA);
        for align in [8usize, 16, 32, 64, 256, 4096] {
            let p = unsafe { h.alloc(l(100, align)) };
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "ptr not aligned to {align}");
            unsafe { core::ptr::write_bytes(p, 0xA5, 100) };
            unsafe { h.dealloc(p, l(100, align)) };
        }
    }

    #[test]
    fn freelist_recycles_after_bump_exhaustion() {
        let h = HarborFreeList::new(ARENA_D.0.get() as *mut u8, ARENA);
        // 耗尽 bump：连续分配直到失败
        let mut ptrs: std::vec::Vec<*mut u8> = std::vec::Vec::new();
        loop {
            let p = unsafe { h.alloc(l(4096, 8)) };
            if p.is_null() {
                break;
            }
            ptrs.push(p);
        }
        assert!(ptrs.len() >= 2, "arena must host several 4 KiB blocks");
        // 释放除首块外全部 → 再分配必须由 free-list 服务（bump 已尽）
        let keep = ptrs[0];
        for &p in &ptrs[1..] {
            unsafe { h.dealloc(p, l(4096, 8)) };
        }
        let (fb, _) = h.free_stamps();
        assert!(fb >= 1);
        let p2 = unsafe { h.alloc(l(4096, 8)) };
        assert!(
            !p2.is_null(),
            "freed blocks must be recyclable after exhaustion"
        );
        unsafe { core::ptr::write_bytes(p2, 0x5A, 4096) };
        unsafe { h.dealloc(keep, l(4096, 8)) };
        unsafe { h.dealloc(p2, l(4096, 8)) };
    }

    #[test]
    fn freelist_zst_and_pattern_integrity() {
        let h = HarborFreeList::new(ARENA_E.0.get() as *mut u8, ARENA);
        // ZST：对齐悬挂指针（= align 值），dealloc 无操作
        let z = unsafe { h.alloc(l(0, 16)) };
        assert!(!z.is_null() && z as usize == 16);
        unsafe { h.dealloc(z, l(0, 16)) };
        // 交错分配/释放 + 填充模式完整性（复用块边界正确性）
        let mut kept: std::vec::Vec<(*mut u8, u8)> = std::vec::Vec::new();
        for i in 0..40u8 {
            let p = unsafe { h.alloc(l(160, 8)) };
            assert!(!p.is_null());
            unsafe { core::ptr::write_bytes(p, i, 160) };
            if i % 2 == 1 {
                unsafe { h.dealloc(p, l(160, 8)) }; // 奇数位即放：后续分配复用
            } else {
                kept.push((p, i));
            }
        }
        for (p, tag) in &kept {
            let buf = unsafe { core::slice::from_raw_parts(*p, 160) };
            assert!(
                buf.iter().all(|&x| x == *tag),
                "pattern clobbered at {:#x}",
                *p as usize
            );
        }
    }
}
