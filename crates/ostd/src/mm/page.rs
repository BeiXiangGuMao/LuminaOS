//! x86_64 四级页表抽象：条目位域 + 表遍历器（map/translate/unmap）。
//!
//! 遍历逻辑零 unsafe：所有物理内存访问经由 [`PhysAccess`] 抽象。
//! 裸机实现 [`IdentityAccess`] 把 unsafe 收口到 [`crate::hw::phys`]；
//! 宿主测试注入伪造内存，同一套遍历代码在 S4 单元测试与 S8 裸机冒烟
//! 两条路径上验证（M3 自检 9 的 MMU 往返即其实机证明）。
//!
//! 约定：M3 只处理 4 KiB 页的 map，但 translate/unmap 兼容启动页表
//! 的 2 MiB 大页条目（PS 位），因为低 1 GiB 恒等映射正是 512 × 2 MiB。

/// 页表条目：x86_64 长模式格式（4 KiB 与 2 MiB 条目共用位域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry(u64);

impl Entry {
    /// 空（P=0）。
    pub const EMPTY: Entry = Entry(0);
    /// Present 位（位 0）。
    pub const PRESENT: u64 = 1 << 0;
    /// Writable 位（位 1）。
    pub const WRITABLE: u64 = 1 << 1;
    /// User 位（位 2；M3 内核映射不使用，保留定义）。
    pub const USER: u64 = 1 << 2;
    /// Page Size 位（位 7；PD 层置位即 2 MiB 大页）。
    pub const HUGE: u64 = 1 << 7;
    /// No-Execute 位（位 63；需 EFER.NXE，M3 未启用故不设置）。
    #[allow(dead_code)]
    pub const NO_EXECUTE: u64 = 1 << 63;
    /// Accessed 位（位 5；MMU 访问时置位，软件清零——二次机会淘汰依据）。
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty 位（位 6；MMU 写入时置位）。
    #[allow(dead_code)]
    pub const DIRTY: u64 = 1 << 6;

    /// 物理地址掩码：位 12..52（页表帧/页基址；M12-B COW 走表公开）。
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// 由原始位域构造。
    pub const fn from_bits(bits: u64) -> Self {
        Entry(bits)
    }

    /// 原始位域。
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// 是否 Present。
    pub const fn is_present(self) -> bool {
        self.0 & Self::PRESENT != 0
    }

    /// 是否大页（PS=1，仅 PD/PDPT 层有意义）。
    pub const fn is_huge(self) -> bool {
        self.0 & Self::HUGE != 0
    }

    /// 条目承载的物理基址（4 KiB 或 2 MiB 对齐，取决于层级 PS）。
    pub const fn addr(self) -> u64 {
        self.0 & Self::ADDR_MASK
    }

    /// 构造下级表指针条目（P | W —— 内核态全局可写表）。
    pub const fn table(phys: u64) -> Self {
        Entry(phys & Self::ADDR_MASK | Self::PRESENT | Self::WRITABLE)
    }

    /// 构造普通页条目（携带调用方 flags，强制清 HUGE）。
    pub const fn page(phys: u64, flags: u64) -> Self {
        Entry(phys & Self::ADDR_MASK | flags & !Self::HUGE | Self::PRESENT)
    }

    /// 构造大页条目（强制 PS=1）。
    #[allow(dead_code)]
    pub const fn huge(phys: u64, flags: u64) -> Self {
        Entry(phys & Self::ADDR_MASK | flags | Self::HUGE | Self::PRESENT)
    }

    /// 萃取条目的**属性位**（剔除物理地址域与 P/A/D 状态位，保留 W/U/
    /// NX 等软件管理的属性）——M8-B 回收链换入重映射时按此恢复映射
    /// 标志；**地址位若混入 flags 会与新帧地址 OR 在一起**（开发期
    /// 实测：四页换入全部映射到同一错误帧）。
    pub const fn attributes(self) -> Self {
        Entry(self.0 & !(Self::ADDR_MASK | Self::PRESENT | Self::ACCESSED | Self::DIRTY))
    }
}

/// 物理内存访问抽象（遍历器的「内存后端」）。
///
/// 方法全部 safe：实现方自行把 unsafe 收口（裸机实现转发到
/// [`crate::hw::phys`]，宿主测试实现访问进程内伪造内存）。
pub trait PhysAccess {
    /// 读物理地址上的 8 字节。
    fn read(&self, addr: u64) -> u64;
    /// 写 8 字节到物理地址。
    fn write(&mut self, addr: u64, value: u64);
    /// 把 `[addr, addr + len)` 清零（len 为 8 的倍数）。
    fn zero(&mut self, addr: u64, len: u64);
}

/// 裸机后端：低 1 GiB 恒等映射下的 volatile 直读直写（phys_offset = 0）。
pub struct IdentityAccess;

impl PhysAccess for IdentityAccess {
    fn read(&self, addr: u64) -> u64 {
        crate::hw::phys::read_u64(addr)
    }

    fn write(&mut self, addr: u64, value: u64) {
        crate::hw::phys::write_u64(addr, value)
    }

    fn zero(&mut self, addr: u64, len: u64) {
        crate::hw::phys::write_zero(addr, len)
    }
}

/// 页表遍历错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageError {
    /// map 时某帧分配失败（页表按需分配耗尽）。
    TableAllocExhausted,
    /// unmap 的虚拟地址未映射。
    NotMapped,
    /// map 的目标虚拟地址已被映射。
    AlreadyMapped,
    /// map 命中了既有 2 MiB 大页分支（M3 不做拆页）。
    HugeConflict,
    /// 虚拟地址未按 4 KiB 对齐。
    UnalignedVirtual,
}

use crate::mm::frame::FRAME_SIZE;

/// 页表遍历器。
///
/// `A` 为物理内存后端；`F` 为中间页表帧分配回调（返回 4 KiB 对齐物理
/// 地址或 `None` 表示耗尽）。
pub struct Walker<'a, A: PhysAccess, F: FnMut() -> Option<u64>> {
    /// 物理内存后端。
    pub mem: &'a mut A,
    /// 中间页表帧分配器。
    pub alloc_table: F,
}

impl<A: PhysAccess, F: FnMut() -> Option<u64>> Walker<'_, A, F> {
    /// 建立映射：`virt`（4 KiB 对齐）→ `phys`（4 KiB 对齐），按需分配
    /// 中间页表并清零。
    pub fn map(&mut self, root: u64, virt: u64, phys: u64, flags: u64) -> Result<(), PageError> {
        if !virt.is_multiple_of(FRAME_SIZE) || !phys.is_multiple_of(FRAME_SIZE) {
            return Err(PageError::UnalignedVirtual);
        }
        let new_leaf = Entry::page(phys, flags);
        let mut table = root;
        // 层级索引：PML4 → PDPT → PD → PT（位 39..47 / 30..38 / 21..29 / 12..20）
        for shift in [39u64, 30, 21] {
            let idx = ((virt >> shift) & 0x1FF) as usize;
            let slot = table + (idx as u64) * 8;
            let cur = Entry::from_bits(self.mem.read(slot));
            if !cur.is_present() {
                let Some(t) = (self.alloc_table)() else {
                    return Err(PageError::TableAllocExhausted);
                };
                self.mem.zero(t, FRAME_SIZE);
                let entry = Entry::table(t);
                self.mem.write(slot, entry.bits());
                table = t;
            } else if cur.is_huge() {
                // 目标落在既有大页区域内：拆页属 M4+，先拒绝
                return Err(PageError::HugeConflict);
            } else {
                table = cur.addr();
            }
        }
        let idx = ((virt >> 12) & 0x1FF) as usize;
        let slot = table + (idx as u64) * 8;
        if Entry::from_bits(self.mem.read(slot)).is_present() {
            return Err(PageError::AlreadyMapped);
        }
        self.mem.write(slot, new_leaf.bits());
        Ok(())
    }

    /// 翻译虚拟地址 → 物理地址（4 KiB 页与 2 MiB 大页皆可）；未映射返回
    /// `None`。不经过 MMU，纯表遍历。
    pub fn translate(&self, root: u64, virt: u64) -> Option<u64> {
        let mut table = root;
        // PML4 / PDPT / PD
        for shift in [39u64, 30, 21] {
            let idx = ((virt >> shift) & 0x1FF) as usize;
            let entry = Entry::from_bits(self.mem.read(table + (idx as u64) * 8));
            if !entry.is_present() {
                return None;
            }
            if entry.is_huge() {
                // 2 MiB 大页：物理基址 + 页内偏移（低 21 位）
                return Some(entry.addr() + (virt & 0x1F_FFFF));
            }
            table = entry.addr();
        }
        let idx = ((virt >> 12) & 0x1FF) as usize;
        let leaf = Entry::from_bits(self.mem.read(table + (idx as u64) * 8));
        if !leaf.is_present() {
            return None;
        }
        Some(leaf.addr() + (virt & 0xFFF))
    }

    /// 读叶表项（不消费不改写；未映射/大页分支返回 `None`）。
    ///
    /// 返回原始条目（含 P=0 形态），调用方自行判 P/位域——M8-B 回收
    /// 扫描（A 位二次机会）与淘汰前取证共用本读取面。
    pub fn leaf_entry(&self, root: u64, virt: u64) -> Option<Entry> {
        let mut table = root;
        for shift in [39u64, 30, 21] {
            let idx = ((virt >> shift) & 0x1FF) as usize;
            let entry = Entry::from_bits(self.mem.read(table + (idx as u64) * 8));
            if !entry.is_present() || entry.is_huge() {
                return None;
            }
            table = entry.addr();
        }
        let idx = ((virt >> 12) & 0x1FF) as usize;
        Some(Entry::from_bits(self.mem.read(table + (idx as u64) * 8)))
    }

    /// 叶表项位域 RMW（`set` 置位、`clear` 清位，clear 优先）。
    ///
    /// 供回收扫描清 A 位（二次机会让渡）与淘汰前取证；未映射即
    /// [`PageError::NotMapped`]，不改写任何层次。
    pub fn set_leaf_bits(
        &mut self,
        root: u64,
        virt: u64,
        set: u64,
        clear: u64,
    ) -> Result<Entry, PageError> {
        let mut table = root;
        for shift in [39u64, 30, 21] {
            let idx = ((virt >> shift) & 0x1FF) as usize;
            let entry = Entry::from_bits(self.mem.read(table + (idx as u64) * 8));
            if !entry.is_present() || entry.is_huge() {
                return Err(PageError::NotMapped);
            }
            table = entry.addr();
        }
        let idx = ((virt >> 12) & 0x1FF) as usize;
        let slot = table + (idx as u64) * 8;
        let leaf = Entry::from_bits(self.mem.read(slot));
        if !leaf.is_present() {
            return Err(PageError::NotMapped);
        }
        let bits = (leaf.bits() | set) & !clear;
        self.mem.write(slot, bits);
        Ok(Entry::from_bits(bits))
    }

    /// 取消映射并返回原物理基址；未映射即 [`PageError::NotMapped`]。
    pub fn unmap(&mut self, root: u64, virt: u64) -> Result<u64, PageError> {
        if !virt.is_multiple_of(FRAME_SIZE) {
            return Err(PageError::UnalignedVirtual);
        }
        let mut table = root;
        for shift in [39u64, 30, 21] {
            let idx = ((virt >> shift) & 0x1FF) as usize;
            let entry = Entry::from_bits(self.mem.read(table + (idx as u64) * 8));
            if !entry.is_present() {
                return Err(PageError::NotMapped);
            }
            // 大页层级上没有下层 PT：直接在此层取消
            if entry.is_huge() {
                self.mem
                    .write(table + (idx as u64) * 8, Entry::EMPTY.bits());
                return Ok(entry.addr());
            }
            table = entry.addr();
        }
        let idx = ((virt >> 12) & 0x1FF) as usize;
        let slot = table + (idx as u64) * 8;
        let leaf = Entry::from_bits(self.mem.read(slot));
        if !leaf.is_present() {
            return Err(PageError::NotMapped);
        }
        self.mem.write(slot, Entry::EMPTY.bits());
        Ok(leaf.addr())
    }
}

/// 使新建根具备内核运行必需的页表分支（M6 缺陷一的架构级修复）。
///
/// 背景：per-CPU 路径（`my_cpu` / LAPIC EOI / ICR）读 LAPIC MMIO 页
/// （0xFEE00000 = PML4[0] → PDPT[3]）。新建根若自带全新 PDPT（用户根
/// 即如此），该分支缺失——内核任务在此根上一触 LAPIC 即 #PF。
///
/// 语义（幂等，不破坏调用方已建立的映射）：
/// 1. 目标 PML4[0] 已存在（Present）→ 保持不变（用户根指向其新 PDPT、
///    测试根共享引导 PDPT，两种拓扑都尊重）；为空 → 复制引导 PML4[0]
///    （整链共享引导 PDPT）；
/// 2. 把引导 PDPT 中 LAPIC 页所在槽位（按 IA32_APIC_BASE 实际基址定位）
///    补植到目标 PDPT 同槽位——共享拓扑下为自拷贝（无副作用）。
///
/// LAPIC 分支条目为 supervisor-only（无 U 位），ring3 不可见，隔离面
/// 不扩大；中间表为共享引用（引导根独占其生存期，内核永不拆除）。
/// 调用契约：目标 PML4[0] 若需指向自有 PDPT，必须先完成链接再调用。
pub fn clone_kernel_branches(boot_root: u64, dst_root: u64) {
    let boot_root = boot_root & !0xFFF;
    let dst_root = dst_root & !0xFFF;
    let boot_pml4e0 = crate::hw::phys::read_u64(boot_root);
    let boot_pdpt = boot_pml4e0 & !0xFFF;
    if boot_pdpt == 0 || boot_pml4e0 & 1 == 0 {
        return;
    }
    let dst_pml4e0 = crate::hw::phys::read_u64(dst_root);
    let (dst_pdpt, linked) = (dst_pml4e0 & !0xFFF, dst_pml4e0 & 1 != 0);
    if !linked {
        // 目标 PML4[0] 为空：整链共享引导分支
        crate::hw::phys::write_u64(dst_root, boot_pml4e0);
    }
    let dst_pdpt = if linked { dst_pdpt } else { boot_pdpt };
    // LAPIC 页所在的 PDPT 槽位（PDPT 索引 = 基址 bit 47:30）
    let lapic_pdpt_idx = (crate::hw::lapic::base() >> 30) & 0x1FF;
    let entry = crate::hw::phys::read_u64(boot_pdpt + lapic_pdpt_idx * 8);
    crate::hw::phys::write_u64(dst_pdpt + lapic_pdpt_idx * 8, entry);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Entry, PageError, PhysAccess, Walker};
    use crate::mm::frame::FRAME_SIZE;

    /// 伪造物理内存：8 字节粒度数组；地址 0..CAP*8。
    struct FakePhys {
        cells: alloc::vec::Vec<u64>,
    }

    impl FakePhys {
        fn new(bytes: u64) -> Self {
            Self {
                cells: alloc::vec![0; (bytes / 8) as usize],
            }
        }
    }

    impl PhysAccess for FakePhys {
        fn read(&self, addr: u64) -> u64 {
            self.cells[(addr / 8) as usize]
        }
        fn write(&mut self, addr: u64, value: u64) {
            self.cells[(addr / 8) as usize] = value;
        }
        fn zero(&mut self, addr: u64, len: u64) {
            let base = (addr / 8) as usize;
            for c in &mut self.cells[base..base + (len / 8) as usize] {
                *c = 0;
            }
        }
    }

    /// 伪造帧分配器：从 0x1000 起顺序发放帧。
    struct FakeFrames {
        next: u64,
    }

    impl FakeFrames {
        fn new() -> Self {
            Self { next: 0x1000 }
        }
        fn alloc(&mut self) -> Option<u64> {
            let f = self.next;
            self.next += FRAME_SIZE;
            Some(f)
        }
    }

    const ROOT: u64 = 0x1000;

    /// 以统一生命周期借出遍历器，规避重复可变借用。
    fn with_walker<A: PhysAccess, F: FnMut() -> Option<u64>>(
        mem: &mut A,
        alloc_table: F,
        f: impl FnOnce(&mut Walker<'_, A, F>),
    ) {
        let mut w = Walker { mem, alloc_table };
        f(&mut w);
    }

    fn no_alloc() -> Option<u64> {
        panic!("测试路径不应再分配页表帧")
    }

    #[test]
    fn entry_bitfields_roundtrip() {
        let e = Entry::page(0x1234_5678_9000, Entry::WRITABLE);
        assert!(e.is_present());
        assert!(!e.is_huge());
        assert_eq!(e.addr(), 0x1234_5678_9000);
        // 高位（含 NX 位与超界物理位）不入掩码
        let raw = Entry::page(0x1234_5678_9000, Entry::WRITABLE | Entry::NO_EXECUTE);
        assert_eq!(raw.addr(), 0x1234_5678_9000);
        let h = Entry::huge(0x200_0000, Entry::WRITABLE);
        assert!(h.is_huge());
        assert_eq!(h.addr(), 0x200_0000);
        assert_eq!(Entry::table(0x3000).bits(), 0x3000 | 0b11);
        assert!(!Entry::EMPTY.is_present());
    }

    #[test]
    fn map_translate_unmap_roundtrip() {
        let (mut mem, mut frames) = (FakePhys::new(0x1_0000), FakeFrames::new());
        mem.zero(ROOT, FRAME_SIZE);
        let target = 0x9000u64;
        let virt = 0x1234_5000u64; // PML4[0]/PDPT[8]/PD[26]/PT[53]
        with_walker(
            &mut mem,
            || frames.alloc(),
            |w| {
                w.map(ROOT, virt, target, Entry::WRITABLE).unwrap();
            },
        );
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.translate(ROOT, virt), Some(target));
        });
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.unmap(ROOT, virt).unwrap(), target);
        });
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.translate(ROOT, virt), None);
            assert_eq!(w.unmap(ROOT, virt), Err(PageError::NotMapped));
        });
    }

    #[test]
    fn translate_unmapped_and_huge_page() {
        let mut mem = FakePhys::new(0x1_0000);
        // 空根：任何翻译都是 None
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.translate(ROOT, 0x1000), None);
        });
        // 人工布置 2 MiB 大页（模拟启动恒等映射形态）：
        // PML4[0]=PDPT、PDPT[0]=PD、PD[1] = 2MiB@0x20_0000 | PS
        mem.write(ROOT, Entry::table(0x2000).bits());
        mem.write(0x2000, Entry::table(0x3000).bits());
        mem.write(0x3000 + 8, Entry::huge(0x20_0000, Entry::WRITABLE).bits());
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.translate(ROOT, 0x21_2345), Some(0x21_2345));
            // 越过 2 MiB 边界即离开大页：PD[2] 未映射 → None
            assert_eq!(w.translate(ROOT, 0x41_0000), None);
        });
    }

    #[test]
    fn map_rejects_already_mapped_unaligned_and_huge() {
        let (mut mem, mut frames) = (FakePhys::new(0x1_0000), FakeFrames::new());
        mem.zero(ROOT, FRAME_SIZE);
        with_walker(
            &mut mem,
            || frames.alloc(),
            |w| {
                w.map(ROOT, 0x5000, 0xA000, Entry::WRITABLE).unwrap();
                assert_eq!(
                    w.map(ROOT, 0x5000, 0xB000, 0),
                    Err(PageError::AlreadyMapped)
                );
                assert_eq!(
                    w.map(ROOT, 0x5001, 0xB000, 0),
                    Err(PageError::UnalignedVirtual)
                );
            },
        );
        // 人工布置大页分支后，在其覆盖范围内 map 4 KiB 页必须被拒绝
        mem.write(ROOT, Entry::table(0x2000).bits());
        mem.write(0x2000, Entry::table(0x3000).bits());
        mem.write(0x3000 + 16, Entry::huge(0x40_0000, Entry::WRITABLE).bits());
        with_walker(
            &mut mem,
            || frames.alloc(),
            |w| {
                assert_eq!(
                    w.map(ROOT, 0x40_1000, 0xA000, 0),
                    Err(PageError::HugeConflict)
                );
            },
        );
    }

    #[test]
    fn map_demand_allocates_missing_branches() {
        let (mut mem, mut frames) = (FakePhys::new(0x1_0000), FakeFrames::new());
        mem.zero(ROOT, FRAME_SIZE);
        let virt = 0x0100_0000_0000u64; // PML4[2]（2×256 GiB）：全新分支
        with_walker(
            &mut mem,
            || frames.alloc(),
            |w| {
                w.map(ROOT, virt, 0x8000, 0).unwrap();
            },
        );
        // PML4[2] 已被填上下级表指针；FakeFrames 从 0x1000 起发放，
        // 故第一张新表即 0x1000（与 ROOT 同帧重叠在平面伪造内存中无害）
        let l4 = Entry::from_bits(mem.read(ROOT + 2 * 8));
        assert!(l4.is_present());
        assert_eq!(l4.addr(), 0x1000);
        with_walker(&mut mem, no_alloc, |w| {
            assert_eq!(w.translate(ROOT, virt), Some(0x8000));
        });
    }
}
