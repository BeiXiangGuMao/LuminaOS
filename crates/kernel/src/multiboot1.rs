//! multiboot1 信息块解析（内存面）。
//!
//! 依据 multiboot1 规范：flags 位 0 提供 mem_lower/mem_upper（KiB），
//! 位 6 提供内存映射表（条目布局 size/addr/len/type，size 含自身 4 字节）。
//! 全部读取经由 [`ostd::hw::phys`] 的 volatile 包装，本模块零 unsafe。

use alloc::vec::Vec;

use ostd::hw::phys;

/// 引导程序交接魔数（multiboot1 规范约定）。
pub const BOOT_MAGIC: u32 = 0x2BADB002;
/// flags 位 0：mem_lower/mem_upper 有效。
const FLAG_MEM: u32 = 0x1;
/// flags 位 6：mmap_length/mmap_addr 有效。
const FLAG_MMAP: u32 = 0x40;
/// mmap 条目类型：可用内存。
const TYPE_USABLE: u32 = 1;
/// mmap 条目 size 字段的最小合法值（addr+len+type 三域 20 字节；
/// size 字段自身不计入该值，QEMU/GRUB 实测均为 20）。
const MMAP_MIN: u64 = 20;

/// 一条可用内存区域（物理地址）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// 起始物理地址（字节）。
    pub start: u64,
    /// 长度（字节）。
    pub len: u64,
}

/// 信息块内存面摘要。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemSummary {
    /// mem_lower（KiB，常规内存下界）。
    pub lower_kib: u32,
    /// mem_upper（KiB，常规内存上界，从 1 MiB 起）。
    pub upper_kib: u32,
    /// 最大可用区域（无 mmap 时为 None）。
    pub largest_usable: Option<Region>,
}

/// 读取信息块原始 flags（诊断用：确认位 0/6 是否由引导程序置位）。
pub fn info_flags(info: u32) -> u32 {
    phys::read_u32(info as u64)
}

/// 解析信息块内存面；异常条目即终止（防御式），不 panic。
pub fn summarize(info: u32) -> MemSummary {
    let base = info as u64;
    let flags = phys::read_u32(base);
    let mut out = MemSummary::default();
    if flags & FLAG_MEM != 0 {
        out.lower_kib = phys::read_u32(base + 4);
        out.upper_kib = phys::read_u32(base + 8);
    }
    if flags & FLAG_MMAP != 0 {
        let mmap_len = phys::read_u32(base + 44) as u64;
        let mmap_addr = phys::read_u32(base + 48) as u64;
        let mut off: u64 = 0;
        while off < mmap_len {
            let ent = mmap_addr + off;
            let size = phys::read_u32(ent) as u64;
            if size < MMAP_MIN {
                break; // 防御：条目长度异常，终止解析
            }
            let addr = phys::read_u64(ent + 4);
            let len = phys::read_u64(ent + 12);
            let typ = phys::read_u32(ent + 20);
            if typ == TYPE_USABLE && out.largest_usable.is_none_or(|r| len > r.len) {
                out.largest_usable = Some(Region { start: addr, len });
            }
            off += size + 4;
        }
    }
    out
}

/// 提取全部可用内存区域（帧分配器输入；防御式：异常条目即终止）。
///
/// 与 [`summarize`] 同一条目遍历，但保留全部 `TYPE_USABLE` 区域而非
/// 只取最大者。容量上限 32 条（QEMU/GRUB 实际 ≤ 8 条，防御越界）。
pub fn usable_regions(info: u32, out: &mut Vec<Region>) {
    out.clear();
    let base = info as u64;
    let flags = phys::read_u32(base);
    if flags & FLAG_MMAP == 0 {
        return;
    }
    let mmap_len = phys::read_u32(base + 44) as u64;
    let mmap_addr = phys::read_u32(base + 48) as u64;
    let mut off: u64 = 0;
    while off < mmap_len && out.len() < 32 {
        let ent = mmap_addr + off;
        let size = phys::read_u32(ent) as u64;
        if size < MMAP_MIN {
            break; // 防御：条目长度异常，终止解析
        }
        let addr = phys::read_u64(ent + 4);
        let len = phys::read_u64(ent + 12);
        let typ = phys::read_u32(ent + 20);
        if typ == TYPE_USABLE && len > 0 {
            out.push(Region { start: addr, len });
        }
        off += size + 4;
    }
}
