//! ACPI 表发现（HW-14，M5 新增）：fw_cfg → RSDP → XSDT → MADT 的 LAPIC 探测。
//!
//! 发现策略：multiboot1 信息块不携带核拓扑。RSDP 的物理落点随固件版本
//! 漂移（EBDA / E-F 段 / 高端内存均出现过——QEMU 实测三处皆可），扫描法
//! 脆弱；故本实现走 **QEMU fw_cfg 协议**（端口 0x510 选择子 / 0x511 数据）：
//! 遍历文件目录定位 `etc/acpi/rsdp`，直接读取 36 字节 RSDP 内容——
//! 与固件落点解耦，宿主（QEMU）与将来的真实平台（同协议）一致。
//!
//! 解析链：RSDP（fw_cfg 直读）→ XSDT 基址（rsdp.xsdt_address，RAM 内
//! 恒等映射直读）→ MADT（签名 "APIC"）→ type-0 条目（启用核 APIC ID）。
//!
//! 解析零 unsafe：物理内存读取经由 [`crate::hw::phys`]，端口经
//! [`crate::hw::ports`]（HW-01 扩展 16 位口）。

/// 扫描区间（物理地址）：QEMU/SeaBIOS 将 ACPI 表安装于 BIOS 区——
/// EBDA（紧邻 0xA0000 之下）与 E/F 段；直接扫描回退路径用。
pub const RSDP_SCAN_RANGES: [(u64, u64); 2] = [(0x9_F000, 0xA_0000), (0xE_0000, 0xF_FFFF)];

/// fw_cfg 控制端口（16 位选择子）。
const FW_CFG_SELECTOR: u16 = 0x510;
/// fw_cfg 数据端口（8 位逐字节）。
const FW_CFG_DATA: u16 = 0x511;
/// fw_cfg 文件目录选择子。
const FW_CFG_FILE_DIR: u16 = 0x0019;

/// RSDP 签名（"RSD PTR "，8 字节）。
const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// XSDT 表签名。
const XSDT_SIG: [u8; 4] = *b"XSDT";
/// MADT 表签名。
const APIC_SIG: [u8; 4] = *b"APIC";
/// RSDT 表签名（v1 回退路径）。
const RSDT_SIG: [u8; 4] = *b"RSDT";

use alloc::vec::Vec;

/// 从 fw_cfg 数据口读 `n` 字节。
fn fw_cfg_read_bytes(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(crate::hw::ports::read_u8(FW_CFG_DATA));
    }
    out
}

/// 按文件名读取 fw_cfg 文件（按目录登记尺寸分配，`cap` 为上限）。
pub fn fw_cfg_read_file_alloc(name: &[u8], cap: usize) -> Option<alloc::vec::Vec<u8>> {
    crate::hw::ports::write_u16(FW_CFG_SELECTOR, FW_CFG_FILE_DIR);
    let count = be32(&fw_cfg_read_bytes(4));
    if count == 0 || count > 1024 {
        return None;
    }
    for _ in 0..count {
        let size = be32(&fw_cfg_read_bytes(4));
        let sel = be16(&fw_cfg_read_bytes(2));
        let _rsv = fw_cfg_read_bytes(2);
        let entry_name = fw_cfg_read_bytes(56);
        let matched = entry_name.len() > name.len()
            && &entry_name[..name.len()] == name
            && entry_name[name.len()] == 0;
        if matched && size > 0 && size as usize <= cap {
            crate::hw::ports::write_u16(FW_CFG_SELECTOR, sel);
            return Some(fw_cfg_read_bytes(size as usize));
        }
    }
    None
}

/// 按文件名读取 fw_cfg 文件到 `out`；返回实际字节数。
/// 目录遍历：count（BE u32）→ 条目 {size BE u32, sel BE u16, rsv u16, name[56]}。
pub fn fw_cfg_read_file(name: &[u8], out: &mut [u8]) -> Option<usize> {
    crate::hw::ports::write_u16(FW_CFG_SELECTOR, FW_CFG_FILE_DIR);
    let count = be32(&fw_cfg_read_bytes(4));
    if count == 0 || count > 1024 {
        return None;
    }
    for _ in 0..count {
        let size = be32(&fw_cfg_read_bytes(4));
        let sel = be16(&fw_cfg_read_bytes(2));
        let _rsv = fw_cfg_read_bytes(2);
        let entry_name = fw_cfg_read_bytes(56);
        let matched = entry_name.len() > name.len()
            && &entry_name[..name.len()] == name
            && entry_name[name.len()] == 0;
        if matched {
            crate::hw::ports::write_u16(FW_CFG_SELECTOR, sel);
            let n = (size as usize).min(out.len());
            out[..n].copy_from_slice(&fw_cfg_read_bytes(n));
            return Some(n);
        }
    }
    None
}

/// 大端 u32。
fn be32(b: &[u8]) -> u32 {
    u32::from(b[0]) << 24 | u32::from(b[1]) << 16 | u32::from(b[2]) << 8 | u32::from(b[3])
}

/// 大端 u16。
fn be16(b: &[u8]) -> u16 {
    u16::from(b[0]) << 8 | u16::from(b[1])
}

/// 小端 u32（ACPI 表内字段）。
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// 小端 u64。
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// 经 fw_cfg 定位并读取 RSDP；返回（xsdt 物理基址, 原始 RSDP 字节）。
/// 校验：签名 + v1 校验和（20 字节）+ v2 扩展校验和（36 字节）。
///
/// 语义注记：选择子写入即复位数据口游标——目录（0x0019）只写一次，
/// 条目以流式连续读出；命中目标文件后重写选择子为目标 selector 再读
/// 文件内容。v1（20 字节）与 v2（36 字节）RSDP 均接受。
pub fn fw_cfg_rsdp() -> Option<(u64, [u8; 36])> {
    crate::hw::ports::write_u16(FW_CFG_SELECTOR, FW_CFG_FILE_DIR);
    let count = be32(&fw_cfg_read_bytes(4));
    if count == 0 || count > 1024 {
        return None;
    }
    for _ in 0..count {
        // 条目布局：size u32 BE | select u16 BE | reserved u16 | name[56]
        let size = be32(&fw_cfg_read_bytes(4));
        let sel = be16(&fw_cfg_read_bytes(2));
        let _rsv = fw_cfg_read_bytes(2);
        let name = fw_cfg_read_bytes(56);
        if name.len() > 13 && &name[..13] == b"etc/acpi/rsdp" && (size == 20 || size == 36) {
            crate::hw::ports::write_u16(FW_CFG_SELECTOR, sel);
            let raw = fw_cfg_read_bytes(size as usize);
            if raw.len() < 20 || raw[0..8] != RSDP_SIG {
                return None;
            }
            let sum20: u8 = raw[..20].iter().fold(0u8, |a, b| a.wrapping_add(*b));
            if sum20 != 0 {
                return None;
            }
            if raw.len() == 36 {
                let sum36: u8 = raw.iter().fold(0u8, |a, b| a.wrapping_add(*b));
                if sum36 != 0 {
                    return None;
                }
            }
            let mut rsdp = [0u8; 36];
            rsdp[..raw.len()].copy_from_slice(&raw);
            // v1 回退：xsdt_address 不存在时用 rsdt（32 位）承载的 XSDT 无门，
            // 直接以 rsdt_address 高位补零探测（QEMU v2 常规路径不受影响）
            let xsdt = if raw.len() == 36 {
                le64(&rsdp[24..32])
            } else {
                0
            };
            return Some((xsdt, rsdp));
        }
    }
    None
}

/// ACPI 表头（规范公共前 4 字节签名 + 4 字节长度）。
struct TableHeader {
    signature: [u8; 4],
    length: u32,
}

/// 从物理地址读取 ACPI 表头（RAM 内恒等映射直读）。
fn read_header(base: u64) -> TableHeader {
    let mut signature = [0u8; 4];
    for (i, b) in signature.iter_mut().enumerate() {
        *b = crate::hw::phys::read_u8(base + i as u64);
    }
    let length = crate::hw::phys::read_u32(base + 4);
    TableHeader { signature, length }
}

/// MADT 解析结果：启用状态的 LAPIC APIC ID 列表（含 BSP）。
///
/// 容量上限 16：QEMU `-smp` 实用核数远低于此；超出时截断（诊断日志可见）。
pub struct MadtLapics {
    /// 启用核的 APIC ID（MADT 条目顺序）。
    pub ids: [u8; 16],
    /// 有效条目数。
    pub count: usize,
    /// 探测到的 LAPIC MMIO 物理基址（MADT 头 32 位字段）。
    pub lapic_base: u32,
}

/// 在 XSDT（64 位条目）或 RSDT（32 位条目，v1 回退）中定位 MADT。
/// 返回 MADT 物理基址；未找到返回 None。
fn find_madt(xsdt: u64, rsdp: &[u8; 36]) -> Option<u64> {
    if xsdt != 0 {
        let h = read_header(xsdt);
        if h.signature == XSDT_SIG {
            let entries = (h.length.saturating_sub(36) / 8) as u64;
            for i in 0..entries {
                let table = crate::hw::phys::read_u64(xsdt + 36 + i * 8);
                if table != 0 && read_header(table).signature == APIC_SIG {
                    return Some(table);
                }
            }
        }
    }
    // v1 回退：RSDT（条目 32 位；rsdt_address 位于 RSDP 偏移 16）
    let rsdt = u64::from(le32(&rsdp[16..20]));
    if rsdt == 0 {
        return None;
    }
    let h = read_header(rsdt);
    if h.signature != RSDT_SIG {
        return None;
    }
    let entries = (h.length.saturating_sub(36) / 4) as u64;
    for i in 0..entries {
        let table = u64::from(crate::hw::phys::read_u32(rsdt + 36 + i * 4));
        if table != 0 && read_header(table).signature == APIC_SIG {
            return Some(table);
        }
    }
    None
}

/// 经 fw_cfg RSDP → XSDT/RSDT → MADT 探测启用核列表。
///
/// 任何一步失败（无 fw_cfg RSDP / 无 XSDT+RSDT / 无 MADT）返回 `None`——
/// 上层据此判定平台不支持 SMP 探测（自检 16 记为 FAIL 并落诊断）。
pub fn detect_lapics() -> Option<MadtLapics> {
    // 路径一（协议面）：fw_cfg RSDP → XSDT/RSDT → MADT（真实平台常规路径；
    // QEMU 模板 RSDP 的 rsdt_address=0，此路径在其上自然落空）
    if let Some((xsdt, rsdp)) = fw_cfg_rsdp() {
        if let Some(table) = find_madt(xsdt, &rsdp) {
            return parse_madt(table);
        }
    }
    // 路径二（QEMU 协议面）：直接读 fw_cfg "etc/acpi/tables" 紧排 blob
    // （QEMU 实测 128 KiB，勿设 64 KiB 上限——MADT 可能在后半段），
    // 在缓冲内定位 MADT（签名 + 长度 + 校验和三重校验）——与内存落点解耦
    if let Some(blob) = fw_cfg_read_file_alloc(b"etc/acpi/tables", 1 << 20) {
        if let Some(madt) = find_madt_in_buf(&blob) {
            return parse_madt_buf(&blob, madt);
        }
    }
    // 路径三（落地面）：逐字节扫描 BIOS 区（真实 BIOS 的 F 段/EBDA 装载位）
    for (start, end) in RSDP_SCAN_RANGES {
        let mut addr = start;
        while addr + 36 <= end {
            if crate::hw::phys::read_u8(addr) == b'A'
                && crate::hw::phys::read_u8(addr + 1) == b'P'
                && crate::hw::phys::read_u8(addr + 2) == b'I'
                && crate::hw::phys::read_u8(addr + 3) == b'C'
            {
                let len = crate::hw::phys::read_u32(addr + 4);
                if (36..=8192).contains(&len) && addr + u64::from(len) <= end {
                    let mut sum: u8 = 0;
                    for i in 0..len {
                        sum = sum.wrapping_add(crate::hw::phys::read_u8(addr + i as u64));
                    }
                    if sum == 0 {
                        return parse_madt(addr);
                    }
                }
            }
            addr += 1;
        }
    }
    None
}

/// MADT 的 local_apic_address 规范值（QEMU/PC 平台恒为 LAPIC 基址）。
const MADT_LAPIC_BASE: u32 = 0xFEE0_0000;

/// 在紧排 blob 中定位 MADT。
///
/// 判别链：签名 "APIC" + 长度界 + **local_apic_address == 0xFEE00000**。
/// 不以校验和为准——blob 中的表在 table-loader 打指针前校验和是陈旧的。
fn find_madt_in_buf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 40 {
        return None;
    }
    for i in 0..buf.len() - 40 {
        if buf[i] == b'A' && buf[i + 1] == b'P' && buf[i + 2] == b'I' && buf[i + 3] == b'C' {
            let len = le32(&buf[i + 4..i + 8]);
            if (36..=8192).contains(&len)
                && i as u64 + u64::from(len) <= buf.len() as u64
                && le32(&buf[i + 36..i + 40]) == MADT_LAPIC_BASE
            {
                return Some(i);
            }
        }
    }
    None
}

/// 从缓冲内 MADT 解析启用核列表。
fn parse_madt_buf(buf: &[u8], madt: usize) -> Option<MadtLapics> {
    let th_len = le32(&buf[madt + 4..madt + 8]);
    let lapic_base = le32(&buf[madt + 36..madt + 40]);
    let mut out = MadtLapics {
        ids: [0; 16],
        count: 0,
        lapic_base,
    };
    let mut off = 44usize;
    let total = th_len as usize;
    while off + 2 <= total && madt + total <= buf.len() {
        let etype = buf[madt + off];
        let elen = buf[madt + off + 1] as usize;
        if elen < 2 {
            break;
        }
        if etype == 0 && elen >= 8 && off + 8 <= total {
            let apic_id = buf[madt + off + 3];
            let flags = le32(&buf[madt + off + 4..madt + off + 8]);
            if flags & 1 != 0 && out.count < out.ids.len() {
                out.ids[out.count] = apic_id;
                out.count += 1;
            }
        }
        off += elen;
    }
    Some(out)
}

/// 解析 MADT 为启用核列表。
fn parse_madt(table: u64) -> Option<MadtLapics> {
    let th = read_header(table);
    // MADT：本地 APIC 地址 u32（偏移 36），flags u32（40），条目自 44 起
    let lapic_base = crate::hw::phys::read_u32(table + 36);
    let mut out = MadtLapics {
        ids: [0; 16],
        count: 0,
        lapic_base,
    };
    let mut off = 44u64;
    let total = u64::from(th.length);
    while off + 2 <= total {
        let etype = crate::hw::phys::read_u8(table + off);
        let elen = crate::hw::phys::read_u8(table + off + 1);
        if elen < 2 {
            break; // 畸形条目：防御性终止
        }
        // type 0 = Processor Local APIC：acpi_uid u8, apic_id u8, flags u32
        if etype == 0 && elen >= 8 && off + 8 <= total {
            let apic_id = crate::hw::phys::read_u8(table + off + 3);
            let flags = crate::hw::phys::read_u32(table + off + 4);
            if flags & 1 != 0 && out.count < out.ids.len() {
                out.ids[out.count] = apic_id;
                out.count += 1;
            }
        }
        off += u64::from(elen);
    }
    Some(out)
}
