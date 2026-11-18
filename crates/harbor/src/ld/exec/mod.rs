//! harbor::ld::exec —— 动态链接机械执行面 v0（M46-LDEXEC49 笔55，
//! ld-lumina.so 交付批）。
//!
//! 承接 [`crate::ld`] v0 语义核判读族（M45-HARBOR48 笔53）挂账机械执行
//! 面：ELF 装载与映射 / 重定位写面 / static TLS 块布点 / .init_array
//! /.fini_array 初始化执行 / dlopen/dlsym/dlclose/dlerror 族外壳 /
//! H-P03 四段打点。本模块为 **v0 机械执行语义核**：全部纯函数、宿主可
//! 测、crate 级 `forbid(unsafe_code)` 不破（零 unsafe 零 panic 路径——
//! 切片定界 + 定容上限 + fail-visible 全显形）；装载计划消费面（ring3
//! mmap/mprotect 电气域）随用户态链接面成形批次落域，如实挂账不变。
//!
//! # 机械执行面域谱
//!
//! - **ET_DYN 结构判读面** [`dyn_parse`]：ELF64 ET_DYN 共享对象结构校验
//!   （魔数→位宽→端序→版本→类型→机器→phentsize→头表自洽→PT_LOAD/PT_TLS/
//!   PT_DYNAMIC 三族收取→同余式→页槽互斥→动态表收取——`bedrock::elf`
//!   静态口径同款防线序，e_type 改收 ET_DYN）；
//! - **装载映射计划面** [`load_plan`]：base 相对 PT_LOAD → 页对齐
//!   [`MapRegion`] 计划（相邻同权并区、跨权并权——Linux 装载器共享页
//!   mprotect 并权语义）+ [`stage_image`] 分级缓冲（filesz 拷贝 +
//!   memsz 尾零——BSS 语义）；
//! - **GNU 式符号查找机械面** [`gnu_hash_lookup`]：DT_GNU_HASH 头
//!   （nbuckets/symoffset/bloom_size/bloom_shift）+ gABI bloom 双位
//!   布局（word = (h/64)%size、bit = h%64 与 (h>>shift)%64——机械
//!   布局；`crate::ld::BloomPanel` v0 判读面板为语义面板，布局口径
//!   分立如实登记）+ 桶链走查（链值低位 1 = 链尾旗）+ strtab 名比
//!   对（`crate::ld::dl_new_hash` 同源哈希）；
//! - **重定位写面** [`reloc_apply`]：R_X86_64 家族四类执行
//!   （RELATIVE = base+addend 直写 / GLOB_DAT·JUMP_SLOT = 决议值直写
//!   / JUMP_SLOT × !bind_now = 惰性跳过并记账——PLT/GOT 延迟绑定 /
//!   COPY = 源对象字节搬运）——越界/未决议 fail-visible；
//! - **TLS 布点面** [`TlsSpace`]：x86_64 Variant II（TCB 前置——模块 1
//!   布点 tp 前域，后继模块 surplus 上域递增布点）+ DTV 扩容判读
//!   （`crate::ld::dtv_needs_resize` 同源）；
//! - **初始化执行序面** [`init_order`] / [`fini_order`]：依赖先序
//!   init（DT_INIT → .init_array 正向）/ 逆序 fini（.fini_array 反向
//!   → DT_FINI）——装载序逆序展开；
//! - **dlopen 族外壳** [`DlState`]：注册表 refcount + RTLD_GLOBAL
//!   插入序 + [`DlState::dlsym`] 查找序三段复用（`crate::ld::scope_lookup`）
//!   + [`DlState::dlerror`] 一次性消费语义（POSIX dlerror 口径）；
//! - **dlopen 真消费面** [`ChainRegistry`] / [`dl_adjacency`] /
//!   [`dl_chain_order`] / [`dl_open_chain`]（M47-DLOPEN54 笔61——
//!   dlopen 族外壳 `present` 布尔挂账域兑现）：链式装载注册表
//!   （SONAME → 映像字节）+ 依赖闭包邻接派生（DT_NEEDED 声明域走查
//!   ∪ UNDEF 决议闭包 as-needed 派生）+ DT_NEEDED 装载序
//!   （`crate::ld::needed_load_order` BFS 语义核机械消费 + 三色环
//!   判读）+ dlopen 族真消费链（群组插序 + 幂等域 + error 槽）；
//! - **H-P03 四段打点面** [`ns_to_tenths`]：纳秒实测 → 0.1 ms 定点
//!   上取整（预算判读归 `crate::ld::{budget_overruns, budget_total_ok}`
//!   同源）；
//! - **ld-lumina.so 交付面** [`auxv_probe`]：动态链接器入口契约
//!   （AT_PHDR/AT_PHENT/AT_PHNUM/AT_BASE/AT_ENTRY 五目——缺失任一
//!   必需目 None fail-visible）+ [`LD_LUMINA_SONAME`] / [`LD_LUMINA_ABI`]
//!   交付常量。

use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use super::{
    budget_overruns, budget_total_ok, dl_new_hash, dtv_needs_resize, scope_lookup, ScopeHit,
};

// ---- ld-lumina.so 交付面常量（M46-LDEXEC49 交付批） ----

/// ld-lumina.so 交付件名（H-P03 权威条款——动态链接器本体口径）。
pub const LD_LUMINA_SONAME: &str = "ld-lumina.so";
/// ld-lumina.so 交付面 ABI 序 v0 = 1（机械执行语义核交付批次铸号；
/// 后继交付批次随装载计划消费面递增）。
pub const LD_LUMINA_ABI: u32 = 1;

// ---- ET_DYN 结构常量（ELF64 gABI——bedrock::elf 静态口径同款域） ----

/// e_type：共享对象（动态链接——ld-lumina.so 口径本体）。
pub const ET_DYN: u16 = 3;
/// 程序头类型：可装载段。
pub const PT_LOAD: u32 = 1;
/// 程序头类型：动态段。
pub const PT_DYNAMIC: u32 = 2;
/// 程序头类型：TLS 模板段。
pub const PT_TLS: u32 = 7;
/// ELF 头长度（64 位）。
pub const EHDR_LEN: usize = 64;
/// 程序头长度（64 位）。
pub const PHDR_LEN: usize = 56;
/// 页粒度。
pub const PAGE: u64 = 0x1000;
/// PT_LOAD 段上限（bedrock::elf ELF_MAX_LOADS 同谱）。
pub const MAX_LOADS: usize = 16;
/// 动态表条目上限（定容 fail-visible——无界扫描禁令）。
pub const DYN_MAX_ENTRIES: usize = 64;
/// RELA 条目上限（定容 fail-visible）。
pub const RELA_MAX: usize = 4096;
/// 分级缓冲跨度上限（16 MiB——宿主/内核活体双域预算闸）。
pub const SPAN_MAX: u64 = 16 * 1024 * 1024;
/// 符号链走查步上限（定容 fail-visible——坏链环禁令）。
pub const CHAIN_MAX: usize = 4096;

// ---- DT_* 动态表标目（gABI 数值权威） ----

/// DT_NULL：动态表收尾哨。
pub const DT_NULL: u64 = 0;
/// DT_NEEDED：依赖库名 strtab 偏移。
pub const DT_NEEDED: u64 = 1;
/// DT_STRTAB：字符串表虚地址。
pub const DT_STRTAB: u64 = 5;
/// DT_SYMTAB：符号表虚地址。
pub const DT_SYMTAB: u64 = 6;
/// DT_RELA：重定位表虚地址。
pub const DT_RELA: u64 = 7;
/// DT_RELASZ：重定位表总字节。
pub const DT_RELASZ: u64 = 8;
/// DT_RELAENT：重定位条目字节（24）。
pub const DT_RELAENT: u64 = 9;
/// DT_STRSZ：字符串表总字节。
pub const DT_STRSZ: u64 = 10;
/// DT_SYMENT：符号条目字节（24）。
pub const DT_SYMENT: u64 = 11;
/// DT_INIT：初始化函数虚地址。
pub const DT_INIT: u64 = 12;
/// DT_FINI：终结函数虚地址。
pub const DT_FINI: u64 = 13;
/// DT_SONAME：本对象名 strtab 偏移。
pub const DT_SONAME: u64 = 14;
/// DT_JMPREL：PLT 重定位表虚地址。
pub const DT_JMPREL: u64 = 23;
/// DT_BIND_NOW：立即绑定标（无条件）。
pub const DT_BIND_NOW: u64 = 24;
/// DT_INIT_ARRAY：初始化数组虚地址。
pub const DT_INIT_ARRAY: u64 = 25;
/// DT_FINI_ARRAY：终结数组虚地址。
pub const DT_FINI_ARRAY: u64 = 26;
/// DT_INIT_ARRAYSZ：初始化数组字节。
pub const DT_INIT_ARRAYSZ: u64 = 27;
/// DT_FINI_ARRAYSZ：终结数组字节。
pub const DT_FINI_ARRAYSZ: u64 = 28;
/// DT_FLAGS：位旗。
pub const DT_FLAGS: u64 = 30;
/// DT_GNU_HASH：GNU 式符号哈希表虚地址。
pub const DT_GNU_HASH: u64 = 0x6FFF_FEF5;
/// DF_BIND_NOW：DT_FLAGS 立即绑定位。
pub const DF_BIND_NOW: u64 = 0x8;
/// DF_STATIC_TLS：静态 TLS 位（dlopen 迟绑拒收语义位——判读面）。
pub const DF_STATIC_TLS: u64 = 0x10;

// ---- AT_* 动态链接器入口契约目（System V AMD64 ABI） ----

const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_NULL: u64 = 0;

// ---- R_X86_64 重定位家族（gABI 数值——crate::ld reloc_kind_of 同源） ----

/// R_X86_64_COPY。
pub const R_X86_64_COPY: u32 = 5;
/// R_X86_64_GLOB_DAT。
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// R_X86_64_JUMP_SLOT。
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// R_X86_64_RELATIVE。
pub const R_X86_64_RELATIVE: u32 = 8;

/// 机械执行面错误（fail-visible 全显形——零 panic 零默认成像）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdExecError {
    /// 魔数不符。
    BadMagic,
    /// 非 ELFCLASS64。
    BadClass,
    /// 非小端。
    BadData,
    /// 非 EV_CURRENT。
    BadVersion,
    /// 非 ET_DYN（ET_EXEC/ET_REL 拒收——动态口径）。
    BadType,
    /// 非 EM_X86_64。
    BadMachine,
    /// e_phentsize ≠ 56。
    BadPhentsize,
    /// blob 截断（头/程序头表/段载荷/动态表/重定位表不完整）。
    Truncated,
    /// PT_LOAD 数超上限（[`MAX_LOADS`]）或为 0。
    TooManyLoads,
    /// 段不一致（memsz < filesz / 同余式违背 / 页槽交叠）。
    BadSeg,
    /// PT_DYNAMIC 缺席（动态链接口径必需）。
    NoDynamic,
    /// 动态表条目超上限（[`DYN_MAX_ENTRIES`]）。
    DynTooMany,
    /// RELA 条目超上限（[`RELA_MAX`]）或 DT_RELAENT ≠ 24。
    BadRela,
    /// 分级缓冲跨度超上限（[`SPAN_MAX`]）。
    SpanTooLarge,
    /// 重定位写目标越出分级缓冲。
    RelocTargetRange,
    /// 未决议符号（GLOB_DAT / bind_now JUMP_SLOT / COPY 域）。
    UndefinedSymbol,
    /// COPY 源对象缺席。
    CopySourceMissing,
    /// TLS 对齐非 2 幂或为零。
    BadTlsAlign,
    /// 模块铸号越界（0 号非铸号域——DTV 1 基口径）。
    BadModid,
    /// 计划面下标越出表长（init/fini 展开域）。
    FaceOutOfRange,
    /// 依赖闭包缺件（DT_NEEDED 名 / dlopen 根名注册表缺席——真消费面）。
    NeededMissing,
    /// 依赖环（DT_NEEDED 环——`crate::ld::needs_cycle` 三色判读）。
    NeededCycle,
    /// 注册表域越界（root 下标越界 / 定容超限 / 重名登记——真消费面输入域）。
    RegistryRange,
    /// 惰性槽未接线（resolver 步命中未 wire 槽——PLT/GOT 惰性绑定域）。
    LazyUnbound,
    /// 惰性槽号越界（JUMP_SLOT 相对号越出 [`LAZY_SLOT_CAP`]——resolver
    /// 越界拒收）。
    LazySlotRange,
}

/// 单个 PT_LOAD 段描述（ET_DYN 解析产物——文件偏移保持原值，装载基址
/// 相对语义由消费面补全）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSeg {
    /// 段载荷文件偏移。
    pub offset: u64,
    /// 段虚地址（装载基址相对）。
    pub vaddr: u64,
    /// 文件映像长度。
    pub file_len: u64,
    /// 内存映像长度（> file_len 尾零——BSS 语义）。
    pub mem_len: u64,
    /// p_flags（PF_X/PF_W/PF_R 位或）。
    pub flags: u32,
}

/// PT_TLS 模板段描述。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsSeg {
    /// 模板内存长度（.tdata + .tbss）。
    pub mem_len: u64,
    /// 模板对齐（2 幂——布局面校验）。
    pub align: u64,
}

/// ET_DYN 解析产物：结构字段 + 动态表 + 段族。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynImage<'a> {
    /// 入口虚地址（装载基址相对）。
    pub entry: u64,
    /// PT_LOAD 段族（0..load_count 有效）。
    pub loads: [LoadSeg; MAX_LOADS],
    /// 有效 PT_LOAD 数。
    pub load_count: usize,
    /// PT_TLS 模板（缺席 None）。
    pub tls: Option<TlsSeg>,
    /// 动态表条目（(tag, val) 对——DT_NULL 收尾已截）。
    pub dyn_entries: Vec<(u64, u64)>,
    /// PT_DYNAMIC 文件偏移（动态表收取域锚）。
    pub dyn_file_off: usize,
    /// 源 blob。
    blob: &'a [u8],
}

impl<'a> DynImage<'a> {
    /// 动态表标目取值（首个同名标目——gABI 单标目域；缺席 None）。
    pub fn dyn_val(&self, tag: u64) -> Option<u64> {
        self.dyn_entries
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| *v)
    }

    /// 立即绑定判读（DT_FLAGS DF_BIND_NOW 位 ∨ DT_BIND_NOW 标——双域
    /// 任一真即 bind_now）。
    pub fn bind_now(&self) -> bool {
        self.dyn_val(DT_FLAGS)
            .map(|f| f & DF_BIND_NOW != 0)
            .unwrap_or(false)
            || self.dyn_val(DT_BIND_NOW).is_some()
    }

    /// 静态 TLS 旗判读（DF_STATIC_TLS——dlopen 迟绑拒收语义位）。
    pub fn static_tls(&self) -> bool {
        self.dyn_val(DT_FLAGS)
            .map(|f| f & DF_STATIC_TLS != 0)
            .unwrap_or(false)
    }

    /// DT_NEEDED 名偏移族（声明序——装载序面输入）。
    pub fn needed(&self) -> Vec<u64> {
        self.dyn_entries
            .iter()
            .filter(|(t, _)| *t == DT_NEEDED)
            .map(|(_, v)| *v)
            .collect()
    }

    /// 虚地址 → 文件偏移（PT_LOAD 覆盖域翻译；越域 None fail-visible）。
    pub fn vaddr_to_file_off(&self, vaddr: u64) -> Option<usize> {
        for ld in self.loads.iter().take(self.load_count) {
            if vaddr >= ld.vaddr && vaddr < ld.vaddr + ld.mem_len {
                let delta = vaddr - ld.vaddr;
                let off = ld.offset + delta;
                return Some(off as usize);
            }
        }
        None
    }

    /// 文件偏移读 u64（越界 None）。
    pub fn rd_u64_at(&self, file_off: usize) -> Option<u64> {
        let s = self.blob.get(file_off..file_off + 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }

    /// strtab NUL 串读（`strtab_vaddr` 表基虚地址 + `off` 名偏移；
    /// DT_STRSZ 界内 NUL 收尾——无 NUL fail-visible）。
    pub fn str_at(&self, strtab_vaddr: u64, off: u64) -> Option<&'a [u8]> {
        let base = self.vaddr_to_file_off(strtab_vaddr)?;
        let strsz = self.dyn_val(DT_STRSZ).unwrap_or(0) as usize;
        let start = base + off as usize;
        let window = self.blob.get(start..start + strsz)?;
        let end = window.iter().position(|&b| b == 0)?;
        Some(&window[..end])
    }

    /// ELF64 符号读（st_name/st_value/st_size——STN_UNDEF 原值透传）。
    pub fn sym_get(&self, symtab_vaddr: u64, idx: u64) -> Option<(u32, u64, u64)> {
        let ent = self.dyn_val(DT_SYMENT).unwrap_or(24);
        if ent != 24 {
            return None;
        }
        let off = self.vaddr_to_file_off(symtab_vaddr)? + (idx as usize) * 24;
        let name = u32::from_le_bytes(self.blob.get(off..off + 4)?.try_into().ok()?);
        let value = self.rd_u64_at(off + 8)?;
        let size = self.rd_u64_at(off + 16)?;
        Some((name, value, size))
    }
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// ET_DYN 结构判读（防线序与 `bedrock::elf::parse` 静态口径同款：
/// 魔数 → 位宽 → 端序 → 版本 → 类型〔ET_DYN〕→ 机器 → phentsize →
/// 头表自洽 → 三族程序头收取 → 同余式 → 页槽互斥 → 动态表收取）。
pub fn dyn_parse(blob: &[u8]) -> Result<DynImage<'_>, LdExecError> {
    if blob.len() < EHDR_LEN {
        return Err(LdExecError::Truncated);
    }
    if blob[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(LdExecError::BadMagic);
    }
    if blob[4] != 2 {
        return Err(LdExecError::BadClass);
    }
    if blob[5] != 1 {
        return Err(LdExecError::BadData);
    }
    if blob[6] != 1 {
        return Err(LdExecError::BadVersion);
    }
    let e_type = rd_u16(blob, 0x10).ok_or(LdExecError::Truncated)?;
    if e_type != ET_DYN {
        return Err(LdExecError::BadType);
    }
    let e_machine = rd_u16(blob, 0x12).ok_or(LdExecError::Truncated)?;
    if e_machine != 62 {
        return Err(LdExecError::BadMachine);
    }
    let entry = rd_u64(blob, 0x18).ok_or(LdExecError::Truncated)?;
    let phoff = rd_u64(blob, 0x20).ok_or(LdExecError::Truncated)?;
    let phentsize = rd_u16(blob, 0x36).ok_or(LdExecError::Truncated)?;
    let phnum = rd_u16(blob, 0x38).ok_or(LdExecError::Truncated)?;
    if phentsize as usize != PHDR_LEN {
        return Err(LdExecError::BadPhentsize);
    }
    let phnum = phnum as usize;
    if phnum == 0 || (phoff as usize) < EHDR_LEN {
        return Err(LdExecError::BadSeg);
    }
    let table_end = phoff as usize + phnum * PHDR_LEN;
    if table_end > blob.len() {
        return Err(LdExecError::Truncated);
    }
    let mut loads = [LoadSeg {
        offset: 0,
        vaddr: 0,
        file_len: 0,
        mem_len: 0,
        flags: 0,
    }; MAX_LOADS];
    let mut load_count = 0usize;
    let mut tls = None;
    let mut dyn_off = None;
    let mut dyn_sz = 0u64;
    for k in 0..phnum {
        let base = phoff as usize + k * PHDR_LEN;
        let p_type = rd_u32(blob, base).ok_or(LdExecError::Truncated)?;
        let p_flags = rd_u32(blob, base + 0x04).ok_or(LdExecError::Truncated)?;
        let p_offset = rd_u64(blob, base + 0x08).ok_or(LdExecError::Truncated)?;
        let p_vaddr = rd_u64(blob, base + 0x10).ok_or(LdExecError::Truncated)?;
        let p_filesz = rd_u64(blob, base + 0x20).ok_or(LdExecError::Truncated)?;
        let p_memsz = rd_u64(blob, base + 0x28).ok_or(LdExecError::Truncated)?;
        match p_type {
            PT_TLS => {
                tls = Some(TlsSeg {
                    mem_len: p_memsz,
                    align: rd_u64(blob, base + 0x30).ok_or(LdExecError::Truncated)?,
                });
            }
            PT_DYNAMIC => {
                dyn_off = Some(p_offset);
                dyn_sz = p_filesz;
            }
            PT_LOAD => {
                let off = p_offset as usize;
                let len = p_filesz as usize;
                if off + len > blob.len() {
                    return Err(LdExecError::Truncated);
                }
                if p_memsz < p_filesz {
                    return Err(LdExecError::BadSeg);
                }
                if (p_vaddr % PAGE) != (p_offset % PAGE) {
                    return Err(LdExecError::BadSeg);
                }
                if load_count >= MAX_LOADS {
                    return Err(LdExecError::TooManyLoads);
                }
                loads[load_count] = LoadSeg {
                    offset: p_offset,
                    vaddr: p_vaddr,
                    file_len: p_filesz,
                    mem_len: p_memsz,
                    flags: p_flags,
                };
                load_count += 1;
            }
            _ => {}
        }
    }
    if load_count == 0 {
        return Err(LdExecError::TooManyLoads);
    }
    // 页槽互斥（段间页区间零交——bedrock::elf 同款 O(n²) 口径）。
    for i in 0..load_count {
        for j in 0..i {
            let a = &loads[i];
            let b = &loads[j];
            let a_lo = a.vaddr / PAGE;
            let a_hi = (a.vaddr + a.mem_len).div_ceil(PAGE);
            let b_lo = b.vaddr / PAGE;
            let b_hi = (b.vaddr + b.mem_len).div_ceil(PAGE);
            if a_lo < b_hi && b_lo < a_hi {
                return Err(LdExecError::BadSeg);
            }
        }
    }
    // 动态表收取（PT_DYNAMIC 缺席 fail-visible——动态口径必需）。
    let dyn_file_off = dyn_off.ok_or(LdExecError::NoDynamic)? as usize;
    let dyn_end = dyn_file_off + dyn_sz as usize;
    if dyn_end > blob.len() {
        return Err(LdExecError::Truncated);
    }
    let mut dyn_entries = Vec::new();
    let mut cur = dyn_file_off;
    while cur + 16 <= dyn_end {
        let tag = rd_u64(blob, cur).ok_or(LdExecError::Truncated)?;
        let val = rd_u64(blob, cur + 8).ok_or(LdExecError::Truncated)?;
        cur += 16;
        if tag == DT_NULL {
            break;
        }
        if dyn_entries.len() >= DYN_MAX_ENTRIES {
            return Err(LdExecError::DynTooMany);
        }
        dyn_entries.push((tag, val));
    }
    Ok(DynImage {
        entry,
        loads,
        load_count,
        tls,
        dyn_entries,
        dyn_file_off,
        blob,
    })
}

/// 页对齐映射计划区（装载基址相对——绝对化 = base + va_start/va_end）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRegion {
    /// 区起点（页对齐）。
    pub va_start: u64,
    /// 区终点（页对齐、开区间）。
    pub va_end: u64,
    /// 并权位集（PF_X/PF_W/PF_R——共享页 mprotect 并权语义）。
    pub flags: u32,
}

/// 装载映射计划面（`base` 相对 PT_LOAD → 页对齐区族）：逐段页区间
/// 展开 → 按起点排序 → 相邻重叠区并权合并（共享页 mprotect 并权
/// 语义——区间零交且同权才保留独立区）；区数超 32 fail-visible
/// （定容禁令）。绝对化由消费面（mmap/mprotect 电气域挂账面）承接。
pub fn load_plan(base: u64, img: &DynImage<'_>) -> Result<Vec<MapRegion>, LdExecError> {
    let mut raw: Vec<MapRegion> = Vec::new();
    for ld in img.loads.iter().take(img.load_count) {
        let lo = (base + ld.vaddr) & !0xFFF;
        let hi = (base + ld.vaddr + ld.mem_len).div_ceil(PAGE) * PAGE;
        raw.push(MapRegion {
            va_start: lo,
            va_end: hi,
            flags: ld.flags,
        });
    }
    raw.sort_by_key(|r| (r.va_start, r.va_end));
    let mut merged: Vec<MapRegion> = Vec::new();
    for r in raw {
        if let Some(last) = merged.last_mut() {
            if r.va_start < last.va_end {
                // 重叠/贴邻：并权合并（起点即 last 起点——排序保证）
                last.va_end = last.va_end.max(r.va_end);
                last.flags |= r.flags;
                continue;
            }
        }
        merged.push(r);
    }
    if merged.len() > 32 {
        return Err(LdExecError::TooManyLoads);
    }
    Ok(merged)
}

/// 分级缓冲分级产物（镜像基址 + 字节面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedImage {
    /// 镜像覆盖基址（= 装载基址 + 最小段 vaddr 页对齐落点）。
    pub base: u64,
    /// 镜像字节面（va = base + 索引；BSS 尾零已铺）。
    pub bytes: Vec<u8>,
}

/// 分级缓冲（装载基址 `base` + PT_LOAD 族 → 连续字节面镜像）：
/// 跨度 = [min vaddr 页对齐落点, max (vaddr+memsz) 页上取整)——超
/// [`SPAN_MAX`] fail-visible；filesz 拷贝 + memsz 尾零（BSS 语义）。
/// 相对 vaddr 寻址：`va - base` 落索引。
pub fn stage_image(base: u64, img: &DynImage<'_>) -> Result<StagedImage, LdExecError> {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for ld in img.loads.iter().take(img.load_count) {
        lo = lo.min(base + ld.vaddr);
        hi = hi.max(base + ld.vaddr + ld.mem_len);
    }
    let lo = lo & !0xFFF;
    let hi = hi.div_ceil(PAGE) * PAGE;
    if hi < lo {
        return Err(LdExecError::BadSeg);
    }
    if hi - lo > SPAN_MAX {
        return Err(LdExecError::SpanTooLarge);
    }
    let mut bytes = vec![0u8; (hi - lo) as usize];
    for ld in img.loads.iter().take(img.load_count) {
        let off = (base + ld.vaddr - lo) as usize;
        let len = ld.file_len as usize;
        let src = img
            .blob
            .get(ld.offset as usize..(ld.offset + ld.file_len) as usize)
            .ok_or(LdExecError::Truncated)?;
        bytes[off..off + len].copy_from_slice(src);
        // mem_len > file_len 尾零已由全零底铺（BSS 语义——零写面）。
        let _ = ld.mem_len;
    }
    Ok(StagedImage { base: lo, bytes })
}

/// RELA 条目（gABI 24 字节——r_info 高 32 位符号号 / 低 32 位类型码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaEntry {
    /// 写目标虚地址（装载基址相对）。
    pub r_offset: u64,
    /// 符号号（高 32 位）。
    pub r_sym: u32,
    /// 类型码（低 32 位）。
    pub r_type: u32,
    /// 加数。
    pub r_addend: i64,
}

/// RELA 表收取（DT_RELA 虚地址 + DT_RELASZ——DT_RELAENT ≠ 24 fail-
/// visible；条目数超 [`RELA_MAX`] fail-visible）。
pub fn rela_entries(img: &DynImage<'_>) -> Result<Vec<RelaEntry>, LdExecError> {
    let ent = img.dyn_val(DT_RELAENT).unwrap_or(24);
    if ent != 24 {
        return Err(LdExecError::BadRela);
    }
    let rela_va = match img.dyn_val(DT_RELA) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let sz = img.dyn_val(DT_RELASZ).unwrap_or(0) as usize;
    let off = img.vaddr_to_file_off(rela_va).ok_or(LdExecError::BadSeg)?;
    let n = sz / 24;
    if n > RELA_MAX {
        return Err(LdExecError::BadRela);
    }
    let mut out = Vec::new();
    for k in 0..n {
        let base = off + k * 24;
        let r_offset = img.rd_u64_at(base).ok_or(LdExecError::Truncated)?;
        let r_info = img.rd_u64_at(base + 8).ok_or(LdExecError::Truncated)?;
        let r_addend = img.rd_u64_at(base + 16).ok_or(LdExecError::Truncated)?;
        out.push(RelaEntry {
            r_offset,
            r_sym: (r_info >> 32) as u32,
            r_type: (r_info & 0xFFFF_FFFF) as u32,
            r_addend: r_addend as i64,
        });
    }
    Ok(out)
}

/// 重定位执行环境（决议值族 + COPY 源域 + bind_now 语义位——零闭包
/// 零回调纯数据面）。
pub struct RelocEnv<'a> {
    /// 逐符号决议值（下标 = 符号号；None = 未决议——惰性跳过或
    /// UndefinedSymbol 显形）。
    pub resolved: &'a [Option<u64>],
    /// 逐符号长度（COPY 字节搬运长度域）。
    pub sym_sizes: &'a [u64],
    /// COPY 源镜像字节面（None = COPY 源缺席）。
    pub src_image: Option<&'a [u8]>,
    /// COPY 源镜像基址（决议值 - 基址 = 源索引）。
    pub src_base: u64,
    /// 立即绑定语义位（DT_FLAGS DF_BIND_NOW ∨ DT_BIND_NOW 判读值——
    /// [`DynImage::bind_now`] 同源）。
    pub bind_now_gate: bool,
}

/// 重定位执行报告（四类记账——t147 RELOC 行字段域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelocReport {
    /// RELATIVE 直写数。
    pub relative: usize,
    /// GLOB_DAT 直写数。
    pub glob_dat: usize,
    /// JUMP_SLOT 立即写数（bind_now 或已决议）。
    pub jump_slot: usize,
    /// JUMP_SLOT 惰性跳过数（!bind_now × 未决议——PLT/GOT 延迟绑定）。
    pub jump_lazy: usize,
    /// COPY 搬运数。
    pub copy: usize,
}

/// 重定位写面（镜像 + RELA 族 + 环境 → 逐条执行）：RELATIVE =
/// base+r_offset 处写 base+addend；GLOB_DAT/JUMP_SLOT = 决议值直写
/// （未决议 × GLOB_DAT ∨ bind_now JUMP_SLOT = UndefinedSymbol；
/// !bind_now JUMP_SLOT × 未决议 = 惰性跳过记账）；COPY = 源镜像
/// sym 长度字节搬运。目标越界 fail-visible 零 panic。
pub fn reloc_apply(
    staged: &mut StagedImage,
    base: u64,
    entries: &[RelaEntry],
    env: &RelocEnv<'_>,
) -> Result<RelocReport, LdExecError> {
    let mut rep = RelocReport::default();
    for e in entries {
        let target = base + e.r_offset;
        let idx = (target - staged.base) as usize;
        let end = idx.checked_add(8).ok_or(LdExecError::RelocTargetRange)?;
        if end > staged.bytes.len() {
            return Err(LdExecError::RelocTargetRange);
        }
        match e.r_type {
            R_X86_64_RELATIVE => {
                staged.bytes[idx..end].copy_from_slice(&(base + e.r_addend as u64).to_le_bytes());
                rep.relative += 1;
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let jump = e.r_type == R_X86_64_JUMP_SLOT;
                let slot = e.r_sym as usize;
                match env.resolved.get(slot).copied().flatten() {
                    Some(addr) => {
                        staged.bytes[idx..end].copy_from_slice(&addr.to_le_bytes());
                        if jump {
                            rep.jump_slot += 1;
                        } else {
                            rep.glob_dat += 1;
                        }
                    }
                    None => {
                        if jump && !env.bind_now_gate {
                            rep.jump_lazy += 1; // PLT/GOT 延迟绑定——首调解析域
                        } else {
                            return Err(LdExecError::UndefinedSymbol);
                        }
                    }
                }
            }
            R_X86_64_COPY => {
                let slot = e.r_sym as usize;
                let len = *env
                    .sym_sizes
                    .get(slot)
                    .ok_or(LdExecError::UndefinedSymbol)? as usize;
                let addr = env
                    .resolved
                    .get(slot)
                    .copied()
                    .flatten()
                    .ok_or(LdExecError::UndefinedSymbol)?;
                let src = env.src_image.ok_or(LdExecError::CopySourceMissing)?;
                let sidx = (addr - env.src_base) as usize;
                let send = sidx.checked_add(len).ok_or(LdExecError::RelocTargetRange)?;
                let dend = idx.checked_add(len).ok_or(LdExecError::RelocTargetRange)?;
                if send > src.len() || dend > staged.bytes.len() {
                    return Err(LdExecError::RelocTargetRange);
                }
                staged.bytes[idx..dend].copy_from_slice(&src[sidx..send]);
                rep.copy += 1;
            }
            _ => return Err(LdExecError::UndefinedSymbol),
        }
    }
    Ok(rep)
}

// RelocEnv 补域（bind_now 语义位——构造点注入）。
impl<'a> RelocEnv<'a> {
    /// 构造（`bind_now` = DT_FLAGS DF_BIND_NOW ∨ DT_BIND_NOW 判读值
    /// ——`DynImage::bind_now` 同源）。
    pub fn new(resolved: &'a [Option<u64>], sym_sizes: &'a [u64], bind_now: bool) -> Self {
        Self {
            resolved,
            sym_sizes,
            src_image: None,
            src_base: 0,
            bind_now_gate: bind_now,
        }
    }
    /// COPY 源域注入（源镜像 + 基址）。
    pub fn with_copy_src(mut self, image: &'a [u8], base: u64) -> Self {
        self.src_image = Some(image);
        self.src_base = base;
        self
    }
}

/// GNU 式符号哈希查找机械面（DT_GNU_HASH）：gABI bloom 双位布局
/// （word = (h/64) % bloom_size、bit = h%64 ∨ (h>>shift)%64——双位齐
/// 置才可能命中）+ 桶链走查（链值低位 1 = 链尾旗）+ strtab 名比对。
/// 命中 = Some(符号号)；缺席 = None。步超 [`CHAIN_MAX`] fail-visible。
#[allow(clippy::explicit_counter_loop)]
pub fn gnu_hash_lookup(img: &DynImage<'_>, name: &[u8]) -> Option<usize> {
    let gh_va = img.dyn_val(DT_GNU_HASH)?;
    let off = img.vaddr_to_file_off(gh_va)?;
    let nbuckets = rd_u32(img.blob, off)? as usize;
    let symoffset = rd_u32(img.blob, off + 4)? as usize;
    let bloom_size = rd_u32(img.blob, off + 8)? as usize;
    let bloom_shift = rd_u32(img.blob, off + 12)?;
    if nbuckets == 0 || bloom_size == 0 || bloom_size > 512 || bloom_shift >= 64 {
        return None;
    }
    let h = dl_new_hash(name);
    // bloom 双位布局（gABI 机械口径——v0 BloomPanel 语义面板布局分立）
    let bpos = (h as usize) % 64;
    let bpos2 = ((h >> bloom_shift) as usize) % 64;
    let word_off = off + 16 + 8 * ((h as usize / 64) % bloom_size);
    let word = img.rd_u64_at(word_off)?;
    if (word >> bpos) & 1 == 0 || (word >> bpos2) & 1 == 0 {
        return None; // 单位缺 = 必不命中
    }
    let buckets_off = off + 16 + 8 * bloom_size;
    let bucket = rd_u32(img.blob, buckets_off + 4 * (h % nbuckets as u32) as usize)? as usize;
    if bucket == 0 {
        return None;
    }
    let chains_off = buckets_off + 4 * nbuckets;
    let mut sym = bucket;
    for _ in 0..CHAIN_MAX {
        if sym < symoffset {
            return None; // 坏表 fail-visible
        }
        let chain = rd_u32(img.blob, chains_off + 4 * (sym - symoffset))?;
        let sym_ent = img.sym_get(img.dyn_val(DT_SYMTAB)?, sym as u64)?;
        let name_off = sym_ent.0 as u64;
        if let Some(nm) = img.str_at(img.dyn_val(DT_STRTAB)?, name_off) {
            if nm == name {
                return Some(sym);
            }
        }
        if chain & 1 == 1 {
            return None; // 链尾旗
        }
        sym += 1;
    }
    None
}

// ---- TLS 布点面（x86_64 Variant II） ----

/// TLS 布点产物。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsLayout {
    /// 模块铸号（1 基——DTV 口径）。
    pub modid: usize,
    /// 模块块相对 tp 偏移（模块 1 = 负域 tp 前布点；后继 = 正域
    /// surplus 上域）。
    pub tp_offset: i64,
    /// 对齐后块长。
    pub memsz: u64,
    /// 对齐。
    pub align: u64,
}

/// static TLS 布点域（x86_64 Variant II——TCB 前置）：模块 1 布点
/// tp 前域（[tp - 块长, tp)），后继模块 surplus 上域递增布点
/// （tp + tcb_size 起对齐累进——dlopen 域布点口径）。
pub struct TlsSpace {
    /// TCB 语义位长（x86_64 TIB 最小双字域——构造面注入）。
    pub tcb_size: u64,
    /// surplus 游标（下一后继模块布点偏移）。
    surplus_next: i64,
    /// 已铸号数。
    pub modules: usize,
}

impl TlsSpace {
    /// 构造（tcb_size = TCB 语义位长）。
    pub const fn new(tcb_size: u64) -> Self {
        Self {
            tcb_size,
            surplus_next: 0,
            modules: 0,
        }
    }

    /// 布点（memsz/align/modid——模块 1 tp 前域 / 后继 surplus 上域；
    /// 对齐非 2 幂 = BadTlsAlign；modid 越序 = BadModid fail-visible）。
    pub fn alloc(
        &mut self,
        memsz: u64,
        align: u64,
        modid: usize,
    ) -> Result<TlsLayout, LdExecError> {
        if modid == 0 || modid != self.modules + 1 {
            return Err(LdExecError::BadModid);
        }
        if align == 0 || !align.is_power_of_two() {
            return Err(LdExecError::BadTlsAlign);
        }
        let block = memsz.div_ceil(align) * align;
        self.modules = modid;
        if modid == 1 {
            // 模块 1：tp 前域（Variant II——tp 为块上缘）
            Ok(TlsLayout {
                modid,
                tp_offset: -(block as i64),
                memsz: block,
                align,
            })
        } else {
            // 后继：surplus 上域（tp + tcb_size 起对齐累进）
            let start = self.surplus_next.max(self.tcb_size as i64);
            let off = (start + align as i64 - 1) & !(align as i64 - 1);
            self.surplus_next = off + block as i64;
            Ok(TlsLayout {
                modid,
                tp_offset: off,
                memsz: block,
                align,
            })
        }
    }

    /// DTV 扩容判读（`crate::ld::dtv_needs_resize` 同源——dtv_len 现
    /// 长对新铸号）。
    pub fn dtv_needs(&self, dtv_len: usize, modid: usize) -> bool {
        dtv_needs_resize(dtv_len, modid)
    }
}

// ---- 初始化执行序面 ----

/// 每模块初始化/终结面族（调用方从 DynImage 收取——init_array 长度
/// = DT_INIT_ARRAYSZ/8，fini 同口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModInitFaces {
    /// DT_INIT 在场。
    pub dt_init: bool,
    /// .init_array 元素数。
    pub init_array_len: usize,
    /// .fini_array 元素数。
    pub fini_array_len: usize,
    /// DT_FINI 在场。
    pub dt_fini: bool,
}

/// 调用点（init/fini 序展开产物——modid + 位型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSite {
    /// DT_INIT（模块初始化函数）。
    DtInit(u32),
    /// .init_array 第 i 元（正向）。
    InitArray(u32, usize),
    /// .fini_array 第 i 元（反向）。
    FiniArray(u32, usize),
    /// DT_FINI（模块终结函数）。
    DtFini(u32),
}

/// 初始化序展开（依赖先序——装载序 BFS 即 init 序）：逐模块
/// DT_INIT → .init_array 正向。`faces` 下标 = 模块 id；装载序项越界
/// fail-visible。
pub fn init_order(
    faces: &[ModInitFaces],
    load_order: &[u32],
) -> Result<Vec<CallSite>, LdExecError> {
    let mut out = Vec::new();
    for id in load_order {
        let f = faces.get(*id as usize).ok_or(LdExecError::FaceOutOfRange)?;
        if f.dt_init {
            out.push(CallSite::DtInit(*id));
        }
        for i in 0..f.init_array_len {
            out.push(CallSite::InitArray(*id, i));
        }
    }
    Ok(out)
}

/// 终结序展开（init 序精确逆序——逐模块 .fini_array 反向 → DT_FINI；
/// 模块序 = 装载序逆序）。与 [`init_order`] 产物严格互逆（同族面）。
pub fn fini_order(
    faces: &[ModInitFaces],
    load_order: &[u32],
) -> Result<Vec<CallSite>, LdExecError> {
    let mut out = Vec::new();
    for id in load_order.iter().rev() {
        let f = faces.get(*id as usize).ok_or(LdExecError::FaceOutOfRange)?;
        for i in (0..f.fini_array_len).rev() {
            out.push(CallSite::FiniArray(*id, i));
        }
        if f.dt_fini {
            out.push(CallSite::DtFini(*id));
        }
    }
    Ok(out)
}

// ---- dlopen 族外壳 ----

/// RTLD_LOCAL（v0 = 0）。
pub const RTLD_LOCAL: u32 = 0;
/// RTLD_GLOBAL。
pub const RTLD_GLOBAL: u32 = 0x100;

/// dlerror 语义串族（POSIX dlerror 口径——固定域串零分配）。
pub const DL_ERR_CANNOT_OPEN: &str = "cannot open shared object file";
/// dlerror：无效句柄。
pub const DL_ERR_INVALID_HANDLE: &str = "invalid handle";
/// dlerror：未决议符号。
pub const DL_ERR_UNDEFINED: &str = "undefined symbol";

/// dlopen 注册表项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlModule {
    /// 模块铸号（1 基）。
    pub modid: u32,
    /// 引用计数。
    pub refcount: u32,
    /// RTLD_GLOBAL 插入旗。
    pub global: bool,
}

/// dlopen 族状态机（注册表 + 全局插入序 + error 槽——零 unsafe 零
/// panic，定容禁令由调用面上限承载）。
pub struct DlState {
    modules: Vec<DlModule>,
    error: Option<&'static str>,
    next_modid: u32,
}

/// dlclose 裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlClose {
    /// 引用仍在——注册表保留。
    Kept,
    /// 计数归零——已出册（fini 序由 `fini_order` 消费面组装）。
    Unloaded(u32),
    /// 无效句柄（error 槽已置）。
    Invalid,
}

impl Default for DlState {
    fn default() -> Self {
        Self::new()
    }
}

impl DlState {
    /// 构造（空册零 error）。
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            error: None,
            next_modid: 1,
        }
    }

    /// dlopen（`present` = 装载计划面已含该 needed——机械读盘面挂账
    /// 域，缺席 = DL_ERR_CANNOT_OPEN；已册对象二次 open 走
    /// [`DlState::ref_open`] 幂等域）。
    pub fn dlopen(&mut self, present: bool, rtld_global: bool) -> Option<u32> {
        if !present {
            self.error = Some(DL_ERR_CANNOT_OPEN);
            return None;
        }
        let modid = self.next_modid;
        self.next_modid += 1;
        self.modules.push(DlModule {
            modid,
            refcount: 1,
            global: rtld_global,
        });
        Some(modid)
    }

    /// 引用递增（dlopen 幂等域——已册对象二次 open 同款）。
    pub fn ref_open(&mut self, modid: u32) -> Option<u32> {
        match self.modules.iter_mut().find(|m| m.modid == modid) {
            Some(m) => {
                m.refcount += 1;
                Some(m.refcount)
            }
            None => {
                self.error = Some(DL_ERR_INVALID_HANDLE);
                None
            }
        }
    }

    /// dlclose（refcount-- → 零 = 出册 + 全局序摘除 + Unloaded）。
    pub fn dlclose(&mut self, modid: u32) -> DlClose {
        let Some(pos) = self.modules.iter().position(|m| m.modid == modid) else {
            self.error = Some(DL_ERR_INVALID_HANDLE);
            return DlClose::Invalid;
        };
        if self.modules[pos].refcount > 1 {
            self.modules[pos].refcount -= 1;
            return DlClose::Kept;
        }
        self.modules.remove(pos);
        DlClose::Unloaded(modid)
    }

    /// dlsym（查找序三段复用 `crate::ld::scope_lookup`——exe → 依赖
    /// 序 → 全局插入序；`syms` = 逐段地址表〔[0] = exe 段 / [1+i] =
    /// 依赖序第 i 段 / 末位 = 全局插入序段——同名先见者胜段位直接
    /// 定位〕；三段皆缺 = DL_ERR_UNDEFINED）。
    pub fn dlsym(
        &mut self,
        target: u32,
        exe: &[u32],
        deps: &[&[u32]],
        syms: &[u64],
    ) -> Option<u64> {
        let globals = self.global_scope();
        match scope_lookup(target, exe, deps, &globals) {
            Some(ScopeHit::Exe) => syms.first().copied(),
            Some(ScopeHit::Dep(i)) => syms.get(i + 1).copied(),
            Some(ScopeHit::Global) => syms.last().copied(),
            None => {
                self.error = Some(DL_ERR_UNDEFINED);
                None
            }
        }
    }

    /// dlerror（一次性消费——POSIX 口径：读取即清；无错 None）。
    pub fn dlerror(&mut self) -> Option<&'static str> {
        self.error.take()
    }

    /// 在册模块数。
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// 空册判读。
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// 全局插入序快照（dlsym 第三段——RTLD_GLOBAL 对象族）。
    pub fn global_scope(&self) -> Vec<u32> {
        self.modules
            .iter()
            .filter(|m| m.global)
            .map(|m| m.modid)
            .collect()
    }
}

// ---- H-P03 四段打点面 ----

/// 纳秒 → 0.1 ms 定点（上取整——0 ns = 0；判读归
/// `crate::ld::{budget_overruns, budget_total_ok}` 同源）。
pub fn ns_to_tenths(ns: u64) -> u32 {
    ns.div_ceil(100_000) as u32
}

/// 四段打点判读（`actual` = 四段 0.1 ms 定点实测，序 =
/// load-map/reloc/tls-init/init-exec——H-P03 权威预算表同谱）。
/// 返值 = (逐段超支旗, 总闸判读)。
pub fn recon_budget_judge(actual: &[u32; 4]) -> ([bool; 4], bool) {
    (budget_overruns(actual), budget_total_ok(actual))
}

// ---- ld-lumina.so 入口契约 ----

/// 动态链接器入口 auxv 契约五目（AT_PHDR/AT_PHENT/AT_PHNUM/AT_BASE/
/// AT_ENTRY——缺任一必需目 None fail-visible；AT_NULL 收尾截断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderAuxv {
    /// AT_PHDR：程序头表虚地址。
    pub phdr: u64,
    /// AT_PHENT：程序头项大小。
    pub phent: u64,
    /// AT_PHNUM：程序头项数。
    pub phnum: u64,
    /// AT_BASE：动态链接器自身装载基址。
    pub base: u64,
    /// AT_ENTRY：可执行入口虚地址。
    pub entry: u64,
}

/// auxv 探针（ld-lumina.so 入口契约——`pairs` = (tag, val) 对序；
/// AT_NULL 收尾即截断扫描；AT_PHENT ≠ 56 fail-visible）。
pub fn auxv_probe(pairs: &[(u64, u64)]) -> Option<LoaderAuxv> {
    let mut phdr = None;
    let mut phent = None;
    let mut phnum = None;
    let mut base = None;
    let mut entry = None;
    for (tag, val) in pairs {
        if *tag == AT_NULL {
            break;
        }
        match *tag {
            AT_PHDR => phdr = Some(*val),
            AT_PHENT => phent = Some(*val),
            AT_PHNUM => phnum = Some(*val),
            AT_BASE => base = Some(*val),
            AT_ENTRY => entry = Some(*val),
            _ => {}
        }
    }
    Some(LoaderAuxv {
        phdr: phdr?,
        phent: phent?,
        phnum: phnum?,
        base: base?,
        entry: entry?,
    })
    .filter(|a| a.phent == PHDR_LEN as u64)
}

/// NonZeroU32 类型码面（`crate::ld::reloc_kind_nz` 同源透传——机械
/// 写面类型码消费口径）。
pub fn reloc_family(rtype: NonZeroU32) -> Option<u32> {
    let v = rtype.get();
    if matches!(
        v,
        R_X86_64_COPY | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_RELATIVE
    ) {
        Some(v)
    } else {
        None
    }
}

// ---- 装载计划消费面（M47-LDCONS53 笔60——ring3 mmap/mprotect 电气域
// 承接位：计划区 → mmap(R|W 分级窗) → 分级缓冲拷贝 → mprotect 终旗，
// Linux 装载器共享页序同谱；电气执行 = kernel::mmap〔SYS_MMAP(46)/
// SYS_MPROTECT(47)〕，本模块产**确定性动作序列**——环上执行面与宿主
// 对账面共用单一事实源）----

/// 页保护位：可读（bedrock::abi PROT_READ 同值——消费面对账断言域，
/// harbor 零外引依赖方向单向：常量本地单点，内核侧 t148 逐目断言兜底）。
pub const PROT_READ: u64 = 0x1;
/// 页保护位：可写（bedrock::abi PROT_WRITE 同值）。
pub const PROT_WRITE: u64 = 0x2;
/// 页保护位：可执行（bedrock::abi PROT_EXEC 同值——内核侧 v0 记账位，
/// EFER.NXE 未启用不落表如实记档）。
pub const PROT_EXEC: u64 = 0x4;

/// gABI 段旗 → 页保护位翻译（PF_R/PF_W/PF_X → PROT_READ/WRITE/EXEC）。
/// R 必含位语义（Linux 装载器同款拒收：p_flags 无 PF_R 段不可装载
/// ——BadSeg fail-visible）。
pub fn prot_of(flags: u32) -> Result<u64, LdExecError> {
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    const PF_R: u32 = 4;
    if flags & PF_R == 0 {
        return Err(LdExecError::BadSeg); // 无 R 段拒收（装载器同款）
    }
    let mut prot = PROT_READ;
    if flags & PF_W != 0 {
        prot |= PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= PROT_EXEC;
    }
    Ok(prot)
}

/// 消费动作（确定性电水单——环上执行器逐条消费：`Mmap` → ring3
/// SYS_MMAP / `Mprotect` → ring3 SYS_MPROTECT / `CopyTo` → 环内拷贝；
/// 宿主对账面同列断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapAction {
    /// 匿名映射（分级窗——R|W 起手；va = 计划区起点，len = 页对齐区长）。
    Mmap {
        /// 映射基址（计划区绝对虚地址——页对齐）。
        va: u64,
        /// 映射长（字节；页对齐区长）。
        len: u64,
        /// 保护位族（分级窗 = R|W；终旗窗由 [`MapAction::Mprotect`] 承接）。
        prot: u64,
    },
    /// 分级缓冲拷贝（staged 字节面 → 已映射窗——`src_off` 为
    /// [`StagedImage`] 字节面内偏移，va = 目标窗虚地址）。
    CopyTo {
        /// 目标虚地址（= staged.base + src_off）。
        va: u64,
        /// 源偏移（[`StagedImage`] 字节面内）。
        src_off: u64,
        /// 拷贝字节数（区∩镜像交集——间隙零拷贝）。
        len: u64,
    },
    /// 页保护改旗（终旗窗——R|W 起手后的最终保护位族；与分级窗同旗
    /// 区零动作——Linux 装载器同款跳过）。
    Mprotect {
        /// 改旗基址（计划区起点）。
        va: u64,
        /// 改旗长（页对齐区长）。
        len: u64,
        /// 终旗保护位族（prot_of 翻译）。
        prot: u64,
    },
}

/// 装载计划消费面：[`load_plan`] 区族 + [`stage_image`] 镜像 → 确定性
/// 消费动作序列（三段式——① 逐区 Mmap R|W 分级窗〔写使能拷贝域〕；
/// ② 逐区 CopyTo 区∩镜像交集拷贝〔间隙零拷贝〕；③ 逐区 Mprotect
/// 终旗〔与分级窗同旗区零动作〕）。基址相对区间已在 [`load_plan`]
/// 绝对化（va_start/va_end 含 base）——动作序列虚地址即环上真值。
/// 消费序 = Linux 装载器共享页序（先全量映射、再统一拷贝、后逐区
/// 终旗——相邻区共享页拷贝免中间旗折腾）。
///
/// fail-visible：空计划 → `TooManyLoads` 域显形（load_plan 已闸 0 段
/// ——本面零区计划复闸收口）；无 PF_R 区 → `BadSeg`（装载器同款拒收
/// ——prot_of 结构闸）。staged 与计划区零交集 = 零 `CopyTo` 动作
/// （间隙零拷贝语义——计划/镜像失配由消费执行器 fail-visible 显形，
/// 非本面错误域）。
pub fn exec_plan(plan: &[MapRegion], staged: &StagedImage) -> Result<Vec<MapAction>, LdExecError> {
    if plan.is_empty() {
        return Err(LdExecError::TooManyLoads); // 空计划显形（load_plan 已闸 0 段）
    }
    let staged_lo = staged.base;
    let staged_hi = staged.base + staged.bytes.len() as u64;
    let mut maps = Vec::new();
    let mut copies = Vec::new();
    let mut protects = Vec::new();
    for r in plan {
        let prot = prot_of(r.flags)?;
        // ① 分级窗（写使能拷贝域）
        maps.push(MapAction::Mmap {
            va: r.va_start,
            len: r.va_end - r.va_start,
            prot: PROT_READ | PROT_WRITE,
        });
        // ② 区∩镜像交集拷贝（间隙零拷贝——staged 覆盖域外零动作）
        let clo = r.va_start.max(staged_lo);
        let chi = r.va_end.min(staged_hi);
        if chi > clo {
            copies.push(MapAction::CopyTo {
                va: clo,
                src_off: clo - staged_lo,
                len: chi - clo,
            });
        }
        // ③ 终旗（与分级窗同旗区零动作——Linux 装载器同款跳过）
        if prot != PROT_READ | PROT_WRITE {
            protects.push(MapAction::Mprotect {
                va: r.va_start,
                len: r.va_end - r.va_start,
                prot,
            });
        }
    }
    // 三段式拼接（消费序 = 先全量映射、再统一拷贝、后逐区终旗——
    // 相邻区共享页拷贝免中间旗折腾）
    let mut actions = maps;
    actions.append(&mut copies);
    actions.append(&mut protects);
    Ok(actions)
}

// ---- dlopen 真消费面（M47-DLOPEN54 笔61——链式装载机械消费） ----

/// 链式装载注册表容量（真消费面输入域定容——8 件）。
pub const CHAIN_REG_CAP: usize = 8;

/// 链式装载注册表项（SONAME 名 → ET_DYN 映像字节）。
#[derive(Clone, Copy)]
pub struct ChainEntry<'a> {
    /// 注册名（SONAME 域——dlopen 根名 / DT_NEEDED 名查键）。
    pub name: &'a [u8],
    /// ET_DYN 映像字节面（交付件单一事实源——artifacts/ 同源）。
    pub blob: &'a [u8],
}

/// 链式装载注册表（dlopen 真消费面输入域——重名拒收 + 定容
/// [`CHAIN_REG_CAP`] fail-visible；零 unsafe 零 panic）。
pub struct ChainRegistry<'a> {
    entries: Vec<ChainEntry<'a>>,
}

impl Default for ChainRegistry<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ChainRegistry<'a> {
    /// 构造（空册）。
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 登记（重名/超容拒收 [`LdExecError::RegistryRange`]——返注册表序）。
    pub fn add(&mut self, name: &'a [u8], blob: &'a [u8]) -> Result<usize, LdExecError> {
        if self.entries.len() >= CHAIN_REG_CAP || self.find(name).is_some() {
            return Err(LdExecError::RegistryRange);
        }
        self.entries.push(ChainEntry { name, blob });
        Ok(self.entries.len() - 1)
    }

    /// 名查序（dlopen 根名 / DT_NEEDED 名查键——注册表序返值）。
    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    /// 注册表序取项。
    pub fn get(&self, idx: usize) -> Option<&ChainEntry<'a>> {
        self.entries.get(idx)
    }

    /// 在册件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空册判读。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 模块定义者判读（GNU 哈希覆盖域 = 定义符号族——命中即定义；
/// 无 DT_GNU_HASH 模块零定义域——判读 None fail-visible 同口径）。
fn module_defines(img: &DynImage<'_>, name: &[u8]) -> bool {
    gnu_hash_lookup(img, name).is_some()
}

/// 依赖闭包邻接派生（真消费面邻接核）：逐模块 `dyn_parse` →
/// ① **DT_NEEDED 声明域**——[`DynImage::needed`] 名走查（声明序）
/// → 注册表名查边（声明域实边——ELF 装载一次语义零容忍：名注册表
/// 缺席 = [`LdExecError::NeededMissing`] fail-visible）；
/// ② **UNDEF 决议闭包**——RELA `r_sym ≠ 0` 名 → 本模块 GNU 哈希缺席
/// （定义域覆盖 = 定义符号族——缺席即 UNDEF 判读）→ 注册表定义者
/// 名查边（as-needed 派生域——COPY/跨模块决议供给方显形；无定义者
/// UNDEF 不产边——决议域由绑定登记面/惰性跳过承接，fail-visible 由
/// [`reloc_apply`] 域承担）。
/// 双域并集逐目标去重（声明序在前）。返回邻接表（下标 = 注册表序）。
pub fn dl_adjacency(reg: &ChainRegistry<'_>) -> Result<Vec<Vec<u32>>, LdExecError> {
    let n = reg.len();
    let mut imgs: Vec<DynImage<'_>> = Vec::new();
    for i in 0..n {
        let blob = reg.get(i).ok_or(LdExecError::RegistryRange)?.blob;
        imgs.push(dyn_parse(blob)?);
    }
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, img) in imgs.iter().enumerate() {
        // ① DT_NEEDED 声明域（名走查 → 注册表名查边——声明序）
        let strtab = img.dyn_val(DT_STRTAB).unwrap_or(0);
        for off in img.needed() {
            let nm = img.str_at(strtab, off).ok_or(LdExecError::NeededMissing)?;
            let j = reg.find(nm).ok_or(LdExecError::NeededMissing)?;
            if j != i && !adj[i].contains(&(j as u32)) {
                adj[i].push(j as u32);
            }
        }
        // ② UNDEF 决议闭包（RELA 符号名 → 本模块缺席 → 注册表定义者边）
        let symtab = img.dyn_val(DT_SYMTAB);
        for e in rela_entries(img)? {
            if e.r_sym == 0 {
                continue; // 无符号重定位（RELATIVE 域）
            }
            let Some(st) = symtab else {
                continue; // symtab 缺席——闭包域跳过（决议域承担）
            };
            let Some(sym) = img.sym_get(st, e.r_sym as u64) else {
                continue; // 符号越界——闭包域跳过（决议域承担）
            };
            let Some(nm) = img.str_at(strtab, sym.0 as u64) else {
                continue;
            };
            if module_defines(img, nm) {
                continue; // 本模块已定义——非 UNDEF
            }
            for (j, oth) in imgs.iter().enumerate() {
                if j != i && module_defines(oth, nm) {
                    if !adj[i].contains(&(j as u32)) {
                        adj[i].push(j as u32);
                    }
                    break;
                }
            }
        }
    }
    Ok(adj)
}

/// DT_NEEDED 装载序（真消费面——BFS 层序 + 去重幂等 + 三色环判读
/// ——`crate::ld::needed_load_order` / `crate::ld::needs_cycle`
/// 语义核机械消费）：`root` 注册表序居首（可执行文件居首同谱）。
/// root 越界 = [`LdExecError::RegistryRange`]；依赖环 =
/// [`LdExecError::NeededCycle`]；邻接派生失败随行显形。
pub fn dl_chain_order(reg: &ChainRegistry<'_>, root: usize) -> Result<Vec<u32>, LdExecError> {
    if root >= reg.len() {
        return Err(LdExecError::RegistryRange);
    }
    let adj = dl_adjacency(reg)?;
    let refs: Vec<&[u32]> = adj.iter().map(|v| v.as_slice()).collect();
    if crate::ld::needs_cycle(&[root as u32], &refs) == Some(true) {
        return Err(LdExecError::NeededCycle);
    }
    crate::ld::needed_load_order(&[root as u32], &refs).ok_or(LdExecError::NeededCycle)
}

/// dlopen 真消费链（注册表 + 装载序 → dlopen 族机械消费）：根名查册
/// （缺席 = error 槽 [`DL_ERR_CANNOT_OPEN`] 落账 +
/// [`LdExecError::NeededMissing`]）→ [`dl_chain_order`] 装载序 →
/// 按序逐模块 [`DlState::dlopen`]（群组插序语义——全链成员随 root 旗
/// 同册；RTLD_GLOBAL 群组域）→ modid 序返值（下标 = 装载序）。
pub fn dl_open_chain(
    state: &mut DlState,
    reg: &ChainRegistry<'_>,
    root_name: &[u8],
    rtld_global: bool,
) -> Result<Vec<u32>, LdExecError> {
    let root = match reg.find(root_name) {
        Some(i) => i,
        None => {
            state.error = Some(DL_ERR_CANNOT_OPEN);
            return Err(LdExecError::NeededMissing);
        }
    };
    let order = dl_chain_order(reg, root)?;
    let mut modids = Vec::new();
    for _ in order {
        match state.dlopen(true, rtld_global) {
            Some(m) => modids.push(m),
            None => return Err(LdExecError::NeededMissing),
        }
    }
    Ok(modids)
}

// ---- dlsym 跨模块查找电气面（M48-DLSYM56 笔64——harbor 第⑤族核心
// 成员桩→真：M47 dl_open_chain 装载序真消费面之上，**符号名→地址跨模
// 块决议**落域——walk 装载序（root 居首 = exe 域 → 依赖 BFS 序 = dep
// 域），逐模块 GNU 哈希查找（`gnu_hash_lookup` 机械面），命中即决议
// base + st_value；全链缺席 = Ok(None)（error 槽由 DlState::dlsym_chain
// 消费面落账——POSIX dlsym 口径）。零 unsafe 零 panic，fail-visible
// 全显形）----

/// dlsym 跨模块命中面（符号名决议产物——段位直接定位 + 地址兑现）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymHit {
    /// 注册表序（0 = root/exe 域，1.. = 依赖 BFS 序段位）。
    pub reg_idx: usize,
    /// 符号号（模块 dynsym 表内号——GNU 哈希命中产物）。
    pub sym_idx: usize,
    /// 决议地址（base + st_value——装载基址兑现域）。
    pub addr: u64,
}

/// dlsym 跨模块查找链（真消费面——`root` 注册表序居首〔exe 域〕→ 依赖
/// BFS 序〔`dl_chain_order` 机械消费〕逐模块 `dyn_parse` +
/// `gnu_hash_lookup` 名查 → `sym_get` 符号取值 → `bases[reg_idx] +
/// st_value` 地址兑现）。全链缺席 = Ok(None)（决议零虚构——error 槽
/// 由调用面落账）；`bases` 长度 < 注册表数 = RegistryRange；装载序/
/// 闭包派生失败随行显形。
pub fn dl_sym_chain(
    reg: &ChainRegistry<'_>,
    root: usize,
    bases: &[u64],
    name: &[u8],
) -> Result<Option<SymHit>, LdExecError> {
    if root >= reg.len() {
        return Err(LdExecError::RegistryRange);
    }
    if bases.len() < reg.len() {
        return Err(LdExecError::RegistryRange);
    }
    let order = dl_chain_order(reg, root)?;
    for idx in order {
        let idx = idx as usize;
        let blob = reg.get(idx).ok_or(LdExecError::RegistryRange)?.blob;
        let img = dyn_parse(blob)?;
        if let Some(sym_idx) = gnu_hash_lookup(&img, name) {
            let symtab = img.dyn_val(DT_SYMTAB).ok_or(LdExecError::NoDynamic)?;
            let (_name_off, value, _size) = img
                .sym_get(symtab, sym_idx as u64)
                .ok_or(LdExecError::UndefinedSymbol)?;
            let base = bases[idx];
            return Ok(Some(SymHit {
                reg_idx: idx,
                sym_idx,
                addr: base + value,
            }));
        }
    }
    Ok(None)
}

/// DlState::dlsym_chain 落账域（POSIX dlsym 口径——命中 = 决议地址；
/// 全链缺席 = error 槽 [`DL_ERR_UNDEFINED`] 落账 + None 返值）。
impl DlState {
    /// dlsym 跨模块真消费（`dl_sym_chain` 决议 + error 槽落账——v0 查找
    /// 域 = 装载序全链〔root 居首 + 依赖 BFS 序〕；RTLD_GLOBAL 垫底段
    /// 随装载序群组插序语义并入——v0 全链同查口径如实记档）。
    pub fn dlsym_chain(
        &mut self,
        reg: &ChainRegistry<'_>,
        root: usize,
        bases: &[u64],
        name: &[u8],
    ) -> Option<u64> {
        match dl_sym_chain(reg, root, bases, name) {
            Ok(Some(hit)) => Some(hit.addr),
            Ok(None) => {
                self.error = Some(DL_ERR_UNDEFINED);
                None
            }
            Err(_) => {
                self.error = Some(DL_ERR_UNDEFINED);
                None
            }
        }
    }
}

// ---- PLT/GOT 惰性绑定电气执行面（M48-PLTGOT55 笔63——harbor 第④族
// 桩→真：M46/M47 惰性跳过记账域（jump_lazy 记账）升级为**真执行域**——
// 接线（wire）→ 首调解析（resolver 步兑现 GOT 槽）→ 直达（已决议槽直
// 呼）。经典 x86_64 PLT/GOT 布局同谱：GOT[1] = link_map 描述子、
// GOT[2] = resolver 入口、GOT[3+i] = 第 i 个 JUMP_SLOT 槽（初值 =
// PLT 存根地址——push rel_idx; jmp PLT0），首调经 PLT0 → resolver 写
// 槽（GOT[3+i] = 决议地址），次调直达。零 unsafe 零 panic，fail-visible
// 全显形）----

/// 惰性槽容量（单模块 JUMP_SLOT 惰性槽定容——16 槽，RELA_MAX 同谱纪律）。
pub const LAZY_SLOT_CAP: usize = 16;

/// 经典 PLT 存根步长（x86_64 gABI 同谱——PLT0 + 每槽 16 B）。
pub const PLT_STUB_STRIDE: u64 = 16;

/// 惰性槽状态（PLT/GOT 延迟绑定两态机）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LazySlotState {
    /// 未决议——槽值 = PLT 存根地址（首调经 PLT0 → resolver）。
    Stub(u64),
    /// 已决议——槽值 = 决议地址（次调直达）。
    Resolved(u64),
}

/// PLT/GOT 惰性绑定表（GOT 槽两态机——wire/resolve/value 全显形；
/// 槽键 = GOT 槽虚地址，定容 [`LAZY_SLOT_CAP`] fail-visible）。
#[derive(Debug)]
pub struct LazyGot {
    plt0: u64,
    slots: Vec<(u64, LazySlotState)>,
}

impl LazyGot {
    /// 构造（`plt0` = PLT0 入口虚地址——存根地址 = plt0 + stride×(idx+1)
    /// 经典布局）。
    pub fn new(plt0: u64) -> Self {
        Self {
            plt0,
            slots: Vec::new(),
        }
    }

    fn slot_pos(&self, got_va: u64) -> Option<usize> {
        self.slots.iter().position(|(va, _)| *va == got_va)
    }

    /// 接线（JUMP_SLOT 惰性槽初值 = PLT 存根地址——`rel_idx` = JUMP_SLOT
    /// 相对号〔0 基，resolver push 值同域〕；重复接线幂等——同槽同存根
    /// 覆写返值；槽号/容量越界 = [`LdExecError::LazySlotRange`]；返值 =
    /// 存根虚地址）。
    pub fn wire(&mut self, got_va: u64, rel_idx: usize) -> Result<u64, LdExecError> {
        if rel_idx >= LAZY_SLOT_CAP {
            return Err(LdExecError::LazySlotRange);
        }
        let stub = self
            .plt0
            .checked_add(PLT_STUB_STRIDE * (rel_idx as u64 + 1))
            .ok_or(LdExecError::LazySlotRange)?;
        match self.slot_pos(got_va) {
            Some(pos) => self.slots[pos].1 = LazySlotState::Stub(stub),
            None => {
                if self.slots.len() >= LAZY_SLOT_CAP {
                    return Err(LdExecError::LazySlotRange);
                }
                self.slots.push((got_va, LazySlotState::Stub(stub)));
            }
        }
        Ok(stub)
    }

    /// 首调解析（resolver 步——`got_va` 槽写入决议地址 `addr`；未接线槽
    /// = [`LdExecError::LazyUnbound`]；已决议槽 = Ok(false) 幂等域
    /// 〔次调直达不走 resolver——重复解析零增〕；返 Ok(true) = 本步兑现）。
    pub fn resolve(&mut self, got_va: u64, addr: u64) -> Result<bool, LdExecError> {
        let pos = self.slot_pos(got_va).ok_or(LdExecError::LazyUnbound)?;
        match self.slots[pos].1 {
            LazySlotState::Resolved(_) => Ok(false),
            LazySlotState::Stub(_) => {
                self.slots[pos].1 = LazySlotState::Resolved(addr);
                Ok(true)
            }
        }
    }

    /// 槽值判读（Stub(v)/Resolved(v) → v——调用面经 GOT 间呼口径同值）。
    pub fn value(&self, got_va: u64) -> Option<u64> {
        self.slot_pos(got_va).map(|pos| match self.slots[pos].1 {
            LazySlotState::Stub(v) | LazySlotState::Resolved(v) => v,
        })
    }

    /// 槽两态判读。
    pub fn state(&self, got_va: u64) -> Option<LazySlotState> {
        self.slot_pos(got_va).map(|pos| self.slots[pos].1)
    }

    /// 已决议槽数（resolver 兑现记账）。
    pub fn resolved_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|(_, s)| matches!(s, LazySlotState::Resolved(_)))
            .count()
    }

    /// 在册槽数。
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// 空表判读。
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// 惰性绑定接线报告（t150 SO 相位记账域——与 [`RelocReport::jump_lazy`]
/// 对账：惰性跳过数 = 接线数〔同批同镜像口径〕）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LazyWireReport {
    /// 接线槽数（JUMP_SLOT × !bind_now × 未决议——PLT 存根初值域）。
    pub wired: usize,
    /// 立即绑定槽数（bind_now ∨ 已决议——决议值直写域）。
    pub bound: usize,
}

/// PLT/GOT 惰性绑定接线判读面（真件消费序——[`rela_entries`] JUMP_SLOT
/// 族逐条判读）：lazy 条目〔[`crate::ld::lazy_bind`] 同源语义——JUMP_SLOT
/// × !bind_now × 未决议〕→ wired 计数（PLT 存根初值域）；立即条目
/// 〔bind_now ∨ 已决议〕→ bound 计数（决议值直写域）。与
/// [`RelocReport::jump_lazy`] 对账口径：同批同镜像下 wired =
/// jump_lazy（惰性跳过域升级为接线执行域——记账守恒）。
pub fn lazy_wire(
    entries: &[RelaEntry],
    resolved: &[Option<u64>],
    bind_now: bool,
) -> Result<LazyWireReport, LdExecError> {
    let mut rep = LazyWireReport::default();
    for e in entries {
        if e.r_type != R_X86_64_JUMP_SLOT {
            continue;
        }
        let hit = resolved.get(e.r_sym as usize).copied().flatten().is_some();
        if bind_now || hit {
            rep.bound += 1;
        } else {
            rep.wired += 1;
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests;
