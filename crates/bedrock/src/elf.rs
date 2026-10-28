//! ELF64 静态映像格式（M33-E1）——Linux 兼容装载路径的结构面。
//!
//! **职责边界**（[`exec`] LXE1 先例同款）：本模块只做**结构**（魔数/
//! 位宽/端序/程序头表/PT_LOAD 载荷一致性）解析与 **Linux 初始栈布局**
//! 计算，纯函数、宿主可测；**放置策略**（FRESH 域段落、页槽互斥、
//! entry 落段、栈域取值）归内核装载器（`kernel::user`）——格式层不
//! 知晓页表布局，内核层不重复结构校验。
//!
//! 口径（M33-计划 裁决注）：仅 ET_EXEC 静态映像（动态链接 ET_DYN 拒
//! 收、无重定位、无符号面）；「Linux 静态 busybox」由制备面重基址构
//! 建（linker script 落 FRESH 域），p_vaddr 与 p_offset 均 4 KiB 页
//! 对齐、PT_LOAD 页槽互斥（段间不共享页，违背即装载面 BadImage 显
//! 形）。System V AMD64 ABI 初始栈：`rsp` 16 字节对齐，自 `rsp` 向上
//! 依次 argc / argv[] / NULL / envp[] / NULL / auxv 对，字符串区与
//! AT_RANDOM 垫顶。
//!
//! 非目标：ET_DYN/PIE、动态链接器、符号重定位（如实记档）。

/// 魔数 \x7f"ELF"（ident[0..4]）。
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// ELFCLASS64。
pub const ELFCLASS64: u8 = 2;
/// 小端两字节序。
pub const ELFDATA2LSB: u8 = 1;
/// 当前 ELF 规范版本。
pub const EV_CURRENT: u8 = 1;
/// e_type：可执行（非 PIE）。
pub const ET_EXEC: u16 = 2;
/// e_machine：x86-64。
pub const EM_X86_64: u16 = 62;
/// 程序头类型：可装载段。
pub const PT_LOAD: u32 = 1;
/// p_flags：可执行。
pub const PF_X: u32 = 1;
/// p_flags：可写。
pub const PF_W: u32 = 2;
/// p_flags：可读。
pub const PF_R: u32 = 4;
/// ELF 头长度。
pub const EHDR_LEN: usize = 64;
/// 程序头长度（64 位）。
pub const PHDR_LEN: usize = 56;
/// 页粒度（装载域对齐与槽位互斥单位）。
pub const PAGE: u64 = 0x1000;
/// PT_LOAD 数上限（v0 静态定容；busybox 精简构建 ≤4 段，宽留余量）。
pub const ELF_MAX_LOADS: usize = 16;

// ---- AT_* auxv 哨兵（System V AMD64 ABI；musl _start 消费面） ----

/// auxv：收尾哨。
pub const AT_NULL: u64 = 0;
/// auxv：程序头表虚地址。
pub const AT_PHDR: u64 = 3;
/// auxv：程序头表项大小。
pub const AT_PHENT: u64 = 4;
/// auxv：程序头表项数。
pub const AT_PHNUM: u64 = 5;
/// auxv：页大小。
pub const AT_PAGESZ: u64 = 6;
/// auxv：动态链接器基址（静态映像 = 0）。
pub const AT_BASE: u64 = 7;
/// auxv：标志位（v0 = 0）。
pub const AT_FLAGS: u64 = 8;
/// auxv：入口虚地址。
pub const AT_ENTRY: u64 = 9;
/// auxv：真实 UID。
pub const AT_UID: u64 = 11;
/// auxv：有效 UID。
pub const AT_EUID: u64 = 12;
/// auxv：真实 GID。
pub const AT_GID: u64 = 13;
/// auxv：有效 GID。
pub const AT_EGID: u64 = 14;
/// auxv：机器能力字（v0 = 无特化）。
pub const AT_HWCAP: u64 = 16;
/// auxv：时钟节拍频率。
pub const AT_CLKTCK: u64 = 17;
/// auxv：安全模式（v0 = 非 secure）。
pub const AT_SECURE: u64 = 23;
/// auxv：16 字节随机值地址。
pub const AT_RANDOM: u64 = 25;
/// auxv：程序名（argv[0] 语义）地址。
pub const AT_EXECFN: u64 = 31;

/// 结构错误（宿主与内核共用；装载器折叠为映像面错误码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// 魔数不符（ident[0..4] ≠ \x7f"ELF"）。
    BadMagic,
    /// 非 ELFCLASS64。
    BadClass,
    /// 非小端。
    BadData,
    /// 非 EV_CURRENT。
    BadVersion,
    /// 非 ET_EXEC（ET_DYN/ET_REL 等拒收——静态口径）。
    BadType,
    /// 非 EM_X86_64。
    BadMachine,
    /// e_phentsize ≠ 56。
    BadPhentsize,
    /// blob 截断（头/程序头表/段载荷不完整）或 e_phoff 不自洽。
    Truncated,
    /// PT_LOAD 数超上限（[`ELF_MAX_LOADS`]）或为 0。
    TooManyLoads,
    /// 段不一致：p_memsz < p_filesz / vaddr 非页对齐 /
    /// 页槽重叠（vaddr 页对齐为映射粒度硬要求；p_offset 按 ELF 宽口径
    /// 不作对齐闸——装载面 blob[offset..] 拷贝语义天然支持）。
    BadSeg,
}

/// 单个 PT_LOAD 段描述（解析产物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtLoad {
    /// 段载荷在映像内的文件偏移（4 KiB 对齐）。
    pub offset: u64,
    /// 段虚地址（4 KiB 对齐；落点策略归内核）。
    pub vaddr: u64,
    /// 文件映像长度（拷贝面）。
    pub file_len: u64,
    /// 内存映像长度（> file_len 的尾部由装载器清零——bss 语义）。
    pub mem_len: u64,
    /// p_flags（PF_X/PF_W/PF_R 位或）。
    pub flags: u32,
}

/// 解析结果：结构字段 + 段数据取用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfImage<'a> {
    /// 入口虚地址。
    pub entry: u64,
    /// 程序头表偏移（auxv AT_PHDR 取用面：装载器换算 phdr 虚地址）。
    pub phoff: u64,
    /// 程序头表项数。
    pub phnum: u64,
    /// PT_LOAD 段表（0..load_count 有效）。
    pub loads: [PtLoad; ELF_MAX_LOADS],
    /// 有效 PT_LOAD 数（1..=ELF_MAX_LOADS）。
    pub load_count: usize,
    /// 源 blob（段数据切片的基底）。
    blob: &'a [u8],
}

impl<'a> ElfImage<'a> {
    /// 第 i 个 PT_LOAD 段的文件数据切片（file_len 长；越界段号为调用
    /// 方 bug，防御式返回空切片）。
    pub fn seg_bytes(&self, i: usize) -> &'a [u8] {
        if i >= self.load_count {
            return &[];
        }
        let ld = self.loads[i];
        let off = ld.offset as usize;
        let len = ld.file_len as usize;
        self.blob.get(off..off + len).unwrap_or(&[])
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

/// 魔数探针（M33-L1 EXEC 分流面）：blob 是否以 \x7f"ELF" 开头。
/// 只看魔数、不做全结构校验（后者归 [`parse`] / 内核装载器）——
/// 供 `kernel::procs::sys_exec` 三分流（ELF / LXE1 / LWP）。
pub fn probe(blob: &[u8]) -> bool {
    blob.len() >= 4 && blob[0..4] == ELF_MAGIC
}

/// 解析 ELF64 静态映像（纯结构校验；放置策略归内核装载器）。
///
/// 防线序（fail-visible 全显形，逐条例独立可测）：魔数 → 位宽 →
/// 端序 → 版本 → 类型 → 机器 → phentsize → 头表自洽 → PT_LOAD 计数
/// → 每段（文件偏移越界 / memsz ≥ filesz / 页对齐 / 页槽互斥）。
pub fn parse(blob: &[u8]) -> Result<ElfImage<'_>, ElfError> {
    if blob.len() < EHDR_LEN {
        return Err(ElfError::Truncated);
    }
    if blob[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if blob[4] != ELFCLASS64 {
        return Err(ElfError::BadClass);
    }
    if blob[5] != ELFDATA2LSB {
        return Err(ElfError::BadData);
    }
    if blob[6] != EV_CURRENT {
        return Err(ElfError::BadVersion);
    }
    let Some(e_type) = rd_u16(blob, 0x10) else {
        return Err(ElfError::Truncated);
    };
    if e_type != ET_EXEC {
        return Err(ElfError::BadType);
    }
    let Some(e_machine) = rd_u16(blob, 0x12) else {
        return Err(ElfError::Truncated);
    };
    if e_machine != EM_X86_64 {
        return Err(ElfError::BadMachine);
    }
    let Some(e_entry) = rd_u64(blob, 0x18) else {
        return Err(ElfError::Truncated);
    };
    let Some(e_phoff) = rd_u64(blob, 0x20) else {
        return Err(ElfError::Truncated);
    };
    let Some(e_phentsize) = rd_u16(blob, 0x36) else {
        return Err(ElfError::Truncated);
    };
    let Some(e_phnum) = rd_u16(blob, 0x38) else {
        return Err(ElfError::Truncated);
    };
    if e_phentsize as usize != PHDR_LEN {
        return Err(ElfError::BadPhentsize);
    }
    // 头表自洽：phoff ≥ EHDR_LEN 且 phnum 项全部落在 blob 内。
    let phnum = e_phnum as usize;
    if phnum == 0 || (e_phoff as usize) < EHDR_LEN {
        return Err(ElfError::BadSeg);
    }
    let table_end = e_phoff as usize + phnum * PHDR_LEN;
    if table_end > blob.len() {
        return Err(ElfError::Truncated);
    }
    // 逐程序头：只收 PT_LOAD，计满即拒（段间页区间交收尾统一查）。
    let mut loads = [PtLoad {
        offset: 0,
        vaddr: 0,
        file_len: 0,
        mem_len: 0,
        flags: 0,
    }; ELF_MAX_LOADS];
    let mut load_count = 0usize;
    for k in 0..phnum {
        let base = e_phoff as usize + k * PHDR_LEN;
        let Some(p_type) = rd_u32(blob, base) else {
            return Err(ElfError::Truncated);
        };
        if p_type != PT_LOAD {
            continue;
        }
        let Some(p_flags) = rd_u32(blob, base + 0x04) else {
            return Err(ElfError::Truncated);
        };
        let Some(p_offset) = rd_u64(blob, base + 0x08) else {
            return Err(ElfError::Truncated);
        };
        let Some(p_vaddr) = rd_u64(blob, base + 0x10) else {
            return Err(ElfError::Truncated);
        };
        let Some(p_filesz) = rd_u64(blob, base + 0x20) else {
            return Err(ElfError::Truncated);
        };
        let Some(p_memsz) = rd_u64(blob, base + 0x28) else {
            return Err(ElfError::Truncated);
        };
        // blob 边界先于结构语义（截断显形优先）。
        let off = p_offset as usize;
        let len = p_filesz as usize;
        if off + len > blob.len() {
            return Err(ElfError::Truncated);
        }
        if p_memsz < p_filesz {
            return Err(ElfError::BadSeg);
        }
        // ELF 规范同余式 p_offset ≡ p_vaddr (mod PAGE)（Linux load_elf_binary
        // 同款语义）。vaddr 页对齐强校验退役（M33-T1 实录）：Alpine 官方
        // 静态介质尾段 vaddr = 0x4f7450 页内余 0x450 是 ld 常规布局（file
        // 偏移与 vaddr 同页内余），强对齐拒绝与「官方介质直载」制备契约相斥。
        if (p_vaddr % PAGE) != (p_offset % PAGE) {
            return Err(ElfError::BadSeg);
        }
        if load_count >= ELF_MAX_LOADS {
            return Err(ElfError::TooManyLoads);
        }
        loads[load_count] = PtLoad {
            offset: p_offset,
            vaddr: p_vaddr,
            file_len: p_filesz,
            mem_len: p_memsz,
            flags: p_flags,
        };
        load_count += 1;
    }
    if load_count == 0 {
        return Err(ElfError::TooManyLoads);
    }
    // 段间页区间零交（页槽互斥——绝对页号两两交检，段数 ≤16 O(n²)
    // 可忽略；共享页违背制备面重基址口径即 BadSeg 显形）。
    for i in 0..load_count {
        for j in 0..i {
            let a = &loads[i];
            let b = &loads[j];
            let a_lo = a.vaddr / PAGE;
            let a_hi = (a.vaddr + a.mem_len).div_ceil(PAGE);
            let b_lo = b.vaddr / PAGE;
            let b_hi = (b.vaddr + b.mem_len).div_ceil(PAGE);
            if a_lo < b_hi && b_lo < a_hi {
                return Err(ElfError::BadSeg);
            }
        }
    }
    Ok(ElfImage {
        entry: e_entry,
        phoff: e_phoff,
        phnum: e_phnum as u64,
        loads,
        load_count,
        blob,
    })
}

/// 初始栈构造错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackError {
    /// 栈页字节面容量不足（布局总尺寸越顶）。
    Overflow,
    /// 16 字节随机值须满额（ABI 面固定 16B）。
    BadRandom,
}

/// auxv 系统值注入面（装载器从 ElfImage 换算，格式层只排布）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxSys {
    /// 页大小（AT_PAGESZ）。
    pub pagesz: u64,
    /// 入口虚地址（AT_ENTRY）。
    pub entry: u64,
    /// 程序头表虚地址（AT_PHDR；装载器 = 映像基 + phoff 换算）。
    pub phdr: u64,
    /// 程序头项大小（AT_PHENT）。
    pub phent: u64,
    /// 程序头项数（AT_PHNUM）。
    pub phnum: u64,
    /// 时钟节拍（AT_CLKTCK）。
    pub clktck: u64,
}

/// 在栈页字节面内构造 Linux 初始栈（System V AMD64 ABI），返回 rsp。
///
/// `region` 为栈页字节面（装载器视角 = 顶帧的镜像缓冲，先构造后落
/// 帧）；`region_base` 为该帧的基虚地址（指针值 = base + 偏移）；
/// `top_off` 为栈顶在 region 内的偏移（顶帧 = region.len()）。布局
/// 自顶向下：字符串区（argv / envp / exec_fn，各含 NUL 收尾）→
/// 16 字节随机值 → 16 字节对齐 → auxv 对数组（[AT_NULL,0] 收尾）→
/// envp 指针数组（NULL 收尾）→ argv 指针数组（NULL 收尾）→ argc；
/// 最终 rsp 向下 16 字节对齐（ABI 进程入口闸）。
#[allow(clippy::too_many_arguments)]
pub fn build_initial_stack(
    region: &mut [u8],
    region_base: u64,
    top_off: usize,
    argv: &[&str],
    envp: &[&str],
    random: &[u8; 16],
    exec_fn: &str,
    aux: &AuxSys,
) -> Result<u64, StackError> {
    if top_off > region.len() {
        return Err(StackError::Overflow);
    }
    // ① 字符串区 + random 自顶向下（写 + 记 region 内偏移）。
    let mut sp = top_off;
    let mut put = |sp: &mut usize, bytes: &[u8]| -> Result<(), StackError> {
        let len = bytes.len();
        if *sp < len {
            return Err(StackError::Overflow);
        }
        *sp -= len;
        region[*sp..*sp + len].copy_from_slice(bytes);
        Ok(())
    };
    let mut argv_off = [0usize; 64];
    if argv.len() > argv_off.len() {
        return Err(StackError::Overflow);
    }
    for (i, s) in argv.iter().enumerate() {
        let mut v = alloc_vec_str(s);
        v.push(0);
        put(&mut sp, &v)?;
        argv_off[i] = sp;
    }
    let mut envp_off = [0usize; 64];
    if envp.len() > envp_off.len() {
        return Err(StackError::Overflow);
    }
    for (i, s) in envp.iter().enumerate() {
        let mut v = alloc_vec_str(s);
        v.push(0);
        put(&mut sp, &v)?;
        envp_off[i] = sp;
    }
    let mut fnv = alloc_vec_str(exec_fn);
    fnv.push(0);
    put(&mut sp, &fnv)?;
    let execfn_off = sp;
    put(&mut sp, random)?;
    let random_off = sp;
    // ② auxv + 指针数组 + argc 的总体尺寸（8B 倍数；随后 rsp 再 16 对齐）。
    let auxv_pairs: [(u64, u64); 14] = [
        (AT_PAGESZ, aux.pagesz),
        (AT_RANDOM, region_base + random_off as u64),
        (AT_EXECFN, region_base + execfn_off as u64),
        (AT_PHDR, aux.phdr),
        (AT_PHENT, aux.phent),
        (AT_PHNUM, aux.phnum),
        (AT_ENTRY, aux.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_HWCAP, 0),
        (AT_SECURE, 0),
        (AT_CLKTCK, aux.clktck),
    ];
    let vec_bytes = 8 + (argv.len() + 1) * 8 + (envp.len() + 1) * 8 + auxv_pairs.len() * 16 + 16;
    if sp < vec_bytes {
        return Err(StackError::Overflow);
    }
    let mut rsp = sp - vec_bytes;
    rsp &= !0xF; // ABI 进程入口 rsp 16 字节对齐闸
    let at = |off: usize| region_base + off as u64;
    let mut w = |off: usize, v: u64| -> Result<(), StackError> {
        let end = off.checked_add(8).ok_or(StackError::Overflow)?;
        if end > region.len() {
            return Err(StackError::Overflow);
        }
        region[off..off + 8].copy_from_slice(&v.to_le_bytes());
        Ok(())
    };
    let mut cur = rsp; // usize 形态供 region 索引；rsp 保留供返回面换算虚地址
                       // argc
    w(cur, argv.len() as u64)?;
    cur += 8;
    // argv[]
    for &o in argv_off.iter().take(argv.len()) {
        w(cur, at(o))?;
        cur += 8;
    }
    w(cur, 0)?; // argv NULL 收尾
    cur += 8;
    // envp[]
    for &o in envp_off.iter().take(envp.len()) {
        w(cur, at(o))?;
        cur += 8;
    }
    w(cur, 0)?; // envp NULL 收尾
    cur += 8;
    // auxv（对数组 + AT_NULL 收尾——上表 14 对后再补一对）
    for (tag, val) in auxv_pairs {
        w(cur, tag)?;
        w(cur + 8, val)?;
        cur += 16;
    }
    w(cur, AT_NULL)?;
    w(cur + 8, 0)?;
    Ok(region_base + rsp as u64)
}

/// 串拷贝（no_std 面 alloc string 转字节；宿主/内核共用）。
fn alloc_vec_str(s: &str) -> alloc::vec::Vec<u8> {
    s.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手编最小 ELF64 映像：ELF 头 64B + 2 程序头 112B + 页对齐载荷。
    /// 段① RX @0x180000000（8 字节代码，offset 0x1000），段② RW
    /// @0x180001000（4 字节数据 + memsz 2 页 = bss 一页余，offset 0x2000）。
    /// M33-T1 同余式校验对齐注：p_offset ≡ p_vaddr (mod PAGE)——golden
    /// 载荷 offset 页对齐化（真实 ld 布局同款；原 176/184 非对齐 offset
    /// 与 0 页内余 vaddr 违反同余式，构造瑕疵如实修正）。
    fn min_elf() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; 0x2000 + 4];
        // ident
        v[0..4].copy_from_slice(&ELF_MAGIC);
        v[4] = ELFCLASS64;
        v[5] = ELFDATA2LSB;
        v[6] = EV_CURRENT;
        // e_type / e_machine
        v[0x10..0x12].copy_from_slice(&ET_EXEC.to_le_bytes());
        v[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
        // e_entry / e_phoff
        v[0x18..0x20].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        v[0x20..0x28].copy_from_slice(&(EHDR_LEN as u64).to_le_bytes());
        // e_phentsize / e_phnum
        v[0x36..0x38].copy_from_slice(&(PHDR_LEN as u16).to_le_bytes());
        v[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());
        // 程序头①：RX 代码 @0x180000000，offset = 0x1000（页对齐），filesz 8
        let p1 = EHDR_LEN;
        v[p1..p1 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        v[p1 + 4..p1 + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        v[p1 + 8..p1 + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        v[p1 + 16..p1 + 24].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        v[p1 + 32..p1 + 40].copy_from_slice(&8u64.to_le_bytes());
        v[p1 + 40..p1 + 48].copy_from_slice(&8u64.to_le_bytes());
        // 程序头②：RW 数据+bss @0x180001000，offset = 0x2000（页对齐），
        // filesz 4 / memsz 0x2000
        let p2 = EHDR_LEN + PHDR_LEN;
        v[p2..p2 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        v[p2 + 4..p2 + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
        v[p2 + 8..p2 + 16].copy_from_slice(&0x2000u64.to_le_bytes());
        v[p2 + 16..p2 + 24].copy_from_slice(&0x1_8000_1000u64.to_le_bytes());
        v[p2 + 32..p2 + 40].copy_from_slice(&4u64.to_le_bytes());
        v[p2 + 40..p2 + 48].copy_from_slice(&0x2000u64.to_le_bytes());
        // 载荷（offset 同步页对齐化）
        v[0x1000..0x1008].copy_from_slice(&[0xB8, 0x2A, 0x00, 0x00, 0x0F, 0x05, 0xCC, 0x90]);
        v[0x2000..0x2004].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        v
    }

    #[test]
    fn parse_golden_two_loads() {
        let img = min_elf();
        let Ok(e) = parse(&img) else {
            panic!("最小映像须过")
        };
        assert_eq!(e.entry, 0x1_8000_0000);
        assert_eq!(e.load_count, 2);
        assert_eq!(e.phnum, 2);
        assert_eq!(e.loads[0].vaddr, 0x1_8000_0000);
        assert_eq!(e.loads[0].flags & PF_X, PF_X);
        assert_eq!(
            e.seg_bytes(0),
            &[0xB8, 0x2A, 0x00, 0x00, 0x0F, 0x05, 0xCC, 0x90]
        );
        assert_eq!(e.seg_bytes(1), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(e.loads[1].mem_len, 0x2000);
        // 防御面：越界段号空切片
        assert!(e.seg_bytes(2).is_empty());
    }

    #[test]
    fn parse_probe_gate() {
        let img = min_elf();
        assert!(probe(&img));
        assert!(!probe(&img[1..]));
        assert!(!probe(&[]));
        // LXE1 魔数非 ELF
        assert!(!probe(b"LXE1xxxx"));
    }

    #[test]
    fn reject_matrix_all_fail_visible() {
        let good = min_elf();
        // 坏魔数
        let mut bad = good.clone();
        bad[0] = 0x00;
        assert_eq!(parse(&bad), Err(ElfError::BadMagic));
        // 坏位宽（ELFCLASS32）
        let mut bad = good.clone();
        bad[4] = 1;
        assert_eq!(parse(&bad), Err(ElfError::BadClass));
        // 坏端序
        let mut bad = good.clone();
        bad[5] = 2;
        assert_eq!(parse(&bad), Err(ElfError::BadData));
        // 坏版本
        let mut bad = good.clone();
        bad[6] = 0;
        assert_eq!(parse(&bad), Err(ElfError::BadVersion));
        // 坏类型（ET_DYN=3 拒收——静态口径）
        let mut bad = good.clone();
        bad[0x10..0x12].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadType));
        // 坏机器（EM_386=3）
        let mut bad = good.clone();
        bad[0x12..0x14].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadMachine));
        // 坏 phentsize（32 位形态 32B）
        let mut bad = good.clone();
        bad[0x36..0x38].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadPhentsize));
        // phoff 越表（表尾越 blob）
        let mut bad = good.clone();
        bad[0x20..0x28].copy_from_slice(&0xFF_F000u64.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::Truncated));
        // 段载荷越 blob（filesz 尾越界）
        let mut bad = good.clone();
        bad[EHDR_LEN + 32..EHDR_LEN + 40].copy_from_slice(&0xFF_FFFFu64.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::Truncated));
        // memsz < filesz
        let mut bad = good.clone();
        bad[EHDR_LEN + 40..EHDR_LEN + 48].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadSeg));
        // vaddr 非页对齐（映射粒度硬闸）
        let mut bad = good.clone();
        bad[EHDR_LEN + 16..EHDR_LEN + 24].copy_from_slice(&0x1_8000_0800u64.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadSeg));
        // 页槽重叠（段② vaddr 改撞段①页）
        let mut bad = good.clone();
        bad[EHDR_LEN + PHDR_LEN + 16..EHDR_LEN + PHDR_LEN + 24]
            .copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        assert_eq!(parse(&bad), Err(ElfError::BadSeg));
        // 截断（头不完整 / 表不完整）
        assert_eq!(parse(&good[..32]), Err(ElfError::Truncated));
        assert_eq!(parse(&good[..100]), Err(ElfError::Truncated));
    }

    #[test]
    fn initial_stack_golden_layout() {
        let mut region = alloc::vec![0u8; 4096];
        let base = 0x1_8040_0000u64 - 4096;
        let top = region.len();
        let aux = AuxSys {
            pagesz: 4096,
            entry: 0x1_8000_0000,
            phdr: 0x1_8000_0040,
            phent: 56,
            phnum: 2,
            clktck: 100,
        };
        let Ok(rsp) = build_initial_stack(
            &mut region,
            base,
            top,
            &["busybox", "echo", "hi"],
            &["LUMINA=1"],
            &[0xAB; 16],
            "busybox",
            &aux,
        ) else {
            panic!("布局须过")
        };
        // rsp 16B 对齐 + 位于页内
        assert_eq!(rsp % 16, 0);
        assert!(rsp > base && rsp <= base + 4096);
        let roff = (rsp - base) as usize;
        let rd = |o: usize| -> u64 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&region[o..o + 8]);
            u64::from_le_bytes(a)
        };
        // argc @rsp
        assert_eq!(rd(roff), 3);
        // argv[0..3] 解引用到 NUL 收尾串
        let p0 = rd(roff + 8) as usize - base as usize;
        assert_eq!(&region[p0..p0 + 8], b"busybox\0");
        let p2 = rd(roff + 24) as usize - base as usize;
        assert_eq!(&region[p2..p2 + 3], b"hi\0");
        // argv NULL 收尾
        assert_eq!(rd(roff + 32), 0);
        // envp[0] = "LUMINA=1"，NULL 收尾
        let e0 = rd(roff + 40) as usize - base as usize;
        assert_eq!(&region[e0..e0 + 9], b"LUMINA=1\0");
        assert_eq!(rd(roff + 48), 0);
        // auxv 首对 AT_PAGESZ=4096；AT_RANDOM 指向 0xAB 垫；AT_NULL 收尾
        assert_eq!(rd(roff + 56), AT_PAGESZ);
        assert_eq!(rd(roff + 64), 4096);
        let r = rd(roff + 80) as usize - base as usize;
        assert_eq!(&region[r..r + 16], &[0xAB; 16]);
        // exec_fn 串在场（AT_EXECFN 值 @ tag+8）
        let f = rd(roff + 96) as usize - base as usize;
        assert_eq!(&region[f..f + 8], b"busybox\0");
        // AT_NULL 收尾对（数组尾）
        let tail = roff + 56 + 14 * 16;
        assert_eq!(rd(tail), AT_NULL);
        assert_eq!(rd(tail + 8), 0);
    }

    #[test]
    fn initial_stack_overflow_gate() {
        // 顶偏移越 region → Overflow
        let mut region = alloc::vec![0u8; 64];
        let aux = AuxSys {
            pagesz: 4096,
            entry: 0,
            phdr: 0,
            phent: 56,
            phnum: 0,
            clktck: 100,
        };
        assert_eq!(
            build_initial_stack(&mut region, 0, 65, &["a"], &[], &[0; 16], "a", &aux),
            Err(StackError::Overflow)
        );
        // 容量不足（region 过小）→ Overflow
        assert_eq!(
            build_initial_stack(
                &mut region,
                0,
                64,
                &["longstring"],
                &[],
                &[0; 16],
                "x",
                &aux
            ),
            Err(StackError::Overflow)
        );
        // argv 超 64 定容 → Overflow
        let big: alloc::vec::Vec<&str> = (0..65).map(|_| "x").collect();
        let mut region = alloc::vec![0u8; 8192];
        assert_eq!(
            build_initial_stack(&mut region, 0, 8192, &big, &[], &[0; 16], "x", &aux),
            Err(StackError::Overflow)
        );
    }
}
