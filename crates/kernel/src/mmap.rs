//! kernel::mmap —— native 匿名映射电气域（v0.24，M47-LDCONS53 笔60，
//! 装载计划消费面承接批）。
//!
//! 承接 harbor::ld::exec 装载映射计划面（笔55——`load_plan` 产出的
//! `MapRegion` 页对齐区族）的 ring3 消费位：[`SYS_MMAP`](bedrock::abi::SYS_MMAP)
//! 匿名映射 + [`SYS_MPROTECT`](bedrock::abi::SYS_MPROTECT) 页保护改旗
//! 双车道。装载序 = 计划区 → 逐区 mmap（R|W 分级窗）→ 分级缓冲拷贝 →
//! 逐区 mprotect 终旗（Linux 装载器共享页序——`exec_plan` 消费面同谱）。
//!
//! # v0 口径（如实记档）
//!
//! - **匿名私有域单一语义**：fd 必须为 [`MMAP_ANON_FD`]（Linux fd = -1
//!   同源），文件映射随后续批次；
//! - **窗域** [`MMAP_ANON_BASE`]..[`MMAP_ANON_LIMIT`]（256 MiB——与
//!   SHM 窗 0x7000_0000..0x7800_0000 / swap 数据区 / FRESH 窗 / 增长栈
//!   零碰撞）；游标分配（提示 0）线性自窗基推进，耗尽回卷报错；
//! - **页立映射**：[`SYS_SHM`] MAP 臂同谱——[`Walker::map`] 建 P|U|W
//!   位域叶项 + 零页清底，无延迟映射/无回收；半程失败不回滚（帧保留，
//!   幂等重试补映射——shm_map 同款纪律）；
//! - **登记面**：每次映射入行登记（pid + va + pages + prot），同任务
//!   重叠拒收（跨任务同 VA 合法——独立地址空间）；定容
//!   [`MMAP_REG_CAP`] 64 行 fail-visible；行存续期 = 任务存续期
//!   （无 munmap/无 reap——回收随 munmap 批次，如实记档）；
//! - **PROT_EXEC v0 记账位**：EFER.NXE 未启用（bit63 属保留位不落表
//!   ——`ostd::mm::page::Entry::NO_EXECUTE` 注同源），全页可执行如实
//!   记档；mprotect 落表位 = RW 位（[`Entry::WRITABLE`]）；
//! - **mprotect 单行覆盖语义**：改旗区间必须被调用方**单行**登记覆盖
//!   （子区间合法；跨行/越行拒收 fail-visible——`exec_plan` 消费序按
//!   计划区逐一 mprotect，单行覆盖语义与消费面对齐）；登记行按需
//!   分裂（前/改/后三段——登记面真值保持）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use ostd::mm::frame::FRAME_SIZE;
use ostd::mm::page::{Entry, IdentityAccess, Walker};
use ostd::sync::SpinLock;

use bedrock::abi::{
    mmap_prot_ok, ERR_CAP, ERR_NOMEM, MMAP_ANON_BASE, MMAP_ANON_FD, MMAP_ANON_LIMIT, PROT_WRITE,
};

/// 登记行容量（定容禁令——v0 工作集 + 余量；耗尽 fail-visible）。
pub const MMAP_REG_CAP: usize = 64;

/// 登记行（一次 [`SYS_MMAP`] 的登记产物——pid 域寻址真值保持）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRow {
    /// 映射任务（pid 域——同任务重叠判据，跨任务同 VA 合法）。
    pub pid: usize,
    /// 映射基址（页对齐）。
    pub va: u64,
    /// 映射页数。
    pub pages: u64,
    /// 登记保护位族（当前生效值——mprotect 分裂随行更新）。
    pub prot: u64,
}

/// 登记面（锁序契约：单取 REG，不嵌套持有多锁——unixsock 同款纪律）。
static REG: SpinLock<Vec<MapRow>> = SpinLock::new(Vec::new());
/// 游标分配游标（线性自窗基推进——`lin_mmap_anon` 同款口径）。
static CURSOR: AtomicU64 = AtomicU64::new(MMAP_ANON_BASE);
/// [`SYS_MMAP`] 受理计数（fail-visible 计数域——census 对账面）。
static MMAP_CALLS: AtomicU64 = AtomicU64::new(0);
/// [`SYS_MPROTECT`] 受理计数（同上）。
static MPROTECT_CALLS: AtomicU64 = AtomicU64::new(0);

/// 登记行快照（t148 断言面——(va, pages, prot) 三元族，va 序）。
pub fn rows_for(pid: usize) -> Vec<(u64, u64, u64)> {
    let mut v: Vec<(u64, u64, u64)> = REG
        .lock()
        .iter()
        .filter(|r| r.pid == pid)
        .map(|r| (r.va, r.pages, r.prot))
        .collect();
    v.sort_unstable();
    v
}

/// 登记行总数读面（t148 断言面）。
pub fn rows_total() -> usize {
    REG.lock().len()
}

/// (mmap, mprotect) 受理计数读面（census 对账面）。
pub fn call_counts() -> (u64, u64) {
    (
        MMAP_CALLS.load(Ordering::Acquire),
        MPROTECT_CALLS.load(Ordering::Acquire),
    )
}

/// 保护位族语义域复审（内核侧纵深——parse 层 [`mmap_prot_ok`] 同源
/// 直调，零复制口径；W ⇒ R、X ⇒ R 组合语义在 bedrock 单点收口）。
fn prot_semantic_ok(prot: u64) -> bool {
    mmap_prot_ok(prot)
}

/// [`SYS_MMAP`] 承接面：native 匿名映射（语义见 bedrock ABI 注）。
///
/// 门禁序：fd 哨兵 → flags 保留域 → prot 语义域 → len 域 → 用户根在环
/// → 基址域（游标/定点）→ 登记面（容量 + 同任务重叠）→ 逐页映射
/// （分配/清底/落表/invlpg）→ 行登记。成功返回映射基址。
pub fn sys_mmap(va: u64, len: u64, prot: u64, flags: u64, fd: u64) -> u64 {
    const BAD: u64 = u64::MAX - 1; // parse 层已闸——执行面纵深防御域
    if fd != MMAP_ANON_FD || flags != 0 {
        return BAD; // 匿名私有单一语义（fd 哨兵 + 旗标保留域）
    }
    if !prot_semantic_ok(prot) {
        return BAD;
    }
    if len == 0 || len > MMAP_ANON_LIMIT - MMAP_ANON_BASE {
        return BAD; // 零长/越窗预算（整窗一映射上界）
    }
    let Some(frames) = crate::vmm::global_frames() else {
        return ERR_NOMEM;
    };
    let root = crate::task::current_user_root();
    if root == 0 {
        return ERR_CAP; // 内核任务无独立用户空间（shm_map 同款域闸）
    }
    let caller = crate::task::current_task_id();
    let pages = len.div_ceil(FRAME_SIZE);
    // 基址域：游标（0）线性分配 / 定点页对齐窗内
    let base = if va == 0 {
        let b = CURSOR.fetch_add(pages * FRAME_SIZE, Ordering::AcqRel);
        if b + pages * FRAME_SIZE > MMAP_ANON_LIMIT {
            CURSOR.store(MMAP_ANON_BASE, Ordering::Relaxed); // 窗耗尽回卷
            return ERR_NOMEM;
        }
        b
    } else {
        if va & (FRAME_SIZE - 1) != 0
            || !(MMAP_ANON_BASE..MMAP_ANON_LIMIT).contains(&va)
            || va + pages * FRAME_SIZE > MMAP_ANON_LIMIT
        {
            return BAD; // 定点域闸：页对齐 + 窗内 + 预算
        }
        va
    };
    // 登记面：容量 + 同任务重叠（跨任务同 VA 合法——独立地址空间）
    {
        let mut reg = REG.lock();
        if reg.len() >= MMAP_REG_CAP {
            return ERR_NOMEM; // 定容禁令 fail-visible
        }
        let (lo, hi) = (base, base + pages * FRAME_SIZE);
        if reg
            .iter()
            .any(|r| r.pid == caller && lo < r.va + r.pages * FRAME_SIZE && r.va < hi)
        {
            return BAD; // 同任务登记重叠
        }
        // 行登记（锁内——映射失败半程不回滚：帧保留，幂等重试补映射，
        // shm_map 同款纪律；行随映射声明先行，重试仅补页不重登记）
        reg.push(MapRow {
            pid: caller,
            va: base,
            pages,
            prot,
        });
    }
    let flags_leaf = Entry::PRESENT
        | Entry::USER
        | if prot & PROT_WRITE != 0 {
            Entry::WRITABLE
        } else {
            0
        };
    for k in 0..pages {
        let Some(f) = frames.alloc() else {
            return ERR_NOMEM; // 半程不回滚（帧保留——幂等重试补映射）
        };
        ostd::hw::phys::write_zero(f, FRAME_SIZE); // 零页清底（BSS 语义）
        if !map_user_page_us(root, base + k * FRAME_SIZE, f, flags_leaf) {
            return ERR_NOMEM;
        }
        ostd::hw::control::invlpg(base + k * FRAME_SIZE);
    }
    MMAP_CALLS.fetch_add(1, Ordering::AcqRel);
    base
}

/// 用户页映射（**中间层逐层补 US 位**——linux.rs `map_user_page` 同款
/// 纪律重铸）：[`ostd::mm::page::Walker::map`] 建表用 `Entry::table`
/// （P|RW——内核表口径），而 x86 要求 **ring3 访问全链路 U/S=1**
/// （SDM：U/S=0 于任一层 → user 访问即 #PF err=P|W|U）——mmap 窗
/// 全新分支的 PDPT/PD 缺 US 时 ring3 首访必雷（t148 首割实录
/// err-code=0x7 + pf-walk pdpte=0x23/pde=0x23 缺 US 实锤）。本函数
/// 四级走查：缺表建表（P|RW|**US**）+ 既有表补 US 位（幂等）→ 叶项
/// 原样落 `flags_leaf`（调用方已带 P|U|W 位族）→ 落表即真值。
///
/// 返回 false = 帧耗尽/建表失败（fail-visible——半程不回滚纪律同源）。
fn map_user_page_us(root: u64, va: u64, frame: u64, leaf_flags: u64) -> bool {
    const PTE_P: u64 = 1;
    const PTE_RW: u64 = 2;
    const PTE_US: u64 = 4;
    const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    let idx = |shift: u32| ((va >> shift) & 0x1FF) * 8;
    let mut table = root;
    for (shift, is_leaf) in [(39u32, false), (30, false), (21, false), (12, true)] {
        let off = idx(shift);
        let ent = ostd::hw::phys::read_u64(table + off);
        if is_leaf {
            ostd::hw::phys::write_u64(table + off, (frame & PTE_ADDR_MASK) | leaf_flags);
            return true;
        }
        if ent & PTE_P == 0 {
            // 缺中间表：申请建表（全零 + P|RW|US——M33-T1 纪律同源）
            let Some(t) = (crate::vmm::global_frames()).and_then(|f| f.alloc()) else {
                return false;
            };
            ostd::hw::phys::write_zero(t, 0x1000);
            ostd::hw::phys::write_u64(table + off, (t & PTE_ADDR_MASK) | PTE_P | PTE_RW | PTE_US);
            table = t;
        } else {
            // 既有表补 US 位（幂等——已带 US 零扰动；缺 US 补齐 +
            // invlpg 免旧翻译残留——TCG softmmu 不追踪页表内存写）
            if ent & PTE_US == 0 {
                ostd::hw::phys::write_u64(table + off, ent | PTE_US);
            }
            table = ent & PTE_ADDR_MASK;
        }
    }
    false
}

/// [`SYS_MPROTECT`] 承接面：登记行域内页保护改旗（语义见 bedrock ABI
/// 注）。门禁序：prot 语义域 → len/基址域 → 用户根在环 → 单行覆盖
/// （分裂容量预检）→ 逐叶 RW 位改写 + invlpg → 登记行分裂更新。
/// 成功返回 0。
pub fn sys_mprotect(va: u64, len: u64, prot: u64) -> u64 {
    const BAD: u64 = u64::MAX - 1;
    if !prot_semantic_ok(prot) {
        return BAD;
    }
    if len == 0 {
        return BAD;
    }
    let Some(frames) = crate::vmm::global_frames() else {
        return ERR_NOMEM;
    };
    let root = crate::task::current_user_root();
    if root == 0 {
        return ERR_CAP;
    }
    let caller = crate::task::current_task_id();
    let pages = len.div_ceil(FRAME_SIZE);
    let (lo, hi) = (va, va.saturating_add(pages * FRAME_SIZE));
    if va & (FRAME_SIZE - 1) != 0
        || !(MMAP_ANON_BASE..MMAP_ANON_LIMIT).contains(&va)
        || hi > MMAP_ANON_LIMIT
    {
        return BAD; // 基址域闸：页对齐 + 窗内 + 预算
    }
    // 单行覆盖判读 + 分裂容量预检（先于任何 PTE 写——fail-visible 纯
    // 前置域）：区间必须被调用方单行登记完整覆盖（跨行/越行拒收）；
    // 分裂增量预检（前/改/后至多 +2 行——越容先于改旗拒收）。
    let covering: Option<MapRow> = {
        let reg = REG.lock();
        let hit = reg
            .iter()
            .find(|r| r.pid == caller && r.va <= lo && hi <= r.va + r.pages * FRAME_SIZE)
            .copied();
        if let Some(r) = hit {
            let (rlo, rhi) = (r.va, r.va + r.pages * FRAME_SIZE);
            let extra = (lo > rlo) as usize + (hi < rhi) as usize;
            if reg.len() + extra > MMAP_REG_CAP {
                return ERR_NOMEM; // 分裂越容——先于改旗拒收
            }
        }
        hit
    };
    let Some(row) = covering else {
        return BAD; // 未登记域/跨行/越行（单行覆盖语义）
    };
    // 逐叶 RW 位改写（NotMapped fail-visible——半程不回滚如实记档）
    let mut walker = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(), // 改旗不建表——分配回调永不触发
    };
    for k in 0..pages {
        let page = lo + k * FRAME_SIZE;
        let res = if prot & PROT_WRITE != 0 {
            walker.set_leaf_bits(root, page, Entry::WRITABLE, 0)
        } else {
            walker.set_leaf_bits(root, page, 0, Entry::WRITABLE)
        };
        if res.is_err() {
            return BAD; // 未映射页（登记面与页表失配——fail-visible）
        }
        ostd::hw::control::invlpg(page); // 旧翻译残留击落（M33-T1 纪律）
    }
    // 登记行分裂更新（前/改/后三段——登记面真值保持）：**内容键锁窗
    // 内重寻**（pid + 区间三元组——跨核索引漂移免疫：单核调度语境 +
    // syscall 慢路径不换任务的常态下恒命中；他任务行增删导致的下标
    // 漂移零影响——按键寻行不按位寻行）。容量已前置预检，锁窗内
    // 复检兜底（他任务行增长越容 → fail-visible，改旗半效如实记档
    // ——幂等重试收口纪律同映射半程）。
    {
        let mut reg = REG.lock();
        if reg.len() + 2 > MMAP_REG_CAP {
            return ERR_NOMEM; // 锁窗内复检（他任务行增长域）
        }
        let pos = reg.iter().position(|r| {
            r.pid == caller && r.va == row.va && r.pages == row.pages && r.prot == row.prot
        });
        let Some(pos) = pos else {
            return BAD; // 行消失（他核同任务并发改旗——fail-visible）
        };
        let (rlo, rhi) = (row.va, row.va + row.pages * FRAME_SIZE);
        let head = lo > rlo;
        let tail = hi < rhi;
        let mut rows: Vec<MapRow> = Vec::with_capacity(3);
        if head {
            rows.push(MapRow {
                pid: row.pid,
                va: rlo,
                pages: (lo - rlo) / FRAME_SIZE,
                prot: row.prot,
            });
        }
        rows.push(MapRow {
            pid: row.pid,
            va: lo,
            pages,
            prot,
        });
        if tail {
            rows.push(MapRow {
                pid: row.pid,
                va: hi,
                pages: (rhi - hi) / FRAME_SIZE,
                prot: row.prot,
            });
        }
        let _ = reg.remove(pos);
        for (k, r) in rows.into_iter().enumerate() {
            reg.insert(pos + k, r);
        }
    }
    MPROTECT_CALLS.fetch_add(1, Ordering::AcqRel);
    0
}
