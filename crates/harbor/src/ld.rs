//! harbor::ld —— 动态链接语义核判读族（M45-HARBOR48 笔53）。
//!
//! 承接《Harbor 港湾开发细则》v1.0.0 §2.3「动态链接与 TLS」+ 表 2-1 `ld/`
//! 子系统行 + 《指标与规范手册》**H-P03 权威条款**：「动态链接启动 ≤ 3 ms
//! （P2）——ld-lumina.so 动态链接器未落（用户态链接面成形前置——M39-HBI
//! 落 C ABI 指针/链接层为前置步）」。本模块为 **v0 语义面**：判读族纯函数
//! 全谱宿主可测，crate 级 `forbid(unsafe_code)` 不破（零 unsafe 零 panic
//! 路径——切片承载 fail-visible）；机械执行面挂账如实登记（随 ld-lumina.so
//! 交付批次落域）：ELF 装载与映射（bedrock::elf 解析面承接输入）/ 重定位
//! 写面 / static TLS 块布点 / .init_array/.fini_array 初始化执行 /
//! dlopen/dlsym/dlclose/dlerror 族外壳 / H-P03 实机四段打点。
//!
//! # 判读族域谱（12 判读面）
//!
//! - **RECON_BUDGET_SEGMENTS 四段预算分解**（H-P03：启动 ≤ 3 ms——装载映射
//!   ≤ 1.2 ms / 重定位 ≤ 1.0 ms / TLS 初始化 ≤ 0.5 ms / 初始化执行 ≤ 0.3 ms；
//!   0.1 ms 定点单位零浮点，合计 30 = 3.0 ms 总闸）+ [`budget_overruns`]
//!   超支段位直接定位判读 + [`budget_total_ok`] 总闸；
//! - [`dl_new_hash`] **GNU 式符号哈希**（const fn 全回绕——5381 初值 × 33
//!   异或逐字节，结构锚手算可验零外引黄金值）；
//! - [`BloomPanel`] **双位判读面板**（2 word × 64 位 + shift 参数化——GNU
//!   hash bloom 一级过滤：双位齐置才可能命中，单位命中必不命中）；
//! - [`load_factor_pct`] / [`load_factor_warn`] **装载率告警谓词**（细则
//!   「装载率超过 0.7 即触发告警」明文——百分制零浮点 + 零桶防御）；
//! - [`needed_load_order`] **DT_NEEDED 广度优先装载序**（去重幂等——ELF
//!   装载一次语义）；
//! - [`needs_cycle`] **DFS 三色环检测**（白/灰/黑——灰遇灰即环；
//!   fail-visible）；
//! - [`scope_lookup`] **查找序三段组装**（细则「可执行文件 → 广度优先依赖
//!   序 → 全局符号插入」ELF 语义——同名先见者胜，RTLD_GLOBAL 插入序垫底）；
//! - [`reloc_kind_of`] **重定位家族四类判读**（gABI x86_64 权威映射：
//!   COPY=5 / GLOB_DAT=6 / JUMP_SLOT=7 / RELATIVE=8——未知类型 None
//!   fail-visible）；
//! - [`lazy_bind`] **惰性绑定语义位**（JUMP_SLOT × !bind_now——PLT/GOT
//!   延迟绑定细则条款）；
//! - [`tls_model_of`] **TLS 四模型判读**（gABI x86_64 权威映射：
//!   TPOFF64=24→local-exec / GOTTPOFF=22→initial-exec / TLSGD=19→
//!   general-dynamic / TLSLD=20→local-dynamic）；
//! - [`dtv_needs_resize`] **DTV 动态扩展判读核**（modid 单调铸号越出现长
//!   即扩容）。

use core::num::NonZeroU32;

/// H-P03 总预算（0.1 ms 定点单位）：四段合计 ≤ 30 = 3.0 ms（启动日志单列
/// 打点口径——真机窗四段打点随机械执行面批次落域，挂账如实登记）。
pub const H_P03_TOTAL_BUDGET_TENTHS: u32 = 30;

/// 预算段（0.1 ms 定点单位零浮点——H-P03 四段分解承载）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BudgetSegment {
    /// 段名（ostd RECON_SEGMENTS 四段同谱：load-map / reloc / tls-init /
    /// init-exec）。
    pub name: &'static str,
    /// 段预算（0.1 ms 定点单位——1.2 ms = 12 / 1.0 ms = 10 / 0.5 ms = 5 /
    /// 0.3 ms = 3）。
    pub budget_tenths: u32,
}

/// H-P03 四段预算分解权威表（细则条款逐段登记——合计 30 = 3.0 ms 总闸）。
pub const RECON_BUDGET_SEGMENTS: [BudgetSegment; 4] = [
    BudgetSegment {
        name: "load-map",
        budget_tenths: 12,
    },
    BudgetSegment {
        name: "reloc",
        budget_tenths: 10,
    },
    BudgetSegment {
        name: "tls-init",
        budget_tenths: 5,
    },
    BudgetSegment {
        name: "init-exec",
        budget_tenths: 3,
    },
];

/// 超支段位直接定位判读（H-P03 四段预算——`actual` 为四段实测值，0.1 ms
/// 定点单位，序与 [`RECON_BUDGET_SEGMENTS`] 对齐；返值 = 逐段超支旗，true =
/// 该段实测 > 段预算——段位直接定位，零聚合遮蔽）。
pub fn budget_overruns(actual: &[u32; 4]) -> [bool; 4] {
    let mut out = [false; 4];
    for (i, a) in actual.iter().enumerate() {
        out[i] = *a > RECON_BUDGET_SEGMENTS[i].budget_tenths;
    }
    out
}

/// 总闸判读（H-P03：四段合计 ≤ 3.0 ms——`actual` 序同上；返 false = 启动
/// 超支总闸翻红）。
pub fn budget_total_ok(actual: &[u32; 4]) -> bool {
    let mut sum: u32 = 0;
    for a in actual {
        sum += *a;
    }
    sum <= H_P03_TOTAL_BUDGET_TENTHS
}

/// GNU 式符号哈希（const fn 全回绕——5381 初值逐字节 × 33 异或；结构锚
/// 手算可验零外引黄金值：空串 = 5381；"a" = 5381 × 33 ^ 97 = 177604 =
/// 0x2B5C4）。
pub const fn dl_new_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < name.len() {
        h = h.wrapping_mul(33) ^ (name[i] as u32);
        i += 1;
    }
    h
}

/// Bloom 双位判读面板（GNU hash bloom 一级过滤——2 word × 64 位 + shift
/// 参数化）：`add` 置双位（bit1 = h 低 7 位、bit2 = (h >> shift) 低 7 位），
/// `may_contain` 判读——**双位齐置才可能命中，单位命中必不命中**（bloom
/// 纪律：可能命中 ≠ 必命中——二级精确比对随机械执行面批次落域）。
pub struct BloomPanel {
    words: [u64; 2],
    shift: u32,
}

impl BloomPanel {
    /// 构造（shift 参数化——GNU bloom_shift 口径；words 全零起步）。
    pub const fn new(shift: u32) -> Self {
        Self {
            words: [0; 2],
            shift,
        }
    }

    /// 置双位（h 低 7 位 + (h >> shift) 低 7 位——word = 位索引 / 64，
    /// 位偏 = 位索引 % 64）。
    pub fn add(&mut self, h: u32) {
        let b1 = (h & 0x7F) as usize;
        let b2 = ((h >> self.shift) & 0x7F) as usize;
        self.words[b1 / 64] |= 1u64 << (b1 % 64);
        self.words[b2 / 64] |= 1u64 << (b2 % 64);
    }

    /// 双位判读（双位齐置 = 可能命中；任一位缺 = 必不命中）。
    pub fn may_contain(&self, h: u32) -> bool {
        let b1 = (h & 0x7F) as usize;
        let b2 = ((h >> self.shift) & 0x7F) as usize;
        self.words[b1 / 64] & (1u64 << (b1 % 64)) != 0
            && self.words[b2 / 64] & (1u64 << (b2 % 64)) != 0
    }
}

/// 装载率告警阈值（百分制——细则「装载率超过 0.7 即触发告警」明文，
/// 0.7 = 70 百分制零浮点）。
pub const LOAD_FACTOR_WARN_PCT: u32 = 70;

/// 装载率百分制判读（零桶防御——buckets == 0 时 None fail-visible；
/// 返值 = filled / buckets 百分制整数）。
pub fn load_factor_pct(filled: usize, buckets: usize) -> Option<u32> {
    if buckets == 0 {
        return None;
    }
    Some(((filled as u64 * 100) / buckets as u64) as u32)
}

/// 装载率告警谓词（细则「超过 0.7 即触发」——严格大于阈值才告警；
/// 零桶 None fail-visible）。
pub fn load_factor_warn(filled: usize, buckets: usize) -> Option<bool> {
    load_factor_pct(filled, buckets).map(|pct| pct > LOAD_FACTOR_WARN_PCT)
}

/// DT_NEEDED 广度优先装载序（ELF 装载一次语义——去重幂等）：`roots` 根序
/// （可执行文件居首），`adj` 为逐 id 的 DT_NEEDED 邻接表（序 = 声明序）；
/// BFS 逐层展开，已装载 id 跳过（去重幂等）；任一入序 id 越出邻接表界 =
/// None fail-visible（零 panic 零默认序）。
pub fn needed_load_order(roots: &[u32], adj: &[&[u32]]) -> Option<alloc::vec::Vec<u32>> {
    let mut order = alloc::vec::Vec::new();
    let mut queued = alloc::vec::Vec::new();
    for r in roots {
        if (*r as usize) >= adj.len() {
            return None;
        }
        if !queued.contains(r) {
            queued.push(*r);
        }
    }
    let mut head = 0usize;
    while head < queued.len() {
        let id = queued[head];
        head += 1;
        order.push(id);
        let deps = adj[id as usize];
        for d in deps {
            let dv = *d;
            if (dv as usize) >= adj.len() {
                return None;
            }
            if !queued.contains(&dv) {
                queued.push(dv);
            }
        }
    }
    Some(order)
}

/// DFS 三色环检测（0 = 白未访 / 1 = 灰在栈 / 2 = 黑完成——灰遇灰即环；
/// fail-visible：任一入栈 id 越出邻接表界 = None）。返 Some(true) = 有环 /
/// Some(false) = 无环。
pub fn needs_cycle(roots: &[u32], adj: &[&[u32]]) -> Option<bool> {
    const WHITE: u8 = 0;
    const GREY: u8 = 1;
    const BLACK: u8 = 2;
    let mut color: alloc::vec::Vec<u8> = alloc::vec![WHITE; adj.len()];
    // 迭代式 DFS（显式栈——零递归零栈深约束；栈元素 = (id, 邻接游标)）
    let mut stack: alloc::vec::Vec<(u32, usize)> = alloc::vec::Vec::new();
    for r in roots {
        if (*r as usize) >= adj.len() {
            return None;
        }
        if color[*r as usize] == WHITE {
            stack.push((*r, 0));
            color[*r as usize] = GREY;
        }
        while let Some((id, cur)) = stack.pop() {
            let deps = adj[id as usize];
            let mut i = cur;
            let mut pushed = false;
            while i < deps.len() {
                let d = deps[i] as usize;
                if d >= adj.len() {
                    return None;
                }
                i += 1;
                if color[d] == GREY {
                    return Some(true); // 灰遇灰即环
                }
                if color[d] == WHITE {
                    color[d] = GREY;
                    stack.push((id, i)); // 本任务游标续扫
                    stack.push((deps[i - 1], 0)); // 深入子树
                    pushed = true;
                    break;
                }
            }
            if !pushed {
                color[id as usize] = BLACK; // 邻接扫尽——黑完成
            }
        }
    }
    Some(false)
}

/// 查找序命中段（三段组装判读——段位直接定位）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScopeHit {
    /// 第一段命中：可执行文件符号表。
    Exe,
    /// 第二段命中：广度优先依赖序第 `0` 段位模块（序位直接定位）。
    Dep(usize),
    /// 第三段命中：RTLD_GLOBAL 已插入序（垫底段）。
    Global,
}

/// 查找序三段组装（细则「可执行文件 → 广度优先依赖序 → 全局符号插入」
/// ELF 语义——**同名先见者胜**：线性扫过三段，首个含 target 的段即命中；
/// 三段皆缺 = None fail-visible）。
pub fn scope_lookup(target: u32, exe: &[u32], deps: &[&[u32]], global: &[u32]) -> Option<ScopeHit> {
    if exe.contains(&target) {
        return Some(ScopeHit::Exe);
    }
    for (i, tab) in deps.iter().enumerate() {
        if tab.contains(&target) {
            return Some(ScopeHit::Dep(i));
        }
    }
    if global.contains(&target) {
        return Some(ScopeHit::Global);
    }
    None
}

/// 重定位家族四类（gABI x86_64 权威类型码——判读面承载）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelocKind {
    /// R_X86_64_COPY = 5（数据复制——可执行文件引用库内对象落域）。
    Copy,
    /// R_X86_64_GLOB_DAT = 6（GOT 槽立即绑定）。
    GlobDat,
    /// R_X86_64_JUMP_SLOT = 7（PLT/GOT 槽——惰性绑定候选）。
    JumpSlot,
    /// R_X86_64_RELATIVE = 8（基址相对——装载地址补偿）。
    Relative,
}

/// 重定位家族判读（gABI 权威映射：5→Copy / 6→GlobDat / 7→JumpSlot /
/// 8→Relative；未知类型 None fail-visible）。
pub fn reloc_kind_of(rtype: u32) -> Option<RelocKind> {
    match rtype {
        5 => Some(RelocKind::Copy),
        6 => Some(RelocKind::GlobDat),
        7 => Some(RelocKind::JumpSlot),
        8 => Some(RelocKind::Relative),
        _ => None,
    }
}

/// 惰性绑定语义位（PLT/GOT 延迟绑定细则条款）：**JUMP_SLOT × !bind_now
/// 才可惰性**（首次调用解析——PLT 存根二次跳转口径）；JUMP_SLOT ×
/// bind_now（DT_FLAGS BIND_NOW / DT_BIND_NOW 在案）与 非 JUMP_SLOT 家族
/// 一律立即域。
pub fn lazy_bind(rtype: Option<RelocKind>, bind_now: bool) -> bool {
    rtype == Some(RelocKind::JumpSlot) && !bind_now
}

/// TLS 访问模型四类（gABI x86_64 权威重定位映射——TLS 初始化序判读面
/// 承载）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsModel {
    /// R_X86_64_TPOFF64 = 24 → local-exec（可执行文件自有 TLS——最快域）。
    LocalExec,
    /// R_X86_64_GOTTPOFF = 22 → initial-exec（GOT 间接——静态链接库域）。
    InitialExec,
    /// R_X86_64_TLSGD = 19 → general-dynamic（完整迟绑——dlopen 域）。
    GeneralDynamic,
    /// R_X86_64_TLSLD = 20 → local-dynamic（模块内迟绑）。
    LocalDynamic,
}

/// TLS 模型判读（gABI 权威映射：24→LocalExec / 22→InitialExec /
/// 19→GeneralDynamic / 20→LocalDynamic；未知类型 None fail-visible）。
pub fn tls_model_of(rtype: u32) -> Option<TlsModel> {
    match rtype {
        24 => Some(TlsModel::LocalExec),
        22 => Some(TlsModel::InitialExec),
        19 => Some(TlsModel::GeneralDynamic),
        20 => Some(TlsModel::LocalDynamic),
        _ => None,
    }
}

/// DTV 动态扩展判读核（modid 单调铸号越出现长即扩容——TLS 模块铸号 1 基；
/// `dtv_len` = 现长槽数，`modid` = 新模块铸号；modid > dtv_len 即需扩容，
/// modid ≤ dtv_len 原位可达）。
pub fn dtv_needs_resize(dtv_len: usize, modid: usize) -> bool {
    modid > dtv_len
}

/// 惰性绑定约束面（NonZeroU32 承载——类型码 0 = 空 R_X86_64_NONE 非家族
/// 成员，NonZero 类型面把零码挡在编译期）。语义同 [`reloc_kind_of`]——
/// 非零类型码 → 家族判读；None 家族外码 → None fail-visible。
pub fn reloc_kind_nz(rtype: NonZeroU32) -> Option<RelocKind> {
    reloc_kind_of(rtype.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H-P03 四段预算权威面：段名/预算逐目登记 + 合计 30 = 3.0 ms 总闸 +
    /// 段名与 ostd RECON_SEGMENTS 同谱对账。
    #[test]
    fn h_p03_budget_segments_authority() {
        assert_eq!(RECON_BUDGET_SEGMENTS.len(), 4);
        assert_eq!(RECON_BUDGET_SEGMENTS[0].name, "load-map");
        assert_eq!(RECON_BUDGET_SEGMENTS[0].budget_tenths, 12);
        assert_eq!(RECON_BUDGET_SEGMENTS[1].name, "reloc");
        assert_eq!(RECON_BUDGET_SEGMENTS[1].budget_tenths, 10);
        assert_eq!(RECON_BUDGET_SEGMENTS[2].name, "tls-init");
        assert_eq!(RECON_BUDGET_SEGMENTS[2].budget_tenths, 5);
        assert_eq!(RECON_BUDGET_SEGMENTS[3].name, "init-exec");
        assert_eq!(RECON_BUDGET_SEGMENTS[3].budget_tenths, 3);
        // 总闸权威：合计 30 = 3.0 ms（H-P03 启动 ≤ 3 ms）
        let sum: u32 = RECON_BUDGET_SEGMENTS.iter().map(|s| s.budget_tenths).sum();
        assert_eq!(sum, H_P03_TOTAL_BUDGET_TENTHS);
        assert_eq!(sum, 30);
        // 满预算实测 = 总闸绿
        let full = [12u32, 10, 5, 3];
        assert!(budget_total_ok(&full));
    }

    /// 超支段位直接定位判读：单段超支逐段旗定位 + 多段超支 + 总闸边界
    /// （30 绿 / 31 红）。
    #[test]
    fn h_p03_budget_overrun_localization() {
        // 单段超支（load-map 12 → 13）：仅段 0 翻旗
        let a = [13u32, 10, 5, 3];
        assert_eq!(budget_overruns(&a), [true, false, false, false]);
        assert!(!budget_total_ok(&a)); // 合计 31 超总闸
                                       // 多段超支（reloc 11 + tls-init 6）：段位直接定位
        let b = [12u32, 11, 6, 3];
        assert_eq!(budget_overruns(&b), [false, true, true, false]);
        assert!(!budget_total_ok(&b)); // 合计 32
                                       // 段内未超支但合计贴线：总闸边界 30 绿
        let c = [12u32, 10, 5, 3];
        assert_eq!(budget_overruns(&c), [false, false, false, false]);
        assert!(budget_total_ok(&c));
        // 段内零超支 + 合计贴线绿（各段让渡给 load-map 不越总闸）
        let d = [13u32, 9, 5, 3];
        assert_eq!(budget_overruns(&d), [true, false, false, false]);
        assert!(budget_total_ok(&d)); // 合计 30 = 总闸贴线绿
    }

    /// GNU 式符号哈希结构锚：空串 5381 + 单字符手算锚（"a" = 177604 =
    /// 0x2B5C4）+ const 上下文可编译 + 回绕不变式（wrapping 全回绕零
    /// panic）。
    #[test]
    fn dl_new_hash_algorithm_anchor() {
        // 结构锚：初值 5381
        const EMPTY: u32 = dl_new_hash(b"");
        assert_eq!(EMPTY, 5381);
        // 单字符手算锚：5381 × 33 = 177573 = 0x2B5A5；^ 0x61 = 0x2B5C4
        const A: u32 = dl_new_hash(b"a");
        assert_eq!(A, 177604);
        assert_eq!(A, 0x2B5C4);
        // 同串幂等 + 异串异值（判读面零碰撞声明域）
        assert_eq!(dl_new_hash(b"libc"), dl_new_hash(b"libc"));
        assert_ne!(dl_new_hash(b"libc"), dl_new_hash(b"libm"));
        // 回绕不变式：长输入 wrapping 全回绕零 panic
        const LONG: u32 = dl_new_hash(&[0xFF; 512]);
        let _ = LONG;
    }

    /// Bloom 双位判读纪律：双位齐置才可能命中 + 单位命中必不命中 + 空
    /// 面必不命中 + shift 参数化。
    #[test]
    fn bloom_panel_two_bit_discipline() {
        // shift = 7：bit1 = h & 127、bit2 = (h >> 7) & 127
        let mut p = BloomPanel::new(7);
        // 空 panel：任何 h 必不命中
        assert!(!p.may_contain(0x0F83));
        // h = 0x0F83：bit1 = 3、bit2 = 31——双位齐置
        p.add(0x0F83);
        assert!(p.may_contain(0x0F83));
        // 单位命中必不命中：0x83 仅 bit1=3（bit2=0 缺）；0x0F00 仅
        // bit2=31（bit1=0 缺）
        assert!(!p.may_contain(0x83));
        assert!(!p.may_contain(0x0F00));
        // 第二哈希入板（bit1=4、bit2=31——bit2 复用域）：双位齐命中
        p.add(0x0F84);
        assert!(p.may_contain(0x0F84));
        // 位图计数对账：words 位图 3 位（3、4、31）
        let bits = p.words[0].count_ones() + p.words[1].count_ones();
        assert_eq!(bits, 3);
    }

    /// 装载率告警阈值：0.7 阈值严格大于口径（70 = 阈值不告警 / 71 = 告
    /// 警）+ 零桶防御 + 百分制整数域。
    #[test]
    fn load_factor_warn_threshold() {
        assert_eq!(load_factor_pct(70, 100), Some(70));
        assert_eq!(load_factor_warn(70, 100), Some(false)); // 阈值贴线不告警
        assert_eq!(load_factor_warn(71, 100), Some(true)); // 超阈值告警
        assert_eq!(load_factor_pct(5, 10), Some(50));
        assert_eq!(load_factor_warn(5, 10), Some(false));
        assert_eq!(load_factor_pct(100, 100), Some(100));
        assert_eq!(load_factor_warn(100, 100), Some(true));
        assert_eq!(load_factor_pct(0, 100), Some(0));
        assert_eq!(load_factor_warn(0, 100), Some(false));
        // 零桶防御：None fail-visible
        assert_eq!(load_factor_pct(7, 0), None);
        assert_eq!(load_factor_warn(7, 0), None);
    }

    /// DT_NEEDED 广度优先装载序：BFS 层序 + 去重幂等（ELF 装载一次语义）
    /// + 根序保持。
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn needed_load_order_bfs_dedup() {
        // 0 → (1,2)；1 → (3)；2 → (1)（1 重复——去重幂等实锤）
        let adj: [&[u32]; 4] = [&[1, 2], &[3], &[1], &[]];
        let order = needed_load_order(&[0], &adj).expect("BFS 序");
        assert_eq!(order, alloc::vec![0, 1, 2, 3]);
        // 根序保持（可执行文件居首 + 多根声明序）
        let order2 = needed_load_order(&[3, 0], &adj).expect("多根序");
        assert_eq!(order2, alloc::vec![3, 0, 1, 2]);
        // 幂等：同入参重跑同序
        let order3 = needed_load_order(&[0], &adj).expect("幂等");
        assert_eq!(order, order3);
        // 越界 fail-visible：根越界 / 依赖越界 → None 零 panic
        assert!(needed_load_order(&[9], &adj).is_none());
        let bad: [&[u32]; 3] = [&[7], &[], &[]];
        assert!(needed_load_order(&[0], &bad).is_none());
    }

    /// DFS 三色环检测：灰遇灰即环（a→b→a）+ DAG 无环 + 越界 fail-visible。
    #[test]
    fn needs_cycle_fail_visible() {
        // 环：0 → 1 → 0
        let cyc: [&[u32]; 2] = [&[1], &[0]];
        assert_eq!(needs_cycle(&[0], &cyc), Some(true));
        // 自环：0 → 0
        let selfc: [&[u32]; 1] = [&[0]];
        assert_eq!(needs_cycle(&[0], &selfc), Some(true));
        // DAG：0 → 1 → 2（2 无依赖）
        let dag: [&[u32]; 3] = [&[1], &[2], &[]];
        assert_eq!(needs_cycle(&[0], &dag), Some(false));
        // 多根 DAG 无环
        assert_eq!(needs_cycle(&[0, 2], &dag), Some(false));
        // 越界 fail-visible
        let bad: [&[u32]; 2] = [&[5], &[]];
        assert!(needs_cycle(&[0], &bad).is_none());
        assert!(needs_cycle(&[4], &dag).is_none());
    }

    /// 查找序三段组装：同名先见者胜（exe 首段权威 / 依赖序 BFS 先见 /
    /// global 垫底）+ 段位直接定位 + 缺席 fail-visible。
    #[test]
    fn scope_chain_exe_bfs_global() {
        // exe 与 dep0 同持符号 7：exe 先见者胜
        let exe = [7u32, 1];
        let d0 = [7u32, 2, 3];
        let d1 = [3u32];
        let deps: [&[u32]; 2] = [&d0, &d1];
        let g = [9u32];
        assert_eq!(scope_lookup(7, &exe, &deps, &g), Some(ScopeHit::Exe));
        // dep1 与 dep0 同持符号 3：BFS 序先见（dep0）
        assert_eq!(scope_lookup(3, &exe, &deps, &g), Some(ScopeHit::Dep(0)));
        // 仅 dep1 持有：段位直接定位
        let d1b = [3u32, 5];
        let deps2: [&[u32]; 2] = [&[2u32], &d1b];
        assert_eq!(scope_lookup(5, &exe, &deps2, &g), Some(ScopeHit::Dep(1)));
        // 仅 global 持有：垫底段命中
        assert_eq!(scope_lookup(9, &exe, &deps, &g), Some(ScopeHit::Global));
        // 三段皆缺：None fail-visible
        assert_eq!(scope_lookup(42, &exe, &deps, &g), None);
    }

    /// 重定位家族判读：gABI 权威四类映射（5/6/7/8）+ 未知类型 None
    /// fail-visible + NonZero 类型面零码挡编译期。
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn reloc_family_judgement() {
        assert_eq!(reloc_kind_of(5), Some(RelocKind::Copy));
        assert_eq!(reloc_kind_of(6), Some(RelocKind::GlobDat));
        assert_eq!(reloc_kind_of(7), Some(RelocKind::JumpSlot));
        assert_eq!(reloc_kind_of(8), Some(RelocKind::Relative));
        // 未知类型：None fail-visible（0 NONE / 1 64 / 9 PC32-B 之外域）
        assert_eq!(reloc_kind_of(0), None);
        assert_eq!(reloc_kind_of(4), None);
        assert_eq!(reloc_kind_of(9), None);
        assert_eq!(reloc_kind_of(u32::MAX), None);
        // NonZero 类型面：零码编译期挡除
        let nz = NonZeroU32::new(7).expect("非零");
        assert_eq!(reloc_kind_nz(nz), Some(RelocKind::JumpSlot));
    }

    /// 惰性绑定语义位：JUMP_SLOT × !bind_now 才可惰性 + bind_now 立即域
    /// + 非 JUMP_SLOT 家族一律立即域。
    #[test]
    fn lazy_bind_semantics() {
        // 惰性：JUMP_SLOT ∧ !bind_now
        assert!(lazy_bind(Some(RelocKind::JumpSlot), false));
        // BIND_NOW：立即域
        assert!(!lazy_bind(Some(RelocKind::JumpSlot), true));
        // 非 JUMP_SLOT 家族：一律立即域
        assert!(!lazy_bind(Some(RelocKind::GlobDat), false));
        assert!(!lazy_bind(Some(RelocKind::Copy), false));
        assert!(!lazy_bind(Some(RelocKind::Relative), false));
        // 家族外（None）：立即域
        assert!(!lazy_bind(None, false));
    }

    /// TLS 四模型判读：gABI 权威映射（24/22/19/20）+ 未知类型 None
    /// fail-visible。
    #[test]
    fn tls_model_four_way() {
        assert_eq!(tls_model_of(24), Some(TlsModel::LocalExec));
        assert_eq!(tls_model_of(22), Some(TlsModel::InitialExec));
        assert_eq!(tls_model_of(19), Some(TlsModel::GeneralDynamic));
        assert_eq!(tls_model_of(20), Some(TlsModel::LocalDynamic));
        // 未知类型：None fail-visible
        assert_eq!(tls_model_of(0), None);
        assert_eq!(tls_model_of(21), None);
        assert_eq!(tls_model_of(23), None);
        assert_eq!(tls_model_of(u32::MAX), None);
    }

    /// DTV 动态扩展判读核：modid 单调铸号越出现长即扩容 + 边界原位可达。
    #[test]
    fn dtv_resize_judgement() {
        // 现长 8：modid 1..=8 原位可达
        assert!(!dtv_needs_resize(8, 1));
        assert!(!dtv_needs_resize(8, 8));
        // modid 9 = 越出现长 → 扩容
        assert!(dtv_needs_resize(8, 9));
        // 初始空表：modid 1 即扩容
        assert!(dtv_needs_resize(0, 1));
        // 单调铸号语义：扩容后现长 = 新长，同号不再扩
        assert!(!dtv_needs_resize(16, 16));
        assert!(dtv_needs_resize(16, 17));
    }
}
