//! 用户态设备访问面（M42-FBDEV1）——SYS_DEV_PIO 端口裁量注册表 +
//! 内核代执车道。
//!
//! **定位（M42 阶段一「用户态 fb 驱动进程」首笔——ADR-0004 混合态
//! 渐进）**：x86 IOPB/IOPL 硬件裁量域零起点（M42-计划 三域挂账之一）
//! 的 v0 承接形态——ring3 不直接执行 in/out（IOPL 保持 0、TSS IOPB
//! 不挂），端口电气由内核以 [`ostd::hw::ports`] 白名单原语**代执**；
//! 授权域 = 本模块端口裁量注册表（per-pid 区间授予，**boot/spawn
//! 路径铸授**——用户态不可自授，特权面收口于内核）。硬件面转化
//! （IOPL 提权 / IOPB 挂 TSS）随驱动进程基础设施批次落域，寄存器面
//! （bedrock::abi v0.19 SYS_DEV_PIO）冻结不变，代执车道与硬件车道
//! 同语义承接。
//!
//! **fail-visible 错误集**：区间非法（BadRange：lo > hi）/ 重复授予
//! （AlreadyGranted：同 pid 同区间幂等面拒绝改写）/ 满容（Full——
//! [`PIO_GRANT_CAP`] 定容）。授权 miss 在 [`sys_dev_pio`] 侧显形为
//! [`bedrock::abi::ERR_CAP`]（不泄露端口占用拓扑——capability 拒绝
//! 同面语义）。
//!
//! unsafe 面：零（端口 I/O 全走 `ostd::hw::ports` 安全原语；
//! SpinLock + Vec 定容，svc 同构纪律）。

use core::sync::atomic::{AtomicU64, Ordering};

use ostd::sync::SpinLock;

/// 授权注册表容量（定容；v0 驱动进程批次域——fbdev 单授予 + 余量）。
pub const PIO_GRANT_CAP: usize = 8;

/// 单条端口裁量授权：pid × 闭区间 [lo, hi]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PioGrant {
    /// 被授权任务 pid（任务槽位号——spawn 返回值同源）。
    pub pid: u64,
    /// 区间下界（含）。
    pub lo: u16,
    /// 区间上界（含）。
    pub hi: u16,
}

/// 授权失败集（fail-visible；铸授闸全数显形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PioGrantError {
    /// 区间非法（lo > hi）。
    BadRange,
    /// 重复授予（同 pid 同区间已铸——幂等改写拒绝）。
    AlreadyGranted,
    /// 注册表满容（[`PIO_GRANT_CAP`] 定容）。
    Full,
}

/// 端口裁量注册表（定容 Vec<Option<_>>；槽位复用与 SVCS 同构）。
static PIO_GRANTS: SpinLock<alloc::vec::Vec<Option<PioGrant>>> =
    SpinLock::new(alloc::vec::Vec::new());

/// 执行面取证戳：IN 次数 / OUT 次数 / 末端口 / 末读值 / 末 op。
static PIO_IN_N: AtomicU64 = AtomicU64::new(0);
static PIO_OUT_N: AtomicU64 = AtomicU64::new(0);
static PIO_LAST_PORT: AtomicU64 = AtomicU64::new(0);
static PIO_LAST_VALUE: AtomicU64 = AtomicU64::new(0);
static PIO_LAST_OP: AtomicU64 = AtomicU64::new(0);

/// 授权铸造（fail-visible 显形）：区间闸 → **幂等闸**（同 pid 同区间 →
/// 幂等放行返回既有槽位——任务槽位复用再授予面：t101 fbdev 与 t102
/// 常驻服务序贯同槽〔spawn 槽位回收复用〕，adopt_user 幂等同 pid 先例
/// 同款；异 pid 同区间 / 同 pid 异区间维持 AlreadyGranted 拒——
/// fail-visible）→ 满容闸。调用域 = boot/spawn 路径（内核裁量面）——
/// ring3 自授通道不存在。
pub fn pio_grant(pid: u64, lo: u16, hi: u16) -> Result<usize, PioGrantError> {
    // 1) 区间闸
    if lo > hi {
        return Err(PioGrantError::BadRange);
    }
    let mut grants = PIO_GRANTS.lock();
    // 2) 幂等闸（同 pid 同区间 → 既有槽位幂等放行——M42-FBSVC2：t101
    //    fbdev 退出后任务槽位被 t102 常驻服务复用，原「重复授予即拒」
    //    语义把槽位复用误判为改写；幂等放行 = 授予面收敛于最终态）
    if let Some(i) = grants.iter().enumerate().find_map(|(i, g)| {
        g.as_ref()
            .filter(|g| g.pid == pid && g.lo == lo && g.hi == hi)
            .map(|_| i)
    }) {
        return Ok(i);
    }
    // 3) 冲突闸（异 pid 同区间 / 同 pid 异区间改写——拒绝）
    if grants
        .iter()
        .flatten()
        .any(|g| g.pid == pid || (g.lo == lo && g.hi == hi))
    {
        return Err(PioGrantError::AlreadyGranted);
    }
    // 4) 满容闸 + 槽位复用
    let slot = match grants
        .iter()
        .enumerate()
        .find_map(|(i, g)| g.is_none().then_some(i))
    {
        Some(i) => i,
        None if grants.len() < PIO_GRANT_CAP => {
            grants.push(None);
            grants.len() - 1
        }
        None => return Err(PioGrantError::Full),
    };
    grants[slot] = Some(PioGrant { pid, lo, hi });
    Ok(slot)
}

/// 端口裁量判定：pid 在任一授权区间内 → true。注册表 miss = 拒
/// （[`sys_dev_pio`] 侧显形 ERR_CAP，不泄露占用拓扑）。
pub fn pio_check(pid: u64, port: u16) -> bool {
    PIO_GRANTS
        .lock()
        .iter()
        .flatten()
        .any(|g| g.pid == pid && port >= g.lo && port <= g.hi)
}

/// 执行面取证快照：(IN 次数, OUT 次数, 末端口, 末读值, 末 op)。
/// t101 成像对账面（dispi 读值 ≥ dispi::ID_MIN 断言数据源）。
pub fn pio_stamps() -> (u64, u64, u64, u64, u64) {
    (
        PIO_IN_N.load(Ordering::Acquire),
        PIO_OUT_N.load(Ordering::Acquire),
        PIO_LAST_PORT.load(Ordering::Acquire),
        PIO_LAST_VALUE.load(Ordering::Acquire),
        PIO_LAST_OP.load(Ordering::Acquire),
    )
}

/// SYS_DEV_PIO 主体（M42-FBDEV1）：裁量闸 → 白名单原语代执 → 取证戳。
///
/// - `op`/`port` 已由 abi parse 层预检（op ≤ [`bedrock::abi::PIO_OUT32`]
///   / port ≤ 0xFFFF），此处只做裁量与代执（纵深防御：解码双检）；
/// - IN = 零扩展读值返回；OUT = 0；裁量 miss = [`bedrock::abi::ERR_CAP`]；
/// - 代执语义：内核上下文执行端口 I/O（ring3 无 in/out 路径——IOPL=0
///   下用户态执行 in/out 触 #GP 落致命域，本面是唯一端口车道）。
pub fn sys_dev_pio(op: u64, port: u16, value: u64) -> u64 {
    use bedrock::abi::{pio_op_decode, ERR_CAP};
    const BAD_ARGS: u64 = u64::MAX - 1;
    let pid = crate::procs::current_pid();
    if !pio_check(pid, port) {
        return ERR_CAP;
    }
    let Some((width, is_out)) = pio_op_decode(op) else {
        return BAD_ARGS; // 纵深防御：parse 层已检，域外 op 不可能达此
    };
    PIO_LAST_PORT.store(u64::from(port), Ordering::Release);
    PIO_LAST_OP.store(op, Ordering::Release);
    match (width, is_out) {
        (1, false) => {
            let v = u64::from(ostd::hw::ports::read_u8(port));
            PIO_IN_N.fetch_add(1, Ordering::AcqRel);
            PIO_LAST_VALUE.store(v, Ordering::Release);
            v
        }
        (1, true) => {
            ostd::hw::ports::write_u8(port, value as u8);
            PIO_OUT_N.fetch_add(1, Ordering::AcqRel);
            0
        }
        (2, false) => {
            let v = u64::from(ostd::hw::ports::read_u16(port));
            PIO_IN_N.fetch_add(1, Ordering::AcqRel);
            PIO_LAST_VALUE.store(v, Ordering::Release);
            v
        }
        (2, true) => {
            ostd::hw::ports::write_u16(port, value as u16);
            PIO_OUT_N.fetch_add(1, Ordering::AcqRel);
            0
        }
        (4, false) => {
            let v = u64::from(ostd::hw::ports::read_u32(port));
            PIO_IN_N.fetch_add(1, Ordering::AcqRel);
            PIO_LAST_VALUE.store(v, Ordering::Release);
            v
        }
        (4, true) => {
            ostd::hw::ports::write_u32(port, value as u32);
            PIO_OUT_N.fetch_add(1, Ordering::AcqRel);
            0
        }
        _ => BAD_ARGS, // 不可达（解码器全谱闭合）
    }
}
