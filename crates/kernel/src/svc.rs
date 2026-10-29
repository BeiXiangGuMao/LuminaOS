//! 驱动服务框架结构面（M34-D1 首割）——服务注册表定容表 + 请求/应答
//! IPC 通道契约 + 驱动进程形态 fail-visible。
//!
//! **电气面零改动宣言**（M34-计划 口径裁决注④）：本模块为纯结构面——
//! M31-N1 五清点域（vnet 1,743 / fb 953 / kbd 250 / console 212 / block
//! 134）的 kernel 驱动代码路径零触碰；注册表 boot 面把五驱动登记为
//! **内核态占位**（[`Owner::KernelResident`]），通道域 (0, 0) = 占位未铸
//! （请求/应答通道对随服务化批次铸造）。缩编起算域不变（M31-N1 三分
//! 分级：纯函数面 crate 化外移先行〔morse 已外移〕；电气面待用户态驱动
//! 进程基础设施成熟分批；策略面随服务化批次）。
//!
//! **契约单一事实源** = [`bedrock::abi`]（SVC_MAX 定容 / SVC_NAME_MAX
//! 词法上界 / SVC_ID_BASE 段基 0x5E00 与文件 0xF11E、通道 0xC0DE 段正交
//! / [`bedrock::abi::svc_name_ok`] 词法闸——宿主对账测试在 bedrock）。
//! 本模块承载运行时：注册（fail-visible）/ 查找 / 快照三 API。
//!
//! **fail-visible 错误集**：重名/重 id（AlreadyRegistered）/ 满容（Full
//! ——SVC_MAX 定容）/ 词法违规（BadName）/ 通道段位违规（InvalidChannel
//! ——(0,0) 占位或双 is_channel_object，单边铸半对拒绝）/ id 段位越域
//! （BadId）。注册闸全数显形，不静默降级。
//!
//! unsafe 面：零（SpinLock + Vec 定容，ostd 同构）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use ostd::sync::SpinLock;

use bedrock::abi::{
    svc_name_ok, SVC_BLOCK, SVC_CONSOLE, SVC_FB, SVC_ID_BASE, SVC_KBD, SVC_MAX, SVC_VNET,
};

/// 注册失败集（fail-visible；注册闸全数显形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcError {
    /// 服务名或 id 已注册（重名/重 id 同闸）。
    AlreadyRegistered,
    /// 注册表满容（SVC_MAX 定容）。
    Full,
    /// 服务名词法违规（bedrock::abi::svc_name_ok 未过）。
    BadName,
    /// 通道域违规：既非 (0,0) 占位、亦非双通道对象（单边铸半对拒绝）。
    InvalidChannel,
    /// 服务 id 段位越域（0x5E00 段外）。
    BadId,
}

/// 驱动进程形态（M31-N1 三分分级承载）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// 内核态占位（v0 口径：电气面未迁移——驱动进程形态随服务化批次；
    /// 本轮五驱动全数此形态）。
    KernelResident,
    /// 用户态驱动进程（任务槽位——后续批次形态；结构面预登记域，
    /// D 批次启用——v0 五驱动全数内核态占位）。
    #[allow(dead_code)]
    UserTask(usize),
}

/// 服务注册项：请求/应答 IPC 通道契约 + 进程形态。
#[derive(Debug, Clone, Copy)]
pub struct ServiceEntry {
    /// 服务 id（0x5E00 段）。
    pub id: u64,
    /// 服务名（词法闸已过）。
    pub name: &'static str,
    /// 请求通道对象 id（0 = 占位未铸——电气面未迁移口径）。
    pub req_ch: u64,
    /// 应答通道对象 id（0 = 占位未铸）。
    pub resp_ch: u64,
    /// 驱动进程形态。
    pub owner: Owner,
}

/// 服务注册表（定容 Vec<Option<_>；槽位复用与 FILES/CHANNELS 同构）。
static SVCS: SpinLock<Vec<Option<ServiceEntry>>> = SpinLock::new(alloc::vec::Vec::new());
/// boot 注册对账锚（init 幂等闸：二次 init 拒绝——fail-visible）。
static BOOT_N: AtomicU64 = AtomicU64::new(0);

/// 注册闸（fail-visible 全数显形）：词法 → id 段位 → 通道域 → 重名/重
/// id → 满容。成功返回注册表槽位号。
pub fn register(
    id: u64,
    name: &'static str,
    req_ch: u64,
    resp_ch: u64,
    owner: Owner,
) -> Result<usize, SvcError> {
    // 1) 词法闸（bedrock 契约单一事实源）
    if !svc_name_ok(name) {
        return Err(SvcError::BadName);
    }
    // 2) id 段位闸（0x5E00 段基起）
    if id <= SVC_ID_BASE || id > SVC_ID_BASE + SVC_MAX as u64 {
        return Err(SvcError::BadId);
    }
    // 3) 通道域闸：(0,0) 占位 OR 双通道对象（单边半对拒绝）
    let chan_pair = (req_ch, resp_ch);
    if chan_pair != (0, 0)
        && !(crate::ipc::is_channel_object(req_ch) && crate::ipc::is_channel_object(resp_ch))
    {
        return Err(SvcError::InvalidChannel);
    }
    let mut svcs = SVCS.lock();
    // 4) 重名/重 id 闸
    if svcs
        .iter()
        .any(|s| s.as_ref().is_some_and(|e| e.id == id || e.name == name))
    {
        return Err(SvcError::AlreadyRegistered);
    }
    // 5) 满容闸 + 槽位占用
    let slot = match svcs
        .iter()
        .enumerate()
        .find_map(|(i, s)| s.is_none().then_some(i))
    {
        Some(i) => i,
        None if svcs.len() < SVC_MAX => {
            svcs.push(None);
            svcs.len() - 1
        }
        None => return Err(SvcError::Full),
    };
    svcs[slot] = Some(ServiceEntry {
        id,
        name,
        req_ch,
        resp_ch,
        owner,
    });
    Ok(slot)
}

/// 服务查找：id →（名, 请求通道, 应答通道, 形态是否用户态）。未命中
/// None（调用方 fail-visible 自裁）。
pub fn lookup(id: u64) -> Option<(&'static str, u64, u64, Owner)> {
    let svcs = SVCS.lock();
    svcs.iter().flatten().find(|e| e.id == id).map(|e| {
        (
            e.name,
            e.req_ch,
            e.resp_ch,
            match e.owner {
                Owner::KernelResident => Owner::KernelResident,
                Owner::UserTask(t) => Owner::UserTask(t),
            },
        )
    })
}

/// 注册表快照（取证面）：(已用槽位, SVC_MAX, 已注册 id 位图——bit n =
/// id = SVC_ID_BASE + n)。
pub fn snapshot() -> (usize, usize, u64) {
    let svcs = SVCS.lock();
    let mut mask = 0u64;
    let mut used = 0usize;
    for e in svcs.iter().flatten() {
        let off = e.id - SVC_ID_BASE;
        if off < 64 {
            mask |= 1u64 << off;
        }
        used += 1;
    }
    (used, SVC_MAX, mask)
}

/// boot 注册面（幂等闸：二次调用拒绝返回 0——kmain 单调用点，防御
/// 面语义）。五驱动全数 [`Owner::KernelResident`] + (0, 0) 占位通道。
/// 返回成功注册数（对账闸 = [`bedrock::abi::SVC_PRESET_COUNT`]）。
pub fn init() -> usize {
    if BOOT_N.load(Ordering::Acquire) != 0 {
        return 0; // 幂等闸（fail-visible——重复 init 计 0，对账闸必炸）
    }
    let presets: [(u64, &'static str); 5] = [
        (SVC_VNET, "vnet"),
        (SVC_FB, "fb"),
        (SVC_KBD, "kbd"),
        (SVC_CONSOLE, "console"),
        (SVC_BLOCK, "block"),
    ];
    let mut n = 0usize;
    for (id, name) in presets {
        if register(id, name, 0, 0, Owner::KernelResident).is_ok() {
            n += 1;
        }
    }
    // 自证消费（fail-visible）：五 id 全数 lookup 命中才算注册完整
    // （半注册/重名吞没在此显形——对账闸由 kmain 的 n==SVC_PRESET_COUNT
    // 承担，本循环把 lookup 面纳入 boot 对账域）。
    for (id, name) in presets {
        match lookup(id) {
            Some((n2, _, _, Owner::KernelResident)) if n2 == name => {}
            _ => {
                n = 0;
                break;
            }
        }
    }
    BOOT_N.store(n as u64, Ordering::Release);
    n
}
