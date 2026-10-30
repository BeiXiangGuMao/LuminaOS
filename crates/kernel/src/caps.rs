//! 系统能力表（M6-B）：Vanguard 能力模型的内核侧全局承载。
//!
//! 单一事实源：按需分页（vmm 的映射门禁）与 IPC 系统调用面（ipc 的通道
//! 门禁）共用同一张 [`CapabilityTable`]——任务的能力槽号（`Task::cap_slot`）
//! 在全系统语义一致，任何特权操作的授权判定都在同一信任面上完成。
//!
//! 槽位编号即任务侧句柄；`Task::cap_slot` 记录调用方当前持有的槽位，
//! 系统调用入口经 [`table`] + 槽号做对象与权限校验（只可收窄派生由
//! Vanguard `derive` 的 RightsEscalation 拒绝路径保证）。
//!
//! unsafe 面：零。自旋锁 + 纯类型能力令牌。

use ostd::sync::SpinLock;
pub use vanguard::{Capability, CapabilityTable};

/// 全局能力表（静态存储期；槽位容量 = vanguard::CAPACITY）。
static CAPS: SpinLock<CapabilityTable> = SpinLock::new(CapabilityTable::new());

/// 能力表全局访问句柄。
pub fn table() -> &'static SpinLock<CapabilityTable> {
    &CAPS
}

/// 分配首个空闲全局槽位并装载能力（M11 测试面；语义与 spawn 主身份
/// 安装一致：槽位单属主不变式由互斥锁窗口保证）。满表返回 None。
pub fn alloc_slot(cap: Capability) -> Option<usize> {
    let mut t = table().lock();
    for s in 0..vanguard::CAPACITY {
        if t.get(s).is_err() {
            return t.install(s, cap).ok().map(|_| s);
        }
    }
    None
}
