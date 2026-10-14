//! Vanguard 前卫 —— 能力模型（capability-based security）。
//!
//! 依据《指标与规范手册》第 8 章（Vanguard）：系统全部特权操作以能力令牌授权，
//! 令牌只能「派生收窄」，不能「派生扩权」；本 crate 定义能力位、能力表与派生规则，
//! 供 Bedrock（内核侧引用计数）与 Meridian（服务侧令牌消费）共同使用。
//!
//! 本 crate 为 `no_std` 纯类型实现：无堆、无锁、无 IO，可同时用于内核态与用户态。
#![no_std]

/// 能力权限位。语义与 SPEC 第 8 章权限中心一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Right(u8);

impl Right {
    /// 读对象。
    pub const READ: Right = Right(1 << 0);
    /// 写对象。
    pub const WRITE: Right = Right(1 << 1);
    /// 执行映射。
    pub const EXEC: Right = Right(1 << 2);
    /// 派生进程。
    pub const SPAWN: Right = Right(1 << 3);
    /// IPC 发送。
    pub const IPC_SEND: Right = Right(1 << 4);
    /// IPC 接收。
    pub const IPC_RECV: Right = Right(1 << 5);
    /// 文件系统根访问。
    pub const FS_ROOT: Right = Right(1 << 6);
    /// 网络绑定。
    pub const NET_BIND: Right = Right(1 << 7);

    /// 全部权限位集合。
    pub const ALL: u32 = 0xFF;

    /// 以位掩码构造（保留未定义位为 0）。
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL == 0 && bits.count_ones() == 1 {
            Some(Right(bits as u8))
        } else {
            None
        }
    }

    /// 位掩码。
    pub const fn bits(self) -> u32 {
        self.0 as u32
    }
}

/// 能力令牌：指向某对象的一组收窄权限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    object: u64,
    rights: u32,
}

/// 能力表错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// 槽位为空。
    SlotEmpty,
    /// 槽位不存在。
    NoSuchSlot,
    /// 派生请求包含父能力没有的权限（提权），拒绝。
    RightsEscalation,
}

/// 固定容量能力表。槽位编号即用户态句柄值（handle）。
pub struct CapabilityTable {
    slots: [Option<Capability>; CAPACITY],
}

/// 能力表槽位容量。
pub const CAPACITY: usize = 64;

impl CapabilityTable {
    /// 创建全空能力表。
    pub const fn new() -> Self {
        const NONE: Option<Capability> = None;
        Self {
            slots: [NONE; CAPACITY],
        }
    }

    /// 向指定槽位写入能力（仅内核启动期使用）。
    pub fn install(&mut self, slot: usize, cap: Capability) -> Result<(), CapError> {
        match self.slots.get_mut(slot) {
            None => Err(CapError::NoSuchSlot),
            Some(s) => {
                *s = Some(cap);
                Ok(())
            }
        }
    }

    /// 读取槽位能力。
    pub fn get(&self, slot: usize) -> Result<Capability, CapError> {
        match self.slots.get(slot).copied() {
            None => Err(CapError::NoSuchSlot),
            Some(None) => Err(CapError::SlotEmpty),
            Some(Some(c)) => Ok(c),
        }
    }

    /// 从父能力派生子能力：权限 MUST 为父权限子集，禁止提权。
    pub fn derive(&mut self, parent_slot: usize, rights: u32) -> Result<usize, CapError> {
        let parent = self.get(parent_slot)?;
        if rights & !parent.rights() != 0 {
            return Err(CapError::RightsEscalation);
        }
        let child = Capability {
            object: parent.object(),
            rights,
        };
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.is_none() {
                *s = Some(child);
                return Ok(i);
            }
        }
        Err(CapError::NoSuchSlot)
    }

    /// 撤销槽位能力（不可恢复）。
    pub fn revoke(&mut self, slot: usize) -> Result<(), CapError> {
        match self.slots.get_mut(slot) {
            None => Err(CapError::NoSuchSlot),
            Some(s @ Some(_)) => {
                *s = None;
                Ok(())
            }
            Some(None) => Err(CapError::SlotEmpty),
        }
    }

    /// 已占用槽位数。
    pub fn used(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability {
    /// 以对象 id 与权限位构造能力（仅系统初始信任边界内可用）。
    pub const fn new(object: u64, rights: u32) -> Self {
        Self {
            object,
            rights: rights & Right::ALL,
        }
    }

    /// 目标对象 id。
    pub const fn object(&self) -> u64 {
        self.object
    }

    /// 权限位掩码。
    pub const fn rights(&self) -> u32 {
        self.rights
    }

    /// 是否具备指定权限。
    pub const fn has(&self, right: Right) -> bool {
        self.rights & right.bits() != 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CapError, Capability, CapabilityTable, Right};

    #[test]
    fn derive_cannot_escalate() {
        let mut t = CapabilityTable::new();
        t.install(
            0,
            Capability::new(1, Right::READ.bits() | Right::WRITE.bits()),
        )
        .expect("install root");
        assert_eq!(
            t.derive(0, Right::EXEC.bits()),
            Err(CapError::RightsEscalation)
        );
        let child = t.derive(0, Right::READ.bits()).expect("subset derive");
        assert!(t.get(child).expect("child").has(Right::READ));
        assert!(!t.get(child).expect("child").has(Right::WRITE));
    }

    #[test]
    fn revoke_and_slot_errors() {
        let mut t = CapabilityTable::new();
        t.install(3, Capability::new(9, Right::IPC_SEND.bits()))
            .expect("install");
        assert_eq!(t.get(4), Err(CapError::SlotEmpty));
        assert_eq!(t.get(999), Err(CapError::NoSuchSlot));
        t.revoke(3).expect("revoke");
        assert_eq!(t.get(3), Err(CapError::SlotEmpty));
        assert_eq!(t.revoke(3), Err(CapError::SlotEmpty));
    }

    #[test]
    fn right_from_bits_rejects_multi_and_unknown() {
        assert!(Right::from_bits(0b11).is_none());
        assert!(Right::from_bits(1 << 9).is_none());
        assert!(Right::from_bits(Right::NET_BIND.bits()).is_some());
    }
}
