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
    use super::{CapError, Capability, CapabilityTable, Right, CAPACITY};

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

    /// V-P05 首批注入矩阵 · 相组一：四相故障注入（仿 WE-P02 `we_p02_fault_matrix` 先例）。
    ///
    /// 逐相注入非法操作，断言错误显形（fail-visible）+ 表状态零副作用：
    /// ① 越权派生 ② 撤销后使用 ③ 未安装槽访问 ④ 重复撤销。
    #[test]
    fn v_p05_injection_matrix() {
        // ① 越权派生相：derive 请求父集外权限 → RightsEscalation。
        let mut t = CapabilityTable::new();
        t.install(
            0,
            Capability::new(7, Right::READ.bits() | Right::WRITE.bits()),
        )
        .expect("install root");
        // 单位越权（EXEC 不在父集）
        assert_eq!(
            t.derive(0, Right::EXEC.bits()),
            Err(CapError::RightsEscalation)
        );
        // 混合请求越权：含一位非法即全拒，不放行部分子集
        assert_eq!(
            t.derive(0, Right::READ.bits() | Right::EXEC.bits()),
            Err(CapError::RightsEscalation)
        );
        // 全位越权与未定义位越权（bit 8+ 不在 ALL 内）均显形
        assert_eq!(t.derive(0, Right::ALL), Err(CapError::RightsEscalation));
        assert_eq!(t.derive(0, 1 << 8), Err(CapError::RightsEscalation));
        // 零副作用不变式：拒绝派生不留痕——占用数不变、子槽仍空、父能力原样
        assert_eq!(t.used(), 1);
        assert_eq!(t.get(1), Err(CapError::SlotEmpty));
        let root = t.get(0).expect("root intact");
        assert!(root.has(Right::READ));
        assert!(root.has(Right::WRITE));
        assert!(!root.has(Right::EXEC));
        // 边界合法态：空权限集 ⊆ 任意父集 → 零权限能力合法派生（最小组不变式）
        let void_slot = t.derive(0, 0).expect("empty-rights derive is a subset");
        let void_cap = t.get(void_slot).expect("void cap");
        assert_eq!(void_cap.rights(), 0);
        assert!(!void_cap.has(Right::READ));
        // 对象传播不变式：子能力继承父 object
        assert_eq!(void_cap.object(), 7);

        // ② 撤销后使用相：撤销后的槽即死——读/为父派生全部显形 SlotEmpty。
        let mut t = CapabilityTable::new();
        t.install(0, Capability::new(1, Right::IPC_SEND.bits()))
            .expect("install");
        let child = t.derive(0, Right::IPC_SEND.bits()).expect("derive child");
        t.revoke(0).expect("revoke parent");
        assert_eq!(t.get(0), Err(CapError::SlotEmpty));
        assert_eq!(
            t.derive(0, Right::IPC_SEND.bits()),
            Err(CapError::SlotEmpty),
            "dead slot must not serve as derive parent"
        );
        // 值语义显形：撤销父不级联撤销子（子槽为派生时刻的快照）；
        // 级联撤销属 Bedrock 内核侧引用计数面，能力表表面不承担。
        assert!(t.get(child).is_ok());
        assert!(t.get(child).expect("child alive").has(Right::IPC_SEND));

        // ③ 未安装槽访问相：空槽（界内未安装）与越界槽全操作面显形，错误语义两级分明。
        let mut t = CapabilityTable::new();
        t.install(5, Capability::new(2, Right::READ.bits()))
            .expect("install@5");
        // 界内空槽 → SlotEmpty
        assert_eq!(t.get(0), Err(CapError::SlotEmpty));
        assert_eq!(t.derive(0, Right::READ.bits()), Err(CapError::SlotEmpty));
        assert_eq!(t.revoke(0), Err(CapError::SlotEmpty));
        // 越界槽 → NoSuchSlot（恰在界外 CAPACITY 与远界 999）
        assert_eq!(t.get(CAPACITY), Err(CapError::NoSuchSlot));
        assert_eq!(t.get(999), Err(CapError::NoSuchSlot));
        assert_eq!(
            t.install(CAPACITY, Capability::new(2, Right::READ.bits())),
            Err(CapError::NoSuchSlot)
        );
        assert_eq!(t.revoke(CAPACITY), Err(CapError::NoSuchSlot));
        // derive 以越界槽为父：错误语义随 get 传播 → NoSuchSlot
        assert_eq!(
            t.derive(CAPACITY, Right::READ.bits()),
            Err(CapError::NoSuchSlot)
        );
        // 边界合法槽：首槽 0 与末槽 CAPACITY-1 可达
        t.install(0, Capability::new(3, Right::EXEC.bits()))
            .expect("first slot");
        t.install(CAPACITY - 1, Capability::new(4, Right::NET_BIND.bits()))
            .expect("last slot");
        assert!(t.get(CAPACITY - 1).expect("last").has(Right::NET_BIND));

        // ④ 重复撤销相：二次与 N 次撤销均显形 SlotEmpty，且不伤邻槽（隔离不变式）。
        let mut t = CapabilityTable::new();
        t.install(1, Capability::new(8, Right::WRITE.bits()))
            .expect("install@1");
        t.install(2, Capability::new(9, Right::READ.bits()))
            .expect("install@2");
        assert_eq!(t.used(), 2);
        t.revoke(1).expect("first revoke");
        assert_eq!(
            t.revoke(1),
            Err(CapError::SlotEmpty),
            "double revoke must be visible"
        );
        assert_eq!(
            t.revoke(1),
            Err(CapError::SlotEmpty),
            "n-th revoke stays visible"
        );
        assert!(t.get(2).expect("neighbor intact").has(Right::READ));
        assert_eq!(t.used(), 1);
    }

    /// V-P05 首批注入矩阵 · 相组二：derive 链传播语义全枚举非法态。
    ///
    /// 任意深度不可回升（收窄单调）+ 对象同源 + 零权限链最小组 + 环满容量显形 + 链尾清账。
    #[test]
    fn v_p05_derive_chain_matrix() {
        // 合法三级链：A(READ|WRITE) → B(READ) → C(READ)
        let mut t = CapabilityTable::new();
        t.install(
            0,
            Capability::new(42, Right::READ.bits() | Right::WRITE.bits()),
        )
        .expect("install A");
        let b = t.derive(0, Right::READ.bits()).expect("A→B");
        let c = t.derive(b, Right::READ.bits()).expect("B→C");
        assert_eq!(t.used(), 3);
        // 对象同源不变式：全链 object 同源
        for s in [0usize, b, c] {
            assert_eq!(t.get(s).expect("chain slot").object(), 42);
        }
        // 收窄单调不变式：链上权限不增
        assert_eq!(t.get(b).expect("B").rights(), Right::READ.bits());
        assert_eq!(t.get(c).expect("C").rights(), Right::READ.bits());

        // 非法态全枚举：链中任意深度提权均显形拒绝
        assert_eq!(
            t.derive(b, Right::WRITE.bits()),
            Err(CapError::RightsEscalation),
            "mid-chain must not recover grandparent right"
        );
        assert_eq!(
            t.derive(c, Right::EXEC.bits()),
            Err(CapError::RightsEscalation),
            "chain tail must not escalate"
        );
        assert_eq!(
            t.derive(c, Right::READ.bits() | Right::WRITE.bits()),
            Err(CapError::RightsEscalation),
            "mixed request with one illegal bit is rejected whole"
        );
        assert_eq!(
            t.derive(c, Right::ALL),
            Err(CapError::RightsEscalation),
            "full-rights request is rejected"
        );
        // 拒绝零副作用：链状态不变
        assert_eq!(t.used(), 3);

        // 零权限链：零权限能力仍可派生零权限，但不可凭空生权
        let z = t.derive(c, 0).expect("zero-rights derive");
        assert_eq!(t.get(z).expect("Z").rights(), 0);
        assert_eq!(
            t.derive(z, Right::READ.bits()),
            Err(CapError::RightsEscalation),
            "zero-rights chain stays powerless"
        );

        // 环满显形：填满 64 槽后再派生 → NoSuchSlot（容量不变式）；释放一槽后可复用
        let mut full = CapabilityTable::new();
        full.install(0, Capability::new(1, Right::ALL))
            .expect("install root@0");
        for i in 1..CAPACITY {
            assert_eq!(full.derive(0, Right::READ.bits()), Ok(i), "fill slot {i}");
        }
        assert_eq!(full.used(), CAPACITY);
        assert_eq!(
            full.derive(0, Right::READ.bits()),
            Err(CapError::NoSuchSlot),
            "full table must refuse further derives"
        );
        full.revoke(CAPACITY - 1).expect("free last slot");
        assert_eq!(
            full.derive(0, Right::READ.bits()),
            Ok(CAPACITY - 1),
            "freed slot is reused"
        );

        // 链尾清账：逐环撤销（含零权限尾槽）后全表归空
        t.revoke(c).expect("revoke C");
        t.revoke(b).expect("revoke B");
        t.revoke(z).expect("revoke Z");
        t.revoke(0).expect("revoke A");
        assert_eq!(t.used(), 0);
    }
}
