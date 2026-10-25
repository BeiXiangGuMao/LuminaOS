//! perm —— 权限中心首割（AF-P03 权限面，M32-A1）。
//!
//! 四相管线（ROADMAP M32-A1 结构界定）：
//!
//! ① **声明 schema 闸**：[`check_schema`] 对 `cap.<域>.<资源>.<动作>` 四段
//!    格式闸（`cap.` 前缀 + 段字符集小写字母 / 数字 / 下划线 + 段数恰四）；
//! ② **安装时授予**：动作段经能力目录 [`action_right`] 映射为 vanguard
//!    `Right` 权限位，经 [`vanguard::CapabilityTable::install`] 落表（承接桥，
//!    [`PermCenter::grant`] / [`PermCenter::grant_manifest`]）；
//! ③ **运行时检查拒绝显形**：[`PermCenter::check`] 对不含请求权限的槽位
//!    显形 [`PermError::Denied`]（fail-visible，无静默放行，拒绝零副作用）；
//! ④ **撤销后访问显形**：[`PermCenter::revoke`] 后再访问显形
//!    [`PermError::SlotEmpty`]（死槽语义沿 vanguard 表面透传）。
//!
//! vanguard 能力模型为单一事实源——本模块零改动 vanguard 本体（M31-V1 先例），
//! 仅以消费面承接（M32-A1 政策边 aurora→vanguard，allowlist 台账先行）。
//! 权限中心自身维护一份影子台账（槽位 → 声明名）供审计与首空槽分配：本结构
//! 是 vanguard 表的唯一写者（grant/revoke 两口），故影子首空槽即表面首空槽，
//! 占用不变式「影子占用数 == `CapabilityTable::used()`」由宿主测试在环断言。
//!
//! 检查序为确定性失败序：**目录闸（动作段已知）→ 槽位闸（存在且已装）→
//! 权限闸（位含）**——任意失败即短路显形，不留痕零副作用。

use alloc::{string::String, vec::Vec};
use vanguard::{Capability, CapabilityTable, Right, CAPACITY};

/// 权限中心错误集（fail-visible，无静默吞并）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermError {
    /// 声明 schema 非法：`cap.` 前缀 + 恰四段 + 段字符集闸（小写字母数字下划线）。
    BadCapability,
    /// 动作段不在能力目录（无法映射 vanguard `Right` 位）。
    UnknownAction,
    /// 运行时检查拒绝：槽位能力不含请求权限。
    Denied,
    /// 槽位为空（未授予或已撤销——撤销后访问显形形态）。
    SlotEmpty,
    /// 槽位不存在（越界），或容量已满（授予/清单声明数超空闲槽）。
    NoSuchSlot,
    /// 提权拒绝（承接桥不经 derive 路径——此形态显形即桥缺陷信号）。
    Escalation,
}

/// vanguard [`vanguard::CapError`] → 权限中心错误全域映射（承接口径单一）。
fn perm_err(e: vanguard::CapError) -> PermError {
    match e {
        vanguard::CapError::SlotEmpty => PermError::SlotEmpty,
        vanguard::CapError::NoSuchSlot => PermError::NoSuchSlot,
        vanguard::CapError::RightsEscalation => PermError::Escalation,
    }
}

/// 校验单条能力声明的 schema（四相①声明闸）。
///
/// 规则：以 `.` 分段**恰四段**——第 1 段恒为 `cap`（能力命名域前缀），第 2/3
/// 段为域与资源（非空），第 4 段为动作（非空；动作是否在能力目录由授予面
/// 判定）；全段字符集为小写字母 / 数字 / 下划线（与清单 app_id 同规）。
pub fn check_schema(cap_decl: &str) -> Result<(), PermError> {
    let segs: Vec<&str> = cap_decl.split('.').collect();
    let ok = segs.len() == 4
        && segs[0] == "cap"
        && segs.iter().all(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
    if ok {
        Ok(())
    } else {
        Err(PermError::BadCapability)
    }
}

/// 能力目录：动作段 → vanguard `Right` 位映射（四相②承接桥的单一事实源）。
///
/// 目录八动作与 vanguard 八权限位一一对应；目录为闭集——目录外动作在授予 /
/// 检查面显形 [`PermError::UnknownAction`]（能力授予不可凭空生权）。
pub fn action_right(action: &str) -> Option<Right> {
    match action {
        "read" => Some(Right::READ),
        "write" => Some(Right::WRITE),
        "exec" => Some(Right::EXEC),
        "spawn" => Some(Right::SPAWN),
        "send" => Some(Right::IPC_SEND),
        "recv" => Some(Right::IPC_RECV),
        "fsroot" => Some(Right::FS_ROOT),
        "bind" => Some(Right::NET_BIND),
        _ => None,
    }
}

/// 权限中心：清单能力声明 → vanguard 能力表的承接面（四相②③④运行体）。
pub struct PermCenter {
    table: CapabilityTable,
    /// 影子台账：槽位 → 已授予能力声明名（审计面 + 首空槽分配依据）。
    names: Vec<Option<String>>,
}

impl PermCenter {
    /// 创建全空权限中心（影子台账与 vanguard 表同构 `CAPACITY` 槽）。
    pub fn new() -> Self {
        Self {
            table: CapabilityTable::new(),
            names: Vec::from_iter((0..CAPACITY).map(|_| None)),
        }
    }

    /// 安装时授予（四相②）：声明经 schema 闸 + 能力目录映射后落 vanguard 表。
    ///
    /// 返回分配的槽位号（首空槽确定性分配——与 vanguard `derive` 同规）；
    /// `object` 为能力指向的对象 id（应用安装期由框架分配，全链传播语义随
    /// vanguard 值语义）。任一闸失败即拒绝且零落表（零副作用不变式）。
    pub fn grant(&mut self, cap_decl: &str, object: u64) -> Result<usize, PermError> {
        check_schema(cap_decl)?;
        let action = cap_decl.split('.').nth(3).ok_or(PermError::BadCapability)?;
        let right = action_right(action).ok_or(PermError::UnknownAction)?;
        let slot = self
            .names
            .iter()
            .position(Option::is_none)
            .ok_or(PermError::NoSuchSlot)?;
        self.table
            .install(slot, Capability::new(object, right.bits()))
            .map_err(perm_err)?;
        self.names[slot] = Some(String::from(cap_decl));
        Ok(slot)
    }

    /// 清单原子授予（承接桥入口）：`LuappManifest` 声明集一次性落表。
    ///
    /// 两遍扫描保原子性——第一遍全量闸（逐条 schema + 目录），任一声明非法
    /// 即整单拒绝且零安装（仿 V-P05「含一位非法即全拒，不放行部分子集」）；
    /// 容量预闸（声明数 > 空闲槽整单拒绝）后第二遍逐条落表。返回槽位号表
    /// （与声明顺序同序）。重复声明各自独立落槽（去重策略随 SDK 服务面裁决，
    /// v0 不折叠）。
    pub fn grant_manifest(
        &mut self,
        manifest: &crate::LuappManifest,
        object: u64,
    ) -> Result<Vec<usize>, PermError> {
        // 第一遍：全量闸（schema + 目录），零安装
        let mut rights = Vec::new();
        for decl in &manifest.capabilities {
            check_schema(decl)?;
            let action = decl.split('.').nth(3).ok_or(PermError::BadCapability)?;
            rights.push(action_right(action).ok_or(PermError::UnknownAction)?);
        }
        // 容量预闸：需求 > 空闲 → 整单拒绝（保第二遍零中途失败）
        let free = CAPACITY - self.table.used();
        if manifest.capabilities.len() > free {
            return Err(PermError::NoSuchSlot);
        }
        // 第二遍：逐条落表（schema/目录/容量均已过，闸不再失败）
        let mut slots = Vec::new();
        for (decl, right) in manifest.capabilities.iter().zip(rights) {
            let slot = self
                .names
                .iter()
                .position(Option::is_none)
                .ok_or(PermError::NoSuchSlot)?;
            self.table
                .install(slot, Capability::new(object, right.bits()))
                .map_err(perm_err)?;
            self.names[slot] = Some(decl.clone());
            slots.push(slot);
        }
        Ok(slots)
    }

    /// 运行时权限检查（四相③）：槽位能力须含动作对应权限位。
    ///
    /// 确定性失败序：目录闸（`UnknownAction`）→ 槽位闸（`NoSuchSlot` /
    /// `SlotEmpty`）→ 权限闸（`Denied`）。拒绝显形不留痕（零副作用）。
    pub fn check(&self, slot: usize, action: &str) -> Result<(), PermError> {
        let right = action_right(action).ok_or(PermError::UnknownAction)?;
        let cap = self.table.get(slot).map_err(perm_err)?;
        if cap.has(right) {
            Ok(())
        } else {
            Err(PermError::Denied)
        }
    }

    /// 撤销槽位能力（四相④入口；不可恢复——死槽语义沿 vanguard 表面）。
    ///
    /// 撤销后对该槽的 [`PermCenter::check`] 显形 [`PermError::SlotEmpty`]；
    /// 重复撤销同显形。影子台账同步清账（占用不变式维持）。
    pub fn revoke(&mut self, slot: usize) -> Result<(), PermError> {
        self.table.revoke(slot).map_err(perm_err)?;
        if let Some(n) = self.names.get_mut(slot) {
            *n = None;
        }
        Ok(())
    }

    /// 已占用槽位数（透传 vanguard 表面）。
    pub fn used(&self) -> usize {
        self.table.used()
    }

    /// 影子台账审计面：槽位的已授予声明名（空槽返回 `None`）。
    pub fn name(&self, slot: usize) -> Option<&str> {
        self.names.get(slot).and_then(Option::as_deref)
    }
}

impl Default for PermCenter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{action_right, check_schema, PermCenter, PermError, CAPACITY};
    use crate::LuappManifest;
    use alloc::{format, vec};
    use vanguard::Right;

    /// 四相① schema 闸矩阵：合法态 + 非法态全枚举（前缀 / 段数 / 空段 / 字符集）。
    #[test]
    fn schema_gate_matrix() {
        // 合法态：规范四段（域 / 资源 / 动作均过字符集闸）
        assert_eq!(check_schema("cap.fs.documents.read"), Ok(()));
        assert_eq!(check_schema("cap.net.socket.bind"), Ok(()));
        assert_eq!(check_schema("cap.fs2.docs_1.read"), Ok(()), "数字与下划线");
        // 前缀闸：非 cap 前缀显形
        assert_eq!(
            check_schema("caps.fs.documents.read"),
            Err(PermError::BadCapability)
        );
        assert_eq!(
            check_schema("CAP.fs.documents.read"),
            Err(PermError::BadCapability)
        );
        // 段数闸：三段（缺资源）与五段（资源越深）均显形
        assert_eq!(
            check_schema("fs.documents.read"),
            Err(PermError::BadCapability)
        );
        assert_eq!(check_schema("cap.fs.read"), Err(PermError::BadCapability));
        assert_eq!(
            check_schema("cap.fs.documents.deep.read"),
            Err(PermError::BadCapability)
        );
        // 空段与字符集闸（大写 / 连字符 / 尾点 / 空串）
        assert_eq!(check_schema("cap.fs..read"), Err(PermError::BadCapability));
        assert_eq!(
            check_schema("cap.fs.Documents.read"),
            Err(PermError::BadCapability)
        );
        assert_eq!(
            check_schema("cap.fs.documents.re-ad"),
            Err(PermError::BadCapability)
        );
        assert_eq!(
            check_schema("cap.fs.documents."),
            Err(PermError::BadCapability)
        );
        assert_eq!(check_schema(""), Err(PermError::BadCapability));
    }

    /// 能力目录：八动作满映射（vanguard 八权限位一一对应）+ 目录外拒收。
    #[test]
    fn action_catalog_maps_all_vanguard_rights() {
        let catalog = [
            ("read", Right::READ),
            ("write", Right::WRITE),
            ("exec", Right::EXEC),
            ("spawn", Right::SPAWN),
            ("send", Right::IPC_SEND),
            ("recv", Right::IPC_RECV),
            ("fsroot", Right::FS_ROOT),
            ("bind", Right::NET_BIND),
        ];
        for (name, right) in catalog {
            assert_eq!(action_right(name), Some(right), "catalog action {name}");
        }
        // 目录闭集：目录外 / 大小写敏感 / 空动作均拒收
        assert_eq!(action_right("admin"), None);
        assert_eq!(action_right("Read"), None);
        assert_eq!(action_right(""), None);
    }

    /// 四相贯通：授予 → 运行时检查（拒绝显形零副作用）→ 撤销 → 撤销后访问显形。
    #[test]
    fn four_phase_pipeline() {
        let mut pc = PermCenter::new();
        // ② 安装时授予：schema 闸过 + 目录映射 READ，首空槽确定性分配
        let slot = pc.grant("cap.fs.documents.read", 100).expect("grant");
        assert_eq!(slot, 0);
        assert_eq!(pc.name(slot), Some("cap.fs.documents.read"), "影子审计面");
        // ③ 运行时检查：具备权限放行
        assert_eq!(pc.check(slot, "read"), Ok(()));
        // ③ 拒绝显形：不含 WRITE / EXEC → Denied
        assert_eq!(pc.check(slot, "write"), Err(PermError::Denied));
        assert_eq!(pc.check(slot, "exec"), Err(PermError::Denied));
        // 拒绝零副作用：占用数不变
        assert_eq!(pc.used(), 1);
        // ④ 撤销后访问显形：SlotEmpty 死槽语义 + 重复撤销显形
        pc.revoke(slot).expect("revoke");
        assert_eq!(pc.check(slot, "read"), Err(PermError::SlotEmpty));
        assert_eq!(
            pc.revoke(slot),
            Err(PermError::SlotEmpty),
            "重复撤销必须显形"
        );
        assert_eq!(pc.used(), 0);
        assert!(pc.name(slot).is_none(), "影子台账同步清账");
    }

    /// 确定性失败序：目录闸 → 槽位闸 → 权限闸（未知动作在空槽 / 越界槽上仍显形 UnknownAction）。
    #[test]
    fn deterministic_check_order() {
        let pc = PermCenter::new();
        // 目录闸先行：未知动作压过槽位形态
        assert_eq!(pc.check(0, "admin"), Err(PermError::UnknownAction));
        assert_eq!(pc.check(999, "admin"), Err(PermError::UnknownAction));
        // 越界槽 + 已知动作 → NoSuchSlot
        assert_eq!(pc.check(999, "read"), Err(PermError::NoSuchSlot));
        // 界内空槽（未授予）+ 已知动作 → SlotEmpty
        assert_eq!(pc.check(0, "read"), Err(PermError::SlotEmpty));
    }

    /// 承接桥不变式：影子台账与 vanguard 表面同源同步 + 首空槽回收复用。
    #[test]
    fn bridge_shadow_invariants() {
        let mut pc = PermCenter::new();
        let a = pc.grant("cap.fs.documents.read", 1).expect("a");
        let b = pc.grant("cap.ipc.channel.send", 2).expect("b");
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(pc.used(), 2);
        pc.revoke(a).expect("revoke a");
        // 首空槽复用：新授予落回收槽 0
        let c = pc.grant("cap.net.socket.bind", 3).expect("c");
        assert_eq!(c, 0);
        // 影子与表面同源：占用数一致 + 名称面同步 + 空槽审计面为 None
        assert_eq!(pc.used(), 2);
        assert_eq!(pc.name(0), Some("cap.net.socket.bind"));
        assert_eq!(pc.name(1), Some("cap.ipc.channel.send"));
        assert!(pc.name(2).is_none());
        assert_eq!(pc.name(CAPACITY), None, "越界槽审计面 None 不 panic");
    }

    /// 清单原子授予：全量闸任一非法即整单拒绝零安装（V-P05「全拒不放行部分子集」同构）。
    #[test]
    fn manifest_atomic_grant() {
        let good = LuappManifest {
            app_id: "org.lumina.notes".into(),
            display_name: "Notes".into(),
            version: "0.3.1".into(),
            capabilities: vec![
                "cap.fs.documents.read".into(),
                "cap.ipc.channel.send".into(),
                "cap.net.socket.bind".into(),
            ],
        };
        assert_eq!(good.validate(), Ok(()));
        let mut pc = PermCenter::new();
        let slots = pc.grant_manifest(&good, 7).expect("atomic grant");
        assert_eq!(slots, vec![0, 1, 2], "槽位号与声明顺序同序");
        assert_eq!(pc.used(), 3);
        assert_eq!(pc.check(0, "read"), Ok(()));
        assert_eq!(pc.check(1, "send"), Ok(()));
        assert_eq!(pc.check(2, "bind"), Ok(()));

        // 混入非法 schema 声明 → 整单拒绝零安装
        let bad_schema = LuappManifest {
            capabilities: vec![
                "cap.fs.documents.read".into(),
                "cap.fs.Documents.read".into(),
            ],
            ..good.clone()
        };
        let mut pc = PermCenter::new();
        assert_eq!(
            pc.grant_manifest(&bad_schema, 7),
            Err(PermError::BadCapability)
        );
        assert_eq!(pc.used(), 0, "零部分安装");

        // 混入目录外动作 → 整单拒绝零安装
        let bad_action = LuappManifest {
            capabilities: vec![
                "cap.fs.documents.read".into(),
                "cap.fs.documents.admin".into(),
            ],
            ..good
        };
        let mut pc = PermCenter::new();
        assert_eq!(
            pc.grant_manifest(&bad_action, 7),
            Err(PermError::UnknownAction)
        );
        assert_eq!(pc.used(), 0, "零部分安装");
    }

    /// 容量不变式：清单容量预闸（需求 > 空闲整单拒绝）+ 满表逐条授予显形与回收复用。
    #[test]
    fn capacity_invariants() {
        // 清单容量预闸：先占 60 槽，10 条声明 > 剩余 4 槽 → 整单拒绝零安装
        let big = LuappManifest {
            app_id: "org.lumina.big".into(),
            display_name: "Big".into(),
            version: "1.0.0".into(),
            capabilities: (0..10).map(|i| format!("cap.fs.res{i}.read")).collect(),
        };
        let mut pc = PermCenter::new();
        for i in 0..(CAPACITY - 4) {
            pc.grant("cap.fs.documents.read", i as u64)
                .expect("fill slots");
        }
        assert_eq!(
            pc.grant_manifest(&big, 999),
            Err(PermError::NoSuchSlot),
            "容量预闸整单拒绝"
        );
        assert_eq!(pc.used(), CAPACITY - 4, "零部分安装");

        // 逐条授予：满 64 槽后显形 NoSuchSlot；撤销后槽位复用
        let mut pc = PermCenter::new();
        for i in 0..CAPACITY {
            assert_eq!(pc.grant("cap.fs.documents.read", i as u64), Ok(i));
        }
        assert_eq!(
            pc.grant("cap.fs.documents.read", 999),
            Err(PermError::NoSuchSlot),
            "满表拒绝"
        );
        pc.revoke(CAPACITY - 1).expect("free last");
        assert_eq!(pc.grant("cap.fs.documents.read", 999), Ok(CAPACITY - 1));
    }
}
