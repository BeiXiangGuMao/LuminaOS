//! WE-P02 断电注入框架——双代际根槽事务 + 提交路径分相注入 + 恢复不变式。
//!
//! 承接 Weave 细则第 15 章「代际事务」机制面（M29-W1）：安装/卸载一律走
//! 代际事务——**提交不可重复、回滚不残留**。本模块把这一承诺落成可注入
//! 验证的机制：
//!
//! - **双代际根槽**：根 = `{gen, 摘要, CRC32}` 两槽轮换（[`GenRoot`]），
//!   提交点 = 活跃槽翻转（单字节指针翻转，进程内原子）；
//! - **注入点矩阵**（[`PowerFault`]）：提交路径四相——prepare 后 /
//!   根槽写入中（撕裂）/ 翻转前 / 翻转后，任一相注入「掉电」后调用
//!   [`GenRoot::recover`] 重演恢复；
//! - **恢复不变式**（宿主矩阵全谱断言）：其一，已提交不丢——翻转后
//!   掉电恢复得新代；其二，回滚不残留——翻转前掉电（含 prepare 后）
//!   恢复得旧代、新载荷不上浮（恢复规则 = 活跃指针胜出，非「最高代
//!   胜出」，未过提交点的新代即便 CRC 完好也不得晋升）；其三，撕裂
//!   可检出——写入中途掉电留 CRC 失配残槽，恢复期丢弃不入账；其四，
//!   代际单调——崩溃恢复后重试提交，代龄严格递增不重置。
//!
//! **CRC32（IEEE 802.3）**：存储校验和，位翻转/撕裂残留检出防线；
//! FNV-1a 64 只作内容寻址（[`crate::store`]），二者职责分离。
//!
//! v0 范围界定：根槽为进程内结构（载荷以完整字节落槽 + CRC32）；持久
//! 介质落盘随 crystal 块域对账批挂账（M26 格式 v1 WAL 为文件系统侧
//! 对应物）；多事务并发调度挂账（v0 单事务串行）。

use alloc::vec::Vec;
use core::fmt;

/// 断电注入点：提交路径分相（WE-P02 矩阵）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerFault {
    /// prepare 相完成（新代根槽已完整写入 CRC 校验域）即掉电——未过提交点。
    AfterPrepare,
    /// 新代根槽写入中途掉电——撕裂残留（部分字节 + CRC 失配）。
    MidRootWrite,
    /// 活跃槽翻转前掉电——提交点之前（回滚域）。
    BeforeFlip,
    /// 活跃槽翻转后掉电——提交点之后（已提交域）。
    AfterFlip,
}

impl fmt::Display for PowerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            PowerFault::AfterPrepare => "after-prepare",
            PowerFault::MidRootWrite => "mid-root-write",
            PowerFault::BeforeFlip => "before-flip",
            PowerFault::AfterFlip => "after-flip",
        };
        f.write_str(name)
    }
}

/// 提交结果：完成或注入掉电（需 [`GenRoot::recover`] 观测恢复态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// 提交完成（活跃代龄）。
    Committed(u64),
    /// 注入掉电于指定相。
    Crashed(PowerFault),
}

/// 恢复报告：掉电后 [`GenRoot::recover`] 的重演结论（**库态语义**
/// ——报告哪个代在活跃位；事务命运属策略面 `Transaction`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// 恢复得已提交代（代龄）——提交点已过或崩溃未达提交点（旧代
    /// 完整保留 = 回滚无残留的库态表达）。
    Committed(u64),
    /// 空库（无任何有效代）。
    Empty,
}

/// CRC32（IEEE 802.3，查表-free 位算法；v0 无预表，长度域小成本可接受）。
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// 根槽：一代事务的落点 `{gen, 摘要, CRC32}`。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootSlot {
    gen: u64,
    /// 载荷 FNV-1a 64 摘要（内容身份，与 store::ObjectId 同源）。
    hash: u64,
    /// 载荷 + gen 的 CRC32（撕裂/位翻转检出域）。
    crc: u32,
    torn: bool,
}

impl RootSlot {
    fn valid(&self) -> bool {
        !self.torn && self.crc == Self::crc_of(self.gen, self.hash)
    }

    fn crc_of(gen: u64, hash: u64) -> u32 {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&gen.to_le_bytes());
        buf.extend_from_slice(&hash.to_le_bytes());
        crc32(&buf)
    }
}

/// 双代际根槽库：活跃槽指针 + 两槽轮换（WE-P02 机制面本体）。
pub struct GenRoot {
    slots: [Option<RootSlot>; 2],
    active: usize,
}

impl GenRoot {
    /// 空库（无任何代）。
    pub const fn new() -> Self {
        Self {
            slots: [None, None],
            active: 0,
        }
    }

    /// 当前活跃代龄（无代返回 0）。
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.slots[self.active].as_ref().map_or(0, |s| s.gen)
    }

    /// 完整提交路径（prepare → 根槽写入 → 翻转），可选注入掉电。
    ///
    /// 相序：一，prepare（新代 = 活跃代 + 1）；二，非活跃槽写入（载荷
    /// 摘要与 CRC32）；三，活跃指针翻转（提交点）。注入语义：在指定相
    /// 「掉电」，返回 [`CommitOutcome::Crashed`] 且库保持掉电瞬间态
    /// （撕裂残槽留存），由 [`GenRoot::recover`] 重演。
    pub fn commit(&mut self, payload: &[u8], fault: Option<PowerFault>) -> CommitOutcome {
        let next_gen = self.generation() + 1;
        let hash = crate::store::fnv1a64(payload);
        let inactive = 1 - self.active;
        match fault {
            Some(PowerFault::AfterPrepare) => {
                // prepare 完成：新代账目在册（策略面 Transaction 同相），
                // 未写根槽即掉电——非活跃槽维持原态（空或旧残留）。
                return CommitOutcome::Crashed(PowerFault::AfterPrepare);
            }
            Some(PowerFault::MidRootWrite) => {
                // 撕裂写入：部分摘要字节 + 失配 CRC（残槽留存）
                let torn_hash = hash ^ 0xFF00_0000_0000_0000;
                self.slots[inactive] = Some(RootSlot {
                    gen: next_gen,
                    hash: torn_hash,
                    crc: RootSlot::crc_of(next_gen, hash), // CRC 与 torn 摘要失配
                    torn: true,
                });
                return CommitOutcome::Crashed(PowerFault::MidRootWrite);
            }
            _ => {}
        }
        self.slots[inactive] = Some(RootSlot {
            gen: next_gen,
            hash,
            crc: RootSlot::crc_of(next_gen, hash),
            torn: false,
        });
        if fault == Some(PowerFault::BeforeFlip) {
            return CommitOutcome::Crashed(PowerFault::BeforeFlip);
        }
        // 提交点：活跃指针翻转
        self.active = inactive;
        if fault == Some(PowerFault::AfterFlip) {
            return CommitOutcome::Crashed(PowerFault::AfterFlip);
        }
        CommitOutcome::Committed(next_gen)
    }

    /// 掉电重演恢复：校验两槽（CRC + torn 旗），撕裂残槽丢弃；
    /// **只保留活跃代**——非活跃槽的一切残留（未过提交点的新代、
    /// 撕裂残片）清零（回滚不残留不变式的机制承载）；恢复规则 =
    /// 活跃指针胜出（非「最高代胜出」——未过提交点的新代即便 CRC
    /// 完好也不得晋升）。活跃槽介质失效时回落备份槽（v0：写入只落
    /// 非活跃槽，活跃槽失效仅出现在介质位翻转场景；回落即放弃崩溃
    /// 中的新代）。
    pub fn recover(&mut self) -> Recovery {
        // 撕裂/失配残槽显形丢弃
        for slot in &mut self.slots {
            if let Some(s) = slot {
                if !s.valid() {
                    *slot = None;
                }
            }
        }
        let active_valid = self.slots[self.active].is_some();
        if !active_valid && self.slots[1 - self.active].is_some() {
            // 活跃槽介质失效：回落备份槽
            self.active = 1 - self.active;
        }
        // 回滚不残留：非活跃槽清零（未提交代数据不得跨恢复存活）
        self.slots[1 - self.active] = None;
        match self.slots[self.active].as_ref() {
            Some(a) => Recovery::Committed(a.gen),
            None => Recovery::Empty,
        }
    }

    /// 未提交残留检查：非活跃槽是否仍持槽（恢复后应恒为 false）。
    #[must_use]
    pub fn uncommitted_residue(&self) -> bool {
        self.slots[1 - self.active].is_some()
    }
}

impl Default for GenRoot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// WE-P02 注入点矩阵全谱：四相掉电 × 恢复不变式逐项断言。
    ///
    /// 不变式以库态表达：提交点前掉电 → 活跃代不变（回滚无残留，
    /// 新代不上浮）；提交点后掉电 → 新代保留（已提交不丢）。
    #[test]
    fn we_p02_fault_matrix() {
        let payload_v1 = b"weave-pkg-v1";
        let payload_v2 = b"weave-pkg-v2";

        // ① 基线：无故障提交往返
        let mut g = GenRoot::new();
        assert_eq!(g.commit(payload_v1, None), CommitOutcome::Committed(1));
        assert_eq!(g.recover(), Recovery::Committed(1));
        assert!(!g.uncommitted_residue());

        // ② AfterPrepare：prepare 后掉电 → 旧代保留（新代未上浮）
        let mut g = GenRoot::new();
        assert_eq!(g.commit(payload_v1, None), CommitOutcome::Committed(1));
        assert_eq!(
            g.commit(payload_v2, Some(PowerFault::AfterPrepare)),
            CommitOutcome::Crashed(PowerFault::AfterPrepare)
        );
        assert_eq!(g.recover(), Recovery::Committed(1));
        assert!(!g.uncommitted_residue(), "rollback must leave no residue");

        // ③ MidRootWrite：撕裂残留 CRC 失配 → 丢弃不入账 → 旧代保留
        let mut g = GenRoot::new();
        assert_eq!(g.commit(payload_v1, None), CommitOutcome::Committed(1));
        assert_eq!(
            g.commit(payload_v2, Some(PowerFault::MidRootWrite)),
            CommitOutcome::Crashed(PowerFault::MidRootWrite)
        );
        assert_eq!(g.recover(), Recovery::Committed(1));
        assert!(!g.uncommitted_residue(), "torn slot must be discarded");

        // ④ BeforeFlip：根槽已完整写入但未翻转 → 旧代保留
        //    （恢复规则 = 活跃指针胜出，非最高代胜出——未过提交点不上浮）
        let mut g = GenRoot::new();
        assert_eq!(g.commit(payload_v1, None), CommitOutcome::Committed(1));
        assert_eq!(
            g.commit(payload_v2, Some(PowerFault::BeforeFlip)),
            CommitOutcome::Crashed(PowerFault::BeforeFlip)
        );
        assert_eq!(g.recover(), Recovery::Committed(1));
        assert!(
            !g.uncommitted_residue(),
            "uncommitted new gen must be purged"
        );

        // ⑤ AfterFlip：翻转后掉电 → 新代保留（已提交不丢）
        let mut g = GenRoot::new();
        assert_eq!(g.commit(payload_v1, None), CommitOutcome::Committed(1));
        assert_eq!(
            g.commit(payload_v2, Some(PowerFault::AfterFlip)),
            CommitOutcome::Crashed(PowerFault::AfterFlip)
        );
        assert_eq!(g.recover(), Recovery::Committed(2));
    }

    /// 崩溃恢复后重试提交：代龄严格递增不重置。
    #[test]
    fn retry_after_crash_monotonic_gen() {
        let mut g = GenRoot::new();
        assert_eq!(g.commit(b"v1", None), CommitOutcome::Committed(1));
        assert_eq!(
            g.commit(b"v2-crash", Some(PowerFault::MidRootWrite)),
            CommitOutcome::Crashed(PowerFault::MidRootWrite)
        );
        assert_eq!(g.recover(), Recovery::Committed(1));
        // 重试：撕裂残槽已被恢复清理，新提交落同槽位成功
        assert_eq!(g.commit(b"v2-retry", None), CommitOutcome::Committed(2));
        assert_eq!(g.recover(), Recovery::Committed(2));
        // 续提交：代际递增
        assert_eq!(g.commit(b"v3", None), CommitOutcome::Committed(3));
    }

    /// 空库恢复与 prepare 域空库掉电。
    #[test]
    fn empty_root_recovery() {
        let mut g = GenRoot::new();
        assert_eq!(g.recover(), Recovery::Empty);
        // 空库上 prepare 后掉电：仍空（prepare 不落根槽）
        assert_eq!(
            g.commit(b"any", Some(PowerFault::AfterPrepare)),
            CommitOutcome::Crashed(PowerFault::AfterPrepare)
        );
        assert_eq!(g.recover(), Recovery::Empty);
    }

    /// CRC32 已知向量锚定（IEEE 802.3：空串与标准校验值 + 经典参考句）。
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    /// 撕裂残槽恢复后的槽位复用：连续撕裂不累积垃圾。
    #[test]
    fn repeated_torn_writes_do_not_accumulate() {
        let mut g = GenRoot::new();
        assert_eq!(g.commit(b"v1", None), CommitOutcome::Committed(1));
        for i in 0..8 {
            assert_eq!(
                g.commit(b"torn", Some(PowerFault::MidRootWrite)),
                CommitOutcome::Crashed(PowerFault::MidRootWrite)
            );
            assert_eq!(g.recover(), Recovery::Committed(1), "iter {i}");
        }
        assert_eq!(g.commit(b"ok", None), CommitOutcome::Committed(2));
    }
}
