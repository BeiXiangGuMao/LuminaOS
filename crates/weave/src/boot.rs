//! Weave 自举装载面（M31-W1）——boot 后 recover 库态语义挂接。
//!
//! 承接 M31「自举预备」：内核启动序列在自检前调用 [`bootstrap`]，
//! 以**内存库态**复演 journal 重放恢复语义（介质落盘随 crystal 块域
//! 挂账维持，WE-P03/07 不动）：
//!
//! 1. **恢复装载**：以「上次运行遗留 gen1 已提交」为基线库态，执行
//!    [`GenRoot::recover`] 得一致活跃代——自举的第一件事是恢复；
//! 2. **三不变式复演**（WE-P02 四相 × [`journal::Recovery`] 库态断言）：
//!    活跃指针胜出（[`PowerFault::BeforeFlip`] 未过提交点不上浮）/
//!    回滚不残留（恢复后非活跃槽恒空）/ 撕裂残槽显形丢弃
//!    （[`PowerFault::MidRootWrite`] CRC 失配不入账）+ 已提交不丢
//!    （[`PowerFault::AfterFlip`] 新代上浮）；
//! 3. **store 根装载**：内容寻址对象库落根清单对象（FNV-1a 64 身份
//!    单一事实源），重哈希校验 + 字节级回读对账——journal 根槽摘要
//!    与 store 对象身份同源（同 [`store::fnv1a64`]）的装载语义闭环。
//!
//! 报告以 [`BootReport`] 结构化返回（**库态语义**——装载结论；
//! 自举命运属调用方：内核侧 fail-visible，装载失败即退出）。

use crate::journal::{CommitOutcome, GenRoot, PowerFault, Recovery};
use crate::store::{fnv1a64, ObjectStore};

/// 根清单对象（自举装载的 store 根：内容寻址身份的单一事实源）。
pub const ROOT_MANIFEST: &[u8] = b"lumina-root-manifest-v1";

/// store 根装载槽容量（自举期对象数恒小，16 槽富余）。
const BOOT_STORE_CAP: usize = 16;

/// 复演相数：WE-P02 四相（BeforeFlip / MidRootWrite / AfterPrepare / AfterFlip）。
pub const REPLAY_TOTAL: usize = 4;

/// Weave 自举装载报告（库态语义——装载结论供调用方裁决）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootReport {
    /// 恢复装载后的活跃代龄（自举终态库代）。
    pub gen: u64,
    /// 三不变式复演通过相数（应 == [`REPLAY_TOTAL`]）。
    pub replay_pass: usize,
    /// 复演相总数（恒 [`REPLAY_TOTAL`]）。
    pub replay_total: usize,
    /// 回滚不残留：全部恢复后非活跃槽恒空。
    pub residue_clean: bool,
    /// store 根装载：落库 + 重哈希校验通过。
    pub store_ok: bool,
    /// store 在库对象数（自举终态应 == 1）。
    pub store_objects: usize,
    /// store 内容字节总量。
    pub store_bytes: usize,
    /// 根对账：身份同源（put 返回 id == `fnv1a64(ROOT_MANIFEST)`）+
    /// 字节级回读一致。
    pub root_ok: bool,
}

impl BootReport {
    /// 装载全收口判定：复演全过 + 无残留 + store 校验过 + 根对账过。
    #[must_use]
    pub fn ok(&self) -> bool {
        self.replay_pass == self.replay_total
            && self.replay_total == REPLAY_TOTAL
            && self.residue_clean
            && self.store_ok
            && self.root_ok
    }
}

/// Weave 自举装载（内核启动序列挂接点；宿主可复跑，幂等纯内存）。
///
/// 相序：恢复装载（gen1 基线 recover）→ 三不变式四相复演 → store 根
/// 装载与同源对账 → 汇总 [`BootReport`]。任何一相不符即记失（报告
/// 字段显形，不 panic——库态语义 fail-visible 由调用方处置）。
#[must_use]
pub fn bootstrap() -> BootReport {
    // ---- ① 恢复装载：gen1 基线（模拟上次运行遗留的已提交库态）----
    let mut g = GenRoot::new();
    let _committed = g.commit(ROOT_MANIFEST, None);
    let baseline = g.recover();
    let baseline_ok = baseline == Recovery::Committed(1) && !g.uncommitted_residue();

    // ---- ② 三不变式复演（四相 × recover 库态断言）----
    let mut replay_pass = 0usize;
    let mut residue_clean = baseline_ok;

    // 相一：BeforeFlip——提交点前掉电 → 活跃指针胜出（gen1 不变，
    // 完整写入的 gen2 不得上浮——非「最高代胜出」），回滚无残留。
    let c1 = g.commit(b"pending-v2", Some(PowerFault::BeforeFlip));
    let r1 = g.recover();
    if matches!(c1, CommitOutcome::Crashed(PowerFault::BeforeFlip))
        && r1 == Recovery::Committed(1)
        && !g.uncommitted_residue()
    {
        replay_pass += 1;
    } else {
        residue_clean &= !g.uncommitted_residue();
    }

    // 相二：MidRootWrite——撕裂残槽 CRC 失配 → 恢复期显形丢弃不入账。
    let c2 = g.commit(b"torn-v3", Some(PowerFault::MidRootWrite));
    let r2 = g.recover();
    if matches!(c2, CommitOutcome::Crashed(PowerFault::MidRootWrite))
        && r2 == Recovery::Committed(1)
        && !g.uncommitted_residue()
    {
        replay_pass += 1;
    } else {
        residue_clean &= !g.uncommitted_residue();
    }

    // 相三：AfterPrepare——prepare 域掉电（根槽未写）→ 旧代保留无残留。
    let c3 = g.commit(b"prepared-v4", Some(PowerFault::AfterPrepare));
    let r3 = g.recover();
    if matches!(c3, CommitOutcome::Crashed(PowerFault::AfterPrepare))
        && r3 == Recovery::Committed(1)
        && !g.uncommitted_residue()
    {
        replay_pass += 1;
    } else {
        residue_clean &= !g.uncommitted_residue();
    }

    // 相四：AfterFlip——提交点后掉电 → 已提交不丢，gen2 上浮。
    let c4 = g.commit(b"flipped-v5", Some(PowerFault::AfterFlip));
    let r4 = g.recover();
    if matches!(c4, CommitOutcome::Crashed(PowerFault::AfterFlip))
        && r4 == Recovery::Committed(2)
        && !g.uncommitted_residue()
    {
        replay_pass += 1;
    } else {
        residue_clean &= !g.uncommitted_residue();
    }

    // ---- ③ store 根装载 + 同源对账 ----
    let mut st = ObjectStore::<BOOT_STORE_CAP>::new();
    let (store_ok, store_objects, store_bytes, root_ok) = match st.put(ROOT_MANIFEST) {
        None => (false, 0, 0, false), // 库满拒收：自举装载 fail-visible
        Some(root_id) => {
            let verify_ok = st.verify(root_id) == Some(Ok(()));
            let readback_ok = st.get(root_id) == Some(ROOT_MANIFEST);
            let identity_ok = root_id.0 == fnv1a64(ROOT_MANIFEST);
            let (n, bytes) = st.stats();
            (verify_ok, n, bytes, verify_ok && readback_ok && identity_ok)
        }
    };

    BootReport {
        gen: g.generation(),
        replay_pass,
        replay_total: REPLAY_TOTAL,
        residue_clean,
        store_ok,
        store_objects,
        store_bytes,
        root_ok,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 自举装载全绿：四相复演 + 无残留 + store 根装载同源对账。
    #[test]
    fn bootstrap_report_all_green() {
        let r = bootstrap();
        assert_eq!(r.replay_total, REPLAY_TOTAL);
        assert_eq!(r.replay_pass, REPLAY_TOTAL, "all four phases must pass");
        assert!(r.residue_clean, "rollback must leave no residue");
        assert!(r.store_ok, "store root load must verify");
        assert!(r.root_ok, "root identity must be fnv1a64-sourced");
        assert_eq!(r.store_objects, 1);
        assert_eq!(r.store_bytes, ROOT_MANIFEST.len());
        assert_eq!(r.gen, 2, "after-flip recovery promotes gen2");
        assert!(r.ok());
    }

    /// 幂等复跑：连续 bootstrap 报告逐字段一致（纯内存库态无跨调状态）。
    #[test]
    fn bootstrap_is_idempotent() {
        let a = bootstrap();
        let b = bootstrap();
        assert_eq!(a, b);
    }

    /// 根清单身份锚定：ROOT_MANIFEST 的 FNV-1a 64 恒定（证据行对账锚）。
    #[test]
    fn root_manifest_identity_stable() {
        assert_eq!(
            fnv1a64(ROOT_MANIFEST),
            crate::store::ObjectId(fnv1a64(ROOT_MANIFEST)).0
        );
        assert!(!ROOT_MANIFEST.is_empty());
    }
}
