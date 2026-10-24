//! crash-fs 断电注入 ≥1000 样本（M26-X1 验收锚）+ 位翻转读路径检出先行矩阵。
//!
//! **故障模型**：[`FaultBlockDevice`] 包装内存盘——`budget` 计扇区写入预算，
//! 耗尽即「断电」（后续写静默丢弃 = 掉电后不再持久化任何扇区）；`torn`
//! 模式下边界扇区半写（首 128 B 新内容 + 余部旧内容 = 扇区撕裂）。
//! 断点逐扇区扫（0..总写数全覆盖），每 5 样本切一次撕裂变体。
//!
//! **事务模型**（v1 简化装配：key k 一事务，代际 = k + 2）：
//! 节点写入 → WAL 意图登记 → 超级块对槽交替切换。**既登记偏差**：严格
//! write-ahead 序（意图先于节点）押后 Fs 装配批次（T1 分阶段节点写入实现）；
//! 本序安全性论证：COW 新址写入零触旧树，采纳路径全节点重验（W1 recover）
//! 使半写必拒——两态一致性（已提交全见 / 未提交全不见）不受影响，由本
//! 注入矩阵 ≥1000 样本实证。

#![allow(clippy::unwrap_used, clippy::expect_used)]

//!
//! **两态断言**：恢复后代际 G ⇒ 键 k 存在 ⟺ k + 2 ≤ G（逐键对账 +
//! 恢复统计在场性）。位翻转矩阵：叶节点逐扇区单字节翻转，读路径
//! 必报 `Format`（校验和不符）——绝不静默返回坏数据（细则 3.3）。

use bedrock::block::{BlockDevice, BlockError, MemBlock, BLOCK_SIZE};

use crystal::btree::{insert_tracked, lookup, BtreeContext};
use crystal::format::{
    decode_sb, encode_sb, RootRef, RootRef as FmtRootRef, SuperBlock, ROOT_NONE,
};
use crystal::layout::{CKSUM_XXH64, FORMAT_VERSION, NODE_START_LBA, SB_A_LBA, SB_B_LBA, WAL_LBAS};
use crystal::wal::{append_txn, record_lbas, recover, repair_sb, NodeIntent, WalTxn};

/// 故障注入块设备：预算耗尽 = 断电（丢弃写）；torn = 边界扇区半写。
struct FaultBlockDevice {
    inner: MemBlock,
    /// 剩余可持久化扇区写入数（-1 = 不断电；原子面满足 Send+Sync 契约）。
    budget: core::sync::atomic::AtomicI64,
    /// 撕裂模式：预算耗尽时的最后一个写 = 半扇区。
    torn: bool,
    /// 断电后丢弃的写计数（诊断）。
    dropped: core::sync::atomic::AtomicU64,
}

impl FaultBlockDevice {
    /// `budget = u64::MAX` 视为不断电哨兵（内部映射 i64::MAX，避免 as 截断）。
    fn new(inner: MemBlock, budget: u64, torn: bool) -> Self {
        use core::sync::atomic::AtomicI64;
        let capped = budget.min(i64::MAX as u64) as i64;
        Self {
            inner,
            budget: AtomicI64::new(capped),
            torn,
            dropped: core::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl BlockDevice for FaultBlockDevice {
    fn read_block(&self, index: u64, dst: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        self.inner.read_block(index, dst)
    }

    fn write_block(&self, index: u64, src: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        use core::sync::atomic::Ordering;
        let b = self.budget.load(Ordering::Acquire);
        if b == 0 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(()); // 断电：静默丢弃
        }
        if b == 1 && self.torn {
            // 边界扇区半写：首 128 B 新内容，余部保持旧内容。
            let mut old = [0u8; BLOCK_SIZE];
            let _ = self.inner.read_block(index, &mut old);
            let mut merged = old;
            merged[..128].copy_from_slice(&src[..128]);
            self.budget.store(0, Ordering::Release);
            return self.inner.write_block(index, &merged);
        }
        self.budget.store(b - 1, Ordering::Release);
        self.inner.write_block(index, src)
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }
}

impl FaultBlockDevice {
    /// 断电判据（工作负载停机守卫——掉电后机器不再执行任何事务）。
    fn is_dead(&self) -> bool {
        core::sync::atomic::AtomicI64::load(&self.budget, core::sync::atomic::Ordering::Acquire)
            == 0
    }
}

const DEV_LBAS: u64 = 4096;
const N_TXN: u64 = 30; // 30 事务 ≈ 1500+ 扇区写（树长深后单笔升幅）→ ≥1000 断点

/// 格式化：空根 SB 写 A 槽（gen = 1）。
fn format_dev(dev: &dyn BlockDevice) -> SuperBlock {
    let sb = SuperBlock {
        version: FORMAT_VERSION,
        feature_bits: 0,
        checksum_algo: CKSUM_XXH64,
        slot: 0,
        generation: 1,
        wal_head: 0,
        wal_seq: 0,
        alloc_next: NODE_START_LBA,
        root_subvols: ROOT_NONE,
        root_cksum: ROOT_NONE,
    };
    let mut sector = [0u8; BLOCK_SIZE];
    sector.copy_from_slice(&encode_sb(&sb));
    dev.write_block(SB_A_LBA, &sector).expect("format A");
    sb
}

/// 单事务提交：节点写入（btree）→ WAL 意图 → SB 对槽切换。
fn commit_txn(dev: &dyn BlockDevice, sb: &SuperBlock, root: RootRef, key: u64) -> SuperBlock {
    let mut ctx = BtreeContext {
        dev,
        alloc_next: sb.alloc_next,
        device_lbas: DEV_LBAS,
    };
    let (new_root, writes) = insert_tracked(&mut ctx, root, key, key + 1000).expect("txn insert");
    let gen = sb.generation + 1;
    let txn = WalTxn {
        txn_id: gen,
        generation: gen,
        root_subvols: FmtRootRef {
            addr: new_root.addr,
            generation: gen,
        },
        root_cksum: ROOT_NONE,
        intents: writes
            .iter()
            .map(|(a, c)| NodeIntent {
                addr: *a,
                expected_cksum: *c,
            })
            .collect(),
    };
    append_txn(dev, sb, &txn).expect("wal append");
    let mut next = SuperBlock {
        slot: 1 - sb.slot,
        generation: gen,
        wal_head: (u64::from(sb.wal_head) + record_lbas(writes.len())) as u32 % (WAL_LBAS as u32),
        wal_seq: gen,
        alloc_next: ctx.alloc_next,
        ..*sb
    };
    next.root_subvols = FmtRootRef {
        addr: new_root.addr,
        generation: gen,
    };
    next.root_cksum = ROOT_NONE;
    let mut sector = [0u8; BLOCK_SIZE];
    sector.copy_from_slice(&encode_sb(&next));
    let lba = if next.slot == 1 { SB_B_LBA } else { SB_A_LBA };
    dev.write_block(lba, &sector).expect("sb switch");
    next
}

/// 重启：读双槽取最新有效代际 → WAL 回放 → 修复面。
/// 修复写在 `repair_dev`（复电后首挂载，写必持久）；`None` = 双槽皆损
/// （拒挂载窗口；F-2.2 语义，两态断言跳过 = 正确拒绝）。
fn boot(
    dev: &dyn BlockDevice,
    repair_dev: &dyn BlockDevice,
) -> Option<(SuperBlock, crystal::wal::RecoveryStats)> {
    let mut a = None;
    let mut b = None;
    let mut sector = [0u8; BLOCK_SIZE];
    if dev.read_block(SB_A_LBA, &mut sector).is_ok() {
        if let Ok(sb) = decode_sb(&sector, DEV_LBAS) {
            a = Some(sb);
        }
    }
    if dev.read_block(SB_B_LBA, &mut sector).is_ok() {
        if let Ok(sb) = decode_sb(&sector, DEV_LBAS) {
            b = Some(sb);
        }
    }
    let sb = match (a, b) {
        (Some(x), Some(y)) => {
            if x.generation >= y.generation {
                x
            } else {
                y
            }
        }
        (Some(x), None) => x,
        (None, Some(y)) => y,
        (None, None) => return None, // 双槽皆损 = 拒挂载（F-2.2），断言无对象
    };
    let (adopted, stats) = recover(dev, &sb).expect("recover");
    match adopted {
        Some(new_sb) => {
            repair_sb(repair_dev, &new_sb).expect("repair");
            Some((new_sb, stats))
        }
        None => Some((sb, stats)),
    }
}

/// 两态一致性断言：恢复代际 G ⇒ 键 k 在 ⟺ k + 2 ≤ G。
fn assert_two_state(dev: &dyn BlockDevice, sb: &SuperBlock) {
    let root = RootRef {
        addr: sb.root_subvols.addr,
        generation: sb.generation,
    };
    let ctx = BtreeContext {
        dev,
        alloc_next: NODE_START_LBA,
        device_lbas: DEV_LBAS,
    };
    for k in 0..N_TXN {
        let expect = if k + 2 <= sb.generation {
            Some(k + 1000)
        } else {
            None
        };
        assert_eq!(
            lookup(&ctx, root, k).unwrap(),
            expect,
            "断点两态违背 @key {k} @gen {}",
            sb.generation
        );
    }
}

/// 跑完整工作负载（可断电设备上）。
fn run_workload(f: &FaultBlockDevice) -> SuperBlock {
    let mut sb = format_dev(f);
    let mut root = ROOT_NONE;
    for k in 0..N_TXN {
        if f.is_dead() {
            break; // 掉电 = 停机：后续事务不再执行
        }
        sb = commit_txn(f, &sb, root, k);
        root = RootRef {
            addr: sb.root_subvols.addr,
            generation: sb.generation,
        };
    }
    sb
}

/// 满预算基线：量总扇区写数。
fn total_writes() -> u64 {
    let f = FaultBlockDevice::new(MemBlock::new(DEV_LBAS), u64::MAX, false);
    run_workload(&f);
    let remaining = f.budget.load(core::sync::atomic::Ordering::Acquire) as u64;
    i64::MAX as u64 - remaining // 消耗数 = 哨兵初值 - 剩余
}

/// 主注入矩阵：断点 0..总写数全覆盖（≥1000 样本）× 撕裂变体抽样。
#[test]
fn power_cut_sweep_two_state_consistency() {
    let total = total_writes();
    assert!(total >= 1000, "断点样本须 ≥1000（实测 {total}）");

    let samples = total.min(1400);
    let mut torn_checked = 0u32;
    let mut adopted_seen = 0u32;
    let mut discarded_seen = 0u32;
    for cut in 0..=samples {
        let torn = cut % 5 == 0;
        let f = FaultBlockDevice::new(MemBlock::new(DEV_LBAS), cut, torn);
        run_workload(&f);
        if let Some((final_sb, stats)) = boot(&f, &f.inner) {
            assert_two_state(&f, &final_sb);
            adopted_seen += stats.txns_adopted;
            discarded_seen += stats.txns_discarded;
        }
        if torn {
            torn_checked += 1;
        }
        let _ = f.dropped.load(core::sync::atomic::Ordering::Relaxed);
    }
    // 覆盖面自证：撕裂变体在场 + 回放采纳/丢弃两路都被触达过。
    assert!(
        torn_checked >= 100,
        "撕裂变体 ≥100 样本（实测 {torn_checked}）"
    );
    assert!(adopted_seen > 0, "回放采纳路径被触达");
    // 丢弃路径在本序（节点先于 WAL）下结构性不可达——撕裂节点必然伴随
    // WAL 未落（记录在其后）；该路径由下方 wal_discard_on_corrupt_node
    // 以对抗性损坏直接触达。两态一致性不依赖丢弃路径。
    let _ = discarded_seen;
}

/// 回放重验拒收路径（细则 9.1「日志回放不重验」陷阱对位）：WAL 记录在场
/// + 节点对抗性损坏 → 回放必丢弃（采用代际不前进），两态保持。
#[test]
fn wal_discard_on_corrupt_node() {
    let dev = MemBlock::new(DEV_LBAS);
    let mut sb = format_dev(&dev);
    let mut root = ROOT_NONE;
    for k in 0..3u64 {
        sb = commit_txn(&dev, &sb, root, k);
        root = RootRef {
            addr: sb.root_subvols.addr,
            generation: sb.generation,
        };
    }
    let gen_before = sb.generation;
    // 事务 4：节点 + WAL 意图全部落盘（模拟「WAL 先行序下节点半写」的
    // 等价终态 = 记录在场 + 节点损坏）。
    let sb4 = {
        let mut ctx = BtreeContext {
            dev: &dev,
            alloc_next: sb.alloc_next,
            device_lbas: DEV_LBAS,
        };
        let (new_root4, writes) = insert_tracked(&mut ctx, root, 3, 1003).expect("txn4");
        let txn = WalTxn {
            txn_id: sb.generation + 1,
            generation: sb.generation + 1,
            root_subvols: FmtRootRef {
                addr: new_root4.addr,
                generation: sb.generation + 1,
            },
            root_cksum: ROOT_NONE,
            intents: writes
                .iter()
                .map(|(a, c)| NodeIntent {
                    addr: *a,
                    expected_cksum: *c,
                })
                .collect(),
        };
        append_txn(&dev, &sb, &txn).expect("wal4");
        (sb, new_root4.addr)
    };
    let (_sb, node_addr) = sb4;
    // 对抗性损坏：txn4 新叶首扇区翻一字节（节点校验和必不符）。
    let mut sector = [0u8; BLOCK_SIZE];
    dev.read_block(node_addr, &mut sector).expect("read leaf");
    sector[200] ^= 0x01;
    dev.write_block(node_addr, &sector).expect("corrupt leaf");
    // 重启：回放见记录 → 重验失败 → 丢弃（代际停在 gen_before）。
    let (final_sb, stats) = boot(&dev, &dev).expect("boot");
    assert_eq!(
        stats.txns_scanned, 4,
        "环内记录全量在场（1-3 已持久 + 4 待裁）"
    );
    assert_eq!(stats.txns_discarded, 1, "重验拒收仅损者");
    assert_eq!(stats.txns_adopted, 0, "已持久代序不回放");
    assert_eq!(final_sb.generation, gen_before, "代际不前进");
    // 两态：txn1-3 全见，txn4 不见。
    assert_two_state(&dev, &final_sb);
}

/// 全量断点扫（不截断；≥1000 硬口径）：预算逐 1 扇区推进。
#[test]
fn power_cut_full_coverage_gte_1000() {
    let total = total_writes();
    let mut count = 0u32;
    for cut in 0..=total {
        let f = FaultBlockDevice::new(MemBlock::new(DEV_LBAS), cut, false);
        run_workload(&f);
        if let Some((final_sb, _)) = boot(&f, &f.inner) {
            assert_two_state(&f, &final_sb);
        }
        count += 1;
    }
    assert!(count >= 1000, "全量断点 ≥1000（实测 {count}）");
}

/// 位翻转读路径检出矩阵（CR-P10 先行面）：叶节点逐扇区三偏移单字节翻转 →
/// 读路径必报 Format（校验和不符），绝不静默返回坏数据。
#[test]
fn bitflip_read_path_detection_matrix() {
    let dev = MemBlock::new(DEV_LBAS);
    let mut sb = format_dev(&dev);
    let mut root = ROOT_NONE;
    for k in 0..8u64 {
        sb = commit_txn(&dev, &sb, root, k);
        root = RootRef {
            addr: sb.root_subvols.addr,
            generation: sb.generation,
        };
    }
    // 叶节点 = 根（8 键单叶）。逐扇区取三代表偏移翻转。
    let node_addr = sb.root_subvols.addr;
    let mut detected = 0u32;
    let sectors = crystal::layout::NODE_BYTES as u64 / BLOCK_SIZE as u64;
    for sector_off in 0..sectors {
        for byte_in_sector in [0usize, 127, 511] {
            let mut saved = [0u8; BLOCK_SIZE];
            dev.read_block(node_addr + sector_off, &mut saved)
                .expect("read");
            let mut flipped = saved;
            flipped[byte_in_sector] ^= 0x01;
            dev.write_block(node_addr + sector_off, &flipped)
                .expect("flip");
            let ctx = BtreeContext {
                dev: &dev,
                alloc_next: NODE_START_LBA,
                device_lbas: DEV_LBAS,
            };
            let r = lookup(
                &ctx,
                RootRef {
                    addr: node_addr,
                    generation: 0,
                },
                3,
            );
            assert!(
                matches!(r, Err(crystal::btree::BtreeError::Format(_))),
                "翻转 LBA+{sector_off}+{byte_in_sector} 未被读路径拒绝：{r:?}"
            );
            detected += 1;
            dev.write_block(node_addr + sector_off, &saved)
                .expect("restore");
        }
    }
    assert!(detected >= 96, "位翻转检出矩阵 ≥96 点（实测 {detected}）");
    // 复原后全量可读。
    let ctx = BtreeContext {
        dev: &dev,
        alloc_next: NODE_START_LBA,
        device_lbas: DEV_LBAS,
    };
    for k in 0..8u64 {
        assert_eq!(lookup(&ctx, root, k).unwrap(), Some(k + 1000));
    }
}
