//! M22-① 败点名内化：自检 census 面（无锁原子计数 + 单行短发射）。
//!
//! 动机（串口丢线盲区）：批跑环境中 QEMU 进程被宿主清理或双核串口交叠
//! 时，长进度/转储行最易丢失——事后尸检只见「无判定行无 fault 行」的
//! 腰斩轮（M20 批 t39 两连杀即实例），败点无从定位。census 把败点信息
//! 内化进内核计数行：
//! ①每 8 项由 report 发射一行 ≤60B 短行（丢行窗口 ≤8 项）；
//! ②fault_hook 入口在任何长转储之前先落 census 短行（转储多行丢失时
//!   项号+vector+rip 定位信息仍在）；
//! ③任何退出路径（kernel_exit，含成功/失败/fail_exit/panic）写调试口
//!   之前必落一行终局 census。
//!
//! 上下文安全性：全原子操作、无锁、无分配——可在异常/panic 现场直写
//! （fault_hook / kernel_exit 均可能处于不可信现场）。

use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// 已完成判定的自检项数（第 N 项 report 后 = N；1..=63）。
static SEQ: AtomicU32 = AtomicU32::new(0);
/// 累计 PASS 项数。
static PASS_N: AtomicU32 = AtomicU32::new(0);
/// 累计 FAIL 项数。
static FAIL_N: AtomicU32 = AtomicU32::new(0);
/// 首败项号（0 = 无）。
static FF_T: AtomicU32 = AtomicU32::new(0);
/// 首败签名：0=无；0xFFFF_FFFF=自检断言败；其余=异常 vector。
static FF_VEC: AtomicU32 = AtomicU32::new(0);
/// 首败异常 rip（仅异常面；断言败为 0）。
static FF_RIP: AtomicU64 = AtomicU64::new(0);

/// 自检断言败签名（非异常 vector——x86 异常 vector 界 ≤32，哨兵取满值）。
const VEC_ASSERT: u32 = 0xFFFF_FFFF;

/// report 每项判定后调用：记账并返回项号（1..=63）。
pub fn record(ok: bool) -> u32 {
    let n = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    if ok {
        PASS_N.fetch_add(1, Ordering::Relaxed);
    } else {
        FAIL_N.fetch_add(1, Ordering::Relaxed);
        // 首败回填：CAS 防 later 败覆盖（first-fail 语义）
        let _ = FF_T.compare_exchange(0, n, Ordering::Relaxed, Ordering::Relaxed);
        let _ = FF_VEC.compare_exchange(0, VEC_ASSERT, Ordering::Relaxed, Ordering::Relaxed);
    }
    n
}

/// 周期发射判据：每 8 项（8/16/.../56）——末项 63 由 kernel_exit 终局行
/// 兜底，不再重复发射。
pub fn periodic(n: u32) -> bool {
    n != 0 && n.is_multiple_of(8)
}

/// fault_hook 入口调用：回填异常签名（首败语义）——必须先于一切转储。
/// 当前项 = 已完成 SEQ + 1（fault 发生在第 SEQ+1 项执行中）。
pub fn fault_mark(vector: u64, rip: u64) {
    let _ = FF_T.compare_exchange(
        0,
        SEQ.load(Ordering::Relaxed) + 1,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    let _ = FF_VEC.compare_exchange(
        0,
        (vector & 0xFFFF) as u32,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    FF_RIP.store(rip, Ordering::Relaxed);
}

/// 单行 census 写出（≤64B）：任何通道（DualLog / 裸串口）。
/// 行格式：`LUMINA-CENSUS n<p> p<p> f<f> ff<t> v<vec> r<rip>`。
pub fn write_to(w: &mut impl fmt::Write) {
    let _ = writeln!(
        w,
        "LUMINA-CENSUS n{} p{} f{} ff{} v{:#x} r{:#x}",
        SEQ.load(Ordering::Relaxed),
        PASS_N.load(Ordering::Relaxed),
        FAIL_N.load(Ordering::Relaxed),
        FF_T.load(Ordering::Relaxed),
        FF_VEC.load(Ordering::Relaxed),
        FF_RIP.load(Ordering::Relaxed),
    );
}
