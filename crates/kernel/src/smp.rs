//! SMP：AP 启动（INIT-SIPI）、跨核工作池、TLB 击落与 FastPath 双机基准（M5）。
//!
//! 职责链（BSP 视角）：LAPIC MMIO 页经页表抽象补映射（4 KiB @0xFEE00000，
//! 引导根 PDPT[3] 分支）→ ACPI MADT 探测启用核（`ostd::acpi`）→ 0x7000
//! 物理页写入 trampoline（实模式 → PM32 → LME/PAE/PG → LM64，复用引导根
//! CR3）→ 经 LAPIC ICR 发 INIT/SIPI → 上线握手（AP 使能本核 LAPIC 后
//! 置 [`AP_ONLINE`]）。
//!
//! M6-A 起：AP 不再运行专用命令轮询环——trampoline 换装后调入 [`ap_main`]
//! → 使能 LAPIC → 上线报告 → 启动本核 LAPIC 定时器（统一抢占源）→
//! 进入 `task::run_idle(1)` per-CPU idle 循环（全局队列拾取 + idle 附加
//! 工作 + halt 等待 IPI）。工作池认领 / FastPath 服务 / TLB 自检阶段读
//! 以 idle 附加工作形式保留（[`idle_work`]，语义与 M5 轮询环一致）。
//!
//! 工作池认领协议：`try_claim` 先窥探（load）后原子认领（fetch_add），
//! 返回值 ≥ 上限即空转——**游标只被有效认领推进**，杜绝空转烧索引导致
//! 任务永久丢失；每个有效索引恰被一个 fetch_add 领走（恰好一次语义）。
//!
//! unsafe 面：trampoline 汇编（框架白名单，与 boot.rs 同级）；其余代码
//! 为 safe Rust。

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
use bedrock::ipc::FastPath;
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::SpinLock;

use crate::console::DualLog;

// ---------------------------------------------------------------------------
// 常量布局
// ---------------------------------------------------------------------------

/// AP trampoline 物理页（< 1 MiB 常规内存，帧分配器保留区外）。
const TRAMPOLINE_PHYS: u64 = 0x7000;
/// SIPI 启动向量（物理页号 = [`TRAMPOLINE_PHYS`] >> 12）。
const TRAMPOLINE_PAGE: u8 = 0x07;
/// handoff/GDT 绝对地址（trampoline 镜像内的固定运行期位置）。
const HO_GDTR: u64 = 0x7608;
const HO_IDTR: u64 = 0x7618;
const HO_STACK_TOP: u64 = 0x7600;
const HO_CR3: u64 = 0x7628;
const HO_AP_MAIN: u64 = 0x7630;
/// trampoline 拷贝长度上限（GDT+描述符止于 ~0x430）。
const TRAMPOLINE_MAX: usize = 0x600;

/// TLB 击落自检用的虚拟地址（boot 根内全新分支，PDPT[5]）。
const TLB_VIRT: u64 = 0x1_4000_0000;
/// 击落前后魔数。
const TLB_MAGIC_A: u64 = 0xCAFE_BABA_0000_0001;
const TLB_MAGIC_B: u64 = 0xCAFE_BABA_0000_0002;

/// 工作池阶段一任务数（AP 独占）。
const WORK_PHASE1: usize = 16;
/// 工作池两阶段任务总数（阶段二 BSP+AP 并发认领 16..32）。
const WORK_TOTAL: usize = 32;
/// FastPath 基准往返轮数。
const FP_ROUNDS: usize = 1000;

// ---------------------------------------------------------------------------
// AP 状态槽（BSP ↔ AP 原子协议）
// ---------------------------------------------------------------------------

/// AP 上线标志：bit63 = 已上线，低 8 位 = APIC ID。
static AP_ONLINE: AtomicU64 = AtomicU64::new(0);
/// 已上线 AP 的 APIC ID（bring_up 成功后写入；后续自检读取）。
static AP_ID: AtomicU64 = AtomicU64::new(0);

/// 已上线 AP 的 APIC ID（bring_up 之前调用返回 0）。
pub fn online_ap_id() -> u8 {
    AP_ID.load(Ordering::Acquire) as u8
}

/// AP 工作池模式开关。
static WORK_MODE: AtomicBool = AtomicBool::new(false);
/// 工作池有效任务上限（阶段一 16，阶段二 32）。
static WORK_LIMIT: AtomicUsize = AtomicUsize::new(0);
/// 共享任务认领游标（fetch_add 即认领，索引唯一归属）。
static WORK_NEXT: AtomicUsize = AtomicUsize::new(0);
/// 任务结果槽（按全局索引 j 直排，32 槽避免两阶段回绕覆写）。
static WORK_RESULTS: [AtomicU64; WORK_TOTAL] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; WORK_TOTAL]
};
/// AP 已完成任务数。
static AP_WORK_DONE: AtomicU64 = AtomicU64::new(0);
/// BSP 已完成任务数（阶段二机会性参与，诊断可见）。
static BSP_WORK_DONE: AtomicU64 = AtomicU64::new(0);

/// TLB 自检阶段：0 空闲 | 1 读 A | 2 读 A 完成 | 3 击落后重读 | 4 完成。
static TLB_PHASE: AtomicU64 = AtomicU64::new(0);
/// AP 第一次读值（期望 A）。
static TLB_READ1: AtomicU64 = AtomicU64::new(0);
/// AP 击落后读值（期望 B）。
static TLB_READ2: AtomicU64 = AtomicU64::new(0);
/// 击落请求序号（AP 侧 ack 计数）。
static SHOOTDOWN_SEQ: AtomicU64 = AtomicU64::new(0);
static SHOOTDOWN_ACK: AtomicU64 = AtomicU64::new(0);

/// 批量击落请求块（M6-C）：mode 0=遗留单地址 | 1=多页批量 | 2=全量。
/// two-shot 纪律：发起方先布置请求（Release）再发 IPI，ack 到达前
/// 不得回收被失映射的物理帧（防 AP 陈旧翻译写入已回收帧）。
static SD_MODE: AtomicU64 = AtomicU64::new(0);
static SD_COUNT: AtomicU64 = AtomicU64::new(0);
static SD_ADDR: AtomicU64 = AtomicU64::new(0);
static SD_PAGES: [AtomicU64; 16] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 16]
};

/// 批量击落自检阶段（M6-C）：0 空闲 | 1 读 A×8 | 2 完成 | 3 重读 B×8 |
/// 4 完成 | 5 全量后重读 | 6 完成。
static BATCH_PHASE: AtomicU64 = AtomicU64::new(0);
/// 批量击落自检虚拟地址（8 页，同 PDPT[5] 分支）。
static BATCH_VA: [u64; 8] = [
    0x1_4000_0000,
    0x1_4000_1000,
    0x1_4000_2000,
    0x1_4000_3000,
    0x1_4000_4000,
    0x1_4000_5000,
    0x1_4000_6000,
    0x1_4000_7000,
];
static BATCH_READ: [AtomicU64; 8] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 8]
};
static BATCH_READ2: [AtomicU64; 8] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 8]
};
static FULL_READ: AtomicU64 = AtomicU64::new(0);

/// FastPath 服务模式。
static FP_MODE: AtomicBool = AtomicBool::new(false);
/// 已服务轮数（AP 侧累计，BSP 终态断言）。
static FP_SERVED: AtomicUsize = AtomicUsize::new(0);
/// 通道注册表（BSP 泄漏全局通道后写入，AP 读取）。
static FP_REQ: AtomicUsize = AtomicUsize::new(0);
static FP_RESP: AtomicUsize = AtomicUsize::new(0);

/// AP 独立内核栈（常驻锚点；与 task.rs 栈同纪律）。
static AP_STACK: SpinLock<Vec<u128>> = SpinLock::new(Vec::new());

/// LAPIC 定时器校准结果（每 10 ms 的计数；BSP 校准、AP 复用）。
static TIMER_COUNTS: AtomicU64 = AtomicU64::new(0);
/// LAPIC 定时器已启动的核位图（bit0 = BSP，bit1 = AP；诊断可见）。
static TIMER_STARTED: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// M6-A 前置初始化与统一调度接入
// ---------------------------------------------------------------------------

/// SMP 前置初始化（kmain 在帧分配器就绪后、调度器启动前调用）：
/// LAPIC 映射/使能（BSP）→ ACPI 探测（缓存核数与 AP id）→ IPI/重调度
/// 门钩子注册 → idle 附加工作桥注册。
/// 调度器/定时器依赖本函数先行（task::init 读 LAPIC id、抢占钩子读本核身份）。
pub fn pre_init(log: &mut DualLog, frames: &FrameAllocator) {
    // 1) LAPIC MMIO 页恒等映射（boot 根 PDPT[3] 分支；P | W）
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    let lapic_page = ostd::hw::lapic::base();
    let map_res = {
        let mut w = Walker {
            mem: &mut IdentityAccess,
            alloc_table: || frames.alloc(),
        };
        w.map(boot_cr3, lapic_page, lapic_page, Entry::WRITABLE)
    };
    if let Err(e) = map_res {
        let _ = writeln!(log, "smp: pre_init lapic map failed {e:?}");
        return;
    }
    ostd::hw::lapic::enable_access();
    let bsp_id = ostd::hw::lapic::id();
    ostd::hw::lapic::enable();

    // 2) ACPI MADT 探测（HW-14；失败不致磁——单核回退，后续 bring_up 重试）
    if let Some(madt) = ostd::acpi::detect_lapics() {
        let _ = writeln!(
            log,
            "smp: pre_init madt cpus={} lapic-base={:#x} bsp-id={bsp_id}",
            madt.count, madt.lapic_base
        );
        DETECTED_CPUS.store(madt.count as u64, Ordering::Release);
    } else {
        let _ = writeln!(log, "smp: pre_init madt not found (单核回退)");
    }

    // 3) IPI / 重调度钩子 + idle 附加工作桥（全部先于 AP 上线与任何 IPI）
    ostd::interrupt::stubs::set_ipi_hook(ipi_hook);
    crate::task::set_idle_work(idle_work);
    let _ = writeln!(log, "smp: pre_init done (lapic enabled, hooks wired)");
}

/// ACPI 探测缓存核数（pre_init 写入；0 = 未探测）。
static DETECTED_CPUS: AtomicU64 = AtomicU64::new(0);

/// BSP LAPIC 定时器校准并启动（统一抢占源；在 PIT 就绪后、自检 12 前调用）。
/// 方法：分频 16 → 初值 u32::MAX → 睡 2 PIT 节拍（~20 ms）→ 读 CCR →
/// 每 10 ms 计数 =（u32::MAX − CCR）/ 2 → 周期模式启动（向量 0x41）。
/// 返回校准出的每节拍计数（0 = 失败）。
pub fn timer_calibrate_and_start() -> u32 {
    ostd::hw::lapic::timer_mask();
    ostd::hw::lapic::timer_set_divide(0x8); // 分频 16
    ostd::hw::lapic::timer_write_count(u32::MAX);
    ostd::time::sleep_ticks(2, 500);
    let elapsed = u32::MAX - ostd::hw::lapic::timer_read_count();
    let per_tick = (elapsed / 2).max(1);
    // SAFETY: 前置条件 —— 向量 0x41 已在 IDT 注册 LAPIC 定时器桩
    //          （interrupts::init_and_enable 先行）；校准完成前 LVT 已屏蔽。
    // 不变式 —— 周期模式；PREEMPT_ENABLED=false 时钩子立即放行。
    // 并发 —— 仅 BSP 启动路径调用一次（AP 在 ap_main 内另行启动）。
    // 违反后果 —— 未注册向量即三重故障（IDT 装载顺序契约封死）。
    unsafe {
        ostd::hw::lapic::timer_start_periodic(ostd::hw::lapic::TIMER_VECTOR, per_tick);
    }
    TIMER_COUNTS.store(u64::from(per_tick), Ordering::Release);
    TIMER_STARTED.fetch_or(1, Ordering::AcqRel);
    per_tick
}

/// 定向门铃（M8-C 泛化）：向指定核槽位发 RESCHED IPI（0 = BSP、
/// 1 = 在线 AP）——跨核通道从「对侧对称化」（M7-A）泛化为「任意核
/// 定向」；AP 未上线时对 1 槽静默（幂等，无副作用）。
pub fn kick_cpu(slot: usize) {
    if slot == 0 {
        let bsp = crate::task::bsp_apic_id();
        ostd::hw::lapic::send_fixed_ipi(bsp, ostd::hw::lapic::RESCHED_VECTOR);
    } else {
        let ap = AP_ID.load(Ordering::Acquire) as u8;
        if AP_ONLINE.load(Ordering::Acquire) >> 63 == 1 && ap != 0 {
            ostd::hw::lapic::send_fixed_ipi(ap, ostd::hw::lapic::RESCHED_VECTOR);
        }
    }
}

/// 跨核重调度提示（task.rs spawn 桥调用；M8-C 定向门铃：提示对侧核）。
fn resched_kick(target: usize) {
    kick_cpu(target);
}

/// AP 侧启动本核 LAPIC 定时器（复用 BSP 校准结果；ap_main 调用）。
fn ap_timer_start() {
    let counts = TIMER_COUNTS.load(Ordering::Acquire) as u32;
    if counts == 0 {
        return;
    }
    ostd::hw::lapic::timer_set_divide(0x8);
    // SAFETY: 前置条件 —— 同 timer_calibrate_and_start（IDT 门已装，
    //          trampoline 已 lidt 共享 IDT）。
    // 不变式 —— 周期模式；AP 侧钩子与 BSP 共用 timer_hook（per-CPU plan）。
    // 并发 —— 仅 AP 启动路径调用一次。
    // 违反后果 —— 未注册向量即三重故障（同上契约封死）。
    unsafe {
        ostd::hw::lapic::timer_start_periodic(ostd::hw::lapic::TIMER_VECTOR, counts);
    }
    TIMER_STARTED.fetch_or(2, Ordering::AcqRel);
}

/// idle 附加工作（task::run_idle 无任务时调用）：TLB 自检阶段读 /
/// FastPath 服务 / 工作池认领。返回 true = 本轮有产出（立即重查队列）。
/// 语义与 M5 专用轮询环完全一致，仅宿主从专用环变为统一 idle 循环。
fn idle_work() -> bool {
    // TLB 自检阶段 1/3：经自身 TLB 读值（A/B 魔数）
    let phase = TLB_PHASE.load(Ordering::Acquire);
    if phase == 1 {
        let v = ostd::hw::phys::read_u64_virt(TLB_VIRT);
        TLB_READ1.store(v, Ordering::Release);
        TLB_PHASE.store(2, Ordering::Release);
        return true;
    }
    if phase == 3 {
        let v = ostd::hw::phys::read_u64_virt(TLB_VIRT);
        TLB_READ2.store(v, Ordering::Release);
        TLB_PHASE.store(4, Ordering::Release);
        return true;
    }
    // 批量击落自检阶段（M6-C）：读 A ×8 / 击落后重读 B ×8
    let bphase = BATCH_PHASE.load(Ordering::Acquire);
    if bphase == 1 {
        for (i, slot) in BATCH_READ.iter().enumerate() {
            slot.store(
                ostd::hw::phys::read_u64_virt(BATCH_VA[i]),
                Ordering::Release,
            );
        }
        BATCH_PHASE.store(2, Ordering::Release);
        return true;
    }
    if bphase == 3 {
        for (i, slot) in BATCH_READ2.iter().enumerate() {
            slot.store(
                ostd::hw::phys::read_u64_virt(BATCH_VA[i]),
                Ordering::Release,
            );
        }
        BATCH_PHASE.store(4, Ordering::Release);
        return true;
    }
    if bphase == 5 {
        FULL_READ.store(
            ostd::hw::phys::read_u64_virt(BATCH_VA[0]),
            Ordering::Release,
        );
        BATCH_PHASE.store(6, Ordering::Release);
        return true;
    }
    // FastPath 服务：收请求 → 应答（tag|0x80 原值回传）
    if FP_MODE.load(Ordering::Acquire) {
        let req = FP_REQ.load(Ordering::Acquire);
        let resp = FP_RESP.load(Ordering::Acquire);
        if req != 0 && resp != 0 {
            // SAFETY: 前置条件 —— 指针来自 BSP 泄漏的 &'static FastPath
            //          （写入先于 FP_MODE 置位，Release/Acquire 配对）。
            // 不变式 —— 泄漏对象常驻；SPSC 契约：AP 只从 REQ 收、向 RESP 发。
            // 并发 —— 双核 SPSC 单发单收配对（BSP 持对偶角色）。
            // 违反后果 —— 破坏 SPSC 契约即消息竞争（协议纪律封死）。
            let (rq, rs) = unsafe { (&*(req as *const FastPath), &*(resp as *const FastPath)) };
            let mut buf = [0u8; FastPath::PAYLOAD];
            if let Some((tag, n)) = rq.recv_frame(&mut buf) {
                while rs.send_frame(tag | 0x80, &buf[..n]).is_err() {
                    core::hint::spin_loop();
                }
                FP_SERVED.fetch_add(1, Ordering::AcqRel);
                return true;
            }
        }
    }
    // 工作池：窥探 + 认领（不烧游标）
    if WORK_MODE.load(Ordering::Acquire) {
        if let Some(j) = try_claim() {
            WORK_RESULTS[j].store(job_hash(j), Ordering::Release);
            AP_WORK_DONE.fetch_add(1, Ordering::AcqRel);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// trampoline 汇编（框架内核白名单：跨模式机器状态初始化无法 safe 表达）
// ---------------------------------------------------------------------------

core::arch::global_asm! {
    // 仅数据（被复制到 0x7000 的字节镜像），不直接执行。
    ".section .rodata.aptramp, \"a\", @progbits",
    ".globl ap_tramp",
    "ap_tramp:",
    // ---- 16 位实模式（SIPI 进入：CS:IP = 0x0700:0000 → 线性 0x7000）----
    ".code16",
    "    cli",
    "    xorw %ax, %ax",
    "    movw %ax, %ds",
    // 心跳 1：实模式已进入（写物理 0x7E00）
    "    movw $0xbeef, 0x7e00",
    "    movw %ax, %ss",
    "    movw $0x7c00, %sp",
    // 加载 trampoline GDT 描述符（限长 + 基址 0x7400，6 字节读取）
    // 注意：desc 位于镜像偏移 0x420（GDT 四表目止于 0x420），运行期 0x7420
    "    lgdt 0x7420",
    // PE=1 → 保护模式（仍 16 位码段）
    "    movl %cr0, %eax",
    "    orl $0x00000001, %eax",
    "    movl %eax, %cr0",
    // 远返回换装 32 位码段（0x08 = 32 位代码，基址 0）
    "    pushw $0x08",
    "    pushw $(pm32_entry - ap_tramp + 0x7000)",
    "    lretw",
    // ---- 32 位保护模式 ----
    ".code32",
    "pm32_entry:",
    "    movw $0x10, %ax",
    "    movw %ax, %ds",
    "    movw %ax, %es",
    "    movw %ax, %ss",
    "    movw %ax, %fs",
    "    movw %ax, %gs",
    // LME=1（IA32_EFER）→ CR3=引导根 → PAE=1 → PG=1 → 长模式激活
    "    movl $0xC0000080, %ecx",
    "    rdmsr",
    "    orl $0x00000100, %eax",
    "    wrmsr",
    "    movl 0x7628, %eax",
    "    movl %eax, %cr3",
    "    movl %cr4, %eax",
    "    orl $0x00000020, %eax",
    "    movl %eax, %cr4",
    "    movl %cr0, %eax",
    "    orl $0x80000000, %eax",
    "    movl %eax, %cr0",
    // 远返回换装 64 位码段（0x18 = L=1）
    "    pushl $0x18",
    "    pushl $(lm64_entry - ap_tramp + 0x7000)",
    "    lretl",
    // ---- 64 位长模式：装载内核 GDT/IDT，换栈后跳入 Rust ----
    // 顺序纪律：必须先 lgdt 内核 GDT 再远返回换 CS——此刻 CS=0x18 是
    // trampoline GDT 的 64 位码段（隐藏描述符缓存仍有效），若先换 CS=0x08
    // 则命中的还是 trampoline GDT 的 32 位码段（M5 开发期实测三重故障根因）
    ".code64",
    "lm64_entry:",
    // 心跳 2：64 位已进入（写物理 0x7E08）
    "    movabs $0x7e08, %rdi",
    "    movabs $0xcafed00d, %rax",
    "    movq %rax, (%rdi)",
    "    movabs $0x7600, %rax",
    "    movq (%rax), %rsp",
    "    xorl %ebp, %ebp",
    "    movabs $0x7608, %rax",
    "    lgdt (%rax)",
    "    movabs $0x7618, %rax",
    "    lidt (%rax)",
    // CS 远返回重装为内核 0x08（此时内核 GDT 已生效）
    "    pushq $0x08",
    "    lea cs_ok(%rip), %rax",
    "    pushq %rax",
    "    lretq",
    "cs_ok:",
    "    movw $0x10, %ax",
    "    movw %ax, %ds",
    "    movw %ax, %es",
    "    movw %ax, %ss",
    "    xorw %ax, %ax",
    "    movw %ax, %fs",
    "    movw %ax, %gs",
    "    movabs $0x7630, %rax",
    "    movq (%rax), %rax",
    "    call *%rax",
    "2:",
    "    hlt",
    "    jmp 2b",
    // ---- trampoline GDT（运行期位于 0x7400）----
    ".org 0x400",
    "tramp_gdt:",
    "    .quad 0x0000000000000000",
    "    .quad 0x00cf9a000000ffff",   // 0x08 32 位代码
    "    .quad 0x00cf92000000ffff",   // 0x10 数据
    "    .quad 0x00209a0000000000",   // 0x18 64 位代码（L=1, D=0）
    // ---- GDTR 描述符 blob（运行期位于 0x7428：u16 界限 + u64 基址，
    //      16/64 位模式 lgdt 兼容布局；基址 = 镜像复制目标，固定）----
    "tramp_gdt_desc:",
    "    .word 4*8-1",
    "    .quad 0x7400",
    ".globl ap_tramp_end",
    "ap_tramp_end:",
    options(att_syntax)
}

extern "C" {
    static ap_tramp: u8;
    static ap_tramp_end: u8;
}

/// AP 主入口（trampoline 换栈后调入；永不返回）。
extern "C" fn ap_main() -> ! {
    // 本核 LAPIC 使能（MMIO 页已随引导根恒等映射）
    ostd::hw::lapic::enable();
    // M7-A：TR 补装——trampoline 已 lgdt 本核 per-CPU GDT
    // （location_cpu(1) 交接），但从未 ltr；ring3 中断向量化需 TR.RSP0，
    // 用户任务跨核前必须就位。
    ostd::hw::gdt::load_tr();
    // M7-A：SYSCALL/SYSRET 约定为 per-CPU MSR（EFER.SCE/STAR/LSTAR/
    // FMASK）——M6 用户任务钉死 CPU0 掩盖了 AP 侧从未编程的事实；
    // 用户任务跨核派发前必须补装（幂等，与 BSP 同值）。
    // SAFETY: GDT 已由 trampoline 按配套布局装载（STAR 选择子基址配套）；
    //         本核尚无 ring3 代码，LSTAR 生效不产生即时入口。
    unsafe { crate::syscall::init() };
    let id = ostd::hw::lapic::id();
    AP_ONLINE.store(u64::from(id) | 0x8000_0000_0000_0000, Ordering::Release);
    // IPI 需要 IDT + IF=1（IDT 已由 trampoline lidt；表与 BSP 共享）
    ostd::hw::intr::enable();
    // 统一调度接入（M6-A）：启动本核 LAPIC 定时器（复用 BSP 校准），
    // 随即进入 per-CPU idle 循环——工作池/FastPath/TLB 阶段语义经
    // idle_work 保留（宿主从专用轮询环变为统一调度 idle）
    ap_timer_start();
    crate::task::run_idle(1);
}

/// 原子认领一个任务索引（BSP/AP 共用）：窥探上限后才 fetch_add，
/// 返回 None 表示当前无有效任务（游标不被无效自转推进）。
fn try_claim() -> Option<usize> {
    if WORK_NEXT.load(Ordering::Acquire) >= WORK_LIMIT.load(Ordering::Acquire) {
        return None;
    }
    let j = WORK_NEXT.fetch_add(1, Ordering::AcqRel);
    (j < WORK_LIMIT.load(Ordering::Acquire)).then_some(j)
}

/// 任务哈希（两核同码同参 → 结果确定性一致）。
fn job_hash(j: usize) -> u64 {
    let mut x = (j as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for _ in 0..500 {
        x ^= x << 13;
        x = x.rotate_left(7);
        x ^= x >> 3;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
    }
    x
}

/// IPI 钩子（AP 中断窗口内调用）：失效请求地址 → LAPIC EOI → ack。
fn ipi_hook() {
    let mode = SD_MODE.load(Ordering::Acquire);
    match mode {
        1 => {
            // 多页批量：逐页 invlpg（M6-C）
            let n = SD_COUNT.load(Ordering::Acquire) as usize;
            for (i, page) in SD_PAGES.iter().enumerate().take(n.min(SD_PAGES.len())) {
                let va = page.load(Ordering::Acquire);
                if va != 0 {
                    ostd::hw::control::invlpg(va);
                }
                let _ = i;
            }
        }
        2 => {
            // 全量击落：重写 CR3（未启用 PCID → 全 TLB 下调；M6-C two-shot）
            let cr3 = ostd::hw::control::read_cr3() & !0xFFF;
            ostd::hw::control::write_cr3(cr3);
        }
        _ => {
            // 遗留单地址语义（M5；SD_MODE=0 且 SD_ADDR 非零）
            let addr = SD_ADDR.load(Ordering::Acquire);
            if addr != 0 {
                ostd::hw::control::invlpg(addr);
            }
        }
    }
    ostd::hw::lapic::eoi();
    SHOOTDOWN_ACK.fetch_add(1, Ordering::AcqRel);
}

// ---------------------------------------------------------------------------
// BSP 侧：AP 启动与四大自检驱动
// ---------------------------------------------------------------------------

/// 写 GDTR/IDTR 描述符 blob（u16 界限 + u64 基址，10 字节）。
fn write_descriptor_blob(phys: u64, base: u64, limit: u16) {
    let mut blob = [0u8; 10];
    blob[0..2].copy_from_slice(&limit.to_le_bytes());
    blob[2..10].copy_from_slice(&base.to_le_bytes());
    ostd::hw::phys::write_bytes(phys, &blob);
}

/// AP 启动全链（自检 16）：映射 LAPIC（幂等）→ 探测 → trampoline →
/// INIT/SIPI → 上线握手。返回 (ok, 在线 APIC ID, 探测核数)。
pub fn bring_up(log: &mut DualLog, frames: &FrameAllocator) -> (bool, u8, usize) {
    // 1) LAPIC MMIO 页恒等映射（boot 根 PDPT[3] 分支；P | W）
    //    pre_init 已映射过则 AlreadyMapped 视为成功（幂等）
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    let lapic_page = ostd::hw::lapic::base();
    let map_res = {
        let mut w = Walker {
            mem: &mut IdentityAccess,
            alloc_table: || frames.alloc(),
        };
        w.map(boot_cr3, lapic_page, lapic_page, Entry::WRITABLE)
    };
    if let Err(e) = map_res {
        if e != PageError::AlreadyMapped {
            let _ = writeln!(log, "smp: lapic map failed {e:?}");
            return (false, 0, 0);
        }
    }
    ostd::hw::lapic::enable_access();
    let bsp_id = ostd::hw::lapic::id();
    ostd::hw::lapic::enable();

    // 2) ACPI MADT 探测（HW-14）
    let Some(madt) = ostd::acpi::detect_lapics() else {
        let _ = writeln!(
            log,
            "smp: acpi madt not found (fw_cfg rsdp/xsdt/tables 与 BIOS 区扫描均未命中)"
        );
        return (false, 0, 0);
    };
    let _ = writeln!(
        log,
        "smp: madt cpus={} lapic-base={:#x} bsp-id={bsp_id}",
        madt.count, madt.lapic_base
    );
    let Some(&ap_id) = madt.ids.iter().take(madt.count).find(|&&i| i != bsp_id) else {
        let _ = writeln!(log, "smp: no ap in madt (cpus={})", madt.count);
        return (false, 0, madt.count);
    };

    // 3) IPI 钩子注册（先于任何 IPI 发送）
    ostd::interrupt::stubs::set_ipi_hook(ipi_hook);

    // 4) trampoline 镜像复制（符号差值定位 → 物理层逐字节搬运，零 unsafe）
    let start = core::ptr::addr_of!(ap_tramp) as usize;
    let end = core::ptr::addr_of!(ap_tramp_end) as usize;
    let len = end - start;
    if len > TRAMPOLINE_MAX {
        let _ = writeln!(log, "smp: trampoline too large {len}");
        return (false, 0, madt.count);
    }
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push(ostd::hw::phys::read_u8((start + i) as u64));
    }
    ostd::hw::phys::write_bytes(TRAMPOLINE_PHYS, &img);

    // 5) handoff：栈 / GDTR / IDTR / CR3 / 入口
    let stack = {
        let mut s = AP_STACK.lock();
        s.clear();
        s.resize(16 * 1024 / core::mem::size_of::<u128>(), 0u128);
        s.as_ptr() as u64 + (16 * 1024) as u64
    };
    let (gdt_base, gdt_limit) = ostd::hw::gdt::location_cpu(1); // M7-A：AP 专属 GDT/TSS
    let (idt_base, idt_limit) = crate::interrupts::idt_location();
    let ap_entry: extern "C" fn() -> ! = ap_main;
    ostd::hw::phys::write_u64(HO_STACK_TOP, stack);
    write_descriptor_blob(HO_GDTR, gdt_base, gdt_limit);
    write_descriptor_blob(HO_IDTR, idt_base, idt_limit);
    ostd::hw::phys::write_u64(HO_CR3, boot_cr3);
    ostd::hw::phys::write_u64(HO_AP_MAIN, ap_entry as usize as u64);

    // 6) INIT → 延时（2 节拍 ≥ 10 ms）→ SIPI（SDM 时序；QEMU 无需 deassert）
    ostd::hw::lapic::send_init(ap_id);
    ostd::time::sleep_ticks(2, 100);
    ostd::hw::lapic::send_sipi(ap_id, TRAMPOLINE_PAGE);

    // 7) 上线握手（两轮 SIPI 预算；SDM 建议二次 SIPI 防首投丢失）
    for _ in 0..2 {
        let deadline = ostd::time::now() + 100;
        while ostd::time::now() < deadline {
            if AP_ONLINE.load(Ordering::Acquire) >> 63 == 1 {
                break;
            }
            ostd::hw::intr::halt();
        }
        if AP_ONLINE.load(Ordering::Acquire) >> 63 == 1 {
            break;
        }
        ostd::hw::lapic::send_sipi(ap_id, TRAMPOLINE_PAGE);
    }
    let online = AP_ONLINE.load(Ordering::Acquire);
    let ok = online >> 63 == 1 && (online & 0xFF) as u8 == ap_id;
    if ok {
        AP_ID.store(u64::from(ap_id), Ordering::Release);
        // 跨核提示桥（M8-C 定向门铃泛化：fn(usize) 定向任意核槽位）
        crate::task::set_resched_kick(resched_kick);
    }
    if !ok {
        // 心跳取证：AP 走到哪一步（0 = 未启动 / beef = 实模式 / cafed00d = 64 位）
        let hb1 = ostd::hw::phys::read_u16(0x7E00);
        let hb2 = ostd::hw::phys::read_u32(0x7E08);
        let stack_echo = ostd::hw::phys::read_u64(HO_STACK_TOP);
        let _ = writeln!(
            log,
            "smp: ap-heartbeat rm={hb1:#06x} lm64={hb2:#010x} stack-echo={stack_echo:#x}"
        );
    }
    let _ = writeln!(log, "smp: ap id={ap_id} online={}", online >> 63 == 1);
    (ok, ap_id, madt.count)
}

/// 跨核工作池自检（自检 17）：阶段一 AP 独占 16 任务；阶段二 BSP+AP
/// 并发认领 16..32（认领原子性保证每任务恰好一次，合计恰 32）。
pub fn parallel_work_check() -> bool {
    WORK_NEXT.store(0, Ordering::Release);
    WORK_LIMIT.store(WORK_PHASE1, Ordering::Release);
    AP_WORK_DONE.store(0, Ordering::Release);
    BSP_WORK_DONE.store(0, Ordering::Release);
    for r in &WORK_RESULTS {
        r.store(0, Ordering::Release);
    }
    // 阶段一：AP 独占（BSP 不参与认领）
    WORK_MODE.store(true, Ordering::Release);
    let deadline = ostd::time::now() + 300;
    while ostd::time::now() < deadline && AP_WORK_DONE.load(Ordering::Acquire) < WORK_PHASE1 as u64
    {
        core::hint::spin_loop();
    }
    let mut ok = AP_WORK_DONE.load(Ordering::Acquire) == WORK_PHASE1 as u64;
    for (i, r) in WORK_RESULTS.iter().enumerate().take(WORK_PHASE1) {
        ok &= r.load(Ordering::Acquire) == job_hash(i);
    }
    // 阶段二：BSP 与 AP 并发认领（合计恰 = WORK_TOTAL）
    WORK_LIMIT.store(WORK_TOTAL, Ordering::Release);
    let deadline = ostd::time::now() + 300;
    loop {
        let total = AP_WORK_DONE.load(Ordering::Acquire) + BSP_WORK_DONE.load(Ordering::Acquire);
        if total >= WORK_TOTAL as u64 || ostd::time::now() >= deadline {
            break;
        }
        if let Some(j) = try_claim() {
            WORK_RESULTS[j].store(job_hash(j), Ordering::Release);
            BSP_WORK_DONE.fetch_add(1, Ordering::AcqRel);
        }
        core::hint::spin_loop();
    }
    WORK_MODE.store(false, Ordering::Release);
    let ap = AP_WORK_DONE.load(Ordering::Acquire);
    let bsp = BSP_WORK_DONE.load(Ordering::Acquire);
    ok &= ap + bsp == WORK_TOTAL as u64 && ap >= WORK_PHASE1 as u64;
    for (i, r) in WORK_RESULTS.iter().enumerate().take(WORK_TOTAL) {
        ok &= r.load(Ordering::Acquire) == job_hash(i);
    }
    ok
}

/// TLB 击落自检（自检 18）：BSP 改映射 → 本核 invlpg → IPI 击落 AP →
/// AP 经新映射读到新值（AP 侧陈旧翻译被真实失效）。
pub fn tlb_shootdown_check(log: &mut DualLog, frames: &FrameAllocator, ap_id: u8) -> bool {
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    let Some(fa) = frames.alloc() else {
        return false;
    };
    let Some(fb) = frames.alloc() else {
        return false;
    };
    ostd::hw::phys::write_u64(fa, TLB_MAGIC_A);
    ostd::hw::phys::write_u64(fb, TLB_MAGIC_B);
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    if w.map(boot_cr3, TLB_VIRT, fa, Entry::WRITABLE).is_err() {
        return false;
    }
    // 阶段 1：AP 首读（其 TLB 载入 A 的翻译）
    TLB_PHASE.store(1, Ordering::Release);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && TLB_PHASE.load(Ordering::Acquire) != 2 {
        core::hint::spin_loop();
    }
    let read1 = TLB_READ1.load(Ordering::Acquire);
    // BSP 自证旧映射
    let bsp_before = ostd::hw::phys::read_u64_virt(TLB_VIRT);
    // 改映射 A→B：本核 invlpg + IPI 击落 AP
    let unmapped = w.unmap(boot_cr3, TLB_VIRT).is_ok();
    let remapped = w.map(boot_cr3, TLB_VIRT, fb, Entry::WRITABLE).is_ok();
    ostd::hw::control::invlpg(TLB_VIRT);
    let bsp_after = ostd::hw::phys::read_u64_virt(TLB_VIRT);
    SD_MODE.store(0, Ordering::Release);
    SD_ADDR.store(TLB_VIRT, Ordering::Release);
    SHOOTDOWN_SEQ.fetch_add(1, Ordering::AcqRel);
    ostd::hw::lapic::send_fixed_ipi(ap_id, ostd::hw::lapic::IPI_VECTOR);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && SHOOTDOWN_ACK.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    // 阶段 3：AP 重读（必须见 B）
    TLB_PHASE.store(3, Ordering::Release);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && TLB_PHASE.load(Ordering::Acquire) != 4 {
        core::hint::spin_loop();
    }
    let read2 = TLB_READ2.load(Ordering::Acquire);
    // 清理：取消映射 → 批量击落（AP 侧陈旧翻译随 IPI 失效）→ 帧回收
    // （two-shot 纪律补全：AP 重读会在其 TLB 缓存 va→fb，若不击落即回收，
    // 该陈旧项将指向已释放帧——M6 缺陷四，由自检 23 复用 VA 段暴露）
    let _ = w.unmap(boot_cr3, TLB_VIRT);
    ostd::hw::control::invlpg(TLB_VIRT);
    let swept = shootdown_batch(&[TLB_VIRT]);
    frames.dealloc(fa);
    frames.dealloc(fb);
    TLB_PHASE.store(0, Ordering::Release);
    let _ = writeln!(
        log,
        "smp: tlb r1={read1:#x} before={bsp_before:#x} after={bsp_after:#x} r2={read2:#x} um={unmapped} rm={remapped}"
    );
    unmapped
        && remapped
        && swept
        && read1 == TLB_MAGIC_A
        && bsp_before == TLB_MAGIC_A
        && bsp_after == TLB_MAGIC_B
        && read2 == TLB_MAGIC_B
}

/// FastPath 双机基准（自检 19）：BSP↔AP 两条 SPSC 环往返 [`FP_ROUNDS`] 轮，
/// TSC 计时（TCG 参考基线；B-P01 0.6 μs 预算对比留环境 B 实测）。
pub fn fastpath_bench(log: &mut DualLog) -> bool {
    let req: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let resp: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    FP_RESP.store(resp as *const _ as usize, Ordering::Release);
    FP_REQ.store(req as *const _ as usize, Ordering::Release);
    FP_SERVED.store(0, Ordering::Release);
    let mut out = [0u8; FastPath::PAYLOAD];
    let t0 = ostd::time::tsc_now();
    FP_MODE.store(true, Ordering::Release);
    let mut ok = true;
    for i in 0..FP_ROUNDS as u32 {
        while req.send_frame(0x20, &i.to_le_bytes()).is_err() {
            core::hint::spin_loop();
        }
        // 生产者门铃（M6 缺陷五修复）：AP idle 为 halt 模型，请求投递后
        // 必须 IPI 唤醒，否则服务延迟退化为 LAPIC 定时器节拍（10 ms/轮）
        resched_kick(1 - crate::task::current_cpu_slot());
        let mut got = false;
        let deadline = ostd::time::now() + 200;
        while ostd::time::now() < deadline {
            match resp.recv_frame(&mut out) {
                Some((0xA0, 4)) => {
                    got = u32::from_le_bytes(out[..4].try_into().unwrap_or([0; 4])) == i;
                    break;
                }
                _ => core::hint::spin_loop(),
            }
        }
        ok &= got;
        if !got {
            break;
        }
    }
    FP_MODE.store(false, Ordering::Release);
    let t1 = ostd::time::tsc_now();
    let total_ns = ostd::time::tsc_clock::elapsed_ns(t1 - t0);
    let per_round = total_ns.and_then(|n| n.checked_div(FP_ROUNDS as u64));
    let _ = writeln!(
        log,
        "bench ipc-fastpath: {FP_ROUNDS} roundtrips -> {:?} ns/round (served {})",
        per_round,
        FP_SERVED.load(Ordering::Acquire)
    );
    ok && FP_SERVED.load(Ordering::Acquire) == FP_ROUNDS
}

// ---------------------------------------------------------------------------
// M6-A/C：批量击落 API 与统一调度自检（21/22/23）
// ---------------------------------------------------------------------------

/// 批量击落（M6-C two-shot 第一击）：失效 `pages` 列表在**对侧核**的翻译。
/// two-shot 纪律：发起方在 ack 到达前不得回收被失映射的物理帧——
/// 调用方（vmm/自检）据此顺序组织「改映射 → 本核 invlpg → 击落 →
/// 等 ack → 回收」。
///
/// **M9-B 目标修正**：IPI 目标 = 对侧核（双核拓扑），而非无条件 AP。
/// 旧代码当调用方本身运行在 AP 上时变成自-IPI（IF=0 窗口内 IRR 积压、
/// now() 冻结 → 击落死锁）且漏掉 BSP 的陈旧翻译——M6 以来潜伏，M9-B
/// swapd 自由跨核执行 evict 首次让非 BSP 上下文调用本函数而现形
/// （devlog S35 记档）。
/// 返回是否收到 ack（对侧未上线 = 无需击落，直接成功）。
pub fn shootdown_batch(pages: &[u64]) -> bool {
    let cur = crate::task::current_cpu_slot();
    let peer_online = if cur == 0 {
        // 发起方 = BSP：对侧 AP 上线才需击落
        let ap = AP_ID.load(Ordering::Acquire) as u8;
        if AP_ONLINE.load(Ordering::Acquire) >> 63 != 1 || ap == 0 {
            return true;
        }
        ap
    } else {
        // 发起方 = AP：对侧 BSP 恒在线（发起方能跑即 BSP 已启动它）
        crate::task::bsp_apic_id()
    };
    SHOOTDOWN_ACK.store(0, Ordering::Release);
    let n = pages.len().min(SD_PAGES.len());
    for (i, slot) in SD_PAGES.iter().enumerate() {
        slot.store(pages.get(i).copied().unwrap_or(0), Ordering::Release);
    }
    SD_COUNT.store(n as u64, Ordering::Release);
    SD_MODE.store(1, Ordering::Release); // mode 最后写（AP 侧 Acquire 门闩）
    SHOOTDOWN_SEQ.fetch_add(1, Ordering::AcqRel);
    ostd::hw::lapic::send_fixed_ipi(peer_online, ostd::hw::lapic::IPI_VECTOR);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && SHOOTDOWN_ACK.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    SHOOTDOWN_ACK.load(Ordering::Acquire) >= 1
}

/// 全量击落（M6-C two-shot 变体）：对侧核重写 CR3 下调整个 TLB（未启用
/// PCID → 全量失效）。语义与返回值同 [`shootdown_batch`]（含 M9-B 目标
/// 修正：对侧核 = 非发起方）。
pub fn shootdown_full() -> bool {
    let cur = crate::task::current_cpu_slot();
    let peer = if cur == 0 {
        let ap = AP_ID.load(Ordering::Acquire) as u8;
        if AP_ONLINE.load(Ordering::Acquire) >> 63 != 1 || ap == 0 {
            return true;
        }
        ap
    } else {
        crate::task::bsp_apic_id()
    };
    SHOOTDOWN_ACK.store(0, Ordering::Release);
    SD_MODE.store(2, Ordering::Release);
    SHOOTDOWN_SEQ.fetch_add(1, Ordering::AcqRel);
    ostd::hw::lapic::send_fixed_ipi(peer, ostd::hw::lapic::IPI_VECTOR);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && SHOOTDOWN_ACK.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    SHOOTDOWN_ACK.load(Ordering::Acquire) >= 1
}

/// per-CPU 派发自检（自检 21）证据槽。
static PC_STAMPS: [AtomicU64; 2] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 2]
};
/// per-CPU 派发自检完成计数。
static PC_DONE: AtomicU64 = AtomicU64::new(0);

/// 自检 21 任务体 A：记录本核 APIC ID 后完成（钉扎 CPU1 → 必落 AP）。
fn pc_body_ap() {
    PC_STAMPS[0].store(u64::from(ostd::hw::lapic::id()), Ordering::Release);
    PC_DONE.fetch_add(1, Ordering::AcqRel);
}

/// 自检 21 任务体 B：记录本核 APIC ID 后完成（钉扎 CPU0 → 必落 BSP）。
fn pc_body_bsp() {
    PC_STAMPS[1].store(u64::from(ostd::hw::lapic::id()), Ordering::Release);
    PC_DONE.fetch_add(1, Ordering::AcqRel);
}

/// 自检 21：per-CPU 统一调度跨核派发（钉扎双向路由 + RESCHED 提示）。
/// 协议：钉扎 CPU1 的任务经 RESCHED 提示由 AP idle 拾取；钉扎 CPU0 的
/// 任务由 BSP 主任务让出后拾取——双侧各有一次「全局队列 → 本核执行面」
/// 的完整派发，证据为任务体记录的所在核 APIC ID。
pub fn percpu_dispatch_check(log: &mut DualLog) -> bool {
    PC_DONE.store(0, Ordering::Release);
    for s in &PC_STAMPS {
        s.store(0, Ordering::Release);
    }
    let hits0 = crate::task::resched_hits();
    let bsp_id = u64::from(ostd::hw::lapic::id());
    let ap_id = u64::from(online_ap_id());
    let _ = crate::task::spawn_pinned("percpu-ap", pc_body_ap, 1);
    let _ = crate::task::spawn_pinned("percpu-bsp", pc_body_bsp, 0);
    let deadline = ostd::time::now() + 200;
    while ostd::time::now() < deadline && PC_DONE.load(Ordering::Acquire) < 2 {
        crate::task::yield_now();
    }
    let hits1 = crate::task::resched_hits();
    let s0 = PC_STAMPS[0].load(Ordering::Acquire);
    let s1 = PC_STAMPS[1].load(Ordering::Acquire);
    let _ = writeln!(
        log,
        "smp: percpu stamps=[{s0:#x},{s1:#x}] done={} resched+={}",
        PC_DONE.load(Ordering::Acquire),
        hits1 - hits0
    );
    let mut ok = PC_DONE.load(Ordering::Acquire) == 2;
    ok &= s0 == ap_id && ap_id != 0;
    ok &= s1 == bsp_id;
    ok &= hits1 > hits0;
    ok
}

/// AP 抢占自检（自检 22）忙等任务体：记录本核后空转到解除旗标。
static APB_STOP: AtomicBool = AtomicBool::new(false);
static APB_STAMP: AtomicU64 = AtomicU64::new(0);

fn apb_body() {
    APB_STAMP.store(u64::from(ostd::hw::lapic::id()), Ordering::Release);
    while !APB_STOP.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

/// 自检 22：AP 侧抢占（LAPIC 定时器驱动的跨核抢占切换）。
/// 协议：连派 2 个永不让出的忙任务（均钉扎 CPU1）→ AP idle 拾取首枚，
/// 量子到期后 LAPIC 定时器在 AP 侧抢占并轮转两任务 → 主任务 busy 等待
/// （自身不参与拾取，BSP 侧零干扰）→ 断言全局抢占切换计数增长 ≥ 2
/// 且任务落在 AP。
pub fn ap_preempt_check(log: &mut DualLog) -> bool {
    APB_STOP.store(false, Ordering::Release);
    APB_STAMP.store(0, Ordering::Release);
    let (pre, _) = crate::task::preempt_stats();
    let ap_id = u64::from(online_ap_id());
    let _ = crate::task::spawn_pinned("ap-busy-a", apb_body, 1);
    let _ = crate::task::spawn_pinned("ap-busy-b", apb_body, 1);
    let mut ok = true;
    // 首枚被 AP 拾取（kick + idle）
    let deadline = ostd::time::now() + 200;
    while ostd::time::now() < deadline && APB_STAMP.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    // 等待 AP 侧抢占发生（忙任务对量子轮转 ≥ 2 次）
    let (mut cur, _) = crate::task::preempt_stats();
    let deadline = ostd::time::now() + 300;
    while ostd::time::now() < deadline && cur < pre + 2 {
        core::hint::spin_loop();
        let (c, _) = crate::task::preempt_stats();
        cur = c;
    }
    APB_STOP.store(true, Ordering::Release);
    let deadline = ostd::time::now() + 200;
    while ostd::time::now() < deadline && !crate::task::all_workers_finished() {
        core::hint::spin_loop();
    }
    let stamp = APB_STAMP.load(Ordering::Acquire);
    let _ = writeln!(
        log,
        "smp: ap-preempt stamp={stamp:#x} preempt+={} finished={}",
        cur - pre,
        crate::task::all_workers_finished()
    );
    ok &= stamp == ap_id && ap_id != 0;
    ok &= cur >= pre + 2;
    ok &= crate::task::all_workers_finished();
    ok
}

/// 自检 23：TLB 击落批量化（多页批量 + 全量 two-shot）。
/// 全链：AP 先读旧值 A×8（批量阶段）→ BSP 一轮改映射 8 页 + 本核 invlpg
/// → 一次批量击落（ack 后才回收帧，two-shot 纪律）→ AP 重读 B×8 →
/// 再改映射首页 → 全量击落（CR3 重写）→ AP 重读 C。
pub fn tlb_batch_check(log: &mut DualLog, frames: &FrameAllocator) -> bool {
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    let mut a_frames: [Option<u64>; 8] = [None; 8];
    let mut b_frames: [Option<u64>; 8] = [None; 8];
    let mut ok = true;
    let mut mapped_any = false;
    for (i, va) in BATCH_VA.iter().enumerate() {
        let (fa, fb) = (frames.alloc(), frames.alloc());
        a_frames[i] = fa;
        b_frames[i] = fb;
        if let (Some(fa), Some(fb)) = (fa, fb) {
            let magic_a = 0xCAFE_BABA_0000_00A0u64 | i as u64;
            let magic_b = 0xCAFE_BABA_0000_00B0u64 | i as u64;
            ostd::hw::phys::write_u64(fa, magic_a);
            ostd::hw::phys::write_u64(fb, magic_b);
            let mut w = Walker {
                mem: &mut IdentityAccess,
                alloc_table: || frames.alloc(),
            };
            ok &= w.map(boot_cr3, *va, fa, Entry::WRITABLE).is_ok();
            mapped_any = true;
        } else {
            ok = false;
        }
    }
    if !ok || !mapped_any {
        for f in a_frames
            .into_iter()
            .flatten()
            .chain(b_frames.into_iter().flatten())
        {
            frames.dealloc(f);
        }
        return false;
    }
    // 阶段 1：AP 读 A×8（其 TLB 载入旧翻译）
    BATCH_PHASE.store(1, Ordering::Release);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && BATCH_PHASE.load(Ordering::Acquire) != 2 {
        core::hint::spin_loop();
    }
    for (i, slot) in BATCH_READ.iter().enumerate() {
        ok &= slot.load(Ordering::Acquire) == 0xCAFE_BABA_0000_00A0u64 | i as u64;
    }
    // 一轮改映射 A→B×8 + 本核批量 invlpg
    for (i, va) in BATCH_VA.iter().enumerate() {
        if let Some(fb) = b_frames[i] {
            let mut w = Walker {
                mem: &mut IdentityAccess,
                alloc_table: || frames.alloc(),
            };
            let _ = w.unmap(boot_cr3, *va);
            ok &= w.map(boot_cr3, *va, fb, Entry::WRITABLE).is_ok();
            ostd::hw::control::invlpg(*va);
        }
    }
    let bsp_seen = ostd::hw::phys::read_u64_virt(BATCH_VA[3]);
    // 一次批量击落（two-shot：ack 后才允许回收 A 帧）
    let batch = shootdown_batch(&BATCH_VA);
    ok &= batch;
    // 阶段 3：AP 重读 B×8
    BATCH_PHASE.store(3, Ordering::Release);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && BATCH_PHASE.load(Ordering::Acquire) != 4 {
        core::hint::spin_loop();
    }
    for (i, slot) in BATCH_READ2.iter().enumerate() {
        ok &= slot.load(Ordering::Acquire) == 0xCAFE_BABA_0000_00B0u64 | i as u64;
    }
    // 全量击落变体：改映射首页 → C → CR3 重写式击落
    let Some(fc) = frames.alloc() else {
        for f in a_frames
            .into_iter()
            .flatten()
            .chain(b_frames.into_iter().flatten())
        {
            frames.dealloc(f);
        }
        return false;
    };
    let magic_c = 0xCAFE_BABA_0000_00C0u64;
    ostd::hw::phys::write_u64(fc, magic_c);
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    let _ = w.unmap(boot_cr3, BATCH_VA[0]);
    ok &= w.map(boot_cr3, BATCH_VA[0], fc, Entry::WRITABLE).is_ok();
    ostd::hw::control::invlpg(BATCH_VA[0]);
    ok &= shootdown_full();
    BATCH_PHASE.store(5, Ordering::Release);
    let deadline = ostd::time::now() + 100;
    while ostd::time::now() < deadline && BATCH_PHASE.load(Ordering::Acquire) != 6 {
        core::hint::spin_loop();
    }
    ok &= FULL_READ.load(Ordering::Acquire) == magic_c;
    // 清理：取消映射 → 本核失效 → 终轮批量击落（拆 AP 侧阶段读残留的
    // 翻译缓存）→ 帧回收（two-shot 完整收口）
    for va in BATCH_VA.iter() {
        let _ = w.unmap(boot_cr3, *va);
        ostd::hw::control::invlpg(*va);
    }
    ok &= shootdown_batch(&BATCH_VA);
    for f in a_frames
        .into_iter()
        .flatten()
        .chain(b_frames.into_iter().flatten())
    {
        frames.dealloc(f);
    }
    frames.dealloc(fc);
    BATCH_PHASE.store(0, Ordering::Release);
    let _ = writeln!(
        log,
        "smp: tlb-batch bsp-seen={bsp_seen:#x} batch-ack={batch}"
    );
    ok
}
