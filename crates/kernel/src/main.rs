//! Lumina OS 内核映像（lumina-kernel）。
//!
//! 里程碑 M3：物理帧管理 + 页表抽象、中断与定时器、上下文切换与首进程
//! （SPEC 第 2/17 章内存与 OSTD 边界；DEV-002 第四/五章 no_std 与
//! panic=abort 纪律；PORT-004 第 3 章 x86_64 自定义三元组）。
//!
//! 启动路径：QEMU `-kernel`（multiboot1）→ 32 位保护模式入口 [`boot::_start`]
//! → 低 1 GiB 恒等映射 → x86_64 长模式 → [`kmain`]（safe Rust 自检 20 项）
//! → isa-debug-exit（0xF4 端口）自动退出。
//!
//! M3 新增（对照 M2 的七项自检，扩至十一项）：
//! - 8  frame-alloc-stats：区间裁剪帧分配器（LIFO 复用 + 统计不变式）；
//! - 9  page-mmu-roundtrip：四级页表 map → CR3 切换 → MMU 写读 →
//!   程序级 translate/unmap（phys_offset = 0 恒等映射窗口内）；
//! - 10 interrupt-timer-ticks：IDT 装载 + PIC 重映射 + PIT 100 Hz +
//!   hlt 睡眠 3 节拍推进；
//! - 11 context-switch-first-process：proc-alpha/proc-beta 两个内核任务
//!   纯轮转交错（共享序列日志精确 [a1,b1,a2,b2,a3,b3]）。
//!
//! unsafe 分布（SPEC 第十七章审批矩阵）：
//! - 启动汇编（本 crate `boot` 模块）与中断桩（`ostd::interrupt::stubs`）：
//!   框架内核白名单模块；
//! - [`ostd::hw`]：端口 I/O、VGA、物理/虚拟内存 volatile、CR3、IDTR
//!   的收口层（HW-01…08）；
//! - 其余内核代码全部为 safe Rust。
//!
//! 自动验收：宿主侧 xtask `smoke` 阶段运行 QEMU（-smp 2），断言串口日志含
//! `LUMINA-BOOT-OK` 与 `LUMINA-SELFTEST-PASS 20/20`，且退出码为 33。

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod boot;
mod caps;
mod console;
mod hostlink;
mod interrupts;
mod ipc;
mod multiboot1;
mod procs;
mod selftest;
mod smp;
mod swap;
mod syscall;
mod task;
mod user;
mod vmm;

use core::fmt::Write as _;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
use bedrock::ipc::Endpoint;
use bedrock::tlv;
use harbor::HarborBump;
use ostd::mm::frame::{FrameAllocator, Region, FRAME_SIZE};
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::SpinLock;

use crate::console::DualLog;
use crate::multiboot1::BOOT_MAGIC;

/// 内核堆大小：4 MiB（M3 任务栈/日志/TLV 充足；帧管理独立于本堆）。
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// 自检项目总数（M2 七项 + M3 四项 + M4 四项 + M5 五项 + M6 五项 + M7 两项
/// + M8 三项）。
const SELFTEST_TOTAL: usize = 33;

/// 内核堆后备区域：静态 4 MiB、4 KiB 对齐，链接进 .bss（NOLOAD）。
#[repr(align(4096))]
struct KernelHeap {
    /// 后备字节区。
    bytes: [u8; HEAP_SIZE],
}

// SAFETY 静态槽说明：MB_MAGIC/MB_INFO 由启动汇编在长模式前写入，
// kmain 仅以 addr_of! 读取；启动后不再变化。
/// 引导装载程序写入的 multiboot1 魔数（应为 0x2BADB002）。
#[no_mangle]
static MB_MAGIC: u32 = 0;
/// 引导装载程序写入的 multiboot1 信息块物理地址。
#[no_mangle]
static MB_INFO: u32 = 0;

static mut KERNEL_HEAP: KernelHeap = KernelHeap {
    bytes: [0; HEAP_SIZE],
};

/// 全局分配器：kmain 早期 rebind 到静态内核堆（Harbor 启动惯用法）。
#[global_allocator]
static ALLOC: HarborBump = HarborBump::new_unbacked();

/// 首批进程共享的交错序列日志（自检 11 的判定证据）。
static ORDER_LOG: SpinLock<Vec<&'static str>> = SpinLock::new(Vec::new());

/// proc-alpha 的推进步（与 proc-beta 交错，构成确定性轮转证据）。
static ALPHA_STEPS: [&str; 3] = ["alpha-1", "alpha-2", "alpha-3"];
/// proc-beta 的推进步。
static BETA_STEPS: [&str; 3] = ["beta-1", "beta-2", "beta-3"];

/// 首进程 proc-alpha：三步推进，每步让出。
fn proc_alpha() {
    for step in ALPHA_STEPS {
        ORDER_LOG.lock().push(step);
        task::yield_now();
    }
}

/// 首进程 proc-beta：与 alpha 同构。
fn proc_beta() {
    for step in BETA_STEPS {
        ORDER_LOG.lock().push(step);
        task::yield_now();
    }
}

// 内核映像末端符号（linker.ld PROVIDE），用于计算映像大小。
extern "C" {
    static kern_end: u8;
}

/// 内核主入口：由启动汇编在长模式下调入（rdi=魔数，rsi=信息块地址）。
#[no_mangle]
pub extern "C" fn kmain(magic: u32, info: u32) -> ! {
    let mut log = DualLog::new();
    // 注：内核控制台路径使用 ASCII（VGA 字体为 CP437）；中文诊断记录在
    // 宿主侧开发日志 lumina-build/logs/devlog.md（见 console.rs 模块文档）。
    let _ = writeln!(
        log,
        "Lumina OS lumina-kernel v{} (M9: process model cap-grant/handle-lifecycle + async paging + priority aging)",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        log,
        "multiboot1 handoff: magic={magic:#010x} info={info:#010x}"
    );

    // ---- 启动期绑定内核堆（必须在任何分配发生之前）----
    // addr_of_mut! 取字段地址不产生中间引用（safe 操作）。
    let heap_ptr = unsafe { core::ptr::addr_of_mut!(KERNEL_HEAP.bytes) } as *mut u8;
    assert!(
        ALLOC.rebind(heap_ptr, HEAP_SIZE),
        "kernel heap rebind failed"
    );
    let _ = writeln!(log, "kernel heap: {HEAP_SIZE} bytes bound (HarborBump)");

    // ---- 引导信息解析 ----
    let summary = multiboot1::summarize(info);
    let _ = writeln!(
        log,
        "mem: lower={}KiB upper={}KiB info-flags={:#x}",
        summary.lower_kib,
        summary.upper_kib,
        multiboot1::info_flags(info)
    );
    if let Some(r) = summary.largest_usable {
        let _ = writeln!(
            log,
            "largest usable region: {:#x}..{:#x}",
            r.start,
            r.start + r.len
        );
    }

    // ---- M3 物理面：完整 mmap → 帧分配器（保留内核足迹）----
    let mut usable_mb: Vec<multiboot1::Region> = Vec::new();
    multiboot1::usable_regions(info, &mut usable_mb);
    let kernel_size = (core::ptr::addr_of!(kern_end) as usize) - 0x10_0000;
    let kernel_span_end = ((0x10_0000 + kernel_size) as u64).next_multiple_of(FRAME_SIZE);
    let info_page = (info as u64) & !0xFFF;
    let usable: Vec<Region> = usable_mb
        .iter()
        .map(|r| Region {
            start: r.start,
            len: r.len,
        })
        .collect();
    let reserved: Vec<Region> = Vec::from(&[
        // 低于 1 MiB：实模式/BIOS/设备区，永不下发
        Region {
            start: 0,
            len: 0x10_0000,
        },
        // 内核映像（含 .boot.bss 的页表/栈与 4 MiB 内核堆）
        Region {
            start: 0x10_0000,
            len: kernel_span_end - 0x10_0000,
        },
        // multiboot 信息块 + mmap 表所在页（防御式双页）
        Region {
            start: info_page,
            len: 0x2000,
        },
    ]);
    let frames = match FrameAllocator::new(&usable, &reserved) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(log, "frame allocator init failed: {e:?}");
            kernel_exit(EXIT_FAILURE);
        }
    };
    // M5：帧服务升级为全局静态引用（SMP/VMM 的 IPI/#PF 上下文无法携参）
    let frames: &'static FrameAllocator = Box::leak(Box::new(frames));
    let fs = frames.stats();
    let _ = writeln!(
        log,
        "frames: total={} (usable {} region(s), kernel span {:#x} KiB reserved)",
        fs.total,
        usable.len(),
        kernel_size / 1024
    );

    // ---- M6-A SMP 前置：LAPIC 提前上线 + 探测 + 门钩子注册 ----
    // （调度器 per-CPU 语义依赖 LAPIC id；先于任何 task::init/spawn）
    smp::pre_init(&mut log, frames);

    // ---- M4 机器面：完整 GDT/TSS 与 SYSCALL/SYSRET 约定 ----
    ostd::hw::gdt::install();
    task::set_user_entry_bridge(user::enter_user_bridge);
    // SAFETY: GDT 已按配套布局装载（syscall::init 的选择子基址与之配套），
    //         且 ring3 代码尚不存在，LSTAR 生效不产生即时入口。
    unsafe { syscall::init() };
    let _ = writeln!(log, "gdt/tss installed, syscall entry bound");

    // ---- M4-F SMP 就绪探测：CPUID 叶 1 + LAPIC 基址（AP 启动留 M5）----
    let leaf1 = ostd::hw::cpuid::leaf1();
    let (apic_present, apic_id) = ostd::hw::cpuid::parse_leaf1(leaf1);
    let lapic_base = ostd::hw::msr::read(0x1B);
    let _ = writeln!(
        log,
        "cpu: family={} apic-present={apic_present} apic-id={apic_id} lapic-base={:#x} (lapic-enabled={})",
        (leaf1.eax >> 8) & 0xF,
        lapic_base & !0xFFF,
        lapic_base & (1 << 11) != 0
    );

    // ---- 十五项自检 ----
    let mut pass: usize = 0;
    let mut report = |log: &mut DualLog, ok: bool, name: &str| {
        selftest::report(log, &mut pass, ok, name);
    };

    // 1) 引导魔数与内存面
    let t1 = magic == BOOT_MAGIC && summary.upper_kib > 0;
    report(&mut log, t1, "multiboot-magic+mem");

    // 2) BootInfo 结构不变式（用真实链接基址与映像大小）
    let bi = ostd::boot::BootInfo {
        kernel_phys_base: 0x10_0000,
        kernel_size: kernel_size as u64,
        phys_offset: 0,
        framebuffer_phys: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_stride: 0,
    };
    let t2 = bi.validate().is_ok() && kernel_size > 0;
    let _ = writeln!(
        log,
        "kernel footprint (loaded+bss): base 0x100000, {kernel_size} bytes"
    );
    report(&mut log, t2, "bootinfo-invariants");

    // 3) OSTD 自旋锁语义
    let lock = SpinLock::new(41u32);
    let t3 = {
        let mut g = lock.lock();
        *g += 1;
        let held = lock.is_locked() && lock.try_lock().is_none();
        drop(g);
        held && !lock.is_locked() && *lock.lock() == 42
    };
    report(&mut log, t3, "spinlock-mutex");

    // 4) 内核堆：Vec 分配/写读/统计
    let t4 = {
        let mut v: Vec<u64> = Vec::new();
        v.extend(0..1000u64);
        let sum: u64 = v.iter().sum();
        drop(v);
        // 统计快照必须在 drop 之后取：deallocs 计数才反映释放行为
        let stats = ALLOC.stats();
        sum == 499_500 && stats.peak_bytes > 0 && stats.deallocs >= 1
    };
    report(&mut log, t4, "heap-alloc-stats");

    // 5) TLV 编帧往返
    let t5 = {
        let mut buf = Vec::new();
        let ok_enc = tlv::encode(&mut buf, 0x0007, b"lumina-m3").is_ok();
        match tlv::decode_all(&buf) {
            Ok(frames) => {
                ok_enc
                    && frames.len() == 1
                    && frames[0].tag == 0x0007
                    && frames[0].value == b"lumina-m3"
            }
            Err(_) => false,
        }
    };
    report(&mut log, t5, "tlv-roundtrip");

    // 6) IPC 端点信箱
    let t6 = {
        let ep = Endpoint::new();
        let send_ok = ep.send(Vec::from(&b"ping"[..])).is_ok();
        send_ok && ep.pending() == 1 && ep.recv() == Ok(Vec::from(&b"ping"[..]))
    };
    report(&mut log, t6, "ipc-endpoint");

    // 7) 系统调用 ABI v0 解析
    let t7 = {
        let regs = bedrock::abi::SyscallRegs {
            num: bedrock::abi::SYS_IPC_SEND,
            args: [3, 1, 0, 0, 0],
        };
        matches!(
            bedrock::abi::parse(regs),
            Ok(bedrock::abi::Syscall::IpcSend { .. })
        ) && matches!(
            bedrock::abi::parse(bedrock::abi::SyscallRegs {
                num: 0x99,
                args: [0; 5]
            }),
            Err(bedrock::abi::AbiError::UnknownSyscall)
        )
    };
    report(&mut log, t7, "abi-v0-parse");

    // 8) 物理帧管理：全量耗尽 → 全还 → LIFO 复用 → 统计自洽
    //    （M6：pre_init 已为 LAPIC 页表预消费若干帧，账目按 h0 基线折算）
    let t8 = {
        let h0 = frames.stats().held;
        let mut all: Vec<u64> = Vec::new();
        while let Some(f) = frames.alloc() {
            all.push(f);
        }
        let s1 = frames.stats();
        let mut ok = all.len() as u64 == s1.total - h0
            && s1.held == s1.total
            && all.first().is_some_and(|f| f.is_multiple_of(FRAME_SIZE))
            && s1.total > 1024;
        // 全部归还 → 空闲表 = 全量 − 基线持有
        for f in &all {
            frames.dealloc(*f);
        }
        let s2 = frames.stats();
        ok &= s2.held == h0 && s2.free_list == s2.total - h0;
        // LIFO：最后归还的最先回来
        let last = all.last().copied();
        ok &= last.is_some() && frames.alloc() == last;
        if let Some(a) = last {
            frames.dealloc(a);
        }
        let s3 = frames.stats();
        // allocs/deallocs 为分配器全寿命计数：与 s1 做增量比较（pre_init
        // 等启动期消费者已产生既有分配，全寿命值天然不等）
        ok &= s3.allocs - s3.deallocs == s3.held && s3.free_list == s3.total - h0;
        ok
    };
    report(&mut log, t8, "frame-alloc-stats");

    // 9) 页表抽象 MMU 往返：map → CR3 切换 → 经新映射写读 → 翻译/取消
    let t9 = {
        const TEST_VIRT: u64 = 0x1_0000_0000; // 4 GiB：PML4[1] 全新分支
        const TEST_MAGIC: u64 = 0xA5A5_1234_5A5A_4321;
        let boot_cr3 = ostd::hw::control::read_cr3();
        let new_root = frames.alloc();
        let target = frames.alloc();
        let mut ok = new_root.is_some() && target.is_some();
        if let (Some(root), Some(dst)) = (new_root, target) {
            ostd::hw::phys::write_zero(root, FRAME_SIZE);
            // 复制启动根的内核必需分支（恒等映射 + LAPIC MMIO），保住
            // 内核代码/栈与 per-CPU 路径（M6：clone_kernel_branches）
            ostd::mm::page::clone_kernel_branches(boot_cr3, root);
            let map_res = {
                let mut w = Walker {
                    mem: &mut IdentityAccess,
                    alloc_table: || frames.alloc(),
                };
                w.map(root, TEST_VIRT, dst, Entry::WRITABLE)
            };
            ok &= map_res.is_ok();
            // MMU 级证明：切 CR3 → 经新映射写 → 恒等映射读同一物理帧
            ostd::hw::control::write_cr3(root);
            ostd::hw::phys::write_u64_virt(TEST_VIRT, TEST_MAGIC);
            let seen = ostd::hw::phys::read_u64(dst);
            ostd::hw::control::write_cr3(boot_cr3);
            ok &= seen == TEST_MAGIC;
            // 程序级翻译/取消（不依赖 MMU）
            let mut w = Walker {
                mem: &mut IdentityAccess,
                alloc_table: || frames.alloc(),
            };
            ok &= w.translate(root, TEST_VIRT) == Some(dst);
            ok &= w.unmap(root, TEST_VIRT) != Err(PageError::NotMapped);
            ok &= w.translate(root, TEST_VIRT).is_none();
            // 回收根与目标帧（3 张中间表留作 M3 遗迹，量小可忽略）
            frames.dealloc(root);
            frames.dealloc(dst);
        }
        ok
    };
    report(&mut log, t9, "page-mmu-roundtrip");

    // 10) 中断与定时器：IDT/PIC/PIT 装配 + hlt 睡眠节拍推进
    let t10 = {
        let hz = interrupts::init_and_enable(&mut log);
        let (m, s) = ostd::hw::pic::masks();
        // PIT 分频为整数：实际频率允许 ±1 Hz 舍入差
        let mut ok = hz.abs_diff(interrupts::TIMER_HZ) <= 1
            && interrupts::timer_gate_ok()
            && m == 0xFE
            && s == 0xFF;
        let t0 = ostd::time::now();
        ok &= ostd::time::sleep_ticks(3, 500);
        ok &= ostd::time::now() >= t0 + 3;
        let _ = writeln!(log, "timer: hz={hz} ticks {} -> {}", t0, ostd::time::now());
        // M6-A：统一 per-CPU 抢占源——LAPIC 定时器校准并启动（BSP 侧；
        // AP 侧在 ap_main 内复用校准结果自行启动）
        let counts = smp::timer_calibrate_and_start();
        let _ = writeln!(log, "lapic-timer calibrated: {counts} counts/tick (100 Hz)");
        ok &= counts > 0;
        ok
    };
    report(&mut log, t10, "interrupt-timer-ticks");

    // 11) 上下文切换与首进程：两个内核任务纯轮转交错
    //     （M4：本窗口保持抢占关闭——协作演示要求精确交错）
    let t11 = {
        task::init();
        let a = task::spawn("proc-alpha", proc_alpha);
        let b = task::spawn("proc-beta", proc_beta);
        let _ = writeln!(log, "tasks spawned: alpha={a} beta={b}, round-robin...");
        while !task::all_workers_finished() {
            task::yield_now();
        }
        let order = ORDER_LOG.lock().clone();
        let _ = writeln!(log, "order log: {order:?}");
        // 确定性轮转证据：a1 → b1 → a2 → b2 → a3 → b3
        order.as_slice()
            == [
                "alpha-1", "beta-1", "alpha-2", "beta-2", "alpha-3", "beta-3",
            ]
    };
    report(&mut log, t11, "context-switch-first-process");

    // 12) 抢占式调度：忙任务（从不让出）被定时器强制切片推进
    let t12 = {
        static GAMMA_COUNTER: AtomicU64 = AtomicU64::new(0);
        static GAMMA_STOP: AtomicBool = AtomicBool::new(false);
        fn gamma_body() {
            // 忙循环：零 yield——全部推进只能来自抢占切片（CONTEXT-02）
            while !GAMMA_STOP.load(Ordering::Relaxed) {
                GAMMA_COUNTER.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
            }
        }
        task::set_preempt_enabled(true);
        let pre_counter = GAMMA_COUNTER.load(Ordering::Relaxed);
        let (pre0, _) = task::preempt_stats();
        let g = task::spawn("proc-gamma", gamma_body);
        let _ = writeln!(
            log,
            "gamma spawned (id={g}), busy-looping, quantum=3 ticks..."
        );
        let t0 = ostd::time::now();
        while ostd::time::now() < t0 + 15 {
            task::yield_now();
        }
        GAMMA_STOP.store(true, Ordering::Relaxed);
        while !task::all_workers_finished() {
            task::yield_now();
        }
        let counter = GAMMA_COUNTER.load(Ordering::Relaxed) - pre_counter;
        let (pre1, _) = task::preempt_stats();
        let preempts = pre1 - pre0;
        let _ = writeln!(
            log,
            "gamma advanced {counter} iters in ~15 ticks; preempt switches: {preempts}"
        );
        counter > 10_000 && preempts >= 2
    };
    report(&mut log, t12, "preempt-busy-task");

    // 13) TSC 计时源校准 + 数值基准（页表遍历 / 上下文切换）
    let t13 = {
        let hz = ostd::time::calibrate_tsc(10, u64::from(interrupts::TIMER_HZ));
        let _ = writeln!(log, "tsc calibrated: {hz} Hz");
        let mut ok = (1_000_000..=10_000_000_000u64).contains(&hz);
        // 页表遍历基准：建 32 页映射 + 1000 轮全量翻译
        let mut walk_ns: Option<u64> = None;
        if let Some(bench_root) = frames.alloc() {
            ostd::hw::phys::write_zero(bench_root, FRAME_SIZE);
            let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
            ostd::mm::page::clone_kernel_branches(boot_cr3, bench_root);
            let mut mapped: Vec<(u64, u64)> = Vec::new();
            let mut map_ok = true;
            for i in 0..32u64 {
                let (virt, phys) = (0x2_0000_0000 + i * FRAME_SIZE, frames.alloc());
                if let Some(p) = phys {
                    let mut w = Walker {
                        mem: &mut IdentityAccess,
                        alloc_table: || frames.alloc(),
                    };
                    map_ok &= w.map(bench_root, virt, p, Entry::WRITABLE).is_ok();
                    mapped.push((virt, p));
                } else {
                    map_ok = false;
                }
            }
            if map_ok && !mapped.is_empty() {
                let t0 = ostd::time::tsc_now();
                let mut sink: u64 = 0;
                for _ in 0..1000 {
                    for (v, _) in &mapped {
                        let w = Walker {
                            mem: &mut IdentityAccess,
                            alloc_table: no_alloc_table,
                        };
                        sink ^= w.translate(bench_root, *v).unwrap_or(0);
                    }
                }
                let t1 = ostd::time::tsc_now();
                walk_ns = ostd::time::tsc_clock::elapsed_ns(t1 - t0);
                let _ = writeln!(
                    log,
                    "bench page-walk: 32000 translates -> {:?} ns (sink {sink:#x})",
                    walk_ns
                );
            }
            ok &= walk_ns.is_some_and(|n| n > 0);
        }
        // 上下文切换基准：两任务互让 200 次（协作路径 ns/switch）
        static BENCH_DONE: AtomicBool = AtomicBool::new(false);
        fn bench_body() {
            for _ in 0..200 {
                task::yield_now();
            }
            if task::all_workers_finished() {
                // 占位：两个 bench 任务互相等待由队列天然完成
            }
            BENCH_DONE.store(true, Ordering::Relaxed);
        }
        let (_, coop0) = task::preempt_stats();
        let t0 = ostd::time::tsc_now();
        let _a = task::spawn("bench-a", bench_body);
        let _b = task::spawn("bench-b", bench_body);
        while !task::all_workers_finished() {
            task::yield_now();
        }
        let t1 = ostd::time::tsc_now();
        let (_, coop1) = task::preempt_stats();
        let switches = coop1 - coop0;
        let switch_ns =
            ostd::time::tsc_clock::elapsed_ns(t1 - t0).and_then(|n| n.checked_div(switches.max(1)));
        let _ = writeln!(
            log,
            "bench ctx-switch: {switches} switches -> {:?} ns/switch",
            switch_ns
        );
        ok &= switch_ns.is_some_and(|n| n > 0 && n < 1_000_000_000);
        ok
    };
    report(&mut log, t13, "tsc-calibrate-bench");

    // 14) 用户态进程 + 系统调用：ring3 执行 → LOG/YIELD×32/EXIT(42)
    let t14 = {
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                let root_ok = user::translate(us.root, user::USER_CODE_VIRT).is_some()
                    && user::translate(us.root, user::USER_STACK_VIRT).is_some();
                let _ = writeln!(
                    log,
                    "user space: root={:#x} code={:#x} stack={:#x}",
                    us.root, us.code_frame, us.stack_frame
                );
                let _id = task::spawn_user("proc-user", user_noop, us.root, 0);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let (clog, cyield, cother) = task::syscall_counts();
                let exit_code = task::user_exit_code();
                let _ = writeln!(
                    log,
                    "user done: exit={exit_code} counts(log={clog}, yield={cyield}, other={cother})"
                );
                root_ok && exit_code == 42 && clog == 1 && cyield == 32 && cother == 1
            }
            Err(e) => {
                let _ = writeln!(log, "user space build failed: {e:?}");
                false
            }
        }
    };
    report(&mut log, t14, "user-ring3-syscall");

    // 15) TLV 宿主-客户机联测（xtask S8 经 QEMU stdio 驱动）
    let t15 = hostlink::run_exchange(&mut log);
    report(&mut log, t15, "tlv-host-guest");

    // 16) SMP：AP 启动（INIT-SIPI）与上线握手（自检 16）
    //     前置：帧服务已全局化；中断已开（check 10）；插桩 IPI 门已注册
    let t16 = {
        let (ok, ap_id, cpus) = smp::bring_up(&mut log, frames);
        ok && cpus >= 2 && ap_id != 0
    };
    report(&mut log, t16, "smp-ap-online");

    // 17) SMP：跨核工作池（AP 独占 16 + BSP/AP 并发认领 16，恰一次性断言）
    let t17 = smp::parallel_work_check();
    report(&mut log, t17, "smp-parallel-work");

    // 18) SMP：TLB 击落（BSP 改映射 → 本核 invlpg → IPI → AP 重读新值）
    let t18 = smp::tlb_shootdown_check(&mut log, frames, smp::online_ap_id());
    report(&mut log, t18, "smp-tlb-shootdown");

    // 19) IPC 快速路径：BSP↔AP 无锁 SPSC 双环往返基准（B-P01，TCG 基线）
    let t19 = smp::fastpath_bench(&mut log);
    report(&mut log, t19, "ipc-fastpath-bench");

    // 20) 按需分页 + 能力化映射（#PF 恢复钩子 + Vanguard 门禁）
    vmm::init(frames);
    let t20 = vmm::demand_paging_check(&mut log, frames);
    report(&mut log, t20, "demand-paging-caps");

    // 21) per-CPU 统一调度：跨核派发（钉扎双向路由 + RESCHED 提示）
    let t21 = smp::percpu_dispatch_check(&mut log);
    report(&mut log, t21, "percpu-dispatch");

    // 22) AP 侧抢占：LAPIC 定时器驱动的跨核抢占切换
    let t22 = smp::ap_preempt_check(&mut log);
    report(&mut log, t22, "smp-ap-preempt");

    // 23) TLB 击落批量化：多页批量 + 全量 two-shot
    let t23 = smp::tlb_batch_check(&mut log, frames);
    report(&mut log, t23, "tlb-shootdown-batch");

    // 24) IPC 系统调用面能力化：ring3 客户端（能力门禁负探针 + 回声往返）
    let t24 = {
        ipc::init();
        // 能力安装：父槽 1（SEND|RECV），派生子槽 2 随任务注入
        let caps_ok = ipc::install_echo_caps(1, 2);
        let mut ok = caps_ok;
        let _ = task::spawn("ipc-echo", ipc::echo_worker_body);
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                // 代码帧覆写为 IPC 客户端映像（build_user_space 默认写入
                // LOG/YIELD 演示程序；帧位置与布局完全一致）
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_IPC_PROGRAM);
                let _id = task::spawn_user("ipc-client", user_noop, us.root, 2);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let exit_code = task::user_exit_code();
                // 接收缓冲取证：接收缓冲虚拟地址 → 栈帧内偏移（恒等映射直读）
                let recv_off = user::USER_IPC_RECV_VA - user::USER_STACK_VIRT;
                let echo_word = ostd::hw::phys::read_u32(us.stack_frame + recv_off);
                ok &= ipc::selfcheck_log(
                    &mut log,
                    exit_code,
                    ipc::echo_served(),
                    u64::from(echo_word),
                );
                ok &= exit_code == 52 && ipc::echo_served() == 1;
                ok &= echo_word == user::PING_WORD;
            }
            Err(e) => {
                let _ = writeln!(log, "ipc client space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t24, "ipc-syscall-caps");

    // 25) swap 预留位：唯一性 / LIFO 复用 / 统计自洽
    let t25 = {
        let mut slots: Vec<u32> = Vec::new();
        let mut ok = true;
        for _ in 0..4 {
            match vmm::reserve_swap_slot() {
                Some(s) => {
                    ok &= !slots.contains(&s);
                    slots.push(s);
                }
                None => ok = false,
            }
        }
        let (next0, free0) = vmm::swap_stats();
        ok &= next0 == 4 && free0 == 0;
        // 归还 2 槽 → LIFO 复用顺序 = 归还逆序
        vmm::release_swap_slot(slots[1]);
        vmm::release_swap_slot(slots[3]);
        let r3 = vmm::reserve_swap_slot();
        let r1 = vmm::reserve_swap_slot();
        ok &= r3 == Some(slots[3]) && r1 == Some(slots[1]);
        // 全量归还 → 空闲队列 4；再预留 → 派发上限不增长
        for s in [r3, r1].into_iter().flatten() {
            vmm::release_swap_slot(s);
        }
        vmm::release_swap_slot(slots[0]);
        vmm::release_swap_slot(slots[2]);
        let (_, free_all) = vmm::swap_stats();
        let (next1, _) = vmm::swap_stats();
        ok &= free_all == 4 && next1 == next0;
        // 收尾排空空闲队列（恰好 free_all 次；reserve 对空队列会派发新号，
        // 不可作排空谓词——开发期实测死循环）
        let mut drained = 0;
        while drained < free_all {
            if vmm::reserve_swap_slot().is_some() {
                drained += 1;
            }
        }
        let _ = writeln!(
            log,
            "vmm: swap slots next={next1} recycled-ok drained={drained}"
        );
        ok
    };
    report(&mut log, t25, "swap-reserve");

    // 26) 用户任务跨核：钉扎 CPU1 的 ring3 任务全程在 AP 执行（M7-A）
    //     取证链：LOG 服务核 == 1（跨核证据）；本核 TSS.RSP0 == 本核
    //     per-CPU syscall 栈（per-CPU TSS 契约）；退出码 42（全链完好）。
    let t26 = {
        task::reset_user_evidence();
        let mut ok = true;
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                let _id = task::spawn_user_pinned("user-ap", user_noop, us.root, 0, 1);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let exit_code = task::user_exit_code();
                let (cpu, rsp0, kstack) = task::log_stamp();
                let (k0, k1, r0, r1) = task::percpu_debug();
                let _ = writeln!(
                    log,
                    "user cross-core: exit={exit_code} log-cpu={cpu} rsp0={rsp0:#x} kstack={kstack:#x} percpu k0={k0:#x} k1={k1:#x} r0={r0:#x} r1={r1:#x}"
                );
                ok &= exit_code == 42; // USER_PROGRAM 退出码（跨核路径完好）
                ok &= cpu == 1; // LOG 在 AP 上被服务（跨核证据）
                ok &= rsp0 != 0 && rsp0 == kstack; // per-CPU TSS.RSP0 契约
            }
            Err(e) => {
                let _ = writeln!(log, "user ap space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t26, "user-cross-core");

    // 27) swap 换页 I/O + 驻留位图（M7-B：ATA PIO HW-15 + vmm 坐标面协同）
    let t27 = swap::paging_io_check(&mut log, frames);
    report(&mut log, t27, "swap-paging-io");

    // 28) syscall 双核并发风暴（M8-A：per-CPU 栈接线 + 全局槽退役）
    //     协议：两个用户任务钉扎双核并发进入 syscall 窗口（LOG+YIELD×64
    //     +EXIT）——旧全局槽形态下后派发者覆写全局面，先入场者帧失去
    //     独占栈（双核并发即互踩，v0.7.0 已知限制）；per-CPU 槽形态下
    //     各任务帧落各自内核栈。取证链：每核退出码 46/47 各自落位 +
    //     LOG 服务核位图 0b11 + per-CPU 槽两栈互异且与本核 TSS.RSP0
    //     同源 + LAPIC 基址契约（入口桩硬编码 0xFEE00020 的前提）。
    let t28 = {
        task::reset_user_evidence();
        let mut ok = true;
        // 定时器屏蔽 + 抢占关闭（TCG 双异常交付规避，S31 记档）：风暴的
        // 并发性来自双核协作 yield，无需节拍；tick 入 ring3 交付面整体移除
        task::set_preempt_enabled(false);
        ostd::hw::lapic::timer_mask();
        ok &= ostd::hw::lapic::base() & !0xFFF == 0xFEE0_0000;
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                // 同一程序映像，退出码帧偏移 30 处改写为 46 / 47（双证分离）
                ostd::hw::phys::write_bytes(usa.code_frame + 30, &[0xBF, 46, 0, 0, 0]);
                ostd::hw::phys::write_bytes(usb.code_frame + 30, &[0xBF, 47, 0, 0, 0]);
                let _ = task::spawn_user_pinned("storm-a", user_noop, usa.root, 0, 0);
                let _ = task::spawn_user_pinned("storm-b", user_noop, usb.root, 0, 1);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let (e0, e1) = task::user_exit_codes();
                let mask = task::log_cpu_mask();
                let (k0, k1, r0, r1) = task::percpu_debug();
                let _ = writeln!(
                    log,
                    "storm: exit=({e0},{e1}) log-mask={mask:#04b} k0={k0:#x} k1={k1:#x} r0={r0:#x} r1={r1:#x}"
                );
                ok &= e0 == 46 && e1 == 47; // 双核并发窗口各自完整收束
                ok &= mask == 0b11; // LOG 双核各自服务
                ok &= k0 != 0 && k1 != 0 && k0 != k1; // per-CPU 栈互异（双栈并存）
                ok &= r0 == k0 && r1 == k1; // RSP0 与 per-CPU 槽同源契约
            }
            _ => {
                let _ = writeln!(log, "storm: user space build failed");
                ok = false;
            }
        }
        task::set_preempt_enabled(true);
        ostd::hw::lapic::timer_unmask();
        ok
    };
    report(&mut log, t28, "syscall-dualcore-storm");

    // 29) 页表级 swap 回收全链（M8-B：A 位二次机会 + unmap/击落/坐标释放
    //     + #PF 换入重映射）。
    //     协议：(a) 淘汰算法确定性——手工置页 0..3 的 A 位，扫描必选
    //     页 4..8（纯页表逻辑，不依赖 MMU A 位行为）；(b) 淘汰全链——
    //     unmap/本核 invlpg/批量击落/帧回收/坐标与驻留落账逐项取证；
    //     (c) ring3 读回——被淘汰 4 页各一次 #PF → swap-in 重映射 →
    //     魔数（含内核预写）经盘往返复原 → EXIT(44)；(d) 收尾——坐标
    //     归还 + 帧账目不变式。
    let t29 = {
        let mut ok = true;
        let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                if let Some(data) = user::attach_data_pages(us.root, &mut || frames.alloc()) {
                    // 内核预写页 4..8 魔数（淘汰 → 盘往返 → 换入复原取证）
                    for (i, f) in data.iter().enumerate().skip(4) {
                        ostd::hw::phys::write_u64(*f, user::SWAP_MAGIC_KERN | i as u64);
                    }
                    // (a) 淘汰算法确定性：手工置页 0..3 A 位 → 扫描必选 4..8
                    for i in 0..4u64 {
                        let va = user::SWAP_DATA_VA + i * 0x1000;
                        let mut w = Walker {
                            mem: &mut IdentityAccess,
                            alloc_table: no_alloc_table,
                        };
                        ok &= w.set_leaf_bits(us.root, va, Entry::ACCESSED, 0).is_ok();
                    }
                    let victims =
                        vmm::reclaim_scan(us.root, user::SWAP_DATA_VA, user::SWAP_DATA_PAGES, 4);
                    let want: Vec<u64> =
                        (4..8u64).map(|i| user::SWAP_DATA_VA + i * 0x1000).collect();
                    ok &= victims == want;
                    let _ = writeln!(log, "reclaim: victims = {victims:?}");
                    // (b) 淘汰全链：I/O → unmap → 击落 → 帧回收 → 落账
                    let (outs0, ins0, _) = swap::stats();
                    let (next0, free0) = vmm::swap_stats();
                    let held0 = frames.stats().held;
                    for va in &victims {
                        ok &= vmm::evict_one(us.root, *va, frames).is_ok();
                    }
                    ok &= vmm::swapped_len() == 4;
                    for va in &victims {
                        // 页表级 unmap 证据（淘汰后翻译必失）
                        ok &= user::translate(us.root, *va).is_none();
                    }
                    let (outs1, _, res1) = swap::stats();
                    let (next1, free1) = vmm::swap_stats();
                    // 坐标面记账：派发上限增量 + 空闲池增量合计 = 淘汰页数
                    // （预留优先走 LIFO 复用，next 不必然增长——t27 遗留
                    // 空闲池非空，开发期实测教训）
                    ok &= outs1 - outs0 == 4
                        && res1 == 4
                        && (next1 - next0) as usize + free0 == free1 + 4;
                    ok &= frames.stats().held == held0 - 4; // two-shot ack 后回收
                                                            // (c) 换入重映射：**内核态触发**（TCG 双异常交付规避，
                                                            //     S31 记档：#PF 自 ring3 交付即推坏异常帧，CS=0x2b
                                                            //     家族指纹——换入链经切 CR3 + 虚拟读触发，与自检 20
                                                            //     同款手法；钩子/swap-in/重映射全链不变，仅 CPL 不同）。
                                                            //     ring3 侧仍全链参与：写阶段（页 0..3 直写）+ 退出码。
                    ostd::hw::lapic::timer_mask();
                    ostd::hw::phys::write_bytes(us.code_frame, &user::USER_SWAP_PROGRAM);
                    task::reset_user_evidence();
                    let _ = task::spawn_user_pinned("swap-user", user_noop, us.root, 0, 0);
                    while !task::all_workers_finished() {
                        task::yield_now();
                    }
                    let exit = task::user_exit_code();
                    ok &= exit == 44; // 写 0..3 + 校验 + EXIT（无缺页路径）
                                      // 内核态逐页读回被淘汰页：每次读 → #PF → swap-in → 重映射
                                      // → 指令重执行 → 魔数（内核预写）经盘往返复原
                    ostd::hw::control::write_cr3(us.root & !0xFFF);
                    let mut kern_seen = true;
                    for i in 4..8u64 {
                        let va = user::SWAP_DATA_VA + i * 0x1000;
                        kern_seen &= ostd::hw::phys::read_u64_virt(va) == user::SWAP_MAGIC_KERN | i;
                    }
                    ostd::hw::control::write_cr3(boot_cr3);
                    ostd::hw::lapic::timer_unmask();
                    ok &= kern_seen;
                    let (outs2, ins2, res2) = swap::stats();
                    let _ = writeln!(
                        log,
                        "reclaim: exit={exit} faults={} outs+={} ins+={} res={res2}",
                        vmm::swap_faults(),
                        outs2 - outs1,
                        ins2 - ins0
                    );
                    ok &= vmm::swap_faults() == 4; // 四页各一次换入重映射
                    ok &= ins2 - ins0 == 4 && res2 == 0; // 驻留清位
                                                         // (d) 收尾：坐标归还 + 帧账目不变式（未淘汰原帧归还；
                                                         //     换入新帧 4 张随废弃根留作遗迹，同自检 9 惯例）
                    vmm::release_swapped(us.root);
                    ok &= vmm::swapped_len() == 0;
                    let s = frames.stats();
                    ok &= s.allocs - s.deallocs == s.held;
                    for f in &data[..4] {
                        frames.dealloc(*f);
                    }
                } else {
                    let _ = writeln!(log, "reclaim: attach data pages failed");
                    ok = false;
                }
            }
            Err(e) => {
                let _ = writeln!(log, "reclaim: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t29, "swap-reclaim-full-chain");

    // 30) 优先级调度面 + 定向门铃（M8-C：四级就绪队列 + 高优先抢前 +
    //     SYS_SET_PRIO/GET_PRIO + fn(usize) 门铃泛化）。
    //     协议：(a) 双忙任务（低优先级、钉扎双核）饱和双核 → 派生 HIGH
    //     自由任务 → 定时器钩子「高优先抢前」必在量子内让渡一核 → HIGH
    //     完成（抢占切换计数 + 定向门铃送达取证）；(b) ring3 面：
    //     GET_PRIO=1（NORMAL 默认）→ SET_PRIO(0) 生效回读 → EXIT(49)。
    let t30 = {
        static BUSY_STOP: AtomicBool = AtomicBool::new(false);
        static BUSY_SEEN: AtomicU64 = AtomicU64::new(0);
        static HIGH_STAMP: AtomicU64 = AtomicU64::new(0);
        static HIGH_DONE: AtomicBool = AtomicBool::new(false);
        fn busy_low_body() {
            BUSY_SEEN.fetch_add(1, Ordering::Relaxed);
            while !BUSY_STOP.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
        }
        fn high_body() {
            HIGH_STAMP.store(u64::from(ostd::hw::lapic::id()), Ordering::Release);
            HIGH_DONE.store(true, Ordering::Release);
        }
        let mut ok = true;
        task::set_preempt_enabled(true);
        let (pre, hits0) = (task::preempt_stats().0, task::resched_hits());
        let _ = task::spawn_pinned_prio("busy-low-0", busy_low_body, 2, 0);
        let _ = task::spawn_pinned_prio("busy-low-1", busy_low_body, 2, 1);
        // 双核饱和证据：两忙任务均在各自核上开跑
        let deadline = ostd::time::now() + 100;
        while ostd::time::now() < deadline && BUSY_SEEN.load(Ordering::Acquire) < 2 {
            core::hint::spin_loop();
        }
        ok &= BUSY_SEEN.load(Ordering::Acquire) == 2;
        // HIGH 自由任务：抢占面必从某忙核抢出（timer_hook 抢前规则）
        let _ = task::spawn_prio("high-prio", high_body, 0);
        let deadline = ostd::time::now() + 200;
        while ostd::time::now() < deadline && !HIGH_DONE.load(Ordering::Acquire) {
            task::yield_now();
        }
        ok &= HIGH_DONE.load(Ordering::Acquire);
        BUSY_STOP.store(true, Ordering::Release);
        let deadline = ostd::time::now() + 200;
        while ostd::time::now() < deadline && !task::all_workers_finished() {
            task::yield_now();
        }
        ok &= task::all_workers_finished();
        let cur = task::preempt_stats().0;
        let hits1 = task::resched_hits();
        let stamp = HIGH_STAMP.load(Ordering::Acquire);
        let _ = writeln!(
            log,
            "prio: high-cpu={stamp} preempt+={} resched+={}",
            cur - pre,
            hits1 - hits0
        );
        ok &= cur > pre; // 高优先抢前真实发生（抢占切换计数增长）
        ok &= hits1 > hits0; // 定向门铃送达（RESCHED 证据）
                             // (b) ring3 优先级面：GET=NORMAL → SET(0) 生效回读 → EXIT(49)
        task::reset_user_evidence();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_PRIO_PROGRAM);
                let _ = task::spawn_user_pinned("prio-user", user_noop, us.root, 0, 0);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let exit = task::user_exit_code();
                let (set_to, get_back) = task::prio_stamps();
                let _ = writeln!(log, "prio: exit={exit} set={set_to} get={get_back}");
                ok &= exit == 49;
                ok &= set_to == 0 && get_back == 1; // GET=默认 NORMAL，SET(0) 生效
            }
            Err(e) => {
                let _ = writeln!(log, "prio: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t30, "priority-sched-face");

    // 31) 优先级老化防护（M9-C：base/effective 分离 + 等待计账逐级提升 +
    //     回队衰减）。饥饿场景构造：同核（CPU1）两枚 0 级忙任务 + 一枚
    //     3 级忙任务——量子到期轮转永远在 0 级队列内循环（M8-C 已知
    //     限制：饱和高优先负载饿死低优先），老化开启后低优先任务至多
    //     3×AGE_TICKS tick 爬升至 0 级进入轮转。取证链：LOW 推进计数 > 0
    //     （饥饿解除）+ 老化提升计数增长（机制真实介入）+ 双 HIGH 存活。
    let t31 = {
        static AG_STOP: AtomicBool = AtomicBool::new(false);
        static AG_SEEN: AtomicU64 = AtomicU64::new(0);
        static AG_LOW: AtomicU64 = AtomicU64::new(0);
        static AG_HI_A: AtomicU64 = AtomicU64::new(0);
        static AG_HI_B: AtomicU64 = AtomicU64::new(0);
        fn ag_low_body() {
            AG_SEEN.fetch_add(1, Ordering::AcqRel);
            while !AG_STOP.load(Ordering::Acquire) {
                AG_LOW.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
            }
        }
        fn ag_high_a_body() {
            AG_SEEN.fetch_add(1, Ordering::AcqRel);
            while !AG_STOP.load(Ordering::Acquire) {
                AG_HI_A.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
            }
        }
        fn ag_high_b_body() {
            AG_SEEN.fetch_add(1, Ordering::AcqRel);
            while !AG_STOP.load(Ordering::Acquire) {
                AG_HI_B.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
            }
        }
        let mut ok = true;
        task::set_preempt_enabled(true);
        let boosts0 = task::aging_boosts();
        // 饱和构造：两枚 0 级 + 一枚 3 级，全部钉扎 CPU1
        let _ = task::spawn_pinned_prio("ag-high-a", ag_high_a_body, 0, 1);
        let _ = task::spawn_pinned_prio("ag-high-b", ag_high_b_body, 0, 1);
        let _ = task::spawn_pinned_prio("ag-low", ag_low_body, 3, 1);
        // 双 HIGH 已在 CPU1 交替运行（饱和态就位）
        let deadline = ostd::time::now() + 100;
        while ostd::time::now() < deadline && AG_SEEN.load(Ordering::Acquire) < 2 {
            core::hint::spin_loop();
        }
        ok &= AG_SEEN.load(Ordering::Acquire) == 2;
        // 老化收敛窗口：至多 3×AGE_TICKS 爬升 + 轮转等待（预算 300 tick，
        // 正常 ~30 tick 内 LOW 首次推进；无老化时该窗口必然超时 → FAIL）
        let deadline = ostd::time::now() + 300;
        while ostd::time::now() < deadline && AG_LOW.load(Ordering::Relaxed) == 0 {
            core::hint::spin_loop();
        }
        AG_STOP.store(true, Ordering::Release);
        let deadline = ostd::time::now() + 200;
        while ostd::time::now() < deadline && !task::all_workers_finished() {
            task::yield_now();
        }
        ok &= task::all_workers_finished();
        let low = AG_LOW.load(Ordering::Acquire);
        let hi_a = AG_HI_A.load(Ordering::Acquire);
        let hi_b = AG_HI_B.load(Ordering::Acquire);
        let boosts1 = task::aging_boosts();
        let _ = writeln!(
            log,
            "aging: low={low} hi=({hi_a},{hi_b}) boosts+={} done={}",
            boosts1 - boosts0,
            task::all_workers_finished()
        );
        ok &= low > 0; // 饥饿解除：低优先任务真实获得执行
        ok &= boosts1 > boosts0; // 老化机制真实介入（提升计数增长）
        ok &= hi_a > 0 && hi_b > 0; // 高优先负载未因老化被清空
        ok
    };
    report(&mut log, t31, "priority-aging-antistarve");

    // 32) 进程模型：跨任务能力授予 + 句柄生命周期（M9-A：SYS_CAP_GRANT/
    //     REVOKE/GET_PID，abi v0.3）。
    //     协议：内核安装授予测试对象 R|W 至父任务 A 主身份句柄 → A（ring3）
    //     三负探针（NULL 句柄 → ERR_HANDLE / 非子任务 → ERR_TARGET / 提权
    //     → ERR_DERIVE）→ 正路径授予（READ 收窄副本装入子任务 B 句柄表）；
    //     B（cap_slot=0 纯被授予型）轮询 REVOKE(handle=1) 直至成功——句柄
    //     真实到达且可撤销的 ring3 侧证据。取证链：双退出码 53/54 + GRANT
    //     戳（成功 + 新句柄 = 1：B 表首空位）+ REVOKE 戳 0 + 终结清算后
    //     能力表占用回归基线（句柄生命周期闭环）。
    let t32 = {
        let mut ok = true;
        let used0 = caps::table().lock().used();
        // 授予测试对象父能力 R|W → 装入首个空闲槽（授予方主身份句柄源）
        let slot_a = {
            let mut table = caps::table().lock();
            let free = (0..vanguard::CAPACITY)
                .find(|i| table.get(*i).is_err())
                .ok_or(())
                .ok();
            free.and_then(|s| {
                table
                    .install(
                        s,
                        vanguard::Capability::new(
                            user::GRANT_OBJECT,
                            vanguard::Right::READ.bits() | vanguard::Right::WRITE.bits(),
                        ),
                    )
                    .is_ok()
                    .then_some(s)
            })
        };
        if let Some(slot_a) = slot_a {
            match (
                user::build_user_space(&mut || frames.alloc()),
                user::build_user_space(&mut || frames.alloc()),
            ) {
                (Ok(usa), Ok(usb)) => {
                    ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_CAP_GRANT_PROGRAM);
                    ostd::hw::phys::write_bytes(usb.code_frame, &user::USER_CAP_RECV_PROGRAM);
                    task::reset_user_evidence();
                    // 派发顺序：A 钉扎 CPU1（kick 后 idle 无竞争拾取，先于 B
                    // 首次派发完成探针全链 + 授予）→ B 钉扎 CPU0 与 main 共享；
                    // A 的 pid 数据槽 spawn 后写入（A 侧轮询等待，无顺序假设）
                    let a_id =
                        task::spawn_user_pinned("cap-granter", user_noop, usa.root, slot_a, 1);
                    let b_id = task::spawn_user_child_pinned(
                        "cap-grantee",
                        user_noop,
                        usb.root,
                        0,
                        0,
                        a_id,
                    );
                    let pid_off = user::GRANT_PID_VA - user::USER_STACK_VIRT;
                    ostd::hw::phys::write_u64(usa.stack_frame + pid_off, b_id as u64);
                    while !task::all_workers_finished() {
                        task::yield_now();
                    }
                    let (e0, e1) = task::user_exit_codes();
                    let (gres, ghandle, rres) = procs::stamps();
                    let _ = writeln!(
                        log,
                        "cap-grant: exit=({e0},{e1}) grant-res={gres:#x} new-handle={ghandle} revoke-res={rres} used={} (base {used0})",
                        caps::table().lock().used()
                    );
                    ok &= e0 == 54 && e1 == 53; // B（CPU0）撤销成功 / A（CPU1）全链成功
                    ok &= gres == 0 && ghandle == 1; // GRANT 成功；B 表首空位 = 1
                    ok &= rres == 0; // B 的 REVOKE(handle=1) 成功返回
                                     // 终结清算闭环：派生槽（B 撤销）+ 主身份槽（A 终结清算）
                                     // 全部归还 → 能力表占用回归基线
                    ok &= caps::table().lock().used() == used0;
                }
                _ => {
                    let _ = writeln!(log, "cap-grant: user space build failed");
                    ok = false;
                }
            }
        } else {
            let _ = writeln!(log, "cap-grant: object install failed");
            ok = false;
        }
        ok
    };
    report(&mut log, t32, "cap-grant-handle-lifecycle");

    // 33) 换页异步化（M9-B：swapd 分页任务 + 请求队列 + #PF 零 I/O 快路径）。
    //     协议：(a) A 位二次机会确定性选页（置页 0..4 A 位 → 扫描必选 4..8）
    //     → swapd（0 级任务）异步执行 evict_one 全链（I/O 出 ISR）；(b) 异步
    //     预取 ×4（swapd 换入暂存，帧就位）；(c) 内核态读回 → #PF → 快路径
    //     零 I/O 重映射 → 魔数复原，FAST_FAULTS == 4（M9-B 核心证据：故障
    //     路径零盘访问）；(d) 换入计数增量 = 4 全部来自 swapd（同步回退路径
    //     0 次）+ 坐标面槽位全归还；(e) 停机旗标 → swapd 终结 + 帧账目不变式。
    let t33 = {
        let mut ok = true;
        let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                if let Some(data) = user::attach_data_pages(us.root, &mut || frames.alloc()) {
                    // 8 页全写内核魔数（经盘往返后复原取证）
                    for (i, f) in data.iter().enumerate() {
                        ostd::hw::phys::write_u64(*f, user::SWAP_MAGIC_KERN | i as u64);
                    }
                    // (a) 淘汰确定性：手工置页 0..4 A 位 → 扫描必选 4..8
                    for i in 0..4u64 {
                        let va = user::SWAP_DATA_VA + i * 0x1000;
                        let mut w = Walker {
                            mem: &mut IdentityAccess,
                            alloc_table: no_alloc_table,
                        };
                        ok &= w.set_leaf_bits(us.root, va, Entry::ACCESSED, 0).is_ok();
                    }
                    let victims =
                        vmm::reclaim_scan(us.root, user::SWAP_DATA_VA, user::SWAP_DATA_PAGES, 4);
                    let want: Vec<u64> =
                        (4..8u64).map(|i| user::SWAP_DATA_VA + i * 0x1000).collect();
                    ok &= victims == want;
                    // swapd 上线（0 级：M8-C 优先级面服务 M9-B 分页延迟）
                    let _ = task::spawn_prio("swapd", vmm::pager_body, 0);
                    let (next0, free0) = vmm::swap_stats();
                    let (outs0, ins0, _) = swap::stats();
                    // 异步淘汰 ×4（I/O 在 swapd 任务上下文执行）
                    for va in &victims {
                        vmm::request_evict(us.root, *va);
                    }
                    let deadline = ostd::time::now() + 300;
                    while ostd::time::now() < deadline && vmm::swapped_len() < 4 {
                        task::yield_now();
                    }
                    ok &= vmm::swapped_len() == 4;
                    // (b) 异步预取 ×4（换入暂存，帧就位；排水预算 600 tick——
                    // 慢 TCG 下 ATA I/O 放大数十倍，300 可能不足）
                    for va in &victims {
                        vmm::request_prefetch(us.root, *va);
                    }
                    let deadline = ostd::time::now() + 600;
                    while ostd::time::now() < deadline && vmm::prefetched_len() < 4 {
                        task::yield_now();
                    }
                    ok &= vmm::prefetched_len() == 4;
                    // (c) 内核态读回：#PF → 快路径零 I/O 重映射 → 魔数复原。
                    // 守卫：仅当全部暂存就绪才读回（部分就绪时未暂存页的缺页
                    // 走致命路径——跳过读回，让 FAIL 落在本自检而非内核级联）
                    if vmm::prefetched_len() == 4 {
                        ostd::hw::control::write_cr3(us.root & !0xFFF);
                        let mut kern_seen = true;
                        for i in 4..8u64 {
                            let va = user::SWAP_DATA_VA + i * 0x1000;
                            kern_seen &=
                                ostd::hw::phys::read_u64_virt(va) == user::SWAP_MAGIC_KERN | i;
                        }
                        ostd::hw::control::write_cr3(boot_cr3);
                        ok &= kern_seen;
                        ok &= vmm::fast_faults() == 4; // 四页全部走零 I/O 快路径
                    } else {
                        ok = false;
                    }
                    // (d) I/O 统计：换入增量 = 4 全部来自 swapd（同步路径 0 次）
                    let (outs1, ins1, res1) = swap::stats();
                    ok &= outs1 - outs0 == 4 && ins1 - ins0 == 4 && res1 == 0;
                    // 坐标面闭环：4 槽位经快路径消费全部归还（空闲池增量 =
                    // 派发上限增量，零泄漏）
                    let (next1, free1) = vmm::swap_stats();
                    ok &= (next1 - next0) as usize == free1 - free0;
                    let _ = writeln!(
                        log,
                        "async-paging: served={} fast={} outs+={} ins+={} slots=({next0},{free0})→({next1},{free1})",
                        vmm::pager_served(),
                        vmm::fast_faults(),
                        outs1 - outs0,
                        ins1 - ins0
                    );
                    // (e) 收尾：登记清空 + swapd 停机终结 + 帧账目不变式
                    vmm::release_prefetched(us.root);
                    vmm::release_swapped(us.root);
                    ok &= vmm::swapped_len() == 0 && vmm::prefetched_len() == 0;
                    vmm::pager_shutdown();
                    let deadline = ostd::time::now() + 200;
                    while ostd::time::now() < deadline && !task::all_workers_finished() {
                        task::yield_now();
                    }
                    ok &= task::all_workers_finished();
                    ok &= vmm::pager_served() >= 8; // 4 淘汰 + 4 预取
                    let s = frames.stats();
                    ok &= s.allocs - s.deallocs == s.held;
                    for f in &data[..4] {
                        frames.dealloc(*f);
                    }
                } else {
                    let _ = writeln!(log, "async-paging: attach data pages failed");
                    ok = false;
                }
            }
            Err(e) => {
                let _ = writeln!(log, "async-paging: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t33, "async-paging-fastpath");

    let _ = writeln!(log, "----");
    interrupts::disable();
    if pass == SELFTEST_TOTAL {
        let _ = writeln!(log, "LUMINA-SELFTEST-PASS {pass}/{SELFTEST_TOTAL}");
        let _ = writeln!(log, "LUMINA-BOOT-OK");
        kernel_exit(EXIT_SUCCESS);
    } else {
        let _ = writeln!(log, "LUMINA-SELFTEST-FAIL {pass}/{SELFTEST_TOTAL}");
        kernel_exit(EXIT_FAILURE);
    }
}

/// 用户任务占位入口（真实进入经 trampoline_user → 桥函数）。
fn user_noop() {}

/// 基准路径禁用分配（翻译不应再分配中间表）。
fn no_alloc_table() -> Option<u64> {
    None
}

/// isa-debug-exit 成功码：QEMU 退出码 = (值 << 1) | 1 = 33。
pub const EXIT_SUCCESS: u32 = 0x10;
/// isa-debug-exit 失败码：QEMU 退出码 = (值 << 1) | 1 = 193。
pub const EXIT_FAILURE: u32 = 0x60;

/// 致命异常出口（interrupts.rs 故障钩子调用）：以失败码停机。
pub(crate) fn fail_exit(_vector: u64) -> ! {
    kernel_exit(EXIT_FAILURE)
}

/// 经 isa-debug-exit（端口 0xF4）请求 QEMU 退出；裸机上写调试口后停机。
fn kernel_exit(code: u32) -> ! {
    ostd::hw::ports::write_u32(0xF4, code);
    loop {
        core::hint::spin_loop();
    }
}

/// 内核 panic 处理：串口 + VGA 落盘诊断后以失败码退出。
/// 不得分配（分配器可能尚未初始化或已损坏）。
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut serial = console::SerialPort::com1();
    serial.init();
    let mut vga = console::VgaConsole::new();
    let _ = writeln!(serial, "\nKERNEL-PANIC: {info}");
    let _ = writeln!(vga, "\nKERNEL-PANIC: {info}");
    let _ = writeln!(serial, "LUMINA-PANIC-EXIT");
    kernel_exit(EXIT_FAILURE);
}
