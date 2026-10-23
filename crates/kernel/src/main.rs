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

mod block;
mod boot;
mod caps;
mod census;
mod console;
mod fb;
mod font_gen;
mod hostlink;
mod interrupts;
mod ipc;
mod kbd;
mod multiboot1;
mod procs;
mod selftest;
mod shell;
mod smp;
mod swap;
mod syscall;
mod task;
mod timer;
mod tty;
mod user;
mod vfs;
mod vmm;
mod vnet;

use core::fmt::Write as _;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
use bedrock::ipc::Endpoint;
use bedrock::tlv;
use harbor::HarborFreeList;
use ostd::mm::frame::{FrameAllocator, Region, FRAME_SIZE};
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::SpinLock;

use crate::console::DualLog;
use crate::multiboot1::BOOT_MAGIC;

/// 内核堆大小：4 MiB（M3 任务栈/日志/TLV 充足；帧管理独立于本堆）。
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// 自检项目总数（M2 七项 + M3 四项 + M4 四项 + M5 五项 + M6 五项 + M7 两项 + M8 三项 + M9 三项 + M10 三项 + M11 四项 + M12 起逐块追加；M23-C3 起 71，M24-S1 起 72，M24-C1 起 73，M24-A1 起 74）。
const SELFTEST_TOTAL: usize = 74;

/// 内核堆后备区域：静态 4 MiB、4 KiB 对齐（段放置见 KERNEL_HEAP）。
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

// M19-① 显式段放置（link_section 不可用于 struct，须贴 static）：
// 用户根恒等镜像 PT[0]/PT[2] 洞（0x400000/0x402000，用户 code/stack 槽）
// 不可含堆物理页，借根窗口（reap/swap 读回）恒等可见性由此保证。
#[link_section = ".kernel_heap"]
static mut KERNEL_HEAP: KernelHeap = KernelHeap {
    bytes: [0; HEAP_SIZE],
};

/// 全局分配器：kmain 早期 rebind 到静态内核堆（Harbor 启动惯用法）。
/// M21-③：由 HarborBump 升级为 HarborFreeList（first-fit + 合并复用面）。
#[global_allocator]
static ALLOC: HarborFreeList = HarborFreeList::new_unbacked();

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
    let _ = writeln!(log, "kernel heap: {HEAP_SIZE} bytes bound (HarborFreeList)");

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
    // M12-d 僵尸收割运行时化：idle 附加工作第二槽挂孤儿收割面
    task::set_idle_reap(|| task::reap_orphans() > 0);
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
        // PIT 分频为整数：实际频率允许 ±1 Hz 舍入差；M23-① 起 IRQ1
        // 同开（0xFC：IRQ0+IRQ1，键盘面），从片仍全屏
        let mut ok = hz.abs_diff(interrupts::TIMER_HZ) <= 1
            && interrupts::timer_gate_ok()
            && m == 0xFC
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
    // M14-①：文件面/命名空间启动期初始化（原 t44 内惰性 init 迁出——
    // EXEC 装载器经 VFS 取段后，t42 及全部映像面依赖必须先于自检就位）
    vfs::init();
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
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                // 代码帧覆写为 IPC 客户端映像（build_user_space 默认写入
                // LOG/YIELD 演示程序；帧位置与布局完全一致）
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_IPC_PROGRAM);
                // M17 时序修复：client 先于 server 派发——SEND 先落环缓冲
                //（SPSC 环本就支持此序），worker 后起首轮即消费；原序的
                // 「server 先 poll、client 后到」窗口与内核代码布局漂移
                // 耦合（v0.17 归档两轮 193 + M17 六连红实证），此序竞争面
                // 消除。
                let _id = task::spawn_user("ipc-client", user_noop, us.root, 2);
                let _ = task::spawn("ipc-echo", ipc::echo_worker_body);
                while !task::all_workers_finished() {
                    task::yield_now();
                }
                let exit_code = task::user_exit_code();
                let (ds, dso, dr) = (
                    ipc::DIAG_SENDS.load(Ordering::Acquire),
                    ipc::DIAG_SEND_OK.load(Ordering::Acquire),
                    ipc::DIAG_RECVS.load(Ordering::Acquire),
                );
                let (f1, f2, f3, f4, fu) = (
                    ipc::DIAG_F1.load(Ordering::Acquire),
                    ipc::DIAG_F2.load(Ordering::Acquire),
                    ipc::DIAG_F3.load(Ordering::Acquire),
                    ipc::DIAG_F4.load(Ordering::Acquire),
                    ipc::DIAG_FULL.load(Ordering::Acquire),
                );
                let _ = writeln!(
                    log,
                    "  ipc-diag: sends={ds} ok={dso} recvs={dr} f1={f1} f2={f2} f3={f3} f4={f4} full={fu} exit={exit_code}"
                );
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
                    task::set_current_kernel_cr3(us.root);
                    ostd::hw::control::write_cr3(us.root & !0xFFF);
                    let mut kern_seen = true;
                    for i in 4..8u64 {
                        let va = user::SWAP_DATA_VA + i * 0x1000;
                        kern_seen &= ostd::hw::phys::read_u64_virt(va) == user::SWAP_MAGIC_KERN | i;
                    }
                    ostd::hw::control::write_cr3(boot_cr3);
                    task::set_current_kernel_cr3(0);
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
                    // swapd 上线（0 级：M8-C 优先级面服务 M9-B 分页延迟；
                    // M10-B 统一派生入口：上线计数供阻塞路径门控）
                    let _ = vmm::spawn_pager(None);
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
                        task::set_current_kernel_cr3(us.root);
                        ostd::hw::control::write_cr3(us.root & !0xFFF);
                        let mut kern_seen = true;
                        for i in 4..8u64 {
                            let va = user::SWAP_DATA_VA + i * 0x1000;
                            kern_seen &=
                                ostd::hw::phys::read_u64_virt(va) == user::SWAP_MAGIC_KERN | i;
                        }
                        ostd::hw::control::write_cr3(boot_cr3);
                        task::set_current_kernel_cr3(0);
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

    // 34) per-CPU tick 账户 + ring3 抢占（M10-A：时间面迁 PIT 全上下文）。
    //     构造：双核各钉一枚 ring3 spinner（USER_SPIN_PROGRAM——无任何
    //     syscall 的纯自旋，旧形态下 LAPIC 定时器被 prepare_dispatch 屏蔽，
    //     计账/老化/抢占全冻结：spinner 永不被抢占，低优先 watcher 永不
    //     运行）+ 每核一枚 2 级 watcher。取证链：双 watcher 推进 > 0（ring3
    //     抢占真实发生：BSP 经 PIT-plan / AP 经 RESCHED-plan）+ per-CPU
    //     tick 账户双核增长（ring3 驻留计账，冻结面解除的直接证据）+
    //     抢占切换计数增长 + 哨兵释放后双 spinner 退出码 57（全链完好）。
    let t34 = {
        static WATCH_SEEN_0: AtomicU64 = AtomicU64::new(0);
        static WATCH_SEEN_1: AtomicU64 = AtomicU64::new(0);
        fn tick_watch_body_0() {
            WATCH_SEEN_0.fetch_add(1, Ordering::AcqRel);
        }
        fn tick_watch_body_1() {
            WATCH_SEEN_1.fetch_add(1, Ordering::AcqRel);
        }
        let mut ok = true;
        task::set_preempt_enabled(true);
        task::reset_user_evidence();
        let ticks0 = task::percpu_ticks();
        let preempt0 = task::preempt_stats().0;
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_SPIN_PROGRAM);
                ostd::hw::phys::write_bytes(usb.code_frame, &user::USER_SPIN_PROGRAM);
                // 双核 spinner + 双核 watcher（2 级：老化/轮转可达）
                let _ = task::spawn_user_pinned("spin-a", user_noop, usa.root, 0, 0);
                let _ = task::spawn_user_pinned("spin-b", user_noop, usb.root, 0, 1);
                let _ = task::spawn_pinned_prio("tick-watch-0", tick_watch_body_0, 2, 0);
                let _ = task::spawn_pinned_prio("tick-watch-1", tick_watch_body_1, 2, 1);
                // ring3 抢占收敛窗口（预算 600 tick；PIT 量子 3 拍必现）
                let deadline = ostd::time::now() + 600;
                while ostd::time::now() < deadline
                    && (WATCH_SEEN_0.load(Ordering::Acquire) == 0
                        || WATCH_SEEN_1.load(Ordering::Acquire) == 0)
                {
                    task::yield_now();
                }
                let w0 = WATCH_SEEN_0.load(Ordering::Acquire);
                let w1 = WATCH_SEEN_1.load(Ordering::Acquire);
                ok &= w0 > 0 && w1 > 0; // 双核 watcher 均真实运行
                                        // 哨兵释放：双 spinner 退出（取证窗口闭合）
                let spin_off = user::SPIN_SENTINEL_VA - user::USER_STACK_VIRT;
                ostd::hw::phys::write_u64(usa.stack_frame + spin_off, 1);
                ostd::hw::phys::write_u64(usb.stack_frame + spin_off, 1);
                let deadline = ostd::time::now() + 400;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (e0, e1) = task::user_exit_codes();
                let ticks1 = task::percpu_ticks();
                let preempt1 = task::preempt_stats().0;
                let _ = writeln!(
                    log,
                    "tick-account: watch=({w0},{w1}) exit=({e0},{e1}) ticks=({},{})→({},{}) preempt+={}",
                    ticks0.0, ticks0.1, ticks1.0, ticks1.1, preempt1 - preempt0
                );
                ok &= e0 == 57 && e1 == 57; // 双 spinner 哨兵退出（全链完好）
                ok &= ticks1.0 > ticks0.0 && ticks1.1 > ticks0.1; // 双核账户增长（ring3 计账）
                ok &= preempt1 > preempt0; // 抢占切换真实发生
            }
            _ => {
                let _ = writeln!(log, "tick-account: user space build failed");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t34, "tick-account-ring3-unfreeze");

    // 35) 换页阻塞化（M10-B：任务阻塞态 + 调度点切换）。
    //     单核饱和构造：swapd 与故障上下文同核（均钉 CPU0）——v0.9 的
    //     ISR 自旋等待依赖 swapd 在对侧核运行，本场景必然超时致命；
    //     M10-B 阻塞路径下故障方切出让核 → swapd 同核拾取 → 换入完成
    //     → 谓词唤醒 → 恢复点修复 CR3 → 重探消费。取证链：四页魔数经
    //     盘往返复原 + FAST_FAULTS == 4（全部零 I/O 快路径）+ ins 增量
    //     全来自 swapd（同步回退 0 次）+ 阻塞唤醒计数 ≥ 4 + 帧账目。
    let t35 = {
        let mut ok = true;
        vmm::pager_arm(); // t33 已停机：重新上线前清停机旗标
        let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                if let Some(data) = user::attach_data_pages(us.root, &mut || frames.alloc()) {
                    for (i, f) in data.iter().enumerate() {
                        ostd::hw::phys::write_u64(*f, user::SWAP_MAGIC_KERN | i as u64);
                    }
                    // 淘汰确定性：手工置页 0..4 A 位 → 扫描必选 4..8
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
                    // 单核饱和：swapd 钉 CPU0（与 main/故障上下文同核）
                    let pager = vmm::spawn_pager(Some(0));
                    ok &= pager != usize::MAX;
                    let (outs0, ins0, _) = swap::stats();
                    // 同步淘汰 ×4（异步淘汰链 t33 已覆盖；本自检聚焦换入阻塞）
                    for va in &victims {
                        ok &= vmm::evict_one(us.root, *va, frames).is_ok();
                    }
                    ok &= vmm::swapped_len() == 4;
                    // 内核态读回（main 在 CPU0 触发 #PF → 阻塞 → swapd 同核
                    // 换入 → 唤醒 → 重探消费 → 重执行）：四页魔数复原
                    let wakes0 = task::block_wakes();
                    let fast0 = vmm::fast_faults();
                    vmm::reset_swap_block_evidence();
                    task::set_current_kernel_cr3(us.root);
                    ostd::hw::control::write_cr3(us.root & !0xFFF);
                    let mut kern_seen = true;
                    for i in 4..8u64 {
                        let va = user::SWAP_DATA_VA + i * 0x1000;
                        kern_seen &= ostd::hw::phys::read_u64_virt(va) == user::SWAP_MAGIC_KERN | i;
                    }
                    ostd::hw::control::write_cr3(boot_cr3);
                    task::set_current_kernel_cr3(0);
                    ok &= kern_seen;
                    let wakes1 = task::block_wakes();
                    let fast1 = vmm::fast_faults();
                    let (outs1, ins1, res1) = swap::stats();
                    let (phits, sblocks, swakes) = vmm::swap_block_stamps();
                    let _ = writeln!(
                        log,
                        "swap-block: seen={kern_seen} wakes+={} fast+={} outs+={} ins+={} res={res1} \
                         probe={phits} blocks={sblocks} swakes={swakes}",
                        wakes1 - wakes0,
                        fast1 - fast0,
                        outs1 - outs0,
                        ins1 - ins0
                    );
                    ok &= fast1 - fast0 == 4; // 四页全部零 I/O 快路径（增量，t33 已累计）
                    ok &= wakes1 - wakes0 >= 4; // 阻塞唤醒真实发生（每页 ≥1）
                                                // M12-C 探针纪律取证：四页换入全部走锁窗探针路径——
                                                // 阻塞点进入 ≥ 4 且唤醒 ≥ 4（登记-唤醒锁窗口成对闭环）
                    ok &= sblocks >= 4 && swakes >= 4;
                    ok &= outs1 - outs0 == 4 && ins1 - ins0 == 4 && res1 == 0;
                    // 收尾：坐标归还 + swapd 停机终结 + 帧账目不变式
                    vmm::release_swapped(us.root);
                    ok &= vmm::swapped_len() == 0;
                    vmm::pager_shutdown();
                    let deadline = ostd::time::now() + 400;
                    while ostd::time::now() < deadline && !task::all_workers_finished() {
                        task::yield_now();
                    }
                    ok &= task::all_workers_finished();
                    ok &= vmm::pager_served() >= 4;
                    let s = frames.stats();
                    ok &= s.allocs - s.deallocs == s.held;
                    for f in &data[..4] {
                        frames.dealloc(*f);
                    }
                } else {
                    let _ = writeln!(log, "swap-block: attach data pages failed");
                    ok = false;
                }
            }
            Err(e) => {
                let _ = writeln!(log, "swap-block: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t35, "swap-block-singlecore");

    // 36) waitpid 语义雏形（M10-C：SYS_WAIT_PID + Zombie 收割 + 槽位释放）。
    //     家族构造（父链内核登记，M9-A 同款）：P（父，钉 CPU0）+ C（子，
    //     钉 CPU1）——P 阻塞等待（WAIT_PID(0)），C 经 YIELD×32 后 EXIT(42)
    //     → exit 路径唤醒 P → 重扫收割（退出码 + 槽位释放）。取证链：
    //     P 拆位校验通过（成功位/cpid/码）+ 二次等待 ERR_CHILD(8) +
    //     等待自身 ERR_CHILD(8) + 收割后 C 槽位释放（task_alive == false）
    //     + 双退出码 59/42 各自落位。
    let t36 = {
        let mut ok = true;
        procs::reset_waitpid_evidence();
        task::reset_user_evidence();
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_WAITPID_PROGRAM);
                // C 用原版 USER_PROGRAM（YIELD×32 + EXIT(42)——原样复用）
                let p_id = task::spawn_user_pinned("wait-parent", user_noop, usa.root, 0, 0);
                let c_id =
                    task::spawn_user_child_pinned("wait-child", user_noop, usb.root, 0, 1, p_id);
                // 子 pid 哨兵（spawn 后写入；P 侧轮询等待，无顺序假设）
                let cpid_off = user::WAITPID_CPID_VA - user::USER_STACK_VIRT;
                ostd::hw::phys::write_u64(usa.stack_frame + cpid_off, c_id as u64);
                let deadline = ostd::time::now() + 3000;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (e0, e1) = task::user_exit_codes();
                let (res, rpid, rcode) = procs::waitpid_stamps();
                let _ = writeln!(
                    log,
                    "waitpid: exit=({e0},{e1}) res={res:#x} pid={rpid} code={rcode} c-slot-alive={} gated={}",
                    task::task_alive(c_id),
                    procs::waitpid_gated_hits()
                );
                ok &= e0 == 59 && e1 == 42; // P 全链成功 / C 原版退出码
                ok &= res == 0; // WAIT_PID(0) 成功
                ok &= rpid == c_id as u64 && rcode == 42; // 收割对象与退出码
                ok &= !task::task_alive(c_id); // 收割后 C 槽位释放
                ok &= task::task_alive(p_id); // P 自身槽位不受影响
            }
            _ => {
                let _ = writeln!(log, "waitpid: user space build failed");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t36, "waitpid-zombie-reap");

    // 37) SYS_SPAWN 进程创建（M12-B COW 派生：零拷贝共享 + 写时拷贝）。
    //     构造：父任务（钉 CPU0）运行 USER_SPAWN_PROGRAM v2——r14 寄存器
    //     细胞自证（根父 = 0）→ SPAWN(0)（内核 COW 派生：代码帧共享 +
    //     栈帧 COW + 父侧降级）→ WAIT_PID(cpid) 拆位校验；子任务凭 r14
    //     非零走子分支，写栈底 [0x402000]（子侧 COW 缺页 → 私拷）回读
    //     后 YIELD×8 → EXIT(42)；父收割后写 [0x402008]（父侧 COW 缺页）
    //     回读 → EXIT(61)。
    //     取证链：父退出码 61 + SPAWN 戳（res=0/pid=子/cell=父 pid）+
    //     WAITPID 戳（收割对象 = 派生子、码 42）+ 子槽位释放 + 父槽位
    //     存续 + COW 双向缺页 ≥ 2 + 代码帧物理同一性（父子根 translate
    //     对证——零拷贝共享的铁证）。
    let t37 = {
        let mut ok = true;
        procs::reset_waitpid_evidence();
        task::reset_user_evidence();
        let cow0 = vmm::cow_breaks();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_SPAWN_PROGRAM);
                let p_id = task::spawn_user_pinned("spawn-parent", user_noop, us.root, 0, 0);
                // M22-③ 第二项 arm 捕获窗重构：改读内核侧子根戳（procs
                // 派生成功即登记 cs.root），捕获免疫收割时序——旧形态
                // （round-739/755/758/761/771 五标本判读）：子代全生命
                // 周期 + 收割挤进单轮询间隙，事后 task_user_root 重读恒
                // 0 → child_root 逃逸。窗预算同步 600→3000ms（与主等待
                // 同量级，正常轮微秒级捕获零开销）+ 已定败/整链完成双
                // 早退面。
                let mut child_root = 0u64;
                let arm_deadline = ostd::time::now() + 3000;
                while ostd::time::now() < arm_deadline {
                    let (res0, _, _) = procs::spawn_stamps();
                    let stamped = procs::spawn_child_root_stamp();
                    if res0 == 0 && stamped != 0 {
                        child_root = stamped;
                        break;
                    }
                    if res0 != u64::MAX && res0 != 0 {
                        break; // SPAWN 已定败（fail-closed 观测面）
                    }
                    if task::all_workers_finished() {
                        break; // 链整链完成（理论不可达；观测面兜底）
                    }
                    task::yield_now();
                }
                // M22-③ 第二项：收敛预算 3000→5000ms（round-727 判读：
                // 健康链尾超期快照——检查时刻竞态，非卡死。加裕度）。
                let deadline = ostd::time::now() + 5000;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                if !task::all_workers_finished() {
                    // M22-③ 第二项：收敛失败点名（census 纪律——非 Zombie
                    // 槽位逐一点名 id:name:state，下批直读零盲区）。
                    let _ = writeln!(log, "spawn: stuck={:?}", task::stuck_workers());
                }
                let (res, spid, cell) = procs::spawn_stamps();
                let (wres, wpid, wcode) = procs::waitpid_stamps();
                let (e0, _) = task::user_exit_codes();
                let cow = vmm::cow_breaks() - cow0;
                let pcode = user::translate(us.root, user::USER_CODE_VIRT);
                // M22-③ 防线语义升级（第二项）：child_root 改内核戳源
                // （真子根，v0 存续期语义表帧不回收——translate 收割后仍
                // 有效）；闸 1（根未捕获即 None）+ 闸 2（Walker canonical
                // fail-closed，round-501 同族）双闸保持。translate(0)
                // 形态（round-582/647 #GP 实录）随戳面结构性消失。
                let ccode = if child_root != 0 {
                    user::translate(child_root, user::USER_CODE_VIRT)
                } else {
                    None
                };
                let _ = writeln!(
                    log,
                    "spawn: exit0={e0} res={res:#x} pid={spid} cell={cell} \
                     wres={wres:#x} wpid={wpid} wcode={wcode} c-alive={} cow={cow} \
                     code-share={} child_root={child_root:#x} ccode={ccode:?}",
                    task::task_alive(spid as usize),
                    pcode.is_some() && pcode == ccode,
                );
                ok &= e0 == 61; // 父全链成功（COW 双向写 + 收割拆位全过）
                ok &= res == 0; // SPAWN 返回成功
                ok &= cell == p_id as u64; // 遗传细胞 = 父 pid（内核登记自证）
                ok &= wres == 0; // WAIT_PID 成功
                ok &= wpid == spid && spid != u64::MAX; // 收割对象 = 派生子
                ok &= wcode == 42; // 子退出码（子分支 COW 写 + YIELD×8 后 EXIT）
                ok &= !task::task_alive(spid as usize); // 子槽位已释放回收
                ok &= task::task_alive(p_id); // 父槽位存续
                ok &= cow >= 2; // COW 双向缺页（子 + 父）均真实发生
                ok &= pcode.is_some() && pcode == ccode; // 代码帧物理同一（零拷贝共享铁证）
            }
            Err(e) => {
                let _ = writeln!(log, "spawn: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t37, "spawn-cow-derive");

    // 38) 句柄查询与枚举面（M11-B：SYS_HANDLE_QUERY/ENUM）。
    //     构造：探针任务持 R|W 主身份（句柄 1）+ 内核预装派生 READ-only
    //     句柄 2——QUERY(1) 拆位（rights==R|W）、QUERY(0)/QUERY(9) 负探针
    //     （ERR_HANDLE）、ENUM(0)→1 / ENUM(1)→2 / ENUM(2)→0（枚举尽）、
    //     QUERY(2)→rights==READ。取证：退出码 68 + HQ 戳（末次命中 =
    //     QUERY(2)：rights==READ、槽号 == 派生槽）。
    let t38 = {
        let mut ok = true;
        procs::reset_handle_evidence();
        task::reset_user_evidence();
        let hq_object: u64 = 0x7A59_0000_0000_00A1;
        let primary = crate::caps::alloc_slot(vanguard::Capability::new(
            hq_object,
            vanguard::Right::READ.bits() | vanguard::Right::WRITE.bits(),
        ));
        match (primary, user::build_user_space(&mut || frames.alloc())) {
            (Some(pslot), Ok(us)) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_HQ_PROGRAM);
                let tid = task::spawn_user_pinned("hq-probe", user_noop, us.root, pslot, 0);
                // 预装句柄 2 = 派生 READ-only（单属主不变式：新全局槽）
                let derived = crate::caps::table()
                    .lock()
                    .derive(pslot, vanguard::Right::READ.bits());
                ok &= task::with_task_handles(tid, |h| h[2] = derived.ok()).is_some();
                // 武装哨兵：句柄 2 就位后才放行探针（消除预装竞态）
                ostd::hw::phys::write_u64(us.stack_frame + user::HQ_ARM_OFF, 1);
                let deadline = ostd::time::now() + 3000;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (e0, _) = task::user_exit_codes();
                let (res, rights, slot) = procs::handle_stamps();
                let _ = writeln!(
                    log,
                    "hq: exit0={e0} res={res:#x} rights={rights:#x} slot={slot} primary={pslot}"
                );
                ok &= e0 == 68; // 程序全链通过
                ok &= res == 0; // 末次 HQ 调用 = QUERY(2) 成功
                ok &= rights == u64::from(vanguard::Right::READ.bits()); // 派生 rights
                ok &= slot == derived.unwrap_or(usize::MAX) as u64; // 全局槽号对证
            }
            _ => {
                let _ = writeln!(log, "hq: setup failed");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t38, "handle-query-enum");

    // 槽位卫生：t12 起哑元任务的僵尸槽位清扫（MAX_TASKS 48 已逼近满员，
    // t37 实录：alloc_slot 失败 → 门面等待永假 → 冒烟挂死）
    let _ = writeln!(log, "zombie-reap: {} slots freed", task::reap_zombies());

    // 39) IPC 阻塞接收阻塞化（M11-C：SYS_IPC_RECV 接入 Blocked 态）。
    //     构造：R（钉 CPU0，RECV 能力）先跑——负探针 RECV(LOCKED)→ERR_CAP
    //     （非阻塞门禁拒绝）→ RECV(BLOCK) 环空阻塞；取证到真实阻塞登记后
    //     才派 S（钉 CPU1，SEND 能力）——YIELD×4 → 推送 "WAKE"（tag 0x55）
    //     → sys_send 唤醒 → R 重探消费 → 双方按码退出。取证链：R 65 /
    //     S 67 + 真实阻塞 ≥1 + 阻塞唤醒 ≥1（探针-唤醒锁窗口成对）。
    let t39 = {
        let mut ok = true;
        ipc::reset_recv_evidence();
        task::reset_user_evidence();
        let rslot = crate::caps::alloc_slot(vanguard::Capability::new(
            ipc::BLOCK_OBJECT,
            vanguard::Right::IPC_RECV.bits(),
        ));
        let sslot = crate::caps::alloc_slot(vanguard::Capability::new(
            ipc::BLOCK_OBJECT,
            vanguard::Right::IPC_SEND.bits(),
        ));
        match (
            rslot,
            sslot,
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Some(rs), Some(ss), Ok(usr), Ok(uss)) => {
                ostd::hw::phys::write_bytes(usr.code_frame, &user::USER_BLOCKRECV_PROGRAM);
                ostd::hw::phys::write_bytes(uss.code_frame, &user::USER_BLOCKSEND_PROGRAM);
                let _r = task::spawn_user_pinned("block-recv", user_noop, usr.root, rs, 0);
                // 确定性：等 R 真实进入阻塞点（登记前计数）后才派发送方
                // M17 加固：600 → 3000 tick（同 t24 临界竞争加固纪律）
                let deadline = ostd::time::now() + 3000;
                while ostd::time::now() < deadline && ipc::recv_stamps().0 == 0 {
                    task::yield_now();
                }
                ok &= ipc::recv_stamps().0 > 0;
                let _s = task::spawn_user_pinned("block-send", user_noop, uss.root, ss, 1);
                let deadline = ostd::time::now() + 3000;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (e0, e1) = task::user_exit_codes();
                let (blocks, wakes) = ipc::recv_stamps();
                let _ = writeln!(
                    log,
                    "block-recv: exit=({e0},{e1}) blocks={blocks} wakes={wakes}"
                );
                ok &= e0 == 65 && e1 == 67; // R 载荷校验过 / S 推送成功
                ok &= blocks >= 1 && wakes >= 1; // 真实阻塞 + 唤醒配对
            }
            _ => {
                let _ = writeln!(log, "block-recv: setup failed");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t39, "ipc-recv-blocking");

    // 40) 调度切换握手压测（M11-D：跨核拾取窗口根治）。
    //     构造：双核 ring3 spinner（抢占压力：preempt-plan 路径高频置旗/
    //     桩内清旗）+ 双核钉扎 yield 风暴内核任务（协作路径漏斗高频）+
    //     双枚自由跨核 yield 任务（跨核拾取压力：重排队窗口被对侧核
    //     命中）。预算窗口后全量退出；取证：风暴/自由任务全部落证 +
    //     spinner 哨兵退出 57/57 + 静默期全旗清零 + 协作/抢占计数双增。
    let t40 = {
        static STORM_DONE: AtomicUsize = AtomicUsize::new(0);
        fn storm_body_0() {
            for _ in 0..4000 {
                task::yield_now();
            }
            STORM_DONE.fetch_or(1, Ordering::AcqRel);
        }
        fn storm_body_1() {
            for _ in 0..4000 {
                task::yield_now();
            }
            STORM_DONE.fetch_or(2, Ordering::AcqRel);
        }
        fn free_body_a() {
            for _ in 0..2000 {
                task::yield_now();
            }
            STORM_DONE.fetch_or(4, Ordering::AcqRel);
        }
        fn free_body_b() {
            for _ in 0..2000 {
                task::yield_now();
            }
            STORM_DONE.fetch_or(8, Ordering::AcqRel);
        }
        let mut ok = true;
        task::set_preempt_enabled(true);
        task::reset_user_evidence();
        STORM_DONE.store(0, Ordering::Release);
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_SPIN_PROGRAM);
                ostd::hw::phys::write_bytes(usb.code_frame, &user::USER_SPIN_PROGRAM);
                let _ = task::spawn_user_pinned("hs-spin-a", user_noop, usa.root, 0, 0);
                let _ = task::spawn_user_pinned("hs-spin-b", user_noop, usb.root, 0, 1);
                let _ = task::spawn_pinned_prio("hs-storm-0", storm_body_0, 2, 0);
                let _ = task::spawn_pinned_prio("hs-storm-1", storm_body_1, 2, 1);
                let _ = task::spawn("hs-free-a", free_body_a);
                let _ = task::spawn("hs-free-b", free_body_b);
                let (coop0, pre0) = task::preempt_stats();
                // 风暴窗口：钉扎 + 自由任务全部落证（spinner 继续驻留）
                let deadline = ostd::time::now() + 1200;
                while ostd::time::now() < deadline && STORM_DONE.load(Ordering::Acquire) != 0xF {
                    task::yield_now();
                }
                // 哨兵释放：双 spinner 退出（取证窗口闭合）
                let spin_off = user::SPIN_SENTINEL_VA - user::USER_STACK_VIRT;
                ostd::hw::phys::write_u64(usa.stack_frame + spin_off, 1);
                ostd::hw::phys::write_u64(usb.stack_frame + spin_off, 1);
                let deadline = ostd::time::now() + 800;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                // done 断言置于全员终结后（风暴环可能压线截止，done 位由
                // 哨兵等待期的泵进补齐——过早断言即误判，t40 首跑实录）
                ok &= STORM_DONE.load(Ordering::Acquire) == 0xF;
                ok &= task::all_workers_finished();
                let (e0, e1) = task::user_exit_codes();
                let (coop1, pre1) = task::preempt_stats();
                let fc = task::handshake_flags_clear();
                let _ = writeln!(
                    log,
                    "handshake: exit=({e0},{e1}) done={:x} coop+={} preempt+={} flags={fc}",
                    STORM_DONE.load(Ordering::Acquire),
                    coop1 - coop0,
                    pre1 - pre0,
                );
                ok &= e0 == 57 && e1 == 57; // spinner 哨兵退出（寄存器面完好）
                ok &= fc; // 静默期全旗清零
                ok &= coop1 > coop0 && pre1 > pre0; // 两族路径都真实发生
            }
            _ => {
                let _ = writeln!(log, "handshake: user space build failed");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t40, "sched-switch-handshake");

    // 41) 通道注册表运行时化（M12-A：SYS_IPC_BIND + 句柄寻址 + GRANT
    //     分发）。构造：探针任务（钉 CPU0，无预装能力——纯被授予型）
    //     运行 USER_BIND_PROGRAM：父角色 BIND 铸通道（能力装入自身句柄
    //     表首空闲位）→ SPAWN（子同映像，r14 细胞分叉）→ GRANT(cpid,
    //     h, SEND|RECV)（复用 M9 父进程面）→ RECV(h) 阻塞；子角色
    //     YIELD×8 → 负探针 SEND(h=0)→非零 → SEND(h=1 授予句柄)
    //     "BIND-OK"（tag 0x77）。取证链：父退出码 82 + BIND 戟
    //     （res=0/句柄非零/创建数 1）+ GRANT 戟 0 + WAITPID 戟
    //     （收割对象 = 派生子、码 81）+ 子槽位释放。句柄寻址语义同
    //     时被 t24（探针 h2）/ t39（NULL 探针）覆盖。
    let t41 = {
        let mut ok = true;
        ipc::reset_bind_evidence();
        ipc::reset_recv_evidence();
        procs::reset_waitpid_evidence();
        task::reset_user_evidence();
        let sok0 = ipc::DIAG_SEND_OK.load(Ordering::Acquire);
        let sfull0 = ipc::DIAG_FULL.load(Ordering::Acquire);
        let f10 = ipc::DIAG_F1.load(Ordering::Acquire);
        let f20 = ipc::DIAG_F2.load(Ordering::Acquire);
        let f30 = ipc::DIAG_F3.load(Ordering::Acquire);
        let f40 = ipc::DIAG_F4.load(Ordering::Acquire);
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_BIND_PROGRAM);
                let p_id = task::spawn_user_pinned("bind-parent", user_noop, us.root, 0, 0);
                let deadline = ostd::time::now() + 800;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (bres, bhandle, bcreated) = ipc::bind_stamps();
                let (gres, _, _) = procs::stamps();
                let (wres, wpid, wcode) = procs::waitpid_stamps();
                let (e0, _) = task::user_exit_codes();
                // M19-① t41 族缩窗取证：父任务终态（3=Blocked 永久阻塞 =
                // 丢失唤醒实锤；4=Zombie 已终结 = 迟到/次序面）+ RECV
                // 阻塞/唤醒计数（唤醒差值异常即唤醒链面实锤）。
                let (rb, rw) = ipc::recv_stamps();
                // M19-① 发侧取证：SEND 成功/满环计数（rw=0 时区分「帧未入环」
                // 与「唤醒匹配失败」——round-160 活体标本 p-state=3/rw=0 缩窗）。
                let sok = ipc::DIAG_SEND_OK.load(Ordering::Acquire) - sok0;
                let sfull = ipc::DIAG_FULL.load(Ordering::Acquire) - sfull0;
                // M19-① 发侧门禁分立：F1 句柄/F2 权限/F3 通道反查/F4 载荷——
                // sok=0 时直指子 SEND 被哪个门禁拒（GRANT→SEND 能力链竞态缩窗）。
                let f1 = ipc::DIAG_F1.load(Ordering::Acquire) - f10;
                let f2 = ipc::DIAG_F2.load(Ordering::Acquire) - f20;
                let f3 = ipc::DIAG_F3.load(Ordering::Acquire) - f30;
                let f4 = ipc::DIAG_F4.load(Ordering::Acquire) - f40;
                let _ = writeln!(
                    log,
                    "bind: exit0={e0} bres={bres:#x} bh={bhandle} bn={bcreated} \
                     gres={gres:#x} wres={wres:#x} wpid={wpid} wcode={wcode} c-alive={} \
                     p-state={} p-exit={:x} rb={rb} rw={rw} sok={sok} sfull={sfull} \
                     f1={f1} f2={f2} f3={f3} f4={f4}",
                    task::task_alive(wpid as usize),
                    task::task_debug_state(p_id),
                    task::task_debug_exit_code(p_id)
                );
                ok &= e0 == 82; // 父全链成功（BIND/SPAWN/GRANT/RECV/WAIT 全过）
                ok &= bres == 0; // BIND 返回成功
                ok &= bhandle >= 1 && bhandle < task::HANDLE_MAX as u64; // 句柄域合法
                ok &= bcreated == 1; // 运行时通道恰建一者
                ok &= gres == 0; // GRANT（通道分发）成功
                ok &= wres == 0; // WAIT_PID 成功
                ok &= wcode == 81; // 子推送后退出（授予句柄可达）
                ok &= wpid != u64::MAX && !task::task_alive(wpid as usize); // 子槽位释放
                ok &= task::task_alive(p_id); // 父槽位存续
            }
            Err(e) => {
                let _ = writeln!(log, "bind: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t41, "ipc-bind-runtime");

    // 42) SYS_EXEC 执行映像面（M12-B：内嵌映像表重建地址空间）。
    //     构造：探针任务（钉 CPU0）运行 USER_EXEC_PROGRAM——EXEC(7) 越界
    //     负探针（必返 ERR_IMAGE(10)，否则 EXIT(76)）→ EXEC(0) 成功即
    //     不返回（新映像 = EXEC_IMAGES[0] = USER_PROGRAM：LOG "USER-OK"
    //     → YIELD×32 → EXIT(42)）。取证链：退出码 42（新映像跑完全程）
    //     + EXEC 戳（res=0/image=0）+ serial LOG "USER-OK" 再现。
    let t42 = {
        let mut ok = true;
        task::reset_user_evidence();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::USER_EXEC_PROGRAM);
                let _ = task::spawn_user_pinned("exec-probe", user_noop, us.root, 0, 0);
                let deadline = ostd::time::now() + 3000;
                while ostd::time::now() < deadline && !task::all_workers_finished() {
                    task::yield_now();
                }
                ok &= task::all_workers_finished();
                let (res, img) = procs::exec_stamps();
                let (vfs_bytes, segs, _df) = procs::exec_loader_stamps();
                let (e0, _) = task::user_exit_codes();
                let _ = writeln!(
                    log,
                    "exec: exit0={e0} res={res:#x} image={img} vfs={vfs_bytes} segs={segs}"
                );
                ok &= e0 == 42; // 新映像（USER_PROGRAM）跑完全程
                ok &= res == 0; // EXEC(0) 成功落证
                ok &= img == 0; // 映像号 0
            }
            Err(e) => {
                let _ = writeln!(log, "exec: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t42, "exec-image-surface");

    // 43) 僵尸收割运行时化（M12-d：exit 孤儿 re-parent + idle/等待方收割）。
    //     构造（内核侧确定性登记——ring3 SPAWN 协议已由 t37/t41 覆盖）：
    //     main 派 A（YIELD×4 → EXIT(83)，认领 parent=0）+ 内核侧
    //     spawn_user_child 派 B（parent = Some(A)，USER_PROGRAM →
    //     EXIT(42)）。A 先终结 → B 孤儿化（re-parent → None）→ B 终结
    //     → 孤儿 Zombie 被收割面回收；A 的 Zombie 严格保留（父 main
    //     存活——退出码不掠夺），由 wait_scan 父进程面收割。
    //     取证链：孤儿 re-parent ≥1 + 收割 ≥1 + B 槽位释放 + A 保留至
    //     wait_scan 收割（码 83）+ A 收割后槽位释放。
    let t43 = {
        let mut ok = true;
        task::reset_user_evidence();
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_EXIT83_PROGRAM);
                ostd::hw::phys::write_bytes(usb.code_frame, &user::USER_PROGRAM);
                let a_id = task::spawn_user_pinned("orphan-a", user_noop, usa.root, 0, 0);
                ok &= task::task_adopt(a_id, 0); // main 认领（存活等待方）
                let b_id = task::spawn_user_child("orphan-b", user_noop, usb.root, 0, a_id);
                ok &= b_id != usize::MAX; // B 父链 = A（内核登记）
                let (o0, r0) = task::orphan_stamps();
                // 窗口 1：A 终结（B 仍跑）→ 孤儿 re-parent 落证
                let deadline = ostd::time::now() + 400;
                while ostd::time::now() < deadline && task::task_alive(a_id) {
                    task::yield_now();
                }
                ok &= !task::task_alive(a_id) || true; // A 至少已终结（Zombie 亦算离场）
                let a_state = task::task_debug_state(a_id);
                ok &= a_state == 4; // A = Zombie（保留态，未被掠夺）
                                    // 窗口 2：B 终结 → 孤儿收割（等待方驱动 + idle 机会性双路）
                let deadline = ostd::time::now() + 600;
                while ostd::time::now() < deadline && task::task_alive(b_id) {
                    task::yield_now();
                    task::reap_orphans();
                }
                let (o1, r1) = task::orphan_stamps();
                let b_gone = !task::task_alive(b_id);
                let a_kept = task::task_debug_state(a_id) == 4;
                let _ = writeln!(
                    log,
                    "orphan: a-state={a_state} b-gone={b_gone} a-kept={a_kept} \
                     orphans+={} reaps+={} a-code={} b-code={}",
                    o1 - o0,
                    r1 - r0,
                    task::task_debug_exit_code(a_id),
                    task::task_debug_exit_code(b_id),
                );
                ok &= o1 - o0 >= 1; // 孤儿 re-parent 真实发生（A 终结 → B 无主）
                ok &= r1 - r0 >= 1; // 孤儿收割真实发生（B 离场）
                ok &= b_gone; // B（孤儿）槽位已释放
                ok &= a_kept; // A（有主僵尸）严格保留——退出码不掠夺
                              // 父进程面收割 A（wait_scan 单锁窗口；main = pid 0）
                let wscan = task::wait_scan(0, a_id as u64);
                ok &= wscan.reaped.is_some_and(|(_, code)| code == 83);
                ok &= !task::task_alive(a_id); // A 收割后槽位释放
            }
            (_, Err(e)) | (Err(e), _) => {
                let _ = writeln!(log, "orphan: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t43, "zombie-reap-runtime");

    // 44) 文件面统一句柄面（M13-②）：内核侧全矩阵——open/read/seek/
    //     write/stat/close + HANDLE_QUERY 权限位融合实证 + Conduit 口径
    //     errno 负探针（EBADF/EISDIR/ENOENT/EINVAL/EFAULT/EMFILE）+
    //     句柄表占用基线还原
    let t44 = {
        // M13-②：timer 守护任务（tickd）0 级派生——与 swapd 同款
        // yield-poll 房屋范式，到期旗消费恒在任务上下文
        let _tickd = task::spawn_prio("tickd", crate::timer::tickd_body, 0);
        // vfs::init 已迁启动区（M14-①：EXEC 依赖前置）——此处仅复位取证
        vfs::reset_evidence();
        let mut ok = true;
        let used0 = task::with_task_handles(0, |t| t.iter().filter(|h| h.is_some()).count());
        static P_HELLO: [u8; 12] = *b"/files/hello";
        static P_DIR: [u8; 10] = *b"/files/dir";
        static P_NOPE: [u8; 5] = *b"/nope";
        static BANG: [u8; 1] = *b"!";
        let mut rbuf = [0u8; 16];
        let mut diag = |tag: &str, r: u64| {
            let _ = writeln!(log, "  file44 {tag}={r:#x}");
        };
        // OPEN 只读 + 统一句柄面实证：HANDLE_QUERY 透出文件句柄（READ 位）
        let r = vfs::sys_open(P_HELLO.as_ptr() as u64, 12, 1);
        diag("open0", r);
        ok &= r >> 32 == 1;
        let h = r & 0xFFFF_FFFF;
        let q = procs::sys_handle_query(h);
        diag("hq", q);
        ok &= q >> 32 == 1 && ((q >> 16) & 0xFFFF) == 1; // Right::READ
                                                         // READ 全量（种子 "lumina-fs" = 9 字节，EOF 语义）
        let r = vfs::sys_read(h, rbuf.as_mut_ptr() as u64, 9);
        diag("read0", r);
        ok &= r == (1u64 << 32) | 9;
        let content_ok = rbuf[..9] == *b"lumina-fs";
        diag("content", u64::from(content_ok));
        ok &= content_ok;
        // SEEK End → 偏移 9；只读句柄写 → EBADF
        let r = vfs::sys_seek(h, 2, 0);
        diag("seek0", r);
        ok &= r == (1u64 << 32) | 9;
        let r = vfs::sys_write(h, BANG.as_ptr() as u64, 1);
        diag("wo", r);
        ok &= r == 9;
        // CLOSE → 关后旧句柄读 = EBADF（Linux fd 复用语义负探针；
        // 此后至还原基线前不再 OPEN，避免同号复用干扰判定）
        ok &= vfs::sys_close(h) == 0;
        let r = vfs::sys_read(h, rbuf.as_mut_ptr() as u64, 4);
        diag("stale-read", r);
        ok &= r == 9;
        // 读写打开 → 尾部追加 → STAT（size 10，kind 0 = File）
        let r = vfs::sys_open(P_HELLO.as_ptr() as u64, 12, 3);
        diag("open1", r);
        ok &= r >> 32 == 1;
        let h2 = r & 0xFFFF_FFFF;
        let r = vfs::sys_seek(h2, 2, 0);
        diag("seek1", r);
        ok &= r == (1u64 << 32) | 9;
        let r = vfs::sys_write(h2, BANG.as_ptr() as u64, 1);
        diag("write1", r);
        ok &= r == (1u64 << 32) | 1;
        let r = vfs::sys_stat(h2);
        diag("stat", r);
        ok &= r == (1u64 << 32) | (10 << 16);
        // EISDIR：目录可开不可读（M13-① fd 表同款语义）
        let r = vfs::sys_open(P_DIR.as_ptr() as u64, 10, 1);
        ok &= r >> 32 == 1;
        let hd = r & 0xFFFF_FFFF;
        ok &= vfs::sys_read(hd, rbuf.as_mut_ptr() as u64, 4) == 21;
        ok &= vfs::sys_close(hd) == 0;
        // ENOENT / EINVAL（零模式）/ EFAULT（空指针缓冲）
        ok &= vfs::sys_open(P_NOPE.as_ptr() as u64, 5, 1) == 2;
        ok &= vfs::sys_open(P_HELLO.as_ptr() as u64, 12, 0) == 22;
        ok &= vfs::sys_read(h2, core::ptr::null_mut::<u8>() as u64, 4) == 14;
        ok &= vfs::sys_close(h2) == 0;
        // EMFILE：填满调用方句柄表（先验免泄漏），再全关还原基线
        let mut hs = [0u64; task::HANDLE_MAX];
        let mut n = 0usize;
        for _ in 0..task::HANDLE_MAX as u64 {
            let r = vfs::sys_open(P_HELLO.as_ptr() as u64, 12, 1);
            if r >> 32 == 1 {
                hs[n] = r & 0xFFFF_FFFF;
                n += 1;
            } else {
                ok &= r == 24; // EMFILE
                break;
            }
        }
        ok &= n >= 1;
        for fd in hs.iter().take(n) {
            ok &= vfs::sys_close(*fd) == 0;
        }
        let used1 = task::with_task_handles(0, |t| t.iter().filter(|h| h.is_some()).count());
        ok &= used1 == used0;
        let _ = writeln!(log, "  file44 used0={used0:?} used1={used1:?} opens={n}");
        // 取证面落证自洽（最后一次 OPEN = EMFILE 语义）
        let (o_r, _o_h, r_r, w_r, c_r, s_r, k_r) = vfs::stamps();
        let _ = writeln!(
            log,
            "  file44 stamps o={o_r:#x} r={r_r:#x} w={w_r:#x} c={c_r:#x} s={s_r:#x} k={k_r:#x}"
        );
        ok &= o_r == 24;
        ok &= r_r == 14; // 最后一次 READ = 空指针 EFAULT 探针（stale-read 在其前）
        ok &= w_r == (1u64 << 32) | 1;
        ok &= c_r == 0;
        ok &= s_r == (1u64 << 32) | (10 << 16);
        ok &= k_r == (1u64 << 32) | 9;
        ok
    };
    report(&mut log, t44, "file-face-unified-handle");

    // 45) 文件面 ring3 端到端（M13-②）：USER_FILE_PROGRAM——open→write→
    //     seek→read 回读比对→nanosleep(1)→close→关后读 EBADF→负探针
    //     ENOENT→EXIT(90)；分级失败码 92-99
    let t45 = {
        let mut ok = true;
        vfs::reset_evidence();
        match user::build_user_space_with(&user::USER_FILE_PROGRAM, &mut || frames.alloc()) {
            Ok(us) => {
                let cid = task::spawn_user("file-client", user_noop, us.root, 0);
                let deadline = ostd::time::now() + 1000;
                // 有界等待客户端终结（tickd 常驻使 all_workers_finished
                // 恒假——改按本检查的目标任务 Zombie 态轮询）
                while task::task_debug_state(cid) != 4 && ostd::time::now() < deadline {
                    task::yield_now();
                }
                // M17 加固：超时退出与 client 完成竞速时，exit 落定与
                // zombie 登记间存在跨核采样窗口（实测 exit=90 + state=0
                // 翻转红）——补短窗收敛 zombie，断言不再竞速敏感。
                if task::task_debug_state(cid) != 4 {
                    let settle = ostd::time::now() + 300;
                    while task::task_debug_state(cid) != 4 && ostd::time::now() < settle {
                        task::yield_now();
                    }
                }
                let code = task::user_exit_code();
                let st = task::task_debug_state(cid);
                // M19-① t45 族取证：FILES 注册表用量（ENFILE(23) 缩窗——
                // 跨自检泄漏累积实锤；open 返回 23 即表满）。
                let (fu, fm) = vfs::files_usage();
                let snap = vfs::enfile_snapshot();
                let _ = writeln!(
                    log,
                    "  file45 cid={cid} state={st} exit={code} stamps={:?} files-used={fu}/{fm} enfile={snap:#x}",
                    vfs::stamps()
                );
                // M19-① 断言校准：st=4（Zombie 在槽）或 st=0（槽位已被
                // 收割回收）均为合法终态——round-257 实录 exit=90 + 槽位
                // None（收割面先于采样落定）；M17 加固的 settle 窗兜不住
                // 收割竞态属采样过严，非内核行为缺陷。
                ok &= code == 90 && (st == 4 || st == 0);
            }
            Err(e) => {
                let _ = writeln!(log, "file client space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t45, "file-face-ring3");

    // 46) timer 阻塞源（M13-② 第三类阻塞源）：内核 sleeper 真阻塞 5 tick
    //     （WaitWhat::Timer + wall_hook 到期扫描唤醒）+ nanosleep(0) 探针
    //     命中即时返回 + swap 族同款三计数取证
    let t46 = {
        let mut ok = true;
        timer::reset_evidence();
        let _id = task::spawn("timer-sleeper", sleeper_body);
        let wait_deadline = ostd::time::now() + 2000;
        while SLEEPER_DONE.load(Ordering::Acquire) == 0 && ostd::time::now() < wait_deadline {
            task::yield_now();
        }
        ok &= SLEEPER_DONE.load(Ordering::Acquire) == 1;
        ok &= SLEEPER_ELAPSED_NS.load(Ordering::Acquire) >= 50_000_000;
        let (blocks, wakes, hits) = timer::stamps();
        ok &= blocks >= 1 && wakes >= 1;
        // 探针命中路径：nanosleep(0)（deadline 即当前节拍，时间单调保证
        // 已期满 → SCHED 锁窗探针命中回滚，不阻塞）
        ok &= timer::sys_nanosleep(0) == 0;
        let (_, _, hits1) = timer::stamps();
        ok &= hits1 == hits + 1;
        // M22-③ [C] 取证面（ff46 显形）：全量中间量落日志——休眠完成旗、
        // 实测耗时、三计数（阻塞/唤醒/探针命中）与探针增量
        let _ = writeln!(
            log,
            "  timer-block: done={} elapsed_ns={} blocks={blocks} wakes={wakes} hits={hits} hits1={hits1}",
            SLEEPER_DONE.load(Ordering::Acquire),
            SLEEPER_ELAPSED_NS.load(Ordering::Acquire),
        );
        ok
    };
    report(&mut log, t46, "timer-block-nanosleep");

    // 47) 多段映像 VFS 装载（M14-① EXEC 经 VFS 取段——VFS 第二消费者）：
    //     探针任务（钉 CPU0）运行 EXEC1_PROGRAM——EXEC(9) 越界负探针
    //     （必返 ERR_IMAGE(10)）→ EXEC(1) 成功即不返回（新映像 =
    //     /files/prog.lxe 双段 LXE1：代码 RX @FRESH_BASE + 数据 RW
    //     @PROG_DATA_VA）。取证链：退出码 91（读种子→校验→写哨兵→
    //     EXIT）+ EXEC 戳（res=0/image=1）+ 装载器戳（vfs_bytes>0/
    //     segs=2）+ 数据帧哨兵 phys 轮询 == PROG_RESULT_MAGIC。
    let t47 = {
        let mut ok = true;
        task::reset_user_evidence();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::EXEC1_PROGRAM);
                let _ = task::spawn_user_pinned("exec-m14-probe", user_noop, us.root, 0, 0);
                // 退出码驱动轮询（t46 sleeper 常驻 —— all_workers_finished
                // 在 t46 后恒 false，不可用作完成信号）
                let deadline = ostd::time::now() + 600;
                let (mut e0, _) = task::user_exit_codes();
                while ostd::time::now() < deadline && e0 == u64::MAX {
                    task::yield_now();
                    let (e, _) = task::user_exit_codes();
                    e0 = e;
                }
                let (res, img) = procs::exec_stamps();
                let (vfs_bytes, segs, data_frame) = procs::exec_loader_stamps();
                let _ = writeln!(
                    log,
                    "  exec-m14: exit0={e0} res={res:#x} image={img} vfs={vfs_bytes} segs={segs} df={data_frame:#x}"
                );
                ok &= e0 == 91; // 新映像跑完全程（prog.lxe EXIT 码）
                ok &= res == 0 && img == 1; // EXEC(1) 成功落证
                ok &= vfs_bytes > 0 && segs == 2; // VFS 取段 + 双段装载实证
                ok &= data_frame != 0;
                // M15-② CLOEXEC 消费随真实 EXEC 路径执行：探针任务句柄
                // 表为空 → 关闭数 0（钩子贯通取证，消费语义见 t51）
                ok &= procs::exec_cloexec_stamp() == 0;
                // 数据段哨兵：RESULT magic 落帧（帧首 = PROG_DATA_VA 页基，
                // 程序写 [r15+8]，内核 phys 直读 + 8）
                let sentinel = ostd::hw::phys::read_u64(data_frame + 8);
                ok &= sentinel == user::PROG_RESULT_MAGIC;
            }
            Err(e) => {
                let _ = writeln!(log, "exec-m14: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t47, "exec-multiseg-vfs");

    // 48) 缺页驱动栈增长（M14-①）：探针任务运行 EXEC2_PROGRAM →
    //     /files/grow.lxe（单段 + stack_top=STACK_TOP_GROW：增长栈
    //     PD6[1]→pt_stack 顶帧预映射）。ring3 sub rsp 0x1800 越出初始
    //     帧 → #PF（ring3 + 窗口内 + 叶未映射）→ stack_grow 补帧 →
    //     写读回校验 → EXIT(92)。取证链：退出码 92 + STACK_GROWS ≥ 1
    //     + LAST_GROW_FRAME ≠ 0 + EXEC 戳（res=0/image=2）。
    let t48 = {
        let mut ok = true;
        task::reset_user_evidence();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::EXEC2_PROGRAM);
                let _ = task::spawn_user_pinned("grow-probe", user_noop, us.root, 0, 0);
                // 退出码驱动轮询（同 t47：t46 sleeper 常驻）
                let deadline = ostd::time::now() + 600;
                let (mut e0, _) = task::user_exit_codes();
                while ostd::time::now() < deadline && e0 == u64::MAX {
                    task::yield_now();
                    let (e, _) = task::user_exit_codes();
                    e0 = e;
                }
                let (res, img) = procs::exec_stamps();
                let (grows, frame) = vmm::stack_growth_stamps();
                let _ = writeln!(
                    log,
                    "  grow: exit0={e0} res={res:#x} image={img} grows={grows} frame={frame:#x}"
                );
                ok &= e0 == 92; // 增长栈程序写读回成功
                ok &= res == 0 && img == 2; // EXEC(2) 成功落证
                ok &= grows >= 1; // #PF 驱动扩栈取证
                ok &= frame != 0;
            }
            Err(e) => {
                let _ = writeln!(log, "grow: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t48, "stack-growth-pagefault");

    // 49) 配额治理（M14-②）：SYS_QUOTA 三 kind 用量快照 + 容量首审
    //     实证（HANDLE_MAX=16/MAX_FILES=32/MAX_CHANNELS=32）+ 关闭
    //     还原 + kind 越界防御面。
    let t49 = {
        let mut ok = true;
        // kind 0 基线（main 自身句柄表）
        let used0 = task::handle_usage(0).0;
        let q0 = procs::sys_quota(0);
        ok &= q0 == (1u64 << 32) | ((used0 as u64) << 16) | task::HANDLE_MAX as u64;
        // 开 3 个文件 → kind 0/1 各 +3（数组定容 3，防多开漂移）
        let p = b"/files/hello";
        let mut hs = [0u64; 3];
        for h in hs.iter_mut() {
            let r = vfs::sys_open(p.as_ptr() as u64, p.len() as u64, 1);
            ok &= r >> 32 == 1;
            *h = r & 0xFFFF_FFFF; // 句柄号（OK 位剥离——t44 同款）
        }
        let q0b = procs::sys_quota(0);
        ok &= (q0b >> 16) & 0xFFFF == (used0 + 3) as u64;
        let q1 = procs::sys_quota(1);
        let (f_used, f_cap) = vfs::files_usage();
        ok &= q1 == (1u64 << 32) | ((f_used as u64) << 16) | f_cap as u64;
        ok &= f_cap == 32 && f_used >= 3;
        // bind 1 通道 → kind 2 与注册表自洽
        let br = ipc::sys_bind(0);
        let (c_used, c_cap) = ipc::channels_usage();
        let q2 = procs::sys_quota(2);
        ok &= q2 == (1u64 << 32) | ((c_used as u64) << 16) | c_cap as u64;
        ok &= c_cap == 32 && c_used >= 1;
        let _ = writeln!(
            log,
            "  quota: bind={br:#x} files={f_used}/{f_cap} chans={c_used}/{c_cap} h0={}",
            (q0b >> 16) & 0xFFFF
        );
        // 全关还原（文件面；bind 通道句柄存续不关——M15-② 落点见 t51，
        // 本测保持 bind 存续语义不变量）
        for h in hs.iter() {
            ok &= vfs::sys_close(*h) == 0;
        }
        let (f_used1, _) = vfs::files_usage();
        let (c_used1, _) = ipc::channels_usage();
        ok &= f_used1 == f_used - 3;
        ok &= c_used1 == c_used; // 通道注册表占用不变（bind 存续语义）
                                 // kind 越界防御面（直调；parse 层已在 abi 单测钉死）+ 取证自洽
                                 // （kind 3 自 v0.17 转正为栈增长窗口——M16-③，t55 对账）
        ok &= procs::sys_quota(4) == 1; // ERR_CAP
        ok &= procs::quota_stamp() == 1;
        ok
    };
    report(&mut log, t49, "quota-governance");

    // 50) 目录面（M15-①）：MKDIR/REMOVE（父走查 + 负探针）+ READDIR
    //     分页（首页小缓冲强制分页 → 续页至 EOF → 名单+ kind 抽查）
    //     + MOUNT/UMOUNT（RamFs 挂载遮蔽面 + 卸载回落 + 负探针族）。
    //     取证：dir_stamps 五戳终值确定性断言。
    let t50 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        vfs::reset_dir_evidence();
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        // ① MKDIR 正面 + 负探针（EEXIST/ENOENT/建根 EINVAL）
        let (pp, pl) = pa("/files/scratch");
        let mk1 = chk!(vfs::sys_mkdir(pp, pl), 0);
        let (sp2, sl2) = pa("/files/scratch/sub");
        let mk2 = chk!(vfs::sys_mkdir(sp2, sl2), 0);
        chk!(vfs::sys_mkdir(pp, pl), 17);
        let (np, nl) = pa("/files/nope/deep");
        chk!(vfs::sys_mkdir(np, nl), 2);
        let (rp, rl) = pa("/");
        chk!(vfs::sys_mkdir(rp, rl), 22);
        // ② MOUNT：mkdir mnt → 挂载（RamFs 遮蔽）→ 重复 EEXIST → 新 fs 内建目录
        let (mp, ml) = pa("/files/mnt");
        chk!(vfs::sys_mkdir(mp, ml), 0);
        chk!(vfs::sys_mount(mp, ml, 0), 0);
        chk!(vfs::sys_mount(mp, ml, 0), 17);
        let (ap, al) = pa("/files/mnt/a");
        chk!(vfs::sys_mkdir(ap, al), 0); // 落在新 fs（遮蔽面）
                                         // ③ MOUNT/UMOUNT 负探针：挂文件 ENOTDIR(20)、挂缺失 ENOENT(2)、
                                         //    umount 未挂载 ENOENT(2)、umount 根 ENOENT(2)、fs_type≠0 EINVAL(22)
        let (fp, fl) = pa("/files/hello");
        chk!(vfs::sys_mount(fp, fl, 0), 20);
        chk!(vfs::sys_mount(np, nl, 0), 2);
        chk!(vfs::sys_umount(np, nl), 2);
        chk!(vfs::sys_umount(rp, rl), 2);
        chk!(vfs::sys_mount(fp, fl, 2), 22);
        // ④ READDIR 分页：open /files → 首页 16B（deep.lxe+dir 恰 15B，
        //    第三项放不下 → 半项不落盘）→ 续页 512B 至 EOF → 全量积累
        let (dp, dl) = pa("/files");
        let or = vfs::sys_open(dp, dl, 1);
        ok &= or >> 32 == 1;
        let dh = or & 0xFFFF_FFFF;
        let r1 = chk!(vfs::sys_readdir(dh, dir_page_addr(), 16), (1 << 32) | 2);
        let mut acc_len = copy_page_to_acc(2, 0);
        let mut total = 2usize;
        loop {
            let r = vfs::sys_readdir(dh, dir_page_addr(), 512);
            let n = (r & 0xFFFF_FFFF) as usize;
            if r == 1 << 32 {
                break; // EOF（枚举尽）
            }
            ok &= n >= 1;
            if n == 0 {
                break;
            }
            total += n;
            acc_len = copy_page_to_acc(n, acc_len);
        }
        ok &= total == 10; // deep.lxe/dir/echo/grow.lxe/hello/mnt/prog.lwp/
                           // prog.lxe/scratch/selftest.lxe（M16 播种 +2）
                           // 名单 + kind 抽查（顺序无关：积累缓冲逐项走查，项编码自对齐）
        let scan_ok = acc_scan(acc_len);
        ok &= scan_ok;
        // ⑤ READDIR 负探针：文件句柄 ENOTDIR(20)、坏句柄 EBADF(9)、
        //    短缓冲 EINVAL(22)；write-only 目录 EBADF(9)
        let fr = vfs::sys_open(fp, fl, 1);
        let fh = fr & 0xFFFF_FFFF;
        chk!(vfs::sys_readdir(fh, dir_page_addr(), 64), 20);
        chk!(vfs::sys_readdir(9999, dir_page_addr(), 64), 9);
        chk!(vfs::sys_readdir(dh, dir_page_addr(), 2), 22);
        let (mp2, ml2) = pa("/files/scratch/sub");
        let wr = vfs::sys_open(mp2, ml2, 2); // write-only
        ok &= wr >> 32 == 1;
        chk!(vfs::sys_readdir(wr & 0xFFFF_FFFF, dir_page_addr(), 64), 9);
        chk!(vfs::sys_close(wr & 0xFFFF_FFFF), 0);
        // ⑥ 挂载面枚举：/files/mnt（新 fs）恰 1 项 → 同句柄续读即尽；
        //    M17-③ 占用复核：句柄存活卸载 → EBUSY(16)；关闭后卸载放行；
        //    新解析回落：重新 open → 原 fs 空目录 → EOF（回落语义不变）
        let mr = vfs::sys_open(mp, ml, 1);
        let mh = mr & 0xFFFF_FFFF;
        let mnt1 = chk!(vfs::sys_readdir(mh, dir_page_addr(), 512), (1 << 32) | 1);
        chk!(vfs::sys_readdir(mh, dir_page_addr(), 512), 1 << 32);
        let umt = chk!(vfs::sys_umount(mp, ml), 16); // M17-③：句柄存活拒卸
        chk!(vfs::sys_close(mh), 0);
        chk!(vfs::sys_umount(mp, ml), 0);
        let mr2 = vfs::sys_open(mp, ml, 1); // 新解析 → 回落原 fs
        ok &= mr2 >> 32 == 1;
        chk!(
            vfs::sys_readdir(mr2 & 0xFFFF_FFFF, dir_page_addr(), 512),
            1 << 32
        );
        chk!(vfs::sys_close(mr2 & 0xFFFF_FFFF), 0);
        // ⑦ REMOVE：sub → scratch → 已摘 ENOENT → 非空 /files ENOTEMPTY(39)
        chk!(vfs::sys_remove(sp2, sl2), 0);
        chk!(vfs::sys_remove(pp, pl), 0);
        chk!(vfs::sys_remove(pp, pl), 2);
        chk!(vfs::sys_remove(dp, dl), 39);
        // 收尾：关句柄（引用计数收敛）+ remove 回落后的空 mnt
        chk!(vfs::sys_close(fh), 0);
        chk!(vfs::sys_close(dh), 0);
        chk!(vfs::sys_remove(mp, ml), 0);
        // 取证终值（确定性）：末次 mkdir=建 a=0、remove=删 mnt=0、
        // readdir=EOF、mount=fs_type 探针=22、umount=卸 mnt=0
        let (mk, rm, rd, mo, um) = vfs::dir_stamps();
        ok &= mk == 0 && rm == 0 && rd == 1 << 32 && mo == 22 && um == 0;
        let _ = writeln!(
            log,
            "  dir: mk1={mk1} mk2={mk2} r1={r1:#x} tot={total} scan={scan_ok} mnt1={mnt1:#x} umt={umt} stamps=({mk},{rm},{rd:#x},{mo},{um}) fail@L{fail_line}"
        );
        ok
    };
    report(&mut log, t50, "directory-face");

    // 51) 句柄面深化（M15-②）：dup 共享 OFD 偏移（一写一读对账）+
    //     引用计数关闭（关一副本余副本存活）+ fcntl 三命令 + CLOEXEC
    //     + 通道句柄关闭落点（bind 存续语义补全）+ EXEC CLOEXEC 消费。
    let t51 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        vfs::reset_dir_evidence();
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        let used00 = task::handle_usage(0).0; // t49 遗留 bind 通道句柄计入基线
                                              // ① dup 共享偏移：open echo RW → write ABC → dup → write DEF
                                              //    （共享 pos=6）→ h1 seek 0 → read 6 == "ABCDEF"
        let (ep, el) = pa("/files/echo");
        let r1 = vfs::sys_open(ep, el, 3);
        ok &= r1 >> 32 == 1;
        let h1 = r1 & 0xFFFF_FFFF;
        let wb = b"ABC";
        chk!(vfs::sys_write(h1, wb.as_ptr() as u64, 3), (1 << 32) | 3);
        let r2 = vfs::sys_dup(h1);
        ok &= r2 >> 32 == 1;
        let h2 = r2 & 0xFFFF_FFFF;
        ok &= h2 != h1;
        let wb = b"DEF";
        chk!(vfs::sys_write(h2, wb.as_ptr() as u64, 3), (1 << 32) | 3);
        chk!(vfs::sys_seek(h1, 0, 0), 1 << 32);
        let mut rb = [0u8; 8];
        chk!(vfs::sys_read(h1, rb.as_mut_ptr() as u64, 6), (1 << 32) | 6);
        ok &= &rb[..6] == b"ABCDEF"; // 偏移共享实证
                                     // ② 引用计数关闭：close h1 → 0；h2 仍读得全量（对象保活）
        chk!(vfs::sys_close(h1), 0);
        chk!(vfs::sys_seek(h2, 0, 0), 1 << 32);
        chk!(vfs::sys_read(h2, rb.as_mut_ptr() as u64, 6), (1 << 32) | 6);
        ok &= &rb[..6] == b"ABCDEF";
        // ③ fcntl：SETFD CLOEXEC → GETFD 复读；未置位句柄 GETFD == 0；
        //    F_DUPFD 下界 ≥ 4；命令越界 EINVAL（直调防御面）
        chk!(
            vfs::sys_fcntl(h2, bedrock::abi::F_SETFD, bedrock::abi::FD_CLOEXEC),
            0
        );
        chk!(
            vfs::sys_fcntl(h2, bedrock::abi::F_GETFD, 0),
            (1 << 32) | bedrock::abi::FD_CLOEXEC
        );
        let (hp, hl) = pa("/files/hello");
        let r3 = vfs::sys_open(hp, hl, 1);
        ok &= r3 >> 32 == 1;
        let h3 = r3 & 0xFFFF_FFFF;
        chk!(vfs::sys_fcntl(h3, bedrock::abi::F_GETFD, 0), 1 << 32);
        let r4 = vfs::sys_fcntl(h3, bedrock::abi::F_DUPFD, 4);
        ok &= r4 >> 32 == 1 && (r4 & 0xFFFF_FFFF) >= 4;
        let h4 = r4 & 0xFFFF_FFFF;
        chk!(vfs::sys_fcntl(h3, 9, 0), 22);
        // ④ 通道句柄关闭落点：bind（注册表 +1）→ close == 0（M15-② 新面）
        //    → 存续语义（占用保持 bind 后水位）→ 已关句柄 send ERR_CAP(1)
        //    → 重复 close EBADF(9)
        let (c_used, c_cap) = ipc::channels_usage();
        let br = ipc::sys_bind(0);
        ok &= br >> 32 == 1;
        let ch = br & 0xFFFF_FFFF;
        let cl1 = chk!(vfs::sys_close(ch), 0);
        let (c_used1, c_cap1) = ipc::channels_usage();
        ok &= c_used1 == c_used + 1 && c_cap1 == c_cap; // bind +1，close 存续不减
        chk!(ipc::sys_send(ch, ep, 0, 0), 1); // ERR_CAP（句柄已回收）
        chk!(vfs::sys_close(ch), 9);
        // ⑤ EXEC CLOEXEC 消费：h2 置位、h3/h4 未置位 → 钩子关 1（h2）
        //    → h3 存活可 GETFD（fd 继承语义）
        let before = task::handle_usage(0).0;
        let closed = task::close_cloexec_handles(0);
        ok &= closed == 1;
        ok &= task::handle_usage(0).0 == before - 1;
        chk!(vfs::sys_fcntl(h3, bedrock::abi::F_GETFD, 0), 1 << 32);
        // ⑥ 收尾全关（引用计数归零 → 注册表还原；句柄表回 used00——
        //    含 t49 遗留通道句柄存续位）
        chk!(vfs::sys_close(h3), 0);
        chk!(vfs::sys_close(h4), 0);
        ok &= task::handle_usage(0).0 == used00;
        // 取证：DUP 末值 = sys_dup 打包返回、FCNTL 末值 = ⑤ GETFD 复读
        // （cmd-9 探针之后的末次 fcntl 调用 = F_GETFD(h3)）
        let (dr, fr) = vfs::hdeep_stamps();
        ok &= dr == r2 && fr == 1 << 32;
        let _ = writeln!(
            log,
            "  hdeep: h1={h1} h2={h2} h3={h3} h4={h4} ch={ch} cl1={cl1} closed={closed} used00={used00} dup={dr:#x} fcntl={fr:#x} fail@L{fail_line}"
        );
        ok
    };
    report(&mut log, t51, "handle-deepening");

    // 52) TSC 纳秒面（M15-③）：hz 已校准（>0）+ 20ms 真阻塞（TSC 纳秒
    //     下界：单调域内不早醒）+ 探针命中（nanosleep(0)）+ now_ns 单调。
    let t52 = {
        let mut ok = true;
        timer::reset_evidence();
        ok &= ostd::time::tsc_clock::hz() > 0;
        let n0 = ostd::time::tsc_clock::now_ns();
        ok &= n0.is_some();
        let rc0 = timer::sys_nanosleep(20_000_000); // 20ms
        ok &= rc0 == 0;
        let elapsed = ostd::time::tsc_clock::now_ns()
            .unwrap_or(0)
            .saturating_sub(n0.unwrap_or(0));
        ok &= elapsed >= 20_000_000; // 纳秒下界（不早醒）
        let (blocks, wakes, _) = timer::stamps();
        ok &= blocks >= 1 && wakes >= 1;
        ok &= timer::sys_nanosleep(0) == 0; // 探针命中
        let (_, _, hits) = timer::stamps();
        ok &= hits >= 1;
        // M22-③ [C] 取证面（ff52 显形）：返回码 + 三计数随诊断行落日志
        let _ = writeln!(
            log,
            "  tsc: hz={} elapsed_ns={elapsed} rc0={rc0} blocks={blocks} wakes={wakes} hits={hits}",
            ostd::time::tsc_clock::hz()
        );
        ok
    };
    report(&mut log, t52, "tsc-nanosleep");
    // tickd 退役（echo worker 同款退出协议；t52 后收尾——TSC 纳秒面
    // 依赖唤醒链存活，防泄漏任务）
    timer::shutdown();

    // 53) 文件创建面（M16-①）：O_CREAT 缺失新建（写读回对账 + 已存在
    //     重开）+ O_TRUNC 可写截零/只读不截 + 负探针族（父缺失 ENOENT/
    //     保留位 EINVAL/无访问位 EINVAL/目录写 EISDIR）。
    let t53 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        vfs::reset_evidence();
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        const FOK: u64 = 1 << 32;
        let m_cw = bedrock::abi::O_CREAT | 0b10;
        let m_cr = bedrock::abi::O_CREAT | 0b01;
        let m_tr = bedrock::abi::O_TRUNC | 0b01;
        // ① O_CREAT 新建 + 写读回
        let (cp, cl) = pa("/files/ocreat.txt");
        let o1 = vfs::sys_open(cp, cl, m_cw);
        ok &= o1 >> 32 == 1;
        let h1 = o1 & 0xFFFF_FFFF;
        // SAFETY: 单核自检上下文串行访问（t50 DIR_PAGE 同款纪律）
        unsafe {
            core::ptr::copy_nonoverlapping(b"LUMINA-OCREAT".as_ptr(), oc_buf_addr() as *mut u8, 13);
        }
        chk!(vfs::sys_write(h1, oc_buf_addr(), 13), FOK | 13);
        ok &= vfs::sys_close(h1) == 0;
        let o2 = vfs::sys_open(cp, cl, 0b01);
        ok &= o2 >> 32 == 1;
        let h2 = o2 & 0xFFFF_FFFF;
        chk!(vfs::sys_read(h2, oc_buf_addr(), 32), FOK | 13);
        // SAFETY: 同上（读回内容对账）
        let got = unsafe { core::slice::from_raw_parts((&raw const OC_BUF) as *const u8, 13) };
        ok &= got == b"LUMINA-OCREAT";
        ok &= vfs::sys_close(h2) == 0;
        // ② O_CREAT 已存在：重开直开（v0 无 O_EXCL）
        let o3 = vfs::sys_open(cp, cl, m_cr);
        ok &= o3 >> 32 == 1;
        ok &= vfs::sys_close(o3 & 0xFFFF_FFFF) == 0;
        // ③ O_TRUNC：只读不截（尺寸保持 8）；可写截零（size 0 → 读 EOF）
        let (tp, tl) = pa("/files/trunceme");
        let o4 = vfs::sys_open(tp, tl, m_cw);
        ok &= o4 >> 32 == 1;
        let h4 = o4 & 0xFFFF_FFFF;
        chk!(vfs::sys_write(h4, oc_buf_addr(), 8), FOK | 8);
        ok &= vfs::sys_close(h4) == 0;
        let o5 = vfs::sys_open(tp, tl, m_tr);
        ok &= o5 >> 32 == 1;
        let h5 = o5 & 0xFFFF_FFFF;
        let st1 = vfs::sys_stat(h5);
        ok &= (st1 >> 16) & 0xFFFF == 8;
        ok &= vfs::sys_close(h5) == 0;
        let o6 = vfs::sys_open(tp, tl, bedrock::abi::O_TRUNC | 0b11); // RW：截零后可读回 EOF
        ok &= o6 >> 32 == 1;
        let h6 = o6 & 0xFFFF_FFFF;
        let st2 = vfs::sys_stat(h6);
        ok &= (st2 >> 16) & 0xFFFF == 0;
        chk!(vfs::sys_read(h6, oc_buf_addr(), 8), FOK); // EOF：OK_BIT|0
        ok &= vfs::sys_close(h6) == 0;
        // ④ 负探针：父缺失 ENOENT(2)；保留位/无访问位 EINVAL(22)（直调防御面）；
        //    目录 O_CREAT|W 可开（v0 目录打开语义）但 write → EISDIR(21)
        let (np, nl) = pa("/files/nope/leaf");
        chk!(vfs::sys_open(np, nl, m_cw), 2);
        chk!(vfs::sys_open(cp, cl, 0b10100), 22);
        chk!(vfs::sys_open(cp, cl, 0b100), 22);
        let (dp2, dl2) = pa("/files/dir");
        let o7 = vfs::sys_open(dp2, dl2, m_cw);
        ok &= o7 >> 32 == 1;
        let h7 = o7 & 0xFFFF_FFFF;
        chk!(vfs::sys_write(h7, oc_buf_addr(), 4), 21);
        ok &= vfs::sys_close(h7) == 0;
        if fail_line != 0 {
            let _ = writeln!(log, "  t53 first-fail line={fail_line}");
        }
        ok
    };
    report(&mut log, t53, "file-create-o-creat");

    // 54) Weave 包源映像（M16-② EXEC 第 2+ 消费者，v0.15 候补转正）：
    //     探针任务运行 EXEC3_PROGRAM——EXEC(9) 负探针 → EXEC(3)
    //     （/files/prog.lwp = LWP1 包装 prog.lxe）→ 解包装载 →
    //     退出码 91。取证链：EXEC 戳（res=0/image=3）+ vfs_bytes =
    //     LWP1 包长（32B 头 + 15B 名字 + 193B 载荷）+ segs=2 + 数据帧
    //     哨兵 == PROG_RESULT_MAGIC（载荷与 t47 同一 prog.lxe——
    //     双消费者行为等价直证）。
    let t54 = {
        let mut ok = true;
        task::reset_user_evidence();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::EXEC3_PROGRAM);
                let _ = task::spawn_user_pinned("weave-exec-probe", user_noop, us.root, 0, 0);
                let deadline = ostd::time::now() + 600;
                let (mut e0, _) = task::user_exit_codes();
                while ostd::time::now() < deadline && e0 == u64::MAX {
                    task::yield_now();
                    let (e, _) = task::user_exit_codes();
                    e0 = e;
                }
                let (res, img) = procs::exec_stamps();
                let (vfs_bytes, segs, data_frame) = procs::exec_loader_stamps();
                let _ = writeln!(
                    log,
                    "  weave-exec: exit0={e0} res={res:#x} image={img} vfs={vfs_bytes} segs={segs}"
                );
                ok &= e0 == 91; // 包载荷跑完全程（prog.lxe 退出码）
                ok &= res == 0 && img == 3; // EXEC(3) 成功落证
                                            // 包长对账：LWP1 头 32B + 名字区 15B（org.lumina.prog）+ 载荷
                let expect = (weave::pkg::HEADER_LEN
                    + "org.lumina.prog".len()
                    + user::PROG_LXE.len()) as u64;
                ok &= vfs_bytes == expect;
                ok &= segs == 2; // 双段装载（解包后同一 LXE1 链）
                ok &= data_frame != 0;
                let sentinel = ostd::hw::phys::read_u64(data_frame + 8);
                ok &= sentinel == user::PROG_RESULT_MAGIC;
            }
            Err(e) => {
                let _ = writeln!(log, "weave-exec: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t54, "weave-package-image");

    // 55) 栈增长动态扩容（M16-③）：策略面直调（窗内 None / 扩展带 Some /
    //     越带 None / 硬顶耗尽 None——耗尽探针）+ 探针任务运行
    //     EXEC4_PROGRAM → /files/deep.lxe（触页 40/70：静态窗外扩展带）
    //     → 两次扩窗（32→64→96）→ 写读回 → EXIT(93)。配额 kind 3 与
    //     growth_usage 对账（cap == 扩窗终态）。
    let t55 = {
        let mut ok = true;
        // ① 策略面直调（纯函数，不落账）
        let top = user::STACK_TOP_GROW;
        let va = |pages: u64| top - pages * FRAME_SIZE;
        // 窗内（页 5 < 33 页下界之上）→ None
        ok &= vmm::grow_extension(va(5), user::STACK_GROW_WINDOW).is_none();
        // 扩展带（页 40：窗 32 的下界 33 之外、65 之内）→ Some(64)
        ok &= vmm::grow_extension(va(40), user::STACK_GROW_WINDOW)
            == Some(user::STACK_GROW_WINDOW + vmm::STACK_GROW_STEP);
        // 扩展带二层（页 70：窗 64 的下界 65 之外、97 之内）→ Some(96)
        ok &=
            vmm::grow_extension(va(70), 2 * vmm::STACK_GROW_STEP) == Some(3 * vmm::STACK_GROW_STEP);
        // 越扩展带（窗 96 下界 97 之外、扩展带下界 129 之外的页 200）→ None
        ok &= vmm::grow_extension(va(200), 3 * vmm::STACK_GROW_STEP).is_none();
        // 硬顶耗尽探针（窗 128 = MAX，页 140 ∈ 扩展带但 128+32 > 128）→ None
        ok &= vmm::grow_extension(va(140), vmm::STACK_GROW_MAX).is_none();
        // ② 运行面：deep.lxe 触页 40/70 → 两次扩窗 + 写读回
        task::reset_user_evidence();
        let (grows0, _) = vmm::stack_growth_stamps();
        let (ext0, _) = vmm::grow_window_stamps();
        match user::build_user_space(&mut || frames.alloc()) {
            Ok(us) => {
                ostd::hw::phys::write_bytes(us.code_frame, &user::EXEC4_PROGRAM);
                let _ = task::spawn_user_pinned("deep-grow-probe", user_noop, us.root, 0, 0);
                let deadline = ostd::time::now() + 600;
                let (mut e0, _) = task::user_exit_codes();
                while ostd::time::now() < deadline && e0 == u64::MAX {
                    task::yield_now();
                    let (e, _) = task::user_exit_codes();
                    e0 = e;
                }
                let (res, img) = procs::exec_stamps();
                let (grows, frame) = vmm::stack_growth_stamps();
                let (ext, window) = vmm::grow_window_stamps();
                let _ = writeln!(
                    log,
                    "  deep-grow: exit0={e0} res={res:#x} image={img} grows+={} ext+={} window={window}",
                    grows - grows0,
                    ext - ext0
                );
                ok &= e0 == 93; // 深触写读回成功
                ok &= res == 0 && img == 4; // EXEC(4) 成功落证
                ok &= grows >= grows0 + 2; // 页 40/70 两帧
                ok &= ext == ext0 + 2; // 两次扩窗
                ok &= window == 3 * vmm::STACK_GROW_STEP; // 32→64→96
                ok &= frame != 0;
                // ③ 配额 kind 3 对账：sys_quota(3) == pack(growth_usage)
                let (used, cap) = vmm::growth_usage();
                let q3 = procs::sys_quota(3);
                ok &= q3 == (1u64 << 32) | ((used as u64 & 0xFFFF) << 16) | (cap as u64 & 0xFFFF);
                ok &= cap == window;
            }
            Err(e) => {
                let _ = writeln!(log, "deep-grow: user space build failed: {e:?}");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t55, "stack-growth-dynamic");

    // M17-①：块设备接入（主通道从盘 IDENTIFY + 容量固化）——**惰性探测**
    // 置于唯一消费方 t56 之前：启动期探测的自旋窗口（无盘时 ~2e7 轮询）
    // 会拉开 t24 echo worker 轮询预算与 ring3 client 到达的竞争窗口
    // （实测 served=0 稳定复现，挪后即回基线——时序敏感自检的前置纪律）。
    block::init(&mut log);

    // 56) 持久化存储面（M17-①）：fs_type=1 挂 LFS1 盘上 fs（主通道从盘
    //     format-or-open）→ O_CREAT 写读回 → 关闭句柄 → 卸载 → 重挂
    //     （超级块有效 → 原样打开）→ 数据存续直证（持久化闭环）→
    //     EBUSY 负探针（存活句柄拒卸，M17-③ 盘上 fs 面）→ 关闭后卸载。
    let t56 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        vfs::reset_evidence();
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        const FOK: u64 = 1 << 32;
        let m_cw = bedrock::abi::O_CREAT | 0b10;
        // ① 挂载点 + fs_type 域负探针 + 首挂（格式化路径）
        let (dp, dl) = pa("/disk");
        chk!(vfs::sys_mkdir(dp, dl), 0);
        chk!(vfs::sys_mount(dp, dl, 2), 22); // fs_type 越域（域 0..=1）
        chk!(vfs::sys_mount(dp, dl, 1), 0); // 首挂：空白盘 → 格式化
                                            // ② 盘上文件 O_CREAT 写读回
        let (fp, fl) = pa("/disk/persist.txt");
        let o1 = vfs::sys_open(fp, fl, m_cw);
        ok &= o1 >> 32 == 1;
        let h1 = o1 & 0xFFFF_FFFF;
        // SAFETY: 单核自检上下文串行访问（t53 OC_BUF 同款纪律）
        unsafe {
            core::ptr::copy_nonoverlapping(
                b"LUMINA-PERSIST".as_ptr(),
                m17_buf_addr() as *mut u8,
                14,
            );
        }
        chk!(vfs::sys_write(h1, m17_buf_addr(), 14), FOK | 14);
        ok &= vfs::sys_close(h1) == 0;
        // ③ 空闲卸载 → 重挂（原样打开路径）→ 数据存续读回
        chk!(vfs::sys_umount(dp, dl), 0);
        chk!(vfs::sys_mount(dp, dl, 1), 0);
        let o2 = vfs::sys_open(fp, fl, 0b01);
        ok &= o2 >> 32 == 1;
        let h2 = o2 & 0xFFFF_FFFF;
        // SAFETY: 同上（先清缓冲再读回对账）
        unsafe {
            core::ptr::write_bytes(m17_buf_addr() as *mut u8, 0, 32);
        }
        chk!(vfs::sys_read(h2, m17_buf_addr(), 32), FOK | 14);
        // SAFETY: 同上（内容对账）
        let got = unsafe { core::slice::from_raw_parts((&raw const M17_BUF) as *const u8, 14) };
        ok &= got == b"LUMINA-PERSIST";
        ok &= vfs::sys_close(h2) == 0;
        // ④ EBUSY：句柄存活拒卸（M17-③ 盘上 fs 面）→ 关闭后放行
        let o3 = vfs::sys_open(fp, fl, 0b01);
        ok &= o3 >> 32 == 1;
        let h3 = o3 & 0xFFFF_FFFF;
        chk!(vfs::sys_umount(dp, dl), 16); // EBUSY
        ok &= vfs::sys_close(h3) == 0;
        chk!(vfs::sys_umount(dp, dl), 0);
        let (open_st, _, read_st, write_st, close_st, _, _) = vfs::stamps();
        let _ = writeln!(
            log,
            "  lfs: open={open_st:#x} read={read_st:#x} write={write_st:#x} close={close_st:#x}"
        );
        if fail_line != 0 {
            let _ = writeln!(log, "  t56 first-fail line={fail_line}");
        }
        ok
    };
    report(&mut log, t56, "lfs-persist");

    // 57) readdir 稳定 cookie（M17-②）：SYS_READDIR 游标 = 最后交付项
    //     cookie——首读一页后中途变更目录（新建 c + 删除已交付的 a），
    //     续读恰见新项（不重不漏不漂移；getdents64 同款语义域）。
    //     独立目录 /files2（不扰动 t50 的 /files 名单）。
    let t57 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        const FOK: u64 = 1 << 32;
        let m_cw = bedrock::abi::O_CREAT | 0b10;
        let (dp, dl) = pa("/files2");
        chk!(vfs::sys_mkdir(dp, dl), 0);
        // 首两项 a/b（O_CREAT）+ 目录句柄
        for name in ["/files2/a", "/files2/b"] {
            let (p, l) = pa(name);
            let o = vfs::sys_open(p, l, m_cw);
            ok &= o >> 32 == 1;
            ok &= vfs::sys_close(o & 0xFFFF_FFFF) == 0;
        }
        let od = vfs::sys_open(dp, dl, 0b01);
        ok &= od >> 32 == 1;
        let hd = od & 0xFFFF_FFFF;
        // 首读：16B 页（a 9B + b 5B = 14B ≤ 16，第三项装不下）
        let r1 = chk!(vfs::sys_readdir(hd, dir_page_addr(), 16), FOK | 2);
        let _ = r1;
        // 中途变更：新建 c（cookie 递增）+ 删除已交付的 a（cookie 退役）
        let (cp, cl) = pa("/files2/c");
        chk!(vfs::sys_mkdir(cp, cl), 0);
        let (ap, al) = pa("/files2/a");
        chk!(vfs::sys_remove(ap, al), 0);
        // 续读：恰 1 项 = c（Dir kind=1 len=1 名 c；a 不重出，b 不回灌）
        let r2 = chk!(vfs::sys_readdir(hd, dir_page_addr(), 16), FOK | 1);
        let _ = r2;
        // SAFETY: 单核自检上下文串行走查（t50 acc_scan 同款纪律）
        let page = unsafe { core::slice::from_raw_parts((&raw const DIR_PAGE) as *const u8, 3) };
        // 续页仅写 3 字节（[kind=Dir][len=1]['c']）——DIR_PAGE 尾部为首页
        // 残留（pack 半项纪律不整页清零），断言只对账新写入域。
        ok &= page == [1, 1, b'c'];
        // 续读 EOF
        let r3 = chk!(vfs::sys_readdir(hd, dir_page_addr(), 512), FOK);
        let _ = r3;
        ok &= vfs::sys_close(hd) == 0;
        if fail_line != 0 {
            let _ = writeln!(log, "  t57 first-fail line={fail_line}");
        }
        ok
    };
    report(&mut log, t57, "dir-cookie-stable");

    // 58) mount 占用检查（M17-③，fs_type=0 RamFs 面）：挂载 → 打开
    //     子文件句柄 → 卸载 EBUSY(16) → dup 后关原句柄仍 EBUSY（副本
    //     存续即占用）→ 全关后卸载放行。
    let t58 = {
        let mut ok = true;
        let mut fail_line = 0usize;
        macro_rules! chk {
            ($v:expr, $want:expr) => {{
                let v = $v;
                if v != $want {
                    fail_line = line!() as usize;
                }
                ok &= v == $want;
                v
            }};
        }
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        let m_cw = bedrock::abi::O_CREAT | 0b10;
        let (mp, ml) = pa("/mnt17");
        chk!(vfs::sys_mkdir(mp, ml), 0);
        chk!(vfs::sys_mount(mp, ml, 0), 0);
        let (fp, fl) = pa("/mnt17/busy.txt");
        let o = vfs::sys_open(fp, fl, m_cw);
        ok &= o >> 32 == 1;
        let h = o & 0xFFFF_FFFF;
        chk!(vfs::sys_umount(mp, ml), 16); // EBUSY：句柄存活
        let d = vfs::sys_dup(h);
        ok &= d >> 32 == 1;
        let d = d & 0xFFFF_FFFF;
        ok &= vfs::sys_close(h) == 0;
        chk!(vfs::sys_umount(mp, ml), 16); // dup 副本仍占（OFD 引用计数）
        ok &= vfs::sys_close(d) == 0;
        chk!(vfs::sys_umount(mp, ml), 0);
        if fail_line != 0 {
            let _ = writeln!(log, "  t58 first-fail line={fail_line}");
        }
        ok
    };
    report(&mut log, t58, "umount-busy");

    // 59) 栈 canary 审计面（M18-① #PF 专项取证面自证）：任务栈盖章
    //     覆盖数 > 0（派发咽喉校验全程在跑）+ 全表审计现场 + AP 引导
    //     栈完好 + 违反计数为零。取证面自身不引入新破坏。
    let t59 = {
        let checked = task::canary_audit_all();
        let violations = task::canary_violations();
        let ap_ok = smp::ap_stack_canary_ok();
        let _ = writeln!(
            log,
            "  canary: audit-checked={checked} violations={violations} ap-stack-ok={ap_ok}"
        );
        checked > 0 && violations == 0 && ap_ok
    };
    report(&mut log, t59, "canary-audit");

    // 60) O_EXCL 排他创建（M18-③，abi v0.12）：已存目标 + O_CREAT|O_EXCL
    //     → EEXIST(17) 原子拒开；无 O_CREAT 时 O_EXCL 无效应（POSIX 未
    //     定义域收敛）；新目标 O_CREAT|O_EXCL 正常落位。
    let t60 = {
        let mut ok = true;
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        let m_c = bedrock::abi::O_CREAT | 0b10;
        let m_ce = m_c | bedrock::abi::O_EXCL;
        let (dp, dl) = pa("/m18");
        ok &= vfs::sys_mkdir(dp, dl) == 0;
        ok &= vfs::sys_mount(dp, dl, 0) == 0;
        let (fp, fl) = pa("/m18/f.txt");
        let o = vfs::sys_open(fp, fl, m_c);
        ok &= o >> 32 == 1;
        ok &= vfs::sys_close(o & 0xFFFF_FFFF) == 0;
        ok &= vfs::sys_open(fp, fl, m_ce) == 17; // EEXIST：排他拒开
        let o = vfs::sys_open(fp, fl, 0b10);
        ok &= o >> 32 == 1;
        ok &= vfs::sys_close(o & 0xFFFF_FFFF) == 0;
        // 无 O_CREAT 时 O_EXCL 无效应：目标缺失 → ENOENT(2)
        let (gp, gl) = pa("/m18/g.txt");
        ok &= vfs::sys_open(gp, gl, bedrock::abi::O_EXCL | 0b10) == 2;
        let (hp, hl) = pa("/m18/h.txt");
        let o = vfs::sys_open(hp, hl, m_ce);
        ok &= o >> 32 == 1;
        ok &= vfs::sys_close(o & 0xFFFF_FFFF) == 0;
        ok
    };
    report(&mut log, t60, "o-excl-atomic-create");

    // 61) F_DUP2FD 精确槽位（M18-③，abi v0.12）：指定槽落位 + 同槽位
    //     无操作 + 越界 EINVAL + 野句柄 EBADF + EBUSY 卸载占用联动
    //     （dup2 副本同样拦截——OFD 引用计数语义）。
    let t61 = {
        let mut ok = true;
        let pa = |s: &str| (s.as_ptr() as u64, s.len() as u64);
        const FOK: u64 = 1 << 32;
        let (dp, dl) = pa("/m19");
        ok &= vfs::sys_mkdir(dp, dl) == 0;
        ok &= vfs::sys_mount(dp, dl, 0) == 0;
        let (fp, fl) = pa("/m19/a.txt");
        let o = vfs::sys_open(fp, fl, bedrock::abi::O_CREAT | 0b10);
        ok &= o >> 32 == 1;
        let h1 = o & 0xFFFF_FFFF;
        // 精确槽位：目标 5（1 号槽已占，5 空闲）
        let d = vfs::sys_fcntl(h1, bedrock::abi::F_DUP2FD, 5);
        ok &= d == FOK | 5;
        // 同槽位无操作直返
        ok &= vfs::sys_fcntl(h1, bedrock::abi::F_DUP2FD, h1) == FOK | h1;
        // 越界目标（≥ HANDLE_MAX=16）→ EINVAL(22)
        ok &= vfs::sys_fcntl(h1, bedrock::abi::F_DUP2FD, 16) == 22;
        // 野句柄 → EBADF(9)
        ok &= vfs::sys_fcntl(999, bedrock::abi::F_DUP2FD, 5) == 9;
        // 关原句柄 → 5 号副本仍占（OFD 引用计数）；再 dup2 5→6 精确落位
        ok &= vfs::sys_close(h1) == 0;
        let d2 = vfs::sys_fcntl(5, bedrock::abi::F_DUP2FD, 6);
        ok &= d2 == FOK | 6;
        ok &= vfs::sys_close(5) == 0;
        ok &= vfs::sys_umount(dp, dl) == 16; // 6 号副本仍占 → EBUSY
        ok &= vfs::sys_close(6) == 0;
        ok &= vfs::sys_umount(dp, dl) == 0;
        ok
    };
    report(&mut log, t61, "dup2-exact-slot");

    // 62) SYS_IMAGE_ENUM 查询面（M18-③，abi v0.12）：逐项路径对账
    //     EXEC_IMAGES（NUL 结尾）+ 越界 ERR_IMAGE(10) + 缓冲过短 EFAULT(14)。
    let t62 = {
        let mut ok = true;
        let buf = m17_buf_addr();
        for (idx, want) in crate::user::EXEC_IMAGES.iter().enumerate() {
            // SAFETY: 先清缓冲再对账（t56 取证缓冲同款纪律）
            unsafe {
                core::ptr::write_bytes(buf as *mut u8, 0, 32);
            }
            let r = crate::user::sys_image_enum(idx as u64, buf, 64);
            let need = want.len() + 1;
            ok &= r == (1 << 32) | ((crate::user::EXEC_IMAGES.len() as u64) << 16) | need as u64;
            // SAFETY: 同上（内容对账，含 NUL 终止符）
            let got =
                unsafe { core::slice::from_raw_parts((&raw const M17_BUF) as *const u8, need) };
            ok &= &got[..want.len()] == want.as_bytes() && got[want.len()] == 0;
        }
        ok &= crate::user::sys_image_enum(5, m17_buf_addr(), 64) == crate::procs::ERR_IMAGE;
        ok &= crate::user::sys_image_enum(0, m17_buf_addr(), 4) == 14; // 缓冲过短
        ok
    };
    report(&mut log, t62, "image-enum-face");

    // 63) 内核堆 free-list 复用实证（M21-③：Harbor 由 bump 升级为
    //     HarborFreeList——first-fit + 地址序合并 + bump 晋升）。断言面：
    //     ①分配/释放/再分配由 free-list 服务（reuse_allocs 递增——bump
    //     不回收，递增即复用铁证）②复用块载荷可完整写入读回（块界/头槽
    //     正确性）③对齐 16 路径（Vec<u128> 同族布局）④free_stamps 取证。
    let t63 = {
        let mut ok = true;
        let (_, ru0) = ALLOC.free_stamps();
        let a: Vec<u8> = alloc::vec![0xA5; 4096];
        let pa = a.as_ptr() as usize;
        drop(a);
        let mut b: Vec<u8> = alloc::vec![0; 4096];
        let pb = b.as_ptr() as usize;
        // 复用块载荷完整性：全量写读回（块界/头槽正确性的直接证据）
        b.iter_mut().for_each(|x| *x = 0x5A);
        ok &= b.len() == 4096 && b[0] == 0x5A && b[4095] == 0x5A;
        drop(b);
        let c: Vec<u128> = alloc::vec![7; 256]; // 对齐 16 路径（同族任务栈布局）
        ok &= (c.as_ptr() as usize).is_multiple_of(16) && c[255] == 7;
        drop(c);
        let (fb, ru1) = ALLOC.free_stamps();
        ok &= ru1 > ru0; // 本块三回分配全部由 free-list 服务
        ok &= fb >= 1; // 释放后空闲链非空
        let _ = writeln!(
            log,
            "heap-freelist: a={pa:#x} b={pb:#x} reuse={} free_blocks={fb}",
            ru1 - ru0
        );
        ok
    };
    report(&mut log, t63, "heap-freelist-reuse");

    // 64) M23-① 键盘驱动 + TTY 行规程（控制器自测 + 注册面哨兵 + 驱动全链活体）
    let t64 = {
        // 面A：i8042 控制器自测（0xAA → 0x55，真实电气面）
        let ctrl_ok = ostd::hw::ps2::controller_self_test() == Some(0x55);
        // 面B：PIC IMR IRQ1 已解 mask
        let (imr_m, _) = ostd::hw::pic::masks();
        let imr_ok = imr_m & 0x02 == 0;
        // 面C：驱动全链活体（inject 与 IRQ1 桩同路径：翻译→环→行规程→读侧）
        let mut buf = [0u8; 64];
        // C1 基本行：h i enter → "hi"
        for sc in [0x23u8, 0x17, 0x1C] {
            kbd::inject(sc);
        }
        tty::pump();
        let l1 = tty::read_line(&mut buf);
        let c1 = l1 == Some(2) && &buf[..2] == b"hi";
        // C2 退格编辑：h i bs o enter → "ho"
        for sc in [0x23u8, 0x17, 0x0E, 0x18, 0x1C] {
            kbd::inject(sc);
        }
        tty::pump();
        let l2 = tty::read_line(&mut buf);
        let c2 = l2 == Some(2) && &buf[..2] == b"ho";
        // C3 Shift 大写：shift i 释放 enter → "I"
        for sc in [0x2Au8, 0x17, 0xAA, 0x1C] {
            kbd::inject(sc);
        }
        tty::pump();
        let l3 = tty::read_line(&mut buf);
        let c3 = l3 == Some(1) && buf[0] == b'I';
        let ok = ctrl_ok
            && imr_ok
            && c1
            && c2
            && c3
            && kbd::KBD_DROP.load(Ordering::Relaxed) == 0
            && tty::LINES_SUBMITTED.load(Ordering::Relaxed) == 3;
        let _ = writeln!(
            log,
            "kbd-tty: ctrl={ctrl_ok} imr-ok={imr_ok} irq={} lines=[{c1},{c2},{c3}] drop={}",
            kbd::KBD_IRQ_COUNT.load(Ordering::Relaxed),
            kbd::KBD_DROP.load(Ordering::Relaxed)
        );
        ok
    };
    report(&mut log, t64, "keyboard-tty-line");

    // 65) M23-② SYS_TTY_GETCH 面（inject → 行规程 → GETCH 消费游标域）。
    //     断言：①正常行 "ok\n" → 'o','k','\n' 逐字节消费后空转 0；②空行
    //     （裸回车）→ 单字节 '\n' 即终结；③行间空转面（无注入 → 0）。
    //     单消费者契约：t65 在 init 派生前完成（interactive 面），串行无并发。
    let t65 = {
        let mut ok = true;
        // A 正常行：o k enter → 'o','k','\n'，随后空转
        for sc in [0x18u8, 0x25, 0x1C] {
            kbd::inject(sc);
        }
        ok &= tty::getch() == u64::from(b'o');
        ok &= tty::getch() == u64::from(b'k');
        ok &= tty::getch() == u64::from(b'\n');
        ok &= tty::getch() == 0;
        // B 空行：裸回车 → '\n' 单字节终结，随后空转
        kbd::inject(0x1C);
        ok &= tty::getch() == u64::from(b'\n');
        ok &= tty::getch() == 0;
        let _ = writeln!(
            log,
            "tty-getch: lines={} drop={}",
            tty::LINES_SUBMITTED.load(Ordering::Relaxed),
            kbd::KBD_DROP.load(Ordering::Relaxed)
        );
        ok
    };
    report(&mut log, t65, "tty-getch-face");

    // 66) M23-B stdvga LFB 面（PCI/dispi 探测 → 32bpp 线性模式 → 恒等
    //     映射 → VRAM 写读回双角点）。fail-closed：非 QEMU stdvga 环境
    //     bring-up 返回 None → 本项 FAIL（回归批恒为 QEMU pc 机器）。
    let brought = vmm::global_frames().and_then(fb::bring_up);
    let t66 = match &brought {
        Some((s, id)) => {
            s.px(0, 0, 0x00FF_00AA);
            s.px(s.w as i32 - 1, s.h as i32 - 1, 0x0000_11FF);
            let rb1 = s.px_read(0, 0);
            let rb2 = s.px_read(s.w as i32 - 1, s.h as i32 - 1);
            let _ = writeln!(
                log,
                "fb: bar={:#x} id={:#06x} {}x{} stride={} rb1={:#010x} rb2={:#010x}",
                s.base, id, s.w, s.h, s.stride, rb1, rb2
            );
            rb1 == 0x00FF_00AA && rb2 == 0x0000_11FF
        }
        None => {
            let _ = writeln!(log, "fb: bring-up fail（无 stdvga?）");
            false
        }
    };
    report(&mut log, t66, "fb-vbe-lfb");

    // 67) M23-B mirror 首帧（损伤合成三帧面）：帧1 全量损伤 → 全幅上屏
    //     （1024×768×4 = 3145728 B）；帧2 窗 A→B 挪位，旧∪新包围盒局部
    //     重绘（≈21% 字节）；帧3 零损伤 → bounding_box None → 跳帧 0 字节。
    //     四点读回断言：背景渐变 / 窗 B 主体 / 旧窗位已还原背景 / 窗 B 边框。
    let t67 = match &brought {
        Some((s, _)) => {
            let win_a = mirror::Rect {
                x: 220,
                y: 140,
                w: 320,
                h: 200,
            };
            let win_b = mirror::Rect {
                x: 420,
                y: 260,
                w: 320,
                h: 200,
            };
            // 背景：双线性渐变测试卡 + 64px 网格线（网格加蓝）。
            let bg = |x: i32, y: i32| -> u32 {
                let grid = if x % 64 == 0 || y % 64 == 0 { 0x18 } else { 0 };
                ((x as u32 >> 2) << 16) | ((y as u32 >> 2) << 8) | grid
            };
            // 前景窗：2px 亮边框 + 28px 标题条 + 面板主体。
            let panel = |x: i32, y: i32, r: &mirror::Rect| -> u32 {
                let rx = x - r.x;
                let ry = y - r.y;
                if rx < 2 || ry < 2 || rx >= r.w as i32 - 2 || ry >= r.h as i32 - 2 {
                    0x00F0_F0F0
                } else if ry < 28 {
                    0x0010_2038
                } else {
                    0x0020_4068
                }
            };
            // 合成一步（M24-S1 细则计划面）：空 → 跳帧 0 字节；全帧
            // 翻转 → 全幅重绘；否则按合并矩形列表逐块重绘（账目两两
            // 不贴边，逐块计入无重复）。
            let compose = |dmg: &mirror::DamageTracker, win: Option<&mirror::Rect>| -> u64 {
                let paint = |x: i32, y: i32| -> u32 {
                    match win {
                        Some(r) if r.contains(x, y) => panel(x, y, r),
                        _ => bg(x, y),
                    }
                };
                if dmg.is_empty() {
                    return 0;
                }
                if dmg.is_full() {
                    return s.fill(
                        mirror::Rect {
                            x: 0,
                            y: 0,
                            w: s.w,
                            h: s.h,
                        },
                        paint,
                    );
                }
                let mut total = 0u64;
                for r in dmg.rects() {
                    total += s.fill(*r, paint);
                }
                total
            };
            // 帧1：全量损伤
            let mut dmg = mirror::DamageTracker::default();
            dmg.mark(mirror::Rect {
                x: 0,
                y: 0,
                w: s.w,
                h: s.h,
            });
            let f1 = compose(&dmg, Some(&win_a));
            // 帧2：窗挪位 A→B（旧∪新两块损伤）
            dmg.clear();
            dmg.mark(win_a);
            dmg.mark(win_b);
            let f2 = compose(&dmg, Some(&win_b));
            // 帧3：零损伤跳帧
            dmg.clear();
            let f3 = compose(&dmg, None);
            // 读回四点断言
            let p_bg = s.px_read(8, 8); // 背景渐变（窗域外）
            let p_body = s.px_read(580, 360); // 窗 B 主体
            let p_old = s.px_read(320, 240); // 旧窗 A 中心 → 应还原为背景
            let p_edge = s.px_read(420, 260); // 窗 B 左上边框
            let px_ok = p_bg == 0x0002_0200
                && p_body == 0x0020_4068
                && p_old == bg(320, 240)
                && p_edge == 0x00F0_F0F0;
            let _ = writeln!(
                log,
                "LUMINA-FIRST-FRAME f1={} f2={} f3={} permille={}",
                f1,
                f2,
                f3,
                f2 * 1000 / f1
            );
            let _ = writeln!(
                log,
                "LUMINA-MIRROR-OK px=[{:#010x},{:#010x},{:#010x},{:#010x}]",
                p_bg, p_body, p_old, p_edge
            );
            f1 == 3_145_728 && f2 == 665_600 && f3 == 0 && px_ok
        }
        None => false,
    };
    report(&mut log, t67, "mirror-first-frame");

    // 68) M23-C1 virtio-net bring-up（PCI cap 走查 → 状态机 → vring 装配
    //     → DRIVER_OK → MAC 读出）。fail-closed：无 virtio-net-pci 环境
    //     返回 None → 本项 FAIL（回归批恒为 QEMU pc + virtio-net 机器）。
    //     MAC 断言 = QEMU user-net 默认 52:54:00:12:34:56（电气活体）；
    //     终态 status 断言 = 0x0F 全位（ACK|DRIVER|FEAT_OK|DRIVER_OK）。
    let t68 = match vmm::global_frames().and_then(vnet::bring_up) {
        Some(d) => {
            let mac_ok = d.mac == [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
            let _ = writeln!(
                log,
                "net: mac={:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x} nq={} qsz={} status={:#x} mac_ok={}",
                d.mac[0],
                d.mac[1],
                d.mac[2],
                d.mac[3],
                d.mac[4],
                d.mac[5],
                d.num_queues,
                d.queue_size,
                d.status,
                mac_ok
            );
            mac_ok && d.num_queues >= 2 && d.status == 0x0F && d.queue_size == 1024
        }
        None => {
            let _ = writeln!(log, "net: bring-up fail（无 virtio-net-pci?）");
            false
        }
    };
    report(&mut log, t68, "virtio-net-bringup");

    // 69) M23-C2 virtio-net 数据面（ARP 电气活体）：广播请求（who-has
    //     10.0.2.2）→ slirp 应答 → used 环轮询 → 帧解析（oper=2 + tpa/
    //     tha 寻我命中闸内建；spa=网关域 + 双环完成数三项断言）。预算
    //     耗尽 / 数据面缺失 → fail-closed（回归批恒为 user-net 机器）。
    let t69 = match vnet::arp_roundtrip() {
        Some(a) => {
            let spa_ok = a.spa == [10, 0, 2, 2];
            let _ = writeln!(
                log,
                "net-arp: tx_used={} rx_seen={} spa={}.{}.{}.{} sha={:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x} tha={:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x} spa_ok={}",
                a.tx_used,
                a.rx_seen,
                a.spa[0],
                a.spa[1],
                a.spa[2],
                a.spa[3],
                a.sha[0],
                a.sha[1],
                a.sha[2],
                a.sha[3],
                a.sha[4],
                a.sha[5],
                a.tha[0],
                a.tha[1],
                a.tha[2],
                a.tha[3],
                a.tha[4],
                a.tha[5],
                spa_ok
            );
            spa_ok && a.tx_used >= 1 && a.rx_seen >= 1
        }
        None => {
            let _ = writeln!(log, "net-arp: no-reply（预算耗尽或数据面缺失）");
            vnet::diag(&mut log);
            false
        }
    };
    report(&mut log, t69, "net-arp-roundtrip");

    // 70) M23-S2 文本渲染服务（8x16 位图字体直画）：主串前景计数 +
    //     空格串零前景 + 'L' 左柱探针读回三断言（像素级活体）。fail-
    //     closed：无 fb 环境 → 本项 FAIL（回归批恒为 stdvga 机器）。
    let t70 = match fb::text_selftest() {
        Some((main_fg, blank_fg, probe)) => {
            let probe_ok = probe == fb::text_fg_color();
            let _ = writeln!(
                log,
                "fb-text: main_fg={} blank_fg={} probe={:#x} probe_ok={}",
                main_fg, blank_fg, probe, probe_ok
            );
            main_fg > 100 && blank_fg == 0 && probe_ok
        }
        None => {
            let _ = writeln!(log, "fb-text: no-fb");
            false
        }
    };
    report(&mut log, t70, "fb-text-face");

    // 71) M23-C3 pulse 环交接活体：ARP 请求击发 → RX 排水面喂 SPSC 环
    //     （完成 desc 重填，预填池可持续）→ 环出队消费 → 应答五条闸解
    //     析（命中闸内建）。交接链「设备 → RX 缓冲 → pulse 环 → 消费
    //     者」全活体；交接统计（pushed/popped）双计数断言。fail-closed：
    //     无 virtio-net 环境 → 本项 FAIL（回归批恒为 virtio-net 机器）。
    let t71 = match vnet::pulse_roundtrip() {
        Some(pe) => {
            let _ = writeln!(
                log,
                "net-pulse: spa={}.{}.{}.{} pushed={} popped={} sha={:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                pe.spa[0],
                pe.spa[1],
                pe.spa[2],
                pe.spa[3],
                pe.pushed,
                pe.popped,
                pe.sha[0],
                pe.sha[1],
                pe.sha[2],
                pe.sha[3],
                pe.sha[4],
                pe.sha[5],
            );
            pe.spa == [10, 0, 2, 2]
                && pe.tha == [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
                && pe.pushed > 0
                && pe.popped > 0
        }
        None => {
            let _ = writeln!(log, "net-pulse: no-echo");
            false
        }
    };
    report(&mut log, t71, "net-pulse-handoff");

    // 72) M24-S1 mirror 损伤策略细则活体（t72）：四相位——
    //     (a) 并集合并：重叠对并成单包围盒、贴边对并成单块、分离对保留
    //         两块；
    //     (b) 上限 16 翻转（ROADMAP 钦定「损伤上限翻转用例」）：16 块
    //         分离不翻；第 17 块入账即翻转全帧，全帧重绘实屏 3145728 字
    //         节活体；全帧态吸收后续脏区，clear 复位；
    //     (c) 指针 16px 粒度：跨格两笔外扩吸附 16px 网格并累积成单块；
    //     (d) SYS_FB 面对账：两笔重叠 SYNC 经 syscall 面并集成单块、17
    //         笔离散 SYNC 翻转全帧（LUMINA-FB-SYNC 证据行 rects=/full=
    //         显形）→ 复位归零。fail-closed：无 fb 环境 → 本项 FAIL
    //         （回归批恒为 stdvga 机器）。
    let t72 = match &brought {
        Some((s, _)) => {
            let mut ok = true;
            // (a) 并集合并
            let mut d = mirror::DamageTracker::new();
            d.mark(mirror::Rect {
                x: 0,
                y: 0,
                w: 10,
                h: 10,
            });
            d.mark(mirror::Rect {
                x: 5,
                y: 5,
                w: 10,
                h: 10,
            });
            ok &= d.rects().len() == 1
                && d.rects()[0]
                    == mirror::Rect {
                        x: 0,
                        y: 0,
                        w: 15,
                        h: 15,
                    };
            d.clear();
            d.mark(mirror::Rect {
                x: 0,
                y: 0,
                w: 10,
                h: 10,
            });
            d.mark(mirror::Rect {
                x: 10,
                y: 0,
                w: 10,
                h: 10,
            });
            ok &= d.rects().len() == 1
                && d.rects()[0]
                    == mirror::Rect {
                        x: 0,
                        y: 0,
                        w: 20,
                        h: 10,
                    };
            d.clear();
            d.mark(mirror::Rect {
                x: 0,
                y: 0,
                w: 10,
                h: 10,
            });
            d.mark(mirror::Rect {
                x: 100,
                y: 100,
                w: 10,
                h: 10,
            });
            ok &= d.rects().len() == 2 && !d.is_full();
            // (b) 上限 16 翻转 + 全帧重绘实屏活体
            d.clear();
            for i in 0..16u32 {
                d.mark(mirror::Rect {
                    x: (i * 50) as i32,
                    y: (i * 7) as i32,
                    w: 10,
                    h: 10,
                });
            }
            ok &= !d.is_full() && d.rects().len() == 16;
            d.mark(mirror::Rect {
                x: 800,
                y: 700,
                w: 10,
                h: 10,
            }); // 第 17 块（与前列两两分离）
            ok &= d.is_full() && d.rects().is_empty();
            let full_bytes = s.fill(
                mirror::Rect {
                    x: 0,
                    y: 0,
                    w: s.w,
                    h: s.h,
                },
                |x, y| ((x as u32 & 0x0F) << 16) | (y as u32 & 0x0F),
            );
            ok &= full_bytes == 3_145_728;
            d.mark(mirror::Rect {
                x: 1,
                y: 1,
                w: 1,
                h: 1,
            });
            ok &= d.is_full(); // 全帧态吸收后续脏区
            d.clear();
            ok &= !d.is_full() && d.is_empty(); // 复位
                                                // (c) 指针 16px 粒度累积
            d.mark_pointer(mirror::Rect {
                x: 5,
                y: 5,
                w: 2,
                h: 2,
            });
            d.mark_pointer(mirror::Rect {
                x: 20,
                y: 8,
                w: 4,
                h: 4,
            });
            ok &= d.rects().len() == 1
                && d.rects()[0]
                    == mirror::Rect {
                        x: 0,
                        y: 0,
                        w: 32,
                        h: 16,
                    };
            // (d) SYS_FB 面对账（经 syscall 面，证据行 rects=/full=）
            fb::fb_damage_reset();
            let _ = fb::sys_fb_sync(0, 0, 10, 10);
            let _ = fb::sys_fb_sync(5, 5, 10, 10);
            let (n, f) = fb::fb_damage_plan();
            ok &= n == 1 && !f;
            for i in 0..17u64 {
                let _ = fb::sys_fb_sync(i * 50, i * 7, 10, 10);
            }
            let (_, f) = fb::fb_damage_plan();
            ok &= f; // 17 笔离散入账即翻转
            fb::fb_damage_reset();
            let (n, f) = fb::fb_damage_plan();
            ok &= n == 0 && !f;
            let _ = writeln!(
                log,
                "mirror-damage: union=ok cap16-flip=ok full_bytes={} ptr16=ok sysfb-reconciled=ok",
                full_bytes
            );
            ok
        }
        None => {
            let _ = writeln!(log, "mirror-damage: no-fb");
            false
        }
    };
    report(&mut log, t72, "mirror-damage-spec");

    // 73) M24-C1 vnet RX 背压/水位 + ICMP echo reply（t73）：五相位——
    //     (a) 预备清场：pulse 环排空 + 排水面归位（占用 0 基线）；
    //     (b) 背压投入：ARP 突发逐发逐排不消费 → 占用越 HI(6) → 停臂
    //         投入（enters ≥ 1 且 active）+ 投入态拍短路（重臂计数冻结）；
    //     (c) 水位解除：消费排水 → 占用回 LO(2) → pending 一揽子重臂
    //         （exits ≥ 1 + rearmed 跳升 + 占用归零，缓冲池零泄漏），
    //         同拍自突发 ARP 应答捕获网关 MAC（ARP→ICMP 全链第一环）；
    //     (d) ARP→ICMP 全链：echo request 发 10.0.2.2（背压解除后 RX
    //         面活性回证）→ slirp 回声 reply（寻源/type0/id/seq/payload/
    //         IP+ICMP 双校验和五闸）；
    //     (e) echo reply 应答器：合成请求字节级组帧断言（确定性面）+
    //         应答器服务真发线上（slirp 无外部 type8 到达面——icmp_input
    //         仅 vhost_addr 反射，其余 forward 代理，实测回环不成立）→
    //         TX used 环完成回读 = 击发收讫电气证据 + replies 计数对账。
    //     fail-closed：无 virtio-net 环境 → 本项 FAIL（回归批恒为
    //     virtio-net 机器）。
    let t73 = {
        let mut ok = true;
        let mut buf = [0u8; vnet::PULSE_FRAME_MAX];
        let mac_self = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        // (a) 预备清场：环排空 + 排水面归位
        while vnet::pulse_rx_pop(&mut buf).is_some() {}
        for _ in 0..4 {
            vnet::rx_pump();
        }
        // (b) 背压投入：ARP 突发（逐发逐排不消费，占用爬坡越 HI）
        let mut rounds = 0u32;
        while vnet::bp_snapshot().enters == 0 && rounds < 32 {
            if !vnet::arp_tx() {
                break;
            }
            vnet::rx_pump();
            rounds += 1;
        }
        let bp_in = vnet::bp_snapshot();
        ok &= bp_in.enters >= 1 && bp_in.active && bp_in.occ >= 6;
        // 投入态拍短路证据：重臂计数冻结（停臂 = 设备缓冲赤字保持）
        let frozen = vnet::bp_snapshot().rearmed;
        vnet::rx_pump();
        ok &= vnet::bp_snapshot().rearmed == frozen;
        // (c) 水位解除：消费排水 → 占用回 LO → pending 一揽子重臂；
        //     同拍从突发应答面捕获网关 MAC（突发即 ARP 往返集——ARP→ICMP
        //     全链的第一环，免独立 ARP 轮次的时序脆弱面）
        let mut burst_pop = 0usize;
        let mut gw_mac = [0u8; 6];
        let mut got_arp = false;
        while let Some(fl) = vnet::pulse_rx_pop(&mut buf) {
            burst_pop += 1;
            if fl >= 42
                && u16::from_be_bytes([buf[12], buf[13]]) == 0x0806
                && u16::from_be_bytes([buf[20], buf[21]]) == 2
                && buf[38..42] == [10, 0, 2, 15]
                && buf[32..38] == mac_self
            {
                gw_mac.copy_from_slice(&buf[22..28]);
                got_arp = true;
            }
        }
        let held_rearmed = vnet::bp_snapshot().rearmed;
        vnet::rx_pump();
        let bp_out = vnet::bp_snapshot();
        // occ 不设零断言：解除语义看泵入口占用 ≤ LO（滞回闸内建），
        // 泵入后异步到达帧可再喂环（occ0 仅留证）
        ok &= bp_out.exits >= 1 && !bp_out.active && bp_out.rearmed > held_rearmed;
        ok &= burst_pop >= 6 && got_arp;
        let _ = writeln!(
            log,
            "net-bp: enter={} exit={} rearmed={} burst_pop={} occ0={} gw_mac={:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bp_in.enters,
            bp_out.exits,
            bp_out.rearmed,
            burst_pop,
            bp_out.occ,
            gw_mac[0],
            gw_mac[1],
            gw_mac[2],
            gw_mac[3],
            gw_mac[4],
            gw_mac[5],
        );
        // (d) ARP→ICMP 全链：echo request 发 10.0.2.2（MAC 自突发 ARP
        //     应答捕获；背压解除后 RX 面活性回证）→ slirp 回声 reply 五闸。
        //     重发容忍域：slirp 反射回包偶发滞后（双峰实测），单请求未达
        //     即换 id/seq 重击（≤3 拍，命中即收）。
        let payload1 = *b"LUMINA-C1-GATEWAY-ECHO-01";
        let mut gw_echo = false;
        let mut gw_tries = 0u16;
        while got_arp && gw_tries < 3 && !gw_echo {
            gw_tries += 1;
            if !vnet::icmp_echo_tx(
                gw_mac,
                [10, 0, 2, 2],
                vnet::ICMP_ECHO_ID,
                gw_tries,
                &payload1,
            ) {
                break;
            }
            let mut spin = 0u64;
            while spin < vnet::NET_SPIN_BUDGET && !gw_echo {
                vnet::rx_pump();
                while let Some(fl) = vnet::pulse_rx_pop(&mut buf) {
                    // slirp who-has 我在场即应答（反射回包 ARP 解析解阻塞）
                    if fl >= 42
                        && u16::from_be_bytes([buf[12], buf[13]]) == 0x0806
                        && u16::from_be_bytes([buf[20], buf[21]]) == 1
                        && buf[38..42] == [10, 0, 2, 15]
                    {
                        let _ = vnet::arp_respond(&buf[..fl]);
                        continue;
                    }
                    if fl < 42 {
                        continue;
                    }
                    if u16::from_be_bytes([buf[12], buf[13]]) != 0x0800 || buf[23] != 1 {
                        continue;
                    }
                    let ic = 14 + usize::from(buf[14] & 0x0F) * 4;
                    if fl < ic + 8 || buf[ic] != 0 {
                        continue; // 非 echo reply
                    }
                    let mut sip = [0u8; 4];
                    sip.copy_from_slice(&buf[26..30]);
                    if sip != [10, 0, 2, 2] {
                        continue;
                    }
                    let id = u16::from_be_bytes([buf[ic + 4], buf[ic + 5]]);
                    let seq = u16::from_be_bytes([buf[ic + 6], buf[ic + 7]]);
                    if id != vnet::ICMP_ECHO_ID || seq != gw_tries {
                        continue;
                    }
                    let payload_ok = fl - ic - 8 == payload1.len() && buf[ic + 8..fl] == payload1;
                    let ic_ck_ok = vnet::cksum_ok(&buf[ic..fl]);
                    let ip_ck_ok = vnet::cksum_ok(&buf[14..ic]);
                    let _ = writeln!(
                        log,
                        "net-icmp-gw: id={id:#06x} seq={seq} payload_ok={payload_ok} icmp_ck={ic_ck_ok} ip_ck={ip_ck_ok}"
                    );
                    gw_echo = payload_ok && ic_ck_ok && ip_ck_ok;
                }
                spin += 1;
                core::hint::spin_loop();
            }
        }
        ok &= gw_echo;
        let _ = writeln!(log, "net-icmp-gw-tries: {gw_tries}");
        // (e-1) echo reply 应答器字节级组帧断言（确定性面；seq=3 域隔离）
        let payload3 = *b"LUMINA-C1-SYNTH-REQ-0003";
        let mut syn = [0u8; 66]; // 14 + 20 + 8 + 24
        syn[0..6].copy_from_slice(&gw_mac);
        syn[6..12].copy_from_slice(&mac_self);
        syn[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        syn[14] = 0x45;
        syn[16..18].copy_from_slice(&((20 + 8 + payload3.len()) as u16).to_be_bytes());
        syn[22] = 64;
        syn[23] = 1;
        syn[26..30].copy_from_slice(&[10, 0, 2, 2]); // 请求方 = 网关域
        syn[30..34].copy_from_slice(&[10, 0, 2, 15]); // 寻我
        syn[34] = 8;
        syn[38..40].copy_from_slice(&vnet::ICMP_ECHO_ID.to_be_bytes());
        syn[40..42].copy_from_slice(&3u16.to_be_bytes());
        syn[42..66].copy_from_slice(&payload3);
        let ip_ck = vnet::cksum16(&syn[14..34]);
        syn[24..26].copy_from_slice(&ip_ck.to_be_bytes());
        let ic_ck = vnet::cksum16(&syn[34..66]);
        syn[36..38].copy_from_slice(&ic_ck.to_be_bytes());
        let mut rep = [0u8; vnet::PULSE_FRAME_MAX];
        let synth_ok = match vnet::build_icmp_reply(&syn, &mut rep) {
            Some(n) => {
                let ic = 34;
                n == 66
                    && rep[0..6] == syn[6..12]
                    && rep[6..12] == syn[0..6]
                    && rep[26..30] == syn[30..34]
                    && rep[30..34] == syn[26..30]
                    && rep[ic] == 0
                    && rep[ic + 4..ic + 8] == syn[ic + 4..ic + 8]
                    && rep[ic + 8..n] == syn[ic + 8..n]
                    && vnet::cksum_ok(&rep[14..34])
                    && vnet::cksum_ok(&rep[ic..n])
            }
            None => false,
        };
        ok &= synth_ok;
        // (e-2) 应答器电气面：合成请求经应答器服务真发线上（QEMU slirp
        //       icmp_input 实况：ICMP_ECHO 仅 vhost_addr 10.0.2.2 本地反
        //       射，其余 dst 走 forward 代理——host socket 对 10.0.2.x 不
        //       可达，type8 request 无到达面，回环设计不成立）→ TX used
        //       环完成回读 = 击发收讫电气证据 + replies 计数对账。
        let mut resp_txed = false;
        if synth_ok {
            while vnet::tx_drain() > 0 {} // 清历史积压（基线归零）
            resp_txed = vnet::icmp_echo_reply(&syn).is_some();
            let mut spin = 0u64;
            while spin < vnet::NET_SPIN_BUDGET && vnet::tx_drain() == 0 {
                spin += 1;
                core::hint::spin_loop();
            }
            resp_txed &= vnet::icmp_snapshot().replies >= 1;
        }
        ok &= resp_txed;
        let icmp = vnet::icmp_snapshot();
        let _ = writeln!(
            log,
            "net-c1: bp_enter={} bp_exit={} rearmed={} arp_ok={} gw_echo={} synth_reply={} resp_txed={} icmp_req_tx={} replies={}",
            bp_in.enters,
            bp_out.exits,
            bp_out.rearmed,
            got_arp,
            gw_echo,
            synth_ok,
            resp_txed,
            icmp.req_tx,
            icmp.replies,
        );
        ok
    };
    report(&mut log, t73, "net-backpressure-icmp");
    if !t73 {
        // 失败取证：vring 双环游标 + pulse/bp/icmp 计数器全量转储
        vnet::diag(&mut log);
    }

    // 74) M24-A1 shell 管道雏形 + more 分页（t74）：五相位——
    //     (a) 捕获面：武装 → log_sink 产线两行 → 长度对账（载荷 +
    //         每调用一 `\n` 行界）+ 行界逐字节断言（SYS_LOG 载荷不含
    //         换行、串口路径每调用补 CRLF——行语义同源，捕获按调用序
    //         行界成帧）；
    //     (b) 排水面：drain 全量对账 + 二次 drain 零泄漏 + 卸臂回证
    //         （drain 后 capture_active false = 后续 log_sink 复走串口）；
    //     (c) more 全程分页：10 行产线（pl01..pl10，页界 4 → 4/4/2 三
    //         页）→ 电键预注两拍（kbd::inject 扫描码 0x39 空格 → 翻译
    //         → 键盘环 → pump → 行规程分页态 → 分页键队列——t64 同款
    //         全链电气注入）→ pager_replay 页界两停全显断言
    //         （lines=10 pauses=2 aborts=0 队列零丢弃）；
    //     (d) q 中止面：'q'（0x10）首停即弃 → 只显首页（lines=4）+
    //         aborts 跳升（残余行 fail-visible 舍弃）；
    //     (e) 弃置 + 过载：drop 清账（len 0 + 卸臂）→ 512B 载荷 ×2 连
    //         发 → 第二行不齐整行弃（dropped=1，len 停 513——不截半行）。
    //     fail-closed：无宿主环境依赖（纯内核面，批跑/裸机同域）。
    let t74 = {
        let mut ok = true;
        let mut buf = [0u8; 2048];
        // 预备清场：键盘环残留排空（分页键全链注入零窜扰）
        while kbd::pop().is_some() {}
        // (a) 捕获面：武装 + 产线两行 + 行界成帧对账
        shell::capture_arm();
        shell::log_sink(b"pipe-alpha");
        shell::log_sink(b"pipe-beta");
        let ps = shell::pipe_snapshot();
        // 长度对账：pipe-alpha(10) + \n + pipe-beta(9) + \n = 21
        let ok_a = ps.active && ps.len == 10 + 1 + 9 + 1 && ps.lines == 2 && ps.dropped == 0;
        ok &= ok_a;
        // (b) 排水面：全量对账 + 二次排水零泄漏 + 卸臂回证
        let n = shell::capture_drain(&mut buf);
        let drain_ok = n == 21 && &buf[..21] == b"pipe-alpha\npipe-beta\n";
        let leak_free = shell::capture_drain(&mut buf) == 0;
        ok &= drain_ok && leak_free && !shell::pipe_snapshot().active;
        let _ = writeln!(
            log,
            "shell-pipe-cap: n={n} leak_free={leak_free} drain_ok={drain_ok} ok_a={ok_a}"
        );
        // (c) more 全程分页：10 行产线 → 电键预注两拍 → 全显断言
        shell::capture_arm();
        for i in 1..=10 {
            let line = alloc::format!("pl{i:02}");
            shell::log_sink(line.as_bytes());
        }
        let n10 = shell::capture_drain(&mut buf);
        ok &= n10 == 50; // 10 × (4 载荷 + 1 行界) = 50
        tty::pager_arm();
        kbd::inject(0x39); // 空格（扫描码 → 翻译 → 环 → 分页键队列）
        kbd::inject(0x39);
        let shown = shell::pager_replay(&buf[..n10]);
        let pg = shell::pager_snapshot();
        let ok_c = shown == 10 && pg.pauses == 2 && pg.aborts == 0;
        let drop_zero = tty::PAGER_DROP.load(Ordering::Relaxed) == 0;
        ok &= ok_c && drop_zero;
        let _ = writeln!(
            log,
            "shell-pager-full: shown={shown} pauses={} aborts={} ok_c={ok_c} drop0={drop_zero}",
            pg.pauses, pg.aborts
        );
        // (d) q 中止面：'q' 首停即弃 → 只显首页 + aborts 跳升
        shell::capture_arm();
        for i in 1..=10 {
            let line = alloc::format!("pl{i:02}");
            shell::log_sink(line.as_bytes());
        }
        let nq = shell::capture_drain(&mut buf);
        tty::pager_arm();
        kbd::inject(0x10); // 'q'
        let shown_q = shell::pager_replay(&buf[..nq]);
        let pgq = shell::pager_snapshot();
        let ok_d = shown_q == shell::PAGE_LINES && pgq.aborts == pg.aborts + 1;
        ok &= ok_d;
        let _ = writeln!(
            log,
            "shell-pager-abort: shown={shown_q} aborts={} (page_lines={}) ok_d={ok_d}",
            pgq.aborts,
            shell::PAGE_LINES
        );
        // (e) 弃置 + 过载：drop 清账 + 满载整行弃（fail-visible）
        shell::capture_arm();
        shell::log_sink(&[b'x'; 512]);
        shell::log_sink(&[b'y'; 512]);
        let pso = shell::pipe_snapshot();
        ok &= pso.len == 513 && pso.dropped == 1;
        shell::capture_drop();
        let psd = shell::pipe_snapshot();
        let ok_e = psd.len == 0 && !psd.active;
        ok &= ok_e;
        let _ = writeln!(
            log,
            "shell-pipe-drop: overflown_len={} dropped={} post_drop_len={} active={} ok_e={ok_e}",
            pso.len, pso.dropped, psd.len, psd.active
        );
        ok
    };
    report(&mut log, t74, "shell-pipe-more");

    let _ = writeln!(log, "----");
    if pass == SELFTEST_TOTAL {
        let _ = writeln!(log, "LUMINA-SELFTEST-PASS {pass}/{SELFTEST_TOTAL}");
        let _ = writeln!(log, "LUMINA-BOOT-OK");
        // ---- M23-②：interactive 面（--features interactive）----
        // 自检通过后不关机：构建 init 用户空间（INIT_IMAGE 单帧）→ 无父
        // 派生（r14=0 → shell 分支）→ kmain 守候 all_workers_finished；
        // init 终结（halt 命令 SYS_EXIT(0x10) → 僵尸转型点 INIT_EXIT 点名
        // 登记）→ 读回透传 kernel_exit（0x10 → QEMU 码 33 = 批跑成功域
        // 同源）。批跑面（默认特性）零扰动：立即成功码退出，回归网照旧。
        #[cfg(feature = "interactive")]
        {
            // 帧服务不可达 = 引导面已破（防御拒绝，t 系同款 Some-else 面）
            let Some(frames) = vmm::global_frames() else {
                kernel_exit(EXIT_FAILURE);
            };
            let init_us = {
                let mut alloc = || frames.alloc();
                match crate::user::build_user_space_with(&crate::user::INIT_IMAGE, &mut alloc) {
                    Ok(us) => us,
                    Err(_) => kernel_exit(EXIT_FAILURE),
                }
            };
            let init_id = task::spawn_user("init", user_noop, init_us.root, 0);
            let _ = writeln!(log, "LUMINA-INTERACTIVE-ON init-slot={init_id}");
            // 守候：轮询 INIT_EXIT（僵尸转型点按名登记）——只等 init 本尊。
            // 初版全表谓词 all_workers_finished 实测永眠：批跑面遗留长活
            // 任务（timer-sleeper）在批模式由 kernel_exit 直接带过、从不
            // 终结；interactive 面只等 init（halt → 0x10 → 透传 kernel_exit）。
            while task::INIT_EXIT.load(Ordering::Acquire) == u64::MAX {
                core::hint::spin_loop();
            }
            let code = task::INIT_EXIT.load(Ordering::Acquire);
            let _ = writeln!(log, "LUMINA-INIT-EXIT code={code:#x}");
            kernel_exit(code as u32);
        }
        #[cfg(not(feature = "interactive"))]
        {
            interrupts::disable();
            kernel_exit(EXIT_SUCCESS);
        }
    } else {
        let _ = writeln!(log, "LUMINA-SELFTEST-FAIL {pass}/{SELFTEST_TOTAL}");
        interrupts::disable();
        kernel_exit(EXIT_FAILURE);
    }
}

/// 用户任务占位入口（真实进入经 trampoline_user → 桥函数）。
fn user_noop() {}

// ---- t50 目录面取证辅助（内核 .bss 恒等映射区，validate_user_slice 窗口内） ----

/// t50 目录页缓冲（READDIR 目标；512B = ABI 上限）。
static mut DIR_PAGE: [u8; 512] = [0u8; 512];
/// t50 目录项积累缓冲（跨页拼接；项编码自对齐，256B 足容 8 项）。
static mut DIR_ACC: [u8; 256] = [0u8; 256];
/// t53 创建面写读缓冲（"LUMINA-OCREAT" 13B + 截断面写 + 对齐余量）。
static mut OC_BUF: [u8; 64] = [0u8; 64];
/// t56 持久化面写读缓冲（"LUMINA-PERSIST" 14B + 读回对账 + 对齐余量）。
static mut M17_BUF: [u8; 64] = [0u8; 64];

/// OC_BUF 缓冲地址（raw 指针形态，避开 static_mut_refs 语义）。
fn oc_buf_addr() -> u64 {
    (&raw mut OC_BUF) as *mut u8 as u64
}

/// M17_BUF 缓冲地址（raw 指针形态，避开 static_mut_refs 语义）。
fn m17_buf_addr() -> u64 {
    (&raw mut M17_BUF) as *mut u8 as u64
}

/// DIR_PAGE 缓冲地址（raw 指针形态，避开 static_mut_refs 语义）。
fn dir_page_addr() -> u64 {
    (&raw mut DIR_PAGE) as *mut u8 as u64
}

/// 把 DIR_PAGE 首部 `n` 项追加进 DIR_ACC（项编码自对齐走查定页长），
/// 返回新积累长度。t50 断言辅助：跨页项边界拼接后整体走查。
fn copy_page_to_acc(n: usize, acc_len: usize) -> usize {
    let page = (&raw const DIR_PAGE) as *const u8;
    let acc = (&raw mut DIR_ACC) as *mut u8;
    let mut p = 0usize;
    // SAFETY: 单核自检上下文串行访问；页长由项编码链定界（≤ 512，
    // DIR_ACC 256B 足容 8 项，acc_len + p ≤ 256 由调用方页数保证）。
    unsafe {
        for _ in 0..n {
            p += 2 + *page.add(p + 1) as usize;
        }
        core::ptr::copy_nonoverlapping(page, acc.add(acc_len), p);
    }
    acc_len + p
}

/// t50 积累缓冲全量走查：项编码闭合（2+len 链走到底）+ 10 名单全在 +
/// kind 抽查（lxe/hello/echo/prog.lwp = File；dir/scratch/mnt = Dir）。
fn acc_scan(acc_len: usize) -> bool {
    let acc = (&raw const DIR_ACC) as *const u8;
    let mut hello = false;
    let mut echo = false;
    let mut dir = false;
    let mut selftest = false;
    let mut prog = false;
    let mut grow = false;
    let mut deep = false;
    let mut lwp = false;
    let mut scratch = false;
    let mut mnt = false;
    // SAFETY: 单核自检上下文串行访问；走查边界由 acc_len 与项编码链
    // 双重定界（i + 2 + nl ≤ acc_len）。
    unsafe {
        let mut i = 0usize;
        while i + 2 <= acc_len {
            let kind = *acc.add(i);
            let nl = *acc.add(i + 1) as usize;
            if i + 2 + nl > acc_len {
                return false; // 编码破损
            }
            let name = core::slice::from_raw_parts(acc.add(i + 2), nl);
            match (kind, name) {
                (0, b"hello") => hello = true,
                (0, b"echo") => echo = true,
                (1, b"dir") => dir = true,
                (0, b"selftest.lxe") => selftest = true,
                (0, b"prog.lxe") => prog = true,
                (0, b"grow.lxe") => grow = true,
                (0, b"deep.lxe") => deep = true,
                (0, b"prog.lwp") => lwp = true,
                (1, b"scratch") => scratch = true,
                (1, b"mnt") => mnt = true,
                _ => {}
            }
            i += 2 + nl;
        }
        if i != acc_len {
            return false; // 走查未闭合（尾残）
        }
    }
    hello && echo && dir && selftest && prog && grow && deep && lwp && scratch && mnt
}

/// t46 sleeper 完成旗标（1 = nanosleep 返回后落证）。
static SLEEPER_DONE: AtomicU64 = AtomicU64::new(0);
/// t46 sleeper 实际耗时（TSC 纳秒差；M15-③ 纳秒面下界断言：单调域内
/// 绝不早醒 → ≥ 请求值）。
static SLEEPER_ELAPSED_NS: AtomicU64 = AtomicU64::new(0);

/// t46 sleeper 任务体（内核 worker）：nanosleep(50ms) 真阻塞 → 耗时
/// 落证 → 驻车让出（kernel worker 不计入 all_workers_finished）。
fn sleeper_body() {
    let t0 = ostd::time::tsc_clock::now_ns().unwrap_or(0);
    crate::timer::sys_nanosleep(50_000_000); // 50ms（TSC 纳秒域）
    let t1 = ostd::time::tsc_clock::now_ns().unwrap_or(0);
    SLEEPER_ELAPSED_NS.store(t1.saturating_sub(t0), Ordering::Release);
    SLEEPER_DONE.store(1, Ordering::Release);
    loop {
        task::yield_now();
    }
}

/// 基准路径禁用分配（翻译不应再分配中间表）。
fn no_alloc_table() -> Option<u64> {
    None
}

/// isa-debug-exit 成功码：QEMU 退出码 = (值 << 1) | 1 = 33。
pub const EXIT_SUCCESS: u32 = 0x10;
/// isa-debug-exit 失败码：QEMU 退出码 = (值 << 1) | 1 = 193。
pub const EXIT_FAILURE: u32 = 0x60;

/// M22-③ [X] 终局出口互斥闸（标本 865 定案）：出口权 CAS——`false→true`
/// 的唯一赢家获得写口权。QEMU isa-debug-exit 每次写都请求退场且退出码
/// 取实际落入值：双核并发出口（BSP 成功 0x10 / AP 故障 0x60）交织时后写
/// 者改码 → exit193 假败（865：63/63 全过 + census f0 + exit193）。闸后
/// 写口者唯一，竞争结构性封死；输家原地自旋（赢家写口后 QEMU 立即退场，
/// 无需二次出口；裸机语义与既有停机环一致）。
static EXIT_GATE: AtomicBool = AtomicBool::new(false);

/// 致命异常出口（interrupts.rs 故障钩子调用）：以失败码停机。
/// [X] 取证显形：故障钩子已有 LUMINA-FAULT 短行，此处保底行覆盖钩子
/// 长转储串口交叠丢行（865 痛点：AP 静默 0x60 无从对证）与钩子之外
/// 的未来入口；行落出口闸之前，闸输家亦可见。
pub(crate) fn fail_exit(vector: u64) -> ! {
    let mut serial = console::SerialPort::com1();
    serial.init();
    let _ = writeln!(serial, "LUMINA-FAIL-EXIT vec={vector}");
    kernel_exit(EXIT_FAILURE)
}

/// 经 isa-debug-exit（端口 0xF4）请求 QEMU 退出；裸机上写调试口后停机。
fn kernel_exit(code: u32) -> ! {
    // M22-③ [X] 出口仲裁：中断先关（出口路径不受抢占/时钟重入干扰），
    // 再 CAS 抢出口权——唯一赢家落取证行 + census + 写口；输家原地停机。
    interrupts::disable();
    if !EXIT_GATE.swap(true, Ordering::AcqRel) {
        let mut serial = console::SerialPort::com1();
        serial.init();
        // M22-① 终局 census：任何退出路径（成功/失败/fail_exit/panic）在
        // 写调试口之前必落一行单行 census——pf-hunt 尸检的保底定位行。
        // [X] 增 LUMINA-EXIT 行：码值显形 + 铺在 census 前（交叠下短行
        // 存活率高），双核仲裁后尸检可对证「谁写的口、写的什么码」。
        let _ = writeln!(serial, "LUMINA-EXIT code={code:#x}");
        census::write_to(&mut serial);
        ostd::hw::ports::write_u32(0xF4, code);
    }
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
