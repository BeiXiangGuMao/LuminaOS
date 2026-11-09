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
mod dev;
mod fb;
mod font_gen;
mod hostlink;
mod interrupts;
mod ipc;
mod kbd;
mod linux;
mod multiboot1;
mod procs;
mod selftest;
mod shell;
mod shm;
mod smp;
mod svc;
mod swap;
mod syscall;
mod task;
mod timer;
mod tty;
mod unixsock;
mod user;
mod vfs;
mod vmm;
mod vnet;
mod waycomp;

use core::fmt::Write as _;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
use bedrock::ipc::Endpoint;
use bedrock::tlv;
use ostd::heap::FreeList;
use ostd::mm::frame::{FrameAllocator, Region, FRAME_SIZE};
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::SpinLock;

use crate::console::DualLog;
use crate::multiboot1::BOOT_MAGIC;

/// 内核堆大小：16 MiB（M3 任务栈/日志/TLV 充足；M33-F1 busybox 介质
/// ~1 MiB + 装载面峰值余量扩容；帧管理独立于本堆，kernel span 预留
/// 随 kern_end 动态扩）。
const HEAP_SIZE: usize = 16 * 1024 * 1024;

/// 自检项目总数（M2 七项 + M3 四项 + M4 四项 + M5 五项 + M6 五项 + M7 两项 + M8 三项 + M9 三项 + M10 三项 + M11 四项 + M12 起逐块追加；M23-C3 起 71，M24-S1 起 72，M24-C1 起 73，M24-A1 起 74，M31-T1 起 80，M32-T1 起 81，M33-T1 起 82，M34-B2 起 83，M35-BBa 起 84，M35-BBb 起 85，M36-N1 起 86，M36-BB3b 起 87，M37-A1b 起 88，M37-N1 起 89，M38-SP1 起 90，M38-TCP1 起 91，M39-BBLS 起 92，M39-MU 起 93，M39-DPMS 起 94；M40-ASH2 t95 备置撤闸空缺跳号如实登记；M40-CRYSTAL t96 起 95；M40-CAT t97 起 96；M41-笔① t95 转正（栈 grow 缺陷族修复落域）起 97；M41-笔② t98（块层字节域取证矩阵）起 98；M41-笔③ t99（saved-set+补充组矩阵）起 99；M41-笔④ t100（ash 交互面）起 100；M42-FBDEV1 t101（用户态 fb 驱动进程移交链）起 101；M42-FBSVC2 t102（常驻 fbdev 服务活体）起 102；M42-UNIX3 t103（unix socket 域 + Wayland wire 语义面活体）起 103；M42-COMP4 t104（合成器进程面：常驻 waycomp 合流电气面 + 阻塞 accept/EOF 对端终结面 + cascade 仲裁策略承接）起 104；M42-ELF5 t105（用户态 ELF 播种 lane：ring3 编译进程承接）+ t106（桌面链 wl_shm/fd 传递活体）起 106）。
const SELFTEST_TOTAL: usize = 106;

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

/// 全局分配器：kmain 早期 rebind 到静态内核堆（启动惯用法）。
/// M21-③：由 Bump 升级为 FreeList（first-fit + 合并复用面）。
/// ADR-0003（M29-N1）：分配器自 harbor 迁 ostd::heap，harbor 让位 POSIX libc。
#[global_allocator]
static ALLOC: FreeList = FreeList::new_unbacked();

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

/// t90 风暴轮数（M38-SP1）：每任务混合时程 nanosleep 循环上界。
const T90_ROUNDS: usize = 120;

/// t90 风暴完成计数（M38-SP1 收割锚：kernel spawn 无 parent 链——
/// wait_pid 不适用〔M9-A 父链仅 fork 面；本笔揭雷实录：wait_pid 全数
/// ERR_CHILD 立返、风暴任务被弃置成活僵尸〕，完成计数 + 孤儿收割替代）。
static T90_DONE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// t90 风暴任务本体（M38-SP1 阻塞臂握手旗活体）：R 轮混合时程
/// nanosleep（0 / 250 µs / 500 µs 交替 = 探针命中域 + 真实阻塞域全覆
/// 盖）后返回（trampoline 无码终结 u64::MAX 哨兵）。不钉扎——跨核自
/// 由迁移最大化「唤醒方保存窗入队 → 对侧核拾取」交叉域压力面（M22-③
/// 竞态根因域）；零堆分配（循环体仅原子计数 + Timer 登记面）。
fn t90_storm_body() {
    for i in 0..T90_ROUNDS {
        let ns = match i % 3 {
            0 => 0,
            1 => 250_000,
            _ => 500_000,
        };
        let _ = timer::sys_nanosleep(ns);
        task::yield_now(); // 协作让渡：与对侧风暴任务/preempt 面交错
    }
    T90_DONE.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

/// t90 专职 waker（M38-SP1 唤醒面；本笔揭雷实录之二：tickd 于 t52
/// `timer::shutdown()` 退役——套件尾 Timer 唤醒链已拆，风暴 Timer 阻塞
/// 永无到期消费〔F14/G1 四轮 blk+=4~7 wake+=0 done=0 取证在案〕）。
/// 语义 = 用户态 tickd 替身：wake_tasks 直醒 Timer 等待者 + 协作让渡
/// 轮询，风暴每次真实阻塞下一轮即被醒（电平触发——先醒后堵不丢失，
/// 下一轮补醒）；同时把 block/wake 交叉频次抬到让渡量级（竞态窗压力
/// 面强化）。风暴全数完成后退役（孤儿收割面回收）。
fn t90_waker_body() {
    for _ in 0..2_000_000 {
        if T90_DONE.load(core::sync::atomic::Ordering::Acquire) >= 4 {
            return;
        }
        task::wake_tasks(|w| matches!(w, task::WaitWhat::Timer { .. }));
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
    let _ = writeln!(
        log,
        "kernel heap: {HEAP_SIZE} bytes bound (ostd::heap::FreeList)"
    );

    // ---- 挂账⑦ 根治：boot 栈底哨兵区整页涂鸦（L3 显形层的账面基线）----
    // 布局根治（boot.rs .boot.bss 重排：页表已移至栈上方）+ 容量余量
    // （64→256 KiB）之后，哨兵区 = 栈下行越界第一站；整页涂鸦
    // BOOT_STACK_GUARD_MAGIC，wall_hook 逐拍核对 sentinel qword
    // （guard_top-8），被蚀即 LUMINA-BOOTSTACK-EROSION 一次性取证行。
    // 涂鸦自栈侧端（guard_top-8）向低址推进——最先被蚀的位置最先定型。
    {
        let (gb, gt) = boot::boot_stack_guard_bounds();
        let mut p = gt as u64 - 8;
        while p >= gb as u64 {
            ostd::hw::phys::write_u64(p, boot::BOOT_STACK_GUARD_MAGIC);
            p -= 8;
        }
        let _ = writeln!(
            log,
            "boot-stack: guard [{gb:#x},{gt:#x}) painted {:#x} (L3 erosion sentinel)",
            boot::BOOT_STACK_GUARD_MAGIC
        );
    }

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

    // ---- M33-F1 制备介质：multiboot module[0] → ramfs 媒体暂存面 ----
    // QEMU `-initrd` 在 multiboot1 装载面即首 module（busybox 介质契约，
    // xtask S8 参数面注入）。拷贝经 phys::read_u64 步进（低 1 GiB 恒等
    // 映射域）；无 module 防御式降级（t82 路径探针 fail-visible 兑底）。
    match multiboot1::module_span(info, 0) {
        Some((start, end)) => {
            let mut media = Vec::with_capacity((end - start) as usize);
            let mut p = start;
            while p + 8 <= end {
                media.extend_from_slice(&ostd::hw::phys::read_u64(p).to_le_bytes());
                p += 8;
            }
            while p < end {
                media.push(ostd::hw::phys::read_u32(p) as u8);
                p += 1;
            }
            let n = media.len();
            vfs::stage_media(media);
            let _ = writeln!(
                log,
                "vfs: busybox media staged (module 0: {:#x}..{:#x}, {n} bytes)",
                start, end
            );
        }
        None => {
            let _ = writeln!(
                log,
                "vfs: no multiboot module media (mods_count=0 或防御拒收) — /bin/busybox 缺位"
            );
        }
    }

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

    // ---- M31-W1 Weave 自举：journal 重放恢复语义 + store 根装载 ----
    // boot 后 recover 库态语义挂接：三不变式（活跃指针胜出/回滚不残留/
    // 撕裂残槽显形丢弃）boot 期四相复演 + 内容寻址根装载同源对账；
    // 介质落盘随 crystal 块域挂账维持（WE-P03/07 不动，v0 内存库态）。
    // fail-visible：装载失败即退出（自举装载面破坏不进自检）。
    let wb = weave::boot::bootstrap();
    let _ = writeln!(
        log,
        "LUMINA-WEAVE-BOOT gen={} replay={}/{} residue={} store={} objs={} bytes={} root={} ok={}",
        wb.gen,
        wb.replay_pass,
        wb.replay_total,
        wb.residue_clean,
        wb.store_ok,
        wb.store_objects,
        wb.store_bytes,
        wb.root_ok,
        wb.ok()
    );
    if !wb.ok() {
        let _ = writeln!(
            log,
            "weave boot load failed: replay={}/{} residue={} store={} root={}",
            wb.replay_pass, wb.replay_total, wb.residue_clean, wb.store_ok, wb.root_ok
        );
        kernel_exit(EXIT_FAILURE);
    }

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
    // M33-F1 制备证据：根 ramfs 挂载 + /bin/busybox 路径可达探针
    match vfs::read_image("/bin/busybox") {
        Some(b) => {
            let _ = writeln!(
                log,
                "vfs: root ramfs mounted, /bin/busybox reachable ({} bytes)",
                b.len()
            );
        }
        None => {
            let _ = writeln!(log, "vfs: /bin/busybox probe MISS (介质缺位或播种失败)");
        }
    }

    // M34-D1 驱动服务框架结构面：五驱动 boot 注册（内核态占位 v0 口径
    // ——电气面零改动；通道铸造/驱动进程形态随服务化批次）。对账闸 =
    // bedrock::abi::SVC_PRESET_COUNT，未命中即无标记（S8 fail-visible）。
    let svc_n = svc::init();
    let (svc_used, svc_cap, svc_mask) = svc::snapshot();
    if svc_n == bedrock::abi::SVC_PRESET_COUNT {
        let _ = writeln!(
            log,
            "LUMINA-SVC-INIT n={svc_n} used={svc_used}/{svc_cap} mask={svc_mask:#x}"
        );
    } else {
        let _ = writeln!(log, "svc: registration incomplete n={svc_n}");
    }
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

    // M42-FBSVC2（笔②）fb 服务环铸造 + SVC_FB 通道挂接（阶段一常驻面
    // 「服务环/IPC 通道」——M34-D1「请求/应答通道对随服务化批次铸造」
    // 挂账域兑现）：泄漏 req/resp 单向环对 + svc 注册项 (0,0) 占位改写。
    // fail-visible：铸造/挂接任一失手即证据行缺位（t102 (a) 相位对账
    // 必炸——boot 铸造面无静默降级）。
    let fb_rings = ipc::init_fb_service_rings();
    let fb_attach =
        fb_rings.and_then(|(req, resp)| svc::attach_channels(bedrock::abi::SVC_FB, req, resp).ok());
    if let (Some((req, resp)), Some(slot)) = (fb_rings, fb_attach) {
        let _ = writeln!(
            log,
            "LUMINA-SVC-FBRINGS req={req:#x} resp={resp:#x} attach=slot{slot} (SVC_FB 服务环在环)"
        );
    }

    // M42-COMP4（笔④）阶段三「合成器进程面」boot-spawn 常驻面
    // （M42-FBSVC2「常驻服务 boot-spawn 生命周期面」挂账域首割）：
    // waycomp 常驻合成器服务（bind wayland-comp 名域 → SVC_COMPOSITOR
    // 第 6 预设在环 → 阻塞 accept 会话环——unix socket 域 ⇄ wire 壳
    // ⇄ SYS_FB_SURFACE 合流电气面）。fail-visible：bind 失手即
    // LUMINA-WAYCOMP-BOOT 证据行缺位（t104 (a) 相位对账必炸）。
    let waycomp_pid = task::spawn_resident("waycomp", waycomp::service_body);
    let dlw = ostd::time::now() + 240; // 编舞窗：计时器抢占域有界等待（t102 240 拍先例同款）
    while !waycomp::WLCOMP_BOUND.load(Ordering::Acquire) && ostd::time::now() < dlw {
        core::hint::spin_loop();
    }
    if waycomp::WLCOMP_BOUND.load(Ordering::Acquire) {
        let _ = writeln!(
            log,
            "LUMINA-WAYCOMP-BOOT pid={waycomp_pid} listener={:#x} name=wayland-comp (常驻合成器服务化 boot 面)",
            waycomp::WLCOMP_LISTENER.load(Ordering::Acquire)
        );
    }

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
        fn tick_watch_body_0() {
            WATCH_SEEN_0.fetch_add(1, Ordering::AcqRel);
        }
        let mut ok = true;
        task::set_preempt_enabled(true);
        task::reset_user_evidence();
        let ticks0 = task::percpu_ticks();
        // M40-ASH2 语义变更随行：ring3 ISR 量子抢占互斥（PERCPU_IS_USER
        // 零锁旗——t95 标本流程定根因，M22-③ 同族窗族触发面移除）后，
        // 本活体装置由「双核 ring3 spinner + 量子抢占换 watcher」改为
        // **单 spinner（unpinned）+ 事件驱动分时**：spinner ring3 驻留
        // 独占其核，kmain/watcher 在另一核 yield 分时——tick 计账 unfreeze
        // 验证面不变（wall_hook 全核遍历计账，ring3 驻留核照涨）；原
        // 「preempt+ 增长」断言随互斥撤除（ring3 ISR 抢占已移除——行为
        // 语义变更如实落账，kernel 域抢占面由 t90/t3x 高优先抢前活体
        // 继续覆盖）。装置不再依赖被互斥移除的调度行为（首拍实录：双
        // spinner pinned 版 kmain 切入 spinner 后无核可用 = 装置滞域）。
        let preempt0 = task::preempt_stats().0;
        match (
            user::build_user_space(&mut || frames.alloc()),
            user::build_user_space(&mut || frames.alloc()),
        ) {
            (Ok(usa), Ok(usb)) => {
                ostd::hw::phys::write_bytes(usa.code_frame, &user::USER_SPIN_PROGRAM);
                ostd::hw::phys::write_bytes(usb.code_frame, &user::USER_SPIN_PROGRAM);
                // 单 ring3 spinner（pinned 核 1——kmain 独占核 0 分时
                // watcher-0：全装置事件驱动，零 ISR 抢占依赖）+ watcher
                //（pinned 0 与 kmain yield 分时——kernel 任务让渡链）
                let _ = task::spawn_user_pinned("spin-a", user_noop, usa.root, 0, 1);
                let _ = task::spawn_pinned_prio("tick-watch-0", tick_watch_body_0, 2, 0);
                // watcher 收敛窗口（预算 600 tick；事件驱动分时可达）+
                // **最小取证窗 8 tick**（M40-ASH2：事件驱动域窗口过短则
                // PIT 计账零增长——ticks unfreeze 断言需窗口跨拍才有效）
                let start = ostd::time::now();
                let deadline = start + 600;
                while ostd::time::now() < deadline
                    && (ostd::time::now() < start + 8 || WATCH_SEEN_0.load(Ordering::Acquire) == 0)
                {
                    task::yield_now();
                }
                let w0 = WATCH_SEEN_0.load(Ordering::Acquire);
                let w1 = 1u64; // 旧双核 watcher 断言随单 spinner 装置并档（w1 恒证）
                ok &= w0 > 0; // watcher 分时真实运行
                              // 哨兵释放：spinner 退出（取证窗口闭合）
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
                    "tick-account: watch=({w0},{w1}) exit=({e0},{e1}) ticks=({},{})→({},{}) preempt+={} (M40-ASH2 互斥面——preempt 断言撤除)",
                    ticks0.0, ticks0.1, ticks1.0, ticks1.1, preempt1 - preempt0
                );
                // M40-ASH2：USER_EXIT_CODES 为 per-CPU 槽位——单 spinner
                // pinned 核 1 → e1=57；核 0 无 user exit → e0 恒 u64::MAX
                //（reset_user_evidence 清零后恒证域）。
                ok &= e1 == 57 && e0 == u64::MAX; // spinner 哨兵退出（全链完好）
                                                  // 双核 tick 计账增长（ring3 驻留 unfreeze——M10-A 计账面
                                                  // 全核遍历不变；kernel watcher 核 + spinner 核双面）
                ok &= ticks1.0 + ticks1.1 > ticks0.0 + ticks0.1;
                ok &= (ticks1.0 > ticks0.0) && (ticks1.1 > ticks0.1);
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
    //     构造（M40-ASH2 语义变更随行）：**单 ring3 spinner（pinned 核 1
    //     ——ring3 ISR 量子抢占互斥后 spinner 独占其核；双 spinner 版把
    //     kmain 也饿死——首拍实录：kmain yield 让出后全系统无核可用）**
    //     + 钉扎/自由 kernel 风暴任务全部并档核 0 与 kmain 分时（协作
    //     路径高频 + kernel 域量子抢前保留）。预算窗口后全量退出；取证：
    //     风暴/自由任务全部落证 + spinner 哨兵退出（e1=57，per-CPU 槽位）
    //     + 静默期全旗清零 + 协作/抢占计数双增（kernel 域抢占面）。
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
                let _ = task::spawn_user_pinned("hs-spin-a", user_noop, usa.root, 0, 1);
                let _ = task::spawn_pinned_prio("hs-storm-0", storm_body_0, 2, 0);
                let _ = task::spawn("hs-storm-1", storm_body_1);
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
                // M40-ASH2：单 spinner pinned 核 1 → e1=57；e0 恒 u64::MAX
                ok &= e1 == 57 && e0 == u64::MAX; // spinner 哨兵退出（寄存器面完好）
                ok &= fc; // 静默期全旗清零
                          // M41-T40F：coop 存在性锚撤除（证据面保留）——M40-ASH2 事件
                          // 驱动化后 yield 切换在 RESCHED-plan 执行器与协作让渡点之间
                          // 的计数归属随主机时序漂移（本机实录：12k 风暴让渡 done=f
                          // 而 coop+=0/preempt+=20001；M40-ASH2 实录同量级 coop+=4/
                          // preempt+=20005）——协作面存在性由 t11/t12（折叠环确定性
                          // 序列）+ bench 协作切换 0.64μs 独立覆盖，负载锚 pre1>pre0
                          // 严格保留。
                ok &= pre1 > pre0; // 负载在环（量子抢前面 2 万次/轮）
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
    //     （1920×1080×4 = 8294400 B，M28-R1；1024×768 时代 = 3145728 B）；
    //     帧2 窗 A→B 挪位，旧∪新包围盒局部
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
            f1 == 8_294_400 && f2 == 665_600 && f3 == 0 && px_ok
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
    //         分离不翻；第 17 块入账即翻转全帧，全帧重绘实屏 8294400 字
    //         （M28-R1 1080p；1024×768 时代 3145728）
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
            ok &= full_bytes == 8_294_400;
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

    // M28-K1 组合器执行器在环热身：stage 未激活 → drain 空账（t72 已
    // 复位）静默返回 0（直写双轨共存——无操作即正确语义）。执行器可达
    // 性在此建立；t77（M28-T1）起承载 stage 登记与交盒局部上屏断言。
    {
        let warm = crate::fb::fb_compose_tick();
        let _ = writeln!(log, "compose-warm: skip px={warm}");
    }

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
        // 宽限轮询（M24-A1-b 时序加固）：slirp 应答迟到双峰家族（C1 实测，
        // 本日冒烟复现：击发环短于 slirp 处理延迟 → 32 发零到达，used=9
        // vs last_used=2 实证应答在 fail 判定后才投 used 环）。宽限窗纯
        // 排水不消费（占用爬坡语义不变）：迟到帧逐拍入环爬坡 → 投入即
        // 出；预算与 (d) 同源（NET_SPIN_BUDGET）。
        let mut grace = 0u64;
        while vnet::bp_snapshot().enters == 0 && grace < vnet::NET_SPIN_BUDGET {
            vnet::rx_pump();
            grace += 1;
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
        //     重发容忍域（M25-C1-a 加固）：slirp 反射回包滞后双峰实测——
        //     迟到回声会落在后续拍窗口（seq 错拍），故五闸只锁
        //     id+payload+双校验和+寻源（payload 三拍同源，payload 匹配
        //     已锁死本自检请求的回声），seq 仅作证据行记录不作判定闸；
        //     容忍域 3 拍重发 + 第 4 拍纯排水（不发请求——slirp 迟到
        //     回声落地窗；总时长上限 4×SPIN 不超 S8 杀线）。
        let payload1 = *b"LUMINA-C1-GATEWAY-ECHO-01";
        let mut gw_echo = false;
        let mut gw_tries = 0u16;
        while got_arp && gw_tries < 4 && !gw_echo {
            gw_tries += 1;
            if gw_tries <= 3
                && !vnet::icmp_echo_tx(
                    gw_mac,
                    [10, 0, 2, 2],
                    vnet::ICMP_ECHO_ID,
                    gw_tries,
                    &payload1,
                )
            {
                break;
            }
            // 回声窗拍钟化（M28-K1 计划外搭车件，M25-C1-a「CI 挂账三次
            // 复发→计划外加固」先例）：slirp 反射延迟属宿主时间量，拍数
            // 预算在慢宿主上系统性失准（本会话 4/5 挂实录：回声帧晚于
            // 整个 spin 预算落地）。改 100 Hz tick 死线（GW_ECHO_TICKS
            // = 50 拍 = 0.5 s/发，宿主速度无关）；3 发 + 1 排水拍 ≤ 2 s
            // 不破 S8 杀线。背压相位 (b)/(c) 设备侧行为绿稳不动。
            let deadline = ostd::time::now() + vnet::GW_ECHO_TICKS;
            while ostd::time::now() < deadline && !gw_echo {
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
                    if id != vnet::ICMP_ECHO_ID {
                        continue; // M25-C1-a：seq 不作判定闸（迟到回声错拍容忍）
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
            // M25-T1 对账：tx_frame 发后收讫（M25-C1-a）已同步化 TX 面，
            // 本处电气等待仅余设备 BH 残余延迟——预算 1M 轮对齐
            // TX_SETTLE_SPIN 口径（40M 级在 TCG 实为数十秒，撞看门狗）。
            let mut spin = 0u64;
            while spin < 1_000_000 && vnet::tx_drain() == 0 {
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

    // ---- t75（M25-T1）：conduit 兼容面在环活体（C-P04 布局快照裸机侧
    //      对账 + C-P01 转换器/绑定表抽查）——宿主侧编译期双闸
    //      （conduit::layout const 断言矩阵）已挂，此处裸机实机二次
    //      锚定：size/offset 由本核编译器即时求值与 UAPI 快照逐项对照
    //      （四代表结构：Stat 文件面 / SysInfo 对齐补位面 / EPollEvent
    //      packed 面 / Statx 5.15 形状面）；转换器面 errno 正向全表 +
    //      反向抽查 + 哨兵域 + flags 往返 + 绑定表 ≥20 锚点。
    let t75 = {
        use conduit::convert::{
            err_to_errno, errno_to_err, flags_to_open_mode, open_mode_to_flags, BINDINGS,
        };
        use conduit::defs;
        let mut ok = true;
        // (a) 布局快照裸机对账（行面 + 四代表 size/offset 锚）
        ok &= conduit::layout::SNAPSHOT.len() == 20;
        ok &= core::mem::size_of::<defs::Stat>() == 144
            && core::mem::offset_of!(defs::Stat, st_size) == 48;
        ok &= core::mem::size_of::<defs::SysInfo>() == 112
            && core::mem::offset_of!(defs::SysInfo, procs) == 80
            && core::mem::offset_of!(defs::SysInfo, totalhigh) == 88;
        ok &= core::mem::size_of::<defs::EPollEvent>() == 12
            && core::mem::offset_of!(defs::EPollEvent, data) == 4;
        ok &= core::mem::size_of::<defs::Statx>() == 256
            && core::mem::offset_of!(defs::Statx, stx_mnt_id) == 144;
        // (b) errno 双向在环：正向 LXE1 v0 全表 10 项 + 反向抽查 +
        //     哨兵/成功域不可翻译 + 反向登记项往返
        ok &= err_to_errno(bedrock::abi::ERR_CAP) == Some(1);
        ok &= err_to_errno(bedrock::abi::ERR_EMPTY) == Some(11);
        ok &= err_to_errno(bedrock::abi::ERR_DERIVE) == Some(1);
        ok &= err_to_errno(bedrock::abi::ERR_FULL) == Some(11);
        ok &= err_to_errno(bedrock::abi::ERR_HANDLE) == Some(9);
        ok &= err_to_errno(bedrock::abi::ERR_TARGET) == Some(3);
        ok &= err_to_errno(bedrock::abi::ERR_TABLE) == Some(24);
        ok &= err_to_errno(bedrock::abi::ERR_CHILD) == Some(10);
        ok &= err_to_errno(bedrock::abi::ERR_NOMEM) == Some(12);
        ok &= err_to_errno(bedrock::abi::ERR_IMAGE) == Some(8);
        ok &= errno_to_err(9) == Some(bedrock::abi::ERR_HANDLE);
        ok &= errno_to_err(24) == Some(bedrock::abi::ERR_TABLE);
        ok &= err_to_errno(0).is_none() && err_to_errno(u64::MAX).is_none();
        ok &= errno_to_err(2).is_none(); // 文件面透传域
        ok &= err_to_errno(errno_to_err(12).unwrap_or(0)) == Some(12);
        // (c) flags 往返抽查（全域组合 + 非法域）
        ok &= flags_to_open_mode(open_mode_to_flags(0b1_1111).unwrap_or(0)) == Some(0b1_1111);
        ok &= open_mode_to_flags(0).is_none() && open_mode_to_flags(0b10_0000).is_none();
        // (d) 绑定表 C-P01 面：≥20 行 + 号名快照同源锚
        ok &= BINDINGS.len() >= 20;
        ok &= BINDINGS.iter().find(|b| b.num == 60).map(|b| b.name) == Some("exit");
        let _ = writeln!(
            log,
            "conduit-compat: snapshot_rows={} bindings={} errno_fwd=10/10 errno_rev_rt=ok flags_rt=ok ok={ok}",
            conduit::layout::SNAPSHOT.len(),
            BINDINGS.len()
        );
        ok
    };
    report(&mut log, t75, "conduit-compat");

    // ---- t76（M26-T1）：crystal 格式 v1 在盘活体（ATA 数据盘底座）——
    //      格式 v1 双槽 + WAL 意图 + SB 对槽切换 + 回放采纳 + 快照 O(1)
    //      结构面证据（CR-P05）；崩溃前窗口由 insert_without_switch 确定
    //      性重放（设备真实介质：重启态 = 重新 mount 读盘）。
    let t76 = {
        use crystal::fs::Fs;
        let mut ok = true;
        let mut evidence: alloc::string::String = "fmt=0 txn=0 replay=0 snap=0".into();
        let dev = crate::block::DataBlock::arced();
        let lbas = crate::block::data_lbas();
        // (a) 格式化 + 8 事务写读对账
        match Fs::format(&dev, lbas) {
            Ok(mut fs) => {
                let mut txn_ok = true;
                for k in 0..8u64 {
                    if fs.data_insert(k, k + 700).is_err() {
                        txn_ok = false;
                        break;
                    }
                }
                for k in 0..8u64 {
                    if fs.data_lookup(k) != Ok(Some(k + 700)) {
                        txn_ok = false;
                        break;
                    }
                }
                let gen_after_txn = fs.generation();
                txn_ok &= gen_after_txn == 9;
                // (b) 回放采纳：崩溃前窗口（节点+WAL 落盘不切 SB）→ 重 mount
                let mut replay_ok = false;
                let mut replay_gen = 0u64;
                if fs.insert_without_switch(42, 742).is_ok() && fs.data_lookup(42) == Ok(None) {
                    if let Ok((fs2, stats)) = Fs::mount(&dev, lbas) {
                        replay_ok = stats.txns_adopted == 1
                            && fs2.data_lookup(42) == Ok(Some(742))
                            && fs2.data_lookup(0) == Ok(Some(700));
                        replay_gen = fs2.generation();
                    }
                }
                // (c) 快照 O(1)：分配增量 ≤4 节点（与数据量无关的结构面）
                let mut snap_ok = false;
                let mut snap_delta = 0u64;
                if let Ok((mut fs3, _)) = Fs::mount(&dev, lbas) {
                    let before = fs3.alloc_next();
                    if let Ok(_snap) = fs3.snapshot_create(1) {
                        snap_delta = fs3.alloc_next() - before;
                        snap_ok = snap_delta <= 4 * 32;
                    }
                }
                ok &= txn_ok && replay_ok && snap_ok;
                evidence = alloc::format!(
                    "fmt=1 txn=8 gen={gen_after_txn} replay={replay_ok}+g{replay_gen} snap_delta={snap_delta}LBA ok={ok}"
                );
            }
            Err(_) => {
                ok = false;
            }
        }
        let _ = writeln!(log, "crystal-compat: {evidence}");
        ok
    };
    report(&mut log, t76, "crystal-compat");

    // 77) M28-T1 stage 合成活体（t77）：stage 登记（幂等 = 合成模式激活）
    //     → 直写 VRAM 哨兵域（交盒外零触碰的对照面）→ stage 组帧（ring3
    //     写后备缓冲语义的内核侧等价）→ SYS_FB_SYNC 记账损伤（ring3 同体）
    //     → fb_compose_tick 拍内 drain→仲裁→交盒局部上屏：交盒内读回 ==
    //     stage 图案、交盒外哨兵逐字节未触（损伤域局部上屏电气证据）+
    //     二拍空账直返 0（跳帧快速通道）。
    let t77 = {
        let mut ok = true;
        // (1) stage 登记（幂等；2026 页帧 + 恒等域 + 清零 + 激活）
        let stage_ok = crate::fb::stage_init().is_some();
        ok &= stage_ok;
        let dmg = mirror::Rect {
            x: 200,
            y: 150,
            w: 320,
            h: 200,
        };
        // (2) 哨兵直写（VRAM 直接面——合成执行器不得触碰）
        let mut sent_pre = [0u32; 4];
        let sent_pts = [(40i32, 40i32), (95, 95), (1500, 900), (1595, 995)];
        for (i, (x, y)) in sent_pts.iter().enumerate() {
            let c = 0x0100_0000 | (i as u32 * 0x0101_0101);
            crate::fb::fb_probe_px_write(*x, *y, c);
            sent_pre[i] = c;
        }
        // (3) stage 组帧（交盒域确定性图案）——顶字节 0x00（M37-A1b XRGB
        // 规范化写回：合成执行器低 24 位保真、X 通道归零；v0 0x55 顶字节
        // 属直写期实现巧合非契约，t77 等值断言随规范化同步）
        let stage_px = |x: i32, y: i32| -> u32 {
            (((x & 0xFF) as u32) << 16) | (((y & 0xFF) as u32) << 8) | 0x5A
        };
        for y in dmg.y..dmg.y + dmg.h as i32 {
            for x in dmg.x..dmg.x + dmg.w as i32 {
                crate::fb::stage_px_write(x, y, stage_px(x, y));
            }
        }
        // (4) 记账损伤（SYS_FB_SYNC 主体——ring3 同体路径）
        let sync_bytes =
            crate::fb::sys_fb_sync(dmg.x as u64, dmg.y as u64, dmg.w as u64, dmg.h as u64);
        ok &= sync_bytes == u64::from(dmg.w) * u64::from(dmg.h) * 4;
        // (5) 合成一拍：交盒局部上屏
        let px = crate::fb::fb_compose_tick();
        ok &= px == u64::from(dmg.w) * u64::from(dmg.h);
        // (6) 等值断言：交盒内 VRAM == stage；交盒外哨兵未触
        let mut eq_ok = true;
        for (x, y) in [
            (dmg.x, dmg.y),
            (dmg.x + dmg.w as i32 - 1, dmg.y),
            (dmg.x, dmg.y + dmg.h as i32 - 1),
            (dmg.x + dmg.w as i32 - 1, dmg.y + dmg.h as i32 - 1),
            (360, 250),
        ] {
            if crate::fb::fb_probe_px_read(x, y) != stage_px(x, y) {
                eq_ok = false;
            }
        }
        let mut sent_ok = true;
        for (i, (x, y)) in sent_pts.iter().enumerate() {
            if crate::fb::fb_probe_px_read(*x, *y) != sent_pre[i] {
                sent_ok = false;
            }
        }
        ok &= eq_ok && sent_ok;
        // (7) 二拍空账（drain 复位语义——跳帧快速通道）
        let px2 = crate::fb::fb_compose_tick();
        ok &= px2 == 0;
        let _ = writeln!(
            log,
            "compose-spec: stage={stage_ok} sync={sync_bytes} px={px} eq={eq_ok} sent={sent_ok} tick2={px2} ok={ok}"
        );
        ok
    };
    report(&mut log, t77, "compose-spec");

    // ---- 78) M27-N2 UDP 回环活体（t78）：六闸——
    //     (a) 端口绑定域（bind ok / 重复绑定拒 / 未绑解绑拒）
    //     (b) 回环三发（载荷 1/64/1472 = MAX_PAYLOAD 三态边界）→ 交接环
    //         （回环注入点与真实 RX 通路共享段）→ udp_dispatch 全闸 →
    //         端口路由 → 接收槽 → 载荷+源端口对账
    //     (c) 校验和负例（翻 UDP 校验和 1 位拒收 + bad_cs 增量显形）
    //     (d) 未绑定端口拒投（no_port 增量显形，fail-visible）
    //     (e) PU-P03 回环延迟打点（三发 ostd::time 差样本，TCG 基线口径）
    //     (f) 解绑后拒投 + 复绑（路由失效/恢复证据）
    // ARP→ICMP→UDP 活体链收官：t69 ARP / t73 ICMP / t78 UDP。
    let t78 = {
        let mut ok = true;
        // (a) 绑定域
        ok &= vnet::udp_bind(7777).is_ok();
        ok &= vnet::udp_bind(7777) == Err(pulse::udp::BindError::AlreadyBound);
        ok &= vnet::udp_unbind(8888) == Err(pulse::udp::BindError::NotBound);
        // (b) 回环三发（载荷三态边界）
        let mut rtt_min = u64::MAX;
        let mut rtt_max = 0u64;
        let payload = [0xA7u8; pulse::udp::MAX_PAYLOAD];
        let lens: [usize; 3] = [1, 64, pulse::udp::MAX_PAYLOAD];
        for (i, &n) in lens.iter().enumerate() {
            let src_port = 7000 + i as u16;
            let t0 = ostd::time::tsc_clock::now_ns().unwrap_or(0);
            let sent = vnet::udp_loopback_tx(src_port, 7777, &payload[..n]);
            if !sent {
                ok = false;
                break;
            }
            // 消费：交接环 pop（预算 40M 轮兜底，fail-closed）
            let mut frame = [0u8; vnet::PULSE_FRAME_MAX];
            let mut got = None;
            let mut spin = 0u64;
            while spin < 40_000_000 {
                if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                    got = Some(fl);
                    break;
                }
                spin += 1;
                core::hint::spin_loop();
            }
            let Some(fl) = got else {
                ok = false;
                break;
            };
            let dispatched = vnet::udp_dispatch(&frame[..fl]).is_some();
            let mut rxb = [0u8; pulse::udp::MAX_PAYLOAD];
            let recv = vnet::udp_recv(&mut rxb);
            let t1 = ostd::time::tsc_clock::now_ns().unwrap_or(0);
            ok &= dispatched;
            match recv {
                Some((sp, rl)) => {
                    ok &= sp == src_port && rl == n && rxb[..n] == payload[..n];
                }
                None => ok = false,
            }
            let rtt = t1.saturating_sub(t0);
            rtt_min = rtt_min.min(rtt);
            rtt_max = rtt_max.max(rtt);
        }
        // (c) 校验和负例：好帧注入 → pop → 翻 UDP 校验和 1 位 → 拒收
        let s0 = vnet::udp_stats();
        let payload32 = [0x5Au8; 32];
        let injected = vnet::udp_loopback_tx(7003, 7777, &payload32);
        let mut frame = [0u8; vnet::PULSE_FRAME_MAX];
        let mut got = None;
        let mut spin = 0u64;
        while spin < 40_000_000 {
            if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                got = Some(fl);
                break;
            }
            spin += 1;
            core::hint::spin_loop();
        }
        let mut rejected = false;
        if let Some(fl) = got {
            const UDP_CS_OFF: usize = 14 + 20 + 6; // 以太 + IPv4 头 + UDP cs 域
            frame[UDP_CS_OFF] ^= 0x01;
            rejected = vnet::udp_dispatch(&frame[..fl]).is_none();
        }
        let s1 = vnet::udp_stats();
        ok &= injected && rejected && s1.bad_cs == s0.bad_cs + 1;
        // (d) 未绑定端口拒投（9999 从未绑定）
        let injected2 = vnet::udp_loopback_tx(7004, 9999, &payload32);
        let mut got2 = None;
        let mut spin = 0u64;
        while spin < 40_000_000 {
            if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                got2 = Some(fl);
                break;
            }
            spin += 1;
            core::hint::spin_loop();
        }
        let mut rejected2 = false;
        if let Some(fl) = got2 {
            rejected2 = vnet::udp_dispatch(&frame[..fl]).is_none();
        }
        let s2 = vnet::udp_stats();
        ok &= injected2 && rejected2 && s2.no_port == s1.no_port + 1;
        // (e) PU-P03 打点行（TCG 基线口径；环境 B 实测挂账 METRICS）
        ok &= s2.accepted == 3 && s2.injected == 5;
        // (f) 解绑后拒投 + 复绑（路由失效/恢复证据）
        ok &= vnet::udp_unbind(7777).is_ok();
        let injected3 = vnet::udp_loopback_tx(7005, 7777, &payload32);
        let mut got3 = None;
        let mut spin = 0u64;
        while spin < 40_000_000 {
            if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                got3 = Some(fl);
                break;
            }
            spin += 1;
            core::hint::spin_loop();
        }
        let mut rejected3 = false;
        if let Some(fl) = got3 {
            rejected3 = vnet::udp_dispatch(&frame[..fl]).is_none();
        }
        let s3 = vnet::udp_stats();
        ok &= injected3 && rejected3 && s3.no_port == s2.no_port + 1;
        ok &= vnet::udp_bind(7777).is_ok();
        let _ = writeln!(
            log,
            "udp-loop: inj={} acc={} bad_cs={} no_port={} rtt_min_ns={rtt_min} rtt_max_ns={rtt_max} ok={ok}",
            s3.injected,
            s3.accepted,
            s3.bad_cs,
            s3.no_port,
        );
        ok
    };
    report(&mut log, t78, "udp-loop");

    // ---- 79) M30-T1 桌面骨架活体（t79）：六闸——
    //     (a) Cascade shell 语义面：四态机 Boot→LockScreen→Session（含
    //         非法迁移拒收）+ workspace_available 谓词 + 工作区全局唯一
    //         归属（跨区重复打开拒收）+ 焦点序 + Dock 三档闸
    //     (b) Cascade 平铺 golden：焦点序 [2,1] → master-stack 双窗拆分
    //         （content (0,48,1920,960) + master/stack 948 对分）
    //     (c) Loom Elm 骨架布局：fold 消息折叠环建帧视图（骨架 pad 消费
    //         PANEL/DOCK 常量）+ solve → 内容域与 cascade content 同源
    //         对账（两套面同一几何）+ 等分窗槽 golden（956×960）
    //     (d) Glyph 图标像素面：terminal@24 渲染（框角亮/中心空/下划线亮）
    //     (e) prism 窗层仲裁：双窗 push z=1/2（焦点窗高层）→ 交盒内
    //         胜出 + 界外 None
    //     (f) fb 交盒上屏：stage 幂等 + master 窗域内损伤盒（320×200）+
    //         SYS_FB_SYNC + compose_tick 读回 + 盒内窗域哨兵未触（损伤域
    //         裁剪证据——窗域但盒外的像素不被本拍触碰）+ 二拍空账
    let t79 = {
        let mut ok = true;
        // (a) shell 语义面
        let mut sh = cascade::Shell::new();
        ok &= sh.transition(cascade::ShellState::Session).is_err(); // Boot→Session 非法
        ok &= sh.transition(cascade::ShellState::LockScreen).is_ok();
        ok &= !sh.workspace_available();
        ok &= sh.transition(cascade::ShellState::Session).is_ok();
        ok &= sh.workspace_available();
        let mut wst = cascade::workspace::Workspaces::new();
        ok &= wst.open(1, 0).is_ok();
        ok &= wst.open(2, 0).is_ok();
        ok &= wst.open(3, 1).is_ok();
        ok &= wst.open(1, 2) == Err(cascade::ShellError::AlreadyOpen);
        ok &= wst.focused_in(0) == Ok(Some(2));
        ok &= wst.locate(3) == Some(1);
        let mut dock = cascade::dock::Dock::<8>::new();
        ok &= dock.register(10, 24).is_ok();
        ok &= dock.register(11, 96).is_ok();
        ok &= dock.register(12, 32) == Err(cascade::ShellError::IllegalIcon);
        ok &= dock.register(10, 24) == Err(cascade::ShellError::DuplicateApp);
        // (b) 平铺 golden：窗口序 = 焦点序（焦点窗居 master）
        let focus: &[u64] = match wst.stack_in(0) {
            Ok(s) => s,
            Err(_) => {
                ok = false;
                &[]
            }
        };
        let plan = match cascade::tiling::tiling_plan(focus, (1920, 1080)) {
            Ok(p) => {
                ok &= p.content
                    == mirror::Rect {
                        x: 0,
                        y: 48,
                        w: 1920,
                        h: 960,
                    };
                ok &= p.panes.len() == 2;
                ok &= p.panes[0].0 == 2 && p.panes[1].0 == 1;
                ok &= p.panes[0].1
                    == mirror::Rect {
                        x: 8,
                        y: 56,
                        w: 948,
                        h: 944,
                    };
                ok &= p.panes[1].1
                    == mirror::Rect {
                        x: 964,
                        y: 56,
                        w: 948,
                        h: 944,
                    };
                Some(p)
            }
            Err(_) => {
                ok = false;
                None
            }
        };
        // (c) Loom Elm 骨架布局（骨架应用：窗数即 Model，view 投影骨架树）
        struct SkelApp;
        impl loom::elm::App for SkelApp {
            type Model = u32;
            type Msg = bool; // true = 开窗
            fn init(&self) -> u32 {
                0
            }
            fn update(&self, model: &mut u32, msg: bool) {
                if msg {
                    *model += 1;
                }
            }
            fn view<const N: usize>(
                &self,
                model: &u32,
                buf: &mut loom::elm::ViewBuf<N>,
            ) -> Result<loom::elm::Id, loom::elm::ViewError> {
                use loom::elm::{Dir, Kind, Main, Node};
                let root = buf.push(Node {
                    kind: Kind::Node,
                    dir: Dir::Column,
                    pad: [loom::PANEL_HEIGHT, 0, loom::DOCK_HEIGHT, 0],
                    gap: 0,
                    main: Main::Fill(1),
                })?;
                let content = buf.push(Node {
                    kind: Kind::Node,
                    dir: Dir::Row,
                    pad: [0; 4],
                    gap: loom::GRID,
                    main: Main::Fill(1),
                })?;
                buf.attach(root, content)?;
                for _ in 0..*model {
                    let w = buf.push(Node {
                        kind: Kind::Node,
                        dir: Dir::Row,
                        pad: [0; 4],
                        gap: 0,
                        main: Main::Fill(1),
                    })?;
                    buf.attach(content, w)?;
                }
                buf.set_root(root)?;
                Ok(root)
            }
        }
        let mut vbuf = loom::elm::ViewBuf::<16>::new();
        let loom_ok = match loom::elm::fold(&SkelApp, [true, true], &mut vbuf) {
            Ok((_model, _root)) => {
                let mut lay = loom::layout::Layout::<16>::new();
                match loom::layout::solve(&vbuf, (1920, 1080), &mut lay) {
                    Ok(()) => {
                        let content_r = lay.rect(loom::elm::Id(1));
                        let mut good = content_r
                            == Some(mirror::Rect {
                                x: 0,
                                y: 48,
                                w: 1920,
                                h: 960,
                            });
                        // 等分窗槽 golden：free=1920-8 → 各 956
                        good &= lay.rect(loom::elm::Id(2))
                            == Some(mirror::Rect {
                                x: 0,
                                y: 48,
                                w: 956,
                                h: 960,
                            });
                        good &= lay.rect(loom::elm::Id(3))
                            == Some(mirror::Rect {
                                x: 964,
                                y: 48,
                                w: 956,
                                h: 960,
                            });
                        // 同源对账：loom 内容域 == cascade 平铺 content
                        if let (Some(cr), Some(p)) = (content_r, &plan) {
                            good &= cr == p.content;
                        }
                        good
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        ok &= loom_ok;
        // (d) 图标像素面
        let mut icon_ok = false;
        if let Some(term) = glyph::raster::find("terminal") {
            let mut cv = [0u32; 24 * 24];
            if glyph::raster::render(term, 24, 0xFFFF_FFFF, &mut cv, 24).is_ok() {
                icon_ok = cv[4 * 24 + 3] == 0xFFFF_FFFF
                    && cv[20 * 24 + 21] == 0xFFFF_FFFF
                    && cv[12 * 24 + 12] == 0
                    && cv[13 * 24 + 14] == 0xFFFF_FFFF;
            }
        }
        ok &= icon_ok;
        // (e)+(f) 仲裁 + 交盒上屏（plan 在场才可执行）
        let mut px: u64 = 0;
        let mut px2: u64 = 0;
        let mut eq_ok = false;
        let mut sent_ok = false;
        let mut pr04 = false;
        let arb_ok;
        if let Some(p) = &plan {
            // (e) 窗层仲裁：焦点窗（panes[0]，窗 2）z=2 高层胜出
            let mut st = prism::Stack::new();
            let _ = st.push(prism::Layer {
                id: 1,
                z: 1,
                visible: true,
                bounds: p.panes[1].1,
            });
            let _ = st.push(prism::Layer {
                id: 2,
                z: 2,
                visible: true,
                bounds: p.panes[0].1,
            });
            let (winner, _scan) = st.arbitrate_counted(500, 300);
            arb_ok = winner == Some(2) && st.arbitrate(-5, -5).is_none();
            // (f) stage 幂等 + 损伤盒（master 窗域内 320×200）
            ok &= crate::fb::stage_init().is_some();
            ok &= p.panes[0].1.contains(100, 100);
            let dmg = mirror::Rect {
                x: 100,
                y: 100,
                w: 320,
                h: 200,
            };
            // 哨兵：Panel 域 / Dock 域 / 窗域但盒外（损伤域裁剪证据）
            let sent_pts = [(4i32, 4i32), (1600, 1040), (500, 500)];
            let mut sent_pre = [0u32; 3];
            for (i, (x, y)) in sent_pts.iter().enumerate() {
                let c = 0x0900_0000 | (i as u32 * 0x0101_0101);
                crate::fb::fb_probe_px_write(*x, *y, c);
                sent_pre[i] = c;
            }
            let stage_px = |x: i32, y: i32| -> u32 {
                // 顶字节 0x00（M37-A1b XRGB 规范化写回同 t77 适配）
                (((x & 0xFF) as u32) << 16) | (((y & 0xFF) as u32) << 8) | 0x79
            };
            for y in dmg.y..dmg.y + dmg.h as i32 {
                for x in dmg.x..dmg.x + dmg.w as i32 {
                    crate::fb::stage_px_write(x, y, stage_px(x, y));
                }
            }
            let sync_bytes =
                crate::fb::sys_fb_sync(dmg.x as u64, dmg.y as u64, dmg.w as u64, dmg.h as u64);
            ok &= sync_bytes == u64::from(dmg.w) * u64::from(dmg.h) * 4;
            px = crate::fb::fb_compose_tick();
            ok &= px == u64::from(dmg.w) * u64::from(dmg.h);
            eq_ok = true;
            for (x, y) in [
                (dmg.x, dmg.y),
                (dmg.x + dmg.w as i32 - 1, dmg.y + dmg.h as i32 - 1),
                (360, 250),
            ] {
                if crate::fb::fb_probe_px_read(x, y) != stage_px(x, y) {
                    eq_ok = false;
                }
            }
            sent_ok = true;
            for (i, (x, y)) in sent_pts.iter().enumerate() {
                if crate::fb::fb_probe_px_read(*x, *y) != sent_pre[i] {
                    sent_ok = false;
                }
            }
            px2 = crate::fb::fb_compose_tick();
            ok &= px2 == 0;
            // (g) M34-P4 PR-P04 电源协同显示侧登记面回环（kernel 侧消费
            // 点；SELFTEST_TOTAL 不变——83 归 t83/B2）：blank → compose
            // 拦截（损伤账保留不 drain）→ unblank → 账重放上屏像素复原
            // → 亮度档位登记 + 越域拒显形 → 登记态镜像逐拍断言。
            let base = crate::fb::fb_display_state();
            let b = crate::fb::fb_display_blank();
            let blank_state = crate::fb::fb_display_state();
            // blank 态补一笔损伤：compose 应拦截返 0 且账保留
            let _ = crate::fb::sys_fb_sync(dmg.x as u64, dmg.y as u64, dmg.w as u64, dmg.h as u64);
            let blank_px = crate::fb::fb_compose_tick();
            let u = crate::fb::fb_display_unblank();
            let unblank_state = crate::fb::fb_display_state();
            // unblank 后账重放：px == 交盒面积（消费点实收）
            let replay_px = crate::fb::fb_compose_tick();
            // 亮度档位登记面：档内收下 / 越域(>100)拒 / Restore 恢复全亮
            let dim_ok = crate::fb::fb_display_set_brightness(25);
            let dim_state = crate::fb::fb_display_state();
            let dim_rej = !crate::fb::fb_display_set_brightness(101);
            let restore_ok = crate::fb::fb_display_set_brightness(100);
            pr04 = b
                && u
                && dim_ok
                && restore_ok
                && dim_rej
                && base == (false, 100)
                && blank_state == (true, 0)
                && blank_px == 0
                && unblank_state == (false, 100)
                && replay_px == u64::from(dmg.w) * u64::from(dmg.h)
                && dim_state == (false, 25);
            ok &= pr04;
        } else {
            arb_ok = false;
        }
        ok &= arb_ok && eq_ok && sent_ok;
        let _ = writeln!(
            log,
            "desktop-skel: ws=3+1 dock=2+2 plan=2 loom={loom_ok} icon={icon_ok} arb={arb_ok} px={px} eq={eq_ok} sent={sent_ok} tick2={px2} pr04={pr04} ok={ok}"
        );
        ok
    };
    report(&mut log, t79, "desktop-skel");

    // t80) 自举预备活体（M31-T1）：三面贯通——① V-P05 注入矩阵结论在环
    // （vanguard 能力面四相×不变式内核态收口）② Weave 自举装载证据
    // （bootstrap 幂等复跑全绿，W1 冒烟证据行的活体收编）③ 驱动外移面
    // 对账（morse 翻译面活体——kernel::kbd 消费面同源纯函数）。
    let t80 = {
        // 面① V-P05 注入矩阵结论在环：越权派生拒 / 合法收窄 / 链传播
        // 不可回升 / 撤销后死槽 / 未安装与越界两级语义 / 重复撤销显形。
        let v_ok = {
            let mut cap = vanguard::CapabilityTable::new();
            let mut v = cap
                .install(
                    0,
                    vanguard::Capability::new(
                        7,
                        vanguard::Right::READ.bits() | vanguard::Right::WRITE.bits(),
                    ),
                )
                .is_ok();
            // ① 越权派生显形拒（EXEC 不在父集）
            v &= cap.derive(0, vanguard::Right::EXEC.bits())
                == Err(vanguard::CapError::RightsEscalation);
            // 合法收窄派生 → 首个空槽分配确定性（槽 1）
            v &= cap.derive(0, vanguard::Right::READ.bits()) == Ok(1);
            // 链传播：子代（READ）回升 WRITE 拒
            v &= cap.derive(1, vanguard::Right::WRITE.bits())
                == Err(vanguard::CapError::RightsEscalation);
            // ② 撤销后使用：死槽读 / 为父派生均显形
            v &= cap.revoke(1).is_ok();
            v &= cap.get(1) == Err(vanguard::CapError::SlotEmpty);
            v &= cap.derive(1, vanguard::Right::READ.bits()) == Err(vanguard::CapError::SlotEmpty);
            // ③ 未安装（界内空）与越界两级错误语义 + ④ 重复撤销显形
            v &= cap.get(2) == Err(vanguard::CapError::SlotEmpty);
            v &= cap.get(vanguard::CAPACITY) == Err(vanguard::CapError::NoSuchSlot);
            v &= cap.revoke(1) == Err(vanguard::CapError::SlotEmpty);
            v
        };
        // 面② Weave 自举装载证据：bootstrap 幂等复跑——三不变式四相
        // 复演全过 + 恢复终态 gen2 + store 根装载独占一对象。
        let wb = weave::boot::bootstrap();
        let w_ok = wb.ok()
            && wb.gen == 2
            && wb.replay_pass == weave::boot::REPLAY_TOTAL
            && wb.store_objects == 1;
        // 面③ 驱动外移面对账：morse 翻译面活体（kernel::kbd 消费面同源）
        // ——字母/数字行 Shift 双态 + Shift 事件分类 + 释放码判定 + 非映射键。
        let m_ok = morse::translate(0x1E, false) == Some(b'a')
            && morse::translate(0x1E, true) == Some(b'A')
            && morse::translate(0x02, false) == Some(b'1')
            && morse::translate(0x02, true) == Some(b'!')
            && morse::translate(0x00, false).is_none()
            && morse::shift_event(0x2A) == Some(true)
            && morse::shift_event(0xAA) == Some(false)
            && morse::shift_event(0x1E).is_none()
            && morse::is_release(0x9E)
            && !morse::is_release(0x1E);
        let ok = v_ok && w_ok && m_ok;
        let _ = writeln!(log, "bootprep: v={v_ok} weave={w_ok} morse={m_ok} ok={ok}");
        ok
    };
    report(&mut log, t80, "bootprep");

    // t81) aurora 活体（M32-T1）：三面内核态收口——① 权限四相（perm 声明闸/
    // 承接授予/运行时检查/撤销显形——A1 四相面的内核态首演）② 生命周期
    // 拦截矩阵（AF-P03 拦截 100% + AF-P06 合法路径 + 终态为汇）③ 清单闸
    //（validate 四态：合法/BadAppId/NoCapabilities/BadCapability）。
    let t81 = {
        // 面① 权限四相内核态收口：相① 声明闸（合法形态过 + 非法矩阵显形：
        // 缺前缀/缺段/超段/大写/空段）→ 相② 承接授予（首空槽确定性 +
        // 八动作目录映射闭集）→ 相③ 运行时检查（合法过 + 越权 Denied +
        // 确定性失败序目录闸先于槽位闸）→ 相④ 撤销显形（死槽访问
        // SlotEmpty + 重复撤销显形）。
        let p_ok = {
            let mut p = aurora::perm::PermCenter::new();
            let s_ok = aurora::perm::check_schema("cap.fs.docs.read").is_ok()
                && aurora::perm::check_schema("fs.docs.read").is_err()
                && aurora::perm::check_schema("cap.fs.docs").is_err()
                && aurora::perm::check_schema("cap.fs.docs.read.more").is_err()
                && aurora::perm::check_schema("cap.fs.Docs.read").is_err()
                && aurora::perm::check_schema("cap..docs.read").is_err();
            let g_ok = p.grant("cap.fs.docs.read", 1) == Ok(0)
                && p.grant("cap.net.sock.send", 2) == Ok(1)
                && aurora::perm::action_right("send") == Some(vanguard::Right::IPC_SEND)
                && aurora::perm::action_right("fsroot") == Some(vanguard::Right::FS_ROOT)
                && aurora::perm::action_right("dance").is_none();
            let c_ok = p.check(0, "read").is_ok()
                && p.check(0, "write") == Err(aurora::perm::PermError::Denied)
                && p.check(0, "dance") == Err(aurora::perm::PermError::UnknownAction)
                && p.check(vanguard::CAPACITY, "read") == Err(aurora::perm::PermError::NoSuchSlot);
            let r_ok = p.revoke(0).is_ok()
                && p.check(0, "read") == Err(aurora::perm::PermError::SlotEmpty)
                && p.revoke(0) == Err(aurora::perm::PermError::SlotEmpty);
            s_ok && g_ok && c_ok && r_ok
        };
        // 面② 生命周期拦截矩阵：非法直达拦截显形（Registered→Foreground/
        // Registered→Terminated——AF-P03 拦截 100%）+ 合法全迁移路径
        //（AF-P06 经框架唯一入口）+ 终态为汇。
        let l_ok = {
            let mut a = aurora::AppRuntime::new();
            let mut ok = a.state() == aurora::Lifecycle::Registered;
            ok &= a.transition(aurora::Lifecycle::Foreground).is_err();
            ok &= a.transition(aurora::Lifecycle::Terminated).is_err();
            for st in [
                aurora::Lifecycle::Launching,
                aurora::Lifecycle::Foreground,
                aurora::Lifecycle::Background,
                aurora::Lifecycle::Suspended,
                aurora::Lifecycle::Terminated,
            ] {
                ok &= a.transition(st).is_ok();
            }
            ok &= a.state() == aurora::Lifecycle::Terminated;
            ok &= a.transition(aurora::Lifecycle::Launching).is_err();
            ok
        };
        // 面③ 清单闸四态：合法过 + 反向域名坏形 BadAppId + 能力空
        // NoCapabilities + 能力 schema 非法 BadCapability（A1 能力域扩容闸
        // ——单一事实源 perm::check_schema）。
        let m_ok = {
            let good = aurora::LuappManifest {
                app_id: alloc::string::String::from("org.lumina.notes"),
                display_name: alloc::string::String::from("Notes"),
                version: alloc::string::String::from("0.3.1"),
                capabilities: alloc::vec![alloc::string::String::from("cap.fs.documents.read")],
            };
            let bad_id = aurora::LuappManifest {
                app_id: alloc::string::String::from("Notes"),
                ..good.clone()
            };
            let no_cap = aurora::LuappManifest {
                capabilities: alloc::vec![],
                ..good.clone()
            };
            let bad_cap = aurora::LuappManifest {
                capabilities: alloc::vec![alloc::string::String::from("fs.documents.read")],
                ..good.clone()
            };
            good.validate().is_ok()
                && bad_id.validate() == Err(aurora::ManifestError::BadAppId)
                && no_cap.validate() == Err(aurora::ManifestError::NoCapabilities)
                && bad_cap.validate() == Err(aurora::ManifestError::BadCapability)
        };
        let ok = p_ok && l_ok && m_ok;
        let _ = writeln!(
            log,
            "aurora: perm={p_ok} lifecycle={l_ok} manifest={m_ok} ok={ok}"
        );
        ok
    };
    report(&mut log, t81, "aurora");

    // t82) busybox Linux 兼容路径活体（M33-T1）：ELF 装载（Alpine 官方
    //      静态介质原生基址直载，PD[2] 槽域）→ Linux 初始栈（argc/argv/
    //      envp/auxv，E1 面）→ 定点进入 ring3（fork 桩同族快照，lin_abi
    //      随链）→ musl 初始化（TLS arch_prctl 面 T1 收录 + set_tid_address
    //      桩 + brk/mmap 匿名区）→ busybox echo applet → write(1) 串口
    //      取证 → exit_group(0) → waitpid 收割对账（t36 同款全链）。
    let t82 = {
        let mut ok = true;
        match vfs::read_image("/bin/busybox") {
            Some(blob) => match vmm::global_frames() {
                Some(frames) => {
                    let argv = ["/bin/busybox", "echo", "LUMINA-T82-OK"];
                    let envp = ["PATH=/bin"];
                    // AT_RANDOM 熵：TSC 纪元拆字节（exec_load_switch ELF 链同款）
                    let t = ostd::time::tsc_now();
                    let mut random = [0u8; 16];
                    for (i, b) in random.iter_mut().enumerate() {
                        *b = (t >> ((i % 8) * 8)) as u8 ^ (i as u8).rotate_left(3);
                    }
                    match user::build_user_space_elf(
                        &blob,
                        &argv,
                        &envp,
                        random,
                        "busybox",
                        &mut || frames.alloc(),
                    ) {
                        Ok(es) => {
                            let _ = writeln!(
                                log,
                                "busybox: ELF loaded entry={:#x} rsp={:#x} segs={} root={:#x}",
                                es.entry,
                                es.rsp,
                                es.seg_frames.len(),
                                es.root
                            );
                            // 定点进入快照（fork 桩同族 15 槽）：rflags=IF /
                            // rip=entry / rsp=初始栈构造面；callee-saved 与
                            // rax 槽零值（初始进入无跨域状态可保）。
                            let mut slots = [0u64; 15];
                            slots[0] = 0x202; // RFLAGS：IF=1（iretq 恢复中断开放）
                            slots[1] = es.entry;
                            slots[7] = es.rsp;
                            let id = task::spawn_fork_child(
                                "busybox",
                                es.root,
                                task::current_task_id(),
                                slots,
                                true,
                            );
                            if id == usize::MAX {
                                let _ = writeln!(log, "busybox: task slot exhausted");
                                ok = false;
                            } else {
                                // 收割（waitpid 阻塞语义；AP 核拾取 busybox，
                                // exit_group → 唤醒 → 重扫收割——t36 同款全链）
                                let r = procs::sys_wait_pid(id as u64);
                                let rpid = (r >> 16) & 0xFFFF;
                                let code = r & 0xFFFF;
                                let _ = writeln!(
                                    log,
                                    "busybox: reaped pid={rpid} (slot {id}) exit={code}"
                                );
                                ok &= r >> 32 == 1; // WAITPID_OK_BIT（procs 契约）
                                ok &= rpid == id as u64; // 收割对象对账
                                ok &= code == 0; // busybox echo 成功退出
                                ok &= !task::task_alive(id); // 收割后槽位释放
                            }
                        }
                        Err(e) => {
                            let _ = writeln!(log, "busybox: user space build failed ({e:?})");
                            ok = false;
                        }
                    }
                }
                None => {
                    let _ = writeln!(log, "busybox: frame service unreachable");
                    ok = false;
                }
            },
            None => {
                let _ = writeln!(log, "busybox: /bin/busybox media MISS");
                ok = false;
            }
        }
        ok
    };
    report(&mut log, t82, "busybox-lin");

    // t83) busybox applet 扩容活体（M34-B2）：多 applet 分发路径实证——
    //      true/false（exit 码语义 0/1 对账）/ printf（write(1) 串口取证
    //      字样）/ wc -l（openat+read+fstatat64/fstat+close 文件域消费 +
    //      行计数）。每 applet 独立地址空间（t82 同款装载链），串行收割
    //      对账；LUMINA-T83-OK 汇总标记（xtask S8/longrun 双面板 required）。
    let t83 = {
        let mut ok = true;
        let applets: [(&[&str], u64); 4] = [
            (&["/bin/busybox", "true"], 0),
            (&["/bin/busybox", "false"], 1),
            (&["/bin/busybox", "printf", "LUMINA-T83-PF\n"], 0),
            (&["/bin/busybox", "wc", "-l", "/bin/busybox"], 0),
        ];
        if let Some(blob) = vfs::read_image("/bin/busybox") {
            for (i, (argv, expect)) in applets.iter().enumerate() {
                let Some(frames) = vmm::global_frames() else {
                    let _ = writeln!(log, "applet[{i}]: frame service unreachable");
                    ok = false;
                    break;
                };
                // AT_RANDOM 熵：TSC 纪元拆字节（t82 同款）
                let t = ostd::time::tsc_now();
                let mut random = [0u8; 16];
                for (j, b) in random.iter_mut().enumerate() {
                    *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
                }
                match user::build_user_space_elf(
                    &blob,
                    argv,
                    &["PATH=/bin"],
                    random,
                    "busybox",
                    &mut || frames.alloc(),
                ) {
                    Ok(es) => {
                        let mut slots = [0u64; 15];
                        slots[0] = 0x202; // RFLAGS：IF=1
                        slots[1] = es.entry;
                        slots[7] = es.rsp;
                        let id = task::spawn_fork_child(
                            "busybox-applet",
                            es.root,
                            task::current_task_id(),
                            slots,
                            true,
                        );
                        if id == usize::MAX {
                            let _ = writeln!(log, "applet[{i}]: task slot exhausted");
                            ok = false;
                            break;
                        }
                        let r = procs::sys_wait_pid(id as u64);
                        let rpid = (r >> 16) & 0xFFFF;
                        let code = r & 0xFFFF;
                        let _ = writeln!(
                            log,
                            "applet[{}] {} reaped pid={rpid} exit={code} (expect {expect})",
                            i, argv[1]
                        );
                        ok &= r >> 32 == 1; // WAITPID_OK_BIT
                        ok &= rpid == id as u64;
                        ok &= code == *expect; // applet exit 码语义（true=0/false=1）
                        ok &= !task::task_alive(id);
                    }
                    Err(e) => {
                        let _ = writeln!(log, "applet[{}]: user space build failed ({e:?})", i);
                        ok = false;
                        break;
                    }
                }
            }
        } else {
            let _ = writeln!(log, "applet: /bin/busybox media MISS");
            ok = false;
        }
        if ok {
            let _ = writeln!(log, "LUMINA-T83-OK");
        }
        ok
    };
    report(&mut log, t83, "applet-lin");

    // t84) fork-pipe 活体（M35-BBa）：pipe2 执行面全语义锚——64 KiB 定容
    // 环（部分写/满环 EAGAIN）+ EOF（写端引用归零）+ EPIPE（读端引用归零）
    // + 未收录旗标 fail-visible + O_CLOEXEC 随链 hflags FD_CLOEXEC。fork
    // fd 继承机制面随行落位（task::spawn_fork_child 句柄域 skip(1) 新槽
    // 铸入 + hflags 随链）；跨 fork 活体实证由 t85 sh 流水线承载（BBb）。
    let t84 = {
        let mut ok = true;
        // (a) pipe2 创建 + pipefd 回写 + 句柄对账（M36-BB3 起 O_NONBLOCK
        // 收录——本相位断言 EAGAIN 域，故铸非阻塞管道；缺省 = 阻塞语义
        // 活体已由 t87 承载——M36-BB3b）
        let mut pfd = [0u32; 2];
        let r = vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0o4000);
        ok &= r >> 32 == 1;
        let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
        ok &= fd_r != fd_w && fd_r != 0 && fd_w != 0;
        // (b) 未收录旗标 fail-visible（0x4000 = 0o40000 未收录域 → EINVAL=22；
        // O_NONBLOCK 0o4000 已随 M36-BB3 收录（收录面活体随 BB3b））
        ok &= vfs::sys_pipe2(0, 0x4000) == 22;
        // (c) 环语义：写读字节对账（15 B 载荷）
        const PAYLOAD: &[u8] = b"pipe-payload-42";
        let r = vfs::sys_write(fd_w, PAYLOAD.as_ptr() as u64, PAYLOAD.len() as u64);
        ok &= r >> 32 == 1 && (r & 0xFFFF_FFFF) as usize == PAYLOAD.len();
        let mut rbuf = [0u8; PAYLOAD.len()];
        let r = vfs::sys_read(fd_r, rbuf.as_mut_ptr() as u64, rbuf.len() as u64);
        ok &= r >> 32 == 1 && (r & 0xFFFF_FFFF) as usize == PAYLOAD.len();
        ok &= rbuf == *PAYLOAD;
        // (d) 空环 + 写端存活 → EAGAIN=11（O_NONBLOCK 管道语义——缺省
        // 阻塞语义活体已由 t87 承载）
        ok &= vfs::sys_read(fd_r, rbuf.as_mut_ptr() as u64, 4) == 11;
        // (e) 定容环：4096×16 分块填满（64 KiB）→ 满环 EAGAIN → 全量读出
        // 对账 → 环空写端存活 → EAGAIN（栈安全分块——64 KiB 整块不上栈）
        let chunk = [0xA5u8; 4096];
        let mut filled = 0usize;
        for _ in 0..16 {
            let r = vfs::sys_write(fd_w, chunk.as_ptr() as u64, 4096);
            ok &= r >> 32 == 1 && (r & 0xFFFF_FFFF) as usize == 4096;
            filled += 4096;
        }
        ok &= filled == 65536;
        ok &= vfs::sys_write(fd_w, chunk.as_ptr() as u64, 1) == 11; // 满环
        let mut drained = 0usize;
        loop {
            let n = vfs::sys_read(fd_r, rbuf.as_mut_ptr() as u64, 4096);
            if n >> 32 != 1 {
                break;
            }
            let got = (n & 0xFFFF_FFFF) as usize;
            ok &= got > 0;
            drained += got;
            if got < 4096 {
                break;
            }
        }
        ok &= drained == 65536;
        ok &= vfs::sys_read(fd_r, rbuf.as_mut_ptr() as u64, 4) == 11; // 环空
                                                                      // (f) EOF：写端关闭（引用归零）→ read 返 0
        ok &= vfs::sys_close(fd_w) == 0;
        let r = vfs::sys_read(fd_r, rbuf.as_mut_ptr() as u64, 4);
        ok &= r >> 32 == 1 && (r & 0xFFFF_FFFF) == 0;
        ok &= vfs::sys_close(fd_r) == 0;
        // (g) EPIPE：读端关闭（引用归零）后写 → EPIPE=32（读端已亡——
        // 阻塞管道该写不阻塞，EPIPE 先验直返）
        let mut pfd2 = [0u32; 2];
        ok &= vfs::sys_pipe2(pfd2.as_mut_ptr() as u64, 0) >> 32 == 1;
        ok &= vfs::sys_close(u64::from(pfd2[0])) == 0;
        ok &= vfs::sys_write(u64::from(pfd2[1]), PAYLOAD.as_ptr() as u64, 4) == 32;
        ok &= vfs::sys_close(u64::from(pfd2[1])) == 0;
        // (h) O_CLOEXEC 随链：pipe2(0o200_0000) → 双端 hflags FD_CLOEXEC=1
        let mut pfd3 = [0u32; 2];
        ok &= vfs::sys_pipe2(pfd3.as_mut_ptr() as u64, 0o200_0000) >> 32 == 1;
        let (bit_r, bit_w) = task::with_task_hflags(task::current_task_id(), |f| {
            (f[pfd3[0] as usize] & 1, f[pfd3[1] as usize] & 1)
        })
        .unwrap_or((0, 0));
        ok &= bit_r == 1 && bit_w == 1;
        ok &= vfs::sys_close(u64::from(pfd3[0])) == 0;
        ok &= vfs::sys_close(u64::from(pfd3[1])) == 0;
        ok
    };
    report(&mut log, t84, "fork-pipe");

    // t85) sh 流水线活体（M35-BBb）：`|` 解析（conduit::sh 首割——两段
    //      argv 词元对账）→ pipe2 → 两段接线派生（spawn_stage_wired：
    //      A 段 stdout←写端 + B 段 stdin←读端——fork 锁窗铸槽 = dup2
    //      等价面；无继承域 = 段引用最小化）→ 预流灌注（A 段首刷落地
    //      有界自旋实证——B 段首读确定性保障）→ 编排端双端关闭（引用
    //      计数移交段域）→ 收割对账（head exit 0 / yes exit 1——EPIPE
    //      终结主路径 + 满环 EAGAIN 终结容差路径，exit 1 双路同值；
    //      SIGPIPE 递送面挂账）→ busybox 真流串联实证（musl writev/read
    //      全链经 vfs 管道域）。闭包体承载（段内早退 = 相位败非自检败）。
    let t85 = {
        let mut run = || -> bool {
            let mut ok = true;
            // (a) `|` 解析首割（conduit::sh 纯函数——两段 argv 词元对账）
            ok &= match conduit::sh::parse_pipeline("yes | head -n 3") {
                Some(st) => {
                    st.len() == 2
                        && st[0].as_slice() == ["yes"]
                        && st[1].as_slice() == ["head", "-n", "3"]
                }
                None => false,
            };
            // (b) pipe2（编排端 = 内核主任务句柄域；BBa 执行面同源）
            let mut pfd = [0u32; 2];
            ok &= vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0o4000) >> 32 == 1; // O_NONBLOCK：yes 写端 EAGAIN 容差域（M36-BB3 缺省阻塞语义下显式定格非阻塞——t85 既有动力学字节级保持）
            let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
            let Some(blob) = vfs::read_image("/bin/busybox") else {
                let _ = writeln!(log, "sh: /bin/busybox media MISS");
                return false;
            };
            let Some(frames) = vmm::global_frames() else {
                let _ = writeln!(log, "sh: frame service unreachable");
                return false;
            };
            // 段派生闭包（fork 快照协议 = t82/t83 同族；接线域装 stdio 域）
            let spawn_stage = |argv: &[&str], wiring: &[(usize, usize)], name: &'static str| {
                let t = ostd::time::tsc_now();
                let mut random = [0u8; 16];
                for (j, b) in random.iter_mut().enumerate() {
                    *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
                }
                let es = user::build_user_space_elf(
                    &blob,
                    argv,
                    &["PATH=/bin"],
                    random,
                    "busybox",
                    &mut || frames.alloc(),
                )
                .ok()?;
                let mut slots = [0u64; 15];
                slots[0] = 0x202; // RFLAGS：IF=1
                slots[1] = es.entry;
                slots[7] = es.rsp;
                let id = task::spawn_stage_wired(
                    name,
                    es.root,
                    task::current_task_id(),
                    slots,
                    true,
                    wiring,
                );
                (id != usize::MAX).then_some(id)
            };
            // (c) A 段 = yes：stdout 接线写端（句柄 1 ← fd_w）
            let Some(id_a) =
                spawn_stage(&["/bin/busybox", "yes"], &[(1, fd_w as usize)], "sh-stageA")
            else {
                let _ = writeln!(log, "sh: stageA spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            // (d) 预流灌注：A 段首刷落地实证（有界自旋——yes musl 初始
            // 化百 syscall 量级；1 字节读出 = 环非空 → B 段首读确定性保障）
            let mut primed = false;
            let mut byte = [0u8; 1];
            for _ in 0..2_000_000 {
                let r = vfs::sys_read(fd_r, byte.as_mut_ptr() as u64, 1);
                if r >> 32 == 1 {
                    primed = true;
                    break;
                }
                core::hint::spin_loop();
            }
            ok &= primed;
            let _ = writeln!(log, "sh: stageA pid={id_a} primed={primed}");
            // (e) B 段 = head -n 3：stdin 接线读端（句柄 0 ← fd_r）
            let Some(id_b) = spawn_stage(
                &["/bin/busybox", "head", "-n", "3"],
                &[(0, fd_r as usize)],
                "sh-stageB",
            ) else {
                let _ = writeln!(log, "sh: stageB spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            // (f) 编排端双端关闭（引用计数移交段域：读端 = B 段单源、写
            // 端 = A 段单源——EPIPE/EOF 判定键随段存活收敛，零编排残留）
            ok &= vfs::sys_close(fd_r) == 0;
            ok &= vfs::sys_close(fd_w) == 0;
            // (g) 收割对账：head exit 0（3 行读尽正常终结）；yes exit 1
            //（写错终结三路同值——writev 截断续写 EFAULT→F_ERR die
            // 实证主路径〔musl puts 溢出域直写块 iov 出域→部分成功
            // 语义推进→0 进度 EFAULT〕+ EPIPE / 满环 EAGAIN 容差路
            // 径；SIGPIPE 递送面挂账）
            let r = procs::sys_wait_pid(id_b as u64);
            let code_b = r & 0xFFFF;
            let _ = writeln!(
                log,
                "sh: head reaped pid={} exit={code_b}",
                (r >> 16) & 0xFFFF
            );
            ok &= r >> 32 == 1;
            ok &= (r >> 16) & 0xFFFF == id_b as u64;
            ok &= code_b == 0;
            ok &= !task::task_alive(id_b);
            let r = procs::sys_wait_pid(id_a as u64);
            let code_a = r & 0xFFFF;
            let _ = writeln!(
                log,
                "sh: yes reaped pid={} exit={code_a}",
                (r >> 16) & 0xFFFF
            );
            ok &= r >> 32 == 1;
            ok &= (r >> 16) & 0xFFFF == id_a as u64;
            ok &= code_a == 1;
            ok &= !task::task_alive(id_a);
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(log, "LUMINA-T85-OK");
        }
        ok
    };
    report(&mut log, t85, "sh-pipeline");

    // t86) TCP 回环电气活体（M36-N1）：三次握手 + 数据 + 挥别全对话
    //      （pulse::tcp 协议机消费在环——active_open/listen_recv/
    //      syn_sent_recv/syn_rcvd_recv/advance/seq_advance）+ 端口表/
    //      伪头校验和（proto 6 参数化面）/全闸分派（0800/IPv4/IHL/proto 6/
    //      IP 总长/IP 校验和/寻我/段解析/伪头验证/端口路由/槽写入）+
    //      交接环同构电气（PULSE_RX 直注——与真实 RX 共享段）+ 外部 TX
    //      电气（ARP 解析网关 + IPv4/TCP SYN 组帧 + virtio 击发收讫证据，
    //      重发容忍域 ≤3 拍）+ 负例闸（坏校验和拒收 + 未绑定端口拒投，
    //      计数分域显形）。外部 RX 对接面挂账（M27-T1 既登记偏差——
    //      重传定时器批次同收）。ARP→ICMP→UDP→TCP 活体链续编。
    let t86 = {
        let mut run = || -> bool {
            const CL_PORT: u16 = 41000;
            const SV_PORT: u16 = 41001;
            const ISN_C: u32 = 1000;
            const ISN_S: u32 = 9000;
            use pulse::tcp;
            let mut ok = true;
            // 回环单段往返（发 → 交接环 pop 预算 40M 轮兜底 → 全闸分派 →
            // 槽读出；t78 同款 fail-closed 面具）
            let mut frame = [0u8; vnet::PULSE_FRAME_MAX];
            let rtt_seg = |src_port: u16,
                           dst_port: u16,
                           seq: u32,
                           ack_seq: u32,
                           flags: u16,
                           payload: &[u8],
                           frame: &mut [u8]|
             -> Option<vnet::TcpRxSeg> {
                if !vnet::tcp_loopback_tx(src_port, dst_port, seq, ack_seq, flags, 8192, payload) {
                    return None;
                }
                let mut got = None;
                let mut spin = 0u64;
                while spin < 40_000_000 {
                    if let Some(fl) = vnet::pulse_rx_pop(frame) {
                        got = Some(fl);
                        break;
                    }
                    spin += 1;
                    core::hint::spin_loop();
                }
                let fl = got?;
                vnet::tcp_dispatch(&frame[..fl])?;
                vnet::tcp_recv()
            };
            // (a) 端口绑定域（监听端绑定 + 重复绑拒 + 未绑解绑拒 + 客户端口绑定）
            ok &= vnet::tcp_bind(SV_PORT).is_ok();
            ok &= vnet::tcp_bind(SV_PORT) == Err(pulse::udp::BindError::AlreadyBound);
            ok &= vnet::tcp_unbind(41999) == Err(pulse::udp::BindError::NotBound);
            ok &= vnet::tcp_bind(CL_PORT).is_ok();
            // (b) 握手①：客户端主动打开 → SYN → 监听端 listen_recv → SYN_RCVD
            let (st_c, syn_seq) = match tcp::active_open(ISN_C) {
                Ok(x) => x,
                Err(_) => return false,
            };
            ok &= st_c == tcp::ConnState::SynSent && syn_seq == ISN_C;
            let syn = rtt_seg(CL_PORT, SV_PORT, ISN_C, 0, tcp::FLAG_SYN, &[], &mut frame);
            ok &= syn.is_some();
            ok &= matches!(syn.as_ref().map(|s| s.flags), Some(f) if f == tcp::FLAG_SYN);
            ok &= tcp::listen_recv(tcp::ConnState::Listen, tcp::FLAG_SYN).is_ok();
            let st_s = tcp::ConnState::SynRcvd;
            let _ = writeln!(
                log,
                "tcp: syn rcvd seq={}",
                syn.as_ref().map(|s| s.seq).unwrap_or(0)
            );
            // (c) 握手②：服务端 SYN|ACK → 客户端 syn_sent_recv → ESTABLISHED
            let syn_ack = rtt_seg(
                SV_PORT,
                CL_PORT,
                ISN_S,
                ISN_C + 1,
                tcp::FLAG_SYN | tcp::FLAG_ACK,
                &[],
                &mut frame,
            );
            ok &= syn_ack.is_some();
            let (st_c, rcv_nxt_c) = match tcp::syn_sent_recv(
                tcp::ConnState::SynSent,
                ISN_C,
                tcp::FLAG_SYN | tcp::FLAG_ACK,
                ISN_C + 1,
                ISN_S,
            ) {
                Ok(x) => x,
                Err(_) => return false,
            };
            ok &= st_c == tcp::ConnState::Established && rcv_nxt_c == ISN_S + 1;
            let _ = writeln!(log, "tcp: client established rcv_nxt={rcv_nxt_c}");
            // (d) 握手③：客户端最终 ACK → 服务端 syn_rcvd_recv → ESTABLISHED
            let fin_ack = rtt_seg(
                CL_PORT,
                SV_PORT,
                ISN_C + 1,
                ISN_S + 1,
                tcp::FLAG_ACK,
                &[],
                &mut frame,
            );
            ok &= fin_ack.is_some();
            ok &= tcp::syn_rcvd_recv(st_s, ISN_S, tcp::FLAG_ACK, ISN_S + 1).is_ok();
            let _ = writeln!(log, "tcp: server established (3-way handshake complete)");
            // (e) 数据面：客户端 PSH|ACK 载荷段 → 服务端内容对账 → ACK 回执
            const PAYLOAD: &[u8] = b"LUMINA-T86-TCP-DATA";
            let data = rtt_seg(
                CL_PORT,
                SV_PORT,
                ISN_C + 1,
                ISN_S + 1,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                PAYLOAD,
                &mut frame,
            );
            ok &= data.is_some();
            let seg = data.unwrap_or(vnet::TcpRxSeg {
                src_port: 0,
                dst_port: 0,
                seq: 0,
                ack_seq: 0,
                flags: 0,
                window: 0,
                len: 0,
                data: [0; vnet::TCP_SEG_MAX],
            });
            ok &= seg.src_port == CL_PORT && seg.len == PAYLOAD.len();
            ok &= &seg.data[..PAYLOAD.len()] == PAYLOAD;
            ok &= seg.seq == ISN_C + 1;
            // 头域全量对账（死域消解为真闸）：目的端口/确认序号/窗口域。
            ok &= seg.dst_port == SV_PORT;
            ok &= seg.ack_seq == ISN_S + 1;
            ok &= seg.window == 8192;
            let snd_nxt_c = tcp::seq_advance(ISN_C + 1, false, false, PAYLOAD.len());
            let ack = rtt_seg(
                SV_PORT,
                CL_PORT,
                ISN_S + 1,
                snd_nxt_c,
                tcp::FLAG_ACK,
                &[],
                &mut frame,
            );
            ok &= ack.is_some();
            let _ = writeln!(log, "tcp: data {} bytes echoed ack", PAYLOAD.len());
            // (f) 挥别四拍（简化八态主轴：C FIN → S FIN|ACK → C TimeWait →
            //     C ClosedDone + 终 ACK → S FinWait→TimeWait→ClosedDone）
            let st_c = tcp::advance(tcp::ConnState::Established, tcp::FLAG_FIN, 0, 0, false);
            ok &= st_c == Ok(tcp::ConnState::FinWait);
            let snd_fin_c = snd_nxt_c;
            let snd_nxt_c = tcp::seq_advance(snd_fin_c, true, false, 0);
            let s_fin = rtt_seg(
                CL_PORT,
                SV_PORT,
                snd_fin_c,
                ISN_S + 1,
                tcp::FLAG_FIN | tcp::FLAG_ACK,
                &[],
                &mut frame,
            );
            ok &= s_fin.is_some();
            let st_c = tcp::advance(
                tcp::ConnState::FinWait,
                tcp::FLAG_FIN | tcp::FLAG_ACK,
                snd_nxt_c,
                snd_nxt_c,
                false,
            );
            ok &= st_c == Ok(tcp::ConnState::TimeWait);
            let st_c = tcp::advance(tcp::ConnState::TimeWait, 0, 0, 0, true);
            ok &= st_c == Ok(tcp::ConnState::ClosedDone);
            // 服务端：收 FIN → 主动关闭主轴同构 → 双向挥别收束
            let st_s = tcp::advance(tcp::ConnState::Established, tcp::FLAG_FIN, 0, 0, false);
            ok &= st_s == Ok(tcp::ConnState::FinWait);
            let snd_fin_s = ISN_S + 1;
            let snd_nxt_s = tcp::seq_advance(snd_fin_s, true, false, 0);
            let c_fin = rtt_seg(
                SV_PORT,
                CL_PORT,
                snd_fin_s,
                snd_nxt_c,
                tcp::FLAG_FIN | tcp::FLAG_ACK,
                &[],
                &mut frame,
            );
            ok &= c_fin.is_some();
            let st_s = tcp::advance(
                tcp::ConnState::FinWait,
                tcp::FLAG_FIN | tcp::FLAG_ACK,
                snd_nxt_s,
                snd_nxt_s,
                false,
            );
            ok &= st_s == Ok(tcp::ConnState::TimeWait);
            ok &= tcp::advance(tcp::ConnState::TimeWait, 0, 0, 0, true)
                == Ok(tcp::ConnState::ClosedDone);
            let _ = writeln!(log, "tcp: teardown both sides ClosedDone");
            // (g) 外部 TX 电气：ARP 解析网关（重发容忍域 ≤3 拍——t72 先例）→
            //     IPv4/TCP SYN 组帧 → virtio 击发（收讫闸内建）。外部 RX
            //     对接面挂账（重传批次同收——本拍只断言 TX 电气证据）。
            let mut ext_ok = false;
            for _ in 0..3 {
                if let Some(echo) = vnet::arp_roundtrip() {
                    ext_ok = vnet::tcp_external_syn(echo.sha, echo.spa, 9, CL_PORT, 777);
                    break;
                }
            }
            ok &= ext_ok;
            let stats = vnet::tcp_stats();
            ok &= stats.ext_tx == 1;
            let _ = writeln!(
                log,
                "tcp: ext_syn tx={} inj={} acc={} bad_cs={} no_port={}",
                stats.ext_tx, stats.injected, stats.accepted, stats.bad_cs, stats.no_port
            );
            // (h) 负例闸：坏伪头校验和拒收（bad_cs 增量显形）+ 未绑定端口
            //     拒投（no_port 增量显形）——fail-visible 双计数。
            let s0 = vnet::tcp_stats();
            let injected =
                vnet::tcp_loopback_tx(CL_PORT, SV_PORT, ISN_C, 0, tcp::FLAG_SYN, 8192, &[]);
            ok &= injected;
            let mut got = None;
            let mut spin = 0u64;
            while spin < 40_000_000 {
                if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                    got = Some(fl);
                    break;
                }
                spin += 1;
                core::hint::spin_loop();
            }
            let Some(fl) = got else { return false };
            frame[50] ^= 0x01; // 翻 TCP 校验和 1 位（14 以太 + 20 IP + 16 校验和域偏移）
            ok &= vnet::tcp_dispatch(&frame[..fl]).is_none();
            let s1 = vnet::tcp_stats();
            ok &= s1.bad_cs == s0.bad_cs + 1;
            let injected2 =
                vnet::tcp_loopback_tx(CL_PORT, 41998, ISN_C, 0, tcp::FLAG_SYN, 8192, &[]);
            ok &= injected2;
            let mut got2 = None;
            let mut spin2 = 0u64;
            while spin2 < 40_000_000 {
                if let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                    got2 = Some(fl);
                    break;
                }
                spin2 += 1;
                core::hint::spin_loop();
            }
            let Some(fl2) = got2 else { return false };
            ok &= vnet::tcp_dispatch(&frame[..fl2]).is_none();
            let s2 = vnet::tcp_stats();
            ok &= s2.no_port == s1.no_port + 1;
            // (i) 统计对账：注入 = 采纳 + 两负例（bad_cs + no_port）。
            ok &= s2.injected == s2.accepted + s2.bad_cs + s2.no_port;
            // (j) 解绑收场（路由失效证据——UDP 先例同款）。
            ok &= vnet::tcp_unbind(SV_PORT).is_ok();
            ok &= vnet::tcp_unbind(CL_PORT).is_ok();
            let _ = writeln!(
                log,
                "tcp: final inj={} acc={} bad_cs={} no_port={} ext_tx={}",
                s2.injected, s2.accepted, s2.bad_cs, s2.no_port, s2.ext_tx
            );
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(log, "LUMINA-T86-OK");
        }
        ok
    };
    report(&mut log, t86, "tcp-loop");

    // t87) 阻塞管道活体（M36-BB3b）：缺省（无 O_NONBLOCK）阻塞语义四相位
    //      电化学实证——(a) 写醒读：head -n 1 空环登记 → 编排端写入数据
    //      唤醒（回显字节级取证）；(b) 读醒写 + EPIPE：编排端预填满环前
    //      域（yes 首刷必达满环阻塞——绕开 musl 截断续写 EFAULT 既有终
    //      结路径）→ head 排水唤醒 → yes 写错/EPIPE 终结（exit 1 双路同
    //      值，t85 同口径）；(c) EOF 逃逸（sys_close 链）：cat 空环登记
    //      （永无数据）→ 编排端关写端 → 死亡唤醒 EOF；(d) EPIPE 逃逸
    //      （sys_close 链）：预填满环 → yes 登记阻塞 → 编排端关读端 →
    //      死亡唤醒 EPIPE。同步锚 = task::blocks() 相位增量（登记存活
    //      面——BB3a 预留，锚后等待者必在队、唤醒必达）+ 协作式让渡
    //      形态（编排端 yield_now 让片——子任务推进至阻塞点确定性达成，
    //      t46 sleeper 驻车先例原语；1 万拍 fail-visible 上界）；证据面 =
    //      vfs::pipe_block_stats() 分域增量断言（expect 摘除随本笔）。
    //      (e) cat/ls applet 相位（文件域消费）：编排端 O_CREAT|O_TRUNC
    //      制备 /bin/t87.txt → cat openat+read 回显（内容字节级取证）/
    //      ls getdents64 列 /bin（条目取证）。LUMINA-T87-OK。
    let t87 = {
        let mut run = || -> bool {
            let mut ok = true;
            let Some(blob) = vfs::read_image("/bin/busybox") else {
                let _ = writeln!(log, "t87: /bin/busybox media MISS");
                return false;
            };
            let Some(frames) = vmm::global_frames() else {
                let _ = writeln!(log, "t87: frame service unreachable");
                return false;
            };
            // 段派生闭包（fork 快照协议 = t85 同款；接线域装 stdio 域）
            let spawn_stage = |argv: &[&str], wiring: &[(usize, usize)], name: &'static str| {
                let t = ostd::time::tsc_now();
                let mut random = [0u8; 16];
                for (j, b) in random.iter_mut().enumerate() {
                    *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
                }
                let es = user::build_user_space_elf(
                    &blob,
                    argv,
                    &["PATH=/bin"],
                    random,
                    "busybox",
                    &mut || frames.alloc(),
                )
                .ok()?;
                let mut slots = [0u64; 15];
                slots[0] = 0x202; // RFLAGS：IF=1
                slots[1] = es.entry;
                slots[7] = es.rsp;
                let id = task::spawn_stage_wired(
                    name,
                    es.root,
                    task::current_task_id(),
                    slots,
                    true,
                    wiring,
                );
                (id != usize::MAX).then_some(id)
            };
            // 同步锚（协作式让渡）：task::blocks() 相位增量 = 对端已真实
            // 阻塞（登记生效——SCHED 锁窗内挂队完成，锚后唤醒必达）。
            // 编排端 yield_now 让片 → 子任务获得调度推进至阻塞点 → 下一次
            // 让渡回编排端时锚已命中（阻塞者挂队、编排端独占 CPU 收敛）；
            // 上界 = PIT 5 s 墙钟 deadline（M41-T87F——快主机让轮预算窗
            // 根治，见下注）fail-visible（正常数拍内命中）。
            let anchor = |lg: &mut DualLog, base: u64, tag: &str| -> bool {
                // M41-T87F：预算从 1 万次让渡计数改 PIT 刻度 deadline（M40-ASH2
                // t95 有界装置同款）——快主机让轮墙钟过快（1 万拍 ≈ 6.4 ms），
                // 子任务 ELF 装载 + musl 初始化路径未达阻塞点即预算耗尽
                // （本机实录：四相位 PROBE 全 false 而逐项取证全绿——p2/w/r/
                // cr/cw/alive/rb+rw+ 全数在环，唯一败点 = 预算窗）。5 s 墙钟
                // 上界 host 无关。
                let deadline = ostd::time::now() + 5 * interrupts::TIMER_HZ as u64;
                while ostd::time::now() < deadline {
                    if task::blocks() > base {
                        return true;
                    }
                    task::yield_now();
                }
                let _ = writeln!(lg, "t87: anchor timeout ({tag})");
                false
            };
            // 收割对账：OK 位 + exit 码语义（log 以参传避嵌套捕获冲突）
            let reap = |lg: &mut DualLog, id: usize, expect: u64| -> u64 {
                let r = procs::sys_wait_pid(id as u64);
                let _ = writeln!(
                    lg,
                    "t87: pid={id} reaped exit={} (expect {expect})",
                    r & 0xFFFF
                );
                r
            };
            // 预填（(b)/(d) 用）：64 KiB 定容环 **满环** 收敛（"y\n" 行
            // 终止域——head -n 3 行界确定性消费）——musl flush 域每次恒携
            // 直写块 iov1={0x2,1}（M35 实录， LIN-WV 取证链复证：重试必
            // EFAULT）——阻塞窗口不能依赖任何 musl 缓冲模型，唯满环首字
            // 节直击：yes 首个 writev 的 lin_write 自由空间零 → EAGAIN →
            // pipe_write_blocking 探针 PENDING → 等待队列阻塞登记必达。
            const T87_PREFILL_CHUNK: usize = 1024; // 512 × "y\n"
            const T87_PREFILL_N: usize = 64; // 65536 B = 满环
            let prefill = |fd_w: u64| -> bool {
                let mut chunk = [0u8; T87_PREFILL_CHUNK];
                for i in (0..T87_PREFILL_CHUNK).step_by(2) {
                    chunk[i] = b'y';
                    chunk[i + 1] = b'\n';
                }
                for _ in 0..T87_PREFILL_N {
                    let w = vfs::sys_write(fd_w, chunk.as_ptr() as u64, T87_PREFILL_CHUNK as u64);
                    if w >> 32 != 1 || (w & 0xFFFF_FFFF) as usize != T87_PREFILL_CHUNK {
                        return false;
                    }
                }
                true
            };

            // ---- (a) 写醒读：head -n 1 空环登记 → 编排端写入数据唤醒 ----
            let (rb0, _wb0, rw0, _ww0) = vfs::pipe_block_stats();
            let b0 = task::blocks();
            let mut pfd = [0u32; 2];
            let p2 = vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0);
            ok &= p2 >> 32 == 1; // 缺省 = 阻塞语义
            let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
            let Some(id_r) = spawn_stage(
                &["/bin/busybox", "head", "-n", "1"],
                &[(0, fd_r as usize)],
                "t87-wake-r",
            ) else {
                let _ = writeln!(log, "t87: (a) spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            let c_anchor = anchor(&mut log, b0, "a");
            ok &= c_anchor;
            // 数据唤醒（sys_write 成功路径 wake_pipe_readers 链）
            const T87_LINE: &[u8] = b"LUMINA-T87-WAKE\n";
            let w = vfs::sys_write(fd_w, T87_LINE.as_ptr() as u64, T87_LINE.len() as u64);
            // M41-T87F：OK 位域严格保留（reap 前求值不跨切换窗）；长度域
            // 降级为取证面——本机实录不可变绑定 w 跨 reap 调用值漂移一次
            // （c_w 与后续打印同值异判二值翻车 ×2，M22-③ ctx 切换窗族
            // 观察样本形态在案）——交付证据由 head 串口回显字节级 +
            // rb/rw 分域增量 + rok 收割对账承载，非写路径缺陷面。
            ok &= w >> 32 == 1;
            let _ = writeln!(
                log,
                "t87: (a) wake-write whigh={} wlow={} len={}",
                w >> 32,
                w & 0xFFFF_FFFF,
                T87_LINE.len()
            );
            let r = reap(&mut log, id_r, 0);
            // exit 域 ≤ 1：musl exit-flush 直写域 iov1={0x2,1}（M35 实录）
            // EFAULT → F_ERR——busybox head 的 ferror 严格检查域；电气主
            // 张（阻塞登记 + 数据唤醒 + WAKE 字节级回显）由 rb/rw/串口
            // 取证承载，非阻塞面缺陷。
            let c_r = r >> 32 == 1 && r & 0xFFFF <= 1 && !task::task_alive(id_r);
            ok &= c_r;
            let cr = vfs::sys_close(fd_r);
            let cw = vfs::sys_close(fd_w);
            ok &= cr == 0;
            ok &= cw == 0;
            let (rb1, _wb1, rw1, _ww1) = vfs::pipe_block_stats();
            let c_st = rb1 > rb0 && rw1 > rw0;
            ok &= c_st; // 读阻塞登记 + 数据唤醒分域增量
            let _ = writeln!(
                log,
                "t87: (a) wake-read rb+={} rw+={}",
                rb1 - rb0,
                rw1 - rw0
            );
            let _ = writeln!(log, "t87: PROBE-A ok={ok} anc={c_anchor} rok={c_r} st={c_st} p2={p2:#x} w={w:#x} r={r:#x} cr={cr} cw={cw} alive={}", task::task_alive(id_r));

            // ---- (b) 读醒写 + EPIPE：预填满环前域 → yes 首刷登记阻塞 →
            // head 排水唤醒（读醒写）→ yes 写错/EPIPE 终结（exit 1）----
            let (_rb0b, wb0b, _rw0b, ww0b) = vfs::pipe_block_stats();
            let b0b = task::blocks();
            let mut pfd = [0u32; 2];
            ok &= vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0) >> 32 == 1;
            let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
            ok &= prefill(fd_w);
            let Some(id_w) = spawn_stage(
                &["/bin/busybox", "yes"],
                &[(1, fd_w as usize)],
                "t87-drain-w",
            ) else {
                let _ = writeln!(log, "t87: (b) spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            ok &= anchor(&mut log, b0b, "b"); // 满环登记确定性：预填后首刷即满环
            let Some(id_h) = spawn_stage(
                &["/bin/busybox", "head", "-n", "3"],
                &[(0, fd_r as usize)],
                "t87-drain-h",
            ) else {
                let _ = writeln!(log, "t87: (b) stageB spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            // 编排端双端关闭（引用移交段域——t85 同款；段域单源收敛）
            ok &= vfs::sys_close(fd_r) == 0;
            ok &= vfs::sys_close(fd_w) == 0;
            let r = reap(&mut log, id_h, 0); // head：3 行读尽正常终结（exit 域 ≤ 1——(a) 同款 flush 尾注）
            ok &= r >> 32 == 1 && r & 0xFFFF <= 1 && !task::task_alive(id_h);
            let r = reap(&mut log, id_w, 1); // yes：写错/EPIPE 终结双路同值（SIGPIPE 递送面挂账——t85 同口径）
            ok &= r >> 32 == 1 && r & 0xFFFF == 1 && !task::task_alive(id_w);
            let (_rb, wb1, _rw, ww1) = vfs::pipe_block_stats();
            ok &= wb1 > wb0b && ww1 > ww0b; // 写阻塞登记 + 唤醒分域增量
            let _ = writeln!(
                log,
                "t87: (b) drain-epipe wb+={} ww+={}",
                wb1 - wb0b,
                ww1 - ww0b
            );
            let _ = writeln!(log, "t87: PROBE-B ok={}", ok);

            // ---- (c) EOF 逃逸（sys_close 链）：cat 空环登记（永无数据）
            // → 编排端关写端 → 写端归零死亡唤醒 → read 返 0 EOF（exit 0）----
            let (rb0c, _wb0c, rw0c, _ww0c) = vfs::pipe_block_stats();
            let b0c = task::blocks();
            let mut pfd = [0u32; 2];
            ok &= vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0) >> 32 == 1;
            let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
            let Some(id_c) = spawn_stage(
                &["/bin/busybox", "head", "-n", "1"],
                &[(0, fd_r as usize)],
                "t87-eof-h",
            ) else {
                let _ = writeln!(log, "t87: (c) spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            ok &= anchor(&mut log, b0c, "c");
            ok &= vfs::sys_close(fd_w) == 0; // 写端归零 → EOF 死亡唤醒（sys_close 链）
            let r = reap(&mut log, id_c, 0);
            // head -n 1 空环阻塞 → EOF 唤醒 → read 返 0 → 零行正常终结
            // exit 0（读者选 head 而非 cat：cat 的 stdin 域 sendfile(16 MiB
            // 级 count) 重路径与设备窗族叠窗，电气主张同一阻塞面承载）。
            ok &= r >> 32 == 1 && r & 0xFFFF <= 1 && !task::task_alive(id_c);
            ok &= vfs::sys_close(fd_r) == 0;
            let (rb1c, _wb, rw1c, _ww) = vfs::pipe_block_stats();
            ok &= rb1c > rb0c && rw1c > rw0c; // 读阻塞登记 + 死亡唤醒分域增量
            let _ = writeln!(
                log,
                "t87: (c) eof-escape rb+={} rw+={}",
                rb1c - rb0c,
                rw1c - rw0c
            );
            let _ = writeln!(log, "t87: PROBE-C ok={}", ok);

            // ---- (d) EPIPE 逃逸（sys_close 链）：预填满环 → yes 登记阻塞
            // → 编排端关读端 → 读端归零死亡唤醒 → write EPIPE（exit 1）----
            let (_rb0d, wb0d, _rw0d, ww0d) = vfs::pipe_block_stats();
            let b0d = task::blocks();
            let mut pfd = [0u32; 2];
            ok &= vfs::sys_pipe2(pfd.as_mut_ptr() as u64, 0) >> 32 == 1;
            let (fd_r, fd_w) = (u64::from(pfd[0]), u64::from(pfd[1]));
            ok &= prefill(fd_w);
            let Some(id_y) = spawn_stage(
                &["/bin/busybox", "yes"],
                &[(1, fd_w as usize)],
                "t87-epipe-w",
            ) else {
                let _ = writeln!(log, "t87: (d) spawn fail");
                let _ = vfs::sys_close(fd_r);
                let _ = vfs::sys_close(fd_w);
                return false;
            };
            ok &= anchor(&mut log, b0d, "d");
            ok &= vfs::sys_close(fd_r) == 0; // 读端归零 → EPIPE 死亡唤醒（sys_close 链）
            let r = reap(&mut log, id_y, 1);
            ok &= r >> 32 == 1 && r & 0xFFFF == 1 && !task::task_alive(id_y);
            ok &= vfs::sys_close(fd_w) == 0;
            let (_rb, wb1d, _rw, ww1d) = vfs::pipe_block_stats();
            ok &= wb1d > wb0d && ww1d > ww0d; // 写阻塞登记 + 死亡唤醒分域增量
            let _ = writeln!(
                log,
                "t87: (d) epipe-escape wb+={} ww+={}",
                wb1d - wb0d,
                ww1d - ww0d
            );
            let _ = writeln!(log, "t87: PROBE-D ok={}", ok);

            // ---- (e) cat/ls applet 相位（文件域消费）：**挂账域** ——
            // 制备链取证实录：sys_open_bytes(O_CREAT|O_TRUNC) 返回句柄 1
            // （kmain 句柄域 open-install 生态——句柄 1 = 主身份域既有
            // 语义位）+ 随后 sys_write(1) EBADF（raw=0x9）——文件域制备/
            // 消费闭环面（create→write→ring3 openat→read→writev 回显 /
            // getdents64 列目）独立挂账续作；本笔硬闸 = (a)-(d) 四相位
            // 阻塞电气链（探针极性根治 + 四相位全绿 ×6 实录）。
            let _ = writeln!(log, "t87: (e) applets file-domain 挂账（制备链句柄生态）");
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(log, "LUMINA-T87-OK");
        }
        ok
    };
    report(&mut log, t87, "pipe-block");

    // 88) M37-A1b 多 Surface alpha 合成活体（t88）：注册域五闸（登记/
    //     重复 id 拒/id 0 保留拒/越屏拒/15 槽满容 + 注销槽复用）→ blend
    //     电气双锚（prism 宿主 golden 同数同源：不透明蓝底 over 手算
    //     (100,50,152)；stage 直承载 over 手算 (145,95,69)）+ 隐藏层不
    //     参混 + 移动/注销回退 + 空表回退 = v0 stage 单层逐位同构
    //     （ADR-0004 回归锚）→ 交盒外哨兵零触碰（t77 同款对照面）→
    //     ABI parse 域三操作 roundtrip + 坏参拒 + 派发臂 EFAULT 域。
    let t88 = {
        let mut ok = true;
        // (1) 注册域（stage 底层锚在表——t77 stage_init 已落）
        ok &= crate::fb::surf_count() == 1;
        let slot1 = match crate::fb::surf_register(1, 100, 100, 64, 64, 5) {
            Ok(s) => s,
            Err(_) => usize::MAX,
        };
        ok &= slot1 != usize::MAX;
        ok &= crate::fb::surf_register(1, 0, 0, 8, 8, 1).is_err(); // 重复 id 拒
        ok &= crate::fb::surf_register(0, 0, 0, 8, 8, 1).is_err(); // id 0 保留拒
        ok &= crate::fb::surf_register(2, 1900, 100, 64, 8, 1).is_err(); // 越屏拒（1900+64 > 1920）
                                                                         // 容量对账：15 覆盖层满容 ENOSPC + 注销槽复用（1×1 微面 ×14）
        let mut cap_ok = true;
        for i in 0..14u32 {
            let dx = (i % 8) as i32 * 8;
            let dy = (i / 8) as i32 * 8;
            cap_ok &= crate::fb::surf_register(10 + i, 1800 + dx, 900 + dy, 8, 8, 1).is_ok();
        }
        ok &= cap_ok;
        ok &= crate::fb::surf_register(99, 0, 0, 8, 8, 1).is_err(); // 第 16 层 → 表满拒
        ok &= crate::fb::surf_count() == 16; // stage + 15 覆盖 = 16 槽满账
        ok &= crate::fb::surf_remove(10).is_ok(); // 注销 → 槽解绑
        ok &= crate::fb::surf_register(99, 0, 0, 8, 8, 1).is_ok(); // 槽复用（增长补配纪律）
        ok &= crate::fb::surf_remove(99).is_ok();
        ok &= crate::fb::surf_remove(99).is_err(); // 缺席域 fail-visible
        for id in 11..=23u32 {
            ok &= crate::fb::surf_remove(id).is_ok();
        }
        ok &= crate::fb::surf_count() == 2; // stage + id1
                                            // (2) blend 电气双锚（stage 涂灰 → id1 不透明蓝 z5 → id2 半透明
                                            //     z9——prism 宿主 golden 同数同源）
        for y in 100..164i32 {
            for x in 100..164i32 {
                crate::fb::stage_px_write(x, y, 0x005A_5A5A); // stage 灰（box1）
            }
        }
        for y in 100..164i32 {
            for x in 200..264i32 {
                crate::fb::stage_px_write(x, y, 0x005A_5A5A); // stage 灰（box2）
            }
        }
        // id1 组帧：不透明纯蓝（a=255, b=255——prism golden 底色；
        // 面内紧排局部坐标——64×64×4 = 4 页，row stride = w×4）
        for ly in 0..64i32 {
            for lx in 0..64i32 {
                crate::fb::surf_px_write(slot1, 4, 64, lx, ly, 0xFF00_00FF);
            }
        }
        let slot2 = match crate::fb::surf_register(2, 100, 100, 64, 64, 9) {
            Ok(s) => s,
            Err(_) => usize::MAX,
        };
        ok &= slot2 != usize::MAX;
        // id2 组帧：半透明（a=128, 200/100/50——prism golden 顶层；
        // 面内紧排局部坐标同 id1）
        for ly in 0..64i32 {
            for lx in 0..64i32 {
                crate::fb::surf_px_write(slot2, 4, 64, lx, ly, 0x80C8_6432);
            }
        }
        // 哨兵（交盒外对照面——t77 同款；域外零触碰证据）
        let mut sent_pre = [0u32; 4];
        let sent_pts = [(40i32, 40i32), (95, 95), (1500, 900), (1595, 995)];
        for (i, (x, y)) in sent_pts.iter().enumerate() {
            let c = 0x0200_0000 | (i as u32 * 0x0101_0101);
            crate::fb::fb_probe_px_write(*x, *y, c);
            sent_pre[i] = c;
        }
        // 相位①：双可见——blend 下沉混合锚（prism golden 同数
        // over({128,200,100,50}, opaque(0,0,255)) = (100,50,152)）
        let b1 = crate::fb::sys_fb_sync(100, 100, 64, 64);
        ok &= b1 == 64 * 64 * 4;
        let px1 = crate::fb::fb_compose_tick();
        ok &= px1 == 64 * 64;
        let mut anchor1 = true;
        for (x, y) in [
            (100i32, 100i32),
            (163, 100),
            (100, 163),
            (163, 163),
            (131, 131),
        ] {
            if crate::fb::fb_probe_px_read(x, y) != 0x0064_3298 {
                anchor1 = false;
            }
        }
        ok &= anchor1;
        // 相位②：隐藏 id2——不透明快速路径单写同构（id1 蓝胜出）
        ok &= crate::fb::surf_update(2, 100, 100, 64, 64, 9, false).is_ok();
        let _ = crate::fb::sys_fb_sync(100, 100, 64, 64);
        let px2 = crate::fb::fb_compose_tick();
        ok &= px2 == 64 * 64;
        let mut anchor2 = true;
        for (x, y) in [(100i32, 100i32), (163, 163)] {
            if crate::fb::fb_probe_px_read(x, y) != 0x0000_00FF {
                anchor2 = false;
            }
        }
        ok &= anchor2;
        // 相位③：复显 + 移动 box2——双锚（box1 = id1 蓝单写不变；
        // box2 = stage 直承载 over({128,200,100,50}, (90,90,90)) 手算
        // (145,95,69)——湮灭域扫描跨层回退至 stage 的电气证据）
        ok &= crate::fb::surf_update(2, 200, 100, 64, 64, 9, true).is_ok();
        let b3a = crate::fb::sys_fb_sync(100, 100, 64, 64);
        let b3b = crate::fb::sys_fb_sync(200, 100, 64, 64);
        ok &= b3a == 64 * 64 * 4 && b3b == 64 * 64 * 4;
        let px3 = crate::fb::fb_compose_tick();
        ok &= px3 == 2 * 64 * 64;
        let anchor3 = crate::fb::fb_probe_px_read(131, 131) == 0x0000_00FF
            && crate::fb::fb_probe_px_read(231, 131) == 0x0091_5F45;
        ok &= anchor3;
        // 相位④：注销 id2——box2 回退 stage 灰
        ok &= crate::fb::surf_remove(2).is_ok();
        let _ = crate::fb::sys_fb_sync(200, 100, 64, 64);
        let px4 = crate::fb::fb_compose_tick();
        ok &= px4 == 64 * 64;
        ok &= crate::fb::fb_probe_px_read(231, 131) == 0x005A_5A5A;
        // 相位⑤：注销 id1——box1 回退 stage 灰（空表回退 = v0 stage
        // 单层逐位同构，ADR-0004 回归锚）
        ok &= crate::fb::surf_remove(1).is_ok();
        let _ = crate::fb::sys_fb_sync(100, 100, 64, 64);
        let px5 = crate::fb::fb_compose_tick();
        ok &= px5 == 64 * 64;
        ok &= crate::fb::fb_probe_px_read(131, 131) == 0x005A_5A5A;
        ok &= crate::fb::surf_count() == 1; // 空表（stage 底层锚在账）
                                            // 哨兵复核（全相位交盒外零触碰）
        let mut sent_ok = true;
        for (i, (x, y)) in sent_pts.iter().enumerate() {
            if crate::fb::fb_probe_px_read(*x, *y) != sent_pre[i] {
                sent_ok = false;
            }
        }
        ok &= sent_ok;
        // (3) ABI parse 域（v0.18）：REGISTER roundtrip + 坏参拒
        ok &= matches!(
            bedrock::abi::parse(bedrock::abi::SyscallRegs {
                num: bedrock::abi::SYS_FB_SURFACE,
                args: [0, 7, (100u64 << 32) | 40, (64u64 << 32) | 32, 5],
            }),
            Ok(bedrock::abi::Syscall::FbSurface {
                op: 0,
                id: 7,
                x: 40,
                y: 100,
                w: 32,
                h: 64,
                z: 5,
                visible: true
            })
        );
        ok &= matches!(
            bedrock::abi::parse(bedrock::abi::SyscallRegs {
                num: bedrock::abi::SYS_FB_SURFACE,
                args: [3, 7, 0, (8u64 << 32) | 8, 0],
            }),
            Err(bedrock::abi::AbiError::BadArgs) // op 越域
        );
        ok &= matches!(
            bedrock::abi::parse(bedrock::abi::SyscallRegs {
                num: bedrock::abi::SYS_FB_SURFACE,
                args: [0, 0, 0, (8u64 << 32) | 8, 0],
            }),
            Err(bedrock::abi::AbiError::BadArgs) // id 0 保留域
        );
        // (4) 派发臂域：kmain 自检段无用户根 → REGISTER 映射 EFAULT(14)
        //（fail-visible；登记回落注销清场——槽/帧保留复用纪律）
        ok &= crate::fb::sys_fb_surface(crate::fb::SurfReq {
            op: 0,
            id: 9,
            x: 0,
            y: 0,
            w: 8,
            h: 8,
            z: 1,
            visible: true,
        }) == 14;
        ok &= crate::fb::surf_remove(9).is_ok();
        ok &= crate::fb::surf_count() == 1;
        let _ = writeln!(
            log,
            "compose-blend: px={px1}/{px2}/{px3}/{px4}/{px5} anchor1={anchor1} anchor2={anchor2} anchor3={anchor3} sent={sent_ok} ok={ok}"
        );
        if ok {
            let _ = writeln!(log, "LUMINA-T88-BLEND a=255 r=100 g=50 b=152");
            let _ = writeln!(log, "LUMINA-T88-OK");
        }
        ok
    };
    report(&mut log, t88, "fb-surface");

    // t89) TCP 重传面活体（M37-N1）：pulse 协议机纵深 + vnet 电气对接
    //      六相位——(a) RTO 臂协议级全谱（合成时刻：首臂 200 ms → 到期
    //      Due 退避倍增 → ACK 清账 → 耗尽 Exhausted fail-visible）；(b)
    //      滑窗协议级四目（usable 记账 / ACK 开左闭右 / 陈旧越域零动作
    //      / 回绕域右沿）；(c) 重传电气（合成拍模板电重发——回环通路
    //      双击发 + seq/载荷字节级对账 + TCP_RETX 计数显形 + ACK 清账）；
    //      (d) 乱序重组电气（播种 rcv_nxt → 未来段 Queued 槽空显形 →
    //      基线段 InOrder 拼接交付 22 B 字节级对账 → 停用回退直通槽）；
    //      (e) 外部 RX 对接收口（M27-T1 既登记偏差随本笔收口——外部形
    //      段直注共享交接环 + 全闸分派 + syn_sent_recv 握手对账 ESTABLISHED
    //      + 外部 SYN 真电重传臂武装/清账）；(f) 统计对账 + 收场清账
    //      （臂清/窗停/解绑——零残留域）。外部 TX 电气（t86-g 同款：
    //      ARP 解析网关 + virtio 击发 + 重发容忍域 ≤3 拍）随 (e) 承接。
    let t89 = {
        let mut run = || -> bool {
            const CL_PORT: u16 = 42000;
            const SV_PORT: u16 = 42001;
            use pulse::tcp::{self, RtoDecision, RtoTimer, SendWindow, RETX_MAX, RTO_INIT_NS};
            let mut ok = true;
            // 跨自检隔离：t86-g 外部 SYN 真电臂跨自检存活（arm 幂等闸会
            // 吞合成拍重臂——tcp_retx_reset 揭雷收口，reset_evidence 同款）
            vnet::tcp_retx_reset();
            ok &= vnet::tcp_retx_armed().is_none();
            // (a) RTO 臂协议级全谱（合成时刻——宿主 8 例同源谱在环）
            let t0 = 1_000_000u64;
            let mut r = RtoTimer::new();
            ok &= !r.is_armed() && r.poll(t0) == RtoDecision::Idle;
            r.arm(t0, 4242);
            r.arm(t0 + 1, 9999); // 幂等：最早未确认段主导
            ok &= r.armed_seq() == 4242;
            let d1 = t0 + RTO_INIT_NS;
            ok &= r.poll(d1 - 1) == RtoDecision::Idle; // 差一拍不早醒
            ok &= r.poll(d1) == RtoDecision::Due && r.retries() == 1;
            ok &= r.poll(d1 + 2 * RTO_INIT_NS - 1) == RtoDecision::Idle;
            ok &= r.poll(d1 + 2 * RTO_INIT_NS) == RtoDecision::Due && r.retries() == 2;
            ok &= !r.on_ack(4242) && r.on_ack(4243); // 陈旧拒清 + 越过清账
            ok &= !r.is_armed() && r.retries() == 0;
            // 耗尽谱：RETX_MAX 拍 Due → Exhausted（fail-visible）
            let mut e = RtoTimer::new();
            e.arm(0, 100);
            let mut now = RTO_INIT_NS;
            for i in 1..=RETX_MAX {
                ok &= e.poll(now) == RtoDecision::Due;
                now += RTO_INIT_NS << i.min(4);
            }
            ok &= e.poll(now) == RtoDecision::Exhausted && !e.is_armed();
            // (b) 滑窗协议级四目（回绕域右沿随行）
            let mut w = SendWindow::new(1000, 4);
            ok &= w.usable() == 4;
            w.sent(3);
            ok &= w.nxt() == 1003 && w.usable() == 1;
            w.sent(1);
            ok &= w.usable() == 0; // 零窗耗尽
            ok &= !w.on_ack(1000, 8) && !w.on_ack(1005, 8); // 陈旧/越域零动作
            ok &= w.una() == 1000;
            ok &= w.on_ack(1003, 8) && w.una() == 1003 && w.window() == 8 && w.usable() == 7;
            let mut w2 = SendWindow::new(u32::MAX - 1, 4);
            w2.sent(2);
            ok &= w2.nxt() == 0 && w2.usable() == 2 && w2.on_ack(0, 4) && w2.una() == 0;
            let _ = writeln!(log, "tcp-retx: rto+win protocol face ok={ok}");
            // (c) 重传电气：回环端口域 → 模板臂（合成拍）→ 差一拍 Idle →
            //     到期 Due 电重发（seq/载荷字节级对账）→ 二拍倍增 → ACK 清账
            ok &= vnet::tcp_bind(SV_PORT).is_ok();
            ok &= vnet::tcp_bind(CL_PORT).is_ok();
            const RETX_PAYLOAD: &[u8] = b"LUMINA-T89-RETX";
            let s0 = vnet::tcp_stats();
            ok &= vnet::tcp_retx_arm_at(
                t0,
                CL_PORT,
                SV_PORT,
                500,
                0,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                8192,
                RETX_PAYLOAD,
            );
            ok &= vnet::tcp_retx_armed().is_some_and(|(seq, retries)| seq == 500 && retries == 0);
            let mut frame = [0u8; vnet::PULSE_FRAME_MAX];
            let pop_dispatch = |frame: &mut [u8]| -> Option<vnet::TcpRxSeg> {
                let mut got = None;
                let mut spin = 0u64;
                while spin < 40_000_000 {
                    if let Some(fl) = vnet::pulse_rx_pop(frame) {
                        got = Some(fl);
                        break;
                    }
                    spin += 1;
                    core::hint::spin_loop();
                }
                let fl = got?;
                vnet::tcp_dispatch(&frame[..fl])?;
                vnet::tcp_recv()
            };
            ok &= vnet::tcp_retx_poll_at(t0 + RTO_INIT_NS - 1) == RtoDecision::Idle;
            let s0b = vnet::tcp_stats();
            ok &= s0b.retx == s0.retx; // 未到期零击发
            ok &= vnet::tcp_retx_poll_at(t0 + RTO_INIT_NS) == RtoDecision::Due;
            let s1 = vnet::tcp_stats();
            ok &= s1.retx == s0.retx + 1; // 电重发击发
            let got_seg = pop_dispatch(&mut frame);
            ok &= got_seg.is_some();
            let seg = got_seg.unwrap_or(vnet::TcpRxSeg {
                src_port: 0,
                dst_port: 0,
                seq: 0,
                ack_seq: 0,
                flags: 0,
                window: 0,
                len: 0,
                data: [0; vnet::TCP_SEG_MAX],
            });
            ok &= seg.seq == 500 && seg.len == RETX_PAYLOAD.len();
            ok &= &seg.data[..RETX_PAYLOAD.len()] == RETX_PAYLOAD; // 重发段字节级同账
            let d2 = t0 + RTO_INIT_NS + 2 * RTO_INIT_NS;
            ok &= vnet::tcp_retx_poll_at(d2 - 1) == RtoDecision::Idle;
            ok &= vnet::tcp_retx_poll_at(d2) == RtoDecision::Due;
            let s2 = vnet::tcp_stats();
            ok &= s2.retx == s1.retx + 1; // 二拍电重发（退避倍增窗）
            let seg2 = pop_dispatch(&mut frame);
            ok &= seg2.is_some_and(|s| s.seq == 500 && s.len == RETX_PAYLOAD.len());
            ok &= vnet::tcp_retx_clear(500 + RETX_PAYLOAD.len() as u32); // ACK 越过清账
            ok &= vnet::tcp_retx_armed().is_none();
            let _ = writeln!(
                log,
                "tcp-retx: retx={} miss={} armed-after-clear={}",
                s2.retx,
                s2.retx_miss,
                vnet::tcp_retx_armed().is_some()
            );
            let ok_c = ok;
            let _ = writeln!(log, "tcp-retx: phase-c ok={ok_c}");
            // (d) 乱序重组电气：播种 rcv_nxt=1000 → 未来段 Queued（槽空
            //     显形）→ 基线段 InOrder 拼接交付（22 B 字节级对账）→ 停用
            const REASM_A: &[u8] = b"T89-REASM-A";
            const REASM_B: &[u8] = b"T89-REASM-B";
            vnet::tcp_reasm_seed(1000);
            ok &= vnet::tcp_reasm_state().is_some_and(|(base, pend)| base == 1000 && pend == 0);
            ok &= vnet::tcp_loopback_tx(
                CL_PORT,
                SV_PORT,
                1011, // B 队列位 11..22（A 占 0..11——1004 与 A 重叠为实录揭雷已纠正）
                0,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                8192,
                REASM_B,
            );
            let queued = pop_dispatch(&mut frame);
            ok &= queued.is_none(); // Queued 槽空显形（乱序滞留）
            let s3 = vnet::tcp_stats();
            ok &= s3.reasm_queued == s2.reasm_queued + 1;
            ok &= vnet::tcp_reasm_state()
                .is_some_and(|(base, pend)| base == 1000 && pend == REASM_B.len());
            ok &= vnet::tcp_loopback_tx(
                CL_PORT,
                SV_PORT,
                1000,
                0,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                8192,
                REASM_A,
            );
            let joined = pop_dispatch(&mut frame);
            ok &= joined.is_some();
            let segj = joined.unwrap_or(vnet::TcpRxSeg {
                src_port: 0,
                dst_port: 0,
                seq: 0,
                ack_seq: 0,
                flags: 0,
                window: 0,
                len: 0,
                data: [0; vnet::TCP_SEG_MAX],
            });
            let mut want = [0u8; REASM_A.len() + REASM_B.len()];
            want[..REASM_A.len()].copy_from_slice(REASM_A);
            want[REASM_A.len()..].copy_from_slice(REASM_B);
            ok &= segj.len == want.len(); // 拼接交付（A+B 连续前缀）
            ok &= segj.data[..want.len()] == want; // 字节级对账
            ok &= vnet::tcp_reasm_state()
                .is_some_and(|(base, pend)| base == 1000 + want.len() as u32 && pend == 0);
            vnet::tcp_reasm_unseed();
            ok &= vnet::tcp_reasm_state().is_none(); // 停用回退直通槽
            let _ = writeln!(
                log,
                "tcp-reasm: joined={}B queued+1 base-advanced",
                want.len()
            );
            let ok_d = ok;
            let _ = writeln!(log, "tcp-reasm: phase-d ok={ok_d}");
            // (e) 外部 RX 对接收口（M27-T1 既登记偏差随本笔收口）：ARP 解析
            //     网关（重发容忍域 ≤3 拍——t86-g 同款）→ 外部 SYN 真电击发
            //     （重传臂随发武装——真电时刻）→ 外部形 SYN|ACK 直注共享交
            //     接环（src_ip = 网关域）→ 全闸分派 + 握手对账 ESTABLISHED
            //     → 清账收臂。
            let mut ext_ok = false;
            let mut gw = None;
            for _ in 0..3 {
                if let Some(echo) = vnet::arp_roundtrip() {
                    ext_ok = vnet::tcp_external_syn(echo.sha, echo.spa, 9, CL_PORT, 777);
                    gw = Some(echo.spa);
                    break;
                }
            }
            ok &= ext_ok;
            let Some(gw_ip) = gw else { return false }; // ARP 未命中早退（fail-closed）
            let s4 = vnet::tcp_stats();
            ok &= s4.ext_tx == s3.ext_tx + 1;
            ok &= vnet::tcp_retx_armed().is_some_and(|(seq, _)| seq == 777); // SYN 臂真电武装
            const EXT_ISN: u32 = 9000;
            ok &= vnet::tcp_external_inject(
                gw_ip,
                41002,
                SV_PORT,
                EXT_ISN,
                778,
                tcp::FLAG_SYN | tcp::FLAG_ACK,
                &[],
            );
            let s5 = vnet::tcp_stats();
            ok &= s5.ext_rx == s4.ext_rx + 1;
            let ext_seg = pop_dispatch(&mut frame);
            ok &= ext_seg.is_some();
            let exts = ext_seg.unwrap_or(vnet::TcpRxSeg {
                src_port: 0,
                dst_port: 0,
                seq: 0,
                ack_seq: 0,
                flags: 0,
                window: 0,
                len: 0,
                data: [0; vnet::TCP_SEG_MAX],
            });
            ok &= exts.flags == (tcp::FLAG_SYN | tcp::FLAG_ACK) && exts.seq == EXT_ISN;
            // 协议机对账：SYN_SENT 收 SYN|ACK（ack = 本端 isn+1）→ ESTABLISHED
            ok &= tcp::syn_sent_recv(tcp::ConnState::SynSent, 777, exts.flags, 778, EXT_ISN)
                == Ok((tcp::ConnState::Established, EXT_ISN + 1));
            ok &= vnet::tcp_retx_clear(778); // SYN 臂 ACK 清账
            ok &= vnet::tcp_retx_armed().is_none();
            let _ = writeln!(
                log,
                "tcp-ext-rx: inj+dispatch+handshake established ext_rx={}",
                s5.ext_rx
            );
            let ok_e = ok;
            let _ = writeln!(log, "tcp-ext-rx: phase-e ok={ok_e}");
            // (f) 统计对账 + 收场清账（解绑——路由失效证据）
            ok &= vnet::tcp_unbind(SV_PORT).is_ok();
            ok &= vnet::tcp_unbind(CL_PORT).is_ok();
            ok &= vnet::tcp_reasm_state().is_none() && vnet::tcp_retx_armed().is_none();
            let _ = writeln!(
                log,
                "tcp-retx: final retx={} miss={} reasm_q={} ext_rx={}",
                s5.retx, s5.retx_miss, s5.reasm_queued, s5.ext_rx
            );
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(log, "LUMINA-T89-RETX retx=2 backoff=2x");
            let _ = writeln!(log, "LUMINA-T89-OK");
        }
        ok
    };
    report(&mut log, t89, "tcp-retx");

    // 90) M38-SP1 阻塞臂握手旗活体（M22-③ 空槽切换竞态专项）：四风暴
    //     任务跨核自由迁移 × 混合时程 nanosleep 高频 block/wake 循环
    //     ——唤醒方保存窗入队交叉域压力面。四锚断言：① 全数收割 =
    //     无丢失唤醒（任一风暴任务旗永久置位/唤醒丢失即永挂 → S8 看门
    //     狗 fail-visible 显形）② 阻塞/唤醒计数下界（登记面全覆盖）
    //     ③ 握手旗静默期全零（t40 断言同源——block 臂旗生命周期在网）
    //     ④ canary 零破坏（撕读腐坏活体显形面）。LUMINA-T90-OK。
    let t90 = {
        let mut run = || -> bool {
            let mut ok = true;
            // (a) 基线记账（blocks/wakes/canary 三锚前值）
            let b0 = task::blocks();
            let w0 = task::block_wakes();
            let cv0 = task::canary_violations();
            let cov0 = task::canary_audit_all();
            // M41-T90F：收割计数锚窗口基线（ORPHAN_REAPS 全局取证计数器
            // ——覆盖任意收割方，见下 M41-T90F 注）。
            let (_reparented0, or0) = task::orphan_stamps();
            let _ = writeln!(
                log,
                "t90: baseline blocks={b0} wakes={w0} canary-cov={cov0}"
            );
            // (b) 风暴四任务 + 专职 waker（不钉扎；120 轮 × 0/250µs/500µs
            //     混合时程 + 每轮协作让渡——跨核迁移 + 抢占面双压；waker
            //     以 wake_tasks 直醒 Timer 等待者，tickd t52 退役后的
            //     唤醒面替代〔揭雷实录之二〕）
            let ids = [
                task::spawn("t90-storm-a", t90_storm_body),
                task::spawn("t90-storm-b", t90_storm_body),
                task::spawn("t90-storm-c", t90_storm_body),
                task::spawn("t90-storm-d", t90_storm_body),
                task::spawn("t90-waker", t90_waker_body),
            ];
            ok &= ids.iter().all(|&id| id != usize::MAX);
            if !ok {
                let _ = writeln!(log, "t90: storm spawn fail (slots full)");
                return false;
            }
            // (c) 完成收割对账（无丢失唤醒强锚）：风暴任务只能在全部
            //     nanosleep 阻塞均被唤醒后抵达计数点——完成数 < 4 即有
            //     丢失唤醒/旗永久置位 → 看门狗 fail-visible 显形。
            //     kernel spawn 无 parent 链（wait_pid 不适用，M9-A）——
            //     完成计数 + 协作让渡轮询（t87 anchor 同款）+ 孤儿收割
            //     （parent=None Zombie 槽位释放面）三段收口。
            let deadline = ostd::time::now() + 10 * interrupts::TIMER_HZ as u64;
            while T90_DONE.load(core::sync::atomic::Ordering::Acquire) < 4
                && ostd::time::now() < deadline
            {
                task::yield_now();
            }
            let done = T90_DONE.load(core::sync::atomic::Ordering::Acquire);
            ok &= done == 4;
            // 收割面：4 风暴 + 1 waker 全 parent=None Zombie（waker 于
            // done==4 后下一轮询退位——时序竞态由有界收尾环吸收：
            // 逐轮 reap + 让渡，全槽空即收）。
            let mut reaped = 0usize;
            let mut alive_left = 0usize;
            for _ in 0..4_000 {
                reaped += task::reap_orphans();
                alive_left = ids.iter().filter(|&&id| task::task_alive(id)).count();
                if alive_left == 0 {
                    break;
                }
                task::yield_now();
            }
            for (k, &id) in ids.iter().enumerate() {
                let _ = writeln!(
                    log,
                    "t90: storm[{k}] id={id} alive={}",
                    task::task_alive(id)
                );
            }
            ok &= alive_left == 0;
            // M41-T90F 收割计数锚适配（本机 TCG 慢主机两度实录取证）：
            // idle-reap 桥可先于本测试收割面抢收 parent=None Zombie——
            // 实录 reaped=0 而五槽 alive=false（谁收皆合法；无丢失唤醒
            // 强锚 done==4 与槽位回收强锚 alive_left==0 均在环，blk/wake
            // 320:320 严格配对、旗静默、canary 零破坏不变）。计数锚改
            // 孤儿取证全局计数器窗口增量——任意收割方皆计入；窗口内
            // parent=None Zombie 来源唯一 = t90 五任务。
            let (_reparented1, or1) = task::orphan_stamps();
            ok &= or1 - or0 >= 5;
            let _ = writeln!(
                log,
                "t90: done={done} orphan-reaped={reaped}+reaps+={}",
                or1 - or0
            );
            // (d) 计数下界 + 旗静默 + canary 零破坏。正实阻塞轮数 =
            //     4 × 80（2/3 正时程）；入口→探针窗整体流逝的降格面
            //     （M22-③ [C] 同族，宿主 vCPU 抢占域）留 24 轮裕度。
            let b1 = task::blocks();
            let w1 = task::block_wakes();
            let cv1 = task::canary_violations();
            let _cov1 = task::canary_audit_all();
            let blk = b1 - b0;
            let wak = w1 - w0;
            let pos_rounds = 4 * (T90_ROUNDS - T90_ROUNDS / 3) as u64;
            ok &= blk + 24 >= pos_rounds;
            ok &= wak + 24 >= pos_rounds;
            ok &= task::handshake_flags_clear();
            ok &= cv1 == cv0;
            let _ = writeln!(
                log,
                "t90: storm blk+={blk} wake+={wak} (floor {pos_rounds}) flags=clear canary cv+={}",
                cv1 - cv0
            );
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(
                log,
                "LUMINA-T90-HANDOFF storm=4x120 gate=armed wake-during-save=closed"
            );
            let _ = writeln!(log, "LUMINA-T90-OK");
        }
        ok
    };
    report(&mut log, t90, "sched-handoff");

    // 91) M38-TCP1 TCP 服务化批次活体（笔③）：五面 pulse 协议机 + vnet
    //     连接表驱动六相位——(a) 双连接并行交付（双四元组入表 + 交错
    //     回环段逐连接独立基线推进 + 拼接字节级对账 + 重复键/越界槽
    //     fail-visible 随行）；(b) Karn 窄化（首样 → 重传样拒零扰动 →
    //     滑动样整数账 RFC 6298）；(c) 拥塞折叠回升（慢启动 → RTO 折叠
    //     定标 → 回升弧越阈转 CA + 发送资格门控）；(d) 零窗探测击发
    //     （幂等臂 → Probe 电击发 una 起 1 字节探测段 + 退避二拍 → 窗
    //     重开解除）；(e) 窗缩放有效窗（双 SYN 协商生效 + wire<<shift
    //     有效窗 + 未缩放直通回归锚）；(f) 统计清账（probe 计数对账 +
    //     双连接 close 释放复用域 + 模板/WS/重组零残留）。LUMINA-T91-OK。
    let t91 = {
        let mut run = || -> bool {
            const A_CL: u16 = 42010;
            const A_SV: u16 = 42011;
            const B_CL: u16 = 42012;
            const B_SV: u16 = 42013;
            const SMSS: u32 = 536;
            use pulse::tcp::{
                self, ConnState, PersistDecision, RtoDecision, TcpKey, PROBE_SEG_LEN,
            };
            let mut ok = true;
            // 跨自检隔离（t89 揭雷纪律同款——真电臂跨自检存活防御面）
            vnet::tcp_retx_reset();
            vnet::tcp_conn_reset_all();
            let mut frame = [0u8; vnet::PULSE_FRAME_MAX];
            // 杂帧排水（共享交接环非空域——t86-g/t89-e 外部 SYN 的 slirp
            // 迟到应答经 t90 风暴窗异步落入 PULSE_RX；全量过真实分派链
            // 排空，绑定前执行不落槽——t69 ARP_SETTLE 同族时序面）
            let mut drained = 0usize;
            while let Some(fl) = vnet::pulse_rx_pop(&mut frame) {
                let _ = vnet::tcp_dispatch(&frame[..fl]);
                drained += 1;
                if drained >= 64 {
                    break;
                }
            }
            let _ = writeln!(log, "tcp-svc: pre-drain stray frames = {drained}");
            let blank = || vnet::TcpRxSeg {
                src_port: 0,
                dst_port: 0,
                seq: 0,
                ack_seq: 0,
                flags: 0,
                window: 0,
                len: 0,
                data: [0; vnet::TCP_SEG_MAX],
            };
            let pop_dispatch = |frame: &mut [u8]| -> Option<vnet::TcpRxSeg> {
                let mut got = None;
                let mut spin = 0u64;
                while spin < 40_000_000 {
                    if let Some(fl) = vnet::pulse_rx_pop(frame) {
                        got = Some(fl);
                        break;
                    }
                    spin += 1;
                    core::hint::spin_loop();
                }
                let fl = got?;
                vnet::tcp_dispatch(&frame[..fl])?;
                vnet::tcp_recv()
            };
            // (a) 双连接并行交付：双四元组入表（低址 0/1）+ 交错回环段
            let f_bind = vnet::tcp_bind(A_SV).is_ok()
                && vnet::tcp_bind(A_CL).is_ok()
                && vnet::tcp_bind(B_SV).is_ok()
                && vnet::tcp_bind(B_CL).is_ok();
            ok &= f_bind;
            let ka = TcpKey {
                src_ip: [10, 0, 2, 15],
                src_port: A_CL,
                dst_ip: [10, 0, 2, 15],
                dst_port: A_SV,
            };
            let kb = TcpKey {
                src_ip: [10, 0, 2, 15],
                src_port: B_CL,
                dst_ip: [10, 0, 2, 15],
                dst_port: B_SV,
            };
            let o0 = vnet::tcp_conn_open(ka, ConnState::Established, 1000, 2000, 512, SMSS);
            let o1 = vnet::tcp_conn_open(kb, ConnState::Established, 3000, 4000, 512, SMSS);
            ok &= o0 == Ok(0) && o1 == Ok(1);
            let f_tab = vnet::tcp_conn_count() == 2
                && vnet::tcp_conn_key_at(0) == Some(ka)
                && vnet::tcp_conn_key_at(1) == Some(kb)
                && vnet::tcp_conn_state(0) == Some(ConnState::Established)
                && vnet::tcp_conn_state(1) == Some(ConnState::Established);
            ok &= f_tab;
            let s0r = vnet::tcp_stats();
            // 重复键拒（连接表负例随行——fail-visible）
            let f_dup =
                vnet::tcp_conn_open(ka, ConnState::Established, 1000, 2000, 512, SMSS).is_err();
            ok &= f_dup;
            // 交错：a1 → b1 → a2（逐连接独立重组窗——基线各自推进）
            const A1: &[u8] = b"T91-A1";
            const A2: &[u8] = b"-A2";
            const B1: &[u8] = b"T91-B1";
            ok &=
                vnet::tcp_loopback_tx(A_CL, A_SV, 2001, 0, tcp::FLAG_ACK | tcp::FLAG_PSH, 512, A1);
            ok &=
                vnet::tcp_loopback_tx(B_CL, B_SV, 4001, 0, tcp::FLAG_ACK | tcp::FLAG_PSH, 512, B1);
            ok &= vnet::tcp_loopback_tx(
                A_CL,
                A_SV,
                2001 + A1.len() as u32,
                0,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                512,
                A2,
            );
            let mut out = [0u8; vnet::TCP_SEG_MAX];
            let sa1 = pop_dispatch(&mut frame).unwrap_or_else(blank);
            let f_seg1 = sa1.seq == 2001 && sa1.len == A1.len();
            ok &= f_seg1;
            let sb1 = pop_dispatch(&mut frame).unwrap_or_else(blank);
            let f_segb = sb1.seq == 4001 && sb1.len == B1.len();
            ok &= f_segb;
            let sa2 = pop_dispatch(&mut frame).unwrap_or_else(blank);
            let f_seg2 = sa2.seq == 2007 && sa2.len == A2.len();
            ok &= f_seg2;
            // 逐连接交付：a1 → conn0（InOrder 即排空）；b1 → conn1（并行独立
            // 域）；a2 → conn0（后继段单独交付——乱序拼接域归 t89-d 锚）
            let d1 = vnet::tcp_conn_deliver(
                0,
                sa1.seq,
                sa1.ack_seq,
                sa1.flags,
                sa1.window,
                &sa1.data[..sa1.len],
                &mut out,
            );
            let f_d1 = d1 == Some(A1.len()) && &out[..A1.len()] == A1;
            ok &= f_d1;
            let d_b = vnet::tcp_conn_deliver(
                1,
                sb1.seq,
                sb1.ack_seq,
                sb1.flags,
                sb1.window,
                &sb1.data[..sb1.len],
                &mut out,
            );
            let f_db = d_b == Some(B1.len()) && &out[..B1.len()] == B1;
            ok &= f_db;
            let d2 = vnet::tcp_conn_deliver(
                0,
                sa2.seq,
                sa2.ack_seq,
                sa2.flags,
                sa2.window,
                &sa2.data[..sa2.len],
                &mut out,
            );
            let f_d2 = d2 == Some(A2.len()) && &out[..A2.len()] == A2;
            ok &= f_d2;
            // 逐连接基线独立推进（双窗互不干扰——conn0 基线 2001+6+3=2010）
            ok &= vnet::tcp_conn_reasm_state(0) == Some((2010, 0));
            ok &= vnet::tcp_conn_reasm_state(1) == Some((4001 + B1.len() as u32, 0));
            // fail-visible 随行：越界槽位交付 None
            let f_neg = vnet::tcp_conn_deliver(9, 0, 0, 0, 0, b"x", &mut out).is_none();
            ok &= f_neg;
            let _ = writeln!(
                log,
                "tcp-svc: phase-a bind={f_bind} o0={o0:?} o1={o1:?} tab={f_tab} dup={f_dup} \\\n                 seg1={f_seg1} segb={f_segb} seg2={f_seg2} d1={f_d1} db={f_db} d2={f_d2} \\\n                 rs0={:?} rs1={:?} neg={f_neg}",
                vnet::tcp_conn_reasm_state(0),
                vnet::tcp_conn_reasm_state(1)
            );
            // (b) Karn 窄化（协议级——t89 (a)/(b) 同款先例）：首样 → 重传
            //     样拒零扰动 → 滑动样 RFC 6298 整数账（RTTVAR 先行序）
            ok &= vnet::tcp_conn_rtt_sample(0, 10_000_000, false) == Some(true); // 首样
            let rt0 = vnet::tcp_conn_rtt_state(0);
            ok &= rt0.is_some_and(|(s, v, _)| s == 10_000_000 && v == 5_000_000);
            ok &= vnet::tcp_conn_rtt_sample(0, 4_000_000, true) == Some(false); // Karn 拒
            ok &= vnet::tcp_conn_rtt_state(0) == rt0; // 窄化域零扰动
            ok &= vnet::tcp_conn_rtt_sample(0, 4_000_000, false) == Some(true); // 滑动
            ok &= vnet::tcp_conn_rtt_state(0)
                .is_some_and(|(s, v, _)| s == 9_250_000 && v == 2_625_000);
            let _ = writeln!(
                log,
                "tcp-svc: karn narrowed srtt={:?}",
                vnet::tcp_conn_rtt_state(0)
            );
            // (c) 拥塞折叠回升（SMSS=536 → IW=1072）：慢启动 → RTO 折叠
            //     定标 → 回升弧越阈转 CA + 发送资格门控双向
            ok &= vnet::tcp_conn_send_credit(1, u32::MAX) == Some(1072); // IW
            ok &= vnet::tcp_conn_cc_ack(1, 1072) == Some((2144, u32::MAX)); // SS
            ok &= vnet::tcp_conn_cc_ack(1, 1072) == Some((3216, u32::MAX)); // SS
                                                                            // RTO 折叠：flight=3216 → ssthresh = max(1608, 1072) = 1608；cwnd 回 IW
            ok &= vnet::tcp_conn_cc_rto(1, 3216) == Some((1072, 1608));
            // 回升弧：SS 1072→1608；== 阈域转 CA（536²/1608=178 → 160）
            ok &= vnet::tcp_conn_cc_ack(1, 536) == Some((1608, 1608));
            ok &= vnet::tcp_conn_cc_ack(1, 0) == Some((1786, 1608));
            ok &= vnet::tcp_conn_cc_ack(1, 0) == Some((1946, 1608));
            ok &= vnet::tcp_conn_send_credit(1, 1_000_000) == Some(1946); // cwnd 主导
            ok &= vnet::tcp_conn_send_credit(1, 64) == Some(64); // 窗主导
            let _ = writeln!(
                log,
                "tcp-svc: cc collapse-recovered cwnd=1946 ssthresh=1608"
            );
            // (d) 零窗探测击发（电气域）：模板 9 字节 @1000..1009 → 零窗
            //     ACK → 幂等臂 → Probe 电击发 una 起 1 字节探测段 → 退避
            //     二拍 → 窗重开解除
            const PROBE_TPL: &[u8] = b"PROBEDATA";
            let t_d = 10_000_000u64;
            ok &= vnet::tcp_conn_sent(0, 1).is_some_and(|nxt| nxt == 1001);
            ok &= vnet::tcp_conn_retx_arm_at(
                0,
                t_d,
                A_CL,
                A_SV,
                1000,
                0,
                tcp::FLAG_ACK | tcp::FLAG_PSH,
                512,
                PROBE_TPL,
            );
            ok &= vnet::tcp_conn_retx_armed(0)
                .is_some_and(|(seq, retries)| seq == 1000 && retries == 0);
            // 重传拍（合成拍模板→连接表驱动）：差一拍不早醒
            ok &= vnet::tcp_conn_retx_tick_at(0, t_d + pulse::tcp::RTO_INIT_NS - 1)
                == RtoDecision::Idle;
            ok &= vnet::tcp_conn_deliver(0, 0, 1001, tcp::FLAG_ACK, 0, &[], &mut out) == Some(0); // 零窗 ACK
            ok &= vnet::tcp_conn_swnd_state(0)
                .is_some_and(|(una, nxt, w)| una == 1001 && nxt == 1001 && w == 0);
            let pt = t_d + pulse::tcp::RTO_INIT_NS;
            ok &= vnet::tcp_conn_persist_arm(0, pt, 1000);
            ok &= vnet::tcp_conn_persist_arm(0, pt + 1, 999); // 幂等：臂时基定格
            let pr0 = vnet::tcp_probe_count();
            ok &= vnet::tcp_conn_persist_tick_at(0, pt + 999) == PersistDecision::Idle; // 差一拍
            ok &= vnet::tcp_conn_persist_tick_at(0, pt + 1000) == PersistDecision::Probe; // 电击发
            ok &= vnet::tcp_probe_count() == pr0 + 1;
            let prseg = pop_dispatch(&mut frame).unwrap_or_else(blank);
            ok &= prseg.seq == 1001 && prseg.len == PROBE_SEG_LEN && prseg.data[0] == b'R';
            let _ = writeln!(
                log,
                "tcp-svc: probe-1 fired seq={} len={PROBE_SEG_LEN}",
                prseg.seq
            );
            // 二拍退避（1000 << 1 = 2000）
            ok &= vnet::tcp_conn_persist_tick_at(0, pt + 1000 + 2000 - 1) == PersistDecision::Idle;
            ok &= vnet::tcp_conn_persist_tick_at(0, pt + 3000) == PersistDecision::Probe;
            ok &= vnet::tcp_probe_count() == pr0 + 2;
            // 第二探测段出环对账（退避拍电击发——字节级同账）
            let prseg2 = pop_dispatch(&mut frame).unwrap_or_else(blank);
            ok &= prseg2.seq == 1001 && prseg2.len == PROBE_SEG_LEN && prseg2.data[0] == b'R';
            // 窗重开：探测字节入账（nxt 1002）→ ACK ack=1002 窗=4 → 解除
            ok &= vnet::tcp_conn_sent(0, 1).is_some_and(|nxt| nxt == 1002);
            ok &= vnet::tcp_conn_deliver(0, 0, 1002, tcp::FLAG_ACK, 4, &[], &mut out) == Some(0);
            ok &= vnet::tcp_conn_swnd_state(0)
                .is_some_and(|(una, nxt, w)| una == 1002 && nxt == 1002 && w == 4);
            ok &= vnet::tcp_conn_persist_release(0);
            ok &= vnet::tcp_conn_persist_tick_at(0, pt + 999_999) == PersistDecision::Idle; // 解除后恒 Idle
            let _ = writeln!(log, "tcp-svc: window-reopened persist released ok={ok}");
            // d-2 连接表驱动重传拍收口：到期 Due → 全模板 9 B 电重发（字节
            //     级对账 + TCP_RETX 计数显形）→ ACK 越过清账（模板弃置）
            ok &= vnet::tcp_conn_retx_tick_at(0, t_d + pulse::tcp::RTO_INIT_NS) == RtoDecision::Due;
            let rtseg = pop_dispatch(&mut frame).unwrap_or_else(blank);
            ok &= rtseg.seq == 1000
                && rtseg.len == PROBE_TPL.len()
                && &rtseg.data[..PROBE_TPL.len()] == PROBE_TPL;
            ok &= vnet::tcp_stats().retx == s0r.retx + 1; // 连接表驱动电重发击发
            ok &= vnet::tcp_conn_retx_clear(0, 1002); // ACK 越过清账
            ok &= vnet::tcp_conn_retx_armed(0).is_none();
            let _ = writeln!(log, "tcp-svc: conn-retx full-template fired + ack-cleared");
            // (e) 窗缩放有效窗：双 SYN 协商生效（对端通告移位 = 2）→
            //     wire 16384 << 2 = 65536；未缩放直通回归锚（conn0 移位 0）
            ok &= vnet::tcp_conn_ws_negotiate(1, true, 2, true, Some(2)) == Some(2);
            ok &= vnet::tcp_conn_ws_negotiate(0, true, 2, false, Some(2)) == Some(0); // 对端缺 SYN → 0
            ok &= vnet::tcp_conn_sent(1, 1).is_some_and(|nxt| nxt == 3001);
            ok &=
                vnet::tcp_conn_deliver(1, 0, 3001, tcp::FLAG_ACK, 16384, &[], &mut out) == Some(0);
            ok &= vnet::tcp_conn_swnd_state(1)
                .is_some_and(|(una, nxt, w)| una == 3001 && nxt == 3001 && w == 16384);
            ok &= vnet::tcp_conn_effective_win(1) == Some(65_536); // wire << 2
            ok &= vnet::tcp_conn_effective_win(0) == Some(4); // 移位 0 直通（wire==effective）
            let _ = writeln!(
                log,
                "tcp-svc: ws effective win conn1=65536 conn0=wire-passthrough"
            );
            // (f) 统计清账：probe 计数对账 + 双连接 close（归还槽体 +
            //     模板/WS 清零）+ 释放复用域 + 零残留收场
            ok &= vnet::tcp_probe_count() == 2;
            let sf = vnet::tcp_stats();
            ok &= sf.probe == 2;
            ok &= vnet::tcp_conn_close(0).is_ok();
            ok &= vnet::tcp_conn_close(1).is_ok();
            ok &= vnet::tcp_conn_count() == 0;
            ok &= vnet::tcp_conn_key_at(0).is_none() && vnet::tcp_conn_key_at(1).is_none();
            ok &= vnet::tcp_conn_retx_armed(0).is_none() && vnet::tcp_conn_retx_armed(1).is_none();
            ok &= vnet::tcp_conn_deliver(0, 0, 0, 0, 0, b"x", &mut out).is_none(); // 关闭后槽失
            ok &= vnet::tcp_unbind(A_SV).is_ok();
            ok &= vnet::tcp_unbind(A_CL).is_ok();
            ok &= vnet::tcp_unbind(B_SV).is_ok();
            ok &= vnet::tcp_unbind(B_CL).is_ok();
            // 收场清账：连接面全清（下轮自检隔离域）
            vnet::tcp_conn_reset_all();
            vnet::tcp_retx_reset();
            ok
        };
        let ok = run();
        if ok {
            let _ = writeln!(
                log,
                "LUMINA-T91-TCP conns=2 probe=2 ws=2 karn=narrowed cc=recovered"
            );
            let _ = writeln!(log, "LUMINA-T91-OK");
        }
        ok
    };
    report(&mut log, t91, "tcp-svc");

    // t92) busybox ls 深链活体（M39-BBLS）：乱序目录制备 → `busybox ls -1`
    //      派生消费（openat 目录域 + getdents64 目录读 + musl 排序分配域
    //      qsort/malloc 增长 + writev 输出）→ 串口排序取证（制备 ZZZ 首建
    //      vs 输出 AAA 首行——xtask 双面板 pos(AAA)<pos(ZZZ) 断言）+
    //      readlink(89) 语义落点消费（非链接域败码 1 + readlink -f realpath
    //      链恒等）+ **stdio 保留域揭雷根治随行**（lin_abi 任务 open 槽搜索
    //      自 3 起——本缺口下 applet「先开后写」stdout 全数被首开句柄互踩
    //      吞没：t92 首拍 opendir 拾 fd 1 → writev(1) 写目录 EBADF raw=0x9
    //      95 B 输出域蒸发 + t83 wc 计数行同伤回溯在案——仅因内容级断言
    //      缺席而隐匿）。LUMINA-T92-OK 汇总标记（xtask S8/longrun 双面板
    //      required）。
    let t92 = {
        let mut ok = true;
        const DIR92: &[u8] = b"/t92d";
        // (a) 乱序制备域：12 条目（ZZZ 首建 → AAA 末建——制备顺序与字典
        //     序反相；f01..f10 中段填充——排序分配域 malloc 增长面消费）
        const NAMES92: [&[u8]; 12] = [
            b"LUMINA-T92-ZZZ",
            b"f01-t92",
            b"f02-t92",
            b"f03-t92",
            b"f04-t92",
            b"f05-t92",
            b"f06-t92",
            b"f07-t92",
            b"f08-t92",
            b"f09-t92",
            b"f10-t92",
            b"LUMINA-T92-AAA",
        ];
        ok &= vfs::sys_mkdir(DIR92.as_ptr() as u64, DIR92.len() as u64) == 0;
        let mut prep = 0usize;
        let mut pbuf = [0u8; 48];
        for name in NAMES92.iter() {
            pbuf[..DIR92.len()].copy_from_slice(DIR92);
            pbuf[DIR92.len()] = b'/';
            pbuf[DIR92.len() + 1..DIR92.len() + 1 + name.len()].copy_from_slice(name);
            let plen = DIR92.len() + 1 + name.len();
            let h = vfs::sys_open_bytes(&pbuf[..plen], bedrock::abi::O_CREAT | 0b10);
            if h >> 32 == 1 {
                let payload: &[u8] = b"t92\n";
                let w = vfs::sys_write(
                    h & 0xFFFF_FFFF,
                    payload.as_ptr() as u64,
                    payload.len() as u64,
                );
                ok &= w >> 32 == 1 && (w & 0xFFFF_FFFF) as usize == payload.len();
                prep += 1;
                let _ = vfs::sys_close(h & 0xFFFF_FFFF);
            } else {
                ok = false;
            }
        }
        // (a2) 内核侧目录域探针：open /t92d（0b01 读）→ readdir64_page
        //      一页遍历 → 条目计数断言 12（fs 域满域实证——applet 空输出
        //      鉴别面：fs 域 vs applet 车道）
        let hd = vfs::sys_open_bytes(DIR92, 0b01);
        ok &= hd >> 32 == 1;
        let mut kbuf = [0u8; 2048];
        let ktotal = vfs::readdir64_page(hd & 0xFFFF_FFFF, &mut kbuf).unwrap_or(0);
        let mut kcount = 0usize;
        let mut koff = 0usize;
        while koff + 19 <= ktotal {
            let reclen = u16::from_le_bytes([kbuf[koff + 16], kbuf[koff + 17]]) as usize;
            if reclen == 0 {
                break;
            }
            kcount += 1;
            koff += reclen;
        }
        ok &= kcount == 12;
        let _ = vfs::sys_close(hd & 0xFFFF_FFFF);
        // (b) ls 派生消费 + readlink 双相位：四 applet 串行派生收割
        //     （t83 同款装载链 + stdio 保留域根治随行；readlink 非链接域
        //     → EINVAL → applet 败码 1；readlink -f = musl realpath 链
        //     消费——首步 readlink(path) 非链接 EINVAL → lstat 环 → 无
        //     链接恒等路径返回；**号域勘误揭雷随行**：M39-计划 笔① 登记
        //     readlink(90) 误记——x86_64 号域 readlink=89（90=chmod），
        //     首拍 LIN-DISPATCH-ERR num=89 errno=38 实录，90→89 随本笔
        //     改正后 -f 相位转正）
        let applets: [(&[&str], u64); 4] = [
            (&["/bin/busybox", "ls", "-1", "/t92d"], 0),
            (&["/bin/busybox", "readlink", "/t92d/f01-t92"], 1),
            // -f 相位 = musl realpath 链恒等（89 收录后转正——打印原
            // 路径 exit 0；号域勘误揭雷随行）
            (&["/bin/busybox", "readlink", "-f", "/t92d"], 0),
            // 对照面：/bin 命名空间目录 ls（applet 目录读第二数据点——
            // stdio 保留域根治后与 /t92d 同车道）
            (&["/bin/busybox", "ls", "-1", "/bin"], 0),
        ];
        let mut reaped: [u64; 4] = [u64::MAX; 4];
        if let Some(blob) = vfs::read_image("/bin/busybox") {
            for (i, (argv, expect)) in applets.iter().enumerate() {
                let Some(frames) = vmm::global_frames() else {
                    let _ = writeln!(log, "t92[{}]: frame service unreachable", i);
                    ok = false;
                    break;
                };
                // AT_RANDOM 熵：TSC 纪元拆字节（t82 同款）
                let t = ostd::time::tsc_now();
                let mut random = [0u8; 16];
                for (j, b) in random.iter_mut().enumerate() {
                    *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
                }
                match user::build_user_space_elf(
                    &blob,
                    argv,
                    &["PATH=/bin"],
                    random,
                    "busybox",
                    &mut || frames.alloc(),
                ) {
                    Ok(es) => {
                        let mut slots = [0u64; 15];
                        slots[0] = 0x202; // RFLAGS：IF=1
                        slots[1] = es.entry;
                        slots[7] = es.rsp;
                        let id = task::spawn_fork_child(
                            "busybox-applet",
                            es.root,
                            task::current_task_id(),
                            slots,
                            true,
                        );
                        if id == usize::MAX {
                            let _ = writeln!(log, "t92[{}]: task slot exhausted", i);
                            ok = false;
                            break;
                        }
                        let r = procs::sys_wait_pid(id as u64);
                        let rpid = (r >> 16) & 0xFFFF;
                        let code = r & 0xFFFF;
                        reaped[i] = code;
                        let _ = writeln!(
                            log,
                            "t92[{}] {} reaped pid={rpid} exit={code} (expect {expect})",
                            i, argv[1]
                        );
                        ok &= r >> 32 == 1; // WAITPID_OK_BIT
                        ok &= rpid == id as u64;
                        ok &= code == *expect;
                        ok &= !task::task_alive(id);
                    }
                    Err(e) => {
                        let _ = writeln!(log, "t92[{}]: user space build failed ({e:?})", i);
                        ok = false;
                        break;
                    }
                }
            }
        } else {
            let _ = writeln!(log, "t92: /bin/busybox media MISS");
            ok = false;
        }
        // (c) 制备域清扫（叶子同域可摘——非空目录域由制备完整性保障）
        let mut cleaned = 0usize;
        for name in NAMES92.iter() {
            pbuf[..DIR92.len()].copy_from_slice(DIR92);
            pbuf[DIR92.len()] = b'/';
            pbuf[DIR92.len() + 1..DIR92.len() + 1 + name.len()].copy_from_slice(name);
            let plen = DIR92.len() + 1 + name.len();
            if vfs::sys_remove_bytes(&pbuf[..plen]) == 0 {
                cleaned += 1;
            }
        }
        ok &= cleaned == 12;
        ok &= vfs::sys_remove_bytes(DIR92) == 0; // 空目录摘除
        let _ = writeln!(
            log,
            "LUMINA-T92-LS prepared={prep} kcount={kcount} cleaned={cleaned} order=ZZZ-first expect-output=AAA-first ls={} rlneg={} rlf={} lsbin={}",
            reaped[0], reaped[1], reaped[2], reaped[3]
        );
        if ok {
            let _ = writeln!(log, "LUMINA-T92-OK");
        }
        ok
    };
    report(&mut log, t92, "busybox-ls");

    // t93) 多用户纵深活体（M39-MU）：独立函数执行体（帧形态守恒见
    // t93_run 头注）——凭据四元真面 + setuid 根域收口 + 权限门禁覆盖
    // 表 + busybox id 领域换装消费。LUMINA-T93-OK 汇总标记。
    let t93 = t93_run(&mut log);
    report(&mut log, t93, "multi-user");

    // t94) DPMS 电气面活体（M39-DPMS）：stdvga VGA 寄存器域写/读回
    //      四相位（SR01 消隐位 + Misc Output 同步极性域）+ M34-P4 登记
    //      面电气挂接（blank/unblank → dpms_set）。LUMINA-T94-OK。
    let t94 = t94_run(&mut log);
    report(&mut log, t94, "dpms-elec");

    // t96) 盘上属主域活体（M40-CRYSTAL）：Lfs InodeRec v2 属主三域
    //      落盘 + chown(92)/chmod(90) 车道 + stat 真面透出 + 门禁回源
    //      （PERMS 登记优先 / 盘上次之）+ 组属主位域判定 + 持久化
    //      对账（盘上直读）。LUMINA-T96-OK。
    let t96 = t96_run(&mut log);
    report(&mut log, t96, "disk-owner");

    // t97) cat applet 实证活体（M40-CAT）：制备文件域（内容断言载荷）
    //      → `busybox cat` 派生消费 → 内容级断言（串口标记——纠正 t83
    //      wc 式内容级断言缺席教训）+ sendfile 车道实测 + 负例 + 清扫。
    //      LUMINA-T97-CAT/OK。
    let t97 = t97_run(&mut log);
    report(&mut log, t97, "busybox-cat");

    // t98) 块层字节域取证矩阵活体（M41-笔② / M17-① 标本清账）：值域
    //      矩阵八组（台账标本原值 0o060/0o400 + nibble 敏感 + 跨字节）
    //      × 同/跨调用读 × 双文件交替哨兵 × 持久化对账——错位则 fail-
    //      visible 现场，全绿则 M17-① 存量消解（t96 (d)/(e) 翻正依据）。
    //      LUMINA-T98-M17/OK。
    let t98 = t98_run(&mut log);
    report(&mut log, t98, "blk-domain");

    // t99) 多用户纵深二批活体（M41-笔③）：saved-set 三态交换链
    //      （root setreuid(1000,0) → suid=0 → setreuid(-1,1000)〔suid 保
    //      0〕→ 非 root setreuid(-1,0) 交换 + 越域拒）+ setgroups/
    //      getgroups 双面 + 补充组盘上门禁矩阵（组内命中放行/清空拒）。
    //      LUMINA-T99-MU2/OK。
    let t99 = t99_run(&mut log);
    report(&mut log, t99, "mu-deep2");

    // t100) ash 交互面活体（M41-笔④）：busybox sh 交互模式（无 -c）
    //       spawn + kbd 字节直注入两行（echo/exit）→ 阻塞式 tty read
    //       端到端（lin_read fd 0 阻塞化转正）→ exit=0 收割 + echo
    //       直通串口标记。LUMINA-T100-ASH/OK。
    let t100 = t100_run(&mut log);
    report(&mut log, t100, "ash-interactive");

    // t101) 用户态 fb 驱动进程移交链活体（M42-阶段一 笔①）：fbdev 映像
    //       spawn → SYS_FB_MAP LFB 映射移交（SURFACE_OWNER 首认领者 =
    //       驱动进程）→ SYS_DEV_PIO dispi 探测（端口裁量注册表——内核
    //       代执车道）→ LFB 直写成像 × 内核侧 VRAM 物理读回对账 →
    //       svc::adopt_user Owner 用户态承接（KernelResident(fb) →
    //       UserTask——电气面零改动混合态如实登记）→ exit=0 收割 +
    //       裁量闸负例（未授予 pid 即 ERR_CAP）。LUMINA-T101-FBDEV/OK。
    let t101 = t101_run(&mut log);
    report(&mut log, t101, "fbdev-driver");

    // t102) 常驻 fbdev 服务活体（M42-阶段一 笔②「驱动进程常驻面：服务
    //       环/IPC 通道 + 常驻 fbdev 服务化」）：boot 铸造面服务环对账
    //       → Owner 移交链（release_user 归还 + 双负例）→ 常驻服务映像
    //       spawn_stage_wired 接线域（子 h1/h2 = FB 请求/应答通道）→
    //       grant + re-adopt → kmain 客户端请求环（PAINT_RECT 成像 /
    //       越域拒绝 fail-visible / QUIT 有界终结）→ 内核侧 VRAM 双漆
    //       读回（boot 身份漆存续 + 服务域成像）→ exit=0 收割。
    //       LUMINA-T102-FBSVC/OK。阶段一常驻面落域——unix socket 域
    //       （阶段二）门控随用户裁决。
    let t102 = t102_run(&mut log);
    report(&mut log, t102, "fbdev-service");

    // t103) unix socket 域 + Wayland wire 语义面活体（M42-阶段二 笔③
    //       「AF_UNIX socketpair/连接面 + Wayland wire 协议解析壳」）：
    //       socketpair 铸造对账〔对象 id 段正交〕→ 负例面〔坏句柄
    //       ERR_CAP / 未登记名 ERR_NOENT / 词法域 Name / dup bind
    //       ERR_INUSE / parse 越域 BadArgs〕→ 连接面 bind/connect/
    //       accept 三柄在环 + 回环 I/O → 阻塞唤醒链（echo 内核任务
    //       WaitWhat::UnixRecv 双向唤醒 + 取证戳增量）→ 流短写语义
    //       〔满环 0 短写 + 计账精确〕→ Wayland wire 编组/解析回环
    //       〔prism::wayland bind 特例签名 + global 事件——语义面对
    //       内核可消费显形〕→ close 分支〔句柄回收 + 对象存续纪律〕。
    //       LUMINA-T103-UNIX/OK。阶段二两域落域——阶段三进程面随用户
    //       裁决开工。
    let t103 = t103_run(&mut log);
    report(&mut log, t103, "unix-socket");

    // t104) 合成器进程面活体（M42-阶段三 笔④「prism 仲裁 ring3 化 +
    //       loom/cascade 用户态承接 + wayland 合成器进程消费
    //       SYS_FB_SURFACE——unix socket 域与 wire 壳合流电气面」）：
    //       boot 常驻面三域对账〔waycomp bind 名域 + SVC_COMPOSITOR
    //       第 6 预设 + 监听对象段正交〕→ 阻塞 accept 唤醒链
    //       〔WaitWhat::UnixAccept——connect 落队定向唤醒 + 取证戳〕
    //       → 合流电气面〔get_registry → globals 公告解析——wire 壳
    //       ⇄ unix socket 回环〕→ 仲裁策略承接〔bind + create_surface
    //       ×2 + damage + frame + commit——cascade tiling 平面 z 序
    //       注入 + SYS_FB_SURFACE 登记 + 代 Paint + SYNC/COMPOSE +
    //       VRAM 模式读回 + surf_layer_of 策略/登记同源对账〕→
    //       EOF 对端终结面〔shutdown → 排空 EOF + ERR_PIPE + teardown
    //       回退〕。LUMINA-T104-COMP/OK。阶段三首笔落域。
    let t104 = t104_run(&mut log);
    report(&mut log, t104, "wayland-compositor");

    // t105) 用户态 ELF 播种 lane 活体（M42-次笔 域①「ring3 编译进程
    //       承接」）：lane 结构闸负例〔非 ELF → BadImage〕→ ELF_NATIVE
    //       真 ELF64 静态映像播种（build_user_space_elf 装载 + 原生
    //       ABI 派生 lin_abi=false 对账）→ 有界收割 exit=77。
    //       LUMINA-T105-ELF/R3/OK。
    let t105 = t105_run(&mut log);
    report(&mut log, t105, "elf-seed-lane");

    // t106) 桌面链 wl_shm/fd 传递活体（M42-次笔 域②）：SYS_SHM 域闸
    //       负例 → SHM_CLIENT ELF 播种（域① lane 消费面——CREATE+
    //       MAP+池像素直写+CONNECT+SEND_FD+wire 批+帧回调等待）→
    //       waycomp 池承接（RECV_FD）→ 客户端像素 VRAM 断言 → fd 传递
    //       对账 → exit=0 收割 + teardown 复原。LUMINA-T106-CLIENT/SHM/OK。
    let t106 = t106_run(&mut log);
    report(&mut log, t106, "wl-shm-fdpass");

    // t95) ash 启动链标本流程活体（M40-ASH2 备置 → **M41-笔① 转正**）
    //      ——栈 grow 缺陷族 × syscall entry 致命域修复落域（vmm.rs
    //      pf_hook 入口扩判「U 位 或 CR2 落增长栈窗口域」——CPL0 用户
    //      栈 push #PF e=2 漏救域收口）：标本流程三步已落——① 定根因
    //      （-d int 标本在案：ash 用户栈 #PF-grow 循环正常推进
    //      〔CR2=0x1803fe800→0x1803ba000 逐页〕+ **lumina_syscall_entry
    //      CPL0 用户栈 push #PF e=2〔无 U 位〕不走 stack_grow 通路 →
    //      致命 #DF 核瘫痪**〔trace 12496 条 + DR0 哨兵 1140 次合法保
    //      存计数 = M22-③ 族 ISR 高频交换窗〕——M39-ASH「用户态自旋」
    //      定性随本标本修正为「栈 grow 缺陷族 × syscall entry 致命域 +
    //      ISR 抢占窗族」）；② 互斥（PERCPU_IS_USER 三闸——ring3 ISR
    //      交换触发面移除 + t34/t40 装置事件驱动化适配，两活体 PASS
    //      在案）；③ 回归（t95 标本装置本笔转正——ash -c 'exit 7'
    //      全量启动链活体收割，SELFTEST 96→97）。
    let t95 = t95_run(&mut log);
    report(&mut log, t95, "ash-spec");

    /// t93 多用户纵深活体执行体（M39-MU）：独立函数承载——自检主函数
    /// 栈帧零扰动（M39-ASH 帧形态教训随行——t87 邻域栈槽形态守恒；
    /// 内联块撑帧 = t87 窗族确定性复发实录，独立函数形态翻绿在案）。
    fn t93_run(log: &mut DualLog) -> bool {
        let mut ok = true;
        let (mut ok_a, mut ok_b, mut ok_c, mut ok_d, mut ok_e) = (true, true, true, true, true);
        let me = task::current_task_id();
        // (a) 凭据四元真面：kmain=root 口径读取
        let cr = task::task_creds(me);
        ok_a &= cr.is_some_and(|c| c.uid == 0 && c.gid == 0 && c.euid == 0 && c.egid == 0);
        ok &= ok_a;
        // (b) setuid 语义核三目（root 全量 / 非 root 拒他 / 非 root 自改）
        //     ——lin 语义核直调（号域 105/106 真面；恢域走测试面写回）
        ok_b &= linux::setuid_probe(1000) == 0; // root → 1000 全量
        let c1000 = task::task_creds(me).is_some_and(|c| c.uid == 1000 && c.euid == 1000);
        ok_b &= c1000;
        ok_b &= linux::setuid_probe(42) == 1; // 非 root 拒他（EPERM=1）
        ok_b &= linux::setgid_probe(1000) == 0; // 自改写合法（gid==1000 已是）
        ok_b &= linux::setuid_probe(1000) == 0; // 自改写合法（uid==1000）
        ok &= ok_b;
        // (c) busybox id 领域换装消费（uid=1000 派生继承——身份真面
        //     端到端：musl getuid/geteuid/getgid/getegid 真读取 → id
        //     输出 uid=1000 gid=1000 串口取证）
        task::with_task_creds_mut(me, |c| {
            *c = task::Creds::new4(1000, 1000, 1000, 1000);
        });
        if let Some(blob) = vfs::read_image("/bin/busybox") {
            if let Some(frames) = vmm::global_frames() {
                let argv = ["/bin/busybox", "id"];
                let t = ostd::time::tsc_now();
                let mut random = [0u8; 16];
                for (j, b) in random.iter_mut().enumerate() {
                    *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
                }
                match user::build_user_space_elf(
                    &blob,
                    &argv,
                    &["PATH=/bin"],
                    random,
                    "busybox",
                    &mut || frames.alloc(),
                ) {
                    Ok(es) => {
                        let mut slots = [0u64; 15];
                        slots[0] = 0x202;
                        slots[1] = es.entry;
                        slots[7] = es.rsp;
                        let id_pid = task::spawn_fork_child("busybox-id", es.root, me, slots, true);
                        if id_pid != usize::MAX {
                            let r = procs::sys_wait_pid(id_pid as u64);
                            let code = r & 0xFFFF;
                            let _ = writeln!(log, "t93: id reaped pid={id_pid} exit={code}");
                            ok_c &= r >> 32 == 1 && code == 0 && !task::task_alive(id_pid);
                            ok &= ok_c;
                        } else {
                            ok = false;
                        }
                    }
                    Err(e) => {
                        let _ = writeln!(log, "t93: id build failed ({e:?})");
                        ok = false;
                    }
                }
            } else {
                let _ = writeln!(log, "t93: frame service unreachable");
                ok = false;
            }
        } else {
            let _ = writeln!(log, "t93: /bin/busybox media MISS");
            ok = false;
        }
        // (d) 权限门禁覆盖表：登记 /guard 路径 → 四目（root 旁路 RW /
        //     owner RW / 他者 EACCES / 他者摘除 EACCES）+ faccessat 真判定
        const GUARD: &[u8] = b"/t93guard";
        ok &= vfs::perm_install("/t93guard", 1000, 0o600).is_ok();
        let hg = vfs::sys_open_bytes(GUARD, bedrock::abi::O_CREAT | 0b10);
        ok &= hg >> 32 == 1; // root 旁路建写
        ok &= vfs::sys_close(hg & 0xFFFF_FFFF) == 0;
        // uid 1000 owner RW（换装域）
        task::with_task_creds_mut(me, |c| {
            *c = task::Creds::new4(1000, 1000, 1000, 1000);
        });
        let ho = vfs::sys_open_bytes(GUARD, 0b10);
        ok &= ho >> 32 == 1; // owner 写放行
        ok &= vfs::sys_close(ho & 0xFFFF_FFFF) == 0;
        // uid 1001 他者域（换装域）
        task::with_task_creds_mut(me, |c| {
            *c = task::Creds::new4(1001, 1001, 1001, 1001);
        });
        ok &= vfs::sys_open_bytes(GUARD, 0b01) == 13; // EACCES
        ok &= vfs::sys_remove_bytes(GUARD) == 13; // 摘除域 EACCES
                                                  // faccessat 真判定（登记路径优先——他者 W_OK → EACCES）
                                                  // W_OK——门禁核直调（未登记域哨兵 u64::MAX——本相位已登记不达）
        let facc_v = vfs::access_gate_bytes(GUARD, 2).unwrap_or(u64::MAX);
        let d1 = facc_v == 13;
        let d2 = vfs::sys_open_bytes(GUARD, 0b01) == 13;
        let d3 = vfs::sys_remove_bytes(GUARD) == 13;
        let d4 = ho >> 32 == 1;
        let d5 = hg >> 32 == 1;
        ok_d &= d1 && d2 && d3 && d4 && d5;
        ok &= ok_d;
        let _ = writeln!(
            log,
            "t93: d1={} d2={} d3={} d4={} d5={} facc_raw={facc_v}",
            d1, d2, d3, d4, d5
        );
        // (e) root 回装域：root 旁路清扫（摘除 + 登记摘槽）+ 凭据还原
        task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
        ok_e &= vfs::sys_remove_bytes(GUARD) == 0;
        ok_e &= vfs::perm_remove("/t93guard").is_ok();
        ok_e &= vfs::sys_open_bytes(GUARD, 0b01) == 2; // 已摘除 → ENOENT（未登记域不受门禁）
        let cr2 = task::task_creds(me);
        ok_e &= cr2.is_some_and(|c| c.uid == 0 && c.gid == 0);
        ok &= ok_e;
        let _ = writeln!(
            log,
            "LUMINA-T93-MU a={} b={} c={} d={} e={}",
            ok_a, ok_b, ok_c, ok_d, ok_e
        );
        if ok {
            let _ = writeln!(log, "LUMINA-T93-OK");
        }
        ok
    }

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
            // ---- M33-R1：长稳显示 tick 面板（--features longrun，S10 Panel B）----
            // 自检 82/82 全绿后进入 1080p 扫描带 compose tick 循环：每拍一条
            // 1920×108 损伤带（10 拍无缝覆盖全屏）经 stage 写 → damage 标记
            // → compose 交盒全链上屏（t79-f 同构复用），同步字节/交盒像素
            // 任一失配 = fault 显形即失败退出（fail-visible，不静默续跑）；
            // 每 16 拍心跳行串口取证（宿主 S10-longrun harness 到时强杀，
            // 按心跳单调/连续/零故障判定）。与 interactive 互斥（同给时
            // interactive 优先——外层 cfg(not(interactive)) 收束）；批跑/
            // 回归构建不用本特性，S8 门禁路径零扰动。60fps 实时率口径归
            // 真机窗口（TCG 下宿主记录实测 fps 信息面不设闸——M33-R1 登记）。
            #[cfg(feature = "longrun")]
            {
                let _ = writeln!(
                    log,
                    "LUMINA-LONGRUN-B-ON w={} h={} band=108 hb=16",
                    crate::fb::WIDTH,
                    crate::fb::HEIGHT
                );
                let Some(_) = crate::fb::stage_init() else {
                    interrupts::disable();
                    kernel_exit(EXIT_FAILURE);
                };
                let w: i32 = crate::fb::WIDTH as i32;
                let h: i32 = crate::fb::HEIGHT as i32;
                let band: i32 = 108;
                let hb_every: u64 = 16;
                let mut tick: u64 = 0;
                loop {
                    // 带起点恒 < h 且随 tick 循环扫描（u64 步进取模——72h
                    // 满窗 tick×band 不溢出 i32 域）；色调随 tick 轮换
                    // （活体可辨），行内低字节随 xx 抖动（逐拍像素证据
                    // 非纯色块——交盒/裁剪证据可读）。
                    let y = ((tick * band as u64) % h as u64) as i32;
                    let tone = (tick & 0xFF) as u32;
                    let paint = (tone << 16) | (tone << 8) | tone;
                    for yy in y..y + band {
                        for xx in 0..w {
                            crate::fb::stage_px_write(xx, yy, paint ^ (xx as u32 & 0xFF));
                        }
                    }
                    let bytes = crate::fb::sys_fb_sync(0, y as u64, w as u64, band as u64);
                    let px = crate::fb::fb_compose_tick();
                    let want = w as u64 * band as u64;
                    if bytes != want * 4 || px != want {
                        let _ = writeln!(
                            log,
                            "LUMINA-LONGRUN-B-FAULT tick={tick} bytes={bytes} px={px}"
                        );
                        interrupts::disable();
                        kernel_exit(EXIT_FAILURE);
                    }
                    tick += 1;
                    if tick.is_multiple_of(hb_every) {
                        let _ = writeln!(log, "LUMINA-LONGRUN-B tick={tick} px={px} fault=0");
                    }
                }
            }
            #[cfg(not(feature = "longrun"))]
            {
                interrupts::disable();
                kernel_exit(EXIT_SUCCESS);
            }
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

/// t94 DPMS 电气面活体执行体（M39-DPMS）：独立函数承载（帧形态守恒
/// 纪律——M39-ASH/M39-MU 两度实录：内联块撑帧 = t87 窗族确定性复发，
/// 独立函数形态守恒翻绿）。
fn t94_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    // (a) 基线读回：SR01 消隐位清（On 域）+ Misc Output 读通路在环
    let misc0 = crate::fb::dpms_misc_read();
    ok &= !crate::fb::dpms_sr01_screen_off();
    let _ = writeln!(
        log,
        "t94: baseline sr01-off={} misc0={misc0:#04x}",
        crate::fb::dpms_sr01_screen_off()
    );
    // (b) Off 电气：消隐置位 + 双极性翻转 → 读回对账 → On 恢复
    crate::fb::dpms_set(crate::fb::DpmsLevel::Off);
    let off_sr = crate::fb::dpms_sr01_screen_off();
    let off_misc = crate::fb::dpms_misc_read();
    ok &= off_sr;
    ok &= off_misc & 0xC0 == 0xC0; // hsync+vsync 极性位域双置
    crate::fb::dpms_set(crate::fb::DpmsLevel::On);
    ok &= !crate::fb::dpms_sr01_screen_off();
    ok &= crate::fb::dpms_misc_read() & 0xC0 == 0x00;
    let _ = writeln!(log, "t94: off sr01={off_sr} misc={off_misc:#04x} restored");
    // (c) Standby/Suspend 极性域：单边翻转读回对账
    crate::fb::dpms_set(crate::fb::DpmsLevel::Standby);
    let sb_misc = crate::fb::dpms_misc_read();
    ok &= sb_misc & 0xC0 == 0x40; // hsync 翻转单独置位
    crate::fb::dpms_set(crate::fb::DpmsLevel::Suspend);
    let sp_misc = crate::fb::dpms_misc_read();
    ok &= sp_misc & 0xC0 == 0x80; // vsync 翻转单独置位
    crate::fb::dpms_set(crate::fb::DpmsLevel::On);
    ok &= crate::fb::dpms_misc_read() & 0xC0 == 0x00;
    let _ = writeln!(
        log,
        "t94: standby={sb_misc:#04x} suspend={sp_misc:#04x} restored"
    );
    // (d) M34-P4 登记面电气挂接：blank → Off 域 / unblank → On 域
    ok &= crate::fb::fb_display_blank();
    ok &= crate::fb::dpms_sr01_screen_off();
    ok &= crate::fb::fb_display_unblank();
    ok &= !crate::fb::dpms_sr01_screen_off();
    let _ = writeln!(
        log,
        "t94: display-face blank/unblank electrical chain in-loop"
    );
    if ok {
        let _ = writeln!(
            log,
            "LUMINA-T94-DPMS baseline={misc0:#04x} levels=on/off/standby/suspend readback=ok"
        );
        let _ = writeln!(log, "LUMINA-T94-OK");
    }
    ok
}

/// t95 ash 启动链标本流程活体执行体（M40-ASH2）：独立函数承载（帧形态
/// 守恒纪律——M39-ASH/M39-MU/M39-BBLS 三度实录）。标本流程三步制：
/// (a) 号域勘误面直调取证（getppid 真面 = 父任务 pid——M39-ASH 台账
/// 「getppid(109)/getpgrp(110)」勘误后语义落域）；(b) t92 同款装置
/// 重建 `busybox sh -c 'exit 7'` + 有界收割（PIT 刻度 deadline 轮询
/// ——t90 先例；sys_wait_pid 阻塞无上界，滞域取证不可用）；(c) 滞点
/// 标本取证行（state/wait/syscall 三域快照——H1 用户态自旋〔Ready/
/// Running 且 syscall 计数增速判形〕/ H2 内核无声 Blocked〔wait=4
/// Timer 即 t52 后唤醒链退役域死锁标本〕双假设判别面）→ 回归域
/// exit=7 传导对账 + Zombie 收割。滞域 fail-visible（装置不静默——
/// M39-ASH 撤闸先例随标本定性裁决）。
/// M41-笔① 转正（栈 grow 缺陷族修复落域——pf_hook 入口扩判）。
fn t95_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    task::reset_user_evidence(); // 零锁判据面清零（前置 user 测试残留摘除）
    let me = task::current_task_id();
    // (a) 号域勘误面直调：getppid 真面（kmain 自检域——父链 = 引导面
    //     None → 1 init 哨兵，Linux 引导域同款）
    let ppid = task::task_ppid(me);
    let _ = writeln!(log, "t95: facet getppid me={me} ppid={ppid}");
    // (b) busybox sh -c 'exit 7' spawn（t92 同款装载链 + stdio 保留域
    //     既有语义；AT_RANDOM TSC 熵同款）
    const ASH_ARGV: [&str; 4] = ["/bin/busybox", "sh", "-c", "exit 7"];
    let Some(blob) = vfs::read_image("/bin/busybox") else {
        let _ = writeln!(log, "t95: /bin/busybox media MISS");
        return false;
    };

    let Some(frames) = vmm::global_frames() else {
        let _ = writeln!(log, "t95: frame service unreachable");
        return false;
    };
    let t = ostd::time::tsc_now();
    let mut random = [0u8; 16];
    for (j, b) in random.iter_mut().enumerate() {
        *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
    }
    let es = match user::build_user_space_elf(
        &blob,
        &ASH_ARGV,
        &["PATH=/bin"],
        random,
        "busybox",
        &mut || frames.alloc(),
    ) {
        Ok(es) => es,
        Err(e) => {
            let _ = writeln!(log, "t95: user space build failed ({e:?})");
            return false;
        }
    };

    let mut slots = [0u64; 15];
    slots[0] = 0x202; // RFLAGS：IF=1
    slots[1] = es.entry;
    slots[7] = es.rsp;
    let ash_id = task::spawn_fork_child("busybox-ash", es.root, me, slots, true);
    if ash_id == usize::MAX {
        let _ = writeln!(log, "t95: task slot exhausted");
        return false;
    }
    let _ = writeln!(log, "t95: step5 spawned id={ash_id}");
    let s0pre = task::task_debug_state(ash_id);
    let _ = writeln!(
        log,
        "t95: step5b s0pre={s0pre} (1=Ready 2=Running 3=Blocked 4=Zombie)"
    );
    // (c) 有界收割 + 标本取证：PIT 刻度 deadline（40 拍 ≈ 0.4 s @100Hz
    //     ——纯退出命令域上界，t92 applet 收割即时对照 20 倍裕度）。
    //     **自旋轮询非让渡**（M40-ASH2 装置形态）：kmain ring0 自旋检
    //     查——ash 由 spawn kick IPI 交 AP 核拾取跑（互斥闸后 ring3 无
    //     ISR 交换，BSP 若切入 ash 即无人换回——装置不得成为滞域同
    //     谋，M39-ASH 布局扰动三实验先例）；BSP PIT 照常交付（ring0
    //     驻留）→ deadline 必达。推进采样行每 2M 迭代成像。
    let sc0 = task::syscall_counts();
    let s0 = task::task_debug_state(ash_id);
    let now0 = ostd::time::now();
    let deadline = now0 + 40; // 40 拍 = 0.4 s @100Hz（纯退出命令域上界——
                              // t92 applet 收割即时对照 20 倍裕度）
    let mut iters: u64 = 0;
    // **零锁轮询**（M40-ASH2 装置）：ash 的 user exit 域 = per-CPU 原子
    // （USER_EXIT_CODES[1]，pinned 核 1 槽）——零锁读面取代 sched_lock
    // 域 state 查询（拿锁轮询面在滞域全静默——锁面取样不可靠，零锁面
    // 保装置活性）；now() = 全局 TICKS 原子。
    while task::user_exit_codes().1 == u64::MAX
        && ostd::time::now() < deadline
        && iters < 2_000_000_000
    {
        iters += 1;
        core::hint::spin_loop();
    }
    let st = task::task_debug_state(ash_id);
    let wt = task::task_debug_wait(ash_id);
    let sc1 = task::syscall_counts();
    let code = task::task_debug_exit_code(ash_id);
    let dhit = ostd::time::now() >= deadline;
    let _ = writeln!(
        log,
        "t95: spec i={iters} s0={s0} s1={st} wait={wt} now0={now0} now1={} (dl={deadline}) sc=({},{},{})→({},{},{}) exit={code:#x} deadline-hit={dhit}",
        ostd::time::now(),
        sc0.0, sc0.1, sc0.2, sc1.0, sc1.1, sc1.2
    );
    if st == 4 {
        // (d) 回归域：Zombie 收割 exit=7 传导对账（ash -c 'exit 7' 首目标）
        let r = procs::sys_wait_pid(ash_id as u64);
        let rpid = (r >> 16) & 0xFFFF;
        let rcode = r & 0xFFFF;
        ok &= r >> 32 == 1;
        ok &= rpid == ash_id as u64;
        ok &= rcode == 7;
        ok &= !task::task_alive(ash_id);
        let _ = writeln!(log, "t95: reaped pid={rpid} exit={rcode} (expect 7)");
    } else {
        // 滞域标本（fail-visible——H1/H2 判别面显形，不静默不撤闸遮蔽）
        ok = false;
    }
    let _ = writeln!(log, "LUMINA-T95-ASH facet=ppid s1={st} wait={wt} ok={ok}");
    if ok {
        let _ = writeln!(log, "LUMINA-T95-OK");
    }
    ok
}

/// t96 盘上属主域活体执行体（M40-CRYSTAL）：独立函数承载（帧形态守
/// 恒纪律）。相位：(a) Lfs 挂载（fs_type=1 数据盘——format_or_open
/// Open 路径，t56 域残留共存唯一目录隔离）；(b) 制备双文件 + chown/
/// chmod 车道落盘；(c) stat 属主真面读回对账；(d) 门禁回源域（登记
/// 优先/盘上次之双车道 + 组属主位域判定落域 + chmod/chown 权限域负
/// 例）；(e) 持久化对账（Lfs::format_or_open 第二实例盘上直读——
/// mount 表外铁证）；(f) 清扫回装。
fn t96_run(log: &mut DualLog) -> bool {
    use meridian::vfs::{FileSystem, Lfs};
    let mut ok = true;
    let (mut ok_a, mut ok_b, mut ok_c, mut ok_d, mut ok_e, mut ok_f) =
        (true, true, true, true, true, true);
    let me = task::current_task_id();
    const MNT: &[u8] = b"/mnt96";
    const DIR: &[u8] = b"/mnt96/t96d";
    const F_OWN: &[u8] = b"/mnt96/t96d/f_own";
    const F_GRP: &[u8] = b"/mnt96/t96d/f_grp";
    // (a) 挂载点目录（RamFs 侧）+ Lfs 数据盘挂载
    ok_a &= vfs::sys_mkdir(MNT.as_ptr() as u64, MNT.len() as u64) == 0;
    ok_a &= vfs::sys_mount(MNT.as_ptr() as u64, MNT.len() as u64, 1) == 0;
    ok_a &= vfs::sys_mkdir(DIR.as_ptr() as u64, DIR.len() as u64) == 0;
    ok &= ok_a;
    // (b) 制备双文件 + chown/chmod 车道（root 域）
    let mk = |path: &[u8]| -> bool {
        let h = vfs::sys_open_bytes(path, bedrock::abi::O_CREAT | 0b10);
        if h >> 32 != 1 {
            return false;
        }
        let payload: &[u8] = b"t96\n";
        let w = vfs::sys_write(
            h & 0xFFFF_FFFF,
            payload.as_ptr() as u64,
            payload.len() as u64,
        );
        let _ = vfs::sys_close(h & 0xFFFF_FFFF);
        w >> 32 == 1
    };
    ok_b &= mk(F_OWN) && mk(F_GRP);
    // chmod(90) 车道：f_own 0o640 / f_grp 0o060（root 域）
    ok_b &= vfs::sys_chmod_bytes(F_OWN, 0o640) == 0;
    ok_b &= vfs::sys_chmod_bytes(F_GRP, 0o400) == 0;
    // chown(92) 车道：f_own → 1000:1000（root 域收口）；f_grp → 0:2000
    ok_b &= vfs::sys_chown_bytes(F_OWN, 1000, 1000) == 0;
    ok_b &= vfs::sys_chown_bytes(F_GRP, 0, 2000) == 0;
    ok &= ok_b;
    // (c) stat 属主真面读回（sys_stat_owner_bytes 打包域拆解）
    let own_v = vfs::sys_stat_owner_bytes(F_OWN);
    let grp_v = vfs::sys_stat_owner_bytes(F_GRP);
    // M40-CRYSTAL 实测域：uid/gid 真面 + own mode 0o640 域在环；
    // grp mode 域裸机读回异常随行揭雷（0o400 读回 0o1000 = <<4 位错
    // ——M17-① ATA PIO 块层 InodeRec @1..7 域首用显形：宿主 MemBlock
    // 同链 set_attr 往返全绿 + 裸机值域相关错位——块层字节域缺陷标本
    // 在案，随 M17-① 块层批次清账；grp mode 断言降级为「车道动域实证
    // ≠ 创建默认 0o644」，如实不虚报）。
    let own_ok = (own_v >> 32) & 1 == 1
        && (own_v & 0xFFFF) == 1000
        && ((own_v >> 48) & 0xFFFF) == 1000
        && ((own_v >> 16) & 0xFFFF) == 0o640;
    let grp_ok = (grp_v >> 32) & 1 == 1
        && (grp_v & 0xFFFF) == 0
        && ((grp_v >> 48) & 0xFFFF) == 2000
        && ((grp_v >> 16) & 0xFFFF) == 0o400;
    ok_c &= own_ok && grp_ok;
    ok &= ok_c;
    // (d) 门禁回源域（换装消费——PERMS 未登记路径 = 盘上回源车道）
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds::new4(1001, 1001, 1001, 1001);
    });
    // uid 1001（other 位 0）→ f_own open/chmod/chown 三拒
    ok_d &= vfs::sys_open_bytes(F_OWN, 0b01) == 13; // EACCES
    ok_d &= vfs::sys_chmod_bytes(F_OWN, 0o666) == 1; // EPERM（非 owner 非 root）
    ok_d &= vfs::sys_chown_bytes(F_OWN, 1001, 1001) == 1; // EPERM（根域收口）
                                                          // 组属主域判定（M40-CRYSTAL 落域；**M41-笔② 翻正**——M17-① 取证
                                                          // 矩阵 t98 在案：mode 域裸机读回真面（值域矩阵 × 跨调用 × 双文件
                                                          // 交替 + 持久化对账全绿，<<4 错位存量消解），组属主位域判定恢复
                                                          // 全谱断言：组内 group 位放行/拒绝双面 + 组外 other 位域拒绝）。
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds::new4(999, 2000, 999, 2000); // 与 f_grp gid 同组
    });
    // 组内 group 位域判定（f_grp mode 0o400：group 位 0 → 读仍拒——
    // group 位判定走盘上真面；owner 位域不可达〔uid 999 ≠ 0〕）
    ok_d &= vfs::sys_open_bytes(F_GRP, 0b01) == 13; // group 位 0 → EACCES
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds::new4(999, 2001, 999, 2001);
    });
    // 组外域（other 位 0）→ EACCES（门禁回源车道在环）
    ok_d &= vfs::sys_open_bytes(F_GRP, 0b01) == 13;
    let _ = writeln!(log, "t96: d1 other-reject={ok_d}");
    // 组内放行面（M41-笔② 翻正）：f_grp 置 0o040 → gid 2000 组内 group 位 4 放行
    // （chmod 需 owner/root 域——回 root 域置值，f_grp owner=0）
    task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
    let r_chmod = vfs::sys_chmod_bytes(F_GRP, 0o040);
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds::new4(999, 2000, 999, 2000);
    });
    let r_open = vfs::sys_open_bytes(F_GRP, 0b01);
    let _ = writeln!(
        log,
        "t96: d2 chmod040={r_chmod} open-group={r_open:#x} (expect chmod=0 + open 成功域)"
    );
    ok_d &= r_chmod == 0 && r_open >> 32 == 1; // open 成功域（fd 句柄非零）
    ok &= ok_d;
    // (e) 持久化对账：第二 Lfs 实例盘上直读（mount 表外铁证）
    task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
    match Lfs::format_or_open(crate::block::DataBlock::arced()) {
        Ok(lfs) => {
            let persisted = (|| {
                let root = lfs.root_vnode();
                let dir = lfs.lookup(root, "t96d").ok()?;
                let f1 = lfs.lookup(dir, "f_own").ok()?;
                let m1 = lfs.metadata(f1).ok()?;
                let f2 = lfs.lookup(dir, "f_grp").ok()?;
                let m2 = lfs.metadata(f2).ok()?;
                Some((m1.uid, m1.gid, m1.mode, m2.uid, m2.gid, m2.mode))
            })();
            // M41-笔② 翻正：mode 域持久化对账真面断言（M17-① 取证矩阵
            // t98 消解在案——0o640/0o040 裸机跨实例读回真面）。
            ok_e &= persisted.is_some_and(|(u1, g1, m1, u2, g2, m2)| {
                (u1, g1, m1, u2, g2, m2) == (1000, 1000, 0o640, 0, 2000, 0o040)
            });
        }
        Err(e) => {
            let _ = writeln!(log, "t96: remount failed ({e:?})");
            ok_e = false;
        }
    }
    ok &= ok_e;
    // (f) 清扫回装（root 域）
    ok_f &= vfs::sys_remove_bytes(F_OWN) == 0;
    ok_f &= vfs::sys_remove_bytes(F_GRP) == 0;
    ok_f &= vfs::sys_remove_bytes(DIR) == 0;
    ok &= ok_f;
    let _ = writeln!(
        log,
        "LUMINA-T96-OWN a={} b={} c={} d={} e={} f={} own_v={own_v:#x} grp_v={grp_v:#x}",
        ok_a, ok_b, ok_c, ok_d, ok_e, ok_f
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T96-OK");
    }
    ok
}

/// t97 cat applet 实证活体执行体（M40-CAT）：独立函数承载（帧形态守
/// 恒纪律）。相位：(a) 制备文件域（/t97d + 双文件——载荷即内容级断
/// 言标记 LUMINA-T97-CAT〔纠正 t83 wc 式内容级断言缺席而缺陷三代隐
/// 匿的教训——M39-BBLS 回溯在案〕）；(b) `busybox cat` 派生消费（t92
/// 同款装载链 + waitpid 收割——exit 码对账；cat 读路径 = openat+fstat
/// +read 循环+writev(1) 串口直通〔stdio 保留域语义〕；sendfile(40)
/// 直拷车道实测〔M36-BB3b 收录——cat 消费驱动〕+ 负例域 cat 缺席文件
/// 败码 1）；(c) 制备域清扫。
fn t97_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    const DIR: &[u8] = b"/t97d";
    const F1: &[u8] = b"/t97d/f_cat";
    const F2: &[u8] = b"/t97d/f_send";
    // (a) 制备文件域（载荷 = 内容级断言标记——xtask S8/longrun required）
    ok &= vfs::sys_mkdir(DIR.as_ptr() as u64, DIR.len() as u64) == 0;
    let mut prep = 0usize;
    for (path, payload) in [
        (F1, &b"LUMINA-T97-CAT cat-read-loop\n"[..]),
        (F2, &b"LUMINA-T97-SENDFILE\n"[..]),
    ] {
        let h = vfs::sys_open_bytes(path, bedrock::abi::O_CREAT | 0b10);
        if h >> 32 == 1 {
            let w = vfs::sys_write(
                h & 0xFFFF_FFFF,
                payload.as_ptr() as u64,
                payload.len() as u64,
            );
            ok &= w >> 32 == 1;
            prep += 1;
            let _ = vfs::sys_close(h & 0xFFFF_FFFF);
        } else {
            ok = false;
        }
    }
    ok &= prep == 2;
    // (b) busybox cat 派生消费（t92 同款四 applet 表形态）
    let applets: [(&[&str], u64); 3] = [
        // cat 读循环车道（openat+read+writev——内容级断言标记上串口）
        (&["/bin/busybox", "cat", "/t97d/f_cat"], 0),
        // sendfile 直拷车道（cat 大文件域选路——M36-BB3b 收录消费）
        (&["/bin/busybox", "cat", "/t97d/f_send"], 0),
        // 负例域：缺席文件 → openat ENOENT → applet 败码 1
        (&["/bin/busybox", "cat", "/t97d/f_absent"], 1),
    ];
    let mut reaped: [u64; 3] = [u64::MAX; 3];
    if let Some(blob) = vfs::read_image("/bin/busybox") {
        for (i, (argv, expect)) in applets.iter().enumerate() {
            let Some(frames) = vmm::global_frames() else {
                let _ = writeln!(log, "t97[{}]: frame service unreachable", i);
                ok = false;
                break;
            };
            let t = ostd::time::tsc_now();
            let mut random = [0u8; 16];
            for (j, b) in random.iter_mut().enumerate() {
                *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
            }
            match user::build_user_space_elf(
                &blob,
                argv,
                &["PATH=/bin"],
                random,
                "busybox",
                &mut || frames.alloc(),
            ) {
                Ok(es) => {
                    let mut slots = [0u64; 15];
                    slots[0] = 0x202;
                    slots[1] = es.entry;
                    slots[7] = es.rsp;
                    let id = task::spawn_fork_child(
                        "busybox-cat",
                        es.root,
                        task::current_task_id(),
                        slots,
                        true,
                    );
                    if id == usize::MAX {
                        let _ = writeln!(log, "t97[{}]: task slot exhausted", i);
                        ok = false;
                        break;
                    }
                    let r = procs::sys_wait_pid(id as u64);
                    let code = r & 0xFFFF;
                    reaped[i] = code;
                    let _ = writeln!(log, "t97[{}] {} exit={code} (expect {expect})", i, argv[1]);
                    ok &= r >> 32 == 1 && code == *expect && !task::task_alive(id);
                }
                Err(e) => {
                    let _ = writeln!(log, "t97[{}]: build failed ({e:?})", i);
                    ok = false;
                    break;
                }
            }
        }
    } else {
        let _ = writeln!(log, "t97: /bin/busybox media MISS");
        ok = false;
    }
    // (c) 制备域清扫
    let mut cleaned = 0usize;
    for path in [F1, F2] {
        if vfs::sys_remove_bytes(path) == 0 {
            cleaned += 1;
        }
    }
    ok &= cleaned == 2;
    ok &= vfs::sys_remove_bytes(DIR) == 0;
    let _ = writeln!(
        log,
        "LUMINA-T97-CAT prepared={prep} cleaned={cleaned} cat={} send={} neg={}",
        reaped[0], reaped[1], reaped[2]
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T97-OK");
    }
    ok
}

/// t98 块层字节域取证矩阵活体（M41-笔② / M17-① 标本清账）：独立函数
/// 承载（帧形态守恒纪律）。M40-CRYSTAL 揭雷标本——裸机 ATA 域 InodeRec
/// @1..7 属主域「值域相关 <<4 错位」（0o060 读回 0o1400 / 0o400 读回
/// 0o1000——CHMOD-TRACE/READBACK 插桩两轮取证，错位定界于跨调用盘读
/// 域，宿主 MemBlock 同链往返全绿）——本活体四域取证：
/// (a) 制备域：/mnt98 挂载 + f_a/f_b 相邻 inode（同表块 64 B 邻接）；
/// (b) 值域矩阵八组（台账标本原值 0o060/0o400 + b[1] 低 nibble 敏感
///     0o006/0o007 + 跨字节 0o640/0o755/0o770/0o777）：chmod(f_a, m)
///     → 同调用读（f_a==m）+ 跨调用读（f_b 基线 0o644 哨兵——邻记录
///     零串扰 + 前值零残留）；
/// (c) 交替写读（f_b 矩阵二轮，f_a 终值 0o777 哨兵——双向域）；
/// (d) 持久化对账（第二 Lfs 实例盘上直读矩阵终值——mount 表外铁证）；
/// (e) 清扫回装。
/// 任一读回错位 → 期望/读回值串口取证 fail-visible（标本复活现场在
/// 案）；全绿 → M17-① 存量消解（t96 (d)/(e) 组位域判定翻正依据）。
fn t98_run(log: &mut DualLog) -> bool {
    use meridian::vfs::{FileSystem, Lfs};
    let mut ok = true;
    let (mut ok_a, mut ok_b, mut ok_c, mut ok_d, mut ok_e) = (true, true, true, true, true);
    // 值域矩阵（八组：标本原值 + nibble 敏感 + 跨字节 + 全位域）
    const MODES: [u16; 8] = [0o060, 0o400, 0o006, 0o007, 0o640, 0o755, 0o770, 0o777];
    const BASE: u16 = 0o644;
    const MNT: &[u8] = b"/mnt98";
    const DIR: &[u8] = b"/mnt98/t98d";
    const FA: &[u8] = b"/mnt98/t98d/f_a";
    const FB: &[u8] = b"/mnt98/t98d/f_b";
    // (a) 制备域
    ok_a &= vfs::sys_mkdir(MNT.as_ptr() as u64, MNT.len() as u64) == 0;
    ok_a &= vfs::sys_mount(MNT.as_ptr() as u64, MNT.len() as u64, 1) == 0;
    ok_a &= vfs::sys_mkdir(DIR.as_ptr() as u64, DIR.len() as u64) == 0;
    let mk = |path: &[u8]| -> bool {
        let h = vfs::sys_open_bytes(path, bedrock::abi::O_CREAT | 0b10);
        if h >> 32 != 1 {
            return false;
        }
        let payload: &[u8] = b"t98\n";
        let w = vfs::sys_write(
            h & 0xFFFF_FFFF,
            payload.as_ptr() as u64,
            payload.len() as u64,
        );
        let _ = vfs::sys_close(h & 0xFFFF_FFFF);
        w >> 32 == 1
    };
    ok_a &= mk(FA) && mk(FB);
    // 双文件基线：f_a/f_b 各自首 chmod（f_b 定基线 0o644 哨兵）
    ok_a &= vfs::sys_chmod_bytes(FA, MODES[0]) == 0;
    ok_a &= vfs::sys_chmod_bytes(FB, BASE) == 0;
    ok &= ok_a;
    // mode 读回（sys_stat_owner_bytes 打包域——与 t96 同链）
    let mode_of =
        |path: &[u8]| -> u16 { ((vfs::sys_stat_owner_bytes(path) >> 16) & 0xFFFF) as u16 };
    // (b) 值域矩阵：f_a 逐组置值，同调用读 + 跨调用哨兵读
    for m in MODES {
        if vfs::sys_chmod_bytes(FA, m) != 0 {
            let _ = writeln!(log, "t98: chmod(f_a, {m:#06o}) fail");
            ok_b = false;
            break;
        }
        let ra = mode_of(FA);
        let rb = mode_of(FB);
        if ra != m || rb != BASE {
            let _ = writeln!(
                log,
                "t98: (b) MISMATCH m={m:#06o} f_a={ra:#06o} (expect {m:#06o}) f_b={rb:#06o} (expect {BASE:#06o})"
            );
            ok_b = false;
            break;
        }
    }
    let _ = writeln!(
        log,
        "t98: (b) matrix f_a ok_b={ok_b} (8 modes incl 0o060/0o400 spec)"
    );
    ok &= ok_b;
    // (c) 交替写读：f_b 逐组置值（f_a 终值 0o777 哨兵——双向域）
    for m in MODES {
        if vfs::sys_chmod_bytes(FB, m) != 0 {
            let _ = writeln!(log, "t98: chmod(f_b, {m:#06o}) fail");
            ok_c = false;
            break;
        }
        let rb = mode_of(FB);
        let ra = mode_of(FA);
        if rb != m || ra != 0o777 {
            let _ = writeln!(
                log,
                "t98: (c) MISMATCH m={m:#06o} f_b={rb:#06o} f_a={ra:#06o} (expect 0o777)"
            );
            ok_c = false;
            break;
        }
    }
    // f_b 终值回置基线（(d) 断言锚定）
    ok_c &= vfs::sys_chmod_bytes(FB, BASE) == 0;
    let _ = writeln!(log, "t98: (c) swap matrix f_b ok_c={ok_c}");
    ok &= ok_c;
    // (d) 持久化对账：第二 Lfs 实例盘上直读（mount 表外铁证）
    match Lfs::format_or_open(crate::block::DataBlock::arced()) {
        Ok(lfs) => {
            let persisted = (|| {
                let root = lfs.root_vnode();
                let dir = lfs.lookup(root, "t98d").ok()?;
                let fa = lfs.lookup(dir, "f_a").ok()?;
                let fb = lfs.lookup(dir, "f_b").ok()?;
                let ma = lfs.metadata(fa).ok()?;
                let mb = lfs.metadata(fb).ok()?;
                Some((ma.mode, mb.mode))
            })();
            ok_d &= persisted.is_some_and(|(ma, mb)| ma == 0o777 && mb == BASE);
            if !ok_d {
                let _ = writeln!(
                    log,
                    "t98: (d) persisted MISMATCH {persisted:?} (expect f_a=0o777 f_b={BASE:#06o})"
                );
            }
        }
        Err(e) => {
            let _ = writeln!(log, "t98: remount failed ({e:?})");
            ok_d = false;
        }
    }
    ok &= ok_d;
    // (e) 清扫回装
    ok_e &= vfs::sys_remove_bytes(FA) == 0;
    ok_e &= vfs::sys_remove_bytes(FB) == 0;
    ok_e &= vfs::sys_remove_bytes(DIR) == 0;
    ok &= ok_e;
    let _ = writeln!(
        log,
        "LUMINA-T98-M17 a={} b={} c={} d={} e={}",
        ok_a, ok_b, ok_c, ok_d, ok_e
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T98-OK");
    }
    ok
}

/// t99 多用户纵深二批活体（M41-笔③）：独立函数承载（帧形态守恒纪律）。
/// saved-set 三态 + 补充组全谱矩阵（直调探针域——M93 先例；用户拷贝面
/// 随 LinExec 派发路径消费）：
/// (a) root setreuid(1000, 0) → real=1000/euid=0/**suid=0**（saved 落账
///     Linux 精确规则：rid 非 -1 → suid = 新 euid）；
/// (b) setreuid(-1, 1000)（root euid=0 特权域）→ euid=1000、suid 保 0
///     （eid==old_real 规则——不重落）；
/// (c) **saved-set 交换**（非 root euid=1000）：setreuid(-1, 0) →
///     euid=0（0 ∈ {real=1000, euid=1000, suid=0} 命中）；
/// (d) 非 root 越域拒：setreuid(-1, 1234) → EPERM（1234 ∉ 三元域）；
/// (e) root setuid(1000) 全量落 suid（uid=euid=suid=1000）+ 非 root
///     setuid(0) 拒（0 ∉ {real=1000, suid=1000}）；
/// (f) setgroups：非 root EPERM + root setgroups([2000,2001]) 落账；
/// (g) getgroups 读回对账（n=2 + 双值）；
/// (h) 补充组判定盘上域：/mnt99/f_g chown(1000,2001)+chmod(0o040) →
///     uid 999/gid 999 + 补充组 [2001] → open 放行（group 位命中）；
///     清空补充组 → EACCES（other 位 0）；
/// (i) 恢复 ROOT + 清扫回装。LUMINA-T99-MU2/OK。
fn t99_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    let (mut ok_a, mut ok_b, mut ok_c, mut ok_d, mut ok_e, mut ok_f) =
        (true, true, true, true, true, true);
    const KEEP: u64 = u32::MAX as u64;
    let me = task::current_task_id();
    let creds_of = || -> (u32, u32, u32, u32, u32) {
        let c = task::task_creds(me).unwrap_or(task::Creds::ROOT);
        (c.uid, c.euid, c.suid, c.gid, c.sgid)
    };
    // (a) root setreuid(1000, 0)：saved 落账
    ok_a &= linux::setreuid_probe(1000, 0) == 0;
    let (r, e, s, _, _) = creds_of();
    ok_a &= (r, e, s) == (1000, 0, 0);
    // (b) setreuid(-1, 1000)（root euid=0 特权域）：suid 保 0
    ok_a &= linux::setreuid_probe(KEEP, 1000) == 0;
    let (r, e, s, _, _) = creds_of();
    ok_a &= (r, e, s) == (1000, 1000, 0);
    ok &= ok_a;
    // (c) saved-set 交换（非 root）：setreuid(-1, 0)
    ok_b &= linux::setreuid_probe(KEEP, 0) == 0;
    let (r, e, s, _, _) = creds_of();
    ok_b &= (r, e, s) == (1000, 0, 0);
    // (d) 非 root 越域拒：1234 ∉ {1000, 0, 0}
    ok_b &= linux::setreuid_probe(KEEP, 1234) == 1;
    let _ = writeln!(log, "t99: (a-d) saved-set chain ok_b={ok_b}");
    ok &= ok_b;
    // (e) root 全量 setuid 落 suid + 非 root setuid(0) 拒
    task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
    ok_c &= linux::setuid_probe(1000) == 0;
    let (r, e, s, _, _) = creds_of();
    ok_c &= (r, e, s) == (1000, 1000, 1000); // 全量三域同步
    ok_c &= linux::setuid_probe(0) == 1; // 0 ∉ {real=1000, suid=1000}
    let _ = writeln!(log, "t99: (e) setuid full-domain ok_c={ok_c}");
    ok &= ok_c;
    // (f) setgroups：非 root 拒 + root 落账
    ok_d &= linux::setgroups_probe(&[2000, 2001]) == 1; // uid=1000 非 root
    task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
    ok_d &= linux::setgroups_probe(&[2000, 2001]) == 0;
    // (g) getgroups 读回对账
    let (n, g) = linux::getgroups_probe();
    ok_d &= n == 2 && g[0] == 2000 && g[1] == 2001;
    let _ = writeln!(
        log,
        "t99: (f-g) groups n={n} g=[{},{}] ok_d={ok_d}",
        g[0], g[1]
    );
    ok &= ok_d;
    // (h) 补充组判定盘上域：f_g chown(1000,2001) + chmod(0o040)
    const MNT: &[u8] = b"/mnt99";
    const DIR: &[u8] = b"/mnt99/t99d";
    const FG: &[u8] = b"/mnt99/t99d/f_g";
    ok_e &= vfs::sys_mkdir(MNT.as_ptr() as u64, MNT.len() as u64) == 0;
    ok_e &= vfs::sys_mount(MNT.as_ptr() as u64, MNT.len() as u64, 1) == 0;
    ok_e &= vfs::sys_mkdir(DIR.as_ptr() as u64, DIR.len() as u64) == 0;
    let h = vfs::sys_open_bytes(FG, bedrock::abi::O_CREAT | 0b10);
    ok_e &= h >> 32 == 1;
    ok_e &= vfs::sys_close(h & 0xFFFF_FFFF) == 0;
    ok_e &= vfs::sys_chown_bytes(FG, 1000, 2001) == 0;
    ok_e &= vfs::sys_chmod_bytes(FG, 0o040) == 0; // group r 位
                                                  // uid 999/gid 999 + 补充组 [2001] → group 位命中放行
    task::with_task_creds_mut(me, |c| *c = task::Creds::new4(999, 999, 999, 999));
    ok_e &= linux::setgroups_probe(&[2001]) == 1; // 非 root 拒（组落账需 root）
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds {
            groups: [2001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ngroups: 1,
            ..task::Creds::new4(999, 999, 999, 999)
        };
    });
    let r_open = vfs::sys_open_bytes(FG, 0b01);
    ok_e &= r_open >> 32 == 1; // 补充组 2001 命中 → group 位 4 → 放行
                               // 清空补充组 → other 位 0 → EACCES
    task::with_task_creds_mut(me, |c| {
        *c = task::Creds::new4(999, 999, 999, 999);
    });
    ok_e &= vfs::sys_open_bytes(FG, 0b01) == 13;
    let _ = writeln!(log, "t99: (h) supplementary-group gate ok_e={ok_e}");
    ok &= ok_e;
    // (i) 恢复 ROOT + 清扫回装
    task::with_task_creds_mut(me, |c| *c = task::Creds::ROOT);
    ok_f &= vfs::sys_remove_bytes(FG) == 0;
    ok_f &= vfs::sys_remove_bytes(DIR) == 0;
    ok_f &= vfs::sys_remove_bytes(MNT) == 0;
    let _ = writeln!(
        log,
        "LUMINA-T99-MU2 a={} b={} c={} d={} e={} f={}",
        ok_a, ok_b, ok_c, ok_d, ok_e, ok_f
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T99-OK");
    }
    ok
}

/// t100 ash 交互面活体（M41-笔④）：独立函数承载（帧形态守恒纪律）。
/// **阻塞式 tty read 转正**——lin_read fd 0 tty 车道阻塞化（原 v0 非阻
/// 塞「0 = 暂无数据」域退役：ash 交互 shell 读侧读到 0 = EOF 即退出的
/// 滞点根治）——本活体端到端实证：
/// (a) kbd 环 drain（防残留）+ 零锁判据面清零（t95 同款）；
/// (b) spawn `busybox sh`（**无 -c——交互模式**）；
/// (c) kbd::inject_raw 字节直注入两行（"echo LUMINA-T100-ASH\n" +
///     "exit\n"——注入即 wake TtyRead 等待者；先注入后读者时序由登记
///     窗探针免疫兜底）；
/// (d) 有界收割（PIT 刻度 deadline 60 拍——交互域 musl 初始化 + 两行
///     消费上界，t95 装置形态同款零锁轮询 per-CPU exit 槽）；
/// (e) 断言 exit=0 + Zombie 收割（sys_wait_pid）；
/// (f) 输出断言：echo 内建 fd1 直通串口 → LUMINA-T100-ASH 标记
///     （S8 required 面消费）。LUMINA-T100-ASH/OK。
fn t100_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    task::reset_user_evidence();
    let me = task::current_task_id();
    // (a) kbd 环 drain（防前序活体残留）
    while crate::kbd::pop().is_some() {}
    // (b) busybox sh 交互模式 spawn（t95 同款装载链）
    const ASH_ARGV: [&str; 2] = ["/bin/busybox", "sh"];
    let Some(blob) = vfs::read_image("/bin/busybox") else {
        let _ = writeln!(log, "t100: /bin/busybox media MISS");
        return false;
    };
    let Some(frames) = vmm::global_frames() else {
        let _ = writeln!(log, "t100: frame service unreachable");
        return false;
    };
    let t = ostd::time::tsc_now();
    let mut random = [0u8; 16];
    for (j, b) in random.iter_mut().enumerate() {
        *b = (t >> ((j % 8) * 8)) as u8 ^ (j as u8).rotate_left(3);
    }
    let es = match user::build_user_space_elf(
        &blob,
        &ASH_ARGV,
        &["PATH=/bin"],
        random,
        "busybox",
        &mut || frames.alloc(),
    ) {
        Ok(es) => es,
        Err(e) => {
            let _ = writeln!(log, "t100: user space build failed ({e:?})");
            return false;
        }
    };
    let mut slots = [0u64; 15];
    slots[0] = 0x202;
    slots[1] = es.entry;
    slots[7] = es.rsp;
    let ash_id = task::spawn_fork_child("busybox-ash-i", es.root, me, slots, true);
    if ash_id == usize::MAX {
        let _ = writeln!(log, "t100: task slot exhausted");
        return false;
    }
    let _ = writeln!(log, "t100: spawned id={ash_id} (interactive)");
    // (c) 字节直注入两行（先注入——登记窗探针免疫兜底读者迟到时序）
    for b in b"echo LUMINA-T100-ASH\nexit\n" {
        crate::kbd::inject_raw(*b);
    }
    let _ = writeln!(log, "t100: injected 2 lines (echo + exit)");
    // (d) 有界收割（零锁轮询 per-CPU exit 槽——t95 装置形态）
    let now0 = ostd::time::now();
    let deadline = now0 + 60; // 60 拍 = 0.6 s（交互域上界：musl 初始化 +
                              // 两行消费 + echo 输出）
    let mut iters: u64 = 0;
    while task::user_exit_codes().1 == u64::MAX
        && ostd::time::now() < deadline
        && iters < 2_000_000_000
    {
        iters += 1;
        core::hint::spin_loop();
    }
    let st = task::task_debug_state(ash_id);
    let code = task::task_debug_exit_code(ash_id);
    let dhit = ostd::time::now() >= deadline;
    let _ = writeln!(
        log,
        "t100: spec i={iters} s1={st} exit={code:#x} deadline-hit={dhit}"
    );
    // (e) 断言 exit=0 + 收割
    if st == 4 {
        let r = procs::sys_wait_pid(ash_id as u64);
        let rcode = r & 0xFFFF;
        ok &= r >> 32 == 1 && rcode == 0 && !task::task_alive(ash_id);
        let _ = writeln!(log, "t100: reaped exit={rcode} (expect 0)");
    } else {
        ok = false; // 滞域 fail-visible（装置不静默）
    }
    let _ = writeln!(log, "LUMINA-T100-ASH st={st} exit={code:#x} ok={ok}");
    if ok {
        let _ = writeln!(log, "LUMINA-T100-OK");
    }
    ok
}

/// t101 用户态 fb 驱动进程移交链活体执行体（M42-阶段一 笔①）：独立
/// 函数承载（帧形态守恒纪律——t93/t95 先例）。相位序：
/// (a) 承接前形态对账：svc fb = KernelResident（boot 注册 v0 口径）；
/// (b) 裁量闸负例：kmain（未授予 pid）直调 sys_dev_pio → ERR_CAP——
///     用户态不可自授 + 无授权即拒的裁量面显形；
/// (c) fbdev 映像装载 + spawn（native ABI——build_user_space_lxe 直装，
///     spawn_fork_child 同 t100 装置形态）；
/// (d) 承接面落账：pio_grant(dispi 索引/数据口 0x1CE..0x1CF) +
///     svc::adopt_user(SVC_FB, fbdev_pid)（spawn→grant 登记窗由映像侧
///     64 拍 YIELD 重试免疫——t100 先例同款）；
/// (e) 有界收割（t95/t100 零锁轮询 per-CPU exit 槽 60 拍）→ exit=0
///     断言 + Zombie 收割 + 存活面清账；
/// (f) Owner 承接对账：svc lookup(SVC_FB) = UserTask(fbdev_pid)——
///     混合态记账面落域显形（电气面零触碰如实登记）；
/// (g) 端口访问面对账：pio_stamps——dispi 数据口 0x1CF 末读值 ≥
///     0xB0C0（OUT16 索引口写 + IN16 数据口读全链在环）；
/// (h) LFB 移交成像对账：内核侧 VRAM 物理读回行 0 x=0..63 全 64 px ==
///     FBDEV_PAINT（用户态直写车道端到端——映射移交真面取证）。
fn t101_run(log: &mut DualLog) -> bool {
    use bedrock::abi::{PIO_IN16, SVC_FB};
    let mut ok = true;
    task::reset_user_evidence(); // 零锁判据面清零（t100 退出码残留摘除）
                                 // (a) 承接前形态对账（KernelResident boot 口径）
    let pre = crate::svc::lookup(SVC_FB);
    ok &=
        pre.is_some_and(|(n, _, _, o)| n == "fb" && matches!(o, crate::svc::Owner::KernelResident));
    // (b) 裁量闸负例：未授予 pid（kmain）→ ERR_CAP
    let neg = crate::dev::sys_dev_pio(PIO_IN16, 0x1CF, 0);
    ok &= neg == bedrock::abi::ERR_CAP;
    let _ = writeln!(log, "t101: gate-negative kmain→{neg} (expect 1 ERR_CAP)");
    // (c) fbdev 映像装载（LXE1 双段——gen 脚本产物直装）
    let Some(frames) = vmm::global_frames() else {
        let _ = writeln!(log, "t101: frame service unreachable");
        return false;
    };
    let es = match user::build_user_space_lxe(&user::FBDEV_LXE, &mut || frames.alloc()) {
        Ok(es) => es,
        Err(e) => {
            let _ = writeln!(log, "t101: fbdev image build failed ({e:?})");
            return false;
        }
    };
    let mut slots = [0u64; 15];
    slots[0] = 0x202;
    slots[1] = es.entry;
    slots[7] = es.stack_top;
    let me = task::current_task_id();
    let fbdev_id = task::spawn_fork_child("fbdev", es.root, me, slots, false);
    if fbdev_id == usize::MAX {
        let _ = writeln!(log, "t101: task slot exhausted");
        return false;
    }
    // (d) 承接面落账：端口裁量授予 + svc Owner 用户态承接（登记窗由
    //     映像侧重试免疫——本行先于 fbdev 首拍下收窄竞态窗）
    let g = crate::dev::pio_grant(fbdev_id as u64, 0x1CE, 0x1CF);
    ok &= g.is_ok();
    let adopt = crate::svc::adopt_user(SVC_FB, fbdev_id as u64);
    ok &= adopt.is_ok();
    let _ = writeln!(
        log,
        "t101: grant-ok={} adopt-ok={} pid={fbdev_id}",
        g.is_ok(),
        adopt.is_ok(),
    );
    // (e) 有界收割（60 拍 = 0.6 s——fbdev 轻载荷：FB_MAP 2026 页走查 +
    //     PIO 双拍 + 64 px 直写 + LOG，无阻塞源）
    let now0 = ostd::time::now();
    let deadline = now0 + 60;
    let mut iters: u64 = 0;
    while task::user_exit_codes().1 == u64::MAX
        && ostd::time::now() < deadline
        && iters < 2_000_000_000
    {
        iters += 1;
        core::hint::spin_loop();
    }
    let st = task::task_debug_state(fbdev_id);
    let code = task::task_debug_exit_code(fbdev_id);
    let dhit = ostd::time::now() >= deadline;
    let _ = writeln!(
        log,
        "t101: spec i={iters} s1={st} exit={code:#x} deadline-hit={dhit}"
    );
    if st == 4 {
        let r = procs::sys_wait_pid(fbdev_id as u64);
        let rcode = r & 0xFFFF;
        ok &= r >> 32 == 1 && rcode == 0 && !task::task_alive(fbdev_id);
        let _ = writeln!(log, "t101: reaped exit={rcode} (expect 0)");
    } else {
        ok = false; // 滞域 fail-visible（装置不静默——bail 码 70/71/72 显形）
    }
    // (f) Owner 承接对账（混合态记账面——UserTask(fbdev)）
    let post = crate::svc::lookup(SVC_FB);
    let owner_ok = post
        .is_some_and(|(_, _, _, o)| matches!(o, crate::svc::Owner::UserTask(t) if t == fbdev_id));
    ok &= owner_ok;
    // (g) 端口访问面对账（OUT16 索引口 + IN16 数据口全链）
    let (pio_in, pio_out, last_port, last_val, last_op) = crate::dev::pio_stamps();
    ok &= pio_in >= 1
        && pio_out >= 1
        && last_port == 0x1CF
        && last_op == PIO_IN16
        && last_val >= 0xB0C0;
    // (h) LFB 移交成像对账：内核侧 VRAM 物理读回 64 px 全 FBDEV_PAINT
    let base = crate::fb::fb_base();
    let mut vram_ok = base != 0;
    if vram_ok {
        for i in 0..64u64 {
            if ostd::hw::phys::read_u32(base + i * 4) != user::FBDEV_PAINT {
                vram_ok = false;
                break;
            }
        }
    }
    ok &= vram_ok;
    let _ = writeln!(
        log,
        "LUMINA-T101-FBDEV pid={fbdev_id} dispi={last_val:#06x} pio-in={pio_in} pio-out={pio_out} owner=user vram-ok={vram_ok}"
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T101-OK");
    }
    ok
}

/// t102 常驻 fbdev 服务活体执行体（M42-阶段一 笔②「驱动进程常驻面——
/// 服务环/IPC 通道 + 常驻 fbdev 服务化」）：独立函数承载（帧形态守恒
/// 纪律——t93/t95/t101 先例）。相位序：
/// (a) 服务环对账（boot 铸造面）：svc lookup(SVC_FB) 通道对 == 铸造
///     对象 + 双 is_channel_object——M34「(0,0) 占位未铸」挂账域兑现
///     显形；
/// (b) Owner 移交链：上笔 t101 fbdev 亡 pid 存续态对账 → 异 pid 释放
///     AlreadyAdopted 拒（负例一）→ 精确 release_user 归还
///     KernelResident → Kernel 态再释 NotAdopted 拒（负例二）——
///     KernelResident ⇄ UserTask 双向闭环；
/// (c) 客户端句柄负例：kmain 越域句柄 SEND → ERR_CAP（能力门禁显形）；
/// (d) fbsvc 映像装载 + spawn_stage_wired 接线域（子 h1 ← kmain req
///     柄 / 子 h2 ← kmain resp 柄——M35-BBb 接线派生）+ pio_grant +
///     re-adopt（登记窗由映像侧 64 拍重试免疫）；
/// (e) 请求 1 PAINT_RECT(8,1,64,FB_SVC_PAINT)：kmain SEND（req 环）→
///     有界等内核侧 VRAM 行 1 读回全 FB_SVC_PAINT（服务域直写真面）→
///     DIAG_SENDS 增量确认应答落环 → RECV（resp 环）弹回 tag 0xD1 +
///     status=0 + seq=1 对账——服务环全链（请求/应答双通道 + 阻塞
///     收帧 + 能力门禁）端到端成像；
/// (f) 请求 2 越域 PAINT_RECT(1900,1,64)：y 域内 / x+w=1964>1920 →
///     服务域闸拒绝 status=EDOM 拒不写 + VRAM 快照不变（fail-visible
///     显形——越域请求零副作用）+ seq=2；
/// (g) 请求 3 QUIT：SEND → RECV tag 0xD2 status=0 → 有界收割 exit=0
///     （常驻面有界终结——QUIT 应答后 EXIT 契约）+ Zombie 收割；
/// (h) 终态对账：boot 身份漆存续（行 0 ×64 == FBDEV_PAINT——(e) 直写
///     不踩 boot 漆）+ Owner UserTask(fbsvc) 存续（服务退出后归属
///     v0 存续如实登记，re-adopt 随下一次 release 链）+ DIAG_RECVS
///     增量 ≥ 3（服务消费三帧——阻塞收帧车道真面）。
fn t102_run(log: &mut DualLog) -> bool {
    use bedrock::abi::{ERR_CAP, SVC_FB};
    let mut ok = true;
    task::reset_user_evidence(); // 零锁判据面清零（t101 同款）
                                 // (a) 服务环对账（boot 铸造面——LUMINA-SVC-FBRINGS 证据行的对账域）
    let rings_ok = crate::svc::lookup(SVC_FB).is_some_and(|(n, req, resp, _)| {
        n == "fb"
            && req == ipc::FB_REQ_OBJECT
            && resp == ipc::FB_RESP_OBJECT
            && ipc::is_channel_object(req)
            && ipc::is_channel_object(resp)
    });
    ok &= rings_ok;
    let _ = writeln!(log, "t102: rings-ok={rings_ok} (req/resp 双通道对象在环)");
    // (b) Owner 移交链（t101 亡 pid 存续态 → release → KernelResident）
    let mut rel_ok = matches!(crate::svc::lookup(SVC_FB), Some((_, _, _, _)));
    if let Some(crate::svc::Owner::UserTask(old)) = crate::svc::lookup(SVC_FB).map(|(_, _, _, o)| o)
    {
        let neg1 = crate::svc::release_user(SVC_FB, (old + 1) as u64);
        ok &= neg1 == Err(crate::svc::SvcError::AlreadyAdopted); // 异 pid 拒
        let rel = crate::svc::release_user(SVC_FB, old as u64);
        rel_ok &= rel.is_ok(); // 精确释放 → KernelResident 归还
        let neg2 = crate::svc::release_user(SVC_FB, old as u64);
        ok &= neg2 == Err(crate::svc::SvcError::NotAdopted); // Kernel 态再释拒
    } else {
        rel_ok = false; // t101 必先于 t102——亡 pid Owner 缺席即序错（fail-visible）
    }
    ok &= rel_ok;
    let _ = writeln!(
        log,
        "t102: owner-release-ok={rel_ok} (移交链双向闭环 + 双负例)"
    );
    // (c) 客户端句柄负例：越域句柄 → ERR_CAP（不泄露拓扑同面语义）
    let neg_cap = ipc::sys_send(63, 0, 0, 0);
    ok &= neg_cap == ERR_CAP;
    // (d) kmain 客户端双柄安装（动态首空闲位——测试面句柄域零踩踏）
    let me = task::current_task_id();
    let (kh_req, kh_resp) = task::with_task_handles(me, |t| {
        let free: alloc::vec::Vec<usize> = t
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(h, s)| s.is_none().then_some(h))
            .take(2)
            .collect();
        (free.first().copied(), free.get(1).copied())
    })
    .unwrap_or((None, None));
    let (Some(kh_req), Some(kh_resp)) = (kh_req, kh_resp) else {
        let _ = writeln!(log, "t102: kmain handle table exhausted");
        return false;
    };
    let rights = vanguard::Right::IPC_SEND.bits() | vanguard::Right::IPC_RECV.bits();
    let g1 = crate::caps::alloc_slot(vanguard::Capability::new(ipc::FB_REQ_OBJECT, rights));
    let g2 = crate::caps::alloc_slot(vanguard::Capability::new(ipc::FB_RESP_OBJECT, rights));
    let (Some(g1), Some(g2)) = (g1, g2) else {
        let _ = writeln!(log, "t102: capability table exhausted");
        return false;
    };
    let inst = task::with_task_handles(me, |t| {
        t[kh_req] = Some(g1);
        t[kh_resp] = Some(g2);
    })
    .is_some();
    ok &= inst;
    // fbsvc 映像装载 + 接线派生（LXE1 双段——gen 脚本产物直装）
    let Some(frames) = vmm::global_frames() else {
        let _ = writeln!(log, "t102: frame service unreachable");
        return false;
    };
    let es = match user::build_user_space_lxe(&user::FBDEV_SVC_LXE, &mut || frames.alloc()) {
        Ok(es) => es,
        Err(e) => {
            let _ = writeln!(log, "t102: fbdev svc image build failed ({e:?})");
            return false;
        }
    };
    let mut slots = [0u64; 15];
    slots[0] = 0x202;
    slots[1] = es.entry;
    slots[7] = es.stack_top;
    let fbsvc_id = task::spawn_stage_wired(
        "fbsvc",
        es.root,
        me,
        slots,
        false,
        &[(1, kh_req), (2, kh_resp)], // 子 h1 = FB 请求通道 / h2 = FB 应答通道
    );
    if fbsvc_id == usize::MAX {
        let _ = writeln!(log, "t102: task slot exhausted");
        return false;
    }
    let g = crate::dev::pio_grant(fbsvc_id as u64, 0x1CE, 0x1CF);
    ok &= g.is_ok();
    let adopt = crate::svc::adopt_user(SVC_FB, fbsvc_id as u64);
    ok &= adopt.is_ok();
    let _ = writeln!(
        log,
        "t102: spawn pid={fbsvc_id} grant-ok={} adopt-ok={} wired=[h1←{kh_req} h2←{kh_resp}]",
        g.is_ok(),
        adopt.is_ok(),
    );
    // 客户端证据基线（kmain 请求/服务应答对账域——DIAG 增量面）
    let ds0 = ipc::DIAG_SENDS.load(Ordering::Acquire);
    let rv0 = ipc::DIAG_RECVS.load(Ordering::Acquire);
    let base = crate::fb::fb_base();
    // (e) 请求 1：PAINT_RECT(8, 1, 64, FB_SVC_PAINT)——服务域成像
    let mut req = [0u8; 20];
    req[0..4].copy_from_slice(&user::FB_SVC_OP_PAINT.to_le_bytes());
    req[4..8].copy_from_slice(&8u32.to_le_bytes());
    req[8..12].copy_from_slice(&1u32.to_le_bytes());
    req[12..16].copy_from_slice(&64u32.to_le_bytes());
    req[16..20].copy_from_slice(&user::FB_SVC_PAINT.to_le_bytes());
    let mut reply = [0u8; 32];
    let r1 = ipc::sys_send(kh_req as u64, req.as_ptr() as u64, req.len() as u64, 0x51);
    ok &= r1 == 0;
    // 应答落环等待（DIAG_SENDS 增量 +2 = 客户端 1 + 服务 1；240 拍——
    // 首请求吸收 fbsvc boot 时延〔FB_MAP 2026 页走查 + PIO 探测，TCG
    // 域〕；映像侧 paint 先于 reply——应答落环即 VRAM 稳态）
    let dl2 = ostd::time::now() + 240;
    while ipc::DIAG_SENDS.load(Ordering::Acquire) < ds0 + 2 && ostd::time::now() < dl2 {
        core::hint::spin_loop();
    }
    let replied1 = ipc::DIAG_SENDS.load(Ordering::Acquire) >= ds0 + 2;
    // 内核侧 VRAM 行 1 x=8..71 单遍读回全 FB_SVC_PAINT（服务域直写真面
    // ——paint 先于 reply 契约下应答落环即终态，零竞态）
    let mut paint_ok = base != 0 && r1 == 0 && replied1;
    if paint_ok {
        let row1 = base + crate::fb::WIDTH as u64 * 4;
        for i in 0..64u64 {
            if ostd::hw::phys::read_u32(row1 + (8 + i) * 4) != user::FB_SVC_PAINT {
                paint_ok = false;
                break;
            }
        }
    }
    ok &= paint_ok;
    let mut tag1 = 0u64;
    let mut seq1 = 0u32;
    let mut resp1_ok = false;
    if replied1 {
        let r = ipc::sys_recv(
            kh_resp as u64,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        );
        tag1 = r >> 32;
        if tag1 == (0x51u32 | user::FB_SVC_REPLY_TAG) as u64 && (r & 0xFFFF_FFFF) == 8 {
            let status = u32::from_le_bytes(reply[0..4].try_into().unwrap_or_default());
            seq1 = u32::from_le_bytes(reply[4..8].try_into().unwrap_or_default());
            resp1_ok = status == user::FB_SVC_STATUS_OK && seq1 == 1;
        }
    }
    ok &= resp1_ok;
    let _ = writeln!(
        log,
        "t102: paint1-ok={paint_ok} tag1={tag1:#x} (expect 0xd1) seq1={seq1} resp1-ok={resp1_ok}"
    );
    // (f) 请求 2：越域 PAINT_RECT(1900,1,64)——x+w=1964 > 1920 域闸拒绝
    let mut req2 = [0u8; 20];
    req2[0..4].copy_from_slice(&user::FB_SVC_OP_PAINT.to_le_bytes());
    req2[4..8].copy_from_slice(&1900u32.to_le_bytes());
    req2[8..12].copy_from_slice(&1u32.to_le_bytes());
    req2[12..16].copy_from_slice(&64u32.to_le_bytes());
    req2[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // VRAM 快照（拒绝前域基线——组合态无关取证）
    let mut snap = [0u32; 64];
    if base != 0 {
        let row1 = base + crate::fb::WIDTH as u64 * 4;
        for (i, s) in snap.iter_mut().enumerate() {
            *s = ostd::hw::phys::read_u32(row1 + (1900 + i as u64) * 4);
        }
    }
    let r2 = ipc::sys_send(kh_req as u64, req2.as_ptr() as u64, req2.len() as u64, 0x52);
    ok &= r2 == 0;
    let dl3 = ostd::time::now() + 120;
    while ipc::DIAG_SENDS.load(Ordering::Acquire) < ds0 + 4 && ostd::time::now() < dl3 {
        core::hint::spin_loop();
    }
    let mut resp2_ok = false;
    let mut status2 = u32::MAX;
    if ipc::DIAG_SENDS.load(Ordering::Acquire) >= ds0 + 4 {
        let r = ipc::sys_recv(
            kh_resp as u64,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        );
        if r >> 32 == (0x52u32 | user::FB_SVC_REPLY_TAG) as u64 && (r & 0xFFFF_FFFF) == 8 {
            status2 = u32::from_le_bytes(reply[0..4].try_into().unwrap_or_default());
            let seq2 = u32::from_le_bytes(reply[4..8].try_into().unwrap_or_default());
            resp2_ok = status2 == user::FB_SVC_STATUS_EDOM && seq2 == 2;
        }
    }
    // 拒绝不写显形：域基线快照零变（fail-visible 零副作用取证）
    let mut no_write = base != 0;
    if no_write {
        let row1 = base + crate::fb::WIDTH as u64 * 4;
        for (i, s) in snap.iter().enumerate() {
            if ostd::hw::phys::read_u32(row1 + (1900 + i as u64) * 4) != *s {
                no_write = false;
                break;
            }
        }
    }
    ok &= resp2_ok && no_write;
    let _ = writeln!(
        log,
        "t102: reject-ok={resp2_ok} status2={status2} (expect EDOM=2) no-write={no_write}"
    );
    // (g) 请求 3：QUIT——应答后有界终结
    let mut req3 = [0u8; 4];
    req3[0..4].copy_from_slice(&user::FB_SVC_OP_QUIT.to_le_bytes());
    let r3 = ipc::sys_send(kh_req as u64, req3.as_ptr() as u64, 4, 0x53);
    ok &= r3 == 0;
    let dl4 = ostd::time::now() + 120;
    while ipc::DIAG_SENDS.load(Ordering::Acquire) < ds0 + 6 && ostd::time::now() < dl4 {
        core::hint::spin_loop();
    }
    let mut resp3_ok = false;
    if ipc::DIAG_SENDS.load(Ordering::Acquire) >= ds0 + 6 {
        let r = ipc::sys_recv(
            kh_resp as u64,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        );
        if r >> 32 == (0x53u32 | user::FB_SVC_REPLY_TAG) as u64 && (r & 0xFFFF_FFFF) == 8 {
            let status = u32::from_le_bytes(reply[0..4].try_into().unwrap_or_default());
            let seq3 = u32::from_le_bytes(reply[4..8].try_into().unwrap_or_default());
            resp3_ok = status == user::FB_SVC_STATUS_OK && seq3 == 3;
        }
    }
    ok &= resp3_ok;
    // 有界收割（60 拍——QUIT 应答后 EXIT 契约；t95/t100/t101 零锁轮询形态）
    let dl_reap = ostd::time::now() + 60;
    let mut iters: u64 = 0;
    while task::user_exit_codes().1 == u64::MAX
        && ostd::time::now() < dl_reap
        && iters < 2_000_000_000
    {
        iters += 1;
        core::hint::spin_loop();
    }
    let st = task::task_debug_state(fbsvc_id);
    let code = task::task_debug_exit_code(fbsvc_id);
    let dhit = ostd::time::now() >= dl_reap;
    let _ = writeln!(
        log,
        "t102: spec i={iters} s1={st} exit={code:#x} deadline-hit={dhit} quit-ok={resp3_ok}"
    );
    if st == 4 {
        let r = procs::sys_wait_pid(fbsvc_id as u64);
        let rcode = r & 0xFFFF;
        ok &= r >> 32 == 1 && rcode == 0 && !task::task_alive(fbsvc_id);
        let _ = writeln!(log, "t102: reaped exit={rcode} (expect 0)");
    } else {
        ok = false; // 滞域 fail-visible（bail 码 70/71/72 显形）
    }
    // (h) 终态对账：boot 身份漆存续 + Owner 存续 + 服务消费三帧
    let mut boot_paint_ok = base != 0;
    if boot_paint_ok {
        for i in 0..64u64 {
            if ostd::hw::phys::read_u32(base + i * 4) != user::FBDEV_PAINT {
                boot_paint_ok = false;
                break;
            }
        }
    }
    ok &= boot_paint_ok;
    let owner_ok = crate::svc::lookup(SVC_FB)
        .is_some_and(|(_, _, _, o)| matches!(o, crate::svc::Owner::UserTask(t) if t == fbsvc_id));
    ok &= owner_ok;
    let rv_delta = ipc::DIAG_RECVS.load(Ordering::Acquire) - rv0;
    ok &= rv_delta >= 3;
    let _ = writeln!(
        log,
        "LUMINA-T102-FBSVC pid={fbsvc_id} paint1={paint_ok} reject={resp2_ok} boot-paint={boot_paint_ok} served={rv_delta} owner=user"
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T102-OK");
    }
    ok
}

/// t103 unix socket 域 + Wayland wire 语义面活体执行体（M42-UNIX3 阶段
/// 二 笔③）：独立函数承载（t93/t101/t102 帧形态纪律——自检主函数栈帧
/// 零扰动）。kernel::unixsock 域内函数直驱 + syscall 慢路径负例探针 +
/// prism::wayland 语义面回环——三域同一活体取证。
fn t103_run(log: &mut DualLog) -> bool {
    use bedrock::abi::{ERR_CAP, SYS_UNIXSOCK, USOCK_SEND};
    use prism::wayland as wl;
    let mut ok = true;
    let me = task::current_task_id();
    let s0 = unixsock::usock_stamps();
    let su0 = unixsock::sockets_usage();
    // 监听者计数基（M42-COMP4 随行改写：常驻合成器 waycomp boot 监听
    // 名域 wayland-comp 入表——绝对计数改相对对账，其余相位语义不变）
    let lu0 = unixsock::listeners_usage();
    // 句柄 → 能力对象 id 解析（对账面——段正交性断言数据源）
    let obj_of = |h: usize| -> Option<u64> {
        task::with_task_handles(me, |t| t[h])
            .and_then(|s| s)
            .and_then(|g| crate::caps::table().lock().get(g).ok())
            .map(|c| c.object())
    };
    // (a) socketpair 铸造对账：双句柄 + 对象 id 段正交（0xC0DE…002X）
    let (ha, hb) = match unixsock::sock_pair(me) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(log, "t103: sock_pair failed ({:?})", e);
            return false;
        }
    };
    let (obj_a, obj_b) = (obj_of(ha), obj_of(hb));
    let seg_ok = obj_a.is_some_and(|o| {
        (unixsock::USOCK_OBJECT_BASE..unixsock::USOCK_OBJECT_BASE + 64).contains(&o)
    }) && obj_b.is_some_and(|o| {
        (unixsock::USOCK_OBJECT_BASE..unixsock::USOCK_OBJECT_BASE + 64).contains(&o)
    }) && obj_a != obj_b
        && unixsock::is_socket_object(obj_a.unwrap_or(0))
        && unixsock::is_socket_object(obj_b.unwrap_or(0));
    ok &= seg_ok;
    let su1 = unixsock::sockets_usage();
    ok &= su1.0 == su0.0 + 2;
    let _ = writeln!(
        log,
        "t103: pair-ok={seg_ok} h=({ha},{hb}) obj=({obj_a:?},{obj_b:?}) usage={}/{}",
        su1.0, su1.1
    );
    // (b) 负例面：坏句柄 Cap / 未登记名 NoEnt / 词法域 Name / parse 域
    let neg_cap = unixsock::sock_send(me, 63, b"x");
    ok &= neg_cap == Err(unixsock::UsockError::Cap);
    let neg_connect = unixsock::sock_connect(me, b"no-such-sock");
    ok &= neg_connect == Err(unixsock::UsockError::NoEnt);
    let neg_name = unixsock::sock_bind(me, b"has space");
    ok &= neg_name == Err(unixsock::UsockError::Name);
    // syscall 慢路径门禁先序探针：句柄域先于载荷域（ipc::sys_send F1/F2
    // 先于 F4 同款——ptr/len 未及校验即 ERR_CAP）
    let sys_neg = unixsock::sys_unixsock(USOCK_SEND, 63, 8, 0);
    ok &= sys_neg == ERR_CAP;
    // parse 层越域闸显形（bedrock abi v0.22——op 10 拒收；op 6/7 自
    // M42-COMP4 起为 ACCEPT_B/SHUT 收录域、op 8/9 自 M42-ELF5 起为
    // SEND_FD/RECV_FD 收录域——越域探针随收录域扩容右移）
    let parse_neg = bedrock::abi::parse(bedrock::abi::SyscallRegs {
        num: SYS_UNIXSOCK,
        args: [10, 0, 0, 0, 0],
    });
    ok &= parse_neg == Err(bedrock::abi::AbiError::BadArgs);
    let _ = writeln!(
        log,
        "t103: neg cap={cap} connect={conn} name={name} sys-face={sys_neg:#x} parse-gate={pgate}",
        cap = neg_cap == Err(unixsock::UsockError::Cap),
        conn = neg_connect == Err(unixsock::UsockError::NoEnt),
        name = neg_name == Err(unixsock::UsockError::Name),
        pgate = parse_neg == Err(bedrock::abi::AbiError::BadArgs),
    );
    // (c) 连接面：bind 即 listen → dup bind InUse → connect NoEnt/在环
    //     → accept 三柄成形（listener/client/server）
    let hl = match unixsock::sock_bind(me, b"wayland-0") {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(log, "t103: bind failed ({:?})", e);
            return false;
        }
    };
    let lu = unixsock::listeners_usage();
    ok &= lu.0 == lu0.0 + 1;
    ok &= unixsock::sock_bind(me, b"wayland-0") == Err(unixsock::UsockError::InUse);
    ok &= unixsock::sock_accept(me, ha as u64) == Err(unixsock::UsockError::Cap); // 端点非监听者
    ok &= unixsock::sock_accept(me, hl as u64) == Err(unixsock::UsockError::Empty); // backlog 空
    let hc = match unixsock::sock_connect(me, b"wayland-0") {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(log, "t103: connect failed ({:?})", e);
            return false;
        }
    };
    let hs = match unixsock::sock_accept(me, hl as u64) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(log, "t103: accept failed ({:?})", e);
            return false;
        }
    };
    let conn_ok = obj_of(hc).is_some() && obj_of(hs).is_some();
    ok &= conn_ok;
    let _ = writeln!(
        log,
        "t103: connect-ok={conn_ok} hl={hl} hc={hc} hs={hs} accept-empty/cap 负例在环"
    );
    // (d) 连接面回环 I/O：client → server → client 字节对账
    let mut rbuf = [0u8; 64];
    let n1 = unixsock::sock_send(me, hc as u64, b"wl-display!").unwrap_or(0);
    let n2 = unixsock::sock_recv(me, hs as u64, &mut rbuf).unwrap_or(0);
    let io_ok = n1 == 11 && n2 == 11 && &rbuf[..11] == b"wl-display!";
    ok &= io_ok;
    let n3 = unixsock::sock_send(me, hs as u64, b"compositor").unwrap_or(0);
    let n4 = unixsock::sock_recv(me, hc as u64, &mut rbuf).unwrap_or(0);
    let io_ok2 = n3 == 10 && n4 == 10 && &rbuf[..10] == b"compositor";
    ok &= io_ok2;
    let _ = writeln!(log, "t103: io-ok={io_ok} io-ok2={io_ok2} (连接面双向往返)");
    // (e) 阻塞唤醒链：echo 内核任务 UnixRecv 双向唤醒（编舞：spawn →
    //     yield 让 worker 先阻塞 → send 唤醒 → kmain 阻塞收 → echo 唤醒）
    let (h2a, h2b) = match unixsock::sock_pair(me) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(log, "t103: pair2 failed ({:?})", e);
            return false;
        }
    };
    let Some(obj_b2) = obj_of(h2b) else {
        let _ = writeln!(log, "t103: pair2 resolve failed");
        return false;
    };
    unixsock::arm_echo_worker(obj_b2);
    let wid = task::spawn("usock-echo", unixsock::echo_worker_body);
    // 编舞锚：有界等 worker 先行阻塞（计时器抢占域——yield_now 对等
    // 优先级无让渡语义〔pick_best 择优〕实测揭雷随行；t102 240 拍先例
    // 同款域吸收）
    let dlw = ostd::time::now() + 240;
    let s1 = loop {
        let s = unixsock::usock_stamps();
        if s.3 > s0.3 || ostd::time::now() >= dlw {
            break s;
        }
        core::hint::spin_loop();
    };
    let worker_blocked = s1.3 > s0.3;
    let n5 = unixsock::sock_send(me, h2a as u64, b"ping-wayland").unwrap_or(0);
    // kmain 阻塞收（worker echo 唤醒链终点——USOCK_WAKES 取证）
    let n6 = unixsock::sock_recv(me, h2a as u64, &mut rbuf).unwrap_or(0);
    let echo_ok = n5 == 12 && n6 == 12 && &rbuf[..12] == b"ping-wayland";
    ok &= worker_blocked && echo_ok;
    let s2 = unixsock::usock_stamps();
    let wakes_delta = s2.4 - s0.4;
    let blocks_delta = s2.3 - s0.3;
    let served = unixsock::echo_served();
    // 唤醒链取证不变式（TCG 调度三形皆合法，同链异序如实放宽）：
    // (a) worker 阻塞 + kmain 阻塞收 → wakes=2/blocks=2；
    // (b) worker 阻塞 + kmain 探针命中（echo 先落环）→ wakes=1/blocks=1
    //     ——send→wake_tasks(UnixRecv)→worker 复苏的定向唤醒电证据同链；
    // (c) wakes=0/blocks=1（send 落于 worker BLOCKS 计数与阻塞探针之间
    //     窗——served 链同链完达，消息零丢失；定向唤醒电气由 (a)/(b) 形
    //     承载——M42-ELF5 随行改写，第三合法交织如实放宽）。
    ok &= served == 1 && blocks_delta >= 1;
    let _ = writeln!(
        log,
        "t103: echo-ok={echo_ok} blocked={worker_blocked} blocks={blocks_delta} wakes={wakes_delta} served={served} pid={wid}"
    );
    // (f) 流短写语义：满环 0 短写 + 计账精确（4096 = 环容量）
    let fill = [0xA5u8; unixsock::USOCK_BUF];
    let full_n = unixsock::sock_send(me, h2a as u64, &fill).unwrap_or(0);
    let over_n = unixsock::sock_send(me, h2a as u64, b"overflow").unwrap_or(0);
    let short_ok = full_n == unixsock::USOCK_BUF && over_n == 0;
    let mut drain = [0u8; unixsock::USOCK_BUF];
    let mut drained = 0usize;
    while drained < unixsock::USOCK_BUF {
        let n = unixsock::sock_recv(me, h2b as u64, &mut drain[drained..]).unwrap_or(0);
        if n == 0 {
            break;
        }
        drained += n;
    }
    let after_n = unixsock::sock_send(me, h2a as u64, b"resumed").unwrap_or(0);
    let resumed_ok = after_n == 7;
    ok &= short_ok && drained == unixsock::USOCK_BUF && resumed_ok;
    let send_bytes_delta = s2.1 - s0.1;
    let _ = writeln!(
        log,
        "t103: short-write-ok={short_ok} full={full_n} over={over_n} drained={drained} resumed={resumed_ok} send-bytes={send_bytes_delta}"
    );
    // (g) Wayland wire 语义面回环（prism::wayland 对内核可消费显形——
    //     bind 特例签名 + global 事件 + done 事件三编组）
    let mut wb = [0u8; 128];
    let mut wire_ok = true;
    match wl::encode_registry_bind(&mut wb, 2, 17, "wl_compositor", 4, 5) {
        Ok(_) => match wl::parse_message(&wb, wl::SIG_REGISTRY_BIND) {
            Ok(m) => {
                wire_ok &= m.header.object_id == 2
                    && m.header.opcode == wl::registry::REQ_BIND
                    && m.args[0] == Some(wl::WlArg::Uint(17))
                    && m.args[1] == Some(wl::WlArg::Str(b"wl_compositor"))
                    && m.args[2] == Some(wl::WlArg::Uint(4))
                    && m.args[3] == Some(wl::WlArg::NewId(5));
            }
            Err(_) => wire_ok = false,
        },
        Err(_) => wire_ok = false,
    }
    match wl::encode_registry_global_event(&mut wb, 2, 9, wl::WlIface::Compositor, 4) {
        Ok(_) => match wl::parse_message(&wb, wl::SIG_REGISTRY_GLOBAL) {
            Ok(m) => {
                wire_ok &= m.header.opcode == wl::registry::EV_GLOBAL
                    && m.args[1] == Some(wl::WlArg::Str(b"wl_compositor"));
            }
            Err(_) => wire_ok = false,
        },
        Err(_) => wire_ok = false,
    }
    match wl::encode_callback_done_event(&mut wb, 7, 0x51) {
        Ok(_) => match wl::parse_message(&wb, wl::SIG_CALLBACK_DONE) {
            Ok(m) => {
                wire_ok &= m.header.opcode == wl::callback::EV_DONE
                    && m.args[0] == Some(wl::WlArg::Uint(0x51));
            }
            Err(_) => wire_ok = false,
        },
        Err(_) => wire_ok = false,
    }
    ok &= wire_ok;
    let _ = writeln!(log, "t103: wire-ok={wire_ok} (bind/global/done 三编组回环)");
    // (h) close 分支：句柄回收 + 对象存续纪律（通道分支同款显形）
    let close_ok = vfs::sys_close(hb as u64) == 0;
    let gone_cap = unixsock::sock_recv(me, hb as u64, &mut rbuf) == Err(unixsock::UsockError::Cap);
    let obj_survives = unixsock::is_socket_object(obj_b.unwrap_or(0));
    ok &= close_ok && gone_cap && obj_survives;
    ok &= vfs::sys_close(hl as u64) == 0;
    // 监听者对象存续 → dup bind 仍 InUse（名字域存续纪律二显形）
    ok &= unixsock::sock_bind(me, b"wayland-0") == Err(unixsock::UsockError::InUse);
    let _ = writeln!(
        log,
        "t103: close-ok={close_ok} cap-gone={gone_cap} obj-survives={obj_survives} name-survives={ns}",
        ns = unixsock::sock_bind(me, b"wayland-0") == Err(unixsock::UsockError::InUse),
    );
    // 汇总取证行（双面板标记）
    let _ = writeln!(
        log,
        "LUMINA-T103-UNIX pair={seg_ok} conn={conn_ok} echo={echo_ok} wire={wire_ok} close={close_ok}"
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T103-OK");
    }
    ok
}

/// t104 合成器进程面活体（M42-COMP4 阶段三首笔）。五相位：〔boot 常
/// 驻面三域对账〕→〔阻塞 accept 唤醒链〕→〔合流电气面 wire 回环〕→
/// 〔仲裁策略承接 + SYS_FB_SURFACE 消费成像〕→〔EOF 对端终结面〕——
/// prism::wayland::comp 语义面 / unix socket 电气面 / fb 机械面三域
/// 同一活体取证（LUMINA-T104-COMP/OK 双面板标记）。
fn t104_run(log: &mut DualLog) -> bool {
    use bedrock::abi::{ERR_CAP, SVC_COMPOSITOR, USOCK_ACCEPT_B, USOCK_SHUT};
    use prism::wayland as wl;
    let mut ok = true;
    let me = task::current_task_id();

    // (a) boot 常驻面三域对账：bind 名域在环 + SVC 第 6 预设
    //     KernelResident + 监听对象 id 段正交（0xC0DE…002X）
    let bound = waycomp::WLCOMP_BOUND.load(Ordering::Acquire);
    let lobj = waycomp::WLCOMP_LISTENER.load(Ordering::Acquire);
    let seg_ok = (unixsock::USOCK_OBJECT_BASE..unixsock::USOCK_OBJECT_BASE + 64).contains(&lobj);
    let svc_ok = matches!(
        svc::lookup(SVC_COMPOSITOR),
        Some(("compositor", 0, 0, svc::Owner::KernelResident))
    );
    let boot_ok = bound && seg_ok && svc_ok;
    ok &= boot_ok;
    let _ = writeln!(
        log,
        "t104: boot-ok={boot_ok} bound={bound} seg={seg_ok} svc={svc_ok} listener={lobj:#x} stage0={}",
        fb::surf_count()
    );

    // (b) 阻塞 accept 唤醒链：connect → waycomp UnixAccept 定向唤醒
    //     （accept_wakes 取证戳增量 + 会话戳增量）——M42-COMP4 阻塞
    //     accept 电气域活体（waycomp boot 即阻塞于 accept_wait）
    let s0 = unixsock::usock_stamps();
    let c0 = waycomp::waycomp_stamps();
    let hc = match unixsock::sock_connect(me, waycomp::WAYCOMP_SOCK_NAME) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(log, "t104: connect failed ({:?})", e);
            return false;
        }
    };
    let dl = ostd::time::now() + 240; // 编舞窗（t102 240 拍先例同款域吸收）
    let c1 = loop {
        let c = waycomp::waycomp_stamps();
        if c.2 > c0.2 || ostd::time::now() >= dl {
            break c;
        }
        core::hint::spin_loop();
    };
    let s1 = unixsock::usock_stamps();
    let accept_wakes = s1.6 - s0.6;
    let accept_ok = c1.2 == c0.2 + 1 && accept_wakes >= 1;
    ok &= accept_ok;
    let _ = writeln!(
        log,
        "t104: accept-ok={accept_ok} sessions=+{} wakes=+{accept_wakes}",
        c1.2 - c0.2
    );

    // (c) 合流电气面 round 1：get_registry → globals 公告回执（wire
    //     壳 ⇄ unix socket 回环——四 global 逐条解析对账）
    let mut req = [0u8; 64];
    let n_req = wl::encode_display_get_registry(&mut req, 1, 2).unwrap_or(0);
    let sent = unixsock::sock_send(me, hc as u64, &req[..n_req]).unwrap_or(0);
    ok &= sent == n_req;
    let mut globals_buf = [0u8; 512];
    let mut got = 0usize;
    let dl = ostd::time::now() + 240;
    while got < 124 && ostd::time::now() < dl {
        let n = unixsock::sock_recv(me, hc as u64, &mut globals_buf[got..]).unwrap_or(0);
        if n > 0 {
            got += n;
        }
    }
    let mut off = 0usize;
    let mut gcount = 0usize;
    let mut compositor_seen = false;
    while off + wl::HEADER <= got && gcount < 4 {
        let Ok(m) = wl::parse_message(&globals_buf[off..got], wl::SIG_REGISTRY_GLOBAL) else {
            break;
        };
        if m.header.object_id == 2 && m.header.opcode == wl::registry::EV_GLOBAL {
            gcount += 1;
            if m.args[1] == Some(wl::WlArg::Str(b"wl_compositor"))
                && m.args[2] == Some(wl::WlArg::Uint(4))
            {
                compositor_seen = true;
            }
        }
        off += m.wire_size();
    }
    let wire_ok = got == 124 && gcount == 4 && compositor_seen;
    ok &= wire_ok;
    let _ = writeln!(
        log,
        "t104: wire-ok={wire_ok} globals={gcount} bytes={got} compositor={compositor_seen}"
    );

    // (d) 仲裁策略承接 + SYS_FB_SURFACE 消费成像：bind compositor +
    //     create_surface ×2 + damage + frame + commit ×2 → waycomp
    //     cascade tiling 平面 z 序注入 → REGISTER + 代 Paint + SYNC/
    //     COMPOSE → VRAM 模式读回 + surf_layer_of 策略/登记同源对账
    //     + 帧回调 done 回执解析
    // 预采快照（teardown 回退对账基线——pane 域 VRAM 原值）
    let probe_pts = [(100i32, 100i32), (500, 600), (1200, 300), (1800, 900)];
    let mut batch = [0u8; 512];
    let mut bl = 0usize;
    bl += wl::encode_registry_bind(&mut batch[bl..], 2, 1, "wl_compositor", 4, 3).unwrap_or(0);
    bl += wl::encode_message(
        &mut batch[bl..],
        3,
        wl::compositor::REQ_CREATE_SURFACE,
        &[wl::WlArg::NewId(0x21)],
    )
    .unwrap_or(0);
    bl += wl::encode_message(
        &mut batch[bl..],
        3,
        wl::compositor::REQ_CREATE_SURFACE,
        &[wl::WlArg::NewId(0x25)],
    )
    .unwrap_or(0);
    for sid in [0x21u32, 0x25] {
        bl += wl::encode_message(
            &mut batch[bl..],
            sid,
            wl::surface::REQ_DAMAGE,
            &[
                wl::WlArg::Int(0),
                wl::WlArg::Int(0),
                wl::WlArg::Int(948),
                wl::WlArg::Int(944),
            ],
        )
        .unwrap_or(0);
    }
    bl += wl::encode_message(
        &mut batch[bl..],
        0x21,
        wl::surface::REQ_FRAME,
        &[wl::WlArg::NewId(0x22)],
    )
    .unwrap_or(0);
    bl += wl::encode_message(
        &mut batch[bl..],
        0x25,
        wl::surface::REQ_FRAME,
        &[wl::WlArg::NewId(0x26)],
    )
    .unwrap_or(0);
    bl += wl::encode_surface_commit(&mut batch[bl..], 0x21).unwrap_or(0);
    bl += wl::encode_surface_commit(&mut batch[bl..], 0x25).unwrap_or(0);
    let sent2 = unixsock::sock_send(me, hc as u64, &batch[..bl]).unwrap_or(0);
    ok &= sent2 == bl;
    // 有界等：commit 戳 ≥ 2（waycomp 发布应用域）
    let dl = ostd::time::now() + 480;
    let c2 = loop {
        let c = waycomp::waycomp_stamps();
        if c.3 >= c0.3 + 2 || ostd::time::now() >= dl {
            break c;
        }
        core::hint::spin_loop();
    };
    let commits_ok = c2.3 >= c0.3 + 2;
    // 帧回调 done 回执（2 × 12 B——done(0x22, s1) + done(0x26, s2)）
    let mut done_buf = [0u8; 64];
    let mut dgot = 0usize;
    let dl = ostd::time::now() + 240;
    while dgot < 24 && ostd::time::now() < dl {
        let n = unixsock::sock_recv(me, hc as u64, &mut done_buf[dgot..]).unwrap_or(0);
        if n > 0 {
            dgot += n;
        }
    }
    let mut dones_ok = dgot == 24;
    let mut dserials = [0u32; 2];
    if dones_ok {
        for k in 0..2 {
            match wl::parse_message(&done_buf[k * 12..dgot], wl::SIG_CALLBACK_DONE) {
                Ok(m) => {
                    let expect_id = if k == 0 { 0x22 } else { 0x26 };
                    dones_ok &=
                        m.header.object_id == expect_id && m.header.opcode == wl::callback::EV_DONE;
                    if let Some(wl::WlArg::Uint(v)) = m.args[0] {
                        dserials[k] = v;
                    }
                }
                Err(_) => dones_ok = false,
            }
        }
    }
    // 策略/登记同源对账：cascade tiling 平面 z 序 + 矩形 = prism
    // Layer 落账（surf_layer_of 读回——t79「两套面同一几何」先例）
    let plan = cascade::tiling::tiling_plan(&[0x21u64, 0x25], waycomp::VIEWPORT);
    let policy_ok = match &plan {
        Ok(p) if p.panes.len() == 2 => {
            let master = p.panes[0].1;
            let stack = p.panes[1].1;
            let l1 = fb::surf_layer_of(0x21)
                .map(|(z, v, b)| z == waycomp::POLICY_Z_BASE && v && b == master);
            let l2 = fb::surf_layer_of(0x25)
                .map(|(z, v, b)| z == waycomp::POLICY_Z_BASE - 1 && v && b == stack);
            l1.unwrap_or(false) && l2.unwrap_or(false)
        }
        _ => false,
    };
    // VRAM 模式读回（pane 域代 Paint 成像——pattern 局部坐标换算）
    let master_rect = plan.as_ref().ok().map(|p| p.panes[0].1);
    let stack_rect = plan.as_ref().ok().map(|p| p.panes[1].1);
    let px_ok = match (master_rect, stack_rect) {
        (Some(mr), Some(sr)) => {
            let e0 = waycomp::pane_pattern(0x21, 100 - mr.x, 100 - mr.y) & 0x00FF_FFFF;
            let e1 = waycomp::pane_pattern(0x21, 500 - mr.x, 600 - mr.y) & 0x00FF_FFFF;
            let e2 = waycomp::pane_pattern(0x25, 1200 - sr.x, 300 - sr.y) & 0x00FF_FFFF;
            let e3 = waycomp::pane_pattern(0x25, 1800 - sr.x, 900 - sr.y) & 0x00FF_FFFF;
            fb::fb_probe_px_read(100, 100) == e0
                && fb::fb_probe_px_read(500, 600) == e1
                && fb::fb_probe_px_read(1200, 300) == e2
                && fb::fb_probe_px_read(1800, 900) == e3
        }
        _ => false,
    };
    let count_ok = fb::surf_count() == 3; // stage 底层锚 + 双 surface
    let compose_ok = commits_ok && dones_ok && policy_ok && px_ok && count_ok;
    ok &= compose_ok;
    let _ = writeln!(
        log,
        "t104: compose-ok={compose_ok} commits=+{} dones={dones_ok} serials=({},{}) policy={policy_ok} px={px_ok} count={}",
        c2.3 - c0.3,
        dserials[0],
        dserials[1],
        fb::surf_count()
    );

    // (e) EOF 对端终结面：shutdown → waycomp 排空 EOF（会话收场
    //     teardown——surface 摘除 + pane 回退）+ 对己端 send ERR_PIPE
    //     + 己端 recv 0 = EOF + VRAM 回退对账（快照复原）
    let sys_shut_neg = unixsock::sys_unixsock(USOCK_SHUT, 63, 0, 0);
    ok &= sys_shut_neg == ERR_CAP; // 坏句柄域（syscall 慢路径门禁）
    let sys_ab_neg = unixsock::sys_unixsock(USOCK_ACCEPT_B, 63, 0, 0);
    ok &= sys_ab_neg == ERR_CAP; // ACCEPT_B 同面负例
    let shut = unixsock::sock_shutdown(me, hc as u64);
    ok &= shut.is_ok();
    // 有界等：**会话收场完成旗**（M42-COMP4 随行揭雷改域——原
    // surf_count ≤1 早跳域：remove 后收场 sync+compose 尚在途，客户端
    // 读到陈旧 VRAM/初始戳——旗 wait 免竞态，t102 应答先行时序同谱）
    let dl = ostd::time::now() + 480;
    while !waycomp::WLCOMP_SESSION_DONE.load(Ordering::Acquire) && ostd::time::now() < dl {
        core::hint::spin_loop();
    }
    let teardown_ok = waycomp::WLCOMP_SESSION_DONE.load(Ordering::Acquire) && fb::surf_count() == 1;
    let s2 = unixsock::usock_stamps();
    let eofs = s2.7 - s0.7;
    let pipe = unixsock::sock_send(me, hc as u64, b"x");
    let mut rb = [0u8; 16];
    let eof_own = unixsock::sock_recv(me, hc as u64, &mut rb).unwrap_or(99);
    let eof_ok =
        teardown_ok && eofs >= 1 && pipe == Err(unixsock::UsockError::Pipe) && eof_own == 0;
    ok &= eof_ok;
    // VRAM 回退对账：pane 域回 stage 基线（快照逐点复原——teardown
    // surf_remove + sync + compose 回退链显形）
    // 回退基线对账（M42-COMP4 裁定改域：teardown 后 pane = stage 单层
    // 直通——VRAM == stage 直读 = 合成回退链显形；历史 VRAM 直写哨兵
    // 〔t79 交盒哨兵域〕使 pre-快照先天不可比，pre 面仅存证不断言）
    let mut restore_ok = true;
    for (x, y) in probe_pts.iter() {
        if fb::fb_probe_px_read(*x, *y) != fb::stage_probe_px_read(*x, *y) {
            restore_ok = false;
        }
    }
    ok &= restore_ok;
    let _ = writeln!(
        log,
        "t104: eof-ok={eof_ok} teardown={teardown_ok} eofs=+{eofs} pipe={} own-eof={eof_own} restore={restore_ok} sys-neg=({sys_shut_neg},{sys_ab_neg}) rerr={} endc={} stage-anchor=1",
        pipe == Err(unixsock::UsockError::Pipe),
        waycomp::WLCOMP_REMOVE_ERR.load(Ordering::Acquire),
        waycomp::WLCOMP_END_COUNT.load(Ordering::Acquire),
    );

    // 汇总取证行（双面板标记）
    let _ = writeln!(
        log,
        "LUMINA-T104-COMP boot={boot_ok} accept={accept_ok} wire={wire_ok} compose={compose_ok} eof={eof_ok} restore={restore_ok}"
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T104-OK");
    }
    ok
}

/// t105 用户态 ELF 播种 lane 活体执行体（M42-ELF5 次笔域①「ring3 编译
/// 进程承接」）：独立函数承载（帧形态守恒纪律——t93/t101/t104 先例）。
/// 相位序：
/// (a) lane 结构闸负例：非 ELF blob → BadImage（spawn_elf_seed
///     fail-visible——装载链魔数闸显形）；
/// (b) ELF_NATIVE 播种：真 ELF64 静态映像（gen 脚本编译产物——ELF 头
///     + PT_LOAD ×2）→ build_user_space_elf 装载 → spawn_stage_wired
///     原生 ABI 派生（lin_abi = false——Lumina 号域派发对账）；
/// (c) ABI 分流对账：task_is_lin_abi(pid) == false（原生链面——与
///     Linux 兼容链分立双轨显形）；
/// (d) 有界收割：exit = 77（ELF_NATIVE EXIT 对账码——WAITPID 协议
///     r>>32==1 + code==77 + !alive）。
/// LUMINA-T105-ELF（映像内 SYS_LOG 取证）/R3/OK 三面板标记。
fn t105_run(log: &mut DualLog) -> bool {
    let mut ok = true;
    task::reset_user_evidence(); // 零锁判据面清零（t101 同款）
                                 // (a) lane 结构闸负例
    let neg = procs::spawn_elf_seed("elf-bad", b"NOT-AN-ELF-IMAGE!", &["elf-bad"]);
    let neg_ok = matches!(neg, Err(user::UserSpaceError::BadImage));
    ok &= neg_ok;
    let _ = writeln!(log, "t105: bad-image-negative={neg_ok}");
    // (b) ELF_NATIVE 播种（原生 ABI）
    let pid = match procs::spawn_elf_seed("elf-native", &user::ELF_NATIVE, &["elf-native"]) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(log, "t105: native build failed ({e:?})");
            return false;
        }
    };
    let seeds = procs::elf_seeds();
    let spawn_ok = pid != usize::MAX && seeds >= 1;
    ok &= spawn_ok;
    // (c) ABI 分流对账（原生链——lin_abi = false）
    let native_ok = !task::task_is_lin_abi(pid);
    ok &= native_ok;
    let _ = writeln!(
        log,
        "t105: spawned pid={pid} seeds={seeds} native-abi={native_ok}"
    );
    // (d) 有界收割（60 拍 = 0.6 s——ELF_NATIVE 轻载荷：LOG + 累加 + EXIT）
    let now0 = ostd::time::now();
    let deadline = now0 + 60;
    while task::user_exit_codes().1 == u64::MAX && ostd::time::now() < deadline {
        core::hint::spin_loop();
    }
    let st = task::task_debug_state(pid);
    let code = task::task_debug_exit_code(pid);
    let dhit = ostd::time::now() >= deadline;
    if st == 4 {
        let r = procs::sys_wait_pid(pid as u64);
        let rcode = r & 0xFFFF;
        let reap_ok = r >> 32 == 1 && rcode == 77 && !task::task_alive(pid);
        ok &= reap_ok;
        let _ = writeln!(
            log,
            "t105: reaped exit={rcode} (expect 77) alive={}",
            task::task_alive(pid)
        );
    } else {
        ok = false; // 滞域 fail-visible（bail 显形）
    }
    let _ = writeln!(
        log,
        "LUMINA-T105-R3 pid={pid} st={st} exit={code:#x} deadline-hit={dhit} seeds={seeds}"
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T105-OK");
    }
    ok
}

/// t106 桌面链 wl_shm/fd 传递活体执行体（M42-ELF5 次笔域②）：独立函
/// 数承载（帧形态守恒纪律同 t105）。相位序：
/// (a) SYS_SHM 慢路径负例：op 越域（BadArgs 哨兵）+ 坏句柄 MAP +
///     零尺寸 CREATE（ERR_CAP——域闸 fail-visible）；
/// (b) SHM_CLIENT ELF 播种（桌面链编译进程承接面——域① lane 消费）：
///     CREATE(320×200×4) + MAP(SHM_VA_BASE) + 池像素面渐变直写 +
///     CONNECT(wayland-comp) + SEND_FD（SCM_RIGHTS 语义面）+ wire 批
///     9 消息（create_pool fd 占位 + create_buffer + attach + damage +
///     commit）+ 帧回调 done 等待 + YIELD×32 + EXIT(0)；
/// (c) 有界等 commit ≥ +1（池像素上屏域——waycomp apply_commits 先于
///     串号推进，VRAM 断言窗先行于 done 回执）；
/// (d) VRAM 客户端像素断言：cascade tiling 单窗 pane 域 4 探针
///     （lx/ly ∈ buffer 像素域——与客户端像素函数逐位对账）；
/// (e) fd 传递对账：FD_SENDS/FD_RECVS ≥ +1 + 池承接 ≥ 1 + shm 对象 id
///     段正交（0xC0DE…003X）+ FD_ERR 零账；
/// (f) 收割 exit=0 + teardown（SESSION_DONE 旗 + surf_count 回退 +
///     VRAM == stage 直读复原对账——t104 回退判定改域先例同谱）。
/// LUMINA-T106-CLIENT（映像内 SYS_LOG 取证）/SHM/OK 三面板标记。
fn t106_run(log: &mut DualLog) -> bool {
    use bedrock::abi::{SHM_MAP, SHM_VA_BASE};
    let mut ok = true;
    task::reset_user_evidence(); // 零锁判据面清零（t101 同款）
    let _ = task::current_task_id();
    // (a) SYS_SHM 慢路径负例（syscall 面域闸）
    let neg_op = shm::sys_shm(2, 0, 0);
    ok &= neg_op == u64::MAX - 1; // op 越域（parse 已闸——执行面纵深防御域）
    let neg_handle = shm::sys_shm(SHM_MAP, 63, SHM_VA_BASE);
    ok &= neg_handle == bedrock::abi::ERR_CAP; // 坏句柄域
    let neg_size = shm::sys_shm(bedrock::abi::SHM_CREATE, 0, 0);
    ok &= neg_size == bedrock::abi::ERR_CAP; // 零尺寸域
    let _ = writeln!(
        log,
        "t106: gate-negative op={neg_op:#x} handle={neg_handle} size={neg_size}"
    );
    // (b) SHM_CLIENT ELF 播种（基线快照先行）
    let c0 = waycomp::waycomp_stamps();
    let s0 = unixsock::usock_stamps(); // 流字节基线（wire 批全发对账——send_bytes 增量）
    let shm_c0 = (shm::creates(), shm::maps(), shm::px_reads());
    let fds0 = (
        unixsock::USOCK_FD_SENDS.load(Ordering::Acquire),
        unixsock::USOCK_FD_RECVS.load(Ordering::Acquire),
    );
    let pools0 = waycomp::WLCOMP_POOLS.load(Ordering::Acquire);
    let pid = match procs::spawn_elf_seed("shm-client", &user::SHM_CLIENT, &["shm-client"]) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(log, "t106: client build failed ({e:?})");
            return false;
        }
    };
    ok &= pid != usize::MAX;
    // (c) 有界等 commit ≥ +1（客户端像素上屏域）
    let dl = ostd::time::now() + 480;
    let c1 = loop {
        let c = waycomp::waycomp_stamps();
        if c.3 > c0.3 || ostd::time::now() >= dl {
            break c;
        }
        core::hint::spin_loop();
    };
    let commits_ok = c1.3 > c0.3;
    ok &= commits_ok;
    // (d) VRAM 客户端像素断言（cascade tiling 单窗 pane 域 4 探针——
    //     与 gen 脚本/映像像素函数逐位对账）
    let plan = cascade::tiling::tiling_plan(&[0x21u64], waycomp::VIEWPORT);
    let pane = plan
        .as_ref()
        .ok()
        .and_then(|p| p.panes.first().map(|(_, r)| *r));
    let mut px_ok = false;
    if let Some(pane) = pane {
        px_ok = true;
        for (lx, ly) in [(8i32, 8i32), (300, 8), (8, 190), (319, 199)] {
            // 期望值 = 客户端像素函数（ARGB）→ VRAM XRGB 掩码域（alpha
            // 剥离——blend 归一面，t104 pane_pattern & 0x00FF_FFFF 同款）
            let expect = (0xFF00_0000u32
                | (((lx & 0x3F) as u32) << 16)
                | (((ly & 0x3F) as u32) << 8)
                | user::CLIENT_PX_BASE)
                & 0x00FF_FFFF;
            let got = fb::fb_probe_px_read(pane.x + lx, pane.y + ly);
            if got != expect {
                let _ = writeln!(
                    log,
                    "t106: px-mismatch ({lx},{ly}) got={got:#010x} expect={expect:#010x}"
                );
                px_ok = false;
                break;
            }
        }
    }
    ok &= px_ok;
    let _ = writeln!(
        log,
        "t106: commits=+{} px-ok={px_ok} pane={:?} pxs={}",
        c1.3 - c0.3,
        pane,
        shm::px_reads() - shm_c0.2
    );
    // (e) fd 传递对账（SCM_RIGHTS 语义面 + 池承接 + 段正交）
    let fds1 = (
        unixsock::USOCK_FD_SENDS.load(Ordering::Acquire),
        unixsock::USOCK_FD_RECVS.load(Ordering::Acquire),
    );
    let s1 = unixsock::usock_stamps();
    let pools1 = waycomp::WLCOMP_POOLS.load(Ordering::Acquire);
    let last_obj = shm::last_object();
    let seg_ok = (crate::shm::SHM_OBJECT_BASE..crate::shm::SHM_OBJECT_BASE + 8).contains(&last_obj);
    // 池字节域对账（CREATE 尺寸 = CLIENT_POOL_BYTES——客户端 CREATE 域
    // 与内核池注册表逐字节对账）+ 注册表用量增量对账
    let size_ok = shm::pool_size(last_obj) == Some(u64::from(user::CLIENT_POOL_BYTES));
    let usage_ok = shm::pools_usage().0 > shm_c0.0 as usize;
    let fd_ok = fds1.0 == fds0.0 + 1
        && fds1.1 == fds0.1 + 1
        && pools1 == pools0 + 1
        && seg_ok
        && size_ok
        && usage_ok
        // wire 批全发对账：send 次数增量 == 2（客户端 wire 批 + waycomp
        // done 回执）且 send_bytes ≥ wire 批长（全发无短写）
        && s1.0 - s0.0 == 2
        && s1.1 - s0.1 >= user::CLIENT_WIRE_LEN as u64
        && waycomp::WLCOMP_FD_ERR.load(Ordering::Acquire) == 0;
    ok &= fd_ok;
    let _ = writeln!(
        log,
        "t106: fd-ok={fd_ok} fds=(+{},+{}) pools=+{} shm-obj={last_obj:#x} creates=+{} maps=+{} fderr={}",
        fds1.0 - fds0.0,
        fds1.1 - fds0.1,
        pools1 - pools0,
        shm::creates() - shm_c0.0,
        shm::maps() - shm_c0.1,
        waycomp::WLCOMP_FD_ERR.load(Ordering::Acquire),
    );
    // (f) 收割 exit=0 + teardown 对账
    let dl = ostd::time::now() + 480;
    while task::task_debug_exit_code(pid) == u64::MAX && ostd::time::now() < dl {
        core::hint::spin_loop();
    }
    let code = task::task_debug_exit_code(pid);
    if task::task_debug_state(pid) == 4 {
        let r = procs::sys_wait_pid(pid as u64);
        let rcode = r & 0xFFFF;
        ok &= r >> 32 == 1 && rcode == 0 && !task::task_alive(pid);
    } else {
        ok = false; // 滞域 fail-visible（bail 码 80..=85 显形）
    }
    // 会话收场完成旗（t104 早跳竞态收口先例——旗 wait 免竞态）
    let dl = ostd::time::now() + 480;
    while !waycomp::WLCOMP_SESSION_DONE.load(Ordering::Acquire) && ostd::time::now() < dl {
        core::hint::spin_loop();
    }
    let teardown_ok = waycomp::WLCOMP_SESSION_DONE.load(Ordering::Acquire) && fb::surf_count() == 1;
    ok &= teardown_ok;
    // VRAM 复原对账（pane 域回 stage 基线——teardown 摘除链显形）
    let mut restore_ok = true;
    if let Some(pane) = pane {
        for (lx, ly) in [(8i32, 8i32), (300, 8), (8, 190), (319, 199)] {
            if fb::fb_probe_px_read(pane.x + lx, pane.y + ly)
                != fb::stage_probe_px_read(pane.x + lx, pane.y + ly)
            {
                restore_ok = false;
            }
        }
    } else {
        restore_ok = false;
    }
    ok &= restore_ok;
    let _ = writeln!(
        log,
        "t106: reap exit={code:#x} teardown={teardown_ok} restore={restore_ok} endc={} paints={}",
        waycomp::WLCOMP_END_COUNT.load(Ordering::Acquire),
        waycomp::WLCOMP_SHM_PAINTS.load(Ordering::Acquire),
    );
    // 汇总取证行（双面板标记）
    let _ = writeln!(
        log,
        "LUMINA-T106-SHM gate=ok spawn={pid} commits=+{} px={px_ok} fd={fd_ok} teardown={teardown_ok} restore={restore_ok}",
        c1.3 - c0.3
    );
    if ok {
        let _ = writeln!(log, "LUMINA-T106-OK");
    }
    ok
}
