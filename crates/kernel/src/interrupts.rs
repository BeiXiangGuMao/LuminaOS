//! 中断子系统初始化（M3）。
//!
//! 职责链：故障钩子注册 → IDT 构建（定时器 + 四类致命异常）→ `lidt` →
//! PIC 重映射（仅开放 IRQ0）→ PIT 编程（100 Hz）→ `sti`。
//! 全模块 safe Rust：机器状态操作收口于 `ostd::hw`（HW-05…07），
//! 桩汇编收口于 `ostd::interrupt::stubs`。
//!
//! IDT 以 SpinLock 承载（内部可变性 + 稳定地址）：持锁完成门表填写与
//! IDTR 装载；装载后本模块再不获取写锁，表内容冻结。
//!
//! M3 取舍：无抢占——IRQ0 只做节拍打点与 EOI；任务切换为协作式
//! （见 task.rs）。抢占式调度钩子随 M4+ SMP 一起落地。

use core::fmt::Write as _;

use ostd::interrupt::{Idt, Stub};
use ostd::sync::SpinLock;

use crate::console::DualLog;
use crate::fail_exit;

/// 定时器目标频率（Hz）：100 Hz 节拍，兼顾延迟与冒烟时长。
pub const TIMER_HZ: u32 = 100;

/// 全局 IDT：静态存储期（IDTR 长期引用其内部 entries 地址）。
static IDT: SpinLock<Idt> = SpinLock::new(Idt::new());

/// 初始化并开启中断（返回 PIT 实际编程频率，供自检断言）。
pub fn init_and_enable(log: &mut DualLog) -> u32 {
    // 故障钩子先行：任何早期异常都能落盘诊断并以失败码退出
    ostd::interrupt::set_fault_hook(fault_hook);

    // 构建门表并装载：仅注册受支持向量，其余空门（误触即三重故障，
    // QEMU -no-reboot 下以非 33 退出码暴露给冒烟门禁）
    let timer_addr = ostd::interrupt::stub_addr(Stub::Timer);
    let pf_rec_addr = ostd::interrupt::stub_addr(Stub::FaultPfRec);
    let ipi_addr = ostd::interrupt::stub_addr(Stub::Ipi);
    let lapic_timer_addr = ostd::interrupt::stub_addr(Stub::LapicTimer);
    let resched_addr = ostd::interrupt::stub_addr(Stub::Resched);
    let kbd_addr = ostd::interrupt::stub_addr(Stub::Irq1);
    let gate_ok = {
        let mut idt = IDT.lock();
        idt.set_raw(32, timer_addr);
        idt.set_raw(0, ostd::interrupt::stub_addr(Stub::FaultDe));
        // 向量 1：#DB 透明探针（M22-③ DR0 写监视点——cont 槽第二写者追捕）
        idt.set_raw(1, ostd::interrupt::stub_addr(Stub::FaultDb));
        idt.set_raw(6, ostd::interrupt::stub_addr(Stub::FaultUd));
        idt.set_raw(13, ostd::interrupt::stub_addr(Stub::FaultGp));
        // 向量 14：可恢复 #PF 桩（M5）。未注册恢复钩子时与致命版行为
        // 严格一致（主体返回 0 → 转原致命路径），现网语义零回归。
        idt.set_raw(14, pf_rec_addr);
        idt.set_raw(10, ostd::interrupt::stub_addr(Stub::FaultTs));
        idt.set_raw(8, ostd::interrupt::stub_addr(Stub::FaultDf));
        // 向量 0x40：LAPIC IPI（TLB 击落；M5）
        idt.set_raw(usize::from(ostd::hw::lapic::IPI_VECTOR), ipi_addr);
        // 向量 0x41：LAPIC 定时器（统一 per-CPU 抢占源；M6-A）
        idt.set_raw(usize::from(ostd::hw::lapic::TIMER_VECTOR), lapic_timer_addr);
        // 向量 0x42：跨核重调度提示 IPI（M6-A）
        idt.set_raw(usize::from(ostd::hw::lapic::RESCHED_VECTOR), resched_addr);
        // 向量 33：IRQ1 PS/2 键盘（M23-①；PIC 主片，桩内 EOI）
        idt.set_raw(33, kbd_addr);
        let ok = idt.entry_points_to(32, timer_addr)
            && idt.entry_points_to(0, ostd::interrupt::stub_addr(Stub::FaultDe))
            && idt.entry_points_to(14, pf_rec_addr)
            && idt.entry_points_to(33, kbd_addr)
            && idt.entry_points_to(usize::from(ostd::hw::lapic::IPI_VECTOR), ipi_addr)
            && idt.entry_points_to(usize::from(ostd::hw::lapic::TIMER_VECTOR), lapic_timer_addr)
            && idt.entry_points_to(usize::from(ostd::hw::lapic::RESCHED_VECTOR), resched_addr);
        // SAFETY: IDT 为静态存储期（SpinLock 静态承载），装载后本模块
        //         不再修改；装载在持锁窗口内完成，无并发写者。
        unsafe { idt.load() };
        ok
    };
    let _ = writeln!(log, "idt loaded @ {timer_addr:#x} gates-ok={gate_ok}");

    let actual_hz = ostd::hw::pit::init_channel0(TIMER_HZ);
    ostd::hw::pic::remap_timer_only();
    // M23-①：IRQ1 解 mask + 键盘钩子注册（t64 前就位；批跑无键入无副作用）
    ostd::hw::pic::unmask_irq1();
    crate::kbd::init();
    let _ = writeln!(log, "pic remapped (irq0+irq1), pit {actual_hz} Hz");

    // 抢占钩子（M6-A）：LAPIC 定时器主体消费（向量 0x41）；M10-A 起本钩子
    // 为纯抢占判定（内核上下文源；计账/老化已迁墙钟钩子）。
    ostd::interrupt::stubs::set_timer_hook(crate::task::timer_hook);
    // 墙钟钩子（M10-A）：PIT 主体消费（向量 32）——per-CPU tick 账户 +
    // 老化扫描唯一站点 + 接收核全上下文抢占（PIT 桩 PreemptPlan 交换路径）。
    ostd::interrupt::stubs::set_wall_hook(crate::task::wall_hook);
    // 跨核重调度提示钩子（M6-A）：置 RESCHED 送达计数（自检 21 证据）
    ostd::interrupt::stubs::set_resched_hook(crate::task::resched_hook);
    // RESCHED 抢占钩子（M10-A）：消费墙钟钩子的对侧核抢占请求
    // （PREEMPT_REQ 旗 + 定向 IPI；对侧 ring3 驻留期间唯一可达抢占通道）。
    ostd::interrupt::stubs::set_resched_preempt_hook(crate::task::resched_preempt_hook);

    // sti 之后 IRQ0 即开始打点
    ostd::hw::intr::enable();
    actual_hz
}

/// 关闭中断（退出路径/自检收尾）。
pub fn disable() {
    ostd::hw::intr::disable();
}

/// 定时器门自检（由 main 自检 10 调用；装载后表已冻结）。
pub fn timer_gate_ok() -> bool {
    let idt = IDT.lock();
    idt.entry_points_to(32, ostd::interrupt::stub_addr(Stub::Timer))
}

/// IDT 位置（AP trampoline handoff 写入用；M5）。
pub fn idt_location() -> (u64, u16) {
    let idt = IDT.lock();
    (idt.base(), ostd::interrupt::Idt::byte_len() - 1)
}

/// 致命异常钩子：落盘诊断后以失败码退出（永不返回）。
/// `aux` = 异常桩入场帧指针（#GP/#PF 设置，M18-① 起 #PF 两路径补齐）：
/// 据此转储被 iretq 消费的中断帧（RIP/CS/RFLAGS/RSP/SS）——M7 调试期
/// 取证面，保留为长期诊断。
///
/// **M18-① 取证面加固**：aux 经合法性门后才转储（v0.18 及之前可恢复
/// #PF 致命分支传入寄存器残渣，转储面读野值指针即产生伪影——「实模式
/// IVT 形态帧」与「二次 #PF cr2=-0x28」均为取证面自身行为，非系统
/// 状态；残渣指向恒等映射低物理区时读到的正是 IVT 内容，指向野值时
/// read_u64(aux) 自身即 #PF）。门限依据：QEMU -m 256M + 恒等映射低
/// 1 GiB——内核栈与帧必落 256 MiB 物理界内且 8 字节对齐。
fn fault_hook(vector: u64, rip: u64, aux: u64) -> ! {
    // 不得分配（异常现场不可信）：使用免分配串口直写
    let mut serial = crate::console::SerialPort::com1();
    serial.init();
    // M22-① census 首发短行：先于一切长转储落盘——转储多行在串口
    // 交叠/进程清理下最易丢失，census 短行保住项号+vector+rip 定位
    // 信息（败点名内化进内核计数行）。
    crate::census::fault_mark(vector, rip);
    let _ = writeln!(serial, "LUMINA-FAULT vector={vector} rip={rip:#x}");
    crate::census::write_to(&mut serial);
    if vector == 14 {
        // #PF 取证：CR2 = 故障线性地址（HW-04 扩展面；定位桩/表路径缺页）
        let _ = writeln!(serial, "  cr2={:#x}", ostd::hw::control::read_cr2());
        // M33-T1 四级表项取证（免分配 phys 直读）：P=1 写拒绝类故障的
        // 叶项定性（present/RW/US/COW 位与中间层 U 位链全显形）
        let cr2 = ostd::hw::control::read_cr2();
        let root = ostd::hw::control::read_cr3() & !0xFFF;
        let idx = |s: u32| ((cr2 >> s) & 0x1FF) * 8;
        const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        let e4 = ostd::hw::phys::read_u64(root + idx(39));
        let e3 = if e4 & 1 != 0 {
            ostd::hw::phys::read_u64((e4 & ADDR_MASK) + idx(30))
        } else {
            0
        };
        let e2 = if e3 & 1 != 0 {
            ostd::hw::phys::read_u64((e3 & ADDR_MASK) + idx(21))
        } else {
            0
        };
        let e1 = if e3 & 1 != 0 && e2 & 1 != 0 && e2 & 0x80 == 0 {
            ostd::hw::phys::read_u64((e2 & ADDR_MASK) + idx(12))
        } else {
            0
        };
        let _ = writeln!(
            serial,
            "  pf-walk pml4e={e4:#x} pdpte={e3:#x} pde={e2:#x} pte={e1:#x}"
        );
    }
    let aux_sane = (0x1000..0x1000_0000).contains(&aux) && aux & 7 == 0;
    if aux != 0 && !aux_sane {
        // 门拒：aux 不像有效内核帧——打印原值即止，绝不解引用
        // （v0.18 伪影链的根治面：宁可少读，不可再制造二次 #PF）
        let _ = writeln!(serial, "  aux-suspect={aux:#x} (dump suppressed)");
    }
    if aux != 0 && aux_sane {
        let err = ostd::hw::phys::read_u64(aux);
        let _ = writeln!(serial, "  err-code={err:#x}");
        let f = aux + 8; // 越过错误码槽：iretq 帧基址（RIP/CS/RFLAGS/RSP/SS）
        let rip2 = ostd::hw::phys::read_u64(f);
        let cs = ostd::hw::phys::read_u64(f + 8);
        let rfl = ostd::hw::phys::read_u64(f + 16);
        let rsp2 = ostd::hw::phys::read_u64(f + 24);
        let ss = ostd::hw::phys::read_u64(f + 32);
        let _ = writeln!(
            serial,
            "  iretq-frame: rip={rip2:#x} cs={cs:#x} rflags={rfl:#x} rsp={rsp2:#x} ss={ss:#x}"
        );
        // 扩展转储：iretq 帧前后各 5 quad + 桩帧区（定位改写者落点）
        for i in -5i64..12 {
            let a = (f as i64 + i * 8) as u64;
            let _ = writeln!(serial, "  stk{a:#x} = {:#x}", ostd::hw::phys::read_u64(a));
        }
    }
    fail_exit(vector)
}
