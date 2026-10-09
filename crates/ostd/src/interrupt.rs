//! 中断基础设施：IDT 门描述符 + 手写中断桩（HW-05 配套，CONTEXT 白名单外延）。
//!
//! rustc 1.99 的 `extern "x86-interrupt"` ABI 仍为实验特性
//! （`abi_x86_interrupt` 门控），故 M3 采用经典手写桩方案：
//!
//! - 每个受支持向量一段最小汇编桩（本模块 `stubs`，框架内核白名单）：
//!   仅保存 caller-saved 寄存器 + 显式对齐栈后调用 Rust 主体；
//! - Rust 主体（`extern "C"`）遵循 SysV ABI，自行保护 callee-saved；
//! - 异常桩路径为「诊断即退出」：向量号经寄存器传入主体，永不返回。
//!
//! 受支持向量（M3）：32 = IRQ0 定时器（tick + EOI）；0/6/13/14 =
//! #DE/#UD/#GP/#PF 致命异常（经故障钩子退出，见 [`set_fault_hook`]）。
//! 其余向量不注册——误触即三重故障，冒烟阶段以非 33 退出码暴露。
//!
//! M5 新增两类桩：
//! - `isr_ipi`（向量 0x40，LAPIC IPI）：定时器同构的对称保存/恢复，
//!   主体转交注册钩子（内核侧完成击落处理 + LAPIC EOI）；
//! - `isrf_pf_rec`（向量 14 的**可恢复**版）：完整保存 caller-saved 现场
//!   → 主体（rdi=CR2，rsi=错误码）返回 handled 标志 → handled 则对称
//!   恢复 + 丢弃错误码 + iretq（故障指令重执行），否则转原致命路径。
//!   未注册钩子时行为与致命版严格一致（现网语义零回归）。
//!
//! M6 新增/重构（per-CPU 统一调度器）：
//! - 抢占目标传递改为**栈上 [`PreemptPlan`]**：桩 `sub rsp,16` 预留、
//!   主体填写、同中断窗口内消费——天然 per-CPU（每核各用自己的栈），
//!   消除 M4 全局静态槽在双核同时抢占时互相覆盖的竞态；
//! - `isr_lapic_timer`（向量 0x41）：统一 per-CPU 抢占源（M6-A）；
//!   M10-A 前 PIT（向量 32）退化为纯墙钟打点，不驱动抢占；
//! - `isr_resched`（向量 0x42）：跨核重调度提示 IPI（唤醒 idle 核重新
//!   检查全局就绪队列；对忙核无副作用）。
//!
//! M10-A 扩展（per-CPU tick 账户，解除 ring3 时间面冻结）：
//! - `isr_timer`（向量 32）升级为**全上下文时间源**：LAPIC 定时器在
//!   ring3 驻留期间被 prepare_dispatch 屏蔽（TCG 双异常交付缺陷族规避，
//!   S31 记档），时间面（计账/老化/抢占）随之冻结；PIT 实测交付不触发
//!   缺陷族 → 桩尾部加装与 LAPIC 定时器同构的 PreemptPlan 交换路径，
//!   主体经墙钟钩子承载 per-CPU 账户 + 老化 + 接收核抢占；
//! - `isr_resched`（向量 0x42）加装同构交换路径：对侧核 ring3 驻留的
//!   抢占经 PREEMPT_REQ 旗 + 本 IPI 送达（交付实测安全：M6-M9 门铃
//!   持续交付于 ring3 驻留核）——三抢占源（LAPIC/PIT/RESCHED）全就位。

use core::sync::atomic::{AtomicUsize, Ordering};

/// 中断门选择子：启动 GDT 的 64 位代码段（见 kernel boot 汇编）。
pub const KERNEL_CS: u64 = 0x08;

/// 64 位中断门属性字节：P=1 | DPL=0 | type=0xE。
pub const GATE_INTERRUPT: u64 = 0x8E;

/// 单条 IDT 门描述符（16 字节：lo|hi 两个 u64）。
#[derive(Debug, Clone, Copy)]
pub struct IdtEntry {
    lo: u64,
    hi: u64,
}

impl IdtEntry {
    /// 空门（P=0）。
    pub const EMPTY: IdtEntry = IdtEntry { lo: 0, hi: 0 };

    /// 以处理程序线性地址构造中断门。
    ///
    /// 布局（Intel SDM Vol.3 §6.14）：lo = 偏移[15:0] | 选择子[31:16] |
    /// IST[39:32] | 属性[47:40] | 偏移[47:32]；hi = 偏移[63:48]。
    pub const fn interrupt(handler: u64) -> Self {
        Self {
            lo: (handler & 0xFFFF)
                | (KERNEL_CS << 16)
                | (GATE_INTERRUPT << 40)
                | ((handler & 0xFFFF_0000) << 32),
            hi: handler >> 32,
        }
    }

    /// 门是否指向给定处理程序地址（自检用）。
    pub const fn points_to(self, handler: u64) -> bool {
        (self.lo & 0xFFFF) | ((self.lo >> 32) & 0xFFFF_0000) | (self.hi << 32) == handler
    }
}

/// 256 向量 IDT（x86_64 恒定 4096 字节）。
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    /// 全空表。
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::EMPTY; 256],
        }
    }

    /// 以原始地址设置向量 `vector`（0..=255）的中断门；越界忽略（防御式）。
    pub fn set_raw(&mut self, vector: usize, handler_addr: u64) {
        if let Some(slot) = self.entries.get_mut(vector) {
            *slot = IdtEntry::interrupt(handler_addr);
        }
    }

    /// 向量 `vector` 的门是否指向 `handler_addr`（自检断言用）。
    pub fn entry_points_to(&self, vector: usize, handler_addr: u64) -> bool {
        self.entries
            .get(vector)
            .is_some_and(|e| e.points_to(handler_addr))
    }

    /// 表常量字节数（IDTR 界限 = 表长 − 1）。
    pub const fn byte_len() -> u16 {
        4096
    }

    /// 表基址（AP handoff / 诊断用；零 deref，safe）。
    pub fn base(&self) -> u64 {
        core::ptr::addr_of!(self.entries) as u64
    }

    /// 装载 IDTR（表基址按实际字段地址计算，与外部布局无关）。
    ///
    /// # Safety
    ///
    /// - 本表必须为静态存储期且装载后不再修改（IDTR 长期引用它）；
    /// - 装载期间不得并发修改（调用方持锁或处于关中断窗口）。
    pub unsafe fn load(&self) {
        let base = core::ptr::addr_of!(self.entries) as usize;
        crate::hw::intr::lidt(base, Self::byte_len() - 1);
    }
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

/// 抢占交换计划（repr(C)：与桩汇编偏移严格对应——old 在 +0、new 在 +8、
/// handoff 在 +16，M11-D 调度切换握手扩展）。
///
/// 生存期：位于中断桩的栈上临时区（`sub rsp,32` 预留），仅在单次中断
/// 窗口内有效——主体填写后立即由桩消费，无跨核、跨窗口引用。
/// 这使抢占目标选择天然 per-CPU：每核写的是自己的栈。
///
/// **handoff（M11-D）**：被抢占任务的切换握手旗地址（`SWITCHING[old]`，
/// u64 槽）。桩在旧上下文全部保存完成后一次性写 0（asm 单 Store）——
/// 从该指令起被抢占者才可被任意核安全拾取（现场已完整，拾取方恢复的
/// 是刚保存的连续帧）；旗置位期间拾取面（eligible）拒绝该槽位，
/// 根治「锁释放 → 物理切换」窗口内对侧核拾取陈旧上下文副本的竞态
/// （t37 裸机实证：自由跨核 spawn 子任务交叉命中，寄存器面腐坏）。
/// 桩在主体调用前将本槽清零，主体仅在真实切换时填写——防野指针。
#[repr(C)]
pub struct PreemptPlan {
    /// 被抢占任务的上下文（桩将全部现场存入）。
    pub old: *mut crate::task::TaskContext,
    /// 即将切入任务的上下文（桩从中加载现场）。
    pub new: *mut crate::task::TaskContext,
    /// 切换握手旗地址（M11-D；0 = 无旗可清——防御桩读垃圾指针）。
    pub handoff: *mut u64,
}

/// 受支持的中断桩。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stub {
    /// 向量 32：IRQ0 定时器。
    Timer,
    /// 向量 0：#DE 除法错误。
    FaultDe,
    /// 向量 6：#UD 非法指令。
    FaultUd,
    /// 向量 13：#GP 一般保护错误。
    FaultGp,
    /// 向量 14：#PF 页错误。
    FaultPf,
    /// 向量 10：#TS 无效 TSS（ring3 切栈失败诊断）。
    FaultTs,
    /// 向量 8：#DF 双重故障（向量化失败的最后一道防线）。
    FaultDf,
    /// 向量 0x40：LAPIC IPI（TLB 击落等核间命令，M5）。
    Ipi,
    /// 向量 14：可恢复 #PF（同 FaultPf 向量号；钩子可补映射后重执行）。
    FaultPfRec,
    /// 向量 0x41：LAPIC 定时器（统一 per-CPU 抢占源，M6-A）。
    LapicTimer,
    /// 向量 0x42：跨核重调度提示 IPI（唤醒 idle 核，M6-A）。
    Resched,
}

/// 桩符号地址（供 [`Idt::set_raw`] 注册）。
pub fn stub_addr(stub: Stub) -> u64 {
    // rustc 1.99 起 extern 块函数指针按 unsafe extern "C" fn() 处理；
    // 我们只需要其地址（注册进 IDT 门），永不直接调用，故取地址转型。
    unsafe extern "C" {
        fn isr_timer();
        fn isr_fault_de();
        fn isr_fault_ud();
        fn isr_fault_gp();
        fn isr_fault_pf();
        fn isr_fault_ts();
        fn isr_fault_df();
        fn isr_ipi();
        fn isrf_pf_rec();
        fn isr_lapic_timer();
        fn isr_resched();
    }
    let f: unsafe extern "C" fn() = match stub {
        Stub::Timer => isr_timer,
        Stub::FaultDe => isr_fault_de,
        Stub::FaultUd => isr_fault_ud,
        Stub::FaultGp => isr_fault_gp,
        Stub::FaultPf => isr_fault_pf,
        Stub::FaultTs => isr_fault_ts,
        Stub::FaultDf => isr_fault_df,
        Stub::Ipi => isr_ipi,
        Stub::FaultPfRec => isrf_pf_rec,
        Stub::LapicTimer => isr_lapic_timer,
        Stub::Resched => isr_resched,
    };
    f as usize as u64
}

static FAULT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// 注册致命异常钩子：收到未恢复异常时以（向量号, 故障 RIP, 诊断帧指针）
/// 调用并永不返回。诊断帧指针 = 异常桩入场时栈指针（#GP 桩传入，
/// 其余传 0）：[frame]=错误码、[frame+8]=RIP、[frame+16]=CS、
/// [frame+24]=RFLAGS、[frame+32]=故障时 RSP、[frame+40]=SS。
///
/// 注册时机 MUST 早于 `sti`（否则早期异常只停机不落盘诊断）。
pub fn set_fault_hook(hook: fn(u64, u64, u64) -> !) {
    FAULT_HOOK.store(hook as usize, Ordering::Release);
}

/// 故障出口：转交钩子；未注册则停机兜底。
fn fault_exit(vector: u64, rip: u64, aux: u64) -> ! {
    let hook = FAULT_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: 前置条件 —— 地址来自 set_fault_hook 存入的
        //          fn(u64,u64,u64)->!。
        // 不变式 —— Release/Acquire 配对保证读取到完整写入。
        // 并发 —— 注册只发生在 sti 之前。
        // 违反后果 —— 转移到伪造地址即跳入任意代码。
        let f: fn(u64, u64, u64) -> ! = unsafe { core::mem::transmute(hook) };
        f(vector, rip, aux);
    }
    loop {
        crate::hw::intr::halt();
    }
}

/// 中断桩（框架内核白名单汇编，SPEC 第十七章申请）。
///
/// - 定时器桩：9 个 caller-saved 入栈 → `and rsp, -16` 对齐 → 主体 →
///   `mov rsp, rbp` 一口气撤栈 → `iretq`；rbp 作锚点由主体按 ABI 保护。
/// - 异常桩：向量号置 edi → 主体（永不返回）→ 兜底 cli+hlt。
///   #GP/#PF 的错误码留在栈上无人读取（致命路径，随退出销毁）。
pub mod stubs {
    core::arch::global_asm! {
        ".text",
        // ---- 向量 32：IRQ0 定时器（M10-A 起：墙钟打点 + per-CPU tick 账户
        // + 抢占源；与 LAPIC 定时器桩同构的 PreemptPlan 交换路径）----
        // M6-M9 历史：纯墙钟打点，不驱动抢占（统一抢占源 = LAPIC 定时器）。
        // M10-A 重构：LAPIC 定时器在 ring3 驻留期间被 prepare_dispatch 屏蔽
        // （TCG 双异常交付缺陷族规避），时间面（计账/老化/抢占）随之冻结；
        // PIT 实测交付不触发缺陷族 → 升级为全上下文时间源。桩尾部与
        // isr_lapic_timer 同构：主体返回 eax=1 则从栈上 PreemptPlan 执行
        // 抢占交换（ring3 抢占首次成立）。
        // 纪律：保存/恢复 caller-saved 全集（rax,rcx,rdx,rsi,rdi,r8-r11）
        // 与 rbp；锚点 rbp 落在 10 个 push 之后（锚点 = 最后压入的 r11 槽），
        // 恢复走对称 POP 而非「mov rsp, rbp 跳过」——否则被中断代码的
        // 寄存器现场全毁。
        //
        // 抢占路径（M10-A 扩展）：栈上 PreemptPlan——桩 `sub rsp,16` 预留，
        // 主体（rdi = &plan）填写后返回 eax=1，桩从 [rsp]/[rsp+8] 取
        // 新旧上下文指针执行交换。计划生存期 = 单次中断窗口（栈上临时区），
        // 天然 per-CPU：双核同时抢占各自写各自的栈，零共享状态。
        ".globl isr_timer",
        "isr_timer:",
        "    push rbp",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rsi",
        "    push rdi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        "    mov rbp, rsp",
        "    and rsp, -16",
        "    sub rsp, 32",
        "    mov qword ptr [rsp + 16], 0",
        "    mov rdi, rsp",
        "    call isr_timer_body",
        "    test eax, eax",
        "    jnz 8f",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        "8:",
        // plan 位于 [rsp]/[rsp+8]/[rsp+16]（handoff = M11-D 握手旗）；
        // 旧上下文七槽保存完成后一次性清旗（asm 单 Store）——从本指令起
        // 被抢占者可被任意核安全拾取（M11-D 握手，根治锁释放→物理切换窗口）
        "    lea rax, [rip + 9f]",
        "    mov rdi, [rsp]",
        "    mov rsi, [rsp + 8]",
        "    mov [rdi + 0x00], rax",
        "    mov [rdi + 0x08], rbx",
        "    mov [rdi + 0x10], rbp",
        "    mov [rdi + 0x18], r12",
        "    mov [rdi + 0x20], r13",
        "    mov [rdi + 0x28], r14",
        "    mov [rdi + 0x30], r15",
        "    mov [rdi + 0x38], rbp",
        "    mov rcx, [rsp + 16]",
        "    test rcx, rcx",
        "    jz 12f",
        "    mov qword ptr [rcx], 0",
        "12:",
        "    mov rbx, [rsi + 0x08]",
        "    mov rbp, [rsi + 0x10]",
        "    mov r12, [rsi + 0x18]",
        "    mov r13, [rsi + 0x20]",
        "    mov r14, [rsi + 0x28]",
        "    mov r15, [rsi + 0x30]",
        "    mov rsp, [rsi + 0x38]",
        "    push QWORD PTR [rsi + 0x00]",
        "    ret",
        // 9: = .resume（被抢占任务的续点，语义同 LAPIC 定时器桩）
        "9:",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        // ---- LAPIC 定时器桩（向量 0x41，M6-A：统一 per-CPU 抢占源）----
        // 与定时器桩同构：对称保存 caller-saved + rbp → 主体（rdi = &plan）
        // 返回 eax=1 则从栈上 PreemptPlan 取新旧上下文执行抢占交换。
        // 标签 6/7 与定时器桩的 4 隔离（同一 global_asm 块内标签唯一）。
        ".globl isr_lapic_timer",
        "isr_lapic_timer:",
        "    push rbp",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rsi",
        "    push rdi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        "    mov rbp, rsp",
        "    and rsp, -16",
        "    sub rsp, 32",
        "    mov qword ptr [rsp + 16], 0",
        "    mov rdi, rsp",
        "    call isr_lapic_timer_body",
        "    test eax, eax",
        "    jnz 6f",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        "6:",
        // plan 位于 [rsp]/[rsp+8]/[rsp+16]（handoff 同 M11-D 握手契约，
        // 与定时器桩 12 标签隔离——同一 global_asm 块内标签唯一）
        "    lea rax, [rip + 7f]",
        "    mov rdi, [rsp]",
        "    mov rsi, [rsp + 8]",
        "    mov [rdi + 0x00], rax",
        "    mov [rdi + 0x08], rbx",
        "    mov [rdi + 0x10], rbp",
        "    mov [rdi + 0x18], r12",
        "    mov [rdi + 0x20], r13",
        "    mov [rdi + 0x28], r14",
        "    mov [rdi + 0x30], r15",
        "    mov [rdi + 0x38], rbp",
        "    mov rcx, [rsp + 16]",
        "    test rcx, rcx",
        "    jz 13f",
        "    mov qword ptr [rcx], 0",
        "13:",
        "    mov rbx, [rsi + 0x08]",
        "    mov rbp, [rsi + 0x10]",
        "    mov r12, [rsi + 0x18]",
        "    mov r13, [rsi + 0x20]",
        "    mov r14, [rsi + 0x28]",
        "    mov r15, [rsi + 0x30]",
        "    mov rsp, [rsi + 0x38]",
        "    push QWORD PTR [rsi + 0x00]",
        "    ret",
        // 7: = .resume（被抢占任务的续点，语义同 M4 设计）
        "7:",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        // ---- 跨核重调度提示 IPI 桩（向量 0x42，M6-A；M10-A 扩展）----
        // 基础语义：唤醒 halt 中的 idle 核；主体 EOI + 置重调度标志。
        // M10-A 扩展：与定时器桩同构的 PreemptPlan 交换路径——对侧核
        // ring3 驻留期间 LAPIC 定时器被屏蔽（TCG 缺陷族），墙钟钩子判定
        // 其需抢占时置 PREEMPT_REQ 并发本 IPI；主体消费旗标后按抢占规则
        // 填写 plan（ring3 交付实测安全：M6-M9 spawn/分页门铃持续交付于
        // ring3 驻留核），桩完成抢占交换。
        ".globl isr_resched",
        "isr_resched:",
        "    push rbp",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rsi",
        "    push rdi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        "    mov rbp, rsp",
        "    and rsp, -16",
        "    sub rsp, 32",
        "    mov qword ptr [rsp + 16], 0",
        "    mov rdi, rsp",
        "    call isr_resched_body",
        "    test eax, eax",
        "    jnz 10f",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        "10:",
        "    lea rax, [rip + 11f]",
        "    mov rdi, [rsp]",
        "    mov rsi, [rsp + 8]",
        "    mov [rdi + 0x00], rax",
        "    mov [rdi + 0x08], rbx",
        "    mov [rdi + 0x10], rbp",
        "    mov [rdi + 0x18], r12",
        "    mov [rdi + 0x20], r13",
        "    mov [rdi + 0x28], r14",
        "    mov [rdi + 0x30], r15",
        "    mov [rdi + 0x38], rbp",
        "    mov rcx, [rsp + 16]",
        "    test rcx, rcx",
        "    jz 14f",
        "    mov qword ptr [rcx], 0",
        "14:",
        "    mov rbx, [rsi + 0x08]",
        "    mov rbp, [rsi + 0x10]",
        "    mov r12, [rsi + 0x18]",
        "    mov r13, [rsi + 0x20]",
        "    mov r14, [rsi + 0x28]",
        "    mov r15, [rsi + 0x30]",
        "    mov rsp, [rsi + 0x38]",
        "    push QWORD PTR [rsi + 0x00]",
        "    ret",
        "11:",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        // ---- 致命异常桩（永不返回）----
        // 约定：rstore 诊断前先取 [rsp] = 故障 RIP（中断帧首字段）。
        // #DE/#UD 无错误码，[rsp] 即 RIP；#GP/#PF 有错误码，
        // RIP 位于 [rsp+8]。诊断用 rip 一律从对应偏移提取。
        ".globl isr_fault_de",
        "isr_fault_de:",
        "    mov edi, 0",
        "    mov rsi, [rsp]",
        "    xor edx, edx",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        ".globl isr_fault_ud",
        "isr_fault_ud:",
        "    mov edi, 6",
        "    mov rsi, [rsp]",
        "    xor edx, edx",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        ".globl isr_fault_gp",
        "isr_fault_gp:",
        "    mov edi, 13",
        "    mov rsi, [rsp+8]",
        "    mov rdx, rsp",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        ".globl isr_fault_pf",
        "isr_fault_pf:",
        "    mov edi, 14",
        "    mov rsi, [rsp+8]",
        "    xor edx, edx",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        ".globl isr_fault_ts",
        "isr_fault_ts:",
        "    mov edi, 10",
        "    mov rsi, [rsp+8]",
        "    xor edx, edx",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        ".globl isr_fault_df",
        "isr_fault_df:",
        "    mov edi, 8",
        "    mov rsi, [rsp+8]",
        "    xor edx, edx",
        "    sub rsp, 8",
        "    and rsp, -16",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        // ---- LAPIC IPI 桩（向量 0x40，M5）----
        // 定时器同构：对称保存 caller-saved + rbp → 主体 → 对称恢复 → iretq。
        // EOI 不在本桩做（PIC/LAPIC 归属由内核钩子决定）。
        ".globl isr_ipi",
        "isr_ipi:",
        "    push rbp",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rsi",
        "    push rdi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        "    mov rbp, rsp",
        "    and rsp, -16",
        "    call isr_ipi_body",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    iretq",
        // ---- 可恢复 #PF 桩（向量 14，M5）----
        // 入场（CPU 推入错误码后）：[rsp]=错误码、[rsp+8]=RIP。
        // 布局：10 次 push 后 rbp=锚点，错误码位于 [rbp+80]（见 offset 注释）。
        // handled：对称恢复 → add rsp,8 丢弃错误码 → iretq（重执行故障指令）；
        // 未 handled：转致命主体（向量 14，RIP 取 [rbp+88]），永不返回。
        ".globl isrf_pf_rec",
        "isrf_pf_rec:",
        "    push rbp",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rsi",
        "    push rdi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        "    mov rbp, rsp",
        "    and rsp, -16",
        "    mov rdi, cr2",
        "    mov rsi, [rbp+80]",
        "    call isrf_pf_rec_body",
        "    test eax, eax",
        "    jnz 5f",
        "    mov rdi, 14",
        "    mov rsi, [rbp+88]",
        "    call isr_fault_body",
        "    cli",
        "    hlt",
        "5:",
        "    mov rsp, rbp",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rdi",
        "    pop rsi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    pop rbp",
        "    add rsp, 8",
        "    iretq",
    }

    /// 定时器钩子：返回 true 表示已填写 plan 并完成切换目标布置
    /// （桩随即从栈上 plan 取指针执行抢占交换）。
    static TIMER_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// 注册定时器钩子（M6：仅 LAPIC 定时器主体消费；PIT 主体不再调用）。
    pub fn set_timer_hook(hook: fn(&mut super::PreemptPlan) -> bool) {
        TIMER_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// 墙钟钩子（M10-A）：IRQ0 主体消费——per-CPU tick 账户 + 老化扫描
    /// + 本核（接收核）抢占判定。返回 true = 已填写 plan（桩执行交换）。
    static WALL_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// 注册墙钟钩子（内核调度器初始化时调用；未注册时 PIT 退回纯墙钟）。
    pub fn set_wall_hook(hook: fn(&mut super::PreemptPlan) -> bool) {
        WALL_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// RESCHED 抢占钩子（M10-A）：RESCHED IPI 主体在重调度提示钩子之后
    /// 消费本核 PREEMPT_REQ 旗——置位则按抢占规则填写 plan。
    static RESCHED_PREEMPT_HOOK: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    /// 注册 RESCHED 抢占钩子（内核调度器初始化时调用）。
    pub fn set_resched_preempt_hook(hook: fn(&mut super::PreemptPlan) -> bool) {
        RESCHED_PREEMPT_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// 重调度提示钩子（M6-A：RESCHED IPI 主体；置跨核唤醒标志）。
    static RESCHED_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// 注册重调度提示钩子（内核调度器初始化时调用）。
    pub fn set_resched_hook(hook: fn()) {
        RESCHED_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// IRQ0 主体（向量 32）：墙钟打点 + 主片 EOI + 墙钟钩子（M10-A）。
    ///
    /// plan 参数由桩汇编契约传入（rdi = &plan）；返回 1 = 已填写 plan
    /// （桩执行抢占交换）。M6-M10 历史语义：M6 起纯墙钟不再驱动抢占；
    /// M10-A 起 PIT 升级为全上下文时间源（账户/老化/接收核抢占）。
    #[no_mangle]
    extern "C" fn isr_timer_body(plan: &mut super::PreemptPlan) -> u32 {
        crate::time::tick();
        crate::hw::pic::eoi_master();
        let hook = WALL_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_wall_hook 存入的
            //          fn(&mut PreemptPlan) -> bool。
            // 不变式 —— Release/Acquire 配对；注册先于 PIT 抢占消费。
            // 并发 —— IRQ0 仅交付接收核（PIC 路由 BSP）；plan 在本核栈上。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn(&mut super::PreemptPlan) -> bool = unsafe { core::mem::transmute(hook) };
            return u32::from(f(plan));
        }
        0
    }

    /// LAPIC 定时器主体（向量 0x41）：LAPIC EOI + 定时器钩子。
    ///
    /// 返回 1 = 已填写 plan（桩执行抢占交换）；0 = 放行。
    #[no_mangle]
    extern "C" fn isr_lapic_timer_body(plan: &mut super::PreemptPlan) -> u32 {
        crate::hw::lapic::eoi();
        let hook = TIMER_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_timer_hook 存入的
            //          fn(&mut PreemptPlan) -> bool。
            // 不变式 —— Release/Acquire 配对；注册先于定时器启动。
            // 并发 —— 各核仅在自身中断窗口内调用（plan 在本核栈上）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn(&mut super::PreemptPlan) -> bool = unsafe { core::mem::transmute(hook) };
            return u32::from(f(plan));
        }
        0
    }

    /// RESCHED IPI 主体（向量 0x42）：LAPIC EOI + 重调度提示钩子 +
    /// 抢占钩子（M10-A：消费本核 PREEMPT_REQ，置位则填写 plan）。
    ///
    /// 返回 1 = 已填写 plan（桩执行抢占交换）；0 = 放行。
    #[no_mangle]
    extern "C" fn isr_resched_body(plan: &mut super::PreemptPlan) -> u32 {
        crate::hw::lapic::eoi();
        let hook = RESCHED_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_resched_hook 存入的 fn()。
            // 不变式 —— Release/Acquire 配对；注册先于任何 RESCHED IPI。
            // 并发 —— 各核处理各自收到的 IPI（钩子只写本核可见状态）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn() = unsafe { core::mem::transmute(hook) };
            f();
        }
        let preempt = RESCHED_PREEMPT_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if preempt != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_resched_preempt_hook 存入的
            //          fn(&mut PreemptPlan) -> bool。
            // 不变式 —— Release/Acquire 配对；注册先于任何抢占请求。
            // 并发 —— 各核仅在自身 IPI 窗口内调用（plan 在本核栈上）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn(&mut super::PreemptPlan) -> bool = unsafe { core::mem::transmute(preempt) };
            return u32::from(f(plan));
        }
        0
    }

    /// 致命异常主体：转交流程（携带故障 RIP 与诊断帧；见 [`super::fault_exit`]）。
    #[no_mangle]
    extern "C" fn isr_fault_body(vector: u64, rip: u64, aux: u64) -> ! {
        super::fault_exit(vector, rip, aux)
    }

    /// IPI 钩子（M5：内核侧击落处理 + LAPIC EOI；向量 0x40 窗口内调用）。
    static IPI_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// 注册 IPI 钩子（内核 SMP 初始化时调用；注册前收到 IPI 将被静默丢弃）。
    pub fn set_ipi_hook(hook: fn()) {
        IPI_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// IPI 主体：转交钩子（EOI 由钩子负责——PIC/LAPIC 归属属内核策略）。
    #[no_mangle]
    extern "C" fn isr_ipi_body() {
        let hook = IPI_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_ipi_hook 存入的 fn()。
            // 不变式 —— Release/Acquire 配对；注册只发生在首次 IPI 之前。
            // 并发 —— IPI 窗口串行（每核各自处理各自收到的 IPI）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn() = unsafe { core::mem::transmute(hook) };
            f();
        }
    }

    /// 可恢复 #PF 钩子（M5：按需分页；参数 = CR2 故障地址 + 错误码，
    /// 返回 true 表示已修复映射、桩将重执行故障指令）。
    static PF_REC_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// 注册可恢复 #PF 钩子（内核 VMM 初始化时调用；未注册时 #PF 保持
    /// 致命语义——与 M3/M4 行为严格一致）。
    pub fn set_pf_rec_hook(hook: fn(u64, u64) -> bool) {
        PF_REC_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
    }

    /// 可恢复 #PF 主体：返回 1 = 已处理（桩恢复现场重执行），0 = 转致命。
    #[no_mangle]
    extern "C" fn isrf_pf_rec_body(cr2: u64, error_code: u64) -> u32 {
        let hook = PF_REC_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_pf_rec_hook 存入的
            //          fn(u64, u64) -> bool。
            // 不变式 —— Release/Acquire 配对；注册先于任何可恢复 #PF。
            // 并发 —— #PF 天然串行于当前核；钩子自身不得再触发 #PF
            //         （其映射路径走物理地址直写，不依赖 MMU）。
            // 违反后果 —— 递归 #PF 将升级为 #DF（致命，冒烟非 33 退出）。
            let f: fn(u64, u64) -> bool = unsafe { core::mem::transmute(hook) };
            return u32::from(f(cr2, error_code));
        }
        0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Idt, IdtEntry};

    #[test]
    fn interrupt_gate_encodes_handler() {
        let addr: u64 = 0x1_2345_6789_ABCD;
        let e = IdtEntry::interrupt(addr);
        assert!(e.points_to(addr));
        assert!(!e.points_to(0xDEAD_BEEF));
    }

    #[test]
    fn gate_layout_matches_sdm() {
        // 0x1000：低 16 位与 [47:32] 承载；属性 0x8E 在 [47:40]；IST=0
        let e = IdtEntry::interrupt(0x1000);
        assert!(e.points_to(0x1000));
        // 空门不指向任何非零地址
        assert!(!IdtEntry::EMPTY.points_to(0x1000));
    }

    #[test]
    fn set_raw_and_check() {
        let mut idt = Idt::new();
        idt.set_raw(32, 0x2000);
        idt.set_raw(14, 0x3000);
        assert!(idt.entry_points_to(32, 0x2000));
        assert!(idt.entry_points_to(14, 0x3000));
        assert!(!idt.entry_points_to(33, 0x2000));
        idt.set_raw(256, 0x4000); // 越界：防御式忽略
        assert_eq!(Idt::byte_len(), 4096);
    }
}
