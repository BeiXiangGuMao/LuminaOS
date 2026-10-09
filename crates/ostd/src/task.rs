//! 协作式任务上下文切换（M3）。
//!
//! 依据 SPEC 第十七章：上下文切换的寄存器保存/恢复无法以 safe Rust
//! 表达，机器级部分集中在本模块（申请编号 CONTEXT-01）：
//!
//! - [`TaskContext`]：被调度切换的寄存器面（callee-saved + rsp）；
//! - [`context_switch`]：保存旧上下文 → 载入新上下文 → `ret` 跳入
//!   新任务的续点（对新建任务即 trampoline 入口）。
//!
//! 设计取舍（M3 单核协作式）：只切换 callee-saved 寄存器与栈指针；
//! 调用方约定在切换窗口内关中断（M3 无抢占，中断不会切入切换路径）。
//! caller-saved 寄存器由 SysV ABI 的普通函数调用约定天然交接。

/// 被调度保存的任务上下文（布局与 [`context_switch`] 偏移严格对应）。
///
/// 续点（continuation）显式入档：恢复路径为 `mov rsp, [new.rsp];
/// push [new.cont]; ret`——**不依赖编译器栈布局**（尾调用/对齐垫
/// 会使「ret 弹当前栈顶」失效，M3 开发期实测踩坑后改为显式续点）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    /// 续点地址（0x00）：本任务下次被切回时 `ret` 的落点。
    pub cont: u64,
    /// RBX（0x08）。
    pub rbx: u64,
    /// RBP（0x10）。
    pub rbp: u64,
    /// R12（0x18）。
    pub r12: u64,
    /// R13（0x20）。
    pub r13: u64,
    /// R14（0x28）。
    pub r14: u64,
    /// R15（0x30）。
    pub r15: u64,
    /// RSP（0x38）：保存时的栈指针（续点之上是调用方帧，之下作废）。
    pub rsp: u64,
}

impl TaskContext {
    /// 停滞上下文（从未运行）。
    pub const fn stopped() -> Self {
        Self {
            cont: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
        }
    }

    /// 为新建任务铺设初始上下文：续点 = trampoline；rsp 留出 16 字节
    /// 暂存槽。恢复时 `push cont; ret` 后入口处 `rsp % 16 == 8`
    /// （SysV 函数入口约定，栈顶 16 对齐前提下）。
    ///
    /// # 参数
    /// - `stack_top_bytes`：任务栈顶的绝对地址（16 字节对齐）；
    /// - `trampoline`：任务首函数（`extern "C"`，永不返回）。
    pub fn boot_new(stack_top_bytes: u64, trampoline: extern "C" fn() -> !) -> Self {
        Self {
            cont: trampoline as *const () as usize as u64,
            // 恢复时 push cont 落在 [top-8]，ret 后入口 rsp = top-8
            // ≡ 8 (mod 16) —— 恰为 SysV 函数入口约定
            rsp: stack_top_bytes,
            ..Self::stopped()
        }
    }
}

/// 上下文交换机器面（CONTEXT-01）：整体以 global_asm 固化——
/// **零编译器序言**，入口处 `[rsp]` 恒为本符号的返回地址（或尾调用
/// 链上游的返回地址，二者都是正确的续点），不存在序言 push 偏移。
///
/// 调用形态（call 或尾 jmp 均正确）：
/// - 保存：`cont = [rsp]`、`rsp_slot = rsp + 8`（预留给恢复时的
///   push cont 落位）；
/// - **握手清旗（M11-D）**：旧上下文七槽全部保存完成后，若第三参数
///   （握手旗地址）非空则单 Store 清零——从该指令起旧任务可被任意核
///   安全拾取（与抢占桩的 PreemptPlan.handoff 同一契约：旗生命周期 =
///   重排队 → 现场保存完成，清除者 = 切换机器自身，无后继配合项，
///   根治「锁释放 → 物理切换」跨核拾取窗口且无 catch-22）；
/// - 恢复：`rsp = new.rsp_slot` → `push new.cont` → `ret`。
///
/// # SAFETY（调用方义务）
/// 两栈互异且有效；切换窗口无并发调度者；`new` 为新建任务时其
/// `cont/rsp` 槽已由 [`TaskContext::boot_new`] 铺设；`handoff` 非空时
/// 必须指向稳定的 u64 旗槽（旧任务存续期内有效）。
pub fn switch_deferred(pair: SwitchPair) {
    // SAFETY: 前置条件 —— SwitchPair 构造契约（稳定指针、两栈互异、
    //          协作窗口、握手旗生存期）由调度器设计保证。
    // 不变式 —— 旧 ctx 七槽先于握手清旗、清旗先于新 ctx 加载全部
    //          写回；续点显式传递，与编译器栈布局无关。
    // 并发 —— 切换期间 IF=0（调用方窗口）；旗清后旧任务跨核可拾取
    //          （现场已完整，拾取方恢复的是连续帧）。
    // 违反后果 —— 指针失效即写穿任意内存（SwitchPair 纪律封死）。
    unsafe { lumina_context_switch(pair.old, pair.new, pair.handoff) }
}

core::arch::global_asm! {
    ".text",
    ".globl lumina_context_switch",
    "lumina_context_switch:",
    // rdi = old ctx, rsi = new ctx, rdx = 握手旗地址（0 = 无旗；SysV 前三整型槽）
    "    mov rax, [rsp]",
    "    mov [rdi + 0x00], rax",
    "    mov [rdi + 0x08], rbx",
    "    mov [rdi + 0x10], rbp",
    "    mov [rdi + 0x18], r12",
    "    mov [rdi + 0x20], r13",
    "    mov [rdi + 0x28], r14",
    "    mov [rdi + 0x30], r15",
    "    lea rcx, [rsp + 8]",
    "    mov [rdi + 0x38], rcx",
    // ---- M11-D 握手清旗：旧现场保存完成 → 旗清零（后继未运行前旧任务
    //      已可被任意核拾取；置位面 = 重排队点，清除面 = 本单 Store）----
    "    test rdx, rdx",
    "    jz 1f",
    "    mov qword ptr [rdx], 0",
    "1:",
    "    mov rbx, [rsi + 0x08]",
    "    mov rbp, [rsi + 0x10]",
    "    mov r12, [rsi + 0x18]",
    "    mov r13, [rsi + 0x20]",
    "    mov r14, [rsi + 0x28]",
    "    mov r15, [rsi + 0x30]",
    "    mov rsp, [rsi + 0x38]",
    "    push QWORD PTR [rsi + 0x00]",
    "    ret",
}

unsafe extern "C" {
    /// 见上方 global_asm 契约。**必须声明为可返回**：返回地址是恢复
    /// 路径的续点；若声明 `-> !`，编译器会以 int3 填充调用点之后，
    /// 续点即成幻影（M3 实测踩坑）。
    fn lumina_context_switch(old: *mut TaskContext, new: *mut TaskContext, handoff: *mut u64);
}

/// 锁外交换的上下文指针对（可携带 M11-D 握手旗）。
///
/// 调度器的正确姿势：互斥窗口内完成全部元数据变更并经
/// [`SwitchPair::from`] 取出两份上下文的裸指针，**先释放锁、再切换**
/// ——否则旧任务的锁守护冻结在其栈上，新任务一启动即死锁。
/// 旧任务重排队（可拾取态）时必须 [`SwitchPair::with_handoff`] 登记
/// 握手旗，由切换机器在旧现场保存完成后清除。
///
/// 指针稳定性论证（单核协作式）：从锁释放到 [`switch_deferred`] 之间
/// 不存在任何并发执行者（切换本身才移交控制权），被指涉的任务表
/// 不可能重分配或移动。
#[derive(Debug)]
pub struct SwitchPair {
    old: *mut TaskContext,
    new: *mut TaskContext,
    /// 旧任务握手旗地址（M11-D；null = 无旗——旧任务非重排队态，
    /// 如 Blocked/Zombie/idle 切出，本就不可拾取）。
    handoff: *mut u64,
}

impl SwitchPair {
    /// 在互斥窗口内由可变引用构造指针对（safe：仅地址萃取；无握手旗）。
    pub fn from(old: &mut TaskContext, new: &mut TaskContext) -> Self {
        Self {
            old: old as *mut TaskContext,
            new: new as *mut TaskContext,
            handoff: core::ptr::null_mut(),
        }
    }

    /// 登记旧任务握手旗（M11-D：旧任务已重排队为可拾取态，现场保存
    /// 完成前拾取面拒绝；旗由切换机器在保存完成后单 Store 清除）。
    #[must_use]
    pub fn with_handoff(mut self, flag: *mut u64) -> Self {
        self.handoff = flag;
        self
    }
}
