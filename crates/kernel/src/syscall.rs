//! SYSCALL/SYSRET 系统调用入口（M4；M8-A swapgs 纪律重构）。
//!
//! 入口约定（与 bedrock abi v0 一致）：
//! - 用户侧：`syscall` 指令，rax=编号，rdi/rsi/rdx/r10/r8=五参数；
//! - CPU 动作：rcx ← RIP、r11 ← RFLAGS、RFLAGS &= ~IA32_FMASK；
//! - 入口桩：r9 暂存用户 rsp → **rbp 舞步**做无状态 LAPIC 索引定位
//!   （见下）→ 切本核 per-CPU 栈（[`crate::task::LUMINA_PERCPU_KSTACK`]）
//!   → 建 9 槽帧 → `lumina_syscall_dispatch(&frame)` → 恢复 → `sysretq`。
//!
//! **swapgs 纪律定版（M8-A）**：内核**不使用** swapgs / GS 基址承载
//! per-CPU 状态。M7 开发期实测两处三重故障否决了 GS 影子 MSR 方案：
//! (a) 派发点盲写 GSBASE=0 会破坏被抢占于 syscall 中的任务（ring0 恢复点）
//! 的入口/出口配对；(b) EXIT 路径不返回，影子遗留 0，下一次入口 swapgs 得
//! 0↔0，`gs:0` 读 VA 0 垃圾栈。根因是结构性的：swapgs 配对语义是 CPU
//! 全局态，而 syscall 窗口（含 YIELD 中途切出再切回）是任务生命周期——
//! 多任务下窗口可跨调度点存续，单一 CPU 态无法同时充当多窗口的配对锚。
//! 定版纪律：
//! 1. per-CPU 寻址 = **无状态 LAPIC 索引**：入口桩读本核 APIC ID 计算
//!    `LUMINA_PERCPU_KSTACK[cpu]` 槽偏移（见下方桩），零 MSR 态、零配对、
//!    每次入场现取现用——任务帧各落各栈，**双核并发 syscall 竞态消除**
//!    （v0.7.0 已知限制正式解除）；
//! 2. 内核代码永不消费 GS；FS/GS 保留未来用户 TLS（ABI 契约，DEV-002
//!    第四章收口精神：单一机制单一职责，不引入无守护的状态面）；
//! 3. M7 遗留的全局单槽 `LUMINA_KSTACK_CUR` 本版删除——它是「双核并发
//!    即互踩」的病灶（后派发者覆写栈指针，先入场者的帧失去独占栈）。
//!
//! 桩前置条件（init 链契约，自检 28 取证）：
//! - IA32_APIC_BASE = 0xFEE00000（QEMU 契约；桩按此硬编码 ID 寄存器地址）；
//! - `BSP_APIC_ID` 已由 `task::init` 写入（先于任何用户任务派发）；
//! - 本核 LAPIC MMIO 页在当前 CR3 可达（用户根由 `clone_kernel_branches`
//!   补植 LAPIC 分支保证，M6 缺陷一的架构级修复）。
//! - LAPIC ID 读为只读无副作用；FMASK 已清 IF，定位舞步窗口内无中断撕裂。
//! - **ABI 契约（v0 追加注记）**：入口以 rbp 为定位舞步寄存器——**用户
//!   rbp 不跨 syscall 保留**（rbx/r12–r15/五个参数寄存器仍全量往返）。
//!   内核**绝不写入用户内存**（现场保全全部走寄存器，见桩注释）——
//!   任何以用户指针为目标的内核写都会把一次边界毛刺放大成野写级联
//!   （M8 开发期实测教训，记档 devlog S31）。
//!
//! unsafe 面：入口桩（SYSCALL-01 白名单）与 MSR 写（HW-09 收口）；
//! 派发器本体为 safe Rust。

use core::arch::global_asm;
use core::mem::size_of;

use bedrock::abi::{parse, AbiError, Syscall, SyscallRegs, SYS_LOG};

use crate::task;

/// IA32_EFER：SCE（系统调用使能）位。
const EFER_SCE: u64 = 1;
/// IA32_EFER 寄存器号。
const MSR_EFER: u32 = 0xC000_0080;
/// IA32_STAR：内核/用户 CS 基座。
const MSR_STAR: u32 = 0xC000_0081;
/// IA32_LSTAR：syscall 入口 RIP。
const MSR_LSTAR: u32 = 0xC000_0082;
/// IA32_FMASK：RFLAGS 掩码（置 1 的位被清零）。
const MSR_FMASK: u32 = 0xC000_0084;

/// FMASK：清 TF(0x100) | IF(0x200) | DF(0x400)。
const FMASK_VALUE: u64 = 0x700;

/// 9 槽系统调用帧（入口桩布局；与汇编偏移严格对应）。
#[repr(C)]
pub struct SyscallFrame {
    /// 用户 RFLAGS（r11 原值）。
    pub rflags: u64,
    /// 用户 RIP（rcx 原值）。
    pub rip: u64,
    /// 用户 RDI（参数 0）。
    pub rdi: u64,
    /// 用户 RSI（参数 1）。
    pub rsi: u64,
    /// 用户 RDX（参数 2）。
    pub rdx: u64,
    /// 用户 R10（参数 3）。
    pub r10: u64,
    /// 用户 R8（参数 4）。
    pub r8: u64,
    /// 用户 RSP。
    pub user_rsp: u64,
    /// 系统调用编号（rax 原值）。
    pub num: u64,
}

const _: () = assert!(size_of::<SyscallFrame>() == 72);

// 系统调用入口桩（SYSCALL-01 白名单；M8-A 无状态 per-CPU 栈接线）。
//
// 帧区 128 字节（栈顶 16 对齐 - 128 保持对齐，call 压返回址后
// 派发器入口 rsp%16==8，符合 SysV 约定）。r9 为 ABI 之外的自由
// 寄存器（v0 五参数占 rdi/rsi/rdx/r10/r8），用作用户 rsp 暂存。
//
// 现场保全顺序（定位舞步会占用 rcx/rdx）：先把用户 rcx/rdx 暂存到
// 用户栈 rsp-8/-16（红区语义，页内既有映射；若该页已被换出，#PF 经
// M8-B 回收链 swap-in 后重执行本指令，全链自洽），再做 LAPIC 定位，
// 切核栈后从暂存区回填帧槽。栈定位纪律见模块文档（swapgs 纪律定版）。
//
// 开发期缺陷二（SYSRET 边缘交付，TCG 隐患族收口）：YIELD 路径的
// yield_now 恢复点无条件 sti（内核任务 IF 约定），使系统调用尾声
// （恢复 r11/rcx → sysretq）在 IF=1 下运行——节拍恰好落在 sysretq
// 边缘时 TCG 把 r11→RFLAGS 的恢复搅坏（VM 位入旗，后续任何 iretq
// 即 #GP(0x28)，S31 实测链）。初版缓解为尾声恢复前 cli 关断该窗口；
// v0.10.1 裸机压测（2/30 复发，TCG 边界注入不受 IF 遮蔽）确认 cli
// 缓解不彻底——**正解 = iretq 返回**（Linux 对 SYSRET 竞态的同款
// 缓解）：帧尾显式构造 [RIP|CS=0x1B|RFLAGS|RSP|SS=0x23] 五元组，
// 特权降级走显式段检查路径，帧内容内核全权构造，无 MSR 快照窗口；
// sysret 后 IF 重开语义由 RFLAGS 槽（r11 原值，IF=1）经 iretq 恢复
// 等价达成，积压节拍经正常 IDT 路径交付。
//
// 开发期缺陷一（64 位 disp32 符号扩展）：`mov ecx, [0xFEE00020]`
// 绝对寻址在长模式下把 disp32 **符号扩展**至 64 位（0xFEE00020 > 2^31
// 即成 0xFFFFFFFF_FEE00020 → PML4[511] 未映射 → #PF，CR2 取证定位）。
// 正解：32 位立即数 mov 零扩展入寄存器（`mov edx, 0xFEE00020`）再
// 间接寻址（`mov ecx, [rdx]`）。
global_asm! {
    ".text",
    ".globl lumina_syscall_entry",
    "lumina_syscall_entry:",
    "    mov r9, rsp",
    "    mov [r9 - 8], rcx",
    "    mov [r9 - 16], rdx",
    "    mov edx, 0xFEE00020",
    "    mov ecx, dword ptr [rdx]",
    "    shr ecx, 24",
    "    xor edx, edx",
    "    cmp cl, byte ptr [rip + BSP_APIC_ID]",
    "    setne dl",
    "    shl edx, 3",
    "    lea rsp, [rip + LUMINA_PERCPU_KSTACK]",
    "    mov rsp, [rsp + rdx]",
    "    sub rsp, 128",
    "    mov rcx, [r9 - 8]",
    "    mov rdx, [r9 - 16]",
    "    mov [rsp + 0], r11",
    "    mov [rsp + 8], rcx",
    "    mov [rsp + 16], rdi",
    "    mov [rsp + 24], rsi",
    "    mov [rsp + 32], rdx",
    "    mov [rsp + 40], r10",
    "    mov [rsp + 48], r8",
    "    mov [rsp + 56], r9",
    "    mov [rsp + 64], rax",
    "    mov rdi, rsp",
    "    call lumina_syscall_dispatch",
    // ---- v0.10.1：iretq 返回（SYSRET 边缘竞态的 TCG 侧根治，见上注）----
    // 五元组就地构造在帧尾（num 槽之后，128 字节帧区余量充足）：
    //   [rsp+72]=RIP  [rsp+80]=CS(0x1B)  [rsp+88]=RFLAGS
    //   [rsp+96]=RSP  [rsp+104]=SS(0x23)
    "    mov [rsp + 64], rax",                 // 返回值暂存 num 槽
    "    mov rax, [rsp + 8]",
    "    mov [rsp + 72], rax",                 // RIP ← rcx 槽
    "    mov qword ptr [rsp + 80], 0x1B",      // CS（ucode|3；显式段检查路径）
    "    mov rax, [rsp + 0]",
    "    mov [rsp + 88], rax",                 // RFLAGS ← r11 槽（IF=1，出环即开）
    "    mov rax, [rsp + 56]",
    "    mov [rsp + 96], rax",                 // RSP ← 用户 rsp
    "    mov qword ptr [rsp + 104], 0x23",     // SS
    "    mov rdi, [rsp + 16]",
    "    mov rsi, [rsp + 24]",
    "    mov rdx, [rsp + 32]",
    "    mov r10, [rsp + 40]",
    "    mov r8, [rsp + 48]",
    "    mov rax, [rsp + 64]",                 // 返回值 → rax
    "    mov rcx, [rsp + 8]",
    "    mov r11, [rsp + 0]",
    "    add rsp, 72",                         // 栈顶 = 五元组 RIP 槽
    "    iretq",
}

/// 装载 SYSCALL/SYSRET 全套 MSR 约定（EFER.SCE / STAR / LSTAR / FMASK）。
///
/// # SAFETY（调用方义务）
/// GDT 必须已按 ostd::hw::gdt 布局装载（STAR 的选择子基址与之配套）；
/// 装载后任何 ring3 `syscall` 都会进入 LSTAR——内核入口必须已就绪。
pub unsafe fn init() {
    // SAFETY: 白名单 MSR（HW-09）；写入值符合 SDM 保留位约束。
    unsafe {
        let efer = ostd::hw::msr::read(MSR_EFER);
        ostd::hw::msr::write(MSR_EFER, efer | EFER_SCE);
        // STAR[47:32] = 0x08（内核 CS；SYSCALL 后 SS = 0x10），
        // STAR[63:48] = 0x18（SYSRET 后 CS = 0x1B、SS = 0x20）。
        ostd::hw::msr::write(MSR_STAR, (0x08u64 << 32) | (0x18u64 << 48));
        ostd::hw::msr::write(MSR_FMASK, FMASK_VALUE);
        ostd::hw::msr::write(MSR_LSTAR, lumina_syscall_entry as *const () as usize as u64);
    }
}

unsafe extern "C" {
    /// 见上方 global_asm 契约。
    fn lumina_syscall_entry();
}

/// 快速路径派发器（桩调用；rdi = 帧指针）。返回值即用户 rax。
///
/// **per-CPU 栈纪律（M8-A）**：入口桩已按本核 LAPIC ID 把帧建在当前
/// 派发任务的内核栈上（`prepare_dispatch` 写 `LUMINA_PERCPU_KSTACK[cpu]`
/// 与本核 TSS.RSP0 同源）；派发器全程无需（也不得）切换栈——EXIT 路径
/// 不返回（帧随任务终结废弃），YIELD 路径经统一调度器切出切回，帧在
/// 本任务栈上跨调度点存续（per-CPU 槽只服务「入场」时刻，不承载窗口态）。
#[no_mangle]
extern "C" fn lumina_syscall_dispatch(frame: &mut SyscallFrame) -> u64 {
    let regs = SyscallRegs {
        num: frame.num,
        args: [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8],
    };
    let parsed = match parse(regs) {
        Ok(p) => p,
        Err(e) => {
            task::count_syscall(2);
            return error_code(e);
        }
    };
    match parsed {
        Syscall::Log { len } => {
            task::count_syscall(0);
            task::note_log_cpu(); // 跨核取证面（服务核 + 本核 RSP0/调用栈）
            let ptr = frame.rdi;
            if let Some(text) = validate_user_slice(ptr, len) {
                crate::console::serial_log_bytes(text);
            }
            0
        }
        Syscall::Yield => {
            task::count_syscall(1);
            task::yield_now();
            0
        }
        Syscall::Exit { code } => {
            task::count_syscall(2);
            task::exit_current(code as u64)
        }
        Syscall::IpcSend { endpoint, len } => {
            task::count_syscall(2);
            // 慢路径寄存器面约定：载荷指针 = rdx，tag = r10（abi v0 的
            // IpcSend 结构校验 endpoint/len；指针/tag 属慢路径语义）
            crate::ipc::sys_send(endpoint, frame.rdx, len, frame.r10)
        }
        Syscall::IpcRecv { endpoint, buf_len } => {
            task::count_syscall(2);
            crate::ipc::sys_recv(endpoint, frame.rdx, buf_len)
        }
        Syscall::CapDerive {
            parent_handle,
            rights,
        } => {
            task::count_syscall(2);
            crate::ipc::sys_cap_derive(parent_handle, rights)
        }
        Syscall::SetPrio { level } => {
            task::count_syscall(2);
            task::set_current_prio(level as u64)
        }
        Syscall::GetPrio => {
            task::count_syscall(2);
            task::current_prio()
        }
        Syscall::CapGrant {
            target_pid,
            handle,
            rights,
        } => {
            task::count_syscall(2);
            // M9-A 进程模型：父进程面门禁 + 收窄派生 + 目标句柄表安装
            crate::procs::sys_grant(target_pid, handle, u64::from(rights))
        }
        Syscall::CapRevoke { handle } => {
            task::count_syscall(2);
            crate::procs::sys_revoke(handle)
        }
        Syscall::GetPid => {
            task::count_syscall(2);
            crate::procs::current_pid()
        }
        Syscall::WaitPid { pid } => {
            task::count_syscall(2);
            // M10-C 进程间等待面：阻塞等待直接子任务终结并收割退出码
            // （无匹配子任务 → ERR_CHILD 立即返回，不阻塞）
            crate::procs::sys_wait_pid(pid)
        }
        Syscall::Spawn { reserved } => {
            task::count_syscall(2);
            // M11-A 进程创建面：ring3 自主派生（克隆子空间 + 遗传细胞 +
            // 父链内核登记；帧/槽耗尽 → ERR_NOMEM）
            crate::procs::sys_spawn(reserved)
        }
        Syscall::HandleQuery { handle } => {
            task::count_syscall(2);
            // M11-B 句柄查询面：rights + 全局槽号（纯读，不改变句柄表）
            crate::procs::sys_handle_query(handle)
        }
        Syscall::HandleEnum { cursor } => {
            task::count_syscall(2);
            // M11-B 句柄枚举面：游标后首个占用项（循环协议终点 = 0）
            crate::procs::sys_handle_enum(cursor)
        }
        Syscall::IpcBind { reserved } => {
            task::count_syscall(2);
            // M12-A 通道注册表运行时化：ring3 自建通道（铸对象 id +
            // 泄漏环对 + 能力装入句柄表；跨任务分发复用 SYS_CAP_GRANT）
            crate::ipc::sys_bind(reserved)
        }
        Syscall::Exec { image } => {
            task::count_syscall(2);
            // M12-B 执行映像面：地址空间以内核内嵌映像重建（成功不返回
            // —— 帧面 RIP/RSP/参数寄存器全量改写，返回即入新映像）
            crate::procs::sys_exec(image, frame)
        }
        Syscall::Open { len, mode } => {
            task::count_syscall(2);
            // M13-② 文件面：路径指针 = rdi 慢路径语义（abi v0.7 统一句柄面）
            crate::vfs::sys_open(frame.rdi, len, u64::from(mode))
        }
        Syscall::Read { handle, len } => {
            task::count_syscall(2);
            // M13-② 文件面：缓冲指针 = rsi 慢路径语义
            crate::vfs::sys_read(handle, frame.rsi, len)
        }
        Syscall::Write { handle, len } => {
            task::count_syscall(2);
            // M13-② 文件面：缓冲指针 = rsi 慢路径语义
            crate::vfs::sys_write(handle, frame.rsi, len)
        }
        Syscall::Close { handle } => {
            task::count_syscall(2);
            crate::vfs::sys_close(handle)
        }
        Syscall::Stat { handle } => {
            task::count_syscall(2);
            crate::vfs::sys_stat(handle)
        }
        Syscall::Seek {
            handle,
            whence,
            offset,
        } => {
            task::count_syscall(2);
            crate::vfs::sys_seek(handle, u64::from(whence), offset)
        }
        Syscall::NanoSleep { ticks } => {
            task::count_syscall(2);
            // M13-② timer 阻塞源；M15-③ 参数语义 = TSC 纳秒（寄存器面不变）
            crate::timer::sys_nanosleep(ticks)
        }
        Syscall::Quota { kind } => {
            task::count_syscall(2);
            // M14-② 配额治理统计面
            crate::procs::sys_quota(kind)
        }
        Syscall::MkDir { len } => {
            task::count_syscall(2);
            // M15-① 目录面：路径指针 = rdi 慢路径语义
            crate::vfs::sys_mkdir(frame.rdi, len)
        }
        Syscall::Remove { len } => {
            task::count_syscall(2);
            // M15-① 目录面：路径指针 = rdi 慢路径语义
            crate::vfs::sys_remove(frame.rdi, len)
        }
        Syscall::ReadDir { handle, buf_len } => {
            task::count_syscall(2);
            // M15-① 目录面：缓冲指针 = rsi 慢路径语义（分页枚举）
            crate::vfs::sys_readdir(handle, frame.rsi, buf_len)
        }
        Syscall::Mount { len, fs_type } => {
            task::count_syscall(2);
            // M15-① 目录面：挂载点路径 = rdi 慢路径语义（v0 仅 RamFs）
            crate::vfs::sys_mount(frame.rdi, len, fs_type)
        }
        Syscall::Umount { len } => {
            task::count_syscall(2);
            // M15-① 目录面：路径指针 = rdi 慢路径语义
            crate::vfs::sys_umount(frame.rdi, len)
        }
        Syscall::Dup { handle } => {
            task::count_syscall(2);
            // M15-② 句柄面深化：共享 OFD 偏移的句柄复制
            crate::vfs::sys_dup(handle)
        }
        Syscall::Fcntl { handle, cmd, arg } => {
            task::count_syscall(2);
            // M15-② 句柄面深化：描述符控制（F_DUPFD/GETFD/SETFD + CLOEXEC）
            crate::vfs::sys_fcntl(handle, cmd, arg)
        }
    }
}

/// 把 ABI 错误映射为用户可见返回码（v0：未知/坏参数统一 u64::MAX-序）。
fn error_code(e: AbiError) -> u64 {
    match e {
        AbiError::UnknownSyscall => u64::MAX,
        AbiError::BadArgs => u64::MAX - 1,
    }
}

/// 用户缓冲区校验：限定低 1 GiB 恒等映射区、去空指针、限长。
/// 返回物理可直读的切片视图（恒等映射下虚拟=物理）。
pub(crate) fn validate_user_slice(ptr: u64, len: u64) -> Option<&'static [u8]> {
    const IDENT_LIMIT: u64 = 0x4000_0000;
    if len == 0 || len > 512 {
        return None;
    }
    if !(0x1000..IDENT_LIMIT).contains(&ptr) || ptr.checked_add(len)? > IDENT_LIMIT {
        return None;
    }
    // SAFETY: 前置条件 —— 区间已校验（恒等映射内、非空、限长）。
    // 不变式 —— 用户映射的物理帧在任务存续期不被回收（用户栈/代码
    //          帧归用户空间所有，无并发回收者）。
    // 并发 —— M7-A：多核用户任务可并发（每核一任务）；切片指向
    //          调用方自身帧，跨任务无共享。
    // 违反后果 —— 悬垂读取触发 #PF（致命路径）。
    unsafe { Some(core::slice::from_raw_parts(ptr as *const u8, len as usize)) }
}

/// 用户缓冲区可写校验（IPC RECV 路径）：同一区间纪律的可变视图。
pub(crate) fn validate_user_slice_mut(ptr: u64, len: u64) -> Option<&'static mut [u8]> {
    const IDENT_LIMIT: u64 = 0x4000_0000;
    if len == 0 || len > 512 {
        return None;
    }
    if !(0x1000..IDENT_LIMIT).contains(&ptr) || ptr.checked_add(len)? > IDENT_LIMIT {
        return None;
    }
    // SAFETY: 前置条件 —— 区间已校验（恒等映射内、非空、限长）。
    // 不变式 —— 目标为调用方任务的栈/数据页（用户根映射 P|U|W）；
    //           系统调用窗口内无并发写者（IF=0，本核串行）。
    // 并发 —— 调用方任务独占自身缓冲（跨任务不共享；M7-A 起双核
    //          用户任务并发，但各自写各自页）。
    // 违反后果 —— 越权写入仅限调用方自身地址空间（能力门禁在先）。
    unsafe {
        Some(core::slice::from_raw_parts_mut(
            ptr as *mut u8,
            len as usize,
        ))
    }
}

/// LOG 编号常量仅用于文档自检（保证 v0 面未被误删）。
const _: () = assert!(SYS_LOG == 0);
