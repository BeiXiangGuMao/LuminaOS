//! CPU 指令基元（停机与中断屏蔽）。
//!
//! 依据 SPEC 第十七章：机器指令基元全部收敛在 ostd；上层（bedrock-boot /
//! Bedrock 内核白名单模块）只调用本层的 safe 包装。x86_64 之外的目标提供
//! 编译可过的桩实现，等待 aarch64-lumina 引入各自的 WFI 等价物。

/// 执行一次 `hlt`：停机直到下一个中断到来。
///
/// # SAFETY（safe 包装的安全性论证）
/// - 前置条件：调用方 MUST 保证存在可用唤醒源（定时器/设备中断），
///   或有意让 CPU 长期停机；
/// - 不变式：只执行一条 `hlt` 指令，不触碰内存与标志位；
/// - 并发：`hlt` 对多核无全局影响，仅作用于当前硬件线程；
/// - 违反后果：无唤醒源时 CPU 停滞直至外部 NMI/复位。
#[cfg(target_arch = "x86_64")]
pub fn halt_once() {
    // SAFETY：见函数头论证；inline asm 仅含一条 hlt 指令。
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// 屏蔽可屏蔽中断（`cli`）。
///
/// # SAFETY（safe 包装的安全性论证）
/// - 前置条件：调用方 MUST 明确屏蔽中断的窗口范围，并在窗口结束处恢复；
/// - 不变式：只执行一条 `cli` 指令；
/// - 并发：仅作用于当前硬件线程的 IF 标志；
/// - 违反后果：中断长期屏蔽会冻结调度与时钟，系统表现为全面挂死。
#[cfg(target_arch = "x86_64")]
pub fn disable_interrupts() {
    // SAFETY：见函数头论证；inline asm 仅含一条 cli 指令。
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// 永久空闲循环：反复 `hlt` 等待中断（P0 DoD「QEMU 启动进入空闲循环」）。
#[cfg(target_arch = "x86_64")]
pub fn idle_halt() -> ! {
    loop {
        halt_once();
    }
}

/// 非 x86_64 目标桩：`hlt` 不可用，退化为让步自旋。
#[cfg(not(target_arch = "x86_64"))]
pub fn halt_once() {
    core::hint::spin_loop();
}

/// 非 x86_64 目标桩：无可屏蔽中断概念，空操作。
#[cfg(not(target_arch = "x86_64"))]
pub fn disable_interrupts() {}

/// 非 x86_64 目标桩：让步自旋空闲循环。
#[cfg(not(target_arch = "x86_64"))]
pub fn idle_halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// 桩可链接性测试仅存在于非 x86_64 目标：x86_64 下上述函数是真实特权指令
// （cli/hlt），在宿主用户态执行会立即 GP 故障（SIGSEGV），只能经 S6-boot
// 的 QEMU 烟测在裸机路径验证。
#[cfg(all(test, not(target_arch = "x86_64")))]
mod tests {
    #[test]
    fn stubs_are_linkable() {
        super::disable_interrupts();
        super::halt_once();
    }
}
