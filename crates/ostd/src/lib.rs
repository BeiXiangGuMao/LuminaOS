//! OSTD —— Lumina OS 的 unsafe 内核基元层。
//!
//! 依据《指标与规范手册》(LUM-SPEC-001) 第十七章：全系统的 unsafe 只允许出现在
//! OSTD 层（申请制）与框架内核白名单模块内；本 crate 之外的代码应当能够以纯 safe
//! Rust 编写。本层向上层（Bedrock 磐基）提供最小而完备的基元：
//!
//! - [`sync::SpinLock`]：自旋锁，内核态最基本的互斥原语；
//! - [`boot::BootInfo`]：引导期信息布局（物理内存偏移、帧缓冲等）；
//! - [`console::Console`]：早期控制台输出抽象（串口/内存缓冲的统一写入口）；
//! - [`hw`]：硬件基元收口层——端口 I/O、VGA 文本、物理内存直读（HW-01…03）、
//!   CR3（HW-04）、cli/sti/hlt/lidt（HW-05）、PIC（HW-06）、PIT（HW-07）；
//! - [`mm`]：物理帧分配器（区间裁剪 + LIFO 空闲表）与四级页表抽象
//!   （map/translate/unmap，经 PhysAccess 抽象零 unsafe 遍历）；
//! - [`time`]：PIT 节拍计数与低功耗等待；
//! - [`task`]：协作式上下文切换（CONTEXT-01，callee-saved + rsp 交换）；
//! - [`interrupt`]：IDT 门描述符与装载（x86-interrupt ABI 注册）。
//!
//! # SAFETY 注释约定
//!
//! 本 crate 内每一处 unsafe 块都必须携带四行 SAFETY 注释：前置条件、不变式、
//! 并发、违反后果（与《系统开发指南》第四章模板一致）。
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// mm 模块的空闲表/帧段管理使用 core alloc（内核堆之上，不属于 unsafe 面）。
extern crate alloc;

pub mod acpi;
pub mod boot;
pub mod console;
#[cfg(target_arch = "x86_64")]
pub mod hw;
#[cfg(target_arch = "x86_64")]
pub mod interrupt;
#[cfg(target_arch = "x86_64")]
pub mod mm;
pub mod sync;
#[cfg(target_arch = "x86_64")]
pub mod task;
#[cfg(target_arch = "x86_64")]
pub mod time;
