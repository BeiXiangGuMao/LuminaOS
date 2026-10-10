//! OSTD —— Lumina OS 的 unsafe 内核基元层。
//!
//! 依据《指标与规范手册》(LUM-SPEC-001) 第十七章：全系统的 unsafe 只允许出现在
//! OSTD 层（申请制）与框架内核白名单模块内；本 crate 之外的代码应当能够以纯 safe
//! Rust 编写。本层向上层（Bedrock 磐基）提供最小而完备的基元：
//!
//! - [`sync::SpinLock`]：自旋锁，内核态最基本的互斥原语；
//! - [`boot::BootInfo`]：引导期信息布局（物理内存偏移、帧缓冲等）；
//! - [`console::Console`]：早期控制台输出抽象（串口/内存缓冲的统一写入口）；
//! - [`serial::SerialPort`]：16550 UART 串口驱动（COM1 早期日志通道）。
//!
//! # SAFETY 注释约定
//!
//! 本 crate 内每一处 unsafe 块都必须携带四行 SAFETY 注释：前置条件、不变式、
//! 并发、违反后果（与《系统开发指南》第四章模板一致）。
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod boot;
pub mod console;
pub mod cpu;
pub mod serial;
pub mod sync;
