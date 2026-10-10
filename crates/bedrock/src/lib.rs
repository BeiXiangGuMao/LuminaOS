//! Bedrock 磐基 —— Lumina OS 的 framekernel 内核核心。
//!
//! 依据《指标与规范手册》第 2 章：单地址空间 framekernel，内核框架为 safe Rust，
//! unsafe 收口在 OSTD；系统调用往返预算 2.5 μs（B-P01）分解到本 crate 的 IPC 快速
//! 路径与 Meridian 分发器。本 crate 覆盖内核的三块骨架：
//!
//! - [`abi`]：系统调用号与寄存器布局（v0 ABI）；
//! - [`tlv`]：内核测试与 IPC 载荷的 TLV 编帧（QEMU 宿主-客户机协议约定）；
//! - [`ipc`]：端点信箱（快速路径的数据结构面）；
//! - [`vfs`]：虚拟文件系统骨架——文件面与多段映像的公共基座（v0.13.0，M13-①）；
//! - [`exec`]：LXE1 多段可执行映像格式结构面（M14-①；放置策略归内核装载器）。
//!
//! 非目标：页表、调度器与中断控制属 bedrock-boot/ostd 后续里程碑（SPEC 表 19-1 P0）。
#![no_std]
extern crate alloc;

pub mod abi;
pub mod exec;
pub mod ipc;
pub mod tlv;
pub mod vfs;

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[global_allocator]
static TEST_ALLOC: std::alloc::System = std::alloc::System;
