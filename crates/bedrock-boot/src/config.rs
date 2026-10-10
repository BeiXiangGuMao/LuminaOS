//! 编译期常量集中地（DEV-002 5.1：bedrock-boot::config）。
//!
//! 页大小、核数上限、串口基址等在编译期冻结；改动 MUST 同步更新规范手册
//! 引用（SPEC 第二章 Bedrock 对应条目），并在提交说明中登记 ABI 影响面。

/// 内存页大小（字节）。x86_64-lumina 固定 4 KiB 粒度。
pub const PAGE_SIZE: u64 = 4096;

/// SMP 核数上限（P0 阶段 QEMU 单核即可，上限按 SPEC 参考环境 A 的 8 vCPU 冻结）。
pub const MAX_CPUS: u32 = 8;

/// COM1 串口 IO 基址（PC/QEMU 标准设备）。
pub const COM1_BASE: u16 = 0x3F8;

/// 串口波特率（38400 为 QEMU 与真机均稳定的中档速率）。
pub const SERIAL_BAUD: u32 = 38400;

/// 空闲循环前打印的启动完成标记（DEV-002 6.2 TLV 协议用例行）。
pub const BOOT_PASS_MARKER: &str = "[tlv] case=boot-p0-001 -> PASS";
