//! Bedrock 引导内核 —— M2：QEMU 裸机启动与串口输出。
//!
//! 依据 SPEC 表 19-1（P0）与表 2-3（Bedrock 阶段门禁）：P0 末完成定义为
//! 「QEMU 启动进入空闲循环，串口可输出日志」。本 crate 是唯一的内核 bin，
//! 经 bootloader 引导进入长模式后从 [`kernel_main`] 开始执行：
//!
//! 1. 初始化 COM1 串口（ostd 的 16550 驱动）；
//! 2. 打印启动横幅与 bootloader 传递的内存映射摘要；
//! 3. 打印 DEV-002 6.2 协议的 PASS 标记（宿主侧 harness 断言该行）；
//! 4. 进入 `hlt` 空闲循环。
//!
//! 本 crate 属于内核白名单入口：除调用 ostd 的 safe 基元外自身不持有任何
//! unsafe（halt/cli 已收敛为 `ostd::cpu` 的 safe 包装），符合 SPEC 第十七章
//! unsafe 分层纪律。

#![no_std]
#![no_main]

mod config;

use bootloader::{entry_point, BootInfo};
use core::fmt::Write as _;
use core::panic::PanicInfo;
use ostd::console::FmtWriter;
use ostd::serial::SerialPort;

entry_point!(kernel_main);

/// 内核入口：引导层完成长模式切换与内核装载后跳转到这里。
///
/// 返回类型恒为 `!`：内核不允许返回（返回即三重故障）。
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    let mut com1 = SerialPort::new(config::COM1_BASE);
    com1.init();

    print_banner(&mut com1);
    report_memory_map(&mut com1, boot_info);
    print_pass_marker(&mut com1);
    enter_idle(&mut com1);
}

/// 启动横幅：版本、目标、串口参数。
fn print_banner(com1: &mut SerialPort) {
    let mut w = FmtWriter::new(com1);
    let _ = writeln!(w, "[boot] Lumina OS bedrock-boot —— M2 QEMU 裸机启动");
    let _ = writeln!(
        w,
        "[boot] target=x86_64-lumina page={}B cpus<={} serial=COM1@0x{:x} baud={}",
        config::PAGE_SIZE,
        config::MAX_CPUS,
        config::COM1_BASE,
        config::SERIAL_BAUD
    );
}

/// 内存映射摘要：区域计数与可用内存合计（KiB）。
fn report_memory_map(com1: &mut SerialPort, boot_info: &'static BootInfo) {
    let mut w = FmtWriter::new(com1);
    let map = &boot_info.memory_map;
    let mut regions = 0u32;
    let mut usable_frames = 0u64;
    for region in map.iter() {
        regions += 1;
        if region.region_type == bootloader::bootinfo::MemoryRegionType::Usable {
            usable_frames += region.range.end_frame_number - region.range.start_frame_number;
        }
    }
    let usable_kib = usable_frames * 4096 / 1024;
    let _ = writeln!(
        w,
        "[boot] memory-map regions={regions} usable={usable_kib} KiB"
    );
}

/// DEV-002 6.2 TLV 协议的启动 PASS 标记；宿主侧 harness 据此判定引导成功。
fn print_pass_marker(com1: &mut SerialPort) {
    let mut w = FmtWriter::new(com1);
    let _ = writeln!(w, "{}", config::BOOT_PASS_MARKER);
}

/// 进入空闲循环：打印提示后 `hlt` 等中断（P0 DoD 的收尾状态）。
fn enter_idle(com1: &mut SerialPort) -> ! {
    let mut w = FmtWriter::new(com1);
    let _ = writeln!(w, "[boot] 进入空闲循环（hlt）—— P0 DoD 达成");
    ostd::cpu::idle_halt()
}

/// 内核 panic 处理：尽力把 panic 信息写到 COM1，随后永久停机。
///
/// 串口初始化幂等，panic 路径重复 init 无害；若串口本身故障，则退化为
/// 静默停机（早期日志通道 MUST NOT 引发二次 panic）。
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut com1 = SerialPort::new(config::COM1_BASE);
    com1.init();
    let mut w = FmtWriter::new(&mut com1);
    let _ = write!(w, "[panic] ");
    if let Some(loc) = info.location() {
        let _ = write!(w, "{}:{}:{}: ", loc.file(), loc.line(), loc.column());
    }
    let _ = write!(w, "{}", info.message());
    let _ = writeln!(w);
    ostd::cpu::disable_interrupts();
    ostd::cpu::idle_halt()
}
