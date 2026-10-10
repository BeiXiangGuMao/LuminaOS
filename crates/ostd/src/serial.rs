//! 16550 UART 串口驱动（早期日志通道）。
//!
//! 依据 DEV-002 第四章日志通道约定与 SPEC 表 2-3 P0 门禁（「串口可输出日志」），
//! Bedrock 引导期通过 COM1 输出全部启动日志。本模块只依赖 [`crate::console::Console`]
//! 的逐字节写入契约；端口 I/O 的 unsafe 全部收敛在本文件内（SPEC 第十七章：
//! unsafe 仅允许出现在 OSTD 层与内核白名单模块）。
//!
//! 宿主机单元测试只覆盖纯逻辑（波特率除数计算、换行展开）；真实端口读写仅在
//! 裸机路径（bedrock-boot → QEMU）验证，避免在宿主进程触碰 IO 端口。

use crate::console::Console;

/// x86_64 架构下的端口 I/O 基元与其余架构的空实现。
///
/// 串口寄存器访问只能出现在 x86_64 目标；其余架构（如 aarch64-lumina）在
/// 引入各自的 UART 基址后再扩展，保证 ostd 对多目标可编译。
#[cfg(target_arch = "x86_64")]
mod port_io {
    /// 向指定 IO 端口写一个字节。
    ///
    /// # SAFETY
    /// - 前置条件：`port` 必须指向由调用方证明存在的设备端口（COM1 基址表），
    ///   写入任意端口可能触发未定义的总线行为或劫持系统状态；
    /// - 不变式：本函数只执行一条 `out` 指令，不触碰内存与栈；
    /// - 并发：IO 端口无锁，调用方 MUST 通过 `&mut self` 串行化访问；
    /// - 违反后果：向错误端口写入可能导致设备误动作或全系统挂死。
    pub(super) unsafe fn outb(port: u16, val: u8) {
        // SAFETY：见函数头四行注释；inline asm 仅含一条 out 指令。
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    /// 从指定 IO 端口读一个字节。
    ///
    /// # SAFETY
    /// - 前置条件：`port` 必须指向由调用方证明存在的设备端口，读任意端口
    ///   可能与无关设备产生副作用（部分设备的读会推进其内部状态机）；
    /// - 不变式：本函数只执行一条 `in` 指令，不触碰内存与栈；
    /// - 并发：IO 端口无锁，调用方 MUST 通过 `&mut self` 串行化访问；
    /// - 违反后果：误读会破坏目标设备状态机或返回无意义数据。
    pub(super) unsafe fn inb(port: u16) -> u8 {
        // SAFETY：见函数头四行注释；inline asm 仅含一条 in 指令。
        unsafe {
            let ret: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") ret,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
            ret
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod port_io {
    /// 非 x86_64 目标：端口 I/O 不可用，写入为空。
    ///
    /// # SAFETY
    /// - 前置条件：无（该实现不执行任何机器操作）；
    /// - 不变式：恒等空操作；
    /// - 并发：无共享状态；
    /// - 违反后果：不存在；调用方在本目标上得不到真实串口输出。
    pub(super) unsafe fn outb(_port: u16, _val: u8) {}

    /// 非 x86_64 目标的读取桩，恒返回 0xFF。
    ///
    /// # SAFETY
    /// - 前置条件：无；
    /// - 不变式：恒返回 0xFF；
    /// - 并发：无共享状态；
    /// - 违反后果：不存在；调用方不得将返回值用于协议判定。
    pub(super) unsafe fn inb(_port: u16) -> u8 {
        0xFF
    }
}

/// 计算 16550 波特率除数（纯函数，宿主机可测）。
///
/// 除数 = 输入时钟 / (16 × 目标波特率)。若目标波特率为 0 或除数下溢为 0，
/// 返回 1（最高速率）；若超出 16 位寄存器则夹取到 0xFFFF，保证除数寄存器
/// 恒不为 0。
pub fn baud_divisor(input_clock: u32, baud: u32) -> u16 {
    if baud == 0 {
        return 1;
    }
    let div = input_clock / (16 * baud);
    if div == 0 {
        1
    } else if div > u32::from(u16::MAX) {
        u16::MAX
    } else {
        div as u16
    }
}

/// 将文本按串口行约定展开为字节序列：`\n` 展开为 `\r\n`（CR LF），其余
/// 字节原样透传；UTF-8 多字节序列不经任何转换，由接收端按 UTF-8 解码。
pub(crate) fn expand_newlines(s: &str) -> ExpandBytes<'_> {
    ExpandBytes {
        bytes: s.bytes(),
        pending: None,
    }
}

/// [`expand_newlines`] 的字节迭代器：把 `\n` 展开为 `\r\n` 两个字节。
pub(crate) struct ExpandBytes<'a> {
    bytes: core::str::Bytes<'a>,
    pending: Option<u8>,
}

impl Iterator for ExpandBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        // 先吐出上一次 \n 拆出的 \n，再继续消费原串。
        if let Some(b) = self.pending.take() {
            return Some(b);
        }
        match self.bytes.next() {
            Some(b'\n') => {
                self.pending = Some(b'\n');
                Some(b'\r')
            }
            other => other,
        }
    }
}

/// 16550 UART 端口抽象。
///
/// 寄存器布局（基址 + 偏移）：0 数据、1 中断允许、2 FIFO 控制（读为中断
/// 标识）、3 线路控制、4 Modem 控制、5 线路状态。DLAB 位（线路控制 bit 7）
/// 置位时偏移 0/1 变为除数低/高字节。
#[derive(Debug)]
pub struct SerialPort {
    base: u16,
}

/// 线路状态寄存器（LSR）位：发送保持寄存器空（THR empty）。
const LSR_THR_EMPTY: u8 = 0x20;
/// 线路状态寄存器（LSR）位：接收数据就绪。
const LSR_DATA_READY: u8 = 0x01;
/// 16550 输入时钟（PC/QEMU 标准）。
const UART_INPUT_CLOCK: u32 = 1_843_200;

impl SerialPort {
    /// 以指定基址构造串口；构造后 MUST 先调用 [`SerialPort::init`]。
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// 基址 + 寄存器偏移合成端口地址。
    fn reg(&self, offset: u16) -> u16 {
        self.base + offset
    }

    /// 初始化串口为 8 数据位、无校验、1 停止位（8N1），启用 FIFO，
    /// 并执行回环自检。幂等：可安全重复调用（如 panic 路径复用）。
    pub fn init(&mut self) {
        let div = baud_divisor(UART_INPUT_CLOCK, 38400);
        // SAFETY：以下端口均来自 COM1 基址表的固定偏移（0x3f8..0x3f8+7），
        // QEMU/PC 标准设备必然存在；顺序遵循 16550 手册初始化序列。
        unsafe {
            port_io::outb(self.reg(1), 0x00); // 关中断：轮询式驱动
            port_io::outb(self.reg(3), 0x80); // DLAB=1，准备写除数
            port_io::outb(self.reg(0), (div & 0xFF) as u8); // 除数低字节
            port_io::outb(self.reg(1), (div >> 8) as u8); // 除数高字节
            port_io::outb(self.reg(3), 0x03); // DLAB=0，8N1
            port_io::outb(self.reg(2), 0xC7); // FIFO 使能+清空，14 字节阈值
            port_io::outb(self.reg(4), 0x0B); // DTR+RTS+OUT2

            // 回环自检：置回环位，发送 0xAE 并校验收回；失败即关闭回环继续
            // （自检失败只降级，不 panic——早期日志通道必须尽量可用）。
            port_io::outb(self.reg(4), 0x1E);
            port_io::outb(self.reg(0), 0xAE);
            if port_io::inb(self.reg(0)) == 0xAE {
                port_io::outb(self.reg(4), 0x0B);
            }
        }
    }

    /// 阻塞发送一个字节（等待 THR 空）。
    pub fn send(&mut self, byte: u8) {
        // SAFETY：LSR 与 THR 均为 COM1 固定偏移；轮询上限由硬件时序保证
        // （波特率有限，THR 必然变空），不会无限阻塞。
        unsafe {
            while port_io::inb(self.reg(5)) & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            port_io::outb(self.reg(0), byte);
        }
    }

    /// 非阻塞尝试接收一个字节；无数据时返回 `None`。
    pub fn try_receive(&mut self) -> Option<u8> {
        // SAFETY：LSR/RBR 均为 COM1 固定偏移，读操作无破坏性副作用。
        unsafe {
            if port_io::inb(self.reg(5)) & LSR_DATA_READY == 0 {
                None
            } else {
                Some(port_io::inb(self.reg(0)))
            }
        }
    }
}

impl Console for SerialPort {
    fn write_str(&mut self, s: &str) {
        for b in expand_newlines(s) {
            self.send(b);
        }
    }
}

#[cfg(test)]
mod tests {
    // no_std crate 的测试构建需要显式引入 std（harness 已链接）。
    extern crate std;

    use super::{baud_divisor, expand_newlines};
    use crate::console::{Console, MemConsole};

    #[test]
    fn divisor_matches_16550_formula() {
        // 1843200 / (16 * 38400) = 3 —— QEMU/PC 经典配置。
        assert_eq!(baud_divisor(1_843_200, 38400), 3);
        assert_eq!(baud_divisor(1_843_200, 115200), 1);
        // 边界：0 波特率与极低波特率均不得返回 0。
        assert_eq!(baud_divisor(1_843_200, 0), 1);
        assert_eq!(baud_divisor(1_843_200, 1), u16::MAX);
    }

    #[test]
    fn newline_expands_to_crlf() {
        let v: std::vec::Vec<u8> = expand_newlines("a\nb").collect();
        assert_eq!(v, b"a\r\nb".to_vec());
    }

    #[test]
    fn utf8_multibyte_passes_through_unmodified() {
        let src = "空闲循环\n";
        let v: std::vec::Vec<u8> = expand_newlines(src).collect();
        let mut expect = src.as_bytes().to_vec();
        // 末尾 \n 前应插入 \r：倒数第一个字节是 \n，倒数第二个是 \r。
        expect.insert(expect.len() - 1, b'\r');
        assert_eq!(v, expect);
    }

    #[test]
    fn serial_console_contract_splits_responsibility() {
        // MemConsole 原样落盘（无 CR LF 展开），行展开是 SerialPort 实现的
        // 职责（见 newline_expands_to_crlf）；两者共享同一 Console 契约。
        let mut c = MemConsole::new();
        c.write_str("boot\n");
        assert_eq!(c.as_bytes(), b"boot\n");
    }
}
