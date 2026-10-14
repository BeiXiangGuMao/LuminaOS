//! 早期控制台：VGA 文本（80×25）+ COM1 串口（115200 8N1）双通道。
//!
//! 约定：内核控制台输出使用 ASCII——VGA 文本模式字体为 CP437，仅含
//! Latin-1 图形集；中文诊断文本一律记录在宿主侧开发日志
//! （lumina-build/logs/devlog.md），不写入内核串口/屏幕路径。
//!
//! 硬件访问全部经由 [`ostd::hw`] 的 safe 包装；本模块自身零 unsafe。

use core::fmt;

use ostd::console::Console;
use ostd::hw::ports;
use ostd::hw::vga_text;

/// VGA 默认属性：黑底白字。
const ATTR: u16 = 0x0F00;

/// VGA 文本控制台：内部维护光标，满行换行、满屏滚动。
pub struct VgaConsole {
    row: usize,
    col: usize,
}

impl VgaConsole {
    /// 清屏并复位光标。
    pub fn new() -> Self {
        for i in 0..vga_text::COLS * vga_text::ROWS {
            vga_text::write_cell(i, (b' ' as u16) | ATTR);
        }
        Self { row: 0, col: 0 }
    }

    fn newline(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= vga_text::ROWS {
            self.scroll();
        }
    }

    fn scroll(&mut self) {
        for r in 1..vga_text::ROWS {
            for c in 0..vga_text::COLS {
                let cell = vga_text::read_cell(r * vga_text::COLS + c);
                vga_text::write_cell((r - 1) * vga_text::COLS + c, cell);
            }
        }
        for c in 0..vga_text::COLS {
            vga_text::write_cell(
                (vga_text::ROWS - 1) * vga_text::COLS + c,
                (b' ' as u16) | ATTR,
            );
        }
        self.row = vga_text::ROWS - 1;
    }

    fn putc(&mut self, ch: char) {
        if ch == '\n' {
            self.newline();
            return;
        }
        let idx = self.row * vga_text::COLS + self.col;
        vga_text::write_cell(idx, ((ch as u32 & 0xFF) as u16) | ATTR);
        self.col += 1;
        if self.col >= vga_text::COLS {
            self.newline();
        }
    }
}

impl Default for VgaConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl Console for VgaConsole {
    fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.putc(ch);
        }
    }
}

impl fmt::Write for VgaConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Console::write_str(self, s);
        Ok(())
    }
}

/// COM1 串口（0x3F8）。
pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    /// 基址 0x3F8 的 COM1。
    pub fn com1() -> Self {
        Self { base: 0x3F8 }
    }

    /// 初始化：115200 波特、8N1、FIFO 使能。
    pub fn init(&self) {
        ports::write_u8(self.base + 1, 0x00); // 关中断（轮询驱动）
        ports::write_u8(self.base + 3, 0x80); // DLAB=1
        ports::write_u8(self.base, 0x01); // 除数低 8 位：1 → 115200
        ports::write_u8(self.base + 1, 0x00); // 除数高 8 位
        ports::write_u8(self.base + 3, 0x03); // 8N1，DLAB=0
        ports::write_u8(self.base + 2, 0xC7); // FIFO 使能并清空
        ports::write_u8(self.base + 4, 0x0B); // RTS/DSR/OUT2
    }

    fn send(&self, b: u8) {
        while ports::read_u8(self.base + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        ports::write_u8(self.base, b);
    }
}

/// 系统调用 SYS_LOG 直写路径：免分配逐字节输出（控制字符过滤为 '.'）。
pub fn serial_log_bytes(bytes: &[u8]) {
    let sp = SerialPort::com1();
    for &b in bytes {
        let out = if b == b'\n' {
            sp.send(b'\r');
            b'\n'
        } else if (0x20..0x7F).contains(&b) {
            b
        } else {
            b'.'
        };
        sp.send(out);
    }
    sp.send(b'\r');
    sp.send(b'\n');
}

/// 原始字节直写（TLV 帧回传用）：不做任何控制字符翻译。
pub fn serial_send_raw(bytes: &[u8]) {
    let sp = SerialPort::com1();
    for &b in bytes {
        sp.send(b);
    }
}

/// 尝试从 COM1 读一字节（LSR 就绪位轮询；无数据返回 None）。
pub fn serial_try_read() -> Option<u8> {
    let sp = SerialPort::com1();
    if ports::read_u8(sp.base + 5) & 0x01 != 0 {
        Some(ports::read_u8(sp.base))
    } else {
        None
    }
}

impl Console for SerialPort {
    fn write_str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if b == b'\n' {
                self.send(b'\r'); // 串口侧换行规范为 CRLF
            }
            self.send(b);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Console::write_str(self, s);
        Ok(())
    }
}

/// 双通道启动日志：先串口（宿主断言面），后 VGA（现场观察面）。
pub struct DualLog {
    vga: VgaConsole,
    serial: SerialPort,
}

impl DualLog {
    /// 初始化两路硬件控制台（清屏 + 串口参数复位）。
    pub fn new() -> Self {
        let serial = SerialPort::com1();
        serial.init();
        Self {
            vga: VgaConsole::new(),
            serial,
        }
    }
}

impl Default for DualLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Console for DualLog {
    fn write_str(&mut self, s: &str) {
        Console::write_str(&mut self.serial, s);
        Console::write_str(&mut self.vga, s);
    }
}

impl fmt::Write for DualLog {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Console::write_str(self, s);
        Ok(())
    }
}
