//! OSTD 硬件基元层（x86_64）。
//!
//! 依据 SPEC 第十七章 unsafe 审批矩阵：端口 I/O、VGA 文本缓冲与物理内存
//! 直读是内核可映射的最低层硬件访问，统一收口于本模块（申请编号 HW-01…03）。
//! 上层（内核框架、驱动逻辑）只允许经由本模块的 safe 包装函数触碰硬件。
//!
//! 每处 unsafe 块均携带四行 SAFETY 注释（前置条件、不变式、并发、违反后果）。

/// x86_64 端口 I/O（in/out 指令族）。
pub mod ports {
    /// 读 8 位 I/O 端口。
    #[inline]
    pub fn read_u8(port: u16) -> u8 {
        let value: u8;
        // SAFETY: 前置条件 —— `port` 为内核白名单寄存器端口（COM1/调试口等）。
        // 不变式 —— `in` 指令只访问 DX 指定端口，不触碰其他内存。
        // 并发 —— 单端口读为原子总线事务，无需额外同步。
        // 违反后果 —— 误读非白名单端口可能触发未定义设备行为或总线挂起。
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") value,
                options(nostack, preserves_flags)
            );
        }
        value
    }

    /// 写 8 位 I/O 端口。
    #[inline]
    pub fn write_u8(port: u16, value: u8) {
        // SAFETY: 前置条件 —— `port` 为内核白名单寄存器端口。
        // 不变式 —— `out` 指令只访问 DX 指定端口。
        // 并发 —— 单端口写为原子总线事务。
        // 违反后果 —— 误写非白名单端口可能改变设备状态或触发总线错误。
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// 读 16 位 I/O 端口（fw_cfg 选择子寄存器等，HW-01 扩展）。
    #[inline]
    pub fn read_u16(port: u16) -> u16 {
        let value: u16;
        // SAFETY: 前置条件 —— `port` 为内核白名单寄存器端口（0x510 fw_cfg）。
        // 不变式 —— `in` 指令只访问 DX 指定端口，不触碰其他内存。
        // 并发 —— 单端口读为原子总线事务。
        // 违反后果 —— 误读非白名单端口可能触发未定义设备行为。
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                in("dx") port,
                out("ax") value,
                options(nostack, preserves_flags)
            );
        }
        value
    }

    /// 读 32 位 I/O 端口（PCI 配置空间 0xCFC 等，M23-B 扩展）。
    #[inline]
    pub fn read_u32(port: u16) -> u32 {
        let value: u32;
        // SAFETY: 前置条件 —— `port` 为内核白名单双字端口（0xCFC 配置数据）。
        // 不变式 —— `in` 指令只访问 DX 指定端口，不触碰其他内存。
        // 并发 —— 单端口读为原子总线事务。
        // 违反后果 —— 误读非白名单端口可能触发未定义设备行为。
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                in("dx") port,
                out("eax") value,
                options(nostack, preserves_flags)
            );
        }
        value
    }

    /// 写 16 位 I/O 端口（fw_cfg 选择子寄存器等，HW-01 扩展）。
    #[inline]
    pub fn write_u16(port: u16, value: u16) {
        // SAFETY: 前置条件 —— `port` 为内核白名单寄存器端口（0x510 fw_cfg）。
        // 不变式 —— `out` 指令只访问 DX 指定端口。
        // 并发 —— 单端口写为原子总线事务。
        // 违反后果 —— 误写非白名单端口可能改变设备状态。
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// 写 32 位 I/O 端口（isa-debug-exit 等双字端口）。
    #[inline]
    pub fn write_u32(port: u16, value: u32) {
        // SAFETY: 前置条件 —— `port` 为内核白名单的双字端口（如 0xF4）。
        // 不变式 —— `out` 指令只访问 DX 指定端口。
        // 并发 —— 单端口写为原子总线事务。
        // 违反后果 —— 误写非白名单端口可能改变设备状态或触发总线错误。
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// VGA 文本模式缓冲（80×25，物理地址 0xB8000）。
pub mod vga_text {
    /// VGA 文本缓冲物理基址。
    pub const VGA_TEXT_PHYS: u64 = 0xB8000;
    /// 每行字符数。
    pub const COLS: usize = 80;
    /// 行数。
    pub const ROWS: usize = 25;

    /// 写一个字符单元（低 8 位 ASCII，高 8 位属性）。
    #[inline]
    pub fn write_cell(index: usize, cell: u16) {
        debug_assert!(index < COLS * ROWS, "vga cell index out of range");
        // SAFETY: 前置条件 —— index < 80×25，地址落在 0xB8000 起的 4 KiB
        //          文本缓冲内（缓冲实际映射 32 KiB，越界断言更严）。
        // 不变式 —— write_volatile 保证不被编译器合并或重排。
        // 并发 —— 多核同时写同一单元为数据竞争；M2 单核启动路径专用，
        //          后续显示器服务接管后本函数仅限引导期调用。
        // 违反后果 —— 越界 index 将覆写 VGA ROM 阴影区，产生显示损坏。
        unsafe {
            core::ptr::write_volatile((VGA_TEXT_PHYS as usize + 2 * index) as *mut u16, cell);
        }
    }

    /// 读一个字符单元（滚动时搬运既有内容）。
    #[inline]
    pub fn read_cell(index: usize) -> u16 {
        debug_assert!(index < COLS * ROWS, "vga cell index out of range");
        // SAFETY: 前置条件 —— 同 [`write_cell`]。
        // 不变式 —— read_volatile 保证不被编译器删除或合并。
        // 并发 —— 同 [`write_cell`]：M2 单核启动路径专用。
        // 违反后果 —— 越界 index 将读到 VGA 缓冲之外的映射区域。
        unsafe { core::ptr::read_volatile((VGA_TEXT_PHYS as usize + 2 * index) as *mut u16) }
    }
}

/// 物理内存直读（引导期信息块解析专用）。
pub mod phys {
    /// 读 32 位物理地址（volatile）。
    ///
    /// # SAFETY（调用方义务）
    /// `addr` 必须指向恒等映射内、引导层保证有效的物理地址
    /// （如 multiboot 信息块及其子结构）。
    #[inline]
    pub fn read_u32(addr: u64) -> u32 {
        // SAFETY: 前置条件 —— 调用方保证 addr 有效且已恒等映射。
        // 不变式 —— volatile 读不被编译器优化删除。
        // 并发 —— 引导期单核，无并发写者。
        // 违反后果 —— 读到无效地址触发页错误即内核 panic。
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// 读 16 位物理地址（volatile；AP 心跳探针，M5）。
    ///
    /// # SAFETY（调用方义务）
    /// `addr` 必须指向恒等映射内、引导层保证有效的物理地址。
    #[inline]
    pub fn read_u16(addr: u64) -> u16 {
        // SAFETY: 前置条件 —— 调用方保证 addr 有效且已恒等映射。
        // 不变式 —— volatile 读不被编译器优化删除。
        // 并发 —— AP 写 / BSP 读经 Release/Acquire 语义由调用方协议保证。
        // 违反后果 —— 读到无效地址触发页错误即内核 panic。
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }

    /// 读 64 位物理地址（volatile；multiboot mmap 的 addr/len 字段）。
    ///
    /// # SAFETY（调用方义务）
    /// 同 [`read_u32`]；要求 8 字节对齐由 multiboot 规范字段布局保证。
    #[inline]
    pub fn read_u64(addr: u64) -> u64 {
        // SAFETY: 前置条件 —— 调用方保证 addr 有效且已恒等映射。
        // 不变式 —— volatile 读不被编译器优化删除。
        // 并发 —— 引导期单核，无并发写者。
        // 违反后果 —— 读到无效地址触发页错误即内核 panic。
        unsafe { core::ptr::read_volatile(addr as *const u64) }
    }

    /// 写 64 位物理地址（volatile；页表条目写入等）。
    ///
    /// # SAFETY（调用方义务）
    /// `addr` 必须落在恒等映射内且调用方独占该 8 字节（如刚分配、
    /// 尚未共享的页表帧内槽位）。
    #[inline]
    pub fn write_u64(addr: u64, value: u64) {
        // SAFETY: 前置条件 —— 调用方保证 addr 有效、恒等映射且独占。
        // 不变式 —— volatile 写不被编译器删除或合并。
        // 并发 —— 独占由分配器契约保证（帧在释放前归分配者所有）。
        // 违反后果 —— 并发写同一页表槽位将产生撕裂条目，触发机器检查或
        //          错误映射。
        unsafe { core::ptr::write_volatile(addr as *mut u64, value) }
    }

    /// 将一段恒等映射物理内存清零（4 KiB 对齐使用；页表帧初始化）。
    ///
    /// # SAFETY（调用方义务）
    /// `[addr, addr+len)` 必须全部落在恒等映射内且调用方独占。
    pub fn write_zero(addr: u64, len_bytes: u64) {
        debug_assert_eq!(len_bytes % 8, 0, "zero length must be 8-byte multiple");
        let mut off: u64 = 0;
        while off < len_bytes {
            // SAFETY: 前置条件 —— 区间有效且独占（见函数级义务说明）。
            // 不变式 —— volatile 写逐 8 字节推进，off 严格递增不回绕。
            // 并发 —— 独占由调用方契约保证。
            // 违反后果 —— 越界清零将破坏相邻页表或内核数据。
            unsafe { core::ptr::write_volatile((addr + off) as *mut u64, 0u64) };
            off += 8;
        }
    }

    /// 读 8 位物理地址（volatile；用户缓冲区/TLV 逐字节拷贝用，HW-03 扩展）。
    ///
    /// # SAFETY（调用方义务）
    /// `addr` 必须落在恒等映射内且调用方拥有读取权（如系统调用传入的
    /// 用户缓冲区经校验后的区间）。
    #[inline]
    pub fn read_u8(addr: u64) -> u8 {
        // SAFETY: 前置条件 —— 调用方保证 addr 有效、恒等映射且已授权。
        // 不变式 —— volatile 读不被编译器删除。
        // 并发 —— 单核；读路径无并发写者（由系统调用契约保证）。
        // 违反后果 —— 无效地址触发 #PF，经致命异常路径退出。
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }

    /// 把宿主字节切片逐字节 volatile 写入恒等映射物理地址（HW-03 扩展：
    /// 用户程序映像装载专用）。
    ///
    /// # SAFETY（调用方义务）
    /// `[addr, addr + src.len())` 必须全部落在恒等映射内且调用方独占
    /// （如刚分配、尚未共享的用户代码帧）。
    pub fn write_bytes(addr: u64, src: &[u8]) {
        for (i, b) in src.iter().enumerate() {
            // SAFETY: 前置条件 —— 区间有效且独占（见函数级义务说明）。
            // 不变式 —— volatile 写逐字节推进，地址由 i 唯一决定。
            // 并发 —— 独占由调用方契约保证。
            // 违反后果 —— 越界写将破坏相邻页表或内核数据。
            unsafe { core::ptr::write_volatile((addr + i as u64) as *mut u8, *b) };
        }
    }

    /// 经当前页表向虚拟地址写 8 字节（volatile）——MMU 级自检专用（HW-08）。
    ///
    /// # SAFETY（调用方义务）
    /// `virt` 必须已被当前 CR3 页表映射、调用方独占且可写。
    #[inline]
    pub fn write_u64_virt(virt: u64, value: u64) {
        // SAFETY: 前置条件 —— 调用方保证 virt 已映射且独占可写。
        // 不变式 —— volatile 写不被编译器删除或合并。
        // 并发 —— 自检窗口内关中断（单核），无并发访问者。
        // 违反后果 —— 未映射地址触发 #PF，经致命异常路径退出。
        unsafe { core::ptr::write_volatile(virt as *mut u64, value) };
    }

    /// 经当前页表读虚拟地址 8 字节（volatile）——配套 [`write_u64_virt`]。
    ///
    /// # SAFETY（调用方义务）
    /// `virt` 必须已被当前 CR3 页表映射且可读。
    #[inline]
    pub fn read_u64_virt(virt: u64) -> u64 {
        // SAFETY: 前置条件 —— 调用方保证 virt 已映射可读。
        // 不变式 —— volatile 读不被编译器优化删除。
        // 并发 —— 自检窗口内关中断（单核）。
        // 违反后果 —— 未映射地址触发 #PF，经致命异常路径退出。
        unsafe { core::ptr::read_volatile(virt as *const u64) }
    }
}

/// 控制寄存器基元（HW-04）。
pub mod control {
    /// 读 CR3（当前页表根物理基址 + PCID/flags 低 12 位）。
    #[inline]
    pub fn read_cr3() -> u64 {
        let value: u64;
        // SAFETY: 前置条件 —— 在 x86_64 上执行（编译期保证）。
        // 不变式 —— mov cr3, reg 为只读传送，不改变任何机器状态。
        // 并发 —— 单核语义；CR3 天然「当前核」视角。
        // 违反后果 —— 无（纯读）。
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags))
        };
        value
    }

    /// 读 CR2（页错误故障地址；HW-04 扩展，M5 可恢复 #PF 依赖）。
    #[inline]
    pub fn read_cr2() -> u64 {
        let value: u64;
        // SAFETY: 前置条件 —— 在 x86_64 上执行（编译期保证）。
        // 不变式 —— mov cr2, reg 为只读传送，不改变任何机器状态。
        // 并发 —— 单核语义；CR2 天然「当前核」视角（每个核各自最后一次 #PF）。
        // 违反后果 —— 无（纯读）。
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags))
        };
        value
    }

    /// 失效单页 TLB 项（invlpg；HW-04 扩展，M5 TLB 击落依赖）。
    ///
    /// # SAFETY（调用方义务）
    /// `virt` 必须是调用方已调整页表映射、需要本核 TLB 失效的虚拟地址；
    /// 多核场景由击落协议（IPI + 各核自失效）保证全局可见。
    #[inline]
    pub fn invlpg(virt: u64) {
        // SAFETY: 前置条件 —— 见函数级义务说明。
        // 不变式 —— invlpg 仅失效指定线性地址的 TLB 项，不影响其他状态。
        // 并发 —— 单核本地语义；跨核可见性由击落协议保证。
        // 违反后果 —— 错过失效即读到陈旧翻译（击落协议纪律封死）。
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
    }

    /// 写 CR3（切换页表根；同时冲刷非全局 TLB）。
    ///
    /// # SAFETY（调用方义务）
    /// `root` 必须是 4 KiB 对齐、完整可用的页表根物理地址；切换后当前
    /// 栈与代码必须在新页表中仍然映射。
    #[inline]
    pub fn write_cr3(root: u64) {
        // SAFETY: 前置条件 —— root 为有效页表根且当前执行环境在其内可见。
        // 不变式 —— mov cr3 原子加载新根并冲刷 TLB；后续取指/访存按新表翻译。
        // 并发 —— 单核切换路径专用；多核 TLB 击落属 M4+ 范畴。
        // 违反后果 —— root 无效或未覆盖当前栈将立即触发三重故障。
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack)) };
    }
}

/// 中断与描述符表基元（HW-05）。
pub mod intr {
    /// 屏蔽可屏蔽中断（IF=0）。
    #[inline]
    pub fn disable() {
        // SAFETY: 前置条件 —— x86_64 执行环境。
        // 不变式 —— cli 只清除 EFLAGS.IF。
        // 并发 —— 单核即时生效；多核仅作用当前核。
        // 违反后果 —— 无。
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) };
    }

    /// 开放可屏蔽中断（IF=1）。
    #[inline]
    pub fn enable() {
        // SAFETY: 前置条件 —— IDT 已就绪（含时钟与异常门），否则首中断即三重故障。
        // 不变式 —— sti 只置位 EFLAGS.IF，且在下一条指令之后才生效。
        // 并发 —— 单核语义。
        // 违反后果 —— IDT 未就绪时开中断，到达的中断将导致停机。
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
    }

    /// 暂停执行直至下一个中断到达（要求 IF=1；否则裸机上无限挂起）。
    #[inline]
    pub fn halt() {
        // SAFETY: 前置条件 —— IF=1（调用方已 sti），有中断源可唤醒。
        // 不变式 —— hlt 使核心进入停等态，中断返回后继续执行。
        // 并发 —— 单核语义；中断处理返回即唤醒。
        // 违反后果 —— IF=0 时调用在无 NMI 的裸机上永不返回。
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }

    /// 探测当前 IF 状态（true = 中断已开放）。
    #[inline]
    pub fn if_enabled() -> bool {
        let flags: u64;
        // SAFETY: 前置条件 —— x86_64 执行环境。
        // 不变式 —— pushfq 只读 RFLAGS 到栈顶再弹出，机器状态不变。
        // 并发 —— 单核即时语义。
        // 违反后果 —— 无（纯读）。
        unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(nomem)) };
        flags & 0x200 != 0
    }

    /// 加载中断描述符表寄存器（IDTR）。
    ///
    /// # SAFETY（调用方义务）
    /// `[base, base+limit]` 指向的 IDT 必须在加载后保持有效且不再修改
    /// （静态存储期或调用方保证）；表中门指向的处理程序必须满足
    /// x86-interrupt ABI。
    #[inline]
    pub fn lidt(base: usize, limit: u16) {
        // IDTR 装载操作数：16 位界限 + 64 位基址（packed(2) 保证 2 字节对齐）。
        #[repr(C, packed(2))]
        struct DescPtr {
            limit: u16,
            base: usize,
        }
        let dp = DescPtr { limit, base };
        // SAFETY: 前置条件 —— 见函数级义务；dp 在本语句栈帧内存活。
        // 不变式 —— lidt 仅读取 [dp] 指向的 10 字节并加载 IDTR。
        // 并发 —— 单核启动路径专用。
        // 违反后果 —— 加载越界或悬垂表地址后，首个中断即三重故障。
        unsafe { core::arch::asm!("lidt [{}]", in(reg) &dp, options(nostack, preserves_flags)) };
    }
}

/// 8259A 可编程中断控制器（PIC）——HW-06。
///
/// M3 单核布局：主 PIC 向量基址 0x20（IRQ0..7 → 32..39），从 PIC 0x28
/// （IRQ8..15 → 40..47）；仅开放 IRQ0（PIT 节拍），其余全屏蔽。
pub mod pic {
    use super::ports;

    const CMD_MASTER: u16 = 0x20;
    const DATA_MASTER: u16 = 0x21;
    const CMD_SLAVE: u16 = 0xA0;
    const DATA_SLAVE: u16 = 0xA1;
    const EOI: u8 = 0x20;

    /// 重映射两片 PIC 至向量 0x20/0x28，随后仅开放 IRQ0。
    pub fn remap_timer_only() {
        // ICW1：级联 + 边沿触发 + ICW4
        ports::write_u8(CMD_MASTER, 0x11);
        ports::write_u8(CMD_SLAVE, 0x11);
        // ICW2：向量基址
        ports::write_u8(DATA_MASTER, 0x20);
        ports::write_u8(DATA_SLAVE, 0x28);
        // ICW3：主片第 2 位接从片；从片接主片 IRQ2
        ports::write_u8(DATA_MASTER, 0x04);
        ports::write_u8(DATA_SLAVE, 0x02);
        // ICW4：8086 模式
        ports::write_u8(DATA_MASTER, 0x01);
        ports::write_u8(DATA_SLAVE, 0x01);
        // OCW1：主片 0xFE（仅 IRQ0 开放），从片全屏蔽
        ports::write_u8(DATA_MASTER, 0xFE);
        ports::write_u8(DATA_SLAVE, 0xFF);
    }

    /// 主片 EOI（IRQ0..7 处理完毕必发）。
    #[inline]
    pub fn eoi_master() {
        ports::write_u8(CMD_MASTER, EOI);
    }

    /// 读中断屏蔽寄存器（OCW1 读回 = IMR），供自检断言。
    pub fn masks() -> (u8, u8) {
        (ports::read_u8(DATA_MASTER), ports::read_u8(DATA_SLAVE))
    }

    /// 解除 IRQ1（PS/2 键盘）屏蔽——M23-①：IMR bit1 清零写回（读改写
    /// 保留其余屏蔽位；remap_timer_only 后主片 IMR=0xFE，清 bit1 → 0xFC）。
    pub fn unmask_irq1() {
        let imr = ports::read_u8(DATA_MASTER) & !0x02;
        ports::write_u8(DATA_MASTER, imr);
    }
}

/// PS/2 键盘控制器（i8042）——M23-①。第一 PS/2 口（0x60 数据）布线
/// IRQ1；QEMU `isa-debug-exit` 机默认挂 i8042（-machine pc 标配）。
pub mod ps2 {
    use super::ports;

    const DATA: u16 = 0x60;
    const STATUS: u16 = 0x64;
    const CMD: u16 = 0x64;

    /// 输出缓冲状态位（STATUS bit0：1 = DATA 可读）。
    pub const ST_OUT_FULL: u8 = 0x01;

    /// 读状态寄存器。
    #[inline]
    pub fn status() -> u8 {
        ports::read_u8(STATUS)
    }

    /// 读数据口（调用方须先确认 status() & ST_OUT_FULL）。
    #[inline]
    pub fn data_read() -> u8 {
        ports::read_u8(DATA)
    }

    /// 控制器自测（命令 0xAA）：通过返回 Some(0x55)。忙等预算 10 万轮
    /// （QEMU TCG 下毫秒级；超限返回 None——控制器缺失/挂死由自检报败）。
    /// **IRQ1 自屏蔽**：i8042 输出缓冲非空即拉 IRQ1（QEMU 实测活体），
    /// ISR 抢读响应字节会饿死本测试——入口存 IMR、临时 mask bit1、
    /// 出口恢复（自包含，任何调用点均安全）。
    pub fn controller_self_test() -> Option<u8> {
        const IMR_MASTER: u16 = 0x21;
        let saved = ports::read_u8(IMR_MASTER);
        ports::write_u8(IMR_MASTER, saved | 0x02);
        ports::write_u8(CMD, 0xAA);
        let mut got = None;
        for _ in 0..100_000 {
            if status() & ST_OUT_FULL != 0 {
                got = Some(data_read());
                break;
            }
            core::hint::spin_loop();
        }
        ports::write_u8(IMR_MASTER, saved);
        got.filter(|&b| b == 0x55)
    }
}

/// 8253/8254 可编程间隔定时器（PIT）——HW-07。通道 0 接 PIC IRQ0。
pub mod pit {
    use super::ports;

    /// PIT 晶振基频（Hz）。
    const BASE_HZ: u32 = 1_193_182;
    const CMD_CH0: u16 = 0x43;
    const DATA_CH0: u16 = 0x40;

    /// 以目标频率编程通道 0（模式 3 方波）；返回实际分频后的频率。
    /// 频率下限 19 Hz（分频 65536），上限为基频。
    pub fn init_channel0(hz: u32) -> u32 {
        let hz = hz.clamp(19, BASE_HZ);
        let div = (BASE_HZ / hz).clamp(1, 65_536);
        // 0x36：通道 0 | 先低后高字节 | 模式 3 | 二进制计数
        ports::write_u8(CMD_CH0, 0x36);
        ports::write_u8(DATA_CH0, (div & 0xFF) as u8);
        ports::write_u8(DATA_CH0, (div >> 8) as u8);
        BASE_HZ / div
    }
}

/// 模型专用寄存器（MSR）读写——HW-09（M4 申请新增）。
///
/// 用途：EFER（SCE 系统调用使能）、IA32_STAR/LSTAR/FMASK（系统调用
/// 入口约定）、IA32_APIC_BASE（SMP 探测）。上层不得绕过本模块触碰 MSR。
pub mod msr {
    /// 读 MSR（ecx=寄存器号，返回 edx:eax 拼合的 64 位值）。
    #[inline]
    pub fn read(msr: u32) -> u64 {
        let (lo, hi): (u32, u32);
        // SAFETY: 前置条件 —— `msr` 为内核白名单寄存器（EFER/STAR/LSTAR/
        //          FMASK/APIC_BASE），rdmsr 不访问内存。
        // 不变式 —— edx:eax 原样拼合，无符号扩展歧义。
        // 并发 —— 单核语义；MSR 天然「当前核」视角。
        // 违反后果 —— 读取保留 MSR 触发 #GP，经致命异常路径退出。
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((hi as u64) << 32) | lo as u64
    }

    /// 写 MSR。
    ///
    /// # Safety
    ///
    /// `msr` 必须为白名单寄存器且写入值符合 SDM 该寄存器的保留位约束
    /// （如 EFER 只允许置位已实现的特性位）。违反即触发 #GP 或改变
    /// 全局机器状态（如 LME），后果由调用方承担。
    #[inline]
    pub unsafe fn write(msr: u32, value: u64) {
        let lo = value as u32;
        let hi = (value >> 32) as u32;
        // SAFETY: 前置条件 —— 见函数级义务说明。
        // 不变式 —— wrmsr 原子写入 64 位值，不触碰内存与栈。
        // 并发 —— 单核语义。
        // 违反后果 —— 非法写入可触发 #GP 或改变全局机器状态（如 LME）。
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") lo,
                in("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// 时间戳计数器（TSC）——HW-10（M4 申请新增）。
pub mod tsc {
    /// 读 TSC（64 位单调计数；频率经 [`crate::time`] 校准）。
    #[inline]
    pub fn read() -> u64 {
        let (lo, hi): (u32, u32);
        // SAFETY: 前置条件 —— x86_64 执行环境（编译期保证）。
        // 不变式 —— rdtsc 返回单调递增计数（QEMU/现代硬件保证不回退）。
        // 并发 —— 单核视角；跨核不做同步比较（M4 单核）。
        // 违反后果 —— 无（纯读）。
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
        };
        ((hi as u64) << 32) | lo as u64
    }
}

/// CPUID 探测——HW-12（M4 申请新增；SMP 就绪探测用）。
pub mod cpuid {
    /// CPUID 叶子 1 的原始返回（eax/ebx/ecx/edx）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Leaf1 {
        /// eax：版本信息（家族/型号/步进）。
        pub eax: u32,
        /// ebx：高 8 位 = 初始 APIC ID。
        pub ebx: u32,
        /// ecx：特性位 1（位 9 = LAPIC 在位）。
        pub ecx: u32,
        /// edx：特性位 2（位 5 = PSE，诊断用）。
        pub edx: u32,
    }

    /// 执行 CPUID 叶子 1。
    pub fn leaf1() -> Leaf1 {
        let (eax, ecx, edx, ebx_via_r11): (u32, u32, u32, u32);
        // SAFETY: 前置条件 —— x86_64 执行环境（编译期保证）。
        // 不变式 —— push/pop rbx 配对保护被调用者保存寄存器；cpuid 为
        //          序列化指令，返回叶子 1 的固定布局；ebx 经 r11d 转出。
        // 并发 —— 单核视角，无共享状态。
        // 违反后果 —— 无（纯读探测）。
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "mov r11d, ebx",
                "pop rbx",
                out("eax") eax,
                out("ecx") ecx,
                out("edx") edx,
                out("r11d") ebx_via_r11,
                options(nostack)
            );
        }
        Leaf1 {
            eax,
            ebx: ebx_via_r11,
            ecx,
            edx,
        }
    }

    /// 从叶子 1 提取（APIC 在位, 初始 APIC ID）——纯函数，宿主可测。
    pub fn parse_leaf1(l: Leaf1) -> (bool, u8) {
        (l.ecx & (1 << 9) != 0, (l.ebx >> 24) as u8)
    }
}

/// 本地 APIC（LAPIC）——HW-13（M5 申请新增：IPI 与 SMP 依赖）。
///
/// xAPIC 模式：MMIO 寄存器窗口 1 KiB（实际跨 4 KiB 页），基址取自
/// IA32_APIC_BASE（MSR 0x1B）。基址物理页 MUST 已被当前 CR3 恒等映射
/// （kernel::smp 经页表抽象在引导根补建 2 MiB 窗口后再启用本模块）。
/// 寄存器一律 32 位宽度访问（SDM Vol.3 §10.12）。
pub mod lapic {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// IA32_APIC_BASE MSR 号。
    pub const MSR_APIC_BASE: u32 = 0x1B;
    /// LAPIC 全局使能位（MSR bit 11）。
    pub const APIC_BASE_ENABLE: u64 = 1 << 11;
    /// BSC 标志（bit 8）：当前核为引导核。
    pub const APIC_BASE_BSC: u64 = 1 << 8;

    /// 寄存器偏移（xAPIC）。
    const REG_ID: u32 = 0x020;
    const REG_EOI: u32 = 0x0B0;
    const REG_SPURIOUS: u32 = 0x0F0;
    const REG_ICR_LOW: u32 = 0x300;
    const REG_ICR_HIGH: u32 = 0x310;
    const REG_TIMER_LVT: u32 = 0x320;
    const REG_TIMER_ICR: u32 = 0x380;
    const REG_TIMER_CCR: u32 = 0x390;
    const REG_TIMER_DIV: u32 = 0x3E0;

    /// 固定交付 IPI 向量：TLB 击落（内核/OSTD 共用，M5）。
    pub const IPI_VECTOR: u8 = 0x40;
    /// LAPIC 定时器向量：统一 per-CPU 抢占源（M6-A，内核/OSTD 共用）。
    pub const TIMER_VECTOR: u8 = 0x41;
    /// 跨核重调度提示 IPI 向量（M6-A：唤醒 idle 核重新拾取全局就绪队列）。
    pub const RESCHED_VECTOR: u8 = 0x42;

    /// ICR 交付模式：INIT（100b→5）。
    const ICR_INIT: u32 = 5 << 8;
    /// ICR 交付模式：StartUp（110b→6）。
    const ICR_SIPI: u32 = 6 << 8;
    /// ICR level 位（INIT assert）。
    const ICR_ASSERT: u32 = 1 << 14;
    /// ICR 交付状态位（bit 12：1 = 发送中）。
    const ICR_SENDING: u32 = 1 << 12;
    /// Spurious 寄存器 APIC 软件使能位（bit 8）。
    const SPURIOUS_ENABLE: u32 = 1 << 8;

    /// MMIO 基址缓存（enable_access 时记录；0 = 尚未就绪）。
    static BASE: AtomicU64 = AtomicU64::new(0);

    /// 读 LAPIC 基址（IA32_APIC_BASE 高位，剔除低 12 位标志）。
    #[inline]
    pub fn base() -> u64 {
        super::msr::read(MSR_APIC_BASE) & !0xFFF
    }

    /// 记录 MMIO 基址（调用方保证基址页已恒等映射）。幂等。
    ///
    /// # SAFETY（调用方义务）
    /// 基址页已被当前与后续所有将运行核的 CR3 映射（M5：引导根恒等补建）。
    pub fn enable_access() {
        BASE.store(base(), Ordering::Release);
    }

    /// 基址是否已就绪（自检断言用）。
    pub fn access_ready() -> bool {
        BASE.load(Ordering::Acquire) != 0
    }

    /// 读寄存器（32 位）。
    ///
    /// # SAFETY（调用方义务）
    /// 基址页已映射（见 [`enable_access`]）且偏移为 LAPIC 白名单寄存器。
    #[inline]
    fn read_reg(offset: u32) -> u32 {
        let b = BASE.load(Ordering::Acquire);
        debug_assert_ne!(b, 0, "lapic access before enable_access");
        // SAFETY: 前置条件 —— b 为已映射 MMIO 基址（enable_access 契约）。
        // 不变式 —— volatile 读不被编译器删除；xAPIC 寄存器 32 位宽度。
        // 并发 —— MMIO 读无副作用，多核并发读安全。
        // 违反后果 —— 未映射基址触发 #PF（经可恢复桩转致命路径退出）。
        unsafe { core::ptr::read_volatile((b + offset as u64) as *const u32) }
    }

    /// 写寄存器（32 位）。
    ///
    /// # SAFETY（调用方义务）
    /// 同 [`read_reg`]；ICR 等命令寄存器的写入有副作用，调用方保证
    /// 时序（INIT → 延时 → SIPI）。
    #[inline]
    fn write_reg(offset: u32, value: u32) {
        let b = BASE.load(Ordering::Acquire);
        debug_assert_ne!(b, 0, "lapic access before enable_access");
        // SAFETY: 前置条件 —— b 为已映射 MMIO 基址（enable_access 契约）。
        // 不变式 —— volatile 写不被编译器合并；32 位宽度符合 xAPIC 约定。
        // 并发 —— ICR/EOI 由协议层串行化（BSP 单发送者 / 中断窗口内）。
        // 违反后果 —— 并发写 ICR 将产生未定义交付行为。
        unsafe { core::ptr::write_volatile((b + offset as u64) as *mut u32, value) }
    }

    /// 软件启用本核 LAPIC（置 spurious 寄存器 bit 8，spurious 向量 0xFF）。
    pub fn enable() {
        let v = read_reg(REG_SPURIOUS);
        write_reg(REG_SPURIOUS, (v & !0xFF) | 0xFF | SPURIOUS_ENABLE);
    }

    /// 本核 APIC ID（xAPIC：ID 寄存器高 8 位有效）。
    pub fn id() -> u8 {
        (read_reg(REG_ID) >> 24) as u8
    }

    /// 发送 EOI（中断处理完毕必发；IPI 与 LAPIC 交付的中断共用）。
    #[inline]
    pub fn eoi() {
        write_reg(REG_EOI, 0);
    }

    /// 向指定 APIC ID 发送 INIT IPI（assert；等待交付状态位清零）。
    pub fn send_init(dest_apic_id: u8) {
        write_reg(REG_ICR_HIGH, u32::from(dest_apic_id) << 24);
        write_reg(REG_ICR_LOW, ICR_INIT | ICR_ASSERT);
        wait_delivery();
    }

    /// 向指定 APIC ID 发送 SIPI（启动向量 = 物理页号，跳转 `page << 12`）。
    pub fn send_sipi(dest_apic_id: u8, start_page: u8) {
        write_reg(REG_ICR_HIGH, u32::from(dest_apic_id) << 24);
        write_reg(REG_ICR_LOW, ICR_SIPI | u32::from(start_page));
        wait_delivery();
    }

    /// 向指定 APIC ID 发送固定交付 IPI（Fixed，边沿触发，指定向量）。
    /// M5：TLB 击落（向量 0x40）。
    pub fn send_fixed_ipi(dest_apic_id: u8, vector: u8) {
        write_reg(REG_ICR_HIGH, u32::from(dest_apic_id) << 24);
        write_reg(REG_ICR_LOW, ICR_ASSERT | u32::from(vector));
        wait_delivery();
    }

    /// 轮询 ICR 交付状态位清零（TCG/QEMU 下数步即清；防御性有界等待）。
    fn wait_delivery() {
        for _ in 0..1_000_000 {
            if read_reg(REG_ICR_LOW) & ICR_SENDING == 0 {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// 配置定时器分频（divide configuration 寄存器；SDM 编码：
    /// 0x0=1，0x1=2，0x2=4，0x3=8，0x8=16，0x9=32，0xA=64，0xB=128）。
    pub fn timer_set_divide(code: u32) {
        write_reg(REG_TIMER_DIV, code & 0xB);
    }

    /// 屏蔽（mask）本核定时器 LVT（启动/校准期防止意外中断交付）。
    pub fn timer_mask() {
        let lvt = read_reg(REG_TIMER_LVT);
        write_reg(REG_TIMER_LVT, lvt | LVT_MASK);
    }

    /// 解除本核定时器 LVT 屏蔽（保留向量/模式位；M8-B 换页 I/O 窗口
    /// 后恢复节拍——长 ISR 期间积压的未决节拍在恢复后经正常 IDT
    /// 路径交付，避开 iretq/sysret 边缘交付的 TCG 隐患族）。
    pub fn timer_unmask() {
        let lvt = read_reg(REG_TIMER_LVT);
        write_reg(REG_TIMER_LVT, lvt & !LVT_MASK);
    }

    /// 以周期模式启动本核定时器：向量 = `vector`，初值计数 =
    /// `initial_count`（递减到 0 重新装载并交付中断）。
    ///
    /// # Safety
    ///
    /// 向量必须已在 IDT 注册 LAPIC 定时器桩，否则首次到期即三重故障。
    pub unsafe fn timer_start_periodic(vector: u8, initial_count: u32) {
        write_reg(REG_TIMER_LVT, (u32::from(vector) & 0xFF) | LVT_PERIODIC);
        write_reg(REG_TIMER_ICR, initial_count);
    }

    /// 读定时器当前计数（递减值）。
    pub fn timer_read_count() -> u32 {
        read_reg(REG_TIMER_CCR)
    }

    /// 写定时器初值计数（校准期用；周期模式下写 ICR 即重启一轮）。
    pub fn timer_write_count(v: u32) {
        write_reg(REG_TIMER_ICR, v);
    }

    /// LVT 定时器掩码位（bit 16）。
    const LVT_MASK: u32 = 1 << 16;
    /// LVT 定时器周期模式位（bit 17）。
    const LVT_PERIODIC: u32 = 1 << 17;
}

/// 64 位 GDT / TSS 装载——HW-11（M4 申请新增：用户态隔离与 RSP0 依赖）。
///
/// 选择子布局（与 SYSCALL/SYSRET 的 IA32_STAR 约定配套）：
/// `0x00` 空 | `0x08` 内核代码 | `0x10` 内核数据 | `0x18` 用户代码 |
/// `0x20` 用户数据 | `0x28` TSS（系统段描述符含高 32 位基址）。
///
/// M7-A per-CPU 化：每 CPU 一套 GDT + TSS（布局相同、槽位同构），ring3
/// 中断/异常按本核 TR 指向的 TSS.RSP0 切栈——用户任务跨核派发的硬件前提。
pub mod gdt {
    /// 内核代码选择子。
    pub const SEL_KERNEL_CODE: u64 = 0x08;
    /// 内核数据选择子。
    pub const SEL_KERNEL_DATA: u64 = 0x10;
    /// 用户代码选择子（RPL=3）。
    pub const SEL_USER_CODE: u64 = 0x1B;
    /// 用户数据选择子（RPL=3）。
    pub const SEL_USER_DATA: u64 = 0x23;
    /// TSS 选择子。
    pub const SEL_TSS: u64 = 0x28;

    /// 64 位任务状态段（SDM Vol.3 Table 7-7 精确布局，104 字节）。
    ///
    /// 关键约束：RSP0 位于偏移 0x04（**非 8 字节对齐**的 u64 域）——
    /// repr(C) 的 u64 对齐会把它错放到 0x08，CPU 读 TSS+4 得 0，
    /// ring3 中断向量化即 #SS（M4 开发期实测三重故障根因）。
    /// 故以 u32 字数组精确落位：RSP0 = words[1](lo) | words[2](hi)。
    #[repr(C, align(16))]
    pub struct TaskStateSegment {
        /// 26 × u32 = 104 字节原始布局。
        words: [u32; 26],
    }

    impl Default for TaskStateSegment {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TaskStateSegment {
        /// 全零 TSS；I/O 位图偏移写至 0x66 = 104（无位图语义）。
        pub const fn new() -> Self {
            let mut w = [0u32; 26];
            // 0x66 字节 = words[25] 的高 16 位（0x64..0x68 窗口内偏移 2）
            w[25] = (core::mem::size_of::<Self>() as u32) << 16;
            Self { words: w }
        }

        /// RSP0 写入（SDM 偏移 0x04..0x0C）。
        fn set_rsp0_raw(&mut self, addr: u64) {
            self.words[1] = addr as u32;
            self.words[2] = (addr >> 32) as u32;
        }
    }

    /// per-CPU 上界（与 kernel::task::MAX_CPUS 同源：MADT 探测契约）。
    const MAX_TSS_CPUS: usize = 2;

    // TSS per-CPU 实例；RSP0 仅由本核调度点独占写入（见 set_rsp0）。
    static mut TSS: [TaskStateSegment; MAX_TSS_CPUS] =
        [TaskStateSegment::new(), TaskStateSegment::new()];

    /// 7 槽 GDT：null / kcode / kdata / ucode / udata / TSS 低 / TSS 高。
    #[repr(C, align(16))]
    struct GdtTable {
        slots: [u64; 7],
    }

    impl GdtTable {
        const fn new() -> Self {
            Self {
                slots: [
                    0x0000_0000_0000_0000, // null
                    0x0020_9A00_0000_0000, // 0x08 内核代码
                    0x0000_9200_0000_0000, // 0x10 内核数据
                    0x0020_FA00_0000_0000, // 0x18 用户代码
                    0x0000_F200_0000_0000, // 0x20 用户数据
                    0,                     // 0x28 TSS 低半部（install 时填写）
                    0,                     // TSS 高半部（install 时填写）
                ],
            }
        }
    }

    // 64 位规范描述符形式（与 boot.rs 启动 GDT 同源）：L=1、D/B=0、
    // 无粒度位——长模式下基址/界限/G/D 全部被忽略，仅属性参与检查；
    // D=1 & L=1 为保留组合（加载即 #GP）。per-CPU 实例：GDTS[cpu] 的
    // TSS 描述符指向 TSS[cpu]（install/location_cpu 时填写）。
    static mut GDTS: [GdtTable; MAX_TSS_CPUS] = [GdtTable::new(), GdtTable::new()];

    /// GDTR 装载操作数（16 位界限 + 64 位基址；packed(2) 保证 2 字节对齐）。
    #[repr(C, packed(2))]
    struct DescPtr {
        limit: u16,
        base: u64,
    }

    /// 当前核用户任务的内核栈顶（RSP0）；调度器派发用户任务前写入。
    ///
    /// # SAFETY（调用方义务）
    /// `cpu` 为当前核槽位；写入点为本核调度派发窗口（IntWindow 内，
    /// 中断关闭），且该 TSS 仅被本核派发路径触碰；`addr` 必须为有效、
    /// 16 字节对齐的内核栈顶。
    pub fn set_rsp0(cpu: usize, addr: u64) {
        // SAFETY: 前置条件 —— 本核调度点独占写入（见函数级义务）。
        // 不变式 —— TSS 常驻静态存储期；写入对下次 ring3 中断可见。
        // 并发 —— per-CPU 索引隔离：每核只写 TSS[本核]。
        // 违反后果 —— RSP0 悬垂将使 ring3 中断切入无效栈（三重故障）。
        unsafe {
            let tss = core::ptr::addr_of_mut!(TSS[cpu]);
            (*tss).set_rsp0_raw(addr);
        }
    }

    /// 读取本核 TSS.RSP0 当前值（自检取证用；与写入同一 per-CPU 纪律）。
    pub fn rsp0(cpu: usize) -> u64 {
        // SAFETY: 仅读取静态 TSS 的 words 字段（不产生中间引用）。
        unsafe {
            let tss = core::ptr::addr_of!(TSS[cpu]);
            u64::from((*tss).words[1]) | (u64::from((*tss).words[2]) << 32)
        }
    }

    /// 填写 `GDTS[cpu]` 的 TSS 描述符两槽（幂等；lgdt 前调用）。
    fn fill_tss_descriptor(cpu: usize) {
        // SAFETY: 静态表槽位填写；调用点在 lgdt 之前（无并发读者）。
        unsafe {
            let tss_base = core::ptr::addr_of!(TSS[cpu]) as u64;
            let tss_len = (core::mem::size_of::<TaskStateSegment>() - 1) as u32;
            let (tlo, thi) = tss_descriptor(tss_base, tss_len);
            let gdt_ptr = core::ptr::addr_of_mut!(GDTS[cpu]);
            (*gdt_ptr).slots[5] = tlo;
            (*gdt_ptr).slots[6] = thi;
        }
    }

    /// AP 侧装载任务寄存器（TR ← SEL_TSS）：AP trampoline 已 lgdt 本核
    /// per-CPU GDT（经 [`location_cpu`] 交接），此处仅补 ltr——M7-A 前
    /// AP 无 TR，ring3 中断向量化即三重故障，故用户任务跨核前必须调用。
    ///
    /// # SAFETY（调用方义务）
    /// 本核已 lgdt 包含 SEL_TSS 描述符的 per-CPU GDT；调用窗口中断关闭。
    pub fn load_tr() {
        // SAFETY: 前置条件 —— 本核 GDT 已装载且描述符已填写（见义务）。
        // 不变式 —— TR 指向 TSS[本核]；此后 ring3 中断按 RSP0 切栈。
        // 并发 —— 仅 AP 启动路径调用（上线握手前）。
        // 违反后果 —— TR 悬空即 ring3 中断三重故障（冒烟门禁拦截）。
        unsafe {
            core::arch::asm!(
                "ltr ax",
                in("ax") SEL_TSS as u16,
            );
        }
    }

    /// per-CPU GDT 基址与界限（AP trampoline handoff 写入用；M7-A）。
    /// 调用即完成该核 TSS 描述符填写（幂等）；零 deref 之外的副作用仅此。
    pub fn location_cpu(cpu: usize) -> (u64, u16) {
        fill_tss_descriptor(cpu);
        // SAFETY: 仅取静态存储地址（不 deref）；无中间引用。
        let g = unsafe { core::ptr::addr_of!(GDTS[cpu]) };
        (g as u64, (core::mem::size_of::<GdtTable>() - 1) as u16)
    }

    /// 构造 TSS 系统段描述符（available 64-bit TSS，type=0x9，G=0）。
    fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
        let lo = (limit & 0xFFFF) as u64
            | ((base & 0xFFFF) << 16)
            | (((base >> 16) & 0xFF) << 32)
            | (0x89u64 << 40)
            | (((base >> 24) & 0xFF) << 56);
        let hi = base >> 32;
        (lo, hi)
    }

    /// 装载 GDT（CPU0 = BSP）+ 重载全部段寄存器 + LTR。
    ///
    /// 装载后段选择子语义固定为模块级布局；重复调用幂等（重载同值）。
    /// AP 侧不经此函数：trampoline 以 [`location_cpu`] 交接的 per-CPU
    /// GDT 自行 lgdt，ap_main 再调 [`load_tr`] 补装任务寄存器。
    pub fn install() {
        // SAFETY: 前置条件 —— 启动期单核，GDT 静态存储期无并发读者。
        // 不变式 —— 描述符填写完成后才执行 lgdt/ltr。
        // 并发 —— 启动期/自检前无其他执行者。
        // 违反后果 —— 并发装载将产生撕裂描述符（调度纪律封死）。
        unsafe {
            let gdt_ptr = core::ptr::addr_of_mut!(GDTS[0]);
            let tss_base = core::ptr::addr_of!(TSS[0]) as u64;
            let tss_len = (core::mem::size_of::<TaskStateSegment>() - 1) as u32;
            let (tlo, thi) = tss_descriptor(tss_base, tss_len);
            (*gdt_ptr).slots[5] = tlo;
            (*gdt_ptr).slots[6] = thi;
            let dp = DescPtr {
                limit: (core::mem::size_of::<GdtTable>() - 1) as u16,
                base: gdt_ptr as u64,
            };
            core::arch::asm!(
                "lgdt [rcx]",
                "push r8",
                "lea r11, [rip + 2f]",
                "push r11",
                "retfq",
                "2:",
                "mov ax, r9w",
                "mov ds, ax",
                "mov es, ax",
                "mov ss, ax",
                "xor ax, ax",
                "mov fs, ax",
                "mov gs, ax",
                "mov ax, r10w",
                "ltr ax",
                in("rcx") &dp,
                in("r8") SEL_KERNEL_CODE,
                in("r9") SEL_KERNEL_DATA as u16,
                in("r10") SEL_TSS as u16,
                out("r11") _,
                out("rax") _,
            );
        }
    }
}

/// ATA PIO（轮询式）块设备基元——HW-15（M7-B 申请新增：swap 换页 I/O 硬件面）。
///
/// 仅支持 LBA28 单扇区 PIO（IDENTIFY / READ SECTORS / WRITE SECTORS），
/// 全程忙等 + 有界超时（不启用 ATA 中断——冒烟面确定性优先；IRQ14 保持
/// PIC 掩码）。驱动无内部状态（端口组即全部状态），通道协议不可重入，
/// 并发访问由调用方（kernel::swap）持锁串行化。
pub mod ata {
    use super::ports;

    /// 扇区字数（256 × u16 = 512 B）。
    pub const SECTOR_WORDS: usize = 256;

    /// ATA 操作错误面。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AtaError {
        /// 忙等超时（设备无响应；上限见 [`AtaDisk::SPIN_LIMIT`]）。
        Timeout,
        /// 设备报告错误（状态寄存器 ERR 位）。
        DeviceError,
        /// 探测失败（通道无设备 / 设备不响应 IDENTIFY）。
        NoDevice,
    }

    /// 一个 ATA PIO 通道盘位端口组（QEMU IDE：PIIX3 双通道主/从盘）。
    ///
    /// M17-① 扩展：原仅主盘（drive 位 0）；新增从盘位（设备寄存器
    /// bit4 = 0x10，LBA 模式下 0xE0|0xF0 高 nibble + drive 位 + LBA 高
    /// 四位），支撑主通道从盘作数据盘（避开启动盘 index=0 与 swap 盘
    /// index=2，双通道物理并行）。
    #[derive(Debug, Clone, Copy)]
    pub struct AtaDisk {
        /// 命令块寄存器基址（0x1F0 主通道 / 0x170 从通道）。
        base: u16,
        /// 控制块寄存器（ALT STATUS；0x3F6 / 0x376）。
        ctrl: u16,
        /// 盘位选择位（0 = 主盘，0x10 = 从盘；并入设备寄存器高 nibble）。
        drive: u8,
    }

    impl AtaDisk {
        /// 主通道主盘。
        pub const PRIMARY_MASTER: Self = Self {
            base: 0x1F0,
            ctrl: 0x3F6,
            drive: 0x00,
        };
        /// 主通道从盘（M17-① 数据盘挂此：与启动盘同通道异盘，运行期
        /// 启动盘静默无交叉；与 swap 盘（从通道）物理并行零冲突）。
        pub const PRIMARY_SLAVE: Self = Self {
            base: 0x1F0,
            ctrl: 0x3F6,
            drive: 0x10,
        };
        /// 从通道主盘（M7 冒烟 swap 盘挂此：避开任何启动设备序交互）。
        pub const SECONDARY_MASTER: Self = Self {
            base: 0x170,
            ctrl: 0x376,
            drive: 0x00,
        };
        /// 从通道从盘（对称补全；当前无消费方，预留给双盘从通道布局）。
        pub const SECONDARY_SLAVE: Self = Self {
            base: 0x170,
            ctrl: 0x376,
            drive: 0x10,
        };

        /// 忙等上限（QEMU TCG 单次远小于 1 s；远超任何合法 PIO 延迟）。
        const SPIN_LIMIT: u32 = 20_000_000;

        // 状态寄存器位。
        const SR_BSY: u8 = 0x80;
        const SR_DRQ: u8 = 0x08;
        const SR_ERR: u8 = 0x01;

        /// 400 ns 设备内部分隔：连读 4 次 ALT STATUS（ATA 约定）。
        fn wait_400ns(&self) {
            for _ in 0..4 {
                let _ = ports::read_u8(self.ctrl);
            }
        }

        /// 轮询直至 BSY=0；返回最终状态字节。
        fn wait_not_busy(&self) -> Result<u8, AtaError> {
            for _ in 0..Self::SPIN_LIMIT {
                let st = ports::read_u8(self.base + 7);
                if st & Self::SR_BSY == 0 {
                    return Ok(st);
                }
                core::hint::spin_loop();
            }
            Err(AtaError::Timeout)
        }

        /// 轮询直至 BSY=0 且 DRQ=1（一扇区数据就绪）。
        fn wait_data_ready(&self) -> Result<(), AtaError> {
            for _ in 0..Self::SPIN_LIMIT {
                let st = ports::read_u8(self.base + 7);
                if st & Self::SR_BSY == 0 {
                    if st & Self::SR_DRQ != 0 {
                        return Ok(());
                    }
                    if st & Self::SR_ERR != 0 {
                        return Err(AtaError::DeviceError);
                    }
                }
                core::hint::spin_loop();
            }
            Err(AtaError::Timeout)
        }

        /// 选择盘位 + 写入 LBA 高 4 位（设备寄存器 0xE0 | drive | lba[27:24]）。
        fn select(&self, lba: u32) {
            // 0xE0 = LBA 模式 + 主盘位；| drive 位（0x10 = 从盘，M17-①）。
            ports::write_u8(
                self.base + 6,
                0xE0 | self.drive | ((lba >> 24) & 0x0F) as u8,
            );
            self.wait_400ns();
        }

        /// 写任务文件寄存器（扇区计数 + LBA 低 24 位）。
        fn task_file(&self, lba: u32) {
            ports::write_u8(self.base + 2, 1);
            ports::write_u8(self.base + 3, lba as u8);
            ports::write_u8(self.base + 4, (lba >> 8) as u8);
            ports::write_u8(self.base + 5, (lba >> 16) as u8);
        }

        /// 数据端口读 256 字（rep insw；HW-15 白名单汇编）。
        fn read_data_words(&self) -> [u16; SECTOR_WORDS] {
            let mut buf = [0u16; SECTOR_WORDS];
            // SAFETY: 前置条件 —— DRQ=1（wait_data_ready 保证）后恰有
            //          一扇区数据可读；端口为白名单数据口。
            // 不变式 —— rep insw 精确读 256 字入栈上缓冲（固定长度）。
            // 并发 —— 通道协议由调用方持锁串行化。
            // 违反后果 —— 无 DRQ 读数据口读到未定义值（纪律封死）。
            unsafe {
                core::arch::asm!(
                    "cld",
                    "rep insw",
                    in("dx") self.base,
                    inout("cx") SECTOR_WORDS => _,
                    inout("rdi") buf.as_mut_ptr() => _,
                );
            }
            buf
        }

        /// 数据端口写 256 字（rep outsw；HW-15 白名单汇编）。
        fn write_data_words(&self, data: &[u16; SECTOR_WORDS]) {
            // SAFETY: 前置条件 —— DRQ=1（设备缓冲就绪），恰收一扇区。
            // 不变式 —— rep outsw 精确写 256 字（固定长度）。
            // 并发 —— 通道协议由调用方持锁串行化。
            // 违反后果 —— 越界读源缓冲（纪律封死；固定长度无越界面）。
            unsafe {
                core::arch::asm!(
                    "cld",
                    "rep outsw",
                    in("dx") self.base,
                    inout("cx") SECTOR_WORDS => _,
                    inout("rsi") data.as_ptr() => _,
                );
            }
        }

        /// IDENTIFY DEVICE：返回 256 字识别字（无设备 → [`AtaError::NoDevice`]）。
        pub fn identify(&self) -> Result<[u16; SECTOR_WORDS], AtaError> {
            self.select(0);
            ports::write_u8(self.base + 7, 0xEC);
            let st = self.wait_not_busy()?;
            // 空通道：状态寄存器恒 0（QEMU/真实设备均如此）
            if st == 0 {
                return Err(AtaError::NoDevice);
            }
            self.wait_data_ready()?;
            let words = self.read_data_words();
            self.wait_400ns();
            Ok(words)
        }

        /// 读单扇区（LBA28）。
        pub fn read_sector(&self, lba: u32, out: &mut [u16; SECTOR_WORDS]) -> Result<(), AtaError> {
            self.select(lba);
            self.task_file(lba);
            ports::write_u8(self.base + 7, 0x20); // READ SECTORS
            self.wait_not_busy()?;
            self.wait_data_ready()?;
            *out = self.read_data_words();
            self.wait_400ns();
            Ok(())
        }

        /// 写单扇区（LBA28；返回即数据已落设备缓冲并冲刷完成）。
        pub fn write_sector(&self, lba: u32, data: &[u16; SECTOR_WORDS]) -> Result<(), AtaError> {
            self.select(lba);
            self.task_file(lba);
            ports::write_u8(self.base + 7, 0x30); // WRITE SECTORS
            self.wait_data_ready()?;
            self.write_data_words(data);
            // 冲刷：等 BSY 清零（缓冲 → 介质）
            let st = self.wait_not_busy()?;
            if st & Self::SR_ERR != 0 {
                return Err(AtaError::DeviceError);
            }
            self.wait_400ns();
            Ok(())
        }
    }
}

#[cfg(test)]
mod cpuid_tests {
    use super::cpuid::{parse_leaf1, Leaf1};

    #[test]
    fn parse_extracts_apic_present_and_id() {
        // ebx 高 8 位 = 初始 APIC ID；ecx 位 9 = LAPIC 在位
        let l = Leaf1 {
            eax: 0x0006_0F00,
            ebx: 0x0500_0005, // APIC ID = 5
            ecx: 1 << 9,
            edx: 0,
        };
        assert_eq!(parse_leaf1(l), (true, 5));
        let l2 = Leaf1 {
            ecx: 0,
            ebx: 0x0100_0000,
            ..l
        };
        assert_eq!(parse_leaf1(l2), (false, 1));
    }
}
