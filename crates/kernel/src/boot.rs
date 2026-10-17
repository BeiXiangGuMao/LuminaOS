//! 启动汇编：multiboot1 32 位入口 → 低 1 GiB 恒等映射 → x86_64 长模式。
//!
//! unsafe 白名单说明（SPEC 第十七章）：本模块是「框架内核白名单模块」，
//! 机器状态初始化（页表、CR/MSR、GDT、远跳）无法以 safe Rust 表达，
//! 因此整段以 `global_asm!` 固化并保持最小化；一旦进入 64 位 `kmain`，
//! 后续内核代码全部为 safe Rust。
//!
//! 交接约定：`_start` 由 multiboot1 引导程序以 eax=魔数、ebx=信息块地址
//! 调入；汇编把两者存入 `MB_MAGIC`/`MB_INFO` 静态槽后，经 `rdi`/`rsi`
//! 传入 `kmain`（SysV ABI 前两个整型参数寄存器）。

use core::arch::global_asm;

global_asm! {
    // ---- multiboot1 头：必须位于映像前 8 KiB（linker.ld 将 .multiboot 置于最前）----
    ".section .multiboot, \"a\", @progbits",
    ".balign 4",
    ".long 0x1BADB002",               // 魔数
    // flags：bit1 meminfo | bit6 mmap | bit16 AOUT_KLUDGE（QEMU 只认 32 位
    // 可装载映像，故经 objcopy -O binary 产出裸映像并由本头声明装载布局）
    ".long 0x00010042",
    ".long -(0x1BADB002 + 0x00010042)", // 校验和 = -(魔数 + flags)
    ".long 0x00100000",               // header_addr：头所在物理地址（链接基址）
    ".long 0x00100000",               // load_addr：映像装载物理基址
    ".long 0",                        // load_end_addr：0 = 装载整个文件
    ".long 0",                        // bss_end_addr：0 = 无需清零（页表自清、堆栈免初始化）
    ".long _start",                   // entry_addr：32 位入口（.multiboot 紧随其后）

    // ---- 页表（3 × 4 KiB）与启动栈（64 KiB）：并入主 .bss（NOLOAD）----
    ".section .boot.bss, \"aw\", @nobits",
    ".balign 4096",
    "pml4_table:",
    ".skip 4096",
    "pdpt_table:",
    ".skip 4096",
    "pd_low_table:",
    ".skip 4096",
    "boot_stack_bottom:",
    ".skip 65536",
    "boot_stack_top:",
    // M22-③ [B] 猎场 v2.2：引导栈界符号全局导出（帧哨兵主任务锚——
    // 667/705/951/1005 四标本毒化目标 = 引导栈上主任务保存帧 RIP 槽，
    // Rust 侧读取栈界作哨兵界桩）。
    ".globl boot_stack_bottom",
    ".globl boot_stack_top",

    // ---- 32 位入口 ----
    ".section .boot.text, \"ax\", @progbits",
    ".code32",
    ".globl _start",
    "_start:",
    "    cli",
    "    cld",
    "    movl $boot_stack_top, %esp",
    "    xorl %ebp, %ebp",
    "    movl %eax, MB_MAGIC",        // 保存 multiboot 魔数
    "    movl %ebx, MB_INFO",         // 保存信息块物理地址
    // 构建恒等映射：PML4[0]=PDPT、PDPT[0]=PD、PD[i]=i×2MiB|P|W|PS —— 覆盖低 1 GiB
    "    movl $pml4_table, %edi",
    "    movl $((pd_low_table - pml4_table + 4096) / 4), %ecx",
    "    xorl %eax, %eax",
        "    rep stosl",                  // 清零三张表（同段连续，含末表整页）
    "    movl $pdpt_table, %eax",
    "    orl $0x03, %eax",
    "    movl %eax, pml4_table",
    "    movl $pd_low_table, %eax",
    "    orl $0x03, %eax",
    "    movl %eax, pdpt_table",
    "    movl $pd_low_table, %edi",
    "    movl $512, %ecx",
    "    movl $0x83, %eax",           // P | W | PS（2 MiB 大页）
    "1:",
    "    movl %eax, (%edi)",
    "    addl $0x200000, %eax",
    "    addl $8, %edi",
    "    loop 1b",
    // PAE → CR3 → EFER.LME → CR0.PG
    "    movl %cr4, %eax",
    "    orl $0x00000020, %eax",      // PAE
    "    movl %eax, %cr4",
    "    movl $pml4_table, %eax",
    "    movl %eax, %cr3",
    "    movl $0xC0000080, %ecx",     // IA32_EFER
    "    rdmsr",
    "    orl $0x00000100, %eax",      // LME
    "    wrmsr",
    "    movl %cr0, %eax",
    "    orl $0x80000000, %eax",      // PG（PE 已由引导程序置位）
    "    movl %eax, %cr0",
    // 加载 64 位 GDT 并远跳进入长模式
    "    lgdt gdt64_desc",
    "    ljmp $0x08, $long_mode_entry",

    // ---- 64 位长模式：进入 Rust ----
    ".code64",
    "long_mode_entry:",
    "    mov $boot_stack_top, %rsp",
    "    xorl %ebp, %ebp",
    "    movl MB_MAGIC, %edi",        // rdi = 魔数（movl 清零高 32 位）
    "    movl MB_INFO, %esi",         // rsi = 信息块物理地址
    "    call kmain",
    "2:",
    "    hlt",
    "    jmp 2b",

    // ---- 64 位 GDT（空描述符 / 代码 L=1 / 数据）----
    ".section .boot.rodata, \"a\", @progbits",
    ".balign 8",
    "gdt64:",
    "    .quad 0x0000000000000000",
    "    .quad 0x00209A0000000000",   // 64 位代码段：L=1, P=1, S=1, type=1010
    "    .quad 0x0000920000000000",   // 数据段
    "gdt64_end:",
    "gdt64_desc:",
    "    .word gdt64_end - gdt64 - 1",
    "    .quad gdt64",

    options(att_syntax)  // rustc 1.99 起 global_asm! 默认 Intel 语法；本模块按 AT&T 书写
}

// M22-③ [B] 猎场 v2.2：引导栈界读取（帧哨兵主任务锚）。
// SAFETY: 前置条件 —— 两符号由本文件 global_asm .globl 导出（.boot.bss
//          NOLOAD 段，链接期定址，nm 可对账：bottom=0xa03000/top=0xa13000
//          量级随链接布局浮动）。不变式 —— 仅取地址不读本体（零尺寸符号
//          约定）。并发 —— 链接期常量，只读无竞争。
// 违反后果 —— 符号缺失即链接期报错（无运行期风险）。
extern "C" {
    static boot_stack_bottom: u8;
    static boot_stack_top: u8;
}

/// 引导栈界 `(bottom, top)`（frame 哨兵主任务/启动语境的栈锚）。
pub fn boot_stack_bounds() -> (usize, usize) {
    (
        core::ptr::addr_of!(boot_stack_bottom) as usize,
        core::ptr::addr_of!(boot_stack_top) as usize,
    )
}
