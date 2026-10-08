/* Lumina OS 内核链接脚本（x86_64-lumina，multiboot1 / QEMU -kernel）。
 *
 * 布局约定（SPEC 第 2 章 / DEV-002 第四章）：
 *   - 内核物理基址 1 MiB，恒等映射（M2 启动路径建低 1 GiB 恒等页表）；
 *   - .multiboot 头必须位于映像前 8 KiB，故置于最前；
 *   - .boot.bss（页表 + 启动栈）并入主 .bss，NOLOAD，不占映像体积。
 */

ENTRY(_start)

SECTIONS {
    . = 1M;

    .boot : ALIGN(4096) {
        KEEP(*(.multiboot))
        KEEP(*(.boot.text))
        *(.boot.rodata)
    }

    .text : ALIGN(4096) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096) {
        *(.data .data.* .gnu.linkonce.d.*)
    }

    .bss (NOLOAD) : ALIGN(4096) {
        *(.boot.bss)
        *(COMMON)
        *(.bss .bss.*)
    }

    /* 内核映像末端符号：kmain 用 kern_end - 0x100000 计算映像大小 */
    PROVIDE(kern_end = .);

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
    }
}
