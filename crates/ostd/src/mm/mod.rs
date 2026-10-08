//! OSTD 内存管理基元（M3）。
//!
//! 依据 SPEC 第十七章 OSTD 职责边界（Asterinas OSTD 范式）：物理帧分配与
//! 页表抽象是内核可映射的最低层内存基元，unsafe 全部收口于 [`crate::hw`]。
//!
//! - [`frame`]：区间裁剪式物理帧分配器（multiboot 内存面 → 可用帧，
//!   LIFO 空闲表回收），纯逻辑、可在宿主单元测试；
//! - [`page`]：x86_64 四级页表条目与遍历器（map/translate/unmap），
//!   经 [`page::PhysAccess`] 抽象物理内存访问——裸机由恒等映射 volatile
//!   实现，宿主测试由伪造内存实现，遍历逻辑零 unsafe。
//!
//! M3 约束：物理内存访问经由低 1 GiB 恒等映射（`phys_offset = 0`），
//! 帧分配器拒绝高于 1 GiB 的可用区域（QEMU 256 MiB 配置全量覆盖）；
//! 高端物理映射（phys offset 窗口）随 M4+ 用户态一起落地。

pub mod frame;
pub mod page;
