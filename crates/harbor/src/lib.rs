//! Harbor 港湾 —— POSIX libc 符号面（ADR-0003 重铸过渡态）。
//!
//! 承接《Harbor 港湾开发细则》v1.0.0：用户态 C ABI 面（POSIX.1-2017），
//! 执行系统库档**零 unsafe** 政策（crate 级 `forbid(unsafe_code)`），
//! P5 门禁 H-P01 ≥150 符号。
//!
//! **本 crate 现为过渡态 stub（M29-N1）**：原 693 行内核堆分配器
//! （HarborBump/HarborFreeList/AllocStats）已按 ADR-0003 裁决整体迁至
//! `ostd::heap`（模块化 `heap::bump`/`heap::freelist`），kernel
//! `#[global_allocator]` 引用点同步切换；harbor 名字与 crate 保留给
//! 细则定义的 POSIX libc 本体，M29-H1 以 H-P01 首批 ≥50 符号垂直切片
//! （errno + string + ctype + stdlib）自此处重铸。
//!
//! 范围界定（v0 偏差登记）：首批符号面 = 纯 safe 语义层（值语义
//! `extern "C"` + 切片语义 safe 面）；C ABI 指针层（raw ptr 解引用需
//! unsafe）待用户态链接面成形后以外置方案补位，不破 crate 级 forbid
//! 承诺（见 ROADMAP §四 M29 计划注）。
#![no_std]
#![forbid(unsafe_code)]
