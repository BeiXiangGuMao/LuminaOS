//! 内核堆分配器面（ADR-0003 归位）。
//!
//! 依据 ADR-0003（Harbor 身份拆分）：内核堆分配器属**机制件**，归
//! `ostd::heap`（ostd 是全仓唯一的 unsafe 白名单 crate，分配器与 hw/mm
//! 同域）；`harbor` 名字让位给细则定义的 POSIX libc 本体（M29 重铸）。
//!
//! - [`bump::Bump`]：区域式（bump）分配器，内核启动期与测试环境的
//!   `GlobalAlloc` 实现；dealloc 只做统计回收，属预期行为并有文档。
//!   （原 `harbor::HarborBump`，M2 起承载内核堆启动期绑定。）
//! - [`freelist::FreeList`]：first-fit + 地址序合并 + bump 晋升的通用
//!   free-list 分配器（M21-③：SPEC 5 章承诺的单块回收复用面），
//!   内核堆现行挂载实现。（原 `harbor::HarborFreeList`。）
//! - [`AllocStats`]：分配统计（次数、在用字节、峰值），供基准与门禁取证；
//!   free-list 扩展取证经 [`freelist::FreeList::free_stamps`]。
//!
//! 迁移为纯移动 + 引用切换（单批 revert 即回）；SAFETY 注释四行模板
//! 与《系统开发指南》第四章保持一致。

pub mod bump;
pub mod freelist;

pub use bump::Bump;
pub use freelist::FreeList;

/// 分配统计快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocStats {
    /// 成功分配次数。
    pub allocs: u64,
    /// 成功释放次数（bump 区域整体回收时按区域计一次）。
    pub deallocs: u64,
    /// 当前在用字节（含对齐填充）。
    pub bytes_in_use: usize,
    /// 历史峰值在用字节。
    pub peak_bytes: usize,
}
