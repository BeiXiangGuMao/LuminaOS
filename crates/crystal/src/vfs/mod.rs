//! VFS 文件域——FS 侧契约与物理面（ADR-0002 迁移步：bedrock::vfs 外移落位）。
//!
//! 定位：文件系统侧的最小完备契约（[`fs::FileSystem`]）、路径词法
//! （[`path`]）、节点契约类型（[`node`]）、内存参照实现（[`ramfs`]）、
//! LFS1 盘上文件系统（[`lfs`]，任意块设备底座）与 fd 表底座（[`fd`]，
//! Crystal 代际槽承载）。挂载表与命名空间策略面归 `meridian::vfs`
//! （消费本契约组装统一名字解析；ADR-0002 补篇归属裁决）。
//!
//! 分层（自底向上）：
//! - [`path`]：绝对路径的词法规范化（组件化、`..` 消解）；
//! - [`node`]：VNode 标识 / 类型 / 元数据 / 错误集；
//! - [`fs`]：`FileSystem` 特征——文件系统侧最小完备契约（含 M17-②
//!   稳定 cookie 枚举面 `readdir_from`）与解析落点类型 `ResolvedNode`；
//! - [`ramfs`]：内存文件系统（参照实现与测试基座）；
//! - [`lfs`]：LFS1 盘上文件系统（M17-① 持久化存储面，任意块设备底座）；
//! - [`fd`]：fd 表——Crystal 代际槽承载的打开文件描述。
//!
//! 并发纪律：全部共享状态经由 OSTD `SpinLock`（[`ostd::sync::SpinLock`]），
//! 本模块自身不含任何 unsafe；`Arc<dyn FileSystem>` 使跨挂载共享实例成立。

pub mod fd;
pub mod fs;
pub mod lfs;
pub mod node;
pub mod path;
pub mod ramfs;

pub use fd::{Fd, FdError, FdTable, OpenFileDescription, OpenFlags, Whence};
pub use fs::{dir_entry_abi_code, pack_dir_page, CookieEntry, FileSystem, ResolvedNode};
pub use lfs::Lfs;
pub use node::{DirEntry, FsError, Metadata, NodeKind, VnodeId};
pub use path::PathBuf;
pub use ramfs::RamFs;
