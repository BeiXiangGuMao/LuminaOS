//! VNode 静态面：节点标识、节点类型、元数据与错误集。
//!
//! VNode（virtual node）是 VFS 对「文件系统内一个可寻址对象」的统一抽象：
//! 上层（挂载解析、fd 表、后续的文件面 syscall）只依赖本模块的类型与
//! [`super::fs::FileSystem`] 特征方法，不感知具体文件系统的内部布局。

use alloc::string::String;

/// 文件系统内部的节点号。仅在单一 [`super::fs::FileSystem`] 实例内有意义；
/// 跨文件系统的同一性由「fs 实例 + 节点号」二元组表达（见 [`super::mount::ResolvedNode`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VnodeId(pub u64);

/// 节点类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// 常规文件：可按偏移读写的字节序列。
    File,
    /// 目录：名字到子 VNode 的映射。
    Dir,
    /// 字符设备：留作设备面接入点（骨架不创建）。
    CharDev {
        /// 主设备号。
        major: u32,
        /// 次设备号。
        minor: u32,
    },
    /// 管道：留作 IPC 文件面接入点（骨架不创建）。
    Pipe,
    /// 符号链接：留待文件面块实现逐段解析时引入。
    Symlink,
}

impl NodeKind {
    /// 是否为目录。
    pub fn is_dir(self) -> bool {
        matches!(self, NodeKind::Dir)
    }
}

/// 节点元数据快照（fstat 面的最小集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// 所属文件系统内的节点号。
    pub vnode: VnodeId,
    /// 节点类型。
    pub kind: NodeKind,
    /// 字节数；目录与无尺寸类型恒为 0。
    pub size: u64,
}

/// 目录项：readdir 的产出单元。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// 名字（单段，不含分隔符）。
    pub name: String,
    /// 子节点号。
    pub vnode: VnodeId,
    /// 子节点类型（免二次 lookup）。
    pub kind: NodeKind,
}

/// VFS 错误集。文件面块落地时由 ABI 层映射为 Linux errno（经 Conduit 口径），
/// 内核内部一律使用本类型，避免 errno 语义提前泄漏进数据结构面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// 路径非法（相对路径、越过根的 `..`、空段名等）。
    InvalidPath,
    /// 目标不存在。
    NotFound,
    /// 期望目录而目标不是目录。
    NotADirectory,
    /// 期望普通文件而目标是目录。
    IsDirectory,
    /// 同名节点已存在。
    AlreadyExists,
    /// 目录非空，拒绝删除。
    DirectoryNotEmpty,
    /// 该文件系统不支持所请求的操作/节点类型。
    NotSupported,
    /// 目标正被占用（M17-③：挂载 fs 上有存活打开句柄时拒卸）。
    Busy,
    /// 存储容量不足（分配失败：块/节点/目录区耗尽）。
    NoSpace,
}

impl FsError {
    /// 映射为 Linux 5.15 errno（**Conduit 口径**——与 conduit crate 的
    /// `errno_name` 快照无依赖同表，交叉核对见本模块测试钉值）。
    ///
    /// 文件面 syscall 错误域专用（进程/能力面错误域 1–10 与本域分立，
    /// 各 syscall 文档各自声明）；内核内部一律继续使用本类型，
    /// errno 语义只在 ABI 边界（本函数）一次性折叠。
    pub const fn errno(self) -> u64 {
        match self {
            // 路径词法非法 → 参数无效
            FsError::InvalidPath => 22, // EINVAL
            // 目标不存在
            FsError::NotFound => 2, // ENOENT
            // 路径组件不是目录
            FsError::NotADirectory => 20, // ENOTDIR
            // 对目录做文件语义操作（如 read）
            FsError::IsDirectory => 21, // EISDIR
            // 同名节点已存在
            FsError::AlreadyExists => 17, // EEXIST
            // 目录非空拒绝删除
            FsError::DirectoryNotEmpty => 39, // ENOTEMPTY
            // 文件系统不支持该操作/节点类型
            FsError::NotSupported => 95, // EOPNOTSUPP
            // 目标正被占用（卸载面 EBUSY）
            FsError::Busy => 16, // EBUSY
            // 存储容量不足
            FsError::NoSpace => 28, // ENOSPC
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FsError, NodeKind, VnodeId};

    #[test]
    fn vnode_id_is_comparable_and_copyable() {
        let a = VnodeId(1);
        let b = a;
        assert_eq!(a, b);
        let mut sorted = [VnodeId(3), VnodeId(1), VnodeId(2)];
        sorted.sort_unstable();
        assert_eq!(sorted, [VnodeId(1), VnodeId(2), VnodeId(3)]);
    }

    #[test]
    fn kind_dir_predicate() {
        assert!(NodeKind::Dir.is_dir());
        assert!(!NodeKind::File.is_dir());
        assert!(!NodeKind::CharDev { major: 4, minor: 0 }.is_dir());
        assert!(!NodeKind::Pipe.is_dir());
        assert!(!NodeKind::Symlink.is_dir());
    }

    #[test]
    fn errno_mapping_matches_conduit_snapshot() {
        // Conduit 口径交叉核对：数值与 conduit::errno_name 快照一一对应
        // （本 crate 不依赖 conduit，此处逐值钉死防漂移）
        assert_eq!(FsError::InvalidPath.errno(), 22); // EINVAL
        assert_eq!(FsError::NotFound.errno(), 2); // ENOENT
        assert_eq!(FsError::NotADirectory.errno(), 20); // ENOTDIR
        assert_eq!(FsError::IsDirectory.errno(), 21); // EISDIR
        assert_eq!(FsError::AlreadyExists.errno(), 17); // EEXIST
        assert_eq!(FsError::DirectoryNotEmpty.errno(), 39); // ENOTEMPTY
        assert_eq!(FsError::NotSupported.errno(), 95); // EOPNOTSUPP
        assert_eq!(FsError::Busy.errno(), 16); // EBUSY
        assert_eq!(FsError::NoSpace.errno(), 28); // ENOSPC
    }
}
