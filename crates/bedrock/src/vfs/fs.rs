//! `FileSystem` 特征：VFS 的文件系统侧契约。
//!
//! 骨架定位（M13-①）：全部方法接收 `&self`——文件系统的可变状态一律经由内部
//! 同步原语（OSTD `SpinLock`）管理，使同一实例可安全地被多 CPU 共享（挂载表
//! 持有 `Arc<dyn FileSystem>`）。方法语义对齐 POSIX 词汇，但错误以
//! [`FsError`](crate::vfs::FsError) 表达；errno 映射收敛在后续文件面块。

use alloc::string::String;
use alloc::vec::Vec;

use super::node::{DirEntry, Metadata, NodeKind, VnodeId};
use super::FsError;

/// 一个可挂载文件系统的最小完备契约。
///
/// 实现者约定：
/// - `dir` 类参数若不是目录，返回 [`FsError::NotADirectory`]；
/// - `vnode` 类参数若在实例中不存在，返回 [`FsError::NotFound`]；
/// - 名字参数为单段名（校验失败返回 [`FsError::InvalidPath`]）。
pub trait FileSystem: Send + Sync {
    /// 本文件系统的根节点号。
    fn root_vnode(&self) -> VnodeId;

    /// 在目录 `dir` 中查找名字 `name`，返回子节点号。
    fn lookup(&self, dir: VnodeId, name: &str) -> Result<VnodeId, FsError>;

    /// 读取节点元数据。
    fn metadata(&self, vnode: VnodeId) -> Result<Metadata, FsError>;

    /// 从 `offset` 起读取至多 `buf.len()` 字节，返回实际读取数（0 表示 EOF）。
    /// 骨架约定仅对常规文件有意义；目录实现应返回 [`FsError::IsDirectory`]。
    fn read_at(&self, vnode: VnodeId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// 从 `offset` 起写入 `data`；`offset` 超出当前长度时以零填充（pwrite 语义），
    /// 返回实际写入数。
    fn write_at(&self, vnode: VnodeId, offset: u64, data: &[u8]) -> Result<usize, FsError>;

    /// 在目录 `dir` 中以 `name` 创建 `kind` 类型的新节点并返回其节点号。
    /// 同名已存在返回 [`FsError::AlreadyExists`]；不支持的目标类型返回
    /// [`FsError::NotSupported`]。
    fn create(&self, dir: VnodeId, name: &str, kind: NodeKind) -> Result<VnodeId, FsError>;

    /// 从目录 `dir` 中摘除名字 `name`。目录需为空（[`FsError::DirectoryNotEmpty`]）。
    fn unlink(&self, dir: VnodeId, name: &str) -> Result<(), FsError>;

    /// 列举目录 `dir` 的全部目录项（骨架一次性返回全量；流式列举留待文件面块）。
    fn readdir(&self, dir: VnodeId) -> Result<Vec<DirEntry>, FsError>;
}

/// 便捷封装：路径组件逐段走查（从 `fs` 的根开始）。
///
/// 供挂载层在确定落点文件系统后使用；空组件序列返回该 fs 的根节点。
pub(crate) fn walk(
    fs: &dyn FileSystem,
    components: impl IntoIterator<Item = String>,
) -> Result<VnodeId, FsError> {
    let mut cur = fs.root_vnode();
    for comp in components {
        cur = fs.lookup(cur, &comp)?;
    }
    Ok(cur)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{walk, FileSystem};
    use crate::vfs::node::{NodeKind, VnodeId};
    use crate::vfs::ramfs::RamFs;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn walk_builds_paths_through_ramfs() {
        let fs = Arc::new(RamFs::new());
        let root = fs.root_vnode();
        let etc = fs.create(root, "etc", NodeKind::Dir).expect("mkdir etc");
        fs.create(etc, "motd", NodeKind::File).expect("touch motd");
        let comps: Vec<String> = vec![String::from("etc"), String::from("motd")];
        assert_eq!(walk(fs.as_ref(), comps), Ok(VnodeId(3)));
        let missing: Vec<String> = vec![String::from("nope")];
        assert_eq!(
            walk(fs.as_ref(), missing),
            Err(crate::vfs::FsError::NotFound)
        );
        assert_eq!(walk(fs.as_ref(), Vec::new()), Ok(root));
    }
}
