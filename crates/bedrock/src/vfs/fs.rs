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

/// 目录项类型域的 ABI 编码（M15-① READDIR 项首字节；与内核 STAT kind
/// 域同一映射，单一事实源落 bedrock——内核侧 `kind_code` 委托至此）。
///
/// 0 = File、1 = Dir、2 = CharDev、3 = Pipe、4 = Symlink。
pub const fn dir_entry_abi_code(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Dir => 1,
        NodeKind::CharDev { .. } => 2,
        NodeKind::Pipe => 3,
        NodeKind::Symlink => 4,
    }
}

/// 目录项分页打包（M15-① READDIR 纯函数面；结构归 bedrock 宿主测试
/// 钉死，游标策略归内核装载——LXE1 同款职责分层）。
///
/// 自 `entries[cursor..]` 起逐项编码进 `buf`：每项 =
/// `[dir_entry_abi_code(kind):u8][name_len:u8][name 字节…]` 紧排；
/// 剩余空间不足以容纳**下一整项**（含 2 字节头）即停——半项不落盘
/// （调用方下次调用自停点续打，无项内续传问题）。
///
/// 返回 `(packed_bytes, consumed)`：实际写入字节数与消费的目录项数；
/// 枚举尽（cursor ≥ len）或 buf 不足 3 字节（连最小项都放不下）返回
/// `(0, 0)`。`cursor > entries.len()` 视为越界按枚举尽处理（游标漂移
/// 防御：目录中途缩短时内核侧 clamp 后传入）。
pub fn pack_dir_page(entries: &[DirEntry], cursor: usize, buf: &mut [u8]) -> (usize, usize) {
    if buf.len() < 3 || cursor >= entries.len() {
        return (0, 0);
    }
    let mut off = 0usize;
    let mut consumed = 0usize;
    for entry in &entries[cursor..] {
        let name = entry.name.as_bytes();
        // 名字超 255（name_len 单字节域上限）拒绝打包——ramfs 单段名
        // 远低于此界，防御性截断面（结构面拒绝而非静默截断）。
        let Ok(name_len) = u8::try_from(name.len()) else {
            break;
        };
        let need = 2 + name.len();
        if off + need > buf.len() {
            break;
        }
        buf[off] = dir_entry_abi_code(entry.kind);
        buf[off + 1] = name_len;
        buf[off + 2..off + need].copy_from_slice(name);
        off += need;
        consumed += 1;
    }
    (off, consumed)
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

    fn entry(name: &str, kind: NodeKind) -> crate::vfs::DirEntry {
        crate::vfs::DirEntry {
            name: String::from(name),
            vnode: crate::vfs::VnodeId(1),
            kind,
        }
    }

    #[test]
    fn pack_dir_page_encodes_kind_len_name() {
        let entries = vec![
            entry("hello", NodeKind::File),
            entry("dir", NodeKind::Dir),
            entry(
                "tty",
                NodeKind::CharDev {
                    major: 4,
                    minor: 64,
                },
            ),
        ];
        let mut buf = [0u8; 64];
        let (packed, consumed) = super::pack_dir_page(&entries, 0, &mut buf);
        // 项编码：[kind][len][name…] 紧排；"hello"=7B、"dir"=5B、"tty"=5B → 17B
        assert_eq!((packed, consumed), (17, 3));
        assert_eq!(&buf[..7], &[0, 5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(&buf[7..12], &[1, 3, b'd', b'i', b'r']);
        assert_eq!(&buf[12..17], &[2, 3, b't', b't', b'y']);
    }

    #[test]
    fn pack_dir_page_stops_at_buffer_boundary_without_half_entries() {
        let entries = vec![entry("alpha", NodeKind::File), entry("b", NodeKind::File)];
        // 恰好容纳首项（7B）：第二项（3B）放不下 → 半项不落盘
        let mut buf = [0u8; 7];
        assert_eq!(super::pack_dir_page(&entries, 0, &mut buf), (7, 1));
        // 续页：游标 1 → 消费剩余
        let mut buf2 = [0u8; 64];
        assert_eq!(super::pack_dir_page(&entries, 1, &mut buf2), (3, 1));
        assert_eq!(&buf2[..3], &[0, 1, b'b']);
    }

    #[test]
    fn pack_dir_page_eof_and_defensive_edges() {
        let entries = vec![entry("x", NodeKind::File)];
        // 枚举尽：cursor = len → (0, 0)
        assert_eq!(super::pack_dir_page(&entries, 1, &mut [0u8; 64]), (0, 0));
        // cursor 越界（目录中途缩短的漂移防御）按枚举尽
        assert_eq!(super::pack_dir_page(&entries, 9, &mut [0u8; 64]), (0, 0));
        // buf 不足最小项（< 3B）→ (0, 0)
        assert_eq!(super::pack_dir_page(&entries, 0, &mut [0u8; 2]), (0, 0));
        // 空目录：cursor 0 = 枚举尽
        let empty: Vec<crate::vfs::DirEntry> = Vec::new();
        assert_eq!(super::pack_dir_page(&empty, 0, &mut [0u8; 64]), (0, 0));
    }

    #[test]
    fn dir_entry_abi_code_mapping_matches_stat_face() {
        // STAT kind 域同一映射（单一事实源交叉钉值）
        assert_eq!(super::dir_entry_abi_code(NodeKind::File), 0);
        assert_eq!(super::dir_entry_abi_code(NodeKind::Dir), 1);
        assert_eq!(
            super::dir_entry_abi_code(NodeKind::CharDev { major: 1, minor: 2 }),
            2
        );
        assert_eq!(super::dir_entry_abi_code(NodeKind::Pipe), 3);
        assert_eq!(super::dir_entry_abi_code(NodeKind::Symlink), 4);
    }
}
