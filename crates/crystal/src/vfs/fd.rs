//! 文件描述符表：打开文件描述（OFD）的代际槽管理。
//!
//! 基座选择（M13-①）：fd 表直接以 Crystal [`GenerationalSlab`] 承载——fd 号
//! 即槽位号，代龄即句柄世代。close 后槽位复用即升代，外泄的旧 fd 自动失效
//! （ABA 从根上杜绝），与能力句柄（M9 语义）同构。
//!
//! 骨架边界：每个 OFD 独占一条槽（`dup` 的共享偏移语义、`fcntl`、`O_CLOEXEC`
//! 等留待文件面块；届时 OFD 改为 `Arc` 共享即可，本表外部形态不变）。

use crate::{GenerationalSlab, Key, SlotError};

use super::fs::ResolvedNode;
use super::node::Metadata;
use super::FsError;

/// 打开标志：读 / 写位（骨架最小集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(u8);

impl OpenFlags {
    /// 只读。
    pub const READ: OpenFlags = OpenFlags(0b01);
    /// 只写。
    pub const WRITE: OpenFlags = OpenFlags(0b10);
    /// 读写。
    pub const READ_WRITE: OpenFlags = OpenFlags(0b11);

    /// 是否允许读。
    pub fn readable(self) -> bool {
        self.0 & 0b01 != 0
    }

    /// 是否允许写。
    pub fn writable(self) -> bool {
        self.0 & 0b10 != 0
    }

    /// 是否至少声明了一个访问位。
    pub fn is_any(self) -> bool {
        self.0 & 0b11 != 0
    }

    /// 以位型构造（bit0 = 读、bit1 = 写；零/保留位拒收 → None）。
    /// 文件面 ABI 边界（M13-②）与宿主面共用的唯一构造入口。
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b01 => Some(Self::READ),
            0b10 => Some(Self::WRITE),
            0b11 => Some(Self::READ_WRITE),
            _ => None,
        }
    }
}

/// 打开文件描述：落点节点 + 私有偏移。
#[derive(Debug, Clone)]
pub struct OpenFileDescription {
    node: ResolvedNode,
    pos: u64,
    flags: OpenFlags,
}

/// fd 表错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdError {
    /// fd 不存在或已失效（代龄不匹配）。
    StaleFd,
    /// fd 表已满（容量上限即代际槽上限）。
    Full,
    /// fd 未以可读方式打开。
    ReadNotAllowed,
    /// fd 未以可写方式打开。
    WriteNotAllowed,
    /// lseek 结果越界（负偏移）。
    InvalidSeek,
    /// 底层文件系统错误。
    Fs(FsError),
}

impl From<SlotError> for FdError {
    fn from(e: SlotError) -> Self {
        match e {
            SlotError::StaleKey => FdError::StaleFd,
            SlotError::Full => FdError::Full,
        }
    }
}

impl From<FsError> for FdError {
    fn from(e: FsError) -> Self {
        FdError::Fs(e)
    }
}

/// 文件描述符。
pub type Fd = Key;

/// 进程级 fd 表。
#[derive(Debug, Default)]
pub struct FdTable {
    ofds: GenerationalSlab<OpenFileDescription>,
}

/// lseek 基准。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whence {
    /// 从文件头起算。
    Set,
    /// 从当前偏移起算。
    Cur,
    /// 从文件尾起算。
    End,
}

impl FdTable {
    /// 空 fd 表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 以 `flags` 打开 `node`，返回新 fd。至少需要声明读或写位。
    pub fn open(&mut self, node: ResolvedNode, flags: OpenFlags) -> Result<Fd, FdError> {
        if !flags.is_any() {
            return Err(FdError::ReadNotAllowed);
        }
        let ofd = OpenFileDescription {
            node,
            pos: 0,
            flags,
        };
        Ok(self.ofds.insert(ofd)?)
    }

    /// 关闭 fd 并取回 OFD；之后同号 fd 一律 [`FdError::StaleFd`]。
    pub fn close(&mut self, fd: Fd) -> Result<OpenFileDescription, FdError> {
        Ok(self.ofds.remove(fd)?)
    }

    /// 存活 fd 数。
    pub fn len(&self) -> usize {
        self.ofds.len()
    }

    /// 表是否为空。
    pub fn is_empty(&self) -> bool {
        self.ofds.is_empty()
    }

    /// 自当前偏移读取，推进偏移。
    pub fn read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize, FdError> {
        let ofd = self.ofds.get_mut(fd)?;
        if !ofd.flags.readable() {
            return Err(FdError::ReadNotAllowed);
        }
        let n = ofd
            .node
            .fs
            .read_at(ofd.node.vnode, ofd.pos, buf)
            .map_err(FdError::Fs)?;
        ofd.pos += n as u64;
        Ok(n)
    }

    /// 自当前偏移写入，推进偏移。
    pub fn write(&mut self, fd: Fd, data: &[u8]) -> Result<usize, FdError> {
        let ofd = self.ofds.get_mut(fd)?;
        if !ofd.flags.writable() {
            return Err(FdError::WriteNotAllowed);
        }
        let n = ofd
            .node
            .fs
            .write_at(ofd.node.vnode, ofd.pos, data)
            .map_err(FdError::Fs)?;
        ofd.pos += n as u64;
        Ok(n)
    }

    /// 重定位偏移，返回新偏移。`End` 以底层元数据尺寸为基准。
    pub fn seek(&mut self, fd: Fd, whence: Whence, offset: i64) -> Result<u64, FdError> {
        let ofd = self.ofds.get_mut(fd)?;
        let base: i128 = match whence {
            Whence::Set => 0,
            Whence::Cur => ofd.pos as i128,
            Whence::End => {
                let meta = ofd.node.fs.metadata(ofd.node.vnode).map_err(FdError::Fs)?;
                meta.size as i128
            }
        };
        let target = base + offset as i128;
        if target < 0 {
            return Err(FdError::InvalidSeek);
        }
        ofd.pos = target as u64;
        Ok(ofd.pos)
    }

    /// 读取元数据快照（不影响偏移）。
    pub fn stat(&self, fd: Fd) -> Result<Metadata, FdError> {
        let ofd = self.ofds.get(fd)?;
        ofd.node.fs.metadata(ofd.node.vnode).map_err(FdError::Fs)
    }

    /// 当前偏移（诊断用；文件面块封装 fstat/tell 时再评估暴露面）。
    pub fn tell(&self, fd: Fd) -> Result<u64, FdError> {
        Ok(self.ofds.get(fd)?.pos)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FdError, FdTable, OpenFlags, Whence};
    use crate::vfs::fs::FileSystem;
    use crate::vfs::fs::{walk, ResolvedNode};
    use crate::vfs::node::{NodeKind, VnodeId};
    use crate::vfs::path::PathBuf;
    use crate::vfs::ramfs::{RamFs, RAMFS_ROOT};
    use alloc::string::ToString;
    use alloc::sync::Arc;

    /// 布局：根 ramfs 挂 /data/file（内容 "lumina-vfs"），返回 (fs, table)。
    /// ADR-0002 迁移后 fd 测试不再依赖挂载层——单 fs 域内用 `walk` 直构
    /// [`ResolvedNode`]（挂载层协同面由 meridian::vfs 测试覆盖）。
    fn setup() -> (Arc<RamFs>, FdTable) {
        let fs = Arc::new(RamFs::new());
        let dir = fs.create(RAMFS_ROOT, "data", NodeKind::Dir).expect("mkdir");
        let file = fs.create(dir, "file", NodeKind::File).expect("touch");
        fs.write_at(file, 0, b"lumina-vfs").expect("seed");
        (fs, FdTable::new())
    }

    fn resolve(fs: &Arc<RamFs>, p: &str) -> ResolvedNode {
        let path = PathBuf::normalize(p).expect("normalize");
        ResolvedNode {
            fs: fs.clone(),
            vnode: walk(fs.as_ref(), path.components().map(str::to_string)).expect("walk"),
            path,
        }
    }

    #[test]
    fn open_read_advances_offset() {
        let (ns, mut table) = setup();
        let fd = table
            .open(resolve(&ns, "/data/file"), OpenFlags::READ)
            .expect("open");
        let mut buf = [0u8; 6];
        assert_eq!(table.read(fd, &mut buf), Ok(6));
        assert_eq!(&buf, b"lumina");
        assert_eq!(table.read(fd, &mut buf), Ok(4), "remainder -vfs");
        assert_eq!(&buf[..4], b"-vfs");
        assert_eq!(table.read(fd, &mut buf), Ok(0), "EOF after drain");
        assert_eq!(table.stat(fd).unwrap().size, 10);
    }

    #[test]
    fn write_appends_via_ofd_offset() {
        let (ns, mut table) = setup();
        let fd = table
            .open(resolve(&ns, "/data/file"), OpenFlags::READ_WRITE)
            .expect("open");
        assert_eq!(table.seek(fd, Whence::End, 0), Ok(10));
        assert_eq!(table.write(fd, b"!"), Ok(1));
        assert_eq!(table.stat(fd).unwrap().size, 11);
        assert_eq!(table.seek(fd, Whence::Set, 0), Ok(0));
        let mut buf = [0u8; 11];
        assert_eq!(table.read(fd, &mut buf), Ok(11));
        assert_eq!(&buf, b"lumina-vfs!");
    }

    #[test]
    fn access_flags_enforced() {
        let (ns, mut table) = setup();
        let ro = table
            .open(resolve(&ns, "/data/file"), OpenFlags::READ)
            .expect("ro");
        assert_eq!(table.write(ro, b"x"), Err(FdError::WriteNotAllowed));
        let wo = table
            .open(resolve(&ns, "/data/file"), OpenFlags::WRITE)
            .expect("wo");
        let mut buf = [0u8; 4];
        assert_eq!(table.read(wo, &mut buf), Err(FdError::ReadNotAllowed));
        assert_eq!(
            table.open(resolve(&ns, "/data/file"), OpenFlags(0)),
            Err(FdError::ReadNotAllowed),
            "zero flags rejected at open"
        );
    }

    #[test]
    fn close_reuse_bumps_generation_and_stale_fd_fails() {
        let (ns, mut table) = setup();
        let node = resolve(&ns, "/data/file");
        let fd1 = table.open(node.clone(), OpenFlags::READ).expect("open1");
        let ofd = table.close(fd1).expect("close");
        assert!(
            matches!(table.close(fd1), Err(FdError::StaleFd)),
            "double close"
        );
        let fd2 = table.open(node.clone(), OpenFlags::READ).expect("reopen");
        assert_eq!(fd2.index, fd1.index, "slot reused");
        assert_ne!(fd2.generation, fd1.generation, "generation bumped");
        assert_eq!(table.read(fd1, &mut [0u8; 1]), Err(FdError::StaleFd));
        assert_eq!(table.read(fd2, &mut [0u8; 1]), Ok(1));
        assert_eq!(ofd.pos, 0, "closed OFD returned intact");
    }

    #[test]
    fn seek_rules() {
        let (ns, mut table) = setup();
        let fd = table
            .open(resolve(&ns, "/data/file"), OpenFlags::READ)
            .expect("open");
        assert_eq!(table.seek(fd, Whence::Set, 4), Ok(4));
        assert_eq!(table.seek(fd, Whence::Cur, 2), Ok(6));
        assert_eq!(table.seek(fd, Whence::Cur, -3), Ok(3));
        assert_eq!(table.seek(fd, Whence::End, 0), Ok(10));
        assert_eq!(table.seek(fd, Whence::End, -2), Ok(8));
        assert_eq!(table.seek(fd, Whence::Set, -1), Err(FdError::InvalidSeek));
        assert_eq!(table.seek(fd, Whence::Cur, -100), Err(FdError::InvalidSeek));
        // 越过 EOF 的 Set 合法（写时零填充，读得 0）。
        assert_eq!(table.seek(fd, Whence::Set, 100), Ok(100));
        assert_eq!(table.read(fd, &mut [0u8; 4]), Ok(0));
    }

    #[test]
    fn stat_does_not_touch_offset_and_dir_openable() {
        let (ns, mut table) = setup();
        let ffd = table
            .open(resolve(&ns, "/data/file"), OpenFlags::READ)
            .expect("open file");
        assert_eq!(table.seek(ffd, Whence::Cur, 3), Ok(3));
        let meta = table.stat(ffd).expect("stat");
        assert_eq!(meta.size, 10);
        assert_eq!(meta.vnode, VnodeId(3));
        assert_eq!(table.tell(ffd), Ok(3), "stat must not move offset");

        let dfd = table
            .open(resolve(&ns, "/data"), OpenFlags::READ)
            .expect("dir openable");
        let mut buf = [0u8; 4];
        assert_eq!(
            table.read(dfd, &mut buf),
            Err(FdError::Fs(crate::vfs::FsError::IsDirectory))
        );
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
    }

    #[test]
    fn ghost_fd_is_stale() {
        let (_ns, mut table) = setup();
        let ghost = crate::Key {
            index: 0,
            generation: 999,
        };
        assert_eq!(table.read(ghost, &mut [0u8; 1]), Err(FdError::StaleFd));
        assert!(matches!(table.close(ghost), Err(FdError::StaleFd)));
        assert_eq!(table.seek(ghost, Whence::Set, 0), Err(FdError::StaleFd));
    }

    #[test]
    fn open_flags_from_bits_roundtrip() {
        use super::OpenFlags;
        assert_eq!(OpenFlags::from_bits(0b01), Some(OpenFlags::READ));
        assert_eq!(OpenFlags::from_bits(0b10), Some(OpenFlags::WRITE));
        assert_eq!(OpenFlags::from_bits(0b11), Some(OpenFlags::READ_WRITE));
        assert_eq!(OpenFlags::from_bits(0), None, "零模式拒收");
        assert_eq!(OpenFlags::from_bits(0b100), None, "保留位拒收");
        assert_eq!(OpenFlags::from_bits(0xFF), None);
        // 往返：位型 → 构造 → 谓词一致
        for bits in [0b01u8, 0b10, 0b11] {
            let f = OpenFlags::from_bits(bits).expect("valid");
            assert_eq!(f.readable(), bits & 0b01 != 0);
            assert_eq!(f.writable(), bits & 0b10 != 0);
            assert!(f.is_any());
        }
    }
}
