//! VFS 骨架 —— 虚拟文件系统的内核数据结构面（M13 路线第①块）。
//!
//! 定位：作为「文件面」（SYS_OPEN/READ/WRITE/CLOSE/STAT 等 syscall 落点）与
//! 「多段映像」（SYS_EXEC 装载器经 VFS 读取映像段）的**公共基座**。本模块只
//! 提供内核内的名字空间与读写语义，不触及寄存器级 ABI（[`crate::abi`]）；
//! 后续块在此之上增量接线，本面形态保持稳定。
//!
//! 分层（自底向上）：
//! - [`path`]：绝对路径的词法规范化（组件化、`..` 消解）；
//! - [`node`]：VNode 标识 / 类型 / 元数据 / 错误集；
//! - [`fs`]：`FileSystem` 特征——文件系统侧最小完备契约；
//! - [`ramfs`]：内存文件系统（参照实现与测试基座）；
//! - [`mount`]：挂载表与命名空间（最长前缀解析）；
//! - [`fd`]：fd 表——Crystal 代际槽承载的打开文件描述。
//!
//! 并发纪律：全部共享状态经由 OSTD `SpinLock`（[`ostd::sync::SpinLock`]），
//! 本模块自身不含任何 unsafe；`Arc<dyn FileSystem>` 使跨挂载共享实例成立。

pub mod fd;
pub mod fs;
pub mod mount;
pub mod node;
pub mod path;
pub mod ramfs;

pub use fd::{Fd, FdError, FdTable, OpenFileDescription, OpenFlags, Whence};
pub use fs::{dir_entry_abi_code, pack_dir_page, FileSystem};
pub use mount::{Namespace, ResolvedNode};
pub use node::{DirEntry, FsError, Metadata, NodeKind, VnodeId};
pub use path::PathBuf;
pub use ramfs::RamFs;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FdTable, Namespace, NodeKind, OpenFlags, PathBuf, RamFs, Whence};
    use crate::vfs::fs::FileSystem;
    use alloc::sync::Arc;

    /// 端到端：命名空间建目录树 → 子 fs 挂载 → fd 表读写穿挂载点 → 卸载回落。
    #[test]
    fn full_stack_namespace_mount_fd_roundtrip() {
        // 根 fs：/conf/seed 内容 "root-fs"。
        let root_fs = Arc::new(RamFs::new());
        let conf = root_fs
            .create(root_fs.root_vnode(), "conf", NodeKind::Dir)
            .expect("mkdir conf");
        let seed = root_fs.create(conf, "seed", NodeKind::File).expect("touch");
        root_fs.write_at(seed, 0, b"root-fs").expect("seed");

        let ns = Namespace::new(root_fs.clone());
        let mut table = FdTable::new();

        // 打开根 fs 上的文件并整读。
        let open_path = |ns: &Namespace, p: &str| {
            ns.resolve(&PathBuf::normalize(p).expect("norm"))
                .expect("resolve")
        };
        let fd = table
            .open(open_path(&ns, "/conf/seed"), OpenFlags::READ)
            .expect("open");
        let mut buf = [0u8; 7];
        assert_eq!(table.read(fd, &mut buf), Ok(7));
        assert_eq!(&buf, b"root-fs");
        table.close(fd).expect("close");

        // 挂载第二 fs 到 /conf/tmpfs（挂载点先建后挂，挂载后被子 fs 遮蔽），写穿挂载点。
        let tmpfs = Arc::new(RamFs::new());
        tmpfs
            .create(tmpfs.root_vnode(), "notes", NodeKind::File)
            .expect("touch notes");
        root_fs
            .create(conf, "tmpfs", NodeKind::Dir)
            .expect("mkdir tmpfs");
        ns.mount(&PathBuf::normalize("/conf/tmpfs").expect("norm"), tmpfs)
            .expect("mount");
        let wfd = table
            .open(open_path(&ns, "/conf/tmpfs/notes"), OpenFlags::READ_WRITE)
            .expect("open in mounted fs");
        assert_eq!(table.write(wfd, b"mounted"), Ok(7));
        assert_eq!(table.seek(wfd, Whence::Set, 0), Ok(0));
        let mut buf2 = [0u8; 7];
        assert_eq!(table.read(wfd, &mut buf2), Ok(7));
        assert_eq!(&buf2, b"mounted");
        table.close(wfd).expect("close");

        // 卸载后同名路径不再可达（回落到根 fs 的视角）。
        ns.unmount(&PathBuf::normalize("/conf/tmpfs").expect("norm"))
            .expect("unmount");
        assert!(ns
            .resolve(&PathBuf::normalize("/conf/tmpfs/notes").expect("norm"))
            .is_err());
    }
}
