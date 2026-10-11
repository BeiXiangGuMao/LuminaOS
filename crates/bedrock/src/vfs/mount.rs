//! 挂载表与命名空间：跨文件系统的统一名字解析。
//!
//! 解析模型（M13-① 骨架）：路径在进入解析前已完成词法规范化（[`super::path`]），
//! 解析时选取**组件意义下最长前缀**的挂载点，余下组件自该文件系统根逐段走查
//! （[`super::fs::walk`]）。最长前缀策略天然覆盖嵌套挂载——更深挂载点必然
//! 拥有更长前缀而被优先选中，无需在逐段走查中二次检查挂载表。
//!
//! 并发模型：挂载表整体置于 OSTD `SpinLock` 之后；`resolve` 在持锁期间完成
//! 走查（骨架级简化——挂载/卸载与解析互斥，文件面块引入路径步行器时再评估
//! 细粒度方案）。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ostd::sync::SpinLock;

use super::fs::{walk, FileSystem};
use super::node::VnodeId;
use super::path::PathBuf;
use super::FsError;

/// 单条挂载记录：挂载路径 + 文件系统实例。
#[derive(Clone)]
struct Mount {
    path: PathBuf,
    fs: Arc<dyn FileSystem>,
}

/// 挂载表：按「组件深度降序、路径字典序」排序，保证最长前缀优先命中。
#[derive(Default)]
struct MountTable {
    mounts: Vec<Mount>,
}

impl MountTable {
    fn sort(&mut self) {
        self.mounts
            .sort_by(|a, b| (b.path.depth(), &b.path).cmp(&(a.path.depth(), &a.path)));
    }

    fn find_exact(&self, path: &PathBuf) -> Option<usize> {
        self.mounts.iter().position(|m| m.path == *path)
    }
}

/// 命名空间：根文件系统 + 挂载表。
pub struct Namespace {
    root: Arc<dyn FileSystem>,
    table: SpinLock<MountTable>,
}

/// 解析结果：落点文件系统 + 节点号 + 解析所用规范路径。
#[derive(Clone)]
pub struct ResolvedNode {
    /// 落点文件系统。
    pub fs: Arc<dyn FileSystem>,
    /// 该文件系统内的节点号。
    pub vnode: VnodeId,
    /// 解析输入的规范路径（诊断与后续 openat 语义复用）。
    pub path: PathBuf,
}

impl core::fmt::Debug for ResolvedNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 文件系统为 trait 对象，不参与 Debug；以节点号 + 路径标识落点。
        f.debug_struct("ResolvedNode")
            .field("vnode", &self.vnode)
            .field("path", &self.path)
            .finish()
    }
}

impl Namespace {
    /// 以 `root` 为根文件系统创建命名空间（根不可卸载）。
    pub fn new(root: Arc<dyn FileSystem>) -> Self {
        Self {
            root,
            table: SpinLock::new(MountTable::default()),
        }
    }

    /// 根文件系统的根节点。
    pub fn root_node(&self) -> VnodeId {
        self.root.root_vnode()
    }

    /// 在既有目录 `path` 上挂载 `fs`。挂载点必须已存在且为目录；
    /// 同一路径重复挂载返回 [`FsError::AlreadyExists`]。
    pub fn mount(&self, path: &PathBuf, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
        let spot = self.resolve_locked(path)?;
        if !spot.fs.metadata(spot.vnode)?.kind.is_dir() {
            return Err(FsError::NotADirectory);
        }
        let mut table = self.table.lock();
        if table.find_exact(path).is_some() {
            return Err(FsError::AlreadyExists);
        }
        table.mounts.push(Mount {
            path: path.clone(),
            fs,
        });
        table.sort();
        Ok(())
    }

    /// 卸载 `path` 处的挂载（根挂载不可卸载，返回 [`FsError::NotFound`]）。
    /// 占用检查（卸载时有打开句柄）留待句柄面复核，骨架不阻塞卸载。
    pub fn unmount(&self, path: &PathBuf) -> Result<(), FsError> {
        self.unmount_if_idle(path, |_| false)
    }

    /// 带占用复核的卸载（M17-③）：摘表前先以 `busy` 闭包复核挂载 fs
    /// ——存活打开句柄等占用面返回 true 时以 [`FsError::Busy`] 拒卸。
    /// 检查与摘表同锁原子（table 自旋锁内完成，检查后无插队窗口）；
    /// `busy` 闭包在锁内执行——锁序约定：挂载表锁 → 闭包内取用的
    /// 下层锁（内核面：NAMESPACE → FILES 单向嵌套，无反向边）。
    pub fn unmount_if_idle(
        &self,
        path: &PathBuf,
        busy: impl Fn(&Arc<dyn FileSystem>) -> bool,
    ) -> Result<(), FsError> {
        let mut table = self.table.lock();
        match table.find_exact(path) {
            Some(idx) => {
                if busy(&table.mounts[idx].fs) {
                    return Err(FsError::Busy);
                }
                table.mounts.swap_remove(idx);
                table.sort();
                Ok(())
            }
            None => Err(FsError::NotFound),
        }
    }

    /// 解析绝对路径至落点（文件系统 + 节点号）。
    pub fn resolve(&self, path: &PathBuf) -> Result<ResolvedNode, FsError> {
        self.resolve_locked(path)
    }

    /// 持锁解析：先选最长前缀挂载，再余段走查。
    fn resolve_locked(&self, path: &PathBuf) -> Result<ResolvedNode, FsError> {
        let table = self.table.lock();
        // 根挂载是保底前缀（空组件序列 → 根节点）。
        let mut best: Option<&Mount> = None;
        for m in &table.mounts {
            if path.starts_with_components(&m.path)
                && best
                    .as_ref()
                    .is_none_or(|b| m.path.depth() > b.path.depth())
            {
                best = Some(m);
            }
        }
        let (fs, base_depth) = match best {
            Some(m) => (m.fs.clone(), m.path.depth()),
            None => (self.root.clone(), 0),
        };
        let rest: Vec<String> = path
            .components()
            .skip(base_depth)
            .map(String::from)
            .collect();
        let vnode = walk(fs.as_ref(), rest)?;
        Ok(ResolvedNode {
            fs,
            vnode,
            path: path.clone(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Namespace, PathBuf};
    use crate::vfs::fs::FileSystem;
    use crate::vfs::node::{NodeKind, VnodeId};
    use crate::vfs::ramfs::{RamFs, RAMFS_ROOT};
    use crate::vfs::FsError;
    use alloc::sync::Arc;

    fn path(s: &str) -> PathBuf {
        PathBuf::normalize(s).expect("normalize")
    }

    /// 布局：根 ramfs 含 /etc/motd 与挂载点 /mnt；/mnt 挂第二 ramfs（内含 /data）；
    /// /mnt/data 上再挂第三 ramfs（嵌套挂载）。
    fn setup() -> Namespace {
        let root = Arc::new(RamFs::new());
        let etc = root
            .create(RAMFS_ROOT, "etc", NodeKind::Dir)
            .expect("mkdir");
        root.create(etc, "motd", NodeKind::File).expect("touch");
        root.create(RAMFS_ROOT, "mnt", NodeKind::Dir)
            .expect("mkdir mnt");
        let ns = Namespace::new(root);

        let mnt_fs = Arc::new(RamFs::new());
        mnt_fs
            .create(mnt_fs.root_vnode(), "data", NodeKind::Dir)
            .expect("mkdir data");
        ns.mount(&path("/mnt"), mnt_fs.clone()).expect("mount /mnt");

        let inner_fs = Arc::new(RamFs::new());
        inner_fs
            .create(inner_fs.root_vnode(), "deep.txt", NodeKind::File)
            .expect("touch deep");
        ns.mount(&path("/mnt/data"), inner_fs)
            .expect("mount nested");
        ns
    }

    #[test]
    fn resolve_root_and_root_level_paths() {
        let ns = setup();
        let root_res = ns.resolve(&path("/")).expect("resolve /");
        assert_eq!(root_res.vnode, VnodeId(1));
        assert_eq!(root_res.fs.root_vnode(), VnodeId(1));
        let etc = ns.resolve(&path("/etc")).expect("resolve /etc");
        assert_eq!(etc.vnode, VnodeId(2));
        let motd = ns.resolve(&path("/etc/motd")).expect("resolve /etc/motd");
        assert_eq!(motd.vnode, VnodeId(3));
    }

    #[test]
    fn resolve_switches_fs_at_mount_point() {
        let ns = setup();
        let root_res = ns.resolve(&path("/")).expect("resolve /");
        let mnt = ns.resolve(&path("/mnt")).expect("resolve /mnt");
        // 命中第二 ramfs 的根（其根节点号同为 1，但实例不同——以 Arc 指针区分）。
        assert_eq!(mnt.vnode, VnodeId(1));
        assert!(
            !Arc::ptr_eq(&mnt.fs, &root_res.fs),
            "mounted fs is a different instance"
        );
        let data = ns.resolve(&path("/mnt/data")).expect("/mnt/data");
        // /mnt/data 是嵌套挂载点 → 落在第三 ramfs 根，而非第二 ramfs 的 data 目录。
        assert_eq!(data.vnode, VnodeId(1));
    }

    #[test]
    fn nested_mount_takes_longest_prefix() {
        let ns = setup();
        let deep = ns.resolve(&path("/mnt/data/deep.txt")).expect("deep");
        assert_eq!(deep.vnode, VnodeId(2), "inner fs node, not dir VnodeId(2)");
        let sibling = ns.resolve(&path("/mnt/etc"));
        // 第二 ramfs 并无 /etc —— 走查发生在挂载 fs 内部。
        assert!(matches!(sibling, Err(FsError::NotFound)));
    }

    #[test]
    fn mount_point_must_exist_and_be_dir() {
        let ns = Namespace::new(Arc::new(RamFs::new()));
        let ghost = Arc::new(RamFs::new());
        assert_eq!(
            ns.mount(&path("/nowhere"), ghost.clone()),
            Err(FsError::NotFound)
        );
        let root = Arc::new(RamFs::new());
        root.create(RAMFS_ROOT, "f", NodeKind::File).expect("touch");
        let ns2 = Namespace::new(root);
        assert_eq!(ns2.mount(&path("/f"), ghost), Err(FsError::NotADirectory));
    }

    #[test]
    fn duplicate_mount_rejected_and_unmount_restores() {
        let ns = setup();
        let another = Arc::new(RamFs::new());
        assert_eq!(
            ns.mount(&path("/mnt"), another),
            Err(FsError::AlreadyExists)
        );
        ns.unmount(&path("/mnt/data")).expect("unmount nested");
        // 卸载后 /mnt/data 落回第二 ramfs 的 data 目录（VnodeId(2)）。
        let data = ns.resolve(&path("/mnt/data")).expect("data");
        assert_eq!(data.vnode, VnodeId(2));
        ns.unmount(&path("/mnt")).expect("unmount /mnt");
        assert_eq!(
            ns.resolve(&path("/mnt/data")).err(),
            Some(FsError::NotFound)
        );
        assert_eq!(ns.unmount(&path("/mnt")), Err(FsError::NotFound));
    }

    #[test]
    fn resolution_errors_propagate() {
        let ns = setup();
        assert_eq!(ns.resolve(&path("/ghost")).err(), Some(FsError::NotFound));
        // 文件下再走一段 → 走查在 lookup 处报 NotADirectory。
        assert_eq!(
            ns.resolve(&path("/etc/motd/child")).err(),
            Some(FsError::NotADirectory)
        );
    }

    #[test]
    fn unmount_if_idle_rejects_busy_fs_with_ebusy() {
        let ns = setup();
        // ① 占用闭包 true → EBUSY，挂载仍存（可继续解析子 fs 内容）。
        assert_eq!(
            ns.unmount_if_idle(&path("/mnt/data"), |_| true),
            Err(FsError::Busy)
        );
        assert!(ns.resolve(&path("/mnt/data/deep.txt")).is_ok(), "survives");
        // ② 闭包按实例精确判定：/mnt/data 挂 inner_fs——命中才拒。
        let probe = ns.resolve(&path("/mnt/data")).expect("data").fs;
        assert_eq!(
            ns.unmount_if_idle(&path("/mnt/data"), |f| Arc::ptr_eq(f, &probe)),
            Err(FsError::Busy)
        );
        // ③ 换用他实例（/mnt 的 fs）作闭包 → 不命中 → 卸载放行。
        let other = ns.resolve(&path("/mnt")).expect("mnt").fs;
        assert!(!Arc::ptr_eq(&probe, &other));
        assert_eq!(
            ns.unmount_if_idle(&path("/mnt/data"), |f| Arc::ptr_eq(f, &other)),
            Ok(())
        );
        assert_eq!(
            ns.resolve(&path("/mnt/data/deep.txt")).err(),
            Some(FsError::NotFound)
        );
    }

    #[test]
    fn unmount_if_idle_not_found_passthrough() {
        let ns = setup();
        assert_eq!(
            ns.unmount_if_idle(&path("/nowhere"), |_| true),
            Err(FsError::NotFound)
        );
    }
}
