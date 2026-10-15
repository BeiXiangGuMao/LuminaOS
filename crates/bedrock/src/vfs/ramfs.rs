//! RamFS —— 内存文件系统（VFS 骨架的参照实现）。
//!
//! 职责边界：以最小数据结构（节点表 + 目录映射 + 字节缓冲）完整兑现
//! [`FileSystem`] 契约，作为挂载/解析/fd 语义的测试基座，也是后续 tmpfs 与
//! 块设备文件系统接入前的行为锚点。目录项以 `BTreeMap` 组织，readdir 天然
//! 按名字典序输出；节点号单调递增不复用，避免 VNode 级 ABA。
//!
//! **M17-② 稳定 cookie**：目录子项升级为 [`DirSlot`]（节点号 + cookie），
//! 另持 cookie → 名字序表（`order`）承载 [`FileSystem::readdir_from`]
//! 的稳定枚举（插入序：已交付 cookie 不因中途增删漂移，getdents64
//! 同款）；name 字典序面（`readdir`/`lookup`/`walk`）语义不变。
//!
//! 语义注记（骨架级简化，均由文件面块复核）：
//! - unlink 直接摘除节点；已打开 fd 后续访问将得到 `NotFound`（无「最后
//!   关闭者」延迟回收）；
//! - 无硬链接与权限位；`Symlink` / `CharDev` / `Pipe` 创建被拒绝。

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use ostd::sync::SpinLock;

use super::fs::{CookieEntry, FileSystem};
use super::node::{DirEntry, Metadata, NodeKind, VnodeId};
use super::path::validate_component;
use super::FsError;

/// RamFS 的根节点号（节点号从 1 起，0 永久空缺以便与「未初始化」区分）。
pub const RAMFS_ROOT: VnodeId = VnodeId(1);

/// 目录子项槽：名字到（节点号 + 稳定 cookie）的落位（M17-②）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirSlot {
    vnode: VnodeId,
    /// 稳定 cookie（per-fs 单调铸造，创建后不变、删除即退役）。
    cookie: u64,
}

#[derive(Debug)]
struct RamNode {
    kind: NodeKind,
    /// 仅 `NodeKind::File` 使用。
    data: Vec<u8>,
    /// 仅 `NodeKind::Dir` 使用：名字 → 子项槽（字典序）。
    children: BTreeMap<String, DirSlot>,
}

#[derive(Debug)]
struct RamFsInner {
    nodes: BTreeMap<VnodeId, RamNode>,
    next_id: u64,
    /// 稳定 cookie 铸造计数（per-fs 单调；0 = 起点哨兵不产出）。
    next_cookie: u64,
    /// cookie → （父目录，名字）（枚举序表：readdir_from 按此序产出，
    /// 插入序；带父目录归属——多目录共存一表，按 dir 过滤）。
    order: BTreeMap<u64, (VnodeId, String)>,
}

/// 内存文件系统实例。
pub struct RamFs {
    inner: SpinLock<RamFsInner>,
}

impl RamFs {
    /// 创建仅含根目录的空文件系统。
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            RAMFS_ROOT,
            RamNode {
                kind: NodeKind::Dir,
                data: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        Self {
            inner: SpinLock::new(RamFsInner {
                nodes,
                next_id: 2,
                next_cookie: 1,
                order: BTreeMap::new(),
            }),
        }
    }

    fn dir_children(
        inner: &RamFsInner,
        dir: VnodeId,
    ) -> Result<&BTreeMap<String, DirSlot>, FsError> {
        let node = inner.nodes.get(&dir).ok_or(FsError::NotFound)?;
        if !node.kind.is_dir() {
            return Err(FsError::NotADirectory);
        }
        Ok(&node.children)
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for RamFs {
    fn root_vnode(&self) -> VnodeId {
        RAMFS_ROOT
    }

    fn lookup(&self, dir: VnodeId, name: &str) -> Result<VnodeId, FsError> {
        validate_component(name)?;
        let inner = self.inner.lock();
        let children = Self::dir_children(&inner, dir)?;
        children.get(name).map(|s| s.vnode).ok_or(FsError::NotFound)
    }

    fn metadata(&self, vnode: VnodeId) -> Result<Metadata, FsError> {
        let inner = self.inner.lock();
        let node = inner.nodes.get(&vnode).ok_or(FsError::NotFound)?;
        let size = match node.kind {
            NodeKind::File => node.data.len() as u64,
            _ => 0,
        };
        Ok(Metadata {
            vnode,
            kind: node.kind,
            size,
        })
    }

    fn read_at(&self, vnode: VnodeId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let inner = self.inner.lock();
        let node = inner.nodes.get(&vnode).ok_or(FsError::NotFound)?;
        if !matches!(node.kind, NodeKind::File) {
            return Err(FsError::IsDirectory);
        }
        if offset >= node.data.len() as u64 || buf.is_empty() {
            return Ok(0);
        }
        let start = offset as usize;
        let end = start.saturating_add(buf.len()).min(node.data.len());
        let count = end - start;
        buf[..count].copy_from_slice(&node.data[start..end]);
        Ok(count)
    }

    fn write_at(&self, vnode: VnodeId, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let mut inner = self.inner.lock();
        let node = inner.nodes.get_mut(&vnode).ok_or(FsError::NotFound)?;
        if !matches!(node.kind, NodeKind::File) {
            return Err(FsError::IsDirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        // pwrite 语义：起点超出 EOF 时先零填充至起点，再原地写入。
        if offset > node.data.len() as u64 {
            node.data.resize(offset as usize, 0);
        }
        let start = offset as usize;
        let new_len = start + data.len();
        if node.data.len() < new_len {
            node.data.resize(new_len, 0);
        }
        node.data[start..new_len].copy_from_slice(data);
        Ok(data.len())
    }

    fn create(&self, dir: VnodeId, name: &str, kind: NodeKind) -> Result<VnodeId, FsError> {
        validate_component(name)?;
        match kind {
            NodeKind::File | NodeKind::Dir => {}
            _ => return Err(FsError::NotSupported),
        }
        let mut inner = self.inner.lock();
        // 借用拆分：目录children检查通过后，children 与 nodes/next_id 分离可变访问。
        if !Self::dir_children(&inner, dir)?.contains_key(name) {
            let id = VnodeId(inner.next_id);
            inner.next_id += 1;
            // M17-②：稳定 cookie 铸造（per-fs 单调，0 哨兵不产出）。
            let cookie = inner.next_cookie;
            inner.next_cookie += 1;
            let fresh = RamNode {
                kind,
                data: Vec::new(),
                children: BTreeMap::new(),
            };
            inner.nodes.insert(id, fresh);
            let name_key = String::from(name);
            inner.order.insert(cookie, (dir, name_key.clone()));
            // insert 对新键返回 None（旧值语义），此处恒为新键，直接落表。
            Self::dir_children_mut(&mut inner, dir)?
                .insert(name_key, DirSlot { vnode: id, cookie });
            return Ok(id);
        }
        Err(FsError::AlreadyExists)
    }

    fn unlink(&self, dir: VnodeId, name: &str) -> Result<(), FsError> {
        validate_component(name)?;
        let mut inner = self.inner.lock();
        let child = Self::dir_children(&inner, dir)?
            .get(name)
            .copied()
            .ok_or(FsError::NotFound)?;
        if let Some(node) = inner.nodes.get(&child.vnode) {
            if node.kind.is_dir() && !node.children.is_empty() {
                return Err(FsError::DirectoryNotEmpty);
            }
        }
        Self::dir_children_mut(&mut inner, dir)?
            .remove(name)
            .ok_or(FsError::NotFound)?;
        // M17-②：cookie 退役（序表同步摘除；cookie 不复用）。
        inner.order.remove(&child.cookie);
        inner.nodes.remove(&child.vnode);
        Ok(())
    }

    fn readdir(&self, dir: VnodeId) -> Result<Vec<DirEntry>, FsError> {
        let inner = self.inner.lock();
        let children = Self::dir_children(&inner, dir)?;
        let mut entries = Vec::with_capacity(children.len());
        for (name, slot) in children {
            let kind = inner
                .nodes
                .get(&slot.vnode)
                .map(|n| n.kind)
                .ok_or(FsError::NotFound)?;
            entries.push(DirEntry {
                name: name.clone(),
                vnode: slot.vnode,
                kind,
            });
        }
        Ok(entries)
    }

    fn readdir_from(&self, dir: VnodeId, after_cookie: u64) -> Result<Vec<CookieEntry>, FsError> {
        let inner = self.inner.lock();
        // 目录存在性判定（与 readdir 同款：非目录/缺失同面拒绝）。
        Self::dir_children(&inner, dir)?;
        let mut items = Vec::new();
        for (cookie, (parent, name)) in inner.order.range((
            core::ops::Bound::Excluded(after_cookie),
            core::ops::Bound::Unbounded,
        )) {
            if *parent != dir {
                continue; // 序表跨目录共享：仅产出本目录子项
            }
            // 序表与目录映射同锁维护；孤儿序项为不变量违反，防御拒绝。
            let slot = Self::dir_children(&inner, dir)?
                .get(name)
                .ok_or(FsError::NotFound)?;
            let kind = inner
                .nodes
                .get(&slot.vnode)
                .map(|n| n.kind)
                .ok_or(FsError::NotFound)?;
            items.push(CookieEntry {
                entry: DirEntry {
                    name: name.clone(),
                    vnode: slot.vnode,
                    kind,
                },
                cookie: *cookie,
            });
        }
        Ok(items)
    }

    fn truncate(&self, vnode: VnodeId) -> Result<(), FsError> {
        let mut inner = self.inner.lock();
        let node = inner.nodes.get_mut(&vnode).ok_or(FsError::NotFound)?;
        if !matches!(node.kind, NodeKind::File) {
            return Err(FsError::IsDirectory);
        }
        node.data.clear();
        Ok(())
    }
}

/// 可变版目录访问（与 [`RamFs::dir_children`] 对偶）。
impl RamFs {
    fn dir_children_mut(
        inner: &mut RamFsInner,
        dir: VnodeId,
    ) -> Result<&mut BTreeMap<String, DirSlot>, FsError> {
        let node = inner.nodes.get_mut(&dir).ok_or(FsError::NotFound)?;
        if !node.kind.is_dir() {
            return Err(FsError::NotADirectory);
        }
        Ok(&mut node.children)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FileSystem, RamFs, RAMFS_ROOT};
    use crate::vfs::node::{NodeKind, VnodeId};
    use crate::vfs::FsError;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn root_exists_and_is_dir() {
        let fs = RamFs::new();
        let meta = fs.metadata(RAMFS_ROOT).expect("root metadata");
        assert_eq!(meta.kind, NodeKind::Dir);
        assert_eq!(meta.size, 0);
        assert_eq!(fs.root_vnode(), VnodeId(1));
    }

    #[test]
    fn file_write_read_roundtrip() {
        let fs = RamFs::new();
        let f = fs
            .create(RAMFS_ROOT, "hello.txt", NodeKind::File)
            .expect("create");
        assert_eq!(fs.write_at(f, 0, b"lumina"), Ok(6));
        let mut buf = [0u8; 16];
        assert_eq!(fs.read_at(f, 0, &mut buf), Ok(6));
        assert_eq!(&buf[..6], b"lumina");
        assert_eq!(fs.metadata(f).unwrap().size, 6);
    }

    #[test]
    fn write_pads_gap_and_overwrites_in_place() {
        let fs = RamFs::new();
        let f = fs.create(RAMFS_ROOT, "g", NodeKind::File).expect("create");
        assert_eq!(fs.write_at(f, 4, b"XY"), Ok(2));
        let mut buf = [0u8; 8];
        assert_eq!(fs.read_at(f, 0, &mut buf), Ok(6));
        assert_eq!(&buf[..6], &[0, 0, 0, 0, b'X', b'Y']);
        assert_eq!(fs.write_at(f, 4, b"Z"), Ok(1));
        let mut buf2 = [0u8; 6];
        assert_eq!(fs.read_at(f, 0, &mut buf2), Ok(6));
        // pwrite 单字节覆盖不截断：末尾 'Y' 保留。
        assert_eq!(&buf2, &[0, 0, 0, 0, b'Z', b'Y']);
        // 远端偏移：写入点必须落在 offset 处，而非旧长度处。
        assert_eq!(fs.write_at(f, 10, b"TAIL"), Ok(4));
        assert_eq!(fs.metadata(f).unwrap().size, 14);
        let mut buf3 = [0u8; 4];
        assert_eq!(fs.read_at(f, 10, &mut buf3), Ok(4));
        assert_eq!(&buf3, b"TAIL");
        assert_eq!(fs.read_at(f, 6, &mut buf3), Ok(4));
        assert_eq!(&buf3, &[0, 0, 0, 0]);
    }

    #[test]
    fn read_past_eof_is_zero_and_empty_write_is_noop() {
        let fs = RamFs::new();
        let f = fs.create(RAMFS_ROOT, "e", NodeKind::File).expect("create");
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(f, 0, &mut buf), Ok(0));
        assert_eq!(fs.read_at(f, 100, &mut buf), Ok(0));
        assert_eq!(fs.write_at(f, 0, &[]), Ok(0));
        assert_eq!(fs.metadata(f).unwrap().size, 0);
    }

    #[test]
    fn dir_tree_readdir_sorted_and_lookup() {
        let fs = RamFs::new();
        let etc = fs.create(RAMFS_ROOT, "etc", NodeKind::Dir).expect("mkdir");
        fs.create(etc, "motd", NodeKind::File).expect("touch");
        fs.create(etc, "conf", NodeKind::File).expect("touch");
        fs.create(RAMFS_ROOT, "bin", NodeKind::Dir).expect("mkdir");
        let root_entries = fs.readdir(RAMFS_ROOT).expect("readdir root");
        let names: Vec<_> = root_entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["bin", "etc"]);
        let etc_entries = fs.readdir(etc).expect("readdir etc");
        let names: Vec<_> = etc_entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["conf", "motd"]);
        assert_eq!(fs.lookup(etc, "motd"), Ok(VnodeId(3)));
        assert_eq!(fs.lookup(etc, "ghost"), Err(FsError::NotFound));
    }

    #[test]
    fn create_conflicts_and_invalid_names() {
        let fs = RamFs::new();
        fs.create(RAMFS_ROOT, "dup", NodeKind::File).expect("first");
        assert_eq!(
            fs.create(RAMFS_ROOT, "dup", NodeKind::File),
            Err(FsError::AlreadyExists)
        );
        assert_eq!(
            fs.create(RAMFS_ROOT, "", NodeKind::File),
            Err(FsError::InvalidPath)
        );
        assert_eq!(
            fs.create(RAMFS_ROOT, "a/b", NodeKind::File),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn unsupported_kinds_rejected() {
        let fs = RamFs::new();
        assert_eq!(
            fs.create(
                RAMFS_ROOT,
                "tty",
                NodeKind::CharDev {
                    major: 4,
                    minor: 64
                }
            ),
            Err(FsError::NotSupported)
        );
        assert_eq!(
            fs.create(RAMFS_ROOT, "pipe", NodeKind::Pipe),
            Err(FsError::NotSupported)
        );
        assert_eq!(
            fs.create(RAMFS_ROOT, "link", NodeKind::Symlink),
            Err(FsError::NotSupported)
        );
    }

    #[test]
    fn unlink_rules() {
        let fs = RamFs::new();
        let dir = fs.create(RAMFS_ROOT, "d", NodeKind::Dir).expect("mkdir");
        fs.create(dir, "inner", NodeKind::File).expect("touch");
        assert_eq!(fs.unlink(RAMFS_ROOT, "d"), Err(FsError::DirectoryNotEmpty));
        assert_eq!(fs.unlink(dir, "inner"), Ok(()));
        assert_eq!(fs.unlink(RAMFS_ROOT, "d"), Ok(()));
        assert_eq!(fs.unlink(RAMFS_ROOT, "d"), Err(FsError::NotFound));
        assert_eq!(fs.unlink(RAMFS_ROOT, "ghost"), Err(FsError::NotFound));
        assert_eq!(fs.unlink(RAMFS_ROOT, ""), Err(FsError::InvalidPath));
    }

    #[test]
    fn unlinked_node_disappears() {
        let fs = RamFs::new();
        let f = fs
            .create(RAMFS_ROOT, "tmp", NodeKind::File)
            .expect("create");
        fs.unlink(RAMFS_ROOT, "tmp").expect("unlink");
        assert_eq!(fs.metadata(f), Err(FsError::NotFound));
    }

    #[test]
    fn truncate_rules() {
        let fs = RamFs::new();
        let f = fs.create(RAMFS_ROOT, "f", NodeKind::File).expect("create");
        fs.write_at(f, 0, b"lumina").expect("write");
        assert_eq!(fs.metadata(f).unwrap().size, 6);
        // 截断后尺寸归零、后续读为 EOF；pwrite 语义下再写仍从偏移落位
        assert_eq!(fs.truncate(f), Ok(()));
        assert_eq!(fs.metadata(f).unwrap().size, 0);
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(f, 0, &mut buf), Ok(0));
        fs.write_at(f, 0, b"ab").expect("rewrite");
        assert_eq!(fs.metadata(f).unwrap().size, 2);
        // 目录 → IsDirectory；缺失 → NotFound
        let d = fs.create(RAMFS_ROOT, "d", NodeKind::Dir).expect("mkdir");
        assert_eq!(fs.truncate(d), Err(FsError::IsDirectory));
        assert_eq!(
            fs.truncate(super::super::node::VnodeId(999)),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn file_used_as_dir_is_rejected() {
        let fs = RamFs::new();
        let f = fs.create(RAMFS_ROOT, "f", NodeKind::File).expect("create");
        assert_eq!(fs.lookup(f, "x"), Err(FsError::NotADirectory));
        assert_eq!(
            fs.create(f, "x", NodeKind::File),
            Err(FsError::NotADirectory)
        );
        assert_eq!(fs.readdir(f), Err(FsError::NotADirectory));
        let mut buf = [0u8; 4];
        assert_eq!(
            fs.read_at(RAMFS_ROOT, 0, &mut buf),
            Err(FsError::IsDirectory)
        );
        assert_eq!(fs.write_at(RAMFS_ROOT, 0, b"x"), Err(FsError::IsDirectory));
    }

    #[test]
    fn missing_vnode_everywhere_is_not_found() {
        let fs = RamFs::new();
        let ghost = VnodeId(999);
        assert_eq!(fs.metadata(ghost), Err(FsError::NotFound));
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(ghost, 0, &mut buf), Err(FsError::NotFound));
        assert_eq!(
            fs.create(ghost, "x", NodeKind::File),
            Err(FsError::NotFound)
        );
    }

    // ---- M17-② 稳定 cookie 枚举（getdents64 同款语义域） ----

    /// 造目录 + n 个子文件，返回目录号。
    fn seeded_dir(fs: &RamFs, name: &str, children: &[&str]) -> VnodeId {
        let d = fs.create(RAMFS_ROOT, name, NodeKind::Dir).expect("mkdir");
        for c in children {
            fs.create(d, c, NodeKind::File).expect("touch");
        }
        d
    }

    #[test]
    fn readdir_from_zero_lists_all_in_insertion_order() {
        let fs = RamFs::new();
        let d = seeded_dir(&fs, "d", &["a", "b", "c"]);
        let items = fs.readdir_from(d, 0).expect("readdir_from 0");
        let names: Vec<_> = items.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"], "insertion order");
        // cookie 单调递增、0 哨兵不产出。
        let cookies: Vec<u64> = items.iter().map(|c| c.cookie).collect();
        assert!(cookies.windows(2).all(|w| w[0] < w[1]));
        assert!(!cookies.contains(&0));
    }

    #[test]
    fn insertion_mid_enumeration_does_not_drift() {
        let fs = RamFs::new();
        let d = seeded_dir(&fs, "d", &["a", "b", "c"]);
        // 首页：交付 a、b（取 b 的 cookie 为续枚举锚）。
        let page1 = fs.readdir_from(d, 0).expect("page1");
        assert_eq!(page1.len(), 3); // v0 内存面无分页——按 cookie 手工切片模拟
        let anchor = page1[1].cookie; // b
                                      // 中途变更：先插 x（在 b 之后）、删 a（在锚之前）。
        fs.create(d, "x", NodeKind::File).expect("touch x");
        fs.unlink(d, "a").expect("rm a");
        // 续枚举：恰为 b 之后的项（c、x），无 a 复现、无漏项。
        let rest = fs.readdir_from(d, anchor).expect("resume");
        let names: Vec<_> = rest.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["c", "x"]);
    }

    #[test]
    fn boundary_deletion_resumes_without_gap() {
        let fs = RamFs::new();
        let d = seeded_dir(&fs, "d", &["a", "b", "c"]);
        let page1 = fs.readdir_from(d, 0).expect("page1");
        let anchor = page1[0].cookie; // a（交付后即被删）
        fs.unlink(d, "a").expect("rm a");
        // 边界项被删：续枚举不重（a 不再出）不漏（b/c 照常）。
        let rest = fs.readdir_from(d, anchor).expect("resume");
        let names: Vec<_> = rest.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["b", "c"]);
    }

    #[test]
    fn cookie_survives_sibling_deletion_and_stays_monotonic() {
        let fs = RamFs::new();
        let d = seeded_dir(&fs, "d", &["a", "b", "c"]);
        let first = fs.readdir_from(d, 0).expect("first");
        let c_cookie = first[2].cookie;
        fs.unlink(d, "a").expect("rm a");
        let second = fs.readdir_from(d, 0).expect("second");
        let c2 = second.iter().find(|c| c.entry.name == "c").expect("c");
        assert_eq!(c2.cookie, c_cookie, "cookie stable across sibling deletion");
        // 已退役 cookie 不复用：新建项的 cookie 严格大于全部历史值。
        fs.create(d, "z", NodeKind::File).expect("touch z");
        let third = fs.readdir_from(d, 0).expect("third");
        let z = third.iter().find(|c| c.entry.name == "z").expect("z");
        assert!(z.cookie > c_cookie);
    }

    #[test]
    fn readdir_from_edges_and_name_order_unchanged() {
        let fs = RamFs::new();
        let d = seeded_dir(&fs, "d", &["b", "a"]);
        // after = u64::MAX → 空；after = 最后项 cookie → 空（枚举尽）。
        assert!(fs.readdir_from(d, u64::MAX).expect("max").is_empty());
        let all = fs.readdir_from(d, 0).expect("all");
        let last = all.last().expect("nonempty").cookie;
        assert!(fs.readdir_from(d, last).expect("exhausted").is_empty());
        // name 序面（readdir）语义不变：字典序。
        let entries = fs.readdir(d).expect("readdir");
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
        // 非目录 / 缺失同面拒绝（与 readdir 对齐）。
        let f = fs.create(RAMFS_ROOT, "f", NodeKind::File).expect("touch");
        assert_eq!(fs.readdir_from(f, 0), Err(FsError::NotADirectory));
        assert_eq!(fs.readdir_from(VnodeId(999), 0), Err(FsError::NotFound));
    }
}
