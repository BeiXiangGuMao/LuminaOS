//! search 域——哈希表、线性搜索、双链队列与二叉搜索树。
//!
//! 承接 POSIX `<search.h>` 15 符号（M35-H1b，71 → 86）：hcreate/
//! hdestroy/hsearch 全局族 + hcreate_r/hdestroy_r/hsearch_r 显式表族 +
//! lfind/lsearch 线性搜索 + insque/remque 双链队列 + tsearch/tfind/
//! tdelete/twalk/tdestroy 二叉搜索树族。
//!
//! # safe 面承载形式（M29/M35 纪律：指针语义 → 值/索引语义等价化）
//!
//! - **hsearch 族**：C 以进程单例静态表（全局族）/ 调用方持表（`_r` 族）
//!   承载；safe 静态可变堆数据在 `forbid(unsafe_code)` 下不可构造——
//!   两族统一以 **atomic 槽位阵列**承载（`GSlot`：`AtomicBool`/`AtomicU32`/
//!   `AtomicU64` 字块，键/值域宽 32 字节偏差登记）；差异在表的所有权与
//!   定容（全局族 = 进程单例定容 64 槽；`_r` 族 = 调用方持有、槽位数
//!   任意——键/值宽度同域）。超宽/满表/未初始化（C UB 或实现定义）→
//!   fail-visible；`Enter` 满表 → `errno = ENOMEM`（POSIX 照办）。
//! - **ENTRY/ACTION**：[`Entry`] 所有权键值对 + [`Action`] 枚举。
//! - **lfind/lsearch**：泛型切片 + `Fn(&T, &T) -> c_int`（0 = 相等，C
//!   语义照办）；`lsearch` 未命中**追加**（C 语义照办，`T: Clone` 界为
//!   所有权承载所需，偏差登记）。
//! - **insque/remque**：C 为自环双链表（`struct qelem` 指针域）；本面为
//!   索引双链（[`Qelem`] 槽位 + [`QNIL`] 哨兵显式终结——C 自环首尾由
//!   哨兵化登记；unlink 后槽位转墓碑保持索引稳定，偏差登记）。
//! - **tsearch 族**：C 以 `void **rootp` 持根 + 节点指针返回；本面为
//!   [`Tree`] 句柄 + **存储键克隆**值语义映射（偏差登记：`tdelete` 返
//!   被删键克隆——C 返被删节点之父指针）；`twalk` 访问序 = glibc 语义
//!   （内部节点 preorder → 左 → postorder → 右 → endorder，叶 = leaf）；
//!   `tdestroy` 消费树逐键回调 free 面（C 未指定释放序——本面槽位序登记）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::c_int;
use crate::errno::{self, ENOMEM};

// ───────────────────────── hsearch 族 ─────────────────────────

/// 哈希表键值对（POSIX `ENTRY` 的所有权面重铸）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 键（查重域）。
    pub key: Vec<u8>,
    /// 值（数据域）。
    pub data: Vec<u8>,
}

/// 查找/插入动作（POSIX `ACTION`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 只查不插（`FIND`）——未命中返 `None`。
    Find,
    /// 查而未中则插（`ENTER`）——命中则更新值域。
    Enter,
}

/// FNV-1a 64（weave 同源，探测哈希基元）。
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 槽位键/值域宽（字节；超出 → fail-visible，偏差登记——C 键域无界）。
const SLOT_WIDTH: usize = 32;

/// atomic 槽位（safe 静态可变面——无 unsafe；单线程消费纪律与 errno/rand
/// 单例同源）。
#[derive(Debug)]
struct GSlot {
    used: AtomicBool,
    klen: AtomicU32,
    dlen: AtomicU32,
    key: [AtomicU64; SLOT_WIDTH / 8],
    data: [AtomicU64; SLOT_WIDTH / 8],
}

impl GSlot {
    const fn new() -> Self {
        Self {
            used: AtomicBool::new(false),
            klen: AtomicU32::new(0),
            dlen: AtomicU32::new(0),
            key: [const { AtomicU64::new(0) }; SLOT_WIDTH / 8],
            data: [const { AtomicU64::new(0) }; SLOT_WIDTH / 8],
        }
    }

    /// 写入键/值（超宽 → `false`）。
    fn store(&self, key: &[u8], data: &[u8]) -> bool {
        if key.len() > SLOT_WIDTH || data.len() > SLOT_WIDTH {
            return false;
        }
        Self::put(&self.key, key);
        self.klen.store(key.len() as u32, Ordering::Relaxed);
        Self::put(&self.data, data);
        self.dlen.store(data.len() as u32, Ordering::Relaxed);
        true
    }

    /// 字节片 → atomic 字块（零填充）。
    fn put(cells: &[AtomicU64; SLOT_WIDTH / 8], bytes: &[u8]) {
        for (i, cell) in cells.iter().enumerate() {
            let mut word = [0u8; 8];
            let lo = i * 8;
            let hi = (lo + 8).min(bytes.len());
            if lo < bytes.len() {
                word[..hi - lo].copy_from_slice(&bytes[lo..hi]);
            }
            cell.store(u64::from_le_bytes(word), Ordering::Relaxed);
        }
    }

    /// 读出键/值。
    fn load(&self) -> (Vec<u8>, Vec<u8>) {
        let klen = self.klen.load(Ordering::Relaxed) as usize;
        let dlen = self.dlen.load(Ordering::Relaxed) as usize;
        (Self::get(&self.key, klen), Self::get(&self.data, dlen))
    }

    /// atomic 字块 → 字节片。
    fn get(cells: &[AtomicU64; SLOT_WIDTH / 8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for cell in cells {
            for b in cell.load(Ordering::Relaxed).to_le_bytes() {
                if out.len() < len {
                    out.push(b);
                }
            }
        }
        out
    }

    /// 清槽。
    fn clear(&self) {
        self.used.store(false, Ordering::Relaxed);
        self.klen.store(0, Ordering::Relaxed);
        self.dlen.store(0, Ordering::Relaxed);
    }
}

/// 全局表容量（C `hcreate(nel)` 的定容承载——`nel` 为 POSIX 下界承诺，
/// 超出 → 0 fail-visible，偏差登记）。
const GLOBAL_SLOTS: usize = 64;

static GLOBAL_READY: AtomicBool = AtomicBool::new(false);
static GLOBAL: [GSlot; GLOBAL_SLOTS] = [const { GSlot::new() }; GLOBAL_SLOTS];

/// 创建全局哈希表（`hcreate`）。
///
/// 返回 1 = 成功 / 0 = 失败（已存在或 `nel` 超出定容承载——C 对重复调用
/// 的行为为 UB，本面 fail-visible 化）。
pub fn hcreate(nel: usize) -> c_int {
    if GLOBAL_READY.swap(true, Ordering::AcqRel) {
        return 0; // 表已存在（C UB → fail-visible）
    }
    if nel == 0 || nel > GLOBAL_SLOTS {
        GLOBAL_READY.store(false, Ordering::Release);
        return 0;
    }
    for slot in &GLOBAL {
        slot.clear();
    }
    1
}

/// 销毁全局哈希表（`hdestroy`）——未创建时为安全 no-op（C UB → 登记化）。
pub fn hdestroy() {
    if GLOBAL_READY.swap(false, Ordering::AcqRel) {
        for slot in &GLOBAL {
            slot.clear();
        }
    }
}

/// 全局表查找/插入（`hsearch`）——须先 [`hcreate`]（未创建 → `None`，
/// C UB → fail-visible）。
///
/// `Enter` 表满 → `None` 且 `errno = ENOMEM`（POSIX 照办）；键/值超宽 →
/// `None` 且 `errno = EINVAL`（偏差登记）。
pub fn hsearch(item: Entry, action: Action) -> Option<Entry> {
    if !GLOBAL_READY.load(Ordering::Acquire) {
        return None;
    }
    probe(&GLOBAL, &item.key, &item.data, action)
}

/// 显式哈希表（POSIX `struct hsearch_data` 的调用方持表面）。
///
/// 由 [`hcreate_r`] 初始化（槽位数 = `nel`）；`Default` 为未初始化态
/// （`hsearch_r` 于其上返 `None`，C UB → fail-visible）。
#[derive(Debug, Default)]
pub struct HsearchData {
    /// atomic 槽位阵列（`GSlot` 私有承载）。
    slots: Vec<GSlot>,
}

/// 创建显式哈希表（`hcreate_r`）——`tab` 须为未初始化态；重复初始化或
/// `nel = 0` → 0（C UB → fail-visible）；容量上界 1<<20（分配面安全带）。
pub fn hcreate_r(nel: usize, tab: &mut HsearchData) -> c_int {
    if !tab.slots.is_empty() || nel == 0 || nel > (1 << 20) {
        return 0;
    }
    tab.slots = (0..nel).map(|_| GSlot::new()).collect();
    1
}

/// 销毁显式哈希表（`hdestroy_r`）——释放全部槽位（复用须重 [`hcreate_r`]）。
pub fn hdestroy_r(tab: &mut HsearchData) {
    tab.slots = Vec::new();
}

/// 显式表查找/插入（`hsearch_r`）——语义同 [`hsearch`]，表为调用方持有
/// （C `ENTRY **retval` 出参 → `Option<Entry>` 返回值映射）。
pub fn hsearch_r(tab: &mut HsearchData, item: Entry, action: Action) -> Option<Entry> {
    if tab.slots.is_empty() {
        return None;
    }
    probe(&tab.slots, &item.key, &item.data, action)
}

/// 线性探测内核（全局/显式两族共用——开址定容、无删除 → 探测至首个空槽
/// 即簇尾，查找/插入不变式成立）。
fn probe(slots: &[GSlot], key: &[u8], data: &[u8], action: Action) -> Option<Entry> {
    let n = slots.len();
    let mut at = (fnv1a(key) as usize) % n;
    for _ in 0..n {
        let slot = &slots[at];
        if !slot.used.load(Ordering::Acquire) {
            return match action {
                Action::Find => None,
                Action::Enter => {
                    if slot.store(key, data) {
                        slot.used.store(true, Ordering::Release);
                        Some(Entry {
                            key: key.to_vec(),
                            data: data.to_vec(),
                        })
                    } else {
                        errno::set_errno(errno::EINVAL); // 超宽（偏差登记）
                        None
                    }
                }
            };
        }
        let (k, d) = slot.load();
        if k == key {
            return match action {
                Action::Find => Some(Entry { key: k, data: d }),
                Action::Enter => {
                    if slot.store(key, data) {
                        Some(Entry {
                            key: k,
                            data: data.to_vec(),
                        })
                    } else {
                        errno::set_errno(errno::EINVAL);
                        None
                    }
                }
            };
        }
        at = (at + 1) % n;
    }
    // 表满（Enter：POSIX ENOMEM 照办；Find：未命中）
    if action == Action::Enter {
        errno::set_errno(ENOMEM);
    }
    None
}

// ───────────────────────── lfind / lsearch ─────────────────────────

/// 线性查找（`lfind`）：`compar` 返 0 = 相等（C 语义照办）；命中返回
/// 元素下标，未命中 → `None`。
pub fn lfind<T>(key: &T, base: &[T], compar: impl Fn(&T, &T) -> c_int) -> Option<usize> {
    base.iter().position(|elem| compar(key, elem) == 0)
}

/// 线性查找/追加（`lsearch`）：命中返回下标；未命中**追加 `key`**（C
/// 语义照办——`T: Clone` 界为本面所有权承载所需，偏差登记）并返回新下标。
pub fn lsearch<T: Clone>(base: &mut Vec<T>, key: &T, compar: impl Fn(&T, &T) -> c_int) -> usize {
    if let Some(at) = lfind(key, base, &compar) {
        return at;
    }
    base.push(key.clone());
    base.len() - 1
}

// ───────────────────────── insque / remque ─────────────────────────

/// 无邻接哨兵（C `NULL` 指针的索引面映射）。
pub const QNIL: usize = usize::MAX;

/// 双链队列槽位（POSIX `struct qelem` 的索引面重铸：指针域 → 下标域）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qelem<T> {
    /// 数据载荷（C `q_data`）。
    pub data: T,
    /// 前驱下标（[`QNIL`] = 无）。
    pub back: usize,
    /// 后继下标（[`QNIL`] = 无）。
    pub forw: usize,
}

/// 双链插入（`insque`）：将新元素插到 `at` 之后（`at = QNIL` = 初始化
/// 单元素队列，C `pred = NULL` 语义照办）；返回新元素下标。
///
/// 无效 pred（越界/墓碑）→ 不插入返 [`QNIL`]（C UB → fail-visible）。
/// 槽位向量由调用方持有并随行扩容；unlink 后为墓碑槽（索引稳定）。
pub fn insque<T>(queue: &mut Vec<Option<Qelem<T>>>, at: usize, data: T) -> usize {
    if at != QNIL && queue.get(at).is_none_or(Option::is_none) {
        return QNIL; // 无效 pred（C UB → fail-visible）
    }
    let idx = queue.len();
    let forw = if at == QNIL {
        QNIL
    } else {
        queue[at].as_ref().map_or(QNIL, |node| node.forw)
    };
    queue.push(Some(Qelem {
        data,
        back: at,
        forw,
    }));
    if at != QNIL {
        if let Some(pred) = queue[at].as_mut() {
            pred.forw = idx;
        }
        if forw != QNIL {
            if let Some(next) = queue[forw].as_mut() {
                next.back = idx;
            }
        }
    }
    idx
}

/// 双链摘除（`remque`）：摘除 `at` 并返回数据载荷；邻接链随行重接；
/// 槽位转墓碑（索引稳定偏差登记）。无效槽位 → `None`（C UB → fail-visible）。
pub fn remque<T>(queue: &mut [Option<Qelem<T>>], at: usize) -> Option<T> {
    let node = queue.get_mut(at)?.take()?;
    if node.back != QNIL {
        if let Some(prev) = queue[node.back].as_mut() {
            prev.forw = node.forw;
        }
    }
    if node.forw != QNIL {
        if let Some(next) = queue[node.forw].as_mut() {
            next.back = node.back;
        }
    }
    Some(node.data)
}

// ───────────────────────── tsearch 族 ─────────────────────────

/// BST 空位哨兵（内部索引域）。
const TNIL: u32 = u32::MAX;

/// BST 节点（内部承载——索引不出面）。
struct TNode<T> {
    key: T,
    left: u32,
    right: u32,
}

/// 二叉搜索树句柄（POSIX `void **rootp` 的所有权面重铸）。
///
/// C 以「NULL 初始化的根指针」隐式建树；本面为显式句柄（[`Tree::new`]/
/// `Default`）——符号清单以 tsearch/tfind/tdelete/twalk/tdestroy 五函数
/// 为口径，构造子为句柄模式基础设施。节点槽位 `Option` 承载删除墓碑
/// （索引稳定；墓碑槽不可达——链接已摘除，`tdestroy` 不及）。
pub struct Tree<T> {
    nodes: Vec<Option<TNode<T>>>,
    root: u32,
}

impl<T> core::fmt::Debug for Tree<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tree")
            .field("live", &self.nodes.iter().filter(|s| s.is_some()).count())
            .field("root", &self.root)
            .finish()
    }
}

impl<T> Tree<T> {
    /// 空树（C：`root = NULL` 初始化语义）。
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            root: TNIL,
        }
    }
}

impl<T> Default for Tree<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// twalk 访问类（POSIX `VISIT`——glibc 语义：内部节点 preorder → 左 →
/// postorder → 右 → endorder；叶 = leaf）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    /// 节点首访（下探左子前）。
    Preorder,
    /// 左子访问毕（下探右子前）。
    Postorder,
    /// 双子访问毕（节点收尾）。
    Endorder,
    /// 叶节点。
    Leaf,
}

/// 查找/插入（`tsearch`）：命中返回**存储键克隆**（C 节点指针的值语义
/// 映射）；未命中插入并返回之（C 分配失败返 NULL——本面分配失败为宿主
/// abort 语义，恒成功，登记）。
pub fn tsearch<T: Clone>(tree: &mut Tree<T>, key: &T, compar: impl Fn(&T, &T) -> c_int) -> T {
    if tree.root == TNIL {
        tree.nodes.push(Some(TNode {
            key: key.clone(),
            left: TNIL,
            right: TNIL,
        }));
        tree.root = 0;
        return key.clone();
    }
    let mut at = tree.root;
    loop {
        let Some(node) = tree.nodes[at as usize].as_ref() else {
            // 墓碑槽不可达（不变式）——防御性停机
            return tree.nodes[tree.root as usize]
                .as_ref()
                .map_or_else(|| key.clone(), |n| n.key.clone());
        };
        let c = compar(key, &node.key);
        if c == 0 {
            return node.key.clone(); // 命中：不扩树（C 节点指针 → 存储键克隆）
        }
        let dir = if c < 0 { node.left } else { node.right };
        if dir != TNIL {
            at = dir;
            continue;
        }
        let idx = tree.nodes.len() as u32;
        tree.nodes.push(Some(TNode {
            key: key.clone(),
            left: TNIL,
            right: TNIL,
        }));
        if let Some(parent) = tree.nodes[at as usize].as_mut() {
            if c < 0 {
                parent.left = idx;
            } else {
                parent.right = idx;
            }
        }
        return key.clone();
    }
}

/// 查找（`tfind`）：只查不插；命中返回存储键克隆，未命中 → `None`。
pub fn tfind<T: Clone>(tree: &Tree<T>, key: &T, compar: impl Fn(&T, &T) -> c_int) -> Option<T> {
    let mut at = tree.root;
    while at != TNIL {
        let node = tree.nodes[at as usize].as_ref()?;
        let c = compar(key, &node.key);
        if c == 0 {
            return Some(node.key.clone());
        }
        at = if c < 0 { node.left } else { node.right };
    }
    None
}

/// 删除（`tdelete`）：删除命中节点并返回**被删键克隆**（C 返被删节点之
/// 父指针——本面值语义映射取更可考的被删键，偏差登记）；未命中 → `None`。
///
/// 删除策略 = 标准 BST（双子取右子树最小键顶位——与 glibc 同型，无平衡
/// 化，C 标准不指定平衡语义）；墓碑槽不可达。
pub fn tdelete<T: Clone>(
    tree: &mut Tree<T>,
    key: &T,
    compar: impl Fn(&T, &T) -> c_int,
) -> Option<T> {
    let mut removed = None;
    tree.root = tdelete_at(tree, tree.root, key, &compar, &mut removed);
    removed
}

/// 递归删除内核：返回重组后的子树根。
fn tdelete_at<T: Clone>(
    tree: &mut Tree<T>,
    at: u32,
    key: &T,
    compar: &impl Fn(&T, &T) -> c_int,
    removed: &mut Option<T>,
) -> u32 {
    if tree
        .nodes
        .get(at as usize)
        .and_then(Option::as_ref)
        .is_none()
    {
        return TNIL;
    }
    let c = {
        let Some(node) = tree.nodes[at as usize].as_ref() else {
            return TNIL;
        };
        compar(key, &node.key)
    };
    if c < 0 {
        let left = tree.nodes[at as usize].as_ref().map_or(TNIL, |n| n.left);
        let new_left = tdelete_at(tree, left, key, compar, removed);
        if let Some(node) = tree.nodes[at as usize].as_mut() {
            node.left = new_left;
        }
        return at;
    }
    if c > 0 {
        let right = tree.nodes[at as usize].as_ref().map_or(TNIL, |n| n.right);
        let new_right = tdelete_at(tree, right, key, compar, removed);
        if let Some(node) = tree.nodes[at as usize].as_mut() {
            node.right = new_right;
        }
        return at;
    }
    // 命中：摘除
    let (left, right) = {
        let Some(node) = tree.nodes[at as usize].as_ref() else {
            return TNIL;
        };
        (node.left, node.right)
    };
    if left == TNIL && right == TNIL {
        if let Some(slot) = tree.nodes[at as usize].as_mut() {
            *removed = Some(slot.key.clone());
        }
        tree.nodes[at as usize] = None; // 墓碑
        return TNIL;
    }
    if left == TNIL || right == TNIL {
        if let Some(slot) = tree.nodes[at as usize].as_mut() {
            *removed = Some(slot.key.clone());
        }
        tree.nodes[at as usize] = None; // 墓碑（子树整链上提）
        return if right != TNIL { right } else { left };
    }
    // 双子：右子树最小键顶位，再从右子树删该键
    let succ = tmin(tree, right);
    let succ_key = match tree.nodes[succ as usize].as_ref() {
        Some(n) => n.key.clone(),
        None => return at,
    };
    if let Some(slot) = tree.nodes[at as usize].as_mut() {
        // 被删键（原位键）交 removed；后继键顶位
        *removed = Some(core::mem::replace(&mut slot.key, succ_key.clone()));
    }
    let mut taken = None;
    let new_right = tdelete_at(tree, right, &succ_key, compar, &mut taken);
    if let Some(slot) = tree.nodes[at as usize].as_mut() {
        slot.right = new_right;
    }
    at
}

/// 右子树最小节点（无左子者）。
fn tmin<T>(tree: &Tree<T>, mut at: u32) -> u32 {
    while let Some(node) = tree.nodes[at as usize].as_ref() {
        if node.left == TNIL {
            break;
        }
        at = node.left;
    }
    at
}

/// 中序遍历（`twalk`）：glibc 访问序照办（见 [`Visit`]）；`level` 自 0 起
/// （根 = 0，POSIX 惯例）。
pub fn twalk<T>(tree: &Tree<T>, action: impl FnMut(&T, Visit, usize)) {
    let mut act = action;
    twalk_at(tree, tree.root, 0, &mut act);
}

/// 递归遍历内核。
fn twalk_at<T>(tree: &Tree<T>, at: u32, level: usize, act: &mut impl FnMut(&T, Visit, usize)) {
    if at == TNIL {
        return;
    }
    let Some(node) = tree.nodes[at as usize].as_ref() else {
        return;
    };
    let (key, left, right) = (&node.key, node.left, node.right);
    if left == TNIL && right == TNIL {
        act(key, Visit::Leaf, level);
        return;
    }
    act(key, Visit::Preorder, level);
    twalk_at(tree, left, level + 1, act);
    act(key, Visit::Postorder, level);
    twalk_at(tree, right, level + 1, act);
    act(key, Visit::Endorder, level);
}

/// 销毁（`tdestroy`）：消费树并逐键回调 free 面（C `free_node` 语义照办；
/// C 未指定释放序——本面为**槽位序**，登记；墓碑槽不及）。
pub fn tdestroy<T>(tree: Tree<T>, freef: impl FnMut(T)) {
    let mut freef = freef;
    tree.nodes
        .into_iter()
        .flatten()
        .for_each(|node| freef(node.key));
}

#[cfg(test)]
impl<T> Tree<T> {
    /// 活体节点计数（测试对账用——墓碑不计）。
    fn nodes_count_for_test(&self) -> usize {
        self.nodes.iter().filter(|s| s.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    /// c_int 比较基元（字节序）。
    fn cmp_bytes(a: &[u8], b: &[u8]) -> c_int {
        match a.cmp(b) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    /// 显式表族生命周期：建表/进入/查找/替换/满表 ENOMEM/销毁重建。
    #[test]
    fn hsearch_r_lifecycle() {
        let mut tab = HsearchData::default();
        assert_eq!(
            hsearch_r(
                &mut tab,
                Entry {
                    key: b"k".to_vec(),
                    data: b"v".to_vec()
                },
                Action::Enter
            ),
            None,
            "uninitialized table"
        );
        assert_eq!(hcreate_r(0, &mut tab), 0, "nel=0 rejected");
        assert_eq!(hcreate_r(8, &mut tab), 1);
        assert_eq!(hcreate_r(8, &mut tab), 0, "re-init on non-empty rejected");
        // 进入 ×3
        for i in 0..3u8 {
            let e = hsearch_r(
                &mut tab,
                Entry {
                    key: format!("key{i}").into_bytes(),
                    data: format!("val{i}").into_bytes(),
                },
                Action::Enter,
            );
            assert!(e.is_some(), "enter {i}");
        }
        // 命中查找
        let found = hsearch_r(
            &mut tab,
            Entry {
                key: b"key1".to_vec(),
                data: Vec::new(),
            },
            Action::Find,
        );
        let Some(found) = found else {
            panic!("find key1")
        };
        assert_eq!(found.data, b"val1");
        // 未命中查找
        assert_eq!(
            hsearch_r(
                &mut tab,
                Entry {
                    key: b"miss".to_vec(),
                    data: Vec::new()
                },
                Action::Find
            ),
            None
        );
        // Enter 命中 = 值替换
        let updated = hsearch_r(
            &mut tab,
            Entry {
                key: b"key1".to_vec(),
                data: b"new".to_vec(),
            },
            Action::Enter,
        );
        let Some(updated) = updated else {
            panic!("update key1")
        };
        assert_eq!(updated.data, b"new");
        // 满表（3 键 + 5 填充 = 8 槽全占）→ over 进不去
        for i in 0..5u8 {
            let e = hsearch_r(
                &mut tab,
                Entry {
                    key: format!("fill{i}").into_bytes(),
                    data: Vec::new(),
                },
                Action::Enter,
            );
            assert!(e.is_some(), "fill {i}");
        }
        errno::set_errno(0);
        assert_eq!(
            hsearch_r(
                &mut tab,
                Entry {
                    key: b"over".to_vec(),
                    data: Vec::new()
                },
                Action::Enter
            ),
            None,
            "table full"
        );
        assert_eq!(errno::errno(), ENOMEM, "POSIX ENOMEM on overflow");
        // 销毁 → 再建 → 可用
        hdestroy_r(&mut tab);
        assert_eq!(hcreate_r(2, &mut tab), 1);
        let e = hsearch_r(
            &mut tab,
            Entry {
                key: b"again".to_vec(),
                data: b"x".to_vec(),
            },
            Action::Enter,
        );
        assert!(e.is_some(), "reuse after destroy");
    }

    /// 全局族：建表/进入/查/改/销毁/复建（全局态共享——单测试函数承载
    /// 全部全局面用例，规避并行测试串扰）。
    #[test]
    fn hsearch_global_lifecycle() {
        hdestroy(); // 预清场（幂等）
        assert_eq!(
            hsearch(
                Entry {
                    key: b"g".to_vec(),
                    data: Vec::new()
                },
                Action::Find
            ),
            None,
            "search before create"
        );
        assert_eq!(hcreate(0), 0, "nel=0 rejected");
        assert_eq!(hcreate(GLOBAL_SLOTS + 1), 0, "over-capacity rejected");
        assert_eq!(hcreate(8), 1);
        assert_eq!(hcreate(8), 0, "double create fail-visible");
        // 键值域宽边界：≤32 通过 / >32 fail-visible
        let e = hsearch(
            Entry {
                key: b"g".to_vec(),
                data: vec![b'a'; 32],
            },
            Action::Enter,
        );
        let Some(e) = e else {
            panic!("enter within width")
        };
        assert_eq!(e.data.len(), 32);
        assert_eq!(
            hsearch(
                Entry {
                    key: vec![b'b'; 33],
                    data: Vec::new()
                },
                Action::Enter
            ),
            None,
            "key over width"
        );
        // 查找命中（数据域 32 字节往返）
        let found = hsearch(
            Entry {
                key: b"g".to_vec(),
                data: Vec::new(),
            },
            Action::Find,
        );
        let Some(found) = found else { panic!("find g") };
        assert_eq!(found.data, vec![b'a'; 32]);
        // 冲突簇：多键同簇线性探测
        for i in 0..10u8 {
            let e = hsearch(
                Entry {
                    key: vec![b'c', i],
                    data: vec![i],
                },
                Action::Enter,
            );
            assert!(e.is_some(), "enter cluster {i}");
        }
        for i in 0..10u8 {
            let found = hsearch(
                Entry {
                    key: vec![b'c', i],
                    data: Vec::new(),
                },
                Action::Find,
            );
            let Some(f) = found else {
                panic!("find cluster {i}")
            };
            assert_eq!(f.data, vec![i]);
        }
        // Enter 更新
        let up = hsearch(
            Entry {
                key: vec![b'c', 3],
                data: b"upd".to_vec(),
            },
            Action::Enter,
        );
        let Some(up) = up else { panic!("update") };
        assert_eq!(up.data, b"upd");
        // 销毁 → 全清 → 复建
        hdestroy();
        assert_eq!(
            hsearch(
                Entry {
                    key: b"g".to_vec(),
                    data: Vec::new()
                },
                Action::Find
            ),
            None,
            "after destroy"
        );
        assert_eq!(hcreate(4), 1);
        assert_eq!(
            hsearch(
                Entry {
                    key: b"g".to_vec(),
                    data: Vec::new()
                },
                Action::Find
            ),
            None,
            "slots cleared"
        );
        hdestroy();
    }

    /// lfind/lsearch：命中/未命中/追加语义。
    #[test]
    fn lfind_lsearch_append_semantics() {
        let base = [3_i32, 1, 4, 1, 5];
        assert_eq!(lfind(&4, &base, |a, b| a.cmp(b) as i32), Some(2));
        assert_eq!(lfind(&9, &base, |a, b| a.cmp(b) as i32), None);
        let mut v: Vec<i32> = vec![7, 8];
        assert_eq!(
            lsearch(&mut v, &8, |a, b| a.cmp(b) as i32),
            1,
            "hit no append"
        );
        assert_eq!(v.len(), 2);
        assert_eq!(
            lsearch(&mut v, &9, |a, b| a.cmp(b) as i32),
            2,
            "miss appends"
        );
        assert_eq!(v, vec![7, 8, 9]);
    }

    /// insque/remque：头插/尾插/中插/摘除（首/中/尾）+ 无效面。
    #[test]
    fn insque_remque_index_chain() {
        let mut q: Vec<Option<Qelem<i32>>> = Vec::new();
        // QNIL 初始化单元素
        let a = insque(&mut q, QNIL, 10);
        assert_eq!(a, 0);
        // 尾插（at = a）
        let b = insque(&mut q, a, 20);
        assert_eq!(b, 1);
        // 中插（a 与 b 之间）
        let c = insque(&mut q, a, 15);
        assert_eq!(c, 2);
        // 链序校验：a → c → b
        let (Some(na), Some(nc), Some(nb)) = (q[a].as_ref(), q[c].as_ref(), q[b].as_ref()) else {
            panic!("nodes live")
        };
        assert_eq!(na.forw, c);
        assert_eq!(nc.back, a);
        assert_eq!(nc.forw, b);
        assert_eq!(nb.back, c);
        // 无效 pred → QNIL 不插入
        assert_eq!(insque(&mut q, 9, 99), QNIL);
        assert_eq!(q.len(), 3, "no insert on invalid pred");
        // 摘中段（c）
        assert_eq!(remque(&mut q, c), Some(15));
        let (Some(na), Some(nb)) = (q[a].as_ref(), q[b].as_ref()) else {
            panic!("a/b live")
        };
        assert_eq!(na.forw, b, "relinked a→b");
        assert_eq!(nb.back, a, "relinked b←a");
        // 摘首（a）
        assert_eq!(remque(&mut q, a), Some(10));
        let Some(nb) = q[b].as_ref() else {
            panic!("b live")
        };
        assert_eq!(nb.back, QNIL);
        // 摘尾（b）
        assert_eq!(remque(&mut q, b), Some(20));
        // 摘墓碑/越界 → None
        assert_eq!(remque(&mut q, b), None, "tombstone");
        assert_eq!(remque(&mut q, 7), None, "out of range");
    }

    /// tsearch 族：插/查/删（叶/单子/双子）+ twalk 有序 + tdestroy 回调。
    #[test]
    fn tsearch_family_full() {
        let mut tree = Tree::new();
        let cmp_i = |a: &i32, b: &i32| a.cmp(b) as c_int;
        // 插入 5/3/7/1/4/6/8（标准 BST 形态）
        for k in [5, 3, 7, 1, 4, 6, 8] {
            assert_eq!(tsearch(&mut tree, &k, cmp_i), k);
        }
        // 重复插入 = 命中不扩
        assert_eq!(tsearch(&mut tree, &5, cmp_i), 5);
        assert_eq!(tree.nodes_count_for_test(), 7);
        // 查找
        assert_eq!(tfind(&tree, &4, cmp_i), Some(4));
        assert_eq!(tfind(&tree, &9, cmp_i), None);
        // 删叶（1）
        assert_eq!(tdelete(&mut tree, &1, cmp_i), Some(1));
        assert_eq!(tfind(&tree, &1, cmp_i), None);
        assert_eq!(tfind(&tree, &3, cmp_i), Some(3));
        // 删单子（3：只剩右子 4）
        assert_eq!(tdelete(&mut tree, &3, cmp_i), Some(3));
        assert_eq!(tfind(&tree, &4, cmp_i), Some(4), "child spliced up");
        // 删双子（5：右子树最小 4 顶位）
        assert_eq!(tdelete(&mut tree, &5, cmp_i), Some(5));
        assert_eq!(tfind(&tree, &4, cmp_i), Some(4));
        // 未命中删除 → None
        assert_eq!(tdelete(&mut tree, &42, cmp_i), None);
        // twalk 中序序列 = 有序集（leaf ∪ postorder 位 = 全体活键中序位）
        let mut inorder: Vec<i32> = Vec::new();
        twalk(&tree, |key, visit, _lvl| {
            if matches!(visit, Visit::Leaf | Visit::Postorder) {
                inorder.push(*key);
            }
        });
        let mut sorted = inorder.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, inorder, "inorder via leaf+postorder positions");
        assert!(sorted.windows(2).all(|w| w[0] < w[1]), "ascending");
        // tdestroy：活键全数回调（槽位序——C 未指定序，登记）
        let mut freed: Vec<i32> = Vec::new();
        tdestroy(tree, |k| freed.push(k));
        assert_eq!(freed.len(), 4);
        freed.sort_unstable();
        assert_eq!(freed, vec![4, 6, 7, 8]);
    }

    /// twalk 访问类全序（glibc 语义锚：preorder→左→postorder→右→endorder）。
    #[test]
    fn twalk_visit_sequence() {
        let mut tree = Tree::new();
        let cmp_i = |a: &i32, b: &i32| a.cmp(b) as c_int;
        for k in [2, 1, 3] {
            let _ = tsearch(&mut tree, &k, cmp_i);
        }
        // 形态：根 2，左 1（叶），右 3（叶）
        let mut seq: Vec<(i32, Visit, usize)> = Vec::new();
        twalk(&tree, |key, visit, lvl| seq.push((*key, visit, lvl)));
        assert_eq!(
            seq,
            vec![
                (2, Visit::Preorder, 0),
                (1, Visit::Leaf, 1),
                (2, Visit::Postorder, 0),
                (3, Visit::Leaf, 1),
                (2, Visit::Endorder, 0),
            ]
        );
        // 空树遍历 = 零回调
        let empty = Tree::<i32>::new();
        let mut n = 0;
        twalk(&empty, |_, _, _| n += 1);
        assert_eq!(n, 0);
    }

    /// 字节键显式表字符串键值对账（第二消费者形态）。
    #[test]
    fn hsearch_r_string_pairs() {
        let mut tab = HsearchData::default();
        assert_eq!(hcreate_r(16, &mut tab), 1);
        let pairs = [("alpha", "1"), ("beta", "2"), ("gamma", "3")];
        for (k, v) in pairs {
            let e = hsearch_r(
                &mut tab,
                Entry {
                    key: k.as_bytes().to_vec(),
                    data: v.as_bytes().to_vec(),
                },
                Action::Enter,
            );
            assert!(e.is_some(), "enter {k}");
        }
        for (k, v) in pairs {
            let found = hsearch_r(
                &mut tab,
                Entry {
                    key: k.as_bytes().to_vec(),
                    data: Vec::new(),
                },
                Action::Find,
            );
            let Some(f) = found else { panic!("find {k}") };
            assert_eq!(f.data, v.as_bytes());
        }
        assert_eq!(cmp_bytes(b"a", b"a"), 0);
    }
}
