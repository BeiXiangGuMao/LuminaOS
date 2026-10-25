//! Elm 架构核心 —— Model/Msg/update/view 消息折叠环 + 定容零堆平面元素树。
//!
//! Elm 架构（The Elm Architecture）三件套在本 crate 的承接形态：
//!
//! - **Model**：应用状态，由 [`App::init`] 产出、[`App::update`] 就地演进；
//! - **Msg**：消息，驱动状态迁移的唯一入口（单向数据流：Msg → update →
//!   Model → view）；
//! - **view**：把 Model 投影为平面元素树（[`ViewBuf`]），供布局求解
//!   （[`crate::layout::solve`]）消费。
//!
//! [`fold`] 是折叠环本体：`init → update* → view`，一次遍历产出终态与
//! view 根节点。消息序列确定性折叠——同序列必得同 Model 同 view 树
//! （可重放调试面，宿主测试锚定）。
//!
//! ## 平面元素树（零堆纪律）
//!
//! [`ViewBuf<const N>`] 以定容数组承载节点与 `first_child`/`next_sibling`
//! 索引链，`const new()` 供内核 static；无 alloc、无指针、`forbid(unsafe_code)`。
//! 建树纪律：**自顶向下**——父节点先于子节点 `push`（`attach` 以
//! `child > parent` 索引序闸承载，结构上排除环）。

/// 空链接哨兵（索引链终点/未挂接标记）。
pub const NIL: u16 = u16::MAX;

/// 元素种类（v0 骨架集）。
///
/// `Node` 是容器（子元素沿 [`Dir`] 主轴排布）；`Text`/`Icon` 是叶子——
/// 布局只决定其槽位矩形，内容渲染由文本/图标子系统（M30 后续批次）承接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 容器节点（可携带子元素）。
    Node,
    /// 文本叶子。
    Text,
    /// 图标叶子（glyph 渲染面消费槽位）。
    Icon,
}

/// 容器主轴方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// 水平排布（子元素沿 x 轴）。
    Row,
    /// 垂直排布（子元素沿 y 轴）。
    Column,
}

/// 主轴尺寸诉求。
///
/// `Fixed(px)` 是确定值；`Fill(weight)` 按权重瓜分内容盒剩余主轴空间
/// （权重 ≥1，余数全归首个 Fill 子——确定性分配，见 README 纪律）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Main {
    /// 固定尺寸（逻辑像素）。
    Fixed(u32),
    /// 按权重填充剩余空间。
    Fill(u32),
}

/// 节点样式与内容描述（布局输入面）。
///
/// `pad` 为 `[上, 右, 下, 左]`；`pad` 与 `gap` 均受 8px 网格闸
/// （ART-003 间距刻度纪律，违者 [`crate::layout::LayoutError::OffGrid`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    /// 元素种类。
    pub kind: Kind,
    /// 主轴方向（容器语义；叶子忽略）。
    pub dir: Dir,
    /// 内边距 `[上, 右, 下, 左]`（8px 网格）。
    pub pad: [u32; 4],
    /// 子元素间距（8px 网格）。
    pub gap: u32,
    /// 主轴尺寸诉求。
    pub main: Main,
}

impl Node {
    /// 中性空节点（容器/纵排/零边距/Fill(1)）——`ViewBuf` 定容初始化用。
    pub const EMPTY: Node = Node {
        kind: Kind::Node,
        dir: Dir::Column,
        pad: [0; 4],
        gap: 0,
        main: Main::Fill(1),
    };
}

/// 节点句柄（`ViewBuf` 内索引）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id(pub u16);

/// 建树错误集（fail-visible，无静默吞并）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewError {
    /// 容量满（`N` 槽用尽）。
    Full {
        /// 容量上限。
        cap: usize,
    },
    /// 句柄越界或指向未入树槽位。
    BadId,
    /// 自挂接（parent == child）。
    SelfAttach,
    /// 重复挂接（该子已有父）。
    Reparent,
    /// 建树次序违规（父必须先于子入树——自顶向下纪律，结构性防环）。
    BuildOrder,
    /// 根重复声明。
    DoubleRoot,
}

/// 定容零堆平面元素树（const new，内核 static 可用）。
///
/// 节点样式存 [`Node`] 数组；拓扑存三条索引链（parent/first_child/
/// next_sibling，[`NIL`] 为空）。全部运算 safe，容量闸 fail-visible。
#[derive(Debug)]
pub struct ViewBuf<const N: usize> {
    nodes: [Node; N],
    parent: [u16; N],
    first: [u16; N],
    next: [u16; N],
    len: usize,
    root: u16,
}

impl<const N: usize> ViewBuf<N> {
    /// 空树（const）。
    pub const fn new() -> Self {
        ViewBuf {
            nodes: [Node::EMPTY; N],
            parent: [NIL; N],
            first: [NIL; N],
            next: [NIL; N],
            len: 0,
            root: NIL,
        }
    }

    /// 清空（复用同一缓冲建下一帧 view——帧边界 reset 纪律）。
    pub fn reset(&mut self) {
        self.nodes = [Node::EMPTY; N];
        self.parent = [NIL; N];
        self.first = [NIL; N];
        self.next = [NIL; N];
        self.len = 0;
        self.root = NIL;
    }

    /// 已入树节点数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 树是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 入树一个节点（不入拓扑，待 [`Self::attach`]）。
    pub fn push(&mut self, node: Node) -> Result<Id, ViewError> {
        if self.len >= N {
            return Err(ViewError::Full { cap: N });
        }
        let idx = self.len as u16;
        self.nodes[idx as usize] = node;
        self.len += 1;
        Ok(Id(idx))
    }

    /// 把 `child` 挂到 `parent` 子链尾。
    ///
    /// 闸序：越界 → 自挂接 → 重复挂接 → 建树次序（child 索引必须大于
    /// parent——父先入树，结构性排除环）。
    pub fn attach(&mut self, parent: Id, child: Id) -> Result<(), ViewError> {
        if parent.0 as usize >= self.len || child.0 as usize >= self.len {
            return Err(ViewError::BadId);
        }
        if parent == child {
            return Err(ViewError::SelfAttach);
        }
        if self.parent[child.0 as usize] != NIL {
            return Err(ViewError::Reparent);
        }
        if child.0 <= parent.0 {
            return Err(ViewError::BuildOrder);
        }
        self.parent[child.0 as usize] = parent.0;
        let mut cur = self.first[parent.0 as usize];
        if cur == NIL {
            self.first[parent.0 as usize] = child.0;
            return Ok(());
        }
        while self.next[cur as usize] != NIL {
            cur = self.next[cur as usize];
        }
        self.next[cur as usize] = child.0;
        Ok(())
    }

    /// 声明 view 根（恰一次）。
    pub fn set_root(&mut self, id: Id) -> Result<(), ViewError> {
        if id.0 as usize >= self.len {
            return Err(ViewError::BadId);
        }
        if self.root != NIL {
            return Err(ViewError::DoubleRoot);
        }
        self.root = id.0;
        Ok(())
    }

    /// view 根。
    pub fn root(&self) -> Option<Id> {
        if self.root == NIL {
            None
        } else {
            Some(Id(self.root))
        }
    }

    /// 节点样式只读访问。
    pub fn node(&self, id: Id) -> Option<&Node> {
        self.nodes.get(id.0 as usize)
    }

    /// 首子。
    pub fn first_child(&self, id: Id) -> Option<Id> {
        let v = *self.first.get(id.0 as usize)?;
        (v != NIL).then_some(Id(v))
    }

    /// 兄弟链下一节点。
    pub fn next_sibling(&self, id: Id) -> Option<Id> {
        let v = *self.next.get(id.0 as usize)?;
        (v != NIL).then_some(Id(v))
    }

    /// 父节点。
    pub fn parent_of(&self, id: Id) -> Option<Id> {
        let v = *self.parent.get(id.0 as usize)?;
        (v != NIL).then_some(Id(v))
    }
}

impl<const N: usize> Default for ViewBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Elm 应用契约：Model/Msg/update/view 三件套。
///
/// `view` 把 Model 投影进调用方提供的定容 [`ViewBuf`]（reset 由 [`fold`]
/// 负责），返回根 [`Id`]——应用不持有树，树是帧边界一次性产物。
pub trait App {
    /// 应用状态。
    type Model;
    /// 消息集。
    type Msg;

    /// 初始状态。
    fn init(&self) -> Self::Model;

    /// 消息演进（就地变异；外部副作用不进本 trait——单向数据流纪律）。
    fn update(&self, model: &mut Self::Model, msg: Self::Msg);

    /// 状态投影：建帧 view 树并返回根。
    fn view<const N: usize>(
        &self,
        model: &Self::Model,
        buf: &mut ViewBuf<N>,
    ) -> Result<Id, ViewError>;
}

/// 折叠环：`init → update*（按序折叠）→ reset → view`。
///
/// 返回终态 Model 与 view 根 [`Id`]；view 建树失败（容量/闸）原样上抛。
/// 同一消息序列必得同一 Model 与同一 view 树（确定性折叠，可重放）。
pub fn fold<A, I, const N: usize>(
    app: &A,
    msgs: I,
    buf: &mut ViewBuf<N>,
) -> Result<(A::Model, Id), ViewError>
where
    A: App,
    I: IntoIterator<Item = A::Msg>,
{
    let mut model = app.init();
    for msg in msgs {
        app.update(&mut model, msg);
    }
    buf.reset();
    let root = app.view(&model, buf)?;
    Ok((model, root))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{fold, App, Id, Kind, Main, Node, ViewBuf, ViewError, NIL};

    /// 计数器应用：Model=u32，Msg=增/减/重置——Elm 三件套最小活体。
    struct Counter;
    enum CMsg {
        Inc,
        Add(u32),
    }

    impl App for Counter {
        type Model = u32;
        type Msg = CMsg;
        fn init(&self) -> u32 {
            0
        }
        fn update(&self, model: &mut u32, msg: CMsg) {
            match msg {
                CMsg::Inc => *model += 1,
                CMsg::Add(n) => *model += n,
            }
        }
        fn view<const N: usize>(&self, model: &u32, buf: &mut ViewBuf<N>) -> Result<Id, ViewError> {
            // 根容器（纵排）+ 一个文本叶子（计数值承载，v0 无文本渲染只占槽位）
            let root = buf.push(Node {
                kind: Kind::Node,
                dir: super::Dir::Column,
                pad: [8, 8, 8, 8],
                gap: 8,
                main: Main::Fill(1),
            })?;
            let label = buf.push(Node {
                kind: Kind::Text,
                dir: super::Dir::Column,
                pad: [0; 4],
                gap: 0,
                main: Main::Fill(1),
            })?;
            buf.attach(root, label)?;
            buf.set_root(root)?;
            debug_assert!(buf.node(root).is_some());
            // Model 投影进树结构的证据：计数值决定叶子数（奇偶面）
            if *model % 2 == 1 {
                let extra = buf.push(Node {
                    kind: Kind::Text,
                    dir: super::Dir::Column,
                    pad: [0; 4],
                    gap: 0,
                    main: Main::Fill(1),
                })?;
                buf.attach(root, extra)?;
            }
            Ok(root)
        }
    }

    #[test]
    fn fold_is_deterministic_over_message_sequence() {
        let mut buf = ViewBuf::<16>::new();
        let (m, root) = fold(&Counter, [CMsg::Inc, CMsg::Add(2), CMsg::Inc], &mut buf).unwrap();
        assert_eq!(m, 4);
        assert_eq!(root, Id(0));
        // 偶数模型 → 单叶子（根 + 文本）
        assert_eq!(buf.len(), 2);
        // 同序列重放得同树
        let mut buf2 = ViewBuf::<16>::new();
        let (m2, root2) = fold(&Counter, [CMsg::Inc, CMsg::Add(2), CMsg::Inc], &mut buf2).unwrap();
        assert_eq!((m2, root2), (m, root));
        assert_eq!(buf2.len(), buf.len());
    }

    #[test]
    fn reset_recycles_buffer_for_next_frame() {
        let mut buf = ViewBuf::<16>::new();
        let _ = fold(&Counter, [CMsg::Inc], &mut buf).unwrap();
        assert_eq!(buf.len(), 3);
        buf.reset();
        assert!(buf.is_empty());
        assert_eq!(buf.root(), None);
        // 复用后再折叠照常
        let _ = fold(&Counter, [], &mut buf).unwrap();
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn capacity_gate_is_visible() {
        let mut buf = ViewBuf::<2>::new();
        buf.push(Node::EMPTY).unwrap();
        buf.push(Node::EMPTY).unwrap();
        assert_eq!(buf.push(Node::EMPTY), Err(ViewError::Full { cap: 2 }));
    }

    #[test]
    fn attach_gates_reject_misuse() {
        let mut buf = ViewBuf::<8>::new();
        let a = buf.push(Node::EMPTY).unwrap();
        let b = buf.push(Node::EMPTY).unwrap();
        let c = buf.push(Node::EMPTY).unwrap();
        // 自挂接
        assert_eq!(buf.attach(a, a), Err(ViewError::SelfAttach));
        // 越界
        assert_eq!(buf.attach(Id(9), b), Err(ViewError::BadId));
        // 建树次序（父必须先于子入树）：a< b<c，attach(c, a) 违序
        assert_eq!(buf.attach(c, a), Err(ViewError::BuildOrder));
        // 正常挂接 + 重复挂接拒绝
        buf.attach(a, b).unwrap();
        assert_eq!(buf.attach(c, b), Err(ViewError::Reparent));
        buf.attach(a, c).unwrap();
        // 链序：a → b → c
        assert_eq!(buf.first_child(a), Some(b));
        assert_eq!(buf.next_sibling(b), Some(c));
        assert_eq!(buf.next_sibling(c), None);
        assert_eq!(buf.parent_of(b), Some(a));
    }

    #[test]
    fn root_declared_exactly_once() {
        let mut buf = ViewBuf::<8>::new();
        let a = buf.push(Node::EMPTY).unwrap();
        let b = buf.push(Node::EMPTY).unwrap();
        buf.set_root(a).unwrap();
        assert_eq!(buf.set_root(b), Err(ViewError::DoubleRoot));
        assert_eq!(buf.root(), Some(a));
        // 越界根
        let mut buf2 = ViewBuf::<8>::new();
        assert_eq!(buf2.set_root(Id(3)), Err(ViewError::BadId));
        assert_eq!(buf2.root, NIL);
    }
}
