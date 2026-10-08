//! 任务调度：per-CPU 统一调度器（M6）→ 用户任务跨核（M7-A）→ 优先级老化（M9-C）。
//!
//! 语义（M6 双核统一，M7 解除用户钉扎，M9-C 饥饿防护）：
//! - 任务 = 定容槽位表（`[Option<Task>; MAX_TASKS]`，地址永久稳定）中的
//!   一项：独立内核栈 + [`ostd::task::TaskContext`] + 入口；
//! - **全局就绪队列 + per-CPU 执行面**：spawn 入全局 FIFO 队列并跨核提示
//!   （RESCHED IPI 唤醒 idle 核）；每核从队列拾取任务执行（M7-A 起
//!   用户任务不再钉扎：per-CPU TSS/RSP0 + per-CPU 系统调用栈全部就位）；
//! - 协作切换 = [`yield_now`]（重排队 + 拾取下一可运行者）；
//! - 抢占切换 = **LAPIC 定时器**（向量 0x41，统一 per-CPU 抢占源；PIT
//!   退化为墙钟）→ [`timer_hook`]（quantum 到期 + 守卫清零 + 队列有
//!   可运行者时，填写栈上 [`PreemptPlan`]，桩同窗口完成现场保存与切换，
//!   CONTEXT-02）；
//! - AP 侧以 [`run_idle`] idle 循环参与调度：无就绪任务时执行 idle 附加
//!   工作（工作池/IPC 服务，由 smp 注册），再无则 halt 等待 IPI/节拍；
//! - 每次派发前 [`prepare_dispatch`] 切换 CR3（用户任务 = 用户根）、
//!   写本核 TSS.RSP0 与本核 per-CPU 系统调用栈（`PERCPU[cpu]`）；
//! - **优先级调度面（M8-C）**：就绪队列四级化（0=最高 … 3=最低，
//!   默认 [`PRIO_NORMAL`] 保持既有轮转语义零回归）；拾取按级扫描
//!   （同级内 FIFO 轮转不变）；抢占规则扩为「高优先就绪者抢前
//!   （严格高于当前，无视量子）∪ 量子到期轮转」；系统调用面
//!   SYS_SET_PRIO/SYS_GET_PRIO（abi v0 追加 7/8，自调节，无跨任务权能）。
//!   无老化/饥饿防护（如实记档，随进程模型演进）。
//! - **优先级老化防护（M9-C）**：`base_prio`（用户设定级）与 `prio`
//!   （有效级）分离——就绪等待每 tick 计账（`waited`），跨 [`AGE_TICKS`
//!   阈值且级 > 0 时逐级提升（3→2→1→0）并重置计账；**回队时衰减回
//!   base**（每次重新入队都从用户设定级起步，避免提升永久化）。饥饿消除论证：
//!   任意就绪任务至多 `3×AGE_TICKS` tick 后升至 0 级，与同级任务 FIFO
//!   轮转竞争，量子到期路径必可达——每核饱和的高优先负载不再永久
//!   压制低优先任务（M8-C 已知限制解除）。
//! - **GS/swapgs 纪律定版（M8-A）**：内核**不使用** swapgs/GS 承载 per-CPU
//!   状态（M7 影子方案两处三重故障的根因是「CPU 全局配对态 vs 任务窗口
//!   生命周期」的结构性错配，见 syscall.rs 模块文档）；per-CPU 寻址 =
//!   无状态 LAPIC 索引，内核代码永不消费 GS，FS/GS 保留未来用户 TLS。
//! - 切换窗口纪律：`IntWindow` 非零期间本核中断物理遮蔽——SMP 下依然
//!   成立（cli 只遮蔽本核）：持锁者被本核定时器打断即死锁的模式被同一
//!   纪律封死；跨核锁竞争仅为有界自旋（临界区内无阻塞操作）。
//!
//! unsafe 面：仅 ostd 收口层（CONTEXT-01/02、HW-04/09/11/13）+ 本模块
//! per-CPU 块的静态地址萃取；裸指针仅用于向桩传递稳定上下文地址。

use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ostd::interrupt::PreemptPlan;
use ostd::sync::SpinLock;
use ostd::task::{switch_deferred, SwitchPair, TaskContext};

/// 任务内核栈大小：16 KiB。
const STACK_BYTES: usize = 16 * 1024;
/// 抢占时间片（LAPIC 定时器节拍数）：3 拍 = 30 ms @100 Hz。
pub const QUANTUM_TICKS: u64 = 3;
/// 最大 CPU 槽位数（QEMU -smp 2；MADT 探测的上界契约）。
pub const MAX_CPUS: usize = 2;
/// 优先级级数（M8-C）：0=最高 … 3=最低。
pub const PRIO_LEVELS: usize = 4;
/// 默认优先级（NORMAL）——既有自检全部落此级，轮转语义零回归。
pub const PRIO_NORMAL: u8 = 1;
/// 老化阈值（M9-C）：就绪等待跨此 tick 数且级 > 0 时提升一级（5 拍 = 50 ms
/// @100 Hz；满级 3→0 爬升 150 ms）。取值权衡：太小扰动 M8 自检的时序假设，
/// 太大拖慢饥饿防护收敛；5 拍下 M8 自检窗口（< 5 tick）不受影响。
pub const AGE_TICKS: u32 = 5;
/// 定容任务槽位数（地址永久稳定 → 上下文指针跨锁释放有效）。
const MAX_TASKS: usize = 32;
/// 每任务句柄表容量（M9-A；句柄 0 = NULL 保留，1..HANDLE_MAX 可用）。
pub const HANDLE_MAX: usize = 8;
/// CURRENT 槽的 idle 哨兵（本核无任务在跑）。
const IDLE: usize = usize::MAX;

/// 任务类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// 内核任务（含主任务）。
    Kernel,
    /// 用户任务（ring3 执行，独立页表）。
    User,
}

/// 任务状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// 在就绪队列中或尚未首跑。
    Ready,
    /// 正在运行（每核至多一个）。
    Running,
    /// 入口已返回，永不复用。
    Finished,
}

/// 任务入口函数指针。
pub type Entry = fn();

/// 一个任务。
struct Task {
    /// 诊断名。
    #[allow(dead_code)]
    name: &'static str,
    /// 独立内核栈（u128 元素 → 16 字节对齐；主任务为空 = 引导栈）。
    /// 生存期锚点：任务存活期内栈内存必须保持分配，字段不被读取属预期。
    #[allow(dead_code)]
    stack: Vec<u128>,
    /// 内核栈顶绝对地址（用户任务派发时写入 TSS.RSP0）。
    stack_top: u64,
    /// 用户页表根物理地址（仅用户任务使用；内核任务恒为 0）。
    user_root: u64,
    /// 类别。
    kind: Kind,
    /// 调度保存/恢复的寄存器面。
    ctx: TaskContext,
    /// 状态。
    state: State,
    /// 当前时间片已用节拍数。
    used_ticks: u64,
    /// 入口（trampoline 经 CURRENT 读取）。
    entry: Entry,
    /// 钉扎的 CPU 槽位（None = 自由跨核；M7-A 起用户任务默认自由）。
    pinned: Option<usize>,
    /// 调用方能力槽号（系统全局能力表；0 = 未持有；语义 = 主身份句柄
    /// ——用户任务派发时与 handles[1] 同源安装，M9-A 后保留为门禁快路径）。
    cap_slot: usize,
    /// 父任务槽位（M9-A 进程模型；None = 内核直接派生或主任务）。
    /// 授权纪律：SYS_CAP_GRANT 仅允许向自己的子任务授予（父链内核登记，
    /// 用户态不可伪造）。
    parent: Option<usize>,
    /// 任务本地句柄表（M9-A：句柄号 → 全局能力槽位；0 = NULL 永空）。
    /// **槽位单属主不变式**：任一全局槽任一时刻至多被一个 (任务, 句柄)
    /// 对引用；终结清算（revoke_all_handles）回收到能力表。
    handles: [Option<usize>; HANDLE_MAX],
    /// 调度优先级（0=最高 … 3=最低；有效级，M9-C 老化提升可临时高于 base）。
    prio: u8,
    /// 基准优先级（M9-C：用户设定级；回队衰减目标，SET_PRIO 写入面）。
    base_prio: u8,
    /// 就绪队列等待计账（tick 数；M9-C 老化阈值判定）。
    waited: u32,
}

impl Task {
    /// 以入口创建新内核任务。
    fn new(name: &'static str, entry: Entry, trampoline: extern "C" fn() -> !) -> Self {
        let stack = alloc::vec![0u128; STACK_BYTES / size_of::<u128>()];
        let top = stack.as_ptr() as u64 + STACK_BYTES as u64;
        Self {
            name,
            stack,
            stack_top: top,
            user_root: 0,
            kind: Kind::Kernel,
            ctx: TaskContext::boot_new(top, trampoline),
            state: State::Ready,
            used_ticks: 0,
            entry,
            pinned: None,
            cap_slot: 0,
            parent: None,
            handles: [None; HANDLE_MAX],
            prio: PRIO_NORMAL,
            base_prio: PRIO_NORMAL,
            waited: 0,
        }
    }

    /// 以入口创建新用户任务（独立内核栈 + 用户页表根 + 能力槽 + 句柄表）。
    fn new_user(
        name: &'static str,
        entry: Entry,
        user_root: u64,
        cap_slot: usize,
        parent: Option<usize>,
        trampoline: extern "C" fn() -> !,
    ) -> Self {
        let mut t = Self::new(name, entry, trampoline);
        t.kind = Kind::User;
        t.user_root = user_root;
        // M7-A：用户任务默认自由跨核（per-CPU TSS/RSP0 + per-CPU syscall
        // 栈已就位）；确定性自检可用 spawn_user_pinned 显式钉扎。
        t.cap_slot = cap_slot;
        // M9-A：主身份句柄（句柄 1）与 cap_slot 同源；cap_slot = 0 则句柄
        // 表全空（纯被授予型任务）。
        if cap_slot != 0 {
            t.handles[1] = Some(cap_slot);
        }
        t.parent = parent;
        t
    }

    /// 句柄表全量清算（M9-A：任务终结路径调用；全局能力槽逐个撤销）。
    /// 锁序：调用方已持 SCHED，内部再取 CAPS（SCHED → CAPS 单向嵌套）。
    fn revoke_all_handles(&mut self) {
        for slot in self.handles.iter_mut().skip(1) {
            if let Some(g) = slot.take() {
                let _ = crate::caps::table().lock().revoke(g);
            }
        }
    }

    /// 主任务槽（运行在引导栈上）。
    const fn main_task() -> Self {
        Self {
            name: "main",
            stack: Vec::new(),
            stack_top: 0,
            user_root: 0,
            kind: Kind::Kernel,
            ctx: TaskContext::stopped(),
            state: State::Running,
            used_ticks: 0,
            entry: main_entry_stub,
            pinned: Some(0),
            cap_slot: 0,
            parent: None,
            handles: [None; HANDLE_MAX],
            prio: PRIO_NORMAL,
            base_prio: PRIO_NORMAL,
            waited: 0,
        }
    }
}

/// 主任务入口占位（主任务从不经 trampoline 进入；永不调用）。
fn main_entry_stub() {}

/// 调度器全局状态（受 [`SCHED`] 保护）。
struct Scheduler {
    /// 定容任务槽位表（Some = 占用；槽位地址永久稳定）。
    tasks: [Option<Task>; MAX_TASKS],
    /// 全局就绪队列（按优先级分级；级内 FIFO，跨核共享派发）。
    ready: [VecDeque<usize>; PRIO_LEVELS],
    /// 引导页表根（内核任务统一回归此 CR3）。
    boot_cr3: u64,
    /// 累计抢占切换次数（自检取证，跨核合计）。
    preempt_switches: u64,
    /// 累计协作切换次数。
    cooperative_switches: u64,
}

impl Scheduler {
    const fn new() -> Self {
        const NONE: Option<Task> = None;
        Self {
            tasks: [NONE; MAX_TASKS],
            ready: [const { VecDeque::new() }; PRIO_LEVELS],
            boot_cr3: 0,
            preempt_switches: 0,
            cooperative_switches: 0,
        }
    }
}

/// 全局调度器。
static SCHED: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

/// BSP 的 APIC ID（init 时捕获；my_cpu 与入口桩的槽位映射基准）。
/// 桩内以字节比对（`cmp al, [rip + LUMINA_BSP_APIC]`），故导出符号。
#[no_mangle]
static BSP_APIC_ID: AtomicU8 = AtomicU8::new(0);
/// 每核当前任务槽位（IDLE = idle 循环 / 未上线）。
static CURRENT: [AtomicUsize; MAX_CPUS] = [AtomicUsize::new(IDLE), AtomicUsize::new(IDLE)];
/// 每核 idle 上下文（静态存储期 → 跨锁释放后指针稳定）。
static mut IDLE_CTX: [TaskContext; MAX_CPUS] = [TaskContext::stopped(); MAX_CPUS];
/// 每核 idle 循环是否已进入（决定终结路径可否切回 idle）。
static IDLE_VALID: [AtomicBool; MAX_CPUS] = [AtomicBool::new(false), AtomicBool::new(false)];
/// 抢占使能（自检 12 起开启；协作演示窗口内关闭）。
static PREEMPT_ENABLED: AtomicBool = AtomicBool::new(false);
/// RESCHED IPI 送达计数（跨核提示证据，自检 21 断言）。
static RESCHED_HITS: AtomicU64 = AtomicU64::new(0);
/// 跨核提示桥（smp 注册：向 AP 发 RESCHED IPI；None = AP 未上线）。
static RESCHED_KICK: AtomicUsize = AtomicUsize::new(0);
/// idle 附加工作桥（smp 注册：工作池/IPC 服务；返回是否有产出）。
static IDLE_WORK: AtomicUsize = AtomicUsize::new(0);

/// 本核任务内核栈顶槽（syscall 入口桩的唯一栈源；M8-A 接线生效）。
///
/// 演进史：M6 全局单槽 `LUMINA_KSTACK_CUR`（双核并发即互踩）→ M7 试
/// GS/swapgs 影子方案（两处三重故障，否决，见 syscall.rs）→ **M8-A 定版
/// 无状态 LAPIC 索引**：入口桩读本核 APIC ID 计算槽偏移（零 MSR 态、
/// 零配对纪律），全局槽已删除。
/// 布局契约：[AtomicU64; MAX_CPUS] 紧凑（槽偏移 = cpu×8），桩内
/// `lea rsp,[rip+sym]` + `mov rsp,[rsp+rdx]` 定位；写入面唯一
/// （prepare_dispatch 按本核槽位派发时更新），消费面唯一（入口桩）。
#[no_mangle]
pub static LUMINA_PERCPU_KSTACK: [AtomicU64; MAX_CPUS] = [AtomicU64::new(0), AtomicU64::new(0)];

/// 用户任务真实入口（user.rs 注入；避免 task ↔ user 循环依赖）。
static USER_ENTRY_BRIDGE: AtomicUsize = AtomicUsize::new(0);

/// 本核 CPU 槽位（LAPIC ID → 0/1；BSP = 0）。
fn my_cpu() -> usize {
    let id = ostd::hw::lapic::id();
    usize::from(id != BSP_APIC_ID.load(Ordering::Acquire)) % MAX_CPUS
}

/// 本核 CPU 槽位（公开形态；跨核门铃与取证面共用）。
pub fn current_cpu_slot() -> usize {
    my_cpu()
}

/// BSP 的 APIC ID（跨核门铃寻址用；init 时捕获）。
pub fn bsp_apic_id() -> u8 {
    BSP_APIC_ID.load(Ordering::Acquire)
}

/// 条件关中断窗口：进入时 IF=1 则 cli（记录原状），离开时恢复。
///
/// 纪律：所有 `SCHED.lock()` 临界区必须包在本窗口内——本核定时器钩子
/// 会在 ISR 中抢同一把锁，持锁者被本核中断打断即自旋死锁（SMP 下 cli
/// 只遮蔽本核，但死锁模式恰是「本核中断打断本核持锁者」，纪律不变）。
/// 中断窗口内（ISR/hook）进入本窗口为 no-op（IF 本就为 0）。
struct IntWindow {
    restore: bool,
}

impl IntWindow {
    fn new() -> Self {
        let on = ostd::hw::intr::if_enabled();
        if on {
            ostd::hw::intr::disable();
        }
        Self { restore: on }
    }
}

impl Drop for IntWindow {
    fn drop(&mut self) {
        if self.restore {
            ostd::hw::intr::enable();
        }
    }
}

/// 钉扎过滤：槽位 `id` 的任务可否在本核 `cpu` 运行。
///
/// 双约束：`pinned`（静态钉扎）与 `bound`（系统调用期间的动态绑定）。
fn eligible(tasks: &[Option<Task>; MAX_TASKS], id: usize, cpu: usize) -> bool {
    tasks
        .get(id)
        .and_then(|t| t.as_ref())
        .is_some_and(|t| t.pinned.is_none_or(|c| c == cpu))
}

/// 轮转式拾取（单级）：从队首弹起、不匹配则回插队尾（保持队列顺序，
/// 杜绝「弹出即丢弃」造成任务丢失——钉扎场景下必须逐轮回插）。
fn pick_rotating(
    queue: &mut VecDeque<usize>,
    tasks: &[Option<Task>; MAX_TASKS],
    cpu: usize,
    exclude: usize,
) -> Option<usize> {
    let rounds = queue.len();
    for _ in 0..rounds {
        let id = queue.pop_front()?;
        queue.push_back(id);
        if id != exclude && eligible(tasks, id, cpu) {
            return Some(id);
        }
    }
    None
}

/// 优先级拾取（M8-C）：自 0 级（最高）向低级扫描，首个有可运行者的
/// 级内做轮转拾取；`up_to` 限定最高扫描级（抢前判定用，None = 全级）。
fn pick_best(
    ready: &mut [VecDeque<usize>; PRIO_LEVELS],
    tasks: &[Option<Task>; MAX_TASKS],
    cpu: usize,
    exclude: usize,
    up_to: Option<u8>,
) -> Option<usize> {
    let top = up_to.map_or(PRIO_LEVELS, |p| p as usize);
    for queue in ready.iter_mut().take(top) {
        if let Some(id) = pick_rotating(queue, tasks, cpu, exclude) {
            return Some(id);
        }
    }
    None
}

/// 从分级就绪队列中移除指定槽位（轮转扫描，保持其余元素顺序）。
fn remove_value(ready: &mut [VecDeque<usize>; PRIO_LEVELS], target: usize) {
    for queue in ready.iter_mut() {
        for _ in 0..queue.len() {
            if queue.front() == Some(&target) {
                queue.pop_front();
                return;
            }
            if let Some(x) = queue.pop_front() {
                queue.push_back(x);
            }
        }
    }
}

/// 就绪入队（按任务优先级落级）。
fn enqueue(ready: &mut [VecDeque<usize>; PRIO_LEVELS], id: usize, prio: u8) {
    ready[prio as usize].push_back(id);
}

/// 优先级老化取证计数（M9-C 自检 33 断言面）：累计提升次数。
static AGING_BOOSTS: AtomicU64 = AtomicU64::new(0);

/// 老化提升计数快照（自检 33 断言面）。
pub fn aging_boosts() -> u64 {
    AGING_BOOSTS.load(Ordering::Acquire)
}

/// 老化扫描（M9-C）：对全部就绪队列逐级做等待计账，跨 [`AGE_TICKS`]
/// 阈值且级 > 0 的任务提升一级并移入更高队列（队尾入队）。
/// 自高向低处理（3→2→1）：本 tick 提升入高队列的任务不再被同轮重复计账
/// （高队列在更晚的迭代中处理——提升者在高队列处理时 waited 已重置，
/// 仅多计一次 +1，无语义影响）。
///
/// **零堆分配纪律**：本函数在定时器 ISR（IF=0）内运行——提升列表必须用
/// 定容栈上数组承载（`[usize; MAX_TASKS]`，容量上界 = 任务槽总数，提升数
/// 不可能超过队列元素总数）。ISR 内堆分配会与被中断打断的 Harbor 分配锁
/// 持有者自旋死锁（S34 实测：t24 间歇挂死，devlog 记档）——ISR 上下文
/// 严禁触碰全局分配器。
fn aging_pass(ready: &mut [VecDeque<usize>; PRIO_LEVELS], tasks: &mut [Option<Task>; MAX_TASKS]) {
    let mut boosts: u64 = 0;
    for level in (1..PRIO_LEVELS).rev() {
        // 定容提升列表（栈上；MAX_TASKS = 全系统任务槽上界）
        let mut promoted = [IDLE; MAX_TASKS];
        let mut promoted_len: usize = 0;
        let len = ready[level].len();
        for _ in 0..len {
            let Some(id) = ready[level].pop_front() else {
                break;
            };
            let boost = match tasks.get_mut(id).and_then(|s| s.as_mut()) {
                Some(t) => {
                    t.waited = t.waited.saturating_add(1);
                    if t.waited >= AGE_TICKS && t.prio > 0 {
                        t.waited = 0;
                        t.prio -= 1;
                        true
                    } else {
                        false
                    }
                }
                None => false,
            };
            if boost {
                promoted[promoted_len] = id;
                promoted_len += 1;
            } else {
                ready[level].push_back(id);
            }
        }
        for &id in &promoted[..promoted_len] {
            let p = tasks.get(id).and_then(|s| s.as_ref()).map_or(0, |t| t.prio);
            ready[p as usize].push_back(id);
            boosts += 1;
        }
    }
    if boosts != 0 {
        AGING_BOOSTS.fetch_add(boosts, Ordering::AcqRel);
    }
}

/// 初始化调度器：槽位 0 = 主任务（钉扎 CPU0）；记录引导 CR3 与 BSP APIC ID。
pub fn init() {
    let mut s = SCHED.lock();
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    s.boot_cr3 = boot_cr3;
    s.tasks[0] = Some(Task::main_task());
    BSP_APIC_ID.store(ostd::hw::lapic::id(), Ordering::Release);
    CURRENT[0].store(0, Ordering::Relaxed);
    CURRENT[1].store(IDLE, Ordering::Relaxed);
}

/// 注册用户入口桥（user.rs 模块初始化时调用一次）。
pub fn set_user_entry_bridge(f: extern "C" fn() -> !) {
    USER_ENTRY_BRIDGE.store(f as usize, Ordering::Relaxed);
}

/// 注册跨核提示桥（smp AP 上线后调用；M8-C 泛化：fn(usize) 定向到
/// 目标核槽位——跨核通道从「对侧」泛化为「任意核」）。
pub fn set_resched_kick(f: fn(usize)) {
    RESCHED_KICK.store(f as usize, Ordering::Release);
}

/// 注册 idle 附加工作桥（smp 初始化时调用；idle 无任务时执行）。
pub fn set_idle_work(f: fn() -> bool) {
    IDLE_WORK.store(f as usize, Ordering::Release);
}

/// 派生新内核任务（入全局队列待拾取；跨核提示 idle 核）；返回槽位号。
pub fn spawn(name: &'static str, entry: Entry) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let Some(id) = alloc_slot(&mut s, Task::new(name, entry, trampoline)) else {
        return IDLE;
    };
    let prio = s.tasks[id].as_ref().map_or(PRIO_NORMAL, |t| t.prio);
    enqueue(&mut s.ready, id, prio);
    kick_other();
    id
}

/// 派生指定优先级的内核任务（M8-C 调度面；0=最高 … 3=最低）。
pub fn spawn_prio(name: &'static str, entry: Entry, prio: u8) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let mut t = Task::new(name, entry, trampoline);
    t.prio = prio.min((PRIO_LEVELS - 1) as u8);
    t.base_prio = t.prio;
    let Some(id) = alloc_slot(&mut s, t) else {
        return IDLE;
    };
    enqueue(&mut s.ready, id, prio.min((PRIO_LEVELS - 1) as u8));
    kick_other();
    id
}

/// 派生新用户任务：`user_root` 为其独立页表根，`cap_slot` 为其能力槽；
/// 入口经桥函数进入 ring3。M7-A 起用户任务自由跨核（任意核可拾取）。
pub fn spawn_user(name: &'static str, entry: Entry, user_root: u64, cap_slot: usize) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let Some(id) = alloc_slot(
        &mut s,
        Task::new_user(name, entry, user_root, cap_slot, None, trampoline_user),
    ) else {
        return IDLE;
    };
    let prio = s.tasks[id].as_ref().map_or(PRIO_NORMAL, |t| t.prio);
    enqueue(&mut s.ready, id, prio);
    kick_other();
    id
}

/// 派生子任务（M9-A 进程模型）：`parent` 为父任务槽位，登记父链供
/// SYS_CAP_GRANT 授权门禁（父链内核登记，用户态不可伪造）。
/// 自由跨核派发；确定性自检用 [`spawn_user_child_pinned`]。
pub fn spawn_user_child_pinned(
    name: &'static str,
    entry: Entry,
    user_root: u64,
    cap_slot: usize,
    cpu: usize,
    parent: usize,
) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let mut t = Task::new_user(
        name,
        entry,
        user_root,
        cap_slot,
        Some(parent),
        trampoline_user,
    );
    t.pinned = Some(cpu % MAX_CPUS);
    let Some(id) = alloc_slot(&mut s, t) else {
        return IDLE;
    };
    let prio = s.tasks[id].as_ref().map_or(PRIO_NORMAL, |t| t.prio);
    enqueue(&mut s.ready, id, prio);
    kick_other();
    id
}

/// 派生钉扎用户任务：仅在 `cpu` 槽位可拾取（自检 26 的跨核确定性协议）。
pub fn spawn_user_pinned(
    name: &'static str,
    entry: Entry,
    user_root: u64,
    cap_slot: usize,
    cpu: usize,
) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let mut t = Task::new_user(name, entry, user_root, cap_slot, None, trampoline_user);
    t.pinned = Some(cpu % MAX_CPUS);
    let Some(id) = alloc_slot(&mut s, t) else {
        return IDLE;
    };
    let prio = s.tasks[id].as_ref().map_or(PRIO_NORMAL, |t| t.prio);
    enqueue(&mut s.ready, id, prio);
    kick_other();
    id
}

/// 派生钉扎任务：仅在 `cpu` 槽位可拾取（自检用跨核确定性协议）。
pub fn spawn_pinned(name: &'static str, entry: Entry, cpu: usize) -> usize {
    spawn_pinned_prio(name, entry, PRIO_NORMAL, cpu)
}

/// 派生钉扎 + 指定优先级的任务（M8-C）。
pub fn spawn_pinned_prio(name: &'static str, entry: Entry, prio: u8, cpu: usize) -> usize {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    let mut t = Task::new(name, entry, trampoline);
    t.pinned = Some(cpu % MAX_CPUS);
    t.prio = prio.min((PRIO_LEVELS - 1) as u8);
    t.base_prio = t.prio;
    let Some(id) = alloc_slot(&mut s, t) else {
        return IDLE;
    };
    enqueue(&mut s.ready, id, prio.min((PRIO_LEVELS - 1) as u8));
    kick_other();
    id
}

/// 占用首个空闲槽位（满则 None）。
fn alloc_slot(s: &mut Scheduler, t: Task) -> Option<usize> {
    let id = s.tasks.iter().position(|slot| slot.is_none())?;
    s.tasks[id] = Some(t);
    Some(id)
}

/// 跨核提示：向其他核发 RESCHED IPI（桥未注册 = AP 未上线，无操作）。
fn kick_other() {
    let kick = RESCHED_KICK.load(Ordering::Acquire);
    if kick != 0 {
        // SAFETY: 前置条件 —— 地址来自 set_resched_kick 存入的 fn(usize)。
        // 不变式 —— Release/Acquire 配对；注册先于任何跨核派生。
        // 并发 —— IPI 发送侧天然多发布者安全（ICR 交付状态轮询）。
        // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
        let f: fn(usize) = unsafe { core::mem::transmute(kick) };
        // 提示对侧核（2 核拓扑的对称化；定向语义由 smp::kick_cpu 承载）
        f(1 - current_cpu_slot());
    }
}

/// RESCHED IPI 钩子（注册进 ostd stubs；本核中断窗口内调用）。
pub fn resched_hook() {
    RESCHED_HITS.fetch_add(1, Ordering::AcqRel);
}

/// RESCHED 送达计数快照（自检 21 断言用）。
pub fn resched_hits() -> u64 {
    RESCHED_HITS.load(Ordering::Acquire)
}

/// 派发前准备：切换 CR3（按任务类别）并写本核 RSP0 / per-CPU 调用栈。
///
/// M8-A：本核 TSS.RSP0 与本核 PERCPU 槽同源写入（前者服务 ring3 中断
/// 向量化，后者服务 syscall 入口切栈——syscall 不经 TSS，需独立接线），
/// 消费面为 syscall 入口桩的 LAPIC 索引读数；全局槽已删除。
/// 内核任务回归引导根（RSP0/PERCPU 留陈旧值无害：内核任务被中断时本就
/// 在 ring0，不经 RSP0 切栈；入 ring3 前必有用户任务派发重写）。
fn prepare_dispatch(t: &Task, boot_cr3: u64, cpu: usize) {
    match t.kind {
        Kind::User => {
            // TCG 双异常交付规避（S31 记档）：tick 交付进 ring3 为缺陷族
            // 触发面——用户任务驻留 ring3 期间屏蔽本核 LAPIC 定时器
            // （LVT per-CPU；内核任务派发即解屏蔽，本函数为唯一咽喉点）。
            // PIT 墙钟不动（实测其交付不触发缺陷族；时间面在 ring3 窗口
            // 冻结为已知语义，自检面事件驱动兼容）。
            ostd::hw::lapic::timer_mask();
            ostd::hw::gdt::set_rsp0(cpu, t.stack_top);
            // syscall 入口桩唯一栈源（M8-A 接线；与本核 RSP0 同源）
            LUMINA_PERCPU_KSTACK[cpu].store(t.stack_top, Ordering::Relaxed);
            if ostd::hw::control::read_cr3() & !0xFFF != t.user_root {
                // 前置条件 —— user_root 为完整可用页表根（用户侧构造路径
                //          保证）；所有 CR3 均映射低 1 GiB 恒等区。
                ostd::hw::control::write_cr3(t.user_root);
            }
        }
        Kind::Kernel => {
            // 内核任务派发即恢复节拍（与 User 分支构成屏蔽不变式咽喉点）
            ostd::hw::lapic::timer_unmask();
            if ostd::hw::control::read_cr3() & !0xFFF != boot_cr3 {
                // 引导根由启动汇编构建并验证（长模式即运行其上）。
                ostd::hw::control::write_cr3(boot_cr3);
            }
        }
    }
}

/// 取两互异槽位上下文的 SwitchPair（split_at_mut 证明互斥性）。
fn slots_pair(s: &mut Scheduler, a: usize, b: usize) -> SwitchPair {
    debug_assert_ne!(a, b, "scheduler never switches a task to itself");
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let (l, r) = s.tasks.split_at_mut(hi);
    if a < b {
        match (l[lo].as_mut(), r[0].as_mut()) {
            (Some(x), Some(y)) => SwitchPair::from(&mut x.ctx, &mut y.ctx),
            _ => unreachable!("both task slots must be occupied"),
        }
    } else {
        match (r[0].as_mut(), l[lo].as_mut()) {
            (Some(x), Some(y)) => SwitchPair::from(&mut x.ctx, &mut y.ctx),
            _ => unreachable!("both task slots must be occupied"),
        }
    }
}

/// 让出 CPU：协作切换（重排队 + 拾取下一可运行者）；无可让渡对象时空转返回。
///
/// 窗口纪律：元数据变更与物理切换全程 IF=0（cli 遮蔽）——本核定时器钩子
/// 在此窗口物理不可入，元数据与真实执行面永不错位；恢复点无条件
/// sti（内核任务的 IF 约定恒为 1，被抢占任务经 .resume→iretq 另行恢复）。
pub fn yield_now() {
    let w = IntWindow::new();
    let cpu = my_cpu();
    let pair = {
        let mut s = SCHED.lock();
        let sc = &mut *s;
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        if cur == IDLE {
            return;
        }
        // 先探测再重排队：无可让渡对象则保持 Running 原地继续
        let Some(target) = pick_best(&mut sc.ready, &sc.tasks, cpu, cur, None) else {
            return;
        };
        remove_value(&mut sc.ready, target);
        // M9-C 回队衰减：按基准级重排队（老化提升不跨运行期保留）
        let cur_prio = sc.tasks[cur].as_ref().map_or(PRIO_NORMAL, |t| t.base_prio);
        enqueue(&mut sc.ready, cur, cur_prio);
        if let Some(t) = sc.tasks[cur].as_mut() {
            t.prio = cur_prio;
            t.state = State::Ready;
            t.used_ticks = 0;
            t.waited = 0;
        }
        if let Some(t) = sc.tasks[target].as_mut() {
            t.state = State::Running;
            t.used_ticks = 0;
        }
        CURRENT[cpu].store(target, Ordering::Relaxed);
        sc.cooperative_switches += 1;
        let boot = sc.boot_cr3;
        if let Some(t) = sc.tasks[target].as_ref() {
            prepare_dispatch(t, boot, cpu);
        }
        slots_pair(sc, cur, target)
    };
    switch_deferred(pair); // 恢复后从此处继续（IF=0）
    ostd::hw::intr::enable(); // 恢复即开中断（内核任务 IF 约定）
    drop(w);
}

/// idle 循环拾取：从全局队列取一个可运行任务，返回（idle → 任务）切换对。
///
/// 首次调用以 idle 真实上下文为 old（switch_deferred 保存续点）；此后
/// 任务切回 idle 时从 [`run_idle`] 的 switch 调用点继续。
fn idle_pick(cpu: usize) -> Option<SwitchPair> {
    let mut s = SCHED.lock();
    let sc = &mut *s;
    let target = pick_best(&mut sc.ready, &sc.tasks, cpu, IDLE, None)?;
    remove_value(&mut sc.ready, target);
    if let Some(t) = sc.tasks[target].as_mut() {
        t.state = State::Running;
        t.used_ticks = 0;
    }
    CURRENT[cpu].store(target, Ordering::Relaxed);
    let boot = sc.boot_cr3;
    if let Some(t) = sc.tasks[target].as_ref() {
        prepare_dispatch(t, boot, cpu);
    }
    // SAFETY: 前置条件 —— IDLE_CTX[cpu] 为本核静态槽（地址稳定），仅本核
    //          访问；target 槽位为定容表内占用项（地址稳定）。
    // 不变式 —— 两栈互异（idle 栈 vs 任务栈）；拾取在锁窗口内完成。
    // 并发 —— idle 仅本核执行；任务槽经队列认领恰一次。
    // 违反后果 —— 指针失效即写穿任意内存（定容槽 + 锁纪律封死）。
    let t = s.tasks[target].as_mut()?;
    // SAFETY: 同上——IDLE_CTX[cpu] 静态槽、仅本核访问；借用于锁窗口内。
    unsafe {
        let idle = &mut *core::ptr::addr_of_mut!(IDLE_CTX[cpu]);
        Some(SwitchPair::from(idle, &mut t.ctx))
    }
}

/// AP idle 主循环（ap_main 调入；永不返回）。
///
/// 循环不变式：每轮先恢复 IF=1（切回 idle 的路径可能以 IF=0 到达）；
/// 优先拾取任务 → 无则执行 idle 附加工作 → 再无则 halt 等待 IPI/节拍。
pub fn run_idle(cpu: usize) -> ! {
    IDLE_VALID[cpu].store(true, Ordering::Release);
    loop {
        ostd::hw::intr::enable();
        if let Some(pair) = idle_pick(cpu) {
            switch_deferred(pair); // 切入任务；被切回时从此继续
            continue;
        }
        let work = IDLE_WORK.load(Ordering::Acquire);
        if work != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_idle_work 存入的 fn() -> bool。
            // 不变式 —— Release/Acquire 配对；注册先于 AP 上线。
            // 并发 —— 仅 idle 核调用（工作池/SPSC 契约由 smp 侧保证）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn() -> bool = unsafe { core::mem::transmute(work) };
            if f() {
                continue;
            }
        }
        ostd::hw::intr::halt();
    }
}

/// 除主任务外是否全部终结（主循环的等待谓词）。
pub fn all_workers_finished() -> bool {
    let _w = IntWindow::new();
    let s = SCHED.lock();
    s.tasks
        .iter()
        .enumerate()
        .all(|(id, slot)| id == 0 || slot.as_ref().is_none_or(|t| t.state == State::Finished))
}

/// 用户任务退出码（EXIT 系统调用写入；自检 14 断言）。
static USER_EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);

/// 每核用户任务退出码（M8-A 自检 28：双核并发任务各自落证；
/// 以终结时所在核槽位索引——确定性自检钉扎派发，槽位即任务身份）。
static USER_EXIT_CODES: [AtomicU64; MAX_CPUS] =
    [AtomicU64::new(u64::MAX), AtomicU64::new(u64::MAX)];

/// 读取用户任务退出码（u64::MAX = 尚未退出）。
pub fn user_exit_code() -> u64 {
    USER_EXIT_CODE.load(Ordering::Relaxed)
}

/// 读取每核退出码快照（M8-A 自检 28 断言面）。
pub fn user_exit_codes() -> (u64, u64) {
    (
        USER_EXIT_CODES[0].load(Ordering::Acquire),
        USER_EXIT_CODES[1].load(Ordering::Acquire),
    )
}

/// 系统调用计数（自检 14 断言）：LOG / YIELD / 其他。
static SC_LOG: AtomicU64 = AtomicU64::new(0);
static SC_YIELD: AtomicU64 = AtomicU64::new(0);
static SC_OTHER: AtomicU64 = AtomicU64::new(0);

/// 系统调用计数快照。
pub fn syscall_counts() -> (u64, u64, u64) {
    (
        SC_LOG.load(Ordering::Relaxed),
        SC_YIELD.load(Ordering::Relaxed),
        SC_OTHER.load(Ordering::Relaxed),
    )
}

/// 优先级系统调用取证（M8-C 自检 30）：最近一次 SET 的生效级 +
/// 最近一次 GET 的返回值。
static PRIO_SET_STAMP: AtomicU64 = AtomicU64::new(u64::MAX);
static PRIO_GET_STAMP: AtomicU64 = AtomicU64::new(u64::MAX);

/// 设置当前任务的调度优先级（SYS_SET_PRIO 慢路径；自调节语义，
/// 越界钳制到 [0, PRIO_LEVELS)）。返回生效级。
pub fn set_current_prio(level: u64) -> u64 {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    let mut s = SCHED.lock();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    let prio = level.min((PRIO_LEVELS - 1) as u64) as u8;
    if let Some(t) = s.tasks.get_mut(cur).and_then(|slot| slot.as_mut()) {
        t.prio = prio;
        t.base_prio = prio; // M9-C：用户设定级 = 基准级（衰减目标同步迁移）
    }
    PRIO_SET_STAMP.store(prio as u64, Ordering::Release);
    prio as u64
}

/// 读取当前任务的调度优先级（SYS_GET_PRIO 慢路径）。
pub fn current_prio() -> u64 {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    let s = SCHED.lock();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    let prio = s
        .tasks
        .get(cur)
        .and_then(|t| t.as_ref())
        .map_or(PRIO_NORMAL as u64, |t| t.prio as u64);
    PRIO_GET_STAMP.store(prio, Ordering::Release);
    prio
}

/// 优先级取证快照（自检 30 断言面）：(SET 生效级, GET 返回值)。
pub fn prio_stamps() -> (u64, u64) {
    (
        PRIO_SET_STAMP.load(Ordering::Acquire),
        PRIO_GET_STAMP.load(Ordering::Acquire),
    )
}

/// 系统调用计数递增（syscall.rs 调用）。
pub fn count_syscall(kind: u8) {
    match kind {
        0 => _ = SC_LOG.fetch_add(1, Ordering::Relaxed),
        1 => _ = SC_YIELD.fetch_add(1, Ordering::Relaxed),
        _ => _ = SC_OTHER.fetch_add(1, Ordering::Relaxed),
    }
}

/// 调用方任务的能力槽号（syscall.rs 能力门禁读取）。
#[allow(dead_code)] // M6-B 接线后移除：SYS_IPC_* 能力门禁即将消费
pub fn current_cap_slot() -> usize {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    let s = SCHED.lock();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    s.tasks
        .get(cur)
        .and_then(|t| t.as_ref())
        .map_or(0, |t| t.cap_slot)
}

/// 调用方任务槽位号（pid；M9-A 进程模型）。
pub fn current_task_id() -> usize {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    CURRENT[cpu].load(Ordering::Relaxed)
}

/// 目标任务的父任务槽位（M9-A 授权门禁；不存在或无父 = None）。
pub fn task_parent(id: usize) -> Option<usize> {
    let _w = IntWindow::new();
    let s = SCHED.lock();
    s.tasks
        .get(id)
        .and_then(|t| t.as_ref())
        .and_then(|t| t.parent)
}

/// 在调度锁窗口内访问目标任务句柄表（M9-A 句柄生命周期操作面）。
/// 任务不存在返回 None；闭包返回值透传。
pub fn with_task_handles<R>(
    id: usize,
    f: impl FnOnce(&mut [Option<usize>; HANDLE_MAX]) -> R,
) -> Option<R> {
    let _w = IntWindow::new();
    let mut s = SCHED.lock();
    s.tasks
        .get_mut(id)
        .and_then(|t| t.as_mut())
        .map(|t| f(&mut t.handles))
}

/// 目标任务的主身份能力槽号（M9-A 撤销保护面；不存在 = None）。
pub fn cap_slot_of(id: usize) -> Option<usize> {
    let _w = IntWindow::new();
    let s = SCHED.lock();
    s.tasks.get(id).and_then(|t| t.as_ref()).map(|t| t.cap_slot)
}

/// 自检 26 取证：最近一次用户 LOG 系统调用的服务核与本核 TSS.RSP0。
static LOG_CPU_STAMP: AtomicUsize = AtomicUsize::new(usize::MAX);
/// 自检 26 取证：LOG 服务时本核 TSS.RSP0（应等于该用户任务内核栈顶）。
static LOG_RSP0_STAMP: AtomicU64 = AtomicU64::new(0);
/// 自检 26 取证：LOG 服务时本核 per-CPU syscall 栈（与 RSP0 同源同值）。
static LOG_KSTACK_STAMP: AtomicU64 = AtomicU64::new(0);
/// 自检 28 取证：LOG 服务核位图（bit0 = BSP、bit1 = AP；M8-A 双核并发面）。
static LOG_CPU_MASK: AtomicUsize = AtomicUsize::new(0);

/// syscall 派发器 LOG 路径调用：记录服务核 + 本核 RSP0 + 本核调用栈
/// （三戳同源：TSS.RSP0 与 PERCPU 槽由同一 prepare_dispatch 写入）。
pub fn note_log_cpu() {
    let cpu = my_cpu();
    LOG_CPU_STAMP.store(cpu, Ordering::Release);
    LOG_RSP0_STAMP.store(ostd::hw::gdt::rsp0(cpu), Ordering::Release);
    LOG_KSTACK_STAMP.store(
        LUMINA_PERCPU_KSTACK[cpu].load(Ordering::Relaxed),
        Ordering::Release,
    );
    // 服务核位图（M8-A 自检 28：双核并发 LOG 各自落位，bit0+bit1 == 0b11）
    LOG_CPU_MASK.fetch_or(1 << cpu, Ordering::AcqRel);
}

/// 读取 LOG 取证戳：(服务核, 本核 RSP0, 本核 per-CPU 调用栈)。
pub fn log_stamp() -> (usize, u64, u64) {
    (
        LOG_CPU_STAMP.load(Ordering::Acquire),
        LOG_RSP0_STAMP.load(Ordering::Acquire),
        LOG_KSTACK_STAMP.load(Ordering::Acquire),
    )
}

/// per-CPU 调试面（自检 26 取证）：(kstack[0], kstack[1], rsp0(0), rsp0(1))。
pub fn percpu_debug() -> (u64, u64, u64, u64) {
    (
        LUMINA_PERCPU_KSTACK[0].load(Ordering::Relaxed),
        LUMINA_PERCPU_KSTACK[1].load(Ordering::Relaxed),
        ostd::hw::gdt::rsp0(0),
        ostd::hw::gdt::rsp0(1),
    )
}

/// 清零用户任务取证面（LOG 戳/位图 + 退出码；跨自检隔离，防陈旧值误判）。
pub fn reset_user_evidence() {
    LOG_CPU_STAMP.store(usize::MAX, Ordering::Release);
    LOG_RSP0_STAMP.store(0, Ordering::Release);
    LOG_KSTACK_STAMP.store(0, Ordering::Release);
    LOG_CPU_MASK.store(0, Ordering::Release);
    USER_EXIT_CODE.store(u64::MAX, Ordering::Relaxed);
    for slot in &USER_EXIT_CODES {
        slot.store(u64::MAX, Ordering::Release);
    }
    PRIO_SET_STAMP.store(u64::MAX, Ordering::Release);
    PRIO_GET_STAMP.store(u64::MAX, Ordering::Release);
}

/// 读取 LOG 服务核位图（M8-A 自检 28 断言面）。
pub fn log_cpu_mask() -> usize {
    LOG_CPU_MASK.load(Ordering::Acquire)
}

/// 终结当前任务（系统调用 EXIT 路径）：记录退出码 → 标记终结 →
/// 切换到下一就绪任务或 idle（永不返回）；两者皆无则停机等待唤醒。
pub fn exit_current(code: u64) -> ! {
    USER_EXIT_CODE.store(code, Ordering::Relaxed);
    // 每核槽位（M8-A 自检 28）：终结发生在终结者所在核，钉扎派发下
    // 槽位即任务身份；自由派发时取「最后终结者所在核」语义（取证面）。
    let cpu = my_cpu();
    USER_EXIT_CODES[cpu].store(code, Ordering::Release);
    finish_and_switch_away()
}

/// 终结切出（任务入口返回路径与 EXIT 共用）：不回队，直接切换。
fn finish_and_switch_away() -> ! {
    let mut w = IntWindow::new();
    loop {
        let cpu = my_cpu();
        let pair = {
            let mut s = SCHED.lock();
            let sc = &mut *s;
            let cur = CURRENT[cpu].load(Ordering::Relaxed);
            if cur == IDLE {
                None
            } else {
                // M9-A 句柄生命周期收口：终结前全表清算（全局槽逐个撤销
                // 归还能力表）。锁序契约：SCHED → CAPS 单向嵌套（反向
                // 嵌套在全内核不存在，见 proc.rs 模块文档）。
                if let Some(t) = sc.tasks[cur].as_mut() {
                    t.revoke_all_handles();
                    t.state = State::Finished;
                }
                match pick_best(&mut sc.ready, &sc.tasks, cpu, IDLE, None) {
                    Some(id) => {
                        remove_value(&mut sc.ready, id);
                        if let Some(t) = sc.tasks[id].as_mut() {
                            t.state = State::Running;
                            t.used_ticks = 0;
                        }
                        CURRENT[cpu].store(id, Ordering::Relaxed);
                        let boot = sc.boot_cr3;
                        if let Some(t) = sc.tasks[id].as_ref() {
                            prepare_dispatch(t, boot, cpu);
                        }
                        Some(slots_pair(sc, cur, id))
                    }
                    None => None,
                }
            }
        };
        match pair {
            Some(p) => switch_deferred(p), // 终结任务永不在此返回
            None => {
                // 无就绪者：本核 idle 可用则切回 idle（终结路径一次性切换，
                // 此后本任务永不被拾取）；否则短暂开中断等节拍后重试。
                let idle_ok = IDLE_VALID[cpu].load(Ordering::Acquire);
                if idle_ok {
                    // SAFETY: 前置条件 —— IDLE_VALID[cpu] 已置位（idle 循环
                    //          已进入，idle 栈存活）；cur 槽位占用且已终结。
                    // 不变式 —— idle 上下文本核独占；切换后本代码不再续跑。
                    // 并发 —— 本核串行；任务槽已从队列剔除（Finished 不可拾取）。
                    // 违反后果 —— 指针失效即写穿任意内存（槽位纪律封死）。
                    unsafe {
                        let idle = &mut *core::ptr::addr_of_mut!(IDLE_CTX[cpu]);
                        let mut s = SCHED.lock();
                        let cur = CURRENT[cpu].load(Ordering::Relaxed);
                        if let Some(t) = s.tasks[cur].as_mut() {
                            let pair = SwitchPair::from(&mut t.ctx, idle);
                            drop(s);
                            switch_deferred(pair);
                        }
                    }
                    // 切回 idle 后本行不可达（Finished 永不恢复）
                    loop {
                        ostd::hw::intr::halt();
                    }
                }
                drop(w);
                ostd::hw::intr::enable();
                ostd::hw::intr::halt();
                w = IntWindow::new();
            }
        }
    }
}

/// 内核任务跳板：标记运行 → 调入口 → 标记终结 → 终结切出。
extern "C" fn trampoline() -> ! {
    // 首派发若经抢占路径切入则 IF=0；内核任务 IF 约定恒为 1
    ostd::hw::intr::enable();
    let entry: Entry = {
        let s = SCHED.lock();
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        s.tasks[cur].as_ref().map_or(main_entry_stub, |t| t.entry)
    };
    entry();
    finish_and_switch_away()
}

/// 用户任务跳板：读桥函数 → 进 ring3（永不返回；终结经 EXIT 系统调用）。
extern "C" fn trampoline_user() -> ! {
    // 首派发若经抢占路径切入则 IF=0；进 ring3 前先开放（iretq 亦会置 IF）
    ostd::hw::intr::enable();
    let entry: Entry = {
        let s = SCHED.lock();
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        s.tasks[cur].as_ref().map_or(main_entry_stub, |t| t.entry)
    };
    let _ = entry;
    let bridge = USER_ENTRY_BRIDGE.load(Ordering::Acquire);
    debug_assert_ne!(bridge, 0, "user entry bridge must be registered");
    if bridge == 0 {
        finish_and_switch_away();
    }
    // SAFETY: 前置条件 —— 地址来自 set_user_entry_bridge 存入的
    //          extern "C" fn() -> !；注册先于任何用户任务派发。
    // 不变式 —— Release/Acquire 配对；注册只发生一次。
    // 并发 —— 用户任务钉扎 CPU0（M6 契约）；首次派发前完成注册。
    // 违反后果 —— 跳转伪造地址即任意代码执行（初始化纪律封死）。
    let f: extern "C" fn() -> ! = unsafe { core::mem::transmute(bridge) };
    f()
}

/// 抢占使能开关（自检 12 开启；协作演示窗口临时关闭）。
pub fn set_preempt_enabled(on: bool) {
    PREEMPT_ENABLED.store(on, Ordering::Release);
}

/// 抢占统计快照（自检取证；跨核合计）。
pub fn preempt_stats() -> (u64, u64) {
    let _w = IntWindow::new();
    let s = SCHED.lock();
    (s.preempt_switches, s.cooperative_switches)
}

/// LAPIC 定时器钩子（注册进 ostd::interrupt::stubs；本核 IRQ 0x41 窗口内调用）。
///
/// 返回 true = 已填写 plan（桩随即从栈上计划完成抢占交换）。
/// 放行条件：抢占未使能 / 本核 idle / 队列无可运行者 / 时间片未满。
pub fn timer_hook(plan: &mut PreemptPlan) -> bool {
    if !PREEMPT_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    // 本钩子在 LAPIC 定时器 IRQ 窗口内执行（IF=0）；切换窗口已被 cli
    // 物理遮蔽，无需守卫检查。锁临界区对持锁者不可见（其已被本核中断打断）。
    let cpu = my_cpu();
    let mut s = SCHED.lock();
    let sc = &mut *s;
    // M9-C：老化扫描先行（每 tick 对全部就绪任务计账/提升，与抢占判定解耦：
    // idle 核与不可派发窗口同样推进——等待时间与谁在运行无关）
    aging_pass(&mut sc.ready, &mut sc.tasks);
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    if cur == IDLE || !eligible(&sc.tasks, cur, cpu) {
        return false;
    }
    let Some(t) = sc.tasks[cur].as_mut() else {
        return false;
    };
    // M8-C 抢占规则：① 高优先就绪者抢前（严格高于当前，无视量子）；
    // ② 量子到期同级（及以下）轮转。
    let cur_prio = t.prio;
    if t.used_ticks < QUANTUM_TICKS {
        t.used_ticks += 1;
        // 抢前判定：自 0 级扫至 cur_prio-1（严格更高）
        let Some(next) = pick_best(&mut sc.ready, &sc.tasks, cpu, cur, Some(cur_prio)) else {
            return false;
        };
        remove_value(&mut sc.ready, next);
        // 被抢占者按基准级回队（遗漏即任务从队列蒸发——开发期实测挂死；
        // M9-C：衰减回 base_prio 并清等待计账，老化提升不跨运行期保留）
        let cur_prio = sc.tasks[cur].as_ref().map_or(PRIO_NORMAL, |t| t.base_prio);
        enqueue(&mut sc.ready, cur, cur_prio);
        if let Some(t) = sc.tasks[cur].as_mut() {
            t.prio = cur_prio;
            t.state = State::Ready;
            t.used_ticks = 0;
            t.waited = 0;
        }
        if let Some(t) = sc.tasks[next].as_mut() {
            t.state = State::Running;
            t.used_ticks = 0;
        }
        CURRENT[cpu].store(next, Ordering::Relaxed);
        sc.preempt_switches += 1;
        let boot = sc.boot_cr3;
        if let Some(t) = sc.tasks[next].as_ref() {
            prepare_dispatch(t, boot, cpu);
        }
        let (lo, hi) = if cur < next { (cur, next) } else { (next, cur) };
        let (l, r) = sc.tasks.split_at_mut(hi);
        let (old_slot, new_slot) = if cur < next {
            (&mut l[lo], &mut r[0])
        } else {
            (&mut r[0], &mut l[lo])
        };
        match (old_slot.as_mut(), new_slot.as_mut()) {
            (Some(o), Some(n)) => {
                plan.old = &mut o.ctx;
                plan.new = &mut n.ctx;
                true
            }
            _ => false,
        }
    } else {
        t.used_ticks = 0;
        // 时间片到：轮转拾取目标（不移除；找不到则放行——保持队列完整）
        let Some(next) = pick_best(&mut sc.ready, &sc.tasks, cpu, cur, None) else {
            return false;
        };
        remove_value(&mut sc.ready, next);
        // 量子到期路径同样衰减回 base（M9-C 老化语义一致性）
        let cur_prio = sc.tasks[cur].as_ref().map_or(PRIO_NORMAL, |t| t.base_prio);
        enqueue(&mut sc.ready, cur, cur_prio);
        if let Some(t) = sc.tasks[cur].as_mut() {
            t.prio = cur_prio;
            t.state = State::Ready;
            t.used_ticks = 0;
            t.waited = 0;
        }
        if let Some(t) = sc.tasks[next].as_mut() {
            t.state = State::Running;
            t.used_ticks = 0;
        }
        CURRENT[cpu].store(next, Ordering::Relaxed);
        sc.preempt_switches += 1;
        let boot = sc.boot_cr3;
        if let Some(t) = sc.tasks[next].as_ref() {
            prepare_dispatch(t, boot, cpu);
        }
        // 稳定指针萃取（定容槽位表 + 中断窗口内无并发分配）
        let (lo, hi) = if cur < next { (cur, next) } else { (next, cur) };
        let (l, r) = sc.tasks.split_at_mut(hi);
        let (old_slot, new_slot) = if cur < next {
            (&mut l[lo], &mut r[0])
        } else {
            (&mut r[0], &mut l[lo])
        };
        match (old_slot.as_mut(), new_slot.as_mut()) {
            (Some(o), Some(n)) => {
                plan.old = &mut o.ctx;
                plan.new = &mut n.ctx;
                true
            }
            _ => false,
        }
    }
}
