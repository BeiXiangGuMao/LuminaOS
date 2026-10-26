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
//!   （有效级）分离——就绪等待每 tick 计账（`waited`），跨 [`AGE_TICKS`]
//!   阈值且级 > 0 时逐级提升（3→2→1→0）并重置计账；**回队时衰减回
//!   base**（每次重新入队都从用户设定级起步，避免提升永久化）。饥饿消除论证：
//!   任意就绪任务至多 `3×AGE_TICKS` tick 后升至 0 级，与同级任务 FIFO
//!   轮转竞争，量子到期路径必可达——每核饱和的高优先负载不再永久
//!   压制低优先任务（M8-C 已知限制解除）。
//! - **per-CPU tick 账户与全上下文抢占（M10-A）**：时间面（计账/老化/
//!   抢占）自 LAPIC 定时器迁址 **PIT 墙钟钩子**（[`wall_hook`]）——
//!   LAPIC 定时器在 ring3 驻留期间被 prepare_dispatch 屏蔽（TCG 双异常
//!   交付缺陷族规避，S31 记档），旧形态下 ring3 驻留 = 计账/老化/抢占
//!   全冻结（双核皆 ring3 时全系统时间面停摆）；PIT 实测交付不触发
//!   缺陷族 → PIT 桩加装 PreemptPlan 交换路径（接收核抢占）+ 对侧核
//!   经 PREEMPT_REQ 旗 + RESCHED-plan 送达（交付实测安全）——三抢占源
//!   （LAPIC 内核态/PIT 全上下文/RESCHED 请求驱动）全就位，ring3 时间
//!   面冻结窗口消除。**ISR 分层**：墙钟钩子极短化（零锁原子计账 +
//!   量子检测 → PREEMPT_REQ + 定向 RESCHED），抢占执行统一移交
//!   RESCHED 抢占钩子（ring3 唯一执行器，交付实测安全）；老化主站
//!   = LAPIC 钩子（内核上下文），RESCHED 钩子兜底（全核 ring3 饱和
//!   场景按 RESCHED 节拍推进）。
//!   （M10 开发期实测：墙钟钩子初版含 SCHED 锁 + 老化扫描——长 ISR
//!   交付 ring3 边缘复现 S31 缺陷族 #GP(0x28) VM 位入旗， isr_timer
//!   内 iretq 处取证——故有极短化分层纪律。）
//! - **任务阻塞态与调度点切换（M10-B）**：`State::Blocked` +
//!   [`block_current_unless`]/[`block_current_waitpid`]（登记等待对象 →
//!   Blocked → 锁窗探针 → 切换下一任务，M12-C 起全族探针化）+
//!   [`wake_tasks`]（谓词匹配批量唤醒入队）——#PF 换入路径阻塞化
//!   （vmm：swapd 在线时故障方阻塞等待异步换入完成，同步回退严格
//!   保留），单核/全核饱和场景的换页时延补齐（M9-B 已知约束解除）。
//!   终结态改为 `State::Zombie`（留证待收割；M10-C waitpid 消费）。
//! - **waitpid 语义雏形（M10-C）**：SYS_WAIT_PID(12)——父任务阻塞等待
//!   直接子任务终结并收割退出码（[`wait_scan`] 单锁窗口原子扫描+收割，
//!   槽位释放回收）；EXIT 路径唤醒 Child 等待者。错误码扩至
//!   8 = ERR_CHILD。
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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ostd::interrupt::PreemptPlan;
use ostd::sync::{SpinGuard, SpinLock};
use ostd::task::{switch_deferred, SwitchPair, TaskContext};

/// 任务内核栈大小：16 KiB。
const STACK_BYTES: usize = 16 * 1024;
/// 栈底 canary 魔数（M18-① 取证面：ASCII "LUMINACN"）。任务栈从高位
/// 向下生长，栈底首四字永不入帧——溢出/越界写最先命中此处。盖章点 =
/// 任务栈分配（Task::new，Kernel/User 同源）+ AP 引导栈（smp）；
/// 校验点 = 派发咽喉（prepare_dispatch，五条派发路径唯一收口）+
/// 全表审计（t59）。pub 供 smp 同源盖章。
pub const STACK_CANARY: u64 = 0x4C55_4D49_4E41_434E;
/// canary 破坏计数（自检 t59 断言 + 串口诊断；只增不减，日志去重由
/// 调用侧负责任何场景下不刷屏——破坏本身即异常路径）。
static CANARY_VIOLATIONS: AtomicU64 = AtomicU64::new(0);
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
/// M10 重核算：阻塞面 + 僵尸留证（waitpid 收割前占槽）抬升并发上界，
/// 32 → 48（静态占用 ≈ 10 KiB；Task 栈为堆分配，槽位表仅承载元数据）。
const MAX_TASKS: usize = 48;
/// 每任务句柄表容量（M9-A；句柄 0 = NULL 保留，1..HANDLE_MAX 可用）。
/// M14-② 首审：8 → 16（文件面 fd 与通道/授予句柄共享命名空间后，
/// 8 槽吃紧——统一句柄面叠加用量实测抬升；TCB 内联表 16×8B/任务，
/// MAX_TASKS=48 下静态增量 ≈ 3 KiB，可忽略）。
pub const HANDLE_MAX: usize = 16;
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
    /// 阻塞等待中（不在就绪队列；仅 [`wake_tasks`]/终结唤醒面可达）。
    Blocked,
    /// 已终结留证（退出码已登记，等待 waitpid 收割释放槽位）。
    Zombie,
}

/// 阻塞等待对象（M10-B/C）：登记于 [`Task::wait`]，唤醒面按值匹配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitWhat {
    /// 换页：等待 (root, va) 的异步换入完成（swapd 唤醒，M10-B）。
    Swap {
        /// 页表根物理地址。
        root: u64,
        /// 页对齐虚拟地址。
        va: u64,
    },
    /// 进程间等待：等待直接子任务终结（pid = 0 任意子任务，M10-C）。
    Child {
        /// 目标子任务 pid（0 = 任意）。
        pid: usize,
    },
    /// IPC 阻塞接收（M11-C）：等待目标通道推送帧（发送方 wake_tasks
    /// 唤醒；endpoint = 通道 id，与 CHANNELS 槽位同域）。
    IpcRecv {
        /// 目标通道 id。
        endpoint: usize,
    },
    /// timer 阻塞源（M13-②；**M15-③ TSC 纳秒面**）：等待 TSC 单调纳秒
    /// 时刻到达 deadline（[`ostd::time::tsc_clock::now_ns`] 同源计数；
    /// wall_hook 到期扫描 + tickd wake_tasks 唤醒——swap/waitpid/ipc
    /// 之外的第三类阻塞源，探针化同族）。
    Timer {
        /// 到期 deadline（TSC 纳秒时刻；v0.14–v0.15 为全局节拍数，
        /// v0.16 单位变更如实记档）。
        deadline: u64,
    },
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
    /// 内核栈底绝对地址（M18-① canary 盖章槽；0 = 无 canary——主任务
    /// 引导栈无堆分配锚点，不纳入校验面，如实记档）。
    stack_base: u64,
    /// 用户页表根物理地址（仅用户任务使用；内核任务恒为 0）。
    user_root: u64,
    /// 类别。
    kind: Kind,
    /// 调度保存/恢复的寄存器面。
    ctx: TaskContext,
    /// 状态。
    state: State,
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
    /// 句柄描述符旗标（M15-② 句柄面深化）：与 `handles` 同域并行的
    /// per-handle 旗标字节（bit0 = `bedrock::abi::FD_CLOEXEC`）。旗标
    /// 随句柄生命周期：F_SETFD 置位、close/revoke 清除、EXEC 成功路径
    /// 消费关闭；首次安装恒 0（Task::new 零化 + 关闭面清理保证无陈值
    /// 继承——首空闲位复用只发生在 close/revoke 之后）。
    hflags: [u8; HANDLE_MAX],
    /// 调度优先级（0=最高 … 3=最低；有效级，M9-C 老化提升可临时高于 base）。
    prio: u8,
    /// 基准优先级（M9-C：用户设定级；回队衰减目标，SET_PRIO 写入面）。
    base_prio: u8,
    /// 就绪队列等待计账（tick 数；M9-C 老化阈值判定）。
    waited: u32,
    /// 阻塞等待对象（M10-B：Blocked 态非空；唤醒时清除）。
    wait: Option<WaitWhat>,
    /// 退出码（M10-C：Zombie 态有效；u64::MAX = 入口返回路径的无码终结）。
    exit_code: u64,
    /// 内核任务期望 CR3（M10-B：0 = 引导根；借用户根执行读回等窗口时
    /// 由 [`set_current_kernel_cr3`] 登记——派发面按任务恢复期望根，
    /// 修复「借根窗口被 PIT 抢占 → 恢复点落引导根 → 后继访存致命
    /// #PF」的根因（M9 靠 timer_mask 屏蔽遮挡，M10 的 PIT 不可屏蔽）。
    kernel_cr3: u64,
    /// Linux ABI 标志（M33-L1）：ELF 链装载的任务 = true，派发器头部
    /// 按此分流至 `kernel::linux::lin_dispatch`（号域原生重叠，不按
    /// 号判源——单号域双语义 = 误判源）。
    lin_abi: bool,
}

impl Task {
    /// 以入口创建新内核任务。
    fn new(name: &'static str, entry: Entry, trampoline: extern "C" fn() -> !) -> Self {
        let stack = alloc::vec![0u128; STACK_BYTES / size_of::<u128>()];
        let base = stack.as_ptr() as u64;
        let top = base + STACK_BYTES as u64;
        // M18-①：栈底 canary 盖章（恒等映射低 1 GiB，write_u64 即写栈
        // 首 qword 低 8 字节——该四字在栈向下生长语义下永不入帧）。
        ostd::hw::phys::write_u64(base, STACK_CANARY);
        Self {
            name,
            stack,
            stack_top: top,
            stack_base: base,
            user_root: 0,
            kind: Kind::Kernel,
            ctx: TaskContext::boot_new(top, trampoline),
            state: State::Ready,
            entry,
            pinned: None,
            cap_slot: 0,
            parent: None,
            handles: [None; HANDLE_MAX],
            prio: PRIO_NORMAL,
            base_prio: PRIO_NORMAL,
            waited: 0,
            wait: None,
            exit_code: u64::MAX,
            kernel_cr3: 0,
            hflags: [0; HANDLE_MAX],
            lin_abi: false,
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
        // M22-③ 第二项：遗传细胞 ctx 焊接（r14 注入竞态根治——round-585/664
        // 实录：旧形态首派发窗口桥面读 CURRENT 定细胞，任一微窗读偏 →
        // r14=0 → 子代走根父分支级联派生）。细胞值在任务创建时点（锁窗内、
        // 入队前）焊入 ctx；首次派发切换机器按 callee-saved 语义自然装载
        // 进 CPU r14，trampoline 与入口点同窗取值传参——派发侧读面单一。
        t.ctx.r14 = parent.map_or(0, |p| p as u64);
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
        // M15-②：句柄随任务终结全撤后，注册表中已无能力引用的文件对象
        // 就地回收（dup/开放句柄跨终结的引用计数收敛面；SCHED → FILES
        // → CAPS 单向链，无反向边）。
        crate::vfs::reap_orphaned_files();
    }

    /// 主任务槽（运行在引导栈上）。
    const fn main_task() -> Self {
        Self {
            name: "main",
            stack: Vec::new(),
            stack_top: 0,
            stack_base: 0,
            user_root: 0,
            kind: Kind::Kernel,
            ctx: TaskContext::stopped(),
            state: State::Running,
            entry: main_entry_stub,
            pinned: Some(0),
            cap_slot: 0,
            parent: None,
            handles: [None; HANDLE_MAX],
            hflags: [0; HANDLE_MAX],
            prio: PRIO_NORMAL,
            base_prio: PRIO_NORMAL,
            waited: 0,
            wait: None,
            exit_code: u64::MAX,
            kernel_cr3: 0,
            lin_abi: false,
        }
    }
}

/// 主任务入口占位（主任务从不经 trampoline 进入；永不调用）。
fn main_entry_stub() {}

/// 调度器全局状态（受 [`SCHED`] 保护）。pub(crate)：sched_lock_at
/// 取证包装的返回签名（M19-①）。
pub(crate) struct Scheduler {
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
/// idle 收割工作桥（M12-d 注册：孤儿僵尸自动收割；返回是否有产出）。
static IDLE_REAP: AtomicUsize = AtomicUsize::new(0);

/// 注册 idle 收割工作（M12-d 僵尸收割运行时化；仅 main 初始化调用）。
pub fn set_idle_reap(f: fn() -> bool) {
    IDLE_REAP.store(f as usize, Ordering::Release);
}

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
/// 三约束：`pinned`（静态钉扎）、`bound`（系统调用期间的动态绑定）与
/// `SWITCHING`（M11-D 握手旗——现场保存未完成者不可拾取，跨核拾取
/// 窗口根治的拾取侧门禁）。
fn eligible(tasks: &[Option<Task>; MAX_TASKS], id: usize, cpu: usize) -> bool {
    tasks
        .get(id)
        .and_then(|t| t.as_ref())
        .is_some_and(|t| t.pinned.is_none_or(|c| c == cpu))
        && SWITCHING[id].load(Ordering::Acquire) == 0
}

/// 内核 `.text` 界（linker.ld PROVIDE 符号 `.text` 段首/尾；M21-② 哨兵用）。
fn ktext_bounds() -> (u64, u64) {
    extern "C" {
        static ktext_start: u8;
        static ktext_end: u8;
    }
    // SAFETY: 前置条件 —— ktext_start/ktext_end 由 linker.ld PROVIDE
    //          （.text 段 ALIGN(4096) 首尾），链接期地址恒定。
    // 不变式 —— 仅取地址不读取本体（零尺寸符号约定）；地址域为内核
    //          恒等映射 1 MiB 段，启动后不变。
    // 并发 —— 链接期常量，只读无竞争。
    // 违反后果 —— 符号缺失即链接期报错（无运行期风险）。
    (
        core::ptr::addr_of!(ktext_start) as usize as u64,
        core::ptr::addr_of!(ktext_end) as usize as u64,
    )
}

// ---- M22-③ 合法续点全集（cont 写者追捕 v2：白名单哨兵）----
/// 合法 `ctx.cont` 仅三类：①协作保存 = `call lumina_context_switch`
/// 站点 +5（直呼站点有限，init 期逐字节扫描 ktext 自动收集）；
/// ②抢占保存 = 三桩 `.resume` 全局标签（ostd 导出）；③新建 =
/// 双 trampoline（boot_new 写入面）。
/// 0x135c6c #GP@kmain 族（round-582/647 三重同指纹）实证：cont 可被
/// 写成 ktext 界内的栈残渣（translate 中段陈旧中断帧 RIP），M21-②
/// 区间校验必然放行——白名单在网后此类腐坏于拾取瞬间落网。
static RESUME_CONTS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static RESUME_CONT_N: AtomicUsize = AtomicUsize::new(0);
/// M22-③ [B] 猎场扩网 v2：三桩 .resume 单独记档（恢复面帧哨兵布防判据
/// ——仅桩 .resume 走保存帧 iretq 消费链；协作站点/trampoline 不适用）。
static STUB_RESUMES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// init 期收集合法续点全集（单核启动早期调用，先于任何拾取）。
fn init_resume_set() {
    let lcs = ostd::task::context_switch_addr() as i64;
    let (ts, te) = ktext_bounds();
    let mut n = 0usize;
    // ① 协作站点扫描：E8/E9 rel32 → 目标 == lumina_context_switch
    let mut a = ts;
    while a + 5 <= te {
        // SAFETY: 前置条件 —— ktext 恒等映射代码段，启动后只读。
        // 不变式 —— 界来自 linker PROVIDE；逐字节读无副作用。
        // 并发 —— init 单核早期，无并发写者。
        // 违反后果 —— 界错即读自身映像，无越权面（fail-safe）。
        let op = unsafe { core::ptr::read(a as *const u8) };
        if op == 0xE8 || op == 0xE9 {
            let rel = unsafe { core::ptr::read((a + 1) as *const i32) } as i64;
            if a as i64 + 5 + rel == lcs && n < RESUME_CONTS.len() {
                RESUME_CONTS[n].store(a + 5, Ordering::Release);
                n += 1;
            }
        }
        a += 1;
    }
    // ② 三桩 .resume + ③ 双 trampoline（[B] 猎场：桩续点同步入 STUB_RESUMES）
    let mut sn = 0usize;
    for l in ostd::interrupt::stubs::preempt_resume_labels() {
        if n < RESUME_CONTS.len() {
            RESUME_CONTS[n].store(l as u64, Ordering::Release);
            n += 1;
        }
        if sn < STUB_RESUMES.len() {
            STUB_RESUMES[sn].store(l as u64, Ordering::Release);
            sn += 1;
        }
    }
    for t in [
        trampoline as *const () as usize,
        trampoline_user as *const () as usize,
    ] {
        if n < RESUME_CONTS.len() {
            RESUME_CONTS[n].store(t as u64, Ordering::Release);
            n += 1;
        }
    }
    RESUME_CONT_N.store(n, Ordering::Release);
    // init 记档：集合规模与成员（ktext 扫描自证，与 ELF 反汇编对账面）
    let mut serial = crate::console::SerialPort::com1();
    serial.init();
    let _ = core::fmt::Write::write_fmt(&mut serial, format_args!("sched: resume-set n={n}"));
    let mut i = 0;
    while i < n {
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(" {:#x}", RESUME_CONTS[i].load(Ordering::Acquire)),
        );
        i += 1;
    }
    let _ = core::fmt::Write::write_fmt(&mut serial, format_args!("\n"));
}

/// cont 是否属于合法续点全集（线性扫 16 槽，拾取面热路径可承受）。
fn cont_in_resume_set(cont: u64) -> bool {
    let n = RESUME_CONT_N.load(Ordering::Acquire);
    let mut i = 0;
    while i < n {
        if RESUME_CONTS[i].load(Ordering::Acquire) == cont {
            return true;
        }
        i += 1;
    }
    false
}

/// cont 是否为三桩 .resume 之一（任务将走保存帧 iretq 消费链——
/// 恢复面帧哨兵的唯一适用面）。
fn cont_is_stub_resume(cont: u64) -> bool {
    STUB_RESUMES
        .iter()
        .any(|s| s.load(Ordering::Acquire) == cont)
}

/// M21-② 切换目标上下文哨兵（cont 写者追捕——哨兵在网；M22-③ 白名单升级）。
///
/// 拾取面在构建切换对/抢占计划**之前**校验目标 `ctx` 合法性：
/// ① `cont` 必须落在内核 `.text` 界内（`ktext_start..ktext_end`）——
///    0（stopped 陈值）/ u64::MAX（round-432 标本族 -1 注入）/ 栈与堆
///    地址一律违例；
/// ② `rsp` 必须落在本任务**自有**内核栈界内（`stack_base != 0` 时强制，
///    闭区间 `stack_base..=stack_top`——boot_new 初值恰为栈顶；主任务
///    引导栈无堆锚点（stack_base=0）跳过，与 M18-① canary 面同款记档）；
/// ③ **M22-③ 白名单**：`cont` 必须属于合法续点全集
///    （[`RESUME_CONTS`]——协作站点/桩 .resume/trampoline 三类来源，
///    init 期收集）。界内≠合法：0x135c6c 族实证 cont 可被写成 ktext
///    界内的栈残渣，区间校验放行、白名单必捕。
///
/// 任何违例 = 存在切换机器之外的非法 TaskContext 写者（S72 次级窗口
/// 鬼影保存族 / cont 槽腐坏族的活体取证面）——SCHED-BUG 全现场转储
/// （含 ctx 全 8 槽深取证行）后 panic（活体标本优先于静默继续；
/// pf-hunt 串口全量留存）。
fn pickup_sentinel(id: usize, t: &Task) {
    let cont = t.ctx.cont;
    let rsp = t.ctx.rsp;
    let (ts, te) = ktext_bounds();
    let cont_ok = cont >= ts && cont < te;
    let rsp_ok = t.stack_base == 0 || (rsp >= t.stack_base && rsp <= t.stack_top);
    // M22-③ 白名单：ktext 界内 ≠ 合法——cont 必须属于合法续点全集。
    // 集合未武装（n=0，扫描异常面）时退化为纯区间校验（fail-safe，
    // 扫描缺陷不阻断调度）。
    let armed = RESUME_CONT_N.load(Ordering::Acquire) != 0;
    let whitelist_ok = !armed || cont_in_resume_set(cont);
    if !cont_ok || !rsp_ok || !whitelist_ok {
        let mut serial = crate::console::SerialPort::com1();
        serial.init();
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(
                "LUMINA-SCHED-BUG pickup-sentinel slot={} name={} state={:?} cont={:#x} rsp={:#x} stack=[{:#x},{:#x}] ktext=[{ts:#x},{te:#x}) pinned={:?} switching={} cont-ok={} rsp-ok={} whitelist-ok={armed}\n",
                id,
                t.name,
                t.state,
                cont,
                rsp,
                t.stack_base,
                t.stack_top,
                t.pinned,
                SWITCHING[id].load(Ordering::Acquire),
                cont_ok,
                rsp_ok,
            ),
        );
        // M22-③ 深取证：ctx 全 8 槽 + 白名单规模——第二写者指纹面
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(
                "LUMINA-SCHED-BUG ctx slot={} cont={:#x} rbx={:#x} rbp={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x} rsp={:#x} resume-set-n={}\n",
                id,
                t.ctx.cont,
                t.ctx.rbx,
                t.ctx.rbp,
                t.ctx.r12,
                t.ctx.r13,
                t.ctx.r14,
                t.ctx.r15,
                t.ctx.rsp,
                RESUME_CONT_N.load(Ordering::Acquire),
            ),
        );
        panic!("pickup-sentinel: illegitimate TaskContext writer (M21-2/M22-3)");
    }
    // ---- M22-③ [B] 猎场扩网 v2.2：恢复面保存帧哨兵（四标本定案落网点）----
    // 667/705/951/1005 四标本逐槽同形（rip=-1 @ 帧 RIP 槽，cs=0x8，cr2=-1）；
    // ELF 对号：毒化帧址 0xa122f8/0xa12308 均落引导栈 boot_stack
    // [0xa03000,0xa13000) 界内 —— 毒化目标 = **引导栈上主任务/启动语境**
    // 的保存中断帧 RIP 槽。消费链 `mov rsp,[ctx+0x38] → ret → .resume 弹
    // 10 寄存器 → iretq` 最终从此槽弹出。v2.1 盲区 = stack_base==0 跳过
    // 分支（主任务无栈锚）——本版补引导栈锚，主任务帧纳入同网。
    // 注：DR1 动态蹲守栈槽方案已撤——TCG 对热地址数据监视点的命中路径
    // 触发 QEMU 10.0.13 MTTCG BQL 重入断言（bql_lock_impl !bql_locked，
    // smoke-bnet 971/972 双轮实证，首个抢占即 abort）；栈槽写者归因
    // 改由帧哨兵转储面承担（毒化轮帧内容 + 槽位 + rsp 区段）。
    // 栈锚双源：自有栈任务用自身界；主任务（stack_base=0，启动语境）
    // 用引导栈界（boot.rs 符号导出，链接期定址）。
    let (sb, st) = if t.stack_base != 0 {
        (t.stack_base, t.stack_top)
    } else {
        // 主任务栈锚 = 引导栈界（boot.rs 符号导出；usize → u64 同域扩展）
        let (b, tp) = crate::boot::boot_stack_bounds();
        (b as u64, tp as u64)
    };
    if sb != 0 && cont_is_stub_resume(cont) {
        // 帧布局（与三桩同构，serial 证据对账）：ctx.rsp = R0-120，
        // RIP@+0x50 CS@+0x58 RFLAGS@+0x60 RSP@+0x68 SS@+0x70。
        let f = t.ctx.rsp;
        if f < sb || f + 0x70 > st || f & 7 != 0 {
            let mut serial = crate::console::SerialPort::com1();
            serial.init();
            let _ = core::fmt::Write::write_fmt(
                &mut serial,
                format_args!(
                    "LUMINA-FRAME-POISON slot={} name={} kind=frame-outside-stack frsp={f:#x} cont={cont:#x} stack=[{sb:#x},{st:#x}]\n",
                    id,
                    t.name,
                ),
            );
            panic!("pickup-sentinel: saved frame outside own stack (M22-3 resume-face net)");
        }
        // SAFETY: 前置条件 —— f 经栈界全包校验（f..f+0x70 ⊆ 自有内核栈，
        // 内核半区全局映射，任一 CR3 下可读）。不变式 —— 只读不写，零副作用。
        // 并发 —— 拾取面持 SCHED 锁 + M11-D 握手门（保存完成后方可拾取），
        //         帧稳定无并发写者。
        // 违反后果 —— 界错即读自身栈区，无越权面（fail-safe）。
        let rip = unsafe { core::ptr::read_volatile((f + 0x50) as *const u64) };
        let cs = unsafe { core::ptr::read_volatile((f + 0x58) as *const u64) };
        let rfl = unsafe { core::ptr::read_volatile((f + 0x60) as *const u64) };
        // 判据：内核帧（cs=0x8）→ RIP ∈ ktext 且 DF=0（Rust/asm ABI 不变式，
        // 951 帧 rfl=0x10446 含 DF 即毒化指纹）；用户帧（cs=0x1b）→ 查毒化
        // 签名（0/-1）；其余 cs = 已腐坏。
        let frame_ok = match cs {
            0x8 => rip >= ts && rip < te && rfl & 0x400 == 0,
            0x1b => rip != 0 && rip != u64::MAX,
            _ => false,
        };
        if !frame_ok {
            let mut serial = crate::console::SerialPort::com1();
            serial.init();
            let _ = core::fmt::Write::write_fmt(
                &mut serial,
                format_args!(
                    "LUMINA-FRAME-POISON slot={} name={} cont={cont:#x} frsp={f:#x} rip={rip:#x} cs={cs:#x} rfl={rfl:#x} ktext=[{ts:#x},{te:#x})\n",
                    id,
                    t.name,
                ),
            );
            let _ = core::fmt::Write::write_fmt(
                &mut serial,
                format_args!(
                    "LUMINA-FRAME-POISON ctx slot={} cont={:#x} rbx={:#x} rbp={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x} rsp={:#x}\n",
                    id,
                    t.ctx.cont,
                    t.ctx.rbx,
                    t.ctx.rbp,
                    t.ctx.r12,
                    t.ctx.r13,
                    t.ctx.r14,
                    t.ctx.r15,
                    t.ctx.rsp,
                ),
            );
            panic!("pickup-sentinel: poisoned saved frame (M22-3 resume-face net)");
        }
        // 帧合法 → 恢复面收口完成（拾取后即消费，哨兵即最后闸门）。
    }
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

/// per-CPU 忙时账（M10-A 自检 34 断言面）：每核累计忙 tick（CURRENT ≠
/// idle 即计，含 ring3 驻留期间——PIT 全上下文交付，解除旧形态的时间面
/// 冻结）。无门控：账户面无副作用，抢占/老化判定另受 PREEMPT_ENABLED
/// 门控。
static PERCPU_TICKS: [AtomicU64; MAX_CPUS] = [AtomicU64::new(0), AtomicU64::new(0)];

/// per-CPU 当前切片长度（M10-A）：本核当前任务本量子已消耗的 PIT tick 数
/// ——原子镜像（墙钟 ISR 锁自由递增；S31 缺陷族规避：PIT 进 ring3 的
/// ISR 必须极短，不得取 SCHED 锁/触碰任务表）。派发点（execute_switch/
/// yield/block/finish/idle_pick，均在 SCHED 锁窗口内）store(0) 归零。
/// 量子判定面：墙钟钩子（锁自由检测 → PREEMPT_REQ + RESCHED）与
/// RESCHED 抢占钩子（锁内最终判定 → 抢占交换）共享。
static PERCPU_RUN_TICKS: [AtomicU32; MAX_CPUS] = [AtomicU32::new(0), AtomicU32::new(0)];

/// per-CPU 忙时账快照（自检 34 断言面）。
pub fn percpu_ticks() -> (u64, u64) {
    (
        PERCPU_TICKS[0].load(Ordering::Acquire),
        PERCPU_TICKS[1].load(Ordering::Acquire),
    )
}

/// 对侧核抢占请求旗（M10-A）：墙钟钩子判定对侧核当前任务需切换时置位
/// 并发 RESCHED IPI；RESCHED 抢占钩子消费（test-and-clear）。
static PREEMPT_REQ: [AtomicBool; MAX_CPUS] = [AtomicBool::new(false), AtomicBool::new(false)];

/// 调度切换握手旗（M11-D）：`SWITCHING[id] = 1` = 该槽位现场保存尚未
/// 完成（重排队已生效但物理切换未落定），拾取面（[`eligible`]）拒绝；
/// 清除点唯一性：
/// - **抢占族**（wall/LAPIC/RESCHED 三源共享 [`execute_switch`] 填
///   plan → 桩执行交换）：桩 asm 在旧上下文七槽保存完成后一次性
///   清旗（`PreemptPlan.handoff` 单 Store）——保存与清旗同窗口完成，
///   从清旗指令起该槽位可被任意核安全拾取；
/// - **协作族**（yield/block/finish/idle 四路统一 [`switch_funnel`]）：
///   后继任务的恢复点漏斗读 `LAST_OUT[cpu]` 清除前任旗（前任现场
///   保存先于控制权移交，后继恢复时保存必然已落定）。
///
/// 置位点唯一性：仅在「任务仍可拾取且即将物理切离」的两族路径置位
/// （yield 重排队 / preempt 重排队）；block（Blocked）与 finish（Zombie）
/// 本不可拾取，不置旗（漏斗仍统一清旗，幂等无副作用）。
static SWITCHING: [AtomicU64; MAX_TASKS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_TASKS]
};

/// 阻塞唤醒计数（M10-B 自检 35/36 断言面）：累计唤醒次数（含换页与
/// 进程间等待两族）。
static BLOCK_WAKES: AtomicU64 = AtomicU64::new(0);

/// 阻塞唤醒计数快照。
pub fn block_wakes() -> u64 {
    BLOCK_WAKES.load(Ordering::Acquire)
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
    // M19-① 取证面第二级：锁等待看门狗钩子注册（早于一切 SCHED 持锁路径；
    // SCHED 地址同时落哨兵量，戳内 sched=Y/N 直接指认是否调度锁）。
    SCHED_ADDR.store(&raw const SCHED as usize, Ordering::Release);
    ostd::sync::set_lock_stall_hook(lock_stall_report);
    // M19-① 防御性同族修复（启动早期单核、IF 状态依赖调用方）。
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    s.boot_cr3 = boot_cr3;
    s.tasks[0] = Some(Task::main_task());
    // M22-③ 写者蹲守坐标：主任务 ctx 槽绝对地址（DR0 写监视点目标——
    // cont 槽腐坏族的第二写者活捉面；幂等诊断行，零行为变更）。
    // （刚写入的槽位，get_or 0 兜底——unwrap 纪律）
    let main_ctx_addr = s.tasks[0]
        .as_ref()
        .map_or(0, |t| &t.ctx as *const _ as usize);
    MAIN_CTX_ADDR.store(main_ctx_addr, Ordering::Release);
    BSP_APIC_ID.store(ostd::hw::lapic::id(), Ordering::Release);
    CURRENT[0].store(0, Ordering::Relaxed);
    CURRENT[1].store(IDLE, Ordering::Relaxed);
    // M22-③：合法续点全集收集（先于任何拾取；ktext 逐字节扫描 +
    // 三桩 .resume + 双 trampoline，init 记档 n 与成员）。
    init_resume_set();
    // M22-③ DR0 写监视点布防：钩子先行 → 双核各自 mov dr0/dr7
    // （AP 侧在 ap_main 内同址补布；此后主任务 cont 槽任意写者均落
    // LUMINA-DRDB 取证行——写者 rip 域外即第二写者实锤）。
    ostd::interrupt::stubs::set_db_hook(db_writer_trap);
    ostd::interrupt::stubs::arm_write_watchpoint(main_ctx_addr as u64);
    // 蹲点坐标行（resume-set 行之后，同一诊断序列）
    {
        let mut serial = crate::console::SerialPort::com1();
        serial.init();
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!("sched: main-ctx @ {main_ctx_addr:#x} dr0-armed\n"),
        );
    }
    // [B] 猎场 v2.2 记档：引导栈界（主任务帧哨兵锚；与 nm 符号表对账面，
    // 667/705/951/1005 四标本毒化帧址皆落此界内）
    {
        let (bsb, bst) = crate::boot::boot_stack_bounds();
        let mut serial = crate::console::SerialPort::com1();
        serial.init();
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!("sched: boot-stack [{bsb:#x},{bst:#x}) frame-net-armed\n"),
        );
    }
}

/// M22-③ [B] 猎场：透明探针转储预算（t52 族教训——全量转储 5596 行/轮
/// 串口轰击扰动时敏面）。预算尽后静默（首个取证行已落盘，毒化复现轮次
/// 由 pf-hunt 批守候续捕）。
static DRDB_BUDGET: AtomicUsize = AtomicUsize::new(8);

/// M22-③ DR0/DR1 命中取证行：写者 rip + 写入值 + 桩锚点。
/// 合法写者仅两类 pc 域：协作保存（lumina_context_switch 内存储指令）
/// 与抢占保存（三桩存储指令）；init 期结构铺设在布防前已完成。
/// pc 域外或写入值 ∉ 合法续点全集 = 第二写者实锤（活体标本教义：
/// 透明探针不阻断——原指令流继续，系统带伤前行供后续取证）。
fn db_writer_trap(trap_rip: u64, anchor: u64) {
    // ---- [B] 猎场扩网 v2：DR1 面（恢复帧 RIP 槽）值签名判别 ----
    // 写监视点为后置陷阱：命中时写入已完成，回读即新值。值 = -1
    // （0xFFFF_FFFF_FFFF_FFFF，951/667/705 三标本同签名）= 毒化写者
    // 实锤 → LUMINA-DRDB1 落证；非毒值 = 布防窗后该栈位被合法复用
    // （寄存器保存/更深调用帧）→ 静默。DR1 未布防（=0）直接走 DR0 面。
    let d1 = ostd::interrupt::stubs::read_dr1();
    if d1 != 0 {
        // SAFETY: 前置条件 —— d1 = 拾取哨兵布防的帧 RIP 槽地址（自有内核
        //          栈界内，内核半区全局映射）。不变式 —— 只读不写（写监视
        //          点后置陷阱零递归）；volatile 防优化重排。
        // 并发 —— DR 每核一套，命中核读本核；帧槽写者唯一性由拾取门
        //         （M11-D 握手）与调度状态机保证。
        // 违反后果 —— 地址来自布防面自洽；野蹲已被撤防面封死。
        let v1 = unsafe { core::ptr::read_volatile(d1 as *const u64) };
        if v1 == u64::MAX {
            if DRDB_BUDGET.load(Ordering::Acquire) > 0 {
                DRDB_BUDGET.fetch_sub(1, Ordering::AcqRel);
                let mut serial = crate::console::SerialPort::com1();
                serial.init();
                let _ = core::fmt::Write::write_fmt(
                    &mut serial,
                    format_args!(
                        "LUMINA-DRDB1 pc={trap_rip:#x} val={v1:#x} slot={d1:#x} anchor={anchor:#x}\n"
                    ),
                );
            }
            return;
        }
    }
    let slot = MAIN_CTX_ADDR.load(Ordering::Acquire);
    if slot == 0 {
        return;
    }
    // SAFETY: 前置条件 —— slot 为 init 登记 的 ctx 槽地址（恒等映射域内）。
    // 不变式 —— 只读不写（写监视点零递归）；volatile 防优化重排。
    // 并发 —— 命中可来自任一核；本函数无共享可变态（串口写幂等）。
    // 违反后果 —— 槽址错误即误报（地址来自同一 init 登记面，自洽）。
    let val = unsafe { core::ptr::read_volatile(slot as *const u64) };
    // M22-③ 降噪门：写入值 ∈ 合法续点全集 = 合法保存（协作站点/桩
    // .resume）——静默直返。实测全量转储 5596 行/轮的串口轰击扰动
    // 时敏面（t52 族误伤 62/63）；域外值才落取证行，第二写者信号
    // 面零丢失（cont=0 属域外，照转储——布防后 stopped 陈值即异象）。
    if cont_in_resume_set(val) {
        return;
    }
    let mut serial = crate::console::SerialPort::com1();
    serial.init();
    let _ = core::fmt::Write::write_fmt(
        &mut serial,
        format_args!("LUMINA-DRDB pc={trap_rip:#x} val={val:#x} anchor={anchor:#x}\n"),
    );
}

/// SCHED 锁运行时地址哨兵（init 时落值；戳内比对用）。
static SCHED_ADDR: AtomicUsize = AtomicUsize::new(0);

/// M22-③：主任务 ctx 槽地址（DR0 布防目标；init 登记，AP 布防面共用）。
static MAIN_CTX_ADDR: AtomicUsize = AtomicUsize::new(0);

/// 主任务 ctx 槽地址读取（AP 布防面；未 init 时 0）。
pub fn main_ctx_addr() -> usize {
    MAIN_CTX_ADDR.load(Ordering::Acquire)
}

/// SCHED 锁持锁点遥测（M19-① 第三级取证）：高 32 位 = 拿锁核，低 32 位 =
/// 调用点行号。语义 = 最近一次成功拿锁的点（guard drop 不清——**死锁
/// 场景下无人再拿锁，值即持锁点**；非死锁场景为陈旧值，仅取证用）。
static SCHED_HOLDER: AtomicU64 = AtomicU64::new(0);

/// 宏：调用点自动登记行号（42 点替换 SCHED.lock() → sched_lock!()）。
macro_rules! sched_lock {
    () => {
        $crate::task::sched_lock_at(line!() as u64)
    };
}
pub(crate) use sched_lock;

/// SCHED.lock() 取证包装：拿锁后登记调用点行号 + 本核（遥测语义见
/// SCHED_HOLDER）。锁本身语义零变化（SpinLock 原语义透传）。
pub(crate) fn sched_lock_at(line: u64) -> SpinGuard<'static, Scheduler> {
    // 直拿底层锁（不包装——本函数即包装本体；line 遥测不递归登记）
    let g = SCHED.lock();
    SCHED_HOLDER.store(
        ((my_cpu() as u64) << 32) | (line & 0xFFFF_FFFF),
        Ordering::Release,
    );
    g
}

/// 锁等待看门狗回调（M19-①）：自旋超阈值即串口直写 LUMINA-LOCK-STALL
/// （免分配免取锁——ISR 语境可达纪律；同核死锁模式中等锁者即本核
/// ISR，永不推进，本戳是唯一能落盘的证据）。
fn lock_stall_report(addr: usize) {
    let mut serial = crate::console::SerialPort::com1();
    serial.init();
    let is_sched = SCHED_ADDR.load(Ordering::Acquire) == addr;
    // IF 旗（M19-① 铁证矩阵）：IF=0 = 本核 ISR 语境等锁——若对侧核
    // IF=1 的任务在推进，持锁者必在本核（同核「持锁者被本核中断打断」
    // 死锁铁证）；双核 IF=1 = 持锁者不存在（锁状态残留，另一族）。
    let iff = ostd::hw::intr::if_enabled() as u8;
    // 持锁点遥测（第三级）：最后成功拿锁的 (cpu, line)——死锁场景下
    // 即持锁者现形（round-173 型「cpu1 持锁卡死 + cpu0 ISR 等锁」的直接
    // 指认面）。
    let h = SCHED_HOLDER.load(Ordering::Acquire);
    let _ = core::fmt::Write::write_fmt(
        &mut serial,
        format_args!(
            "LUMINA-LOCK-STALL addr={:#x} sched={} ticks={} cpu={} iff={iff} h-cpu={} h-line={}\n",
            addr,
            is_sched as u8,
            ostd::time::now(),
            current_cpu_slot(),
            h >> 32,
            h & 0xFFFF_FFFF,
        ),
    );
}

/// 注册用户入口桥（user.rs 模块初始化时调用一次；M22-③ 第二项起
/// 桥取遗传细胞参数——跳板入口窗同窗取值传参，桥面免读 CURRENT）。
pub fn set_user_entry_bridge(f: extern "C" fn(u64) -> !) {
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
    let mut s = sched_lock!();
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
    let mut s = sched_lock!();
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
    let mut s = sched_lock!();
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
    let mut s = sched_lock!();
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

/// 派生自由跨核子任务（M11-A：SYS_SPAWN 慢路径；M7-A 起用户任务
/// 默认自由跨核，本变体与 [`spawn_user_child_pinned`] 的差异仅在
/// 不钉扎）。父链内核登记同 M9-A；槽位耗尽返回 [`IDLE`]。
pub fn spawn_user_child(
    name: &'static str,
    entry: Entry,
    user_root: u64,
    cap_slot: usize,
    parent: usize,
) -> usize {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let Some(id) = alloc_slot(
        &mut s,
        Task::new_user(
            name,
            entry,
            user_root,
            cap_slot,
            Some(parent),
            trampoline_user,
        ),
    ) else {
        return IDLE;
    };
    let prio = s.tasks[id].as_ref().map_or(PRIO_NORMAL, |t| t.prio);
    enqueue(&mut s.ready, id, prio);
    kick_other();
    id
}

/// 当前任务的独立页表根（M11-A：SYS_SPAWN 克隆源；内核任务恒 0）。
pub fn current_user_root() -> u64 {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    let s = sched_lock!();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    s.tasks
        .get(cur)
        .and_then(|t| t.as_ref())
        .map_or(0, |t| t.user_root)
}

/// 任务认领（M12-d t43 取证面）：内核侧把目标任务父链登记为指定
/// 父任务——内核直接派生任务（parent = None）经此挂靠存活的等待方
/// （未来 init/守护进程收养语义的内核侧原语）。
/// M22-③ 第二项注记：原相邻面 task_user_root（arm 窗事后重读源）已
/// 退役——消费面改内核侧 SPAWN_CHILD_ROOT 戳（procs），收割时序脱靶
/// 结构性消失，见 procs::spawn_child_root_stamp。
pub fn task_adopt(id: usize, parent: usize) -> bool {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    match s.tasks.get_mut(id).and_then(|t| t.as_mut()) {
        Some(t) if t.parent.is_none() && parent < MAX_TASKS => {
            t.parent = Some(parent);
            true
        }
        _ => false,
    }
}

/// 登记目标任务的新页表根（M12-B SYS_EXEC：地址空间整体重建后由
/// 慢路径写入；仅调用方自身任务上下文，单核串行）。
pub fn set_user_root(id: usize, root: u64) {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    if let Some(t) = s.tasks.get_mut(id).and_then(|t| t.as_mut()) {
        t.user_root = root;
    }
}

/// 当前核任务 Linux ABI 标志（M33-L1 派发分流面）。
pub fn current_lin_abi() -> bool {
    let cpu = my_cpu();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    if cur == IDLE {
        return false;
    }
    let _w = IntWindow::new();
    let s = sched_lock!();
    s.tasks
        .get(cur)
        .and_then(|t| t.as_ref())
        .is_some_and(|t| t.lin_abi)
}

/// 设任务 Linux ABI 标志（M33-E1 ELF 链装载点调用；M33-L1 消费）。
pub fn set_lin_abi(id: usize, on: bool) {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    if let Some(t) = s.tasks.get_mut(id).and_then(|t| t.as_mut()) {
        t.lin_abi = on;
    }
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
    let mut s = sched_lock!();
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
    let mut s = sched_lock!();
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
    // M21-① 纵深防御：新任务入槽即清握手旗——槽位复用链上任一历史
    // 路径的陈旗（含修复前遗留语义）不再可能令 eligible 永拒新任务
    // （钉扎拾取缺陷的静态面封死）。
    SWITCHING[id].store(0, Ordering::Release);
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
    // M18-①：canary 校验（五条派发路径唯一收口；两次 volatile 读，
    // 锁内无分配、无锁获取——中断语境可达）。旧任务的下一次派发即
    // 校验其运行期/驻留期栈底完整性。
    canary_check(t);
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
            // M10-B：按任务期望根恢复（kernel_cr3 ≠ 0 = 借用户根窗口，
            // 如 swap 读回；被抢占后经派发面恢复现场根，后继访存可达）
            let want = if t.kernel_cr3 == 0 {
                boot_cr3
            } else {
                t.kernel_cr3
            };
            if ostd::hw::control::read_cr3() & !0xFFF != want {
                // 引导根由启动汇编构建并验证（长模式即运行其上）；借根
                // 由登记窗口保证其页表存活（任务存续期）。
                ostd::hw::control::write_cr3(want);
            }
        }
    }
}

/// 取两互异槽位上下文的 SwitchPair（split_at_mut 证明互斥性）。
/// **M18-① 专项取证点**：a == b（自切换）= 调度面竞态实锤——v0.18 观察期
/// 即有本点 panic（len/idx 同值成对：2/2 与 0/0），此处升级为全现场
/// 转储（双方状态 + 就绪队列在位性 + SWITCHING 旗 + 全队列内容）后再
/// 触达既有的不可达断言（串口证据先于崩溃落盘，pf-hunt 全量留存）。
fn slots_pair(s: &mut Scheduler, a: usize, b: usize) -> SwitchPair {
    if a == b {
        let mut serial = crate::console::SerialPort::com1();
        serial.init();
        let state_of = |id: usize| s.tasks.get(id).and_then(|t| t.as_ref().map(|t| t.state));
        let in_ready = |id: usize| s.ready.iter().any(|q| q.contains(&id));
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(
                "LUMINA-SCHED-BUG self-switch slot={} state-a={:?} in-ready-a={} switching-a={} state-b={:?}\n",
                a,
                state_of(a),
                in_ready(a),
                SWITCHING[a].load(Ordering::Acquire),
                state_of(b),
            ),
        );
        for (lvl, q) in s.ready.iter().enumerate() {
            let _ =
                core::fmt::Write::write_fmt(&mut serial, format_args!("  ready[{lvl}]={:?}\n", q));
        }
    }
    debug_assert_ne!(a, b, "scheduler never switches a task to itself");
    // M21-② 哨兵：切换目标（b = 切入方）上下文合法性——yield/block/finish
    // 三族路径共经本构建点，一处校验全覆盖。
    if let Some(t) = s.tasks[b].as_ref() {
        pickup_sentinel(b, t);
    }
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

/// 栈底 canary 校验（M18-①）：读栈底首 qword 与魔数对账；破坏则
/// 计数 + 免分配串口直写取证行（LUMINA-CANARY-FAIL）。永不分配、
/// 永不取锁——prepare_dispatch 在中断语境可达（抢占派发路径）。
fn canary_check(t: &Task) {
    if t.stack_base == 0 {
        return; // 主任务引导栈：无盖章面（如实记档）
    }
    let got = ostd::hw::phys::read_u64(t.stack_base);
    if got != STACK_CANARY {
        CANARY_VIOLATIONS.fetch_add(1, Ordering::AcqRel);
        let mut serial = crate::console::SerialPort::com1();
        serial.init();
        let _ = core::fmt::Write::write_fmt(
            &mut serial,
            format_args!(
                "LUMINA-CANARY-FAIL base={:#x} top={:#x} got={got:#x} want={STACK_CANARY:#x}\n",
                t.stack_base, t.stack_top
            ),
        );
    }
}

/// canary 破坏计数快照（自检 t59 断言面）。
pub fn canary_violations() -> u64 {
    CANARY_VIOLATIONS.load(Ordering::Acquire)
}

/// 全任务栈 canary 审计（M18-① t59）：遍历槽位表逐栈校验，返回覆盖
/// 数（有盖章面的任务数）。SCHED 锁内快照遍历——破坏即现场（驻留期
/// 被越界写亦会在下一次派发/本审计中现形）。主任务引导栈无盖章面，
/// 不计入覆盖数（如实记档）。
pub fn canary_audit_all() -> usize {
    // M19-① 取证升级：入口戳（挂死轮若停在 enter 后 = 拿锁死锁实锤；
    // 停在 enter 前 = 间隙路径实锤）。
    let mut serial = crate::console::SerialPort::com1();
    serial.init();
    let _ = core::fmt::Write::write_fmt(
        &mut serial,
        format_args!("ca: enter ticks={}\n", ostd::time::now()),
    );
    // M19-① 同族修复：IntWindow 包裹（main 上下文 IF=1 裸拿锁同风险）。
    let _w = IntWindow::new();
    let s = sched_lock!();
    let mut checked = 0usize;
    for slot in s.tasks.iter().flatten() {
        if slot.stack_base != 0 {
            canary_check(slot);
            checked += 1;
        }
    }
    checked
}

/// 让出 CPU：协作切换（重排队 + 拾取下一可运行者）；无可让渡对象时空转返回。
///
/// 窗口纪律：元数据变更与物理切换全程 IF=0（cli 遮蔽）——本核定时器钩子
/// 在此窗口物理不可入，元数据与真实执行面永不错位；恢复点无条件
/// sti（内核任务的 IF 约定恒为 1，被抢占任务经 .resume→iretq 另行恢复）。
pub fn yield_now() {
    let w = IntWindow::new();
    let cpu = my_cpu();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    let pair = {
        let mut s = sched_lock!();
        let sc = &mut *s;
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
            t.waited = 0;
        }
        // M11-D 握手：cur 已重排队（可拾取态）但现场保存未完成——置旗
        // 拒绝拾取；旗由切换机器（lumina_context_switch）在旧现场保存
        // 完成后单 Store 清除（锁释放→物理切换窗口封死，无后继配合项）
        SWITCHING[cur].store(1, Ordering::Release);
        if let Some(t) = sc.tasks[target].as_mut() {
            t.state = State::Running;
        }
        PERCPU_RUN_TICKS[cpu].store(0, Ordering::Relaxed);
        CURRENT[cpu].store(target, Ordering::Relaxed);
        sc.cooperative_switches += 1;
        let boot = sc.boot_cr3;
        if let Some(t) = sc.tasks[target].as_ref() {
            prepare_dispatch(t, boot, cpu);
        }
        slots_pair(sc, cur, target).with_handoff(SWITCHING[cur].as_ptr()) // M11-D：旗随切换机器清除
    };
    switch_deferred(pair); // 恢复后从此处继续（IF=0；旗已在保存完成后清除）
    ostd::hw::intr::enable(); // 恢复即开中断（内核任务 IF 约定）
    drop(w);
}

/// idle 循环拾取：从全局队列取一个可运行任务，返回（idle → 任务）切换对。
///
/// 首次调用以 idle 真实上下文为 old（switch_deferred 保存续点）；此后
/// 任务切回 idle 时从 [`run_idle`] 的 switch 调用点继续。
fn idle_pick(cpu: usize) -> Option<SwitchPair> {
    // M19-① 根因修复：IntWindow 包裹（idle 循环 IF=1 语境裸拿锁被本核
    // tick 打断 = 持锁者冻结 + timer_hook ISR 等锁互等死锁——round-038/
    // 046/049 双核 iff=0 铁证实锤；drop 逆序保证解锁后才恢复 IF）。
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let sc = &mut *s;
    let target = pick_best(&mut sc.ready, &sc.tasks, cpu, IDLE, None)?;
    remove_value(&mut sc.ready, target);
    if let Some(t) = sc.tasks[target].as_mut() {
        t.state = State::Running;
    }
    PERCPU_RUN_TICKS[cpu].store(0, Ordering::Relaxed);
    CURRENT[cpu].store(target, Ordering::Relaxed);
    let boot = sc.boot_cr3;
    if let Some(t) = sc.tasks[target].as_ref() {
        prepare_dispatch(t, boot, cpu);
    }
    // M21-② 哨兵：idle 拾取面切换对构建前校验目标 ctx（cont∈.text +
    // rsp∈自有栈界）——round-432 鬼影族的活体前置网。
    if let Some(t) = s.tasks[target].as_ref() {
        pickup_sentinel(target, t);
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
        // M20-② 根因修复（round-432 #PF rip=-1 活体标本闭环）：切换机器
        // 契约修复——[`switch_deferred`] 的 SAFETY 契约要求「切换期间
        // IF=0（调用方窗口）」。原实现中 idle_pick 内部 IntWindow 在函数
        // 返回时已恢复 IF=1，switch_deferred 裸奔在开中断语境调用：
        // context_switch asm 中段被本核 LAPIC tick 打断 → timer_hook/
        // resched 在「旧现场未保存完/新现场已部分加载」窗口重入 →
        // target.ctx.rsp 被写成 boot stack 指针（跨任务栈污染）→ 栈上
        // -1 残值被 ret 消费 → 取指 #PF @u64::MAX（round-432 标本
        // rsp=0xa12420 ∈ boot stack [0xA03000,0xA13000) 实锤，与其余
        // 四个调用点全部窗口内 IF=0 形成对照）。修复：IntWindow 覆盖
        // idle_pick+switch_deferred 全程（内部窗口在 IF=0 下 no-op）；
        // continue 离开作用域时 w.drop 恢复 IF=1，与循环头 enable() 衔接。
        let w = IntWindow::new();
        if let Some(pair) = idle_pick(cpu) {
            switch_deferred(pair); // 切入任务；被切回时从此继续（IF=0 契约恢复）
            continue;
        }
        drop(w);
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
        let reap = IDLE_REAP.load(Ordering::Acquire);
        if reap != 0 {
            // SAFETY: 同上——地址来自 set_idle_reap 存入的 fn() -> bool。
            let f: fn() -> bool = unsafe { core::mem::transmute(reap) };
            if f() {
                continue;
            }
        }
        ostd::hw::intr::halt();
    }
}

/// 收敛失败点名（M22-③ 第二项，census 纪律）：非 Zombie 占用槽位
/// （id, 任务名, 状态短串）快照——t37 收敛失败取证面（round-727 形态：
/// 健康链尾超期快照），点名直读，下批零盲区。
pub fn stuck_workers() -> alloc::vec::Vec<(usize, &'static str, &'static str)> {
    let _w = IntWindow::new();
    let s = sched_lock!();
    s.tasks
        .iter()
        .enumerate()
        .filter_map(|(id, slot)| {
            let t = slot.as_ref()?;
            if t.state == State::Zombie {
                return None;
            }
            let st = match t.state {
                State::Ready => "ready",
                State::Running => "running",
                State::Blocked => "blocked",
                State::Zombie => "zombie",
            };
            Some((id, t.name, st))
        })
        .collect()
}

/// 除主任务外是否全部终结（主循环的等待谓词；Blocked = 存活继续等待，
/// Zombie = 终结留证——waitpid 收割与否不影响本谓词，M10-C）。
pub fn all_workers_finished() -> bool {
    let _w = IntWindow::new();
    let s = sched_lock!();
    s.tasks
        .iter()
        .enumerate()
        .all(|(id, slot)| id == 0 || slot.as_ref().is_none_or(|t| t.state == State::Zombie))
}

/// 用户任务退出码（EXIT 系统调用写入；自检 14 断言）。
static USER_EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);

/// init（PID 1）终结码（M23-② interactive 面）：僵尸转型点按任务名
/// 点名登记——kmain 自检通过后派 init 并**轮询本面守候**（初版全表
/// 谓词 all_workers_finished 实测永眠：批跑面遗留长活任务 timer-sleeper
/// 在批模式由 kernel_exit 直接带过、从不终结——HANG-DUMP 点名 id=2
/// 定案，改只等 init 本尊）。读到非 MAX 即 init 终结，码值透传
/// `kernel_exit`（halt 命令 → SYS_EXIT(0x10) → QEMU 码 33 = 批跑
/// 成功域同源）。
pub static INIT_EXIT: AtomicU64 = AtomicU64::new(u64::MAX);

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
    let mut s = sched_lock!();
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
    let s = sched_lock!();
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
    let s = sched_lock!();
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

/// 本核是否运行在任务上下文（非 idle；M10-B 阻塞面调用前置检查——
/// idle 无 Task 上下文与内核栈续点，不可阻塞）。
/// M22-③ 第二项注记：原相邻面 current_parent_pid（M12 细胞桥面读）
/// 已退役——首派发窗口二次 CURRENT 读即 round-585/664 r14 注入竞态
/// 根因，消费面改跳板入口窗传参（trampoline_user → cell），结构性移除。
pub fn on_task_context() -> bool {
    current_task_id() != IDLE
}

/// 登记当前内核任务的期望 CR3（M10-B：借用户根窗口的抢占安全面）。
/// `cr3 = 0` 回归引导根。窗口模式：进入借根窗口前登记目标根，退出时
/// 登记 0；窗口内的抢占/阻塞经派发面按任务恢复现场根。
pub fn set_current_kernel_cr3(cr3: u64) {
    let _w = IntWindow::new();
    let cpu = my_cpu();
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    if cur == IDLE {
        return;
    }
    let mut s = sched_lock!();
    if let Some(t) = s.tasks.get_mut(cur).and_then(|slot| slot.as_mut()) {
        t.kernel_cr3 = cr3 & !0xFFF;
    }
}

/// 目标任务的父任务槽位（M9-A 授权门禁；不存在或无父 = None）。
pub fn task_parent(id: usize) -> Option<usize> {
    let _w = IntWindow::new();
    let s = sched_lock!();
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
    let mut s = sched_lock!();
    s.tasks
        .get_mut(id)
        .and_then(|t| t.as_mut())
        .map(|t| f(&mut t.handles))
}

/// 在调度锁窗口内访问目标任务句柄旗标（M15-② 句柄面深化）：
/// F_GETFD/F_SETFD 的 TCB 承载面；任务不存在返回 None。
pub fn with_task_hflags<R>(id: usize, f: impl FnOnce(&mut [u8; HANDLE_MAX]) -> R) -> Option<R> {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    s.tasks
        .get_mut(id)
        .and_then(|t| t.as_mut())
        .map(|t| f(&mut t.hflags))
}

/// 清除目标句柄旗标（M15-② close/revoke 面配套：同号复用不继承陈值；
/// 任务/句柄不存在静默忽略）。
pub fn clear_hflag(id: usize, h: usize) {
    if h > 0 && h < HANDLE_MAX {
        let _ = with_task_hflags(id, |f| f[h] = 0);
    }
}

/// EXEC CLOEXEC 消费钩子（M15-② 句柄面深化）：关闭目标任务全部
/// CLOEXEC 置位句柄（句柄清除 + 全局槽撤销 + 旗标复位），返回关闭数。
/// fd 继承语义：未置位句柄跨 exec 存续。被撤能力槽的孤儿文件对象由
/// [`crate::vfs::reap_orphaned_files`] 收敛（本函数尾部统一补扫）。
/// 锁序：SCHED（收集）→ CAPS（撤销）→ FILES/CAPS（reap），全程单向。
pub fn close_cloexec_handles(id: usize) -> usize {
    let _w = IntWindow::new();
    let mut revoked: Vec<(usize, usize)> = Vec::new();
    {
        let mut s = sched_lock!();
        if let Some(Some(t)) = s.tasks.get_mut(id) {
            for h in 1..HANDLE_MAX {
                if t.hflags[h] & (bedrock::abi::FD_CLOEXEC as u8) != 0 {
                    if let Some(g) = t.handles[h].take() {
                        revoked.push((h, g));
                    }
                    t.hflags[h] = 0;
                }
            }
        }
    }
    let n = revoked.len();
    for (_h, g) in revoked {
        let _ = crate::caps::table().lock().revoke(g);
    }
    if n > 0 {
        crate::vfs::reap_orphaned_files();
    }
    n
}

/// 句柄表用量快照（M14-② SYS_QUOTA kind 0 断言面）：(used, HANDLE_MAX)。
/// 任务不存在返回 (0, 0)（调用方按错误面处置）。
pub fn handle_usage(id: usize) -> (usize, usize) {
    with_task_handles(id, |t| t.iter().filter(|h| h.is_some()).count())
        .map_or((0, 0), |used| (used, HANDLE_MAX))
}

/// 目标任务的主身份能力槽号（M9-A 撤销保护面；不存在 = None）。
pub fn cap_slot_of(id: usize) -> Option<usize> {
    let _w = IntWindow::new();
    let s = sched_lock!();
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

/// 终结当前任务（系统调用 EXIT 路径）：记录退出码 → 僵尸留证 →
/// 唤醒等待本任务的父任务 → 切换到下一就绪任务或 idle（永不返回）；
/// 两者皆无则停机等待唤醒。
pub fn exit_current(code: u64) -> ! {
    USER_EXIT_CODE.store(code, Ordering::Relaxed);
    // 每核槽位（M8-A 自检 28）：终结发生在终结者所在核，钉扎派发下
    // 槽位即任务身份；自由派发时取「最后终结者所在核」语义（取证面）。
    let cpu = my_cpu();
    USER_EXIT_CODES[cpu].store(code, Ordering::Release);
    finish_and_switch_away(code)
}

/// 终结切出（任务入口返回路径与 EXIT 共用；code = u64::MAX 表示入口
/// 返回的无码终结）：不回队，直接切换。M10-C：终结态 = Zombie（留证
/// 待 waitpid 收割；遗留 v0.9 Finished 语义等价——无人收割的僵尸同样
/// 永不复用），并在此锁窗口内唤醒 Child 等待者（匹配谓词：定向 pid
/// 或任意子任务且退出任务确为其直接子任务）。
fn finish_and_switch_away(code: u64) -> ! {
    let mut w = IntWindow::new();
    loop {
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        let pair = {
            let mut s = sched_lock!();
            let sc = &mut *s;
            if cur == IDLE {
                None
            } else {
                // M9-A 句柄生命周期收口 + M10-C 僵尸留证：终结前全表清算
                // （全局槽逐个撤销归还能力表），退出码/状态登记。
                let parent = sc.tasks[cur].as_ref().and_then(|t| t.parent);
                if let Some(t) = sc.tasks[cur].as_mut() {
                    t.revoke_all_handles();
                    t.exit_code = code;
                    // M23-② init 点名登记（interactive 守候读回面；锁窗口
                    // 内 Release 落账，kmain 见 finished 后 Acquire 读回）。
                    if t.name == "init" {
                        INIT_EXIT.store(code, Ordering::Release);
                    }
                    t.state = State::Zombie;
                }
                // M21-① 护槽握手（S72 次级窗口正式转正收口）：Zombie 登记
                // 即置握手旗——本任务 drop(s) 后在锁外由切换机器完成七槽
                // 保存（保存完成时单 Store 清旗）。旗未清期间三处收割面
                // （wait_scan / reap_orphans / reap_zombies）一律跳过本槽，
                // 杜绝「收割→复用→boot_new 交错→死者鬼影保存写入复用槽
                // ctx」的跨任务上下文污染（Type A 簇败族根因）。
                SWITCHING[cur].store(1, Ordering::Release);
                // M12-d 孤儿链 re-parent：退出任务的全部子任务改挂无主
                // （parent = None）——Unix 孤儿语义的内核侧等价；孤儿
                // Zombie 由 idle 附加工作自动收割（见 reap_orphans），
                // 不再依赖原父存活的 waitpid 面。
                let mut orphans = 0usize;
                for id in 0..MAX_TASKS {
                    if let Some(t) = sc.tasks[id].as_mut() {
                        if t.parent == Some(cur) {
                            t.parent = None;
                            orphans += 1;
                        }
                    }
                }
                if orphans != 0 {
                    ORPHANS_REPARENTED.fetch_add(orphans as u64, Ordering::AcqRel);
                }
                // M10-C：唤醒等待本任务的 Child 等待者（同锁窗口原子完成；
                // pid=0 语义 = 任意直接子任务 → 必须校验 parent 归属；
                // 扫描含槽位 0——主任务可作等待者）
                let mut woken = 0usize;
                for id in 0..MAX_TASKS {
                    let Some(waiter) = sc.tasks[id].as_mut() else {
                        continue;
                    };
                    if waiter.state != State::Blocked {
                        continue;
                    }
                    let matched = match waiter.wait {
                        Some(WaitWhat::Child { pid }) => {
                            pid == cur || (pid == 0 && parent == Some(id))
                        }
                        _ => false,
                    };
                    if matched {
                        waiter.wait = None;
                        waiter.state = State::Ready;
                        waiter.waited = 0;
                        let p = waiter.base_prio;
                        enqueue(&mut sc.ready, id, p);
                        woken += 1;
                    }
                }
                if woken != 0 {
                    BLOCK_WAKES.fetch_add(woken as u64, Ordering::AcqRel);
                }
                match pick_best(&mut sc.ready, &sc.tasks, cpu, IDLE, None) {
                    Some(id) => {
                        remove_value(&mut sc.ready, id);
                        if let Some(t) = sc.tasks[id].as_mut() {
                            t.state = State::Running;
                        }
                        PERCPU_RUN_TICKS[cpu].store(0, Ordering::Relaxed);
                        CURRENT[cpu].store(id, Ordering::Relaxed);
                        let boot = sc.boot_cr3;
                        if let Some(t) = sc.tasks[id].as_ref() {
                            prepare_dispatch(t, boot, cpu);
                        }
                        // M21-①：护槽旗随切换机器清除（保存完成时单 Store）。
                        Some(slots_pair(sc, cur, id).with_handoff(SWITCHING[cur].as_ptr()))
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
                // M10 缺陷修复：切回 idle 前 CURRENT 纠正为 IDLE——v0.9
                // 遗留陈旧指针（窗口期内抢占钩子可对已终结任务误判）。
                let idle_ok = IDLE_VALID[cpu].load(Ordering::Acquire);
                if idle_ok {
                    // SAFETY: 前置条件 —— IDLE_VALID[cpu] 已置位（idle 循环
                    //          已进入，idle 栈存活）；cur 槽位占用且已终结。
                    // 不变式 —— idle 上下文本核独占；切换后本代码不再续跑。
                    // 并发 —— 本核串行；任务槽已从队列剔除（Zombie 不可拾取）。
                    // 违反后果 —— 指针失效即写穿任意内存（槽位纪律封死）。
                    unsafe {
                        let idle = &mut *core::ptr::addr_of_mut!(IDLE_CTX[cpu]);
                        let mut s = sched_lock!();
                        let cur = CURRENT[cpu].load(Ordering::Relaxed);
                        CURRENT[cpu].store(IDLE, Ordering::Relaxed);
                        if let Some(t) = s.tasks[cur].as_mut() {
                            // M21-①：护槽旗随切换机器清除（同 Some 分支）。
                            let pair = SwitchPair::from(&mut t.ctx, idle)
                                .with_handoff(SWITCHING[cur].as_ptr());
                            drop(s);
                            switch_deferred(pair);
                        }
                    }
                    // 切回 idle 后本行不可达（Zombie 永不恢复）
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
        // M20-①：SCHED 锁中断纪律——enable() 后 IF=1，此处临界区必须包
        // 中断窗口（round-417 铁证：持锁@1660 被本核 LAPIC tick 打断 →
        // timer_hook ISR 等同锁互等死锁，与 idle_pick 同族）；块内 drop
        // 逆序保证解锁后才恢复 IF（M19 同款）。
        let _w = IntWindow::new();
        let s = sched_lock!();
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        s.tasks[cur].as_ref().map_or(main_entry_stub, |t| t.entry)
    };
    entry();
    finish_and_switch_away(u64::MAX) // 入口返回 = 无码终结（防御路径）
}

/// 用户任务跳板：入口点与遗传细胞同窗取值 → 桥传参 → 进 ring3
/// （永不返回；终结经 EXIT 系统调用）。
extern "C" fn trampoline_user() -> ! {
    // 首派发若经抢占路径切入则 IF=0；进 ring3 前先开放（iretq 亦会置 IF）
    ostd::hw::intr::enable();
    // M22-③ 第二项：遗传细胞与入口点同窗读取（M20-① IntWindow 纪律）。
    // cell = 任务创建时登记的父链（ctx.r14 焊接同源）；根父/内核面
    // None → 0。桥面不再二次读 CURRENT（round-585/664 竞态根治：
    // 派发侧读面单一，两次读之间的额外裸窗不复存在）。
    let (entry, cell): (Entry, u64) = {
        let _w = IntWindow::new();
        let s = sched_lock!();
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        match s.tasks[cur].as_ref() {
            Some(t) => (t.entry, t.parent.map_or(0, |p| p as u64)),
            None => (main_entry_stub, 0),
        }
    };
    let _ = entry;
    let bridge = USER_ENTRY_BRIDGE.load(Ordering::Acquire);
    debug_assert_ne!(bridge, 0, "user entry bridge must be registered");
    if bridge == 0 {
        finish_and_switch_away(u64::MAX);
    }
    // SAFETY: 前置条件 —— 地址来自 set_user_entry_bridge 存入的
    //          extern "C" fn(u64) -> !；注册先于任何用户任务派发。
    // 不变式 —— Release/Acquire 配对；注册只发生一次。
    // 并发 —— 用户任务自由跨核（M7-A）；首次派发前完成注册。
    // 违反后果 —— 跳转伪造地址即任意代码执行（初始化纪律封死）。
    let f: extern "C" fn(u64) -> ! = unsafe { core::mem::transmute(bridge) };
    f(cell)
}

/// 抢占使能开关（自检 12 开启；协作演示窗口临时关闭）。
pub fn set_preempt_enabled(on: bool) {
    PREEMPT_ENABLED.store(on, Ordering::Release);
}

/// 抢占统计快照（自检取证；跨核合计）。
pub fn preempt_stats() -> (u64, u64) {
    let _w = IntWindow::new();
    let s = sched_lock!();
    (s.preempt_switches, s.cooperative_switches)
}

/// 抢占切换执行器（M10-A 三抢占源共享；ISR 窗口内调用，调用方持锁）。
/// 执行被抢占者回队（M9-C 衰减回 base）→ 目标记 Running → CURRENT 更新
/// → prepare_dispatch → plan 填写。返回 true = 已填写 plan（桩执行交换）。
///
/// M11-D 握手：cur 重排队（可拾取态）同时置 SWITCHING[cur] = 1，并把
/// 旗地址写入 `plan.handoff`——桩在旧现场保存完成后清旗（asm 单
/// Store），锁释放 → 桩保存完成之间的跨核拾取窗口被拾取侧门禁封死。
fn execute_switch(
    sc: &mut Scheduler,
    cpu: usize,
    cur: usize,
    next: usize,
    plan: &mut PreemptPlan,
) -> bool {
    remove_value(&mut sc.ready, next);
    // 被抢占者按基准级回队（遗漏即任务从队列蒸发——开发期实测挂死；
    // M9-C：衰减回 base_prio 并清等待计账，老化提升不跨运行期保留）
    let cur_prio = sc.tasks[cur].as_ref().map_or(PRIO_NORMAL, |t| t.base_prio);
    enqueue(&mut sc.ready, cur, cur_prio);
    if let Some(t) = sc.tasks[cur].as_mut() {
        t.prio = cur_prio;
        t.state = State::Ready;
        t.waited = 0;
    }
    if let Some(t) = sc.tasks[next].as_mut() {
        t.state = State::Running;
    }
    PERCPU_RUN_TICKS[cpu].store(0, Ordering::Relaxed);
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
            // M21-② 哨兵：抢占切入面同款校验（execute_switch 为四拾取族
            // 中唯一不经 slots_pair 的路径，逐点补齐）。
            pickup_sentinel(next, n);
            plan.old = &mut o.ctx;
            plan.new = &mut n.ctx;
            // M11-D：握手旗置位（锁内，拾取面立即生效）+ 桩清除面登记
            SWITCHING[cur].store(1, Ordering::Release);
            plan.handoff = SWITCHING[cur].as_ptr();
            true
        }
        _ => false,
    }
}

/// 抢占判定（M10-A 三抢占源共享；ISR 窗口内调用，调用方持锁）。
/// 规则（M8-C 定版）：① 高优先就绪者抢前（严格高于当前，无视量子）；
/// ② 量子到期同级（及以下）轮转。当前任务必须处于 Running 态——
/// 阻塞/终结切换窗口期的陈旧 CURRENT 指针防御（M10 缺陷修复：v0.9
/// 终结路径 idle 分支不更新 CURRENT，窗口期内 LAPIC 钩子可对已终结
/// 任务误判 eligible 并重入队）。
/// 返回 true = 已填写 plan（桩执行抢占交换）。
fn try_preempt_switch(sc: &mut Scheduler, cpu: usize, plan: &mut PreemptPlan) -> bool {
    let cur = CURRENT[cpu].load(Ordering::Relaxed);
    if cur == IDLE || !eligible(&sc.tasks, cur, cpu) {
        return false;
    }
    let Some(t) = sc.tasks[cur].as_mut() else {
        return false;
    };
    if t.state != State::Running {
        return false;
    }
    let cur_prio = t.prio;
    let quantum_hit = PERCPU_RUN_TICKS[cpu].load(Ordering::Relaxed) >= QUANTUM_TICKS as u32;
    // ① 高优先抢前（自 0 级扫至 cur_prio-1，严格更高）
    if let Some(next) = pick_best(&mut sc.ready, &sc.tasks, cpu, cur, Some(cur_prio)) {
        return execute_switch(sc, cpu, cur, next, plan);
    }
    // ② 量子到期轮转（不移除；找不到则放行——保持队列完整，计账不清
    // 以便下拍重试，M9 原语义的「先清后败」窗口在此收敛）
    if quantum_hit {
        if let Some(next) = pick_best(&mut sc.ready, &sc.tasks, cpu, cur, None) {
            return execute_switch(sc, cpu, cur, next, plan);
        }
    }
    false
}

/// LAPIC 定时器钩子（注册进 ostd::interrupt::stubs；本核 IRQ 0x41 窗口内调用）。
///
/// 返回 true = 已填写 plan（桩随即从栈上计划完成抢占交换）。
/// 放行条件：抢占未使能 / 本核 idle / 队列无可运行者 / 时间片未满。
/// M10-A：量子判定数据源改为 per-CPU 切片镜像（PERCPU_RUN_TICKS，
/// 墙钟 ISR 锁自由计账，ring3 驻留期不再冻结）；本钩子保持 M9 形态
/// （老化 + 本核抢占判定，内核上下文抢占源；ring3 驻留期间本核 LVT
/// 被屏蔽，该场景的抢占经 RESCHED-plan 送达）。
pub fn timer_hook(plan: &mut PreemptPlan) -> bool {
    if !PREEMPT_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    // 本钩子在 LAPIC 定时器 IRQ 窗口内执行（IF=0）；切换窗口已被 cli
    // 物理遮蔽，无需守卫检查。锁临界区对持锁者不可见（其已被本核中断打断）。
    // M10-A：老化扫描回归本钩子（ring3 驻留期间本核 LVT 被屏蔽 = 老化
    // 随之暂停；该窗口的饥饿防护由 RESCHED 抢占钩子按 RESCHED 节拍兜底
    // ——量子轮转语义下双核 ring3 饱和仍无永久饥饿，见 t34/t31）。
    // M13-② 注记：timer 到期旗消费在 tickd 任务上下文（中断语境零
    // SCHED 触碰），本钩子保持 M9 形态。
    let cpu = my_cpu();
    let mut s = sched_lock!();
    let sc = &mut *s;
    aging_pass(&mut sc.ready, &mut sc.tasks);
    try_preempt_switch(sc, cpu, plan)
}

/// RESCHED 抢占判定体（wall_hook 本核路径与 RESCHED 钩子共享）：锁内
/// 老化扫描（全核 ring3 饱和期的饥饿防护供血）+ 本核抢占判定与 plan
/// 填写。调用方保证处于中断窗口（IF=0）。
fn resched_preempt_body(cpu: usize, plan: &mut PreemptPlan) -> bool {
    let mut s = sched_lock!();
    let sc = &mut *s;
    aging_pass(&mut sc.ready, &mut sc.tasks);
    try_preempt_switch(sc, cpu, plan)
}

/// 墙钟钩子（M10-A 核心；注册进 ostd::interrupt::stubs::set_wall_hook，
/// PIT IRQ0 窗口内调用——实测 ring3 交付安全，全上下文时间源）。
///
/// **极短 ISR 纪律（S31 缺陷族规避，M10 开发期实测记档）**：PIT 在
/// ring3 驻留期间不再被屏蔽（正是 M10-A 的时间源本意），而「长 ISR +
/// iretq 进 ring3 边缘」= TCG 帧腐坏触发面（VM 位入旗 #GP(0x28)，S31
/// 同族；初版墙钟钩子每 tick 取 SCHED 锁 + 老化扫描即复现）。故本钩子
/// 快路径**零锁、零任务表触碰**，全部原子操作：
/// 1. per-CPU 忙时账（CURRENT ≠ idle 即计，含 ring3 驻留——冻结面解除
///    的直接证据）；
/// 2. per-CPU 切片镜像 +1（量子判定数据源）；
/// 3. 量子越限检测（锁自由，`QUANTUM_TICKS` 边界才进入慢路径）：
///    - **本核**：直接以 [`resched_preempt_body`] 本地执行（量子边界
///      频次 ≈ 33 Hz，与 RESCHED 钩子在对侧的实测安全剖面一致；不经
///      自-IPI——QEMU xAPIC 自定向 ICR 实测不交付，M10 开发期记档）；
///    - **对侧核**：PREEMPT_REQ 旗 test-and-set + 定向 RESCHED IPI
///      （对侧 RESCHED 钩子消费执行，交付实测安全）。
///
/// 本核量子路径返回 try_preempt_switch 结果（可能填写 plan 桩执行交换）。
pub fn wall_hook(plan: &mut PreemptPlan) -> bool {
    for (c, slot) in CURRENT.iter().enumerate() {
        if slot.load(Ordering::Relaxed) != IDLE {
            PERCPU_TICKS[c].fetch_add(1, Ordering::Relaxed);
        }
    }
    for slot in PERCPU_RUN_TICKS.iter() {
        slot.fetch_add(1, Ordering::Relaxed);
    }
    // timer 阻塞源到期检测（M13-②）：PIT ISR 零锁纪律（S31 极短 ISR）
    // ——只碰原子量：置到期旗 + 跨核提示；唤醒工作由 RESCHED IPI /
    // LAPIC tick 消费者承载（本函数绝不取 SCHED / 触任务表）。
    if crate::timer::expire_pending_isr() {
        let kick = RESCHED_KICK.load(Ordering::Acquire);
        if kick != 0 {
            // SAFETY: 前置条件 —— 地址来自 set_resched_kick 存入的
            //          fn(usize)（与下方量子路径同一注册面）。
            // 不变式 —— Release/Acquire 配对；注册先于任何跨核派生。
            // 并发 —— IPI 发送侧天然多发布者安全（ICR 交付状态轮询）。
            // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
            let f: fn(usize) = unsafe { core::mem::transmute(kick) };
            f(1 - my_cpu());
        }
    }
    if !PREEMPT_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let cpu = my_cpu();
    let mut local_done = false;
    for c in 0..MAX_CPUS {
        let cur = CURRENT[c].load(Ordering::Relaxed);
        if cur == IDLE {
            continue;
        }
        if PERCPU_RUN_TICKS[c].load(Ordering::Relaxed) < QUANTUM_TICKS as u32 {
            continue;
        }
        if c == cpu {
            // 本核量子越限：本地执行（仅量子边界进入，快路径不受影响）
            let r = resched_preempt_body(cpu, plan);
            local_done = true;
            if r {
                return true;
            }
        } else if !PREEMPT_REQ[c].swap(true, Ordering::AcqRel) {
            // 对侧核：置请求旗 + 定向 RESCHED（旗未决时不重复发送）
            let kick = RESCHED_KICK.load(Ordering::Acquire);
            if kick != 0 {
                // SAFETY: 前置条件 —— 地址来自 set_resched_kick 存入的
                //          fn(usize)。
                // 不变式 —— Release/Acquire 配对；注册先于任何跨核派生。
                // 并发 —— IPI 发送侧天然多发布者安全（ICR 交付状态轮询）。
                // 违反后果 —— 跳转伪造地址即任意代码执行（注册纪律封死）。
                let f: fn(usize) = unsafe { core::mem::transmute(kick) };
                f(c);
            }
        }
    }
    let _ = local_done;
    false
}

/// RESCHED 抢占钩子（M10-A；注册进 set_resched_preempt_hook，向量 0x42
/// 窗口内调用）：消费本核 PREEMPT_REQ 旗（墙钟钩子量子检测置位——本核
/// 自-IPI 或对侧定向 IPI）→ 老化扫描兜底 → 抢占判定与 plan 交换。
///
/// 本钩子是 **ring3 抢占的唯一执行器**（LAPIC 钩子在 ring3 驻留期间被
/// prepare_dispatch 屏蔽，墙钟钩子极短化不填 plan）：交付实测安全
/// （t34 起全程冒烟无边缘缺陷）。旗未置（普通门铃：spawn/kick_pager）
/// → 立即放行，既有 RESCHED 语义零回归。
/// 老化兜底：双核皆 ring3 驻留时 LAPIC 钩子停摆，老化经本钩子按
/// RESCHED 节拍推进（饱和场景 ~量子级频次），饥饿防护不断供。
pub fn resched_preempt_hook(plan: &mut PreemptPlan) -> bool {
    let cpu = my_cpu();
    // M13-② 注记：timer 到期旗的消费在 tickd 任务上下文（timer::tickd_body
    // ，swapd 同款房屋范式）——中断语境零 SCHED 触碰（S31 纪律扩展到
    // RESCHED IPI 实测记档），本钩子保持 M10-A 原形态。
    if !PREEMPT_REQ[cpu].swap(false, Ordering::AcqRel) {
        return false;
    }
    if !PREEMPT_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    resched_preempt_body(cpu, plan)
}

// ---------------------------------------------------------------------------
// 任务阻塞态与调度点切换（M10-B）/ waitpid 收割面（M10-C）
// ---------------------------------------------------------------------------
// 语义：
// - **block_current_unless/waitpid**：登记等待对象 → Blocked（脱离就绪
//   队列）→ 锁窗探针（命中回滚）→ 切换下一
//   就绪任务（无则开中断等节拍重试——唤醒方入队 + RESCHED/节拍必达）。
//   `resume_if` 区分恢复点中断约定：syscall 上下文传 true（yield_now
//   同款，内核任务 IF 约定恒 1）；#PF 桩窗口传 false（iretq 前不得开窗
//   ——S31 缺陷族规避，恢复点保持 IF=0 直至桩尾重执行）。
// - **wake_tasks**：谓词匹配批量唤醒（wait 清除 → Ready → 按 base 级
//   入队 → RESCHED 跨核提示）。谓词由调用方定义（vmm 换页 / procs 进程
//   间等待各自语义，调度器不硬编码）。
// - **wait_scan**：WAIT_PID 扫描 + 收割原子面（单锁窗口）：遍历直接
//   子任务，首个 Zombie 即取退出码并释放槽位（Zombie 不在任何队列、
//   CURRENT 已随终结切换面更新、句柄表已清算——三条件收割安全）。
//   收割任务若有存活子任务则成为孤儿（其 parent 指向已释放槽位 →
//   授权/等待面 fail-closed，v0 不递归收割）。
//
// 竞态窗口记档：block/yield/finish 的「锁释放 → 物理切换」间隙内，另
// 一核理论上可拾取本核刚回队的任务（ctx 尚未保存）——与 M6 以来
// yield_now 同款既有窗口（数指令宽度，M6–M9 三十余项裸机自检未观测）；
// M10 不扩大该窗口（block 无就绪者时走 halt 重试而非 idle 二段锁），
// 根治 = 切换握手协议，随 M11 调度面演进。

/// 阻塞当前任务（M10-B）：登记等待对象 → Blocked → 切换到下一就绪任务；
/// 唤醒后从调用点之后继续（恢复点 IF 约定见 `resume_if`）。
///
/// 无就绪任务时：开中断 halt 等待节拍/RESCHED 后重试拾取（唤醒方入队
/// 后必经 kick_other 或节拍驱动重派发）。阻塞态登记在重试循环外幂等。
///
/// # PANIC（防御）
/// 本核 CURRENT = idle 时阻塞即调度不变式破坏（idle 无任务上下文），
/// 直接终止调用方（调用面契约：仅任务上下文可调用）。
/// 条件阻塞（M11-C）：登记等待对象前在**同一 SCHED 锁窗口**内执行
/// `still_pending` 重探。返回 `false` = 探针命中（条件已就绪）：登记
/// 已回滚、任务保持 Running 原地继续，调用方应直接重试消费；返回
/// `true` = 已真实阻塞且已被唤醒（恢复点在本调用返回之后）。
///
/// 丢失唤醒免疫论证：探针与发送方的 `wake_tasks` 同以 SCHED 锁串行化
/// ——若推送先于探针，探针命中（不阻塞，直接消费）；若推送晚于探针，
/// 发送方随后的 `wake_tasks` 在锁窗口内必然观察到 Blocked 登记并唤醒。
/// 二者必有其一观察到对方，无中间窗口。探针必须**非消费**（如
/// `FastPath::pending` 哨兵读数），消费性操作由调用方在阻塞返回后
/// 的重试路径完成。
///
/// # PANIC（防御）
/// 本核 CURRENT = idle 时阻塞即调度不变式破坏，直接终止调用方。
pub fn block_current_unless(
    what: WaitWhat,
    resume_if: bool,
    mut still_pending: impl FnMut() -> bool,
) -> bool {
    block_current_impl(what, resume_if, Probe::Raw(&mut still_pending))
}

/// WAIT_PID 专用条件阻塞（丢失唤醒窗口补钉）：登记 Child 等待后于
/// **同一 SCHED 锁窗口**内重扫直接子任务——匹配者已是 Zombie（粘滞
/// 终态）则回滚登记返回 `false`（调用方重扫即收割，判定与收割之间
/// 无新窗口）；否则照常阻塞，返回 `true` = 已真实阻塞且被唤醒。
/// 子任务 EXIT 的唤醒（finish 锁窗口内）与本探针同锁串行化——
/// 「先收割后阻塞」或「先登记后唤醒」二者必有其一成立。
pub fn block_current_waitpid(parent: usize, want: u64, resume_if: bool) -> bool {
    block_current_impl(
        WaitWhat::Child { pid: want as usize },
        resume_if,
        Probe::WaitScan { parent, want },
    )
}

/// 锁窗口探针（M11-C/M11 补钉）：登记 Blocked 后在同一 SCHED 锁窗口
/// 内执行——命中（返回 true = 条件已就绪）则回滚登记不阻塞。探针在
/// 锁窗口内运行是与唤醒方（wake_tasks 同锁串行化）互见的全部根据，
/// 丢失唤醒免疫由此成立。Zombie/SWAPPED 等粘滞态使命中判定与后续
/// 消费之间无新窗口。
enum Probe<'a> {
    /// 调用方闭包（IPC pending 哨兵等非消费读数）。
    Raw(&'a mut dyn FnMut() -> bool),
    /// WAIT_PID 专用：锁内重扫直接子任务，匹配者已 Zombie 即命中
    /// （want = 0 任意 / 非 0 定向）。
    WaitScan { parent: usize, want: u64 },
}
fn block_current_impl(what: WaitWhat, resume_if: bool, mut probe: Probe) -> bool {
    let mut w = IntWindow::new();
    // M22-③ [C] 收口（ff46/ff52 家族根治）：halt 停机经历旗。None 分支
    // 的停机等待 = **真实阻塞**（任务已登记 Blocked、时钟真实推进、到期
    // 链真实点火）；停机被中断打断后循环重入的探针重判若逢条件已达成，
    // 语义是「阻塞期间条件满足」= 唤醒，而非「从未阻塞」的探针命中——
    // 旧码一律降格为探针命中返回 false，nanosleep 唤醒计数（TIMER_WAKES）
    // 被 halt 重入路径吞掉（t46 `wakes>=1` / t52 `blocks>=1&&wakes>=1`
    // 隐形击发根因，闲置核上阻塞必现）。
    let mut halted = false;
    loop {
        let cpu = my_cpu();
        let cur = CURRENT[cpu].load(Ordering::Relaxed);
        let pair = {
            let mut s = sched_lock!();
            let sc = &mut *s;
            if cur == IDLE {
                panic!("block_current: no task context (idle)");
            }
            // 唤醒检测（halt 重试环专用）：wait 已被 wake 清除且状态 Ready
            // = 本任务停机等待期间已被唤醒入队——**不得重登记**（重登记吞掉
            // 唤醒并令 pick_best 自拾取队列中的自己 → slots_pair 自切换越界，
            // t37 压测实录）。处置：出队 + 回 Running + 返回「已唤醒」，
            // 调用方按语义重扫（收割/消费）。首入不含此态（调用方 Running，
            // wait 本为 None 但状态非 Ready）。
            let woken = sc.tasks[cur]
                .as_ref()
                .is_some_and(|t| t.wait.is_none() && t.state == State::Ready);
            if woken {
                remove_value(&mut sc.ready, cur);
                if let Some(t) = sc.tasks[cur].as_mut() {
                    t.state = State::Running;
                    t.waited = 0;
                }
                drop(s);
                if resume_if {
                    ostd::hw::intr::enable();
                }
                drop(w);
                return true; // 已唤醒：调用方重扫（探针/扫描语义）
            }
            if let Some(t) = sc.tasks[cur].as_mut() {
                t.wait = Some(what);
                t.state = State::Blocked;
                t.waited = 0;
            }
            // 条件探针（同一 SCHED 锁窗口）：命中即回滚登记——登记与探针
            // 的原子性是丢失唤醒免疫的全部根据
            let probe_hit = match &mut probe {
                Probe::Raw(f) => !f(),
                Probe::WaitScan { parent, want } => {
                    sc.tasks.iter().enumerate().any(|(id, slot)| {
                        slot.as_ref().is_some_and(|t| {
                            t.parent == Some(*parent)
                                && t.state == State::Zombie
                                && (*want == 0 || id == *want as usize)
                        })
                    })
                }
            };
            if probe_hit {
                if let Some(t) = sc.tasks[cur].as_mut() {
                    t.wait = None;
                    t.state = State::Running;
                }
                drop(s);
                drop(w);
                if halted {
                    // 停机经历后的「命中」= 真实阻塞期间条件达成，按唤醒
                    // 分类返回（调用方唤醒计数如实落账）。探针闭包可能已
                    // 再武装陈值哨兵（nanosleep fetch_min 旧 deadline）——
                    // 到期链「陈值只致多一次空检」无害收敛，语义不变。
                    if resume_if {
                        ostd::hw::intr::enable();
                    }
                    return true;
                }
                return false; // 探针命中：未阻塞，调用方直接重试消费
            }
            match pick_best(&mut sc.ready, &sc.tasks, cpu, IDLE, None) {
                Some(id) => {
                    remove_value(&mut sc.ready, id);
                    if let Some(t) = sc.tasks[id].as_mut() {
                        t.state = State::Running;
                    }
                    PERCPU_RUN_TICKS[cpu].store(0, Ordering::Relaxed);
                    CURRENT[cpu].store(id, Ordering::Relaxed);
                    sc.cooperative_switches += 1; // 自愿让出（阻塞）计入协作面
                    let boot = sc.boot_cr3;
                    if let Some(t) = sc.tasks[id].as_ref() {
                        prepare_dispatch(t, boot, cpu);
                    }
                    Some(slots_pair(sc, cur, id))
                }
                None => None,
            }
        };
        match pair {
            Some(p) => {
                switch_deferred(p); // 唤醒重派发后从此继续
                break;
            }
            None => {
                // 无就绪任务：开中断等节拍/RESCHED（唤醒方入队必伴随后者）
                drop(w);
                ostd::hw::intr::enable();
                ostd::hw::intr::halt();
                w = IntWindow::new();
                halted = true; // 停机 = 真实阻塞面（重入探针命中按唤醒分类）
            }
        }
    }
    if resume_if {
        ostd::hw::intr::enable();
    }
    drop(w);
    true
}
/// 扫描含槽位 0（主任务可阻塞——t35 的故障上下文即主任务）。
pub fn wake_tasks(matcher: impl Fn(&WaitWhat) -> bool) -> usize {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let sc = &mut *s;
    let mut woken = 0usize;
    for id in 0..MAX_TASKS {
        let Some(t) = sc.tasks[id].as_mut() else {
            continue;
        };
        if t.state != State::Blocked {
            continue;
        }
        let matched = t.wait.is_some_and(|w| matcher(&w));
        if matched {
            t.wait = None;
            t.state = State::Ready;
            t.waited = 0;
            let p = t.base_prio;
            enqueue(&mut sc.ready, id, p);
            woken += 1;
        }
    }
    drop(s);
    if woken != 0 {
        BLOCK_WAKES.fetch_add(woken as u64, Ordering::AcqRel);
        kick_other();
    }
    woken
}

/// WAIT_PID 扫描结果（单锁窗口内原子完成扫描 + 收割）。
pub struct ChildScan {
    /// 存在匹配条件的直接子任务（无论是否已终结）。
    pub has_child: bool,
    /// 收割到的首个已终结子任务 (pid, exit_code)；槽位已释放。
    pub reaped: Option<(usize, u64)>,
    /// M21-① 护槽：存在匹配 Zombie 但握手旗未清（锁外现场保存进行中）
    /// ——调用方须改挂短 Timer 等待重扫（Child 等待唤醒已发射完毕，
    /// 再挂 Child 等待将永失唤醒）。
    pub gated: bool,
}

/// WAIT_PID 扫描 + 收割（M10-C）：在单 SCHED 锁窗口内遍历 `parent` 的
/// 直接子任务（`want` = 0 任意 / 非 0 定向），收割首个 Zombie（取退出码
/// 并释放槽位）。收割安全性：Zombie 不在任何队列、CURRENT 已随终结
/// 切换面更新、句柄表已清算、退出码已登记。
#[allow(clippy::needless_range_loop)] // tasks 与 SWITCHING 双数组并行索引，迭代器化反失语义
pub fn wait_scan(parent: usize, want: u64) -> ChildScan {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let sc = &mut *s;
    let mut scan = ChildScan {
        has_child: false,
        reaped: None,
        gated: false,
    };
    for id in 1..MAX_TASKS {
        let Some(t) = sc.tasks[id].as_ref() else {
            continue;
        };
        if t.parent != Some(parent) {
            continue;
        }
        if want != 0 && id != want as usize {
            continue;
        }
        scan.has_child = true;
        if t.state == State::Zombie {
            if SWITCHING[id].load(Ordering::Acquire) != 0 {
                // M21-① 护槽：死者现场保存未完成（微秒级窗口），本窗
                // 不收割——槽位释放必须等旗清（鬼影保存写复用槽封死）。
                scan.gated = true;
            } else if scan.reaped.is_none() {
                let code = t.exit_code;
                scan.reaped = Some((id, code));
                sc.tasks[id] = None; // 收割：槽位释放回收（alloc_slot 可复用）
            }
        }
    }
    scan
}

/// 目标任务槽位是否存活（M10-C 自检 36 收割断言面；None = 未占用/已收割）。
pub fn task_alive(id: usize) -> bool {
    let _w = IntWindow::new();
    let s = sched_lock!();
    s.tasks.get(id).is_some_and(|slot| slot.is_some())
}

/// 孤儿链取证（M12-d t43 断言面）：累计 re-parent 孤儿数 / idle 自动
/// 收割孤儿僵尸数。
static ORPHANS_REPARENTED: AtomicU64 = AtomicU64::new(0);
static ORPHAN_REAPS: AtomicU64 = AtomicU64::new(0);

/// 任务退出码诊断（M12-d t43 排障临时面）。
pub fn task_debug_exit_code(id: usize) -> u64 {
    let _w = IntWindow::new();
    let s = sched_lock!();
    s.tasks
        .get(id)
        .and_then(|t| t.as_ref())
        .map_or(u64::MAX, |t| t.exit_code)
}

/// 任务状态诊断戳（M12-d t43 排障临时面；0 无 1 Ready 2 Running
/// 3 Blocked 4 Zombie）。
pub fn task_debug_state(id: usize) -> u8 {
    let _w = IntWindow::new();
    let s = sched_lock!();
    match s.tasks.get(id).and_then(|t| t.as_ref()) {
        None => 0,
        Some(t) => match t.state {
            State::Ready => 1,
            State::Running => 2,
            State::Blocked => 3,
            State::Zombie => 4,
        },
    }
}

/// 孤儿链取证快照：(re-parent 孤儿数, idle 自动收割数)。
pub fn orphan_stamps() -> (u64, u64) {
    (
        ORPHANS_REPARENTED.load(Ordering::Acquire),
        ORPHAN_REAPS.load(Ordering::Acquire),
    )
}

/// 孤儿僵尸收割（M12-d 运行时化面）：仅收割 **parent = None** 的
/// Zombie（无主 = 原父已终结 or 内核直接派生的哑元）；有主 Zombie
/// 严格保留给其父的 WAIT_PID（退出码不掠夺——否则等待方语义破环）。
/// 返回清扫数。idle 附加工作调用（见 IDLE_REAP 桥）。
#[allow(clippy::needless_range_loop)] // tasks 与 SWITCHING 双数组并行索引，迭代器化反失语义
pub fn reap_orphans() -> usize {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let sc = &mut *s;
    let mut n = 0usize;
    for id in 1..MAX_TASKS {
        if sc.tasks[id]
            .as_ref()
            .is_some_and(|t| t.state == State::Zombie && t.parent.is_none())
            && SWITCHING[id].load(Ordering::Acquire) == 0
        {
            // M21-① 护槽：旗未清（锁外现场保存进行中）不收割——idle
            // 轮询面下一轮自然重扫（保存窗微秒级，无饥饿面）。
            sc.tasks[id] = None;
            n += 1;
        }
    }
    if n != 0 {
        ORPHAN_REAPS.fetch_add(n as u64, Ordering::AcqRel);
    }
    n
}

/// 僵尸清扫（M11 槽位卫生面）：收割全部 Zombie 槽位（句柄已随终结
/// 清算、退出码已留证——与 wait_scan 收割同款三条件安全）。返回清扫数。
/// 自检序列的槽位回收面：t12 起的哑元任务/哑终点不再永久占位。
#[allow(clippy::needless_range_loop)] // tasks 与 SWITCHING 双数组并行索引，迭代器化反失语义
pub fn reap_zombies() -> usize {
    let _w = IntWindow::new();
    let mut s = sched_lock!();
    let sc = &mut *s;
    let mut n = 0usize;
    for id in 1..MAX_TASKS {
        if sc.tasks[id]
            .as_ref()
            .is_some_and(|t| t.state == State::Zombie)
            && SWITCHING[id].load(Ordering::Acquire) == 0
        {
            // M21-① 护槽：同 reap_orphans——旗未清不收割。
            sc.tasks[id] = None;
            n += 1;
        }
    }
    n
}

/// 握手旗全清快照（t40 断言面：系统静默期全部槽位应为 0——旗置位
/// 仅存在于切换窗口内数指令宽度，任何非切换时刻观测到置位即失约）。
pub fn handshake_flags_clear() -> bool {
    let _w = IntWindow::new();
    SWITCHING.iter().all(|f| f.load(Ordering::Acquire) == 0)
}
