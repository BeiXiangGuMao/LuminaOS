//! 常驻 Wayland 合成器服务面（M42-COMP4 阶段三首笔——「合成器进程面」
//! 电气承接域）。
//!
//! **定位**：M42-计划 阶段三「wayland 合成器进程消费 SYS_FB_SURFACE +
//! unix socket 域与 wire 壳的合流电气面」的常驻服务首割——boot-spawn
//! 常驻服务（kmain 单调用点，M42-FBSVC2 服务环铸造 boot 面同谱）：
//! unix socket 名域监听（bind 即 listen）→ **阻塞 accept**（op 6
//! ACCEPT_B 电气域——`WaitWhat::UnixAccept` 唤醒链）→ 会话环
//! （recv 流积累 → [`prism::wayland::comp::CompSession::feed`] 合流
//! 解析 → commit 发布应用 → 事件回执 send）→ EOF 对端终结（shutdown
//! 面排空 EOF 即会话收场）。
//!
//! **合流电气面**（unix socket 域 ⇄ wire 壳 ⇄ SYS_FB_SURFACE）：
//! - wire 壳 = [`prism::wayland::comp`]（仲裁策略面——registry 公告/
//!   bind/surface 生命周期/damage-commit 发布语义，零堆纯函数）；
//! - unix socket 域 = [`crate::unixsock`]（对象寻址双生面——
//!   bind_by_name/accept_by_object/send_by_object/recv_by_object，
//!   t103 echo worker 先例同心出口）；
//! - SYS_FB_SURFACE = [`crate::fb`] 机械面（surf_register/update/
//!   remove + sys_fb_sync 损伤量化 + fb_compose_tick 合成执行——
//!   prism Stack::blend 内核机械域保持，ADR-0004 双轨）。
//!
//! **仲裁策略面承接**（loom/cascade 用户态承接首割）：合成器窗口几
//! 何/z 序 = cascade::tiling::tiling_plan 产出（窗口首次映射序 = 焦
//! 点序 v0 口径；loom PANEL_HEIGHT/DOCK_HEIGHT/GRID 常量同源经由
//! cascade 消费——t79「两套面同一几何」先例），z = [`POLICY_Z_BASE`]
//! − 平面序号（master 顶层）。策略产出经 prism::wayland::comp
//! set_geometry 注入 + SYS_FB_SURFACE 登记（t104 经
//! [`crate::fb::surf_layer_of`] 读回对账——策略面产出 = 表内登记）。
//!
//! **内容面**（M42-ELF5 次笔——客户端像素缓冲域落域）：commit 损伤
//! 域优先自 **wl_shm 池**读客户端像素（`prism::wayland::comp`
//! BufferRec 几何 + [`crate::shm::pool_px_read`] 物理帧直读——fd 附
//! 带数据 SEND_FD/RECV_FD 传递面承接）；无附 buffer / 池缺席回退代
//! Paint（[`pane_pattern`] 确定性模式——t104 语义面保持）；ring3 客
//! 户端直写窗 face = SYS_FB_SURFACE op0 单客户 CAS 既有在环（t88
//! 同源）。
//!
//! **ring3 编译进程承接**（M42-ELF5 同笔落域）：桌面链客户端 = 用户
//! 态 ELF 播种 lane 环内进程（[`crate::procs::spawn_elf_seed`]——真
//! ELF64 静态映像原生 ABI 播种，t106 SHM_CLIENT 消费面）。
//!
//! **重排改写面**（M42-GEOM6 域①——UPDATE 几何演进，M42-COMP4
//! 「窗数演进重排 × REGISTER 形状锁」挂账域兑现）：窗数演进（增窗/
//! 销窗）→ cascade tiling 重排 → [`policy_rewrite`] 重排改写执行器
//! 对几何演进窗执行 fb 演进域 UPDATE（[`crate::fb::surf_update`] 形
//! 状锁退役——增长补配 + 透明基线）+ **全幅重呈现**（客户端池像素
//! 全 pane 重漆 / 代 Paint 回退）+ SYNC/COMPOSE；destroy 摘除记录
//! （[`DropLog`]）经 [`drop_apply`] 摘窗 → 存活窗重排。策略驱动
//! （feed 后每轮）而非 commit 驱动——重排改写与客户端提交解耦
//! （真实合成器语义：重排不依赖客户端重绘）。
//!
//! **输入链**（M42-INPUT7——waycomp 主体迁移前置，wl_seat +
//! wl_keyboard 输入链；**M42-WAYCOMP12 笔⑫ 双域落域**；**M42-WAYCOMP13
//! 笔⑬ evdev 键码映射 + keymap 内容面落域**；**M42-WAYCOMP14 笔⑭
//! wl_pointer axis 族/frame 落域**）：全局输入源
//! （[`input_key`] / [`input_pointer_motion`] / [`input_pointer_button`]
//! / [`input_pointer_axis`] / [`input_pointer_axis_stop`]
//! 生产面——v0 内核态注入域，**ring3 输入守护门禁在环**〔域①——
//! Kind::User 语境拒绝 fail-visible，ABI 负空间纪律：SYS 号域零注入
//! 臂〕）→ 会话环排空（[`drain_input`]——键盘 evdev 映射直注入；
//! 指针 hit-test 焦点裁决〔z 序顶窗优先——cascade 平面逆序首个含点
//! 窗〕+ click-to-focus〔按下域指针焦点面 = 键盘焦点迁移域〕+ 轴域
//! 扫掠〔AXIS_Q 排空 → axis_source 前置 + axis/axis_stop 批 + 扫掠
//! 终结 frame——官方分组语义〕）→ 会话待发队列（prism CompSession
//! 焦点/注入钩子）→ feed 冲刷 wl_keyboard/wl_pointer 事件出域 → 客
//! 户端。会话环 = **阻塞输入等
//! 待面**（域②——WaitWhat::CompIn 扩域：三静域〔输入队列空 + 会话
//! 流空 + 非终结〕登记阻塞，v0 探针轮询 + 让步口径退役；唤醒源三向
//! = 输入生产 wake 全域 + send 落环 conn 匹配域 + shutdown 双向；
//! 探针预捕获静态视图零锁读——SCHED 锁窗内零 SOCKETS 取锁）。
//!
//! **常驻生命周期**（M42-FBSVC2 挂账域首割）：boot-spawn（kmain 单
//! 调用点）+ 会话环常驻（accept ↔ session 循环不退出）；bind 失败/
//! 监听者终结 = 服务退场（fail-visible——boot 证据行
//! `LUMINA-WAYCOMP-BOOT` 缺位即 S8 显形）；**服务退出后 boot 重启
//! 面挂账**（M42-FBSVC2 既录口径不变）。
//!
//! **多产者域**（M42-WAYCOMP16 笔⑯——v0 事实单生产者域退役）：内核
//! 任务语境多产者并发注入经 [`IN_MU`] SpinLock 串行化窗承接（SPSC
//! 环 SPSC 契约以生产侧互斥保持——消费侧单线程不变；锁窗 send 即放
//! 零嵌套，唤醒链锁外域）。
//!
//! **ISR 臂**（M42-WAYCOMP17 笔⑰——kbd→waycomp 转接臂落域）：kbd
//! IRQ1 桩体（[`crate::kbd`] `on_scancode` 转接臂车道）scancode 键
//! 态语义直传 [`input_key_isr`]——**内核语境旗** [`IN_ISR_CTX`] 随
//! 批（per-cpu 置位/复位：ISR 语境 = 内核语境定义域，被打断任务的
//! 用户性与本批无关——[`input_guard`] 旗快路径放行，current_is_user
//! 的 SCHED 锁窗任务查询免除〔M40-ASH2 ISR 快路径纪律同谱——
//! PERCPU_IS_USER 零锁旗先例〕）+ **[`IN_MU`] try_lock 有界退避随
//! 批**（ISR 语境禁自旋——持锁者可能为被打断任务，同核自旋永不推
//! 进死锁窗；退避耗尽即丢弃 + [`WLCOMP_ISR_DROP`] fail-visible）。
//! tty 车道（KBD_RING ASCII 控制面）与 waycomp 车道（KEY_Q 键态语
//! 义直传）双车道分域——同批 scancode 双投递独立消费（tty 消费者 =
//! 行规程读侧，waycomp 消费者 = 会话环 drain，互不相扰）。
//!
//! 锁序契约：[`IN_MU`] 自持锁（生产域串行化——单锁窗即放，零嵌套，
//! 唤醒链锁外域；ISR 臂 try_lock 窗同谱——try_lock 零等待无自旋
//! 窗）；[`IN_ISR_CTX`] 零锁旗（per-cpu 随批自持——PERCPU_IS_USER
//! 同谱纪律，非锁零嵌套）；域内锁全部单取即放（unixsock/fb 单锁纪
//! 律同谱）；阻塞点 = accept_wait（WaitWhat::UnixAccept）+ 会话环
//! 三静域（WaitWhat::CompIn——M42-WAYCOMP12 扩域，探针零锁读）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use mirror::Rect;
use morse::KEYCODE_WL_OFFSET;
use ostd::sync::spsc::SpscRing;
use ostd::sync::SpinLock;
use prism::wayland::comp::{
    BufferRec, CommitRecord, CompSession, FeedReport, GlobalDef, GLOBALS_MAX, KEYMAP_XKB_V1,
};

use crate::{fb, shm, task, unixsock};

/// 合成器套接字名（平名命名域——`wayland-0` 名字域被 t103 回环面终身
/// 占用〔对象存续纪律〕，常驻合成器名域正交登记如实记档）。
pub const WAYCOMP_SOCK_NAME: &[u8] = b"wayland-comp";
/// 策略面视口（stdvga LFB 全谱 1920×1080——fb WIDTH/HEIGHT 同源）。
pub const VIEWPORT: (u32, u32) = (1920, 1080);
/// z 序基（master 顶层——t79 仲裁样本同谱；cascade 平面序号递减）。
pub const POLICY_Z_BASE: i32 = 20;
/// 会话 fb surface id 基跨度（session_seq − 1 左移域——跨会话 id 正交）。
pub const FB_ID_SESSION_STRIDE: u32 = 0x1000;
/// registry 公告名单（核心子集四 global——t104 客户端对账事实源）。
const GLOBALS: [GlobalDef; GLOBALS_MAX] = [
    GlobalDef {
        name: 1,
        iface: prism::wayland::WlIface::Compositor,
        version: 4,
    },
    GlobalDef {
        name: 2,
        iface: prism::wayland::WlIface::Seat,
        version: 1,
    },
    GlobalDef {
        name: 3,
        iface: prism::wayland::WlIface::Shm,
        version: 1,
    },
    GlobalDef {
        name: 4,
        iface: prism::wayland::WlIface::Output,
        version: 2,
    },
];

// ---- 取证戳（t104 断言面）----
/// 常驻监听者对象 id（0 = 未 bind——boot 面对账锚）。
pub static WLCOMP_LISTENER: AtomicU64 = AtomicU64::new(0);
/// bind 完成旗（boot 证据行 `LUMINA-WAYCOMP-BOOT` 门槛）。
pub static WLCOMP_BOUND: AtomicBool = AtomicBool::new(false);
/// 会话建立数（connect → accept 唤醒链对账）。
pub static WLCOMP_SESSIONS: AtomicU64 = AtomicU64::new(0);
/// commit 应用数（damage-commit 发布域对账）。
pub static WLCOMP_COMMITS: AtomicU64 = AtomicU64::new(0);
/// 合成执行数（fb_compose_tick 调用数——合流电气面对账）。
pub static WLCOMP_COMPOSES: AtomicU64 = AtomicU64::new(0);
/// 最近登记 z（仲裁策略面承接证据——cascade 平面序号域）。
pub static WLCOMP_LAST_Z: AtomicI32 = AtomicI32::new(0);
/// 会话序号铸造器（fb id 域正交基）。
static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);
/// teardown 域 remove 失败计数（t104 取证面）。
pub static WLCOMP_REMOVE_ERR: AtomicU64 = AtomicU64::new(0);
/// teardown 末态 surf_count 快照（t104 取证面）。
pub static WLCOMP_END_COUNT: AtomicU64 = AtomicU64::new(0);
/// 会话收场完成旗（teardown 全域终了——t104 客户端等待域；accept 时
/// 复位，收场 store(true) 于 shutdown_by_object 前）。
pub static WLCOMP_SESSION_DONE: AtomicBool = AtomicBool::new(false);
/// wl_shm 池承接成功数（fd 附带数据 RECV_FD 落账——t106 断言面）。
pub static WLCOMP_POOLS: AtomicU64 = AtomicU64::new(0);
/// wl_shm 池承接失败数（RECV_FD 空队/能力缺——fail-visible 取证）。
pub static WLCOMP_FD_ERR: AtomicU64 = AtomicU64::new(0);
/// 客户端像素上屏数（池像素写——pane 代 Paint 替代域对账）。
pub static WLCOMP_SHM_PAINTS: AtomicU64 = AtomicU64::new(0);
/// 重排改写执行数（M42-GEOM6 域①——几何演进 UPDATE + 全幅重呈现
/// 执行计数，t107 断言面）。
pub static WLCOMP_REWRITES: AtomicU64 = AtomicU64::new(0);
/// destroy 摘除执行数（M42-GEOM6 域①——DropLog 电气面摘窗计数，
/// t107 断言面）。
pub static WLCOMP_DROPS: AtomicU64 = AtomicU64::new(0);
/// 键盘事件 wire 发出数（M42-INPUT7——feed 冲刷 KeyLog 记录批计数，
/// t109 断言面）。
pub static WLCOMP_KEYS: AtomicU64 = AtomicU64::new(0);
/// 指针事件 wire 发出数（M42-INPUT7——feed 冲刷 PtrLog 记录批计数，
/// t109 断言面）。
pub static WLCOMP_PTRS: AtomicU64 = AtomicU64::new(0);
/// 键盘焦点面快照（M42-INPUT7——首窗初始聚焦 + click-to-focus 迁移
/// 取证，t109 断言面）。
pub static WLCOMP_KBFOCUS: AtomicU32 = AtomicU32::new(0);
/// 输入源键盘注入受理数（M42-INPUT7——会话注入成功计数）。
pub static WLCOMP_INPUT_KEYS: AtomicU64 = AtomicU64::new(0);
/// 输入源指针注入受理数（M42-INPUT7——会话 hit-test 命中域计数）。
pub static WLCOMP_INPUT_PTRS: AtomicU64 = AtomicU64::new(0);
/// ring3 输入守护违规计数（M42-WAYCOMP12 域①——Kind::User 任务语境
/// 的注入调用拒绝取证；fail-visible 零静默——t113 断言面）。
pub static WLCOMP_GUARD_ERR: AtomicU64 = AtomicU64::new(0);
/// 会话环阻塞登记数（M42-WAYCOMP12 域②——三静域阻塞点登记前计数
/// 〔t39 口径：阻塞点即落证〕；含探针命中未阻塞域——WAKES 为真实
/// 阻塞显形面，t113 断言面）。
pub static WLCOMP_IN_WAITS: AtomicU64 = AtomicU64::new(0);
/// 会话环阻塞唤醒数（M42-WAYCOMP12 域②——CompIn 真实阻塞后被唤醒
/// 计数：唤醒源三向〔输入生产/send 落环/shutdown〕全谱对账，t113
/// 断言面）。
pub static WLCOMP_IN_WAKES: AtomicU64 = AtomicU64::new(0);
/// evdev 映射拒收数（M42-WAYCOMP13——键码域外 scancode 排空丢弃取
/// 证：0x59..=0x7F 杂域/0xE0 前缀扩展域挂账随批，t114 断言面）。
pub static WLCOMP_KEY_UNMAPPED: AtomicU64 = AtomicU64::new(0);
/// keymap 内容面承接成功数（M42-WAYCOMP13——铸池+填充+SEND_FD 全链
/// 落账，t114 断言面）。
pub static WLCOMP_KEYMAPS: AtomicU64 = AtomicU64::new(0);
/// keymap 承接失败数（M42-WAYCOMP13——铸池/填充/SEND_FD 任一域失败
/// fail-visible 取证：内容面零交付）。
pub static WLCOMP_KEYMAP_FD_ERR: AtomicU64 = AtomicU64::new(0);
/// 轴事件 wire 发出数（M42-WAYCOMP14——drain 轴域扫掠受理计数，t115
/// 断言面）。
pub static WLCOMP_AXES: AtomicU64 = AtomicU64::new(0);
/// 手势终结 wire 发出数（M42-WAYCOMP14——axis_stop 扫掠受理计数，
/// t115 断言面）。
pub static WLCOMP_AXIS_STOPS: AtomicU64 = AtomicU64::new(0);
/// 轴源声明 wire 发出数（M42-WAYCOMP14——扫掠内轴源变化域计数，t115
/// 断言面）。
pub static WLCOMP_AXSRC: AtomicU64 = AtomicU64::new(0);
/// 分组终结 wire 发出数（M42-WAYCOMP14——每扫掠一 frame 出域计数，
/// t115 断言面）。
pub static WLCOMP_FRAMES: AtomicU64 = AtomicU64::new(0);
/// 轴域越界拒收数（M42-WAYCOMP14——axis>1/source>3 生产域闸 fail-
/// visible 取证，t115 断言面）。
pub static WLCOMP_AXIS_BAD: AtomicU64 = AtomicU64::new(0);
/// modifiers wire 发出数（M42-WAYCOMP15——feed 回执 Modifiers 记录批
/// 计数：语义核变更域 + enter 快照域全谱，t116 断言面）。
pub static WLCOMP_MODS: AtomicU64 = AtomicU64::new(0);
/// 修饰键 depressed 掩码快照（M42-WAYCOMP15——排空域会话语义核末态
/// 读出，t116 端到端断言面）。
pub static WLCOMP_MODS_DEP: AtomicU32 = AtomicU32::new(0);
/// 生产域串行化计数（M42-WAYCOMP16——IN_MU 锁窗受理次数 = 多产者域
/// 取证戳，t117 断言面；ISR 臂锁窗同谱计入，t118 断言面）。
pub static WLCOMP_MPS: AtomicU64 = AtomicU64::new(0);
/// ISR 臂内核语境旗路径放行数（M42-WAYCOMP17——[`IN_ISR_CTX`] 旗命
/// 中即计：放行路径可辨——旗路径而非任务查询路径，旗面活体取证，
/// t118 断言面）。
pub static WLCOMP_ISR_PASS: AtomicU64 = AtomicU64::new(0);
/// ISR 臂 try_lock 有界退避耗尽丢弃数（M42-WAYCOMP17——[`IN_MU`]
/// 争用窗退避耗尽 fail-visible 取证：ISR 语境零静默丢弃，t118 断言
/// 面）。
pub static WLCOMP_ISR_DROP: AtomicU64 = AtomicU64::new(0);
/// ISR 臂队满丢弃数（M42-WAYCOMP17——KEY_Q 容量域 fail-visible 取
/// 证：消费域停滞窗〔会话缺席/阻塞〕溢出显形，t118 断言面）。
pub static WLCOMP_ISR_FULL: AtomicU64 = AtomicU64::new(0);

/// 输入源队列深度（键盘/指针/轴各一定容——定容零堆纪律；M42-WAYCOMP16
/// 多产者域在环——SPSC 契约以 IN_MU 生产侧互斥保持）。
const INPUT_CAP: usize = 16;
/// 键盘输入队列（元素 = (key << 32) | state 打包）。
static KEY_Q: SpscRing<u64, INPUT_CAP> = SpscRing::new();
/// 指针输入队列（元素 = bit63=按钮旗 | (button/x << 32) | state/y）。
static PTR_Q: SpscRing<u64, INPUT_CAP> = SpscRing::new();
/// 轴输入队列（M42-WAYCOMP14——独立定容环与 PTR_Q 分域：元素 =
/// bit36=手势终结旗 | bit37=轴源有效旗 | **bit38=帧界标记旗**
/// 〔M42-WAYCOMP17 揭雷③收口——生产者标记帧界〕 | source << 34 |
/// axis << 32 | value i32 原字；位域正交性 = 独立环承载，无 bit63/62
/// 冲突窗）。
static AXIS_Q: SpscRing<u64, INPUT_CAP> = SpscRing::new();
/// 输入生产域互斥（M42-WAYCOMP16 笔⑯——**多产者域**：内核任务语境
/// 多产者并发注入经 SpinLock 串行化窗承接——SpscRing SPSC 契约以生
/// 产侧互斥保持，消费侧单线程不变；锁窗 = send 即放零嵌套，唤醒链
/// 锁外域〔IN_MU → SCHED 锁序单向〕；ISR 臂在环（M42-WAYCOMP17——
/// `input_key_isr`：try_lock 有界退避随批 + IN_ISR_CTX 内核语境旗
/// 随批，try_lock 零等待无自旋窗——ISR 语境纪律在环）。
static IN_MU: SpinLock<u32> = SpinLock::new(0);

/// 内核语境旗（M42-WAYCOMP17 笔⑰——ISR 臂随批携带）：per-cpu ISR
/// 语境旗——kbd IRQ1 转接臂入批前置位、出批复位（swap/restore 嵌套
/// 安全）。[`input_guard`] 旗命中即放行（ISR 语境 = 内核语境定义域：
/// 被打断任务的用户性与本批无关——current_is_user 的 SCHED 锁窗权
/// 威读在 ISR 语境免除，M40-ASH2 ISR 快路径纪律同谱〔PERCPU_IS_USER
/// 零锁旗先例——ISR 语境零 SCHED 查询〕）。
static IN_ISR_CTX: [AtomicBool; task::MAX_CPUS] = [AtomicBool::new(false), AtomicBool::new(false)];

/// ISR 臂锁窗退避上界（M42-WAYCOMP17——try_lock 有界退避随批：ISR
/// 语境禁自旋〔持锁者可能为被打断任务——同核自旋永不推进死锁窗〕，
/// 退避耗尽即丢弃 + [`WLCOMP_ISR_DROP`] fail-visible；4 次有界窗 ≈
/// 微秒级——持锁窗 μs 量级纪律下充裕）。
const ISR_LOCK_TRIES: u32 = 4;

/// 输入注入域门禁（M42-WAYCOMP12 域①——ring3 输入守护）：当前语境
/// = ring3（Kind::User 任务——syscall 派发器执行域同源）→ 拒绝（违规
/// 计数 + false——fail-visible 零静默）；内核任务 / IDLE 语境 → 放行
/// （true）。判定面 = [`task::current_is_user`]（SCHED 锁窗权威读）。
/// M42-WAYCOMP17 前置扩域：ISR 语境旗快路径（[`IN_ISR_CTX`] 随批置
/// 位——ISR 语境 = 内核语境定义域，任务查询免除；旗命中即计
/// [`WLCOMP_ISR_PASS`] 放行路径可辨）。
/// ABI 负空间纪律：SYS 号域零输入注入臂——ring3 可达内核面仅 syscall
/// 派发器，门禁使任何未来误接线 fail-visible 显形（t113 对账）。
fn input_guard() -> bool {
    // ISR 语境旗快路径（M42-WAYCOMP17——kbd→waycomp 转接臂随批置位）：
    // ISR 语境 = 内核语境定义域，current_is_user 的 SCHED 锁窗权威读
    // 免除（M40-ASH2 ISR 快路径纪律同谱——PERCPU_IS_USER 零锁旗先
    // 例）；旗命中即计 ISR_PASS（放行路径可辨——旗面活体取证，t118
    // 对账面）。
    if IN_ISR_CTX[task::current_cpu_slot()].load(Ordering::Acquire) {
        WLCOMP_ISR_PASS.fetch_add(1, Ordering::AcqRel);
        return true;
    }
    if task::current_is_user() {
        WLCOMP_GUARD_ERR.fetch_add(1, Ordering::AcqRel);
        return false;
    }
    true
}

/// 输入链生产面：击键（M42-INPUT7——v0 内核态输入源注入域；键码
/// v0 口径 = scancode set 1 原值，evdev 键码映射挂账）。M42-WAYCOMP12
/// 域①守护门禁前置（Kind::User 语境拒绝）+ 域②受理入环唤醒链
/// （CompIn 全域 wake——阻塞会话环定向显形）。返回受理（入环成功）。
pub fn input_key(key: u32, state: u32) -> bool {
    if !input_guard() {
        return false;
    }
    let raw = ((key as u64) << 32) | (state as u64 & 0xFFFF_FFFF);
    // 多产者串行化窗（M42-WAYCOMP16——IN_MU 锁窗 send 即放；唤醒链
    // 锁外域〔IN_MU → SCHED 锁序单向〕）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        KEY_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false // 队满丢弃（SPSC 环纪律——KBD_DROP 同谱）
    }
}

/// 输入链生产面：指针移动（屏幕坐标——会话侧 hit-test 裁决焦点域）。
/// 守护门禁 + 受理入环唤醒链同 [`input_key`]。
pub fn input_pointer_motion(x: i32, y: i32) -> bool {
    if !input_guard() {
        return false;
    }
    let raw = (((x as u32) as u64) << 32) | ((y as u32) as u64 & 0xFFFF_FFFF);
    // 多产者串行化窗（M42-WAYCOMP16——input_key 同谱）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        PTR_Q.send(raw & !(1u64 << 63)).is_ok() // bit63 = 0（移动域）
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 输入链生产面：指针按键（evdev 按钮码 + 键态——BTN_LEFT 0x110 等）。
/// 守护门禁 + 受理入环唤醒链同 [`input_key`]。
pub fn input_pointer_button(button: u32, state: u32) -> bool {
    if !input_guard() {
        return false;
    }
    let raw = (1u64 << 63) | ((button as u64) << 32) | (state as u64 & 0xFFFF_FFFF);
    // 多产者串行化窗（M42-WAYCOMP16——input_key 同谱）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        PTR_Q.send(raw).is_ok() // bit63 = 1（按钮域）
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 输入链生产面：轴滚动（M42-WAYCOMP14 axis 族——axis 值域官方
/// enum axis 0..=1，value fixed 24.8 原字可负〔反向滚动〕，source
/// 官方 enum axis_source 0..=3；独立 AXIS_Q 承载与 PTR_Q 分域）。守
/// 护门禁 + 受理入环唤醒链同 [`input_key`]。返回受理（入环成功）。
pub fn input_pointer_axis(axis: u32, value: i32, source: u32) -> bool {
    if !input_guard() {
        return false;
    }
    if axis > prism::wayland::comp::AXIS_AXIS_MAX || source > prism::wayland::comp::AXIS_SOURCE_MAX
    {
        WLCOMP_AXIS_BAD.fetch_add(1, Ordering::AcqRel);
        return false; // 轴/轴源域越界（生产域闸——fail-visible）
    }
    let raw = (1u64 << 37) // 轴源有效旗（扫掠域 axis_source 前置声明）
        | ((u64::from(source) & 0x3) << 34)
        | ((u64::from(axis) & 0x3) << 32)
        | ((value as u32) as u64 & 0xFFFF_FFFF);
    // 多产者串行化窗（M42-WAYCOMP16——input_key 同谱）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        AXIS_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false // 队满丢弃（SPSC 环纪律——KBD_DROP 同谱）
    }
}

/// 输入链生产面：滚动手势终结（M42-WAYCOMP14——axis_stop(time, axis)
/// 官方语义：手势终结后该轴不再有 axis 事件直至新手势）。守护门禁
/// + 受理入环唤醒链同 [`input_key`]。
pub fn input_pointer_axis_stop(axis: u32) -> bool {
    if !input_guard() {
        return false;
    }
    if axis > prism::wayland::comp::AXIS_AXIS_MAX {
        WLCOMP_AXIS_BAD.fetch_add(1, Ordering::AcqRel);
        return false; // 轴域越界（生产域闸——fail-visible）
    }
    let raw = (1u64 << 36) // 手势终结旗
        | ((u64::from(axis) & 0x3) << 32);
    // 多产者串行化窗（M42-WAYCOMP16——input_key 同谱）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        AXIS_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 输入链 ISR 臂（M42-WAYCOMP17 笔⑰——kbd→waycomp 转接臂落域）：
/// kbd IRQ1 桩体 scancode 键态语义直传（释放位剥离与 state 0/1 编码
/// 由 kbd 转接臂车道承载——臂面收键态语义原字）。**内核语境旗随批**
/// （[`IN_ISR_CTX`] per-cpu 置位/复位——守护门禁旗快路径放行，任务
/// 查询免除）+ **[`IN_MU`] try_lock 有界退避随批**（ISR 语境禁自旋
/// ——持锁者可能为被打断任务，同核自旋永不推进死锁窗；退避耗尽即
/// 丢弃 + [`WLCOMP_ISR_DROP`] fail-visible；锁窗受理同谱计
/// [`WLCOMP_MPS`]，队满 [`WLCOMP_ISR_FULL`] 显形）。受理入环唤醒链
/// 同任务语境面（锁外域——wake_tasks 自带 IntWindow，wall_hook
/// SCHED 慢路径同谱先例；ISR 语境可达）。返回受理（入环成功）。
pub fn input_key_isr(sc: u8, state: u32) -> bool {
    let cpu = task::current_cpu_slot();
    let prev = IN_ISR_CTX[cpu].swap(true, Ordering::AcqRel);
    let ok = if input_guard() {
        let raw = ((u64::from(sc)) << 32) | (u64::from(state) & 0xFFFF_FFFF);
        // ISR 臂锁窗：try_lock 有界退避随批（M42-WAYCOMP17——禁自旋；
        // 退避窗 = PAUSE 提示重试，非等锁自旋——零挂起重试窗微秒级）
        let mut tries = 0u32;
        let accepted = loop {
            match IN_MU.try_lock() {
                Some(g) => {
                    WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
                    let ok = KEY_Q.send(raw).is_ok();
                    if !ok {
                        WLCOMP_ISR_FULL.fetch_add(1, Ordering::AcqRel);
                    }
                    drop(g);
                    break ok;
                }
                None => {
                    tries += 1;
                    if tries >= ISR_LOCK_TRIES {
                        WLCOMP_ISR_DROP.fetch_add(1, Ordering::AcqRel);
                        break false; // 退避耗尽丢弃（fail-visible——零静默）
                    }
                    core::hint::spin_loop();
                }
            }
        };
        if accepted {
            // 唤醒链锁外域（IN_MU → SCHED 锁序单向——任务语境面同谱；
            // wake_tasks 自带 IntWindow，ISR 语境可达——wall_hook
            // SCHED 慢路径同谱先例）
            task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        }
        accepted
    } else {
        false
    };
    IN_ISR_CTX[cpu].store(prev, Ordering::Release);
    ok
}

/// ISR 臂争用装置面（M42-WAYCOMP17——t118 (c) 争用域承载）：闭包运
/// 行期持 [`IN_MU`]——臂 try_lock 有界退避耗尽域活体（任务语境持锁
/// × 臂语境 try_lock 同核交叠窗——ISR 语境禁自旋纪律的确定性证据
/// 窗）。仅自检装置使用。
pub fn in_mu_hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = IN_MU.lock();
    f()
}

/// 输入链生产面：帧界标记（M42-WAYCOMP17 揭雷③收口——官方 frame
/// 分组「同源批单 frame」细化落域：扫掠边界由生产者标记承载——SMP
/// 域部分排空窗〔生产者逐元素入队 × 消费者并发 drain——v0 每 drain
/// 调用一 frame 发射，同批元素跨 drain 分割即帧多计，t115 TCG 实录
/// frames=+3〕退役，帧计数 = 标记数确定性对账）。守护门禁 + 受理入
/// 环唤醒链同 [`input_pointer_axis_stop`]。返回受理（入环成功）。
pub fn input_pointer_frame() -> bool {
    if !input_guard() {
        return false;
    }
    let raw = 1u64 << 38; // 帧界标记旗（零 axis/stop/source 载荷）
    let accepted = {
        let _g = IN_MU.lock();
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        AXIS_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 输入队列深度取证读面（M42-WAYCOMP12 域①——t113 守护受理对账
/// 域）：(键盘队列, 指针队列) 各自可消费元素数。零变更只读。
pub fn input_queue_depth() -> (usize, usize) {
    (KEY_Q.len(), PTR_Q.len())
}

/// 轴队列深度取证读面（M42-WAYCOMP14——t115 扫掠排空对账域）。零变
/// 更只读。
pub fn input_axis_depth() -> usize {
    AXIS_Q.len()
}

/// 输入队列排水装置面（M42-WAYCOMP12——t113 相位间卫生域：守护受理
/// 对账后排水复原，零污染后续批次；drain_input 会话消费面同款出环
/// 纪律——逐元素弹出丢弃，零会话注入）。
pub fn input_queue_flush() {
    while KEY_Q.recv().is_some() {}
    while PTR_Q.recv().is_some() {}
    while AXIS_Q.recv().is_some() {}
}

/// 取证戳快照：(listener, bound, sessions, commits, composes, last_z,
/// rewrites, drops, keys, ptrs)——前八位 t104/t106/t107 断言面索引稳
/// 定（追加位序；9/10 位 = M42-INPUT7 keys/ptrs）。
#[allow(clippy::type_complexity)]
pub fn waycomp_stamps() -> (u64, bool, u64, u64, u64, i32, u64, u64, u64, u64) {
    (
        WLCOMP_LISTENER.load(Ordering::Acquire),
        WLCOMP_BOUND.load(Ordering::Acquire),
        WLCOMP_SESSIONS.load(Ordering::Acquire),
        WLCOMP_COMMITS.load(Ordering::Acquire),
        WLCOMP_COMPOSES.load(Ordering::Acquire),
        WLCOMP_LAST_Z.load(Ordering::Acquire),
        WLCOMP_REWRITES.load(Ordering::Acquire),
        WLCOMP_DROPS.load(Ordering::Acquire),
        WLCOMP_KEYS.load(Ordering::Acquire),
        WLCOMP_PTRS.load(Ordering::Acquire),
    )
}

/// 窗格内容模式（v0 代 Paint 客户端内容替代域——确定性双色 8px 棋
/// 盘；色相随 fb surface id 显形——t104 读回对账事实源）。ARGB8888
/// 不透明域（a=0xFF——surface 像素契约，透明 = a=0）。
pub fn pane_pattern(fb_id: u32, lx: i32, ly: i32) -> u32 {
    let tint = u32::from((fb_id & 0xFF) as u8);
    let checker = ((lx >> 3) + (ly >> 3)) & 1;
    if checker == 0 {
        0xFF00_0000 | (tint << 16) | 0x0000_3030 // r = tint / g = 0x30 / b = 0x30
    } else {
        0xFF00_0000 | 0x0000_30C0 | tint // r = tint / g = 0x30 / b = 0xC0
    }
}

/// 会话窗口登记行（fb 机械面槽位记账——teardown 域消费）。
struct Window {
    /// wl surface id（客户端域）。
    wl: u32,
    /// fb surface id（`base | wl`——跨会话正交域）。
    fb: u32,
    /// fb 散帧槽号。
    slot: usize,
    /// 屏域矩形（策略面几何——重排改写域对账基准）。
    rect: Rect,
    /// 末次 commit 附带 buffer 几何（M42-GEOM6 域①全幅重呈现像素
    /// 源——None = 代 Paint 回退域）。
    buf: Option<BufferRec>,
    /// 末次 buffer 所属池的 shm 对象 id（0 = 无池——pattern 回退域）。
    pool: u64,
}

/// 常驻服务任务体（kmain boot 单调用点——`task::spawn("waycomp", …)`）：
/// bind → 常驻环（阻塞 accept ↔ 会话环）。bind 失败即退场（fail-
/// visible——boot 证据行缺位显形）。
pub fn service_body() {
    let lobj = match unixsock::bind_by_name(WAYCOMP_SOCK_NAME) {
        Ok(o) => o,
        Err(_) => return, // bind 失败退场（boot 面对账必炸——无静默降级）
    };
    WLCOMP_LISTENER.store(lobj, Ordering::Release);
    WLCOMP_BOUND.store(true, Ordering::Release);
    loop {
        match unixsock::accept_by_object(lobj) {
            Ok(conn) => {
                WLCOMP_SESSIONS.fetch_add(1, Ordering::AcqRel);
                WLCOMP_SESSION_DONE.store(false, Ordering::Release);
                session_loop(conn);
            }
            Err(_) => return, // 监听者终结退场（重启面挂账——M42-FBSVC2 既录口径）
        }
    }
}

/// 会话环：recv 流积累 → feed 合流解析 → 策略同步〔创建期入窗 + 几何
/// 注入〕→ **池承接**（fd 附带数据 RECV_FD → 池对象映射）→ commit
/// 发布应用 → 事件回执 send；EOF/会话错误即收场（surface 摘除 +
/// 损伤量化回退 + 回 accept）。
fn session_loop(conn: u64) {
    let seq = SESSION_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
    let me = task::current_task_id(); // keymap 内容池铸域属主（M42-WAYCOMP13）
    let base = ((seq - 1) as u32) * FB_ID_SESSION_STRIDE;
    let mut session = CompSession::new(GLOBALS);
    let mut windows: Vec<u64> = Vec::new(); // 创建序 = 焦点序（策略面输入）
    let mut slots: Vec<Window> = Vec::new();
    let mut pools: Vec<(u32, u64)> = Vec::new(); // pool_wl → shm 对象 id（池承接域）
    let mut keymap_pools: Vec<u64> = Vec::new(); // keymap 内容池（M42-WAYCOMP13 收场域）
    let mut stream: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    let mut eof = false; // EOF 收场旗（终末冲刷域判定——M42-WAYCOMP15）
    loop {
        // 输入面排空（M42-INPUT7 输入链——队列 → 会话注入 + 焦点裁决）
        drain_input(&mut session, &windows);
        // 流消费探针（非消费双读——环空且终结旗 = EOF 收场域）
        let (pending, dead) = unixsock::session_probe_by_object(conn);
        let mut got = 0usize;
        if pending > 0 || dead {
            match unixsock::recv_by_object(conn, &mut chunk) {
                Ok(0) => {
                    eof = true; // EOF（对端终结——会话收场；USOCK_EOFS 计数域）
                    break;
                }
                Ok(n) => {
                    stream.extend_from_slice(&chunk[..n]);
                    got = n;
                }
                Err(_) => break,
            }
        }
        let mut out = [0u8; 2048];
        match session.feed(&stream, &mut out) {
            Ok(rep) => {
                drop_apply(&rep, &mut windows, &mut slots);
                policy_sync(&mut session, &mut windows);
                policy_focus(&mut session, &windows);
                policy_rewrite(&windows, &mut slots);
                pool_admit(conn, &rep, &mut pools);
                keymap_serve(conn, &rep, me, &mut keymap_pools);
                apply_commits(&rep, &windows, &mut slots, base, &pools);
                // 输入事件 wire 发出数（M42-INPUT7——KeyLog/PtrLog 记录批对账）
                WLCOMP_KEYS.fetch_add(rep.keys.n as u64, Ordering::AcqRel);
                WLCOMP_PTRS.fetch_add(rep.ptrs.n as u64, Ordering::AcqRel);
                // modifiers wire 发出数（M42-WAYCOMP15——Modifiers 记录批）
                for r in rep.keys.items[..rep.keys.n].iter().flatten() {
                    if prism::wayland::comp::KbKind::Modifiers == r.kind {
                        WLCOMP_MODS.fetch_add(1, Ordering::AcqRel);
                    }
                }
                if rep.out_len > 0 {
                    send_all(conn, &out[..rep.out_len]);
                }
                stream.drain(..rep.consumed);
            }
            Err(_) => break, // 会话域 fail-visible 断连（v0 口径——回执 error 事件挂账）
        }
        if pending == 0 && got == 0 {
            // M42-WAYCOMP12 域②阻塞输入等待面（WaitWhat::CompIn 扩域
            // ——v0 探针轮询 + 让步口径退役）：三静域（输入队列空 +
            // 会话流空 + 非终结）登记阻塞。**M42-WAYCOMP17 揭雷④收口
            // ——静域扩 AXIS_Q**（笔⑭轴环在环时停靠谓词漏列——SMP 域
            // 轴元素/帧界标记滞留停靠窗：元素入队前谓词已判静 → 停靠，
            // 入队 wake 落于 block 注册前 = 丢失唤醒域——t115 TCG 实录
            // frames=+1 帧界标记滞留至 EOF 才扫出域）。探针 = 预捕获静
            // 态视图零锁读（rx 环 len + 终结旗对 + 输入队列 is_empty）
            // ——SCHED 锁窗内零 SOCKETS 取锁（锁序 SOCKETS→SCHED 单向
            // 保持，recv_by_object 探针同款纪律）。唤醒源三向：输入生
            // 产（wake 全域）+ 会话流到达（send 落环 conn 匹配域）+
            // 对端终结（shutdown 双向）。miss → 零阻塞回环（顶层探
            // 针 dead 收场——fail-visible）。fd 附带数据域维持 feed
            // 报告驱动（v0 协议时序域不变——pool_admit 触发源 = feed
            // 池记录，阻塞面零触碰）。
            let views = unixsock::session_wait_views(conn);
            WLCOMP_IN_WAITS.fetch_add(1, Ordering::AcqRel); // 登记前计数（t39 口径）
            let blocked = task::block_current_unless(task::WaitWhat::CompIn { conn }, true, || {
                // still_pending 契约（recv_by_object 探针同款）：true = 三
                // 静域持续（输入队列空〔键盘/指针/轴——M42-WAYCOMP17 扩
                // AXIS_Q〕∧ 会话流空 ∧ 非终结）——继续阻塞；任一唤醒源
                // 就绪 = false → 探针命中回滚，调用方重试消费。
                match views {
                    Some((rx, dead, peer_dead)) => {
                        KEY_Q.is_empty()
                            && PTR_Q.is_empty()
                            && AXIS_Q.is_empty()
                            && rx.is_empty()
                            && !dead.load(Ordering::Acquire)
                            && !peer_dead.load(Ordering::Acquire)
                    }
                    None => false, // 对象不在域——零阻塞回环收场（fail-visible）
                }
            });
            if blocked {
                WLCOMP_IN_WAKES.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    // M42-WAYCOMP15：EOF 收场域终末冲刷（**drained→delivered 契约**
    // ——已受理输入事件〔会话待发队列余量〕出域后 teardown；客户端
    // 字节计数车道提前收口域〔modifiers enter 快照随行 +28B〕的按钮
    // 批交付保障——t109 客户端阈值在 ptr enter 域提前满足竞逐窗收
    // 口）。空流 feed 冲刷待发队列（官方语义——输入事件异步于请求
    // 流）；会话域错误断连路径不冲刷（fail-visible 原貌）。
    if eof {
        // M42-WAYCOMP17 揭雷②收口：EOF 收场域内核侧输入队列扫入
        // （drained→delivered 契约内核侧扩展——会话存续窗产出的输入事
        // 件〔仍在 KEY_Q/PTR_Q/AXIS_Q 排队者〕于 teardown 前扫入会话，
        // 终末冲刷随行出域——press/release 批 vs 客户端字节门控 SHUT
        // 的 EOF 竞速域确定性收口〔生产域 enqueue 晚于客户端 SHUT wake
        // 到达窗：v0 EOF break 直落 teardown，排队事件永滞队列——
        // t109 ptr 相位 TCG 实录 ptrs=+1/+2 漂移域〕）。
        drain_input(&mut session, &windows);
        let mut out2 = [0u8; 2048];
        if let Ok(rep2) = session.feed(&[], &mut out2) {
            WLCOMP_KEYS.fetch_add(rep2.keys.n as u64, Ordering::AcqRel);
            WLCOMP_PTRS.fetch_add(rep2.ptrs.n as u64, Ordering::AcqRel);
            for r in rep2.keys.items[..rep2.keys.n].iter().flatten() {
                if prism::wayland::comp::KbKind::Modifiers == r.kind {
                    WLCOMP_MODS.fetch_add(1, Ordering::AcqRel);
                }
            }
            if rep2.out_len > 0 {
                send_all(conn, &out2[..rep2.out_len]);
            }
        }
    }
    // 收场域：surface 摘除 + 损伤量化回退（pane 回退 stage 基线）
    for w in slots.iter() {
        if fb::surf_remove(w.fb).is_err() {
            WLCOMP_REMOVE_ERR.fetch_add(1, Ordering::AcqRel);
        }
        let _ = fb::sys_fb_sync(
            w.rect.x as u64,
            w.rect.y as u64,
            u64::from(w.rect.w),
            u64::from(w.rect.h),
        );
        let _ = fb::fb_compose_tick();
        windows.retain(|id| *id != u64::from(w.wl));
    }
    // M42-WAYCOMP11：池承接域生命周期收场（RECV_FD 句柄撤销 + 引用
    // 归零池回收——客户端已亡会话的池帧归还分配器；fd 传递存续池
    // 引用 > 0 延迟回收 fail-visible）。surface 摘除后执行——合成
    // 像素读域先行收口，池帧归还无读后释放窗。
    release_session_pools(&pools);
    // M42-WAYCOMP13：keymap 内容池收场清扫（客户端已弹出+关闭 → 引
    // 用归零就地回收；未弹出域由 SHUT 遗留槽 revoke 随行——引用归零
    // 后本清扫窗承接回收。引用 > 0 延迟回收 fail-visible）。
    for obj in keymap_pools.iter() {
        let _ = shm::release_if_unreferenced(*obj);
    }
    WLCOMP_END_COUNT.store(fb::surf_count() as u64, Ordering::Release);
    WLCOMP_SESSION_DONE.store(true, Ordering::Release);
    let _ = unixsock::shutdown_by_object(conn);
}

/// 池承接域收场释放（M42-WAYCOMP11 卫生批次）：RECV_FD 装入的池句柄
/// 逐条撤销 + 引用归零池就地回收（[`shm::release_if_unreferenced`]——
/// 帧归还 + 注册表摘除；客户端尚存活则引用 > 0 延迟回收 fail-visible）。
/// 句柄查找 = 本任务句柄表快照 → CAPS 对象比对 → 精确撤销（锁序纪律
/// 两段式——句柄表窗与 CAPS 锁分离，shm::resolve 同款手法）。
fn release_session_pools(pools: &[(u32, u64)]) {
    if pools.is_empty() {
        return;
    }
    let me = task::current_task_id();
    for (_, obj) in pools {
        // 段一：本任务句柄表全谱快照（SCHED 锁窗——零 CAPS 嵌套）。
        let slots: Vec<usize> = task::with_task_handles(me, |t| {
            t.iter()
                .enumerate()
                .skip(1)
                .filter_map(|(_, s)| *s)
                .collect::<Vec<usize>>()
        })
        .unwrap_or_default();
        // 段二：CAPS 对象比对（单取 CAPS 锁）→ 精确撤销 + 回收尝试。
        let g = slots
            .into_iter()
            .find(|g| crate::caps::table().lock().get(*g).map(|c| c.object()) == Ok(*obj));
        if let Some(g) = g {
            let _ = crate::caps::table().lock().revoke(g);
            let _ = shm::release_if_unreferenced(*obj);
        }
    }
}

/// 焦点策略（feed 后每轮——M42-INPUT7 键盘焦点裁决域）：键盘焦点空
/// 域且键盘设备已派生且窗口在案 → **首窗初始聚焦**（创建序 v0 口径
/// ——t104 焦点序口径同源）。click-to-focus 迁移 = [`drain_input`]
/// 指针按键域裁决。受理即落 [`WLCOMP_KBFOCUS`] 取证（t109 断言面）。
fn policy_focus(session: &mut CompSession, windows: &[u64]) {
    if session.keyboard_object() == 0 || session.keyboard_focus() != 0 || windows.is_empty() {
        return; // 设备未派生 / 焦点在域 / 窗口空域——零动作快径
    }
    let first = windows[0] as u32;
    if session.set_keyboard_focus(first).is_ok() {
        WLCOMP_KBFOCUS.store(first, Ordering::Release);
    }
}

/// 输入源排空（M42-INPUT7 输入链电气面——全局输入队列 → 会话注入）：
/// 键盘批直注入（受理即计 [`WLCOMP_INPUT_KEYS`]）；指针批 hit-test
/// 焦点裁决——cascade 平面**逆序**首个含点窗（z 序顶窗优先）→ 面切
/// 换域 set_pointer_focus / 同面域 pointer_motion；按下域 click-to-
/// focus（指针焦点面 = 键盘焦点迁移域）。受理即计
/// [`WLCOMP_INPUT_PTRS`]（t109 断言面）。
fn drain_input(session: &mut CompSession, windows: &[u64]) {
    while let Some(raw) = KEY_Q.recv() {
        let state = (raw & 0xFFFF_FFFF) as u32;
        let sc = (raw >> 32) as u32;
        // M42-WAYCOMP13 evdev 键码映射出域（morse 纯函数面）：scancode
        // → evdev → wl 键码（+8）。域外 scancode（0x59..=0x7F 杂域/
        // 0xE0 扩展域挂账）拒收丢弃 + UNMAPPED 取证（fail-visible）。
        let Some(ev) = morse::evdev(sc as u8) else {
            WLCOMP_KEY_UNMAPPED.fetch_add(1, Ordering::AcqRel);
            continue;
        };
        let key = u32::from(ev) + u32::from(KEYCODE_WL_OFFSET);
        if session.keyboard_inject(key, state).is_ok() {
            WLCOMP_INPUT_KEYS.fetch_add(1, Ordering::AcqRel);
        }
    }
    while let Some(raw) = PTR_Q.recv() {
        let is_btn = raw >> 63 == 1;
        let lo = (raw & 0xFFFF_FFFF) as u32;
        let hi = ((raw >> 32) & 0x7FFF_FFFF) as u32;
        if is_btn {
            let (button, state) = (hi, lo);
            if state == 1 {
                // click-to-focus：指针焦点面按键 = 键盘焦点迁移域
                let pf = session.pointer_focus();
                if pf != 0 && session.set_keyboard_focus(pf).is_ok() {
                    WLCOMP_KBFOCUS.store(pf, Ordering::Release);
                }
            }
            if session.pointer_button(button, state).is_ok() {
                WLCOMP_INPUT_PTRS.fetch_add(1, Ordering::AcqRel);
            }
        } else {
            let (x, y) = (hi as i32, lo as i32);
            // hit-test：z 序顶窗优先（cascade 平面逆序——master 顶层）
            let mut hit = (0u32, 0i32, 0i32);
            if let Ok(plan) = cascade::tiling::tiling_plan(windows, VIEWPORT) {
                for (id, rect) in plan.panes.iter().rev() {
                    let r = *rect;
                    if x >= r.x && x < r.x + r.w as i32 && y >= r.y && y < r.y + r.h as i32 {
                        hit = (
                            *id as u32,
                            (x - r.x).wrapping_mul(256), // surface 局部 fixed 24.8
                            (y - r.y).wrapping_mul(256),
                        );
                        break;
                    }
                }
            }
            let (target, lx, ly) = hit;
            let prev = session.pointer_focus();
            if target != prev {
                // 面切换域（含 target=0 离域 leave）
                let _ = session.set_pointer_focus(target, lx, ly);
            } else if target != 0 {
                // 同面移动域
                let _ = session.pointer_motion(lx, ly);
            }
            if target != 0 {
                WLCOMP_INPUT_PTRS.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    // 轴域排空（M42-WAYCOMP14 axis 族——AXIS_Q 排空 → 会话注入；扫
    // 掠分组语义 = 官方 frame 定界：轴源变化域 axis_source 前置声明
    // + axis/axis_stop 事件批 + **帧界标记出域**〔M42-WAYCOMP17 揭雷③
    // 收口——生产者标记帧界：v0「每 drain 调用一 frame」发射退役——
    // SMP 域部分排空窗同批元素跨 drain 分割即帧多计（t115 TCG 实录
    // frames=+3），帧计数 = 标记数确定性对账，与注入面直通域
    // pointer_frame 解耦〕）。
    let mut src_pending = None::<u32>;
    while let Some(raw) = AXIS_Q.recv() {
        if (raw >> 38) & 1 == 1 {
            // 帧界标记：标记即 frame 出域（零 axis/stop/轴源计数）
            if session.pointer_frame().is_ok() {
                WLCOMP_FRAMES.fetch_add(1, Ordering::AcqRel);
            }
            continue;
        }
        let value = ((raw & 0xFFFF_FFFF) as u32) as i32;
        let axis = ((raw >> 32) & 0x3) as u32;
        let source = ((raw >> 34) & 0x3) as u32;
        let stop = (raw >> 36) & 1 == 1;
        let src_valid = (raw >> 37) & 1 == 1;
        if src_valid && src_pending != Some(source) {
            if session.pointer_axis_source(source).is_ok() {
                WLCOMP_AXSRC.fetch_add(1, Ordering::AcqRel);
            }
            src_pending = Some(source);
        }
        if stop {
            if session.pointer_axis_stop(axis).is_ok() {
                WLCOMP_AXIS_STOPS.fetch_add(1, Ordering::AcqRel);
            }
        } else if session.pointer_axis(axis, value).is_ok() {
            WLCOMP_AXES.fetch_add(1, Ordering::AcqRel);
        }
    }
    // 修饰键态快照读出（M42-WAYCOMP15——排空域语义核末态取证，t116
    // 端到端断言面）
    WLCOMP_MODS_DEP.store(session.modifiers_snapshot().0, Ordering::Release);
}

/// 策略同步（feed 后每轮执行——**仲裁策略面承接域**）：新建 surface
/// 创建期即入窗（创建序 = 焦点序 v0 口径——同批 create+commit 时窗
/// 全量在册，窗格形状一次定形）+ cascade tiling 平面几何注入会话
/// （commit 发布域的损伤裁剪键）。
fn policy_sync(session: &mut CompSession, windows: &mut Vec<u64>) {
    let (ids, n) = session.surface_ids();
    for id in ids[..n].iter().flatten() {
        if !windows.contains(&u64::from(*id)) {
            windows.push(u64::from(*id));
        }
    }
    let Ok(plan) = cascade::tiling::tiling_plan(windows, VIEWPORT) else {
        return; // 平面失败（视口越域等）——几何维持上轮态，fail-visible
    };
    for (id, rect) in plan.panes.iter() {
        let _ = session.set_geometry(*id as u32, *rect);
    }
}

/// destroy 摘除执行（feed 后每轮——**M42-GEOM6 域①重排前置域**）：
/// DropLog 记录逐条电气面摘窗（窗口表摘除 + fb surface 摘除〔未登记
/// 窗容忍——会话域已建未 commit 的摘除无 fb 行〕+ 旧矩形损伤量化
/// 回退 + 合成执行）→ 存活窗交 [`policy_rewrite`] 重排改写。
/// [`WLCOMP_DROPS`] 取证（t107 断言面）。
fn drop_apply(rep: &FeedReport, windows: &mut Vec<u64>, slots: &mut Vec<Window>) {
    for d in rep.drops.items[..rep.drops.n].iter().flatten() {
        windows.retain(|id| *id != u64::from(d.wl_id));
        if let Some(pos) = slots.iter().position(|w| w.wl == d.wl_id) {
            let w = slots.remove(pos);
            let _ = fb::surf_remove(w.fb);
            let _ = fb::sys_fb_sync(
                w.rect.x.max(0) as u64,
                w.rect.y.max(0) as u64,
                u64::from(w.rect.w),
                u64::from(w.rect.h),
            );
            let _ = fb::fb_compose_tick();
        }
        WLCOMP_DROPS.fetch_add(1, Ordering::AcqRel);
    }
}

/// **重排改写执行器**（feed 后每轮——M42-GEOM6 域①核心）：cascade
/// tiling 平面 vs 窗口台账几何对账——矩形演进的已登记窗执行 fb 演进
/// 域 UPDATE（[`fb::surf_update`] 形状锁退役：增长补配 + 全量透明基
/// 线）+ **全幅重呈现**（形状演进 = 旧像素布局失效：客户端池像素全
/// pane 重漆优先，无池回退代 Paint 确定性模式）+ 旧/新矩形双域损伤
/// 量化 + 合成执行。**策略驱动而非 commit 驱动**——重排改写与客户
/// 端提交解耦（窗数演进〔增窗/销窗〕后存活窗几何改写不依赖客户端
/// 重绘；移动域零重漆——store 面位置无关，bounds 平转即呈现域平
/// 移）。[`WLCOMP_REWRITES`] 取证（t107 断言面）。
fn policy_rewrite(windows: &[u64], slots: &mut [Window]) {
    let Ok(plan) = cascade::tiling::tiling_plan(windows, VIEWPORT) else {
        return; // 平面失败——台账维持上轮态，fail-visible
    };
    for (idx, (id, rect)) in plan.panes.iter().enumerate() {
        let wl = *id as u32;
        let z = POLICY_Z_BASE - idx as i32;
        let Some(pos) = slots.iter().position(|w| w.wl == wl) else {
            continue; // 未 commit 窗（创建期入窗未 REGISTER）——REGISTER 域归 apply_commits
        };
        let old = slots[pos].rect;
        if old == *rect {
            continue; // 几何同形——零改写快径
        }
        let shape_changed = old.w != rect.w || old.h != rect.h;
        let (fb_id, slot, src) = {
            let w = &slots[pos];
            (w.fb, w.slot, (w.buf, w.pool))
        };
        if fb::surf_update(fb_id, rect.x, rect.y, rect.w, rect.h, z, true).is_err() {
            continue; // 机械面拒收（演进域 ENOMEM 等——fail-visible，台账维持旧态）
        }
        slots[pos].rect = *rect;
        if shape_changed {
            // 全幅重呈现（透明基线上的完整内容重建——像素源分流同
            // commit 发布域：池像素优先 / 代 Paint 回退）
            match src {
                (Some(b), p) if p != 0 => paint_pool_damage(fb_id, slot, *rect, *rect, &b, p),
                _ => paint_damage(fb_id, slot, *rect, *rect),
            }
        }
        // 旧/新矩形双域损伤量化（旧呈现域回退 + 新呈现域成像）+ 合成
        let _ = fb::sys_fb_sync(
            old.x.max(0) as u64,
            old.y.max(0) as u64,
            u64::from(old.w),
            u64::from(old.h),
        );
        let _ = fb::sys_fb_sync(
            rect.x.max(0) as u64,
            rect.y.max(0) as u64,
            u64::from(rect.w),
            u64::from(rect.h),
        );
        let _ = fb::fb_compose_tick();
        WLCOMP_REWRITES.fetch_add(1, Ordering::AcqRel);
    }
}

/// 池承接（feed 后每轮——**fd 附带数据传递消费域**）：feed 回执池记
/// 录逐条 RECV_FD（内核侧双生面 [`unixsock::recvfd_object_by_object`]
/// ——SCM_RIGHTS 语义面同心出口），pool_wl → shm 对象 id 映射入会话
/// 域。空队/能力缺 = [`WLCOMP_FD_ERR`] 取证（fail-visible——后续
/// commit 回退代 Paint 面）。
fn pool_admit(conn: u64, rep: &FeedReport, pools: &mut Vec<(u32, u64)>) {
    for p in rep.pools.items[..rep.pools.n].iter().flatten() {
        match unixsock::recvfd_object_by_object(conn) {
            Ok(obj) => {
                pools.retain(|(w, _)| *w != p.pool_wl);
                pools.push((p.pool_wl, obj));
                WLCOMP_POOLS.fetch_add(1, Ordering::AcqRel);
            }
            Err(_) => {
                WLCOMP_FD_ERR.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

/// keymap 内容面承接（M42-WAYCOMP13 笔⑬——「keymap 内容面」挂账域
/// 电气面）：feed 回执 keymap 公告记录逐条——铸池（内容域 4 字节对
/// 齐）→ 内容填充（[`KEYMAP_XKB_V1`] 词域 LE 写入，[`shm::pool_px_write`]
/// 内核服务写域）→ **SEND_FD 对端交付**（[`unixsock::sendfd_object_by_object`]
/// ——SCM_RIGHTS dup 铸槽纪律：客户端槽独立于自有句柄）→ 自有句柄
/// 收口（SYS_CLOSE 池臂——dup 纪律发送方自槽即时撤销，客户端槽持
/// 引用）。任一域失败 = [`WLCOMP_KEYMAP_FD_ERR`] fail-visible（内容
/// 面零交付——客户端 keymap 事件已出域但 fd 缺席，如实显形）；成功
/// 域 [`WLCOMP_KEYMAPS`] 落账 + 池对象入收场清扫表（会话终了域
/// release_if_unreferenced 承接——引用归零回收）。
fn keymap_serve(conn: u64, rep: &FeedReport, me: usize, pools_out: &mut Vec<u64>) {
    let Some(km) = rep.keymaps else {
        return; // 无公告——零动作快径
    };
    if km.size as usize != KEYMAP_XKB_V1.len() {
        WLCOMP_KEYMAP_FD_ERR.fetch_add(1, Ordering::AcqRel);
        return; // 记录与事实源长度域背离（prism 面漂移）——fail-visible
    }
    let size = ((km.size as u64) + 3) & !3; // 内容域 4 字节对齐（tail 零填充）
    let h = match shm::shm_create(me, size) {
        Ok(h) => h,
        Err(_) => {
            WLCOMP_KEYMAP_FD_ERR.fetch_add(1, Ordering::AcqRel);
            return;
        }
    };
    // 句柄 → 能力 → 对象 id（release_session_pools 同款解析域）
    let obj = task::with_task_handles(me, |t| t[h])
        .flatten()
        .and_then(|g| crate::caps::table().lock().get(g).ok().map(|c| c.object()));
    let Some(obj) = obj else {
        let _ = crate::vfs::sys_close(h as u64);
        WLCOMP_KEYMAP_FD_ERR.fetch_add(1, Ordering::AcqRel);
        return;
    };
    // 内容填充（词域 LE——tail 域零填充；pool_px_write 越域 false =
    // fail-soft 截断取证）
    let mut filled = true;
    for off in (0..km.size as usize).step_by(4) {
        let end = (off + 4).min(KEYMAP_XKB_V1.len());
        let mut b = [0u8; 4];
        b[..end - off].copy_from_slice(&KEYMAP_XKB_V1[off..end]);
        if !shm::pool_px_write(obj, off as u64, u32::from_le_bytes(b)) {
            filled = false;
            break;
        }
    }
    // SEND_FD 对端交付 + 自有句柄收口（dup 铸槽纪律）
    if filled && unixsock::sendfd_object_by_object(conn, obj).is_ok() {
        pools_out.push(obj);
        WLCOMP_KEYMAPS.fetch_add(1, Ordering::AcqRel);
    } else {
        WLCOMP_KEYMAP_FD_ERR.fetch_add(1, Ordering::AcqRel);
    }
    let _ = crate::vfs::sys_close(h as u64);
}

/// commit 发布应用（仲裁策略面承接域——cascade tiling 几何/z 注入
/// 〔policy_sync 已在环〕+ fb 机械面 REGISTER + 几何一致性裁决
/// 〔重排改写执行器主责——commit 面兜底，M42-GEOM6 域①〕+ 损伤域
/// 像素源分流〔wl_shm 池直读 / 代 Paint 回退〕+ SYNC/COMPOSE 合流）。
fn apply_commits(
    rep: &FeedReport,
    windows: &[u64],
    slots: &mut Vec<Window>,
    base: u32,
    pools: &[(u32, u64)],
) {
    for rec in rep.commits.items[..rep.commits.n].iter().flatten() {
        let rec: CommitRecord = *rec;
        let wl = rec.wl_id;
        // 策略面：cascade tiling 平面（窗口序 = 焦点序 v0 口径——
        // loom/cascade 承接域；平面失败即跳过发布，fail-visible）
        let plan = match cascade::tiling::tiling_plan(windows, VIEWPORT) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let Some(idx) = plan.panes.iter().position(|(id, _)| *id == u64::from(wl)) else {
            continue;
        };
        let (_, rect) = plan.panes[idx];
        let z = POLICY_Z_BASE - idx as i32;
        let fb_id = base | wl;
        // 像素源预解（M42-ELF5）：attach buffer 且池已承接 → 客户端像
        // 素直读（pool_px_read 物理帧域）；否则代 Paint 替代域。
        let pool_obj = rec
            .buffer
            .as_ref()
            .and_then(|b| pools.iter().find(|(w, _)| *w == b.pool_wl))
            .map(|(_, o)| *o)
            .unwrap_or(0);
        // 借用域纪律：存在性判定先行（bool——零借用滞留），登记/更新
        // 两域分别行动（match scrutinee 借用滞留面规避）
        let existing = slots.iter().any(|w| w.wl == wl);
        let slot = if existing {
            // 已登记：几何一致性裁决（M42-GEOM6 域①——重排改写执行
            // 器〔policy_rewrite〕主责，此处兜底：执行器未及的时序差
            // 窗〔同 feed 重排 + commit 竞逐等〕几何演进 UPDATE + 全
            // 幅重呈现；几何同形零改写快径——同形 commit 只走内容面）
            let Some(pos) = slots.iter().position(|w| w.wl == wl) else {
                continue; // 纵深防御域（查找窗内不可能——v0 单线程会话环）
            };
            let old = slots[pos].rect;
            if old != rect {
                let shape_changed = old.w != rect.w || old.h != rect.h;
                let (row_fb, row_slot, src) = {
                    let w = &slots[pos];
                    (w.fb, w.slot, (w.buf, w.pool))
                };
                if fb::surf_update(row_fb, rect.x, rect.y, rect.w, rect.h, z, true).is_err() {
                    continue; // 机械面拒收（演进域 ENOMEM 等——fail-visible）
                }
                slots[pos].rect = rect;
                if shape_changed {
                    // 全幅重呈现（透明基线上的完整内容重建——像素源
                    // 分流：池像素优先 / 代 Paint 回退）
                    match src {
                        (Some(b), p) if p != 0 => {
                            paint_pool_damage(row_fb, row_slot, rect, rect, &b, p)
                        }
                        _ => paint_damage(row_fb, row_slot, rect, rect),
                    }
                }
                // 旧/新矩形双域损伤量化 + 合成（重排改写执行器同款）
                let _ = fb::sys_fb_sync(
                    old.x.max(0) as u64,
                    old.y.max(0) as u64,
                    u64::from(old.w),
                    u64::from(old.h),
                );
                let _ = fb::sys_fb_sync(
                    rect.x.max(0) as u64,
                    rect.y.max(0) as u64,
                    u64::from(rect.w),
                    u64::from(rect.h),
                );
                let _ = fb::fb_compose_tick();
                WLCOMP_REWRITES.fetch_add(1, Ordering::AcqRel);
            }
            slots[pos].slot
        } else {
            match fb::surf_register(fb_id, rect.x, rect.y, rect.w, rect.h, z) {
                Ok(slot) => {
                    slots.push(Window {
                        wl,
                        fb: fb_id,
                        slot,
                        rect,
                        buf: None,
                        pool: 0,
                    });
                    slot
                }
                Err(_) => continue, // 机械面拒收（槽池耗尽等——fail-visible）
            }
        };
        WLCOMP_LAST_Z.store(z, Ordering::Release);
        // 末次 buffer 几何入台账（M42-GEOM6 域①——全幅重呈现像素源
        // = 末次 commit 承载域；无 buffer commit 保持既有台账）
        if rec.buffer.is_some() {
            if let Some(row) = slots.iter_mut().find(|w| w.wl == wl) {
                row.buf = rec.buffer;
                row.pool = pool_obj;
            }
        }
        // 内容面：损伤域代 Paint（v0 客户端缓冲域挂账——模式替代）。
        // 首映射兜底面：策略几何于创建期注入（policy_sync），commit
        // 损伤映射域在 feed 内执行〔同批 create→commit 的映射仍以零
        // 几何域运行——时序差如实记档〕——首映射 commit 无先前呈现态
        // = 全 pane 内容呈现（首帧全量域）；非首映射按 commit 记录损
        // 伤（后续轮次几何已在环）。
        let paint_dmg = if rec.first_map && rec.damage.w == 0 {
            rect
        } else {
            rec.damage
        };
        match rec.buffer.as_ref() {
            Some(b) if pool_obj != 0 => {
                paint_pool_damage(fb_id, slot, rect, paint_dmg, b, pool_obj)
            }
            _ => paint_damage(fb_id, slot, rect, paint_dmg),
        }
        // 合流电气面：损伤量化 + 合成执行（SYS_FB_SYNC → fb_compose_tick）
        let _ = fb::sys_fb_sync(
            paint_dmg.x.max(0) as u64,
            paint_dmg.y.max(0) as u64,
            u64::from(paint_dmg.w),
            u64::from(paint_dmg.h),
        );
        let _ = fb::fb_compose_tick();
        WLCOMP_COMMITS.fetch_add(1, Ordering::AcqRel);
        WLCOMP_COMPOSES.fetch_add(1, Ordering::AcqRel);
    }
}

/// 损伤域代 Paint（fb 机械面像素写——pane 局部坐标域；越域静默丢弃
/// 同 surf_px_write 契约）。
fn paint_damage(fb_id: u32, slot: usize, pane: Rect, dmg: Rect) {
    if dmg.w == 0 || dmg.h == 0 {
        return;
    }
    let pages = fb::surf_slot_pages(slot);
    for sy in dmg.y..dmg.y + dmg.h as i32 {
        for sx in dmg.x..dmg.x + dmg.w as i32 {
            let lx = sx - pane.x;
            let ly = sy - pane.y;
            fb::surf_px_write(slot, pages, pane.w, lx, ly, pane_pattern(fb_id, lx, ly));
        }
    }
}

/// 损伤域客户端像素 Paint（M42-ELF5——wl_shm 池直读域）：buffer 局
/// 部坐标域裁剪（lx/ly ∈ buffer 像素域）+ 池内偏移换算（offset +
/// ly×stride + lx×4）+ [`shm::pool_px_read`] 物理帧直读（越池域 None
/// = 跳过该像素 fail-soft）；命中域 [`WLCOMP_SHM_PAINTS`] 取证。
fn paint_pool_damage(_fb_id: u32, slot: usize, pane: Rect, dmg: Rect, b: &BufferRec, obj: u64) {
    if dmg.w == 0 || dmg.h == 0 || b.w <= 0 || b.h <= 0 || b.stride <= 0 || b.offset < 0 {
        return;
    }
    let pages = fb::surf_slot_pages(slot);
    for sy in dmg.y..dmg.y + dmg.h as i32 {
        for sx in dmg.x..dmg.x + dmg.w as i32 {
            let lx = sx - pane.x;
            let ly = sy - pane.y;
            if lx < 0 || ly < 0 || lx >= b.w || ly >= b.h {
                continue; // buffer 像素域外（pane > buffer 缘口——余域透明态）
            }
            let off = b.offset as u64 + (ly as u64) * b.stride as u64 + (lx as u64) * 4;
            if let Some(px) = shm::pool_px_read(obj, off) {
                fb::surf_px_write(slot, pages, pane.w, lx, ly, px);
                WLCOMP_SHM_PAINTS.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

/// 事件回执发送（让步重试纪律——对端环由对端消费，慢则让出；echo
/// worker 先例同款）。
fn send_all(conn: u64, payload: &[u8]) {
    for _ in 0..4096 {
        if unixsock::send_by_object(conn, payload)
            .map(|n| n == payload.len())
            .unwrap_or(false)
        {
            return;
        }
        core::hint::spin_loop();
        task::yield_now();
    }
}
