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
//! 扫掠〔AXIS_Q 排空 → axis_source 前置 + axis/axis_stop 批 + **wheel
//! 源离散步进随行**〔M43-AV12036——axis 后同 frame 随行 axis_value120，
//! value120 = dz×120 原字同字派生；非 wheel 源/零步进不随行〕+ 扫掠
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
//! **多产者域**（M42-WAYCOMP16 笔⑯落域 + M45-MPMC46 笔51 替换升级）：内核
//! 任务语境多产者并发注入经 [`MpmcRing`] 无锁 MPMC 环直推承接（v0
//! `IN_MU` SpinLock 串行化窗口径退役——生产域零锁零串行化窗，消费侧
//! 单线程不变；唤醒链锁外域）。
//!
//! **ISR 臂**（M42-WAYCOMP17 笔⑰落域 + M45-MPMC46 笔51 升级）：kbd
//! IRQ1 桩体（[`crate::kbd`] `on_scancode` 转接臂车道）scancode 键
//! 态语义直传 [`input_key_isr`]——**内核语境旗** [`IN_ISR_CTX`] 随
//! 批（per-cpu 置位/复位：ISR 语境 = 内核语境定义域，被打断任务的
//! 用户性与本批无关——[`input_guard`] 旗快路径放行，current_is_user
//! 的 SCHED 锁窗任务查询免除〔M40-ASH2 ISR 快路径纪律同谱——
//! PERCPU_IS_USER 零锁旗先例〕）+ **MPMC 零锁直推随批**（v0
//! `IN_MU` try_lock 有界退避口径退役——MPMC 环生产域无锁，ISR 语境
//! 零自旋窗零退避窗；队满 [`WLCOMP_ISR_FULL`] fail-visible 显形，
//! [`WLCOMP_ISR_DROP`] 退役戳恒零）。tty 车道（KBD_RING ASCII 控制面）
//! 与 waycomp 车道（KEY_Q 键态语义直传）双车道分域——同批 scancode
//! 双投递独立消费（tty 消费者 = 行规程读侧，waycomp 消费者 = 会话
//! 环 drain，互不相扰）。
//!
//! 锁序契约：输入生产域零锁（MPMC 环直推——v0 `IN_MU` 单锁窗口径退
//! 役，锁序图单点消除）；[`IN_ISR_CTX`] 零锁旗（per-cpu 随批自持——
//! PERCPU_IS_USER 同谱纪律，非锁零嵌套）；域内余锁全部单取即放
//! （unixsock/fb 单锁纪律同谱）；阻塞点 = accept_wait（WaitWhat::UnixAccept）
//! + 会话环三静域（WaitWhat::CompIn——M42-WAYCOMP12 扩域，探针零锁读）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use mirror::Rect;
use morse::KEYCODE_WL_OFFSET;
use ostd::sync::mpmc::MpmcRing;
use prism::wayland::comp::{
    BufferRec, CommitRecord, CompSession, FeedReport, GlobalDef, GLOBALS_MAX, KEYMAP_XKB_V1,
};

use crate::{fb, shm, task, unixsock};

/// 合成器套接字名（平名命名域——`wayland-0` 名字域被 t103 回环面终身
/// 占用〔对象存续纪律〕，常驻合成器名域正交登记如实记档）。
pub const WAYCOMP_SOCK_NAME: &[u8] = b"wayland-comp";
/// 策略面视口（stdvga LFB 全谱 1920×1080——fb WIDTH/HEIGHT 同源）。
pub const VIEWPORT: (u32, u32) = (1920, 1080);

// --- 窗格标题栏带（M50-TEXT69 笔79——glyph::text 同源字体消费面） ---

/// 标题栏带高（像素行 = glyph::text::GLYPH_H 同谱）。
pub const PANE_TITLE_H: u32 = glyph::text::GLYPH_H as u32;
/// 标题栏带底色（ARGB）。
pub const PANE_TITLE_BG: u32 = 0xFF1A_1A1E;
/// 标题栏文本前景色（ARGB）。
pub const PANE_TITLE_FG: u32 = 0xFFE8_E8E8;
/// 标题栏文本起点（窗格局部 x）。
pub const PANE_TITLE_X: i32 = 8;
/// 标题栏文本（v0 常量行——窗名动态域挂账）。
pub const PANE_TITLE: &str = "LUMINA";

/// 标题栏带像素（M50-TEXT69 笔79——纯函数：ly ∈ [0, 16) 带内
/// glyph::text 字形命中 → 前景，否则底色；带外不适用〔消费面分流〕。
/// 字形事实源 = glyph::text::FONT8X16（scripts/gen_font8x16.py 同源——
/// 内核 font_gen.rs 为内核域同源副本，t158 金值双面锚定）。
pub fn title_bar_px(lx: i32, ly: i32) -> u32 {
    title_bar_text_px(PANE_TITLE.as_bytes(), lx, ly)
}

/// 标题栏带像素·动态标题域（M50-XDGSHELL67 笔77——客户端 set_title
/// wire 请求 → 会话标题承载 → 窗格标题带像素的电气闭环消费面：
/// glyph::text 同源字形，title 为本窗真实标题字节域；空标题 = 全底
/// 色快径。title_bar_px = 本函数 PANE_TITLE 常量域特例——t158 金值
/// 域同源不变）。
pub fn title_bar_text_px(title: &[u8], lx: i32, ly: i32) -> u32 {
    // O(1) 算术定位（M50 揭雷②收口同款：除法定位字符 + glyph_row 单行
    // 读——逐像素零数组拷贝）。
    let cx_all = lx - PANE_TITLE_X;
    if cx_all < 0 {
        return PANE_TITLE_BG;
    }
    let glyph_i = (cx_all / glyph::text::GLYPH_W as i32) as usize;
    if glyph_i >= title.len() {
        return PANE_TITLE_BG;
    }
    let cx = (cx_all % glyph::text::GLYPH_W as i32) as usize;
    let ch = title[glyph_i] as char;
    let bits = glyph::text::glyph_row(ch, ly as usize);
    if bits & (0x80 >> cx) != 0 {
        PANE_TITLE_FG
    } else {
        PANE_TITLE_BG
    }
}
/// z 序基（master 顶层——t79 仲裁样本同谱；cascade 平面序号递减）。
pub const POLICY_Z_BASE: i32 = 20;
/// 会话 fb surface id 基跨度（session_seq − 1 左移域——跨会话 id 正交）。
pub const FB_ID_SESSION_STRIDE: u32 = 0x1000;
/// registry 公告名单（核心子集 + xdg_shell 五 global——t159 客户端对
/// 账事实源；M50-XDGSHELL67 笔77 公告面演化 4→5 目同源）。
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
    GlobalDef {
        name: 5,
        iface: prism::wayland::WlIface::XdgWmBase,
        version: 1,
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
/// 合成执行数（commit 发布域 = 批尾单合成批计数〔M42-DMGC21——N commit
/// 批 = 1；v0 逐 commit 计数退役，t122 断言面〕）。
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
/// xdg close 事件出域数（M50-XDGSHELL67——close 车道冲刷域计数，
/// t159 断言面）。
pub static WLCOMP_CLOSES: AtomicU64 = AtomicU64::new(0);
/// xdg close 请求受理数（M50-XDGSHELL67——会话环排空域入队受理计
/// 数：请求队列 → 会话 close 队列链路对账，t159 断言面）。
pub static WLCOMP_CLOSES_REQ: AtomicU64 = AtomicU64::new(0);
/// xdg close 请求拒收数（M50-XDGSHELL67——对象域闸拒收取证：非在
/// 册 toplevel 等——fail-visible 零静默）。
pub static WLCOMP_CLOSES_ERR: AtomicU64 = AtomicU64::new(0);
/// 窗格标题刷新数（M50-XDGSHELL67——客户端 set_title → 窗格标题带
/// 消费链电气取证：非空标题 commit 域刷新计数，t159 断言面）。
pub static WLCOMP_TITLED: AtomicU64 = AtomicU64::new(0);
/// size-configure 请求受理数（M51-XDGPOP75 笔86——policy size 车道：
/// tiling 形变 → request_configure 入队受理计数，t164 断言面）。
pub static WLCOMP_CFGS: AtomicU64 = AtomicU64::new(0);
/// size-configure 对出域数（M51-XDGPOP75 笔86——feed 冲刷域 configure
/// 对出域计数，t164 断言面）。
pub static WLCOMP_CFGS_SENT: AtomicU64 = AtomicU64::new(0);
/// popup_done 事件出域数（M51-XDGPOP75 笔86——父窗收场派生域冲刷计
/// 数，t164 断言面）。
pub static WLCOMP_PDONES: AtomicU64 = AtomicU64::new(0);
/// repositioned+configure 对出域数（M52-POPCON78 笔90——v3 重定位
/// 车道冲刷域计数，t167 断言面）。
pub static WLCOMP_REPOS: AtomicU64 = AtomicU64::new(0);
/// popup_done 入队受理数（M51-XDGPOP75 笔86——close 车道派生域受理
/// 计数：request_popup_done_for_parent 成功域，t164 断言面）。
pub static WLCOMP_PDONES_SENT: AtomicU64 = AtomicU64::new(0);
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
/// 离散步进随行 wire 发出数（M43-AV12036——wheel 源 frame 域 axis
/// 随行 axis_value120 出域计数：非 wheel 源〔finger/continuous〕零
/// 离散步进不随行，value=0 零步进不随行——官方语义域闸，t135 断言
/// 面）。
pub static WLCOMP_V120: AtomicU64 = AtomicU64::new(0);
/// 水平滚轮 axis 出域数（M43-HWDW40 笔㊺——AXIS_HORIZONTAL_SCROLL
/// 域 axis 事件出域计数；竖轮域零计入——t139 断言面）。
pub static WLCOMP_HAXES: AtomicU64 = AtomicU64::new(0);
/// 键重复出域数（M43-KBREP37 笔㊷——repeat 泵重复 key 事件出域计
/// 数，t136 断言面）。
pub static WLCOMP_REPS: AtomicU64 = AtomicU64::new(0);
/// set_cursor 请求受理数（M43-KBREP37 笔㊷——wl_keyboard.set_cursor
/// 官方请求域回执计数，t136 断言面）。
pub static WLCOMP_KBSETCUR: AtomicU64 = AtomicU64::new(0);
/// 光标直迁出域数（M43-CURSOR41 笔㊻——窗亡重排域 pointer_relink
/// 迁移笔数：异窗才计，幂等零扰零计——t140 断言面）。
pub static WLCOMP_RELINK: AtomicU64 = AtomicU64::new(0);
/// map 域光标直迁出域数（M44-MAP42 笔㊼——创建期/map 域
/// pointer_relink 迁移笔数：首映射批后 stationary 光标位 hit-test
/// 异窗才计，幂等零扰零计——t141 断言面；窗亡域戳
/// [`WLCOMP_RELINK`] 分立双戳——触发源分域取证）。
pub static WLCOMP_MAP_RELINK: AtomicU64 = AtomicU64::new(0);
/// modifiers wire 发出数（M42-WAYCOMP15——feed 回执 Modifiers 记录批
/// 计数：语义核变更域 + enter 快照域全谱，t116 断言面）。
pub static WLCOMP_MODS: AtomicU64 = AtomicU64::new(0);
/// 修饰键 depressed 掩码快照（M42-WAYCOMP15——排空域会话语义核末态
/// 读出，t116 端到端断言面）。
pub static WLCOMP_MODS_DEP: AtomicU32 = AtomicU32::new(0);
/// 生产域直推受理计数（M42-WAYCOMP16 落域 + M45-MPMC46 口径升级——
/// 多产者域取证戳：v0 IN_MU 锁窗受理口径退役，MPMC 直推受理计数同戳
/// 承接，t117 断言面；ISR 臂同谱计入，t118 断言面）。
pub static WLCOMP_MPS: AtomicU64 = AtomicU64::new(0);
/// sync 即时完成数（M42-WAYCOMP18 多注册表面——feed 回执 syncs 增量
/// 计数：每 sync 恰一 done + delete_id 对，t119 断言面）。
pub static WLCOMP_SYNCS: AtomicU64 = AtomicU64::new(0);
/// frame callback done+delete_id 对数（M42-DMGC22 笔㉒——feed 回执
/// frame_dels 增量计数：commit 冲刷域每 frame callback 恰一
/// done + delete_id 对，t123 断言面）。
pub static WLCOMP_FRAME_DELS: AtomicU64 = AtomicU64::new(0);
/// SYNC 矩形调用数（M42-DMG20 damage 联合域——waycomp 侧 sys_fb_sync
/// 调用计数〔commit 发布域 + 改写域 + teardown 收场域全谱〕：联合域
/// 对账面——marks/rects 差分域，t121 断言面）。
pub static WLCOMP_SYNC_RECTS: AtomicU64 = AtomicU64::new(0);

/// SYNC 矩形承接（M42-DMG20——waycomp 侧 sys_fb_sync 单出口：取证戳
/// 随行 + 机械面透传；联合域口径 = 块级入账，联合由 mirror tracker
/// 并集合并承载）。
fn sync_rect(x: i32, y: i32, w: u32, h: u32) {
    WLCOMP_SYNC_RECTS.fetch_add(1, Ordering::AcqRel);
    let _ = fb::sys_fb_sync(x.max(0) as u64, y.max(0) as u64, u64::from(w), u64::from(h));
}
/// ISR 臂内核语境旗路径放行数（M42-WAYCOMP17——[`IN_ISR_CTX`] 旗命
/// 中即计：放行路径可辨——旗路径而非任务查询路径，旗面活体取证，
/// t118 断言面）。
pub static WLCOMP_ISR_PASS: AtomicU64 = AtomicU64::new(0);
/// ISR 臂退避耗尽丢弃数（M42-WAYCOMP17 落域 + **M45-MPMC46 口径退役**
/// ——v0 [`IN_MU`] try_lock 有界退避耗尽丢弃域退役：MPMC 环生产域
/// 无锁，退避窗不存在；本戳退役保留为恒零判据面——零静默纪律在环，
/// t118 断言面随行升级）。
pub static WLCOMP_ISR_DROP: AtomicU64 = AtomicU64::new(0);
/// ISR 臂队满丢弃数（M42-WAYCOMP17——KEY_Q 容量域 fail-visible 取
/// 证：消费域停滞窗〔会话缺席/阻塞〕溢出显形，t118 断言面）。
pub static WLCOMP_ISR_FULL: AtomicU64 = AtomicU64::new(0);

/// 输入源队列深度（键盘/指针/轴各一定容——定容零堆纪律；M42-WAYCOMP16
/// 多产者域在环 + M45-MPMC46 无锁 MPMC 环直推——v0 SPSC+IN_MU 串行化
/// 口径退役，多产者/ISR 臂零锁直推，消费侧单线程不变）。
const INPUT_CAP: usize = 16;
/// drain 批次限排上限（M43-KBREP37 揭雷⑤——与 prism 会话队列
/// INPUT_Q_MAX 同值：批界失配零丢域收口）。
const INPUT_CAP_MAX: usize = 8;
/// 键盘输入队列（元素 = (key << 32) | state 打包）。
static KEY_Q: MpmcRing<u64, INPUT_CAP> = MpmcRing::new();
/// 指针输入队列（元素 = bit63=按钮旗 | (button/x << 32) | state/y）。
static PTR_Q: MpmcRing<u64, INPUT_CAP> = MpmcRing::new();
/// 轴输入队列（M42-WAYCOMP14——独立定容环与 PTR_Q 分域：元素 =
/// bit36=手势终结旗 | bit37=轴源有效旗 | **bit38=帧界标记旗**
/// 〔M42-WAYCOMP17 揭雷③收口——生产者标记帧界〕 | source << 34 |
/// axis << 32 | value i32 原字；位域正交性 = 独立环承载，无 bit63/62
/// 冲突窗）。
static AXIS_Q: MpmcRing<u64, INPUT_CAP> = MpmcRing::new();
/// xdg close 请求队列（M50-XDGSHELL67 笔77——policy 车道定容环：
/// [`request_close`] 生产（内核侧用户关窗请求），会话环逐轮排空 →
/// session.request_close 入会话 close 队列 → feed 冲刷域
/// xdg_toplevel.close 事件出域。元素 = wl_surface id；唤醒链 =
/// [`input_key`] 同款 CompIn 全域 wake）。
static CLOSE_Q: MpmcRing<u32, INPUT_CAP> = MpmcRing::new();

/// 用户关窗请求生产核（M50-XDGSHELL67 笔77——policy 车道：入队 +
/// CompIn 全域 wake 唤醒链；队满 = false fail-visible 取证）。真值返
/// 回受理（入环成功）。
pub fn request_close(wl: u32) -> bool {
    let accepted = CLOSE_Q.send(wl).is_ok();
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 内核语境旗（M42-WAYCOMP17 笔⑰——ISR 臂随批携带）：per-cpu ISR
/// 语境旗——kbd IRQ1 转接臂入批前置位、出批复位（swap/restore 嵌套
/// 安全）。[`input_guard`] 旗命中即放行（ISR 语境 = 内核语境定义域：
/// 被打断任务的用户性与本批无关——current_is_user 的 SCHED 锁窗权
/// 威读在 ISR 语境免除，M40-ASH2 ISR 快路径纪律同谱〔PERCPU_IS_USER
/// 零锁旗先例——ISR 语境零 SCHED 查询〕）。
static IN_ISR_CTX: [AtomicBool; task::MAX_CPUS] = [AtomicBool::new(false), AtomicBool::new(false)];

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
    // MPMC 零锁直推（M45-MPMC46——v0 IN_MU 串行化窗口径退役；唤醒链
    // 锁外域同谱）
    let accepted = {
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        KEY_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false // 队满丢弃（MPMC 环纪律——KBD_DROP 同谱）
    }
}

/// 光标绝对坐标 x（M42-DMG28 笔㉘——生产域寄存，屏域钳制）。
static CUR_X: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// 光标绝对坐标 y（M42-DMG28 笔㉘）。
static CUR_Y: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// 上次消费域光标格（16px 网格坐标——-1 哨兵 = 未定位；格跳变门控
/// 域——同格重注零扰动）。
static CUR_CELL: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(-1);

/// 光标坐标寄存（M42-DMG28 笔㉘生产域——受理受理同源推进；屏域钳
/// 制 fb::WIDTH/HEIGHT）。
fn cursor_store(x: i32, y: i32) {
    let cx = x.clamp(0, crate::fb::WIDTH as i32 - 1);
    let cy = y.clamp(0, crate::fb::HEIGHT as i32 - 1);
    CUR_X.store(cx, Ordering::Release);
    CUR_Y.store(cy, Ordering::Release);
}

/// 光标坐标读面（M42-DMG28 笔㉘——t128 对账面）。
pub fn waycomp_cursor() -> (i32, i32) {
    (CUR_X.load(Ordering::Acquire), CUR_Y.load(Ordering::Acquire))
}

/// 消费域光标格读面（M42-DMG28 笔㉘——格坐标 = 坐标 div_euclid 16；
/// -1 哨兵 = 未定位）。
pub fn waycomp_cursor_cell() -> (i32, i32) {
    let c = CUR_CELL.load(Ordering::Acquire);
    if c < 0 {
        (-1, -1)
    } else {
        ((c >> 16) as i16 as i32, (c & 0xFFFF) as i16 as i32)
    }
}

/// 联动状态复位（t128 装置面——格门控回哨兵未定位域，首笔=单标
/// 新格确定性基线）。
pub fn waycomp_ptr_cell_reset() {
    CUR_CELL.store(-1, Ordering::Release);
}

/// 指针 16px 粗粒度域联动（M42-DMG28 笔㉘消费域核心——v0「指针面
/// 留合成器直标」注记域兑现）：消费域 motion 逐笔格门控——格跳变
/// 即旧格 + 新格双笔 16×16 直标（[`fb::sys_fb_sync_pointer`] →
/// mark_pointer 16px 网格外扩吸附入账），同格重注零扰动（碎片损伤
/// 聚成粗粒度块不灌爆预算）；首笔哨兵域单标新格。
/// 调用域 = 消费域任务语境（drain_input motion 分支——ISR 语境零
/// 重活纪律：SpinLock 窗不越 ISR）。
fn pointer_cell_link(x: i32, y: i32) {
    const G: i32 = mirror::POINTER_GRANULARITY;
    let cx = x.div_euclid(G);
    let cy = y.div_euclid(G);
    let packed = ((cx as i64) << 16) | (cy as i64 & 0xFFFF);
    let prev = CUR_CELL.swap(packed, Ordering::AcqRel);
    if prev == packed {
        return; // 同格重注——零扰动（门控域）
    }
    if prev >= 0 {
        let (px, py) = ((prev >> 16) as i16 as i32, (prev & 0xFFFF) as i16 as i32);
        let _ = crate::fb::sys_fb_sync_pointer(
            (px * G).max(0) as u64,
            (py * G).max(0) as u64,
            G as u64,
            G as u64,
        );
    }
    let _ = crate::fb::sys_fb_sync_pointer(
        (cx * G).max(0) as u64,
        (cy * G).max(0) as u64,
        G as u64,
        G as u64,
    );
}

// ---- M42-SPRITE29 笔㉙：光标 sprite 渲染面（消费域联动核）----

/// sprite 平面位置镜像（打包 i64 同 [`crate::fb::CURSOR_PLANE`] 编码——
/// 授权域 = fb 平面单事实源，本寄存器只承载同位重注变更检测）。
static SPRITE_RECT: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
/// sprite 批移动旗（drain_input 批尾单合成门控——零移动批零合成零扰动
/// 〔M42-DMGC21 批尾单合成纪律同谱〕）。
static SPRITE_MOVED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 光标 sprite 平面联动核（M42-SPRITE29 笔㉙消费域——v0「光标 sprite
/// 渲染面（16px 图形域）」像素面挂账兑现）：热点对位画布左上角 = 指针
/// 落点 − 热点偏移，屏域钳制（画布完整落屏——边缘域热点位移如实显形，
/// [`mirror::CURSOR_HOT_X`] 尖端语义保持近缘）；位移非零域旧/新画布双
/// 笔损伤记账（[`sync_rect`]——联合域单出口；[`crate::fb::DAMAGE_PTR_MARKS`]
/// 计数域零扰动——t128 marks 断言面保持）+ [`fb::fb_cursor_plane_set`]
/// 寄存 + 移动旗随批（批尾单合成域——drain_input 尾承接）。同位重注零
/// 扰动（门控域——[`pointer_cell_link`] 同谱）。
/// 调用域 = 消费域任务语境（drain_input motion 分支——ISR 语境零重活
/// 纪律同 [`pointer_cell_link`]：SpinLock 窗不越 ISR）。
fn cursor_sprite_move(x: i32, y: i32) {
    let cw = mirror::CURSOR_W as i32;
    let ch = mirror::CURSOR_H as i32;
    let sx = (x - mirror::CURSOR_HOT_X as i32).clamp(0, crate::fb::WIDTH as i32 - cw);
    let sy = (y - mirror::CURSOR_HOT_Y as i32).clamp(0, crate::fb::HEIGHT as i32 - ch);
    let packed = ((sx as i64) << 32) | (sy as i64 & 0xFFFF_FFFF);
    let prev = SPRITE_RECT.swap(packed, Ordering::AcqRel);
    if prev == packed {
        return; // 同位重注——零扰动（门控域）
    }
    if prev >= 0 {
        let (px, py) = ((prev >> 32) as i32, (prev & 0xFFFF_FFFF) as i32);
        sync_rect(px, py, mirror::CURSOR_W, mirror::CURSOR_H);
    }
    sync_rect(sx, sy, mirror::CURSOR_W, mirror::CURSOR_H);
    crate::fb::fb_cursor_plane_set(sx, sy);
    SPRITE_MOVED.store(true, Ordering::Release);
}

/// 光标 sprite 渲染面取证读面（t129 对账——(画布左上角, 指针落点)；
/// 零变更只读）。
pub fn waycomp_cursor_sprite() -> ((i32, i32), (i32, i32)) {
    (crate::fb::fb_cursor_plane(), waycomp_cursor())
}

// ---- M42-PTRLINK 笔㉛：Enter/Leave 域联动（焦点切换光标格直标）----

/// 焦点切换 enter 取证戳（wl_pointer.enter 出域计数——t131 对账域）。
pub static WLCOMP_PTR_ENTER: AtomicU64 = AtomicU64::new(0);
/// 焦点切换 leave 取证戳（wl_pointer.leave 出域计数——t131 对账域）。
pub static WLCOMP_PTR_LEAVE: AtomicU64 = AtomicU64::new(0);

// ---- M42-CLICKF33 笔㉝：click-to-focus 焦点迁移联动面（按钮域随批）----

/// 点击焦点迁移取证戳（按钮按下域 keyboard focus 迁移笔数——同窗
/// 幂等零计，t133 对账域；v0 click-to-focus 无迁移取证戳——本戳补
/// 面）。
pub static WLCOMP_CLICK_FOCUS: AtomicU64 = AtomicU64::new(0);

/// 焦点切换域光标格直标（M42-PTRLINK 笔㉛——笔㉘挂账「Enter/Leave 域
/// 联动（焦点切换光标格直标——v0 motion-only 口径）」兑现）：焦点面
/// 切换（leave/enter 对出域）即光标格 16px 直标强制入账 + sprite 平
/// 面批尾合成旗——v0 motion-only 口径退役：[`pointer_cell_link`] 格门
/// 控只覆盖格跳变，同格跨窗焦点切换（tiling 边界近邻域）无直标则合
/// 成器不知光标已易窗；本核强制入账 + sprite 重影随批（SPRITE_MOVED
/// 旗——drain 尾单合成承接）。调用域 = 消费域任务语境（ISR 语境零重
/// 活纪律同谱——SpinLock 窗不越 ISR）。
fn pointer_focus_link(x: i32, y: i32) {
    let g = mirror::POINTER_GRANULARITY;
    let cx = x.clamp(0, crate::fb::WIDTH as i32 - 1).div_euclid(g);
    let cy = y.clamp(0, crate::fb::HEIGHT as i32 - 1).div_euclid(g);
    let _ = crate::fb::sys_fb_sync_pointer(
        (cx * g).max(0) as u64,
        (cy * g).max(0) as u64,
        g as u64,
        g as u64,
    );
    SPRITE_MOVED.store(true, Ordering::Release);
}

// ---- M42-AUXR3 笔㉚：ring3 指针生产授权车道 ----

/// ring3 指针注入受理数（`SYS_PTR_INJECT` 生产闸放行域——t130 对账）。
pub static WLCOMP_R3PTRS: AtomicU64 = AtomicU64::new(0);
/// ring3 指针注入拒收数（pid 门禁 / 接管态闸 / kind 域闸 fail-visible
/// 取证——ABI 负空间纪律显形域）。
pub static WLCOMP_R3_DENY: AtomicU64 = AtomicU64::new(0);

/// [`SYS_PTR_INJECT`](bedrock::abi::SYS_PTR_INJECT) 承接面：ring3 指针
/// 生产授权车道。**双闸门禁**——(a) pid 闸：调用方 = boot 常驻
/// aux-svc-elf（[`crate::procs::aux_svc_pid`]——ABI 负空间纪律收口面，
/// ring3 指针生产唯一合法路径，其余进程 fail-visible 拒收）；(b) 接管
/// 态闸：kbd 环属 ring3 驱动（[`crate::kbd::aux_elf_owned`]——双轨回
/// 归锚纪律，内核车道持有期驱动无生产资格）。kind 0 = motion（a =
/// x<<32|y）；kind 1 = button（a = 按钮码<<32|键态）。生产核与任务语
/// 境面同心出口（[`ptr_motion_produce`]/[`ptr_button_produce`]——MPMC
/// 零锁直推 + 光标随批 + 唤醒链同谱）。返回 0 = 受理，1 = 拒收（计数
/// 域随行）。
pub fn sys_ptr_inject(kind: u64, a: u64) -> u64 {
    let me = task::current_task_id();
    let authorized = me == crate::procs::aux_svc_pid()
        && crate::procs::aux_svc_pid() != usize::MAX
        && crate::kbd::aux_elf_owned();
    if !authorized {
        WLCOMP_R3_DENY.fetch_add(1, Ordering::AcqRel);
        return 1;
    }
    let accepted = match kind {
        bedrock::abi::PTR_INJECT_MOTION => {
            let x = (a >> 32) as u32 as i32;
            let y = (a & 0xFFFF_FFFF) as u32 as i32;
            ptr_motion_produce(x, y)
        }
        bedrock::abi::PTR_INJECT_BUTTON => {
            let button = (a >> 32) as u32;
            let state = (a & 0xFFFF_FFFF) as u32;
            ptr_button_produce(button, state)
        }
        _ => false,
    };
    if accepted {
        WLCOMP_R3PTRS.fetch_add(1, Ordering::AcqRel);
        0
    } else {
        1
    }
}

/// 输入链生产面：指针移动（屏幕坐标——会话侧 hit-test 裁决焦点域）。
/// 守护门禁 + 受理入环唤醒链同 [`input_key`]。
pub fn input_pointer_motion(x: i32, y: i32) -> bool {
    if !input_guard() {
        return false;
    }
    ptr_motion_produce(x, y)
}

/// 指针移动生产核（M42-AUXR3 笔㉚抽取面——[`input_pointer_motion`] 与
/// ring3 授权车道 [`sys_ptr_inject`] 同心出口）：MPMC 直推受理
/// + 光标状态随批 + 唤醒链锁外域。
fn ptr_motion_produce(x: i32, y: i32) -> bool {
    let raw = (((x as u32) as u64) << 32) | ((y as u32) as u64 & 0xFFFF_FFFF);
    // MPMC 零锁直推（M45-MPMC46——input_key 同谱）
    let accepted = {
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        PTR_Q.send(raw & !(1u64 << 63)).is_ok() // bit63 = 0（移动域）
    };
    if accepted {
        // 光标状态随批（M42-DMG28 笔㉘——生产域屏幕坐标寄存，消费域
        // 消费联动直标——cursor 与受理事件同源推进）。
        cursor_store(x, y);
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false
    }
}

/// 指针按键生产核（M42-AUXR3 笔㉚抽取面——[`input_pointer_button`] 与
/// ring3 授权车道同心出口）。
fn ptr_button_produce(button: u32, state: u32) -> bool {
    let raw = (1u64 << 63) | ((button as u64) << 32) | (state as u64 & 0xFFFF_FFFF);
    let accepted = {
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

/// 输入链生产面：指针按键（evdev 按钮码 + 键态——BTN_LEFT 0x110 等）。
/// 守护门禁 + 受理入环唤醒链同 [`input_key`]。
pub fn input_pointer_button(button: u32, state: u32) -> bool {
    if !input_guard() {
        return false;
    }
    ptr_button_produce(button, state)
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
    // MPMC 零锁直推（M45-MPMC46——input_key 同谱）
    let accepted = {
        WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
        AXIS_Q.send(raw).is_ok()
    };
    if accepted {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        true
    } else {
        false // 队满丢弃（MPMC 环纪律——KBD_DROP 同谱）
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
    // MPMC 零锁直推（M45-MPMC46——input_key 同谱）
    let accepted = {
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
/// 查询免除）+ **MPMC 零锁直推随批**（M45-MPMC46——v0 [`IN_MU`]
/// try_lock 有界退避口径退役：MPMC 环生产域无锁，ISR 语境零自旋窗
/// 零退避窗；受理同谱计 [`WLCOMP_MPS`]，队满 [`WLCOMP_ISR_FULL`]
/// fail-visible 显形，[`WLCOMP_ISR_DROP`] 退役戳恒零）。受理入环唤
/// 醒链同任务语境面（wake_tasks 自带 IntWindow，wall_hook SCHED 慢
/// 路径同谱先例；ISR 语境可达）。返回受理（入环成功）。
pub fn input_key_isr(sc: u8, state: u32) -> bool {
    let cpu = task::current_cpu_slot();
    let prev = IN_ISR_CTX[cpu].swap(true, Ordering::AcqRel);
    let ok = if input_guard() {
        let raw = ((u64::from(sc)) << 32) | (u64::from(state) & 0xFFFF_FFFF);
        // MPMC 零锁直推（M45-MPMC46——v0 try_lock 有界退避随批口径
        // 退役：MPMC 环生产域无锁，ISR 臂与任务产者同谱直推）
        let accepted = isr_arm_send(|| KEY_Q.send(raw).is_ok());
        if accepted {
            // 唤醒链锁外域（MPMC 零锁域——任务语境面同谱；wake_tasks
            // 自带 IntWindow，ISR 语境可达——wall_hook SCHED 慢路径
            // 同谱先例）
            task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
        }
        accepted
    } else {
        false
    };
    IN_ISR_CTX[cpu].store(prev, Ordering::Release);
    ok
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

// ---- M42-DMGI24（笔㉔）：kbd→waycomp ISR 臂指针/轴域扩展 ----
//（笔⑰挂账「kbd→waycomp ISR 臂指针/轴域扩展（input_pointer_*_isr 臂
// 面随批）」兑现——[`input_key_isr`] 同谱五臂：motion/button/axis/
// axis_stop/frame 全谱 ISR 语境面。**PS/2 aux（IRQ12）电气源挂账**：
// 臂面先在环（inject 同谱自检入口承载——t124），kbd.rs 双车道接线随
// aux 驱动批次。臂样板对 = [`isr_arm_enter`]/[`isr_arm_exit`] 旗随批
// + [`isr_arm_send`] **MPMC 零锁直推核**（M45-MPMC46——v0 try_lock
// 有界退避核口径退役）——直推受理、队满 [`WLCOMP_ISR_FULL`] 显形、
// [`WLCOMP_ISR_DROP`] 退役戳恒零、受理唤醒链锁外域——
// [`input_key_isr`] 全谱同语义（t118 断言面随行升级）。）

/// ISR 臂旗随批进入（per-cpu 置位——守护门禁旗快路径放行前批）。
/// 返回 (cpu 槽号, 前值)——[`isr_arm_exit`] 配对复位（嵌套安全）。
fn isr_arm_enter() -> (usize, bool) {
    let cpu = task::current_cpu_slot();
    let prev = IN_ISR_CTX[cpu].swap(true, Ordering::AcqRel);
    (cpu, prev)
}

/// ISR 臂旗随批退出（前值复位——嵌套安全配对面）。
fn isr_arm_exit(cpu: usize, prev: bool) {
    IN_ISR_CTX[cpu].store(prev, Ordering::Release);
}

/// ISR 臂通用直推核（M45-MPMC46——[`input_key_isr`] 同谱语义单点化；
/// v0 `IN_MU.try_lock()` 有界退避核口径退役）：MPMC 环生产域零锁直
/// 推 + [`WLCOMP_MPS`] 计数；队满 [`WLCOMP_ISR_FULL`] fail-visible
/// 显形；[`WLCOMP_ISR_DROP`] 退役戳恒零（退避窗不存在——生产域无锁）。返回受理。
fn isr_arm_send(send: impl FnOnce() -> bool) -> bool {
    WLCOMP_MPS.fetch_add(1, Ordering::AcqRel);
    let ok = send();
    if !ok {
        WLCOMP_ISR_FULL.fetch_add(1, Ordering::AcqRel);
    }
    ok
}

/// ISR 臂受理唤醒链（锁外域——MPMC 零锁域；wake_tasks 自带
/// IntWindow，ISR 语境可达）。
fn isr_arm_wake() {
    task::wake_tasks(|w| matches!(w, task::WaitWhat::CompIn { .. }));
}

/// ISR 臂：指针移动（屏幕坐标——bit63=0 移动域，[`input_pointer_motion`]
/// 同谱载荷编码）。旗随批 + MPMC 零锁直推 + 受理唤醒锁外。
pub fn input_pointer_motion_isr(x: i32, y: i32) -> bool {
    let (cpu, prev) = isr_arm_enter();
    let ok = if input_guard() {
        let raw = (((x as u32) as u64) << 32) | ((y as u32) as u64 & 0xFFFF_FFFF);
        let accepted = isr_arm_send(|| PTR_Q.send(raw & !(1u64 << 63)).is_ok());
        if accepted {
            // 光标状态随批（M42-DMG28 笔㉘——ISR 臂受理同谱寄存；原子
            // 存零锁 ISR 语境纪律，损伤直标留消费域）。
            cursor_store(x, y);
            isr_arm_wake();
        }
        accepted
    } else {
        false
    };
    isr_arm_exit(cpu, prev);
    ok
}

/// ISR 臂：指针按键（evdev 按钮码 + 键态——bit63=1 按钮域，
/// [`input_pointer_button`] 同谱载荷编码）。
pub fn input_pointer_button_isr(button: u32, state: u32) -> bool {
    let (cpu, prev) = isr_arm_enter();
    let ok = if input_guard() {
        let raw = (1u64 << 63) | ((u64::from(button)) << 32) | (u64::from(state) & 0xFFFF_FFFF);
        let accepted = isr_arm_send(|| PTR_Q.send(raw).is_ok());
        if accepted {
            isr_arm_wake();
        }
        accepted
    } else {
        false
    };
    isr_arm_exit(cpu, prev);
    ok
}

/// ISR 臂：轴滚动（axis/source 值域闸同任务面——[`WLCOMP_AXIS_BAD`]
/// fail-visible；bit37 轴源有效旗 + source<<34 + axis<<32 载荷编码，
/// [`input_pointer_axis`] 同谱）。
pub fn input_pointer_axis_isr(axis: u32, value: i32, source: u32) -> bool {
    let (cpu, prev) = isr_arm_enter();
    let ok = if input_guard() {
        if axis > prism::wayland::comp::AXIS_AXIS_MAX
            || source > prism::wayland::comp::AXIS_SOURCE_MAX
        {
            WLCOMP_AXIS_BAD.fetch_add(1, Ordering::AcqRel);
            isr_arm_exit(cpu, prev);
            return false; // 轴/轴源域越界（生产域闸——fail-visible）
        }
        let raw = (1u64 << 37)
            | ((u64::from(source) & 0x3) << 34)
            | ((u64::from(axis) & 0x3) << 32)
            | ((value as u32) as u64 & 0xFFFF_FFFF);
        let accepted = isr_arm_send(|| AXIS_Q.send(raw).is_ok());
        if accepted {
            isr_arm_wake();
        }
        accepted
    } else {
        false
    };
    isr_arm_exit(cpu, prev);
    ok
}

/// ISR 臂：滚动手势终结（bit36 手势终结旗——[`input_pointer_axis_stop`]
/// 同谱载荷编码；axis 值域闸同 [`input_pointer_axis_isr`]）。
pub fn input_pointer_axis_stop_isr(axis: u32) -> bool {
    let (cpu, prev) = isr_arm_enter();
    let ok = if input_guard() {
        if axis > prism::wayland::comp::AXIS_AXIS_MAX {
            WLCOMP_AXIS_BAD.fetch_add(1, Ordering::AcqRel);
            isr_arm_exit(cpu, prev);
            return false;
        }
        let raw = (1u64 << 36) | ((u64::from(axis) & 0x3) << 32);
        let accepted = isr_arm_send(|| AXIS_Q.send(raw).is_ok());
        if accepted {
            isr_arm_wake();
        }
        accepted
    } else {
        false
    };
    isr_arm_exit(cpu, prev);
    ok
}

/// ISR 臂：帧界标记（bit38 帧界旗零载荷——[`input_pointer_frame`] 同
/// 谱；扫掠边界生产者标记 ISR 语境面）。
pub fn input_pointer_frame_isr() -> bool {
    let (cpu, prev) = isr_arm_enter();
    let ok = if input_guard() {
        let raw = 1u64 << 38;
        let accepted = isr_arm_send(|| AXIS_Q.send(raw).is_ok());
        if accepted {
            isr_arm_wake();
        }
        accepted
    } else {
        false
    };
    isr_arm_exit(cpu, prev);
    ok
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
    /// 窗口标题字节域（M50-XDGSHELL67——客户端 set_title 承接，commit
    /// 域刷新；空 = 标题带底色快径）。
    title: [u8; prism::wayland::comp::XDG_TITLE_CAP],
    /// 标题有效字节数。
    title_n: usize,
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
    // M52-POPCON78 笔90：屏域约束域注入（place_in_bounds 屏域权威域——
    // VIEWPORT 全幅，popup 约束域收口事实源）。
    session.set_screen_bound((
        0,
        0,
        i32::try_from(VIEWPORT.0).unwrap_or(0),
        i32::try_from(VIEWPORT.1).unwrap_or(0),
    ));
    let mut windows: Vec<u64> = Vec::new(); // 创建序 = 焦点序（策略面输入）
    let mut slots: Vec<Window> = Vec::new();
    let mut cfg_track: Vec<(u32, i32, i32)> = Vec::new(); // last-sent configure 跟踪（M51-XDGPOP75 笔86 节流域）
    let mut pools: Vec<(u32, u64)> = Vec::new(); // pool_wl → shm 对象 id（池承接域）
    let mut keymap_pools: Vec<u64> = Vec::new(); // keymap 内容池（M42-WAYCOMP13 收场域）
    let mut stream: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    let mut eof = false; // EOF 收场旗（终末冲刷域判定——M42-WAYCOMP15）
    loop {
        // 输入面排空（M42-INPUT7 输入链——队列 → 会话注入 + 焦点裁决）
        drain_input(&mut session, &windows);
        // xdg close 车道排空（M50-XDGSHELL67——policy close 请求 → 会
        // 话 close 队列，feed 冲刷域 xdg_toplevel.close 出域；受理落账
        // + 拒收取证双面）。M51-XDGPOP75 笔86：父窗收场 → popup 派生
        // 域随行（request_popup_done_for_parent——官方语义：父窗亡则
        // popup 收场，popup_done 事件出域）。
        while let Some(wl) = CLOSE_Q.recv() {
            match session.request_close(wl) {
                Ok(()) => {
                    WLCOMP_CLOSES_REQ.fetch_add(1, Ordering::AcqRel);
                    if session.request_popup_done_for_parent(wl).is_ok() {
                        WLCOMP_PDONES.fetch_add(1, Ordering::AcqRel);
                    }
                }
                Err(_) => {
                    WLCOMP_CLOSES_ERR.fetch_add(1, Ordering::AcqRel);
                }
            };
        }
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
        // 毫秒时间源承接（M42-WAYCOMP19——官方 Wayland 事件 time 域事
        // 实源：冲刷批时刻 now_ms()，同批事件同刻批粒度口径）
        session.set_time_ms(ostd::time::now_ms());
        match session.feed(&stream, &mut out) {
            Ok(rep) => {
                drop_apply(&rep, &mut windows, &mut slots);
                // M43-CURSOR41 笔㊻：窗亡域光标直迁重评（drop 摘除后
                // stationary 光标位 hit-test——pane 蒸发域焦点面直迁
                // 0→存活窗，零 motion 前提；幂等域 hit==pf 零扰）。
                if rep.drops.n > 0 {
                    pointer_relink(&mut session, &windows, &WLCOMP_RELINK);
                }
                policy_sync(&mut session, &mut windows, &mut cfg_track);
                policy_focus(&mut session, &windows);
                policy_rewrite(&windows, &mut slots);
                pool_admit(conn, &rep, &mut pools);
                keymap_serve(conn, &rep, me, &mut keymap_pools);
                apply_commits(&rep, &session, &windows, &mut slots, base, &pools);
                // M44-MAP42 笔㊼：创建期/map 域光标直迁重评（首映射批后
                // stationary 光标位 hit-test——官方 map 域 enter 半域
                // 兑现：新映射窗 pane 蒸发/新生域指针焦点随行，零
                // motion 前提；幂等域 hit==pf 零扰；戳 MAP_RELINK 分
                // 域取证——窗亡域 RELINK 同核异戳）。
                if rep.commits.items[..rep.commits.n]
                    .iter()
                    .flatten()
                    .any(|c| c.first_map)
                {
                    pointer_relink(&mut session, &windows, &WLCOMP_MAP_RELINK);
                }
                // 输入事件 wire 发出数（M42-INPUT7——KeyLog/PtrLog 记录批对账）
                WLCOMP_KEYS.fetch_add(rep.keys.n as u64, Ordering::AcqRel);
                WLCOMP_PTRS.fetch_add(rep.ptrs.n as u64, Ordering::AcqRel);
                // sync 即时完成数（M42-WAYCOMP18——done + delete_id 对计数）
                WLCOMP_SYNCS.fetch_add(rep.syncs as u64, Ordering::AcqRel);
                // frame callback done+delete_id 对数（M42-DMGC22——commit
                // 冲刷域 frame callback 销毁面计数）
                WLCOMP_FRAME_DELS.fetch_add(rep.frame_dels as u64, Ordering::AcqRel);
                // xdg close 事件出域数（M50-XDGSHELL67——close 车道冲刷
                // 域计数，t159 断言面）
                WLCOMP_CLOSES.fetch_add(rep.closes as u64, Ordering::AcqRel);
                // size-configure 对出域数（M51-XDGPOP75 笔86——size 车道
                // 冲刷域计数，t164 断言面）
                WLCOMP_CFGS_SENT.fetch_add(rep.configs as u64, Ordering::AcqRel);
                // popup_done 事件出域数（M51-XDGPOP75 笔86——pdone 车道
                // 冲刷域计数，t164 断言面）
                WLCOMP_PDONES_SENT.fetch_add(rep.popup_dones as u64, Ordering::AcqRel);
                // repositioned+configure 对出域数（M52-POPCON78 笔90——
                // v3 重定位车道冲刷域计数，t167 断言面）
                WLCOMP_REPOS.fetch_add(rep.repos as u64, Ordering::AcqRel);
                // modifiers wire 发出数（M42-WAYCOMP15——Modifiers 记录批）
                for r in rep.keys.items[..rep.keys.n].iter().flatten() {
                    if prism::wayland::comp::KbKind::Modifiers == r.kind {
                        WLCOMP_MODS.fetch_add(1, Ordering::AcqRel);
                    }
                }
                // set_cursor 请求回执计数（M43-KBREP37 笔㊷——记录批消
                // 费域：回执域双载判读 kind = SetCursor）。
                for r in rep.keys.items[..rep.keys.n].iter().flatten() {
                    if prism::wayland::comp::KbKind::SetCursor == r.kind {
                        WLCOMP_KBSETCUR.fetch_add(1, Ordering::AcqRel);
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
            // M43-KBREP37 笔㊷阻塞面豁免：重复域待产（rep_key 非零且
            // rate > 0）= 非静——零登记轮询推进（repeat_tick 在 drain
            // 尾消费域时钟驱动；v0 消费域轮询泵口径，repeat 唤醒器
            // 挂账远线）。零重复窗回归三静域阻塞原貌。
            if session.repeat_pending() {
                task::yield_now();
            } else {
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
                let blocked =
                    task::block_current_unless(task::WaitWhat::CompIn { conn }, true, || {
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
        session.set_time_ms(ostd::time::now_ms()); // 毫秒时间源承接（笔⑲）
        if let Ok(rep2) = session.feed(&[], &mut out2) {
            WLCOMP_KEYS.fetch_add(rep2.keys.n as u64, Ordering::AcqRel);
            WLCOMP_PTRS.fetch_add(rep2.ptrs.n as u64, Ordering::AcqRel);
            WLCOMP_SYNCS.fetch_add(rep2.syncs as u64, Ordering::AcqRel);
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
        sync_rect(w.rect.x, w.rect.y, w.rect.w, w.rect.h);
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
    // M42-AUX25 笔㉕：aux 电气源消费泵前置（kbd.rs 双车道扩谱任务面
    // ——IRQ12 → AUX_RING 原始字节 → 三字节包状态机 → 增量光标 →
    // input_pointer_motion/button 任务语境生产——产出元素与既有队列
    // 同批 drain 消费）。内核双轨回归锚 face（ELF 车道 aux 消费域挂
    // 账随 aux 驱动 ring3 批次）。
    crate::kbd::aux_pump();
    // M43-KBREP37 批次限排（揭雷⑤收口——drain 一次全排 KEY_Q(16)
    // vs 会话 key_q(8) 批界失配：inject Err 即丢键，tcg 慢消费窗
    // 20 键并发实录丢 6——限排 = 每批至多 INPUT_Q_MAX 笔，与会话队
    // 列容量对齐，零丢域闭环；余量滞环下轮消费——KEY_Q 16 容承载）。
    let mut kn_batch = 0usize;
    loop {
        if kn_batch >= INPUT_CAP_MAX {
            break;
        }
        let Some(raw) = KEY_Q.recv() else {
            break;
        };
        kn_batch += 1;
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
    let mut pn_batch = 0usize;
    loop {
        if pn_batch >= INPUT_CAP_MAX {
            break;
        }
        let Some(raw) = PTR_Q.recv() else {
            break;
        };
        pn_batch += 1;
        let is_btn = raw >> 63 == 1;
        let lo = (raw & 0xFFFF_FFFF) as u32;
        let hi = ((raw >> 32) & 0x7FFF_FFFF) as u32;
        if is_btn {
            let (button, state) = (hi, lo);
            if state == 1 {
                // M42-CLICKF33 笔㉝：click-to-focus 焦点迁移联动面（按
                // 钮域随批——笔㉝挂账兑现）。按钮按下域 hit-test 复用
                // （光标位权威 waycomp_cursor——点击发生在光标处，v0
                // pointer_focus 直读口径退役）：跨窗域复用 t131 联动核
                // （enter/leave 取证计数 + 光标格直标
                // pointer_focus_link 强制入账——motion-only 口径退役延
                // 伸到按钮域）+ 面切换域 set_pointer_focus；同窗域键
                // 盘焦点迁移（click-to-focus 本义——指针焦点面 = 键盘
                // 焦点迁移域）+ WLCOMP_CLICK_FOCUS 取证戳（同窗幂等零
                // 计）。
                let (cx, cy) = waycomp_cursor();
                let mut hit_id = 0u32;
                let mut hit_lx = 0i32;
                let mut hit_ly = 0i32;
                if let Ok(plan) = cascade::tiling::tiling_plan(windows, VIEWPORT) {
                    for (id, rect) in plan.panes.iter().rev() {
                        let r = *rect;
                        if cx >= r.x && cx < r.x + r.w as i32 && cy >= r.y && cy < r.y + r.h as i32
                        {
                            hit_id = *id as u32;
                            hit_lx = (cx - r.x).wrapping_mul(256); // surface 局部 fixed 24.8
                            hit_ly = (cy - r.y).wrapping_mul(256);
                            break;
                        }
                    }
                }
                let prev_pf = session.pointer_focus();
                if hit_id != prev_pf {
                    // 跨窗/离域域：t131 联动核复用（取证计数 + 格直标）
                    if prev_pf != 0 {
                        WLCOMP_PTR_LEAVE.fetch_add(1, Ordering::AcqRel);
                    }
                    if hit_id != 0 {
                        WLCOMP_PTR_ENTER.fetch_add(1, Ordering::AcqRel);
                    }
                    pointer_focus_link(cx, cy);
                    let _ = session.set_pointer_focus(hit_id, hit_lx, hit_ly);
                }
                let kb_prev = WLCOMP_KBFOCUS.load(Ordering::Acquire);
                if hit_id != 0 && hit_id != kb_prev && session.set_keyboard_focus(hit_id).is_ok() {
                    WLCOMP_KBFOCUS.store(hit_id, Ordering::Release);
                    WLCOMP_CLICK_FOCUS.fetch_add(1, Ordering::AcqRel);
                }
            }
            if session.pointer_button(button, state).is_ok() {
                WLCOMP_INPUT_PTRS.fetch_add(1, Ordering::AcqRel);
            }
        } else {
            let (x, y) = (hi as i32, lo as i32);
            // M42-DMG28 笔㉘：指针 16px 粗粒度域联动（消费域光标损伤
            // 直标——格跳变 old+new 双笔 16px 吸附入账，同格零扰）。
            pointer_cell_link(x, y);
            // M42-SPRITE29 笔㉙：光标 sprite 平面联动（消费域热点对位
            // 寄存——旧/新画布双笔损伤记账，批尾单合成随 drain 尾）。
            cursor_sprite_move(x, y);
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
                // M42-PTRLINK 笔㉛：Enter/Leave 域联动（焦点切换取证计
                // 数 + 光标格直标强制入账——v0 motion-only 口径退役）
                if prev != 0 {
                    WLCOMP_PTR_LEAVE.fetch_add(1, Ordering::AcqRel);
                }
                if target != 0 {
                    WLCOMP_PTR_ENTER.fetch_add(1, Ordering::AcqRel);
                }
                pointer_focus_link(x, y);
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
    let mut an_batch = 0usize;
    loop {
        if an_batch >= INPUT_CAP_MAX {
            break;
        }
        let Some(raw) = AXIS_Q.recv() else {
            break;
        };
        an_batch += 1;
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
            // 水平滚轮域分账（M43-HWDW40 笔㊺——AXIS_HORIZONTAL_SCROLL
            // 域 axis 出域计数，t139 断言面）。
            if axis == prism::wayland::AXIS_HORIZONTAL_SCROLL {
                WLCOMP_HAXES.fetch_add(1, Ordering::AcqRel);
            }
            // 离散步进随行声明（M43-AV12036——官方语义：wheel 源
            // frame 域 axis 事件随行 axis_value120；v0 口径 value =
            // dz × 120 原字〔120 倍轮单位〕，value120 同字派生透传
            // 〔int 非 fixed〕。非 wheel 源零离散步进不随行；value=0
            // 零步进不随行——零扰域不占计数不占 wire）。
            if source == prism::wayland::AXIS_SOURCE_WHEEL
                && value != 0
                && session.pointer_axis_value120(axis, value).is_ok()
            {
                WLCOMP_V120.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    // 键重复生产泵（M43-KBREP37 笔㊷——drain 尾消费域时钟推进：按住
    // 键 delay/rate 到点产重复 key 事件入待发队列，本轮 feed 冲刷出
    // 域；毫秒时间源承接笔⑲。重复窗内阻塞面豁免——repeat_pending
    // 非静域零登记，消费域轮询推进）。
    let reps = session.repeat_tick(ostd::time::now_ms());
    if reps > 0 {
        WLCOMP_REPS.fetch_add(reps as u64, Ordering::AcqRel);
    }
    // sprite 平面批尾单合成（M42-SPRITE29 笔㉙——移动域损伤记账完毕后
    // 单 fb_compose_tick drain：旧/新画布域 + 格直标域联合一次上屏；
    // 零移动批零合成零扰动——DMGC21 批尾单合成纪律同谱）。
    if SPRITE_MOVED.swap(false, Ordering::AcqRel) {
        let _ = fb::fb_compose_tick();
    }
    // 修饰键态快照读出（M42-WAYCOMP15——排空域语义核末态取证，t116
    // 端到端断言面）
    WLCOMP_MODS_DEP.store(session.modifiers_snapshot().0, Ordering::Release);
}

/// 策略同步（feed 后每轮执行——**仲裁策略面承接域**）：新建 surface
/// 创建期即入窗（创建序 = 焦点序 v0 口径——同批 create+commit 时窗
/// 全量在册，窗格形状一次定形）+ cascade tiling 平面几何注入会话
/// （commit 发布域的损伤裁剪键）。
fn policy_sync(
    session: &mut CompSession,
    windows: &mut Vec<u64>,
    cfg_track: &mut Vec<(u32, i32, i32)>,
) {
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
        // M51-XDGPOP75 笔86：min/max 尺寸宣告消费域（官方语义——
        // configure/几何须落 set_min/set_max 承载域内，0 = 未设定；
        // waycomp tiling 面唯一几何权威域同谱）。
        let rect = clamp_minmax(*rect, session.surface_minmax(*id as u32));
        let _ = session.set_geometry(*id as u32, rect);
        // size-configure 车道（M51-XDGPOP75 笔86——官方语义：configure
        // (w,h) 非零值 = 客户端应重定窗尺寸。节流三重闸：toplevel 角
        // 色在环（surface_acked = Some）∧ 最近 configure 已 ack（单挂
        // 起口径不叠发）∧ 尺寸形变（last-sent 去重——同尺寸零入队）。
        let wl = *id as u32;
        let (w, h) = (rect.w as i32, rect.h as i32);
        if session.surface_acked(wl) != Some(true) {
            continue; // 挂起 configure 未 ack——不叠发（串号对账域）
        }
        if cfg_track
            .iter()
            .any(|(wl_sent, w_sent, h_sent)| wl_sent == &wl && w_sent == &w && h_sent == &h)
        {
            continue; // 尺寸未形变——零入队（last-sent 去重域）
        }
        if session.request_configure(wl, w, h).is_ok() {
            WLCOMP_CFGS.fetch_add(1, Ordering::AcqRel);
            cfg_track.retain(|(wl_sent, _, _)| wl_sent != &wl);
            cfg_track.push((wl, w, h));
        }
    }
    // 窗亡域跟踪清尾（drop 摘除窗口的 last-sent 记录退役）。
    cfg_track.retain(|(wl, _, _)| plan.panes.iter().any(|(id, _)| *id as u32 == *wl));
}

/// min/max 尺寸宣告钳制（M51-XDGPOP75 笔86 语义核——官方语义：
/// max 非零上钳 + min 非零下钳；0 = 未设定域跳过）。
pub fn clamp_minmax(rect: Rect, mm: Option<(i32, i32, i32, i32)>) -> Rect {
    let Some((min_w, min_h, max_w, max_h)) = mm else {
        return rect;
    };
    let mut r = rect;
    if max_w > 0 && r.w > max_w as u32 {
        r.w = max_w as u32;
    }
    if max_h > 0 && r.h > max_h as u32 {
        r.h = max_h as u32;
    }
    if min_w > 0 && r.w < min_w as u32 {
        r.w = min_w as u32;
    }
    if min_h > 0 && r.h < min_h as u32 {
        r.h = min_h as u32;
    }
    r
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
            sync_rect(w.rect.x, w.rect.y, w.rect.w, w.rect.h);
            let _ = fb::fb_compose_tick();
        }
        WLCOMP_DROPS.fetch_add(1, Ordering::AcqRel);
    }
}

/// 光标直迁重评域（M43-CURSOR41 笔㊻窗亡半域 + **M44-MAP42 笔㊼
/// 创建期/map 半域**——官方语义：指针下窗格变更域
/// enter/leave 随行；v0「跨窗直迁须 motion 先行」口径退役〔M42-CLICKF33 挂账兑
/// 现〕）：stationary 光标位（waycomp_cursor 权威）hit-test 重评 →
/// 焦点异窗域 t131 联动核直迁（LEAVE/ENTER 取证计数 + 光标格直标
/// [`pointer_focus_link`] + `set_pointer_focus`——零 motion 前提）。
/// **双触发源分域**：〔窗亡域〕destroy 摘除（[`drop_apply`] 后——
/// `rep.drops.n > 0` 门控，戳 [`WLCOMP_RELINK`]，t140 断言面）；
/// 〔map 域〕创建期首映射批（`apply_commits` 后——批内任一
/// `first_map` commit 门控，戳 [`WLCOMP_MAP_RELINK`]，t141 断言
/// 面——v0「创建期不直迁」口径退役：官方 map 域 enter 半域兑现，
/// stationary 光标位落于新映射窗 pane 即 enter 随行）。幂等域：
/// hit == 现焦点零扰（enter/leave/relink 零增——t140/t141 判据）。
/// 亡窗 leave 由 prism `session_surface_drop` wire 面承接（pf 摘除
/// 域 Leave 记录随行）——窗亡域计数面 enter 单增口径；map 域
/// leave 面全谱计数（prev ≠ 0 即计——跨窗直迁实证域）。
fn pointer_relink(session: &mut CompSession, windows: &[u64], stamp: &AtomicU64) {
    // 无 wl_pointer 派生域零指针焦点语义（官方语义守卫——纯几何会话
    // t121/t122 同谱无 wl_seat/get_pointer：set_pointer_focus
    // BadObject 域无 wire 承载面，直迁重评零触发零计——v0 窗亡域无
    // 守卫口径退役：无设备域 enter/leave 计数属伪取证，本守卫双域
    // 〔窗亡/map〕同收口）。
    if session.pointer_object() == 0 {
        return;
    }
    let (cx, cy) = waycomp_cursor();
    let mut hit = 0u32;
    let mut hit_lx = 0i32;
    let mut hit_ly = 0i32;
    if let Ok(plan) = cascade::tiling::tiling_plan(windows, VIEWPORT) {
        for (id, rect) in plan.panes.iter().rev() {
            let r = *rect;
            if cx >= r.x && cx < r.x + r.w as i32 && cy >= r.y && cy < r.y + r.h as i32 {
                hit = *id as u32;
                hit_lx = (cx - r.x).wrapping_mul(256); // surface 局部 fixed 24.8
                hit_ly = (cy - r.y).wrapping_mul(256);
                break;
            }
        }
    }
    let prev = session.pointer_focus();
    if hit == prev {
        return; // 幂等零扰域（同窗直迁零计——t140 IDEMP 判据）
    }
    if prev != 0 {
        WLCOMP_PTR_LEAVE.fetch_add(1, Ordering::AcqRel);
    }
    if hit != 0 {
        WLCOMP_PTR_ENTER.fetch_add(1, Ordering::AcqRel);
    }
    pointer_focus_link(cx, cy);
    let _ = session.set_pointer_focus(hit, hit_lx, hit_ly);
    stamp.fetch_add(1, Ordering::AcqRel);
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
    // 联合域批尾合成（M42-DMG20——N 窗改写的损伤矩形全谱入账〔tracker
    // 并集合并——相邻/相交域块联合〕+ 批尾单 fb_compose_tick：v0 逐窗
    // 合成退役〔N 窗改写 = N 次合成 → 1 次联合合成——合成节拍对账域
    // t121〕）
    let mut rewrote = false;
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
        // 标题承载值拷贝（Copy 借用域分离——slots[pos] 借用终结后可
        // 变写位不冲突；[u8; CAP] 值拷贝零堆）。
        let (fb_id, slot, src, title, title_n) = {
            let w = &slots[pos];
            (w.fb, w.slot, (w.buf, w.pool), w.title, w.title_n)
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
                _ => paint_damage(fb_id, slot, *rect, *rect, &title[..title_n]),
            }
        }
        // 旧/新矩形双域损伤量化（旧呈现域回退 + 新呈现域成像——联合
        // 域入账，批尾单合成〔M42-DMG20〕）
        sync_rect(old.x, old.y, old.w, old.h);
        sync_rect(rect.x, rect.y, rect.w, rect.h);
        rewrote = true;
        WLCOMP_REWRITES.fetch_add(1, Ordering::AcqRel);
    }
    if rewrote {
        let _ = fb::fb_compose_tick(); // 联合域批尾单合成（v0 逐窗合成退役）
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
/// **批尾单合成（M42-DMGC21 commit 发布域批量化）**：批内 N commit 的
/// 全部损伤矩形〔内容域 + 几何演进兜底域〕入账（[`sync_rect`]——联合
/// 域单出口）完毕后批尾单 `fb::fb_compose_tick` drain——v0 逐 commit
/// 合成退役（N commit = N 次合成 → 1 次联合合成；mirror tracker 并集
/// 合并承载联合）；[`WLCOMP_COMPOSES`] 随批计数（t122 断言面）。
fn apply_commits(
    rep: &FeedReport,
    session: &CompSession,
    windows: &[u64],
    slots: &mut Vec<Window>,
    base: u32,
    pools: &[(u32, u64)],
) {
    // 批内成功 commit 计数（批尾单合成门控——M42-DMGC21：零 commit
    // 批零合成零 COMPOSES，快径零扰动）
    let mut committed = 0u64;
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
                let row_fb = slots[pos].fb;
                if fb::surf_update(row_fb, rect.x, rect.y, rect.w, rect.h, z, true).is_err() {
                    continue; // 机械面拒收（演进域 ENOMEM 等——fail-visible）
                }
                slots[pos].rect = rect;
                if shape_changed {
                    // 全幅重呈现（透明基线上的完整内容重建——像素源
                    // 分流：池像素优先 / 代 Paint 回退。标题承载值拷贝
                    // 同款借用域分离）。
                    let (row_fb, row_slot, src, title, title_n) = {
                        let w = &slots[pos];
                        (w.fb, w.slot, (w.buf, w.pool), w.title, w.title_n)
                    };
                    match src {
                        (Some(b), p) if p != 0 => {
                            paint_pool_damage(row_fb, row_slot, rect, rect, &b, p)
                        }
                        _ => paint_damage(row_fb, row_slot, rect, rect, &title[..title_n]),
                    }
                }
                // 旧/新矩形双域损伤量化（重排改写执行器同款——联合域
                // 单出口承接〔M42-DMG20〕；兜底合成随批尾〔M42-DMGC21
                // ——v0 逐 commit 兜底合成退役：演进域入账与内容域同
                // 批联合 drain〕）
                sync_rect(old.x, old.y, old.w, old.h);
                sync_rect(rect.x, rect.y, rect.w, rect.h);
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
                        title: [0; prism::wayland::comp::XDG_TITLE_CAP],
                        title_n: 0,
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
        // 窗口标题刷新（M50-XDGSHELL67——客户端 set_title 承接：会话
        // 标题承载 → 窗格标题带消费事实源；commit 域刷新，空标题保持
        // 底色快径）。
        if let Some(t) = session.surface_title(wl) {
            if let Some(row) = slots.iter_mut().find(|w| w.wl == wl) {
                let n = t.len().min(row.title.len());
                row.title[..n].copy_from_slice(&t[..n]);
                row.title_n = n;
                if n > 0 {
                    WLCOMP_TITLED.fetch_add(1, Ordering::AcqRel);
                }
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
            _ => {
                let title = slots
                    .iter()
                    .find(|w| w.wl == wl)
                    .map(|w| &w.title[..w.title_n])
                    .unwrap_or(&[]);
                paint_damage(fb_id, slot, rect, paint_dmg, title)
            }
        }
        // 合流电气面：损伤量化入账（SYS_FB_SYNC——联合域单出口承接
        //〔M42-DMG20〕；合成随批尾〔M42-DMGC21——v0 逐 commit 合成
        // 退役〕）
        sync_rect(
            paint_dmg.x.max(0),
            paint_dmg.y.max(0),
            paint_dmg.w,
            paint_dmg.h,
        );
        committed += 1;
    }
    // 批尾单合成（M42-DMGC21 commit 发布域批量化——N commit 批 = N 次
    // 逐 commit 合成 → 1 次联合合成：批内全部损伤矩形〔内容域 + 几何
    // 演进兜底域〕入账完毕后单 fb_compose_tick drain——mirror tracker
    // 并集合并承载联合；COMPOSES 随批计数）。**COMMITS 批量落账随行**
    //（笔⑳揭雷①同根收口：计数递增 = 批含合成全完——v0 逐 commit 落
    // 账语义〔合成后计数〕保持，既有活体 stamps 门控读窗零扰动）
    if committed > 0 {
        let _ = fb::fb_compose_tick();
        WLCOMP_COMMITS.fetch_add(committed, Ordering::AcqRel);
        WLCOMP_COMPOSES.fetch_add(1, Ordering::AcqRel);
    }
}

/// 损伤域代 Paint（fb 机械面像素写——pane 局部坐标域；越域静默丢弃
/// 同 surf_px_write 契约。M50-TEXT69 笔79：窗格顶部 16px 标题栏带
/// 分流〔title_bar_px glyph::text 渲染〕，内容域棋盘模式不变——
/// 既有活体取样域 ly ≥ 16 正交〔t104 ly≥100 / t106 池直读域〕。
/// M50-XDGSHELL67 笔77：标题带改由本窗动态标题驱动（客户端
/// set_title 电气闭环消费面；空标题 = 底色快径——常量域标题退役）。
fn paint_damage(fb_id: u32, slot: usize, pane: Rect, dmg: Rect, title: &[u8]) {
    if dmg.w == 0 || dmg.h == 0 {
        return;
    }
    let pages = fb::surf_slot_pages(slot);
    for sy in dmg.y..dmg.y + dmg.h as i32 {
        for sx in dmg.x..dmg.x + dmg.w as i32 {
            let lx = sx - pane.x;
            let ly = sy - pane.y;
            let color = if (0..PANE_TITLE_H as i32).contains(&ly) {
                title_bar_text_px(title, lx, ly)
            } else {
                pane_pattern(fb_id, lx, ly)
            };
            fb::surf_px_write(slot, pages, pane.w, lx, ly, color);
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
