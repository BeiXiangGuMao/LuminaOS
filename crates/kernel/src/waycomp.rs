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
//! wl_keyboard 输入链）：全局输入源（[`input_key`] /
//! [`input_pointer_motion`] / [`input_pointer_button`] 生产面——v0
//! 内核态注入域，ring3 输入守护挂账随 waycomp 主体迁移批次）→ 会
//! 话环排空（[`drain_input`]——键盘直注入；指针 hit-test 焦点裁决
//! 〔z 序顶窗优先——cascade 平面逆序首个含点窗〕+ click-to-focus
//! 〔按下域指针焦点面 = 键盘焦点迁移域〕）→ 会话待发队列（prism
//! CompSession 焦点/注入钩子）→ feed 冲刷 wl_keyboard/wl_pointer
//! 事件出域 → 客户端。会话环 v0 = 探针轮询 + 让步
//! （[`unixsock::session_probe_by_object`] 非消费双读——阻塞输入
//! 等待面〔WaitWhat 扩域〕挂账随 waycomp 主体迁移批次）。
//!
//! **常驻生命周期**（M42-FBSVC2 挂账域首割）：boot-spawn（kmain 单
//! 调用点）+ 会话环常驻（accept ↔ session 循环不退出）；bind 失败/
//! 监听者终结 = 服务退场（fail-visible——boot 证据行
//! `LUMINA-WAYCOMP-BOOT` 缺位即 S8 显形）；**服务退出后 boot 重启
//! 面挂账**（M42-FBSVC2 既录口径不变）。
//!
//! 锁序契约：无自持锁（全部域内锁单取即放——unixsock/fb 单锁纪律
//! 同谱）；阻塞点 = accept_wait/recv（WaitWhat 双源，探针无锁读）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use mirror::Rect;
use ostd::sync::spsc::SpscRing;
use prism::wayland::comp::{
    BufferRec, CommitRecord, CompSession, FeedReport, GlobalDef, GLOBALS_MAX,
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

/// 输入源队列深度（键盘/指针各一定容——定容零堆纪律，SPSC 单生产
/// 者域 v0 如实记档：批跑环境事实单生产者，多产者域挂账）。
const INPUT_CAP: usize = 16;
/// 键盘输入队列（元素 = (key << 32) | state 打包）。
static KEY_Q: SpscRing<u64, INPUT_CAP> = SpscRing::new();
/// 指针输入队列（元素 = bit63=按钮旗 | (button/x << 32) | state/y）。
static PTR_Q: SpscRing<u64, INPUT_CAP> = SpscRing::new();

/// 输入链生产面：击键（M42-INPUT7——v0 内核态输入源注入域；键码
/// v0 口径 = scancode set 1 原值，evdev 键码映射挂账）。
pub fn input_key(key: u32, state: u32) {
    let raw = ((key as u64) << 32) | (state as u64 & 0xFFFF_FFFF);
    let _ = KEY_Q.send(raw); // 队满静默丢弃（SPSC 环纪律——KBD_DROP 同谱）
}

/// 输入链生产面：指针移动（屏幕坐标——会话侧 hit-test 裁决焦点域）。
pub fn input_pointer_motion(x: i32, y: i32) {
    let raw = (((x as u32) as u64) << 32) | ((y as u32) as u64 & 0xFFFF_FFFF);
    let _ = PTR_Q.send(raw & !(1u64 << 63)); // bit63 = 0（移动域）
}

/// 输入链生产面：指针按键（evdev 按钮码 + 键态——BTN_LEFT 0x110 等）。
pub fn input_pointer_button(button: u32, state: u32) {
    let raw = (1u64 << 63) | ((button as u64) << 32) | (state as u64 & 0xFFFF_FFFF);
    let _ = PTR_Q.send(raw); // bit63 = 1（按钮域）
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
    let base = ((seq - 1) as u32) * FB_ID_SESSION_STRIDE;
    let mut session = CompSession::new(GLOBALS);
    let mut windows: Vec<u64> = Vec::new(); // 创建序 = 焦点序（策略面输入）
    let mut slots: Vec<Window> = Vec::new();
    let mut pools: Vec<(u32, u64)> = Vec::new(); // pool_wl → shm 对象 id（池承接域）
    let mut stream: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        // 输入面排空（M42-INPUT7 输入链——队列 → 会话注入 + 焦点裁决）
        drain_input(&mut session, &windows);
        // 流消费探针（非消费双读——环空且终结旗 = EOF 收场域）
        let (pending, dead) = unixsock::session_probe_by_object(conn);
        let mut got = 0usize;
        if pending > 0 || dead {
            match unixsock::recv_by_object(conn, &mut chunk) {
                Ok(0) => break, // EOF（对端终结——会话收场；USOCK_EOFS 计数域）
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
                apply_commits(&rep, &windows, &mut slots, base, &pools);
                // 输入事件 wire 发出数（M42-INPUT7——KeyLog/PtrLog 记录批对账）
                WLCOMP_KEYS.fetch_add(rep.keys.n as u64, Ordering::AcqRel);
                WLCOMP_PTRS.fetch_add(rep.ptrs.n as u64, Ordering::AcqRel);
                if rep.out_len > 0 {
                    send_all(conn, &out[..rep.out_len]);
                }
                stream.drain(..rep.consumed);
            }
            Err(_) => break, // 会话域 fail-visible 断连（v0 口径——回执 error 事件挂账）
        }
        if pending == 0 && got == 0 {
            task::yield_now(); // 无流无输入域让步（v0 轮询口径——TCG 批跑时序域）
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
    WLCOMP_END_COUNT.store(fb::surf_count() as u64, Ordering::Release);
    WLCOMP_SESSION_DONE.store(true, Ordering::Release);
    let _ = unixsock::shutdown_by_object(conn);
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
        let key = (raw >> 32) as u32;
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
