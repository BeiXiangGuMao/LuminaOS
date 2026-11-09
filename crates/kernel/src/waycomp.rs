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
//! **常驻生命周期**（M42-FBSVC2 挂账域首割）：boot-spawn（kmain 单
//! 调用点）+ 会话环常驻（accept ↔ session 循环不退出）；bind 失败/
//! 监听者终结 = 服务退场（fail-visible——boot 证据行
//! `LUMINA-WAYCOMP-BOOT` 缺位即 S8 显形）；**服务退出后 boot 重启
//! 面挂账**（M42-FBSVC2 既录口径不变）。
//!
//! 锁序契约：无自持锁（全部域内锁单取即放——unixsock/fb 单锁纪律
//! 同谱）；阻塞点 = accept_wait/recv（WaitWhat 双源，探针无锁读）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use mirror::Rect;
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

/// 取证戳快照：(listener, bound, sessions, commits, composes, last_z)。
pub fn waycomp_stamps() -> (u64, bool, u64, u64, u64, i32) {
    (
        WLCOMP_LISTENER.load(Ordering::Acquire),
        WLCOMP_BOUND.load(Ordering::Acquire),
        WLCOMP_SESSIONS.load(Ordering::Acquire),
        WLCOMP_COMMITS.load(Ordering::Acquire),
        WLCOMP_COMPOSES.load(Ordering::Acquire),
        WLCOMP_LAST_Z.load(Ordering::Acquire),
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
    /// 屏域矩形（策略面几何——teardown sync 域）。
    rect: Rect,
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
        match unixsock::recv_by_object(conn, &mut chunk) {
            Ok(0) => break, // EOF（对端终结——会话收场）
            Ok(n) => stream.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        let mut out = [0u8; 1024];
        match session.feed(&stream, &mut out) {
            Ok(rep) => {
                policy_sync(&mut session, &mut windows);
                pool_admit(conn, &rep, &mut pools);
                apply_commits(&rep, &windows, &mut slots, base, &pools);
                if rep.out_len > 0 {
                    send_all(conn, &out[..rep.out_len]);
                }
                stream.drain(..rep.consumed);
            }
            Err(_) => break, // 会话域 fail-visible 断连（v0 口径——回执 error 事件挂账）
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

/// 策略同步（feed 后每轮执行——**仲裁策略面承接域**）：新建 surface
/// 创建期即入窗（创建序 = 焦点序 v0 口径——同批 create+commit 时窗
/// 全量在册，窗格形状一次定形；首映射序入窗的窗数演进重排域随行
/// 揭雷收口：v0 REGISTER 形状锁不收重排改写，如实记档）+ cascade
/// tiling 平面几何注入会话（commit 发布域的损伤裁剪键）。
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
/// 〔policy_sync 已在环〕+ fb 机械面 REGISTER/UPDATE + 损伤域像素源
/// 分流〔wl_shm 池直读 / 代 Paint 回退〕+ SYNC/COMPOSE 合流）。
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
        // 借用域纪律：存在性判定先行（bool——零借用滞留），登记/更新
        // 两域分别行动（match scrutinee 借用滞留面规避）
        let existing = slots.iter().any(|w| w.wl == wl);
        let slot = if existing {
            // 已登记：UPDATE 域（几何/z 改写——形状锁定口径 v0 几何
            // 不变形，重写同域）
            let _ = fb::surf_update(fb_id, rect.x, rect.y, rect.w, rect.h, z, true);
            let row = slots.iter_mut().find(|w| w.wl == wl);
            match row {
                Some(w) => {
                    w.rect = rect;
                    w.slot
                }
                None => continue, // 纵深防御域（查找窗内不可能——v0 单线程会话环）
            }
        } else {
            match fb::surf_register(fb_id, rect.x, rect.y, rect.w, rect.h, z) {
                Ok(slot) => {
                    slots.push(Window {
                        wl,
                        fb: fb_id,
                        slot,
                        rect,
                    });
                    slot
                }
                Err(_) => continue, // 机械面拒收（槽池耗尽等——fail-visible）
            }
        };
        WLCOMP_LAST_Z.store(z, Ordering::Release);
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
        // 像素源分流（M42-ELF5）：attach buffer 且池已承接 → 客户端像
        // 素直读（pool_px_read 物理帧域）；否则代 Paint 替代域（t104
        // 语义面保持——无 buffer commit 回退路径不变）。
        let pool_obj = rec
            .buffer
            .as_ref()
            .and_then(|b| pools.iter().find(|(w, _)| *w == b.pool_wl))
            .map(|(_, o)| *o)
            .unwrap_or(0);
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
