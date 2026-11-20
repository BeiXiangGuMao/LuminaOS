//! Prism Wayland 合成器会话面 v1（M42-COMP4 阶段三首笔——「合成器进程
//! 面」核心语义域）。
//!
//! **定位**：M42-计划 阶段三「prism 仲裁 ring3 化 + wayland 合成器进程
//! 消费 SYS_FB_SURFACE」的**仲裁策略面首割**——合成器会话状态机
//! （registry 公告 / bind / surface 生命周期 / damage-commit 发布语
//! 义 / 帧回调）自内核 fb 消费域升出为**纯函数面**：no_std 零堆零
//! unsafe（crate 纪律不变），非 test 门控（`wayland` v0 同口径——
//! ring3 编译进程可直接链接；电气面消费方 = 常驻合成器服务
//! kernel-resident lane〔ADR-0004 双轨〕，ring3 编译进程承接随用户
//! 态 ELF 播种批次挂账如实登记）。
//!
//! **会话语义**（官方 wayland.xml 1.21.0 + wire 文档同源对账）：
//! - 客户端流入口 [`CompSession::feed`]：字节流推进式解析（部分消息
//!   留缓冲——[`FeedReport::consumed`] 承载流步长），签名驱动解析
//!   （v0 `SIG_*` 表复用）+ 对象表路由（v0 [`super::WlObjectTable`]
//!   复用）；
//! - registry 面：get_registry → globals 逐条公告（[`GlobalDef`] 名
//!   单 = 合成器策略面输入）；bind 校验接口名在册 + 版本上界 → 对象
//!   登记；
//! - surface 面：create_surface → 会话槽登记；damage → pending 损伤
//!   并集（surface 坐标域）；commit → **发布语义**（损伤平移屏域后与
//!   窗口几何交集裁剪 = 屏域损伤矩形；帧回调队列一次冲刷为 done 事件
//!   ——官方 commit 域语义）；
//! - 帧回调：frame(new_id) 入队 → commit 冲刷（官方语义——callback
//!   于下次 commit 完成）；
//! - sync：callback done 即时回发（官方语义，callback_data = 0）。
//!
//! **策略面钩子**：合成器窗口几何由 shell/tiling 策略承载（LuminaOS
//! 域 = cascade::tiling::tiling_plan 产出 mirror::Rect，loom 常量同
//! 源承接——t79「两套面同一几何」先例），经 [`CompSession::set_geometry`]
//! 注入会话；commit 记录（[`CommitRecord`]）携带屏域几何与损伤，电气
//! 面消费方据此驱动 SYS_FB_SURFACE 登记/更新 + SYS_FB_SYNC 损伤量化
//! ——**仲裁策略（哪个 surface 在哪个矩形、z 序）自会话面出，内核
//! 合成机械面（Stack::blend）零触碰**（ADR-0004 双轨共存）。
//!
//! **v0 子集域**（如实记档）：请求承接域 = display/registry/
//! compositor/surface 核心四接口（attach/damage/frame/commit/destroy）
//! + **shm 域（M42-ELF5 桌面链批次首割）**：wl_shm.create_pool（fd
//! 占位字记账 → 电气面 SEND_FD/RECV_FD 承接）+ wl_shm_pool.
//! create_buffer（buffer 几何/池偏移记账）+ wl_surface.attach buffer
//! 实录 → commit 记录携带 buffer 几何（电气面自池读像素上屏——
//! pane 代 Paint 替代域随行落域）；region 绑定域登记、其余请求域外
//! fail-visible；callback 对象 commit 后不回收（delete_id 复用面挂
//! 账）；fixed 原字透传（语义换算挂账）。**M42-GEOM6 域①**：destroy
//! 摘除记录批（[`DropLog`]）——重排改写触发源（电气面摘 fb surface
//! + 窗口表行 → 存活窗 tiling 重排 → 几何演进 UPDATE 改写）。
//!
//! 错误域 fail-visible 全谱显形（[`CompError`]）——不吞畸形不静默降
//! 级；feed 单消息失败即 Err（会话域由消费方裁决：回 error 事件或断
//! 连——v0 电气面 = 断连）。

#![forbid(unsafe_code)]

use mirror::Rect;

use super::{
    compositor, display, encode_callback_done_event, encode_display_delete_id_event,
    encode_keyboard_enter_event, encode_keyboard_key_event, encode_keyboard_keymap_event,
    encode_keyboard_leave_event, encode_keyboard_modifiers_event,
    encode_keyboard_repeat_info_event, encode_pointer_axis_event, encode_pointer_axis_source_event,
    encode_pointer_axis_stop_event, encode_pointer_axis_value120_event,
    encode_pointer_button_event, encode_pointer_enter_event, encode_pointer_frame_event,
    encode_pointer_leave_event, encode_pointer_motion_event, encode_registry_global_event,
    encode_seat_capabilities_event, encode_xdg_popup_configure_event, encode_xdg_popup_done_event,
    encode_xdg_popup_repositioned_event, encode_xdg_surface_configure_event,
    encode_xdg_toplevel_close_event, encode_xdg_toplevel_configure_event,
    encode_xdg_wm_base_ping_event, iface_name, keyboard_req, parse_args, parse_header, registry,
    seat, shm, shm_pool, surface, xdg_popup, xdg_positioner, xdg_surface, xdg_toplevel,
    xdg_wm_base, PosDef, WlArg, WlError, WlHeader, WlIface, WlObjectTable, HEADER,
    KEYMAP_FORMAT_XKB_V1, MOD_ALT, MOD_CAPS, MOD_CTRL, MOD_MOD4, MOD_NUM2, MOD_SHIFT,
    SEAT_CAPS_KEYBOARD, SEAT_CAPS_POINTER, SIG_COMPOSITOR_CREATE_REGION,
    SIG_COMPOSITOR_CREATE_SURFACE, SIG_DISPLAY_GET_REGISTRY, SIG_DISPLAY_SYNC,
    SIG_KEYBOARD_SET_CURSOR, SIG_REGISTRY_BIND, SIG_SEAT_GET_KEYBOARD, SIG_SEAT_GET_POINTER,
    SIG_SHM_CREATE_POOL, SIG_SHM_POOL_CREATE_BUFFER, SIG_SHM_POOL_DESTROY, SIG_SURFACE_ATTACH,
    SIG_SURFACE_COMMIT, SIG_SURFACE_DAMAGE, SIG_SURFACE_FRAME, SIG_XDG_POPUP_GRAB,
    SIG_XDG_POPUP_REPOSITION, SIG_XDG_POSITIONER_SET_ANCHOR, SIG_XDG_POSITIONER_SET_ANCHOR_RECT,
    SIG_XDG_POSITIONER_SET_CONSTRAINT_ADJUSTMENT, SIG_XDG_POSITIONER_SET_GRAVITY,
    SIG_XDG_POSITIONER_SET_OFFSET, SIG_XDG_POSITIONER_SET_PARENT_CONFIGURE,
    SIG_XDG_POSITIONER_SET_PARENT_SIZE, SIG_XDG_POSITIONER_SET_REACTIVE,
    SIG_XDG_POSITIONER_SET_SIZE, SIG_XDG_SURFACE_ACK_CONFIGURE, SIG_XDG_SURFACE_GET_POPUP,
    SIG_XDG_SURFACE_GET_TOPLEVEL, SIG_XDG_SURFACE_SET_WINDOW_GEOMETRY, SIG_XDG_TOPLEVEL_SET_APP_ID,
    SIG_XDG_TOPLEVEL_SET_MAX_SIZE, SIG_XDG_TOPLEVEL_SET_MIN_SIZE, SIG_XDG_TOPLEVEL_SET_TITLE,
    SIG_XDG_WM_BASE_CREATE_POSITIONER, SIG_XDG_WM_BASE_GET_XDG_SURFACE, SIG_XDG_WM_BASE_PONG,
    WIRE_MAX, XDG_ANCHOR_MAX, XDG_ANCHOR_NONE, XDG_CADJ_FLIP_X, XDG_CADJ_FLIP_Y, XDG_CADJ_RESIZE_X,
    XDG_CADJ_RESIZE_Y, XDG_CADJ_SLIDER_X, XDG_CADJ_SLIDER_Y,
};

/// 单会话 surface 槽容量（定容零堆——SurfaceTable 同量级先例）。
pub const SESSION_SURFACES: usize = 8;
/// 单次 feed 的 commit 记录上限（多消息流批量回执定容域）。
pub const MAX_COMMITS_PER_FEED: usize = 8;
/// 每 surface 帧回调队列深度（官方无上界——v0 定容裁量如实记档）。
pub const MAX_FRAME_CBS: usize = 4;
/// registry globals 名单上限（核心子集 + xdg_shell：compositor/seat/
/// shm/output/xdg_wm_base——M50-XDGSHELL67 笔77 公告面演化 4→5 目）。
pub const GLOBALS_MAX: usize = 5;
/// xdg_toplevel 窗口标题承载上界（set_title 截断域——定容零堆；
/// waycomp 标题带消费面同谱）。
pub const XDG_TITLE_CAP: usize = 32;
/// app_id 承载上界（set_app_id 截断域）。
pub const XDG_APPID_CAP: usize = 16;
/// 服务端 close 请求队列深度（policy 车道——request_close 定容）。
pub const CLOSE_Q_MAX: usize = 8;
/// 会话 positioner 定容表深度（M51-XDGPOP75 笔86——create_positioner
/// 定容零堆；同会话 popup 数同量级裁量）。
pub const POSITIONER_CAP: usize = 4;
/// 服务端 size-configure 待发队列深度（M51-XDGPOP75 笔86——
/// request_configure policy 车道定容；单挂起 configure 口径随行）。
pub const SIZE_Q_MAX: usize = 4;
/// popup 嵌套深度上界（M52-POPCON78 笔90 G-4——嵌套父域定容裁量；
/// 官方无上界，零堆定容纪律裁量如实记档——越界 XdgRoleBusy fail-visible）。
const POPUP_NEST_MAX: usize = 4;
/// 服务端 popup_done 待发队列深度（M51-XDGPOP75 笔86——父窗收场
/// 派生域定容）。
pub const PDONE_Q_MAX: usize = 4;
/// 单次 feed 的 create_pool 记录上限（定容零堆）。
pub const MAX_POOLS_PER_FEED: usize = 4;
/// 单次 feed 的 destroy 摘除记录上限（定容零堆——MAX_POOLS_PER_FEED 同量级）。
pub const MAX_DROPS_PER_FEED: usize = 4;
/// 单会话 buffer 槽容量（定容零堆——SESSION_SURFACES 同量级先例）。
pub const SESSION_BUFFERS: usize = 8;
/// 输入事件队列深度（M42-INPUT7——键盘/指针各一定容；定容零堆纪律）。
pub const INPUT_Q_MAX: usize = 8;
/// 单次 feed 的输入事件记录上限（定容零堆——INPUT_Q_MAX 同量级）。
pub const MAX_INPUTS_PER_FEED: usize = 8;
/// enum axis 值域上界（官方声明序 vertical_scroll=0 / horizontal_scroll=
/// 1——M42-WAYCOMP14 注入面域闸）。
pub const AXIS_AXIS_MAX: u32 = 1;
/// enum axis_source 值域上界（官方声明序 wheel=0 / finger=1 /
/// continuous=2 / wheel_tilt=3——注入面域闸）。
pub const AXIS_SOURCE_MAX: u32 = 3;

/// keymap 内容面（M42-WAYCOMP13 笔⑬——「keymap 内容面」挂账域兑现）：
/// wl_keyboard.keymap 承载的 XKB keymap 内容事实源（xkb v1 文本域——
/// 官方语义：合成器将 keymap 内容放入 shm 池、keymap 事件携带 fd +
/// 字节长度；客户端经 libxkbcommon 编译消费）。v0 内容 = 最小合法
/// keymap 壳（evdev 键码域 + complete types/compat + pc+us 符号域
/// ——与 wlroots/weston 产出形同构；include 展开由客户端 xkb 数据
/// 域承接）。`.rodata` 静态零堆——电气面（shm 池铸造 + fd 传递）由
/// 消费方（waycomp keymap 承接域）执行。
pub const KEYMAP_XKB_V1: &[u8] = b"xkb_keymap {\n\
\x20   xkb_keycodes { include \"evdev\" };\n\
\x20   xkb_types { include \"complete\" };\n\
\x20   xkb_compat { include \"complete\" };\n\
\x20   xkb_symbols { include \"pc+us\" };\n\
};\n";

/// keymap 公告记录（M42-WAYCOMP13——feed 回执域：电气面据 size 铸池
/// + SEND_FD 承接内容面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeymapRecord {
    /// wl_keyboard 对象 id（客户端域——get_keyboard new_id）。
    pub keyboard_id: u32,
    /// keymap 内容字节长度（官方语义：size = fd 内容字节域——prism
    /// 事实源 [`KEYMAP_XKB_V1`] 长度，v0 单 keymap 会话域 last-wins
    /// 如实记档）。
    pub size: u32,
}

/// registry global 名单项（合成器策略面输入——公告名单与版本域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalDef {
    /// registry global 名（uint——bind 寻址域）。
    pub name: u32,
    /// 接口语义。
    pub iface: WlIface,
    /// 公告版本（bind 版本域上界）。
    pub version: u32,
}

/// 会话内 surface 状态（生命周期 + 损伤积累 + 帧回调队列）。
#[derive(Debug, Clone, Copy)]
pub struct CompSurface {
    /// wl 对象 id（客户端域——create_surface new_id）。
    pub wl_id: u32,
    /// attach 记账位（v0 buffer 域——记 id 不承载像素，wl_shm 挂账）。
    pub attached: bool,
    /// attach 的 buffer 对象 id（M42-ELF5——0 = 无；create_buffer
    /// 登记域实-id，commit 时解析为 [`BufferRec`] 几何）。
    pub attach_buf: u32,
    /// 合成器侧窗口几何（屏域——策略面 [`CompSession::set_geometry`]
    /// 注入；未注入 = 零面积矩形，commit 产物零面积损伤域）。
    pub geom: Rect,
    /// pending 损伤并集（surface 坐标域——damage 请求积累，commit 冲
    /// 刷后清零）。
    pub damage: Option<Rect>,
    /// pending 帧回调（客户端域 id 队列——commit 冲刷为 done 事件）。
    pub frames: [u32; MAX_FRAME_CBS],
    /// 帧回调队列长度。
    pub frame_n: usize,
    /// 首映射位（commit 一次后置位——电气面 REGISTER/UPDATE 分流键）。
    pub mapped: bool,
    /// xdg_surface 对象 id（M50-XDGSHELL67——0 = 无窗口角色；
    /// wm_base.get_xdg_surface 派生域，destroy 域清除）。
    pub xdg_surf: u32,
    /// xdg_toplevel 对象 id（0 = 未派生 toplevel——get_toplevel 域）。
    pub xdg_toplevel: u32,
    /// 最近一次 configure 串号（get_toplevel 域铸造——自 1 起，v0 单
    /// 挂起 configure 口径）。
    pub config_serial: u32,
    /// 最近 configure 已 ack 位（commit 前置闸事实源——官方双向序契
    /// 约：commit 前必须 ack 最近一次 configure）。
    pub acked: bool,
    /// 窗口标题承载（set_title 截断域——waycomp 标题带消费事实源）。
    pub title: [u8; XDG_TITLE_CAP],
    /// 标题有效字节数。
    pub title_n: usize,
    /// app_id 承载（set_app_id 截断域）。
    pub app_id: [u8; XDG_APPID_CAP],
    /// app_id 有效字节数。
    pub app_id_n: usize,
    /// xdg_popup 对象 id（M51-XDGPOP75 笔86——0 = 未派生 popup；
    /// get_popup 派生域，destroy 域清除）。
    pub xdg_popup: u32,
    /// popup 位置 x（父面局部坐标——placement 语义核产出，configure
    /// 事件同值出域）。
    pub popup_x: i32,
    /// popup 位置 y。
    pub popup_y: i32,
    /// popup grab 记账位（xdg_popup.grab 官方请求域——v0 记账面，
    /// 输入 grab 施策挂账如实记档）。
    pub popup_grabbed: bool,
    /// popup 父面 wl id（popup_done 派生域寻址键——父窗收场扫描域）。
    pub popup_parent_wl: u32,
    /// popup 屏域裁剪后宽（M52-POPCON78 笔90——约束域收口：place_in_bounds
    /// 产出，屏域权威渲染域）。
    pub popup_w: i32,
    /// popup 屏域裁剪后高。
    pub popup_h: i32,
    /// toplevel 最小尺寸宣告（set_min_size——0 = 未设定，官方语义；
    /// waycomp tiling 面消费域事实源）。
    pub min_w: i32,
    /// 最小高度宣告。
    pub min_h: i32,
    /// toplevel 最大尺寸宣告（set_max_size——0 = 未设定）。
    pub max_w: i32,
    /// 最大高度宣告。
    pub max_h: i32,
}

/// wl_shm 池创建记录（feed 回执——电气面 fd 传递对账域：每记录恰
/// 对一 fd 占位字，消费方据 [`FeedReport::fd_need`] 承接 RECV_FD）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolRecord {
    /// 新池对象 id（客户端域——create_pool new_id）。
    pub pool_wl: u32,
    /// 池字节域（create_pool size 参——客户端 CREATE 域对账键）。
    pub size: i32,
}

/// 单次 feed 的池创建记录批（定容零堆）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<PoolRecord>; MAX_POOLS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl PoolLog {
    /// 空批。
    pub const EMPTY: PoolLog = PoolLog {
        items: [None; MAX_POOLS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，如实记档）。
    fn push(&mut self, rec: PoolRecord) {
        if self.n < MAX_POOLS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }
}

/// 键盘事件类别（M42-INPUT7——焦点域迁移 + 击键域双分）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbKind {
    /// 键盘焦点入域（wl_keyboard.enter）。
    Enter,
    /// 键盘焦点离域（wl_keyboard.leave）。
    Leave,
    /// 击键（wl_keyboard.key）。
    Key,
    /// 修饰键态事件（wl_keyboard.modifiers——M42-WAYCOMP15 语义核）。
    Modifiers,
    /// 键盘光标面宣告回执（wl_keyboard.set_cursor 请求域——
    /// M43-KBREP37 笔㊷；KeyRecord 复用域：surface = 目标面〔0 = 默
    /// 认光标回退〕、key = hotspot_x、state = hotspot_y）。
    SetCursor,
}

/// 键盘事件记录（feed 回执取证域——电气面对账 + t109 断言面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRecord {
    /// 事件类别。
    pub kind: KbKind,
    /// 焦点 surface 对象 id（击键域 = 注入时焦点面）。
    pub surface: u32,
    /// 输入串号（单调——官方 serial 域；time 域 = 冲刷批时刻 ms——M42-WAYCOMP19）。
    pub serial: u32,
    /// 键码（v0 口径 = scancode set 1 原值——evdev 键码映射挂账）。
    pub key: u32,
    /// 键态。
    pub state: u32,
    /// 修饰键掩码 depressed（Modifiers 有效——M42-WAYCOMP15）。
    pub mods_d: u32,
    /// 修饰键掩码 latched（Modifiers 有效——v0 恒零域挂账）。
    pub mods_l: u32,
    /// 修饰键掩码 locked（Modifiers 有效）。
    pub mods_lk: u32,
    /// 布局组（Modifiers 有效——v0 恒零域挂账）。
    pub group: u32,
}

/// 单次 feed 的键盘事件记录批（定容零堆）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<KeyRecord>; MAX_INPUTS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl KeyLog {
    /// 空批。
    pub const EMPTY: KeyLog = KeyLog {
        items: [None; MAX_INPUTS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，如实记档）。
    fn push(&mut self, rec: KeyRecord) {
        if self.n < MAX_INPUTS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }
}

/// 指针事件类别（M42-INPUT7——焦点域/移动域/按键域三分；M42-WAYCOMP14
/// axis 族/frame 扩族——官方声明序事件域七分）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrKind {
    /// 指针焦点入域（wl_pointer.enter）。
    Enter,
    /// 指针焦点离域（wl_pointer.leave）。
    Leave,
    /// 指针移动（wl_pointer.motion）。
    Motion,
    /// 指针按键（wl_pointer.button）。
    Button,
    /// 轴滚动（wl_pointer.axis——value fixed 24.8 原字）。
    Axis,
    /// 分组终结逻辑事件（wl_pointer.frame——axis 族批出域定界）。
    Frame,
    /// 轴源声明（wl_pointer.axis_source——frame 域前置）。
    AxisSource,
    /// 滚动手势终结（wl_pointer.axis_stop）。
    AxisStop,
    /// 离散步进语义（wl_pointer.axis_value120——wheel 源 frame 域随
    /// axis 事件随行，M43-AV12036）。
    AxisValue120,
}

/// 指针事件记录（feed 回执取证域——电气面对账 + t109 断言面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrRecord {
    /// 事件类别。
    pub kind: PtrKind,
    /// 焦点 surface 对象 id（0 = 无焦点——Leave 记录保留旧面）。
    pub surface: u32,
    /// 输入串号（单调——time 域 = 冲刷批时刻 ms——M42-WAYCOMP19）。
    pub serial: u32,
    /// surface 局部坐标 x（fixed 24.8 原字——Enter/Motion 有效）。
    pub x: i32,
    /// surface 局部坐标 y（fixed 24.8 原字）。
    pub y: i32,
    /// evdev 按钮码（Button 有效）。
    pub button: u32,
    /// 按钮态（Button 有效）。
    pub state: u32,
    /// 轴域（Axis/AxisStop 有效——官方 enum axis 值域）。
    pub axis: u32,
    /// 轴位移增量（Axis 有效——fixed 24.8 原字，可负）。
    pub value: i32,
    /// 轴源（AxisSource 有效——官方 enum axis_source 值域）。
    pub source: u32,
}

/// 单次 feed 的指针事件记录批（定容零堆）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<PtrRecord>; MAX_INPUTS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl PtrLog {
    /// 空批。
    pub const EMPTY: PtrLog = PtrLog {
        items: [None; MAX_INPUTS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，如实记档）。
    fn push(&mut self, rec: PtrRecord) {
        if self.n < MAX_INPUTS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }
}

/// destroy 摘除记录（feed 回执——**重排改写触发源**，M42-GEOM6 域①：
/// 电气面消费方据此摘除 fb surface/窗口表行 → 存活窗 tiling 重排
/// → 几何演进 UPDATE 改写；会话域已同步摘槽，记录 = 电气面对账域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropRecord {
    /// 摘除 surface 的 wl 对象 id（客户端域）。
    pub wl_id: u32,
}

/// 单次 feed 的摘除记录批（定容零堆——CommitLog 同构）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<DropRecord>; MAX_DROPS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl DropLog {
    /// 空批。
    pub const EMPTY: DropLog = DropLog {
        items: [None; MAX_DROPS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，如实记档）。
    fn push(&mut self, rec: DropRecord) {
        if self.n < MAX_DROPS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }
}

/// 会话内 buffer 几何（M42-ELF5——客户端像素承载域）：池引用 +
/// 池内偏移 + 像素域 + 行距 + 像素格式（wl_shm 标准格式值：
/// ARGB8888 = 0 / XRGB8888 = 1——v0 双格式同承载，像素域原字透传）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferRec {
    /// buffer 对象 id（客户端域——create_buffer new_id）。
    pub wl: u32,
    /// 所属池对象 id（客户端域——create_buffer 发起方）。
    pub pool_wl: u32,
    /// 池内字节偏移（create_buffer offset 参）。
    pub offset: i32,
    /// 像素域宽。
    pub w: i32,
    /// 像素域高。
    pub h: i32,
    /// 行距（字节——row stride）。
    pub stride: i32,
    /// 像素格式（wl_shm 格式枚举原值）。
    pub format: u32,
}

/// commit 发布记录（feed 回执——电气面消费域：REGISTER/UPDATE 分流 +
/// SYS_FB_SYNC 损伤量化 + 帧冲刷计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitRecord {
    /// 发布 surface 的 wl 对象 id。
    pub wl_id: u32,
    /// 屏域窗口几何（策略面几何——非首次 commit 亦可对账域）。
    pub geom: Rect,
    /// 屏域损伤矩形（pending 损伤平移屏域 ∩ 窗口几何；零面积 = 无实
    /// 效损伤）。
    pub damage: Rect,
    /// 本次冲刷的帧回调数（done 事件已回执）。
    pub frames_fired: usize,
    /// 首映射位（true = 电气面 REGISTER 域；false = UPDATE 域）。
    pub first_map: bool,
    /// commit 时 surface 所附 buffer 几何（M42-ELF5——None = 无附
    /// buffer，电气面代 Paint 替代域；Some = 自池读像素上屏）。
    pub buffer: Option<BufferRec>,
}

/// 单次 feed 的 commit 记录批（定容零堆——feed 回执域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<CommitRecord>; MAX_COMMITS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl CommitLog {
    /// 空批。
    pub const EMPTY: CommitLog = CommitLog {
        items: [None; MAX_COMMITS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，超量 commit 以会话
    /// 串号域为准如实记档）。
    fn push(&mut self, rec: CommitRecord) {
        if self.n < MAX_COMMITS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }

    /// 按 wl id 末次记录查找（同 feed 双 commit 后者胜——电气面对账
    /// 消费域）。
    pub fn last_of(&self, wl_id: u32) -> Option<CommitRecord> {
        self.items[..self.n]
            .iter()
            .flatten()
            .rev()
            .find(|r| r.wl_id == wl_id)
            .copied()
    }
}

/// feed 回执（流推进 + 产生字节 + commit 批记录）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedReport {
    /// 流推进字节数（完整消息前缀；部分消息留缓冲——残段由消费方前
    /// 移承载）。
    pub consumed: usize,
    /// `out` 回执缓冲产出字节数（事件序列化域）。
    pub out_len: usize,
    /// commit 批记录（`commits.items[..commits.n]` 有效）。
    pub commits: CommitLog,
    /// 池创建记录批（M42-ELF5——`pools.items[..pools.n]` 有效；每记
    /// 录对一 fd 占位字）。
    pub pools: PoolLog,
    /// destroy 摘除记录批（M42-GEOM6 域①——`drops.items[..drops.n]`
    /// 有效；重排改写触发源：电气面摘除域）。
    pub drops: DropLog,
    /// 本 feed 消费的 fd 占位字数（电气面 RECV_FD 承接计数——与
    /// pools 批对账：每 create_pool 恰一 fd）。
    pub fd_need: usize,
    /// 键盘事件记录批（M42-INPUT7——`keys.items[..keys.n]` 有效；
    /// 输入链电气面对账域）。
    pub keys: KeyLog,
    /// 指针事件记录批（M42-INPUT7——`ptrs.items[..ptrs.n]` 有效）。
    pub ptrs: PtrLog,
    /// keymap 公告记录（M42-WAYCOMP13——本 feed 内 get_keyboard 派生
    /// 域公告；None = 无公告。电气面（waycomp keymap 承接域）据 size
    /// 铸池 + SEND_FD 承接内容面。v0 单 keymap 会话域 last-wins 如实
    /// 记档——每 get_keyboard 公告覆盖前次）。
    pub keymaps: Option<KeymapRecord>,
    /// sync 即时完成数（M42-WAYCOMP18 多注册表面——本 feed 增量；
    /// 每 sync 恰一 done + delete_id 对，客户端 id 复用域对账）。
    pub syncs: usize,
    /// frame callback done+delete_id 对数（M42-DMGC22 笔㉒——本 feed
    /// 增量；每 commit 冲刷域 frame callback 恰一 done + delete_id 对，
    /// 客户端 id 复用域对账）。
    pub frame_dels: usize,
    /// xdg_toplevel.close 事件出域数（M50-XDGSHELL67——policy close
    /// 车道冲刷域增量；每入队 toplevel 恰一 close 事件出域）。
    pub closes: usize,
    /// size-configure 对出域数（M51-XDGPOP75 笔86——policy size 车道
    /// 冲刷域增量；每入队窗口恰一 configure 对〔surface.configure
    /// + toplevel.configure(w,h)〕出域）。
    pub configs: usize,
    /// xdg_popup.popup_done 事件出域数（M51-XDGPOP75 笔86——父窗收
    /// 场派生域冲刷增量）。
    pub popup_dones: usize,
    /// xdg_popup.repositioned 事件出域数（M52-POPCON78 笔90——v3
    /// 重定位车道冲刷增量；每 reposition 请求恰一 repositioned +
    /// configure 对）。
    pub repos: usize,
}

impl FeedReport {
    /// 是否零产出（无推进且无 commit——电气面 skip 快径判定域）。
    pub fn is_skip(&self) -> bool {
        self.consumed == 0 && self.commits.n == 0
    }
}

/// 合成器会话错误域（fail-visible 全谱显形——WlError 原样透传 + 语
/// 义域新增）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompError {
    /// wire 域错误（v0 解析壳同面透传）。
    Wire(WlError),
    /// 路由对象未登记 / 对象域不在册（不泄会话拓扑同面）。
    BadObject,
    /// 接口 × opcode 未收录（核心子集域外——fail-visible 拒收）。
    UnknownRequest,
    /// 会话 surface 槽满（[`SESSION_SURFACES`]）。
    SurfaceFull,
    /// bind 名不在公告名单 / 版本域越上界（策略面名单域——fail-visible）。
    UnknownGlobal,
    /// 会话 buffer 槽满（[`SESSION_BUFFERS`]——M42-ELF5）。
    BufferFull,
    /// 输入事件队列满（[`INPUT_Q_MAX`]——M42-INPUT7）。
    InputQFull,
    /// 对象表域错误（v0 表纪律透传——满容/id 冲突）。
    Table(WlError),
    /// xdg_surface configure 未 ack 即 commit（官方契约：commit 前必须
    /// ack 最近一次 configure——M50-XDGSHELL67 电气闸 fail-visible）。
    XdgUnacked,
    /// xdg serial 域失配（ack_configure / pong——官方 serial 契约：
    /// 必须回执最近一次 configure/ping 的串号）。
    XdgBadSerial,
    /// xdg 角色冲突（wl_surface 已持 xdg_surface 角色再派生 / xdg_
    /// surface 已派生 toplevel 再派生——官方角色域单占）。
    XdgRoleBusy,
    /// 服务端 close 请求队列满（[`CLOSE_Q_MAX`] 定容——policy 车道）。
    XdgCloseQFull,
    /// positioner 完整性闸失守（M51-XDGPOP75 笔86——官方契约：
    /// set_size ∧ set_anchor_rect 双宣告在位才可用于 get_popup）。
    XdgPosIncomplete,
    /// xdg 枚举值域越界（M51-XDGPOP75 笔86——anchor/gravity 值域
    /// [`crate::wayland::mod::XDG_ANCHOR_MAX`] 越界 fail-visible）。
    XdgBadEnum,
    /// 服务端 size-configure 待发队列满（[`SIZE_Q_MAX`] 定容）。
    XdgSizeQFull,
    /// 服务端 popup_done 待发队列满（[`PDONE_Q_MAX`] 定容）。
    XdgDoneQFull,
}

/// 合成器会话状态机（registry 公告面 + surface 生命周期 + commit 发
/// 布语义——零堆定容）。
pub struct CompSession {
    /// 对象表（display 固定 id 1 装载 + 客户端域登记记录）。
    table: WlObjectTable,
    /// registry 公告名单（策略面输入——new 装载后只读）。
    globals: [GlobalDef; GLOBALS_MAX],
    /// 会话 surface 槽。
    surfaces: [Option<CompSurface>; SESSION_SURFACES],
    /// surface 在账数。
    surf_n: usize,
    /// 会话 buffer 槽（M42-ELF5——create_buffer 登记域）。
    buffers: [Option<BufferRec>; SESSION_BUFFERS],
    /// buffer 在账数。
    buf_n: usize,
    /// commit 串号（帧回调 done 事件 callback_data 事实源）。
    commit_serial: u32,
    /// 冲刷批时刻毫秒域（M42-WAYCOMP19 毫秒时间源——官方 Wayland 事
    /// 件 time 域事实源：电气面每 feed 前置 set_time_ms 承接，冲刷域
    /// 批粒度口径〔同批事件同刻〕——v0 串号复用口径退役）。
    time_ms: u64,
    /// sync 即时完成累计（M42-WAYCOMP18 多注册表面——feed 报告 syncs
    /// 增量事实源；每 sync 恰一 done + delete_id 随行）。
    syncs_total: usize,
    /// frame callback done+delete_id 累计（M42-DMGC22 笔㉒——feed 报
    /// 告 frame_dels 增量事实源；commit 冲刷域每 frame callback 恰一
    /// done + delete_id 随行）。
    frame_dels_total: usize,
    /// 输入串号（M42-INPUT7——wl_keyboard/wl_pointer 事件 serial 事实
    /// 源，单调）。
    input_serial: u32,
    /// wl_seat 派生 pointer 对象 id（0 = 客户端未 get_pointer）。
    pointer_obj: u32,
    /// wl_seat 派生 keyboard 对象 id（0 = 客户端未 get_keyboard）。
    keyboard_obj: u32,
    /// 键盘焦点 surface（0 = 无焦点——策略面钩子注入域）。
    kb_focus: u32,
    /// 指针焦点 surface（0 = 无焦点）。
    ptr_focus: u32,
    /// 修饰键态（M42-WAYCOMP15 语义核——XKB 掩码域：depressed/latched/
    /// locked/group 四域快照；latched/group v0 恒零域挂账）。
    mods_depressed: u32,
    /// 修饰键 latched 掩码（v0 恒零域挂账）。
    mods_latched: u32,
    /// 修饰键 locked 掩码（Lock 键翻转域——CapsLock/NumLock）。
    mods_locked: u32,
    /// 布局组（v0 恒零域挂账）。
    mods_group: u32,
    /// 键盘事件待发队列（feed 冲刷域——定容零堆）。
    key_q: [Option<KeyRecord>; INPUT_Q_MAX],
    /// 键盘队列在队数。
    key_n: usize,
    /// 键重复 rate（chars/s——0 = 关闭；M43-KBREP37 笔㊷ 生产域，
    /// 默认 25 = weston 同量级默认）。
    rep_rate: u32,
    /// 键重复首延迟（ms——默认 400）。
    rep_delay: u32,
    /// 当前按住键（重复登记域——0 = 无；修饰键零登记）。
    rep_key: u32,
    /// 下次重复时刻（ms——now + delay / +1000/rate 步进）。
    rep_next_ms: u64,
    /// 指针事件待发队列（feed 冲刷域）。
    ptr_q: [Option<PtrRecord>; INPUT_Q_MAX],
    /// 指针队列在队数。
    ptr_n: usize,
    /// keymap 公告待提记录（M42-WAYCOMP13——dispatch_seat 公告域
    /// 登记，feed 回执提走 take）。None = 无待提。
    keymap_out: Option<KeymapRecord>,
    /// xdg 串号铸造器（M50-XDGSHELL67——configure/ping serial 事实
    /// 源，自 1 起单调；input_serial 分域正交）。
    xdg_serial: u32,
    /// 已 bind 的 xdg_wm_base 对象 id（0 = 未 bind——send_ping 车道
    /// 前置闸；bind 域登记，destroy 域清零）。
    wm_base_obj: u32,
    /// 未决 ping（wmbase id, serial）——pong 域串号对账事实源。
    ping_pending: Option<(u32, u32)>,
    /// 服务端 close 请求队列（policy 车道——request_close 入队，feed
    /// 冲刷域 xdg_toplevel.close 事件出域）。
    close_q: [Option<u32>; CLOSE_Q_MAX],
    /// close 队列在队数。
    close_n: usize,
    /// positioner 定容表（M51-XDGPOP75 笔86——create_positioner 登记
    /// 域，对象 id → [`PosDef`]；destroy 域摘除）。
    pos_tbl: [Option<(u32, PosDef)>; POSITIONER_CAP],
    /// positioner 在账数。
    pos_n: usize,
    /// 服务端 size-configure 待发队列（M51-XDGPOP75 笔86——
    /// request_configure 入队，feed 冲刷域 configure 对出域）。
    size_q: [Option<(u32, u32, i32, i32)>; SIZE_Q_MAX],
    /// size 队列在队数。
    size_n: usize,
    /// 服务端 popup_done 待发队列（M51-XDGPOP75 笔86——父窗收场
    /// request_popup_done_for_parent 入队，feed 冲刷域事件出域）。
    pdone_q: [Option<u32>; PDONE_Q_MAX],
    /// pdone 队列在队数。
    pdone_n: usize,
    /// 约束域矩形（M52-POPCON78 笔90——place_in_bounds 屏域权威域；
    /// policy 面注入，父面局部坐标口径。未注入 = 零域——裁剪域零面积
    /// 全谱显形，消费方 boot 域 set_screen_bound 承接）。
    bound: (i32, i32, i32, i32),
}

impl CompSession {
    /// 会话构造（display 固定 id 1 入表 + globals 名单装载）。globals
    /// 空名单 = 公告面空域（get_registry 零事件回执）。
    pub fn new(globals: [GlobalDef; GLOBALS_MAX]) -> Self {
        let mut table = WlObjectTable::new();
        // wl_display 固定 id 1（官方域——Display 固定分配）。
        let _ = table.install(1, WlIface::Display);
        Self {
            table,
            globals,
            surfaces: [None; SESSION_SURFACES],
            surf_n: 0,
            buffers: [None; SESSION_BUFFERS],
            buf_n: 0,
            commit_serial: 0,
            time_ms: 0,
            syncs_total: 0,
            frame_dels_total: 0,
            input_serial: 0,
            pointer_obj: 0,
            keyboard_obj: 0,
            kb_focus: 0,
            ptr_focus: 0,
            mods_depressed: 0,
            mods_latched: 0,
            mods_locked: 0,
            mods_group: 0,
            key_q: [None; INPUT_Q_MAX],
            key_n: 0,
            rep_rate: 25,
            rep_delay: 400,
            rep_key: 0,
            rep_next_ms: 0,
            ptr_q: [None; INPUT_Q_MAX],
            ptr_n: 0,
            keymap_out: None,
            xdg_serial: 0,
            wm_base_obj: 0,
            ping_pending: None,
            close_q: [None; CLOSE_Q_MAX],
            close_n: 0,
            pos_tbl: [None; POSITIONER_CAP],
            pos_n: 0,
            size_q: [None; SIZE_Q_MAX],
            size_n: 0,
            pdone_q: [None; PDONE_Q_MAX],
            pdone_n: 0,
            bound: (0, 0, 0, 0),
        }
    }

    /// 屏域约束域注入（M52-POPCON78 笔90——waycomp boot 域承接：fb
    /// 全幅为父面局部坐标屏域，popup 约束域收口事实源）。
    pub fn set_screen_bound(&mut self, bound: (i32, i32, i32, i32)) {
        self.bound = bound;
    }

    /// 屏域约束域读面（取证面——t167 对账域）。
    pub fn screen_bound(&self) -> (i32, i32, i32, i32) {
        self.bound
    }

    /// 会话 buffer 在账数（M42-ELF5 取证面）。
    pub fn buffers_count(&self) -> usize {
        self.buf_n
    }

    /// 会话内 buffer 只读快照（取证面——t106 对账消费）。
    pub fn buffer(&self, wl_id: u32) -> Option<BufferRec> {
        self.buffers
            .iter()
            .flatten()
            .find(|b| b.wl == wl_id)
            .copied()
    }

    /// 对象表只读视图（取证面——t104 对账消费）。
    pub fn table(&self) -> &WlObjectTable {
        &self.table
    }

    /// sync 即时完成累计读面（M42-WAYCOMP18 多注册表面——会话域取证）。
    pub fn syncs_snapshot(&self) -> usize {
        self.syncs_total
    }

    /// frame callback done+delete_id 累计读面（M42-DMGC22 笔㉒——会话
    /// 域取证，t123 断言面）。
    pub fn frame_dels_snapshot(&self) -> usize {
        self.frame_dels_total
    }

    /// 冲刷批时刻毫秒域承接（M42-WAYCOMP19 毫秒时间源——电气面每
    /// feed 前置调用：ostd::time::now_ms() 单调毫秒，事件 time 域事
    /// 实源；批粒度口径——同批 flush 事件同刻如实记档）。
    pub fn set_time_ms(&mut self, ms: u64) {
        self.time_ms = ms;
    }

    /// 会话 surface 在账数。
    pub fn surfaces_count(&self) -> usize {
        self.surf_n
    }

    /// commit 串号快照（帧回调对账域）。
    pub fn commit_serial(&self) -> u32 {
        self.commit_serial
    }

    /// wl_seat 派生 pointer 对象 id（0 = 客户端未 get_pointer——取证面）。
    pub fn pointer_object(&self) -> u32 {
        self.pointer_obj
    }

    /// wl_seat 派生 keyboard 对象 id（0 = 客户端未 get_keyboard——取证面）。
    pub fn keyboard_object(&self) -> u32 {
        self.keyboard_obj
    }

    /// 键盘焦点 surface 快照（0 = 无焦点——策略面对账域）。
    pub fn keyboard_focus(&self) -> u32 {
        self.kb_focus
    }

    /// 修饰键态快照（M42-WAYCOMP15——(depressed, latched, locked,
    /// group) 四元组；waycomp 取证戳消费域 + 宿主/内核测试断言面）。
    pub fn modifiers_snapshot(&self) -> (u32, u32, u32, u32) {
        (
            self.mods_depressed,
            self.mods_latched,
            self.mods_locked,
            self.mods_group,
        )
    }

    /// 指针焦点 surface 快照（0 = 无焦点）。
    pub fn pointer_focus(&self) -> u32 {
        self.ptr_focus
    }

    /// 键盘焦点注入（M42-INPUT7 策略面钩子——waycomp 首窗初始聚焦 +
    /// click-to-focus 迁移消费面）：焦点面切换 → 旧面 leave + 新面
    /// enter 入队（serial 单调）；同面幂等零事件；设备未派生/目标面
    /// 不在册 = BadObject；队列余量不足 = InputQFull（状态零扰动）。
    pub fn set_keyboard_focus(&mut self, wl_id: u32) -> Result<(), CompError> {
        if self.keyboard_obj == 0 {
            return Err(CompError::BadObject); // 设备未派生——聚焦无承载
        }
        if wl_id == self.kb_focus {
            return Ok(()); // 同面幂等快径（零事件零串号推进）
        }
        if wl_id != 0 && self.surface_slot(wl_id).is_none() {
            return Err(CompError::BadObject); // 目标面不在册
        }
        // M42-WAYCOMP15：enter 域 modifiers 快照随行（官方语义——修饰
        // 键态事件随后 enter 交付，weston 同谱）——容量前置闸 +1。
        let need =
            usize::from(self.kb_focus != 0) + usize::from(wl_id != 0) + usize::from(wl_id != 0);
        if self.key_n + need > INPUT_Q_MAX {
            return Err(CompError::InputQFull); // 容量前置闸——状态零扰动
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let old = self.kb_focus;
        self.kb_focus = wl_id;
        if old != 0 {
            self.key_q[self.key_n] = Some(KeyRecord {
                kind: KbKind::Leave,
                surface: old,
                serial,
                key: 0,
                state: 0,
                mods_d: 0,
                mods_l: 0,
                mods_lk: 0,
                group: 0,
            });
            self.key_n += 1;
        }
        if wl_id != 0 {
            self.key_q[self.key_n] = Some(KeyRecord {
                kind: KbKind::Enter,
                surface: wl_id,
                serial,
                key: 0,
                state: 0,
                mods_d: 0,
                mods_l: 0,
                mods_lk: 0,
                group: 0,
            });
            self.key_n += 1;
            // modifiers 快照随行（enter 后交付——当前修饰键态全谱）
            self.input_serial = self.input_serial.wrapping_add(1);
            let mserial = self.input_serial;
            self.key_q[self.key_n] = Some(KeyRecord {
                kind: KbKind::Modifiers,
                surface: wl_id,
                serial: mserial,
                key: 0,
                state: 0,
                mods_d: self.mods_depressed,
                mods_l: self.mods_latched,
                mods_lk: self.mods_locked,
                group: self.mods_group,
            });
            self.key_n += 1;
        }
        Ok(())
    }

    /// 击键注入（M42-INPUT7——输入链生产域）：设备未派生或焦点域空 =
    /// BadObject（官方语义：key 仅在键盘焦点在域时合法）；队列满 =
    /// InputQFull。键码 v0 口径 = scancode set 1 原值。**M42-WAYCOMP15
    /// modifiers 语义核**：键态变更承载修饰键态机——按下/释放位域更新
    /// 〔depressed 位域 ∪/∖ + Lock 键（CapsLock/NumLock）按下翻转
    /// locked〕，掩码变更即随行 modifiers 事件入队（官方语义：修饰键
    /// 态变更时发）；容量前置闸 = 1 + 变更域（状态零扰动纪律）。
    pub fn keyboard_inject(&mut self, key: u32, state: u32) -> Result<(), CompError> {
        if self.keyboard_obj == 0 || self.kb_focus == 0 {
            return Err(CompError::BadObject); // 无设备/无焦点——击键无承载
        }
        // 修饰键位域预解（wl 键码 − 8 = evdev 域映射——morse 偏移事实
        // 源同谱；非修饰键 = None 零变更域）
        let mod_bit = modifier_bit_of_wl_key(key);
        let pressed = state == super::KEY_STATE_PRESSED;
        let (new_d, new_lk) = match mod_bit {
            Some(bit) if pressed => {
                let lk = if lock_key_of_wl_key(key) {
                    self.mods_locked ^ bit // Lock 键按下翻转 locked
                } else {
                    self.mods_locked
                };
                (self.mods_depressed | bit, lk)
            }
            Some(bit) => (self.mods_depressed & !bit, self.mods_locked),
            None => (self.mods_depressed, self.mods_locked),
        };
        let mods_changed = new_d != self.mods_depressed || new_lk != self.mods_locked;
        let need = 1 + usize::from(mods_changed);
        if self.key_n + need > INPUT_Q_MAX {
            return Err(CompError::InputQFull); // 容量前置闸——状态零扰动
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.kb_focus;
        self.key_q[self.key_n] = Some(KeyRecord {
            kind: KbKind::Key,
            surface: focus,
            serial,
            key,
            state,
            mods_d: 0,
            mods_l: 0,
            mods_lk: 0,
            group: 0,
        });
        self.key_n += 1;
        // 键重复登记域（M43-KBREP37 笔㊷——按下非修饰键登记 + 释放撤
        // 销；修饰键零登记零撤销——官方语义修饰键不产重复文本）。
        if mod_bit.is_none() {
            if pressed {
                self.rep_key = key;
                self.rep_next_ms = self.time_ms + u64::from(self.rep_delay);
            } else if self.rep_key == key {
                self.rep_key = 0;
            }
        }
        self.mods_depressed = new_d;
        self.mods_locked = new_lk;
        if mods_changed {
            self.input_serial = self.input_serial.wrapping_add(1);
            let mserial = self.input_serial;
            self.key_q[self.key_n] = Some(KeyRecord {
                kind: KbKind::Modifiers,
                surface: focus,
                serial: mserial,
                key: 0,
                state: 0,
                mods_d: self.mods_depressed,
                mods_l: self.mods_latched,
                mods_lk: self.mods_locked,
                group: self.mods_group,
            });
            self.key_n += 1;
        }
        Ok(())
    }

    /// 键重复参数设定（M43-KBREP37 笔㊷——waycomp 侧会话配置域：
    /// repeat_info 公告真值承载 + 生产域参数。rate = chars/s（0 =
    /// 关闭合法——官方语义 no-repeat），delay = 首重复前 ms。域外
    /// clamp：rate 0..=100、delay 0..=2000——v0 clamp 域如实登记。
    pub fn set_repeat_info(&mut self, rate: u32, delay: u32) {
        self.rep_rate = rate.min(100);
        self.rep_delay = delay.min(2000);
    }

    /// 键重复参数读面（公告域 + 取证面）。
    pub fn repeat_info(&self) -> (u32, u32) {
        (self.rep_rate, self.rep_delay)
    }

    /// 重复域待产读面（阻塞面豁免判据——rep_key 非零且 rate > 0 =
    /// 非静：重复窗内消费域轮询推进，阻塞面零登记挂账）。
    pub fn repeat_pending(&self) -> bool {
        self.rep_key != 0 && self.rep_rate > 0
    }

    /// 键重复生产泵（M43-KBREP37 笔㊷——drain 尾消费域推进）：按住
    /// 键（rep_key 登记）且 rate > 0 时，now ≥ rep_next_ms 产重复
    /// key 事件（state = PRESSED 重复按下——官方 wl_keyboard.key 语
    /// 义）入待发队列 + rep_next_ms 步进 1000/rate（钳 ≥1——多拍
    /// 追产上限 8 防风暴）。焦点丢失域撤销 / 容量满容 skip 本拍（追
    /// 产窗保持——feed 冲刷后继续）。返回本拍产数。
    pub fn repeat_tick(&mut self, now_ms: u64) -> usize {
        let mut produced = 0usize;
        while self.rep_key != 0 && self.rep_rate > 0 && now_ms >= self.rep_next_ms && produced < 8 {
            if self.kb_focus == 0 {
                self.rep_key = 0; // 焦点丢失——重复域撤销
                break;
            }
            if self.key_n >= INPUT_Q_MAX {
                break; // 满容 skip 本拍（追产窗保持）
            }
            self.input_serial = self.input_serial.wrapping_add(1);
            let serial = self.input_serial;
            let focus = self.kb_focus;
            let key = self.rep_key;
            self.key_q[self.key_n] = Some(KeyRecord {
                kind: KbKind::Key,
                surface: focus,
                serial,
                key,
                state: super::KEY_STATE_PRESSED,
                mods_d: 0,
                mods_l: 0,
                mods_lk: 0,
                group: 0,
            });
            self.key_n += 1;
            produced += 1;
            self.rep_next_ms = self
                .rep_next_ms
                .saturating_add((1000 / self.rep_rate).max(1) as u64);
        }
        produced
    }

    /// 指针焦点注入（M42-INPUT7 策略面钩子——hit-test 消费域）：
    /// wl_id != 0 = 入域（leave 旧面 + enter 新面）；wl_id == 0 = 离域；
    /// 同面幂等零事件。
    pub fn set_pointer_focus(&mut self, wl_id: u32, x: i32, y: i32) -> Result<(), CompError> {
        if self.pointer_obj == 0 {
            return Err(CompError::BadObject); // 设备未派生
        }
        if wl_id == self.ptr_focus {
            return Ok(()); // 同面幂等快径
        }
        if wl_id != 0 && self.surface_slot(wl_id).is_none() {
            return Err(CompError::BadObject); // 目标面不在册
        }
        let need = usize::from(self.ptr_focus != 0) + usize::from(wl_id != 0);
        if self.ptr_n + need > INPUT_Q_MAX {
            return Err(CompError::InputQFull); // 容量前置闸——状态零扰动
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let old = self.ptr_focus;
        self.ptr_focus = wl_id;
        if old != 0 {
            self.ptr_q[self.ptr_n] = Some(PtrRecord {
                kind: PtrKind::Leave,
                surface: old,
                serial,
                x: 0,
                y: 0,
                button: 0,
                state: 0,
                axis: 0,
                value: 0,
                source: 0,
            });
            self.ptr_n += 1;
        }
        if wl_id != 0 {
            self.ptr_q[self.ptr_n] = Some(PtrRecord {
                kind: PtrKind::Enter,
                surface: wl_id,
                serial,
                x,
                y,
                button: 0,
                state: 0,
                axis: 0,
                value: 0,
                source: 0,
            });
            self.ptr_n += 1;
        }
        Ok(())
    }

    /// 指针移动注入（M42-INPUT7）：无焦点域移动零事件（官方语义——
    /// 静默丢弃，Ok 返回）；队列满 = InputQFull。
    pub fn pointer_motion(&mut self, x: i32, y: i32) -> Result<(), CompError> {
        if self.pointer_obj == 0 || self.ptr_focus == 0 {
            return Ok(()); // 无焦点域移动零事件（官方语义——静默丢弃）
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.ptr_focus;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::Motion,
            surface: focus,
            serial,
            x,
            y,
            button: 0,
            state: 0,
            axis: 0,
            value: 0,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 指针按键注入（M42-INPUT7）：无焦点域按键无承载 = BadObject；
    /// 队列满 = InputQFull。click-to-focus 迁移 = 电气面裁决。
    pub fn pointer_button(&mut self, button: u32, state: u32) -> Result<(), CompError> {
        if self.pointer_obj == 0 || self.ptr_focus == 0 {
            return Err(CompError::BadObject); // 无焦点——按键无承载
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.ptr_focus;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::Button,
            surface: focus,
            serial,
            x: 0,
            y: 0,
            button,
            state,
            axis: 0,
            value: 0,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 轴滚动注入（M42-WAYCOMP14 axis 族——value fixed 24.8 原字，可
    /// 负〔反向滚动〕）：无焦点域零事件（官方语义——静默丢弃，Ok 返
    /// 回，motion 同谱）；队列满 = InputQFull。axis 值域越界 = BadObject
    /// （官方 enum axis 声明序 0..=1，fail-visible）。
    pub fn pointer_axis(&mut self, axis: u32, value: i32) -> Result<(), CompError> {
        if axis > AXIS_AXIS_MAX {
            return Err(CompError::BadObject); // 轴域越界（enum axis 声明序）
        }
        if self.pointer_obj == 0 || self.ptr_focus == 0 {
            return Ok(()); // 无焦点域滚动零事件（官方语义——静默丢弃）
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.ptr_focus;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::Axis,
            surface: focus,
            serial,
            x: 0,
            y: 0,
            button: 0,
            state: 0,
            axis,
            value,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 分组终结注入（M42-WAYCOMP14——官方语义：axis/axis_source/
    /// axis_stop 批由 frame 定界出域；注入面显式 frame 注入 = 组装
    /// 面交由电气面〔waycomp 排空域每扫掠一 frame〕，本 API 直通域
    /// 面向单事件粒度消费方）。设备未派生 = BadObject。
    pub fn pointer_frame(&mut self) -> Result<(), CompError> {
        if self.pointer_obj == 0 {
            return Err(CompError::BadObject); // 设备未派生——frame 无承载
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::Frame,
            surface: self.ptr_focus,
            serial,
            x: 0,
            y: 0,
            button: 0,
            state: 0,
            axis: 0,
            value: 0,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 轴源声明注入（M42-WAYCOMP14——frame 域前置声明，官方 enum
    /// axis_source 值域 0..=3 越界 = BadObject fail-visible）。
    pub fn pointer_axis_source(&mut self, axis_source: u32) -> Result<(), CompError> {
        if axis_source > AXIS_SOURCE_MAX {
            return Err(CompError::BadObject); // 轴源域越界
        }
        if self.pointer_obj == 0 {
            return Err(CompError::BadObject); // 设备未派生
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::AxisSource,
            surface: self.ptr_focus,
            serial,
            x: 0,
            y: 0,
            button: 0,
            state: 0,
            axis: 0,
            value: 0,
            source: axis_source,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 滚动手势终结注入（M42-WAYCOMP14——axis_stop(time, axis) 官方
    /// 语义：手势终结后该轴不再有 axis 事件直至新手势）。
    pub fn pointer_axis_stop(&mut self, axis: u32) -> Result<(), CompError> {
        if axis > AXIS_AXIS_MAX {
            return Err(CompError::BadObject); // 轴域越界
        }
        if self.pointer_obj == 0 || self.ptr_focus == 0 {
            return Ok(()); // 无焦点域手势终结零事件（官方语义——静默丢弃）
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.ptr_focus;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::AxisStop,
            surface: focus,
            serial,
            x: 0,
            y: 0,
            button: 0,
            state: 0,
            axis,
            value: 0,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 离散步进语义注入（M43-AV12036——axis_value120(axis, value120)
    /// 官方语义：wheel 源 frame 域随 axis 事件随行声明，value120 =
    /// 步进累计 × 120 原字〔int 非 fixed〕，负值反向）。轴域闸同
    /// [`pointer_axis`]（官方 enum axis 0..=1，fail-visible）；无焦点
    /// 域零事件（官方语义——静默丢弃，Ok 返回）；队满 = InputQFull。
    pub fn pointer_axis_value120(&mut self, axis: u32, value120: i32) -> Result<(), CompError> {
        if axis > AXIS_AXIS_MAX {
            return Err(CompError::BadObject); // 轴域越界（enum axis 声明序）
        }
        if self.pointer_obj == 0 || self.ptr_focus == 0 {
            return Ok(()); // 无焦点域步进零事件（官方语义——静默丢弃）
        }
        if self.ptr_n >= INPUT_Q_MAX {
            return Err(CompError::InputQFull);
        }
        self.input_serial = self.input_serial.wrapping_add(1);
        let serial = self.input_serial;
        let focus = self.ptr_focus;
        self.ptr_q[self.ptr_n] = Some(PtrRecord {
            kind: PtrKind::AxisValue120,
            surface: focus,
            serial,
            x: 0,
            y: 0,
            button: 0,
            state: 0,
            axis,
            value: value120,
            source: 0,
        });
        self.ptr_n += 1;
        Ok(())
    }

    /// 公告名单只读视图。
    pub fn globals(&self) -> &[GlobalDef; GLOBALS_MAX] {
        &self.globals
    }

    /// 策略面钩子：窗口几何注入（cascade::tiling_plan 产出域——屏域
    /// Rect）。未登记 surface → [`CompError::BadObject`]。
    pub fn set_geometry(&mut self, wl_id: u32, geom: Rect) -> Result<(), CompError> {
        let slot = self
            .surfaces
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|sf| sf.wl_id == wl_id))
            .ok_or(CompError::BadObject)?;
        if let Some(sf) = slot.as_mut() {
            sf.geom = geom;
        }
        Ok(())
    }

    /// 会话内 surface 只读快照（取证面）。
    pub fn surface(&self, wl_id: u32) -> Option<CompSurface> {
        self.surfaces
            .iter()
            .flatten()
            .find(|sf| sf.wl_id == wl_id)
            .copied()
    }

    /// 会话在册 surface id 清单（槽序 = 创建序——策略面入窗消费域；
    /// 产物 =（id 槽, 有效数），None 槽跳过）。零堆定容返回。
    pub fn surface_ids(&self) -> ([Option<u32>; SESSION_SURFACES], usize) {
        let mut ids = [None; SESSION_SURFACES];
        let mut n = 0usize;
        for s in self.surfaces.iter().flatten() {
            ids[n] = Some(s.wl_id);
            n += 1;
        }
        (ids, n)
    }

    /// global 名单查找（bind 校验域——接口名对账）。
    fn global_by_iface_name(&self, iface: &[u8]) -> Option<GlobalDef> {
        self.globals
            .iter()
            .copied()
            .find(|g| iface_name(g.iface).as_bytes() == iface)
    }

    /// 客户端流入口：推进式解析 + 事件回执（官方事件序列化域）。
    ///
    /// 流语义：`stream` 内**完整消息前缀**逐条派发（部分消息留缓冲
    /// ——`consumed` 承载推进步长，残段由消费方前移）；`out` 承载事
    /// 件回执（globals 公告 / sync done / frame done），`out_len` 承
    /// 载产出字节数。畸形头（尺寸域越界）即时 fail-visible（Err 透
    /// 传）；部分消息（尺寸域完整但残段不足）干净断流。
    pub fn feed(&mut self, stream: &[u8], out: &mut [u8]) -> Result<FeedReport, CompError> {
        let syncs0 = self.syncs_total; // sync 增量基（M42-WAYCOMP18）
        let fdels0 = self.frame_dels_total; // frame dels 增量基（M42-DMGC22）
        let mut log = CommitLog::EMPTY;
        let mut pools = PoolLog::EMPTY;
        let mut drops = DropLog::EMPTY;
        let mut keys = KeyLog::EMPTY;
        let mut ptrs = PtrLog::EMPTY;
        let mut fd_need = 0usize;
        let mut out_len = 0usize;
        let mut consumed = 0usize;
        let mut closes = 0usize;
        let mut configs = 0usize;
        let mut popup_dones = 0usize;
        let mut repos = 0usize;
        // xdg close 车道冲刷（M50-XDGSHELL67——policy close 请求异步于
        // 请求流：空流 feed 亦承载冲刷，输入冲刷同谱纪律）。
        self.flush_xdg(
            out,
            &mut out_len,
            &mut closes,
            &mut configs,
            &mut popup_dones,
        )?;
        self.flush_inputs(out, &mut out_len, &mut keys, &mut ptrs)?;
        while consumed + HEADER <= stream.len() {
            // 尺寸前窥：完整消息域判定（部分消息干净断流——非错误域；
            // 畸形尺寸域由派发层 BadLength fail-visible 显形）
            let size = u16::from_le_bytes([stream[consumed + 6], stream[consumed + 7]]) as usize;
            if (HEADER..=WIRE_MAX).contains(&size) && consumed + size > stream.len() {
                break; // 部分消息——留缓冲（流推进干净域）
            }
            let step = self.dispatch(
                &stream[consumed..],
                &mut out_len,
                out,
                &mut log,
                &mut pools,
                &mut drops,
                &mut fd_need,
                &mut repos,
            )?;
            consumed += step;
        }
        // 派生回执二次冲刷（M43-KBREP37 笔㊷——同批请求回执同批出域：
        // set_cursor 回执在 dispatch 域入待发队列，flush 先行段已过——
        // 尾部二次冲刷承接，空队列零操作幂等）。
        self.flush_xdg(
            out,
            &mut out_len,
            &mut closes,
            &mut configs,
            &mut popup_dones,
        )?;
        self.flush_inputs(out, &mut out_len, &mut keys, &mut ptrs)?;
        Ok(FeedReport {
            consumed,
            out_len,
            commits: log,
            pools,
            drops,
            fd_need,
            keys,
            ptrs,
            keymaps: self.keymap_out.take(),
            syncs: self.syncs_total - syncs0,
            frame_dels: self.frame_dels_total - fdels0,
            closes,
            configs,
            popup_dones,
            repos,
        })
    }

    /// 输入事件待发队列冲刷（M42-INPUT7——队列非空即编组出域：键盘批
    /// 先随、指针批后随〔双队列分域冲刷——严格全局序挂账〕；设备对象
    /// 缺席 = 仅记账不编组，防御域）；冲刷后队列清零。事件记录同步入
    /// 回执批（KeyLog/PtrLog——电气面对账域）。
    fn flush_inputs(
        &mut self,
        out: &mut [u8],
        out_len: &mut usize,
        keys: &mut KeyLog,
        ptrs: &mut PtrLog,
    ) -> Result<(), CompError> {
        for i in 0..self.key_n {
            if let Some(r) = self.key_q[i] {
                if self.keyboard_obj != 0 {
                    let n = match r.kind {
                        KbKind::Enter => encode_keyboard_enter_event(
                            &mut out[*out_len..],
                            self.keyboard_obj,
                            r.serial,
                            r.surface,
                            &[],
                        ),
                        KbKind::Leave => encode_keyboard_leave_event(
                            &mut out[*out_len..],
                            self.keyboard_obj,
                            r.serial,
                            r.surface,
                        ),
                        KbKind::Key => encode_keyboard_key_event(
                            &mut out[*out_len..],
                            self.keyboard_obj,
                            r.serial,
                            self.time_ms as u32, // time 域 = 冲刷批时刻 ms（官方 32 位回绕口径——M42-WAYCOMP19）
                            r.key,
                            r.state,
                        ),
                        KbKind::Modifiers => encode_keyboard_modifiers_event(
                            &mut out[*out_len..],
                            self.keyboard_obj,
                            r.serial,
                            r.mods_d,
                            r.mods_l,
                            r.mods_lk,
                            r.group,
                        ),
                        // M43-KBREP37 笔㊷：set_cursor 回执 = 记录批域
                        // （回执取证——零 wire 出域，电气面对账消费）。
                        KbKind::SetCursor => Ok(0),
                    }
                    .map_err(CompError::Wire)?;
                    *out_len += n;
                }
                keys.push(r);
            }
        }
        self.key_n = 0;
        for i in 0..self.ptr_n {
            if let Some(r) = self.ptr_q[i] {
                if self.pointer_obj != 0 {
                    let n = match r.kind {
                        PtrKind::Enter => encode_pointer_enter_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            r.serial,
                            r.surface,
                            r.x,
                            r.y,
                        ),
                        PtrKind::Leave => encode_pointer_leave_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            r.serial,
                            r.surface,
                        ),
                        PtrKind::Motion => encode_pointer_motion_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            self.time_ms as u32, // time 域 = 冲刷批时刻 ms（官方 32 位回绕——M42-WAYCOMP19）
                            r.x,
                            r.y,
                        ),
                        PtrKind::Button => encode_pointer_button_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            r.serial,
                            self.time_ms as u32, // time 域 = 冲刷批时刻 ms（官方 32 位回绕——M42-WAYCOMP19）
                            r.button,
                            r.state,
                        ),
                        PtrKind::Axis => encode_pointer_axis_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            self.time_ms as u32, // time 域 = 冲刷批时刻 ms（官方 32 位回绕——M42-WAYCOMP19）
                            r.axis,
                            r.value,
                        ),
                        PtrKind::Frame => {
                            encode_pointer_frame_event(&mut out[*out_len..], self.pointer_obj)
                        }
                        PtrKind::AxisSource => encode_pointer_axis_source_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            r.source,
                        ),
                        PtrKind::AxisStop => encode_pointer_axis_stop_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            self.time_ms as u32, // time 域 = 冲刷批时刻 ms（官方 32 位回绕——M42-WAYCOMP19）
                            r.axis,
                        ),
                        PtrKind::AxisValue120 => encode_pointer_axis_value120_event(
                            &mut out[*out_len..],
                            self.pointer_obj,
                            r.axis,
                            r.value, // value120 = 步进 × 120 原字（int 非 fixed——M43-AV12036）
                        ),
                    }
                    .map_err(CompError::Wire)?;
                    *out_len += n;
                }
                ptrs.push(r);
            }
        }
        self.ptr_n = 0;
        Ok(())
    }

    /// 单消息派发（头 + 签名驱动解析 + 对象路由 + 事件回执写入 +
    /// commit/池记录批）。返回消息 wire 尺寸（流步长）。
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
        msg: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
        pools: &mut PoolLog,
        drops: &mut DropLog,
        fd_need: &mut usize,
        repos: &mut usize,
    ) -> Result<usize, CompError> {
        let header = parse_header(msg).map_err(CompError::Wire)?;
        let body = &msg[HEADER..header.size as usize];
        let Some(iface) = self.table.lookup(header.object_id) else {
            return Err(CompError::BadObject);
        };
        match iface {
            WlIface::Display => self.dispatch_display(&header, body, out_len, out)?,
            WlIface::Registry => self.dispatch_registry(&header, body, out_len, out)?,
            WlIface::Compositor => self.dispatch_compositor(&header, body)?,
            WlIface::Surface => self.dispatch_surface(&header, body, out_len, out, log, drops)?,
            WlIface::Shm => self.dispatch_shm(&header, body, pools, fd_need)?,
            WlIface::ShmPool => self.dispatch_shm_pool(&header, body)?,
            WlIface::Seat => self.dispatch_seat(&header, body, out_len, out)?,
            // xdg_shell 窗口管理协议域（M50-XDGSHELL67 笔77 电气闭环——
            // wm_base 派生面 / surface 角色域 / toplevel 标题域三臂在环；
            // M51-XDGPOP75 笔86——positioner/popup 双臂入环）
            WlIface::XdgWmBase => self.dispatch_xdg_wm_base(&header, body, out_len, out)?,
            WlIface::XdgSurface => self.dispatch_xdg_surface(&header, body, out_len, out)?,
            WlIface::XdgToplevel => self.dispatch_xdg_toplevel(&header, body)?,
            WlIface::XdgPositioner => self.dispatch_xdg_positioner(&header, body)?,
            WlIface::XdgPopup => self.dispatch_xdg_popup(&header, body, out, out_len, repos)?,
            // keyboard：set_cursor 官方请求域在环（M43-KBREP37 笔㊷）
            // ——release 挂账维持（对象摘除域随会话收场承载）。
            WlIface::Keyboard => self.dispatch_keyboard(&header, body, out_len, out)?,
            // pointer：客户端只消费事件——请求域外（v0 子集）。
            WlIface::Pointer => return Err(CompError::UnknownRequest),
            // callback/output/region/buffer：服务端
            // 请求域外（v0 子集——fail-visible）。
            _ => return Err(CompError::UnknownRequest),
        }
        Ok(header.size as usize)
    }

    /// wl_keyboard 请求域（M43-KBREP37 笔㊷——set_cursor 官方请求域
    /// 落域：客户端键盘焦点光标面宣告，回执记录批 KeyRecord 复用域
    /// 〔kind = SetCursor、surface = 目标面、key = hotspot_x、state =
    /// hotspot_y——记录域双载判读〕；surface = 0 合法 = 默认光标回退
    /// 域。release 挂账维持——v0 对象摘除域随会话收场承载）。
    fn dispatch_keyboard(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        _out_len: &mut usize,
        _out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            keyboard_req::REQ_SET_CURSOR => {
                let (args, _) =
                    parse_args(body, SIG_KEYBOARD_SET_CURSOR).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(_serial)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let surface = match args[1] {
                    Some(WlArg::Object(id)) => id,
                    _ => return Err(CompError::Wire(WlError::BadLength)),
                };
                let hot_x = match args[2] {
                    Some(WlArg::Int(v)) => v,
                    _ => return Err(CompError::Wire(WlError::BadLength)),
                };
                let hot_y = match args[3] {
                    Some(WlArg::Int(v)) => v,
                    _ => return Err(CompError::Wire(WlError::BadLength)),
                };
                // 目标面在册闸（surface = 0 默认光标回退合法域；非零
                // 不在册 = BadObject fail-visible）。
                if surface != 0 && self.surface_slot(surface).is_none() {
                    return Err(CompError::BadObject);
                }
                if self.key_n >= INPUT_Q_MAX {
                    return Err(CompError::InputQFull);
                }
                self.input_serial = self.input_serial.wrapping_add(1);
                let serial = self.input_serial;
                self.key_q[self.key_n] = Some(KeyRecord {
                    kind: KbKind::SetCursor,
                    surface,
                    serial,
                    key: hot_x as u32,
                    state: hot_y as u32,
                    mods_d: 0,
                    mods_l: 0,
                    mods_lk: 0,
                    group: 0,
                });
                self.key_n += 1;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest), // release 挂账维持
        }
    }

    /// wl_display 请求域（sync 即时 done + **delete_id 随行销毁**
    /// 〔M42-WAYCOMP18 多注册表面——官方生命周期：callback done 后服
    /// 务端销毁对象 + delete_id 宣告随行，客户端据以回收 id 复用域；
    /// 对象表同步摘除——v0 永驻表膨胀域退役〕/ get_registry 公告面）。
    fn dispatch_display(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            display::REQ_SYNC => {
                let (args, _) = parse_args(body, SIG_DISPLAY_SYNC).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(cb_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(cb_id, WlIface::Callback)
                    .map_err(CompError::Table)?;
                // 官方语义：sync callback 即时完成（callback_data 无官
                // 方约束域——v0 记 0）。**M42-WAYCOMP18 多注册表面**：
                // done 后服务端销毁 callback + delete_id 随行（客户端 id
                // 复用域事实源——同 id 多轮 sync 在环面），对象表同步摘
                // 除（v0 永驻表膨胀域退役——表容量回收域）。
                let n = encode_callback_done_event(&mut out[*out_len..], cb_id, 0)
                    .map_err(CompError::Wire)?;
                *out_len += n;
                self.syncs_total += 1;
                self.table.remove(cb_id);
                let n =
                    encode_display_delete_id_event(&mut out[*out_len..], header.object_id, cb_id)
                        .map_err(CompError::Wire)?;
                *out_len += n;
                Ok(())
            }
            display::REQ_GET_REGISTRY => {
                let (args, _) =
                    parse_args(body, SIG_DISPLAY_GET_REGISTRY).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(reg_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(reg_id, WlIface::Registry)
                    .map_err(CompError::Table)?;
                for g in &self.globals {
                    let n = encode_registry_global_event(
                        &mut out[*out_len..],
                        reg_id,
                        g.name,
                        g.iface,
                        g.version,
                    )
                    .map_err(CompError::Wire)?;
                    *out_len += n;
                }
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_registry 请求域（bind——接口名名单校验 + 版本上界 + 对象登
    /// 记 + **seat 设备能力公告**〔M42-INPUT7——bind wl_seat 后
    /// capabilities 事件随行，官方语义〕）。
    fn dispatch_registry(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            registry::REQ_BIND => {
                let (args, _) = parse_args(body, SIG_REGISTRY_BIND).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(_name)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Str(iface)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadString));
                };
                let Some(WlArg::Uint(ver)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::NewId(new_id)) = args[3] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let g = self
                    .global_by_iface_name(iface)
                    .ok_or(CompError::UnknownGlobal)?;
                // bind 版本域上界校验（公告版本为上界——越界 = 客户端
                // 违约，fail-visible；0 = 非法版本域）。
                if ver == 0 || ver > g.version {
                    return Err(CompError::UnknownGlobal);
                }
                self.table
                    .install(new_id, g.iface)
                    .map_err(CompError::Table)?;
                // seat 设备能力公告（M42-INPUT7 输入链——pointer|
                // keyboard 位域；官方语义：bind wl_seat 后随行）。
                if g.iface == WlIface::Seat {
                    let n = encode_seat_capabilities_event(
                        &mut out[*out_len..],
                        new_id,
                        SEAT_CAPS_POINTER | SEAT_CAPS_KEYBOARD,
                    )
                    .map_err(CompError::Wire)?;
                    *out_len += n;
                }
                // xdg_wm_base bind 登记（M50-XDGSHELL67——send_ping 车道
                // 前置闸事实源；v0 单 wm_base 会话域 last-wins 记档）。
                if g.iface == WlIface::XdgWmBase {
                    self.wm_base_obj = new_id;
                }
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_seat 请求域（M42-INPUT7 输入链——get_pointer/get_keyboard
    /// 设备派生：对象装表 + 键盘 keymap 公告〔fd 占位字域，内容面挂
    /// 账〕；get_touch/release 域外 fail-visible）。
    fn dispatch_seat(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            seat::REQ_GET_POINTER => {
                let (args, _) = parse_args(body, SIG_SEAT_GET_POINTER).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(ptr_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(ptr_id, WlIface::Pointer)
                    .map_err(CompError::Table)?;
                self.pointer_obj = ptr_id;
                Ok(())
            }
            seat::REQ_GET_KEYBOARD => {
                let (args, _) = parse_args(body, SIG_SEAT_GET_KEYBOARD).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(kbd_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(kbd_id, WlIface::Keyboard)
                    .map_err(CompError::Table)?;
                self.keyboard_obj = kbd_id;
                // keymap 公告（官方语义：keyboard 派生即发——fd 占位字
                // 0 + xkb v1 格式 + **真实内容长度**〔M42-WAYCOMP13 内
                // 容面——零尺寸域退役：size = KEYMAP_XKB_V1 字节域，
                // 电气面据回执铸池 + SEND_FD 承接〕）。
                let n = encode_keyboard_keymap_event(
                    &mut out[*out_len..],
                    kbd_id,
                    0,
                    KEYMAP_FORMAT_XKB_V1,
                    KEYMAP_XKB_V1.len() as u32,
                )
                .map_err(CompError::Wire)?;
                *out_len += n;
                self.keymap_out = Some(KeymapRecord {
                    keyboard_id: kbd_id,
                    size: KEYMAP_XKB_V1.len() as u32,
                });
                // repeat_info 公告（M42-KBREP34 笔㉞——官方语义：键盘派生
                // 域 keymap 后随行；M43-KBREP37 笔㊷ 真值域——v0 关闭声
                // 明 0/0 退役，会话域默认 25/400 + set_repeat_info 配置
                // 域承载，生产域在环）。
                let (rep_rate, rep_delay) = self.repeat_info();
                let n = encode_keyboard_repeat_info_event(
                    &mut out[*out_len..],
                    kbd_id,
                    rep_rate,
                    rep_delay,
                )
                .map_err(CompError::Wire)?;
                *out_len += n;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg_wm_base 请求域（M50-XDGSHELL67 笔77 电气闭环）：
    /// destroy / get_xdg_surface（窗口角色派生——surface 在册闸 + 角
    /// 色单占闸）/ pong（ping 串号对账——官方 liveness 契约）。
    fn dispatch_xdg_wm_base(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        _out_len: &mut usize,
        _out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            xdg_wm_base::REQ_DESTROY => {
                let _ = parse_args(body, &[]).map_err(CompError::Wire)?;
                if self.table.lookup(header.object_id) != Some(WlIface::XdgWmBase) {
                    return Err(CompError::BadObject);
                }
                self.table.remove(header.object_id);
                if self.wm_base_obj == header.object_id {
                    self.wm_base_obj = 0;
                }
                Ok(())
            }
            xdg_wm_base::REQ_GET_XDG_SURFACE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_WM_BASE_GET_XDG_SURFACE).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(xdg_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Object(surf_id)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // surface 在册闸 + 角色单占闸（官方角色域——单 wl_surface
                // 至多一 xdg_surface；两闸全 fail-visible）。
                let Some(sf) = self.surface_slot_mut(surf_id) else {
                    return Err(CompError::BadObject);
                };
                if sf.xdg_surf != 0 {
                    return Err(CompError::XdgRoleBusy);
                }
                sf.xdg_surf = xdg_id;
                self.table
                    .install(xdg_id, WlIface::XdgSurface)
                    .map_err(CompError::Table)?;
                Ok(())
            }
            xdg_wm_base::REQ_CREATE_POSITIONER => {
                let (args, _) =
                    parse_args(body, SIG_XDG_WM_BASE_CREATE_POSITIONER).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(pos_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // wm_base 在册闸（bind 域登记对象——create 车道前置闸）。
                if self.table.lookup(header.object_id) != Some(WlIface::XdgWmBase) {
                    return Err(CompError::BadObject);
                }
                // 定容表满容闸（[`POSITIONER_CAP`]——fail-visible）。
                if self.pos_n >= POSITIONER_CAP {
                    return Err(CompError::BufferFull);
                }
                self.table
                    .install(pos_id, WlIface::XdgPositioner)
                    .map_err(CompError::Table)?;
                let Some(slot) = self.pos_tbl.iter_mut().find(|s| s.is_none()) else {
                    return Err(CompError::BufferFull);
                };
                *slot = Some((
                    pos_id,
                    PosDef {
                        size: (0, 0),
                        anchor_rect: (0, 0, 0, 0),
                        anchor: XDG_ANCHOR_NONE,
                        gravity: XDG_ANCHOR_NONE,
                        cadj: 0,
                        offset: (0, 0),
                        reactive: false,
                        parent_size: (0, 0),
                        parent_config: 0,
                    },
                ));
                self.pos_n += 1;
                Ok(())
            }
            xdg_wm_base::REQ_PONG => {
                let (args, _) = parse_args(body, SIG_XDG_WM_BASE_PONG).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(serial)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // 官方 liveness 契约：pong 必须回执最近一次 ping 的串号
                // （v0 严格串号纪律——未决 ping 缺席/串号失配皆拒）。
                match self.ping_pending {
                    Some((_, s)) if s == serial => {
                        self.ping_pending = None;
                        Ok(())
                    }
                    _ => Err(CompError::XdgBadSerial),
                }
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg_surface 请求域（M50-XDGSHELL67 笔77）：destroy（角色摘除）/
    /// get_toplevel（toplevel 派生 + **初始 configure 对出域**——xdg_
    /// surface.configure(serial) + xdg_toplevel.configure(0,0,[])，零
    /// 值几何 = 服务端策略自主，tiling 面承接）/ ack_configure（最近
    /// 串号对账——commit 前置闸）/ set_window_geometry（解析面记账
    /// 域外挂账）；get_popup 域外 fail-visible。
    fn dispatch_xdg_surface(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            xdg_surface::REQ_DESTROY => {
                let _ = parse_args(body, &[]).map_err(CompError::Wire)?;
                if let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_surf == header.object_id)
                {
                    sf.xdg_surf = 0;
                    sf.xdg_toplevel = 0;
                    sf.config_serial = 0;
                    sf.acked = false;
                    sf.xdg_popup = 0;
                    sf.popup_x = 0;
                    sf.popup_y = 0;
                    sf.popup_grabbed = false;
                    sf.popup_parent_wl = 0;
                }
                self.table.remove(header.object_id);
                Ok(())
            }
            xdg_surface::REQ_GET_TOPLEVEL => {
                let (args, _) =
                    parse_args(body, SIG_XDG_SURFACE_GET_TOPLEVEL).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(top_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_surf == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                if sf.xdg_toplevel != 0 {
                    return Err(CompError::XdgRoleBusy);
                }
                sf.xdg_toplevel = top_id;
                self.table
                    .install(top_id, WlIface::XdgToplevel)
                    .map_err(CompError::Table)?;
                // 初始 configure 对出域（官方语义：get_toplevel 后服务端
                // 必发初始 configure——串号铸造 + 未 ack 位铸造，commit
                // 闸事实源；v0 单挂起 configure 口径）。
                self.xdg_serial = self.xdg_serial.wrapping_add(1);
                let ser = self.xdg_serial;
                sf.config_serial = ser;
                sf.acked = false;
                let n =
                    encode_xdg_surface_configure_event(&mut out[*out_len..], header.object_id, ser)
                        .map_err(CompError::Wire)?;
                *out_len += n;
                let n =
                    encode_xdg_toplevel_configure_event(&mut out[*out_len..], top_id, 0, 0, &[])
                        .map_err(CompError::Wire)?;
                *out_len += n;
                Ok(())
            }
            xdg_surface::REQ_ACK_CONFIGURE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_SURFACE_ACK_CONFIGURE).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(serial)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_surf == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                // 官方串号契约：ack 必须针对最近一次 configure（v0 单挂
                // 起 configure——串号相等即最近；失配 = XdgBadSerial）。
                if sf.config_serial != serial {
                    return Err(CompError::XdgBadSerial);
                }
                sf.acked = true;
                Ok(())
            }
            xdg_surface::REQ_GET_POPUP => {
                let (args, _) =
                    parse_args(body, SIG_XDG_SURFACE_GET_POPUP).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(pop_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Object(parent_id)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Object(pos_id)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // positioner 在册闸 + 完整性闸（官方契约：set_size ∧
                // set_anchor_rect 双宣告在位——缺位 XdgPosIncomplete）。
                let Some(pos) = self.pos_get(pos_id) else {
                    return Err(CompError::BadObject);
                };
                if !pos.complete() {
                    return Err(CompError::XdgPosIncomplete);
                }
                // parent 闸（M52-POPCON78 笔90 G-4 嵌套父域：parent 持
                // toplevel 或 popup 角色皆可派生——嵌套弹层链官方语义；
                // 先借后置——child 可变借用前收口，借用域不相交）。
                let Some(parent) = self
                    .surfaces
                    .iter()
                    .flatten()
                    .find(|sf| sf.xdg_surf == parent_id)
                    .copied()
                else {
                    return Err(CompError::BadObject);
                };
                if parent.xdg_toplevel == 0 && parent.xdg_popup == 0 {
                    return Err(CompError::XdgRoleBusy);
                }
                // 嵌套深度闸（POPUP_NEST_MAX 定容裁量——沿 popup_parent_wl
                // 链走查深度，越界 XdgRoleBusy fail-visible 如实记档）。
                {
                    let mut depth = 0usize;
                    let mut cur = Some(parent.wl_id);
                    while let Some(wl) = cur {
                        depth += 1;
                        if depth > POPUP_NEST_MAX {
                            return Err(CompError::XdgRoleBusy);
                        }
                        cur = self
                            .surfaces
                            .iter()
                            .flatten()
                            .find(|sf| sf.wl_id == wl && sf.xdg_popup != 0)
                            .map(|sf| sf.popup_parent_wl)
                            .filter(|&p| p != 0);
                    }
                }
                // 自身（child）xdg_surface 在册闸 + 角色单占闸（popup 与
                // toplevel 同面单占——官方角色域）。
                let Some(child) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_surf == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                if child.xdg_toplevel != 0 || child.xdg_popup != 0 {
                    return Err(CompError::XdgRoleBusy);
                }
                // placement 语义核 v1（M52-POPCON78 笔90——place_in_bounds
                // 约束域收口：flip→slide→resize 逐轴 + 屏域裁剪；x/y
                // configure 出域，w/h 会话域承载）。
                let pr = pos.place_in_bounds(self.bound);
                child.xdg_popup = pop_id;
                child.popup_x = pr.x;
                child.popup_y = pr.y;
                child.popup_w = pr.w;
                child.popup_h = pr.h;
                child.popup_parent_wl = parent.wl_id;
                self.table
                    .install(pop_id, WlIface::XdgPopup)
                    .map_err(CompError::Table)?;
                // 初始 popup configure 出域（官方语义：get_popup 后必发
                // configure(x,y)——位置父面局部坐标，约束域施策后值）。
                let n = encode_xdg_popup_configure_event(&mut out[*out_len..], pop_id, pr.x, pr.y)
                    .map_err(CompError::Wire)?;
                *out_len += n;
                Ok(())
            }
            xdg_surface::REQ_SET_WINDOW_GEOMETRY => {
                let _ = parse_args(body, SIG_XDG_SURFACE_SET_WINDOW_GEOMETRY)
                    .map_err(CompError::Wire)?;
                // 解析面记账（几何内容 v0 域外——tiling 面策略自主，
                // 客户端几何请求挂账如实记档）。
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg_toplevel 请求域（M50-XDGSHELL67 笔77）：destroy / set_title
    /// （标题承载域——waycomp 标题带消费事实源）/ set_app_id；窗口交
    /// 互请求域〔move/resize/maximized/fullscreen/minimized 族〕域外
    /// fail-visible（笔76 挂账维持）。
    fn dispatch_xdg_toplevel(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            xdg_toplevel::REQ_DESTROY => {
                let _ = parse_args(body, &[]).map_err(CompError::Wire)?;
                if let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_toplevel == header.object_id)
                {
                    sf.xdg_toplevel = 0;
                }
                self.table.remove(header.object_id);
                Ok(())
            }
            xdg_toplevel::REQ_SET_TITLE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_TOPLEVEL_SET_TITLE).map_err(CompError::Wire)?;
                let Some(WlArg::Str(title)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadString));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_toplevel == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                let n = title.len().min(XDG_TITLE_CAP);
                sf.title[..n].copy_from_slice(&title[..n]);
                sf.title_n = n;
                Ok(())
            }
            xdg_toplevel::REQ_SET_APP_ID => {
                let (args, _) =
                    parse_args(body, SIG_XDG_TOPLEVEL_SET_APP_ID).map_err(CompError::Wire)?;
                let Some(WlArg::Str(app_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadString));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_toplevel == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                let n = app_id.len().min(XDG_APPID_CAP);
                sf.app_id[..n].copy_from_slice(&app_id[..n]);
                sf.app_id_n = n;
                Ok(())
            }
            xdg_toplevel::REQ_SET_MIN_SIZE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_TOPLEVEL_SET_MIN_SIZE).map_err(CompError::Wire)?;
                let Some(WlArg::Int(w)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(h)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_toplevel == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                // 尺寸宣告承载域（0 = 未设定，官方语义——waycomp tiling
                // 面消费事实源）。
                sf.min_w = w;
                sf.min_h = h;
                Ok(())
            }
            xdg_toplevel::REQ_SET_MAX_SIZE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_TOPLEVEL_SET_MAX_SIZE).map_err(CompError::Wire)?;
                let Some(WlArg::Int(w)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(h)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_toplevel == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                sf.max_w = w;
                sf.max_h = h;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg_positioner 请求域（M51-XDGPOP75 笔86）：create_positioner
    /// 派生后的六 setter 语义核在环（set_size/set_anchor_rect/set_
    /// anchor/set_gravity/set_constraint_adjustment/set_offset）+
    /// destroy（destructor 摘除）；v3 三请求〔set_reactive/
    /// set_parent_size/set_parent_configure〕域外 fail-visible 如实挂账。
    fn dispatch_xdg_positioner(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            xdg_positioner::REQ_DESTROY => {
                let _ = parse_args(body, &[]).map_err(CompError::Wire)?;
                // 槽位摘除（destructor 语义——内层 Option take 清位；
                // 不在册对象 = 表摘除幂等域零故障）。
                if let Some(slot) = self
                    .pos_tbl
                    .iter_mut()
                    .find(|s| matches!(s, Some((id, _)) if *id == header.object_id))
                {
                    slot.take();
                    self.pos_n -= 1;
                }
                self.table.remove(header.object_id);
                Ok(())
            }
            xdg_positioner::REQ_SET_SIZE => {
                let (args, _) =
                    parse_args(body, SIG_XDG_POSITIONER_SET_SIZE).map_err(CompError::Wire)?;
                let Some(WlArg::Int(w)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(h)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.size = (w, h);
                Ok(())
            }
            xdg_positioner::REQ_SET_ANCHOR_RECT => {
                let (args, _) = parse_args(body, SIG_XDG_POSITIONER_SET_ANCHOR_RECT)
                    .map_err(CompError::Wire)?;
                let Some(WlArg::Int(x)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(y)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(w)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(h)) = args[3] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.anchor_rect = (x, y, w, h);
                Ok(())
            }
            xdg_positioner::REQ_SET_ANCHOR => {
                let (args, _) =
                    parse_args(body, SIG_XDG_POSITIONER_SET_ANCHOR).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(a)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // 值域闸（[`XDG_ANCHOR_MAX`]——官方枚举域越界拒收）。
                if a > XDG_ANCHOR_MAX {
                    return Err(CompError::XdgBadEnum);
                }
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.anchor = a;
                Ok(())
            }
            xdg_positioner::REQ_SET_GRAVITY => {
                let (args, _) =
                    parse_args(body, SIG_XDG_POSITIONER_SET_GRAVITY).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(g)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                if g > XDG_ANCHOR_MAX {
                    return Err(CompError::XdgBadEnum);
                }
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.gravity = g;
                Ok(())
            }
            xdg_positioner::REQ_SET_CONSTRAINT_ADJUSTMENT => {
                let (args, _) = parse_args(body, SIG_XDG_POSITIONER_SET_CONSTRAINT_ADJUSTMENT)
                    .map_err(CompError::Wire)?;
                let Some(WlArg::Uint(c)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // 位域闸（官方六位全谱 = 0x3F——越位拒收）。
                if c > XDG_CADJ_RESIZE_X
                    | XDG_CADJ_RESIZE_Y
                    | XDG_CADJ_FLIP_X
                    | XDG_CADJ_FLIP_Y
                    | XDG_CADJ_SLIDER_X
                    | XDG_CADJ_SLIDER_Y
                {
                    return Err(CompError::XdgBadEnum);
                }
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.cadj = c;
                Ok(())
            }
            xdg_positioner::REQ_SET_OFFSET => {
                let (args, _) =
                    parse_args(body, SIG_XDG_POSITIONER_SET_OFFSET).map_err(CompError::Wire)?;
                let Some(WlArg::Int(x)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(y)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.offset = (x, y);
                Ok(())
            }
            // v3 三请求（M52-POPCON78 笔90——reactive 重定位宣告域在环）。
            xdg_positioner::REQ_SET_REACTIVE => {
                let _ =
                    parse_args(body, SIG_XDG_POSITIONER_SET_REACTIVE).map_err(CompError::Wire)?;
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.reactive = true;
                Ok(())
            }
            xdg_positioner::REQ_SET_PARENT_SIZE => {
                let (args, _) = parse_args(body, SIG_XDG_POSITIONER_SET_PARENT_SIZE)
                    .map_err(CompError::Wire)?;
                let Some(WlArg::Int(w)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(h)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.parent_size = (w, h);
                Ok(())
            }
            xdg_positioner::REQ_SET_PARENT_CONFIGURE => {
                let (args, _) = parse_args(body, SIG_XDG_POSITIONER_SET_PARENT_CONFIGURE)
                    .map_err(CompError::Wire)?;
                let Some(WlArg::Uint(ser)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(pos) = self.pos_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                pos.parent_config = ser;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg_popup 请求域（M51-XDGPOP75 笔86 + M52-POPCON78 笔90）：destroy
    /// （destructor 角色摘除）/ grab（seat + serial 宣告——v0 记账面，
    /// 输入 grab 施策挂账如实记档）/ reposition（v3 重定位：positioner
    /// 完整性闸 + 约束域重算 + repositioned(token)→configure(x,y) 官方
    /// 序双事件出域）。
    fn dispatch_xdg_popup(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out: &mut [u8],
        out_len: &mut usize,
        repos: &mut usize,
    ) -> Result<(), CompError> {
        match header.opcode {
            xdg_popup::REQ_DESTROY => {
                let _ = parse_args(body, &[]).map_err(CompError::Wire)?;
                if let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_popup == header.object_id)
                {
                    sf.xdg_popup = 0;
                    sf.popup_x = 0;
                    sf.popup_y = 0;
                    sf.popup_grabbed = false;
                    sf.popup_parent_wl = 0;
                    sf.popup_w = 0;
                    sf.popup_h = 0;
                }
                self.table.remove(header.object_id);
                Ok(())
            }
            xdg_popup::REQ_GRAB => {
                let (args, _) = parse_args(body, SIG_XDG_POPUP_GRAB).map_err(CompError::Wire)?;
                let Some(WlArg::Object(seat_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Uint(_serial)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // seat 在册闸（官方 arg：对象域必须在册 wl_seat）。
                if self.table.lookup(seat_id) != Some(WlIface::Seat) {
                    return Err(CompError::BadObject);
                }
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_popup == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                sf.popup_grabbed = true;
                Ok(())
            }
            // v3 reposition（M52-POPCON78 笔90——重定位车道）。
            xdg_popup::REQ_REPOSITION => {
                let (args, _) =
                    parse_args(body, SIG_XDG_POPUP_REPOSITION).map_err(CompError::Wire)?;
                let Some(WlArg::Object(pos_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Uint(token)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // positioner 在册闸 + 完整性闸（get_popup 同谱）。
                let Some(pos) = self.pos_get(pos_id) else {
                    return Err(CompError::BadObject);
                };
                if !pos.complete() {
                    return Err(CompError::XdgPosIncomplete);
                }
                // popup 角色闸（在册面寻址）。
                let Some(sf) = self
                    .surfaces
                    .iter_mut()
                    .flatten()
                    .find(|sf| sf.xdg_popup == header.object_id)
                else {
                    return Err(CompError::BadObject);
                };
                // 约束域重算（place_in_bounds——get_popup 同源语义核）。
                let pr = pos.place_in_bounds(self.bound);
                sf.popup_x = pr.x;
                sf.popup_y = pr.y;
                sf.popup_w = pr.w;
                sf.popup_h = pr.h;
                let pop_id = header.object_id;
                // 官方序：repositioned(token) 先行、configure(x,y) 随行。
                let n = encode_xdg_popup_repositioned_event(&mut out[*out_len..], pop_id, token)
                    .map_err(CompError::Wire)?;
                *out_len += n;
                let n = encode_xdg_popup_configure_event(&mut out[*out_len..], pop_id, pr.x, pr.y)
                    .map_err(CompError::Wire)?;
                *out_len += n;
                *repos += 1;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// xdg policy 车道冲刷（M50-XDGSHELL67 close 车道 + M51-XDGPOP75
    /// 笔86 size/pdone 双车道——policy 请求队列逐项编组出域：xdg_
    /// toplevel.close 事件 + size-configure 对〔surface.configure +
    /// xdg_toplevel.configure(w,h,[])〕+ xdg_popup.popup_done 事件；
    /// 对象域已摘 = 静默丢弃（防御域——drop 与冲刷竞逐窗）；冲刷后
    /// 队列清零，记录数出域）。
    fn flush_xdg(
        &mut self,
        out: &mut [u8],
        out_len: &mut usize,
        closes: &mut usize,
        configs: &mut usize,
        popup_dones: &mut usize,
    ) -> Result<(), CompError> {
        for i in 0..self.close_n {
            if let Some(top_id) = self.close_q[i] {
                if self.table.lookup(top_id) == Some(WlIface::XdgToplevel) {
                    let n = encode_xdg_toplevel_close_event(&mut out[*out_len..], top_id)
                        .map_err(CompError::Wire)?;
                    *out_len += n;
                    *closes += 1;
                }
            }
        }
        self.close_q = [None; CLOSE_Q_MAX];
        self.close_n = 0;
        // size-configure 车道（M51-XDGPOP75 笔86——request_configure
        // policy 请求冲刷：串号铸造 + 未 ack 位铸造 + configure 对出
        // 域，官方双向序契约同谱——commit 前必须 ack 最近串号）。
        for i in 0..self.size_n {
            if let Some((wl, top, w, h)) = self.size_q[i] {
                if self.table.lookup(top) == Some(WlIface::XdgToplevel) {
                    let Some(sf) = self.surfaces.iter_mut().flatten().find(|sf| sf.wl_id == wl)
                    else {
                        continue;
                    };
                    self.xdg_serial = self.xdg_serial.wrapping_add(1);
                    let ser = self.xdg_serial;
                    sf.config_serial = ser;
                    sf.acked = false;
                    let n =
                        encode_xdg_surface_configure_event(&mut out[*out_len..], sf.xdg_surf, ser)
                            .map_err(CompError::Wire)?;
                    *out_len += n;
                    let n =
                        encode_xdg_toplevel_configure_event(&mut out[*out_len..], top, w, h, &[])
                            .map_err(CompError::Wire)?;
                    *out_len += n;
                    *configs += 1;
                }
            }
        }
        self.size_q = [None; SIZE_Q_MAX];
        self.size_n = 0;
        // popup_done 车道（M51-XDGPOP75 笔86——父窗收场派生域冲刷）。
        for i in 0..self.pdone_n {
            if let Some(pop_id) = self.pdone_q[i] {
                if self.table.lookup(pop_id) == Some(WlIface::XdgPopup) {
                    let n = encode_xdg_popup_done_event(&mut out[*out_len..], pop_id)
                        .map_err(CompError::Wire)?;
                    *out_len += n;
                    *popup_dones += 1;
                }
            }
        }
        self.pdone_q = [None; PDONE_Q_MAX];
        self.pdone_n = 0;
        Ok(())
    }

    /// wl_compositor 请求域（create_surface / create_region）。
    fn dispatch_compositor(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            compositor::REQ_CREATE_SURFACE => {
                let (args, _) =
                    parse_args(body, SIG_COMPOSITOR_CREATE_SURFACE).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(surf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.session_surface_new(surf_id)
            }
            compositor::REQ_CREATE_REGION => {
                let (args, _) =
                    parse_args(body, SIG_COMPOSITOR_CREATE_REGION).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(reg_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(reg_id, WlIface::Region)
                    .map_err(CompError::Table)?;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_shm 请求域（M42-ELF5 桌面链批次——create_pool：池对象登记 +
    /// fd 占位字记账 + 池记录入批；resize 域外 fail-visible）。
    fn dispatch_shm(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        pools: &mut PoolLog,
        fd_need: &mut usize,
    ) -> Result<(), CompError> {
        match header.opcode {
            shm::REQ_CREATE_POOL => {
                let (args, _) = parse_args(body, SIG_SHM_CREATE_POOL).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(pool_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Fd(_)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(size)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(pool_id, WlIface::ShmPool)
                    .map_err(CompError::Table)?;
                pools.push(PoolRecord {
                    pool_wl: pool_id,
                    size,
                });
                *fd_need += 1; // 每 create_pool 恰一 fd（电气面 RECV_FD 承接计数）
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_shm_pool 请求域（M42-ELF5——create_buffer：buffer 几何记账
    /// + 对象登记；destroy：双清；resize 域外 fail-visible）。
    fn dispatch_shm_pool(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            shm_pool::REQ_CREATE_BUFFER => {
                let (args, _) =
                    parse_args(body, SIG_SHM_POOL_CREATE_BUFFER).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(buf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let mut vals = [0i32; 4];
                for (k, a) in args.iter().take(5).skip(1).enumerate() {
                    match a {
                        Some(WlArg::Int(v)) => vals[k] = *v,
                        _ => return Err(CompError::Wire(WlError::BadLength)),
                    }
                }
                let Some(WlArg::Uint(format)) = args[5] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                if self.buf_n >= SESSION_BUFFERS {
                    return Err(CompError::BufferFull);
                }
                let Some(slot) = self.buffers.iter_mut().find(|b| b.is_none()) else {
                    return Err(CompError::BufferFull);
                };
                self.table
                    .install(buf_id, WlIface::Buffer)
                    .map_err(CompError::Table)?;
                *slot = Some(BufferRec {
                    wl: buf_id,
                    pool_wl: header.object_id,
                    offset: vals[0],
                    w: vals[1],
                    h: vals[2],
                    stride: vals[3],
                    format,
                });
                self.buf_n += 1;
                Ok(())
            }
            shm_pool::REQ_DESTROY => {
                let _ = parse_args(body, SIG_SHM_POOL_DESTROY).map_err(CompError::Wire)?;
                // 池对象摘除（表清；会话 buffer 域不连带——buffer 生命
                // 周期独立，池亡后像素域失效由池电气面承载，如实记档）
                let _ = self.table.remove(header.object_id);
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_surface 请求域（destroy/attach/damage/frame/commit——v0 子
    /// 集；其余 opcode fail-visible）。
    fn dispatch_surface(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
        drops: &mut DropLog,
    ) -> Result<(), CompError> {
        match header.opcode {
            surface::REQ_DESTROY => {
                if self.surface_slot(header.object_id).is_none() {
                    return Err(CompError::BadObject);
                }
                self.session_surface_drop(header.object_id);
                // 摘除记录入批（M42-GEOM6 域①——重排改写触发源；会话
                // 槽已摘，电气面据记录摘 fb surface + 窗口表行）。
                drops.push(DropRecord {
                    wl_id: header.object_id,
                });
                Ok(())
            }
            surface::REQ_ATTACH => {
                let (args, _) = parse_args(body, SIG_SURFACE_ATTACH).map_err(CompError::Wire)?;
                let Some(WlArg::Object(buf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(_)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(_)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // buffer 域校验（未登记 buffer id → BadObject fail-visible
                // ——M42-ELF5 像素承载域前置闸；借用域分离——先只读查
                // 槽后可变写位，同 session_commit 分离窗先例）
                let buf_ok = self.buffers.iter().flatten().any(|b| b.wl == buf_id);
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if buf_id == 0 {
                    // 官方语义：attach(null) = 解附（下轮 commit 无内容域）
                    sf.attached = false;
                    sf.attach_buf = 0;
                    return Ok(());
                }
                if !buf_ok {
                    return Err(CompError::BadObject);
                }
                sf.attached = true; // buffer id 记账域（M42-ELF5 像素承载实-id）
                sf.attach_buf = buf_id;
                Ok(())
            }
            surface::REQ_DAMAGE => {
                let (args, _) = parse_args(body, SIG_SURFACE_DAMAGE).map_err(CompError::Wire)?;
                let mut vals = [0i32; 4];
                for (k, a) in args.iter().take(4).enumerate() {
                    match a {
                        Some(WlArg::Int(v)) => vals[k] = *v,
                        _ => return Err(CompError::Wire(WlError::BadLength)),
                    }
                }
                // 负域非负化（官方语义 damage 可越界——交集裁剪在
                // commit 域承担，此处仅积累域规整）。
                let dx = vals[0].max(0);
                let dy = vals[1].max(0);
                let dw = vals[2].max(0) as u32;
                let dh = vals[3].max(0) as u32;
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if dw > 0 && dh > 0 {
                    let r = Rect {
                        x: dx,
                        y: dy,
                        w: dw,
                        h: dh,
                    };
                    sf.damage = Some(match sf.damage {
                        Some(prev) => prev.union(&r),
                        None => r,
                    });
                }
                Ok(())
            }
            surface::REQ_FRAME => {
                let (args, _) = parse_args(body, SIG_SURFACE_FRAME).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(cb_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(cb_id, WlIface::Callback)
                    .map_err(CompError::Table)?;
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if sf.frame_n >= MAX_FRAME_CBS {
                    return Err(CompError::SurfaceFull);
                }
                sf.frames[sf.frame_n] = cb_id;
                sf.frame_n += 1;
                Ok(())
            }
            surface::REQ_COMMIT => {
                let _ = parse_args(body, SIG_SURFACE_COMMIT).map_err(CompError::Wire)?;
                self.session_commit(header.object_id, out_len, out, log)
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// 会话 surface 登记槽位分配（create_surface 域）。
    fn session_surface_new(&mut self, surf_id: u32) -> Result<(), CompError> {
        if self.surf_n >= SESSION_SURFACES {
            return Err(CompError::SurfaceFull);
        }
        let Some(slot) = self.surfaces.iter_mut().find(|s| s.is_none()) else {
            return Err(CompError::SurfaceFull);
        };
        self.table
            .install(surf_id, WlIface::Surface)
            .map_err(CompError::Table)?;
        *slot = Some(CompSurface {
            wl_id: surf_id,
            attached: false,
            attach_buf: 0,
            geom: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            damage: None,
            frames: [0; MAX_FRAME_CBS],
            frame_n: 0,
            mapped: false,
            xdg_surf: 0,
            xdg_toplevel: 0,
            config_serial: 0,
            acked: false,
            xdg_popup: 0,
            popup_x: 0,
            popup_y: 0,
            popup_grabbed: false,
            popup_parent_wl: 0,
            popup_w: 0,
            popup_h: 0,
            min_w: 0,
            min_h: 0,
            max_w: 0,
            max_h: 0,
            title: [0; XDG_TITLE_CAP],
            title_n: 0,
            app_id: [0; XDG_APPID_CAP],
            app_id_n: 0,
        });
        self.surf_n += 1;
        Ok(())
    }

    /// 会话 surface 摘除（destroy 域——对象表 + 槽位双清；id 不复用
    /// v0 表纪律；焦点域摘除随行：被摘面即焦点面 → leave 事件入队 +
    /// 焦点清零，M42-INPUT7）。
    fn session_surface_drop(&mut self, wl_id: u32) {
        if self.kb_focus == wl_id {
            if self.keyboard_obj != 0 && self.key_n < INPUT_Q_MAX {
                self.input_serial = self.input_serial.wrapping_add(1);
                self.key_q[self.key_n] = Some(KeyRecord {
                    kind: KbKind::Leave,
                    surface: wl_id,
                    serial: self.input_serial,
                    key: 0,
                    state: 0,
                    mods_d: 0,
                    mods_l: 0,
                    mods_lk: 0,
                    group: 0,
                });
                self.key_n += 1;
            }
            self.kb_focus = 0;
        }
        if self.ptr_focus == wl_id {
            if self.pointer_obj != 0 && self.ptr_n < INPUT_Q_MAX {
                self.input_serial = self.input_serial.wrapping_add(1);
                self.ptr_q[self.ptr_n] = Some(PtrRecord {
                    kind: PtrKind::Leave,
                    surface: wl_id,
                    serial: self.input_serial,
                    x: 0,
                    y: 0,
                    button: 0,
                    state: 0,
                    axis: 0,
                    value: 0,
                    source: 0,
                });
                self.ptr_n += 1;
            }
            self.ptr_focus = 0;
        }
        let _ = self.table.remove(wl_id);
        if let Some(slot) = self
            .surfaces
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|sf| sf.wl_id == wl_id))
        {
            *slot = None;
            self.surf_n -= 1;
        }
    }

    /// surface 槽位只读查找。
    fn surface_slot(&self, wl_id: u32) -> Option<&CompSurface> {
        self.surfaces.iter().flatten().find(|sf| sf.wl_id == wl_id)
    }

    /// surface 槽位可变查找。
    fn surface_slot_mut(&mut self, wl_id: u32) -> Option<&mut CompSurface> {
        self.surfaces
            .iter_mut()
            .flatten()
            .find(|sf| sf.wl_id == wl_id)
    }

    /// commit 发布语义（损伤平移屏域 ∩ 窗口几何交集裁剪 + 帧回调冲刷
    /// done 事件 + 串号推进 + commit 记录入批）。零面积几何/零损伤
    /// 域 = 记录照常入批（映射态推进语义——损伤矩形零面积，电气面
    /// sync 零量化收敛）。**xdg commit 前置闸（M50-XDGSHELL67）**：
    /// 窗口角色面未 ack 最近 configure 即 commit = [`CompError::XdgUnacked`]
    /// fail-visible（官方契约：commit 前必须 ack）。
    fn session_commit(
        &mut self,
        wl_id: u32,
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
    ) -> Result<(), CompError> {
        // 帧回调冲刷先行取值（借用域分离——状态读 + 事件写分离窗）
        let (geom, screen_damage, frames_fired, frame_ids, first_map, attach_buf, unacked) = {
            let Some(sf) = self.surface_slot_mut(wl_id) else {
                return Err(CompError::BadObject);
            };
            let unacked = sf.xdg_surf != 0 && !sf.acked;
            let screen_damage = match (sf.damage, sf.geom.area()) {
                (Some(d), a) if a > 0 => {
                    // 损伤（surface 坐标）平移屏域后与窗口几何交集裁
                    // 剪——几何外损伤无实效（官方裁剪语义）。
                    let cand = Rect {
                        x: sf.geom.x + d.x,
                        y: sf.geom.y + d.y,
                        w: d.w,
                        h: d.h,
                    };
                    cand.intersection(&sf.geom).unwrap_or(Rect {
                        x: 0,
                        y: 0,
                        w: 0,
                        h: 0,
                    })
                }
                _ => Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                },
            };
            let fired = sf.frame_n;
            let ids = sf.frames;
            let first = !sf.mapped;
            let abuf = sf.attach_buf;
            sf.mapped = true;
            sf.damage = None;
            sf.frame_n = 0;
            (sf.geom, screen_damage, fired, ids, first, abuf, unacked)
        };
        if unacked {
            return Err(CompError::XdgUnacked);
        }
        // attach buffer 几何解析（M42-ELF5——commit 快照：buffer 对象
        // 在会话槽内即携几何出域；未附/已解附 = None。借用域分离：可
        // 变槽借用终结后缓冲槽只读域）
        let buffer = if attach_buf != 0 {
            self.buffers
                .iter()
                .flatten()
                .find(|b| b.wl == attach_buf)
                .copied()
        } else {
            None
        };
        self.commit_serial = self.commit_serial.wrapping_add(1);
        // 帧回调 done 事件冲刷（官方语义——callback_data = commit 串
        // 号）。**M42-DMGC22 笔㉒ delete_id 复用面**：done 后服务端销毁
        // frame callback + wl_display.delete_id 随行（客户端 id 复用域
        // 事实源——同 id 多轮 frame 在环面），对象表同步摘除（v0 「不
        // 回收」口径退役——表容量回收域；sync 域同款语义
        // M42-WAYCOMP18）。display id = 1（wire 首对象约定——t119
        // 对读同谱）。
        for cb in frame_ids.iter().take(frames_fired) {
            let n = encode_callback_done_event(&mut out[*out_len..], *cb, self.commit_serial)
                .map_err(CompError::Wire)?;
            *out_len += n;
            self.table.remove(*cb);
            let n = encode_display_delete_id_event(&mut out[*out_len..], 1, *cb)
                .map_err(CompError::Wire)?;
            *out_len += n;
            self.frame_dels_total += 1;
        }
        log.push(CommitRecord {
            wl_id,
            geom,
            damage: screen_damage,
            frames_fired,
            first_map,
            buffer,
        });
        Ok(())
    }

    /// 会话窗口标题读面（M50-XDGSHELL67——xdg_toplevel.set_title 承载
    /// 域的消费访问面：waycomp 窗格标题带刷新事实源；无 xdg 角色 /
    /// 空标题 = None（调用方保持既有台账））。
    pub fn surface_title(&self, wl_id: u32) -> Option<&[u8]> {
        let sf = self.surface_slot(wl_id)?;
        if sf.title_n == 0 {
            return None;
        }
        Some(&sf.title[..sf.title_n])
    }

    /// 服务端 liveness 探测（M50-XDGSHELL67——官方 ping/pong 契约：
    /// wm_base 未 bind = [`CompError::BadObject`] 前置闸；ping 事件
    /// 即时编组入 out 首部〔调用方 send_all 承接〕，串号入未决 ping
    /// 记账，pong 域对账事实源）。返回串号。
    pub fn send_ping(&mut self, out: &mut [u8]) -> Result<u32, CompError> {
        if self.wm_base_obj == 0 {
            return Err(CompError::BadObject);
        }
        self.xdg_serial = self.xdg_serial.wrapping_add(1);
        let ser = self.xdg_serial;
        self.ping_pending = Some((self.wm_base_obj, ser));
        encode_xdg_wm_base_ping_event(out, self.wm_base_obj, ser).map_err(CompError::Wire)?;
        Ok(ser)
    }

    /// 服务端 close 请求入队（M50-XDGSHELL67——policy 车道：用户关窗
    /// 请求 → close 队列，下次 feed 冲刷域 xdg_toplevel.close 出域。
    /// 对象域闸：toplevel 必须在册（fail-visible——不泄会话拓扑同
    /// 面）；队满 = [`CompError::XdgCloseQFull`]）。
    pub fn request_close(&mut self, toplevel_id: u32) -> Result<(), CompError> {
        if self.table.lookup(toplevel_id) != Some(WlIface::XdgToplevel) {
            return Err(CompError::BadObject);
        }
        if self.close_n >= CLOSE_Q_MAX {
            return Err(CompError::XdgCloseQFull);
        }
        self.close_q[self.close_n] = Some(toplevel_id);
        self.close_n += 1;
        Ok(())
    }

    // --- M51-XDGPOP75 笔86：popup 尺寸交互族 policy 钩子 + 取证面 ---

    /// positioner 只读快照（对象 id → [`PosDef`]——get_popup 完整性
    /// 闸消费 + 宿主取证面）。
    fn pos_get(&self, pos_id: u32) -> Option<PosDef> {
        self.pos_tbl
            .iter()
            .flatten()
            .find(|(id, _)| *id == pos_id)
            .map(|(_, def)| *def)
    }

    /// positioner 可变槽位（六 setter 语义核承载）。
    fn pos_slot_mut(&mut self, pos_id: u32) -> Option<&mut PosDef> {
        self.pos_tbl
            .iter_mut()
            .flatten()
            .find(|(id, _)| *id == pos_id)
            .map(|(_, def)| def)
    }

    /// 服务端 size-configure 请求（policy 车道——waycomp tiling 面消
    /// 费域：tiling 矩形随行入队，feed 冲刷域 configure 对出域〔串号
    /// 铸造 + 未 ack 位铸造〕。官方语义：configure(w,h) 非零值 = 客户
    /// 端应重定窗尺寸；同窗重入队 = 覆盖（单挂起口径 last-wins）。
    /// toplevel 角色缺席 / surface 缺席 = BadObject fail-visible）。
    pub fn request_configure(
        &mut self,
        wl_id: u32,
        width: i32,
        height: i32,
    ) -> Result<(), CompError> {
        let Some(sf) = self.surface_slot(wl_id) else {
            return Err(CompError::BadObject);
        };
        let top_id = sf.xdg_toplevel;
        if top_id == 0 {
            return Err(CompError::BadObject);
        }
        // 覆盖快径：同窗已入队 = last-wins 覆盖。
        for slot in self.size_q.iter_mut().flatten() {
            if slot.0 == wl_id {
                slot.2 = width;
                slot.3 = height;
                return Ok(());
            }
        }
        if self.size_n >= SIZE_Q_MAX {
            return Err(CompError::XdgSizeQFull);
        }
        self.size_q[self.size_n] = Some((wl_id, top_id, width, height));
        self.size_n += 1;
        Ok(())
    }

    /// 服务端 popup_done 请求（policy 车道——父窗收场派生域：close 车道
    /// 同谱寻址域 = toplevel 对象 id；M52-POPCON78 笔90 G-4 **传递闭包**
    /// 扩容：worklist = [父面 wl id]，扫描 popup_parent_wl ∈ worklist 的
    /// popup 面 → 入队 popup_done + 自身 wl id 入 worklist 迭代至不动点
    /// 〔嵌套弹层链全谱收场——父窗亡则全链 popup 官方收场语义〕。定容
    /// [`PDONE_Q_MAX`] 满容拒收）。父面缺席或无 popup = BadObject。
    pub fn request_popup_done_for_parent(&mut self, parent_top: u32) -> Result<(), CompError> {
        // 父面解析：toplevel 对象 id → 父 surface（wl id 寻址域）。
        let Some(parent_wl) = self
            .surfaces
            .iter()
            .flatten()
            .find(|sf| sf.xdg_toplevel == parent_top)
            .map(|sf| sf.wl_id)
        else {
            return Err(CompError::BadObject);
        };
        // 传递闭包（worklist 定容——嵌套深度 POPUP_NEST_MAX 上界 + 根。
        let mut wl_q = [0u32; PDONE_Q_MAX + POPUP_NEST_MAX + 2];
        let mut wl_n = 1usize;
        wl_q[0] = parent_wl;
        let mut pops: [u32; PDONE_Q_MAX] = [0; PDONE_Q_MAX];
        let mut pn = 0usize;
        let mut i = 0usize;
        while i < wl_n {
            let wl = wl_q[i];
            i += 1;
            for sf in self.surfaces.iter().flatten() {
                if sf.popup_parent_wl == wl && sf.xdg_popup != 0 {
                    if pn >= PDONE_Q_MAX {
                        return Err(CompError::XdgDoneQFull);
                    }
                    // 同一 popup 面双亲域零重复（id 去重哨兵）。
                    if !pops[..pn].contains(&sf.xdg_popup) {
                        pops[pn] = sf.xdg_popup;
                        pn += 1;
                    }
                    if wl_n < wl_q.len() && !wl_q[..wl_n].contains(&sf.wl_id) {
                        wl_q[wl_n] = sf.wl_id;
                        wl_n += 1;
                    }
                }
            }
        }
        if pn == 0 {
            return Err(CompError::BadObject);
        }
        for pop in pops.iter().take(pn) {
            if self.pdone_n >= PDONE_Q_MAX {
                return Err(CompError::XdgDoneQFull);
            }
            self.pdone_q[self.pdone_n] = Some(*pop);
            self.pdone_n += 1;
        }
        Ok(())
    }

    /// toplevel 尺寸宣告取证面（surface_minmax——waycomp tiling 面消
    /// 费事实源：(min_w, min_h, max_w, max_h)，0 = 未设定；toplevel
    /// 角色缺席 = None）。
    pub fn surface_minmax(&self, wl_id: u32) -> Option<(i32, i32, i32, i32)> {
        self.surface_slot(wl_id)
            .filter(|sf| sf.xdg_toplevel != 0)
            .map(|sf| (sf.min_w, sf.min_h, sf.max_w, sf.max_h))
    }

    /// 最近 configure ack 位取证面（toplevel 角色缺席 = None——waycomp
    /// size-configure 节流域事实源）。
    pub fn surface_acked(&self, wl_id: u32) -> Option<bool> {
        self.surface_slot(wl_id)
            .filter(|sf| sf.xdg_toplevel != 0)
            .map(|sf| sf.acked)
    }

    /// popup 取证面（(popup 对象 id, x, y, 裁剪后 w, 裁剪后 h)——父面
    /// 局部坐标 + 屏域权威渲染域；popup 角色缺席 = None）。
    pub fn surface_popup(&self, wl_id: u32) -> Option<(u32, i32, i32, i32, i32)> {
        self.surface_slot(wl_id)
            .filter(|sf| sf.xdg_popup != 0)
            .map(|sf| (sf.xdg_popup, sf.popup_x, sf.popup_y, sf.popup_w, sf.popup_h))
    }

    /// positioner 取证面（PosDef 值快照——v3 reactive 三域记账断言面；
    /// 缺席 = None）。
    pub fn pos_snapshot(&self, id: u32) -> Option<PosDef> {
        self.pos_tbl
            .iter()
            .flatten()
            .find(|(i, _)| *i == id)
            .map(|(_, p)| *p)
    }
}

/// wl 键码 → XKB 修饰键位域映射（M42-WAYCOMP15 语义核纯函数——wl
/// 键码 − 8 = evdev 域：42/54 = Shift、58 = CapsLock〔Lock〕、29/97 =
/// Ctrl、56/100 = Alt、69 = NumLock〔Lock〕、125/126 = Super/Mod4；
/// 非修饰键 = None）。XKB 掩码事实源 = xkbcommon 语义域（MOD_*
/// 常量同源）。
fn modifier_bit_of_wl_key(key: u32) -> Option<u32> {
    let ev = key.checked_sub(8)?;
    match ev {
        42 | 54 => Some(MOD_SHIFT),  // KEY_LEFTSHIFT / KEY_RIGHTSHIFT
        58 => Some(MOD_CAPS),        // KEY_CAPSLOCK（Lock 域）
        29 | 97 => Some(MOD_CTRL),   // KEY_LEFTCTRL / KEY_RIGHTCTRL
        56 | 100 => Some(MOD_ALT),   // KEY_LEFTALT / KEY_RIGHTALT
        69 => Some(MOD_NUM2),        // KEY_NUMLOCK（Lock 域）
        125 | 126 => Some(MOD_MOD4), // KEY_LEFTMETA / KEY_RIGHTMETA
        _ => None,
    }
}

/// Lock 键判定（M42-WAYCOMP15——按下翻转 locked 域的键：CapsLock 58 /
/// NumLock 69；evdev 域）。
fn lock_key_of_wl_key(key: u32) -> bool {
    matches!(key.checked_sub(8), Some(58) | Some(69))
}

// -------------------------------------------------------- 宿主测试谱
// （M34-P4「宿主测试谱先行」——`cargo test -p prism`；事实源 = 官方
//   wayland.xml 1.21.0 会话语义 + wire 壳 v0 表复用对账）

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::*;
    use crate::wayland::{
        callback, display, encode_display_get_registry, encode_display_sync, encode_message,
        encode_registry_bind, encode_surface_commit, surface as surf_ops, SIG_CALLBACK_DONE,
        SIG_DISPLAY_DELETE_ID, SIG_KEYBOARD_ENTER, SIG_KEYBOARD_KEY, SIG_KEYBOARD_KEYMAP,
        SIG_POINTER_BUTTON, SIG_POINTER_ENTER, SIG_POINTER_MOTION, SIG_REGISTRY_GLOBAL,
        SIG_SEAT_CAPABILITIES,
    };

    /// 测试用公告名单：核心子集 + xdg_shell 五 global（compositor v4 /
    /// seat v1 / shm v1 / output v2 / xdg_wm_base v1——名 1..=5；
    /// M50-XDGSHELL67 公告面演化同源）。
    const GLOBALS: [GlobalDef; GLOBALS_MAX] = [
        GlobalDef {
            name: 1,
            iface: WlIface::Compositor,
            version: 4,
        },
        GlobalDef {
            name: 2,
            iface: WlIface::Seat,
            version: 1,
        },
        GlobalDef {
            name: 3,
            iface: WlIface::Shm,
            version: 1,
        },
        GlobalDef {
            name: 4,
            iface: WlIface::Output,
            version: 2,
        },
        GlobalDef {
            name: 5,
            iface: WlIface::XdgWmBase,
            version: 1,
        },
    ];

    /// t79 平铺 golden 域主窗几何（1920×1080 master pane——策略面几何
    /// 承接样本）。
    const PANE: Rect = Rect {
        x: 8,
        y: 56,
        w: 948,
        h: 944,
    };

    /// 多消息流拼接（std 域——测试体零堆纪律不受限）。
    fn stream_of(msgs: &[&[u8]]) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        for m in msgs {
            v.extend_from_slice(m);
        }
        v
    }

    fn new_session() -> CompSession {
        CompSession::new(GLOBALS)
    }

    /// registry 轮转前置（get_registry + globals 回执解析——四公告
    /// 全谱断言 + registry 对象登记显形）。
    fn setup_registry(s: &mut CompSession) -> std::vec::Vec<u8> {
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        let mut out = [0u8; 512];
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        // 回执字节数逐项对账：compositor(36) + seat(28) + shm(28) + output(32)
        // + xdg_wm_base(32)——M50-XDGSHELL67 公告面演化五目
        assert_eq!(rep.out_len, 36 + 28 + 28 + 32 + 32);
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
        // 回执解析：四 global 事件逐条对账（声明序 = 名单序）
        let mut off = 0usize;
        for g in GLOBALS.iter() {
            let m =
                crate::wayland::parse_message(&out[off..rep.out_len], SIG_REGISTRY_GLOBAL).unwrap();
            assert_eq!(m.header.object_id, 2);
            assert_eq!(m.header.opcode, crate::wayland::registry::EV_GLOBAL);
            assert_eq!(m.args[0], Some(WlArg::Uint(g.name)));
            assert_eq!(m.args[1], Some(WlArg::Str(iface_name(g.iface).as_bytes())));
            assert_eq!(m.args[2], Some(WlArg::Uint(g.version)));
            off += m.wire_size();
        }
        assert_eq!(off, rep.out_len, "globals 回执逐字节对账");
        out[..rep.out_len].to_vec()
    }

    /// registry 公告面轮转：get_registry → 四 global 全谱回执 + 表登记。
    #[test]
    fn session_registry_roundtrip() {
        let mut s = new_session();
        setup_registry(&mut s);
        // display 固定 id 1 在账 + registry id 2 客户端域登记
        assert_eq!(s.table().lookup(1), Some(WlIface::Display));
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
    }

    /// bind + create_surface 双请求单流推进：接口名名单校验 + 对象登
    /// 记 + 会话槽登记。
    #[test]
    fn bind_and_create_surface() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let stream = stream_of(&[&bind, &cs]);
        let mut out = [0u8; 64];
        let rep = s.feed(&stream, &mut out).unwrap();
        assert_eq!(rep.consumed, stream.len());
        assert_eq!(rep.out_len, 0, "bind/create_surface 无事件回执");
        assert_eq!(s.table().lookup(3), Some(WlIface::Compositor));
        assert_eq!(s.table().lookup(0x21), Some(WlIface::Surface));
        assert_eq!(s.surfaces_count(), 1);
        let sf = s.surface(0x21).unwrap();
        assert!(!sf.attached && !sf.mapped && sf.damage.is_none());
    }

    /// damage → commit 发布语义：损伤交集裁剪 + 帧回调冲刷 + 首映射位
    /// + 记录批回执。
    #[test]
    fn damage_commit_report() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let dmg = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[
                    WlArg::Int(0),
                    WlArg::Int(0),
                    WlArg::Int(100),
                    WlArg::Int(50),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let frame = {
            let mut b = [0u8; 64];
            let n =
                encode_message(&mut b, 0x21, surf_ops::REQ_FRAME, &[WlArg::NewId(0x22)]).unwrap();
            b[..n].to_vec()
        };
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        let mut out = [0u8; 128];
        let rep = s
            .feed(&stream_of(&[&dmg, &frame, &commit]), &mut out)
            .unwrap();
        // commit 记录：屏域损伤 = surface 域损伤平移 ∩ 几何；首映射位
        let rec = rep.commits.last_of(0x21).expect("commit 记录在批");
        assert_eq!(rec.geom, PANE);
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 100,
                h: 50
            }
        );
        assert!(rec.first_map);
        assert_eq!(rec.frames_fired, 1);
        assert_eq!(rep.commits.n, 1);
        // 帧回调 done 事件回执解析（callback_data = commit 串号 1；
        // M42-DMGC22 后随 delete_id——out_len = 24，首消息域精确切片）
        let m = crate::wayland::parse_message(&out[..12], SIG_CALLBACK_DONE).unwrap();
        assert_eq!(m.header.object_id, 0x22);
        assert_eq!(m.header.opcode, callback::EV_DONE);
        assert_eq!(m.args[0], Some(WlArg::Uint(1)));
        // 会话态：损伤冲刷清零 + 首映射位翻转 + 串号推进
        let sf = s.surface(0x21).unwrap();
        assert!(sf.mapped && sf.damage.is_none() && sf.frame_n == 0);
        assert_eq!(s.commit_serial(), 1);
    }

    /// 二次 commit（无损伤无帧）：零面积损伤域 + UPDATE 分流键 + 零
    /// 事件回执。
    #[test]
    fn second_commit_zero_damage() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        // 首映射 commit（无损伤——映射态推进）
        let rep1 = s.feed(&commit, &mut [0u8; 16]).unwrap();
        let r1 = rep1.commits.last_of(0x21).unwrap();
        assert!(r1.first_map);
        assert_eq!(r1.damage.w, 0);
        // 二次 commit：UPDATE 分流键 + 零面积 + 零回执
        let mut out = [0u8; 64];
        let rep2 = s.feed(&commit, &mut out).unwrap();
        let r2 = rep2.commits.last_of(0x21).unwrap();
        assert!(!r2.first_map);
        assert_eq!(
            r2.damage,
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0
            }
        );
        assert_eq!(r2.frames_fired, 0);
        assert_eq!(rep2.out_len, 0);
    }

    /// frame done + delete_id 对 + 表摘除（M42-DMGC22 笔㉒——delete_id
    /// 复用面：frame callback commit 冲刷后销毁 + wl_display.delete_id
    /// 随行 + 对象表同步摘除——v0「不回收」口径退役；sync 域同款语义
    /// M42-WAYCOMP18）。
    #[test]
    fn frame_commit_done_delete_id_pair() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let frame = {
            let mut b = [0u8; 64];
            let n =
                encode_message(&mut b, 0x21, surf_ops::REQ_FRAME, &[WlArg::NewId(0x22)]).unwrap();
            b[..n].to_vec()
        };
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        let mut out = [0u8; 128];
        let rep = s.feed(&stream_of(&[&frame, &commit]), &mut out).unwrap();
        assert_eq!(
            rep.out_len, 24,
            "done + delete_id 对（v0 单 done 12B 退役）"
        );
        // done(0x22, serial 1) + delete_id(display 1 → 0x22) 逐目对读
        let m = crate::wayland::parse_message(&out[..12], SIG_CALLBACK_DONE).unwrap();
        assert_eq!(m.header.object_id, 0x22);
        assert_eq!(m.args[0], Some(WlArg::Uint(1)));
        let m = crate::wayland::parse_message(&out[12..24], SIG_DISPLAY_DELETE_ID).unwrap();
        assert_eq!(m.header.object_id, 1);
        assert_eq!(m.args[0], Some(WlArg::Uint(0x22)));
        // 对象表摘除（v0 永驻表膨胀域退役——同 id 复用域前提）
        assert_eq!(s.table().lookup(0x22), None);
        assert_eq!(rep.frame_dels, 1);
        assert_eq!(s.frame_dels_snapshot(), 1);
    }

    /// 同 id 多轮 frame 复用（M42-DMGC22——delete_id 回收后同 id 重装
    /// 在环面；第二轮 commit 串号推进 2——done callback_data 对账）。
    #[test]
    fn frame_same_id_multi_round_reuse() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let mut out = [0u8; 128];
        for round in 1..3u32 {
            let frame = {
                let mut b = [0u8; 64];
                // 同 id 0x22 两轮（delete_id 回收域在环——v0 install 拒
                // 收域退役）
                let n = encode_message(&mut b, 0x21, surf_ops::REQ_FRAME, &[WlArg::NewId(0x22)])
                    .unwrap();
                b[..n].to_vec()
            };
            let commit = {
                let mut b = [0u8; 64];
                let n = encode_surface_commit(&mut b, 0x21).unwrap();
                b[..n].to_vec()
            };
            let rep = s.feed(&stream_of(&[&frame, &commit]), &mut out).unwrap();
            assert_eq!(rep.out_len, 24, "轮 {} done + delete_id 对", round);
            let m = crate::wayland::parse_message(&out[..12], SIG_CALLBACK_DONE).unwrap();
            assert_eq!(m.header.object_id, 0x22);
            assert_eq!(m.args[0], Some(WlArg::Uint(round)), "commit 串号推进");
            let m = crate::wayland::parse_message(&out[12..24], SIG_DISPLAY_DELETE_ID).unwrap();
            assert_eq!(m.args[0], Some(WlArg::Uint(0x22)));
            assert_eq!(s.table().lookup(0x22), None, "轮 {} 后摘除", round);
        }
        assert_eq!(s.frame_dels_snapshot(), 2);
    }

    /// 损伤并集 + 屏域交集裁剪：两次 damage 积累 + 越几何域裁剪。
    #[test]
    fn damage_union_and_screen_clip() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let d1 = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[WlArg::Int(0), WlArg::Int(0), WlArg::Int(50), WlArg::Int(50)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        // 越几何域损伤（surface 域 900×900 > 窗口 948×944）——交集裁剪
        let d2 = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[
                    WlArg::Int(10),
                    WlArg::Int(10),
                    WlArg::Int(900),
                    WlArg::Int(900),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        let rep = s
            .feed(&stream_of(&[&d1, &d2, &commit]), &mut [0u8; 64])
            .unwrap();
        let rec = rep.commits.last_of(0x21).unwrap();
        // 并集 = (0,0,910,910)（union 包络）→ 平移屏域 (8,56) 交集
        // PANE(8,56,948,944) → (8,56,910,910)
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 910,
                h: 910
            }
        );
    }

    /// sync 即时 done + delete_id 随行销毁（官方生命周期——M42-WAYCOMP18
    /// 多注册表面：done + delete_id 对 + 对象表摘除）。
    #[test]
    fn sync_callback_immediate() {
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_sync(&mut req, 1, 9).unwrap();
        let mut out = [0u8; 64];
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        assert_eq!(rep.out_len, 8 + 4 + 8 + 4, "done + delete_id 双事件");
        assert_eq!(rep.syncs, 1);
        // done 事件（头 + uint）
        let m = crate::wayland::parse_message(&out[..12], SIG_CALLBACK_DONE).unwrap();
        assert_eq!(m.header.object_id, 9);
        assert_eq!(m.header.opcode, callback::EV_DONE);
        assert_eq!(m.args[0], Some(WlArg::Uint(0)));
        // delete_id 事件（display 域 + 销毁 id）
        let m =
            crate::wayland::parse_message(&out[12..rep.out_len], SIG_DISPLAY_DELETE_ID).unwrap();
        assert_eq!(m.header.object_id, 1);
        assert_eq!(m.header.opcode, display::EV_DELETE_ID);
        assert_eq!(m.args[0], Some(WlArg::Uint(9)));
        // 对象表摘除（v0 永驻域退役——同 id 可复用事实源）
        assert_eq!(s.table().lookup(9), None);
    }

    /// 多轮 sync 同 id 复用（M42-WAYCOMP18 多注册表面——delete_id 回收
    /// 后同 id 重装域：两轮 done + delete_id 对 + syncs 累计 + 表终态
    /// 摘除）。
    #[test]
    fn sync_multi_round_same_id_reuse() {
        let mut s = new_session();
        let mut out = [0u8; 128];
        for round in 0..2u32 {
            let mut req = [0u8; 64];
            let n = encode_display_sync(&mut req, 1, 0x51).unwrap(); // 同 id 两轮
            let rep = s.feed(&req[..n], &mut out).unwrap();
            assert_eq!(rep.consumed, n);
            assert_eq!(rep.out_len, 24, "done + delete_id 对");
            assert_eq!(rep.syncs, 1);
            let m = crate::wayland::parse_message(&out[..12], SIG_CALLBACK_DONE).unwrap();
            assert_eq!(m.header.object_id, 0x51);
            let m = crate::wayland::parse_message(&out[12..24], SIG_DISPLAY_DELETE_ID).unwrap();
            assert_eq!(m.args[0], Some(WlArg::Uint(0x51)));
            assert_eq!(s.table().lookup(0x51), None, "轮 {} 后摘除", round);
        }
        assert_eq!(s.syncs_snapshot(), 2);
    }

    /// 多 registry 多公告（M42-WAYCOMP18 多注册表面——同会话第二
    /// get_registry：双公告域 + 经第二 registry bind 可用域）。
    #[test]
    fn multi_registry_announce_and_bind() {
        let mut s = new_session();
        let mut out = [0u8; 512];
        // 第一 registry（id 2）公告
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.out_len, 156, "首公告五 global");
        // 第二 registry（id 0x52）公告——多注册面在环
        let n = encode_display_get_registry(&mut req, 1, 0x52).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.out_len, 156, "次公告五 global（reg_id 0x52）");
        let m = crate::wayland::parse_message(&out[..rep.out_len], SIG_REGISTRY_GLOBAL).unwrap();
        assert_eq!(m.header.object_id, 0x52, "次公告首 global 承新 registry id");
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
        assert_eq!(s.table().lookup(0x52), Some(WlIface::Registry));
        // 经第二 registry bind wl_seat——多 registry 可用域
        let n = encode_registry_bind(&mut req, 0x52, 2, "wl_seat", 1, 0x53).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert!(rep.out_len >= 12, "capabilities 随行");
        assert_eq!(s.table().lookup(0x53), Some(WlIface::Seat));
    }

    /// 负例域全谱：未登记对象 / 域外 opcode / 名单外 bind / 版本越上
    /// 界 / 版本 0 / 会话槽满。
    #[test]
    fn negative_domain_fail_visible() {
        let mut s = new_session();
        // 未登记对象路由拒收（合法头 + 非在册 id——BadObject 显形）
        let mut out = [0u8; 64];
        let ghost = [
            0x99u8, 0x09, 0x00, 0x00, // object_id = 0x999（未登记域）
            0x00, 0x00, 0x08, 0x00, // opcode 0 + size 8
        ];
        assert_eq!(s.feed(&ghost, &mut out), Err(CompError::BadObject));
        setup_registry(&mut s);
        // bind 名单外接口
        let bad_bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 9, "wl_rogue", 1, 9).unwrap();
            b[..n].to_vec()
        };
        assert_eq!(s.feed(&bad_bind, &mut out), Err(CompError::UnknownGlobal));
        // bind 版本越上界（公告 v4，bind v5）+ 版本 0
        for ver in [5u32, 0] {
            let b = {
                let mut buf = [0u8; 64];
                let n = encode_registry_bind(&mut buf, 2, 1, "wl_compositor", ver, 9).unwrap();
                buf[..n].to_vec()
            };
            assert_eq!(s.feed(&b, &mut out), Err(CompError::UnknownGlobal));
        }
        // display 域外 opcode（EV_ERROR 属客户端向事件——服务端拒收）
        let rogue = {
            let mut b = [0u8; 64];
            let n = encode_message(&mut b, 1, 7, &[WlArg::Uint(0)]).unwrap();
            b[..n].to_vec()
        };
        assert_eq!(s.feed(&rogue, &mut out), Err(CompError::UnknownRequest));
        // 会话槽满（9 surface → SurfaceFull）
        let bind_ok = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        s.feed(&bind_ok, &mut [0u8; 16]).unwrap();
        for k in 0..SESSION_SURFACES + 1 {
            let cs = {
                let mut b = [0u8; 64];
                let n = encode_message(
                    &mut b,
                    3,
                    compositor::REQ_CREATE_SURFACE,
                    &[WlArg::NewId(0x100 + k as u32)],
                )
                .unwrap();
                b[..n].to_vec()
            };
            let last = k == SESSION_SURFACES;
            match s.feed(&cs, &mut [0u8; 16]) {
                Ok(_) if !last => {}
                Err(CompError::SurfaceFull) if last => {}
                _ if last => panic!("槽满域未显形"),
                _ => {}
            }
        }
        assert_eq!(s.surfaces_count(), SESSION_SURFACES);
    }

    /// 部分消息断流：半消息 consumed=0 留缓冲，续喂全量即推进。
    #[test]
    fn partial_message_stream() {
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_sync(&mut req, 1, 9).unwrap();
        let mut out = [0u8; 64];
        // 半消息（头 + 半参域）——干净断流
        let rep = s.feed(&req[..n - 2], &mut out).unwrap();
        assert_eq!(rep.consumed, 0);
        assert!(rep.is_skip());
        // 全量续喂——推进 + done 回执 + delete_id 随行（M42-WAYCOMP18）
        let rep2 = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep2.consumed, n);
        assert_eq!(rep2.out_len, 24);
    }

    /// 多消息单流推进：sync + get_registry 双消息同批——consumed =
    /// 双消息和 + 双回执并存。
    #[test]
    fn stream_multi_message() {
        let mut s = new_session();
        let sync = {
            let mut b = [0u8; 64];
            let n = encode_display_sync(&mut b, 1, 9).unwrap();
            b[..n].to_vec()
        };
        let gregr = {
            let mut b = [0u8; 64];
            let n = encode_display_get_registry(&mut b, 1, 2).unwrap();
            b[..n].to_vec()
        };
        let stream = stream_of(&[&sync, &gregr]);
        let mut out = [0u8; 512];
        let rep = s.feed(&stream, &mut out).unwrap();
        assert_eq!(rep.consumed, stream.len());
        // 回执 = sync done(12) + delete_id(12)〔M42-WAYCOMP18 生命周期随
        // 行〕 + globals(36+28+28+32)
        assert_eq!(rep.out_len, 12 + 12 + 156);
        assert_eq!(rep.syncs, 1);
        assert_eq!(s.table().lookup(9), None, "callback done 后销毁摘除");
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
    }

    /// destroy 生命周期：对象表 + 会话槽双清（id 不复用——表纪律）。
    #[test]
    fn destroy_surface_lifecycle() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        assert_eq!(s.surfaces_count(), 1);
        let destroy = {
            let mut b = [0u8; 64];
            let n = encode_message(&mut b, 0x21, surf_ops::REQ_DESTROY, &[]).unwrap();
            b[..n].to_vec()
        };
        let rep = s.feed(&destroy, &mut [0u8; 16]).unwrap();
        assert_eq!(rep.consumed, destroy.len());
        assert_eq!(s.surfaces_count(), 0);
        assert_eq!(s.table().lookup(0x21), None);
        // 销毁后路由拒收（BadObject——不泄拓扑同面）
        assert_eq!(s.feed(&destroy, &mut [0u8; 16]), Err(CompError::BadObject));
    }

    /// attach 记账域 + 双 surface 几何注入（策略面钩子）。
    /// wl_shm 池域回环（M42-ELF5 桌面链批次）：create_pool（fd 占位字
    /// 记账）→ create_buffer → attach → commit —— 池记录批 + fd_need
    /// 计数 + buffer 几何随 commit 记录出域（客户端像素承载语义面）。
    #[test]
    fn shm_pool_buffer_commit_chain() {
        use crate::wayland::{shm, shm_pool};
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        s.feed(&req[..n], &mut [0u8; 512]).unwrap();
        // bind compositor（名 1 → new_id 3）+ bind wl_shm（名 3 → new_id 4）
        // + create_surface
        let mut batch = [0u8; 160];
        let mut bl = 0usize;
        bl += encode_registry_bind(&mut batch[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
        bl += encode_registry_bind(&mut batch[bl..], 2, 3, "wl_shm", 1, 4).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x21)],
        )
        .unwrap();
        // create_pool(pool=5, fd 占位, size=256000) + create_buffer(buf=6)
        bl += encode_message(
            &mut batch[bl..],
            4,
            shm::REQ_CREATE_POOL,
            &[WlArg::NewId(5), WlArg::Fd(0), WlArg::Int(256000)],
        )
        .unwrap();
        bl += encode_message(
            &mut batch[bl..],
            5,
            shm_pool::REQ_CREATE_BUFFER,
            &[
                WlArg::NewId(6),
                WlArg::Int(0),
                WlArg::Int(320),
                WlArg::Int(200),
                WlArg::Int(1280),
                WlArg::Uint(1),
            ],
        )
        .unwrap();
        let mut out = [0u8; 512];
        let rep = s.feed(&batch[..bl], &mut out).unwrap();
        // 池记录批 + fd_need 对账（每 create_pool 恰一 fd）
        assert_eq!(rep.pools.n, 1);
        assert_eq!(rep.fd_need, 1);
        let pool = rep.pools.items[0].unwrap();
        assert_eq!(pool.pool_wl, 5);
        assert_eq!(pool.size, 256000);
        // 对象登记域：pool=5 ShmPool / buffer=6 Buffer
        assert_eq!(s.table().lookup(5), Some(WlIface::ShmPool));
        assert_eq!(s.table().lookup(6), Some(WlIface::Buffer));
        assert_eq!(s.buffers_count(), 1);
        // buffer 几何快照（取证面）
        let buf = s.buffer(6).unwrap();
        assert_eq!(buf.pool_wl, 5);
        assert_eq!(buf.offset, 0);
        assert_eq!(buf.w, 320);
        assert_eq!(buf.h, 200);
        assert_eq!(buf.stride, 1280);
        assert_eq!(buf.format, 1);
        // attach + commit → CommitRecord.buffer 携几何出域
        let mut batch2 = [0u8; 128];
        let mut bl2 = 0usize;
        bl2 += encode_message(
            &mut batch2[bl2..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(6), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        bl2 += encode_message(
            &mut batch2[bl2..],
            0x21,
            surf_ops::REQ_DAMAGE,
            &[
                WlArg::Int(0),
                WlArg::Int(0),
                WlArg::Int(320),
                WlArg::Int(200),
            ],
        )
        .unwrap();
        bl2 += encode_surface_commit(&mut batch2[bl2..], 0x21).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let rep2 = s.feed(&batch2[..bl2], &mut out).unwrap();
        let rec = rep2.commits.last_of(0x21).unwrap();
        let b = rec.buffer.expect("commit 须携 attach buffer 几何");
        assert_eq!(b.wl, 6);
        assert_eq!(b.w, 320);
        assert_eq!(b.stride, 1280);
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 320,
                h: 200
            },
            "buffer 域损伤平移屏域 ∩ pane"
        );
    }

    /// wl_shm 负例域（M42-ELF5）：attach 未登记 buffer → BadObject；
    /// attach(null) 解附；buffer 槽满 → BufferFull；create_buffer 域外
    /// opcode 拒收。
    #[test]
    fn shm_negative_matrix() {
        use crate::wayland::{encode_surface_commit, shm, shm_pool};
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        s.feed(&req[..n], &mut [0u8; 512]).unwrap();
        let mut batch = [0u8; 128];
        let mut bl = 0usize;
        bl += encode_registry_bind(&mut batch[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x21)],
        )
        .unwrap();
        bl += encode_registry_bind(&mut batch[bl..], 2, 3, "wl_shm", 1, 4).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            4,
            shm::REQ_CREATE_POOL,
            &[WlArg::NewId(5), WlArg::Fd(0), WlArg::Int(4096)],
        )
        .unwrap();
        s.feed(&batch[..bl], &mut [0u8; 512]).unwrap();
        // attach 未登记 buffer（id 0x99）→ BadObject
        let mut bad = [0u8; 32];
        let n = encode_message(
            &mut bad,
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0x99), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        assert_eq!(
            s.feed(&bad[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::BadObject
        );
        // buffer 槽满谱：8 buffer 入账后第 9 → BufferFull
        for k in 0..SESSION_BUFFERS {
            let mut one = [0u8; 48];
            let n = encode_message(
                &mut one,
                5,
                shm_pool::REQ_CREATE_BUFFER,
                &[
                    WlArg::NewId(0x40 + k as u32),
                    WlArg::Int(0),
                    WlArg::Int(8),
                    WlArg::Int(8),
                    WlArg::Int(32),
                    WlArg::Uint(1),
                ],
            )
            .unwrap();
            s.feed(&one[..n], &mut [0u8; 16]).unwrap();
        }
        let mut one = [0u8; 48];
        let n = encode_message(
            &mut one,
            5,
            shm_pool::REQ_CREATE_BUFFER,
            &[
                WlArg::NewId(0x50),
                WlArg::Int(0),
                WlArg::Int(8),
                WlArg::Int(8),
                WlArg::Int(32),
                WlArg::Uint(1),
            ],
        )
        .unwrap();
        assert_eq!(
            s.feed(&one[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::BufferFull
        );
        // attach(null) 解附：attach 已登记 buffer → attach 0 → commit 无 buffer
        let mut pair = [0u8; 64];
        let mut pl = 0usize;
        pl += encode_message(
            &mut pair[pl..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0x40), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        pl += encode_message(
            &mut pair[pl..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        pl += encode_surface_commit(&mut pair[pl..], 0x21).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let rep = s.feed(&pair[..pl], &mut [0u8; 64]).unwrap();
        assert!(rep.commits.last_of(0x21).unwrap().buffer.is_none());
        // 域外 opcode：wl_shm resize 域外（wl_shm 无 resize——opcode 1 拒收）
        let mut bad = [0u8; 16];
        let n = encode_message(&mut bad, 4, 1, &[]).unwrap();
        assert_eq!(
            s.feed(&bad[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::UnknownRequest
        );
    }

    /// destroy 摘除记录批回执（M42-GEOM6 域①——重排改写触发源）：
    /// 单 destroy → DropLog 单记录（wl id 对账）+ 摘除后槽/表双清；
    /// 摘除后同 id commit → BadObject fail-visible（拓扑不泄）。
    #[test]
    fn destroy_drop_record() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x31)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        let destroy = {
            let mut b = [0u8; 64];
            let n = encode_message(&mut b, 0x31, surf_ops::REQ_DESTROY, &[]).unwrap();
            b[..n].to_vec()
        };
        let rep = s.feed(&destroy, &mut [0u8; 16]).unwrap();
        assert_eq!(rep.drops.n, 1, "单 destroy → 单摘除记录");
        let rec = rep.drops.items[0].expect("记录在批");
        assert_eq!(rec.wl_id, 0x31);
        assert_eq!(s.surfaces_count(), 0);
        assert_eq!(s.table().lookup(0x31), None);
        // 摘除后同 id commit → BadObject（会话槽已摘——拓扑不泄）
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x31).unwrap();
            b[..n].to_vec()
        };
        assert_eq!(
            s.feed(&commit, &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::BadObject
        );
    }

    /// 多 destroy 单流批记录（M42-GEOM6 域①——批量摘除 = 批量重排
    /// 触发源：双 surface 同批 destroy → DropLog 双记录槽序对账 +
    /// surfaces_count 归零）。
    #[test]
    fn destroy_multi_drop_batch() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 160];
            let mut bl = 0usize;
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x41)],
            )
            .unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x42)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        assert_eq!(s.surfaces_count(), 2);
        let drops = {
            let mut b = [0u8; 128];
            let mut bl = 0usize;
            bl += encode_message(&mut b[bl..], 0x41, surf_ops::REQ_DESTROY, &[]).unwrap();
            bl += encode_message(&mut b[bl..], 0x42, surf_ops::REQ_DESTROY, &[]).unwrap();
            b[..bl].to_vec()
        };
        let rep = s.feed(&drops, &mut [0u8; 16]).unwrap();
        assert_eq!(rep.drops.n, 2, "双 destroy → 双摘除记录");
        assert_eq!(rep.drops.items[0].map(|r| r.wl_id), Some(0x41));
        assert_eq!(rep.drops.items[1].map(|r| r.wl_id), Some(0x42));
        assert_eq!(s.surfaces_count(), 0);
        assert_eq!(rep.commits.n, 0, "纯摘除流零 commit 记录");
    }

    // ---- M42-INPUT7 输入链宿主测试谱（wl_seat 派生 + 焦点/击键/指针
    // ---- 事件语义 + 负例域——事实源 = 官方 wayland.xml 1.21.0） ----

    /// seat bind 能力公告 + 设备派生域。
    #[test]
    fn seat_bind_capabilities_and_devices() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 160];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_POINTER,
                &[WlArg::NewId(0x31)],
            )
            .unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        let mut out = [0u8; 256];
        let rep = s.feed(&batch, &mut out).unwrap();
        assert_eq!(rep.consumed, batch.len());
        // M42-KBREP34 笔㉞判据随行升级（官方语义：repeat_info 随键盘
        // 派生公告——keymap 后随行 +16B，t131 判据升级先例同谱）
        assert_eq!(
            rep.out_len,
            12 + 20 + 16,
            "capabilities(12) + keymap(20) + repeat_info(16)"
        );
        let m = crate::wayland::parse_message(&out, SIG_SEAT_CAPABILITIES).unwrap();
        assert_eq!(m.header.object_id, 0x30);
        assert_eq!(m.header.opcode, crate::wayland::seat::EV_CAPABILITIES);
        assert_eq!(
            m.args[0],
            Some(WlArg::Uint(
                crate::wayland::SEAT_CAPS_POINTER | crate::wayland::SEAT_CAPS_KEYBOARD
            ))
        );
        let m = crate::wayland::parse_message(&out[12..rep.out_len], SIG_KEYBOARD_KEYMAP).unwrap();
        assert_eq!(m.header.object_id, 0x32);
        assert_eq!(m.header.opcode, crate::wayland::keyboard::EV_KEYMAP);
        assert_eq!(m.args[0], Some(WlArg::Fd(0)));
        assert_eq!(
            m.args[1],
            Some(WlArg::Uint(crate::wayland::KEYMAP_FORMAT_XKB_V1))
        );
        // M42-WAYCOMP13 内容面：size = KEYMAP_XKB_V1 真实字节域 +
        // feed 回执 keymap 记录对账（电气面铸池承接域事实源）。
        assert_eq!(
            m.args[2],
            Some(WlArg::Uint(KEYMAP_XKB_V1.len() as u32)),
            "keymap size = 内容真实长度"
        );
        // M43-KBREP37 笔㊷判据随行升级（官方语义：repeat_info 公告真值域
        // ——v0 关闭声明 0/0 退役，会话域默认 25/400）。
        let m = crate::wayland::parse_message(
            &out[12 + 20..rep.out_len],
            crate::wayland::SIG_KEYBOARD_REPEAT_INFO,
        )
        .unwrap();
        assert_eq!(m.header.opcode, crate::wayland::keyboard::EV_REPEAT_INFO);
        assert_eq!(m.args[0], Some(WlArg::Uint(25)), "默认 rate = 25 chars/s");
        assert_eq!(m.args[1], Some(WlArg::Uint(400)), "默认 delay = 400 ms");
        assert_eq!(
            rep.keymaps,
            Some(KeymapRecord {
                keyboard_id: 0x32,
                size: KEYMAP_XKB_V1.len() as u32
            })
        );
        assert!(KEYMAP_XKB_V1.starts_with(b"xkb_keymap {"), "xkb v1 内容壳");
        assert_eq!(s.table().lookup(0x30), Some(WlIface::Seat));
        assert_eq!(s.table().lookup(0x31), Some(WlIface::Pointer));
        assert_eq!(s.table().lookup(0x32), Some(WlIface::Keyboard));
        assert_eq!(s.pointer_object(), 0x31);
        assert_eq!(s.keyboard_object(), 0x32);
    }

    /// 键盘焦点 + 击键冲刷链。
    #[test]
    fn keyboard_focus_inject_flush_chain() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 224];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_keyboard_focus(0x21).unwrap();
        assert_eq!(s.keyboard_focus(), 0x21);
        s.keyboard_inject(0x02, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        s.keyboard_inject(0x02, crate::wayland::KEY_STATE_RELEASED)
            .unwrap();
        let mut out = [0u8; 160];
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.consumed, 0);
        // M42-WAYCOMP15：enter 域 modifiers 快照随行（官方语义——修饰
        // 键态事件随后 enter 交付）→ 记录批 = enter + modifiers + key ×2
        assert_eq!(rep.keys.n, 4, "enter + modifiers + key ×2 记录批");
        assert_eq!(
            rep.out_len,
            20 + 28 + 24 + 24,
            "enter(20) + modifiers(28) + key(24) ×2 回执"
        );
        let m = crate::wayland::parse_message(&out, SIG_KEYBOARD_ENTER).unwrap();
        assert_eq!(m.header.object_id, 0x32);
        assert_eq!(m.header.opcode, crate::wayland::keyboard::EV_ENTER);
        assert_eq!(m.args[0], Some(WlArg::Uint(1)), "串号 1 起步（单调域）");
        assert_eq!(m.args[1], Some(WlArg::Object(0x21)));
        assert_eq!(m.args[2], Some(WlArg::Array(&[])), "v0 空 keys 数组");
        let m = crate::wayland::parse_message(&out[20..], crate::wayland::SIG_KEYBOARD_MODIFIERS)
            .unwrap();
        assert_eq!(m.header.opcode, crate::wayland::keyboard::EV_MODIFIERS);
        assert_eq!(m.args[0], Some(WlArg::Uint(2)), "快照串号随行");
        assert_eq!(
            m.args[1],
            Some(WlArg::Uint(0)),
            "初值域零掩码（v0 全零快照）"
        );
        let m = crate::wayland::parse_message(&out[48..], SIG_KEYBOARD_KEY).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::keyboard::EV_KEY);
        assert_eq!(m.args[2], Some(WlArg::Uint(0x02)));
        assert_eq!(
            m.args[3],
            Some(WlArg::Uint(crate::wayland::KEY_STATE_PRESSED))
        );
        let m = crate::wayland::parse_message(&out[48 + 24..], SIG_KEYBOARD_KEY).unwrap();
        assert_eq!(
            m.args[3],
            Some(WlArg::Uint(crate::wayland::KEY_STATE_RELEASED))
        );
        assert_eq!(rep.keys.items[0].map(|r| r.kind), Some(KbKind::Enter));
        assert_eq!(
            rep.keys.items[1].map(|r| r.kind),
            Some(KbKind::Modifiers),
            "enter 域 modifiers 快照随行（M42-WAYCOMP15）"
        );
        assert_eq!(rep.keys.items[2].map(|r| (r.key, r.state)), Some((0x02, 1)));
        assert_eq!(rep.keys.items[3].map(|r| (r.key, r.state)), Some((0x02, 0)));
    }

    /// M43-AV12036 axis_value120 冲刷链（wheel 源 frame 域随行——官方
    /// 序 axis_source → axis → axis_value120 → frame 同 frame 出域，
    /// value120 = 120 倍步进原字 int 透传）。
    #[test]
    fn pointer_axis_value120_flush_chain() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 160];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_POINTER,
                &[WlArg::NewId(0x31)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_pointer_focus(0x21, 8, 8).unwrap();
        s.pointer_axis_source(crate::wayland::AXIS_SOURCE_WHEEL)
            .unwrap();
        s.pointer_axis(crate::wayland::AXIS_VERTICAL_SCROLL, 120)
            .unwrap();
        s.pointer_axis_value120(crate::wayland::AXIS_VERTICAL_SCROLL, 120)
            .unwrap();
        s.pointer_frame().unwrap();
        let mut out = [0u8; 256];
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(
            rep.ptrs.n, 5,
            "enter + axis_source + axis + value120 + frame 记录批"
        );
        assert_eq!(
            rep.out_len,
            24 + 12 + 20 + 16 + 8,
            "enter(24·带 x/y) + axis_source(12) + axis(20) + value120(16) + frame(8)"
        );
        let m = crate::wayland::parse_message(&out, crate::wayland::SIG_POINTER_ENTER).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_ENTER);
        let m = crate::wayland::parse_message(&out[24..], crate::wayland::SIG_POINTER_AXIS_SOURCE)
            .unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_AXIS_SOURCE);
        let m =
            crate::wayland::parse_message(&out[36..], crate::wayland::SIG_POINTER_AXIS).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_AXIS);
        // value120 紧随 axis（官方序——同 frame 域随行声明）
        let m =
            crate::wayland::parse_message(&out[56..], crate::wayland::SIG_POINTER_AXIS_VALUE120)
                .unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_AXIS_VALUE120);
        assert_eq!(
            m.args[0],
            Some(WlArg::Uint(crate::wayland::AXIS_VERTICAL_SCROLL))
        );
        assert_eq!(m.args[1], Some(WlArg::Int(120)), "120 倍步进原字");
        let m =
            crate::wayland::parse_message(&out[72..], crate::wayland::SIG_POINTER_FRAME).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_FRAME);
    }

    /// M43-KBREP37 键重复语义核链（登记/撤销 + delay/rate 步进追产 +
    /// 修饰键零登记 + 焦点丢失撤销 + 关闭域）。
    #[test]
    fn keyboard_repeat_core_chain() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 192];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_keyboard_focus(0x21).unwrap();
        // 默认域 + 配置域（rate 域外 clamp）
        assert_eq!(s.repeat_info(), (25, 400), "默认 25/400");
        s.set_repeat_info(50, 20);
        assert_eq!(s.repeat_info(), (50, 20));
        s.set_repeat_info(500, 9999);
        assert_eq!(s.repeat_info(), (100, 2000), "rate/delay 域外 clamp");
        s.set_repeat_info(50, 20);
        // 按下 'a'（wl 30 = evdev 22——非修饰键）→ 登记 rep_key
        s.keyboard_inject(30, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        // delay 未到零产
        assert_eq!(s.repeat_tick(19), 0, "delay 未到零产");
        // delay 到点产 1（state = PRESSED 重复）
        assert_eq!(s.repeat_tick(20), 1);
        s.feed(&[], &mut [0u8; 256]).unwrap(); // 冲刷清队列（容量域复位）
                                               // rate 步进 1000/50 = 20ms
        assert_eq!(s.repeat_tick(39), 0);
        assert_eq!(s.repeat_tick(40), 1);
        s.feed(&[], &mut [0u8; 256]).unwrap();
        // 多拍追产（now >> next——上限 8）
        assert_eq!(s.repeat_tick(1000), 8, "追产上限 8");
        s.feed(&[], &mut [0u8; 256]).unwrap();
        // 修饰键零登记（Shift 按下不扰动 rep_key——重复域继续）
        s.keyboard_inject(50, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        assert_eq!(s.repeat_tick(250), 2, "修饰键按下不撤销重复域");
        s.feed(&[], &mut [0u8; 256]).unwrap();
        // 释放撤销
        s.keyboard_inject(30, crate::wayland::KEY_STATE_RELEASED)
            .unwrap();
        assert!(!s.repeat_pending(), "释放撤销登记");
        assert_eq!(s.repeat_tick(5000), 0, "撤销后零产");
        // 关闭域（rate=0 官方 no-repeat）
        s.keyboard_inject(31, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        s.set_repeat_info(0, 0);
        assert!(!s.repeat_pending(), "rate=0 关闭域");
        assert_eq!(s.repeat_tick(9000), 0, "关闭域零产");
    }

    /// M43-KBREP37 set_cursor 请求域（回执记录批 + surface 在册闸 +
    /// 默认光标回退域 surface=0）。
    #[test]
    fn keyboard_set_cursor_dispatch() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 192];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        // set_cursor 目标面在册（hotspot (3,5)）→ 回执记录批
        let req = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x32,
                keyboard_req::REQ_SET_CURSOR,
                &[
                    WlArg::Uint(9),
                    WlArg::Object(0x21),
                    WlArg::Int(3),
                    WlArg::Int(5),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let mut out = [0u8; 64];
        let rep = s.feed(&req, &mut out).unwrap();
        assert_eq!(rep.consumed, req.len());
        assert_eq!(rep.keys.n, 1, "set_cursor 回执恰一笔");
        let r = rep.keys.items[0].unwrap();
        assert_eq!(r.kind, KbKind::SetCursor);
        assert_eq!(r.surface, 0x21);
        assert_eq!(r.key, 3, "hotspot_x 复用域");
        assert_eq!(r.state, 5, "hotspot_y 复用域");
        // surface = 0 默认光标回退域（合法）
        let req0 = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x32,
                keyboard_req::REQ_SET_CURSOR,
                &[
                    WlArg::Uint(10),
                    WlArg::Object(0),
                    WlArg::Int(0),
                    WlArg::Int(0),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let rep2 = s.feed(&req0, &mut [0u8; 64]).unwrap();
        assert_eq!(rep2.keys.n, 1);
        assert_eq!(rep2.keys.items[0].unwrap().surface, 0, "默认光标回退域");
        // 目标面不在册 = BadObject fail-visible（feed Err 透传）
        let bad = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x32,
                keyboard_req::REQ_SET_CURSOR,
                &[
                    WlArg::Uint(11),
                    WlArg::Object(0x99),
                    WlArg::Int(0),
                    WlArg::Int(0),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        assert!(s.feed(&bad, &mut [0u8; 64]).is_err(), "不在册面拒收");
    }

    /// 修饰键语义核链（M42-WAYCOMP15——Shift 位域 ∪/∖ + CapsLock
    /// locked 翻转存续 + 非修饰键零变更域 + 组合键掩码累积）。
    #[test]
    fn modifiers_semantics_chain() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 192];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_keyboard_focus(0x21).unwrap();

        // Shift 按下（wl 50 = evdev 42）→ depressed = MOD_SHIFT
        s.keyboard_inject(50, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        let mut out = [0u8; 128];
        let rep = s.feed(&[], &mut out).unwrap();
        // 尾序 modifiers 记录（enter 快照随行在前——语义核记录取尾序）
        let mrec = rep.keys.items[..rep.keys.n]
            .iter()
            .flatten()
            .rev()
            .find(|r| r.kind == KbKind::Modifiers);
        assert_eq!(
            mrec.map(|r| r.mods_d),
            Some(crate::wayland::MOD_SHIFT),
            "Shift 位域 ∪"
        );
        assert_eq!(s.modifiers_snapshot(), (crate::wayland::MOD_SHIFT, 0, 0, 0));
        // 非修饰键（wl 54 = evdev 46 KEY_C）按下 → 零变更域（零
        // modifiers 事件）
        s.keyboard_inject(54, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        let rep = s.feed(&[], &mut [0u8; 64]).unwrap();
        assert!(
            !rep.keys.items[..rep.keys.n]
                .iter()
                .flatten()
                .any(|r| r.kind == KbKind::Modifiers),
            "非修饰键零变更域"
        );
        // 组合键累积：Ctrl（wl 37 = evdev 29）按下 → depressed = CTRL|SHIFT
        s.keyboard_inject(37, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        assert_eq!(
            s.modifiers_snapshot().0,
            crate::wayland::MOD_CTRL | crate::wayland::MOD_SHIFT,
            "组合键掩码累积"
        );
        // Shift 释放 → depressed = MOD_CTRL（Shift 位域 ∖）
        s.keyboard_inject(50, crate::wayland::KEY_STATE_RELEASED)
            .unwrap();
        assert_eq!(s.modifiers_snapshot().0, crate::wayland::MOD_CTRL);
        s.keyboard_inject(37, crate::wayland::KEY_STATE_RELEASED)
            .unwrap();
        assert_eq!(s.modifiers_snapshot().0, 0, "全谱清零");
        let _ = s.feed(&[], &mut [0u8; 256]).unwrap(); // 队列冲刷（容量域）

        // CapsLock（wl 66 = evdev 58）按下 → depressed = CAPS ∧ locked 翻转
        s.keyboard_inject(66, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        assert_eq!(
            s.modifiers_snapshot(),
            (crate::wayland::MOD_CAPS, 0, crate::wayland::MOD_CAPS, 0),
            "Lock 键按下：depressed ∧ locked 双域"
        );
        // CapsLock 释放 → depressed 清零，locked 存续（官方语义——
        // Lock 态持续至再翻转）
        s.keyboard_inject(66, crate::wayland::KEY_STATE_RELEASED)
            .unwrap();
        assert_eq!(
            s.modifiers_snapshot(),
            (0, 0, crate::wayland::MOD_CAPS, 0),
            "locked 存续域"
        );
        // CapsLock 再按下 → locked 翻转归零
        s.keyboard_inject(66, crate::wayland::KEY_STATE_PRESSED)
            .unwrap();
        assert_eq!(s.modifiers_snapshot().2, 0, "locked 再翻转归零");
    }

    /// 指针焦点/移动/按键链。
    #[test]
    fn pointer_focus_motion_button_chain() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 224];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_POINTER,
                &[WlArg::NewId(0x31)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_pointer_focus(0x21, 32 << 8, 64 << 8).unwrap();
        assert_eq!(s.pointer_focus(), 0x21);
        s.pointer_motion(40 << 8, 80 << 8).unwrap();
        s.pointer_button(crate::wayland::BTN_LEFT, crate::wayland::BTN_STATE_PRESSED)
            .unwrap();
        let mut out = [0u8; 128];
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.ptrs.n, 3, "enter + motion + button 记录批");
        assert_eq!(
            rep.out_len,
            24 + 20 + 24,
            "enter(24) + motion(20) + button(24)"
        );
        let m = crate::wayland::parse_message(&out, SIG_POINTER_ENTER).unwrap();
        assert_eq!(m.header.object_id, 0x31);
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_ENTER);
        assert_eq!(m.args[1], Some(WlArg::Object(0x21)));
        assert_eq!(m.args[2], Some(WlArg::Fixed(32 << 8)));
        let m = crate::wayland::parse_message(&out[24..], SIG_POINTER_MOTION).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_MOTION);
        assert_eq!(m.args[1], Some(WlArg::Fixed(40 << 8)));
        let m = crate::wayland::parse_message(&out[24 + 20..], SIG_POINTER_BUTTON).unwrap();
        assert_eq!(m.header.opcode, crate::wayland::pointer::EV_BUTTON);
        assert_eq!(m.args[2], Some(WlArg::Uint(crate::wayland::BTN_LEFT)));
        assert_eq!(
            m.args[3],
            Some(WlArg::Uint(crate::wayland::BTN_STATE_PRESSED))
        );
        assert_eq!(rep.ptrs.items[0].map(|r| r.kind), Some(PtrKind::Enter));
        assert_eq!(rep.ptrs.items[1].map(|r| r.kind), Some(PtrKind::Motion));
        assert_eq!(
            rep.ptrs.items[2].map(|r| (r.button, r.state)),
            Some((0x110, 1))
        );
    }

    /// 焦点面 destroy → leave 事件入域（flush 先行于 dispatch——双 feed 断言）。
    #[test]
    fn focus_destroy_emits_leave() {
        let mut s = new_session();
        setup_registry(&mut s);
        let batch = {
            let mut b = [0u8; 224];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_POINTER,
                &[WlArg::NewId(0x31)],
            )
            .unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        s.set_keyboard_focus(0x21).unwrap();
        s.set_pointer_focus(0x21, 0, 0).unwrap();
        let drop = {
            let mut b = [0u8; 16];
            let n = encode_message(&mut b, 0x21, surf_ops::REQ_DESTROY, &[]).unwrap();
            b[..n].to_vec()
        };
        let mut out = [0u8; 128];
        let rep = s.feed(&drop, &mut out).unwrap();
        assert_eq!(rep.drops.n, 1);
        assert_eq!(s.keyboard_focus(), 0, "键盘焦点清零");
        assert_eq!(s.pointer_focus(), 0, "指针焦点清零");
        // M43-KBREP37 判据随行升级（官方语义：destroy 摘除 leave 同批
        // 响应出域——派生回执二次冲刷后 leave 不再滞留至下一 feed）。
        assert_eq!(
            rep.keys.n, 3,
            "kb Enter + modifiers 快照 + destroy 摘除 leave 同批（M43-KBREP37）"
        );
        assert_eq!(
            rep.ptrs.n, 2,
            "ptr Enter（焦点 set 残队）+ destroy 摘除 leave 同批"
        );
        assert_eq!(rep.keys.items[2].map(|r| r.kind), Some(KbKind::Leave));
        assert_eq!(rep.ptrs.items[1].map(|r| r.kind), Some(PtrKind::Leave));
        let mut out2 = [0u8; 128];
        let rep2 = s.feed(&[], &mut out2).unwrap();
        assert_eq!(rep2.keys.n, 0, "摘除域已同批出（二次冲刷）");
        assert_eq!(rep2.ptrs.n, 0);
        assert_eq!(rep.keys.items[2].map(|r| r.surface), Some(0x21));
    }

    /// 输入链负例域。
    #[test]
    fn input_gates_negative() {
        let mut s = new_session();
        setup_registry(&mut s);
        assert_eq!(s.set_keyboard_focus(0x21), Err(CompError::BadObject));
        assert_eq!(s.keyboard_inject(1, 1), Err(CompError::BadObject));
        assert_eq!(s.pointer_button(0x110, 1), Err(CompError::BadObject));
        assert_eq!(s.set_pointer_focus(0x21, 0, 0), Err(CompError::BadObject));
        let batch = {
            let mut b = [0u8; 224];
            let mut bl = 0usize;
            bl += encode_registry_bind(&mut b[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
            bl += encode_message(
                &mut b[bl..],
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            bl += encode_registry_bind(&mut b[bl..], 2, 2, "wl_seat", 1, 0x30).unwrap();
            bl += encode_message(
                &mut b[bl..],
                0x30,
                seat::REQ_GET_KEYBOARD,
                &[WlArg::NewId(0x32)],
            )
            .unwrap();
            b[..bl].to_vec()
        };
        s.feed(&batch, &mut [0u8; 256]).unwrap();
        assert_eq!(s.set_keyboard_focus(0x99), Err(CompError::BadObject));
        assert_eq!(s.keyboard_focus(), 0);
        assert_eq!(s.keyboard_inject(1, 1), Err(CompError::BadObject));
        s.set_keyboard_focus(0x21).unwrap();
        s.feed(&[], &mut [0u8; 64]).unwrap(); // Enter 冲净——容量复位
        for i in 0..INPUT_Q_MAX {
            assert_eq!(s.keyboard_inject(0x10 + i as u32, 1), Ok(()));
        }
        assert_eq!(s.keyboard_inject(0x99, 1), Err(CompError::InputQFull));
        let mut out = [0u8; 512];
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.keys.n, INPUT_Q_MAX);
        assert_eq!(s.keyboard_inject(0xAA, 1), Ok(()));
    }

    /// xdg_shell 电气闭环全谱（M50-XDGSHELL67 笔77——真实编码字节双向
    /// 回环：bind → get_xdg_surface → get_toplevel → configure 对出域
    /// → ack → commit 闸 → set_title 承载 → close 车道 → destroy 收
    /// 场；负例域全谱 fail-visible）。
    #[test]
    fn xdg_shell_loop_face() {
        use crate::wayland::{
            encode_xdg_surface_ack_configure, encode_xdg_surface_get_toplevel,
            encode_xdg_toplevel_set_title, encode_xdg_wm_base_get_xdg_surface,
            encode_xdg_wm_base_pong, xdg_surface as xs, xdg_toplevel as xt,
            SIG_XDG_SURFACE_CONFIGURE, SIG_XDG_TOPLEVEL_CLOSE, SIG_XDG_TOPLEVEL_CONFIGURE,
        };
        let mut s = new_session();
        let mut out = [0u8; 512];

        // (a) 前置链域：get_registry + 三 bind（compositor / xdg_wm_base）+
        //     create_surface
        setup_registry(&mut s);
        let mut req = [0u8; 128];
        let mut n = 0usize;
        n += encode_registry_bind(&mut req[n..], 2, 1, "wl_compositor", 4, 3).unwrap();
        n += encode_registry_bind(&mut req[n..], 2, 5, "xdg_wm_base", 1, 0x71).unwrap();
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x60)],
        )
        .unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        assert_eq!(rep.out_len, 0, "bind 无事件域（seat 除外）");
        assert_eq!(s.table().lookup(0x71), Some(WlIface::XdgWmBase));

        // (b) 角色派生对：get_xdg_surface(0x61←0x60) + get_toplevel(0x62)
        //     → 初始 configure 对出域（12 + 20 = 32 B）
        let mut n2 = 0usize;
        n2 += encode_xdg_wm_base_get_xdg_surface(&mut req[n2..], 0x71, 0x61, 0x60).unwrap();
        n2 += encode_xdg_surface_get_toplevel(&mut req[n2..], 0x61, 0x62).unwrap();
        let rep = s.feed(&req[..n2], &mut out).unwrap();
        assert_eq!(rep.consumed, n2);
        assert_eq!(rep.out_len, 12 + 20, "初始 configure 对 32 B");
        let m = crate::wayland::parse_message(&out[..12], SIG_XDG_SURFACE_CONFIGURE).unwrap();
        assert_eq!(m.header.object_id, 0x61);
        assert_eq!(m.header.opcode, xs::EV_CONFIGURE);
        let ser = match m.args[0] {
            Some(WlArg::Uint(v)) => v,
            _ => panic!("configure serial"),
        };
        let m = crate::wayland::parse_message(&out[12..32], SIG_XDG_TOPLEVEL_CONFIGURE).unwrap();
        assert_eq!(m.header.object_id, 0x62);
        assert_eq!(m.header.opcode, xt::EV_CONFIGURE);
        assert_eq!(
            m.args[0],
            Some(WlArg::Int(0)),
            "初始几何零值 = 服务端策略自主"
        );
        assert_eq!(m.args[1], Some(WlArg::Int(0)));

        // (c) commit 闸：未 ack 即 commit → XdgUnacked fail-visible
        let mut n3 = 0usize;
        n3 += encode_surface_commit(&mut req[n3..], 0x60).unwrap();
        assert_eq!(s.feed(&req[..n3], &mut out), Err(CompError::XdgUnacked));

        // (d) ack 串号域：错串号 → XdgBadSerial；对串号放行
        let mut n4 = 0usize;
        n4 += encode_xdg_surface_ack_configure(&mut req[n4..], 0x61, ser.wrapping_add(1)).unwrap();
        assert_eq!(s.feed(&req[..n4], &mut out), Err(CompError::XdgBadSerial));
        let n4 = encode_xdg_surface_ack_configure(&mut req, 0x61, ser).unwrap();
        s.feed(&req[..n4], &mut out).unwrap();
        let sf = s.surface(0x60).unwrap();
        assert!(sf.acked && sf.config_serial == ser);

        // (e) commit → 映射（mapped 位 + 表存续）
        s.feed(&req[..n3], &mut out).unwrap();
        assert!(s.surface(0x60).unwrap().mapped);
        assert_eq!(s.table().lookup(0x62), Some(WlIface::XdgToplevel));

        // (f) set_title 承载域（标题 + app_id）
        let n5 = encode_xdg_toplevel_set_title(&mut req, 0x62, "LUMINA-APP").unwrap();
        s.feed(&req[..n5], &mut out).unwrap();
        let sf = s.surface(0x60).unwrap();
        assert_eq!(&sf.title[..sf.title_n], b"LUMINA-APP");

        // (g) close 车道：request_close 入队 → 空流 feed 冲刷 close 事件
        //     （8 B）+ closes 计数；对象域闸（非 toplevel 拒）
        assert_eq!(s.request_close(0x61), Err(CompError::BadObject));
        s.request_close(0x62).unwrap();
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.out_len, 8, "close 事件 8 B");
        assert_eq!(rep.closes, 1);
        let m = crate::wayland::parse_message(&out[..8], SIG_XDG_TOPLEVEL_CLOSE).unwrap();
        assert_eq!(m.header.object_id, 0x62);
        assert_eq!(m.header.opcode, xt::EV_CLOSE);

        // (h) ping/pong 车道：send_ping 即时出域 + 串号对账；错串号拒
        let ser_p = s.send_ping(&mut out).unwrap();
        let m = crate::wayland::parse_message(&out[..12], crate::wayland::SIG_XDG_WM_BASE_PING)
            .unwrap();
        assert_eq!(m.header.object_id, 0x71);
        assert_eq!(m.args[0], Some(WlArg::Uint(ser_p)));
        let n6 = encode_xdg_wm_base_pong(&mut req, 0x71, ser_p.wrapping_add(1)).unwrap();
        assert_eq!(s.feed(&req[..n6], &mut out), Err(CompError::XdgBadSerial));
        let n6 = encode_xdg_wm_base_pong(&mut req, 0x71, ser_p).unwrap();
        s.feed(&req[..n6], &mut out).unwrap();

        // (i) 负例域：角色单占（二次 get_xdg_surface / 二次 get_toplevel）
        //     + 非在册 surface 派生
        let n7 = encode_xdg_wm_base_get_xdg_surface(&mut req, 0x71, 0x63, 0x60).unwrap();
        assert_eq!(s.feed(&req[..n7], &mut out), Err(CompError::XdgRoleBusy));
        let n7 = encode_xdg_wm_base_get_xdg_surface(&mut req, 0x71, 0x63, 0x99).unwrap();
        assert_eq!(s.feed(&req[..n7], &mut out), Err(CompError::BadObject));

        // (j) 收场：xdg_surface destroy（角色摘除）→ surface destroy
        //     （槽位 + 表双清）
        let n8 = encode_message(&mut req, 0x61, xs::REQ_DESTROY, &[]).unwrap();
        s.feed(&req[..n8], &mut out).unwrap();
        assert_eq!(s.table().lookup(0x61), None);
        assert_eq!(s.surface(0x60).unwrap().xdg_surf, 0, "角色摘除域");
        let n8 = encode_message(&mut req, 0x60, surface::REQ_DESTROY, &[]).unwrap();
        s.feed(&req[..n8], &mut out).unwrap();
        assert!(s.surface(0x60).is_none());
    }

    /// xdg_popup 尺寸交互族电气回环（M51-XDGPOP75 笔86——positioner
    /// 语义核 + popup 角色派生 + configure 出域 + grab 记账 + min/max
    /// 承载 + size-configure 车道 + popup_done 车道 + NEG 全谱）。
    #[test]
    fn xdg_popup_loop_face() {
        use crate::wayland::{
            encode_registry_bind, encode_xdg_positioner_set_anchor,
            encode_xdg_positioner_set_anchor_rect, encode_xdg_positioner_set_constraint_adjustment,
            encode_xdg_positioner_set_gravity, encode_xdg_positioner_set_offset,
            encode_xdg_positioner_set_size, encode_xdg_surface_ack_configure,
            encode_xdg_surface_get_popup, encode_xdg_surface_get_toplevel,
            encode_xdg_toplevel_set_max_size, encode_xdg_toplevel_set_min_size,
            encode_xdg_wm_base_create_positioner, encode_xdg_wm_base_get_xdg_surface,
            xdg_popup as xp, xdg_positioner as xpo, SIG_XDG_POPUP_CONFIGURE,
            SIG_XDG_POPUP_POPUP_DONE, SIG_XDG_SURFACE_CONFIGURE, SIG_XDG_TOPLEVEL_CONFIGURE,
        };
        let mut s = new_session();
        let mut out = [0u8; 512];

        // (a) 前置链域：get_registry + 四 bind（compositor / seat /
        //     xdg_wm_base）+ 双 create_surface（父 0x60 / 子 0x66）
        setup_registry(&mut s);
        let mut req = [0u8; 192];
        let mut n = 0usize;
        n += encode_registry_bind(&mut req[n..], 2, 1, "wl_compositor", 4, 3).unwrap();
        n += encode_registry_bind(&mut req[n..], 2, 2, "wl_seat", 1, 0x65).unwrap();
        n += encode_registry_bind(&mut req[n..], 2, 5, "xdg_wm_base", 1, 0x71).unwrap();
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x60)],
        )
        .unwrap();
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x66)],
        )
        .unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        assert_eq!(
            rep.out_len, 12,
            "seat bind 附带 capabilities 事件（官方语义）"
        );

        // (b) 父链：get_xdg_surface(0x61←0x60) + get_toplevel(0x62) →
        //     初始 configure 对 32 B → ack 最近串号
        let mut n2 = 0usize;
        n2 += encode_xdg_wm_base_get_xdg_surface(&mut req[n2..], 0x71, 0x61, 0x60).unwrap();
        n2 += encode_xdg_surface_get_toplevel(&mut req[n2..], 0x61, 0x62).unwrap();
        let rep = s.feed(&req[..n2], &mut out).unwrap();
        assert_eq!(rep.out_len, 12 + 20, "初始 configure 对 32 B");
        let m = crate::wayland::parse_message(&out[..12], SIG_XDG_SURFACE_CONFIGURE).unwrap();
        let Some(WlArg::Uint(ser0)) = m.args[0] else {
            panic!("surface configure 串号");
        };
        let m = crate::wayland::parse_message(&out[12..32], SIG_XDG_TOPLEVEL_CONFIGURE).unwrap();
        assert_eq!(m.header.object_id, 0x62);
        assert_eq!(m.args[0], Some(WlArg::Int(0)));
        let mut n3 = 0usize;
        n3 += encode_xdg_surface_ack_configure(&mut req, 0x61, ser0).unwrap();
        s.feed(&req[..n3], &mut out).unwrap();
        assert_eq!(s.surface_acked(0x60), Some(true));

        // (c) positioner 语义核：create_positioner(0x63) + 六 setter
        //     全谱 → 无事件域（out_len 0）
        let mut n4 = 0usize;
        n4 += encode_xdg_wm_base_create_positioner(&mut req[n4..], 0x71, 0x63).unwrap();
        n4 += encode_xdg_positioner_set_size(&mut req[n4..], 0x63, 200, 80).unwrap();
        n4 += encode_xdg_positioner_set_anchor_rect(&mut req[n4..], 0x63, 10, 20, 100, 40).unwrap();
        n4 += encode_xdg_positioner_set_anchor(&mut req[n4..], 0x63, 7).unwrap();
        n4 += encode_xdg_positioner_set_gravity(&mut req[n4..], 0x63, 2).unwrap();
        n4 += encode_xdg_positioner_set_constraint_adjustment(&mut req[n4..], 0x63, 3).unwrap();
        n4 += encode_xdg_positioner_set_offset(&mut req[n4..], 0x63, 4, 8).unwrap();
        let rep = s.feed(&req[..n4], &mut out).unwrap();
        assert_eq!(rep.consumed, n4);
        assert_eq!(rep.out_len, 0, "setter 全谱无事件");

        // (d) popup 派生：子链 get_xdg_surface(0x67←0x66) +
        //     get_popup(0x68←0x67, parent 0x61, pos 0x63) → popup
        //     configure 16 B 出域（placement 金值 (14, 28)）
        let mut n5 = 0usize;
        n5 += encode_xdg_wm_base_get_xdg_surface(&mut req[n5..], 0x71, 0x67, 0x66).unwrap();
        n5 += encode_xdg_surface_get_popup(&mut req[n5..], 0x67, 0x68, 0x61, 0x63).unwrap();
        let rep = s.feed(&req[..n5], &mut out).unwrap();
        assert_eq!(rep.consumed, n5);
        assert_eq!(rep.out_len, 16, "popup configure 16 B");
        let m = crate::wayland::parse_message(&out[..16], SIG_XDG_POPUP_CONFIGURE).unwrap();
        assert_eq!(m.header.object_id, 0x68);
        assert_eq!(m.header.opcode, xp::EV_CONFIGURE);
        assert_eq!(m.args[0], Some(WlArg::Int(14)), "placement 语义核金值");
        assert_eq!(m.args[1], Some(WlArg::Int(28)));
        assert_eq!(s.surface_popup(0x66), Some((0x68, 14, 28, 200, 80)));

        // (e) grab 记账域：seat 0x65 在册 → 放行；非 seat 对象 →
        //     BadObject fail-visible
        let n6 = encode_message(
            &mut req,
            0x68,
            xp::REQ_GRAB,
            &[WlArg::Object(0x65), WlArg::Uint(5)],
        )
        .unwrap();
        s.feed(&req[..n6], &mut out).unwrap();
        assert!(s.surface(0x66).unwrap().popup_grabbed, "grab 记账位");
        let n6 = encode_message(
            &mut req,
            0x68,
            xp::REQ_GRAB,
            &[WlArg::Object(0x99), WlArg::Uint(5)],
        )
        .unwrap();
        assert_eq!(s.feed(&req[..n6], &mut out), Err(CompError::BadObject));

        // (f) min/max 承载域：set_min_size(400,200) + set_max_size(
        //     1600,900) → 取证面金值
        let mut n7 = 0usize;
        n7 += encode_xdg_toplevel_set_min_size(&mut req[n7..], 0x62, 400, 200).unwrap();
        n7 += encode_xdg_toplevel_set_max_size(&mut req[n7..], 0x62, 1600, 900).unwrap();
        s.feed(&req[..n7], &mut out).unwrap();
        assert_eq!(s.surface_minmax(0x60), Some((400, 200, 1600, 900)));

        // (g) size-configure 车道：request_configure(960,540) → 空流
        //     feed 冲刷 configure 对 32 B（串号铸造 + 未 ack 位铸造）
        s.request_configure(0x60, 960, 540).unwrap();
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.out_len, 12 + 20, "size-configure 对 32 B");
        assert_eq!(rep.configs, 1);
        let m = crate::wayland::parse_message(&out[..12], SIG_XDG_SURFACE_CONFIGURE).unwrap();
        let Some(WlArg::Uint(ser1)) = m.args[0] else {
            panic!("size configure 串号");
        };
        assert_eq!(ser1, ser0.wrapping_add(1), "串号单调铸造");
        let m = crate::wayland::parse_message(&out[12..32], SIG_XDG_TOPLEVEL_CONFIGURE).unwrap();
        assert_eq!(
            m.args[0],
            Some(WlArg::Int(960)),
            "configure 非零值 = 客户端应重定窗"
        );
        assert_eq!(m.args[1], Some(WlArg::Int(540)));
        assert_eq!(s.surface_acked(0x60), Some(false), "未 ack 位铸造");
        //     last-wins 覆盖：同窗重入队 → 单对出域（640×480）
        s.request_configure(0x60, 800, 600).unwrap();
        s.request_configure(0x60, 640, 480).unwrap();
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.configs, 1, "last-wins 覆盖");
        let m = crate::wayland::parse_message(&out[12..32], SIG_XDG_TOPLEVEL_CONFIGURE).unwrap();
        assert_eq!(m.args[0], Some(WlArg::Int(640)));
        assert_eq!(m.args[1], Some(WlArg::Int(480)));

        // (h) popup_done 车道：request_popup_done_for_parent(0x62) →
        //     空流 feed 冲刷 popup_done 8 B；无 popup 父面 = BadObject
        s.request_popup_done_for_parent(0x62).unwrap();
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.out_len, 8, "popup_done 8 B");
        assert_eq!(rep.popup_dones, 1);
        let m = crate::wayland::parse_message(&out[..8], SIG_XDG_POPUP_POPUP_DONE).unwrap();
        assert_eq!(m.header.object_id, 0x68);
        assert_eq!(m.header.opcode, xp::EV_POPUP_DONE);
        assert_eq!(
            s.request_popup_done_for_parent(0x66),
            Err(CompError::BadObject),
            "无 popup 父面 fail-visible"
        );

        // (i) NEG 谱①：不完整 positioner（仅 set_size）→ get_popup
        //     XdgPosIncomplete；未知 positioner → BadObject；枚举越界
        //     → XdgBadEnum；toplevel 缺位父 → XdgRoleBusy
        let mut n9 = 0usize;
        n9 += encode_xdg_wm_base_create_positioner(&mut req[n9..], 0x71, 0x64).unwrap();
        n9 += encode_xdg_positioner_set_size(&mut req[n9..], 0x64, 100, 40).unwrap();
        s.feed(&req[..n9], &mut out).unwrap();
        let n9 = encode_xdg_surface_get_popup(&mut req, 0x67, 0x69, 0x61, 0x64).unwrap();
        assert_eq!(
            s.feed(&req[..n9], &mut out),
            Err(CompError::XdgPosIncomplete),
            "完整性闸（官方契约）"
        );
        let n9 = encode_xdg_surface_get_popup(&mut req, 0x67, 0x69, 0x61, 0x7F).unwrap();
        assert_eq!(s.feed(&req[..n9], &mut out), Err(CompError::BadObject));
        let n9 = encode_xdg_positioner_set_anchor(&mut req, 0x63, 9).unwrap();
        assert_eq!(s.feed(&req[..n9], &mut out), Err(CompError::XdgBadEnum));
        let mut n10 = 0usize;
        n10 += encode_message(
            &mut req[n10..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x70)],
        )
        .unwrap();
        n10 += encode_xdg_wm_base_get_xdg_surface(&mut req[n10..], 0x71, 0x72, 0x70).unwrap();
        n10 += encode_xdg_surface_get_popup(&mut req[n10..], 0x72, 0x73, 0x72, 0x63).unwrap();
        assert_eq!(
            s.feed(&req[..n10], &mut out),
            Err(CompError::XdgRoleBusy),
            "无 toplevel 角色父面 → parent 闸"
        );

        // (j) 收场：popup destroy（角色摘除 + 取证面翻转）→
        //     positioner destroy（pos_tbl 摘除 → get_popup BadObject）
        let n11 = encode_message(&mut req, 0x68, xp::REQ_DESTROY, &[]).unwrap();
        s.feed(&req[..n11], &mut out).unwrap();
        assert_eq!(s.table().lookup(0x68), None);
        assert_eq!(s.surface_popup(0x66), None, "popup 角色摘除");
        let n11 = encode_message(&mut req, 0x63, xpo::REQ_DESTROY, &[]).unwrap();
        s.feed(&req[..n11], &mut out).unwrap();
        assert_eq!(s.table().lookup(0x63), None);
        let n11 = encode_xdg_surface_get_popup(&mut req, 0x67, 0x69, 0x61, 0x63).unwrap();
        assert_eq!(
            s.feed(&req[..n11], &mut out),
            Err(CompError::BadObject),
            "positioner 摘除后 get_popup fail-visible"
        );
    }

    /// M52-POPCON78 笔90 会话域 face——v3 reposition 车道（repositioned
    /// →configure 官方序双事件 + repos 计数）+ 嵌套父域（popup 父角色
    /// 派生）+ popup_done 传递闭包（父窗亡全链收场）+ NEG 双目。
    #[test]
    fn xdg_popup_reposition_face() {
        use crate::wayland::{
            encode_xdg_popup_reposition, encode_xdg_positioner_set_anchor,
            encode_xdg_positioner_set_anchor_rect, encode_xdg_positioner_set_constraint_adjustment,
            encode_xdg_positioner_set_gravity, encode_xdg_positioner_set_offset,
            encode_xdg_positioner_set_parent_configure, encode_xdg_positioner_set_parent_size,
            encode_xdg_positioner_set_reactive, encode_xdg_positioner_set_size,
            encode_xdg_surface_get_popup, encode_xdg_surface_get_toplevel,
            encode_xdg_wm_base_create_positioner, encode_xdg_wm_base_get_xdg_surface,
            xdg_popup as xp, SIG_XDG_POPUP_CONFIGURE, SIG_XDG_POPUP_REPOSITIONED,
        };
        let mut s = new_session();
        let mut out = [0u8; 512];
        setup_registry(&mut s);

        // (a) 前置链域：compositor + wm_base bind + create_surface +
        //     父 toplevel（loop_face 同谱对象域）。
        let mut req = [0u8; 128];
        let mut n = 0usize;
        n += encode_registry_bind(&mut req[n..], 2, 1, "wl_compositor", 4, 3).unwrap();
        n += encode_registry_bind(&mut req[n..], 2, 5, "xdg_wm_base", 1, 0x71).unwrap();
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x60)],
        )
        .unwrap();
        n += encode_xdg_wm_base_get_xdg_surface(&mut req[n..], 0x71, 0x61, 0x60).unwrap();
        n += encode_xdg_surface_get_toplevel(&mut req[n..], 0x61, 0x62).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.out_len, 32, "初始 configure 对 32 B");

        // (b) 屏域约束域注入（policy 面——1000×900 屏域）。
        s.set_screen_bound((0, 0, 1000, 900));
        assert_eq!(s.screen_bound(), (0, 0, 1000, 900));

        // (c) popup1：约束域 flip_y 施策（出上界→翻转入界）。positioner
        //     0x63：size (20,10) + anchor_rect (500,0,10,5) + anchor TOP
        //     + gravity TOP + cadj FLIP_Y（8）→ raw y=-10 出上界 → flip
        //     → gravity BOTTOM → y=0 全包容施策。v3 三请求随行在环。
        let mut req = [0u8; 512];
        let mut n = 0usize;
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x66)],
        )
        .unwrap();
        n += encode_xdg_wm_base_create_positioner(&mut req[n..], 0x71, 0x63).unwrap();
        n += encode_xdg_positioner_set_size(&mut req[n..], 0x63, 20, 10).unwrap();
        n += encode_xdg_positioner_set_anchor_rect(&mut req[n..], 0x63, 500, 0, 10, 5).unwrap();
        n += encode_xdg_positioner_set_anchor(&mut req[n..], 0x63, 1).unwrap();
        n += encode_xdg_positioner_set_gravity(&mut req[n..], 0x63, 1).unwrap();
        n += encode_xdg_positioner_set_constraint_adjustment(&mut req[n..], 0x63, 8).unwrap();
        n += encode_xdg_positioner_set_offset(&mut req[n..], 0x63, 0, 0).unwrap();
        n += encode_xdg_positioner_set_reactive(&mut req[n..], 0x63).unwrap();
        n += encode_xdg_positioner_set_parent_size(&mut req[n..], 0x63, 1000, 900).unwrap();
        n += encode_xdg_positioner_set_parent_configure(&mut req[n..], 0x63, 42).unwrap();
        n += encode_xdg_wm_base_get_xdg_surface(&mut req[n..], 0x71, 0x67, 0x66).unwrap();
        n += encode_xdg_surface_get_popup(&mut req[n..], 0x67, 0x68, 0x61, 0x63).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.out_len, 16, "popup configure 16 B");
        let m = crate::wayland::parse_message(&out[..16], SIG_XDG_POPUP_CONFIGURE).unwrap();
        assert_eq!(
            m.args[0],
            Some(WlArg::Int(495)),
            "flip_y 施策金值 x〔锚中 505 − 半宽 10〕"
        );
        assert_eq!(
            m.args[1],
            Some(WlArg::Int(0)),
            "flip_y 施策金值 y〔出上界 −10 → 翻转入界 0〕"
        );
        assert_eq!(
            s.surface_popup(0x66),
            Some((0x68, 495, 0, 20, 10)),
            "flip_y 施策 + 屏域尺寸承载"
        );
        // positioner 记账取证（reactive/parent_size/parent_config 三域）。
        let pos = s.pos_snapshot(0x63).expect("positioner");
        assert!(pos.reactive);
        assert_eq!(pos.parent_size, (1000, 900));
        assert_eq!(pos.parent_config, 42);

        // (d) 嵌套父域：popup2 以 popup1 为父（子面 wl 0x6B + xdg_surf
        //     0x69 + popup 0x6A，parent = 0x67〔popup1 的 xdg_surface〕）
        //     → 深度 2 ≤ POPUP_NEST_MAX 放行。
        let mut n = 0usize;
        n += encode_message(
            &mut req[n..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x6B)],
        )
        .unwrap();
        n += encode_xdg_wm_base_get_xdg_surface(&mut req[n..], 0x71, 0x69, 0x6B).unwrap();
        n += encode_xdg_surface_get_popup(&mut req[n..], 0x69, 0x6A, 0x67, 0x63).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.out_len, 16, "嵌套 popup configure 16 B");
        assert!(s.surface_popup(0x6B).is_some(), "嵌套派生在环");

        // (e) v3 reposition：新 positioner 0x64（锚 rect 界内右下域）→
        //     repositioned(0xAB) + configure(x,y) 官方序双事件 + repos=1。
        let mut n = 0usize;
        n += encode_xdg_wm_base_create_positioner(&mut req[n..], 0x71, 0x64).unwrap();
        n += encode_xdg_positioner_set_size(&mut req[n..], 0x64, 20, 10).unwrap();
        n += encode_xdg_positioner_set_anchor_rect(&mut req[n..], 0x64, 500, 500, 10, 5).unwrap();
        n += encode_xdg_positioner_set_anchor(&mut req[n..], 0x64, 8).unwrap();
        n += encode_xdg_positioner_set_gravity(&mut req[n..], 0x64, 8).unwrap();
        n += encode_xdg_positioner_set_constraint_adjustment(&mut req[n..], 0x64, 0).unwrap();
        n += encode_xdg_positioner_set_offset(&mut req[n..], 0x64, 0, 0).unwrap();
        n += encode_xdg_popup_reposition(&mut req[n..], 0x68, 0x64, 0xAB).unwrap();
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.repos, 1, "repositioned 出域计数");
        // 官方序：repositioned(token) 先行、configure 随行。
        let m = crate::wayland::parse_message(&out[..12], SIG_XDG_POPUP_REPOSITIONED).unwrap();
        assert_eq!(m.header.opcode, xp::EV_REPOSITIONED);
        assert_eq!(m.args[0], Some(WlArg::Uint(0xAB)));
        let m = crate::wayland::parse_message(&out[12..28], SIG_XDG_POPUP_CONFIGURE).unwrap();
        // 锚 BOTTOM_RIGHT(8) → (510,505)；gravity BOTTOM_RIGHT(8) → popup
        // 左上 (510,505)；bound 1000×900 界内 → 全尺寸。
        assert_eq!(m.args[0], Some(WlArg::Int(510)));
        assert_eq!(m.args[1], Some(WlArg::Int(505)));
        assert_eq!(
            s.surface_popup(0x66),
            Some((0x68, 510, 505, 20, 10)),
            "reposition 后约束域重算承载"
        );

        // (f) NEG 双目：reposition 未知 positioner → BadObject；不完整
        //     positioner（仅 set_size）→ XdgPosIncomplete。
        let n = encode_xdg_popup_reposition(&mut req, 0x68, 0x7F, 1).unwrap();
        assert_eq!(s.feed(&req[..n], &mut out), Err(CompError::BadObject));
        let mut n = 0usize;
        n += encode_xdg_wm_base_create_positioner(&mut req[n..], 0x71, 0x6C).unwrap();
        n += encode_xdg_positioner_set_size(&mut req[n..], 0x6C, 20, 10).unwrap();
        n += encode_xdg_popup_reposition(&mut req[n..], 0x68, 0x6C, 2).unwrap();
        assert_eq!(
            s.feed(&req[..n], &mut out),
            Err(CompError::XdgPosIncomplete),
            "缺 anchor_rect 宣告 → 完整性闸"
        );

        // (g) 传递闭包：toplevel 收场（0x62）→ popup1 + popup2 全链
        //     popup_done 入队（嵌套域全谱收场）→ 空流 feed 冲刷双事件。
        s.request_close(0x62).unwrap();
        s.request_popup_done_for_parent(0x62).unwrap();
        let rep = s.feed(&[], &mut out).unwrap();
        assert_eq!(rep.closes, 1, "toplevel close 事件");
        assert_eq!(rep.popup_dones, 2, "popup1 + popup2 传递闭包全谱收场");
        // 全链 popup destroy 摘除（客户端收场契约随行——取证面翻转）。
        let mut n = 0usize;
        n += encode_message(&mut req[n..], 0x68, xp::REQ_DESTROY, &[]).unwrap();
        n += encode_message(&mut req[n..], 0x6A, xp::REQ_DESTROY, &[]).unwrap();
        s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(s.surface_popup(0x66), None, "popup1 角色摘除");
        assert_eq!(s.surface_popup(0x6B), None, "popup2 角色摘除");
    }
}
