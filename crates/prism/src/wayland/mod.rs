//! Prism Wayland 语义面 —— wire 协议解析壳 v0（M42-UNIX3 阶段二）。
//!
//! **定位**：M42-计划 阶段二「unix socket 域 + Wayland 协议语义面」的
//! 协议面首割——**M34-P4「语义面先行」手法同款**（prism::compute
//! SPIR-V 解析壳先例）：落 wire 协议解析壳 v0，电气面（套接字 I/O 与
//! [`crate::unixsock`] 的合成器接线）挂账随阶段三进程面批次，如实
//! 登记。本面为纯函数域：no_std 零堆零 unsafe（crate 纪律不变），
//! 宿主测试谱先行（`cargo test -p prism`）。
//!
//! **wire 格式事实源**（官方 `wayland.xml` + Wayland 官方文档
//! "Wayland Protocol and Model of Operation"，本面常量逐条对账）：
//! - 消息头 2 字（8 字节）：字 0 = 发送方对象 id（32 位）；字 1 =
//!   低 16 位 opcode + 高 16 位消息尺寸（**主机字节序**——LuminaOS
//!   目标域 x86_64 = 小端，解析面按 LE 固定编码，如实记档）；
//! - 对象 id 分域：0 = null；1 = wl_display 固定；**客户端分配域**
//!   `2..=0xFEFF_FFFF`；**服务端分配域** `0xFF00_0000..=0xFFFF_FFFF`；
//! - string 参数 = u32 长度（**含 NUL 终止符**）+ NUL 结尾 UTF-8 +
//!   零填充至 4 字节边界；array = u32 尺寸 + 字节 + 零填充；
//! - fd 参数 = 消息内 1 字占位（实际 fd 走 unix socket 附带数据
//!   [`SYS_UNIXSOCK`] 电外面——本壳按占位字解析，fd 传递电气挂账）；
//! - `wl_registry.bind` 特例：new_id 前随 interface 名 string + 版本
//!   uint（XML 未标注接口的 new_id——本面以四参签名收录）。
//!
//! **签名驱动解析**（wire 无类型标签——参数型由接口签名表带外承载）：
//! 核心子集签名表随本面落库（`SIG_*` 常量，逐条对账官方 XML 声明序）；
//! [`parse_message`] 按签名逐参解析 + 尾字拒收（fail-visible——多余
//! 域即畸形，解析壳 v0 严格口径）。opcode 事实 = 官方 XML 声明序
//! （自 0 起计），回归锚见宿主测试 `opcode_tables_match_xml`。

#![forbid(unsafe_code)]

/// M42-COMP4：合成器会话面 v1——**非 test 门控域**（阶段三「合成器
/// 进程面」仲裁策略面：registry 公告/bind/surface 生命周期/damage-
/// commit 发布语义/帧回调——电气面消费方 = 常驻合成器服务
/// kernel-resident lane〔t104〕+ ring3 编译进程承接随用户态 ELF 播
/// 种批次挂账）。
pub mod comp;

/// wire 消息头字节数（2 字）。
pub const HEADER: usize = 8;
/// 单消息尺寸预算（v0 解析壳口径——libwayland 连接缓冲同量级；
/// 越域拒收 fail-visible）。
pub const WIRE_MAX: usize = 4096;
/// 单消息参数上限（核心子集最大 6 参〔wl_output.geometry〕× 2 余量）。
pub const MAX_ARGS: usize = 16;
/// string 编码上界（含 NUL；接口名/全局名域远低于此）。
pub const STR_MAX: usize = 512;
/// 客户端对象 id 分配下界（wl_display 固定 1 之后）。
pub const WL_CLIENT_ID_MIN: u32 = 2;
/// 客户端对象 id 分配上界（官方域：`0xFEFF_FFFF`）。
pub const WL_CLIENT_ID_MAX: u32 = 0xFEFF_FFFF;
/// 服务端对象 id 分配下界（官方域：`0xFF00_0000`）。
pub const WL_SERVER_ID_MIN: u32 = 0xFF00_0000;

/// 解析/编组错误域（fail-visible 全谱显形——compute::ParseError 同款纪律）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlError {
    /// 长度域违面：头不足 / 非 4 倍数 / 尺寸 < 头 / 尺寸越缓冲或越
    /// [`WIRE_MAX`] / 签名域参数截断 / 尾字多余。
    BadLength,
    /// string 参数违面：长度 0 / 末字节非 NUL / 非 UTF-8。
    BadString,
    /// 参数超 [`MAX_ARGS`]（签名域防线）。
    TooManyArgs,
    /// 编码缓冲不足。
    BufferTooSmall,
    /// 编码结果越 [`WIRE_MAX`]。
    TooLarge,
    /// 编码 string 越 [`STR_MAX`]。
    StrTooLong,
    /// 对象表满（[`TABLE_CAP`]）。
    TableFull,
    /// 对象 id 域违面：插入 id 不属于声明域 / null 域不可登记。
    BadDomain,
}

/// 参数型签名（wire 无类型标签——签名表带外承载；官方 XML `type` 属性域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlType {
    /// int（i32）。
    Int,
    /// uint（u32）。
    Uint,
    /// fixed（i32，24.8 定点——本壳按原字透传，语义换算挂账）。
    Fixed,
    /// string（NUL 结尾 UTF-8 + 填充）。
    Str,
    /// object（既有对象 id）。
    Object,
    /// new_id（新对象 id——bind 特例签名含 interface string + version）。
    NewId,
    /// array（u32 尺寸 + 字节 + 填充）。
    Array,
    /// fd（消息内 1 字占位——附带数据电气挂账）。
    Fd,
}

/// 参数值视图（解析产物——string/array 以零拷贝切片引用入参缓冲；
/// 全变体 Copy，宿主/内核两侧同构消费）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlArg<'a> {
    /// int 值。
    Int(i32),
    /// uint 值。
    Uint(u32),
    /// fixed 原字（24.8 定点语义换算挂账）。
    Fixed(i32),
    /// string 载荷（**不含** NUL 终止符；NUL 存在性由解析面保证）。
    Str(&'a [u8]),
    /// object id。
    Object(u32),
    /// new_id 值。
    NewId(u32),
    /// array 载荷。
    Array(&'a [u8]),
    /// fd 占位字（附带数据面挂账——值域语义不在本壳）。
    Fd(u32),
}

/// 消息头视图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WlHeader {
    /// 发送方对象 id。
    pub object_id: u32,
    /// opcode（官方 XML 声明序，自 0 起计）。
    pub opcode: u16,
    /// 消息总尺寸（含头；= 流推进步长）。
    pub size: u16,
}

/// 签名驱动解析产物：头 + 定容参数槽（零堆——compute 先例同款）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WlMessage<'a> {
    /// 消息头。
    pub header: WlHeader,
    /// 参数槽（按签名序填充；`args[..arg_count]` 有效）。
    pub args: [Option<WlArg<'a>>; MAX_ARGS],
    /// 实际参数数。
    pub arg_count: usize,
}

impl<'a> WlMessage<'a> {
    /// wire 尺寸（流推进步长——多消息缓冲逐条消费域）。
    pub fn wire_size(&self) -> usize {
        self.header.size as usize
    }
}

/// 4 字节对齐上取。
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// 小端 u32 读取（切片边界由调用方保证）。
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// 头解析（通用域——签名无关）：域闸 = 头完整 + 全缓冲 4 倍数 +
/// 尺寸 ≥ 头 + 尺寸 ≤ 缓冲 + 尺寸 ≤ [`WIRE_MAX`]。
pub fn parse_header(buf: &[u8]) -> Result<WlHeader, WlError> {
    if buf.len() < HEADER || !buf.len().is_multiple_of(4) {
        return Err(WlError::BadLength);
    }
    let size = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    if size < HEADER || size > buf.len() || size > WIRE_MAX {
        return Err(WlError::BadLength);
    }
    Ok(WlHeader {
        object_id: le32(buf, 0),
        opcode: u16::from_le_bytes([buf[4], buf[5]]),
        size: size as u16,
    })
}

/// 单参数解析（签名驱动）：返回（参数值, 消费字节数）。
/// `rest` = 自本参起的消息体（边界判定就地承载）。
fn parse_arg<'a>(rest: &'a [u8], ty: WlType) -> Result<(WlArg<'a>, usize), WlError> {
    if rest.len() < 4 {
        return Err(WlError::BadLength);
    }
    match ty {
        WlType::Int => Ok((WlArg::Int(le32(rest, 0) as i32), 4)),
        WlType::Uint => Ok((WlArg::Uint(le32(rest, 0)), 4)),
        WlType::Fixed => Ok((WlArg::Fixed(le32(rest, 0) as i32), 4)),
        WlType::Object => Ok((WlArg::Object(le32(rest, 0)), 4)),
        WlType::NewId => Ok((WlArg::NewId(le32(rest, 0)), 4)),
        WlType::Fd => Ok((WlArg::Fd(le32(rest, 0)), 4)),
        WlType::Str => {
            let len = le32(rest, 0) as usize;
            // 官方域：长度含 NUL ⇒ ≥ 1；载荷须以 NUL 结尾
            if len < 1 || 4 + len > rest.len() || rest[4 + len - 1] != 0 {
                return Err(WlError::BadString);
            }
            let payload = &rest[4..4 + len - 1];
            if core::str::from_utf8(payload).is_err() {
                return Err(WlError::BadString);
            }
            Ok((WlArg::Str(payload), 4 + align4(len)))
        }
        WlType::Array => {
            let len = le32(rest, 0) as usize;
            if 4 + len > rest.len() {
                return Err(WlError::BadLength);
            }
            Ok((WlArg::Array(&rest[4..4 + len]), 4 + align4(len)))
        }
    }
}

/// 签名驱动参数解析：`body` = 头后消息体（`buf[HEADER..size]`）。
/// 产物 = 定容槽 + 参数数；签名长越 [`MAX_ARGS`] → [`WlError::TooManyArgs`]；
/// 消息体与签名长不齐（截断/尾字）→ [`WlError::BadLength`]（解析壳
/// v0 严格口径——多余域即畸形）。
pub fn parse_args<'a>(
    body: &'a [u8],
    sig: &[WlType],
) -> Result<([Option<WlArg<'a>>; MAX_ARGS], usize), WlError> {
    if sig.len() > MAX_ARGS {
        return Err(WlError::TooManyArgs);
    }
    let mut args = [None; MAX_ARGS];
    let mut off = 0usize;
    for (n, ty) in sig.iter().enumerate() {
        let (arg, adv) = parse_arg(&body[off..], *ty)?;
        args[n] = Some(arg);
        off += adv;
    }
    if off != body.len() {
        return Err(WlError::BadLength); // 截断或尾字多余——严格拒收
    }
    Ok((args, sig.len()))
}

/// 全消息解析（头 + 签名驱动参数；尺寸外尾字 = 缓冲内后续消息，本壳
/// 忽略——流推进以 [`WlMessage::wire_size`] 承载）。
pub fn parse_message<'a>(buf: &'a [u8], sig: &[WlType]) -> Result<WlMessage<'a>, WlError> {
    let header = parse_header(buf)?;
    let (args, arg_count) = parse_args(&buf[HEADER..header.size as usize], sig)?;
    Ok(WlMessage {
        header,
        args,
        arg_count,
    })
}

/// 单参数编码尺寸。
fn arg_size(arg: &WlArg) -> usize {
    match arg {
        WlArg::Int(_)
        | WlArg::Uint(_)
        | WlArg::Fixed(_)
        | WlArg::Object(_)
        | WlArg::NewId(_)
        | WlArg::Fd(_) => 4,
        WlArg::Str(b) => 4 + align4(b.len() + 1), // 长度含 NUL
        WlArg::Array(b) => 4 + align4(b.len()),
    }
}

/// 全消息编码：头 + 参数按序写入；两段式（先算总尺寸再写）——缓冲
/// 不足/越 [`WIRE_MAX`] fail-visible，写入路径无半成品状态。返回总
/// 尺寸（= 流推进步长）。
pub fn encode_message(
    buf: &mut [u8],
    object_id: u32,
    opcode: u16,
    args: &[WlArg],
) -> Result<usize, WlError> {
    if args.len() > MAX_ARGS {
        return Err(WlError::TooManyArgs);
    }
    let total = HEADER + args.iter().map(arg_size).sum::<usize>();
    if total > WIRE_MAX {
        return Err(WlError::TooLarge);
    }
    if total > buf.len() {
        return Err(WlError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&object_id.to_le_bytes());
    buf[4..6].copy_from_slice(&opcode.to_le_bytes());
    buf[6..8].copy_from_slice(&(total as u16).to_le_bytes());
    let mut off = HEADER;
    for arg in args {
        match arg {
            WlArg::Int(v) => buf[off..off + 4].copy_from_slice(&(*v as u32).to_le_bytes()),
            WlArg::Uint(v) | WlArg::Object(v) | WlArg::NewId(v) | WlArg::Fd(v) => {
                buf[off..off + 4].copy_from_slice(&v.to_le_bytes())
            }
            WlArg::Fixed(v) => buf[off..off + 4].copy_from_slice(&(*v as u32).to_le_bytes()),
            WlArg::Str(b) => {
                let wire_len = b.len() + 1; // 含 NUL
                if wire_len > STR_MAX {
                    return Err(WlError::StrTooLong);
                }
                buf[off..off + 4].copy_from_slice(&(wire_len as u32).to_le_bytes());
                buf[off + 4..off + 4 + b.len()].copy_from_slice(b);
                buf[off + 4 + b.len()] = 0;
                for p in buf[off + 4 + wire_len..off + 4 + align4(wire_len)].iter_mut() {
                    *p = 0;
                }
            }
            WlArg::Array(b) => {
                buf[off..off + 4].copy_from_slice(&(b.len() as u32).to_le_bytes());
                buf[off + 4..off + 4 + b.len()].copy_from_slice(b);
                for p in buf[off + 4 + b.len()..off + 4 + align4(b.len())].iter_mut() {
                    *p = 0;
                }
            }
        }
        off += arg_size(arg);
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// 对象 id 分域（官方域常量 + 判定面——对象表登记闸）
// ---------------------------------------------------------------------------

/// 对象 id 分域判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdDomain {
    /// null 对象（0）。
    Null,
    /// wl_display 固定 id（1）。
    Display,
    /// 客户端分配域（2..=0xFEFF_FFFF）。
    Client,
    /// 服务端分配域（0xFF00_0000..）。
    Server,
}

/// 对象 id 分域判定（官方域逐字对账）。
pub fn id_domain(id: u32) -> IdDomain {
    match id {
        0 => IdDomain::Null,
        1 => IdDomain::Display,
        WL_CLIENT_ID_MIN..=WL_CLIENT_ID_MAX => IdDomain::Client,
        WL_SERVER_ID_MIN..=u32::MAX => IdDomain::Server,
    }
}

/// 对象表容量（定容零堆——SurfaceTable/MAX_LAYERS 同量级先例）。
pub const TABLE_CAP: usize = 64;

/// 接口语义枚举（核心子集——官方 XML 接口域；扩展随批次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlIface {
    /// wl_display（固定 id 1）。
    Display,
    /// wl_registry。
    Registry,
    /// wl_callback。
    Callback,
    /// wl_compositor。
    Compositor,
    /// wl_surface。
    Surface,
    /// wl_buffer。
    Buffer,
    /// wl_seat。
    Seat,
    /// wl_pointer（M42-INPUT7 输入链——seat.get_pointer 派生对象）。
    Pointer,
    /// wl_keyboard（M42-INPUT7 输入链——seat.get_keyboard 派生对象）。
    Keyboard,
    /// wl_output。
    Output,
    /// wl_region。
    Region,
    /// wl_shm。
    Shm,
    /// wl_shm_pool。
    ShmPool,
    /// xdg_wm_base（M50-XDGSHELL66 笔76——xdg_shell 窗口管理协议入口，
    /// version 1..=6 域；registry 名 "xdg_wm_base"）。
    XdgWmBase,
    /// xdg_surface（M50-XDGSHELL66 笔76——wm_base.get_xdg_surface 派生
    /// 对象：per-surface 窗口角色装载体）。
    XdgSurface,
    /// xdg_toplevel（M50-XDGSHELL66 笔76——xdg_surface.get_toplevel
    /// 派生对象：toplevel 应用窗角色）。
    XdgToplevel,
    /// xdg_positioner（M51-XDGPOP75 笔86——xdg_wm_base.create_
    /// positioner 派生对象：popup 定位参数装载体，v1 七请求域）。
    XdgPositioner,
    /// xdg_popup（M51-XDGPOP75 笔86——xdg_surface.get_popup 派生
    /// 对象：popup 临时窗角色——configure(x,y) 定位 + popup_done
    /// 收场契约）。
    XdgPopup,
}

/// 接口官方名（registry global 事件 interface string 事实源）。
pub fn iface_name(iface: WlIface) -> &'static str {
    match iface {
        WlIface::Display => "wl_display",
        WlIface::Registry => "wl_registry",
        WlIface::Callback => "wl_callback",
        WlIface::Compositor => "wl_compositor",
        WlIface::Surface => "wl_surface",
        WlIface::Buffer => "wl_buffer",
        WlIface::Seat => "wl_seat",
        WlIface::Pointer => "wl_pointer",
        WlIface::Keyboard => "wl_keyboard",
        WlIface::Output => "wl_output",
        WlIface::Region => "wl_region",
        WlIface::Shm => "wl_shm",
        WlIface::ShmPool => "wl_shm_pool",
        WlIface::XdgWmBase => "xdg_wm_base",
        WlIface::XdgSurface => "xdg_surface",
        WlIface::XdgToplevel => "xdg_toplevel",
        WlIface::XdgPositioner => "xdg_positioner",
        WlIface::XdgPopup => "xdg_popup",
    }
}

/// 对象表：id → 接口语义（定容槽 + 客户端/服务端双分配器单调铸造；
/// v0 无复用——id 退役即废弃，delete_id 复用面电气挂账如实登记）。
/// M42-WAYCOMP18：**sync callback 域摘牌在环**——done 后服务端销毁 +
/// delete_id 随行 + 对象表摘除（同 id 多轮 sync 复用在环面）；
/// M42-DMGC22：**frame callback 域摘牌在环**——commit 冲刷域 done 后
/// 服务端销毁 + delete_id 随行 + 对象表摘除（同 id 多轮 frame 复用在
/// 环面——v0 「commit 冲刷后不回收」口径退役）。
#[derive(Debug, Clone, Copy)]
pub struct WlObjectTable {
    slots: [Option<(u32, WlIface)>; TABLE_CAP],
    len: usize,
    next_client: u32,
    next_server: u32,
}

impl Default for WlObjectTable {
    fn default() -> Self {
        Self::new()
    }
}

impl WlObjectTable {
    /// 空表（客户端分配器自 2、服务端分配器自 0xFF00_0000 起）。
    pub const fn new() -> Self {
        Self {
            slots: [None; TABLE_CAP],
            len: 0,
            next_client: WL_CLIENT_ID_MIN,
            next_server: WL_SERVER_ID_MIN,
        }
    }

    /// 登记对象数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 表是否为空（clippy is_empty 契约伴生面）。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 对象查找。
    pub fn lookup(&self, id: u32) -> Option<WlIface> {
        self.slots
            .iter()
            .find_map(|s| s.filter(|(sid, _)| *sid == id).map(|(_, i)| i))
    }

    /// 客户端域铸造登记（单调新 id——复用面挂账；域越界/表满拒收）。
    pub fn insert_client(&mut self, iface: WlIface) -> Result<u32, WlError> {
        if self.next_client > WL_CLIENT_ID_MAX {
            return Err(WlError::BadDomain); // 客户端域耗尽（u32 域无溢出）
        }
        let id = self.next_client;
        self.next_client += 1;
        self.install(id, iface)?;
        Ok(id)
    }

    /// 服务端域铸造登记（同款）。
    pub fn insert_server(&mut self, iface: WlIface) -> Result<u32, WlError> {
        let id = self.next_server;
        if id == u32::MAX {
            return Err(WlError::BadDomain);
        }
        self.next_server += 1;
        self.install(id, iface)?;
        Ok(id)
    }

    /// 显式 id 登记（域闸：null 域拒收——misuse 防线；wl_display 固定
    /// id 1 为唯一 Display 域可登记项）。
    pub fn install(&mut self, id: u32, iface: WlIface) -> Result<(), WlError> {
        if id_domain(id) == IdDomain::Null {
            return Err(WlError::BadDomain);
        }
        if self.lookup(id).is_some() {
            return Err(WlError::BadDomain); // id 冲突（同 id 双登记域拒收）
        }
        if self.len >= TABLE_CAP {
            return Err(WlError::TableFull);
        }
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(WlError::TableFull);
        };
        *slot = Some((id, iface));
        self.len += 1;
        Ok(())
    }

    /// 摘除（v0 无 id 复用——退役即废弃）。
    pub fn remove(&mut self, id: u32) -> bool {
        let Some(pos) = self
            .slots
            .iter()
            .position(|s| s.is_some_and(|(sid, _)| sid == id))
        else {
            return false;
        };
        self.slots[pos] = None;
        self.len -= 1;
        true
    }
}

// ---------------------------------------------------------------------------
// 核心子集 opcode 事实源（官方 wayland.xml 声明序逐条对账——回归锚）
// ---------------------------------------------------------------------------

/// wl_display（固定 id 1）请求/事件 opcode。
pub mod display {
    /// request sync（new_id callback）。
    pub const REQ_SYNC: u16 = 0;
    /// request get_registry（new_id registry）。
    pub const REQ_GET_REGISTRY: u16 = 1;
    /// event error（object, uint, string）。
    pub const EV_ERROR: u16 = 0;
    /// event delete_id（uint）。
    pub const EV_DELETE_ID: u16 = 1;
}

/// wl_registry 请求/事件 opcode。
pub mod registry {
    /// request bind（uint name, string interface, uint version, new_id）。
    pub const REQ_BIND: u16 = 0;
    /// event global（uint, string, uint）。
    pub const EV_GLOBAL: u16 = 0;
    /// event global_remove（uint）。
    pub const EV_GLOBAL_REMOVE: u16 = 1;
}

/// wl_callback 事件 opcode。
pub mod callback {
    /// event done（uint callback_data）。
    pub const EV_DONE: u16 = 0;
}

/// wl_compositor 请求 opcode。
pub mod compositor {
    /// request create_surface（new_id）。
    pub const REQ_CREATE_SURFACE: u16 = 0;
    /// request create_region（new_id）。
    pub const REQ_CREATE_REGION: u16 = 1;
}

/// wl_surface 请求/事件 opcode（官方 XML 声明序——v0.21.0 域 0..=10）。
pub mod surface {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// request attach（object, int, int）。
    pub const REQ_ATTACH: u16 = 1;
    /// request damage（int × 4）。
    pub const REQ_DAMAGE: u16 = 2;
    /// request frame（new_id）。
    pub const REQ_FRAME: u16 = 3;
    /// request set_opaque_region（object）。
    pub const REQ_SET_OPAQUE_REGION: u16 = 4;
    /// request set_input_region（object）。
    pub const REQ_SET_INPUT_REGION: u16 = 5;
    /// request commit。
    pub const REQ_COMMIT: u16 = 6;
    /// request set_buffer_transform（int）。
    pub const REQ_SET_BUFFER_TRANSFORM: u16 = 7;
    /// request set_buffer_scale（int）。
    pub const REQ_SET_BUFFER_SCALE: u16 = 8;
    /// request damage_buffer（int × 4）。
    pub const REQ_DAMAGE_BUFFER: u16 = 9;
    /// request offset（int × 2）。
    pub const REQ_OFFSET: u16 = 10;
    /// event enter（object output）。
    pub const EV_ENTER: u16 = 0;
    /// event leave（object output）。
    pub const EV_LEAVE: u16 = 1;
}

/// wl_buffer 请求/事件 opcode。
pub mod buffer {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// event release。
    pub const EV_RELEASE: u16 = 0;
}

/// wl_seat 请求/事件 opcode。
pub mod seat {
    /// request get_pointer（new_id）。
    pub const REQ_GET_POINTER: u16 = 0;
    /// request get_keyboard（new_id）。
    pub const REQ_GET_KEYBOARD: u16 = 1;
    /// request get_touch（new_id）。
    pub const REQ_GET_TOUCH: u16 = 2;
    /// request release。
    pub const REQ_RELEASE: u16 = 3;
    /// event capabilities（uint）。
    pub const EV_CAPABILITIES: u16 = 0;
    /// event name（string）。
    pub const EV_NAME: u16 = 1;
}

/// wl_keyboard 事件 opcode（M42-INPUT7 输入链——官方 XML 声明序；
/// 请求域〔release/set_repeat_info〕域外挂账）。
pub mod keyboard {
    /// event keymap（fd + uint format + uint size——fd 占位字）。
    pub const EV_KEYMAP: u16 = 0;
    /// event enter（uint serial + object surface + array keys）。
    pub const EV_ENTER: u16 = 1;
    /// event leave（uint serial + object surface）。
    pub const EV_LEAVE: u16 = 2;
    /// event key（uint serial + uint time + uint key + uint state）。
    pub const EV_KEY: u16 = 3;
    /// event modifiers（uint × 5：serial + depressed/latched/locked
    /// mods + group）。
    pub const EV_MODIFIERS: u16 = 4;
    /// event repeat_info（uint rate + uint delay）。
    pub const EV_REPEAT_INFO: u16 = 5;
}

/// wl_keyboard 请求 opcode（M43-KBREP37 笔㊷——客户端请求域落域：
/// v0 release/set_repeat_info 挂账注退役、set_cursor 官方请求域在环。
/// repeat_info 是服务端公告事件非客户端请求——公告面笔㉞已落域）。
pub mod keyboard_req {
    /// request release（v0 挂账维持——对象摘除域随会话收场承载）。
    pub const REQ_RELEASE: u16 = 0;
    /// request set_cursor（uint serial + object surface + int
    /// hotspot_x + int hotspot_y——客户端键盘焦点光标面宣告，
    /// surface = 0 合法〔默认光标回退域〕）。
    pub const REQ_SET_CURSOR: u16 = 1;
}

/// wl_pointer 事件 opcode（M42-INPUT7 输入链——官方 XML 声明序；
/// axis 族/frame/请求域域外挂账）。
pub mod pointer {
    /// event enter（uint serial + object surface + fixed x + fixed y）。
    pub const EV_ENTER: u16 = 0;
    /// event leave（uint serial + object surface）。
    pub const EV_LEAVE: u16 = 1;
    /// event motion（uint time + fixed x + fixed y）。
    pub const EV_MOTION: u16 = 2;
    /// event button（uint serial + uint time + uint button + uint
    /// state）。
    pub const EV_BUTTON: u16 = 3;
    /// event axis（uint time + uint axis + fixed value）。
    pub const EV_AXIS: u16 = 4;
    /// event frame（——axis 族分组终结，v5+ 声明序）。
    pub const EV_FRAME: u16 = 5;
    /// event axis_source（uint axis_source——frame 域前置声明）。
    pub const EV_AXIS_SOURCE: u16 = 6;
    /// event axis_stop（uint time + uint axis——滚动手势终结）。
    pub const EV_AXIS_STOP: u16 = 7;
    /// event axis_value120（uint axis + int value120——离散步进语义，
    /// M43-AV12036：官方 wl_pointer v9+ 事件声明序 8 = axis_discrete
    /// 〔已废弃倾向〕、9 = axis_value120——本仓取 9 号 axis_value120
    /// 承接，8 号 axis_discrete 域外挂账如实登记）。
    pub const EV_AXIS_VALUE120: u16 = 9;
}

/// wl_output 请求/事件 opcode。
pub mod output {
    /// request release。
    pub const REQ_RELEASE: u16 = 0;
    /// event geometry（int × 5 + string × 2 + int）。
    pub const EV_GEOMETRY: u16 = 0;
    /// event mode（uint + int × 3）。
    pub const EV_MODE: u16 = 1;
    /// event done。
    pub const EV_DONE: u16 = 2;
    /// event scale（int）。
    pub const EV_SCALE: u16 = 3;
    /// event name（string）。
    pub const EV_NAME: u16 = 4;
    /// event description（string）。
    pub const EV_DESCRIPTION: u16 = 5;
}

/// wl_region 请求 opcode。
pub mod region {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// request add（int × 4）。
    pub const REQ_ADD: u16 = 1;
    /// request subtract（int × 4）。
    pub const REQ_SUBTRACT: u16 = 2;
}

/// wl_shm 请求/事件 opcode。
pub mod shm {
    /// request create_pool（new_id, fd, int）。
    pub const REQ_CREATE_POOL: u16 = 0;
    /// event format（uint）。
    pub const EV_FORMAT: u16 = 0;
}

/// wl_shm_pool 请求 opcode。
pub mod shm_pool {
    /// request create_buffer（new_id, int × 4, uint）。
    pub const REQ_CREATE_BUFFER: u16 = 0;
    /// request destroy。
    pub const REQ_DESTROY: u16 = 1;
    /// request resize（int）。
    pub const REQ_RESIZE: u16 = 2;
}

/// xdg_wm_base 请求/事件 opcode（M50-XDGSHELL66 笔76——官方
/// xdg-shell.xml 声明序；事件 ping——窗口管理协议入口 + liveness
/// 契约。**M51-XDGPOP75 笔86 揭雷①序修正**：官方声明序 destroy/
/// **create_positioner**/get_xdg_surface/pong 四请求——笔76 v0 最小
/// 面缺 create_positioner 时将 get_xdg_surface/pong 顶位到 1/2，
/// 与官方 XML（get_xdg_surface=2 / pong=3）偏差一一目——真件
/// 客户端（western 同序）首撞即断的谱系雷，随笔86 官方序对齐修正
/// + create_positioner 补位在环）。
pub mod xdg_wm_base {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// request create_positioner（new_id——popup 定位参数装载体）。
    pub const REQ_CREATE_POSITIONER: u16 = 1;
    /// request get_xdg_surface（new_id + object surface）。
    pub const REQ_GET_XDG_SURFACE: u16 = 2;
    /// request pong（uint serial——ping 应答，官方 liveness 契约）。
    pub const REQ_PONG: u16 = 3;
    /// event ping（uint serial——客户端必须回 pong，v0 死亡拒绝禁令
    /// 域外挂账：服务端 v0 不主动 ping，契约面先行）。
    pub const EV_PING: u16 = 0;
}

/// xdg_surface 请求/事件 opcode（M50-XDGSHELL66 笔76——官方声明序；
/// configure/ack_configure 双向序契约：commit 前必须 ack 最近一次
/// configure，v0 契约面先行，电气挂账笔77）。
pub mod xdg_surface {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// request get_toplevel（new_id）。
    pub const REQ_GET_TOPLEVEL: u16 = 1;
    /// request get_popup（new_id + object parent + object positioner——
    /// M51-XDGPOP75 笔86 在环：popup 临时窗角色派生域）。
    pub const REQ_GET_POPUP: u16 = 2;
    /// request set_window_geometry（int × 4）。
    pub const REQ_SET_WINDOW_GEOMETRY: u16 = 3;
    /// request ack_configure（uint serial）。
    pub const REQ_ACK_CONFIGURE: u16 = 4;
    /// event configure（uint serial——toled 初始几何零值 = 服务端策略
    /// 自主；客户端 commit 前必须 ack）。
    pub const EV_CONFIGURE: u16 = 0;
}

/// xdg_toplevel 请求/事件 opcode（M50-XDGSHELL66 笔76——官方声明序；
/// v0 最小面主事件 = configure/close，窗口交互请求域外如实挂账）。
pub mod xdg_toplevel {
    /// request destroy。
    pub const REQ_DESTROY: u16 = 0;
    /// request set_parent（object）。
    pub const REQ_SET_PARENT: u16 = 1;
    /// request set_title（string——v0 最小面主请求）。
    pub const REQ_SET_TITLE: u16 = 2;
    /// request set_app_id（string）。
    pub const REQ_SET_APP_ID: u16 = 3;
    /// request show_window_menu（object seat + uint serial + int × 2）。
    pub const REQ_SHOW_WINDOW_MENU: u16 = 4;
    /// request move（object seat + uint serial）。
    pub const REQ_MOVE: u16 = 5;
    /// request resize（object seat + uint serial + uint edges）。
    pub const REQ_RESIZE: u16 = 6;
    /// request set_max_size（int × 2）。
    pub const REQ_SET_MAX_SIZE: u16 = 7;
    /// request set_min_size（int × 2）。
    pub const REQ_SET_MIN_SIZE: u16 = 8;
    /// request set_maximized。
    pub const REQ_SET_MAXIMIZED: u16 = 9;
    /// request unset_maximized。
    pub const REQ_UNSET_MAXIMIZED: u16 = 10;
    /// request set_fullscreen（object output）。
    pub const REQ_SET_FULLSCREEN: u16 = 11;
    /// request unset_fullscreen。
    pub const REQ_UNSET_FULLSCREEN: u16 = 12;
    /// request set_minimized。
    pub const REQ_SET_MINIMIZED: u16 = 13;
    /// event configure（int width + int height + array states）。
    pub const EV_CONFIGURE: u16 = 0;
    /// event close（——v0 最小面主事件：用户关闭请求）。
    pub const EV_CLOSE: u16 = 1;
    /// event configure_bounds（int × 2，v4+）。
    pub const EV_CONFIGURE_BOUNDS: u16 = 2;
    /// event wm_capabilities（array，v5+）。
    pub const EV_WM_CAPABILITIES: u16 = 3;
}

/// xdg_positioner 请求 opcode（M51-XDGPOP75 笔86 官方声明序 + M52-POPCON78
/// 笔90 v3 三请求在环：v1 七请求 destroy/set_size/set_anchor_rect/
/// set_anchor/set_gravity/set_constraint_adjustment/set_offset + v3
/// set_reactive/set_parent_size/set_parent_configure 全谱十请求在环）。
pub mod xdg_positioner {
    /// request destroy（destructor）。
    pub const REQ_DESTROY: u16 = 0;
    /// request set_size（int width + int height——popup 内容尺寸宣告）。
    pub const REQ_SET_SIZE: u16 = 1;
    /// request set_anchor_rect（int × 4——锚矩形〔父面局部坐标〕）。
    pub const REQ_SET_ANCHOR_RECT: u16 = 2;
    /// request set_anchor（uint anchor——锚边枚举，[`XDG_ANCHOR_MAX`]）。
    pub const REQ_SET_ANCHOR: u16 = 3;
    /// request set_gravity（uint gravity——重力枚举，[`XDG_ANCHOR_MAX`]）。
    pub const REQ_SET_GRAVITY: u16 = 4;
    /// request set_constraint_adjustment（uint——约束调整位域）。
    pub const REQ_SET_CONSTRAINT_ADJUSTMENT: u16 = 5;
    /// request set_offset（int × 2——锚点偏移）。
    pub const REQ_SET_OFFSET: u16 = 6;
    /// request set_reactive（v3——reactive 重定位宣告，零参）。
    pub const REQ_SET_REACTIVE: u16 = 7;
    /// request set_parent_size（v3——reactive 重定位父尺寸宣告）。
    pub const REQ_SET_PARENT_SIZE: u16 = 8;
    /// request set_parent_configure（v3——reactive 重定位父 configure 串号）。
    pub const REQ_SET_PARENT_CONFIGURE: u16 = 9;
}

/// xdg_popup 请求/事件 opcode（M51-XDGPOP75 笔86 官方声明序 + M52-POPCON78
/// 笔90 v3 reposition/repositioned 在环：请求 destroy/grab/reposition +
/// 事件 configure/popup_done/repositioned 全谱在环）。
pub mod xdg_popup {
    /// request destroy（destructor——popup 角色摘除）。
    pub const REQ_DESTROY: u16 = 0;
    /// request grab（object seat + uint serial——输入 grab 宣告）。
    pub const REQ_GRAB: u16 = 1;
    /// request reposition（object positioner + uint token，v3——重定位）。
    pub const REQ_REPOSITION: u16 = 2;
    /// event configure（int × 2——popup 位置〔父面局部坐标〕）。
    pub const EV_CONFIGURE: u16 = 0;
    /// event popup_done（——收场契约：客户端应销毁 popup）。
    pub const EV_POPUP_DONE: u16 = 1;
    /// event repositioned（uint token，v3——重定位完成回执）。
    pub const EV_REPOSITIONED: u16 = 2;
}

// --- xdg_shell 枚举语义常量（官方 XML 枚举值逐字对账——M51-XDGPOP75
// 笔86 placement 语义核 + 域闸） ---

/// xdg_positioner.anchor/gravity 枚举值域上界（官方声明序 none/top/
/// bottom/left/right/top_left/bottom_left/top_right/bottom_right）。
pub const XDG_ANCHOR_MAX: u32 = 8;
/// anchor/gravity 枚举：none。
pub const XDG_ANCHOR_NONE: u32 = 0;
/// anchor/gravity 枚举：top。
pub const XDG_ANCHOR_TOP: u32 = 1;
/// anchor/gravity 枚举：bottom。
pub const XDG_ANCHOR_BOTTOM: u32 = 2;
/// anchor/gravity 枚举：left。
pub const XDG_ANCHOR_LEFT: u32 = 3;
/// anchor/gravity 枚举：right。
pub const XDG_ANCHOR_RIGHT: u32 = 4;
/// anchor/gravity 枚举：top_left。
pub const XDG_ANCHOR_TOP_LEFT: u32 = 5;
/// anchor/gravity 枚举：bottom_left。
pub const XDG_ANCHOR_BOTTOM_LEFT: u32 = 6;
/// anchor/gravity 枚举：top_right。
pub const XDG_ANCHOR_TOP_RIGHT: u32 = 7;
/// anchor/gravity 枚举：bottom_right。
pub const XDG_ANCHOR_BOTTOM_RIGHT: u32 = 8;
/// constraint_adjustment 位域：slider_x（1）。
pub const XDG_CADJ_SLIDER_X: u32 = 1;
/// constraint_adjustment 位域：slider_y（2）。
pub const XDG_CADJ_SLIDER_Y: u32 = 2;
/// constraint_adjustment 位域：flip_x（4）。
pub const XDG_CADJ_FLIP_X: u32 = 4;
/// constraint_adjustment 位域：flip_y（8）。
pub const XDG_CADJ_FLIP_Y: u32 = 8;
/// constraint_adjustment 位域：resize_x（16）。
pub const XDG_CADJ_RESIZE_X: u32 = 16;
/// constraint_adjustment 位域：resize_y（32）。
pub const XDG_CADJ_RESIZE_Y: u32 = 32;

// --- xdg_toplevel 状态族语义常量 + 决策核（M53-XDGSTAT83 笔96——B 线②
//     开工令：官方 xdg-shell.xml state 枚举声明序 + configure 决策核） ---

/// xdg_toplevel.state 枚举：maximized（0）。
pub const XDG_TOPLEVEL_STATE_MAXIMIZED: u8 = 0;
/// xdg_toplevel.state 枚举：fullscreen（1）。
pub const XDG_TOPLEVEL_STATE_FULLSCREEN: u8 = 1;
/// xdg_toplevel.state 枚举：activated（2——焦点宣告，v0 域外挂账）。
pub const XDG_TOPLEVEL_STATE_ACTIVATED: u8 = 2;

/// xdg_toplevel 状态族决策核（M53-XDGSTAT83 笔96——官方 configure 序：
/// 状态旗 → (宽, 高, states 数组字节槽, 有效数)）。全屏 = 屏域全幅
/// 〔全屏优先——官方 fullscreen 与 maximized 同置时全屏胜〕；最大化 =
/// 屏域（工作区扣减面挂账如实）；常态 = 恢复几何 min/max 钳制
/// （clamp_minmax 同谱——max 非零上钳先行 + min 非零下钳后随，0 =
/// 未设定域跳过）。states 数组按官方枚举序出域（maximized 0 /
/// fullscreen 1）。
#[allow(clippy::too_many_arguments)]
pub fn toplevel_state_decide(
    maximized: bool,
    fullscreen: bool,
    cur_w: u32,
    cur_h: u32,
    screen_w: u32,
    screen_h: u32,
    min_w: i32,
    min_h: i32,
    max_w: i32,
    max_h: i32,
) -> (u32, u32, [u8; 4], usize) {
    let mut states = [0u8; 4];
    let mut n = 0usize;
    if fullscreen {
        states[n] = XDG_TOPLEVEL_STATE_FULLSCREEN;
        n += 1;
        (screen_w, screen_h, states, n)
    } else if maximized {
        states[n] = XDG_TOPLEVEL_STATE_MAXIMIZED;
        n += 1;
        (screen_w, screen_h, states, n)
    } else {
        let mut w = cur_w;
        let mut h = cur_h;
        if max_w > 0 && w > max_w as u32 {
            w = max_w as u32;
        }
        if max_h > 0 && h > max_h as u32 {
            h = max_h as u32;
        }
        if min_w > 0 && w < min_w as u32 {
            w = min_w as u32;
        }
        if min_h > 0 && h < min_h as u32 {
            h = min_h as u32;
        }
        (w, h, states, n)
    }
}

/// positioner 定位参数装载体（M51-XDGPOP75 笔86 六 setter 语义核 +
/// M52-POPCON78 笔90 v3 三域随行——reactive 重定位宣告/父尺寸/父
/// configure 串号；定容零堆值语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosDef {
    /// set_size 宣告（popup 内容尺寸）。
    pub size: (i32, i32),
    /// set_anchor_rect 宣告（父面局部坐标锚矩形）。
    pub anchor_rect: (i32, i32, i32, i32),
    /// set_anchor 宣告（[`XDG_ANCHOR_MAX`] 值域）。
    pub anchor: u32,
    /// set_gravity 宣告（[`XDG_ANCHOR_MAX`] 值域）。
    pub gravity: u32,
    /// set_constraint_adjustment 宣告（位域——M52-POPCON78 约束域施策
    /// 位：flip/slide/resize 双轴全谱）。
    pub cadj: u32,
    /// set_offset 宣告（锚点偏移）。
    pub offset: (i32, i32),
    /// set_reactive 宣告（v3——父面几何变更时重定位宣告）。
    pub reactive: bool,
    /// set_parent_size 宣告（v3——reactive 重定位父尺寸〔w, h〕）。
    pub parent_size: (i32, i32),
    /// set_parent_configure 宣告（v3——reactive 重定位父 configure 串号）。
    pub parent_config: u32,
}

impl PosDef {
    /// 完整性闸（官方契约：set_size ∧ set_anchor_rect 双宣告在位才
    /// 可用于 get_popup——缺位即 [`crate::wayland::comp::CompError::
    /// XdgPosIncomplete`] fail-visible）。
    pub fn complete(&self) -> bool {
        self.size.0 > 0 && self.size.1 > 0 && self.anchor_rect.2 > 0 && self.anchor_rect.3 > 0
    }

    /// raw placement 语义核（官方定位公式）：锚点取锚矩形边〔左/右/中
    /// × 上/下/中〕，popup 边缘按重力对齐锚点后施加 offset。返回 popup
    /// 左上角（父面局部坐标）。
    pub fn place(&self) -> (i32, i32) {
        let (arx, ary, arw, arh) = self.anchor_rect;
        // 锚点：水平边（left/right/中）× 垂直边（top/bottom/中）。
        let ax = match self.anchor {
            XDG_ANCHOR_LEFT | XDG_ANCHOR_TOP_LEFT | XDG_ANCHOR_BOTTOM_LEFT => arx,
            XDG_ANCHOR_RIGHT | XDG_ANCHOR_TOP_RIGHT | XDG_ANCHOR_BOTTOM_RIGHT => arx + arw,
            _ => arx + arw / 2,
        };
        let ay = match self.anchor {
            XDG_ANCHOR_TOP | XDG_ANCHOR_TOP_LEFT | XDG_ANCHOR_TOP_RIGHT => ary,
            XDG_ANCHOR_BOTTOM | XDG_ANCHOR_BOTTOM_LEFT | XDG_ANCHOR_BOTTOM_RIGHT => ary + arh,
            _ => ary + arh / 2,
        };
        // 重力对齐：popup 对应边缘落在锚点（left = popup 右缘贴锚点等）。
        let (pw, ph) = self.size;
        let px = match self.gravity {
            XDG_ANCHOR_LEFT | XDG_ANCHOR_TOP_LEFT | XDG_ANCHOR_BOTTOM_LEFT => ax - pw,
            XDG_ANCHOR_RIGHT | XDG_ANCHOR_TOP_RIGHT | XDG_ANCHOR_BOTTOM_RIGHT => ax,
            _ => ax - pw / 2,
        };
        let py = match self.gravity {
            XDG_ANCHOR_TOP | XDG_ANCHOR_TOP_LEFT | XDG_ANCHOR_TOP_RIGHT => ay - ph,
            XDG_ANCHOR_BOTTOM | XDG_ANCHOR_BOTTOM_LEFT | XDG_ANCHOR_BOTTOM_RIGHT => ay,
            _ => ay - ph / 2,
        };
        (px + self.offset.0, py + self.offset.1)
    }

    /// placement 语义核 v1（M52-POPCON78 笔90 约束域收口——官方施策序
    /// flip→slide→resize 逐轴 + 屏域裁剪）：`bound` = 约束域矩形（屏域
    /// /父域——消费方策略面注入，父面局部坐标）。逐轴：① flip（越界
    /// 且 FLIP 位在——重力对该轴翻转重算一次，翻转后全包容才施策）②
    /// slide（仍越界且 SLIDER 位在且 popup 全长界内可容——钳到界内）③
    /// resize（仍越界且 RESIZE 位在——对界求交截尺寸）。末段屏域裁剪
    /// 无条件施策（合成器永不外报越界 rect——无位域轴保持 raw 位置、
    /// 尺寸对界求交；完全出界 = 零面积域，零面积快径如实显形）。
    pub fn place_in_bounds(&self, bound: (i32, i32, i32, i32)) -> PlacedRect {
        let (bx, by, bw, bh) = bound;
        let (mut x, mut y) = self.place();
        let mut w = self.size.0;
        let mut h = self.size.1;
        // 零界守卫（bound 零面积 = 未注入约束域——raw 直通：t164 既有
        // 金值域零扰，消费方 boot 域 set_screen_bound 后施策域生效）。
        if bw <= 0 || bh <= 0 {
            return PlacedRect {
                x,
                y,
                w,
                h,
                flip_x: false,
                flip_y: false,
            };
        }
        let mut flip_x = false;
        let mut flip_y = false;
        // X 轴：flip → slide → resize（官方施策序逐轴）。
        let out_x = x < bx || x + w > bx + bw;
        if out_x && self.cadj & XDG_CADJ_FLIP_X != 0 {
            let mut flipped = *self;
            flipped.gravity = flip_gravity_x(self.gravity);
            let (fx, _) = flipped.place();
            if fx >= bx && fx + w <= bx + bw {
                x = fx;
                flip_x = true;
            }
        }
        if (x < bx || x + w > bx + bw) && self.cadj & XDG_CADJ_SLIDER_X != 0 && w <= bw {
            x = x.max(bx).min(bx + bw - w);
        }
        if (x < bx || x + w > bx + bw) && self.cadj & XDG_CADJ_RESIZE_X != 0 {
            let nx = x.max(bx);
            let nend = (x + w).min(bx + bw);
            x = nx;
            w = (nend - nx).max(0);
        }
        // Y 轴同构。
        let out_y = y < by || y + h > by + bh;
        if out_y && self.cadj & XDG_CADJ_FLIP_Y != 0 {
            let mut flipped = *self;
            flipped.gravity = flip_gravity_y(self.gravity);
            let (_, fy) = flipped.place();
            if fy >= by && fy + h <= by + bh {
                y = fy;
                flip_y = true;
            }
        }
        if (y < by || y + h > by + bh) && self.cadj & XDG_CADJ_SLIDER_Y != 0 && h <= bh {
            y = y.max(by).min(by + bh - h);
        }
        if (y < by || y + h > by + bh) && self.cadj & XDG_CADJ_RESIZE_Y != 0 {
            let ny = y.max(by);
            let nend = (y + h).min(by + bh);
            y = ny;
            h = (nend - ny).max(0);
        }
        // 屏域裁剪（无条件——合成器永不外报越界 rect）。
        let cx0 = x.max(bx);
        let cx1 = (x + w).min(bx + bw);
        let cy0 = y.max(by);
        let cy1 = (y + h).min(by + bh);
        PlacedRect {
            x,
            y,
            w: (cx1 - cx0).max(0),
            h: (cy1 - cy0).max(0),
            flip_x,
            flip_y,
        }
    }
}

/// 重力 X 轴翻转（官方 flip 语义——锚点不变，重力对该轴镜像：left↔
/// right；top/bottom/中轴保持）。top_left↔top_right、bottom_left↔
/// bottom_right 对称对换。
pub fn flip_gravity_x(g: u32) -> u32 {
    match g {
        XDG_ANCHOR_LEFT => XDG_ANCHOR_RIGHT,
        XDG_ANCHOR_RIGHT => XDG_ANCHOR_LEFT,
        XDG_ANCHOR_TOP_LEFT => XDG_ANCHOR_TOP_RIGHT,
        XDG_ANCHOR_TOP_RIGHT => XDG_ANCHOR_TOP_LEFT,
        XDG_ANCHOR_BOTTOM_LEFT => XDG_ANCHOR_BOTTOM_RIGHT,
        XDG_ANCHOR_BOTTOM_RIGHT => XDG_ANCHOR_BOTTOM_LEFT,
        _ => g,
    }
}

/// 重力 Y 轴翻转（top↔bottom；left/right/中轴保持）。
pub fn flip_gravity_y(g: u32) -> u32 {
    match g {
        XDG_ANCHOR_TOP => XDG_ANCHOR_BOTTOM,
        XDG_ANCHOR_BOTTOM => XDG_ANCHOR_TOP,
        XDG_ANCHOR_TOP_LEFT => XDG_ANCHOR_BOTTOM_LEFT,
        XDG_ANCHOR_BOTTOM_LEFT => XDG_ANCHOR_TOP_LEFT,
        XDG_ANCHOR_TOP_RIGHT => XDG_ANCHOR_BOTTOM_RIGHT,
        XDG_ANCHOR_BOTTOM_RIGHT => XDG_ANCHOR_TOP_RIGHT,
        _ => g,
    }
}

/// placement 约束域产出（M52-POPCON78 笔90）：x/y = flip/slide 后位置
/// （无施策轴 = raw）；w/h = 屏域裁剪后尺寸（屏域权威渲染域）；flip
/// 双旗 = 施策实录（t167 断言域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacedRect {
    /// popup 左上 x（父面局部坐标——configure 事件同值出域）。
    pub x: i32,
    /// popup 左上 y。
    pub y: i32,
    /// 屏域裁剪后宽。
    pub w: i32,
    /// 屏域裁剪后高。
    pub h: i32,
    /// X 轴 flip 实旗。
    pub flip_x: bool,
    /// Y 轴 flip 实旗。
    pub flip_y: bool,
}

// ---------------------------------------------------------------------------
// 核心子集签名表（官方 XML arg 声明序逐条对账——parse_message 消费域）
// ---------------------------------------------------------------------------

/// wl_display.sync：`(new_id)`。
pub const SIG_DISPLAY_SYNC: &[WlType] = &[WlType::NewId];
/// wl_display.get_registry：`(new_id)`。
pub const SIG_DISPLAY_GET_REGISTRY: &[WlType] = &[WlType::NewId];
/// wl_display.error 事件：`(object, uint, string)`。
pub const SIG_DISPLAY_ERROR: &[WlType] = &[WlType::Object, WlType::Uint, WlType::Str];
/// wl_display.delete_id 事件：`(uint)`。
pub const SIG_DISPLAY_DELETE_ID: &[WlType] = &[WlType::Uint];
/// wl_registry.bind：`(uint name, string interface, uint version, new_id)`
/// ——bind 特例（XML 未标注接口的 new_id：interface string + version
/// 前随，官方文档口径）。
pub const SIG_REGISTRY_BIND: &[WlType] = &[WlType::Uint, WlType::Str, WlType::Uint, WlType::NewId];
/// wl_registry.global 事件：`(uint, string, uint)`。
pub const SIG_REGISTRY_GLOBAL: &[WlType] = &[WlType::Uint, WlType::Str, WlType::Uint];
/// wl_registry.global_remove 事件：`(uint)`。
pub const SIG_REGISTRY_GLOBAL_REMOVE: &[WlType] = &[WlType::Uint];
/// wl_callback.done 事件：`(uint)`。
pub const SIG_CALLBACK_DONE: &[WlType] = &[WlType::Uint];
/// wl_compositor.create_surface：`(new_id)`。
pub const SIG_COMPOSITOR_CREATE_SURFACE: &[WlType] = &[WlType::NewId];
/// wl_compositor.create_region：`(new_id)`。
pub const SIG_COMPOSITOR_CREATE_REGION: &[WlType] = &[WlType::NewId];
/// wl_surface.attach：`(object, int, int)`。
pub const SIG_SURFACE_ATTACH: &[WlType] = &[WlType::Object, WlType::Int, WlType::Int];
/// wl_surface.damage：`(int × 4)`。
pub const SIG_SURFACE_DAMAGE: &[WlType] = &[WlType::Int, WlType::Int, WlType::Int, WlType::Int];
/// wl_surface.frame：`(new_id)`。
pub const SIG_SURFACE_FRAME: &[WlType] = &[WlType::NewId];
/// wl_surface.commit：`()`。
pub const SIG_SURFACE_COMMIT: &[WlType] = &[];
/// wl_surface.enter 事件：`(object)`。
pub const SIG_SURFACE_ENTER: &[WlType] = &[WlType::Object];
/// wl_buffer.release 事件：`()`。
pub const SIG_BUFFER_RELEASE: &[WlType] = &[];
/// wl_seat.capabilities 事件：`(uint)`。
pub const SIG_SEAT_CAPABILITIES: &[WlType] = &[WlType::Uint];
/// wl_seat.get_pointer：`(new_id)`。
pub const SIG_SEAT_GET_POINTER: &[WlType] = &[WlType::NewId];
/// wl_seat.get_keyboard：`(new_id)`。
pub const SIG_SEAT_GET_KEYBOARD: &[WlType] = &[WlType::NewId];
/// wl_keyboard.keymap 事件：`(fd, uint format, uint size)`——fd 走
/// 消息内 1 字占位（附带数据电气挂账，M42-UNIX3 口径同源）。
pub const SIG_KEYBOARD_KEYMAP: &[WlType] = &[WlType::Fd, WlType::Uint, WlType::Uint];
/// wl_keyboard.enter 事件：`(uint serial, object surface, array keys)`
/// ——keys = 当前按下键码数组（v0 空数组域）。
pub const SIG_KEYBOARD_ENTER: &[WlType] = &[WlType::Uint, WlType::Object, WlType::Array];
/// wl_keyboard.leave 事件：`(uint serial, object surface)`。
pub const SIG_KEYBOARD_LEAVE: &[WlType] = &[WlType::Uint, WlType::Object];
/// wl_keyboard.key 事件：`(uint serial, uint time, uint key, uint state)`。
pub const SIG_KEYBOARD_KEY: &[WlType] = &[WlType::Uint, WlType::Uint, WlType::Uint, WlType::Uint];
/// wl_keyboard.modifiers 事件：`(uint × 5)`（v0 全零域——修饰键语义挂账）。
pub const SIG_KEYBOARD_MODIFIERS: &[WlType] = &[
    WlType::Uint,
    WlType::Uint,
    WlType::Uint,
    WlType::Uint,
    WlType::Uint,
];
/// wl_keyboard.repeat_info 事件（M42-KBREP34 笔㉞）：`(uint rate,
/// uint delay)`——键重复公告面（rate = 每秒重复数，delay = 首重复前
/// 毫秒；M43-KBREP37 笔㊷ 真值公告域——v0 关闭声明 0/0 退役，默认
/// rate=25/delay=400 会话域承载 + 生产域在环）。
pub const SIG_KEYBOARD_REPEAT_INFO: &[WlType] = &[WlType::Uint, WlType::Uint];
/// wl_keyboard.set_cursor 请求：`(uint serial, object surface,
/// int hotspot_x, int hotspot_y)`（M43-KBREP37 笔㊷——surface 0 合法
/// = 默认光标回退域）。
pub const SIG_KEYBOARD_SET_CURSOR: &[WlType] =
    &[WlType::Uint, WlType::Object, WlType::Int, WlType::Int];
/// wl_pointer.enter 事件：`(uint serial, object surface, fixed x,
/// fixed y)`——surface 局部坐标域（fixed 24.8 原字透传）。
pub const SIG_POINTER_ENTER: &[WlType] =
    &[WlType::Uint, WlType::Object, WlType::Fixed, WlType::Fixed];
/// wl_pointer.leave 事件：`(uint serial, object surface)`。
pub const SIG_POINTER_LEAVE: &[WlType] = &[WlType::Uint, WlType::Object];
/// wl_pointer.motion 事件：`(uint time, fixed x, fixed y)`。
pub const SIG_POINTER_MOTION: &[WlType] = &[WlType::Uint, WlType::Fixed, WlType::Fixed];
/// wl_pointer.button 事件：`(uint serial, uint time, uint button,
/// uint state)`。
pub const SIG_POINTER_BUTTON: &[WlType] = &[WlType::Uint, WlType::Uint, WlType::Uint, WlType::Uint];
/// wl_pointer.axis 事件：`(uint time, uint axis, fixed value)`——value
/// 为 fixed 24.8 位移增量（M42-WAYCOMP14 axis 族）。
pub const SIG_POINTER_AXIS: &[WlType] = &[WlType::Uint, WlType::Uint, WlType::Fixed];
/// wl_pointer.frame 事件：`()`——axis/axis_source/axis_stop 分组终结
/// 逻辑事件（M42-WAYCOMP14 axis 族）。
pub const SIG_POINTER_FRAME: &[WlType] = &[];
/// wl_pointer.axis_source 事件：`(uint axis_source)`。
pub const SIG_POINTER_AXIS_SOURCE: &[WlType] = &[WlType::Uint];
/// wl_pointer.axis_stop 事件：`(uint time, uint axis)`。
pub const SIG_POINTER_AXIS_STOP: &[WlType] = &[WlType::Uint, WlType::Uint];
/// wl_pointer.axis_value120 事件：`(uint axis, int value120)`——离散步
/// 进语义（M43-AV12036：value120 = 自上次 value120 以来的步进累计 ×
/// 120，负值反向——官方 "ui" 签名逐字对账）。
pub const SIG_POINTER_AXIS_VALUE120: &[WlType] = &[WlType::Uint, WlType::Int];
/// wl_shm.create_pool：`(new_id, fd, int)`。
pub const SIG_SHM_CREATE_POOL: &[WlType] = &[WlType::NewId, WlType::Fd, WlType::Int];
/// wl_shm_pool.create_buffer：`(new_id, int offset, int width, int
/// height, int stride, uint format)`（M42-ELF5 桌面链批次——客户端
/// 像素缓冲承载面）。
pub const SIG_SHM_POOL_CREATE_BUFFER: &[WlType] = &[
    WlType::NewId,
    WlType::Int,
    WlType::Int,
    WlType::Int,
    WlType::Int,
    WlType::Uint,
];
/// wl_shm_pool.destroy：`()`。
pub const SIG_SHM_POOL_DESTROY: &[WlType] = &[];

// --- xdg_shell 窗口管理协议签名表（M50-XDGSHELL66 笔76——官方
// xdg-shell.xml arg 声明序逐条对账） ---

/// xdg_wm_base.get_xdg_surface：`(new_id, object)`。
pub const SIG_XDG_WM_BASE_GET_XDG_SURFACE: &[WlType] = &[WlType::NewId, WlType::Object];
/// xdg_wm_base.pong：`(uint)`。
pub const SIG_XDG_WM_BASE_PONG: &[WlType] = &[WlType::Uint];
/// xdg_wm_base.ping：`(uint)`。
pub const SIG_XDG_WM_BASE_PING: &[WlType] = &[WlType::Uint];
/// xdg_surface.get_toplevel：`(new_id)`。
pub const SIG_XDG_SURFACE_GET_TOPLEVEL: &[WlType] = &[WlType::NewId];
/// xdg_surface.set_window_geometry：`(int × 4)`。
pub const SIG_XDG_SURFACE_SET_WINDOW_GEOMETRY: &[WlType] =
    &[WlType::Int, WlType::Int, WlType::Int, WlType::Int];
/// xdg_surface.ack_configure：`(uint)`。
pub const SIG_XDG_SURFACE_ACK_CONFIGURE: &[WlType] = &[WlType::Uint];
/// xdg_surface.configure：`(uint)`。
pub const SIG_XDG_SURFACE_CONFIGURE: &[WlType] = &[WlType::Uint];
/// xdg_toplevel.set_title：`(string)`。
pub const SIG_XDG_TOPLEVEL_SET_TITLE: &[WlType] = &[WlType::Str];
/// xdg_toplevel.set_app_id：`(string)`。
pub const SIG_XDG_TOPLEVEL_SET_APP_ID: &[WlType] = &[WlType::Str];
/// xdg_toplevel.configure：`(int, int, array)`——states 数组字节域。
pub const SIG_XDG_TOPLEVEL_CONFIGURE: &[WlType] = &[WlType::Int, WlType::Int, WlType::Array];
/// xdg_toplevel.close：`()`。
pub const SIG_XDG_TOPLEVEL_CLOSE: &[WlType] = &[];
/// xdg_wm_base.create_positioner：`(new_id)`（M51-XDGPOP75 笔86）。
pub const SIG_XDG_WM_BASE_CREATE_POSITIONER: &[WlType] = &[WlType::NewId];
/// xdg_surface.get_popup：`(new_id, object, object)`（M51-XDGPOP75
/// 笔86——popup new_id + parent xdg_surface + positioner）。
pub const SIG_XDG_SURFACE_GET_POPUP: &[WlType] = &[WlType::NewId, WlType::Object, WlType::Object];
/// xdg_toplevel.set_min_size：`(int, int)`（M51-XDGPOP75 笔86——0 = 未
/// 设定，官方语义）。
pub const SIG_XDG_TOPLEVEL_SET_MIN_SIZE: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_toplevel.set_max_size：`(int, int)`。
pub const SIG_XDG_TOPLEVEL_SET_MAX_SIZE: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_toplevel.set_maximized：零参（M53-XDGSTAT83 笔96 状态族消费面）。
pub const SIG_XDG_TOPLEVEL_SET_MAXIMIZED: &[WlType] = &[];
/// xdg_toplevel.unset_maximized：零参。
pub const SIG_XDG_TOPLEVEL_UNSET_MAXIMIZED: &[WlType] = &[];
/// xdg_toplevel.set_fullscreen：`(object)`——官方可空 output（v0 承载
/// 不入账，output 对象域语义挂账如实）。
pub const SIG_XDG_TOPLEVEL_SET_FULLSCREEN: &[WlType] = &[WlType::Object];
/// xdg_toplevel.unset_fullscreen：零参。
pub const SIG_XDG_TOPLEVEL_UNSET_FULLSCREEN: &[WlType] = &[];
/// xdg_toplevel.set_minimized：零参（官方无 unset_minimized——解除由
/// 合成器策略面承接，域外挂账如实）。
pub const SIG_XDG_TOPLEVEL_SET_MINIMIZED: &[WlType] = &[];
/// xdg_positioner.set_size：`(int, int)`。
pub const SIG_XDG_POSITIONER_SET_SIZE: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_positioner.set_anchor_rect：`(int × 4)`。
pub const SIG_XDG_POSITIONER_SET_ANCHOR_RECT: &[WlType] =
    &[WlType::Int, WlType::Int, WlType::Int, WlType::Int];
/// xdg_positioner.set_anchor：`(uint)`。
pub const SIG_XDG_POSITIONER_SET_ANCHOR: &[WlType] = &[WlType::Uint];
/// xdg_positioner.set_gravity：`(uint)`。
pub const SIG_XDG_POSITIONER_SET_GRAVITY: &[WlType] = &[WlType::Uint];
/// xdg_positioner.set_constraint_adjustment：`(uint)`。
pub const SIG_XDG_POSITIONER_SET_CONSTRAINT_ADJUSTMENT: &[WlType] = &[WlType::Uint];
/// xdg_positioner.set_offset：`(int, int)`。
pub const SIG_XDG_POSITIONER_SET_OFFSET: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_popup.grab：`(object, uint)`（seat + serial——官方 arg 序）。
pub const SIG_XDG_POPUP_GRAB: &[WlType] = &[WlType::Object, WlType::Uint];
/// xdg_popup.configure：`(int, int)`——popup 位置（父面局部坐标）。
pub const SIG_XDG_POPUP_CONFIGURE: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_popup.popup_done：`()`。
pub const SIG_XDG_POPUP_POPUP_DONE: &[WlType] = &[];
/// xdg_positioner.set_reactive：`()`（v3——零参宣告，M52-POPCON78 笔90）。
pub const SIG_XDG_POSITIONER_SET_REACTIVE: &[WlType] = &[];
/// xdg_positioner.set_parent_size：`(int, int)`（v3——reactive 父尺寸）。
pub const SIG_XDG_POSITIONER_SET_PARENT_SIZE: &[WlType] = &[WlType::Int, WlType::Int];
/// xdg_positioner.set_parent_configure：`(uint)`（v3——reactive 父串号）。
pub const SIG_XDG_POSITIONER_SET_PARENT_CONFIGURE: &[WlType] = &[WlType::Uint];
/// xdg_popup.reposition：`(object, uint)`（v3——positioner + token）。
pub const SIG_XDG_POPUP_REPOSITION: &[WlType] = &[WlType::Object, WlType::Uint];
/// xdg_popup.repositioned 事件：`(uint)`（v3——token 回执）。
pub const SIG_XDG_POPUP_REPOSITIONED: &[WlType] = &[WlType::Uint];

// --- 输入链语义常量（官方 XML 枚举值逐字对账——宿主测试 + t109 消费面） ---

/// wl_seat.capabilities 位域：pointer（1）。
pub const SEAT_CAPS_POINTER: u32 = 1;
/// wl_seat.capabilities 位域：keyboard（2）。
pub const SEAT_CAPS_KEYBOARD: u32 = 2;
/// wl_keyboard.keymap format：no keymap（0）。
pub const KEYMAP_FORMAT_NO_KEYMAP: u32 = 0;
/// wl_keyboard.keymap format：xkb v1（1）。
pub const KEYMAP_FORMAT_XKB_V1: u32 = 1;
/// wl_keyboard.key state：released（0）。
pub const KEY_STATE_RELEASED: u32 = 0;
/// wl_keyboard.key state：pressed（1）。
pub const KEY_STATE_PRESSED: u32 = 1;
/// XKB 修饰键掩码：Shift（1<<0——xkbcommon 语义域，M42-WAYCOMP15）。
pub const MOD_SHIFT: u32 = 1 << 0;
/// XKB 修饰键掩码：Caps Lock（1<<1，Lock 域）。
pub const MOD_CAPS: u32 = 1 << 1;
/// XKB 修饰键掩码：Control（1<<2）。
pub const MOD_CTRL: u32 = 1 << 2;
/// XKB 修饰键掩码：Alt / Mod1（1<<3）。
pub const MOD_ALT: u32 = 1 << 3;
/// XKB 修饰键掩码：Num Lock / Mod2（1<<4，Lock 域）。
pub const MOD_NUM2: u32 = 1 << 4;
/// XKB 修饰键掩码：Mod3（1<<5）。
pub const MOD_MOD3: u32 = 1 << 5;
/// XKB 修饰键掩码：Super / Mod4（1<<6）。
pub const MOD_MOD4: u32 = 1 << 6;
/// XKB 修饰键掩码：Mod5（1<<7）。
pub const MOD_MOD5: u32 = 1 << 7;
/// wl_pointer.button state：released（0）。
pub const BTN_STATE_RELEASED: u32 = 0;
/// wl_pointer.button state：pressed（1）。
pub const BTN_STATE_PRESSED: u32 = 1;
/// wl_pointer axis：vertical scroll（0——官方 enum axis）。
pub const AXIS_VERTICAL_SCROLL: u32 = 0;
/// wl_pointer axis：horizontal scroll（1——官方 enum axis）。
pub const AXIS_HORIZONTAL_SCROLL: u32 = 1;
/// wl_pointer axis_source：wheel（0——物理滚轮）。
pub const AXIS_SOURCE_WHEEL: u32 = 0;
/// wl_pointer axis_source：finger（1——触摸板手势）。
pub const AXIS_SOURCE_FINGER: u32 = 1;
/// wl_pointer axis_source：continuous（2——高精度滚动）。
pub const AXIS_SOURCE_CONTINUOUS: u32 = 2;
/// wl_pointer axis_source：wheel_tilt（3——滚轮倾斜）。
pub const AXIS_SOURCE_WHEEL_TILT: u32 = 3;
/// evdev 按钮码：BTN_LEFT（0x110——官方 XML 枚举域）。
pub const BTN_LEFT: u32 = 0x110;

// ---------------------------------------------------------------------------
// 语义便利编组器（阶段三合成器/客户端车道预置——宿主测试 + t103 消费面）
// ---------------------------------------------------------------------------

/// wl_display.sync 请求编组。
pub fn encode_display_sync(
    buf: &mut [u8],
    display_id: u32,
    callback_new_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        display_id,
        display::REQ_SYNC,
        &[WlArg::NewId(callback_new_id)],
    )
}

/// wl_display.get_registry 请求编组。
pub fn encode_display_get_registry(
    buf: &mut [u8],
    display_id: u32,
    registry_new_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        display_id,
        display::REQ_GET_REGISTRY,
        &[WlArg::NewId(registry_new_id)],
    )
}

/// wl_registry.bind 请求编组（bind 特例签名——interface string + version）。
pub fn encode_registry_bind(
    buf: &mut [u8],
    registry_id: u32,
    name: u32,
    iface: &str,
    version: u32,
    new_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        registry_id,
        registry::REQ_BIND,
        &[
            WlArg::Uint(name),
            WlArg::Str(iface.as_bytes()),
            WlArg::Uint(version),
            WlArg::NewId(new_id),
        ],
    )
}

/// wl_registry.global 事件编组（事件序列化样本——合成器面向客户端的
/// global 公告；iface = [`WlIface`]，名取 [`iface_name`] 官方面）。
pub fn encode_registry_global_event(
    buf: &mut [u8],
    registry_id: u32,
    name: u32,
    iface: WlIface,
    version: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        registry_id,
        registry::EV_GLOBAL,
        &[
            WlArg::Uint(name),
            WlArg::Str(iface_name(iface).as_bytes()),
            WlArg::Uint(version),
        ],
    )
}

/// wl_callback.done 事件编组（帧回调语义样本）。
pub fn encode_callback_done_event(
    buf: &mut [u8],
    callback_id: u32,
    callback_data: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        callback_id,
        callback::EV_DONE,
        &[WlArg::Uint(callback_data)],
    )
}

/// wl_display.delete_id 事件编组（M42-WAYCOMP18 多注册表面——callback
/// 对象 done 后服务端销毁随行宣告：官方生命周期语义——客户端据
/// delete_id 回收 id 复用域，服务端对象表同步摘除）。
pub fn encode_display_delete_id_event(
    buf: &mut [u8],
    display_id: u32,
    destroyed_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        display_id,
        display::EV_DELETE_ID,
        &[WlArg::Uint(destroyed_id)],
    )
}

/// wl_surface.commit 请求编组（零参消息——签名空表域）。
pub fn encode_surface_commit(buf: &mut [u8], surface_id: u32) -> Result<usize, WlError> {
    encode_message(buf, surface_id, surface::REQ_COMMIT, &[])
}

// --- xdg_shell 窗口管理协议编组器（M50-XDGSHELL66 笔76——v0 最小面：
//     get_xdg_surface / get_toplevel / set_title / set_app_id / pong /
//     ack_configure 六请求 + ping/configure/close 三事件；官方
//     xdg-shell.xml 声明序，configure/ack 双向序契约面先行） ---

/// xdg_wm_base.get_xdg_surface 请求编组（per-surface 窗口角色装载体）。
pub fn encode_xdg_wm_base_get_xdg_surface(
    buf: &mut [u8],
    wmbase_id: u32,
    xdg_surface_new_id: u32,
    surface_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        wmbase_id,
        xdg_wm_base::REQ_GET_XDG_SURFACE,
        &[WlArg::NewId(xdg_surface_new_id), WlArg::Object(surface_id)],
    )
}

/// xdg_wm_base.pong 请求编组（ping 应答——官方 liveness 契约）。
pub fn encode_xdg_wm_base_pong(
    buf: &mut [u8],
    wmbase_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        wmbase_id,
        xdg_wm_base::REQ_PONG,
        &[WlArg::Uint(serial)],
    )
}

/// xdg_wm_base.ping 事件编组（服务端 → 客户端 liveness 探测；v0 服务端
/// 不主动 ping——契约面先行，电气挂账）。
pub fn encode_xdg_wm_base_ping_event(
    buf: &mut [u8],
    wmbase_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(buf, wmbase_id, xdg_wm_base::EV_PING, &[WlArg::Uint(serial)])
}

/// xdg_surface.get_toplevel 请求编组（toplevel 应用窗角色派生）。
pub fn encode_xdg_surface_get_toplevel(
    buf: &mut [u8],
    xdg_surface_id: u32,
    toplevel_new_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        xdg_surface_id,
        xdg_surface::REQ_GET_TOPLEVEL,
        &[WlArg::NewId(toplevel_new_id)],
    )
}

/// xdg_surface.ack_configure 请求编组（commit 前必须 ack 最近一次
/// configure——官方双向序契约）。
pub fn encode_xdg_surface_ack_configure(
    buf: &mut [u8],
    xdg_surface_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        xdg_surface_id,
        xdg_surface::REQ_ACK_CONFIGURE,
        &[WlArg::Uint(serial)],
    )
}

/// xdg_surface.configure 事件编组（初始几何零值 = 服务端策略自主；
/// 客户端 commit 前必须 ack 本串号）。
pub fn encode_xdg_surface_configure_event(
    buf: &mut [u8],
    xdg_surface_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        xdg_surface_id,
        xdg_surface::EV_CONFIGURE,
        &[WlArg::Uint(serial)],
    )
}

/// xdg_toplevel.set_title 请求编组（v0 最小面主请求——标题字符串）。
pub fn encode_xdg_toplevel_set_title(
    buf: &mut [u8],
    toplevel_id: u32,
    title: &str,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        toplevel_id,
        xdg_toplevel::REQ_SET_TITLE,
        &[WlArg::Str(title.as_bytes())],
    )
}

/// xdg_toplevel.set_app_id 请求编组。
pub fn encode_xdg_toplevel_set_app_id(
    buf: &mut [u8],
    toplevel_id: u32,
    app_id: &str,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        toplevel_id,
        xdg_toplevel::REQ_SET_APP_ID,
        &[WlArg::Str(app_id.as_bytes())],
    )
}

/// xdg_toplevel.configure 事件编组（w/h 零值 = 服务端策略自主 +
/// states 数组字节域——v0 空态数组）。
pub fn encode_xdg_toplevel_configure_event(
    buf: &mut [u8],
    toplevel_id: u32,
    width: i32,
    height: i32,
    states: &[u8],
) -> Result<usize, WlError> {
    encode_message(
        buf,
        toplevel_id,
        xdg_toplevel::EV_CONFIGURE,
        &[WlArg::Int(width), WlArg::Int(height), WlArg::Array(states)],
    )
}

/// xdg_toplevel.close 事件编组（v0 最小面主事件——用户关闭请求，
/// 官方语义：客户端销毁窗口对象不再等 configure）。
pub fn encode_xdg_toplevel_close_event(buf: &mut [u8], toplevel_id: u32) -> Result<usize, WlError> {
    encode_message(buf, toplevel_id, xdg_toplevel::EV_CLOSE, &[])
}

// --- xdg_popup 尺寸交互族编组器（M51-XDGPOP75 笔86——官方
//     xdg-shell.xml 声明序：positioner 六 setter + create_positioner +
//     get_popup + toplevel min/max + popup grab/configure/done） ---

/// xdg_wm_base.create_positioner 请求编组（popup 定位参数装载体派生）。
pub fn encode_xdg_wm_base_create_positioner(
    buf: &mut [u8],
    wmbase_id: u32,
    positioner_new_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        wmbase_id,
        xdg_wm_base::REQ_CREATE_POSITIONER,
        &[WlArg::NewId(positioner_new_id)],
    )
}

/// xdg_positioner.set_size 请求编组（popup 内容尺寸宣告）。
pub fn encode_xdg_positioner_set_size(
    buf: &mut [u8],
    positioner_id: u32,
    width: i32,
    height: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_SIZE,
        &[WlArg::Int(width), WlArg::Int(height)],
    )
}

/// xdg_positioner.set_anchor_rect 请求编组（父面局部坐标锚矩形）。
pub fn encode_xdg_positioner_set_anchor_rect(
    buf: &mut [u8],
    positioner_id: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_ANCHOR_RECT,
        &[
            WlArg::Int(x),
            WlArg::Int(y),
            WlArg::Int(width),
            WlArg::Int(height),
        ],
    )
}

/// xdg_positioner.set_anchor 请求编组（锚边枚举）。
pub fn encode_xdg_positioner_set_anchor(
    buf: &mut [u8],
    positioner_id: u32,
    anchor: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_ANCHOR,
        &[WlArg::Uint(anchor)],
    )
}

/// xdg_positioner.set_gravity 请求编组（重力枚举）。
pub fn encode_xdg_positioner_set_gravity(
    buf: &mut [u8],
    positioner_id: u32,
    gravity: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_GRAVITY,
        &[WlArg::Uint(gravity)],
    )
}

/// xdg_positioner.set_constraint_adjustment 请求编组（约束调整位域）。
pub fn encode_xdg_positioner_set_constraint_adjustment(
    buf: &mut [u8],
    positioner_id: u32,
    cadj: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_CONSTRAINT_ADJUSTMENT,
        &[WlArg::Uint(cadj)],
    )
}

/// xdg_positioner.set_offset 请求编组（锚点偏移）。
pub fn encode_xdg_positioner_set_offset(
    buf: &mut [u8],
    positioner_id: u32,
    x: i32,
    y: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_OFFSET,
        &[WlArg::Int(x), WlArg::Int(y)],
    )
}

/// xdg_surface.get_popup 请求编组（popup 角色派生——parent xdg_
/// surface + positioner 双参在环）。
pub fn encode_xdg_surface_get_popup(
    buf: &mut [u8],
    xdg_surface_id: u32,
    popup_new_id: u32,
    parent_id: u32,
    positioner_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        xdg_surface_id,
        xdg_surface::REQ_GET_POPUP,
        &[
            WlArg::NewId(popup_new_id),
            WlArg::Object(parent_id),
            WlArg::Object(positioner_id),
        ],
    )
}

/// xdg_toplevel.set_min_size 请求编组（0 = 未设定，官方语义）。
pub fn encode_xdg_toplevel_set_min_size(
    buf: &mut [u8],
    toplevel_id: u32,
    width: i32,
    height: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        toplevel_id,
        xdg_toplevel::REQ_SET_MIN_SIZE,
        &[WlArg::Int(width), WlArg::Int(height)],
    )
}

/// xdg_toplevel.set_max_size 请求编组。
pub fn encode_xdg_toplevel_set_max_size(
    buf: &mut [u8],
    toplevel_id: u32,
    width: i32,
    height: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        toplevel_id,
        xdg_toplevel::REQ_SET_MAX_SIZE,
        &[WlArg::Int(width), WlArg::Int(height)],
    )
}

/// xdg_popup.grab 请求编组（seat + serial——官方 arg 序）。
pub fn encode_xdg_popup_grab(
    buf: &mut [u8],
    popup_id: u32,
    seat_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        popup_id,
        xdg_popup::REQ_GRAB,
        &[WlArg::Object(seat_id), WlArg::Uint(serial)],
    )
}

/// xdg_popup.configure 事件编组（popup 位置——父面局部坐标）。
pub fn encode_xdg_popup_configure_event(
    buf: &mut [u8],
    popup_id: u32,
    x: i32,
    y: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        popup_id,
        xdg_popup::EV_CONFIGURE,
        &[WlArg::Int(x), WlArg::Int(y)],
    )
}

/// xdg_popup.popup_done 事件编组（收场契约——客户端应销毁 popup）。
pub fn encode_xdg_popup_done_event(buf: &mut [u8], popup_id: u32) -> Result<usize, WlError> {
    encode_message(buf, popup_id, xdg_popup::EV_POPUP_DONE, &[])
}

/// xdg_positioner.set_reactive 请求编组（v3——零参宣告）。
pub fn encode_xdg_positioner_set_reactive(
    buf: &mut [u8],
    positioner_id: u32,
) -> Result<usize, WlError> {
    encode_message(buf, positioner_id, xdg_positioner::REQ_SET_REACTIVE, &[])
}

/// xdg_positioner.set_parent_size 请求编组（v3——reactive 父尺寸）。
pub fn encode_xdg_positioner_set_parent_size(
    buf: &mut [u8],
    positioner_id: u32,
    width: i32,
    height: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_PARENT_SIZE,
        &[WlArg::Int(width), WlArg::Int(height)],
    )
}

/// xdg_positioner.set_parent_configure 请求编组（v3——reactive 父串号）。
pub fn encode_xdg_positioner_set_parent_configure(
    buf: &mut [u8],
    positioner_id: u32,
    serial: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        positioner_id,
        xdg_positioner::REQ_SET_PARENT_CONFIGURE,
        &[WlArg::Uint(serial)],
    )
}

/// xdg_popup.reposition 请求编组（v3——positioner + token 官方 arg 序）。
pub fn encode_xdg_popup_reposition(
    buf: &mut [u8],
    popup_id: u32,
    positioner_id: u32,
    token: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        popup_id,
        xdg_popup::REQ_REPOSITION,
        &[WlArg::Object(positioner_id), WlArg::Uint(token)],
    )
}

/// xdg_popup.repositioned 事件编组（v3——token 回执；官方序 =
/// repositioned 先行、configure(x,y) 随行）。
pub fn encode_xdg_popup_repositioned_event(
    buf: &mut [u8],
    popup_id: u32,
    token: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        popup_id,
        xdg_popup::EV_REPOSITIONED,
        &[WlArg::Uint(token)],
    )
}

/// wl_seat.capabilities 事件编组（M42-INPUT7 输入链——seat bind 后
/// 设备能力公告；caps = [`SEAT_CAPS_POINTER`] ∪ [`SEAT_CAPS_KEYBOARD`]）。
pub fn encode_seat_capabilities_event(
    buf: &mut [u8],
    seat_id: u32,
    caps: u32,
) -> Result<usize, WlError> {
    encode_message(buf, seat_id, seat::EV_CAPABILITIES, &[WlArg::Uint(caps)])
}

/// wl_keyboard.keymap 事件编组（fd 占位字域——keymap 内容面挂账）。
pub fn encode_keyboard_keymap_event(
    buf: &mut [u8],
    keyboard_id: u32,
    fd_placeholder: u32,
    format: u32,
    size: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_KEYMAP,
        &[
            WlArg::Fd(fd_placeholder),
            WlArg::Uint(format),
            WlArg::Uint(size),
        ],
    )
}

/// wl_keyboard.enter 事件编组（键盘焦点域——keys 数组 v0 空域）。
pub fn encode_keyboard_enter_event(
    buf: &mut [u8],
    keyboard_id: u32,
    serial: u32,
    surface_id: u32,
    keys: &[u8],
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_ENTER,
        &[
            WlArg::Uint(serial),
            WlArg::Object(surface_id),
            WlArg::Array(keys),
        ],
    )
}

/// wl_keyboard.leave 事件编组（键盘焦点离域）。
pub fn encode_keyboard_leave_event(
    buf: &mut [u8],
    keyboard_id: u32,
    serial: u32,
    surface_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_LEAVE,
        &[WlArg::Uint(serial), WlArg::Object(surface_id)],
    )
}

/// wl_keyboard.key 事件编组（击键域）。
pub fn encode_keyboard_key_event(
    buf: &mut [u8],
    keyboard_id: u32,
    serial: u32,
    time: u32,
    key: u32,
    state: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_KEY,
        &[
            WlArg::Uint(serial),
            WlArg::Uint(time),
            WlArg::Uint(key),
            WlArg::Uint(state),
        ],
    )
}

/// wl_keyboard.modifiers 事件编组（M42-WAYCOMP15——官方五参语义域：
/// serial + mods_depressed + mods_latched + mods_locked + group）。
pub fn encode_keyboard_modifiers_event(
    buf: &mut [u8],
    keyboard_id: u32,
    serial: u32,
    mods_depressed: u32,
    mods_latched: u32,
    mods_locked: u32,
    group: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_MODIFIERS,
        &[
            WlArg::Uint(serial),
            WlArg::Uint(mods_depressed),
            WlArg::Uint(mods_latched),
            WlArg::Uint(mods_locked),
            WlArg::Uint(group),
        ],
    )
}

/// wl_keyboard.repeat_info 事件编组（M42-KBREP34 笔㉞——键盘派生
/// 域 keymap 后随行公告：rate/delay 双 uint，v0 重复关闭声明口径
/// 0/0）。返回编组字节数（8 头 + 8 体 = 16）。
pub fn encode_keyboard_repeat_info_event(
    buf: &mut [u8],
    keyboard_id: u32,
    rate: u32,
    delay: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        keyboard_id,
        keyboard::EV_REPEAT_INFO,
        &[WlArg::Uint(rate), WlArg::Uint(delay)],
    )
}

/// wl_pointer.enter 事件编组（指针焦点域——fixed 24.8 原字）。
pub fn encode_pointer_enter_event(
    buf: &mut [u8],
    pointer_id: u32,
    serial: u32,
    surface_id: u32,
    x: i32,
    y: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_ENTER,
        &[
            WlArg::Uint(serial),
            WlArg::Object(surface_id),
            WlArg::Fixed(x),
            WlArg::Fixed(y),
        ],
    )
}

/// wl_pointer.leave 事件编组（指针焦点离域）。
pub fn encode_pointer_leave_event(
    buf: &mut [u8],
    pointer_id: u32,
    serial: u32,
    surface_id: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_LEAVE,
        &[WlArg::Uint(serial), WlArg::Object(surface_id)],
    )
}

/// wl_pointer.motion 事件编组（指针移动域）。
pub fn encode_pointer_motion_event(
    buf: &mut [u8],
    pointer_id: u32,
    time: u32,
    x: i32,
    y: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_MOTION,
        &[WlArg::Uint(time), WlArg::Fixed(x), WlArg::Fixed(y)],
    )
}

/// wl_pointer.button 事件编组（按键域——evdev 按钮码 + 键态）。
pub fn encode_pointer_button_event(
    buf: &mut [u8],
    pointer_id: u32,
    serial: u32,
    time: u32,
    button: u32,
    state: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_BUTTON,
        &[
            WlArg::Uint(serial),
            WlArg::Uint(time),
            WlArg::Uint(button),
            WlArg::Uint(state),
        ],
    )
}

/// wl_pointer.axis 事件编组（M42-WAYCOMP14——axis 族：value 为 fixed
/// 24.8 原字）。
pub fn encode_pointer_axis_event(
    buf: &mut [u8],
    pointer_id: u32,
    time: u32,
    axis: u32,
    value: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_AXIS,
        &[WlArg::Uint(time), WlArg::Uint(axis), WlArg::Fixed(value)],
    )
}

/// wl_pointer.frame 事件编组（M42-WAYCOMP14——axis 族分组终结逻辑事
/// 件，零载荷）。
pub fn encode_pointer_frame_event(buf: &mut [u8], pointer_id: u32) -> Result<usize, WlError> {
    encode_message(buf, pointer_id, pointer::EV_FRAME, &[])
}

/// wl_pointer.axis_source 事件编组（M42-WAYCOMP14——frame 域轴源前置
/// 声明）。
pub fn encode_pointer_axis_source_event(
    buf: &mut [u8],
    pointer_id: u32,
    axis_source: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_AXIS_SOURCE,
        &[WlArg::Uint(axis_source)],
    )
}

/// wl_pointer.axis_stop 事件编组（M42-WAYCOMP14——滚动手势终结）。
pub fn encode_pointer_axis_stop_event(
    buf: &mut [u8],
    pointer_id: u32,
    time: u32,
    axis: u32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_AXIS_STOP,
        &[WlArg::Uint(time), WlArg::Uint(axis)],
    )
}

/// wl_pointer.axis_value120 事件编组（M43-AV12036——离散步进语义：
/// wheel 源 frame 域 axis 事件随行声明，官方序 axis → value120 同
/// frame；value120 = 步进 × 120 原字透传〔int 非 fixed〕）。
pub fn encode_pointer_axis_value120_event(
    buf: &mut [u8],
    pointer_id: u32,
    axis: u32,
    value120: i32,
) -> Result<usize, WlError> {
    encode_message(
        buf,
        pointer_id,
        pointer::EV_AXIS_VALUE120,
        &[WlArg::Uint(axis), WlArg::Int(value120)],
    )
}

// -------------------------------------------------------- 宿主测试谱
// （M34-P4「宿主测试谱先行」——`cargo test -p prism`；事实源 =
//   官方 wayland.xml 1.21.0 + 官方 wire 文档逐条对账）

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 头布局对账：字 0 = 对象 id、字 1 低 16 = opcode、高 16 = 尺寸
    /// （官方 wire 文档逐字对账——LE 域）。
    #[test]
    fn header_layout_matches_spec() {
        let mut buf = [0u8; 64];
        let n = encode_message(&mut buf, 0x0102_0304, 0x0B0A, &[WlArg::Uint(0xDEAD_BEEF)])
            .expect("encode");
        assert_eq!(n, 12);
        assert_eq!(&buf[0..4], &[0x04, 0x03, 0x02, 0x01], "对象 id LE 域");
        assert_eq!(&buf[4..6], &[0x0A, 0x0B], "opcode 低 16 位 LE 域");
        assert_eq!(&buf[6..8], &[12, 0], "尺寸高 16 位 LE 域");
        let h = parse_header(&buf).expect("header");
        assert_eq!(
            h,
            WlHeader {
                object_id: 0x0102_0304,
                opcode: 0x0B0A,
                size: 12
            }
        );
    }

    /// 全参数型编组/解析回环（Int/Uint/Fixed/Str/Object/NewId/Array/Fd
    /// 八型全谱 + 零拷贝切片载荷对账）。
    #[test]
    fn roundtrip_all_arg_types() {
        let mut buf = [0u8; 256];
        let args = [
            WlArg::Int(-42),
            WlArg::Uint(0x1234_5678),
            WlArg::Fixed(-0x0100_0000i32), // -256.0 fixed 24.8
            WlArg::Str(b"wl_compositor"),
            WlArg::Object(0xCAFE_0001),
            WlArg::NewId(0xCAFE_0002),
            WlArg::Array(&[1, 2, 3, 4, 5]), // 尾填充域（5 → pad 3）
            WlArg::Fd(7),
        ];
        let n = encode_message(&mut buf, 6, 3, &args).expect("encode");
        let m = parse_message(
            &buf,
            &[
                WlType::Int,
                WlType::Uint,
                WlType::Fixed,
                WlType::Str,
                WlType::Object,
                WlType::NewId,
                WlType::Array,
                WlType::Fd,
            ],
        )
        .expect("parse");
        assert_eq!(m.header.object_id, 6);
        assert_eq!(m.header.opcode, 3);
        assert_eq!(m.header.size as usize, n);
        assert_eq!(m.arg_count, 8);
        assert_eq!(m.args[0], Some(WlArg::Int(-42)));
        assert_eq!(m.args[1], Some(WlArg::Uint(0x1234_5678)));
        assert_eq!(m.args[2], Some(WlArg::Fixed(-0x0100_0000)));
        assert_eq!(m.args[3], Some(WlArg::Str(b"wl_compositor")));
        assert_eq!(m.args[4], Some(WlArg::Object(0xCAFE_0001)));
        assert_eq!(m.args[5], Some(WlArg::NewId(0xCAFE_0002)));
        assert_eq!(m.args[6], Some(WlArg::Array(&[1, 2, 3, 4, 5])));
        assert_eq!(m.args[7], Some(WlArg::Fd(7)));
    }

    /// string 编码域逐字对账：长度含 NUL + 零填充至 4 字节（官方域）。
    #[test]
    fn string_encoding_layout() {
        let mut buf = [0u8; 64];
        // "abc" → len=4（含 NUL）+ 'a''b''c'\0 + 无填充（4 已对齐）
        // 总尺寸 = 头 8 + 长字 4 + 载荷 4 = 16
        let n = encode_message(&mut buf, 1, 0, &[WlArg::Str(b"abc")]).expect("encode");
        assert_eq!(n, 16);
        assert_eq!(&buf[8..12], &[4, 0, 0, 0]);
        assert_eq!(&buf[12..16], &[b'a', b'b', b'c', 0]);
        // "ab" → len=3 + 'a''b'\0 + 1 字节零填充
        let n2 = encode_message(&mut buf, 1, 0, &[WlArg::Str(b"ab")]).expect("encode");
        assert_eq!(n2, 16);
        assert_eq!(&buf[8..12], &[3, 0, 0, 0]);
        assert_eq!(&buf[12..16], &[b'a', b'b', 0, 0], "填充域零字节");
        let (args, cnt) = parse_args(&buf[8..n2], &[WlType::Str]).expect("parse");
        assert_eq!(cnt, 1);
        assert_eq!(args[0], Some(WlArg::Str(b"ab")));
    }

    /// 零参消息（wl_surface.commit 形态）：头 8 字节即全消息。
    #[test]
    fn zero_arg_message() {
        let mut buf = [0u8; 16];
        let n = encode_surface_commit(&mut buf, 42).expect("encode");
        assert_eq!(n, HEADER);
        let m = parse_message(&buf, SIG_SURFACE_COMMIT).expect("parse");
        assert_eq!(m.header.object_id, 42);
        assert_eq!(m.header.opcode, surface::REQ_COMMIT);
        assert_eq!(m.arg_count, 0);
    }

    /// 畸形域 fail-visible 全谱：头不足 / 非 4 倍数 / 尺寸 < 头 /
    /// 尺寸越缓冲 / 尺寸越 WIRE_MAX / 截断 / 尾字多余 / string 违面。
    #[test]
    fn malformed_inputs_fail_visible() {
        let mut buf = [0u8; 64];
        let n = encode_message(&mut buf, 1, 0, &[WlArg::Uint(1), WlArg::Uint(2)]).expect("encode");
        // 头不足
        assert_eq!(parse_header(&buf[..4]), Err(WlError::BadLength));
        // 非 4 倍数
        let mut odd = buf;
        assert_eq!(parse_header(&odd[..n + 1]), Err(WlError::BadLength));
        // 尺寸 < 头：改写尺寸域为 4
        odd[6] = 4;
        odd[7] = 0;
        assert_eq!(parse_header(&odd), Err(WlError::BadLength));
        // 尺寸越缓冲：尺寸域 > 缓冲实长
        odd[6] = 0xFF;
        odd[7] = 0x0F;
        assert_eq!(parse_header(&odd), Err(WlError::BadLength));
        // 签名域截断：双参消息按单参签名解析 → 尾字多余 BadLength
        let full = buf;
        assert_eq!(
            parse_message(&full[..n], &[WlType::Uint]),
            Err(WlError::BadLength),
            "尾字多余即畸形（解析壳 v0 严格口径）"
        );
        // string 违面：长度 0
        let mut bad_str = [0u8; 16];
        bad_str[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_args(&bad_str[8..12], &[WlType::Str]),
            Err(WlError::BadString)
        );
        // string 违面：末字节非 NUL
        bad_str[8..12].copy_from_slice(&4u32.to_le_bytes());
        bad_str[12] = b'a';
        bad_str[13] = b'b';
        bad_str[14] = b'c';
        bad_str[15] = b'd';
        assert_eq!(
            parse_args(&bad_str[8..16], &[WlType::Str]),
            Err(WlError::BadString)
        );
        // array 截断：len 越体
        let mut bad_arr = [0u8; 12];
        bad_arr[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            parse_args(&bad_arr[8..12], &[WlType::Array]),
            Err(WlError::BadLength)
        );
    }

    /// 编码容量域：缓冲不足 / 越预算 / string 越 STR_MAX。
    #[test]
    fn encode_capacity_fail_visible() {
        let mut small = [0u8; 8];
        assert_eq!(
            encode_message(&mut small, 1, 0, &[WlArg::Uint(1)]),
            Err(WlError::BufferTooSmall)
        );
        let mut big = [0u8; 8192];
        let long = [0x61u8; STR_MAX]; // 512 字节 → wire_len 513 > STR_MAX
        assert_eq!(
            encode_message(&mut big, 1, 0, &[WlArg::Str(&long)]),
            Err(WlError::StrTooLong)
        );
        // WIRE_MAX 域：大 array 尾撞预算（4 + 4 + align4(8192) > 4096）
        let huge = [0x7Fu8; 8192];
        let mut mid = [0u8; 8192];
        assert_eq!(
            encode_message(&mut mid, 1, 0, &[WlArg::Array(&huge)]),
            Err(WlError::TooLarge)
        );
    }

    /// 对象表纪律：客户端/服务端双分配器 + 域闸 + 冲突域 + 摘除面。
    #[test]
    fn object_table_discipline() {
        let mut t = WlObjectTable::new();
        // 客户端域自 2 单调铸造
        assert_eq!(t.insert_client(WlIface::Registry), Ok(2));
        assert_eq!(t.insert_client(WlIface::Compositor), Ok(3));
        assert_eq!(t.insert_client(WlIface::Surface), Ok(4));
        // 服务端域自 0xFF00_0000 单调铸造
        assert_eq!(t.insert_server(WlIface::Callback), Ok(WL_SERVER_ID_MIN));
        assert_eq!(t.lookup(3), Some(WlIface::Compositor));
        assert_eq!(t.lookup(WL_SERVER_ID_MIN), Some(WlIface::Callback));
        assert_eq!(t.len(), 4);
        // 域判定逐字对账（官方域边界）
        assert_eq!(id_domain(0), IdDomain::Null);
        assert_eq!(id_domain(1), IdDomain::Display);
        assert_eq!(id_domain(2), IdDomain::Client);
        assert_eq!(id_domain(WL_CLIENT_ID_MAX), IdDomain::Client);
        assert_eq!(id_domain(WL_SERVER_ID_MIN), IdDomain::Server);
        assert_eq!(id_domain(u32::MAX), IdDomain::Server);
        // null 域拒收 + 冲突域拒收
        assert_eq!(t.install(0, WlIface::Surface), Err(WlError::BadDomain));
        assert_eq!(t.install(3, WlIface::Buffer), Err(WlError::BadDomain));
        // 摘除 + 复查
        assert!(t.remove(3));
        assert_eq!(t.lookup(3), None);
        assert!(!t.remove(3));
        // 摘除后同号重登（显式 id 域——v0 无自动复用，面仅在表可用性）
        assert!(t.install(3, WlIface::Buffer).is_ok());
    }

    /// opcode 事实源回归锚：官方 XML 声明序逐条对账（M42-UNIX3 事实源
    /// = Debian wayland 1.21.0 protocol/wayland.xml）。
    #[test]
    fn opcode_tables_match_xml() {
        assert_eq!(display::REQ_SYNC, 0);
        assert_eq!(display::REQ_GET_REGISTRY, 1);
        assert_eq!(display::EV_ERROR, 0);
        assert_eq!(display::EV_DELETE_ID, 1);
        assert_eq!(registry::REQ_BIND, 0);
        assert_eq!(registry::EV_GLOBAL, 0);
        assert_eq!(registry::EV_GLOBAL_REMOVE, 1);
        assert_eq!(callback::EV_DONE, 0);
        assert_eq!(compositor::REQ_CREATE_SURFACE, 0);
        assert_eq!(compositor::REQ_CREATE_REGION, 1);
        assert_eq!(surface::REQ_DESTROY, 0);
        assert_eq!(surface::REQ_ATTACH, 1);
        assert_eq!(surface::REQ_DAMAGE, 2);
        assert_eq!(surface::REQ_FRAME, 3);
        assert_eq!(surface::REQ_SET_OPAQUE_REGION, 4);
        assert_eq!(surface::REQ_SET_INPUT_REGION, 5);
        assert_eq!(surface::REQ_COMMIT, 6);
        assert_eq!(surface::REQ_SET_BUFFER_TRANSFORM, 7);
        assert_eq!(surface::REQ_SET_BUFFER_SCALE, 8);
        assert_eq!(surface::REQ_DAMAGE_BUFFER, 9);
        assert_eq!(surface::REQ_OFFSET, 10);
        assert_eq!(surface::EV_ENTER, 0);
        assert_eq!(surface::EV_LEAVE, 1);
        assert_eq!(buffer::REQ_DESTROY, 0);
        assert_eq!(buffer::EV_RELEASE, 0);
        assert_eq!(seat::REQ_GET_POINTER, 0);
        assert_eq!(seat::REQ_GET_KEYBOARD, 1);
        assert_eq!(seat::REQ_GET_TOUCH, 2);
        assert_eq!(seat::REQ_RELEASE, 3);
        assert_eq!(seat::EV_CAPABILITIES, 0);
        assert_eq!(seat::EV_NAME, 1);
        assert_eq!(output::EV_GEOMETRY, 0);
        assert_eq!(output::EV_MODE, 1);
        assert_eq!(output::EV_DONE, 2);
        assert_eq!(output::EV_SCALE, 3);
        assert_eq!(output::EV_NAME, 4);
        assert_eq!(output::EV_DESCRIPTION, 5);
        assert_eq!(region::REQ_ADD, 1);
        assert_eq!(shm::REQ_CREATE_POOL, 0);
        assert_eq!(shm::EV_FORMAT, 0);
        assert_eq!(shm_pool::REQ_CREATE_BUFFER, 0);
        assert_eq!(shm_pool::REQ_DESTROY, 1);
        assert_eq!(shm_pool::REQ_RESIZE, 2);
        // M42-INPUT7 输入链：wl_seat 派生 + wl_keyboard / wl_pointer
        // 事件 opcode（官方 XML 声明序逐字对账）。
        assert_eq!(keyboard::EV_KEYMAP, 0);
        assert_eq!(keyboard::EV_ENTER, 1);
        assert_eq!(keyboard::EV_LEAVE, 2);
        assert_eq!(keyboard::EV_KEY, 3);
        assert_eq!(keyboard::EV_MODIFIERS, 4);
        assert_eq!(keyboard::EV_REPEAT_INFO, 5);
        assert_eq!(pointer::EV_ENTER, 0);
        assert_eq!(pointer::EV_LEAVE, 1);
        assert_eq!(pointer::EV_MOTION, 2);
        assert_eq!(pointer::EV_BUTTON, 3);
    }

    /// 接口官方名面（registry global interface string 事实源）。
    #[test]
    fn iface_names_match_xml() {
        assert_eq!(iface_name(WlIface::Display), "wl_display");
        assert_eq!(iface_name(WlIface::Registry), "wl_registry");
        assert_eq!(iface_name(WlIface::Callback), "wl_callback");
        assert_eq!(iface_name(WlIface::Compositor), "wl_compositor");
        assert_eq!(iface_name(WlIface::Surface), "wl_surface");
        assert_eq!(iface_name(WlIface::Buffer), "wl_buffer");
        assert_eq!(iface_name(WlIface::Seat), "wl_seat");
        assert_eq!(iface_name(WlIface::Pointer), "wl_pointer");
        assert_eq!(iface_name(WlIface::Keyboard), "wl_keyboard");
        assert_eq!(iface_name(WlIface::Output), "wl_output");
        assert_eq!(iface_name(WlIface::Region), "wl_region");
        assert_eq!(iface_name(WlIface::Shm), "wl_shm");
        assert_eq!(iface_name(WlIface::ShmPool), "wl_shm_pool");
    }

    /// bind 特例签名回环：uint + string + uint + new_id（官方域——
    /// XML 未标注接口的 new_id 前随 interface string + version）。
    #[test]
    fn registry_bind_roundtrip() {
        let mut buf = [0u8; 64];
        let n = encode_registry_bind(&mut buf, 2, 17, "wl_compositor", 4, 5).expect("encode");
        let m = parse_message(&buf, SIG_REGISTRY_BIND).expect("parse");
        assert_eq!(m.header.object_id, 2);
        assert_eq!(m.header.opcode, registry::REQ_BIND);
        assert_eq!(m.args[0], Some(WlArg::Uint(17)));
        assert_eq!(m.args[1], Some(WlArg::Str(b"wl_compositor")));
        assert_eq!(m.args[2], Some(WlArg::Uint(4)));
        assert_eq!(m.args[3], Some(WlArg::NewId(5)));
        assert_eq!(m.wire_size(), n);
    }

    /// global 事件编组/解析回环 + sync/get_registry/done/commit 语义
    /// 便利编组器回环（t103 (g) 消费面同谱）。
    #[test]
    fn semantic_encoders_roundtrip() {
        let mut buf = [0u8; 128];
        // global 事件
        let n =
            encode_registry_global_event(&mut buf, 2, 9, WlIface::Compositor, 4).expect("encode");
        let m = parse_message(&buf, SIG_REGISTRY_GLOBAL).expect("parse");
        assert_eq!(m.header.opcode, registry::EV_GLOBAL);
        assert_eq!(m.args[0], Some(WlArg::Uint(9)));
        assert_eq!(m.args[1], Some(WlArg::Str(b"wl_compositor")));
        assert_eq!(m.args[2], Some(WlArg::Uint(4)));
        assert_eq!(m.wire_size(), n);
        // sync 请求 + done 事件（帧回调编舞对）
        let n_sync = encode_display_sync(&mut buf, 1, 7).expect("encode");
        let ms = parse_message(&buf, SIG_DISPLAY_SYNC).expect("parse");
        assert_eq!(ms.header.object_id, 1);
        assert_eq!(ms.header.opcode, display::REQ_SYNC);
        assert_eq!(ms.args[0], Some(WlArg::NewId(7)));
        assert_eq!(ms.wire_size(), n_sync);
        let n_done = encode_callback_done_event(&mut buf, 7, 0x51).expect("encode");
        let md = parse_message(&buf, SIG_CALLBACK_DONE).expect("parse");
        assert_eq!(md.header.opcode, callback::EV_DONE);
        assert_eq!(md.args[0], Some(WlArg::Uint(0x51)));
        assert_eq!(md.wire_size(), n_done);
        // get_registry
        encode_display_get_registry(&mut buf, 1, 2).expect("encode");
        let mg = parse_message(&buf, SIG_DISPLAY_GET_REGISTRY).expect("parse");
        assert_eq!(mg.header.opcode, display::REQ_GET_REGISTRY);
        assert_eq!(mg.args[0], Some(WlArg::NewId(2)));
    }

    /// 输入链语义面回环（M42-INPUT7）：capabilities / keymap / enter /
    /// leave / key / pointer enter / motion / button 八编组器逐对
    /// encode→parse 对账（签名表 + fixed/array/fd 域原字透传）。
    #[test]
    fn input_chain_encoders_roundtrip() {
        let mut buf = [0u8; 128];
        let n = encode_seat_capabilities_event(&mut buf, 3, SEAT_CAPS_POINTER | SEAT_CAPS_KEYBOARD)
            .expect("encode");
        let m = parse_message(&buf, SIG_SEAT_CAPABILITIES).expect("parse");
        assert_eq!(m.header.opcode, seat::EV_CAPABILITIES);
        assert_eq!(m.args[0], Some(WlArg::Uint(3)));
        assert_eq!(m.wire_size(), n);
        let n =
            encode_keyboard_keymap_event(&mut buf, 7, 0, KEYMAP_FORMAT_XKB_V1, 0).expect("encode");
        let m = parse_message(&buf, SIG_KEYBOARD_KEYMAP).expect("parse");
        assert_eq!(m.header.opcode, keyboard::EV_KEYMAP);
        assert_eq!(m.args[0], Some(WlArg::Fd(0)));
        assert_eq!(m.args[1], Some(WlArg::Uint(KEYMAP_FORMAT_XKB_V1)));
        assert_eq!(m.wire_size(), n);
        let n = encode_keyboard_enter_event(&mut buf, 7, 11, 5, &[]).expect("encode");
        let m = parse_message(&buf, SIG_KEYBOARD_ENTER).expect("parse");
        assert_eq!(m.header.opcode, keyboard::EV_ENTER);
        assert_eq!(m.args[0], Some(WlArg::Uint(11)));
        assert_eq!(m.args[1], Some(WlArg::Object(5)));
        assert_eq!(m.args[2], Some(WlArg::Array(&[])));
        assert_eq!(m.wire_size(), n);
        let n = encode_keyboard_leave_event(&mut buf, 7, 12, 5).expect("encode");
        let m = parse_message(&buf, SIG_KEYBOARD_LEAVE).expect("parse");
        assert_eq!(m.header.opcode, keyboard::EV_LEAVE);
        assert_eq!(m.args[0], Some(WlArg::Uint(12)));
        assert_eq!(m.wire_size(), n);
        let n = encode_keyboard_key_event(&mut buf, 7, 13, 13, 0x02, KEY_STATE_PRESSED)
            .expect("encode");
        let m = parse_message(&buf, SIG_KEYBOARD_KEY).expect("parse");
        assert_eq!(m.header.opcode, keyboard::EV_KEY);
        assert_eq!(m.args[2], Some(WlArg::Uint(0x02)));
        assert_eq!(m.args[3], Some(WlArg::Uint(KEY_STATE_PRESSED)));
        assert_eq!(m.wire_size(), n);
        let n = encode_keyboard_repeat_info_event(&mut buf, 7, 0, 0).expect("encode");
        assert_eq!(keyboard::EV_REPEAT_INFO, 5);
        let m = parse_message(&buf, SIG_KEYBOARD_REPEAT_INFO).expect("parse");
        assert_eq!(m.header.opcode, keyboard::EV_REPEAT_INFO);
        assert_eq!(m.args[0], Some(WlArg::Uint(0)));
        assert_eq!(m.args[1], Some(WlArg::Uint(0)));
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 16);
        // M43-KBREP37 set_cursor 请求签名对账（"uoi i" 四参——官方
        // wl_keyboard.set_cursor 逐字对账）。
        assert_eq!(keyboard_req::REQ_SET_CURSOR, 1);
        let n = encode_message(
            &mut buf,
            6,
            keyboard_req::REQ_SET_CURSOR,
            &[
                WlArg::Uint(7),
                WlArg::Object(0x41),
                WlArg::Int(3),
                WlArg::Int(5),
            ],
        )
        .expect("encode");
        let m = parse_message(&buf, SIG_KEYBOARD_SET_CURSOR).expect("parse");
        assert_eq!(m.header.opcode, keyboard_req::REQ_SET_CURSOR);
        assert_eq!(m.args[0], Some(WlArg::Uint(7)));
        assert_eq!(m.args[1], Some(WlArg::Object(0x41)));
        assert_eq!(m.args[2], Some(WlArg::Int(3)));
        assert_eq!(m.args[3], Some(WlArg::Int(5)));
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 24, "8 头 + 16 体（uint + object + int + int）");
        let n = encode_pointer_enter_event(&mut buf, 6, 14, 5, 32 << 8, 64 << 8).expect("encode");
        let m = parse_message(&buf, SIG_POINTER_ENTER).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_ENTER);
        assert_eq!(m.args[1], Some(WlArg::Object(5)));
        assert_eq!(m.args[2], Some(WlArg::Fixed(32 << 8)));
        assert_eq!(m.wire_size(), n);
        let n = encode_pointer_motion_event(&mut buf, 6, 14, 40 << 8, 80 << 8).expect("encode");
        let m = parse_message(&buf, SIG_POINTER_MOTION).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_MOTION);
        assert_eq!(m.args[1], Some(WlArg::Fixed(40 << 8)));
        assert_eq!(m.wire_size(), n);
        let n = encode_pointer_button_event(&mut buf, 6, 15, 15, BTN_LEFT, BTN_STATE_PRESSED)
            .expect("encode");
        let m = parse_message(&buf, SIG_POINTER_BUTTON).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_BUTTON);
        assert_eq!(m.args[2], Some(WlArg::Uint(BTN_LEFT)));
        assert_eq!(m.args[3], Some(WlArg::Uint(BTN_STATE_PRESSED)));
        assert_eq!(m.wire_size(), n);
        // M42-WAYCOMP14 axis 族四编组器全谱（官方声明序 opcode 对账）。
        let n =
            encode_pointer_axis_event(&mut buf, 6, 16, AXIS_VERTICAL_SCROLL, -120).expect("encode");
        let m = parse_message(&buf, SIG_POINTER_AXIS).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_AXIS);
        assert_eq!(m.args[0], Some(WlArg::Uint(16)));
        assert_eq!(m.args[1], Some(WlArg::Uint(AXIS_VERTICAL_SCROLL)));
        assert_eq!(m.args[2], Some(WlArg::Fixed(-120)), "fixed 原字透传");
        assert_eq!(m.wire_size(), n);
        let n = encode_pointer_frame_event(&mut buf, 6).expect("encode");
        let m = parse_message(&buf, SIG_POINTER_FRAME).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_FRAME);
        assert!(
            m.args[0].is_none(),
            "frame 零载荷（签名零参——args 首位 None）"
        );
        assert_eq!(m.wire_size(), n);
        let n = encode_pointer_axis_source_event(&mut buf, 6, AXIS_SOURCE_WHEEL).expect("encode");
        let m = parse_message(&buf, SIG_POINTER_AXIS_SOURCE).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_AXIS_SOURCE);
        assert_eq!(m.args[0], Some(WlArg::Uint(AXIS_SOURCE_WHEEL)));
        assert_eq!(m.wire_size(), n);
        let n = encode_pointer_axis_stop_event(&mut buf, 6, 17, AXIS_HORIZONTAL_SCROLL)
            .expect("encode");
        let m = parse_message(&buf, SIG_POINTER_AXIS_STOP).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_AXIS_STOP);
        assert_eq!(m.args[1], Some(WlArg::Uint(AXIS_HORIZONTAL_SCROLL)));
        assert_eq!(m.wire_size(), n);
        // M43-AV12036 axis_value120 编组器（官方序：8 = axis_discrete
        // 域外挂账、9 = axis_value120 在环——签名 "ui" 逐字对账）。
        let n = encode_pointer_axis_value120_event(&mut buf, 6, AXIS_VERTICAL_SCROLL, 120)
            .expect("encode");
        let m = parse_message(&buf, SIG_POINTER_AXIS_VALUE120).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_AXIS_VALUE120);
        assert_eq!(pointer::EV_AXIS_VALUE120, 9, "官方事件声明序 9 号");
        assert_eq!(m.args[0], Some(WlArg::Uint(AXIS_VERTICAL_SCROLL)));
        assert_eq!(m.args[1], Some(WlArg::Int(120)), "120 倍步进原字");
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 16, "8 头 + 8 体（uint + int）");
        // 负向步进原字透传（dz=-2 → value120=-240 同字派生口径）。
        let n = encode_pointer_axis_value120_event(&mut buf, 6, AXIS_VERTICAL_SCROLL, -240)
            .expect("encode");
        let m = parse_message(&buf, SIG_POINTER_AXIS_VALUE120).expect("parse");
        assert_eq!(m.header.opcode, pointer::EV_AXIS_VALUE120);
        assert_eq!(m.args[1], Some(WlArg::Int(-240)));
        assert_eq!(m.wire_size(), n);
    }

    /// xdg_shell 窗口管理协议 wire 面（M50-XDGSHELL66 笔76）：
    /// 接口名事实源 + 六请求三事件编组/解析回环 + opcode 官方声明序锚
    /// + states 空数组域 + close 零参域。
    #[test]
    fn xdg_shell_wire_face() {
        // (a) 接口名事实源（registry global interface string 域）。
        assert_eq!(iface_name(WlIface::XdgWmBase), "xdg_wm_base");
        assert_eq!(iface_name(WlIface::XdgSurface), "xdg_surface");
        assert_eq!(iface_name(WlIface::XdgToplevel), "xdg_toplevel");
        // (b) opcode 官方声明序锚（xdg-shell.xml 逐条对账；
        // M51-XDGPOP75 笔86 揭雷①序修正——create_positioner 补位，
        // get_xdg_surface 1→2 / pong 2→3 官方序对齐）。
        assert_eq!(xdg_wm_base::REQ_DESTROY, 0);
        assert_eq!(xdg_wm_base::REQ_CREATE_POSITIONER, 1);
        assert_eq!(xdg_wm_base::REQ_GET_XDG_SURFACE, 2);
        assert_eq!(xdg_wm_base::REQ_PONG, 3);
        assert_eq!(xdg_wm_base::EV_PING, 0);
        assert_eq!(xdg_surface::REQ_DESTROY, 0);
        assert_eq!(xdg_surface::REQ_GET_TOPLEVEL, 1);
        assert_eq!(xdg_surface::REQ_GET_POPUP, 2);
        assert_eq!(xdg_surface::REQ_SET_WINDOW_GEOMETRY, 3);
        assert_eq!(xdg_surface::REQ_ACK_CONFIGURE, 4);
        assert_eq!(xdg_surface::EV_CONFIGURE, 0);
        assert_eq!(xdg_toplevel::REQ_DESTROY, 0);
        assert_eq!(xdg_toplevel::REQ_SET_PARENT, 1);
        assert_eq!(xdg_toplevel::REQ_SET_TITLE, 2);
        assert_eq!(xdg_toplevel::REQ_SET_APP_ID, 3);
        assert_eq!(xdg_toplevel::EV_CONFIGURE, 0);
        assert_eq!(xdg_toplevel::EV_CLOSE, 1);
        assert_eq!(xdg_toplevel::EV_CONFIGURE_BOUNDS, 2);
        assert_eq!(xdg_toplevel::EV_WM_CAPABILITIES, 3);
        // (c) get_xdg_surface 请求编组/回环（new_id + object 双参）。
        let mut buf = [0u8; 64];
        let n = encode_xdg_wm_base_get_xdg_surface(&mut buf, 0x40, 0x41, 0x21).expect("encode");
        let m = parse_message(&buf, SIG_XDG_WM_BASE_GET_XDG_SURFACE).expect("parse");
        assert_eq!(m.header.object_id, 0x40);
        assert_eq!(m.header.opcode, xdg_wm_base::REQ_GET_XDG_SURFACE);
        assert_eq!(m.args[0], Some(WlArg::NewId(0x41)));
        assert_eq!(m.args[1], Some(WlArg::Object(0x21)));
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 16, "8 头 + 8 体（new_id + object）");
        // (d) get_toplevel 请求（单 new_id）+ ack_configure（单 uint）。
        let n = encode_xdg_surface_get_toplevel(&mut buf, 0x41, 0x42).expect("encode");
        let m = parse_message(&buf, SIG_XDG_SURFACE_GET_TOPLEVEL).expect("parse");
        assert_eq!(m.header.opcode, xdg_surface::REQ_GET_TOPLEVEL);
        assert_eq!(m.args[0], Some(WlArg::NewId(0x42)));
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 12, "8 头 + 4 体");
        let n = encode_xdg_surface_ack_configure(&mut buf, 0x41, 7).expect("encode");
        let m = parse_message(&buf, SIG_XDG_SURFACE_ACK_CONFIGURE).expect("parse");
        assert_eq!(m.args[0], Some(WlArg::Uint(7)));
        assert_eq!(m.wire_size(), n);
        // (e) set_title/set_app_id 请求（string 载荷 NUL 填充域回读）。
        let n = encode_xdg_toplevel_set_title(&mut buf, 0x42, "Lumina Terminal").expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_SET_TITLE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_TITLE);
        match m.args[0] {
            Some(WlArg::Str(s)) => {
                // 官方 wire 契约：编组载荷不含 NUL 终止符，wire 层尾部
                // NUL 填充域由 encode_message 补齐、解析面保证剔除。
                assert_eq!(s, b"Lumina Terminal");
                assert_eq!(s.len(), 15, "载荷字节数（NUL 在 wire 尾填充域）");
            }
            _ => panic!("title 应为 Str 载荷"),
        }
        assert_eq!(m.wire_size(), n);
        let n = encode_xdg_toplevel_set_app_id(&mut buf, 0x42, "org.lumina.term").expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_SET_APP_ID).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_APP_ID);
        assert_eq!(m.wire_size(), n);
        // (f) configure/ack 双向序契约面（服务端 configure 事件串号 +
        //     客户端 ack 同串号回环——官方 liveness 同谱）。
        let n = encode_xdg_surface_configure_event(&mut buf, 0x41, 7).expect("encode");
        let m = parse_message(&buf, SIG_XDG_SURFACE_CONFIGURE).expect("parse");
        assert_eq!(m.header.opcode, xdg_surface::EV_CONFIGURE);
        assert_eq!(m.args[0], Some(WlArg::Uint(7)));
        assert_eq!(m.wire_size(), n);
        // (g) toplevel configure 事件（w/h + 空态数组域）。
        let n = encode_xdg_toplevel_configure_event(&mut buf, 0x42, 0, 0, &[]).expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_CONFIGURE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::EV_CONFIGURE);
        assert_eq!(m.args[0], Some(WlArg::Int(0)), "w 零值 = 服务端策略自主");
        assert_eq!(m.args[1], Some(WlArg::Int(0)));
        match m.args[2] {
            Some(WlArg::Array(s)) => assert_eq!(s, b"", "v0 空态数组"),
            _ => panic!("states 应为 Array 载荷"),
        }
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 20, "8 头 + 8 体（int×2）+ 4 数组长 + 0 载荷");
        // (h) close 事件（零参——v0 最小面主事件）+ ping/pong liveness。
        let n = encode_xdg_toplevel_close_event(&mut buf, 0x42).expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_CLOSE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::EV_CLOSE);
        assert_eq!(m.wire_size(), n);
        assert_eq!(n, 8, "零参 = 纯头");
        let n = encode_xdg_wm_base_ping_event(&mut buf, 0x40, 99).expect("encode");
        let m = parse_message(&buf, SIG_XDG_WM_BASE_PING).expect("parse");
        assert_eq!(m.header.opcode, xdg_wm_base::EV_PING);
        assert_eq!(m.args[0], Some(WlArg::Uint(99)));
        assert_eq!(m.wire_size(), n);
        let n = encode_xdg_wm_base_pong(&mut buf, 0x40, 99).expect("encode");
        let m = parse_message(&buf, SIG_XDG_WM_BASE_PONG).expect("parse");
        assert_eq!(m.header.opcode, xdg_wm_base::REQ_PONG);
        assert_eq!(m.args[0], Some(WlArg::Uint(99)));
        assert_eq!(m.wire_size(), n);
    }

    /// xdg_popup 尺寸交互族 wire 面（M51-XDGPOP75 笔86——positioner/
    /// popup 官方声明序锚 + 编组回环 + PosDef placement 语义核金值 +
    /// 完整性闸）。
    #[test]
    fn xdg_popup_wire_face() {
        // (a) 接口名事实源（registry global interface string 域）。
        assert_eq!(iface_name(WlIface::XdgPositioner), "xdg_positioner");
        assert_eq!(iface_name(WlIface::XdgPopup), "xdg_popup");
        // (b) opcode 官方声明序锚（xdg-shell.xml 逐条对账）。
        assert_eq!(xdg_positioner::REQ_DESTROY, 0);
        assert_eq!(xdg_positioner::REQ_SET_SIZE, 1);
        assert_eq!(xdg_positioner::REQ_SET_ANCHOR_RECT, 2);
        assert_eq!(xdg_positioner::REQ_SET_ANCHOR, 3);
        assert_eq!(xdg_positioner::REQ_SET_GRAVITY, 4);
        assert_eq!(xdg_positioner::REQ_SET_CONSTRAINT_ADJUSTMENT, 5);
        assert_eq!(xdg_positioner::REQ_SET_OFFSET, 6);
        assert_eq!(xdg_positioner::REQ_SET_REACTIVE, 7);
        assert_eq!(xdg_positioner::REQ_SET_PARENT_SIZE, 8);
        assert_eq!(xdg_positioner::REQ_SET_PARENT_CONFIGURE, 9);
        assert_eq!(xdg_popup::REQ_DESTROY, 0);
        assert_eq!(xdg_popup::REQ_GRAB, 1);
        assert_eq!(xdg_popup::REQ_REPOSITION, 2);
        assert_eq!(xdg_popup::EV_CONFIGURE, 0);
        assert_eq!(xdg_popup::EV_POPUP_DONE, 1);
        assert_eq!(xdg_popup::EV_REPOSITIONED, 2);
        // (c) 枚举语义常量锚（官方枚举值逐字对账）。
        assert_eq!(XDG_ANCHOR_NONE, 0);
        assert_eq!(XDG_ANCHOR_TOP, 1);
        assert_eq!(XDG_ANCHOR_BOTTOM, 2);
        assert_eq!(XDG_ANCHOR_LEFT, 3);
        assert_eq!(XDG_ANCHOR_RIGHT, 4);
        assert_eq!(XDG_ANCHOR_TOP_LEFT, 5);
        assert_eq!(XDG_ANCHOR_BOTTOM_LEFT, 6);
        assert_eq!(XDG_ANCHOR_TOP_RIGHT, 7);
        assert_eq!(XDG_ANCHOR_BOTTOM_RIGHT, 8);
        assert_eq!(XDG_CADJ_SLIDER_X, 1);
        assert_eq!(XDG_CADJ_SLIDER_Y, 2);
        assert_eq!(XDG_CADJ_FLIP_X, 4);
        assert_eq!(XDG_CADJ_FLIP_Y, 8);
        assert_eq!(XDG_CADJ_RESIZE_X, 16);
        assert_eq!(XDG_CADJ_RESIZE_Y, 32);
        // (d) 编组回环全谱（字节金值）。
        let mut buf = [0u8; 64];
        let n = encode_xdg_wm_base_create_positioner(&mut buf, 0x40, 0x63).expect("encode");
        let m = parse_message(&buf, SIG_XDG_WM_BASE_CREATE_POSITIONER).expect("parse");
        assert_eq!(m.header.opcode, xdg_wm_base::REQ_CREATE_POSITIONER);
        assert_eq!(m.args[0], Some(WlArg::NewId(0x63)));
        assert_eq!(n, 12, "8 头 + 4 体（new_id）");
        let n = encode_xdg_positioner_set_size(&mut buf, 0x63, 200, 80).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_SIZE).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_SIZE);
        assert_eq!(m.args[0], Some(WlArg::Int(200)));
        assert_eq!(m.args[1], Some(WlArg::Int(80)));
        assert_eq!(n, 16, "8 头 + 8 体（int×2）");
        let n =
            encode_xdg_positioner_set_anchor_rect(&mut buf, 0x63, 10, 20, 100, 40).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_ANCHOR_RECT).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_ANCHOR_RECT);
        assert_eq!(m.args[3], Some(WlArg::Int(40)));
        assert_eq!(n, 24, "8 头 + 16 体（int×4）");
        let n =
            encode_xdg_positioner_set_anchor(&mut buf, 0x63, XDG_ANCHOR_TOP_RIGHT).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_ANCHOR).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_ANCHOR);
        assert_eq!(m.args[0], Some(WlArg::Uint(XDG_ANCHOR_TOP_RIGHT)));
        assert_eq!(n, 12, "8 头 + 4 体（uint）");
        let n =
            encode_xdg_positioner_set_gravity(&mut buf, 0x63, XDG_ANCHOR_BOTTOM).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_GRAVITY).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_GRAVITY);
        assert_eq!(n, 12);
        let n = encode_xdg_positioner_set_constraint_adjustment(
            &mut buf,
            0x63,
            XDG_CADJ_SLIDER_X | XDG_CADJ_SLIDER_Y,
        )
        .expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_CONSTRAINT_ADJUSTMENT).expect("parse");
        assert_eq!(
            m.header.opcode,
            xdg_positioner::REQ_SET_CONSTRAINT_ADJUSTMENT
        );
        assert_eq!(m.args[0], Some(WlArg::Uint(3)));
        assert_eq!(n, 12);
        let n = encode_xdg_positioner_set_offset(&mut buf, 0x63, 4, 8).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_OFFSET).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_OFFSET);
        assert_eq!(n, 16);
        let n = encode_xdg_surface_get_popup(&mut buf, 0x67, 0x68, 0x61, 0x63).expect("encode");
        let m = parse_message(&buf, SIG_XDG_SURFACE_GET_POPUP).expect("parse");
        assert_eq!(m.header.opcode, xdg_surface::REQ_GET_POPUP);
        assert_eq!(m.args[0], Some(WlArg::NewId(0x68)));
        assert_eq!(m.args[1], Some(WlArg::Object(0x61)));
        assert_eq!(m.args[2], Some(WlArg::Object(0x63)));
        assert_eq!(n, 20, "8 头 + 12 体（new_id + object ×2）");
        let n = encode_xdg_toplevel_set_min_size(&mut buf, 0x62, 400, 200).expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_SET_MIN_SIZE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_MIN_SIZE);
        assert_eq!(n, 16);
        let n = encode_xdg_toplevel_set_max_size(&mut buf, 0x62, 1600, 900).expect("encode");
        let m = parse_message(&buf, SIG_XDG_TOPLEVEL_SET_MAX_SIZE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_MAX_SIZE);
        assert_eq!(n, 16);
        let n = encode_xdg_popup_grab(&mut buf, 0x68, 0x65, 5).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POPUP_GRAB).expect("parse");
        assert_eq!(m.header.opcode, xdg_popup::REQ_GRAB);
        assert_eq!(m.args[0], Some(WlArg::Object(0x65)));
        assert_eq!(m.args[1], Some(WlArg::Uint(5)));
        assert_eq!(n, 16, "8 头 + 8 体（object + uint）");
        let n = encode_xdg_popup_configure_event(&mut buf, 0x68, 14, 28).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POPUP_CONFIGURE).expect("parse");
        assert_eq!(m.header.opcode, xdg_popup::EV_CONFIGURE);
        assert_eq!(m.args[0], Some(WlArg::Int(14)));
        assert_eq!(m.args[1], Some(WlArg::Int(28)));
        assert_eq!(n, 16, "8 头 + 8 体（int×2）");
        let n = encode_xdg_popup_done_event(&mut buf, 0x68).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POPUP_POPUP_DONE).expect("parse");
        assert_eq!(m.header.opcode, xdg_popup::EV_POPUP_DONE);
        assert_eq!(n, 8, "零参 = 纯头");
        // (e) PosDef placement 语义核金值（官方定位公式）。
        let pos = PosDef {
            size: (200, 80),
            anchor_rect: (10, 20, 100, 40),
            anchor: XDG_ANCHOR_TOP_RIGHT,
            gravity: XDG_ANCHOR_BOTTOM,
            cadj: 3,
            offset: (4, 8),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        assert!(pos.complete());
        assert_eq!(pos.place(), (14, 28), "锚点(110,20) + 重力 bottom + 偏移");
        let neg = PosDef {
            anchor: XDG_ANCHOR_BOTTOM,
            gravity: XDG_ANCHOR_BOTTOM,
            offset: (0, 0),
            ..pos
        };
        assert_eq!(
            neg.place(),
            (-40, 60),
            "raw 域负位如实出域（约束域 v1 挂账）"
        );
        let left = PosDef {
            anchor: XDG_ANCHOR_LEFT,
            gravity: XDG_ANCHOR_RIGHT,
            offset: (0, 0),
            ..pos
        };
        assert_eq!(left.place(), (10, 0), "左锚右重力 = popup 左缘贴锚点");
        // (f) 完整性闸（官方契约——双宣告缺位拒收）。
        let empty = PosDef {
            size: (0, 0),
            anchor_rect: (0, 0, 0, 0),
            anchor: 0,
            gravity: 0,
            cadj: 0,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        assert!(!empty.complete(), "缺省 positioner 不完整");
        let half = PosDef {
            size: (200, 80),
            ..empty
        };
        assert!(!half.complete(), "仅 set_size 仍不完整");
    }

    /// M52-POPCON78 笔90：约束域收口 face——place_in_bounds 官方施策序
    /// flip→slide→resize 逐轴金值矩阵 + 屏域裁剪 + 零界守卫 + flip 重
    /// 力镜像 + v3 编组器字节金值回环。
    #[test]
    fn xdg_popup_constraint_face() {
        // 编组器回环：set_reactive 8 B / set_parent_size 16 B /
        // set_parent_configure 12 B / reposition 16 B / repositioned 12 B
        let mut buf = [0u8; 64];
        let n = encode_xdg_positioner_set_reactive(&mut buf, 0x63).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_REACTIVE).expect("parse");
        assert_eq!(m.header.opcode, xdg_positioner::REQ_SET_REACTIVE);
        assert_eq!(n, 8, "零参 = 纯头");
        let n = encode_xdg_positioner_set_parent_size(&mut buf, 0x63, 800, 600).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_PARENT_SIZE).expect("parse");
        assert_eq!(m.args[0], Some(WlArg::Int(800)));
        assert_eq!(n, 16);
        let n = encode_xdg_positioner_set_parent_configure(&mut buf, 0x63, 77).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POSITIONER_SET_PARENT_CONFIGURE).expect("parse");
        assert_eq!(m.args[0], Some(WlArg::Uint(77)));
        assert_eq!(n, 12);
        let n = encode_xdg_popup_reposition(&mut buf, 0x68, 0x63, 0xAB).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POPUP_REPOSITION).expect("parse");
        assert_eq!(m.args[0], Some(WlArg::Object(0x63)));
        assert_eq!(m.args[1], Some(WlArg::Uint(0xAB)));
        assert_eq!(n, 16);
        let n = encode_xdg_popup_repositioned_event(&mut buf, 0x68, 0xAB).expect("encode");
        let m = parse_message(&buf, SIG_XDG_POPUP_REPOSITIONED).expect("parse");
        assert_eq!(m.header.opcode, xdg_popup::EV_REPOSITIONED);
        assert_eq!(m.args[0], Some(WlArg::Uint(0xAB)));
        assert_eq!(n, 12);

        // flip_gravity 镜像矩阵（锚点不变——轴内对换）。
        assert_eq!(flip_gravity_x(XDG_ANCHOR_LEFT), XDG_ANCHOR_RIGHT);
        assert_eq!(flip_gravity_x(XDG_ANCHOR_TOP_RIGHT), XDG_ANCHOR_TOP_LEFT);
        assert_eq!(flip_gravity_y(XDG_ANCHOR_TOP), XDG_ANCHOR_BOTTOM);
        assert_eq!(flip_gravity_y(XDG_ANCHOR_BOTTOM_LEFT), XDG_ANCHOR_TOP_LEFT);
        assert_eq!(flip_gravity_y(XDG_ANCHOR_LEFT), XDG_ANCHOR_LEFT, "轴外保持");

        // 零界守卫：bound 零面积 = raw 直通（t164 金值域零扰）。
        let p = PosDef {
            size: (10, 6),
            anchor_rect: (0, 0, 20, 20),
            anchor: XDG_ANCHOR_TOP_RIGHT,
            gravity: XDG_ANCHOR_BOTTOM,
            cadj: 0,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = p.place_in_bounds((0, 0, 0, 0));
        assert_eq!(
            (pr.x, pr.y, pr.w, pr.h),
            (p.place().0, p.place().1, 10, 6),
            "零界 = raw 直通"
        );

        // flip_y 金值：popup 出上界 → FLIP_Y 翻转后入界（flip_y=true）。
        // 锚 rect (50,0,10,5)，anchor TOP → ay=0；gravity TOP → py=0-10=-10
        // 出上界；flip → gravity BOTTOM → py=0 全包容 → y=0。
        let flip = PosDef {
            size: (20, 10),
            anchor_rect: (50, 0, 10, 5),
            anchor: XDG_ANCHOR_TOP,
            gravity: XDG_ANCHOR_TOP,
            cadj: XDG_CADJ_FLIP_Y,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = flip.place_in_bounds((0, 0, 100, 100));
        assert_eq!(pr.y, 0, "flip_y 施策后入界");
        assert!(pr.flip_y && !pr.flip_x);
        assert_eq!(pr.w, 20);

        // slide_x 金值：右越界 → SLIDER_X 钳到界内（x = 100-20 = 80）。
        let slide = PosDef {
            size: (20, 10),
            anchor_rect: (95, 5, 10, 10),
            anchor: XDG_ANCHOR_BOTTOM_RIGHT,
            gravity: XDG_ANCHOR_RIGHT,
            cadj: XDG_CADJ_SLIDER_X,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = slide.place_in_bounds((0, 0, 100, 100));
        assert_eq!(pr.x, 80, "slide_x 钳制金值");
        assert!(!pr.flip_x, "slide 不翻转");
        assert_eq!(pr.y, 10);

        // resize_x 金值：右越界且 FLIP/SLIDE 缺位 → RESIZE_X 对界求交
        // （x=80 不动，w = 100-80 = 20）。
        let resize = PosDef {
            size: (60, 10),
            anchor_rect: (70, 10, 10, 10),
            anchor: XDG_ANCHOR_BOTTOM_RIGHT,
            gravity: XDG_ANCHOR_RIGHT,
            cadj: XDG_CADJ_RESIZE_X,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = resize.place_in_bounds((0, 0, 100, 100));
        assert_eq!((pr.x, pr.w), (80, 20), "resize_x 截尺寸金值");

        // 无位域轴：raw 位置保持 + 屏域裁剪（w 截到界内余量）。
        let raw = PosDef {
            size: (20, 10),
            anchor_rect: (95, 5, 10, 10),
            anchor: XDG_ANCHOR_BOTTOM_RIGHT,
            gravity: XDG_ANCHOR_RIGHT,
            cadj: 0,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = raw.place_in_bounds((0, 0, 100, 100));
        assert_eq!(pr.x, 105, "raw 位置保持（无位域轴不施策）");
        assert_eq!(pr.w, 0, "屏域裁剪零余量如实显形");

        // 完全出界：零面积域（零面积快径显形）。
        let out = PosDef {
            size: (20, 10),
            anchor_rect: (50, 5, 10, 10),
            anchor: XDG_ANCHOR_BOTTOM_RIGHT,
            gravity: XDG_ANCHOR_RIGHT,
            cadj: 0,
            offset: (0, 0),
            reactive: false,
            parent_size: (0, 0),
            parent_config: 0,
        };
        let pr = out.place_in_bounds((0, 0, 50, 100));
        assert_eq!(pr.w, 0, "全出界 = 零面积域");
    }

    /// M53-XDGSTAT83 笔96：xdg_toplevel 状态族——官方 opcode 序 + 状态
    /// 枚举值 + 决策核全谱 + wire 面五请求编组回环。
    #[test]
    fn toplevel_state_family() {
        // 官方 opcode 序（xdg-shell.xml 声明序锚）。
        assert_eq!(xdg_toplevel::REQ_SET_MAXIMIZED, 9);
        assert_eq!(xdg_toplevel::REQ_UNSET_MAXIMIZED, 10);
        assert_eq!(xdg_toplevel::REQ_SET_FULLSCREEN, 11);
        assert_eq!(xdg_toplevel::REQ_UNSET_FULLSCREEN, 12);
        assert_eq!(xdg_toplevel::REQ_SET_MINIMIZED, 13);
        // 官方 state 枚举值域。
        assert_eq!(XDG_TOPLEVEL_STATE_MAXIMIZED, 0);
        assert_eq!(XDG_TOPLEVEL_STATE_FULLSCREEN, 1);
        assert_eq!(XDG_TOPLEVEL_STATE_ACTIVATED, 2);

        // 决策核：全屏优先（全屏/最大化同置时全屏胜）。
        let (w, h, st, n) = toplevel_state_decide(true, true, 500, 400, 1920, 1080, 0, 0, 0, 0);
        assert_eq!((w, h, n), (1920, 1080, 1));
        assert_eq!(st[0], XDG_TOPLEVEL_STATE_FULLSCREEN);
        // 最大化 = 屏域全幅（工作区扣减面挂账如实）。
        let (w, h, st, n) = toplevel_state_decide(true, false, 500, 400, 1920, 1080, 0, 0, 0, 0);
        assert_eq!((w, h, n), (1920, 1080, 1));
        assert_eq!(st[0], XDG_TOPLEVEL_STATE_MAXIMIZED);
        // 常态恢复 = 恢复几何（零钳制域）。
        let (w, h, _st, n) = toplevel_state_decide(false, false, 500, 400, 1920, 1080, 0, 0, 0, 0);
        assert_eq!((w, h, n), (500, 400, 0));
        // 常态恢复 + min 下钳（max 未设定）。
        let (w, h, _, _) =
            toplevel_state_decide(false, false, 500, 400, 1920, 1080, 800, 600, 0, 0);
        assert_eq!((w, h), (800, 600));
        // 常态恢复 + max 上钳。
        let (w, h, _, _) =
            toplevel_state_decide(false, false, 500, 400, 1920, 1080, 0, 0, 400, 300);
        assert_eq!((w, h), (400, 300));
        // min/max 交叉域：max 先行 min 后随（clamp_minmax 同谱——min 胜）。
        let (w, h, _, _) =
            toplevel_state_decide(false, false, 500, 400, 1920, 1080, 900, 800, 400, 300);
        assert_eq!((w, h), (900, 800));
        // 负 min/max = 未设定域跳过（官方 0 = unset 外延）。
        let (w, h, _, _) =
            toplevel_state_decide(false, false, 500, 400, 1920, 1080, -1, -1, -1, -1);
        assert_eq!((w, h), (500, 400));

        // wire 面五请求编组回环（官方序锚 + SIG 对账）。
        let mut buf = [0u8; 64];
        let n = encode_message(&mut buf, 0x62, xdg_toplevel::REQ_SET_MAXIMIZED, &[]).expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_SET_MAXIMIZED).expect("parse");
        assert_eq!(m.header.object_id, 0x62);
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_MAXIMIZED);
        let n =
            encode_message(&mut buf, 0x62, xdg_toplevel::REQ_UNSET_MAXIMIZED, &[]).expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_UNSET_MAXIMIZED).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_UNSET_MAXIMIZED);
        let n = encode_message(
            &mut buf,
            0x62,
            xdg_toplevel::REQ_SET_FULLSCREEN,
            &[WlArg::Object(0)],
        )
        .expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_SET_FULLSCREEN).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_FULLSCREEN);
        assert!(matches!(m.args[0], Some(WlArg::Object(0))));
        let n =
            encode_message(&mut buf, 0x62, xdg_toplevel::REQ_UNSET_FULLSCREEN, &[]).expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_UNSET_FULLSCREEN).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_UNSET_FULLSCREEN);
        let n = encode_message(&mut buf, 0x62, xdg_toplevel::REQ_SET_MINIMIZED, &[]).expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_SET_MINIMIZED).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::REQ_SET_MINIMIZED);

        // configure states 数组编组回环（官方序：maximized 0 / fullscreen 1）。
        let n = encode_xdg_toplevel_configure_event(
            &mut buf,
            0x62,
            1920,
            1080,
            &[XDG_TOPLEVEL_STATE_MAXIMIZED],
        )
        .expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_CONFIGURE).expect("parse");
        assert_eq!(m.header.opcode, xdg_toplevel::EV_CONFIGURE);
        assert_eq!(m.args[0], Some(WlArg::Int(1920)));
        assert_eq!(m.args[1], Some(WlArg::Int(1080)));
        match m.args[2] {
            Some(WlArg::Array(bytes)) => assert_eq!(bytes, &[XDG_TOPLEVEL_STATE_MAXIMIZED]),
            _ => panic!("states 数组缺位"),
        }
        let n = encode_xdg_toplevel_configure_event(&mut buf, 0x62, 0, 0, &[]).expect("enc");
        let m = parse_message(&buf[..n], SIG_XDG_TOPLEVEL_CONFIGURE).expect("parse");
        match m.args[2] {
            Some(WlArg::Array(bytes)) => assert!(bytes.is_empty(), "空 states 数组"),
            _ => panic!("states 数组缺位"),
        }
    }
}
