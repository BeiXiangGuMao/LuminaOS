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
    /// wl_output。
    Output,
    /// wl_region。
    Region,
    /// wl_shm。
    Shm,
    /// wl_shm_pool。
    ShmPool,
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
        WlIface::Output => "wl_output",
        WlIface::Region => "wl_region",
        WlIface::Shm => "wl_shm",
        WlIface::ShmPool => "wl_shm_pool",
    }
}

/// 对象表：id → 接口语义（定容槽 + 客户端/服务端双分配器单调铸造；
/// v0 无复用——id 退役即废弃，delete_id 复用面电气挂账如实登记）。
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
/// wl_shm.create_pool：`(new_id, fd, int)`。
pub const SIG_SHM_CREATE_POOL: &[WlType] = &[WlType::NewId, WlType::Fd, WlType::Int];

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

/// wl_surface.commit 请求编组（零参消息——签名空表域）。
pub fn encode_surface_commit(buf: &mut [u8], surface_id: u32) -> Result<usize, WlError> {
    encode_message(buf, surface_id, surface::REQ_COMMIT, &[])
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
}
