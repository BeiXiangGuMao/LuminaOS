//! TCP 传输控制协议首割（RFC 9293 简化面）。
//!
//! M27-T1 范围界定（偏差登记，**M37-N1 转正收口**）：协议面结构——段头
//! 编解码 + 连接状态机骨架 + 三次握手序号推进面（宿主对账测试承载）；
//! vnet 电气接线（M36-N1 转正）与重传定时器、滑动窗口、分片重组
//! （**M37-N1 本笔转正**——[`RtoTimer`] TSC 纳秒重传臂 + [`SendWindow`]
//! 发送滑窗 + [`ReasmBuf`] 接收乱序重组，全纯函数零堆零 unsafe）。
//! 状态集按 ROADMAP M27-T1 清单八态（FIN_WAIT 合并半关闭双态 v0 简化）。
//!
//! 分层定位：pulse 只承载 L4 段面（同 [`crate::udp`]）；校验和伪头核心
//! 与 UDP 共用（proto 6 vs 17 参数化）。
//!
//! 重传面 v0 简化域（偏差如实登记）：RTO 初值 200 ms（RFC 9293 §5 建议
//! 1 s——回环电气面短臂口径）+ 固定倍增退避封顶 [`RTO_MAX_NS`]（无 RTT
//! 采样自适应——Karn 算法挂账）；同段重传上限 [`RETX_MAX`] 耗尽
//! fail-visible（拆除判定交消费方）；滑窗无窗口缩放选项（16 位通告域
//! 直用）；重组窗旧段/跨基线重叠整段拒收（RFC 9293 允许部分重叠修剪
//! ——v0 全拒保确定性）；零窗探测挂账。

/// TCP 头最小长（data_offset = 5，无选项域）。
pub const HDR_LEN: usize = 20;

/// IP 协议号：TCP（伪头协议域）。
pub const PROTO_TCP: u8 = 6;

// 控制位（低 12 位旗域；RFC 9293 §3.1）。
/// FIN：发送方无更多数据。
pub const FLAG_FIN: u16 = 0x001;
/// SYN：同步序号（连接建立）。
pub const FLAG_SYN: u16 = 0x002;
/// RST：重置连接。
pub const FLAG_RST: u16 = 0x004;
/// PSH：推数据。
pub const FLAG_PSH: u16 = 0x008;
/// ACK：确认域有效。
pub const FLAG_ACK: u16 = 0x010;
/// URG：紧急指针有效。
pub const FLAG_URG: u16 = 0x020;

/// 解析后的 TCP 头（多字节域为大端）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHdr {
    /// 源端口。
    pub src_port: u16,
    /// 目的端口。
    pub dst_port: u16,
    /// 发送序号。
    pub seq: u32,
    /// 确认序号（ACK 置位时有效）。
    pub ack_seq: u32,
    /// 数据偏移（32 位字数，≥ 5）+ 保留域原值。
    pub data_offset: u8,
    /// 控制位（低 12 位）。
    pub flags: u16,
    /// 接收窗口。
    pub window: u16,
    /// 校验和（线序原值）。
    pub checksum: u16,
    /// 紧急指针。
    pub urgent: u16,
}

impl TcpHdr {
    /// 从段缓冲头部解析（返回头 + 载荷切片）。
    ///
    /// 闸序：头足额 → data_offset ≥ 5（且 ≤ 缓冲 32 位字域）→ 选项域
    /// 步进。v0 首割不解释选项域（载荷起算 = offset × 4）。
    pub fn parse(seg: &[u8]) -> Option<(TcpHdr, &[u8])> {
        if seg.len() < HDR_LEN {
            return None;
        }
        let data_offset = seg[12] >> 4;
        let hdr_len = usize::from(data_offset) * 4;
        if data_offset < 5 || hdr_len > seg.len() {
            return None; // offset 足额闸 + 选项域界内闸
        }
        let hdr = TcpHdr {
            src_port: u16::from_be_bytes([seg[0], seg[1]]),
            dst_port: u16::from_be_bytes([seg[2], seg[3]]),
            seq: u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]),
            ack_seq: u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]),
            data_offset,
            flags: u16::from_be_bytes([seg[12], seg[13]]) & 0x0FFF,
            window: u16::from_be_bytes([seg[14], seg[15]]),
            checksum: u16::from_be_bytes([seg[16], seg[17]]),
            urgent: u16::from_be_bytes([seg[18], seg[19]]),
        };
        Some((hdr, &seg[hdr_len..]))
    }

    /// 编码基线段（无选项域，校验和域 0）到 `out`，返回写入长度。
    ///
    /// 载荷与 `out` 容量闸 fail-visible（静默截断禁令，UDP 同款）。
    /// 参数域 = 头字段全量直写（端口对/序号对/旗/窗），协议面天然
    /// 8 元形状，无省略空间——too_many_arguments 登记。
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack_seq: u32,
        flags: u16,
        window: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let total = HDR_LEN + payload.len();
        if out.len() < total {
            return None;
        }
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&seq.to_be_bytes());
        out[8..12].copy_from_slice(&ack_seq.to_be_bytes());
        out[12] = 0x50; // data_offset = 5（无选项域 v0）
        out[13] = (flags & 0xFF) as u8; // 低 8 位旗（SYN/ACK/FIN 全在低域）
        out[14..16].copy_from_slice(&window.to_be_bytes());
        out[16..18].copy_from_slice(&0u16.to_be_bytes()); // 校验和域基线 0
        out[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent v0 恒 0
        out[HDR_LEN..total].copy_from_slice(payload);
        Some(total)
    }
}

/// TCP 校验和（RFC 9293，伪头 proto 6——与 UDP 共用折叠核心）。
#[must_use]
pub fn checksum(src_ip: [u8; 4], dst_ip: [u8; 4], seg: &[u8]) -> u16 {
    super::udp::checksum_pseudo(src_ip, dst_ip, PROTO_TCP, seg)
}

/// 段校验和验证（反码自消性质，UDP 同构——见 [`crate::udp::verify`]）。
#[must_use]
pub fn verify(src_ip: [u8; 4], dst_ip: [u8; 4], seg: &[u8]) -> bool {
    if seg.len() < HDR_LEN {
        return false;
    }
    let cs = u16::from_be_bytes([seg[16], seg[17]]);
    if cs == 0 {
        return true;
    }
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = PROTO_TCP;
    let ulen = seg.len() as u16;
    pseudo[10..12].copy_from_slice(&ulen.to_be_bytes());
    super::udp::fold16(super::udp::fold16(0, &pseudo), seg) == 0xFFFF
}

/// 连接状态（RFC 9293 §3.3.2 简化八态，ROADMAP M27-T1 清单）。
///
/// v0 简化（偏差登记）：FIN_WAIT 合并 FIN_WAIT_1/2 半关闭双态；
/// CLOSE_WAIT/LAST_ACK/CLOSING（被动关闭半程）押后服务化批次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// 关闭/初始态。
    Closed,
    /// 被动打开监听。
    Listen,
    /// 主动打开：SYN 已发。
    SynSent,
    /// 被动打开：SYN&ACK 已发。
    SynRcvd,
    /// 数据传输态。
    Established,
    /// 主动关闭：FIN 已发。
    FinWait,
    /// 主动关闭：收到对方 FIN，等待 2MSL。
    TimeWait,
    /// 终态。
    ClosedDone,
}

/// 状态迁移/握手错误（fail-visible 枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// 当前态不接受该事件。
    BadTransition,
    /// ACK 序号与期望不符（握手对账失败）。
    BadAck,
    /// 非法参数（ISN 冲突等）。
    BadParam,
}

/// 序号推进一步（SYN/FIN 各消耗 1 序号，RFC 9293 §3.3.1）。
#[must_use]
pub fn seq_advance(seq: u32, syn: bool, fin: bool, payload_len: usize) -> u32 {
    seq.wrapping_add(u32::from(syn) + u32::from(fin) + payload_len as u32)
}

/// 主动打开第一步（CLOSED → SYN_SENT）：登记 ISN，返回应发 SYN 段序号。
pub fn active_open(isn: u32) -> Result<(ConnState, u32), TcpError> {
    if isn == 0 {
        return Err(TcpError::BadParam); // ISN 0 保留域拒收（v0 确定性面）
    }
    Ok((ConnState::SynSent, isn))
}

/// 握手第二步对账（SYN_SENT 收段）：SYN|ACK 且 ack_seq == isn+1 →
/// ESTABLISHED（对端 seq = 对端 ISN，记 rcv_nxt = 对端 isn+1）。
pub fn syn_sent_recv(
    state: ConnState,
    isn: u32,
    seg_flags: u16,
    seg_ack: u32,
    peer_isn: u32,
) -> Result<(ConnState, u32), TcpError> {
    if state != ConnState::SynSent {
        return Err(TcpError::BadTransition);
    }
    if seg_flags & (FLAG_SYN | FLAG_ACK) != (FLAG_SYN | FLAG_ACK) {
        return Err(TcpError::BadTransition);
    }
    if seg_ack != isn.wrapping_add(1) {
        return Err(TcpError::BadAck);
    }
    Ok((ConnState::Established, peer_isn.wrapping_add(1)))
}

/// 被动打开（LISTEN 收 SYN → SYN_RCVD，回 SYN&ACK 携带本端 isn；
/// 第三步 ACK 对账 rcv_nxt → ESTABLISHED）。
pub fn listen_recv(state: ConnState, seg_flags: u16) -> Result<ConnState, TcpError> {
    if state != ConnState::Listen {
        return Err(TcpError::BadTransition);
    }
    if seg_flags & FLAG_SYN == 0 {
        return Err(TcpError::BadTransition);
    }
    Ok(ConnState::SynRcvd)
}

/// SYN_RCVD 收最终 ACK → ESTABLISHED（ack_seq 对账本端 isn+1）。
pub fn syn_rcvd_recv(
    state: ConnState,
    isn: u32,
    seg_flags: u16,
    seg_ack: u32,
) -> Result<ConnState, TcpError> {
    if state != ConnState::SynRcvd {
        return Err(TcpError::BadTransition);
    }
    if seg_flags & FLAG_ACK == 0 {
        return Err(TcpError::BadTransition);
    }
    if seg_ack != isn.wrapping_add(1) {
        return Err(TcpError::BadAck);
    }
    Ok(ConnState::Established)
}

/// 主动关闭主轴（ESTABLISHED --FIN--> FIN_WAIT --FIN&ACK--> TIME_WAIT
/// --close_done--> CLOSED_DONE）。事件驱动单步：
/// - ESTABLISHED + [`FLAG_FIN`] 发出 → FIN_WAIT
/// - FIN_WAIT + 对端 FIN&ACK → TIME_WAIT（ack 对账本端 snd_nxt）
/// - TIME_WAIT + 显式超时收敛（`timeout` 旗）→ CLOSED_DONE
pub fn advance(
    state: ConnState,
    seg_flags: u16,
    seg_ack: u32,
    snd_nxt: u32,
    timeout: bool,
) -> Result<ConnState, TcpError> {
    match state {
        ConnState::Established if seg_flags & FLAG_FIN != 0 => Ok(ConnState::FinWait),
        ConnState::FinWait => {
            if seg_flags & FLAG_FIN == 0 || seg_flags & FLAG_ACK == 0 {
                return Err(TcpError::BadTransition);
            }
            if seg_ack != snd_nxt {
                return Err(TcpError::BadAck);
            }
            Ok(ConnState::TimeWait)
        }
        ConnState::TimeWait if timeout => Ok(ConnState::ClosedDone),
        _ => Err(TcpError::BadTransition),
    }
}

// ===================== M37-N1：TCP 重传面（定时器/滑窗/重组） =====================

/// 32 位序号串行小于（RFC 1982 回绕安全：`a` 在 `b` 之前当且仅当
/// `a − b` 的补码解释为负；差距恰 2^31 既不小于也不大于——保守域）。
#[must_use]
pub fn seq_lt(a: u32, b: u32) -> bool {
    ((a.wrapping_sub(b)) as i32) < 0
}

/// 32 位序号串行小于等于（相等显式先行——回绕比较不覆盖恒等域）。
#[must_use]
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// RTO 初值（TSC 纳秒域；200 ms——回环电气面短臂口径，偏差登记见模块头）。
pub const RTO_INIT_NS: u64 = 200_000_000;
/// RTO 退避上限（2⁴ × 初值 = 3.2 s；RFC 9293 §5 建议上限 ≥ 60 s——v0
/// 回环口径取 16 倍封顶，偏差登记）。
pub const RTO_MAX_NS: u64 = 3_200_000_000;
/// 同段重传上限（第 6 拍到期判 Exhausted——耗尽 fail-visible，拆除判定
/// 交消费方；RFC 9293 建议至少 3 次重传，v0 取 5 次上限）。
pub const RETX_MAX: u32 = 5;

/// 到期拍判定（[`RtoTimer::poll`] 出参；fail-visible 三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtoDecision {
    /// 未武装或未到期（零动作）。
    Idle,
    /// 到期重传拍——调用方必须重发最早未确认段（退避已内部再臂）。
    Due,
    /// 重传耗尽（[`RETX_MAX`] 上限）——定时器已解除武装，连接应拆除。
    Exhausted,
}

/// 重传定时器（TSC 纳秒域；M15-③ [`crate::time`] 同源单调面——pulse
/// 侧时间源不可知：`now_ns` 由调用方注入，宿主测试合成时刻，内核侧
/// `tsc_clock::now_ns` 单调纳秒）。
///
/// 口径：最早未确认段主导（RFC 6298 本义简化——`arm` 幂等，已武装不
/// 重置；ACK 越过武装段首序号清账复位；到期拍固定倍增退避再臂）。
/// 零堆零 unsafe，`Copy` 语义面（嵌核账面定式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtoTimer {
    /// 到期时刻（纳秒；u64::MAX = 未武装）。
    deadline: u64,
    /// 武装段首序号（ACK 清账对账域）。
    armed_seq: u32,
    /// 本臂重传计数（退避指数域）。
    retries: u32,
}

impl RtoTimer {
    /// 空闲定时器（未武装）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deadline: u64::MAX,
            armed_seq: 0,
            retries: 0,
        }
    }
}

impl Default for RtoTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RtoTimer {
    /// 是否武装中。
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.deadline != u64::MAX
    }

    /// 武装段首序号（未武装时返回最近一次登记值——证据面）。
    #[must_use]
    pub const fn armed_seq(&self) -> u32 {
        self.armed_seq
    }

    /// 本臂重传计数。
    #[must_use]
    pub const fn retries(&self) -> u32 {
        self.retries
    }

    /// 武装（幂等：已武装不重置——最早未确认段主导，新段不重启本臂；
    /// 首臂 deadline = now + [`RTO_INIT_NS`]，退避推进由 [`RtoTimer::poll`]
    /// 内部承担）。
    pub fn arm(&mut self, now_ns: u64, seq: u32) {
        if self.is_armed() {
            return;
        }
        self.deadline = now_ns.saturating_add(RTO_INIT_NS);
        self.armed_seq = seq;
        self.retries = 0;
    }

    /// ACK 清账：`ack` 越过武装段首序号（`armed_seq < ack`，串行域）→
    /// 解除武装 + 退避复位。返回 true = 本臂已清（false = 陈旧/重复 ACK
    /// 或未武装——零动作）。
    pub fn on_ack(&mut self, ack: u32) -> bool {
        if self.is_armed() && seq_lt(self.armed_seq, ack) {
            self.deadline = u64::MAX;
            self.retries = 0;
            true
        } else {
            false
        }
    }

    /// 到期拍：Idle（未武装/未到期）→ Due（重传拍；`retries` 推进 +
    /// 倍增退避再臂，封顶 [`RTO_MAX_NS`]）→ Exhausted（第 [`RETX_MAX`]+1
    /// 拍到期——解除武装交消费方拆除，fail-visible）。
    pub fn poll(&mut self, now_ns: u64) -> RtoDecision {
        if !self.is_armed() || now_ns < self.deadline {
            return RtoDecision::Idle;
        }
        if self.retries >= RETX_MAX {
            self.deadline = u64::MAX;
            return RtoDecision::Exhausted;
        }
        self.retries += 1;
        // 倍增退避：2ⁿ × 初值，指数封顶 2⁴（= RTO_MAX_NS，位移域饱和）
        let backoff = RTO_INIT_NS << self.retries.min(4);
        self.deadline = now_ns.saturating_add(backoff.min(RTO_MAX_NS));
        RtoDecision::Due
    }
}

/// 发送侧滑动窗口（v0 无窗口缩放——16 位通告域直用，偏差登记见模块头）。
///
/// 序号域全串行算术（[`seq_lt`]/[`seq_le`] 回绕安全）；`peer_win` 随最新
/// 合法 ACK 更新（陈旧 ACK 不动窗）。零堆零 unsafe。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendWindow {
    /// 最早未确认序号（发送窗左沿）。
    una: u32,
    /// 下一发送序号（发送窗右沿外）。
    nxt: u32,
    /// 对端通告窗（字节）。
    peer_win: u16,
}

impl SendWindow {
    /// 自 ISN 起（una = nxt = isn；握手期 SYN 消耗 1 序号由调用方并入
    /// `sent` 记账口径）。
    #[must_use]
    pub const fn new(isn: u32, peer_win: u16) -> Self {
        Self {
            una: isn,
            nxt: isn,
            peer_win,
        }
    }

    /// 发送窗左沿（最早未确认）。
    #[must_use]
    pub const fn una(&self) -> u32 {
        self.una
    }

    /// 下一发送序号。
    #[must_use]
    pub const fn nxt(&self) -> u32 {
        self.nxt
    }

    /// 当前对端通告窗。
    #[must_use]
    pub const fn window(&self) -> u16 {
        self.peer_win
    }

    /// 可用窗字节 = (una + peer_win) − nxt（串行域，饱和下限 0——零窗
    /// → 0，零窗探测挂账；nxt 越过右沿 = 窗耗尽同域）。
    #[must_use]
    pub fn usable(&self) -> usize {
        let right = self.una.wrapping_add(u32::from(self.peer_win));
        if seq_le(self.nxt, right) {
            right.wrapping_sub(self.nxt) as usize
        } else {
            0
        }
    }

    /// 发出记账：`nxt` 前进 `len`（载荷 + SYN/FIN 序号消耗由调用方并入
    /// 口径——[`seq_advance`] 同源）。
    pub fn sent(&mut self, len: u32) {
        self.nxt = self.nxt.wrapping_add(len);
    }

    /// ACK 推进：`ack ∈ (una, nxt]`（串行域开左闭右——恰越 una 才前进）
    /// → `una = ack` + 窗口更新，true；否则 false（陈旧/重复/越域 ACK
    /// ——零动作 fail-visible，消费方可显形取证）。
    pub fn on_ack(&mut self, ack: u32, peer_win: u16) -> bool {
        if seq_lt(self.una, ack) && seq_le(ack, self.nxt) {
            self.una = ack;
            self.peer_win = peer_win;
            true
        } else {
            false
        }
    }
}

/// 重组注入判定（[`ReasmBuf::insert`] 出参；fail-visible 四态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasmOutcome {
    /// 段首恰落基线（rcv_nxt）——前缀立即连续，drain 即可交付。
    InOrder,
    /// 段落窗内未来域——缓存待洞补齐（乱序容错本体）。
    Queued,
    /// 旧段（段首在基线之前，含跨基线重叠——v0 整段拒收，偏差登记）。
    Old,
    /// 越窗（段尾越过基线 + 窗容量 N——v0 整段拒收）。
    Overflow,
}

/// 接收侧乱序重组窗（字节粒度 presence 位图 + 定容窗 `N`；M37-N1 v0
/// 单流单实例——多连接扩容随服务化批次挂账）。
///
/// 语义：段按序号定位窗内偏移，presence 标记 + 幂等拷贝（重复域零
/// 扰动）；`drain` 交付基线起连续前缀并左移对齐（基线推进 = 交付数）。
/// 全定容零堆零 unsafe（`[u8; N]` + `[bool; N]` 直存——TCP_SEG_MAX
/// 量级窗 1 KiB 级 .bss 定容，增长复用纪律无关域）。
#[derive(Debug, Clone, Copy)]
pub struct ReasmBuf<const N: usize> {
    /// 重组基线（rcv_nxt——下个期望字节序号）。
    base: u32,
    /// 窗内字节存储。
    buf: [u8; N],
    /// 字节粒度 presence 位图。
    have: [bool; N],
    /// 在窗字节数（presence 计数账——t89 证据域）。
    have_count: usize,
}

impl<const N: usize> ReasmBuf<N> {
    /// 以初始基线（对端 ISN + 1）建窗。
    #[must_use]
    pub const fn new(rcv_nxt: u32) -> Self {
        Self {
            base: rcv_nxt,
            buf: [0; N],
            have: [false; N],
            have_count: 0,
        }
    }

    /// 当前重组基线。
    #[must_use]
    pub const fn rcv_nxt(&self) -> u32 {
        self.base
    }

    /// 在窗缓存字节数（乱序滞留账）。
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.have_count
    }

    /// 注入段：序号定位 → 四态判定 → presence 标记 + 幂等拷贝。
    ///
    /// 闸序：旧段（段首串行 < 基线——含跨基线重叠）→ [`ReasmOutcome::Old`]；
    /// 越窗（段首 ≥ 窗容量或段尾越界）→ [`ReasmOutcome::Overflow`]；
    /// 空载荷段（纯旗域 SYN/ACK/FIN——不参与重组）仅序号域对账判定；
    /// 否则窗内标记拷贝，段首恰基线 → [`ReasmOutcome::InOrder`]，其余
    /// → [`ReasmOutcome::Queued`]。
    pub fn insert(&mut self, seq: u32, data: &[u8]) -> ReasmOutcome {
        // 空载荷（纯旗段）：不落窗，仅对账判定
        if data.is_empty() {
            if seq == self.base {
                return ReasmOutcome::InOrder;
            }
            return if seq_lt(seq, self.base) {
                ReasmOutcome::Old
            } else {
                ReasmOutcome::Queued
            };
        }
        let off = seq.wrapping_sub(self.base) as i32;
        if off < 0 {
            return ReasmOutcome::Old; // 旧段（含跨基线重叠——v0 整段拒）
        }
        let off_us = off as usize;
        if off_us >= N || off_us + data.len() > N {
            return ReasmOutcome::Overflow; // 越窗
        }
        for (i, b) in data.iter().enumerate() {
            let k = off_us + i;
            if !self.have[k] {
                self.have[k] = true;
                self.buf[k] = *b;
                self.have_count += 1;
            }
        }
        if off_us == 0 {
            ReasmOutcome::InOrder
        } else {
            ReasmOutcome::Queued
        }
    }

    /// 交付：基线起连续前缀拷入 `out`（至多窗容量与 `out` 容量的较小
    /// 值），基线前进交付数，余项左移对齐（定容窗内 memmove 语义）。
    /// 返回交付字节数（0 = 基线位有洞——乱序滞留中）。
    pub fn drain(&mut self, out: &mut [u8]) -> usize {
        let mut k = 0usize;
        while k < N && self.have[k] {
            k += 1;
        }
        let n = k.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.base = self.base.wrapping_add(n as u32);
        self.buf.copy_within(n..N, 0);
        for i in 0..N - n {
            self.have[i] = self.have[i + n];
        }
        for i in N - n..N {
            self.have[i] = false;
        }
        self.have_count -= n;
        n
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        active_open, advance, checksum, listen_recv, seq_advance, syn_rcvd_recv, syn_sent_recv,
        verify, ConnState, TcpError, TcpHdr, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_SYN, HDR_LEN,
    };
    use crate::udp::PROTO_UDP;

    const SRC: [u8; 4] = [10, 0, 2, 15];
    const DST: [u8; 4] = [10, 0, 2, 2];

    #[test]
    fn parse_encode_roundtrip() {
        let payload = *b"tcp";
        let mut seg = [0u8; HDR_LEN + 3];
        assert_eq!(
            TcpHdr::encode(
                1000,
                2000,
                42,
                43,
                FLAG_ACK | FLAG_PSH,
                8192,
                &payload,
                &mut seg
            ),
            Some(23)
        );
        let (h, pl) = TcpHdr::parse(&seg).expect("parse");
        assert_eq!(h.src_port, 1000);
        assert_eq!(h.dst_port, 2000);
        assert_eq!(h.seq, 42);
        assert_eq!(h.ack_seq, 43);
        assert_eq!(h.flags, FLAG_ACK | FLAG_PSH);
        assert_eq!(h.window, 8192);
        assert_eq!(h.data_offset, 5);
        assert_eq!(pl, &payload);
    }

    #[test]
    fn parse_rejects_short_and_bad_offset() {
        assert!(TcpHdr::parse(&[0u8; 19]).is_none(), "头不足 20 B");
        let mut seg = [0u8; HDR_LEN];
        seg[12] = 0x40; // data_offset = 4 < 5
        assert!(TcpHdr::parse(&seg).is_none());
        seg[12] = 0xF0; // offset 15 × 4 = 60 > 缓冲 20
        assert!(TcpHdr::parse(&seg).is_none());
    }

    /// 手工核算向量：SYN 基线段（头 20 B：src=0x1234 dst=0x5678 seq/ack=0，
    /// offset 5 + SYN = 0x5002，win=0x2000，cs/urg=0）。
    /// 伪头四字和 0x1811 + [00 06] + [00 14] = 0x182B；
    /// 段和 = 0x1234+0x5678+0x5002+0x2000 = 0xD8AE；
    /// 总 0x182B + 0xD8AE = 0xF0D9 → cs = ~0xF0D9 = 0x0f26。
    #[test]
    fn checksum_known_vector_syn() {
        let mut seg = [0u8; HDR_LEN];
        TcpHdr::encode(0x1234, 0x5678, 0, 0, FLAG_SYN, 0x2000, &[], &mut seg).expect("encode");
        assert_eq!(seg[12], 0x50);
        assert_eq!(seg[13], 0x02);
        assert_eq!(checksum(SRC, DST, &seg), 0x0f26);
        seg[16..18].copy_from_slice(&0x0f26u16.to_be_bytes());
        assert!(verify(SRC, DST, &seg));
        // 位翻转检出 + cs=0 语义
        seg[4] ^= 0x01;
        assert!(!verify(SRC, DST, &seg));
        seg[4] ^= 0x01;
        seg[16..18].copy_from_slice(&0u16.to_be_bytes());
        assert!(verify(SRC, DST, &seg));
    }

    #[test]
    fn seq_advance_syn_fin_payload() {
        assert_eq!(seq_advance(100, true, false, 0), 101, "SYN 消耗 1 序号");
        assert_eq!(seq_advance(101, false, false, 10), 111, "载荷 10 序号");
        assert_eq!(seq_advance(111, false, true, 0), 112, "FIN 消耗 1 序号");
        assert_eq!(seq_advance(u32::MAX, true, false, 0), 0, "回绕语义");
    }

    #[test]
    fn handshake_active_open_full() {
        let isn = 1000;
        let (st, snd_nxt) = active_open(isn).expect("open");
        assert_eq!(st, ConnState::SynSent);
        assert_eq!(snd_nxt, isn);
        // 服务端 SYN&ACK：ack_seq 必须 = isn+1（错序号拒）
        let peer_isn = 5000;
        assert_eq!(
            syn_sent_recv(st, isn, FLAG_SYN | FLAG_ACK, isn, peer_isn),
            Err(TcpError::BadAck),
            "ack_seq 未对账 isn+1"
        );
        let (st, rcv_nxt) =
            syn_sent_recv(st, isn, FLAG_SYN | FLAG_ACK, isn + 1, peer_isn).expect("SYN&ACK 对账");
        assert_eq!(st, ConnState::Established);
        assert_eq!(rcv_nxt, peer_isn + 1, "对端 SYN 消耗 1 序号");
        // SYN-only（无 ACK）在 SYN_SENT 态不接受
        assert_eq!(
            syn_sent_recv(ConnState::SynSent, isn, FLAG_SYN, isn + 1, peer_isn),
            Err(TcpError::BadTransition)
        );
    }

    #[test]
    fn handshake_passive_open_full() {
        let isn = 2000;
        // LISTEN 收 SYN → SYN_RCVD
        let st = listen_recv(ConnState::Listen, FLAG_SYN).expect("SYN");
        assert_eq!(st, ConnState::SynRcvd);
        assert_eq!(
            listen_recv(ConnState::Listen, FLAG_ACK),
            Err(TcpError::BadTransition),
            "非 SYN 不入握手"
        );
        // 第三步 ACK：错对账拒
        assert_eq!(syn_rcvd_recv(st, isn, FLAG_ACK, isn), Err(TcpError::BadAck));
        let st = syn_rcvd_recv(st, isn, FLAG_ACK, isn + 1).expect("final ACK");
        assert_eq!(st, ConnState::Established);
    }

    #[test]
    fn close_axis_and_bad_transitions() {
        let snd_nxt = 3001;
        // ESTABLISHED 发 FIN → FIN_WAIT
        let st = advance(ConnState::Established, FLAG_FIN, 0, snd_nxt, false).expect("FIN out");
        assert_eq!(st, ConnState::FinWait);
        // 对端 FIN&ACK：ack 错账拒
        assert_eq!(
            advance(st, FLAG_FIN | FLAG_ACK, snd_nxt - 1, snd_nxt, false),
            Err(TcpError::BadAck)
        );
        // 对端 FIN&ACK 对账 → TIME_WAIT
        let st = advance(st, FLAG_FIN | FLAG_ACK, snd_nxt, snd_nxt, false).expect("peer FIN");
        assert_eq!(st, ConnState::TimeWait);
        // 未超时不收敛
        assert_eq!(
            advance(st, 0, 0, snd_nxt, false),
            Err(TcpError::BadTransition)
        );
        // 超时收敛终态
        let st = advance(st, 0, 0, snd_nxt, true).expect("2MSL");
        assert_eq!(st, ConnState::ClosedDone);
        // 终态冻结
        assert_eq!(
            advance(ConnState::ClosedDone, FLAG_FIN, 0, snd_nxt, true),
            Err(TcpError::BadTransition)
        );
        // SYN_SENT 态不接受关闭事件
        assert_eq!(
            advance(ConnState::SynSent, FLAG_FIN, 0, snd_nxt, false),
            Err(TcpError::BadTransition)
        );
    }

    #[test]
    fn active_open_rejects_zero_isn() {
        assert_eq!(active_open(0), Err(TcpError::BadParam));
    }

    #[test]
    fn proto_constant_is_tcp() {
        assert_eq!(super::PROTO_TCP, 6);
        assert_ne!(super::PROTO_TCP, PROTO_UDP);
    }

    // ---- M37-N1：重传面（seq 串行域 / RTO / 滑窗 / 重组） ----

    #[test]
    fn seq_serial_wrap() {
        use super::{seq_le, seq_lt};
        assert!(seq_lt(9, 10));
        assert!(!seq_lt(10, 9));
        assert!(!seq_lt(10, 10), "恒等域不属小于");
        assert!(seq_lt(u32::MAX, 0), "回绕：MAX 在 0 之前");
        assert!(!seq_lt(0, u32::MAX));
        assert!(seq_le(10, 10), "恒等域显式覆盖");
        assert!(seq_le(u32::MAX - 1, 3));
    }

    /// RTO 三拍全谱：首臂 200 ms → 未到期 Idle → 到期 Due（retries 1，
    /// 再臂 +400 ms = 2× 初值）→ 第二到期窗边界双向验证 → ACK 清账复位
    /// → 空闲 poll 恒 Idle。
    #[test]
    fn rto_arm_poll_backoff_and_ack() {
        use super::{RtoDecision, RtoTimer, RTO_INIT_NS};
        let t0 = 1_000_000;
        let mut r = RtoTimer::new();
        assert!(!r.is_armed());
        assert_eq!(r.poll(t0), RtoDecision::Idle, "未武装 Idle");
        r.arm(t0, 4242);
        assert!(r.is_armed() && r.armed_seq() == 4242 && r.retries() == 0);
        r.arm(t0 + 1, 9999); // 幂等：已武装不重置
        assert_eq!(r.armed_seq(), 4242, "最早未确认段主导");
        let d1 = t0 + RTO_INIT_NS;
        assert_eq!(r.poll(d1 - 1), RtoDecision::Idle, "差一拍不早醒");
        assert_eq!(r.poll(d1), RtoDecision::Due);
        assert_eq!(r.retries(), 1);
        // 再臂 = 2× 初值倍增（d1 + 2 × RTO）
        let d2 = d1 + 2 * RTO_INIT_NS;
        assert_eq!(r.poll(d2 - 1), RtoDecision::Idle);
        assert_eq!(r.poll(d2), RtoDecision::Due);
        assert_eq!(r.retries(), 2);
        // 陈旧 ACK 不清账；越过武装段首序号才清
        assert!(!r.on_ack(4242), "重复 ACK 零动作");
        assert!(r.on_ack(4243));
        assert!(!r.is_armed() && r.retries() == 0, "清账复位");
        assert_eq!(
            r.poll(d2 + 10 * RTO_INIT_NS),
            RtoDecision::Idle,
            "空闲恒 Idle"
        );
    }

    /// 耗尽谱：连续 5 拍 Due（每次退避倍增）→ 第 6 拍 Exhausted +
    /// 解除武装（fail-visible 拆除判定交消费方）。
    #[test]
    fn rto_exhaustion_visible() {
        use super::{RtoDecision, RtoTimer, RETX_MAX, RTO_INIT_NS};
        let mut r = RtoTimer::new();
        r.arm(0, 100);
        let mut now = RTO_INIT_NS;
        for i in 1..=RETX_MAX {
            assert_eq!(r.poll(now), RtoDecision::Due, "第 {i} 拍重传");
            // 倍增窗：min(retries,4) 指数
            now += RTO_INIT_NS << i.min(4);
        }
        assert_eq!(r.retries(), RETX_MAX);
        assert_eq!(r.poll(now), RtoDecision::Exhausted, "耗尽显形");
        assert!(!r.is_armed(), "解除武装");
        assert_eq!(r.poll(now), RtoDecision::Idle);
    }

    /// 滑窗四目：usable 发送记账 / ACK 开左闭右推进 + 窗更新 / 陈旧与
    /// 越域 ACK 零动作 / 零窗耗尽 / 回绕域 right 沿。
    #[test]
    fn sendwindow_accounting() {
        use super::SendWindow;
        let mut w = SendWindow::new(1000, 4);
        assert_eq!(w.usable(), 4);
        w.sent(3);
        assert_eq!(w.nxt(), 1003);
        assert_eq!(w.usable(), 1);
        // 恰填满 → 零窗
        w.sent(1);
        assert_eq!(w.usable(), 0, "窗耗尽");
        // 陈旧/重复 ACK 零动作；恰越 nxt 为越域（ack == nxt 是全量确认合法域）
        assert!(!w.on_ack(1000, 8), "重复 ACK");
        assert!(!w.on_ack(1005, 8), "越域 ACK（未来域）");
        assert_eq!(w.una(), 1000, "una 不动");
        // 合法 ACK 推进 + 窗更新（nxt=1004 在飞——usable = 右沿 − nxt）
        assert!(w.on_ack(1003, 8));
        assert_eq!(w.una(), 1003);
        assert_eq!(w.window(), 8);
        assert_eq!(w.usable(), 7, "右沿 = 1003 + 8 = 1011，nxt = 1004 在飞");
        // 回绕域：una 近 MAX，右沿跨 0（MAX−1 + 2 = MAX + 1 ≡ 0 回绕）
        let mut w2 = SendWindow::new(u32::MAX - 1, 4);
        assert_eq!(w2.usable(), 4);
        w2.sent(2);
        assert_eq!(w2.nxt(), 0, "nxt 回绕（MAX−1+2 ≡ 0）");
        assert_eq!(w2.usable(), 2, "右沿 = MAX−1+4 ≡ 2（回绕）");
        assert!(w2.on_ack(0, 4), "ack = nxt = 0 全量确认（回绕域）");
        assert_eq!(w2.una(), 0);
    }

    /// 重组主谱：乱序先到 Queued（洞滞留）→ 补洞 InOrder → drain 拼接
    /// 交付 + 基线推进 + 计数账对账。
    #[test]
    fn reasm_reorder_and_drain() {
        use super::{ReasmBuf, ReasmOutcome};
        let mut q: ReasmBuf<16> = ReasmBuf::new(100);
        assert_eq!(q.rcv_nxt(), 100);
        // (b) 未来段先到：缓存 4 B
        assert_eq!(q.insert(104, b"efgh"), ReasmOutcome::Queued);
        assert_eq!(q.pending(), 4);
        let mut out = [0u8; 16];
        assert_eq!(q.drain(&mut out), 0, "基线有洞不交付");
        // (a) 基线段后到：前缀连通
        assert_eq!(q.insert(100, b"abcd"), ReasmOutcome::InOrder);
        assert_eq!(q.pending(), 8);
        assert_eq!(q.drain(&mut out), 8);
        assert_eq!(&out[..8], b"abcdefgh", "乱序拼接字节级");
        assert_eq!(q.rcv_nxt(), 108);
        assert_eq!(q.pending(), 0);
        // (c) 连续第二段直接 InOrder + 交付
        assert_eq!(q.insert(108, b"ij"), ReasmOutcome::InOrder);
        assert_eq!(q.drain(&mut out), 2);
        assert_eq!(&out[..2], b"ij");
    }

    /// 重组负例四态：旧段 / 跨基线重叠整段拒 / 越窗 / 重复域幂等
    /// （先到者胜——重复注入零扰动）。
    #[test]
    fn reasm_negative_gates() {
        use super::{ReasmBuf, ReasmOutcome};
        let mut q: ReasmBuf<8> = ReasmBuf::new(100);
        // 旧段（段尾恰基线——整段已确认域）
        assert_eq!(q.insert(96, b"old!"), ReasmOutcome::Old);
        // 跨基线重叠（v0 整段拒——偏差登记）
        assert_eq!(q.insert(99, b"xyzw"), ReasmOutcome::Old);
        // 越窗（段首出窗 + 段尾越界两形态）
        assert_eq!(q.insert(108, b"a"), ReasmOutcome::Overflow, "段首出窗");
        assert_eq!(q.insert(106, b"12345"), ReasmOutcome::Overflow, "段尾越界");
        // 重复域幂等：先到者胜
        assert_eq!(q.insert(100, b"AA"), ReasmOutcome::InOrder);
        assert_eq!(
            q.insert(100, b"BB"),
            ReasmOutcome::InOrder,
            "基线重复仍 InOrder"
        );
        let mut out = [0u8; 8];
        assert_eq!(q.drain(&mut out), 2);
        assert_eq!(&out[..2], b"AA", "幂等：首写胜出");
        // 空载荷（纯旗段）序号域对账
        assert_eq!(q.insert(102, b""), ReasmOutcome::InOrder);
        assert_eq!(q.insert(101, b""), ReasmOutcome::Old);
        assert_eq!(q.insert(150, b""), ReasmOutcome::Queued);
        assert_eq!(q.pending(), 0, "空载荷不落窗");
    }

    /// 重组 out 容量部分交付：连续前缀超 out 容量 → 分次交付
    /// （余项左移滞留，基线只按交付数推进）。
    #[test]
    fn reasm_partial_drain() {
        use super::{ReasmBuf, ReasmOutcome};
        let mut q: ReasmBuf<8> = ReasmBuf::new(0);
        assert_eq!(q.insert(0, b"abcdef"), ReasmOutcome::InOrder);
        let mut out = [0u8; 2];
        assert_eq!(q.drain(&mut out), 2);
        assert_eq!(&out, b"ab");
        assert_eq!(q.rcv_nxt(), 2, "基线只按交付数推进");
        assert_eq!(q.pending(), 4, "余项滞留");
        assert_eq!(q.drain(&mut out), 2);
        assert_eq!(&out, b"cd");
        assert_eq!(q.drain(&mut out), 2);
        assert_eq!(&out, b"ef");
        assert_eq!(q.drain(&mut out), 0, "排空");
        assert_eq!(q.rcv_nxt(), 6);
    }
}
