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
//!
//! **M38-TCP1 转正注（TCP 服务化批次——重传面 v0 简化域收口）**：上列
//! 偏差四目随本笔落域——Karn 算法（[`RttEst`] RFC 6298 整数式 RTT
//! 估计：首样 `srtt=r, rttvar=r/2` + 滑动 `srtt=(7s+r)/8,
//! rttvar=(3v+Δ)/8` + 重传样窄化不采 + RTO 夹逼导出）、窗口缩放
//! （[`ws_encode`]/[`ws_decode`]/[`ws_negotiate`]/[`ws_effective_window`]
//! RFC 7323 选项面——双方 SYN 才生效、缺省移位 0、有效窗 `wire <<
//! shift` 封顶算术；旧 [`TcpHdr::encode`] 路径保留作未缩放回归锚）、
//! 零窗探测（[`PersistTimer`] 幂等武装 + 退避 Probe + 独立拍数上限
//! Broken fail-visible + 窗重开解除）、多连接（[`ConnTable`] 定容 8 槽
//! 四元组查表——槽体 [`TcpConn`] 六面聚合）。仍不在域（如实记账不扩
//! 域）：快速重传/快速恢复（RFC 5681 §3.2——[`CcState`] v0 只承载慢
//! 启动/拥塞避免/RTO 折叠三态）、SACK、时间戳选项（kind=8）。

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// ===================== M38-TCP1：TCP 服务化批次五面（重传面 v0 简化域收口） =====================
//
// 五面纯函数域（零堆零 unsafe——crate 级 [`forbid(unsafe_code)`] 不变，
// PU-P06 预算内固定布局：连接状态定容、重传/探测账面定式，无无界增长
// 载体）。面次依定式清单：WinScale / RttEst / CongestCtl / PersistTimer
// / ConnTable。

// ---- 面 1：WinScale（RFC 7323 窗口缩放选项） ------------------------------

/// WS 选项 kind（RFC 7323 §2.2：window scale = kind 3）。
pub const WS_KIND: u8 = 3;
/// WS 选项定长（kind + len + shift = 3 B）。
pub const WS_OPT_LEN: u8 = 3;
/// WS 移位上限（RFC 7323：shift ≤ 14——65535 << 14 = 2³⁰−2¹⁴ 界内，
/// u32 不溢；越域值拒收 fail-visible）。
pub const WS_SHIFT_MAX: u8 = 14;

/// WS 选项编码：`[WS_KIND, WS_OPT_LEN, shift]` 三字节写 `out`，返回 3。
///
/// 闸序：容量 ≥ 3 → shift ≤ 14（越域拒——fail-visible，静默截断禁令
/// 同 [`TcpHdr::encode`] 族口径）。
#[must_use]
pub fn ws_encode(shift: u8, out: &mut [u8]) -> Option<usize> {
    if out.len() < 3 || shift > WS_SHIFT_MAX {
        return None;
    }
    out[0] = WS_KIND;
    out[1] = WS_OPT_LEN;
    out[2] = shift;
    Some(3)
}

/// 选项区解析：TLV 步进扫描，kind=3 命中返回 `Some(shift)`。
///
/// 闸序：kind 0（EOL）停扫 / kind 1（NOP）单字节步进 / 其余 kind 取
/// len 界内闸（len < 2 或越缓冲 = 畸形 → None）→ WS 命中须定长 3 且
/// shift ≤ 14。未见 WS → None（缺省域——协商降 0 的解析侧输入）。
#[must_use]
pub fn ws_decode(opts: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i] {
            0 => break,  // EOL：剩余填充域
            1 => i += 1, // NOP：单字节步进
            kind => {
                let len = usize::from(*opts.get(i + 1)?);
                if len < 2 || i + len > opts.len() {
                    return None; // 畸形（len 越界）fail-visible
                }
                if kind == WS_KIND {
                    if len != usize::from(WS_OPT_LEN) {
                        return None; // WS 定长闸
                    }
                    let shift = opts[i + 2];
                    return (shift <= WS_SHIFT_MAX).then_some(shift);
                }
                i += len;
            }
        }
    }
    None
}

/// WS 协商：双方 SYN 均携 WS 选项才生效，缺省移位 0（RFC 7323 §6.1.2
/// ——任一侧未发选项即全双工未缩放）。
///
/// 语义（§2.2 通告域）：选项值 = 通告方的**接收窗移位**——本端解释
/// 对端来窗的移位 = **对端通告值**（对端来窗 wire 域已按其接收粒度
/// 缩除）。`local_shift` 只作合法性闸（越域 = 协商不成同域降 0——v0
/// 确定性面）；生效输出即对端移位（对端合法界内取值）。
#[must_use]
pub fn ws_negotiate(
    local_syn: bool,
    local_shift: u8,
    peer_syn: bool,
    peer_shift: Option<u8>,
) -> u8 {
    let local_ok = local_syn && local_shift <= WS_SHIFT_MAX;
    match (local_ok, peer_syn, peer_shift) {
        (true, true, Some(p)) if p <= WS_SHIFT_MAX => p,
        _ => 0,
    }
}

/// 有效窗算术：对端来窗 `wire << shift`（饱和封顶——移位/溢出域不回
/// 绕不翻转，u32 上限饱和；shift 先夹逼 [`WS_SHIFT_MAX`]，RFC 7323
/// 界内值域 65535 << 14 不触顶，封顶算术为越域防御面）。
#[must_use]
pub fn ws_effective_window(wire: u16, shift: u8) -> u32 {
    u32::from(wire)
        .checked_shl(u32::from(shift.min(WS_SHIFT_MAX)))
        .unwrap_or(u32::MAX)
}

// ---- 面 2：RttEst（RFC 6298 整数式 RTT 估计） ------------------------------

/// rttvar 夹逼下限（整数化防零——`(3v+Δ)/8` 向零塌缩域的退化禁令）。
pub const RTTVAR_MIN: u64 = 1;

/// RTT 估计器（RFC 6298 整数式——TSC 纳秒域；pulse 侧时间源不可知：
/// 样本由调用方注入，宿主测试合成时刻，内核侧 TSC 单调纳秒同源）。
///
/// 口径（RFC 6298 §2 整数化，增益 1/8 = 移位除）：
/// - 首样（§2.2 第一测）：`srtt = r`，`rttvar = r / 2`；
/// - 滑动（§2.3，RTTVAR 先行序）：`Δ = |旧 srtt − r|` → `rttvar =
///   (3v + Δ) / 8`（夹逼下限 [`RTTVAR_MIN`]）→ `srtt = (7s + r) / 8`；
/// - Karn 窄化：重传段样本不采（`sample` 带 `from_retx` 旗——窄化
///   域，调用方按段重传史挂旗）；
/// - RTO 导出（§2.1 + §2.4）：`srtt + 4·rttvar` 夹逼域
///   [`RTO_INIT_NS`]（下限——回环短臂口径同源）到 [`RTO_MAX_NS`]
///   （上限——退避封顶同源）。
///
/// 零堆零 unsafe，`Copy` 语义面（嵌核账面定式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttEst {
    /// 平滑 RTT（纳秒；未 primed 恒 0）。
    srtt: u64,
    /// RTT 偏差平滑（纳秒）。
    rttvar: u64,
    /// 首样已落（首样/滑动两域闸）。
    primed: bool,
}

impl RttEst {
    /// 空估计器（未 primed）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            srtt: 0,
            rttvar: 0,
            primed: false,
        }
    }

    /// 平滑 RTT 读数（纳秒）。
    #[must_use]
    pub const fn srtt(&self) -> u64 {
        self.srtt
    }

    /// RTT 偏差平滑读数（纳秒）。
    #[must_use]
    pub const fn rttvar(&self) -> u64 {
        self.rttvar
    }

    /// 首样已落（滑动域准入）。
    #[must_use]
    pub const fn primed(&self) -> bool {
        self.primed
    }

    /// 首样（§2.2）：`srtt = r`，`rtttvar = r / 2`。已 primed 重入拒
    /// （首样唯一性——滑动域走 [`RttEst::sample`]）；`r == 0` 退化样
    /// 拒。返回 true = 样本已采。
    pub fn first_sample(&mut self, r: u64) -> bool {
        if self.primed || r == 0 {
            return false;
        }
        self.srtt = r;
        self.rttvar = r / 2;
        self.primed = true;
        true
    }

    /// 滑动样（§2.3 整数式，RTTVAR 先行序）：Δ = |旧 srtt − r| →
    /// `rttvar = (3v + Δ) / 8`（下限夹逼）→ `srtt = (7s + r) / 8`。
    /// Karn 窄化：`from_retx` = 样本出自重传段 → 不采（false，账面
    /// 零扰动）。未 primed → false（首样须走 [`RttEst::first_sample`]）。
    pub fn sample(&mut self, r: u64, from_retx: bool) -> bool {
        if from_retx || !self.primed || r == 0 {
            return false;
        }
        let delta = self.srtt.abs_diff(r);
        self.rttvar = ((3 * self.rttvar + delta) / 8).max(RTTVAR_MIN);
        self.srtt = (7 * self.srtt + r) / 8;
        true
    }

    /// RTO 导出（§2.1 + §2.4 整数化）：`srtt + 4·rttvar` 夹逼域
    /// [`RTO_INIT_NS`]…[`RTO_MAX_NS`]（上下限同 [`RtoTimer`] 退避域
    /// ——单一定时器时间基）。
    #[must_use]
    pub fn rto(&self) -> u64 {
        let raw = self.srtt.saturating_add(self.rttvar.saturating_mul(4));
        raw.clamp(RTO_INIT_NS, RTO_MAX_NS)
    }
}

impl Default for RttEst {
    fn default() -> Self {
        Self::new()
    }
}

// ---- 面 3：CongestCtl（RFC 5681 简化域） ----------------------------------

/// 慢启动初值倍数（RFC 5681 §3.1 原初域：IW = 2·SMSS 下限口径——
/// RFC 9293/modern 10·SMSS 建议不入 v0，偏差如实登记）。
pub const IW_SMSS_MULT: u32 = 2;

/// 拥塞控制账面（RFC 5681 简化域：慢启动 + 拥塞避免 + RTO 折叠三态）。
///
/// 口径：
/// - 慢启动（§3.1）：`cwnd += acked_bytes`（每 ACK 字节域直加）；
/// - 越阈转换：`cwnd ≥ ssthresh` 转拥塞避免 `cwnd += SMSS²/cwnd`
///   （整数除，下限 1——单调不凝滞）；
/// - RTO 折叠（§3.1 原初域）：`ssthresh = max(flight/2, 2·SMSS)` +
///   `cwnd` 回初值 IW（慢启动重启）；
/// - 发送资格：`min(可用窗, cwnd)`（窗域与拥塞域取小——门控面）。
///
/// **快速重传/快速恢复不在 v0 域清单（如实记账不扩域）**：RFC 5681
/// §3.2 三重复制 ACK 触发面未落——虚耗域（丢包恢复退化为 RTO 折叠拍）
/// 随服务化后续批次裁决。零堆零 unsafe，`Copy` 语义面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcState {
    /// 拥塞窗（字节）。
    cwnd: u32,
    /// 慢启动阈值（字节；初态 u32::MAX = 有效无穷——直达首个 RTO 定标）。
    ssthresh: u32,
    /// 初值 IW（RTO 折叠回退锚）。
    iw: u32,
    /// 发送方最大段长 SMSS（字节；折叠算术域）。
    smss: u32,
}

impl CcState {
    /// 初值态：`cwnd = IW = IW_SMSS_MULT·SMSS`，`ssthresh = u32::MAX`
    /// （有效无穷——慢启动直达首个 RTO 折叠定标）。
    #[must_use]
    pub const fn new(smss: u32) -> Self {
        Self {
            cwnd: smss.saturating_mul(IW_SMSS_MULT),
            ssthresh: u32::MAX,
            iw: smss.saturating_mul(IW_SMSS_MULT),
            smss,
        }
    }

    /// 拥塞窗读数。
    #[must_use]
    pub const fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// 慢启动阈值读数。
    #[must_use]
    pub const fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// SMSS 读数。
    #[must_use]
    pub const fn smss(&self) -> u32 {
        self.smss
    }

    /// ACK 拍：`cwnd < ssthresh` → 慢启动 `+= acked_bytes`；否则拥塞
    /// 避免 `+= max(SMSS²/cwnd, 1)`（整数除下限 1）。全饱和封顶 u32
    /// （不回绕）。
    pub fn on_ack(&mut self, acked_bytes: u32) {
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked_bytes);
        } else {
            let inc = (self.smss.saturating_mul(self.smss) / self.cwnd).max(1);
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    /// RTO 折叠拍（§3.1 原初域）：`ssthresh = max(flight/2, 2·SMSS)`
    /// （下限 2·SMSS 闸——深折叠域），`cwnd` 回初值 IW。
    pub fn on_rto(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(self.smss.saturating_mul(IW_SMSS_MULT));
        self.cwnd = self.iw;
    }

    /// 发送资格：`min(avail_window, cwnd)`（对端窗域与拥塞域取小）。
    #[must_use]
    pub const fn send_credit(&self, avail_window: u32) -> u32 {
        if self.cwnd < avail_window {
            self.cwnd
        } else {
            avail_window
        }
    }
}

// ---- 面 4：PersistTimer（零窗探测） ----------------------------------------

/// 零窗探测独立拍数上限（与 [`RETX_MAX`] 分账——独立计数域；第 6 拍
/// 到期判 Broken fail-visible）。
pub const PERSIST_MAX_PROBES: u32 = 5;
/// 探测段长（重发 una 起 1 字节——RFC 9293 §3.7.3 探测口径）。
pub const PROBE_SEG_LEN: usize = 1;

/// 探测拍判定（[`PersistTimer::poll`] 出参；fail-visible 三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistDecision {
    /// 未武装或未到期（零动作）。
    Idle,
    /// 到期探测拍——调用方必须发探测段（una 起 [`PROBE_SEG_LEN`] 字节；
    /// 退避已内部再臂）。
    Probe,
    /// 独立拍数上限（[`PERSIST_MAX_PROBES`]）耗尽——定时器已解除武装，
    /// 连接应拆除（fail-visible）。
    Broken,
}

/// 零窗探测定时器（TSC 纳秒域——[`RtoTimer`] 同源单调面）。
///
/// 口径：零窗臂幂等武装（已武装不重置不换基——臂时基 RTO 定格）→
/// 到期拍 Probe（退避 `rto << retries` 封顶 [`RTO_MAX_NS`]）→ 对端窗
/// 重开解除（[`PersistTimer::release`]，幂等）→ 独立拍数上限
/// [`PERSIST_MAX_PROBES`] 耗尽 Broken（解除武装，拆除判定交消费方）。
/// 零堆零 unsafe，`Copy` 语义面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistTimer {
    /// 到期时刻（纳秒；u64::MAX = 未武装）。
    deadline: u64,
    /// 武装基 RTO（臂时定格——退避基域）。
    base_rto: u64,
    /// 本臂探测计数（退避指数域——独立账面）。
    retries: u32,
}

impl PersistTimer {
    /// 空闲定时器（未武装）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deadline: u64::MAX,
            base_rto: RTO_INIT_NS,
            retries: 0,
        }
    }

    /// 是否武装中。
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.deadline != u64::MAX
    }

    /// 本臂探测计数。
    #[must_use]
    pub const fn retries(&self) -> u32 {
        self.retries
    }

    /// 武装（幂等：已武装不重置——零窗期单臂域，重入零动作；首臂
    /// deadline = now + `rto_ns`（下限 1 夹逼），退避推进由
    /// [`PersistTimer::poll`] 内部承担）。
    pub fn arm(&mut self, now_ns: u64, rto_ns: u64) {
        if self.is_armed() {
            return;
        }
        self.base_rto = rto_ns.max(1);
        self.deadline = now_ns.saturating_add(self.base_rto);
        self.retries = 0;
    }

    /// 对端窗重开解除：武装态 → 解除 + 计数复位（true）；未武装幂等
    /// 零动作（false——消费方证据面）。
    pub fn release(&mut self) -> bool {
        if !self.is_armed() {
            return false;
        }
        self.deadline = u64::MAX;
        self.retries = 0;
        true
    }

    /// 到期拍：Idle（未武装/未到期）→ Probe（探测拍；`retries` 推进 +
    /// `rto << retries` 封顶 [`RTO_MAX_NS`] 再臂）→ Broken（第
    /// [`PERSIST_MAX_PROBES`]+1 拍到期——解除武装交消费方拆除，
    /// fail-visible）。
    pub fn poll(&mut self, now_ns: u64) -> PersistDecision {
        if !self.is_armed() || now_ns < self.deadline {
            return PersistDecision::Idle;
        }
        if self.retries >= PERSIST_MAX_PROBES {
            self.deadline = u64::MAX;
            return PersistDecision::Broken;
        }
        self.retries += 1;
        // 退避：rto << retries，指数域夹逼（1 << 24 移位界）+ 封顶
        // RTO_MAX_NS（饱和乘法域——不回绕不翻转）
        let backoff = self
            .base_rto
            .saturating_mul(1u64 << self.retries.min(24))
            .min(RTO_MAX_NS);
        self.deadline = now_ns.saturating_add(backoff);
        PersistDecision::Probe
    }
}

impl Default for PersistTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ---- 面 5：ConnTable<N, C>（定容四元组连接表） ------------------------------

/// 连接槽重组窗容量（同 kernel vnet [`TCP_SEG_MAX`] 口径——PU-P06 预算
/// 内固定布局：单槽 ≈ 1.1 KiB，8 槽表 ≈ 9 KiB 量级）。
pub const TCP_CONN_REASM_CAP: usize = 512;

/// TCP 四元组键（查表域——(源 IP, 源端口, 目的 IP, 目的端口)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKey {
    /// 源 IP（四段）。
    pub src_ip: [u8; 4],
    /// 源端口。
    pub src_port: u16,
    /// 目的 IP（四段）。
    pub dst_ip: [u8; 4],
    /// 目的端口。
    pub dst_port: u16,
}

/// 连接槽体（服务化批次聚合账面——状态/重传/估计/拥塞/持久/滑窗/重组
/// 七域全置；零堆零 unsafe，`Copy` 语义面嵌核账面定式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    /// 连接状态（八态机）。
    pub state: ConnState,
    /// RTO 重传定时器。
    pub rto: RtoTimer,
    /// RTT 估计器（RFC 6298 整数式——Karn 窄化域）。
    pub rttest: RttEst,
    /// 拥塞控制账面（RFC 5681 简化域三态）。
    pub cwnd: CcState,
    /// 零窗探测定时器（独立拍数域）。
    pub persist: PersistTimer,
    /// 发送滑窗（16 位通告域——缩放有效窗解释面在消费方）。
    pub swnd: SendWindow,
    /// 接收乱序重组窗（定容 [`TCP_CONN_REASM_CAP`]）。
    pub reasm: ReasmBuf<TCP_CONN_REASM_CAP>,
}

impl TcpConn {
    /// 建槽：重组基线 = 对端 ISN + 1（SYN 消耗 1 序号——RFC 9293
    /// §3.3.1），发送窗自本端 ISN 起。
    #[must_use]
    pub const fn new(state: ConnState, isn: u32, peer_isn: u32, peer_win: u16, smss: u32) -> Self {
        Self {
            state,
            rto: RtoTimer::new(),
            rttest: RttEst::new(),
            cwnd: CcState::new(smss),
            persist: PersistTimer::new(),
            swnd: SendWindow::new(isn, peer_win),
            reasm: ReasmBuf::new(peer_isn.wrapping_add(1)),
        }
    }
}

/// 连接表错误（fail-visible 三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnTableError {
    /// 四元组已占用（重复键拒）。
    Duplicate,
    /// 定容槽满（耗尽 fail-visible——PU-P06 预算面，无无界增长）。
    Exhausted,
    /// 键/槽位不存在。
    NotFound,
}

/// 表项（键 + 槽体——`Option<ConnEntry<C>>` 直存定容数组）。
#[derive(Debug, Clone, Copy)]
struct ConnEntry<C: Copy> {
    key: TcpKey,
    conn: C,
}

/// 定容 N 槽四元组查找表（零堆零 unsafe——`[Option<ConnEntry<C>>; N]`
/// 直存 .bss 定容，线性扫描域；PU-P06 预算内固定布局）。
///
/// 语义：`alloc` 重复键拒 + 槽满拒 + 首个空槽低址优先（`close` 释放
/// 复用自然回收——释放槽即下轮 `alloc` 落点）；`lookup`/`slot` 双访问
/// 面（键查 + 槽位直驱）；`close` 槽释放并归还槽体（证据面）。全
/// fail-visible（[`ConnTableError`] 三态）。
pub struct ConnTable<const N: usize, C: Copy> {
    /// 定容槽阵（None = 空）。
    slots: [Option<ConnEntry<C>>; N],
    /// 在册连接数（占用账——O(1) 读出）。
    live: usize,
}

impl<const N: usize, C: Copy> ConnTable<N, C> {
    /// 空表（定容 N 槽全空——const 面供 static 初始化）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            live: 0,
        }
    }

    /// 在册连接数。
    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    /// 槽位键读出（None = 空槽/越界）。
    #[must_use]
    pub fn key_at(&self, idx: usize) -> Option<&TcpKey> {
        self.slots.get(idx)?.as_ref().map(|e| &e.key)
    }

    /// 键查找（`&C` 只读面）。
    #[must_use]
    pub fn lookup(&self, key: &TcpKey) -> Option<&C> {
        self.slots
            .iter()
            .find(|s| s.as_ref().is_some_and(|e| e.key == *key))?
            .as_ref()
            .map(|e| &e.conn)
    }

    /// 键查找（`&mut C` 驱动面）。
    pub fn lookup_mut(&mut self, key: &TcpKey) -> Option<&mut C> {
        self.slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|e| e.key == *key))?
            .as_mut()
            .map(|e| &mut e.conn)
    }

    /// 槽位直读（tick 驱动域证据面）。
    #[must_use]
    pub fn slot(&self, idx: usize) -> Option<&C> {
        self.slots.get(idx)?.as_ref().map(|e| &e.conn)
    }

    /// 槽位直写（tick 驱动域）。
    pub fn slot_mut(&mut self, idx: usize) -> Option<&mut C> {
        self.slots.get_mut(idx)?.as_mut().map(|e| &mut e.conn)
    }

    /// 分配：重复键拒（[`ConnTableError::Duplicate`]——四元组唯一性）
    /// → 槽满拒（[`ConnTableError::Exhausted`]）→ 首个空槽低址优先
    /// 写入，返回槽位号。释放复用：`close` 腾出的低址槽即下轮落点。
    pub fn alloc(&mut self, key: TcpKey, conn: C) -> Result<usize, ConnTableError> {
        if self.lookup(&key).is_some() {
            return Err(ConnTableError::Duplicate);
        }
        let Some(idx) = (0..N).find(|&i| self.slots[i].is_none()) else {
            return Err(ConnTableError::Exhausted);
        };
        self.slots[idx] = Some(ConnEntry { key, conn });
        self.live += 1;
        Ok(idx)
    }

    /// 槽位关闭：释放槽（复用域）并归还槽体；空槽/越界 →
    /// [`ConnTableError::NotFound`]。
    pub fn close(&mut self, idx: usize) -> Result<C, ConnTableError> {
        let slot = self.slots.get_mut(idx).ok_or(ConnTableError::NotFound)?;
        let entry = slot.take().ok_or(ConnTableError::NotFound)?;
        self.live -= 1;
        Ok(entry.conn)
    }

    /// 四元组关闭：键查（[`ConnTableError::NotFound`] fail-visible）→
    /// 释放复用同 [`ConnTable::close`]。
    pub fn close_key(&mut self, key: &TcpKey) -> Result<C, ConnTableError> {
        let idx = (0..N).find(|&i| self.slots[i].as_ref().is_some_and(|e| e.key == *key));
        match idx {
            Some(i) => self.close(i),
            None => Err(ConnTableError::NotFound),
        }
    }
}

impl<const N: usize, C: Copy> Default for ConnTable<N, C> {
    fn default() -> Self {
        Self::new()
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

    // ---- M38-TCP1：服务化批次五面（WS / RTT / 拥塞 / 持久 / 连接表） ----

    /// WS 往返：kind=3 编解码往返 + 选项区 TLV 扫描（NOP 前垫 / EOL 后
    /// 填）+ 畸形四态拒（len 越界 / 定长破 / 越域 shift / 未见）。
    #[test]
    fn ws_option_roundtrip() {
        use super::{ws_decode, ws_encode, WS_KIND, WS_OPT_LEN, WS_SHIFT_MAX};
        let mut buf = [0u8; 4];
        assert_eq!(ws_encode(2, &mut buf), Some(3));
        assert_eq!(&buf[..3], &[WS_KIND, WS_OPT_LEN, 2]);
        assert_eq!(ws_decode(&buf[..3]), Some(2), "裸选项往返");
        // NOP 前垫 + EOL 后填（真实 SYN 选项区布局）
        let padded = [0x01, WS_KIND, WS_OPT_LEN, 2, 0x00, 0x00];
        assert_eq!(ws_decode(&padded), Some(2), "NOP/EOL 域内命中");
        // 容量不足拒 + 越域 shift 拒
        assert_eq!(ws_encode(2, &mut [0u8; 2]), None, "容量闸");
        assert_eq!(ws_encode(WS_SHIFT_MAX + 1, &mut buf), None, "shift 越域闸");
        // 畸形：len 越缓冲 / WS 定长破 / 越域 shift / 未见 WS
        assert_eq!(ws_decode(&[WS_KIND, 8, 2]), None, "len 越缓冲");
        assert_eq!(ws_decode(&[WS_KIND, 2, 2]), None, "WS 定长破");
        assert_eq!(
            ws_decode(&[WS_KIND, WS_OPT_LEN, WS_SHIFT_MAX + 1]),
            None,
            "shift 越域"
        );
        assert_eq!(ws_decode(&[0x01, 0x00]), None, "未见 WS");
    }

    /// WS 协商：双方 SYN 才生效（对端通告移位为生效值）+ 缺省移位 0
    /// 六目（缺本端 SYN / 缺对端 SYN / 缺选项 / 本端越域 / 对端越域 /
    /// 全缺）。
    #[test]
    fn ws_negotiation_both_syn() {
        use super::ws_negotiate;
        assert_eq!(
            ws_negotiate(true, 2, true, Some(3)),
            3,
            "双 SYN 生效——对端通告移位"
        );
        assert_eq!(ws_negotiate(true, 2, true, Some(0)), 0, "对端显式 0 生效域");
        assert_eq!(ws_negotiate(true, 2, true, Some(14)), 14, "上限域");
        assert_eq!(ws_negotiate(false, 2, true, Some(3)), 0, "缺本端 SYN → 0");
        assert_eq!(ws_negotiate(true, 2, false, Some(3)), 0, "缺对端 SYN → 0");
        assert_eq!(ws_negotiate(true, 2, true, None), 0, "对端缺选项 → 0");
        assert_eq!(
            ws_negotiate(true, 15, true, Some(3)),
            0,
            "本端越域 → 协商不成"
        );
        assert_eq!(ws_negotiate(true, 2, true, Some(15)), 0, "对端越域 → 0");
    }

    /// WS 移位：有效窗 wire << shift 封顶算术 + 未缩放回归锚（旧
    /// encode 路径窗域原样直写——M37-N1 语义逐位保持）。
    #[test]
    fn ws_effective_window_cap() {
        use super::{ws_effective_window, TcpHdr, FLAG_ACK, FLAG_PSH, HDR_LEN};
        assert_eq!(ws_effective_window(16384, 2), 65_536, "wire << 2");
        assert_eq!(
            ws_effective_window(65535, 14),
            1_073_725_440,
            "上限域 2³⁰−2¹⁴ 界内"
        );
        assert_eq!(ws_effective_window(8192, 0), 8192, "移位 0 = 未缩放直通");
        // 未缩放回归锚：旧 encode 路径 data_offset=5 + 窗域原样（无选项域）
        let mut seg = [0u8; HDR_LEN];
        TcpHdr::encode(1000, 2000, 0, 0, FLAG_ACK | FLAG_PSH, 8192, &[], &mut seg).expect("encode");
        assert_eq!(seg[12], 0x50, "旧路径 offset=5 逐位保持");
        assert_eq!(u16::from_be_bytes([seg[14], seg[15]]), 8192, "窗域原样直写");
    }

    /// RTT 首样（RFC 6298 §2.2 整数式）：srtt=r, rttvar=r/2 + 首样
    /// 唯一性（重入拒）+ 退化样拒。
    #[test]
    fn rtt_first_sample() {
        use super::RttEst;
        let mut e = RttEst::new();
        assert!(!e.primed());
        assert!(
            !e.sample(1000, false),
            "未 primed 滑动拒（首样须走 first_sample）"
        );
        assert!(e.first_sample(10_000), "首样受理");
        assert_eq!(e.srtt(), 10_000);
        assert_eq!(e.rttvar(), 5_000, "rttvar = r/2");
        assert!(e.primed());
        assert!(!e.first_sample(4_000), "首样重入拒（滑动域唯一入口）");
        assert_eq!(e.srtt(), 10_000, "重入零扰动");
        assert!(!e.first_sample(0), "退化样拒");
    }

    /// RTT 滑动（RFC 6298 §2.3 整数式 RTTVAR 先行序）：Δ=|旧 srtt−r|
    /// → var=(3v+Δ)/8 → srtt=(7s+r)/8，两次样手算锚逐位对账。
    #[test]
    fn rtt_sliding_update() {
        use super::RttEst;
        let mut e = RttEst::new();
        assert!(e.first_sample(800), "首样受理");
        // 样 2：r=400 → Δ=|800−400|=400；var=(3·400+400)/8=200；srtt=(7·800+400)/8=750
        assert!(e.sample(400, false));
        assert_eq!(e.srtt(), 750, "(7s+r)/8 整数除");
        assert_eq!(e.rttvar(), 200, "(3v+Δ)/8 RTTVAR 先行序");
        // 样 3：r=900 → Δ=|750−900|=150；var=(3·200+150)/8=93；srtt=(7·750+900)/8=768
        assert!(e.sample(900, false));
        assert_eq!(e.srtt(), 768);
        assert_eq!(e.rttvar(), 93, "整数下取整域");
    }

    /// RTT Karn 窄化：重传段样本不采（from_retx 旗——账面零扰动）+
    /// 清样对照（同值非重传样正常入账）。
    #[test]
    fn rtt_karn_narrowing() {
        use super::RttEst;
        let mut e = RttEst::new();
        assert!(e.first_sample(10_000), "首样受理");
        let (s0, v0) = (e.srtt(), e.rttvar());
        assert!(!e.sample(4_000, true), "Karn：重传样窄化不采");
        assert_eq!(e.srtt(), s0, "窄化域 srtt 零扰动");
        assert_eq!(e.rttvar(), v0, "窄化域 rttvar 零扰动");
        assert!(e.sample(4_000, false), "同值非重传样正常入账（对照域）");
        assert_eq!(e.srtt(), (7 * 10_000 + 4_000) / 8, "滑动账随行");
        assert_eq!(e.rttvar(), (3 * 5_000 + 6_000) / 8);
    }

    /// RTT 夹逼：RTO 导出 = srtt + 4·rttvar 夹逼域 [RTO_INIT_NS,
    /// RTO_MAX_NS] 双向 + rttvar 下限夹逼（(3v+Δ)/8 向零塌缩禁令）。
    #[test]
    fn rtt_clamp_bounds() {
        use super::{RttEst, RTO_INIT_NS, RTO_MAX_NS, RTTVAR_MIN};
        // 下限域：微样 → 原始导出远低于 RTO_INIT_NS → 夹逼下限
        let mut lo = RttEst::new();
        assert!(lo.first_sample(4), "首样受理"); // srtt=4, var=2 → raw=12
        assert_eq!(lo.srtt(), 4);
        assert_eq!(lo.rttvar(), 2);
        assert_eq!(lo.rto(), RTO_INIT_NS, "下限夹逼（回环短臂口径）");
        // 上限域：巨样 → 原始导出远超 RTO_MAX_NS → 夹逼上限
        let mut hi = RttEst::new();
        assert!(hi.first_sample(4_000_000_000), "首样受理"); // raw = 4e9 + 8e9 = 1.2e10
        assert_eq!(hi.rto(), RTO_MAX_NS, "上限夹逼（退避封顶同源）");
        // rttvar 下限夹逼：Δ=0 收敛拍 → (3v+0)/8 向零塌缩 → RTTVAR_MIN 兜底
        let mut z = RttEst::new();
        assert!(z.first_sample(8), "首样受理"); // var=4
        assert!(z.sample(8, false), "Δ=0 收敛样");
        assert_eq!(z.rttvar(), RTTVAR_MIN, "(3·4+0)/8=1 → 下限兜底");
    }

    /// 拥塞三态之一·慢启动（RFC 5681 §3.1）：IW = 2·SMSS 起步 +
    /// cwnd += acked_bytes + 有效无穷阈域 + 发送资格 min 门控。
    #[test]
    fn cc_slow_start() {
        use super::CcState;
        let mut c = CcState::new(100);
        assert_eq!(c.cwnd(), 200, "IW = 2·SMSS");
        assert_eq!(c.ssthresh(), u32::MAX, "初态有效无穷（慢启动直达）");
        assert_eq!(c.smss(), 100);
        c.on_ack(100);
        assert_eq!(c.cwnd(), 300, "慢启动 += acked_bytes");
        c.on_ack(150);
        assert_eq!(c.cwnd(), 450);
        // 发送资格：min(可用窗, cwnd) 双向门控
        assert_eq!(c.send_credit(1_000), 450, "窗域大于 cwnd → cwnd 主导");
        assert_eq!(c.send_credit(120), 120, "窗域小于 cwnd → 窗主导");
    }

    /// 拥塞三态之二·拥塞避免（越 ssthresh 转 SMSS²/cwnd）：RTO 定标
    /// 后越阈转换 + 整数除下限 1 单调域。
    #[test]
    fn cc_congestion_avoidance() {
        use super::CcState;
        let mut c = CcState::new(64); // IW=128
        c.on_rto(512); // ssthresh = max(256, 128) = 256, cwnd 回 128
        assert_eq!(c.ssthresh(), 256);
        assert_eq!(c.cwnd(), 128);
        c.on_ack(128); // 慢启动尾拍：128 < 256 → += 128 → 256
        assert_eq!(c.cwnd(), 256, "慢启动顶满阈域");
        c.on_ack(0); // 256 ≥ 256 → 拥塞避免：4096/256 = 16
        assert_eq!(c.cwnd(), 272, "SMSS²/cwnd = 16");
        c.on_ack(0); // 4096/272 = 15
        assert_eq!(c.cwnd(), 287, "整数除随行");
        c.on_ack(0); // 4096/287 = 14
        assert_eq!(c.cwnd(), 301);
        // 下限 1 域：cwnd 越过 SMSS² → inc 兜底 1（单调不凝滞）
        // smss=4 → IW=8；on_rto(8) → ssthresh=max(4,8)=8、cwnd=8
        //（== 阈域即转 CA——RFC 5681 cwnd ≥ ssthresh 口径）
        let mut big = CcState::new(4);
        big.on_rto(8);
        assert_eq!(big.ssthresh(), 8);
        assert_eq!(big.cwnd(), 8);
        big.on_ack(8); // CA：16/8 = 2
        assert_eq!(big.cwnd(), 10, "== 阈域即转 CA：16/8 = 2");
        big.on_ack(0); // CA：16/10 = 1（整数除）
        assert_eq!(big.cwnd(), 11);
        big.on_ack(0); // CA：16/11 = 1 → 兜底 1 域
        assert_eq!(big.cwnd(), 12, "SMSS²/cwnd 兜底 1（单调不凝滞）");
    }

    /// 拥塞三态之三·RTO 折叠回升（§3.1 原初域）：ssthresh =
    /// max(flight/2, 2·SMSS) 下限闸 + cwnd 回初值 + 折叠后回升弧
    /// （慢启动 → 越阈 → 拥塞避免）。
    #[test]
    fn cc_rto_collapse_recovery() {
        use super::CcState;
        let mut c = CcState::new(100); // IW=200
                                       // 折叠前爬升（慢启动域）
        c.on_ack(300);
        assert_eq!(c.cwnd(), 500);
        // RTO 折叠：flight=800 → ssthresh = max(400, 200) = 400，cwnd 回 200
        c.on_rto(800);
        assert_eq!(c.ssthresh(), 400);
        assert_eq!(c.cwnd(), 200, "回初值 IW");
        // 回升弧：慢启动 200→300→400（越阈前 SS 域），随后 CA
        c.on_ack(100);
        c.on_ack(100);
        assert_eq!(c.cwnd(), 400, "慢启动回升至阈域（== 边界）");
        c.on_ack(0); // CA：10_000/400 = 25
        assert_eq!(c.cwnd(), 425, "越阈转拥塞避免");
        c.on_ack(0); // 10_000/425 = 23
        assert_eq!(c.cwnd(), 448);
        // 深折叠域：2·SMSS 下限闸 + == 阈域即转 CA（RFC 5681 ≥ 口径）
        c.on_rto(100);
        assert_eq!(c.ssthresh(), 200, "2·SMSS 下限闸");
        assert_eq!(c.cwnd(), 200);
        c.on_ack(100); // CA：10_000/200 = 50（== 阈域不再走 SS）
        assert_eq!(c.cwnd(), 250, "== 阈域即转 CA 域随行取证");
        // 发送资格门控随行（折叠深谷域资格被 cwnd 压制）
        assert_eq!(c.send_credit(10_000), 250);
        assert_eq!(c.send_credit(64), 64);
    }

    /// 持久四态之一·零窗臂幂等武装 + 窗重开解除：arm 幂等（重入不换
    /// 基）→ release 解除 + 未武装幂等 false → 解除后 poll 恒 Idle。
    #[test]
    fn persist_arm_release() {
        use super::{PersistDecision, PersistTimer};
        let t0 = 1_000_000;
        let mut p = PersistTimer::new();
        assert!(!p.is_armed());
        p.arm(t0, 1000);
        assert!(p.is_armed() && p.retries() == 0);
        p.arm(t0 + 500, 999_999); // 幂等：已武装不重置不换基
        assert_eq!(
            p.poll(t0 + 999),
            PersistDecision::Idle,
            "臂时基定格（原基 1000）"
        );
        assert_eq!(
            p.poll(t0 + 1000),
            PersistDecision::Probe,
            "原基到期（非重入基）"
        );
        // 窗重开解除 + 幂等域
        assert!(p.release());
        assert!(!p.is_armed() && p.retries() == 0, "解除复位");
        assert!(!p.release(), "未武装幂等 false（证据面）");
        assert_eq!(p.poll(t0 + 9_999), PersistDecision::Idle, "解除后恒 Idle");
    }

    /// 持久四态之二·到期探测拍退避封顶：Probe 拍退避 rto << retries
    /// 逐拍对账 + 大基 RTO 封顶 RTO_MAX_NS + 探测段 1 字节常量域。
    #[test]
    fn persist_probe_backoff() {
        use super::{PersistDecision, PersistTimer, PROBE_SEG_LEN, RTO_MAX_NS};
        assert_eq!(PROBE_SEG_LEN, 1, "探测段 = una 起 1 字节");
        let t0 = 0;
        let mut p = PersistTimer::new();
        p.arm(t0, 1000);
        assert_eq!(p.poll(t0 + 999), PersistDecision::Idle, "差一拍不早醒");
        assert_eq!(p.poll(t0 + 1000), PersistDecision::Probe, "首探测拍");
        assert_eq!(p.retries(), 1);
        assert_eq!(
            p.poll(t0 + 1000 + 2000 - 1),
            PersistDecision::Idle,
            "退避 2× 前不醒"
        );
        assert_eq!(
            p.poll(t0 + 3000),
            PersistDecision::Probe,
            "二探测拍（rto<<1 再臂）"
        );
        assert_eq!(p.retries(), 2);
        assert_eq!(
            p.poll(t0 + 3000 + 4000),
            PersistDecision::Probe,
            "三探测拍（rto<<2）"
        );
        assert_eq!(p.retries(), 3);
        // 大基 RTO 封顶域：base = RTO_MAX_NS → 退避 << 不超 RTO_MAX_NS
        let mut cap = PersistTimer::new();
        cap.arm(t0, RTO_MAX_NS);
        assert_eq!(cap.poll(t0 + RTO_MAX_NS), PersistDecision::Probe);
        assert_eq!(
            cap.poll(t0 + RTO_MAX_NS + RTO_MAX_NS),
            PersistDecision::Probe,
            "退避封顶 RTO_MAX_NS（<<1 饱和截断）"
        );
    }

    /// 持久四态之三·独立拍数上限 Broken fail-visible：PERSIST_MAX_PROBES
    /// 拍 Probe 全谱 → 下一到期 Broken + 解除武装（拆除判定交消费方）。
    #[test]
    fn persist_broken_fail_visible() {
        use super::{PersistDecision, PersistTimer, PERSIST_MAX_PROBES};
        let mut p = PersistTimer::new();
        p.arm(0, 1000);
        let mut now = 1000u64;
        for i in 1..=PERSIST_MAX_PROBES {
            assert_eq!(p.poll(now), PersistDecision::Probe, "第 {i} 探测拍");
            now += 1000 << i; // 退避 rto << retries（基 1000）
        }
        assert_eq!(p.retries(), PERSIST_MAX_PROBES);
        assert_eq!(p.poll(now), PersistDecision::Broken, "上限耗尽显形");
        assert!(!p.is_armed(), "解除武装（fail-visible）");
        assert_eq!(p.poll(now), PersistDecision::Idle);
    }

    /// 连接表之一·alloc/lookup/close 基础谱：分配落位 + 键查双访问面
    /// + 槽位直驱 + 关闭归还槽体 + 关闭后键失（fail-visible）。
    #[test]
    fn conntable_alloc_lookup_close() {
        use super::{ConnState, ConnTable, ConnTableError, TcpConn, TcpKey};
        let k0 = TcpKey {
            src_ip: [10, 0, 2, 15],
            src_port: 42000,
            dst_ip: [10, 0, 2, 2],
            dst_port: 80,
        };
        let k1 = TcpKey {
            src_ip: [10, 0, 2, 15],
            src_port: 42002,
            dst_ip: [10, 0, 2, 2],
            dst_port: 443,
        };
        let mut t: ConnTable<8, TcpConn> = ConnTable::new();
        assert_eq!(t.live(), 0);
        assert_eq!(
            t.alloc(
                k0,
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Ok(0)
        );
        assert_eq!(
            t.alloc(k1, TcpConn::new(ConnState::SynSent, 3000, 4000, 512, 536)),
            Ok(1)
        );
        assert_eq!(t.live(), 2);
        // 键查双访问面
        assert_eq!(t.lookup(&k0).map(|c| c.state), Some(ConnState::Established));
        if let Some(c) = t.lookup_mut(&k1) {
            c.state = ConnState::Established;
        }
        assert_eq!(
            t.lookup(&k1).map(|c| c.state),
            Some(ConnState::Established),
            "mut 面驱动随行"
        );
        // 槽位直驱 + 槽体六面聚合账（reasm 基线 = 对端 ISN+1）
        assert_eq!(t.key_at(0), Some(&k0));
        assert_eq!(t.slot(0).map(|c| c.reasm.rcv_nxt()), Some(2001));
        assert_eq!(t.key_at(8), None, "越界 fail-visible");
        // 关闭归还槽体 + 关闭后键失
        let closed = t.close(0);
        assert_eq!(closed.map(|c| c.state), Ok(ConnState::Established));
        assert_eq!(t.live(), 1);
        assert_eq!(t.lookup(&k0), None, "关闭后键失");
        assert_eq!(t.close(0), Err(ConnTableError::NotFound), "空槽再关拒");
        assert_eq!(t.close(9), Err(ConnTableError::NotFound), "越界拒");
    }

    /// 连接表之二·重复键拒：同四元组二次 alloc 拒（槽体零扰动）+
    /// 不同端口对并存域。
    #[test]
    fn conntable_duplicate_reject() {
        use super::{ConnState, ConnTable, ConnTableError, TcpConn, TcpKey};
        let k = TcpKey {
            src_ip: [10, 0, 2, 15],
            src_port: 42004,
            dst_ip: [10, 0, 2, 2],
            dst_port: 8080,
        };
        let mut t: ConnTable<8, TcpConn> = ConnTable::new();
        assert_eq!(
            t.alloc(
                k,
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Ok(0)
        );
        assert_eq!(t.lookup(&k).map(|c| c.swnd.una()), Some(1000));
        // 重复键：拒 + 原槽零扰动
        assert_eq!(
            t.alloc(k, TcpConn::new(ConnState::SynSent, 9999, 9999, 512, 536)),
            Err(ConnTableError::Duplicate)
        );
        assert_eq!(t.live(), 1, "重复分配不入账");
        assert_eq!(t.lookup(&k).map(|c| c.swnd.una()), Some(1000), "原槽体保持");
        assert_eq!(t.key_at(1), None, "未落新槽");
        // 四元组任一分量不同 = 新键（端口对区分域）
        let k2 = TcpKey {
            src_port: 42005,
            ..k
        };
        assert_eq!(
            t.alloc(
                k2,
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Ok(1)
        );
        assert_eq!(t.live(), 2);
    }

    /// 连接表之三·释放复用：中位槽关闭 → 下轮 alloc 低址落位（复用
    /// 域）+ close_key 键关闭路径随行。
    #[test]
    fn conntable_release_reuse() {
        use super::{ConnState, ConnTable, TcpConn, TcpKey};
        let key = |p: u16| TcpKey {
            src_ip: [10, 0, 2, 15],
            src_port: p,
            dst_ip: [10, 0, 2, 2],
            dst_port: 80,
        };
        let mut t: ConnTable<8, TcpConn> = ConnTable::new();
        for (i, p) in [42010u16, 42011, 42012].iter().enumerate() {
            assert_eq!(
                t.alloc(
                    key(*p),
                    TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
                ),
                Ok(i)
            );
        }
        // 中位槽释放 → 新键低址复用槽 1
        assert!(t.close(1).is_ok());
        let k4 = key(42013);
        assert_eq!(
            t.alloc(
                k4,
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Ok(1),
            "释放槽低址复用"
        );
        // close_key 键关闭路径
        assert!(t.close_key(&k4).is_ok());
        assert_eq!(t.live(), 2);
        assert_eq!(
            t.close_key(&k4),
            Err(super::ConnTableError::NotFound),
            "键失 fail-visible"
        );
    }

    /// 连接表之四·耗尽 fail-visible：8 槽填满 → 第 9 分配 Exhausted →
    /// 释放一槽恢复受理（预算面 fail-visible，无无界增长）。
    #[test]
    fn conntable_exhaustion() {
        use super::{ConnState, ConnTable, ConnTableError, TcpConn, TcpKey};
        let key = |p: u16| TcpKey {
            src_ip: [10, 0, 2, 15],
            src_port: p,
            dst_ip: [10, 0, 2, 2],
            dst_port: 80,
        };
        let mut t: ConnTable<8, TcpConn> = ConnTable::new();
        for i in 0u16..8 {
            assert_eq!(
                t.alloc(
                    key(43000 + i),
                    TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
                ),
                Ok(i as usize),
                "第 {} 槽受理",
                i
            );
        }
        assert_eq!(t.live(), 8);
        assert_eq!(
            t.alloc(
                key(43099),
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Err(ConnTableError::Exhausted),
            "耗尽 fail-visible"
        );
        // 释放一槽 → 恢复受理（复用域闭环）
        assert!(t.close(3).is_ok());
        assert_eq!(
            t.alloc(
                key(43099),
                TcpConn::new(ConnState::Established, 1000, 2000, 512, 536)
            ),
            Ok(3),
            "释放后恢复受理"
        );
    }
}
