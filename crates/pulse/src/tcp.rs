//! TCP 传输控制协议首割（RFC 9293 简化面）。
//!
//! M27-T1 范围界定（偏差登记）：**协议面结构**——段头编解码 + 连接状态机
//! 骨架 + 三次握手序号推进面（宿主对账测试承载）；vnet 电气接线、重传
//! 定时器、滑动窗口流量控制、分片重组属后续批次（挂账）。状态集按
//! ROADMAP M27-T1 清单八态（FIN_WAIT 合并半关闭双态 v0 简化）。
//!
//! 分层定位：pulse 只承载 L4 段面（同 [`crate::udp`]）；校验和伪头核心
//! 与 UDP 共用（proto 6 vs 17 参数化）。

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
}
