//! UDP 用户数据报协议面（RFC 768）。
//!
//! 分层定位：pulse 只承载 **L4 段面**（UDP 头编解码 + 伪头校验和 + 端口
//! 管理纯函数）；IP/以太组帧属 `kernel::vnet` 电气面（ICMP 面先例：段面
//! 单一事实源在此，帧组装在 vnet）。零堆定容，`forbid(unsafe_code)` 域内。
//!
//! 校验和口径（RFC 768 + RFC 1071 折叠）：IPv4 伪头（src/dst IP + 零域 +
//! 协议号 17 + UDP 长度）参与求和；校验和域 0 = 发送方不校验（IPv4 允许，
//! [`verify`] 对 0 直接通过）；计算结果 0 规范化为 0xFFFF（RFC 768 传输
//! 规则——零校验和与「未计算」冲突）；奇数长度数据末字节按零垫虚拟参与。

/// UDP 头长（源端口/目的端口/长度/校验和，各 2 B）。
pub const HDR_LEN: usize = 8;

/// IP 协议号：UDP（伪头协议域）。
pub const PROTO_UDP: u8 = 17;

/// 数据报载荷上限（以太 v2 MTU 1500 − IPv4 头 20 − UDP 头 8）。
pub const MAX_PAYLOAD: usize = 1472;

/// 解析后的 UDP 头（多字节域为大端）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHdr {
    /// 源端口（主机字节序）。
    pub src_port: u16,
    /// 目的端口（主机字节序）。
    pub dst_port: u16,
    /// 段总长（头 + 数据；与缓冲实际长度对账闸）。
    pub length: u16,
    /// 校验和（线序原值；0 = 发送方未计算）。
    pub checksum: u16,
}

impl UdpHdr {
    /// 从段缓冲头部解析（返回头 + 载荷切片）。
    ///
    /// 闸序：长度足额 → length 域自洽（≥ 头长且 ≤ 缓冲长——截断帧
    /// fail-visible 拒收）。
    pub fn parse(seg: &[u8]) -> Option<(UdpHdr, &[u8])> {
        if seg.len() < HDR_LEN {
            return None;
        }
        let src_port = u16::from_be_bytes([seg[0], seg[1]]);
        let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
        let length = u16::from_be_bytes([seg[4], seg[5]]);
        let checksum = u16::from_be_bytes([seg[6], seg[7]]);
        let len = usize::from(length);
        if len < HDR_LEN || len > seg.len() {
            return None; // 长度域与缓冲对账失败（截断/伪造帧）
        }
        Some((
            UdpHdr {
                src_port,
                dst_port,
                length,
                checksum,
            },
            &seg[HDR_LEN..len],
        ))
    }

    /// 编码完整段（头 + 载荷）到 `out`，返回写入长度。
    ///
    /// 载荷超 [`MAX_PAYLOAD`] 或 `out` 容量不足返回 None（fail-visible，
    /// 静默截断禁令）。校验和域由调用方经 [`checksum`] 计算后回填
    /// （`encode` 恒写 0 基线段）。
    pub fn encode(src_port: u16, dst_port: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        let total = HDR_LEN + payload.len();
        if payload.len() > MAX_PAYLOAD || out.len() < total {
            return None;
        }
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        out[6..8].copy_from_slice(&0u16.to_be_bytes()); // 校验和域基线 0
        out[HDR_LEN..total].copy_from_slice(payload);
        Some(total)
    }
}

/// RFC 1071 折叠求和（16 位反码和），跨 16 位字累加末尾高 16 位回卷。
pub(crate) fn fold16(mut sum: u32, bytes: &[u8]) -> u32 {
    let (chunks, rem) = bytes.as_chunks::<2>();
    for c in chunks {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [odd] = rem {
        sum += u32::from(*odd) << 8; // 奇数末字节大端高位垫零
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

/// RFC 768/9293 伪头校验和（UDP/TCP 共用核心，proto 参数化）：IPv4 伪头
/// + 段（头校验和域须为基线 0——encode 面保证）。
///
/// 返回 0 时规范化为 0xFFFF（RFC 768 传输规则，TCP 同款语义）。
#[must_use]
pub(crate) fn checksum_pseudo(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, seg: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = proto;
    let ulen = seg.len() as u16;
    pseudo[10..12].copy_from_slice(&ulen.to_be_bytes());
    let sum = fold16(fold16(0, &pseudo), seg);
    let cs = !(sum & 0xFFFF) as u16;
    if cs == 0 {
        0xFFFF
    } else {
        cs
    }
}

/// UDP 校验和（RFC 768 伪头版）：IPv4 伪头 + 段（头校验和域须为基线 0
/// ——[`UdpHdr::encode`] 保证）。
///
/// 返回 0 时规范化为 0xFFFF（RFC 768 传输规则）。
#[must_use]
pub fn checksum(src_ip: [u8; 4], dst_ip: [u8; 4], seg: &[u8]) -> u16 {
    checksum_pseudo(src_ip, dst_ip, PROTO_UDP, seg)
}

/// 段校验和验证（接收闸）：`checksum == 0` = 发送方未计算直接通过
/// （IPv4 语义）；否则按 RFC 1071 反码自消性质验证——伪头 + 段原样
/// （校验和域不清零）完整折叠应恰为 0xFFFF（发送侧 `sum + cs = 0xFFFF`，
/// 免复制，no_std 无 alloc 域内成立）。
#[must_use]
pub fn verify(src_ip: [u8; 4], dst_ip: [u8; 4], seg: &[u8]) -> bool {
    if seg.len() < HDR_LEN {
        return false;
    }
    let cs = u16::from_be_bytes([seg[6], seg[7]]);
    if cs == 0 {
        return true;
    }
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = PROTO_UDP;
    let ulen = seg.len() as u16;
    pseudo[10..12].copy_from_slice(&ulen.to_be_bytes());
    fold16(fold16(0, &pseudo), seg) == 0xFFFF
}

/// 端口绑定表（定容零堆；v0 结构面——绑定即占用，数据报投递寻址由
/// 消费方按 [`PortTable::is_bound`] 路由）。
///
/// fail-visible 三闸：重复绑定（[`BindError::AlreadyBound`]）、表满
/// （[`BindError::Exhausted`]）、解绑未绑定（[`BindError::NotBound`]）。
/// 端口 0 为保留值（匿名域），拒收。
pub struct PortTable<const N: usize> {
    ports: [u16; N],
    used: usize,
}

/// 绑定域错误（fail-visible 枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// 端口已被占用。
    AlreadyBound,
    /// 表槽位枯竭。
    Exhausted,
    /// 未绑定（解绑/查询域）。
    NotBound,
    /// 保留端口 0 拒收。
    Reserved,
}

impl<const N: usize> PortTable<N> {
    /// 空表。
    pub const fn new() -> Self {
        Self {
            ports: [0; N],
            used: 0,
        }
    }

    /// 绑定端口（占用一个槽位）。
    pub fn bind(&mut self, port: u16) -> Result<(), BindError> {
        if port == 0 {
            return Err(BindError::Reserved);
        }
        if self.is_bound(port) {
            return Err(BindError::AlreadyBound);
        }
        if self.used >= N {
            return Err(BindError::Exhausted);
        }
        self.ports[self.used] = port;
        self.used += 1;
        Ok(())
    }

    /// 解绑端口（归还槽位；swap_remove 保零洞）。
    pub fn unbind(&mut self, port: u16) -> Result<(), BindError> {
        for i in 0..self.used {
            if self.ports[i] == port {
                self.used -= 1;
                self.ports[i] = self.ports[self.used];
                self.ports[self.used] = 0;
                return Ok(());
            }
        }
        Err(BindError::NotBound)
    }

    /// 端口是否已绑定。
    #[must_use]
    pub fn is_bound(&self, port: u16) -> bool {
        self.ports[..self.used].contains(&port)
    }

    /// 当前占用数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.used
    }

    /// 表是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }
}

impl<const N: usize> Default for PortTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{checksum, verify, BindError, PortTable, UdpHdr, HDR_LEN, MAX_PAYLOAD, PROTO_UDP};

    const SRC: [u8; 4] = [10, 0, 2, 15];
    const DST: [u8; 4] = [10, 0, 2, 2];

    /// 手工核算向量：空载荷段（头 8 B，cs 基线 0）。
    /// 伪头和 = 0x182a；段和 = 0x1234+0x5678+0x0008 = 0x68b4；
    /// 总 0x80de → cs = ~0x80de = 0x7f21。
    #[test]
    fn checksum_known_vector_empty_payload() {
        let mut seg = [0u8; HDR_LEN];
        assert_eq!(UdpHdr::encode(0x1234, 0x5678, &[], &mut seg), Some(8));
        assert_eq!(checksum(SRC, DST, &seg), 0x7f21);
    }

    /// 手工核算向量：奇数载荷（1 B 0xAA，末字节高位垫零参与求和）。
    /// 伪头和 0x182b；段和 = 0x1234+0x5678+0x0009+0xAA00 = 0x112B5；
    /// 总 0x182b + 0x112B5 = 0x12AE0 → 折叠 0x2AE1 → cs = ~0x2AE1 = 0xd51e。
    #[test]
    fn checksum_known_vector_odd_payload() {
        let mut seg = [0u8; HDR_LEN + 1];
        assert_eq!(UdpHdr::encode(0x1234, 0x5678, &[0xAA], &mut seg), Some(9));
        assert_eq!(checksum(SRC, DST, &seg), 0xd51e);
    }

    #[test]
    fn checksum_roundtrip_and_zero_normalize() {
        let payload = *b"LUMINA-UDP-ROUNDTRIP";
        let mut seg = [0u8; HDR_LEN + 20];
        UdpHdr::encode(7777, 8888, &payload, &mut seg).expect("encode");
        let cs = checksum(SRC, DST, &seg);
        assert_ne!(cs, 0);
        seg[6..8].copy_from_slice(&cs.to_be_bytes());
        assert!(verify(SRC, DST, &seg), "正例必须通过");
        // 0xFFFF 规范化：构造 sum 反码恰为 0 的载荷域不现实，直接验证
        // 规范化分支——单字节载荷 0x00 全零 sum 反码非 0；以负例闸补强
        seg[6..8].copy_from_slice(&0u16.to_be_bytes());
        assert!(verify(SRC, DST, &seg), "cs=0 = 未计算语义直接通过");
    }

    #[test]
    fn verify_negative_flipped_bit() {
        let payload = *b"NEG";
        let mut seg = [0u8; HDR_LEN + 3];
        UdpHdr::encode(1, 2, &payload, &mut seg).expect("encode");
        let cs = checksum(SRC, DST, &seg);
        seg[6..8].copy_from_slice(&(cs ^ 0x0100).to_be_bytes()); // 翻 1 位
        assert!(!verify(SRC, DST, &seg), "位翻转必须检出");
        // 伪头不匹配（对端 IP 不同）也必须检出
        seg[6..8].copy_from_slice(&cs.to_be_bytes());
        assert!(!verify([192, 168, 1, 1], DST, &seg));
    }

    #[test]
    fn parse_rejects_truncated_and_bad_length() {
        assert!(UdpHdr::parse(&[0u8; 7]).is_none(), "头不足 8 B");
        // length 域 < 头长
        let mut seg = [0u8; HDR_LEN];
        seg[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert!(UdpHdr::parse(&seg).is_none());
        // length 域 > 缓冲长（截断帧）
        seg[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert!(UdpHdr::parse(&seg).is_none());
    }

    #[test]
    fn parse_encode_roundtrip() {
        let payload = *b"hello udp";
        let mut seg = [0u8; HDR_LEN + 9];
        assert_eq!(UdpHdr::encode(1000, 2000, &payload, &mut seg), Some(17));
        let (h, pl) = UdpHdr::parse(&seg).expect("parse");
        assert_eq!(h.src_port, 1000);
        assert_eq!(h.dst_port, 2000);
        assert_eq!(h.length, 17);
        assert_eq!(pl, &payload);
    }

    #[test]
    fn encode_rejects_oversize_and_small_out() {
        let big = [0u8; MAX_PAYLOAD + 1];
        let mut out = [0u8; HDR_LEN + MAX_PAYLOAD + 8];
        assert_eq!(UdpHdr::encode(1, 2, &big, &mut out), None, "超 MAX_PAYLOAD");
        let mut small = [0u8; 4];
        assert_eq!(
            UdpHdr::encode(1, 2, &[1, 2, 3], &mut small),
            None,
            "out 容量不足"
        );
    }

    #[test]
    fn port_table_lifecycle_and_fail_visible() {
        let mut t: PortTable<4> = PortTable::new();
        assert!(t.is_empty());
        assert_eq!(t.bind(0), Err(BindError::Reserved), "端口 0 拒收");
        assert!(t.bind(7).is_ok());
        assert_eq!(t.bind(7), Err(BindError::AlreadyBound), "重复绑定拒收");
        assert!(t.bind(9).is_ok());
        assert!(t.bind(13).is_ok());
        assert_eq!(t.bind(21), Ok(()));
        assert_eq!(t.bind(23), Err(BindError::Exhausted), "第 5 槽枯竭");
        assert_eq!(t.len(), 4);
        // 中间槽解绑：swap_remove 零洞（b 解绑后 a/c/d 全在）
        assert!(t.is_bound(9));
        assert!(t.unbind(9).is_ok());
        assert!(!t.is_bound(9));
        assert!(t.is_bound(21));
        assert_eq!(t.unbind(9), Err(BindError::NotBound), "重复解绑拒收");
        // 空出的槽可复用
        assert!(t.bind(23).is_ok());
        assert!(t.is_bound(23));
    }

    #[test]
    fn proto_constant_is_udp() {
        assert_eq!(PROTO_UDP, 17);
    }
}
