//! LXE1 多段可执行映像格式（M14-①）——EXEC 装载器的结构面。
//!
//! **职责边界**：本模块只做**结构**（magic/版本/段表/载荷一致性）的
//! 解析与构造，纯函数、宿主可测；**放置策略**（段 vaddr 允许域、槽位
//! 互斥、entry 落段、stack_top 取值）归内核装载器（`kernel::user`）——
//! 格式层不知晓页表布局，内核层不重复结构校验。
//!
//! 布局（小端）：
//!
//! ```text
//! 头 64 字节：
//!   0x00 u32 magic = "LXE1"（0x3145_584C）
//!   0x04 u32 version = 1
//!   0x08 u32 seg_count（1..=MAX_SEGS）
//!   0x0C u32 保留（0）
//!   0x10 u64 entry（入口虚地址；落段校验归内核）
//!   0x18 u64 stack_top（0 = 内核默认栈；非 0 须 4K 对齐）
//!   0x20 u64 payload_off（= 64 + 32 * seg_count，显式自描述）
//!   0x28 u64 保留 ×3（0）
//! 段头 32 字节 × seg_count：
//!   u64 vaddr（4K 对齐）u64 mem_len u64 file_len（≤ mem_len）
//!   u64 flags（bit0 = W、bit1 = X；其余位保留须 0，全零段非法）
//! 载荷：seg[i] 数据 = payload_off + Σ file_len[0..i]，长 file_len[i]，
//!       紧密排布无填充；mem_len > file_len 的尾部由装载器清零补齐
//! ```
//!
//! 非目标：重定位、符号面、动态链接（v0 位置固定映像，如实记档）。

use alloc::vec::Vec;

/// 魔数 "LXE1"（小端 u32）。
pub const LXE_MAGIC: u32 = 0x3145_584C;
/// 格式版本。
pub const LXE_VERSION: u32 = 1;
/// 段数上限（v0 静态定容；配额治理口径见 kernel::user 策略面）。
pub const MAX_SEGS: usize = 8;
/// 头长度。
pub const HEADER_LEN: usize = 64;
/// 段头长度。
pub const SEG_HDR_LEN: usize = 32;
/// 页粒度（对齐与 mem_len 补齐单位）。
pub const PAGE: u64 = 0x1000;
/// 段 flags：可写。
pub const FLAG_W: u64 = 1 << 0;
/// 段 flags：可执行。
pub const FLAG_X: u64 = 1 << 1;
/// flags 合法域掩码（其余位保留须 0）。
const FLAG_MASK: u64 = FLAG_W | FLAG_X;

/// 结构错误（宿主与内核共用；装载器折叠为映像面错误码并记戳）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxeError {
    /// 魔数不符。
    BadMagic,
    /// 版本不符。
    BadVersion,
    /// 段数为 0 或超上限。
    BadSegCount,
    /// blob 截断（头/段表/载荷不完整）或 payload_off 不自洽。
    Truncated,
    /// vaddr / stack_top 未按 4K 对齐。
    Unaligned,
    /// file_len > mem_len 或 flags 非法（保留位置 1 / 全零段）。
    BadSeg,
}

/// 单段描述（解析产物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// 虚地址（4K 对齐；落点策略归内核）。
    pub vaddr: u64,
    /// 内存映像长度（> file_len 的尾部清零）。
    pub mem_len: u64,
    /// 载荷内实际数据长度。
    pub file_len: u64,
    /// flags（FLAG_W / FLAG_X）。
    pub flags: u64,
}

/// 解析结果：结构字段 + 段数据取用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LxeImage<'a> {
    /// 入口虚地址。
    pub entry: u64,
    /// 栈顶（0 = 内核默认栈布局）。
    pub stack_top: u64,
    /// 段表（0..seg_count 有效）。
    pub segments: [Segment; MAX_SEGS],
    /// 有效段数（1..=MAX_SEGS）。
    pub seg_count: usize,
    /// 源 blob（段数据切片的基底）。
    blob: &'a [u8],
    /// 载荷基（已校验 = HEADER_LEN + SEG_HDR_LEN * seg_count）。
    payload_off: usize,
}

impl<'a> LxeImage<'a> {
    /// 第 i 段的载荷数据切片（file_len 长；越界段号为调用方 bug，
    /// 防御式返回空切片）。
    pub fn seg_bytes(&self, i: usize) -> &'a [u8] {
        if i >= self.seg_count {
            return &[];
        }
        let mut off = self.payload_off;
        for s in self.segments.iter().take(i) {
            off += s.file_len as usize;
        }
        let len = self.segments[i].file_len as usize;
        self.blob.get(off..off + len).unwrap_or(&[])
    }
}

/// 读 u32/u64 小端标量（截断防御：不足返回 None）。
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// 解析 LXE1 映像（纯结构校验；放置策略归内核装载器）。
pub fn parse(blob: &[u8]) -> Result<LxeImage<'_>, LxeError> {
    if blob.len() < HEADER_LEN {
        return Err(LxeError::Truncated);
    }
    if rd_u32(blob, 0) != Some(LXE_MAGIC) {
        return Err(LxeError::BadMagic);
    }
    if rd_u32(blob, 4) != Some(LXE_VERSION) {
        return Err(LxeError::BadVersion);
    }
    let seg_count = rd_u32(blob, 8).unwrap_or(0) as usize;
    if seg_count == 0 || seg_count > MAX_SEGS {
        return Err(LxeError::BadSegCount);
    }
    let payload_off = rd_u64(blob, 0x20).unwrap_or(0) as usize;
    if payload_off != HEADER_LEN + SEG_HDR_LEN * seg_count {
        return Err(LxeError::Truncated);
    }
    let mut segments = [Segment {
        vaddr: 0,
        mem_len: 0,
        file_len: 0,
        flags: 0,
    }; MAX_SEGS];
    let mut payload_len = 0usize;
    for (i, seg) in segments.iter_mut().enumerate().take(seg_count) {
        let base = HEADER_LEN + SEG_HDR_LEN * i;
        let vaddr = rd_u64(blob, base).ok_or(LxeError::Truncated)?;
        let mem_len = rd_u64(blob, base + 8).ok_or(LxeError::Truncated)?;
        let file_len = rd_u64(blob, base + 16).ok_or(LxeError::Truncated)?;
        let flags = rd_u64(blob, base + 24).ok_or(LxeError::Truncated)?;
        if !vaddr.is_multiple_of(PAGE) {
            return Err(LxeError::Unaligned);
        }
        if file_len > mem_len || flags & !FLAG_MASK != 0 || flags == 0 {
            return Err(LxeError::BadSeg);
        }
        *seg = Segment {
            vaddr,
            mem_len,
            file_len,
            flags,
        };
        payload_len += file_len as usize;
    }
    if blob.len() < payload_off + payload_len {
        return Err(LxeError::Truncated);
    }
    let stack_top = rd_u64(blob, 0x18).unwrap_or(0);
    if !stack_top.is_multiple_of(PAGE) {
        return Err(LxeError::Unaligned);
    }
    Ok(LxeImage {
        entry: rd_u64(blob, 0x10).unwrap_or(0),
        stack_top,
        segments,
        seg_count,
        blob,
        payload_off,
    })
}

/// 段构造规约（encode 输入）。
pub struct SegSpec<'a> {
    /// 虚地址（encode 侧仅查 4K 对齐；落点域归内核策略）。
    pub vaddr: u64,
    /// flags（须为 FLAG_W/FLAG_X 非零组合）。
    pub flags: u64,
    /// 载荷数据（长 = file_len）。
    pub data: &'a [u8],
    /// 内存映像长度（≥ data.len()；尾部清零）。
    pub mem_len: u64,
}

/// 构造 LXE1 映像（seed 播种与宿主 roundtrip 测试用；encode 与 parse
/// 共用同一布局常量，漂移即测试红）。
pub fn encode(entry: u64, stack_top: u64, segs: &[SegSpec]) -> Result<Vec<u8>, LxeError> {
    if segs.is_empty() || segs.len() > MAX_SEGS {
        return Err(LxeError::BadSegCount);
    }
    if !stack_top.is_multiple_of(PAGE) {
        return Err(LxeError::Unaligned);
    }
    for s in segs {
        if !s.vaddr.is_multiple_of(PAGE) {
            return Err(LxeError::Unaligned);
        }
        if s.data.len() as u64 > s.mem_len || s.flags & !FLAG_MASK != 0 || s.flags == 0 {
            return Err(LxeError::BadSeg);
        }
    }
    let seg_count = segs.len();
    let payload_off = HEADER_LEN + SEG_HDR_LEN * seg_count;
    let mut out =
        Vec::with_capacity(payload_off + segs.iter().map(|s| s.data.len()).sum::<usize>());
    out.extend_from_slice(&LXE_MAGIC.to_le_bytes());
    out.extend_from_slice(&LXE_VERSION.to_le_bytes());
    out.extend_from_slice(&(seg_count as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&entry.to_le_bytes());
    out.extend_from_slice(&stack_top.to_le_bytes());
    out.extend_from_slice(&(payload_off as u64).to_le_bytes());
    out.extend_from_slice(&[0u8; 24]); // 0x28..0x40 保留
    for s in segs {
        out.extend_from_slice(&s.vaddr.to_le_bytes());
        out.extend_from_slice(&s.mem_len.to_le_bytes());
        out.extend_from_slice(&(s.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&s.flags.to_le_bytes());
    }
    for s in segs {
        out.extend_from_slice(s.data);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const D1: &[u8] = b"\x90\x31\xc0\xc3"; // 4 字节假代码
    const D2: &[u8] = b"LUMINA";

    #[test]
    fn encode_parse_roundtrip_two_segs() {
        let blob = encode(
            0x1_8000_0000,
            0,
            &[
                SegSpec {
                    vaddr: 0x1_8000_0000,
                    flags: FLAG_X,
                    data: D1,
                    mem_len: PAGE,
                },
                SegSpec {
                    vaddr: 0x1_8000_1000,
                    flags: FLAG_W,
                    data: D2,
                    mem_len: PAGE,
                },
            ],
        )
        .unwrap();
        let img = parse(&blob).unwrap();
        assert_eq!(img.entry, 0x1_8000_0000);
        assert_eq!(img.stack_top, 0);
        assert_eq!(img.seg_count, 2);
        assert_eq!(img.segments[0].vaddr, 0x1_8000_0000);
        assert_eq!(img.segments[0].flags, FLAG_X);
        assert_eq!(img.segments[0].mem_len, PAGE);
        assert_eq!(img.segments[0].file_len, D1.len() as u64);
        assert_eq!(img.segments[1].flags, FLAG_W);
        assert_eq!(img.seg_bytes(0), D1);
        assert_eq!(img.seg_bytes(1), D2);
        assert_eq!(img.seg_bytes(2), &[]); // 越界段号防御
    }

    #[test]
    fn encode_parse_stack_top_and_tail_zero_semantics() {
        // mem_len > file_len：载荷只含 file_len 字节（尾部清零由装载器做）
        let blob = encode(
            0x400000,
            0x1_8040_0000,
            &[SegSpec {
                vaddr: 0x400000,
                flags: FLAG_X | FLAG_W,
                data: D2,
                mem_len: 2 * PAGE,
            }],
        )
        .unwrap();
        let img = parse(&blob).unwrap();
        assert_eq!(img.stack_top, 0x1_8040_0000);
        assert_eq!(img.seg_bytes(0).len(), D2.len());
        // 载荷总长 = file_len（紧排无填充）
        assert_eq!(blob.len(), HEADER_LEN + SEG_HDR_LEN + D2.len());
    }

    #[test]
    fn parse_negatives() {
        let good = encode(
            0x400000,
            0,
            &[SegSpec {
                vaddr: 0x400000,
                flags: FLAG_X,
                data: D1,
                mem_len: PAGE,
            }],
        )
        .unwrap();
        // BadMagic
        let mut b = good.clone();
        b[0] = b'X';
        assert_eq!(parse(&b), Err(LxeError::BadMagic));
        // BadVersion
        let mut b = good.clone();
        b[4] = 9;
        assert_eq!(parse(&b), Err(LxeError::BadVersion));
        // BadSegCount（0 与超限）
        let mut b = good.clone();
        b[8] = 0;
        assert_eq!(parse(&b), Err(LxeError::BadSegCount));
        // Truncated（头不足）
        assert_eq!(parse(&good[..32]), Err(LxeError::Truncated));
        // Truncated（payload_off 不自洽）
        let mut b = good.clone();
        b[0x20] += 8;
        assert_eq!(parse(&b), Err(LxeError::Truncated));
        // Truncated（载荷截断）
        assert_eq!(parse(&good[..good.len() - 1]), Err(LxeError::Truncated));
        // Unaligned（vaddr：段头 0x40 起，patch vaddr 低字节）
        let mut b = good.clone();
        b[HEADER_LEN] = 0x23;
        assert_eq!(parse(&b), Err(LxeError::Unaligned));
        // Unaligned（stack_top：头 0x18 域 patch 低字节）
        let mut b = good.clone();
        b[0x18] = 0x01;
        assert_eq!(parse(&b), Err(LxeError::Unaligned));
        // BadSeg（file_len > mem_len：mem_len patch 至 2 < file_len(4)）
        let mut b = good.clone();
        b[HEADER_LEN + 8] = 2; // u64 LE 低字节
        b[HEADER_LEN + 9] = 0; // 清高位（原 0x10）
        assert_eq!(parse(&b), Err(LxeError::BadSeg));
        // BadSeg（全零 flags）
        let mut b = good.clone();
        b[HEADER_LEN + 24] = 0;
        assert_eq!(parse(&b), Err(LxeError::BadSeg));
        // BadSeg（保留位置 1）
        let mut b = good.clone();
        b[HEADER_LEN + 24] = FLAG_X as u8 | 0x04;
        assert_eq!(parse(&b), Err(LxeError::BadSeg));
        // encode 侧拒绝：9 段超限
        let segs: Vec<SegSpec> = (0..9)
            .map(|i| SegSpec {
                vaddr: 0x1_8000_0000 + i * PAGE,
                flags: FLAG_W,
                data: D1,
                mem_len: PAGE,
            })
            .collect();
        assert_eq!(encode(0, 0, &segs), Err(LxeError::BadSegCount));
        // encode 侧拒绝：file_len > mem_len
        assert_eq!(
            encode(
                0,
                0,
                &[SegSpec {
                    vaddr: 0x400000,
                    flags: FLAG_X,
                    data: &[0u8; 16],
                    mem_len: 8,
                }]
            ),
            Err(LxeError::BadSeg)
        );
        // encode 侧拒绝：stack_top 未对齐
        assert_eq!(
            encode(
                0,
                0x1_8040_0001,
                &[SegSpec {
                    vaddr: 0x400000,
                    flags: FLAG_X,
                    data: D1,
                    mem_len: PAGE,
                }]
            ),
            Err(LxeError::Unaligned)
        );
    }

    #[test]
    fn max_segs_roundtrip() {
        let segs: Vec<SegSpec> = (0..MAX_SEGS)
            .map(|i| SegSpec {
                vaddr: 0x1_8000_0000 + i as u64 * PAGE,
                flags: if i % 2 == 0 { FLAG_X } else { FLAG_W },
                data: &D2[..(i + 1).min(D2.len())],
                mem_len: PAGE,
            })
            .collect();
        let blob = encode(0x1_8000_0000, 0, &segs).unwrap();
        let img = parse(&blob).unwrap();
        assert_eq!(img.seg_count, MAX_SEGS);
        for i in 0..MAX_SEGS {
            assert_eq!(img.segments[i].vaddr, 0x1_8000_0000 + i as u64 * PAGE);
        }
    }
}
