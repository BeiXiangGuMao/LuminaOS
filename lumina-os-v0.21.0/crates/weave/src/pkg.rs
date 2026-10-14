//! Weave 包容器格式 LWP1（M16-②）——EXEC 装载链的包源映像结构面。
//!
//! **职责边界**（LXE1 同款分层）：本模块只做**结构**（magic/版本/名字区/
//! 载荷一致性）的解析与构造，纯函数、宿主可测；**解包策略**（载荷是否为
//! 合法 LXE1、放置映射）归内核 EXEC 装载器（`kernel::procs`）——格式层
//! 不知晓映像布局，内核层不重复结构校验。
//!
//! 布局（小端）：
//!
//! ```text
//! 头 32 字节：
//!   0x00 u32 magic = "LWP1"（0x3150_574C）
//!   0x04 u32 fmt_version = 1
//!   0x08 u16 semver major
//!   0x0A u16 semver minor
//!   0x0C u16 semver patch
//!   0x0E u8  name_len（1..=MAX_NAME）
//!   0x0F u8  保留（0）
//!   0x10 u64 payload_len（≥ MIN_PAYLOAD）
//!   0x18 u64 保留（0）
//! 名字区：name_len 字节（UTF-8，无 NUL；紧接头之后）
//! 载荷：payload_len 字节（v0 = LXE1 映像字节，紧接名字区）
//! ```
//!
//! EXEC 第 2+ 消费者（v0.15 候补转正）：LXE1 多段映像的直接装载为第一
//! 消费者；Weave 包源映像经本格式解包后进入同一 LXE1 装载链，为第二
//! 消费者——载荷结构校验仍由 `bedrock::exec::parse` 承担（单一事实源）。

use alloc::vec::Vec;
use core::str;

/// 魔数 "LWP1"（小端 u32；Lumina Weave Package v1）。
pub const LWP_MAGIC: u32 = 0x3150_574C;
/// 格式版本。
pub const LWP_VERSION: u32 = 1;
/// 头长度。
pub const HEADER_LEN: usize = 32;
/// 包名长度上限（单字节域收窄至 64；反向域名足够）。
pub const MAX_NAME: usize = 64;
/// 载荷长度下界（v0 载荷恒为 LXE1 映像，头即 64 字节；更低无意义）。
pub const MIN_PAYLOAD: usize = 64;

/// 结构错误（宿主与内核共用；装载器折叠为映像面错误码并记戳）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgError {
    /// 魔数不符。
    BadMagic,
    /// 格式版本不符。
    BadVersion,
    /// 名字区非法（零长/越界/截断/非 UTF-8）。
    BadName,
    /// blob 截断（头/名字区/载荷不完整）或 payload_len 低于下界。
    Truncated,
}

/// 解析结果：包元数据 + 载荷取用（借用视图）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeavePkg<'a> {
    /// 包名（UTF-8，无 NUL）。
    pub name: &'a str,
    /// 包版本（语义化三段）。
    pub version: crate::Version,
    /// 载荷切片（v0 = LXE1 映像字节）。
    payload: &'a [u8],
}

impl<'a> WeavePkg<'a> {
    /// 载荷切片（EXEC 装载器据此进入 LXE1 链）。
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// 解析 LWP1 包（纯结构校验；载荷的 LXE1 合法性归内核装载器）。
pub fn parse(blob: &[u8]) -> Result<WeavePkg<'_>, PkgError> {
    if blob.len() < HEADER_LEN {
        return Err(PkgError::Truncated);
    }
    if rd_u32(blob, 0) != Some(LWP_MAGIC) {
        return Err(PkgError::BadMagic);
    }
    if rd_u32(blob, 4) != Some(LWP_VERSION) {
        return Err(PkgError::BadVersion);
    }
    let major = rd_u16(blob, 8).unwrap_or(0);
    let minor = rd_u16(blob, 10).unwrap_or(0);
    let patch = rd_u16(blob, 12).unwrap_or(0);
    let name_len = blob[14] as usize;
    if name_len == 0 || name_len > MAX_NAME {
        return Err(PkgError::BadName);
    }
    if blob[15] != 0 || rd_u64(blob, 0x18) != Some(0) {
        return Err(PkgError::BadVersion); // 保留域非零：版本面拒绝
    }
    let name_end = HEADER_LEN
        .checked_add(name_len)
        .ok_or(PkgError::Truncated)?;
    if blob.len() < name_end {
        return Err(PkgError::Truncated);
    }
    let name = str::from_utf8(&blob[HEADER_LEN..name_end]).map_err(|_| PkgError::BadName)?;
    let payload_len = rd_u64(blob, 0x10).ok_or(PkgError::Truncated)? as usize;
    if payload_len < MIN_PAYLOAD {
        return Err(PkgError::Truncated);
    }
    let payload = blob
        .get(
            name_end
                ..name_end
                    .checked_add(payload_len)
                    .ok_or(PkgError::Truncated)?,
        )
        .ok_or(PkgError::Truncated)?;
    Ok(WeavePkg {
        name,
        version: crate::Version {
            major,
            minor,
            patch,
        },
        payload,
    })
}

/// 构造 LWP1 包（播种与宿主 roundtrip 测试用；encode 与 parse 共用同一
/// 布局常量，漂移即测试红）。名字越界（空/超 [`MAX_NAME`]）→ [`PkgError::
/// BadName`]；载荷低于 [`MIN_PAYLOAD`] → [`PkgError::Truncated`]。
pub fn encode(name: &str, version: crate::Version, payload: &[u8]) -> Result<Vec<u8>, PkgError> {
    let nb = name.as_bytes();
    if nb.is_empty() || nb.len() > MAX_NAME {
        return Err(PkgError::BadName);
    }
    if payload.len() < MIN_PAYLOAD {
        return Err(PkgError::Truncated);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + nb.len() + payload.len());
    out.extend_from_slice(&LWP_MAGIC.to_le_bytes());
    out.extend_from_slice(&LWP_VERSION.to_le_bytes());
    out.extend_from_slice(&version.major.to_le_bytes());
    out.extend_from_slice(&version.minor.to_le_bytes());
    out.extend_from_slice(&version.patch.to_le_bytes());
    out.push(nb.len() as u8);
    out.push(0); // 保留
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // 保留
    out.extend_from_slice(nb);
    out.extend_from_slice(payload);
    Ok(out)
}

/// 读 u16/u32/u64 小端标量（截断防御：不足返回 None）。
fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{encode, parse, PkgError, HEADER_LEN, MAX_NAME, MIN_PAYLOAD};
    use crate::Version;
    use alloc::vec;
    use alloc::vec::Vec;

    /// 合法 LXE1 载荷替身（≥ MIN_PAYLOAD；真实合法性归 bedrock::exec）。
    fn fake_lxe() -> Vec<u8> {
        let mut v = vec![0u8; MIN_PAYLOAD + 8];
        v[..4].copy_from_slice(b"LXE1");
        v
    }

    #[test]
    fn encode_parse_roundtrip() {
        let payload = fake_lxe();
        let blob = encode(
            "org.lumina.prog",
            Version {
                major: 1,
                minor: 2,
                patch: 3,
            },
            &payload,
        )
        .unwrap();
        let pkg = parse(&blob).unwrap();
        assert_eq!(pkg.name, "org.lumina.prog");
        assert_eq!(
            pkg.version,
            Version {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        assert_eq!(pkg.payload(), &payload[..]);
        assert_eq!(blob.len(), HEADER_LEN + 15 + payload.len());
    }

    #[test]
    fn parse_negatives() {
        let payload = fake_lxe();
        let good = encode("pkg", Version::parse("0.1.0").unwrap(), &payload).unwrap();
        // BadMagic
        let mut b = good.clone();
        b[0] = b'X';
        assert_eq!(parse(&b), Err(PkgError::BadMagic));
        // BadVersion
        let mut b = good.clone();
        b[4] = 9;
        assert_eq!(parse(&b), Err(PkgError::BadVersion));
        // 保留域非零 → BadVersion
        let mut b = good.clone();
        b[0x18] = 1;
        assert_eq!(parse(&b), Err(PkgError::BadVersion));
        // BadName：name_len 零
        let mut b = good.clone();
        b[14] = 0;
        assert_eq!(parse(&b), Err(PkgError::BadName));
        // BadName：名字区非 UTF-8
        let mut b = encode("pkg", Version::parse("0.1.0").unwrap(), &payload).unwrap();
        b[HEADER_LEN] = 0xFF;
        assert_eq!(parse(&b), Err(PkgError::BadName));
        // Truncated：头不足
        assert_eq!(parse(&good[..16]), Err(PkgError::Truncated));
        // Truncated：payload_len 低于下界（patch 至 MIN-1）
        let mut b = good.clone();
        let short = (MIN_PAYLOAD - 1) as u64;
        b[0x10..0x18].copy_from_slice(&short.to_le_bytes());
        assert_eq!(parse(&b), Err(PkgError::Truncated));
        // Truncated：载荷区截断（名字区加长后 blob 不含全部载荷）
        let long_name = "n".repeat(MAX_NAME);
        let b = encode(&long_name, Version::parse("0.1.0").unwrap(), &payload).unwrap();
        assert_eq!(parse(&b[..b.len() - 1]), Err(PkgError::Truncated));
    }

    #[test]
    fn encode_rejects_bad_name_and_short_payload() {
        let payload = fake_lxe();
        // 空名
        assert_eq!(
            encode("", Version::parse("0.1.0").unwrap(), &payload),
            Err(PkgError::BadName)
        );
        // 超长名（MAX_NAME + 1）
        let long = "n".repeat(MAX_NAME + 1);
        assert_eq!(
            encode(&long, Version::parse("0.1.0").unwrap(), &payload),
            Err(PkgError::BadName)
        );
        // 载荷低于下界
        assert_eq!(
            encode(
                "pkg",
                Version::parse("0.1.0").unwrap(),
                &payload[..MIN_PAYLOAD - 1]
            ),
            Err(PkgError::Truncated)
        );
    }

    #[test]
    fn max_name_roundtrip_and_version_zero() {
        let payload = fake_lxe();
        let long = "n".repeat(MAX_NAME);
        let blob = encode(
            &long,
            Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
            &payload,
        )
        .unwrap();
        let pkg = parse(&blob).unwrap();
        assert_eq!(pkg.name, long.as_str());
        assert_eq!(pkg.version.major, 0);
    }
}
