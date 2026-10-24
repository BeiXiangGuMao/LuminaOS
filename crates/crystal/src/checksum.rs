//! XXH64 校验和（in-crate 零依赖实现；格式 v1 首发算法，ID = [`crate::layout::CKSUM_XXH64`]）。
//!
//! **既登记偏差**（M26-计划，ROADMAP M26 子节）：细则 2.4 默认 xxh3-128——
//! v1 以 XXH64 首发收敛实现面（零依赖、`no_std`、无 unsafe），xxh3-128 按
//! 细则 3.4 演进规则经算法 ID + 特性位（`layout::feature::XXH3_128`）并存
//! 推进，uplift 挂账；CR-P10 全量口径验收随 uplift 重跑。
//!
//! 实现依据 xxHash v0.8 参考语义（seed 恒 0）：32 字节条带四累加器轮 +
//! 长度并入 + 尾部 8/4/1 字节收尾 + 三段雪崩。正确性锚定 = 三条规范测试
//! 向量（空串 / `a` / `abc`，见测试模块）；任何偏离向量即视为实现缺陷。
//!
//! 用途纪律（细则 5.2 防线三）：校验和先于任何解释执行——所有来自磁盘的
//! 字节在通过校验前不得被赋予语义（codec 侧保证，本模块只提供纯函数）。

/// 素数 P1（xxHash 规范常量）。
const P1: u64 = 0x9E37_79B1_85EB_CA87;
/// 素数 P2。
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
/// 素数 P3。
const P3: u64 = 0x1656_67B1_9E37_79F9;
/// 素数 P4。
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
/// 素数 P5。
const P5: u64 = 0x27D4_EB2F_1656_67C5;

/// 单轮混合：`rotl(acc + lane·P2, 31) · P1`。
#[inline]
fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

/// 累加器合并（条带收尾）：`((acc ^ round(0,val)) · P1) + P4`。
#[inline]
fn merge_round(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val)).wrapping_mul(P1).wrapping_add(P4)
}

/// 小端 u64 读取（调用方保证 `b.len() >= 8`）。
#[inline]
fn read_u64(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    u64::from_le_bytes(buf)
}

/// 小端 u32 读取（调用方保证 `b.len() >= 4`）。
#[inline]
fn read_u32(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&b[..4]);
    u32::from_le_bytes(buf)
}

/// XXH64（seed 恒 0；输入任意字节串，空串合法）。
pub fn xxh64(input: &[u8]) -> u64 {
    let len = input.len();
    let mut h: u64;
    let mut i = 0usize;

    if len >= 32 {
        let mut v1 = P1.wrapping_add(P2);
        let mut v2 = P2;
        let mut v3: u64 = 0;
        let mut v4 = P1.wrapping_neg();
        while len - i >= 32 {
            v1 = round(v1, read_u64(&input[i..]));
            v2 = round(v2, read_u64(&input[i + 8..]));
            v3 = round(v3, read_u64(&input[i + 16..]));
            v4 = round(v4, read_u64(&input[i + 24..]));
            i += 32;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        h = merge_round(h, v4);
    } else {
        h = P5;
    }

    h = h.wrapping_add(len as u64);

    while len - i >= 8 {
        h ^= round(0, read_u64(&input[i..]));
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        i += 8;
    }
    if len - i >= 4 {
        h ^= u64::from(read_u32(&input[i..])).wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        i += 4;
    }
    while i < len {
        h ^= (input[i] as u64).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
        i += 1;
    }

    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::xxh64;

    /// 规范测试向量（xxHash v0.8 参考；seed = 0）。
    #[test]
    fn spec_vectors() {
        assert_eq!(xxh64(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a"), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc"), 0x44BC_2CF5_AD77_0999);
    }

    /// 条带边界扫描：32 字节边界前后（24..40 字节）全部长度稳定可得。
    #[test]
    fn stripe_boundary_lengths_stable() {
        let base = [0x5Au8; 128];
        for n in 24..40usize {
            let h = xxh64(&base[..n]);
            // 长度并入保证不同长度不同摘要（该输入域内）。
            assert_ne!(h, xxh64(&base[..n + 1]), "len {n} 与 {n}+1 摘要撞车");
        }
    }

    /// 单位翻转雪崩：100 字节输入逐位翻转（64 位域）摘要必变。
    #[test]
    fn bit_flip_changes_digest() {
        let mut input = [0u8; 100];
        input[..].fill(0x3C);
        let base = xxh64(&input);
        for bit in 0..64usize {
            let mut flipped = input;
            flipped[40 + bit / 8] ^= 1 << (bit % 8);
            assert_ne!(xxh64(&flipped), base, "bit {bit} 翻转摘要未变");
        }
    }
}
