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
//!
//! # XXH3-128（M36-C1a uplift 算法面）
//!
//! 细则 2.4 默认算法 xxh3-128 的 in-crate 零依赖实现（`no_std`、无 unsafe），
//! xxHash v0.8.2 规范语义——短（0..16）/中（17..240）/长（>240）三径标量实
//! 现，seed 恒 0。正确性锚定 = 规范黄金向量表（40 长度点 × python `xxhash`
//! C 参考实现生成，覆盖三径全部边界：1/3/4/8/9/16/17/128/129/240/241 及
//! 条带/块边界，见测试模块；生成脚本 `scripts/gen_xxh3_vectors.py`）+ 单位
//! 翻转雪崩 + 长度邻域不变式。盘上接入（算法 ID 2 + 特性位并存）随 C1b，
//! 本笔只交付算法面。

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

// ===================== XXH3-128（M36-C1a uplift 算法面） =====================

/// PRIME_MX1（XXH3 雪崩素数；参考源 PRIME_MX1）。
const PRIME_MX1: u64 = 0x1656_6791_9E37_79F9;
/// PRIME_MX2（rrmxmx/4to8 域素数；参考源 PRIME_MX2）。
const PRIME_MX2: u64 = 0x9FB2_1C65_1E98_DF25;
/// PRIME32_1（scramble 乘法素数）。
const PRIME32_1: u32 = 0x9E37_79B1;
/// PRIME32_2（9to16 高域乘法素数）。
const PRIME32_2: u32 = 0x85EB_CA77;
/// PRIME32_3（长路径累加器初值）。
const PRIME32_3: u32 = 0xC2B2_AE3D;

/// 默认秘密（xxHash v0.8.2 `XXH3_kSecret` 192 字节，参考源逐字转录）。
const KSECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

/// 条带长（字节；`XXH_STRIPE_LEN`）。
const STRIPE_LEN: usize = 64;
/// 累加器通道数（`XXH_ACC_NB`）。
const ACC_NB: usize = 8;
/// 每条带消耗秘密字节数（`XXH_SECRET_CONSUME_RATE`）。
const SECRET_CONSUME_RATE: usize = 8;
/// mergeAccs 秘密起始偏移（`XXH_SECRET_MERGEACCS_START`）。
const MERGEACCS_START: usize = 11;
/// 末条带秘密起始偏移（`XXH_SECRET_LASTACC_START`）。
const LASTACC_START: usize = 7;

/// XXH3-128 摘要（low/high 双 64 位域）。
///
/// 盘上编码约定（C1b 勘误注承接面）：16 字节小端、low 8 字节先行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xxh3_128 {
    /// 低 64 位域。
    pub low: u64,
    /// 高 64 位域。
    pub high: u64,
}

impl Xxh3_128 {
    /// 16 字节小端序列（low 8 字节 + high 8 字节；超级块/节点校验和域共用）。
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.low.to_le_bytes());
        out[8..].copy_from_slice(&self.high.to_le_bytes());
        out
    }
}

/// 64×64 → 128 位乘（core `u128` 承载；返回 (low, high)）。
#[inline]
fn mult64to128(lhs: u64, rhs: u64) -> (u64, u64) {
    let p = u128::from(lhs).wrapping_mul(u128::from(rhs));
    (p as u64, (p >> 64) as u64)
}

/// 128 位乘高低折叠 XOR（`XXH3_mul128_fold64`）。
#[inline]
fn mul128_fold64(lhs: u64, rhs: u64) -> u64 {
    let (lo, hi) = mult64to128(lhs, rhs);
    lo ^ hi
}

/// 32×32 → 64 位宽乘。
#[inline]
fn mult32to64(lhs: u32, rhs: u32) -> u64 {
    u64::from(lhs).wrapping_mul(u64::from(rhs))
}

/// 右移异或（`XXH_xorshift64`）。
#[inline]
fn xorshift64(v: u64, shift: u32) -> u64 {
    v ^ (v >> shift)
}

/// XXH3 快速雪崩（输入已部分混合时适用；`XXH3_avalanche`）。
#[inline]
fn avalanche3(h64: u64) -> u64 {
    let h = xorshift64(h64, 37);
    let h = h.wrapping_mul(PRIME_MX1);
    xorshift64(h, 32)
}

/// XXH64 强雪崩（`XXH64_avalanche`）。
#[inline]
fn avalanche64(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(P3);
    hash ^= hash >> 32;
    hash
}

/// 16 字节混合（`XXH3_mix16B`；seed 恒 0）。
#[inline]
fn mix16b(input: &[u8], secret: &[u8]) -> u64 {
    let input_lo = read_u64(input);
    let input_hi = read_u64(&input[8..]);
    mul128_fold64(
        input_lo ^ read_u64(secret),
        input_hi ^ read_u64(&secret[8..]),
    )
}

/// 32 字节双域混合（`XXH128_mix32B`；seed 恒 0）。
#[inline]
fn mix32b(acc: (u64, u64), in1: &[u8], in2: &[u8], secret: &[u8]) -> (u64, u64) {
    let (mut lo, mut hi) = acc;
    lo = lo.wrapping_add(mix16b(in1, secret));
    lo ^= read_u64(in2).wrapping_add(read_u64(&in2[8..]));
    hi = hi.wrapping_add(mix16b(in2, &secret[16..]));
    hi ^= read_u64(in1).wrapping_add(read_u64(&in1[8..]));
    (lo, hi)
}

/// 条带累加（64 字节节 × 8 通道；相邻通道交换累加——参考 `XXH3_scalarRound` 语义）。
fn accumulate_512(acc: &mut [u64; ACC_NB], input: &[u8], secret: &[u8]) {
    for lane in 0..ACC_NB {
        let data_val = read_u64(&input[lane * 8..]);
        let data_key = data_val ^ read_u64(&secret[lane * 8..]);
        acc[lane ^ 1] = acc[lane ^ 1].wrapping_add(data_val);
        let lo32 = (data_key & 0xFFFF_FFFF) as u32;
        let hi32 = data_key >> 32;
        acc[lane] = u64::from(lo32).wrapping_mul(hi32).wrapping_add(acc[lane]);
    }
}

/// 累加器扰频（参考 `XXH3_scalarScrambleRound` 语义）。
fn scramble_acc(acc: &mut [u64; ACC_NB], secret: &[u8]) {
    for lane in 0..ACC_NB {
        let key64 = read_u64(&secret[lane * 8..]);
        let a = xorshift64(acc[lane], 47);
        let a = a ^ key64;
        acc[lane] = a.wrapping_mul(u64::from(PRIME32_1));
    }
}

/// 累加器收敛（`XXH3_mergeAccs`）。
fn merge_accs(acc: &[u64; ACC_NB], secret: &[u8], start: u64) -> u64 {
    let mut result = start;
    for i in 0..4 {
        result = result.wrapping_add(mul128_fold64(
            acc[2 * i] ^ read_u64(&secret[16 * i..]),
            acc[2 * i + 1] ^ read_u64(&secret[16 * i + 8..]),
        ));
    }
    avalanche3(result)
}

/// 长路径（len > 240；`XXH3_hashLong_128b_internal` 默认秘密/seed=0 标量面）。
fn hash_long(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let mut acc: [u64; ACC_NB] = [
        u64::from(PRIME32_3),
        P1,
        P2,
        P3,
        P4,
        u64::from(PRIME32_2),
        P5,
        u64::from(PRIME32_1),
    ];
    let nb_stripes_per_block = (KSECRET.len() - STRIPE_LEN) / SECRET_CONSUME_RATE; // 16
    let block_len = STRIPE_LEN * nb_stripes_per_block; // 1024
    let nb_blocks = (len - 1) / block_len;
    for n in 0..nb_blocks {
        for s in 0..nb_stripes_per_block {
            accumulate_512(
                &mut acc,
                &input[n * block_len + s * STRIPE_LEN..],
                &KSECRET[s * 8..],
            );
        }
        scramble_acc(&mut acc, &KSECRET[KSECRET.len() - STRIPE_LEN..]);
    }
    // 最后残块（整块计提后的短条带尾）。
    let nb_stripes = ((len - 1) - block_len * nb_blocks) / STRIPE_LEN;
    for s in 0..nb_stripes {
        accumulate_512(
            &mut acc,
            &input[nb_blocks * block_len + s * STRIPE_LEN..],
            &KSECRET[s * 8..],
        );
    }
    // 末条带（末 64 字节重叠读；秘密偏移 121——与累加/扰频面异偏移纪律）。
    accumulate_512(
        &mut acc,
        &input[len - STRIPE_LEN..],
        &KSECRET[KSECRET.len() - STRIPE_LEN - LASTACC_START..],
    );
    let low = merge_accs(
        &acc,
        &KSECRET[MERGEACCS_START..],
        (len as u64).wrapping_mul(P1),
    );
    let high = merge_accs(
        &acc,
        &KSECRET[KSECRET.len() - 64 - MERGEACCS_START..],
        !(len as u64).wrapping_mul(P2),
    );
    (low, high)
}

/// 1..3 字节径（`XXH3_len_1to3_128b`；seed 恒 0）。
fn len_1to3_128b(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let c1 = u32::from(input[0]);
    let c2 = u32::from(input[len >> 1]);
    let c3 = u32::from(input[len - 1]);
    let combinedl = (c1 << 16) | (c2 << 24) | c3 | ((len as u32) << 8);
    let combinedh = combinedl.swap_bytes().rotate_left(13);
    let bitflipl = u64::from(read_u32(&KSECRET) ^ read_u32(&KSECRET[4..]));
    let bitfliph = u64::from(read_u32(&KSECRET[8..]) ^ read_u32(&KSECRET[12..]));
    let keyed_lo = u64::from(combinedl) ^ bitflipl;
    let keyed_hi = u64::from(combinedh) ^ bitfliph;
    (avalanche64(keyed_lo), avalanche64(keyed_hi))
}

/// 4..8 字节径（`XXH3_len_4to8_128b`；seed 恒 0）。
fn len_4to8_128b(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let input_lo = read_u32(input);
    let input_hi = read_u32(&input[len - 4..]);
    let input_64 = u64::from(input_lo).wrapping_add(u64::from(input_hi) << 32);
    let bitflip = read_u64(&KSECRET[16..]) ^ read_u64(&KSECRET[24..]);
    let keyed = input_64 ^ bitflip;
    let (mut lo, mut hi) = mult64to128(keyed, P1.wrapping_add((len as u64) << 2));
    hi = hi.wrapping_add(lo << 1);
    lo ^= hi >> 3;
    lo = xorshift64(lo, 35);
    lo = lo.wrapping_mul(PRIME_MX2);
    lo = xorshift64(lo, 28);
    hi = avalanche3(hi);
    (lo, hi)
}

/// 9..16 字节径（`XXH3_len_9to16_128b`；seed 恒 0，64 位机语义面）。
fn len_9to16_128b(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let bitflipl = read_u64(&KSECRET[32..]) ^ read_u64(&KSECRET[40..]);
    let bitfliph = read_u64(&KSECRET[48..]) ^ read_u64(&KSECRET[56..]);
    let input_lo = read_u64(input);
    let mut input_hi = read_u64(&input[len - 8..]);
    let (mut lo, mut hi) = mult64to128(input_lo ^ input_hi ^ bitflipl, P1);
    lo = lo.wrapping_add((len as u64 - 1) << 54);
    input_hi ^= bitfliph;
    // 64 位机恒等式面：input_hi + lo32(input_hi)·(PRIME32_2 − 1)。
    hi = hi
        .wrapping_add(input_hi)
        .wrapping_add(mult32to64((input_hi & 0xFFFF_FFFF) as u32, PRIME32_2 - 1));
    lo ^= hi.swap_bytes();
    let (lo2, hi2) = mult64to128(lo, P2);
    let out_hi = hi2.wrapping_add(hi.wrapping_mul(P2));
    (avalanche3(lo2), avalanche3(out_hi))
}

/// 17..128 字节径（`XXH3_len_17to128_128b`；seed 恒 0）。
fn len_17to128_128b(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let mut acc: (u64, u64) = ((len as u64).wrapping_mul(P1), 0);
    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = mix32b(acc, &input[48..], &input[len - 64..], &KSECRET[96..]);
            }
            acc = mix32b(acc, &input[32..], &input[len - 48..], &KSECRET[64..]);
        }
        acc = mix32b(acc, &input[16..], &input[len - 32..], &KSECRET[32..]);
    }
    acc = mix32b(acc, input, &input[len - 16..], &KSECRET);
    let (alo, ahi) = acc;
    let lo = avalanche3(alo.wrapping_add(ahi));
    let hi = 0u64.wrapping_sub(avalanche3(
        alo.wrapping_mul(P1)
            .wrapping_add(ahi.wrapping_mul(P4))
            .wrapping_add((len as u64).wrapping_mul(P2)),
    ));
    (lo, hi)
}

/// 129..240 字节径（`XXH3_len_129to240_128b`；seed 恒 0）。
fn len_129to240_128b(input: &[u8]) -> (u64, u64) {
    let len = input.len();
    let mut acc: (u64, u64) = ((len as u64).wrapping_mul(P1), 0);
    let mut i = 32usize;
    while i < 160 {
        acc = mix32b(acc, &input[i - 32..], &input[i - 16..], &KSECRET[i - 32..]);
        i += 32;
    }
    acc.0 = avalanche3(acc.0);
    acc.1 = avalanche3(acc.1);
    let mut i = 160usize;
    while i <= len {
        acc = mix32b(
            acc,
            &input[i - 32..],
            &input[i - 16..],
            &KSECRET[3 + i - 160..],
        );
        i += 32;
    }
    // 末 32 字节（镜像序 + 秘密偏移 103——SECRET_SIZE_MIN − MIDSIZE_LASTOFFSET − 16）。
    acc = mix32b(acc, &input[len - 16..], &input[len - 32..], &KSECRET[103..]);
    let (alo, ahi) = acc;
    let lo = avalanche3(alo.wrapping_add(ahi));
    let hi = 0u64.wrapping_sub(avalanche3(
        alo.wrapping_mul(P1)
            .wrapping_add(ahi.wrapping_mul(P4))
            .wrapping_add((len as u64).wrapping_mul(P2)),
    ));
    (lo, hi)
}

/// XXH3-128（seed 恒 0；输入任意字节串，空串合法）。
///
/// 调度面与 xxHash v0.8.2 `XXH3_128bits` 一致：≤16 三子径 → 17..128 →
/// 129..240 → 长路径。
pub fn xxh3_128(input: &[u8]) -> Xxh3_128 {
    let len = input.len();
    let (low, high) = if len <= 16 {
        if len > 8 {
            len_9to16_128b(input)
        } else if len >= 4 {
            len_4to8_128b(input)
        } else if len > 0 {
            len_1to3_128b(input)
        } else {
            // len == 0：纯秘密域雪崩（`XXH3_len_0to16_128b` len=0 面）。
            let bitflipl = read_u64(&KSECRET[64..]) ^ read_u64(&KSECRET[72..]);
            let bitfliph = read_u64(&KSECRET[80..]) ^ read_u64(&KSECRET[88..]);
            (avalanche64(bitflipl), avalanche64(bitfliph))
        }
    } else if len <= 128 {
        len_17to128_128b(input)
    } else if len <= 240 {
        len_129to240_128b(input)
    } else {
        hash_long(input)
    };
    Xxh3_128 { low, high }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::xxh3_128;
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

    /// XXH3-128 黄金向量数据（确定性模式：`(i*31+7) & 0xFF`；与生成脚本一致）。
    fn golden_data(n: usize, buf: &mut [u8; 20000]) -> &[u8] {
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            *b = ((i * 31 + 7) & 0xFF) as u8;
        }
        &buf[..n]
    }

    /// XXH3-128 规范黄金向量（40 长度点 × (len, high, low)；python `xxhash`
    /// C 参考实现生成 seed=0——`scripts/gen_xxh3_vectors.py`；覆盖三径全部
    /// 边界：1to3/4to8/9to16/17to128/129to240/长路径 + 条带/块边界）。
    #[test]
    fn xxh3_spec_vectors() {
        const V: &[(usize, u64, u64)] = &[
            (0, 0x99AA_06D3_0147_98D8, 0x6001_C324_468D_497F),
            (1, 0x495B_6207_3EF7_0CA4, 0x4C5C_CA45_D0F4_811F),
            (2, 0x12B2_847A_A0DE_5AAA, 0xA7E2_50C9_7710_FF27),
            (3, 0x46F6_6CB9_3538_1565, 0x15F7_093B_173D_005C),
            (4, 0x7FEF_EEFF_B4D0_EAB3, 0xB987_CA5D_9241_572A),
            (7, 0x9194_EFBD_DB0D_752C, 0x90D8_D40E_8B5C_A9C4),
            (8, 0x803C_675A_846C_C6C2, 0x56BB_836C_EB6D_4BAA),
            (9, 0xD465_5687_2D23_0F22, 0x4376_6735_8031_0154),
            (16, 0x650F_E308_C566_747D, 0xF853_DD94_614D_FA07),
            (17, 0x1821_7300_B513_2D5A, 0x78C3_49FE_81B2_F26C),
            (32, 0x3220_FF5F_E507_B3C0, 0x5726_E079_716C_6A62),
            (63, 0x44E1_980E_B144_E6C8, 0x87E6_BB29_553B_8E31),
            (64, 0xF9BF_A77D_A089_1A96, 0x36C5_F7E5_4742_6BC4),
            (65, 0x5642_C5D3_8E6E_787D, 0xD0D1_D788_4590_A330),
            (127, 0x3117_B681_087B_4EF4, 0x8A02_B1F7_5C55_6AC3),
            (128, 0xB4F8_7B99_D2DB_8A51, 0x1E04_FAD9_F0CA_CB4D),
            (129, 0x6881_6336_50CD_8924, 0xC51B_C887_976A_EF63),
            (159, 0x23D7_3D2C_FA83_C4B0, 0x4710_980F_5843_2F1D),
            (160, 0xC000_B788_DF6D_BBC4, 0xF661_814E_6669_7391),
            (191, 0xA738_C169_D152_E2BC, 0x07E4_807E_2B80_6AC0),
            (192, 0xD447_9CAA_4BEA_0DCE, 0xD8D6_FBD4_7501_6236),
            (223, 0x1F6F_96FD_FD9F_843C, 0xD9D9_EFA6_0133_F611),
            (224, 0x20D5_C625_7506_48FC, 0x202D_FE46_7F90_949C),
            (239, 0x75AC_B2EC_D970_B399, 0x6DF5_C761_356A_5057),
            (240, 0xDE57_AAB3_1E77_A2FF, 0x93E1_7383_3F75_AB66),
            (241, 0x92B9_91A7_192F_3F08, 0x0B3B_6309_48CE_4A00),
            (255, 0x3E68_B7E4_15CE_7E5C, 0x8993_2170_686C_DD9A),
            (256, 0x24EE_3063_3CA5_2C6A, 0xEC85_B75B_AFE6_CA74),
            (257, 0x0F84_9A4F_3E33_B6C2, 0x12EF_0FF6_3384_1459),
            (511, 0xF7B1_9289_ED75_6843, 0x0FEC_8FB6_EAE1_DF8B),
            (512, 0x2080_C7D3_6A7E_A4BB, 0xEFC2_E52D_1C2F_FBAA),
            (513, 0x5743_258C_AA8D_9322, 0xEB39_B64B_9DF9_8485),
            (1023, 0x8E8E_D756_AA1F_01FA, 0xF0D3_30CE_2B33_00FB),
            (1024, 0x4C17_271C_906D_F792, 0x23BC_880E_BF0D_29C6),
            (1025, 0x70A4_EB1B_9691_D77F, 0xC09F_DFBC_398C_7D82),
            (2048, 0xB318_976B_177A_38C7, 0x19F6_F9C9_8733_1373),
            (4096, 0x49D3_842B_33D5_1E8A, 0xA3C1_9F81_74CD_E0BB),
            (8192, 0xC724_E692_3329_F38C, 0x0CDD_0953_4F24_7713),
            (16384, 0x2168_2671_02D5_B431, 0xC76B_744A_2648_8B31),
            (20000, 0x9A78_8920_73B6_83E8, 0x6C04_8A02_5190_66F9),
        ];
        let mut buf = [0u8; 20000];
        for (n, hi, lo) in V {
            let d = xxh3_128(golden_data(*n, &mut buf));
            assert_eq!((d.high, d.low), (*hi, *lo), "len {n} 黄金向量失配");
        }
    }

    /// XXH3-128 经典短样本锚定（规范域代表性字符串）。
    #[test]
    fn xxh3_classic_short() {
        assert_eq!(xxh3_128(b"").low, 0x6001_C324_468D_497F);
        assert_eq!(xxh3_128(b"").high, 0x99AA_06D3_0147_98D8);
        assert_eq!(xxh3_128(b"a").high, 0xA96F_AF70_5AF1_6834);
        assert_eq!(xxh3_128(b"a").low, 0xE6C6_32B6_1E96_4E1F);
        assert_eq!(xxh3_128(b"abc").high, 0x06B0_5AB6_733A_6185);
        assert_eq!(xxh3_128(b"abc").low, 0x78AF_5F94_892F_3950);
        assert_eq!(xxh3_128(b"abcd").high, 0x8D6B_6038_3DFA_90C2);
        assert_eq!(xxh3_128(b"abcd").low, 0x1BE7_9EEC_D1B1_353D);
        assert_eq!(xxh3_128(b"Call me Ishmael.").high, 0xFB94_FF73_58ED_06D2);
        assert_eq!(xxh3_128(b"Call me Ishmael.").low, 0x674C_A85D_64E9_C2E9);
    }

    /// XXH3-128 条带边界扫描：64 字节条带边界前后（56..72）长度邻域摘要互异。
    #[test]
    fn xxh3_stripe_boundary_lengths_stable() {
        let base = [0x5Au8; 128];
        for n in 56..72usize {
            let a = xxh3_128(&base[..n]);
            let b = xxh3_128(&base[..n + 1]);
            assert_ne!(
                (a.high, a.low),
                (b.high, b.low),
                "len {n} 与 {n}+1 摘要撞车"
            );
        }
    }

    /// XXH3-128 单位翻转雪崩：100 字节输入逐位翻转（128 位域）摘要必变。
    #[test]
    fn xxh3_bit_flip_changes_digest() {
        let mut input = [0u8; 100];
        input[..].fill(0x3C);
        let base = xxh3_128(&input);
        for byte in [40usize, 41, 42, 43, 60, 61, 62, 63] {
            for bit in 0..8usize {
                let mut flipped = input;
                flipped[byte] ^= 1 << bit;
                let d = xxh3_128(&flipped);
                assert_ne!(
                    (d.high, d.low),
                    (base.high, base.low),
                    "byte {byte} bit {bit} 翻转摘要未变"
                );
            }
        }
    }

    /// XXH3-128 盘上代表向量：超级块校验域规模（496B）与节点满块（16 KiB）
    /// 的确定性模式（`(i*13+5) & 0xFF`）锚定——C1b 盘上接入的宿主回归锚。
    #[test]
    fn xxh3_onscale_anchors() {
        let mut buf = [0u8; 16384];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i * 13 + 5) & 0xFF) as u8;
        }
        let sb = xxh3_128(&buf[..496]);
        assert_eq!(
            (sb.high, sb.low),
            (0x046B_B44B_E65B_28FE, 0xC5AD_6E9F_64F3_3C0C)
        );
        let node = xxh3_128(&buf);
        assert_eq!(
            (node.high, node.low),
            (0x915B_BF42_D129_5B2C, 0x6D94_8893_57A6_08E9)
        );
    }

    /// 16 字节小端序列：low 先行（盘上编码约定自证）。
    #[test]
    fn xxh3_le_bytes_layout() {
        let d = xxh3_128(b"abc");
        let le = d.to_le_bytes();
        assert_eq!(&le[..8], d.low.to_le_bytes().as_slice());
        assert_eq!(&le[8..], d.high.to_le_bytes().as_slice());
    }
}
