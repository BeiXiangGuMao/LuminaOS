//! harbor::ld::exec 宿主单元测试全谱（M46-LDEXEC49 笔55——机械执行面
//! 13 例：ET_DYN 结构判读 / 拒收矩阵 / 装载映射并权 / 分级缓冲 BSS /
//! 重定位四类写面 / 惰性绑定 / GNU 哈希桶链 / TLS Variant II 布点 /
//! init/fini 互逆序 / dlopen 族状态机 / auxv 入口契约 / 四段打点 /
//! NonZero 类型码）。

use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use super::*;
use crate::ld::dl_new_hash;

/// PF_X。
pub const PF_X: u32 = 1;
/// PF_W。
pub const PF_W: u32 = 2;
/// PF_R。
pub const PF_R: u32 = 4;

/// 合成 ET_DYN 共享对象（ld-lumina.so 形态标本）：
/// RX 段 @0x2000（0x400 代码 + strtab + symtab + gnu_hash + rela）、
/// RW 段 @0x3000（0x200 filesz GOT/数组 + 0x2000 memsz BSS 尾 +
/// 0x110 PT_DYNAMIC）、PT_TLS @0x3000（memsz 32 / align 16）。
fn synth_so() -> Vec<u8> {
    let mut v = vec![0u8; 0x3400];
    // ---- ELF 头 ----
    v[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    v[4] = 2; // ELFCLASS64
    v[5] = 1; // ELFDATA2LSB
    v[6] = 1; // EV_CURRENT
    v[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    v[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    v[0x18..0x20].copy_from_slice(&0x2000u64.to_le_bytes()); // e_entry
    v[0x20..0x28].copy_from_slice(&(EHDR_LEN as u64).to_le_bytes()); // e_phoff
    v[0x36..0x38].copy_from_slice(&(PHDR_LEN as u16).to_le_bytes());
    v[0x38..0x3A].copy_from_slice(&4u16.to_le_bytes()); // phnum = 4

    // ---- 程序头（EHDR_LEN 起，各 56B）：LOAD RX / LOAD RW / TLS / DYNAMIC ----
    let ph = |i: usize| EHDR_LEN + i * PHDR_LEN;
    // ① PT_LOAD RX @0x2000 file 0x2000 len 0x400
    v[ph(0)..ph(0) + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    v[ph(0) + 4..ph(0) + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    v[ph(0) + 8..ph(0) + 16].copy_from_slice(&0x2000u64.to_le_bytes());
    v[ph(0) + 16..ph(0) + 24].copy_from_slice(&0x2000u64.to_le_bytes());
    v[ph(0) + 32..ph(0) + 40].copy_from_slice(&0x400u64.to_le_bytes());
    v[ph(0) + 40..ph(0) + 48].copy_from_slice(&0x400u64.to_le_bytes());
    // ② PT_LOAD RW @0x3000 file 0x3000 filesz 0x200 memsz 0x2000
    v[ph(1)..ph(1) + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    v[ph(1) + 4..ph(1) + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
    v[ph(1) + 8..ph(1) + 16].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(1) + 16..ph(1) + 24].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(1) + 32..ph(1) + 40].copy_from_slice(&0x200u64.to_le_bytes());
    v[ph(1) + 40..ph(1) + 48].copy_from_slice(&0x2000u64.to_le_bytes());
    // ③ PT_TLS @0x3000 memsz 32 align 16
    v[ph(2)..ph(2) + 4].copy_from_slice(&PT_TLS.to_le_bytes());
    v[ph(2) + 8..ph(2) + 16].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(2) + 16..ph(2) + 24].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(2) + 40..ph(2) + 48].copy_from_slice(&32u64.to_le_bytes());
    v[ph(2) + 48..ph(2) + 56].copy_from_slice(&16u64.to_le_bytes());
    // ④ PT_DYNAMIC @0x3180 filesz 0x110
    v[ph(3)..ph(3) + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
    v[ph(3) + 8..ph(3) + 16].copy_from_slice(&0x3180u64.to_le_bytes());
    v[ph(3) + 16..ph(3) + 24].copy_from_slice(&0x3180u64.to_le_bytes());
    v[ph(3) + 32..ph(3) + 40].copy_from_slice(&0x110u64.to_le_bytes());

    // ---- RX 段内容 ----
    // 代码载荷 @0x2000（16B——e_entry 同域）
    v[0x2000..0x2010].copy_from_slice(&[
        0x48, 0x89, 0xF8, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x48, 0x89, 0xF8, 0xC3, 0x90, 0x90, 0x90,
        0x90,
    ]);
    // strtab @0x2040："\0libstart\0libhelp\0libdyn.so\0"（STRSZ = 40）
    let strtab: &[u8] = b"\0libstart\0libhelp\0libdyn.so\0";
    v[0x2040..0x2040 + strtab.len()].copy_from_slice(strtab);
    // symtab @0x2080：sym0 UNDEF / sym1 name=1 val=0x2040 size=8 / sym2
    // name=10 val=0x2008 size=4
    let sym = |i: usize| 0x2080 + i * 24;
    v[sym(1)..sym(1) + 4].copy_from_slice(&1u32.to_le_bytes());
    v[sym(1) + 8..sym(1) + 16].copy_from_slice(&0x2040u64.to_le_bytes());
    v[sym(1) + 16..sym(1) + 24].copy_from_slice(&8u64.to_le_bytes());
    v[sym(2)..sym(2) + 4].copy_from_slice(&10u32.to_le_bytes());
    v[sym(2) + 8..sym(2) + 16].copy_from_slice(&0x2008u64.to_le_bytes());
    v[sym(2) + 16..sym(2) + 24].copy_from_slice(&4u64.to_le_bytes());
    // gnu_hash @0x20C0：nbuckets=2 / symoffset=1 / bloom_size=1 /
    // bloom_shift=8 + bloom word + buckets[2] + chains[2]
    let h1 = dl_new_hash(b"libstart");
    let h2 = dl_new_hash(b"libhelp");
    v[0x20C0..0x20C4].copy_from_slice(&2u32.to_le_bytes());
    v[0x20C4..0x20C8].copy_from_slice(&1u32.to_le_bytes());
    v[0x20C8..0x20CC].copy_from_slice(&1u32.to_le_bytes());
    v[0x20CC..0x20D0].copy_from_slice(&8u32.to_le_bytes());
    let mut bloom = 0u64;
    bloom |= 1u64 << (h1 % 64);
    bloom |= 1u64 << ((h1 >> 8) % 64);
    bloom |= 1u64 << (h2 % 64);
    bloom |= 1u64 << ((h2 >> 8) % 64);
    v[0x20D0..0x20D8].copy_from_slice(&bloom.to_le_bytes());
    // buckets：h1 % 2 与 h2 % 2 落桶（同桶链序 1→2；异桶各置链头）
    let b1 = (h1 % 2) as usize;
    let b2 = (h2 % 2) as usize;
    let bucket_base = 0x20D8;
    v[bucket_base + 4 * b1..bucket_base + 4 * b1 + 4].copy_from_slice(&1u32.to_le_bytes());
    if b2 != b1 {
        v[bucket_base + 4 * b2..bucket_base + 4 * b2 + 4].copy_from_slice(&2u32.to_le_bytes());
    }
    let chain_base = bucket_base + 8;
    let c1 = if b1 == b2 { h1 & !1 } else { h1 | 1 };
    let c2 = h2 | 1;
    v[chain_base..chain_base + 4].copy_from_slice(&c1.to_le_bytes());
    v[chain_base + 4..chain_base + 8].copy_from_slice(&c2.to_le_bytes());
    // rela @0x2200：RELATIVE(GOT0) / GLOB_DAT(sym1) / JUMP_SLOT(sym2) /
    // COPY(sym2)
    let rela = |i: usize| 0x2200 + i * 24;
    let mut wr_rela = |i: usize, off: u64, sym: u32, ty: u32, add: i64| {
        v[rela(i)..rela(i) + 8].copy_from_slice(&off.to_le_bytes());
        let info = ((sym as u64) << 32) | ty as u64;
        v[rela(i) + 8..rela(i) + 16].copy_from_slice(&info.to_le_bytes());
        v[rela(i) + 16..rela(i) + 24].copy_from_slice(&(add as u64).to_le_bytes());
    };
    wr_rela(0, 0x3000, 0, R_X86_64_RELATIVE, 0x40);
    wr_rela(1, 0x3008, 1, R_X86_64_GLOB_DAT, 0);
    wr_rela(2, 0x3010, 2, R_X86_64_JUMP_SLOT, 0);
    wr_rela(3, 0x3018, 2, R_X86_64_COPY, 0);

    // ---- RW 段内容 ----
    // GOT @0x3000：4 槽 0xEE 初值
    for i in 0..4 {
        v[0x3000 + i * 8..0x3000 + i * 8 + 8].fill(0xEE);
    }
    // init_array @0x30C0（2 元）/ fini_array @0x30E0（1 元）
    v[0x30C0..0x30C8].copy_from_slice(&0x2000u64.to_le_bytes());
    v[0x30C8..0x30D0].copy_from_slice(&0x2008u64.to_le_bytes());
    v[0x30E0..0x30E8].copy_from_slice(&0x2000u64.to_le_bytes());

    // ---- 动态表 @0x3180 ----
    let dyn_entries: [(u64, u64); 17] = [
        (DT_NEEDED, 19),
        (DT_STRTAB, 0x2040),
        (DT_STRSZ, 40),
        (DT_SYMTAB, 0x2080),
        (DT_SYMENT, 24),
        (DT_GNU_HASH, 0x20C0),
        (DT_RELA, 0x2200),
        (DT_RELASZ, 96),
        (DT_RELAENT, 24),
        (DT_INIT_ARRAY, 0x30C0),
        (DT_INIT_ARRAYSZ, 16),
        (DT_FINI_ARRAY, 0x30E0),
        (DT_FINI_ARRAYSZ, 8),
        (DT_INIT, 0x2000),
        (DT_FINI, 0x2008),
        (DT_SONAME, 19),
        (DT_FLAGS, 0),
    ];
    for (i, (tag, val)) in dyn_entries.iter().enumerate() {
        let base = 0x3180 + i * 16;
        v[base..base + 8].copy_from_slice(&tag.to_le_bytes());
        v[base + 8..base + 16].copy_from_slice(&val.to_le_bytes());
    }
    // DT_NULL 收尾
    v[0x3180 + 17 * 16..0x3180 + 17 * 16 + 8].fill(0);
    v
}

/// COPY 期望字节面（RX 载荷 0x2008 起 4B——st_value vaddr 域）。
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn staged_copy_expect(base: u64, img: &super::DynImage<'_>) -> [u8; 4] {
    let src = stage_image(base, img).expect("源镜像");
    let sidx = (base + 0x2008 - src.base) as usize;
    [
        src.bytes[sidx],
        src.bytes[sidx + 1],
        src.bytes[sidx + 2],
        src.bytes[sidx + 3],
    ]
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn dyn_parse_golden_et_dyn() {
    let blob = synth_so();
    let img = dyn_parse(&blob).expect("ET_DYN 标本须过");
    assert_eq!(img.entry, 0x2000);
    assert_eq!(img.load_count, 2);
    assert_eq!(img.loads[0].vaddr, 0x2000);
    assert_eq!(img.loads[0].flags & PF_X, PF_X);
    assert_eq!(img.loads[1].mem_len, 0x2000);
    assert_eq!(
        img.tls,
        Some(TlsSeg {
            mem_len: 32,
            align: 16
        })
    );
    assert_eq!(img.dyn_entries.len(), 17);
    assert_eq!(img.dyn_val(DT_SONAME), Some(19));
    assert_eq!(img.needed(), vec![19]);
    assert!(!img.bind_now());
    assert!(!img.static_tls());
    // 虚地址 → 文件偏移翻译（RX / RW 双段覆盖域）
    assert_eq!(img.vaddr_to_file_off(0x2041), Some(0x2041));
    assert_eq!(img.vaddr_to_file_off(0x30C0), Some(0x30C0));
    // 越域 fail-visible
    assert_eq!(img.vaddr_to_file_off(0x9999), None);
}

#[test]
fn dyn_parse_reject_matrix() {
    let good = synth_so();
    // 坏魔数
    let mut bad = good.clone();
    bad[0] = 0;
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadMagic));
    // 非 ET_DYN（ET_EXEC = 2 拒收——动态口径）
    let mut bad = good.clone();
    bad[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadType));
    // 坏机器
    let mut bad = good.clone();
    bad[0x12..0x14].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadMachine));
    // 坏 phentsize
    let mut bad = good.clone();
    bad[0x36..0x38].copy_from_slice(&32u16.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadPhentsize));
    // 截断（头/表）
    assert_eq!(dyn_parse(&good[..32]), Err(LdExecError::Truncated));
    assert_eq!(dyn_parse(&good[..120]), Err(LdExecError::Truncated));
    // PT_DYNAMIC 缺席（phnum 改 2——仅 LOAD 双段）
    let mut bad = good.clone();
    bad[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::NoDynamic));
    // memsz < filesz
    let mut bad = good.clone();
    bad[EHDR_LEN + PHDR_LEN + 40..EHDR_LEN + PHDR_LEN + 48].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadSeg));
    // 页槽交叠（段② vaddr 撞段①页域）
    let mut bad = good.clone();
    bad[EHDR_LEN + PHDR_LEN + 16..EHDR_LEN + PHDR_LEN + 24]
        .copy_from_slice(&0x2500u64.to_le_bytes());
    assert_eq!(dyn_parse(&bad), Err(LdExecError::BadSeg));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn load_plan_merge_and_stage_bss() {
    let blob = synth_so();
    let mut img = dyn_parse(&blob).expect("标本须过");
    let base = 0x1000_0000u64;
    // 页对齐计划面：双段零交 → 双区（RX / RW）
    let plan = load_plan(base, &img).expect("计划面");
    assert_eq!(
        plan[0],
        MapRegion {
            va_start: base + 0x2000,
            va_end: base + 0x3000,
            flags: PF_R | PF_X,
        }
    );
    assert_eq!(plan[1].va_start, base + 0x3000);
    assert_eq!(plan[1].va_end, base + 0x5000);
    assert_eq!(plan[1].flags, PF_R | PF_W);
    // 共享页并权合并（人工改写段② vaddr 入段①页域——计划面并权口径：
    // RX|RW 并权单区）
    img.loads[1].vaddr = 0x2100;
    let plan2 = load_plan(base, &img).expect("并权计划面");
    assert_eq!(plan2.len(), 1);
    assert_eq!(plan2[0].flags, (PF_R | PF_X) | (PF_R | PF_W));
    // 分级缓冲：base 相对寻址 + BSS 尾零
    img.loads[1].vaddr = 0x3000;
    let staged = stage_image(base, &img).expect("分级缓冲");
    assert_eq!(staged.base, base + 0x2000);
    assert_eq!(staged.bytes.len(), 0x3000); // [0x2000, 0x5000)
                                            // RX 载荷在位
    assert_eq!(staged.bytes[0], 0x48);
    // BSS 尾零（RW filesz 0x200 截止——0x3200 后全零）
    assert!(staged.bytes[(base + 0x3210 - staged.base) as usize..]
        .iter()
        .all(|&b| b == 0));
    // 跨度超限 fail-visible
    img.loads[1].mem_len = SPAN_MAX;
    assert_eq!(stage_image(base, &img), Err(LdExecError::SpanTooLarge));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn reloc_relative_globdat_jumpslot_lazy() {
    let blob = synth_so();
    let img = dyn_parse(&blob).expect("标本须过");
    let base = 0x1000_0000u64;
    let entries = rela_entries(&img).expect("RELA 族");
    assert_eq!(entries.len(), 4);
    let mut staged = stage_image(base, &img).expect("分级缓冲");
    // 决议族：sym1 = 0x8000（GLOB_DAT 立即）/ sym2 = None（JUMP_SLOT
    // 惰性域）
    let resolved = [None, Some(0x8000u64), None];
    let sizes = [0u64, 8, 4];
    let env = RelocEnv::new(&resolved, &sizes, false);
    // 首拍：仅 RELATIVE/GLOB_DAT/JUMP_SLOT 三条（COPY 需源域——次拍）
    let rep = reloc_apply(&mut staged, base, &entries[0..3], &env).expect("写面");
    assert_eq!(rep.relative, 1);
    assert_eq!(rep.glob_dat, 1);
    assert_eq!(rep.jump_slot, 0);
    assert_eq!(rep.jump_lazy, 1);
    assert_eq!(rep.copy, 0);
    // RELATIVE：GOT[0] = base + 0x40
    let got0 = (base + 0x3000 - staged.base) as usize;
    assert_eq!(
        u64::from_le_bytes(staged.bytes[got0..got0 + 8].try_into().expect("8B")),
        base + 0x40
    );
    // GLOB_DAT：GOT[1] = 0x8000 直写
    let got1 = got0 + 8;
    assert_eq!(
        u64::from_le_bytes(staged.bytes[got1..got1 + 8].try_into().expect("8B")),
        0x8000
    );
    // JUMP_SLOT 惰性：GOT[2] 初值 0xEE 原貌（PLT/GOT 延迟绑定域）
    let got2 = got1 + 8;
    assert!(staged.bytes[got2..got2 + 8].iter().all(|&b| b == 0xEE));
    // COPY（sym2 size 4，决议值 = 源镜像内 0x2008 对应绝对址——源
    // 定义在 RX 载荷域）；源缺席 = CopySourceMissing（决议在先）
    let resolved_c = [None, Some(0x8000u64), Some(base + 0x2008)];
    let env_c = RelocEnv::new(&resolved_c, &sizes, false);
    let mut s_copy = stage_image(base, &img).expect("分级缓冲");
    assert_eq!(
        reloc_apply(&mut s_copy, base, &entries[3..4], &env_c),
        Err(LdExecError::CopySourceMissing)
    );
    // COPY 实施拍：源镜像注入 → 源字节搬运落 GOT[3]
    let src = stage_image(base, &img).expect("源镜像");
    let env2 = env_c.with_copy_src(&src.bytes, src.base);
    let rep2 = reloc_apply(&mut staged, base, &entries[3..4], &env2).expect("COPY 写面");
    assert_eq!(rep2.copy, 1);
    let got3 = got2 + 8;
    assert_eq!(
        &staged.bytes[got3..got3 + 4],
        &staged_copy_expect(base, &img)
    );
    // bind_now：JUMP_SLOT 未决议即 UndefinedSymbol（立即域）
    let env4 = RelocEnv::new(&resolved, &sizes, true);
    let mut s4 = stage_image(base, &img).expect("分级缓冲");
    assert_eq!(
        reloc_apply(&mut s4, base, &entries[2..3], &env4),
        Err(LdExecError::UndefinedSymbol)
    );
    // GLOB_DAT 未决议：UndefinedSymbol（GLOB_DAT 无惰性域）
    let resolved_none = [None, None, Some(0x8000u64)];
    let env5 = RelocEnv::new(&resolved_none, &sizes, false);
    let mut s5 = stage_image(base, &img).expect("分级缓冲");
    assert_eq!(
        reloc_apply(&mut s5, base, &entries[1..2], &env5),
        Err(LdExecError::UndefinedSymbol)
    );
    // 目标越界 fail-visible
    let bad_entry = [RelaEntry {
        r_offset: 0xF000,
        r_sym: 0,
        r_type: R_X86_64_RELATIVE,
        r_addend: 0,
    }];
    assert_eq!(
        reloc_apply(&mut staged, base, &bad_entry, &env),
        Err(LdExecError::RelocTargetRange)
    );
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn gnu_hash_bucket_chain_lookup() {
    let blob = synth_so();
    let img = dyn_parse(&blob).expect("标本须过");
    assert_eq!(gnu_hash_lookup(&img, b"libstart"), Some(1));
    assert_eq!(gnu_hash_lookup(&img, b"libhelp"), Some(2));
    assert_eq!(gnu_hash_lookup(&img, b"absent"), None);
    // 符号真面读出（sym_get——st_name/st_value/st_size）
    let symtab = img.dyn_val(DT_SYMTAB).expect("SYMTAB");
    let (name, value, size) = img.sym_get(symtab, 1).expect("sym1");
    assert_eq!((name, value, size), (1, 0x2040, 8));
    let nm = img.str_at(img.dyn_val(DT_STRTAB).expect("STRTAB"), name as u64);
    assert_eq!(nm, Some(&b"libstart"[..]));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn tls_layout_variant2_golden() {
    let mut sp = TlsSpace::new(16);
    // 模块 1：memsz 32 align 16 → tp 前域 [tp-32, tp)
    let m1 = sp.alloc(32, 16, 1).expect("模块 1 布点");
    assert_eq!(m1.tp_offset, -32);
    assert_eq!(m1.memsz, 32);
    // 模块 2：memsz 8 align 8 → surplus 上域 tp+16（TCB 16 起对齐）
    let m2 = sp.alloc(8, 8, 2).expect("模块 2 布点");
    assert_eq!(m2.tp_offset, 16);
    assert_eq!(m2.memsz, 8);
    // 模块 3：memsz 4 align 4 → tp+24（surplus 累进）
    let m3 = sp.alloc(4, 4, 3).expect("模块 3 布点");
    assert_eq!(m3.tp_offset, 24);
    // DTV 扩容判读（同源）：现长 2 对 modid 3 → 扩容
    assert!(sp.dtv_needs(2, 3));
    assert!(!sp.dtv_needs(4, 3));
    // 非法对齐（3 非幂 / 0）fail-visible
    let mut sp2 = TlsSpace::new(16);
    assert_eq!(sp2.alloc(8, 3, 1), Err(LdExecError::BadTlsAlign));
    assert_eq!(sp2.alloc(8, 0, 1), Err(LdExecError::BadTlsAlign));
    // 铸号越序 fail-visible（0 号非铸号域 / 跳号）
    let mut sp3 = TlsSpace::new(16);
    assert_eq!(sp3.alloc(8, 8, 0), Err(LdExecError::BadModid));
    assert_eq!(sp3.alloc(8, 8, 2), Err(LdExecError::BadModid));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn init_fini_order_exact_reverse() {
    let faces = [
        ModInitFaces {
            dt_init: true,
            init_array_len: 2,
            fini_array_len: 2,
            dt_fini: true,
        },
        ModInitFaces {
            dt_init: false,
            init_array_len: 1,
            fini_array_len: 1,
            dt_fini: false,
        },
    ];
    let order = [0u32, 1];
    let init = init_order(&faces, &order).expect("init 序");
    assert_eq!(
        init,
        vec![
            CallSite::DtInit(0),
            CallSite::InitArray(0, 0),
            CallSite::InitArray(0, 1),
            CallSite::InitArray(1, 0),
        ]
    );
    let fini = fini_order(&faces, &order).expect("fini 序");
    assert_eq!(
        fini,
        vec![
            CallSite::FiniArray(1, 0),
            CallSite::FiniArray(0, 1),
            CallSite::FiniArray(0, 0),
            CallSite::DtFini(0),
        ]
    );
    // 越界 fail-visible
    assert_eq!(init_order(&faces, &[2]), Err(LdExecError::FaceOutOfRange));
    assert_eq!(fini_order(&faces, &[2]), Err(LdExecError::FaceOutOfRange));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn dl_family_state_machine() {
    let mut st = DlState::new();
    // dlopen 缺席 → error 一次性消费
    assert!(st.dlopen(false, false).is_none());
    assert_eq!(st.dlerror(), Some(DL_ERR_CANNOT_OPEN));
    assert_eq!(st.dlerror(), None); // 读取即清
                                    // dlopen RTLD_GLOBAL → modid 1
    let m1 = st.dlopen(true, true).expect("dlopen");
    assert_eq!(m1, 1);
    // 引用递增 + dlclose Kept/Unloaded
    assert_eq!(st.ref_open(1), Some(2));
    assert_eq!(st.dlclose(1), DlClose::Kept);
    assert_eq!(st.dlclose(1), DlClose::Unloaded(1));
    assert!(st.is_empty());
    // 无效句柄
    assert_eq!(st.dlclose(9), DlClose::Invalid);
    assert_eq!(st.dlerror(), Some(DL_ERR_INVALID_HANDLE));
    // dlsym 查找序三段：exe 命中段位 [0] / 依赖序命中 [1+i] / 全局垫底
    let exe = [7u32];
    let d0 = [7u32, 3];
    let deps: [&[u32]; 1] = [&d0];
    st.dlopen(true, false).expect("dlopen local");
    let syms = [0x1000u64, 0x2000, 0x3000];
    assert_eq!(st.dlsym(7, &exe, &deps, &syms), Some(0x1000));
    assert_eq!(st.dlsym(3, &exe, &deps, &syms), Some(0x2000));
    // 三段皆缺 → UNDEFINED error
    assert_eq!(st.dlsym(42, &exe, &deps, &syms), None);
    assert_eq!(st.dlerror(), Some(DL_ERR_UNDEFINED));
    // RTLD_GLOBAL 插入序快照（dlopen global → 全局段 [末位]）
    let _ = st.dlopen(true, true).expect("dlopen global");
    assert_eq!(st.global_scope(), vec![3]);
    // global 垫底语义实证：3 在依赖序命中先见（0x2000）
    assert_eq!(st.dlsym(3, &exe, &deps, &syms), Some(0x2000));
    // 依赖序不含 3 → global 段命中（末位 0x3000）
    let deps_no3: [&[u32]; 1] = [&[7u32]];
    assert_eq!(st.dlsym(3, &exe, &deps_no3, &syms), Some(0x3000));
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn auxv_probe_entry_contract() {
    // 五目齐备 + AT_NULL 收尾
    let full = [
        (3u64, 0x8000u64), // AT_PHDR
        (4, 56),           // AT_PHENT
        (5, 4),            // AT_PHNUM
        (7, 0x7000_0000),  // AT_BASE
        (9, 0x6000_1000),  // AT_ENTRY
        (0, 0),            // AT_NULL
    ];
    let a = auxv_probe(&full).expect("契约五目");
    assert_eq!(
        a,
        LoaderAuxv {
            phdr: 0x8000,
            phent: 56,
            phnum: 4,
            base: 0x7000_0000,
            entry: 0x6000_1000,
        }
    );
    // 缺 AT_BASE → None fail-visible
    let missing = [(3u64, 0x8000u64), (4, 56), (5, 4), (9, 0x6000)];
    assert!(auxv_probe(&missing).is_none());
    // AT_PHENT ≠ 56 → None
    let bad_ent = [(3u64, 0x8000u64), (4, 32), (5, 4), (7, 0x10), (9, 0x20)];
    assert!(auxv_probe(&bad_ent).is_none());
    // AT_NULL 截断（后随目不扫）
    let truncated = [(3u64, 0x8000u64), (0, 0), (7, 0x7000_0000)];
    assert!(auxv_probe(&truncated).is_none());
}

#[test]
fn ns_to_tenths_and_budget_judge() {
    // 上取整定点：0 → 0 / 1ns → 1 / 99_999 → 1 / 100_000 → 1 / 100_001 → 2
    assert_eq!(ns_to_tenths(0), 0);
    assert_eq!(ns_to_tenths(1), 1);
    assert_eq!(ns_to_tenths(100_000), 1);
    assert_eq!(ns_to_tenths(100_001), 2);
    // 四段判读：满预算绿 / 单段超支定位 + 总闸翻红
    assert_eq!(
        recon_budget_judge(&[12, 10, 5, 3]),
        ([false, false, false, false], true)
    );
    assert_eq!(
        recon_budget_judge(&[13, 10, 5, 3]),
        ([true, false, false, false], false)
    );
    // 段内让渡贴线：总闸绿超支旗单置（crate::ld 同源口径）
    assert_eq!(
        recon_budget_judge(&[13, 9, 5, 3]),
        ([true, false, false, false], true)
    );
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn reloc_family_nz_face() {
    assert_eq!(
        reloc_family(NonZeroU32::new(5).expect("5")),
        Some(R_X86_64_COPY)
    );
    assert_eq!(
        reloc_family(NonZeroU32::new(7).expect("7")),
        Some(R_X86_64_JUMP_SLOT)
    );
    assert_eq!(reloc_family(NonZeroU32::new(9).expect("9")), None);
    assert_eq!(reloc_family(NonZeroU32::new(u32::MAX).expect("MAX")), None);
}
