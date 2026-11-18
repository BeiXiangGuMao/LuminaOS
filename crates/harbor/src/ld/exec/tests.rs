//! harbor::ld::exec 宿主单元测试全谱（M46-LDEXEC49 笔55——机械执行面
//! 13 例：ET_DYN 结构判读 / 拒收矩阵 / 装载映射并权 / 分级缓冲 BSS /
//! 重定位四类写面 / 惰性绑定 / GNU 哈希桶链 / TLS Variant II 布点 /
//! init/fini 互逆序 / dlopen 族状态机 / auxv 入口契约 / 四段打点 /
//! NonZero 类型码；M47-DLOPEN54 笔61 起 +1 例——dlopen 真消费面
//! 链式装载全谱 = 14 例；M48-PLTGOT55 笔63 起 +1 例——PLT/GOT 惰性
//! 绑定电气执行面全谱 = 15 例；M48-DLSYM56 笔64 起 +1 例——dlsym 跨
//! 模块查找电气面全谱 = 16 例）。

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

/// 装载计划消费面（M47-LDCONS53 笔60）：prot_of 翻译域 + exec_plan
/// 三段式动作序列（Mmap R|W 分级窗 ×N → CopyTo 交集拷贝 ×N →
/// Mprotect 终旗 ×N′——同旗区零动作）+ 空计划/无 R 区 fail-visible。
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn exec_plan_consumer_face() {
    // prot_of：gABI 旗 → PROT 位族（R 必含位语义）
    assert_eq!(prot_of(4), Ok(PROT_READ)); // PF_R
    assert_eq!(prot_of(6), Ok(PROT_READ | PROT_WRITE)); // PF_R|PF_W
    assert_eq!(prot_of(5), Ok(PROT_READ | PROT_EXEC)); // PF_R|PF_X
    assert_eq!(prot_of(7), Ok(PROT_READ | PROT_WRITE | PROT_EXEC)); // 全谱
    assert_eq!(prot_of(2), Err(LdExecError::BadSeg)); // PF_W 无 R 拒收
    assert_eq!(prot_of(1), Err(LdExecError::BadSeg)); // PF_X 无 R 拒收
    assert_eq!(prot_of(0), Err(LdExecError::BadSeg)); // 零旗拒收
                                                      // exec_plan 金值：双区计划（RX 前段 + RW 后段——t147 同谱布局）
    let base = 0x1000_0000u64;
    let plan = vec![
        MapRegion {
            va_start: base,
            va_end: base + 0x2000,
            flags: 5, // PF_R|PF_X
        },
        MapRegion {
            va_start: base + 0x2000,
            va_end: base + 0x3000,
            flags: 6, // PF_R|PF_W
        },
    ];
    let staged = StagedImage {
        base,
        bytes: vec![0xAB; 0x3000],
    };
    let acts = exec_plan(&plan, &staged).expect("动作序列");
    // 三段式：Mmap×2（R|W 分级窗）→ CopyTo×2（交集 0x2000 + 0x1000）→
    // Mprotect×1（RX 区终旗；RW 区同旗零动作）
    assert_eq!(
        acts,
        vec![
            MapAction::Mmap {
                va: base,
                len: 0x2000,
                prot: PROT_READ | PROT_WRITE,
            },
            MapAction::Mmap {
                va: base + 0x2000,
                len: 0x1000,
                prot: PROT_READ | PROT_WRITE,
            },
            MapAction::CopyTo {
                va: base,
                src_off: 0,
                len: 0x2000,
            },
            MapAction::CopyTo {
                va: base + 0x2000,
                src_off: 0x2000,
                len: 0x1000,
            },
            MapAction::Mprotect {
                va: base,
                len: 0x2000,
                prot: PROT_READ | PROT_EXEC,
            },
        ],
        "消费序 = 先全量映射、再统一拷贝、后逐区终旗（Linux 共享页序）"
    );
    // 空计划 fail-visible
    let empty: Vec<MapRegion> = vec![];
    assert_eq!(
        exec_plan(&empty, &staged),
        Err(LdExecError::TooManyLoads),
        "空计划显形（load_plan 已闸 0 段——复闸收口）"
    );
    // 无 R 区 fail-visible（prot_of 结构闸透传）
    let no_r = vec![MapRegion {
        va_start: base,
        va_end: base + 0x1000,
        flags: 2, // PF_W 无 PF_R——装载器同款拒收
    }];
    assert_eq!(
        exec_plan(&no_r, &staged),
        Err(LdExecError::BadSeg),
        "无 R 区拒收（Linux 装载器同款）"
    );
    // 间隙零拷贝：计划区后段脱离镜像覆盖域 → 零 CopyTo 动作
    let gap = vec![MapRegion {
        va_start: base + 0x10000,
        va_end: base + 0x11000,
        flags: 6, // PF_R|PF_W——与 staged 零交集
    }];
    let acts_gap = exec_plan(&gap, &staged).expect("间隙计划");
    assert_eq!(
        acts_gap,
        vec![MapAction::Mmap {
            va: base + 0x10000,
            len: 0x1000,
            prot: PROT_READ | PROT_WRITE,
        }],
        "零交集 = 零 CopyTo 零 Mprotect（间隙零拷贝语义）"
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

// ---- M47-DLOPEN54 笔61：dlopen 真消费面（链式装载机械消费） ----

/// 链标本组件开关（声明域 / UNDEF 闭包域 / 定义域可选装配）。
struct ChainSoSpec<'a> {
    /// dynstr 字节面（"\0soname\0...\0" 形——offset 由调用方换算）。
    strtab: &'a [u8],
    /// DT_SONAME strtab 偏移。
    soname_off: u64,
    /// DT_NEEDED strtab 偏移（None = 声明域空——UNDEF 闭包单域判读）。
    needed_off: Option<u64>,
    /// UNDEF 闭包域组件（sym1 = UNDEF 名 + strtab 偏移——RELA GLOB_DAT
    /// 引用 + GNU 哈希零覆盖）。
    undef: Option<(&'a [u8], u64)>,
    /// 定义域组件（sym1 = DEFINED 名 + strtab 偏移——GNU 哈希覆盖
    /// st_value 0x1000 / FUNC / 8B——UNDEF 闭包供给方）。
    def: Option<(&'a [u8], u64)>,
}

/// 链标本合成器（最小 ET_DYN——RX 页 dynstr/dynsym/gnu_hash/rela +
/// RW 页 dynamic；同余式/页槽互斥过 `dyn_parse` 结构闸——链式装载
/// 宿主对账域）。
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn synth_chain_so(spec: &ChainSoSpec<'_>) -> Vec<u8> {
    let mut v = vec![0u8; 0x2100];
    // ---- ELF 头（EHDR + 3 PHDR：LOAD RX / LOAD RW / PT_DYNAMIC） ----
    v[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    v[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    v[0x20..0x28].copy_from_slice(&(EHDR_LEN as u64).to_le_bytes());
    v[0x36..0x38].copy_from_slice(&(PHDR_LEN as u16).to_le_bytes());
    v[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes());
    let ph = |i: usize| EHDR_LEN + i * PHDR_LEN;
    // ① PT_LOAD RX @0x1000 filesz=memsz=0x100（内容页）
    v[ph(0)..ph(0) + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    v[ph(0) + 4..ph(0) + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    v[ph(0) + 8..ph(0) + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    v[ph(0) + 16..ph(0) + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    v[ph(0) + 32..ph(0) + 40].copy_from_slice(&0x100u64.to_le_bytes());
    v[ph(0) + 40..ph(0) + 48].copy_from_slice(&0x100u64.to_le_bytes());
    // ② PT_LOAD RW @0x3000 filesz=memsz=0x100（dynamic 页）
    v[ph(1)..ph(1) + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    v[ph(1) + 4..ph(1) + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
    v[ph(1) + 8..ph(1) + 16].copy_from_slice(&0x2000u64.to_le_bytes());
    v[ph(1) + 16..ph(1) + 24].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(1) + 32..ph(1) + 40].copy_from_slice(&0x100u64.to_le_bytes());
    v[ph(1) + 40..ph(1) + 48].copy_from_slice(&0x100u64.to_le_bytes());
    // ③ PT_DYNAMIC @0x3000 filesz 0x100
    v[ph(2)..ph(2) + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
    v[ph(2) + 4..ph(2) + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
    v[ph(2) + 8..ph(2) + 16].copy_from_slice(&0x2000u64.to_le_bytes());
    v[ph(2) + 16..ph(2) + 24].copy_from_slice(&0x3000u64.to_le_bytes());
    v[ph(2) + 32..ph(2) + 40].copy_from_slice(&0x100u64.to_le_bytes());
    // ---- RX 页内容 @0x1000：dynstr → dynsym → gnu_hash → rela ----
    v[0x1000..0x1000 + spec.strtab.len()].copy_from_slice(spec.strtab);
    let mut have_gnu = false;
    if spec.undef.is_some() || spec.def.is_some() {
        // dynsym @0x1040：sym0 null（零槽）+ sym1 @0x1058（UNDEF 或 DEFINED）
        let (name_off, info, shndx, val, size) = match (spec.undef, spec.def) {
            (Some((_, off)), None) => (off, 0x10u8, 0u16, 0u64, 0u64), // UNDEF GLOBAL
            (None, Some((_, off))) => (off, 0x12u8, 1u16, 0x1000u64, 8u64), // DEFINED GLOBAL|FUNC
            _ => unreachable!("undef/def 单域装配"),
        };
        v[0x1058..0x1058 + 4].copy_from_slice(&(name_off as u32).to_le_bytes()); // st_name
        v[0x1058 + 4] = info; // st_info
        v[0x1058 + 5] = 0; // st_other
        v[0x1058 + 6..0x1058 + 8].copy_from_slice(&shndx.to_le_bytes()); // st_shndx
        v[0x1058 + 8..0x1058 + 16].copy_from_slice(&val.to_le_bytes()); // st_value
        v[0x1058 + 16..0x1058 + 24].copy_from_slice(&size.to_le_bytes()); // st_size
                                                                          // gnu_hash @0x1080：header + bloom(8B) + buckets[1]（+ chains[1]
                                                                          // 定义域单符号）——UNDEF 域 bloom 零位零桶（零覆盖判读域）
        let hdr = 0x1080;
        v[hdr..hdr + 4].copy_from_slice(&1u32.to_le_bytes()); // nbuckets
        v[hdr + 4..hdr + 8].copy_from_slice(&1u32.to_le_bytes()); // symoffset
        v[hdr + 8..hdr + 12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size
        v[hdr + 12..hdr + 16].copy_from_slice(&0u32.to_le_bytes()); // bloom_shift
        let mut bloom = 0u64;
        let mut bucket0 = 0u32;
        let mut chain0 = 0u32;
        if let Some((nm, _)) = spec.def {
            let h = dl_new_hash(nm);
            bloom |= 1u64 << (h % 64); // 双位同位（bloom_shift = 0——单位即双位，语义同生成器）
            bucket0 = 1;
            chain0 = h | 1;
        }
        v[hdr + 16..hdr + 24].copy_from_slice(&bloom.to_le_bytes());
        v[hdr + 24..hdr + 28].copy_from_slice(&bucket0.to_le_bytes());
        v[hdr + 28..hdr + 32].copy_from_slice(&chain0.to_le_bytes());
        have_gnu = true;
        // rela @0x10C0：UNDEF 域 = GLOB_DAT(sym1)；定义域零 RELA
        if spec.undef.is_some() {
            let r = 0x10C0;
            v[r..r + 8].copy_from_slice(&0x3000u64.to_le_bytes()); // GOT 槽
            let info = (1u64 << 32) | R_X86_64_GLOB_DAT as u64;
            v[r + 8..r + 16].copy_from_slice(&info.to_le_bytes());
            v[r + 16..r + 24].copy_from_slice(&0u64.to_le_bytes());
        }
    }
    // ---- RW 页内容（文件偏移 0x2000——p_offset ≡ p_vaddr mod PAGE） ----
    let mut dyn_entries: Vec<(u64, u64)> = Vec::new();
    if let Some(off) = spec.needed_off {
        dyn_entries.push((DT_NEEDED, off));
    }
    dyn_entries.push((DT_STRTAB, 0x1000));
    dyn_entries.push((DT_STRSZ, spec.strtab.len() as u64));
    if have_gnu {
        dyn_entries.push((DT_SYMTAB, 0x1040));
        dyn_entries.push((DT_SYMENT, 24));
        dyn_entries.push((DT_GNU_HASH, 0x1080));
        if spec.undef.is_some() {
            dyn_entries.push((DT_RELA, 0x10C0));
            dyn_entries.push((DT_RELASZ, 24));
            dyn_entries.push((DT_RELAENT, 24));
        }
    }
    dyn_entries.push((DT_SONAME, spec.soname_off));
    for (i, (tag, val)) in dyn_entries.iter().enumerate() {
        let base = 0x2000 + i * 16;
        v[base..base + 8].copy_from_slice(&tag.to_le_bytes());
        v[base + 8..base + 16].copy_from_slice(&val.to_le_bytes());
    }
    v
}

/// dlopen 真消费面全谱（M47-DLOPEN54 笔61）——八域对账：
/// 注册表登记/重名/越界拒收；DT_NEEDED 声明域实边；UNDEF 决议闭包
/// as-needed 派生实边；BFS 装载序；dlopen 真消费链（群组插序/幂等域/
/// error 槽一次性消费）；依赖环；声明域缺件；root 越界——fail-visible
/// 全显形。
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn dl_chain_consumer_face() {
    // 标本族：app --DT_NEEDED--> dyn（声明域实边）；appu --UNDEF
    // 闭包--> depu（"shared_fn" 名匹配派生实边——GNU 哈希定义者查边）；
    // 闭环对 cya<->cyb（三色判读域）；缺件对 ghosty→libnowhere。
    let app = synth_chain_so(&ChainSoSpec {
        strtab: b"\0libapp.so\0libdyn.so\0",
        soname_off: 1,
        needed_off: Some(11), // "libdyn.so"
        undef: None,
        def: None,
    });
    let dep = synth_chain_so(&ChainSoSpec {
        strtab: b"\0libdyn.so\0",
        soname_off: 1,
        needed_off: None,
        undef: None,
        def: None,
    });
    let appu = synth_chain_so(&ChainSoSpec {
        strtab: b"\0appu.so\0shared_fn\0",
        soname_off: 1,
        needed_off: None, // 声明域空——UNDEF 闭包单域派生
        undef: Some((b"shared_fn", 9)),
        def: None,
    });
    let depu = synth_chain_so(&ChainSoSpec {
        strtab: b"\0depu.so\0shared_fn\0",
        soname_off: 1,
        needed_off: None,
        undef: None,
        def: Some((b"shared_fn", 9)),
    });
    let cyc_a = synth_chain_so(&ChainSoSpec {
        strtab: b"\0cya.so\0cyb.so\0",
        soname_off: 1,
        needed_off: Some(8), // "cyb.so"
        undef: None,
        def: None,
    });
    let cyc_b = synth_chain_so(&ChainSoSpec {
        strtab: b"\0cyb.so\0cya.so\0",
        soname_off: 1,
        needed_off: Some(8), // "cya.so"
        undef: None,
        def: None,
    });
    let ghost = synth_chain_so(&ChainSoSpec {
        strtab: b"\0ghosty.so\0libnowhere.so\0",
        soname_off: 1,
        needed_off: Some(10), // "libnowhere.so"（注册表缺席）
        undef: None,
        def: None,
    });

    // ① 注册表：登记 + 重名拒收 + root 越界
    let mut reg = ChainRegistry::new();
    assert_eq!(reg.add(b"libapp.so", &app).expect("登记 app"), 0);
    assert_eq!(reg.add(b"libdyn.so", &dep).expect("登记 dyn"), 1);
    assert_eq!(
        reg.add(b"libapp.so", &dep).unwrap_err(),
        LdExecError::RegistryRange,
        "重名拒收 fail-visible"
    );
    assert_eq!(reg.len(), 2);
    assert_eq!(reg.find(b"libdyn.so"), Some(1));
    assert_eq!(reg.find(b"libghost.so"), None);
    assert_eq!(
        dl_chain_order(&reg, 9).unwrap_err(),
        LdExecError::RegistryRange,
        "root 越界 fail-visible"
    );

    // ② 邻接派生：声明域实边 app→dyn + dyn 零边（双域并集）
    let adj = dl_adjacency(&reg).expect("邻接派生");
    assert_eq!(adj, vec![vec![1], vec![]], "DT_NEEDED 声明域实边派生");

    // ③ DT_NEEDED 装载序：BFS 层序 [0,1]（语义核机械消费）
    assert_eq!(
        dl_chain_order(&reg, 0).expect("装载序"),
        vec![0, 1],
        "BFS 装载序（root 居首 + 依赖随行）"
    );

    // ④ dlopen 真消费链：modid 序 + RTLD_GLOBAL 群组插序 + 幂等域 +
    //    error 槽一次性消费
    let mut dl = DlState::new();
    let ids = dl_open_chain(&mut dl, &reg, b"libapp.so", true).expect("消费链");
    assert_eq!(ids, vec![1, 2], "modid 序 = 装载序同谱");
    assert_eq!(dl.len(), 2);
    assert_eq!(dl.global_scope(), vec![1, 2], "群组插序（RTLD_GLOBAL 域）");
    assert_eq!(dl.ref_open(ids[0]), Some(2), "幂等域（二次 open 引用递增）");
    assert_eq!(dl.dlclose(ids[0]), DlClose::Kept, "引用仍在——册保留");
    assert_eq!(
        dl.dlclose(ids[0]),
        DlClose::Unloaded(ids[0]),
        "计数归零出册"
    );
    assert_eq!(
        dl_open_chain(&mut dl, &reg, b"libghost.so", false).unwrap_err(),
        LdExecError::NeededMissing,
        "根名缺件 fail-visible"
    );
    assert_eq!(dl.dlerror(), Some(DL_ERR_CANNOT_OPEN), "error 槽落账");
    assert_eq!(dl.dlerror(), None, "一次性消费（POSIX 口径）");

    // ⑤ UNDEF 决议闭包：声明域空 × "shared_fn" 名匹配 → as-needed 实边
    let mut reg2 = ChainRegistry::new();
    reg2.add(b"appu.so", &appu).expect("登记 appu");
    reg2.add(b"depu.so", &depu).expect("登记 depu");
    let adj2 = dl_adjacency(&reg2).expect("闭包派生");
    assert_eq!(
        adj2,
        vec![vec![1], vec![]],
        "UNDEF 闭包 as-needed 实边（GNU 哈希定义者查边）"
    );
    assert_eq!(dl_chain_order(&reg2, 0).expect("闭包装载序"), vec![0, 1]);

    // ⑥ 依赖环：三色判读 NeededCycle
    let mut reg3 = ChainRegistry::new();
    reg3.add(b"cya.so", &cyc_a).expect("登记 cya");
    reg3.add(b"cyb.so", &cyc_b).expect("登记 cyb");
    assert_eq!(
        dl_chain_order(&reg3, 0).unwrap_err(),
        LdExecError::NeededCycle,
        "依赖环 fail-visible（三色判读）"
    );

    // ⑦ 声明域缺件：needed 名注册表缺席 NeededMissing
    let mut reg4 = ChainRegistry::new();
    reg4.add(b"ghosty.so", &ghost).expect("登记 ghosty");
    assert_eq!(
        dl_chain_order(&reg4, 0).unwrap_err(),
        LdExecError::NeededMissing,
        "声明域缺件 fail-visible（ELF 装载一次语义零容忍）"
    );

    // ⑧ 定容闸：8 件满 + 第 9 件拒收
    const CAP_NAMES: [&[u8]; CHAIN_REG_CAP] = [
        b"m0.so", b"m1.so", b"m2.so", b"m3.so", b"m4.so", b"m5.so", b"m6.so", b"m7.so",
    ];
    let cap_blob = synth_chain_so(&ChainSoSpec {
        strtab: b"\0m.so\0",
        soname_off: 1,
        needed_off: None,
        undef: None,
        def: None,
    });
    let mut reg5 = ChainRegistry::new();
    for nm in CAP_NAMES {
        reg5.add(nm, &cap_blob).expect("定容内登记");
    }
    assert_eq!(
        reg5.add(b"overflow.so", &dep).unwrap_err(),
        LdExecError::RegistryRange,
        "定容超限拒收（8 件满）"
    );
}

/// PLT/GOT 惰性绑定电气执行面全谱（M48-PLTGOT55 笔63）——七域对账：
/// 接线（PLT 存根初值 = plt0+stride×(idx+1) 经典布局）；首调解析兑现
/// （Stub→Resolved 槽值翻转）；次调幂等（已决议槽 resolve = Ok(false)
/// 零增）；未接线槽拒收（LazyUnbound）；槽号越界拒收（LazySlotRange
/// ——rel_idx ≥ LAZY_SLOT_CAP）；容量闸（16 槽满 + 第 17 槽拒收）；
/// lazy_wire 记账对账（wired = jump_lazy 同镜像守恒 + bound = 立即域）。
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn pltgot_lazy_bind_exec_face() {
    const PLT0: u64 = 0x4000_1000;
    const GOT3: u64 = 0x2_0000_0018;
    const GOT4: u64 = 0x2_0000_0020;
    const TARGET: u64 = 0x4000_2000;

    // ① 接线：PLT 存根初值 = plt0 + stride × (rel_idx + 1)
    let mut got = LazyGot::new(PLT0);
    let s1 = got.wire(GOT3, 0).expect("接线 slot0");
    assert_eq!(s1, PLT0 + 0x10, "存根地址 = plt0 + 16×(0+1)");
    assert_eq!(got.state(GOT3), Some(LazySlotState::Stub(s1)));
    assert_eq!(got.value(GOT3), Some(s1), "首调前槽值 = PLT 存根");
    assert_eq!(got.len(), 1);
    // 重复接线幂等（同槽同存根覆写）
    assert_eq!(got.wire(GOT3, 0).expect("重复接线"), s1, "接线幂等域");
    assert_eq!(got.len(), 1, "同槽不重复入册");

    // ② 首调解析兑现：Stub → Resolved
    assert!(got.resolve(GOT3, TARGET).expect("首调解析"));
    assert_eq!(got.state(GOT3), Some(LazySlotState::Resolved(TARGET)));
    assert_eq!(got.value(GOT3), Some(TARGET), "首调后槽值 = 决议地址");
    assert_eq!(got.resolved_count(), 1);

    // ③ 次调幂等：已决议槽 resolve = Ok(false)（直达域——resolver 零重入）
    assert!(!got.resolve(GOT3, TARGET).expect("次调幂等"));
    assert_eq!(got.resolved_count(), 1, "重复解析零增");

    // ④ 未接线槽拒收：LazyUnbound
    assert_eq!(
        got.resolve(GOT4, TARGET).unwrap_err(),
        LdExecError::LazyUnbound,
        "未接线槽 resolver 步 fail-visible"
    );
    assert_eq!(got.value(GOT4), None);

    // ⑤ 槽号越界拒收：LazySlotRange（rel_idx ≥ LAZY_SLOT_CAP）
    let mut got2 = LazyGot::new(PLT0);
    assert_eq!(
        got2.wire(GOT3, LAZY_SLOT_CAP).unwrap_err(),
        LdExecError::LazySlotRange,
        "槽号越界 fail-visible"
    );
    assert!(got2.is_empty(), "拒收域零残留");

    // ⑥ 容量闸：16 槽满 + 第 17 槽拒收
    for i in 0..LAZY_SLOT_CAP {
        got2.wire(0x2_0000_1000 + 8 * i as u64, i)
            .expect("容量内接线");
    }
    assert_eq!(got2.len(), LAZY_SLOT_CAP);
    assert_eq!(
        got2.wire(0x2_0000_2000, LAZY_SLOT_CAP - 1).unwrap_err(),
        LdExecError::LazySlotRange,
        "容量超限拒收（16 槽满）"
    );

    // ⑦ lazy_wire 记账对账：wired = jump_lazy 同镜像守恒 + bound = 立即域
    // 标本 RELA：[0] RELATIVE / [1] JUMP_SLOT 未决议（lazy）/ [2]
    // JUMP_SLOT 已决议（bound）/ [3] GLOB_DAT（非族跳过）
    let mk = |off: u64, sym: u32, typ: u32| RelaEntry {
        r_offset: off,
        r_sym: sym,
        r_type: typ,
        r_addend: 0,
    };
    let entries = vec![
        mk(0x100, 0, R_X86_64_RELATIVE),
        mk(0x108, 2, R_X86_64_JUMP_SLOT),
        mk(0x110, 3, R_X86_64_JUMP_SLOT),
        mk(0x118, 4, R_X86_64_GLOB_DAT),
    ];
    let resolved = vec![None, None, None, Some(TARGET), None];
    // 惰性域（bind_now = false）：wired=1（slot1 未决议）/ bound=1（slot3 已决议）
    let rep = lazy_wire(&entries, &resolved, false).expect("接线判读");
    assert_eq!(
        rep,
        LazyWireReport { wired: 1, bound: 1 },
        "lazy_wire 惰性/立即分账"
    );
    // bind_now 域：全 JUMP_SLOT 立即（wired=0 / bound=2）
    let rep_now = lazy_wire(&entries, &resolved, true).expect("立即判读");
    assert_eq!(rep_now, LazyWireReport { wired: 0, bound: 2 });
    // 空表：零账
    let rep0 = lazy_wire(&[], &resolved, false).expect("空表");
    assert_eq!(rep0, LazyWireReport::default());
}

/// dlsym 跨模块查找电气面全谱（M48-DLSYM56 笔64）——七域对账：
/// root 域命中（exe 域先见者胜）；依赖域命中（BFS 序段位定位）；
/// 全链缺席 Ok(None)（决议零虚构）；error 槽一次性消费（POSIX 口径）；
/// root 越界拒收；bases 欠长拒收；决议地址 = base + st_value 兑现。
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn dl_sym_chain_face() {
    // 标本族（synth_chain_so 同谱）：appu 定义 "shared_fn" @0x1000 /
    // depu 定义 "shared_fn" @0x2000 + "dep_only" @0x2008——同名先见者胜
    // 域 + 依赖独占域。
    let mk_so = |name: &[u8], needed: Option<&[u8]>, syms: &[(&[u8], u64)]| -> Vec<u8> {
        // strtab = \0 name \0 sym...；dynsym 3 目内；RELA 空；GNU 头 +
        // bloom + 桶链。布局：RX@0x2000（代码 0x40 + strtab + dynsym +
        // gnu）；RW@0x3000（dynamic）。vaddr = 文件偏移同余式。
        let mut strtab: Vec<u8> = b"\0".to_vec();
        strtab.extend_from_slice(name);
        strtab.push(0);
        // needed 名前置（DT_NEEDED 名偏移域——本模块 dynstr 必含依赖名）
        let needed_off = if needed.is_some() {
            let off = strtab.len() as u32;
            strtab.extend_from_slice(needed.unwrap_or(b""));
            strtab.push(0);
            off
        } else {
            0
        };
        let mut name_offs = Vec::new();
        for (s, _) in syms {
            name_offs.push(strtab.len() as u32);
            strtab.extend_from_slice(s);
            strtab.push(0);
        }
        let mut dynsym: Vec<u8> = vec![0u8; 24 * (1 + syms.len())];
        for (k, (_, value)) in syms.iter().enumerate() {
            // gABI 布局写：name u32 / info u8 / other u8 / shndx u16 /
            // value u64 / size u64
            let o = 24 + k * 24;
            let mut e = vec![0u8; 24];
            e[0..4].copy_from_slice(&name_offs[k].to_le_bytes());
            e[4] = 0x12; // GLOBAL|FUNC
            e[6..8].copy_from_slice(&1u16.to_le_bytes());
            e[8..16].copy_from_slice(&value.to_le_bytes());
            dynsym[o..o + 24].copy_from_slice(&e);
        }
        // GNU 哈希（全符号覆盖——nbuckets = syms.len().max(1)）
        let n = syms.len();
        let hashes: Vec<u32> = syms.iter().map(|(s, _)| dl_new_hash(s)).collect();
        let mut bloom = 0u64;
        for h in &hashes {
            bloom |= 1u64 << (h % 64);
            bloom |= 1u64 << (h % 64); // bloom_shift = 0——bit1 == bit2 域
        }
        let nbuckets = n.max(1) as u32;
        let mut buckets = vec![0u32; nbuckets as usize];
        let mut chains = vec![0u32; n];
        // 同桶末符号判读（定容小域线性扫——no_std 零容器外引）
        let mut last_in_bucket = vec![0usize; nbuckets as usize];
        for (k, h) in hashes.iter().enumerate() {
            last_in_bucket[(h % nbuckets) as usize] = k;
        }
        for (k, h) in hashes.iter().enumerate() {
            let b = (h % nbuckets) as usize;
            if buckets[b] == 0 {
                buckets[b] = (k + 1) as u32;
            }
            chains[k] = if last_in_bucket[b] == k {
                h | 1
            } else {
                h & !1
            };
        }
        let gnu = {
            let mut v = Vec::new();
            v.extend_from_slice(&nbuckets.to_le_bytes());
            v.extend_from_slice(&1u32.to_le_bytes()); // symoffset
            v.extend_from_slice(&1u32.to_le_bytes()); // bloom_size
            v.extend_from_slice(&0u32.to_le_bytes()); // bloom_shift
            v.extend_from_slice(&bloom.to_le_bytes());
            for b in &buckets {
                v.extend_from_slice(&b.to_le_bytes());
            }
            for c in &chains {
                v.extend_from_slice(&c.to_le_bytes());
            }
            v
        };
        // RX 布局：0x2000 代码留白 0x40 → strtab → dynsym → gnu
        let rx_base = 0x2000usize;
        let strtab_va = (rx_base + 0x40) as u64;
        let dynsym_va = strtab_va + strtab.len() as u64;
        let gnu_va = dynsym_va + dynsym.len() as u64;
        let mut text: Vec<u8> = vec![0x90; 0x40];
        text.extend_from_slice(&strtab);
        text.extend_from_slice(&dynsym);
        text.extend_from_slice(&gnu);
        // dynamic（RW@0x3000）
        let mut dyn_ent: Vec<u8> = Vec::new();
        if needed.is_some() {
            // DT_NEEDED（needed 名偏移——strtab needed 域）
            dyn_ent.extend_from_slice(&DT_NEEDED.to_le_bytes());
            dyn_ent.extend_from_slice(&(needed_off as u64).to_le_bytes());
        }
        for (t, v) in [
            (DT_STRTAB, strtab_va),
            (DT_STRSZ, strtab.len() as u64),
            (DT_SYMTAB, dynsym_va),
            (DT_SYMENT, 24),
            (DT_GNU_HASH, gnu_va),
            (DT_NULL, 0),
        ] {
            dyn_ent.extend_from_slice(&t.to_le_bytes());
            dyn_ent.extend_from_slice(&v.to_le_bytes());
        }
        let mut blob = vec![0u8; 0x4000];
        blob[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        blob[4] = 2;
        blob[5] = 1;
        blob[6] = 1;
        let phnum = 3;
        // 手写 ehdr（gen 同款——e_phoff 0x40 / phentsize 56）
        let e_type_dyn: u16 = 3; // ET_DYN
        blob[0x10..0x12].copy_from_slice(&e_type_dyn.to_le_bytes());
        blob[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
        blob[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        blob[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        blob[0x38..0x3A].copy_from_slice(&(phnum as u16).to_le_bytes());
        // PT_LOAD RX
        macro_rules! ph {
            ($off:expr, $pt:expr, $fl:expr, $foff:expr, $va:expr, $fsz:expr) => {{
                blob[$off..$off + 4].copy_from_slice(&($pt).to_le_bytes());
                blob[$off + 4..$off + 8].copy_from_slice(&($fl).to_le_bytes());
                blob[$off + 8..$off + 16].copy_from_slice(&($foff).to_le_bytes());
                blob[$off + 16..$off + 24].copy_from_slice(&($va).to_le_bytes());
                blob[$off + 24..$off + 32].copy_from_slice(&($va).to_le_bytes());
                blob[$off + 32..$off + 40].copy_from_slice(&($fsz).to_le_bytes());
                blob[$off + 40..$off + 48].copy_from_slice(&($fsz).to_le_bytes());
                blob[$off + 48..$off + 56].copy_from_slice(&0x1000u64.to_le_bytes());
            }};
        }
        ph!(
            64,
            1u32,
            5u32,
            rx_base as u64,
            rx_base as u64,
            text.len() as u64
        ); // R|X
        blob[rx_base..rx_base + text.len()].copy_from_slice(&text);
        ph!(
            64 + 56,
            1u32,
            6u32,
            0x3000u64,
            0x3000u64,
            dyn_ent.len() as u64
        ); // R|W
        ph!(
            64 + 112,
            2u32,
            6u32,
            0x3000u64,
            0x3000u64,
            dyn_ent.len() as u64
        ); // PT_DYNAMIC
        blob[0x3000..0x3000 + dyn_ent.len()].copy_from_slice(&dyn_ent);
        blob
    };

    let appu = mk_so(b"libapp.so", Some(b"libdep.so"), &[(b"shared_fn", 0x1000)]);
    let depu = mk_so(
        b"libdep.so",
        None,
        &[(b"shared_fn", 0x2000), (b"dep_only", 0x2008)],
    );
    let mut reg = ChainRegistry::new();
    reg.add(b"libapp.so", &appu).expect("登记 appu");
    reg.add(b"libdep.so", &depu).expect("登记 depu");
    let bases = [0x10_0000u64, 0x20_0000];

    // ① root 域命中：appu "shared_fn"（exe 域先见者胜——addr = base+st_value）
    let hit = dl_sym_chain(&reg, 0, &bases, b"shared_fn")
        .expect("链查找")
        .expect("命中");
    assert_eq!(hit.reg_idx, 0, "root 域先见者胜");
    assert_eq!(hit.addr, 0x10_0000 + 0x1000, "决议地址 = base + st_value");

    // ② 依赖域命中："dep_only"（BFS 序段位定位——depu 独占）
    let hit2 = dl_sym_chain(&reg, 0, &bases, b"dep_only")
        .expect("链查找")
        .expect("命中");
    assert_eq!(hit2.reg_idx, 1, "依赖域段位定位");
    assert_eq!(hit2.addr, 0x20_0000 + 0x2008);

    // ③ 全链缺席 = Ok(None)（决议零虚构）
    assert_eq!(
        dl_sym_chain(&reg, 0, &bases, b"nosuch").expect("链查找"),
        None,
        "全链缺席零虚构"
    );

    // ④ DlState::dlsym_chain error 槽一次性消费（POSIX 口径）
    let mut dl = DlState::new();
    let a = dl.dlsym_chain(&reg, 0, &bases, b"dep_only");
    assert_eq!(a, Some(0x20_0000 + 0x2008));
    assert_eq!(dl.dlerror(), None, "命中域零 error 落账");
    let miss = dl.dlsym_chain(&reg, 0, &bases, b"ghost");
    assert_eq!(miss, None);
    assert_eq!(dl.dlerror(), Some(DL_ERR_UNDEFINED), "缺席 error 槽落账");
    assert_eq!(dl.dlerror(), None, "一次性消费");

    // ⑤ root 越界拒收
    assert_eq!(
        dl_sym_chain(&reg, 2, &bases, b"shared_fn").unwrap_err(),
        LdExecError::RegistryRange,
        "root 越界 fail-visible"
    );

    // ⑥ bases 欠长拒收
    assert_eq!(
        dl_sym_chain(&reg, 0, &[0x10_0000], b"shared_fn").unwrap_err(),
        LdExecError::RegistryRange,
        "bases 欠长 fail-visible"
    );

    // ⑦ 依赖环域（闭环标本——查找前环判读随行显形）
    let cyc_a = mk_so(b"cya.so", None, &[(b"cfn", 0x1000)]);
    let mut reg2 = ChainRegistry::new();
    reg2.add(b"cya.so", &cyc_a).expect("登记 cya");
    let b2 = [0x30_0000u64];
    // 单模块零依赖——查找直返 root 域命中
    let hit3 = dl_sym_chain(&reg2, 0, &b2, b"cfn")
        .expect("链查找")
        .expect("命中");
    assert_eq!(hit3.addr, 0x30_0000 + 0x1000);
}
