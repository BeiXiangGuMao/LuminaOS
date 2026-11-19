//! M51-VECFONT74 笔85 —— 矢量字体栅格化：TTF 真件语义面 + 二次贝塞尔
//! 轮廓 + 4×4 超采样非零缠绕 8bpp 抗锯齿扫描线。
//!
//! 真件基座：DejaVu Sans Mono 1.16（`artifacts/fonts/DejaVuSansMono.ttf`
//! ——head magic 0x5F0F3CF5 / unitsPerEm 2048 / indexToLocFormat 1
//! / numGlyphs 3377 / numberOfHMetrics 4〔等宽共享槽〕/ advance 1233；
//! 'L' gid 47 单轮廓 6 点全 on / 'o' gid 82 双轮廓 24 点 on-off 贝塞尔
//! 混合——python 同源预演金值锚随行宿主测试）。
//!
//! 零 alloc 纪律（本 crate `no_std` 无 alloc 依赖——render_text 同谱）：
//! [`GlyphOutline`] / 交点缓冲 / coverage 缓冲全部定容数组（调用方栈
//! 承载），越界 fail-visible（[`VecFontError::GlyphTooComplex`]），
//! 零 panic。坐标算术 i64/i32 定点（1/256 亚像素）——内核软浮点域
//! 避雷（x86_64-unknown-none 禁 SSE——整数模拟慢——t163 QEMU 自检
//! 时长窗如实录档）。
//!
//! 栅格化算法（扫描线区间法）：每像素行 4 亚行 × 每亚行收集有向交点
//! （边向上 +1 / 向下 -1——非零缠绕）→ x 排序 → winding 扫描命中
//! 区间 → 每像素 4×4 亚采样命中数 → 8bpp coverage。二次贝塞尔
//! （off-curve）8 段定点细分；连续 off 中点隐式 on；首尾 off 闭合
//! （TTF 规范同谱——python 预演与 Rust 同源对账）。

// ---------------------------------------------------------------------------
// 常量与错误面
// ---------------------------------------------------------------------------

/// 轮廓点定容（DejaVu 最复杂 simple glyph < 200 点——512 富余）。
pub const NPT_MAX: usize = 512;
/// 轮廓数定容（simple glyph 上界——composite 拒收域外）。
pub const NC_MAX: usize = 16;
/// 单亚行交点定容（'o' 双轮廓 ~6 交点——256 富余）。
pub const XSEC_MAX: usize = 256;
/// 每像素轴亚采样数（4×4 = 16 采样/像素）。
pub const SUB: u32 = 4;
/// 二次贝塞尔细分段数（每 off-curve 段折线化 8 段）。
pub const FLAT_STEPS: u32 = 8;
/// coverage 缓冲边上限（栅格化画布 64×64 = 4 KB——栈承载域）。
pub const RASTER_MAX: u32 = 64;
/// 定点亚精度（1/256 像素）。
const FIX: i64 = 256;
/// 满格亚采样数（每像素 4×4 = 16 采样 → coverage 顶格换算基数）。
const FULL_COV: u32 = SUB * SUB;

/// 矢量字体域错误（fail-visible 全谱）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecFontError {
    /// sfnt 魔数缺席（TrueType 0x00010000 域外——'OTTO'/ttcf 拒收）。
    BadMagic,
    /// 表缺席（head/loca/glyf/cmap/hmtx/hhea/maxp 任一）。
    TableMiss,
    /// head 结构非法（magic 0x5F0F3CF5 缺席 / unitsPerEm 0 / itlf 域外）。
    BadHead,
    /// hhea numberOfHMetrics 域外（0 或超 numGlyphs）。
    BadMetrics,
    /// cmap (3,1) format 4 子表缺席。
    CmapMiss,
    /// glyf composite glyph（numberOfContours < 0）——v0 域外拒收。
    CompositeGlyph,
    /// 字形越界或结构截断。
    BadGlyph,
    /// 点数/轮廓数/交点超定容（fail-visible——零截断）。
    GlyphTooComplex,
    /// 栅格化画布越界（out 容量 < w*h 或 w/h 超 [`RASTER_MAX`]）。
    BadCanvas,
}

// ---------------------------------------------------------------------------
// 轮廓面
// ---------------------------------------------------------------------------

/// 解析后字形轮廓（定容——零 alloc）。
#[derive(Debug, Clone, Copy)]
pub struct GlyphOutline {
    /// 轮廓数（0 = 空字形——space 域合法）。
    pub n_contours: usize,
    /// 每轮廓终点索引（inclusive，点序 0 基）。
    pub ends: [u16; NC_MAX],
    /// 点数（= ends[n_contours-1] + 1；空字形 0）。
    pub n_pts: usize,
    /// 点序 x 列（font 单位——解析域直写）。
    pub xs: [i32; NPT_MAX],
    /// 点序 y 列（font 单位——解析域直写）。
    pub ys: [i32; NPT_MAX],
    /// on-curve 锚列（false = off-curve 贝塞尔控制点）。
    pub on: [bool; NPT_MAX],
    /// glyf 头 bbox（font 单位——对账锚）。
    pub bbox: (i32, i32, i32, i32),
}

impl GlyphOutline {
    /// 空轮廓（out 重铸基面）。
    pub fn new() -> Self {
        Self {
            n_contours: 0,
            ends: [0; NC_MAX],
            n_pts: 0,
            xs: [0; NPT_MAX],
            ys: [0; NPT_MAX],
            on: [false; NPT_MAX],
            bbox: (0, 0, 0, 0),
        }
    }

    /// 轮廓 c 的点序区间 [lo, hi]（inclusive）。
    fn span(&self, c: usize) -> Option<(usize, usize)> {
        if c >= self.n_contours {
            return None;
        }
        let lo = if c == 0 {
            0
        } else {
            self.ends[c - 1] as usize + 1
        };
        let hi = self.ends[c] as usize;
        if hi >= self.n_pts || hi < lo {
            return None;
        }
        Some((lo, hi))
    }
}

impl Default for GlyphOutline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TTF 解析面
// ---------------------------------------------------------------------------

/// TTF 字体（blob 借用——零 alloc；解析即定位表偏移）。
pub struct TtfFont<'a> {
    blob: &'a [u8],
    loca_off: usize,
    glyf_off: usize,
    cmap_fmt4: usize,
    hmtx_off: usize,
    upem: u16,
    itlf: u8,
    num_glyphs: u16,
    nhm: u16,
}

impl<'a> TtfFont<'a> {
    /// sfnt 解析（TrueType 0x00010000 域；表目录定位 + head/hhea/maxp
    /// 结构校验 + cmap (3,1) format 4 子表定位——fail-visible 全谱）。
    pub fn parse(blob: &'a [u8]) -> Result<Self, VecFontError> {
        if blob.len() < 12 || u32_be(blob, 0).ok() != Some(0x0001_0000) {
            return Err(VecFontError::BadMagic);
        }
        let num = u16_be(blob, 4)? as usize;
        if num == 0 || num > 128 || blob.len() < 12 + num * 16 {
            return Err(VecFontError::BadMagic);
        }
        let mut head = None;
        let mut loca = None;
        let mut glyf = None;
        let mut cmap = None;
        let mut hmtx = None;
        let mut hhea = None;
        let mut maxp = None;
        for i in 0..num {
            let off = 12 + i * 16;
            let tag = &blob[off..off + 4];
            let toff = u32_be(blob, off + 8)? as usize;
            let tlen = u32_be(blob, off + 12)? as usize;
            if toff > blob.len() || tlen > blob.len() - toff {
                return Err(VecFontError::TableMiss);
            }
            match tag {
                b"head" => head = Some(toff),
                b"loca" => loca = Some(toff),
                b"glyf" => glyf = Some(toff),
                b"cmap" => cmap = Some(toff),
                b"hmtx" => hmtx = Some(toff),
                b"hhea" => hhea = Some(toff),
                b"maxp" => maxp = Some(toff),
                _ => {}
            }
        }
        let (Some(head), Some(loca), Some(glyf), Some(cmap), Some(hmtx), Some(hhea), Some(maxp)) =
            (head, loca, glyf, cmap, hmtx, hhea, maxp)
        else {
            return Err(VecFontError::TableMiss);
        };
        // head：magic 0x5F0F3CF5 @ +12 / unitsPerEm u16 @ +18 / itlf i16 @ +50
        if blob.len() < head + 54 || u32_be(blob, head + 12).ok() != Some(0x5F0F_3CF5) {
            return Err(VecFontError::BadHead);
        }
        let upem = u16_be(blob, head + 18)?;
        let itlf = i16_be(blob, head + 50)?;
        if upem == 0 || !(itlf == 0 || itlf == 1) {
            return Err(VecFontError::BadHead);
        }
        // maxp：numGlyphs u16 @ +4
        let num_glyphs = u16_be(blob, maxp + 4)?;
        if num_glyphs == 0 {
            return Err(VecFontError::TableMiss);
        }
        // hhea：numberOfHMetrics u16 @ +34
        let nhm = u16_be(blob, hhea + 34)?;
        if nhm == 0 || nhm > num_glyphs {
            return Err(VecFontError::BadMetrics);
        }
        let cmap_fmt4 = find_cmap_fmt4(blob, cmap)?;
        Ok(Self {
            blob,
            loca_off: loca,
            glyf_off: glyf,
            cmap_fmt4,
            hmtx_off: hmtx,
            upem,
            itlf: itlf as u8,
            num_glyphs,
            nhm,
        })
    }

    /// unitsPerEm（真件锚 2048）。
    pub fn units_per_em(&self) -> u16 {
        self.upem
    }

    /// numGlyphs（真件锚 3377）。
    pub fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    /// numberOfHMetrics（真件锚 4——等宽共享槽）。
    pub fn num_h_metrics(&self) -> u16 {
        self.nhm
    }

    /// indexToLocFormat（真件锚 1 = long）。
    pub fn index_to_loc_format(&self) -> u8 {
        self.itlf
    }

    /// cmap format 4 码点 → gid（缺码点 None）。
    pub fn glyph_id(&self, cp: u32) -> Option<u16> {
        cmap4_lookup(self.blob, self.cmap_fmt4, cp)
    }

    /// hmtx advance（等宽共享槽收口——gid ≥ nhm 取 nhm-1 槽）。
    pub fn advance(&self, gid: u16) -> Result<u16, VecFontError> {
        if gid >= self.num_glyphs {
            return Err(VecFontError::BadGlyph);
        }
        let i = gid.min(self.nhm - 1) as usize;
        u16_be(self.blob, self.hmtx_off + i * 4)
    }

    /// loca 跨度（glyf 字节偏移对）。
    fn loca_span(&self, gid: u16) -> Option<(usize, usize)> {
        let g = gid as usize;
        if self.itlf == 0 {
            let a = u16_be(self.blob, self.loca_off + g * 2).ok()? as usize;
            let b = u16_be(self.blob, self.loca_off + (g + 1) * 2).ok()? as usize;
            Some((a * 2, b * 2))
        } else {
            let a = u32_be(self.blob, self.loca_off + g * 4).ok()? as usize;
            let b = u32_be(self.blob, self.loca_off + (g + 1) * 4).ok()? as usize;
            Some((a, b))
        }
    }

    /// glyf 轮廓解析（simple glyph 域；composite 拒收 fail-visible；
    /// 空字形 = 零轮廓 Ok——space 域合法）。out 全量重铸。
    pub fn outline(&self, gid: u16, out: &mut GlyphOutline) -> Result<(), VecFontError> {
        *out = GlyphOutline::new();
        if gid >= self.num_glyphs {
            return Err(VecFontError::BadGlyph);
        }
        let Some((a, b)) = self.loca_span(gid) else {
            return Err(VecFontError::TableMiss);
        };
        if a == b {
            return Ok(()); // 空字形（space 域）
        }
        let base = self.glyf_off + a;
        if base + 10 > self.blob.len() || self.glyf_off + b > self.blob.len() {
            return Err(VecFontError::BadGlyph);
        }
        let nc_raw = i16_be(self.blob, base)? as i32;
        if nc_raw < 0 {
            return Err(VecFontError::CompositeGlyph);
        }
        if nc_raw == 0 {
            return Ok(()); // 零轮廓
        }
        let nc = nc_raw as usize;
        if nc > NC_MAX {
            return Err(VecFontError::GlyphTooComplex);
        }
        out.bbox = (
            i16_be(self.blob, base + 2)? as i32,
            i16_be(self.blob, base + 4)? as i32,
            i16_be(self.blob, base + 6)? as i32,
            i16_be(self.blob, base + 8)? as i32,
        );
        let mut pos = base + 10;
        for k in 0..nc {
            out.ends[k] = u16_be(self.blob, pos + k * 2)?;
        }
        out.n_contours = nc;
        out.n_pts = out.ends[nc - 1] as usize + 1;
        if out.n_pts > NPT_MAX {
            return Err(VecFontError::GlyphTooComplex);
        }
        pos += nc * 2;
        let il = u16_be(self.blob, pos)? as usize;
        pos += 2 + il;
        // flags（REPEAT 展开）
        let npt = out.n_pts;
        let mut flags = [0u8; NPT_MAX];
        let mut nf = 0usize;
        while nf < npt {
            let fl = *self.blob.get(pos).ok_or(VecFontError::BadGlyph)?;
            pos += 1;
            let mut rep = 1usize;
            if fl & 8 != 0 {
                rep = *self.blob.get(pos).ok_or(VecFontError::BadGlyph)? as usize;
                pos += 1;
            }
            if nf + rep > npt {
                return Err(VecFontError::BadGlyph);
            }
            for _ in 0..rep {
                flags[nf] = fl;
                nf += 1;
            }
        }
        // x 增量段（TTF 规范：全 x 后全 y 分立两段）
        let mut px = 0i32;
        for (k, &fl) in flags.iter().enumerate().take(npt) {
            if fl & 2 != 0 {
                let d = *self.blob.get(pos).ok_or(VecFontError::BadGlyph)? as i32;
                pos += 1;
                px += if fl & 16 != 0 { d } else { -d };
            } else if fl & 16 == 0 {
                px += i16_be(self.blob, pos)? as i32;
                pos += 2;
            }
            out.xs[k] = px;
        }
        // y 增量段
        let mut py = 0i32;
        for (k, &fl) in flags.iter().enumerate().take(npt) {
            if fl & 4 != 0 {
                let d = *self.blob.get(pos).ok_or(VecFontError::BadGlyph)? as i32;
                pos += 1;
                py += if fl & 32 != 0 { d } else { -d };
            } else if fl & 32 == 0 {
                py += i16_be(self.blob, pos)? as i32;
                pos += 2;
            }
            out.ys[k] = py;
        }
        for (k, &fl) in flags.iter().enumerate().take(npt) {
            out.on[k] = fl & 1 != 0;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 大端读域（blob 切片安全——越界 None）
// ---------------------------------------------------------------------------

fn u32_be(blob: &[u8], off: usize) -> Result<u32, VecFontError> {
    blob.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(VecFontError::TableMiss)
}

fn u16_be(blob: &[u8], off: usize) -> Result<u16, VecFontError> {
    blob.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(VecFontError::TableMiss)
}

fn i16_be(blob: &[u8], off: usize) -> Result<i16, VecFontError> {
    blob.get(off..off + 2)
        .map(|s| i16::from_be_bytes([s[0], s[1]]))
        .ok_or(VecFontError::TableMiss)
}

// ---------------------------------------------------------------------------
// cmap format 4（(3,1) Windows Unicode BMP——seg 有序扫描）
// ---------------------------------------------------------------------------

fn find_cmap_fmt4(blob: &[u8], cmap: usize) -> Result<usize, VecFontError> {
    let n = u16_be(blob, cmap + 2)? as usize;
    for i in 0..n {
        let rec = cmap + 4 + i * 8;
        let pid = u16_be(blob, rec)?;
        let eid = u16_be(blob, rec + 2)?;
        let off = u32_be(blob, rec + 4)? as usize;
        if (pid, eid) != (3, 1) {
            continue;
        }
        let fo = cmap + off;
        if u16_be(blob, fo)? == 4 {
            return Ok(fo);
        }
    }
    Err(VecFontError::CmapMiss)
}

fn cmap4_lookup(blob: &[u8], fo: usize, cp: u32) -> Option<u16> {
    if cp > 0xFFFF {
        return None;
    }
    let seg_x2 = u16_be(blob, fo + 6).ok()? as usize;
    let seg = seg_x2 / 2;
    let ends_base = fo + 14;
    let starts_base = ends_base + seg_x2 + 2;
    let deltas_base = starts_base + seg_x2;
    let ranges_base = deltas_base + seg_x2;
    for k in 0..seg {
        let end = u16_be(blob, ends_base + k * 2).ok()? as u32;
        if cp > end {
            continue;
        }
        let start = u16_be(blob, starts_base + k * 2).ok()? as u32;
        if cp < start {
            return None; // seg 有序——后段全越域
        }
        let ro = u16_be(blob, ranges_base + k * 2).ok()?;
        let delta = i16_be(blob, deltas_base + k * 2).ok()? as i32;
        let g = if ro == 0 {
            (cp as i32 + delta) & 0xFFFF
        } else {
            let glo = ranges_base + k * 2 + ro as usize + (cp as usize - start as usize) * 2;
            let g = u16_be(blob, glo).ok()? as i32;
            if g == 0 {
                return None;
            }
            (g + delta) & 0xFFFF
        };
        return Some(g as u16);
    }
    None
}

// ---------------------------------------------------------------------------
// 栅格化面（4×4 超采样 + 非零缠绕扫描线区间——i64 定点 1/256）
// ---------------------------------------------------------------------------

/// 轮廓规范化折线段发射（on/off 规范化：连续 off 中点隐式 on、首尾
/// off 闭合——font 单位 i64 定点；段 = (x0,y0,x1,y1)——line 直发 /
/// quad FLAT_STEPS 细分逐段发）。
fn for_each_segment(out: &GlyphOutline, mut emit: impl FnMut(i64, i64, i64, i64)) {
    for c in 0..out.n_contours {
        let Some((lo, hi)) = out.span(c) else {
            continue;
        };
        let n = hi - lo + 1;
        // 旋转到首个 on（全 off 退化——取 0 号锚）
        let f0 = (lo..=hi).find(|&k| out.on[k]).unwrap_or(lo);
        let idx = |k: usize| lo + (f0 - lo + k) % n;
        let at = |k: usize| (out.xs[k] as i64, out.ys[k] as i64);
        let mut cur = at(idx(0));
        let mut pending: Option<usize> = None;
        for k in 1..=n {
            let j = idx(k);
            let pj = at(j);
            if out.on[j] {
                match pending.take() {
                    Some(p) => {
                        quad_segments(cur, at(p), pj, &mut emit);
                        cur = pj;
                    }
                    None => {
                        emit(cur.0, cur.1, pj.0, pj.1);
                        cur = pj;
                    }
                }
            } else if let Some(p) = pending.replace(j) {
                // 连续 off：中点隐式 on
                let pp = at(p);
                let mid = ((pp.0 + pj.0) / 2, (pp.1 + pj.1) / 2);
                quad_segments(cur, pp, mid, &mut emit);
                cur = mid;
            }
        }
        if let Some(p) = pending {
            quad_segments(cur, at(p), at(idx(0)), &mut emit);
        }
    }
}

/// 二次贝塞尔 FLAT_STEPS 段定点细分（p0 起锚 / p1 off 控制 / p2 终锚
/// ——B(t) = mt²·p0 + 2·t·mt·p1 + t²·p2，i64 中间量防溢出；每段
/// emit(B((s-1)/n), B(s/n))——折线段起终点对）。
fn quad_segments(
    p0: (i64, i64),
    p1: (i64, i64),
    p2: (i64, i64),
    emit: &mut impl FnMut(i64, i64, i64, i64),
) {
    for s in 1..=FLAT_STEPS {
        let t1 = ((s - 1) as i64) * FIX / FLAT_STEPS as i64;
        let t2 = (s as i64) * FIX / FLAT_STEPS as i64;
        emit(
            bx(t1, p0, p1, p2),
            by(t1, p0, p1, p2),
            bx(t2, p0, p1, p2),
            by(t2, p0, p1, p2),
        );
    }
}

fn bx(t: i64, p0: (i64, i64), p1: (i64, i64), p2: (i64, i64)) -> i64 {
    let mt = FIX - t;
    (mt * mt * p0.0 + 2 * t * mt * p1.0 + t * t * p2.0) / (FIX * FIX)
}

fn by(t: i64, p0: (i64, i64), p1: (i64, i64), p2: (i64, i64)) -> i64 {
    let mt = FIX - t;
    (mt * mt * p0.1 + 2 * t * mt * p1.1 + t * t * p2.1) / (FIX * FIX)
}

/// 栅格化到 8bpp coverage 画布（4×4 超采样非零缠绕——零 alloc 定容）。
///
/// `out.len() ≥ w*h` 且 `w/h ≤ RASTER_MAX` 契约；font→像素域换算
/// y 翻转（TTF y 向上）。
pub fn rasterize_into(
    font: &TtfFont,
    outline: &GlyphOutline,
    px: u32,
    w: u32,
    h: u32,
    out: &mut [u8],
) -> Result<(), VecFontError> {
    if w == 0 || h == 0 || w > RASTER_MAX || h > RASTER_MAX {
        return Err(VecFontError::BadCanvas);
    }
    if out.len() < (w as usize) * (h as usize) {
        return Err(VecFontError::BadCanvas);
    }
    out[..(w * h) as usize].fill(0);
    let (w, h) = (w as usize, h as usize);
    let upem = font.units_per_em() as i64;
    let scale = (px as i64) * FIX / upem; // font → 1/256 像素
    let hfix = (h as i64) * FIX;
    for py in 0..h {
        for sub in 0..SUB as i64 {
            // 亚行 y：像素 py 的第 sub 亚行中心（1/256 像素域）
            let sy = (py as i64) * FIX + (sub * FIX + FIX / 2) / SUB as i64;
            let mut xs = [0i32; XSEC_MAX];
            let mut dirs = [0i8; XSEC_MAX];
            let mut nx = 0usize;
            let mut overflow = false;
            // 段扫描（font 单位段 → 像素域 y 翻转交点插值）
            let mut on_seg = |x0f: i64, y0f: i64, x1f: i64, y1f: i64| {
                if nx >= XSEC_MAX {
                    overflow = true;
                    return;
                }
                let y0 = hfix - y0f * scale;
                let y1 = hfix - y1f * scale;
                if (y0 <= sy && sy < y1) || (y1 <= sy && sy < y0) {
                    let t = ((sy - y0) << 8) / (y1 - y0); // 1/256 插值系数
                    let xf = x0f + (x1f - x0f) * t / FIX;
                    xs[nx] = (xf * scale) as i32;
                    dirs[nx] = if y1 > y0 { 1 } else { -1 };
                    nx += 1;
                }
            };
            for_each_segment(outline, &mut on_seg);
            if overflow {
                return Err(VecFontError::GlyphTooComplex);
            }
            // x 插入排序（小数组——交点 ≤256）
            for i in 1..nx {
                let kx = xs[i];
                let kd = dirs[i];
                let mut j = i;
                while j > 0 && xs[j - 1] > kx {
                    xs[j] = xs[j - 1];
                    dirs[j] = dirs[j - 1];
                    j -= 1;
                }
                xs[j] = kx;
                dirs[j] = kd;
            }
            // winding 扫描 → 命中区间 → 亚采样判定
            let mut winding = 0i32;
            for i in 0..nx.saturating_sub(1) {
                winding += dirs[i] as i32;
                if winding == 0 {
                    continue;
                }
                let (lo_x, hi_x) = (xs[i] as i64, xs[i + 1] as i64);
                for pxc in 0..w {
                    for m in 0..SUB as i64 {
                        let sx = (pxc as i64) * FIX + (m * FIX + FIX / 2) / SUB as i64;
                        if lo_x <= sx && sx < hi_x {
                            out[py * w + pxc] = out[py * w + pxc].saturating_add(1);
                        }
                    }
                }
            }
        }
    }
    // coverage 次数 → 8bpp 换算（python 预演同源：c*255/16——顶格 255）
    for cell in out[..(w * h)].iter_mut() {
        *cell = ((*cell as u32) * 255 / FULL_COV) as u8;
    }
    Ok(())
}

/// 8bpp coverage → ARGB 混合（u32 逐通道定点——透明合成同谱）。
pub fn blend_px(dst: u32, fg: u32, cov: u8) -> u32 {
    let a = cov as u32;
    if a == 0 {
        return dst;
    }
    let ia = 255 - a;
    let mix = |d: u32, f: u32| ((f * a + d * ia) / 255) & 0xFF;
    (dst & 0xFF00_0000)
        | (mix((dst >> 16) & 0xFF, (fg >> 16) & 0xFF) << 16)
        | (mix((dst >> 8) & 0xFF, (fg >> 8) & 0xFF) << 8)
        | mix(dst & 0xFF, fg & 0xFF)
}

/// advance 定点换算（font → 像素）。
pub fn advance_px(font: &TtfFont, gid: u16, px_size: u32) -> i32 {
    let aw = font.advance(gid).unwrap_or(0) as i64;
    let upem = font.units_per_em() as i64;
    ((aw * px_size as i64 + upem / 2) / upem) as i32
}

/// AA 文本渲染（零 alloc——逐字符栅格化到字形级 coverage 缓冲后
/// blend 落画布；advance 推进；越界裁剪零 panic）。
#[allow(clippy::too_many_arguments)]
pub fn render_text_aa(
    dst: &mut [u32],
    stride: usize,
    ox: i32,
    oy: i32,
    s: &str,
    font: &TtfFont,
    px_size: u32,
    fg: u32,
) {
    let mut outline = GlyphOutline::new();
    let mut cov = [0u8; (RASTER_MAX * RASTER_MAX) as usize];
    // 画布 = 字形级尺寸（px+2 宽 / px+4 高——y 翻转 font y=0 贴画布底，
    // 字形内容 ~px 行内；bbox 下探 y_min 域 4 行余量）——blend 目标域
    // 内命中率最大化（64×64 满画布把字形推到画布底缘 = blend 越界域）。
    let cw = (px_size + 2).min(RASTER_MAX);
    let chh = (px_size + 4).min(RASTER_MAX);
    if cov.len() < (cw * chh) as usize {
        return;
    }
    let mut pen_x = ox;
    for ch in s.chars() {
        let Some(gid) = font.glyph_id(ch as u32) else {
            continue;
        };
        if font.outline(gid, &mut outline).is_err() {
            continue;
        }
        if outline.n_contours == 0 {
            pen_x += advance_px(font, gid, px_size);
            continue;
        }
        if rasterize_into(font, &outline, px_size, cw, chh, &mut cov).is_ok() {
            for r in 0..chh as usize {
                for c in 0..cw as usize {
                    let a = cov[r * cw as usize + c];
                    if a == 0 {
                        continue;
                    }
                    let dx = pen_x + c as i32;
                    let dy = oy + r as i32;
                    if dx < 0 || dy < 0 || dx as usize >= stride {
                        continue;
                    }
                    let cell = dy as usize * stride + dx as usize;
                    if cell >= dst.len() {
                        continue;
                    }
                    dst[cell] = blend_px(dst[cell], fg, a);
                }
            }
        }
        pen_x += advance_px(font, gid, px_size);
    }
}

// ---------------------------------------------------------------------------
// 宿主测试域（真件金值锚——python 同源预演对账）
// ---------------------------------------------------------------------------

#[cfg(all(test, not(target_os = "none")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 真件（DejaVu Sans Mono 1.16——artifacts/ 单一事实源）。
    const DEJAVU_MONO: &[u8] = include_bytes!("../../../artifacts/fonts/DejaVuSansMono.ttf");

    /// vecfont_face 十域（glyph 宿主 15 → 16+——真件金值锚全谱）。
    #[test]
    fn vecfont_face() {
        // ① sfnt 解析 + head 锚（magic/upem/itlf——python 预演金值）
        let font = TtfFont::parse(DEJAVU_MONO).expect("真件解析");
        assert_eq!(font.units_per_em(), 2048);
        assert_eq!(font.index_to_loc_format(), 1);
        assert_eq!(font.num_glyphs(), 3377);
        assert_eq!(font.num_h_metrics(), 4);
        // ② cmap (3,1) format 4 码点锚（L/o/A/g——python 预演）
        assert_eq!(font.glyph_id('L' as u32), Some(47));
        assert_eq!(font.glyph_id('o' as u32), Some(82));
        assert_eq!(font.glyph_id('A' as u32), Some(36));
        assert_eq!(font.glyph_id('g' as u32), Some(74));
        assert_eq!(font.glyph_id(0x1F600), None); // 域外码点（emoji BMP 外）
                                                  // ③ hmtx 等宽锚（advance 1233——共享槽收口）
        assert_eq!(font.advance(47).unwrap(), 1233);
        assert_eq!(font.advance(82).unwrap(), 1233);
        assert_eq!(font.advance(4000).unwrap_err(), VecFontError::BadGlyph);
        // ④ 'L' 轮廓锚（1 轮廓 6 点全 on——bbox 对账）
        let mut out = GlyphOutline::new();
        font.outline(47, &mut out).expect("L outline");
        assert_eq!(out.n_contours, 1);
        assert_eq!(out.n_pts, 6);
        assert_eq!(out.bbox, (215, 0, 1139, 1493));
        assert!(out.on[..6].iter().all(|&v| v));
        assert_eq!((out.xs[0], out.ys[0]), (215, 1493)); // 起点锚
        assert_eq!((out.xs[5], out.ys[5]), (215, 0)); // 闭合锚
                                                      // ⑤ 'o' 轮廓锚（2 轮廓 24 点贝塞尔混合——endPts 对账）
        font.outline(82, &mut out).expect("o outline");
        assert_eq!(out.n_contours, 2);
        assert_eq!(out.n_pts, 24);
        assert_eq!(out.ends[0], 11);
        assert_eq!(out.ends[1], 23);
        assert_eq!(out.bbox, (137, -29, 1096, 1147));
        assert!(out.on[0]); // 'o' 首点 on
        assert!(!out.on[1]); // 次点 off（贝塞尔控制锚）
                             // ⑥ 空字形锚（space 0x20 = 零轮廓 Ok）
        let sp = font.glyph_id(0x20).expect("space gid");
        font.outline(sp, &mut out).expect("space outline");
        assert_eq!(out.n_contours, 0);
        // ⑦ composite 拒收锚（gid 122 = 首个 composite——真件事实）
        assert_eq!(
            font.outline(122, &mut out),
            Err(VecFontError::CompositeGlyph)
        );
        // ⑧ 栅格化 'L'@24px（python 预演金值 nz=72 / sum=15352——
        //    定点 ±2% 区间容差）
        font.outline(47, &mut out).expect("L outline");
        let mut cov = [0u8; (RASTER_MAX * RASTER_MAX) as usize];
        rasterize_into(&font, &out, 24, 24, 24, &mut cov).expect("raster L");
        let nz = cov[..576].iter().filter(|&&v| v > 0).count();
        let sum: u32 = cov[..576].iter().map(|&v| v as u32).sum();
        assert!((62..=82).contains(&nz), "L@24 nz={nz} 域外");
        assert!((15000..=15700).contains(&sum), "L@24 sum={sum} 域外");
        // ⑨ 栅格化 'o'@24px（贝塞尔 AA 双边渐变锚——nz=101 / sum=18139）
        font.outline(82, &mut out).expect("o outline");
        rasterize_into(&font, &out, 24, 24, 24, &mut cov).expect("raster o");
        let nzo = cov[..576].iter().filter(|&&v| v > 0).count();
        let sumo: u32 = cov[..576].iter().map(|&v| v as u32).sum();
        assert!((91..=111).contains(&nzo), "o@24 nz={nzo} 域外");
        assert!((17800..=18500).contains(&sumo), "o@24 sum={sumo} 域外");
        // AA 渐变结构锚（python midrow 锚——127 中间值 + 255 顶格并存）
        let midrow = &cov[12 * 24..13 * 24];
        assert!(midrow.contains(&255), "o 中行 255 顶格缺席");
        assert!(
            midrow.iter().any(|&v| (100..=160).contains(&v)),
            "o 中行 AA 中间值缺席"
        );
        // ⑩ 缩放一致性锚（'L'@32px——ratio 守恒 0.1039±2%）
        font.outline(47, &mut out).expect("L outline");
        rasterize_into(&font, &out, 32, 32, 32, &mut cov).expect("raster L32");
        let nz32 = cov[..1024].iter().filter(|&&v| v > 0).count();
        let sum32: u32 = cov[..1024].iter().map(|&v| v as u32).sum();
        assert!((119..=139).contains(&nz32), "L@32 nz={nz32} 域外");
        assert!((26500..=27750).contains(&sum32), "L@32 sum={sum32} 域外");
        // ⑪ blend 锚（8bpp → ARGB 逐通道定点混合）
        assert_eq!(blend_px(0x11_223344, 0x00_FF0000, 0), 0x11_223344); // 零覆盖透传
        let b = blend_px(0xFF_000000, 0xFF_FF0000, 255);
        assert_eq!(b, 0xFF_FF0000); // 满覆盖全替换
        let half = blend_px(0xFF_000000, 0xFF_FFFFFF, 128);
        assert!((120..=132).contains(&((half >> 16) & 0xFF))); // 半覆盖中值
                                                               // ⑫ 画布越界拒收锚（BadCanvas fail-visible）
        assert_eq!(
            rasterize_into(&font, &out, 24, 0, 24, &mut cov),
            Err(VecFontError::BadCanvas)
        );
        assert_eq!(
            rasterize_into(&font, &out, 24, 24, 24, &mut [0u8; 8]),
            Err(VecFontError::BadCanvas)
        );
        // ⑬ 损件拒收锚（魔数翻转 → BadMagic）
        let mut bad = DEJAVU_MONO.to_vec();
        bad[0..4].copy_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(TtfFont::parse(&bad), Err(VecFontError::BadMagic)));
        let mut trunc = DEJAVU_MONO[..100].to_vec();
        trunc[3] = b'F';
        assert!(matches!(
            TtfFont::parse(&trunc),
            Err(VecFontError::BadMagic)
        ));
        // ⑭ render_text_aa 画布锚（"Lo" 双字符 blend——advance 推进
        //    1233×24/2048 ≈ 14 px/字符）
        let mut canvas = [0x11_223344u32; 40 * 30];
        render_text_aa(&mut canvas, 40, 2, 2, "Lo", &font, 24, 0xFF_FFFF00);
        let lit = canvas.iter().filter(|&&v| v != 0x11_223344).count();
        assert!(lit > 100, "render_text_aa 亮像素 {lit} 域外（笔画缺席）");
        assert!(lit < 40 * 30, "render_text_aa 全幅污染（越界裁剪失效）");
    }
}
