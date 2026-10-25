//! Glyph 曜纹 —— 图标网格与同源缩放。
//!
//! 依据《美术设计指南》第五章：图标以 24px 基准网格设计，24/48/96 三档由同一
//! 源几何按整数倍缩放（×1/×2/×4），禁止非同源重绘；悬停反馈为 1.05× 缩放、
//! 120ms 过渡（走 Ripple 弹簧）。本 crate 提供网格换算与尺寸档位的纯函数面。
//!
//! M30-G1 起渲染库本体归位（ROADMAP M30）：[`raster`] 模块承载图标注册表
//! （24 源网格几何基元声明）与同源缩放光栅化器——基元坐标只能经
//! [`map_point`] 变换到目标画布（非同源重绘禁令的工程面兑现），描边随
//! 倍率加粗，像素写入有界（越界裁剪不 panic）。
#![no_std]
#![forbid(unsafe_code)]

pub mod raster;

/// 基准网格（逻辑像素）。
pub const BASE_GRID: u32 = 24;

/// 合法尺寸档位（逻辑像素）。
pub const SIZES: [u32; 3] = [24, 48, 96];

/// 悬停放大倍率。
pub const HOVER_SCALE: f32 = 1.05;

/// 悬停过渡时长（毫秒）。
pub const HOVER_DURATION_MS: u32 = 120;

/// 尺寸档位错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlyphError {
    /// 尺寸不在 24/48/96 档位内。
    IllegalSize,
}

/// 尺寸对应的整数缩放倍数。
pub fn scale_factor(size: u32) -> Result<u32, GlyphError> {
    match size {
        24 => Ok(1),
        48 => Ok(2),
        96 => Ok(4),
        _ => Err(GlyphError::IllegalSize),
    }
}

/// 基准网格坐标到目标尺寸画布的坐标换算（同源缩放的唯一合法路径）。
pub fn map_point(x: f32, y: f32, size: u32) -> Result<(f32, f32), GlyphError> {
    let f = scale_factor(size)? as f32;
    Ok((x * f, y * f))
}

/// 悬停状态的显示尺寸。
pub fn hovered_size(size: u32) -> Result<f32, GlyphError> {
    Ok(size as f32 * HOVER_SCALE)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        hovered_size, map_point, scale_factor, GlyphError, HOVER_DURATION_MS, HOVER_SCALE, SIZES,
    };

    #[test]
    fn scale_factors_match_grid() {
        assert_eq!(scale_factor(24), Ok(1));
        assert_eq!(scale_factor(48), Ok(2));
        assert_eq!(scale_factor(96), Ok(4));
        assert_eq!(scale_factor(32), Err(GlyphError::IllegalSize));
    }

    #[test]
    fn same_source_scaling_is_exact() {
        // 基准点 (6, 18) 在三档画布上必须精确落在整数倍网格
        for size in SIZES {
            let (x, y) = map_point(6.0, 18.0, size).expect("legal size");
            let f = scale_factor(size).expect("factor") as f32;
            assert_eq!((x, y), (6.0 * f, 18.0 * f));
            assert_eq!(x % 6.0, 0.0);
        }
    }

    #[test]
    fn hover_spec_matches_art_guide() {
        assert_eq!(HOVER_SCALE, 1.05);
        assert_eq!(HOVER_DURATION_MS, 120);
        let hovered = hovered_size(48).expect("legal size");
        assert!((hovered - 50.4).abs() < 1e-3, "hovered={hovered}");
    }
}
