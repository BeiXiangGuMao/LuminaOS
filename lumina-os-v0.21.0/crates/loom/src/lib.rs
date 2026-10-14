//! Loom 织机 —— 主题系统与设计 token 消费面。
//!
//! 依据《美术设计指南》(LUM-ART-003)：色彩 token、间距刻度与字号公式由美术指南
//! 定义，Loom 是它们的工程消费方；性能上限见《指标与规范手册》Loom 章。
//! 本 crate 固化美术指南的数值事实：
//!
//! - 8 px 基础网格与间距刻度（间距值必须是网格的整数倍）；
//! - 字号公式 `16 + vw/100`（逻辑像素，随窗口宽度呼吸）；
//! - 骨架常量：Panel 高 48 px、Dock 高 72 px；
//! - 主题 token 的最小类型（颜色 + 语义别名）。
#![no_std]

/// 基础网格（逻辑像素）。
pub const GRID: u32 = 8;

/// Panel 骨架高度（逻辑像素，ART-003 第三章）。
pub const PANEL_HEIGHT: u32 = 48;

/// Dock 骨架高度（逻辑像素，ART-003 第三章）。
pub const DOCK_HEIGHT: u32 = 72;

/// 间距刻度：第 `step` 级间距（8 的整数倍）；`step` 上限 16。
///
/// # Panics
/// 调试断言 `step > 16`（越界刻度说明设计稿偏离网格，按指南视为缺陷）。
pub fn spacing(step: u32) -> u32 {
    assert!(step <= 16, "spacing step out of grid scale");
    step * GRID
}

/// 检查数值是否落在 8px 网格上。
pub fn on_grid(px: u32) -> bool {
    px.is_multiple_of(GRID)
}

/// 字号公式：`16 + vw/100`（ART-003 第三章），输入窗口宽度（逻辑像素）。
pub fn font_size(viewport_w: u32) -> f32 {
    16.0 + viewport_w as f32 / 100.0
}

/// 颜色 token：sRGB 八位通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorToken {
    /// 红 0-255。
    pub r: u8,
    /// 绿 0-255。
    pub g: u8,
    /// 蓝 0-255。
    pub b: u8,
}

impl ColorToken {
    /// 以 `0xRRGGBB` 构造。
    pub const fn from_hex(hex: u32) -> Self {
        ColorToken {
            r: (hex >> 16) as u8,
            g: (hex >> 8) as u8,
            b: hex as u8,
        }
    }

    /// `#RRGGBB` 形式。
    pub fn hex_string(self) -> [u8; 7] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        [
            b'#',
            HEX[(self.r >> 4) as usize],
            HEX[(self.r & 0xF) as usize],
            HEX[(self.g >> 4) as usize],
            HEX[(self.g & 0xF) as usize],
            HEX[(self.b >> 4) as usize],
            HEX[(self.b & 0xF) as usize],
        ]
    }
}

/// 语义色槽位（亮/暗主题各持一份值，槽位名固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticSlot {
    /// 主题主色（由壁纸提取）。
    Primary,
    /// 强调色。
    Accent,
    /// 正文。
    OnSurface,
    /// 表面背景。
    Surface,
}

/// 主题：语义槽位到色值的映射。
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// 语义槽位表。
    pub slots: [(SemanticSlot, ColorToken); 4],
}

impl Theme {
    /// 查询语义槽位色值。
    pub fn get(&self, slot: SemanticSlot) -> Option<ColorToken> {
        self.slots.iter().find(|(s, _)| *s == slot).map(|(_, c)| *c)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        font_size, on_grid, spacing, ColorToken, SemanticSlot, Theme, DOCK_HEIGHT, GRID,
        PANEL_HEIGHT,
    };

    #[test]
    fn spacing_stays_on_grid() {
        assert_eq!(spacing(0), 0);
        assert_eq!(spacing(6), 48);
        for step in 0..=16u32 {
            assert!(on_grid(spacing(step)));
        }
    }

    #[test]
    #[should_panic(expected = "spacing step out of grid scale")]
    fn spacing_beyond_scale_panics() {
        spacing(17);
    }

    #[test]
    fn font_formula_breathes_with_viewport() {
        assert!((font_size(1920) - 35.2).abs() < 1e-4);
        assert!((font_size(800) - 24.0).abs() < 1e-4);
    }

    #[test]
    fn skeleton_constants_match_art_guide() {
        assert_eq!(GRID, 8);
        assert_eq!(PANEL_HEIGHT, 48);
        assert_eq!(DOCK_HEIGHT, 72);
    }

    #[test]
    fn color_token_hex_roundtrip() {
        let c = ColorToken::from_hex(0xC9A84C);
        assert_eq!((c.r, c.g, c.b), (0xC9, 0xA8, 0x4C));
        assert_eq!(&c.hex_string(), b"#c9a84c");
    }

    #[test]
    fn theme_slot_lookup() {
        let t = Theme {
            slots: [
                (SemanticSlot::Primary, ColorToken::from_hex(0x1A1A1A)),
                (SemanticSlot::Accent, ColorToken::from_hex(0xC9A84C)),
                (SemanticSlot::OnSurface, ColorToken::from_hex(0x000000)),
                (SemanticSlot::Surface, ColorToken::from_hex(0xF5F2E8)),
            ],
        };
        assert_eq!(t.get(SemanticSlot::Accent).expect("accent").r, 0xC9);
        assert!(t.get(SemanticSlot::Surface).is_some());
    }
}
