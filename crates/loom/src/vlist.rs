//! 虚拟化列表 —— 可见窗纯函数（零堆零状态）。
//!
//! 大列表只渲染视口内条目（虚拟化）：给定条目总数、等高条目高、视口高
//! 与滚动偏移，产出可见窗（首条索引 / 可见条数 / 首条被遮挡的头部像素）。
//! 滚动偏移钳位到内容末端（越界滚动不产生负域，确定性收敛）。
//!
//! 纯函数无副作用——调用方以任意状态机承接滚动输入（Cascade shell 面
//! 或应用 Model），本面只回答「此刻该画哪些、从哪儿开始画」。

/// 可见窗（虚拟化列表输出面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualWindow {
    /// 可见首条索引。
    pub first: usize,
    /// 可见条数（≤ 剩余条目数）。
    pub count: usize,
    /// 首条被视口上沿遮挡的头部像素（0..item_h）。
    pub head_skip: u32,
}

/// 计算可见窗。
///
/// 退化输入（零条目 / 零条高 / 零视口）→ 空窗 `{0,0,0}`；滚动钳位到
/// `max(total_h − viewport_h, 0)`；可见条数按 `ceil((viewport + head_skip)
/// / item_h)` 计（首尾条被部分遮挡也计入），再钳位到剩余条目数。
pub fn virtual_window(
    item_count: usize,
    item_h: u32,
    viewport_h: u32,
    scroll: u32,
) -> VirtualWindow {
    if item_count == 0 || item_h == 0 || viewport_h == 0 {
        return VirtualWindow {
            first: 0,
            count: 0,
            head_skip: 0,
        };
    }
    let total = (item_count as u64) * item_h as u64;
    let max_scroll = total.saturating_sub(viewport_h as u64);
    let s = (scroll as u64).min(max_scroll);
    let first = (s / item_h as u64) as usize;
    let head_skip = (s % item_h as u64) as u32;
    let visible = (viewport_h as u64 + head_skip as u64).div_ceil(item_h as u64);
    let count = (visible as usize).min(item_count - first);
    VirtualWindow {
        first,
        count,
        head_skip,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::virtual_window;

    #[test]
    fn full_list_at_top() {
        let w = virtual_window(100, 48, 960, 0);
        assert_eq!((w.first, w.count, w.head_skip), (0, 20, 0));
    }

    #[test]
    fn partial_head_offset_counts_extra_item() {
        // scroll=53：首条 48px 露出 5px 后是第 1 条，视口内首尾各半条 → 21 条
        let w = virtual_window(100, 48, 960, 53);
        assert_eq!((w.first, w.count, w.head_skip), (1, 21, 5));
    }

    #[test]
    fn scroll_clamps_to_end() {
        let w = virtual_window(100, 48, 960, 100_000);
        assert_eq!((w.first, w.count, w.head_skip), (80, 20, 0));
    }

    #[test]
    fn exact_fit_scroll_beyond_total_is_noop() {
        // 20 条恰满一屏：内容末端 = 滚动起点，任何滚动都不动
        let w = virtual_window(20, 48, 960, 960);
        assert_eq!((w.first, w.count, w.head_skip), (0, 20, 0));
    }

    #[test]
    fn degenerate_inputs_yield_empty_window() {
        let a = virtual_window(0, 48, 960, 0);
        let b = virtual_window(100, 0, 960, 0);
        let c = virtual_window(100, 48, 0, 0);
        for w in [a, b, c] {
            assert_eq!((w.first, w.count, w.head_skip), (0, 0, 0));
        }
    }

    #[test]
    fn tiny_list_never_overranges() {
        // 3 条 96px、视口 960：可见 960/96=10 → 钳位 3
        let w = virtual_window(3, 96, 960, 0);
        assert_eq!((w.first, w.count, w.head_skip), (0, 3, 0));
    }
}
