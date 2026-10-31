//! sh 流水线解析面（M35-BBb 笔⑦ 首割）——单级 `|` 命令线解析，纯函数
//! 宿主可测（bedrock::elf 解析面同款纪律）。
//!
//! v0 口径（t85 sh 流水线活体消费面）：
//! - 单级 `|`（多级级联随 sh 批次三挂账）；
//! - 空白分词（无引号域——引号承载挂账，fail-visible：含引号段解析
//!   原样保留引号字符由消费方 argv 语义承担，不预解释）；
//! - 任一段空白词元空 = 解析失败 `None`（fail-visible——`"yes |"`/
//!   `"| head"`/`"a || b"` 空段拒绝，不静默截断）；
//! - 返回 `Some(stages)`：按 `|` 切分的逐段 argv 词元表（左→右域序，
//!   与 fork/pipe2/dup2/execve 两段串联编排的消费序一致）。
//!
//! 消费面：kernel 自检 t85（M35-BBb）——`"yes | head -n 3"` 两段
//! argv → A 段 stdout 接管写端 + B 段 stdin 接管读端（spawn_fork_child_
//! wired 接线铸槽 = dup2 等价面）→ busybox 真流管道串联实证。

use alloc::vec::Vec;

/// 单级流水线解析：`line` → 逐段 argv 词元表。
///
/// - 无 `|`：单段词元表（单命令形态，消费方按段数分派）；
/// - 有 `|`：切分后逐段分词；任一段空 = `None`；
/// - 全空白行 = `None`（无命令）。
pub fn parse_pipeline(line: &str) -> Option<Vec<Vec<&str>>> {
    let stages: Vec<Vec<&str>> = line
        .split('|')
        .map(|seg| seg.split_whitespace().collect::<Vec<&str>>())
        .collect();
    // 全空白 = 无命令（fail-visible）
    if stages.iter().all(|s| s.is_empty()) {
        return None;
    }
    // 任一段空 = 悬垂管道（`yes |` / `| head` / `a || b`）——拒绝
    if stages.iter().any(|s| s.is_empty()) {
        return None;
    }
    Some(stages)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::parse_pipeline;
    use alloc::vec;

    #[test]
    fn two_stage_basic() {
        let st = parse_pipeline("yes | head -n 3").expect("two-stage parse");
        assert_eq!(st.len(), 2);
        assert_eq!(st[0], vec!["yes"]);
        assert_eq!(st[1], vec!["head", "-n", "3"]);
    }

    #[test]
    fn single_command_no_pipe() {
        let st = parse_pipeline("echo hi").expect("single parse");
        assert_eq!(st.len(), 1);
        assert_eq!(st[0], vec!["echo", "hi"]);
    }

    #[test]
    fn dangling_right_rejected() {
        assert!(parse_pipeline("yes |").is_none());
    }

    #[test]
    fn dangling_left_rejected() {
        assert!(parse_pipeline("| head").is_none());
    }

    #[test]
    fn double_pipe_empty_middle_rejected() {
        assert!(parse_pipeline("yes || head").is_none());
    }

    #[test]
    fn blank_line_rejected() {
        assert!(parse_pipeline("   ").is_none());
        assert!(parse_pipeline("").is_none());
    }

    #[test]
    fn multi_space_tolerated() {
        let st = parse_pipeline("  yes   |   head  -n  3 ").expect("spacing parse");
        assert_eq!(st[0], vec!["yes"]);
        assert_eq!(st[1], vec!["head", "-n", "3"]);
    }
}
