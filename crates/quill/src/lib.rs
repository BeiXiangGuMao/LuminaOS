//! Quill 羽管笔 —— 终端文本规程纯函数面（M34-D2 旁路缩编批次二外移）。
//!
//! **外移宣言**（M31-N1 三分分级兑现）：本 crate 承载 console/tty 的
//! **纯函数面**——零依赖、零 unsafe、零电气（`forbid(unsafe_code)`
//! 与零 Cargo 依赖并存，harbor 同款纪律）。kernel 电气面（串口端口 I/O、
//! 行缓冲 static 域）零改动，消费面切换至本面（缩编起算域：M31-N1
//! 台账 P5 行续记）。
//!
//! 两面——其一为 console 字节翻译（[`console::translate_log_bytes`]）：
//! 串口日志路径的纯翻译核，`\n` → CRLF 展开、可打印域直通、控制字节
//! → `'.'` 占位、尾部 CRLF 追加；原形态为 kernel::console::
//! serial_log_bytes 内联逻辑（M13-② 起），外移后 kernel 以闭包下发电
//! 气发送（零分配，emit 流式下发）。其二为 tty 行编辑分类
//! （[`line::classify`] + [`line::LineAction`]）：行规程单字节分类状
//! 态机，提交/退格/追加/忽略四动作（M23-① 最小行规程语义——回车提交、
//! `\b` 抹迹、可打印入缓冲、余者忽略；长度上界由调用方 len/cap 传入，
//! 分类器纯函数无状态）。
//! 宿主对账：golden 测试全谱在库（翻译九目 + 分类十二目）。
#![no_std]
#![forbid(unsafe_code)]

pub mod console;
pub mod line;
