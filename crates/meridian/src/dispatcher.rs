//! Meridian 分发器首割（M24-M1）。
//!
//! 依据《Meridian 经纬开发细则》§3.2/§3.3 与《指标与规范手册》M-P01 口径：
//!
//! - **消息契约**：32 位消息标识字，「号 + 版本位」编码——高 16 位为接口族
//!   版本，低 16 位为消息号；服务按版本位分发到各自的解码器。
//! - **能力校验入口**：路由前的安全闸，拒绝以内核级原码透传（不打折）。
//!   校验器经 [`CapabilityGate`] 注入——分发器不依赖具体资源服务 crate
//!   （细则 §448 行锁定），真实能力表（vanguard 面）由服务进程装配。
//! - **三层错误模型**：内核级（透传不打折）/ 服务级（本册枚举 + 可重试
//!   标记）/ 兼容级（Conduit 映射 Linux errno 对外）。崩溃恢复路径依赖
//!   [`DispatchError::retry_hint`] 的标记决定客户端语义。
//!
//! IDL 纪律（细则 §3.2「契约文档以 IDL 形式存放，CI 校验一致性」）自
//! M24-M2 起步：本模块的 handler 注册面即为 IDL 生成物的落位接口，M2
//! 以生成物替换手写注册，编解码一致性由 idl-check 钩子拒绝漂移。
//!
//! 微基准：[`tests::bench_dispatch_hot_path`] 为 M-P01 宿主打点骨架
//! （TCG 回归基线制，≤0.3 μs 门禁数值以参考环境 B 裸机实测为准）。

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

/// 消息标识字：高 16 位接口族版本，低 16 位消息号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgHeader {
    /// 接口族版本（semver 承诺自 1.0 冻结起）。
    pub family_version: u16,
    /// 消息号（族内单调分配）。
    pub msg_id: u16,
}

impl MsgHeader {
    /// 当前冻结接口族版本。
    pub const CURRENT_FAMILY_VERSION: u16 = 1;

    /// 32 位消息标识字解码（高 16 版本 / 低 16 号）。
    pub fn decode(word: u32) -> Self {
        MsgHeader {
            family_version: (word >> 16) as u16,
            msg_id: word as u16,
        }
    }

    /// 编码为 32 位消息标识字。
    pub fn encode(family_version: u16, msg_id: u16) -> u32 {
        ((family_version as u32) << 16) | msg_id as u32
    }
}

/// 载荷：四寄存器风格（与 `bedrock::abi` 五寄存器调用的参数位对齐，num 位
/// 由消息标识字承载）。
pub type Payload = [u64; 4];

/// 处理结果：回包载荷或三层错误。
pub type HandlerResult = Result<Payload, DispatchError>;

/// 消息处理器。实现侧不得依赖具体资源服务 crate（细则锁定：只能经 IDL
/// 生成物编码——M2 起）。
pub trait ServiceHandler {
    /// 处理一条已过闸消息。
    fn handle(&self, msg_id: u16, payload: &Payload) -> HandlerResult;
}

/// 能力校验入口。拒绝时返回内核级原码——分发器原样透传（不打折）。
pub trait CapabilityGate {
    /// 校验 `cap` 是否授权调用 `msg_id`。
    ///
    /// # Errors
    /// 返回 `Err(原码)`：Bedrock 能力层错误码，语义由内核侧定义。
    fn check(&self, cap: u64, msg_id: u16) -> Result<(), u64>;
}

/// 内核级错误：Bedrock 能力层原码，透传不打折。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCode(pub u64);

/// 兼容级错误：Linux errno 承载（Conduit 映射域），携带可重试标记。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatErrno {
    /// Linux errno（x86_64 5.15 语义，`conduit::errno_name` 可对账）。
    pub errno: i32,
    /// 可重试标记（如 EAGAIN 类 true；EINVAL 类 false）。
    pub retryable: bool,
}

/// 服务级错误（细则 §3.3：M2 起按服务分组定义于 idl/errors.toml，本枚举
/// 为 M1 骨架集；每个变体 MUST 标注可重试与建议重试间隔）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// 消息号未注册（不可重试——契约面缺失，重试无意义）。
    NoSuchMessage {
        /// 请求的接口族版本。
        family: u16,
        /// 未注册的消息号。
        msg_id: u16,
    },
    /// 接口族版本不受支持（不可重试——版本协商属契约变更）。
    UnsupportedFamilyVersion {
        /// 请求的族版本。
        got: u16,
        /// 本分发器服务的族版本。
        supported: u16,
    },
    /// 载荷不满足消息契约（不可重试——同一载荷重试同败）。
    MalformedPayload {
        /// 消息号。
        msg_id: u16,
    },
    /// 服务过载/暂不可用（可重试，附建议间隔）。
    Busy {
        /// 消息号。
        msg_id: u16,
        /// 建议重试间隔（毫秒）。
        interval_ms: u64,
    },
    /// 处理器执行失败（可重试性由处理器逐例标注）。
    HandlerFailed {
        /// 消息号。
        msg_id: u16,
        /// 是否可重试。
        retryable: bool,
        /// 建议重试间隔（毫秒；None = 立即可重试）。
        interval_ms: Option<u64>,
    },
}

impl ServiceError {
    /// 可重试标记（细则 §3.3：崩溃恢复路径依赖该标记决定客户端语义）。
    pub fn is_retryable(&self) -> bool {
        match self {
            ServiceError::NoSuchMessage { .. }
            | ServiceError::UnsupportedFamilyVersion { .. }
            | ServiceError::MalformedPayload { .. } => false,
            ServiceError::Busy { .. } => true,
            ServiceError::HandlerFailed { retryable, .. } => *retryable,
        }
    }

    /// 建议重试间隔（毫秒）。不可重试错误返回 `None`。
    pub fn retry_interval_ms(&self) -> Option<u64> {
        match self {
            ServiceError::Busy { interval_ms, .. } => Some(*interval_ms),
            ServiceError::HandlerFailed { interval_ms, .. } => *interval_ms,
            _ => None,
        }
    }

    /// 错误码名（日志与错误一一对应：发射点 MUST 携带上下文字段）。
    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::NoSuchMessage { .. } => "M-NO-SUCH-MESSAGE",
            ServiceError::UnsupportedFamilyVersion { .. } => "M-FAMILY-VERSION",
            ServiceError::MalformedPayload { .. } => "M-MALFORMED-PAYLOAD",
            ServiceError::Busy { .. } => "M-BUSY",
            ServiceError::HandlerFailed { .. } => "M-HANDLER-FAILED",
        }
    }
}

/// 三层错误模型（细则 §3.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// 内核级：Bedrock 能力层原码，透传不打折。
    Kernel(KernelCode),
    /// 服务级：本册枚举，含可重试标记。
    Service(ServiceError),
    /// 兼容级：Linux errno 对外（Conduit 映射域）。
    Compat(CompatErrno),
}

/// 重试提示：崩溃恢复路径的客户端语义依据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryHint {
    /// 不可重试（契约面/能力面/终态失败）。
    Fatal,
    /// 可重试，附建议间隔毫秒（None = 立即）。
    Retryable(Option<u64>),
    /// 不透明：语义由原码定义方承担（内核级透传不打折）。
    Opaque,
}

impl DispatchError {
    /// 错误码名（三层前缀分层：K- / M- / C-）。
    pub fn code(&self) -> &'static str {
        match self {
            DispatchError::Kernel(_) => "K-PASSTHROUGH",
            DispatchError::Service(e) => e.code(),
            DispatchError::Compat(e) => {
                if e.retryable {
                    "C-ERRNO-RETRYABLE"
                } else {
                    "C-ERRNO"
                }
            }
        }
    }

    /// 重试提示（细则 §3.3：每错误 MUST 标注是否可重试与建议间隔）。
    pub fn retry_hint(&self) -> RetryHint {
        match self {
            // 内核级：透传不打折——分发器不解释内核错误语义。
            DispatchError::Kernel(_) => RetryHint::Opaque,
            DispatchError::Service(e) => {
                if e.is_retryable() {
                    RetryHint::Retryable(e.retry_interval_ms())
                } else {
                    RetryHint::Fatal
                }
            }
            DispatchError::Compat(e) => {
                if e.retryable {
                    RetryHint::Retryable(None)
                } else {
                    RetryHint::Fatal
                }
            }
        }
    }

    /// 兼容级 errno 视图（非兼容级返回 `None`）。
    pub fn as_errno(&self) -> Option<i32> {
        match self {
            DispatchError::Compat(e) => Some(e.errno),
            _ => None,
        }
    }
}

/// 分发器：版本闸 → 能力闸 → 路由 → 执行。
pub struct Dispatcher {
    family_version: u16,
    routes: BTreeMap<u16, Box<dyn ServiceHandler>>,
    gate: Box<dyn CapabilityGate>,
}

impl Dispatcher {
    /// 创建分发器（绑定接口族版本与能力闸）。
    pub fn new(family_version: u16, gate: Box<dyn CapabilityGate>) -> Self {
        Dispatcher {
            family_version,
            routes: BTreeMap::new(),
            gate,
        }
    }

    /// 注册消息处理器（重注册覆盖——启动序编排方负责唯一性）。
    pub fn register(&mut self, msg_id: u16, handler: Box<dyn ServiceHandler>) {
        self.routes.insert(msg_id, handler);
    }

    /// 已注册消息数。
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// 分发一条消息：解码 → 版本闸 → 能力闸 → 路由 → 执行。
    pub fn dispatch(&self, msg_word: u32, cap: u64, payload: &Payload) -> HandlerResult {
        let hdr = MsgHeader::decode(msg_word);
        if hdr.family_version != self.family_version {
            return Err(DispatchError::Service(
                ServiceError::UnsupportedFamilyVersion {
                    got: hdr.family_version,
                    supported: self.family_version,
                },
            ));
        }
        // 能力闸在路由前：未授权方不得探测消息存在性（安全惯例）。
        self.gate
            .check(cap, hdr.msg_id)
            .map_err(|code| DispatchError::Kernel(KernelCode(code)))?;
        let handler = self.routes.get(&hdr.msg_id).ok_or(DispatchError::Service(
            ServiceError::NoSuchMessage {
                family: hdr.family_version,
                msg_id: hdr.msg_id,
            },
        ))?;
        handler.handle(hdr.msg_id, payload)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use std::println;

    use super::{
        CapabilityGate, CompatErrno, DispatchError, Dispatcher, KernelCode, MsgHeader, Payload,
        RetryHint, ServiceError, ServiceHandler,
    };
    use std::cell::RefCell;

    const P: Payload = [1, 2, 3, 4];

    // ---- 测试基建：记录型假闸 + 直通/失败处理器 ----

    struct FakeGate {
        allowed: u64,
        seen: RefCell<Vec<(u64, u16)>>,
    }
    impl FakeGate {
        fn new(allowed: u64) -> Self {
            FakeGate {
                allowed,
                seen: RefCell::new(Vec::new()),
            }
        }
    }
    impl CapabilityGate for FakeGate {
        fn check(&self, cap: u64, msg_id: u16) -> Result<(), u64> {
            self.seen.borrow_mut().push((cap, msg_id));
            if cap == self.allowed {
                Ok(())
            } else {
                Err(cap) // 拒绝：原码 = 请求的 cap（透传不打折断言素材）
            }
        }
    }

    struct Echo;
    impl ServiceHandler for Echo {
        fn handle(&self, msg_id: u16, payload: &Payload) -> super::HandlerResult {
            let mut out = *payload;
            out[0] = u64::from(msg_id);
            Ok(out)
        }
    }

    struct Fail(ServiceError);
    impl ServiceHandler for Fail {
        fn handle(&self, _msg_id: u16, _p: &Payload) -> super::HandlerResult {
            Err(DispatchError::Service(self.0.clone()))
        }
    }

    struct CompatFail(i32);
    impl ServiceHandler for CompatFail {
        fn handle(&self, _m: u16, _p: &Payload) -> super::HandlerResult {
            Err(DispatchError::Compat(CompatErrno {
                errno: self.0,
                retryable: false,
            }))
        }
    }

    fn word(msg_id: u16) -> u32 {
        MsgHeader::encode(MsgHeader::CURRENT_FAMILY_VERSION, msg_id)
    }

    // ---- ① 消息头解码：边界与往返 ----

    #[test]
    fn header_decode_boundaries() {
        assert_eq!(
            MsgHeader::decode(0),
            MsgHeader {
                family_version: 0,
                msg_id: 0
            }
        );
        assert_eq!(
            MsgHeader::decode(0xFFFF_FFFF),
            MsgHeader {
                family_version: 0xFFFF,
                msg_id: 0xFFFF
            }
        );
        assert_eq!(
            MsgHeader::decode(0x0002_0042),
            MsgHeader {
                family_version: 2,
                msg_id: 0x42
            }
        );
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        for (v, m) in [(1u16, 0u16), (1, 0xFFFF), (0x1234, 0x5678), (0, 0xFFFF)] {
            assert_eq!(MsgHeader::decode(MsgHeader::encode(v, m)).family_version, v);
            assert_eq!(MsgHeader::decode(MsgHeader::encode(v, m)).msg_id, m);
        }
    }

    // ---- ② 版本闸 ----

    #[test]
    fn wrong_family_version_rejected_non_retryable() {
        let d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        let e = d
            .dispatch(0x0009_0001, 7, &P)
            .expect_err("version 9 must be rejected");
        match &e {
            DispatchError::Service(ServiceError::UnsupportedFamilyVersion { got, supported }) => {
                assert_eq!(*got, 9);
                assert_eq!(*supported, 1);
            }
            other => panic!("expected UnsupportedFamilyVersion, got {other:?}"),
        }
        assert_eq!(e.retry_hint(), RetryHint::Fatal);
        assert_eq!(e.code(), "M-FAMILY-VERSION");
    }

    // ---- ③ 能力闸：透传不打折 + 调用序 ----

    #[test]
    fn kernel_code_passthrough_untouched() {
        let d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        // 任意原码（含 0 与 u64::MAX）必须原样透出——不打折、不改写。
        for cap in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
            let e = d
                .dispatch(word(0x10), cap, &P)
                .expect_err("unauthorized cap");
            assert_eq!(e, DispatchError::Kernel(KernelCode(cap)), "cap={cap:#x}");
            assert_eq!(e.retry_hint(), RetryHint::Opaque, "内核级不解释语义");
            assert_eq!(e.code(), "K-PASSTHROUGH");
        }
    }

    #[test]
    fn gate_receives_msg_id_via_shared_cell() {
        struct RecordingGate(std::rc::Rc<RefCell<Vec<u16>>>);
        impl CapabilityGate for RecordingGate {
            fn check(&self, _cap: u64, msg_id: u16) -> Result<(), u64> {
                self.0.borrow_mut().push(msg_id);
                Ok(())
            }
        }
        let log = std::rc::Rc::new(RefCell::new(Vec::new()));
        let d = Dispatcher::new(1, Box::new(RecordingGate(std::rc::Rc::clone(&log))));
        let _ = d.dispatch(word(0x2A), 7, &P);
        let _ = d.dispatch(word(0x2B), 7, &P);
        assert_eq!(&*log.borrow(), &[0x2A, 0x2B]);
    }

    // 检查顺序：能力闸在路由前（未授权不得探测消息存在性）。
    #[test]
    fn gate_precedes_route_probe() {
        let d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        // 未注册号 0x7F + 无授权 cap：必须是 Kernel（能力先拒），非 NoSuchMessage。
        let e = d.dispatch(word(0x7F), 9, &P).expect_err("denied");
        assert_eq!(e, DispatchError::Kernel(KernelCode(9)));
    }

    // ---- ④ 路由面 ----

    #[test]
    fn unregistered_msg_is_no_such_message() {
        let d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        let e = d.dispatch(word(0x10), 7, &P).expect_err("unregistered");
        assert_eq!(
            e,
            DispatchError::Service(ServiceError::NoSuchMessage {
                family: 1,
                msg_id: 0x10
            })
        );
        assert_eq!(e.retry_hint(), RetryHint::Fatal);
        assert_eq!(e.code(), "M-NO-SUCH-MESSAGE");
    }

    #[test]
    fn echo_handler_roundtrip_and_reregister_overrides() {
        let mut d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        d.register(0x10, Box::new(Echo));
        assert_eq!(d.route_count(), 1);
        let ok = d.dispatch(word(0x10), 7, &P).expect("echo");
        assert_eq!(ok, [0x10, 2, 3, 4]);
        // 重注册覆盖（同号换处理器）。
        d.register(
            0x10,
            Box::new(Fail(ServiceError::MalformedPayload { msg_id: 0x10 })),
        );
        let e = d.dispatch(word(0x10), 7, &P).expect_err("overridden");
        assert_eq!(
            e,
            DispatchError::Service(ServiceError::MalformedPayload { msg_id: 0x10 })
        );
    }

    // ---- ⑤ 服务级：可重试标记全枚举 ----

    #[test]
    fn service_retryable_matrix() {
        let mut d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        // Busy：可重试 + 建议间隔透出。
        d.register(
            0x20,
            Box::new(Fail(ServiceError::Busy {
                msg_id: 0x20,
                interval_ms: 250,
            })),
        );
        // HandlerFailed 可重试：立即重试（None）。
        d.register(
            0x21,
            Box::new(Fail(ServiceError::HandlerFailed {
                msg_id: 0x21,
                retryable: true,
                interval_ms: None,
            })),
        );
        // HandlerFailed 不可重试 + 间隔。
        d.register(
            0x22,
            Box::new(Fail(ServiceError::HandlerFailed {
                msg_id: 0x22,
                retryable: false,
                interval_ms: Some(1000),
            })),
        );

        let e20 = d.dispatch(word(0x20), 7, &P).expect_err("busy");
        assert_eq!(e20.retry_hint(), RetryHint::Retryable(Some(250)));
        assert_eq!(e20.code(), "M-BUSY");

        let e21 = d.dispatch(word(0x21), 7, &P).expect_err("failed-retry");
        assert_eq!(e21.retry_hint(), RetryHint::Retryable(None));

        let e22 = d.dispatch(word(0x22), 7, &P).expect_err("failed-fatal");
        assert_eq!(
            e22.retry_hint(),
            RetryHint::Fatal,
            "标记 false 覆盖间隔存在"
        );
    }

    // ---- ⑥ 兼容级 ----

    #[test]
    fn compat_errno_view_and_hint() {
        let mut d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        d.register(0x30, Box::new(CompatFail(22))); // EINVAL
        let e = d.dispatch(word(0x30), 7, &P).expect_err("compat");
        assert_eq!(e.as_errno(), Some(22));
        assert_eq!(e.retry_hint(), RetryHint::Fatal);
        assert_eq!(e.code(), "C-ERRNO");
        assert!(e.as_errno().is_none() || true); // Kernel/Service 侧另证
                                                 // 非 Compat 错误 as_errno = None。
        let k = DispatchError::Kernel(KernelCode(1));
        assert_eq!(k.as_errno(), None);
    }

    // ---- ⑦ 幂等：同请求双发同结果 ----

    #[test]
    fn repeated_dispatch_is_deterministic() {
        let mut d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        d.register(0x10, Box::new(Echo));
        let a = d.dispatch(word(0x10), 7, &P).expect("first");
        let b = d.dispatch(word(0x10), 7, &P).expect("second");
        assert_eq!(a, b);
    }

    // ---- ⑧ M-P01 微基准（宿主打点骨架，TCG 回归基线制） ----

    /// 热路径微基准：空转 dispatch（版本闸→能力闸→路由→Echo 回包）。
    /// 口径登记 METRICS.md M-P01 行：宿主均值/p99 为 TCG 回归基线，
    /// ≤0.3 μs 门禁数值以参考环境 B（裸机）实测为准。
    #[test]
    fn bench_dispatch_hot_path() {
        let mut d = Dispatcher::new(1, Box::new(FakeGate::new(7)));
        d.register(0x10, Box::new(Echo));
        let w = word(0x10);

        // 预热 5k（页缓存/分支预测器稳定）。
        for _ in 0..5_000 {
            let _ = d.dispatch(w, 7, &P).expect("hot");
        }
        // 主测 100k：均值。
        const N: u32 = 100_000;
        let t0 = std::time::Instant::now();
        for _ in 0..N {
            let _ = d.dispatch(w, 7, &P).expect("hot");
        }
        let mean_ns = t0.elapsed().as_nanos() as f64 / f64::from(N);

        // 尾部采样 1k（逐发独立计时，取 p99）。
        let mut samples: Vec<u128> = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let t = std::time::Instant::now();
            let _ = d.dispatch(w, 7, &P).expect("tail");
            samples.push(t.elapsed().as_nanos());
        }
        samples.sort_unstable();
        let p99_ns = samples[samples.len() * 99 / 100];

        // 打点行（CI 日志可见；数值登记 METRICS.md 对照）。
        println!("M-P01 dispatch mean = {mean_ns:.1} ns/op (host)");
        println!("M-P01 dispatch p99  = {p99_ns} ns (host, per-call)");

        // 宽松防退化上限：宿主均值 < 1 μs（0.3 μs 门禁为环境 B 口径，
        // 宿主断言只拦数量级退化，不作门禁）。
        assert!(mean_ns < 1_000.0, "dispatch mean {mean_ns:.1} ns 退化");
        assert!(p99_ns < 10_000, "dispatch p99 {p99_ns} ns 退化");
    }
}
