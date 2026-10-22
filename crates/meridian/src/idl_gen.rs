//! vfs-registry 契约生成物（IDL 纪律，M24-M2 起步）。
//!
//! 本文件由 `cargo run -p xtask -- idl-gen` 生成 —— 禁止手编。
//! 契约源：crates/meridian/idl/vfs-registry.toml（消息面）与 crates/meridian/idl/errors.toml（组错误集）。
//! 一致性由 `cargo run -p xtask -- idl-check`（ci S5b-idl 阶段）以字节级
//! 比对守护：任何手编在下一轮 ci 即被拒绝。契约变更流程：改 toml →
//! idl-gen → 生成物随契约同批提交。
//!
//! VFS 注册策略面：挂载点注册/注销/统计/事件订阅四操作（极小面草案）
//!
//! 载荷模型：dispatcher::Payload = [u64; 4]（四寄存器；消息标识字高 16 位
//! 族版本 / 低 16 位消息号，见 dispatcher::MsgHeader）。解码纪律 strict：
//! 保留寄存器 MUST 为 0，非零即拒（DecodeError::ReservedNonZero）。
//! 组错误映射：errno 绑定 → DispatchError::Compat（草案；开放问题见契约头注）。

use crate::dispatcher::{
    CompatErrno, DispatchError, Dispatcher, Payload, ServiceError, ServiceHandler,
};
use std::sync::Arc;

/// 接口族版本（契约 family_version；版本闸语义见 dispatcher）。
pub const FAMILY_VERSION: u16 = 1;

/// 消息号：Register —— 注册文件系统挂载点，返回注册令牌（后续操作的关联键）
pub const MSG_REGISTER: u16 = 0x0001;

/// 消息号：Unregister —— 按令牌注销挂载点，返回释放计数
pub const MSG_UNREGISTER: u16 = 0x0002;

/// 消息号：Statfs —— 按路径查询文件系统统计面（块规模与旗标）
pub const MSG_STATFS: u16 = 0x0003;

/// 消息号：Events —— 订阅注册表变更事件（挂载/注销），返回事件队列标识
pub const MSG_EVENTS: u16 = 0x0004;

/// 消息描述条目（自省表元素：注册面与诊断共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// 消息号。
    pub number: u16,
    /// 消息名（契约原文）。
    pub name: &'static str,
}

/// 全消息自省表（按消息号升序；与常量一致性由生成物测试锁定）。
pub const MESSAGES: &[MessageInfo] = &[
    MessageInfo {
        number: MSG_REGISTER,
        name: "Register",
    },
    MessageInfo {
        number: MSG_UNREGISTER,
        name: "Unregister",
    },
    MessageInfo {
        number: MSG_STATFS,
        name: "Statfs",
    },
    MessageInfo {
        number: MSG_EVENTS,
        name: "Events",
    },
];

// ---------------------------------------------------------------- Register

/// 注册文件系统挂载点，返回注册令牌（后续操作的关联键）（request面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRequest {
    /// 路径缓冲区指针（调用方线性地址）（寄存器 0）。
    pub path_ptr: u64,
    /// 路径字节数（不含 NUL 终止符）（寄存器 1）。
    pub path_len: u64,
    /// 文件系统类型枚举（0 = LFS，1 = RAMFS）（寄存器 2）。
    pub fs_kind: u64,
    /// 注册旗标位面（0 = 默认）（寄存器 3）。
    pub flags: u64,
}

impl RegisterRequest {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.path_ptr, self.path_len, self.fs_kind, self.flags]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 本消息无保留槽，当前恒 `Ok`（签名统一以稳适配器面）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        Ok(Self {
            path_ptr: p[0],
            path_len: p[1],
            fs_kind: p[2],
            flags: p[3],
        })
    }
}

/// 注册文件系统挂载点，返回注册令牌（后续操作的关联键）（response面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterResponse {
    /// 注册令牌（注销与事件订阅的关联键）（寄存器 0）。
    pub token: u64,
}

impl RegisterResponse {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.token, 0, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[1] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 1 });
        }
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self { token: p[0] })
    }
}

// ---------------------------------------------------------------- Unregister

/// 按令牌注销挂载点，返回释放计数（request面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnregisterRequest {
    /// 注册令牌（Register 应答颁发）（寄存器 0）。
    pub token: u64,
    /// 注销旗标位面（0 = 默认）（寄存器 1）。
    pub flags: u64,
}

impl UnregisterRequest {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.token, self.flags, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self {
            token: p[0],
            flags: p[1],
        })
    }
}

/// 按令牌注销挂载点，返回释放计数（response面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnregisterResponse {
    /// 释放计数（1 = 已注销）（寄存器 0）。
    pub released: u64,
}

impl UnregisterResponse {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.released, 0, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[1] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 1 });
        }
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self { released: p[0] })
    }
}

// ---------------------------------------------------------------- Statfs

/// 按路径查询文件系统统计面（块规模与旗标）（request面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatfsRequest {
    /// 路径缓冲区指针（调用方线性地址）（寄存器 0）。
    pub path_ptr: u64,
    /// 路径字节数（不含 NUL 终止符）（寄存器 1）。
    pub path_len: u64,
}

impl StatfsRequest {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.path_ptr, self.path_len, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self {
            path_ptr: p[0],
            path_len: p[1],
        })
    }
}

/// 按路径查询文件系统统计面（块规模与旗标）（response面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatfsResponse {
    /// 块字节（2 的幂约定）（寄存器 0）。
    pub block_size: u64,
    /// 总块数（寄存器 1）。
    pub blocks_total: u64,
    /// 空闲块数（寄存器 2）。
    pub blocks_free: u64,
    /// 文件系统旗标位面（0 = 默认）（寄存器 3）。
    pub fs_flags: u64,
}

impl StatfsResponse {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [
            self.block_size,
            self.blocks_total,
            self.blocks_free,
            self.fs_flags,
        ]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 本消息无保留槽，当前恒 `Ok`（签名统一以稳适配器面）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        Ok(Self {
            block_size: p[0],
            blocks_total: p[1],
            blocks_free: p[2],
            fs_flags: p[3],
        })
    }
}

// ---------------------------------------------------------------- Events

/// 订阅注册表变更事件（挂载/注销），返回事件队列标识（request面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsRequest {
    /// 事件掩码位面（位 0 = 挂载，位 1 = 注销）（寄存器 0）。
    pub mask: u64,
    /// 事件队列深度（1..=4096）（寄存器 1）。
    pub queue_depth: u64,
}

impl EventsRequest {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.mask, self.queue_depth, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self {
            mask: p[0],
            queue_depth: p[1],
        })
    }
}

/// 订阅注册表变更事件（挂载/注销），返回事件队列标识（response面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsResponse {
    /// 事件队列标识（pulse SocketAddr 承载前置占位，M27 对账）（寄存器 0）。
    pub queue_id: u64,
}

impl EventsResponse {
    /// 编码为四寄存器载荷（保留槽补零）。
    pub fn encode(self) -> Payload {
        [self.queue_id, 0, 0, 0]
    }

    /// 从载荷严格解码。
    ///
    /// # Errors
    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。
    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {
        if p[1] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 1 });
        }
        if p[2] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 2 });
        }
        if p[3] != 0 {
            return Err(DecodeError::ReservedNonZero { reg: 3 });
        }
        Ok(Self { queue_id: p[0] })
    }
}

/// 严格解码错误（生成面统一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// 保留寄存器非零（strict 纪律：保留位 MUST 为 0，防语义漂移夹带）。
    ReservedNonZero {
        /// 违约寄存器槽位。
        reg: u8,
    },
}

/// vfs-registry 服务组错误集（idl/errors.toml 生成；细则 §3.3 按服务分组）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsRegistryError {
    /// 挂载点已注册（EEXIST 语义；同路径重复注册被拒）
    AlreadyRegistered,
    /// 挂载点未注册（ENOENT 语义；令牌或路径无对应注册项）
    NotRegistered,
    /// 路径非法（EINVAL 语义；指针/长度不成立或路径格式违约）
    PathInvalid,
    /// 文件系统类型不支持（ENODEV 语义；fs_kind 枚举值未注册）
    FsKindUnsupported,
    /// 注册表过载（EAGAIN 语义；建议 50 ms 后重试）
    RegistryBusy,
}

impl VfsRegistryError {
    /// 错误码名（M-VFS-* 前缀分层；日志与错误一一对应）。
    pub fn code(self) -> &'static str {
        match self {
            Self::AlreadyRegistered => "M-VFS-ALREADY-REGISTERED",
            Self::NotRegistered => "M-VFS-NOT-REGISTERED",
            Self::PathInvalid => "M-VFS-PATH-INVALID",
            Self::FsKindUnsupported => "M-VFS-FS-UNSUPPORTED",
            Self::RegistryBusy => "M-VFS-REGISTRY-BUSY",
        }
    }

    /// 可重试标记（崩溃恢复路径的客户端语义依据）。
    pub fn is_retryable(self) -> bool {
        match self {
            Self::AlreadyRegistered => false,
            Self::NotRegistered => false,
            Self::PathInvalid => false,
            Self::FsKindUnsupported => false,
            Self::RegistryBusy => true,
        }
    }

    /// 建议重试间隔（毫秒；不可重试项为 `None`）。
    pub fn retry_interval_ms(self) -> Option<u64> {
        match self {
            Self::AlreadyRegistered => None,
            Self::NotRegistered => None,
            Self::PathInvalid => None,
            Self::FsKindUnsupported => None,
            Self::RegistryBusy => Some(50),
        }
    }

    /// Linux errno 绑定（x86_64 5.15；与 conduit::errno_name 快照对账）。
    pub fn errno(self) -> i32 {
        match self {
            Self::AlreadyRegistered => 17,
            Self::NotRegistered => 2,
            Self::PathInvalid => 22,
            Self::FsKindUnsupported => 19,
            Self::RegistryBusy => 11,
        }
    }

    /// 草案映射：经 errno 绑定走兼容级面（[`DispatchError::Compat`]）。
    ///
    /// 组内 errno 唯一（契约校验器强制）保客户端可辨识性；组 code 名在
    /// 分发层载体的身份保全为开放问题（契约头注，Conduit 接入批次裁决）。
    pub fn into_dispatch_error(self) -> DispatchError {
        DispatchError::Compat(CompatErrno {
            errno: self.errno(),
            retryable: self.is_retryable(),
        })
    }
}

/// vfs-registry 服务实现面（生成骨架：实现方提供类型化操作；错误面为组错误集
/// [`VfsRegistryError`]）。
pub trait VfsRegistryService {
    /// 注册文件系统挂载点，返回注册令牌（后续操作的关联键）
    ///
    /// # Errors
    /// 组错误集语义（逐项标注见 [`VfsRegistryError`] 变体文档）。
    fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, VfsRegistryError>;

    /// 按令牌注销挂载点，返回释放计数
    ///
    /// # Errors
    /// 组错误集语义（逐项标注见 [`VfsRegistryError`] 变体文档）。
    fn unregister(&self, req: UnregisterRequest) -> Result<UnregisterResponse, VfsRegistryError>;

    /// 按路径查询文件系统统计面（块规模与旗标）
    ///
    /// # Errors
    /// 组错误集语义（逐项标注见 [`VfsRegistryError`] 变体文档）。
    fn statfs(&self, req: StatfsRequest) -> Result<StatfsResponse, VfsRegistryError>;

    /// 订阅注册表变更事件（挂载/注销），返回事件队列标识
    ///
    /// # Errors
    /// 组错误集语义（逐项标注见 [`VfsRegistryError`] 变体文档）。
    fn events(&self, req: EventsRequest) -> Result<EventsResponse, VfsRegistryError>;
}

/// 消息操作标签（适配器分派用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Register,
    Unregister,
    Statfs,
    Events,
}

/// 类型化服务 → 分发器的适配器（生成物注册面的执行体）。
struct Adapter {
    op: Op,
    svc: Arc<dyn VfsRegistryService>,
}

impl ServiceHandler for Adapter {
    fn handle(&self, msg_id: u16, payload: &Payload) -> Result<Payload, DispatchError> {
        match self.op {
            Op::Register => {
                let req = RegisterRequest::decode(payload).map_err(|_| {
                    DispatchError::Service(ServiceError::MalformedPayload { msg_id })
                })?;
                let resp = self
                    .svc
                    .register(req)
                    .map_err(|e| e.into_dispatch_error())?;
                Ok(resp.encode())
            }
            Op::Unregister => {
                let req = UnregisterRequest::decode(payload).map_err(|_| {
                    DispatchError::Service(ServiceError::MalformedPayload { msg_id })
                })?;
                let resp = self
                    .svc
                    .unregister(req)
                    .map_err(|e| e.into_dispatch_error())?;
                Ok(resp.encode())
            }
            Op::Statfs => {
                let req = StatfsRequest::decode(payload).map_err(|_| {
                    DispatchError::Service(ServiceError::MalformedPayload { msg_id })
                })?;
                let resp = self.svc.statfs(req).map_err(|e| e.into_dispatch_error())?;
                Ok(resp.encode())
            }
            Op::Events => {
                let req = EventsRequest::decode(payload).map_err(|_| {
                    DispatchError::Service(ServiceError::MalformedPayload { msg_id })
                })?;
                let resp = self.svc.events(req).map_err(|e| e.into_dispatch_error())?;
                Ok(resp.encode())
            }
        }
    }
}

/// 生成物注册面：把四操作接入分发器（M1 前向声明「以生成物替换手写注册」
/// 的落位接口；消息号与族版本取自契约常量）。
pub fn attach(d: &mut Dispatcher, svc: Arc<dyn VfsRegistryService>) {
    d.register(
        MSG_REGISTER,
        Box::new(Adapter {
            op: Op::Register,
            svc: Arc::clone(&svc),
        }),
    );
    d.register(
        MSG_UNREGISTER,
        Box::new(Adapter {
            op: Op::Unregister,
            svc: Arc::clone(&svc),
        }),
    );
    d.register(
        MSG_STATFS,
        Box::new(Adapter {
            op: Op::Statfs,
            svc: Arc::clone(&svc),
        }),
    );
    d.register(
        MSG_EVENTS,
        Box::new(Adapter {
            op: Op::Events,
            svc,
        }),
    );
}

// ---------------------------------------------------------------- 生成物自测

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        attach, DecodeError, EventsRequest, EventsResponse, RegisterRequest, RegisterResponse,
        StatfsRequest, StatfsResponse, UnregisterRequest, UnregisterResponse, VfsRegistryError,
        VfsRegistryService, FAMILY_VERSION, MESSAGES, MSG_EVENTS, MSG_REGISTER, MSG_STATFS,
        MSG_UNREGISTER,
    };
    use crate::dispatcher::{CapabilityGate, DispatchError, Dispatcher, MsgHeader};

    /// 测试闸：全放行（能力面语义由 dispatcher 自测覆盖）。
    struct AllowGate;
    impl CapabilityGate for AllowGate {
        fn check(&self, _cap: u64, _msg_id: u16) -> Result<(), u64> {
            Ok(())
        }
    }

    /// 假服务：逐操作固定应答；末位消息（Events）恒返 NotRegistered（错误路径取证）。
    struct FakeService;
    impl VfsRegistryService for FakeService {
        fn register(&self, _req: RegisterRequest) -> Result<RegisterResponse, VfsRegistryError> {
            Ok(RegisterResponse { token: 1 })
        }
        fn unregister(
            &self,
            _req: UnregisterRequest,
        ) -> Result<UnregisterResponse, VfsRegistryError> {
            Ok(UnregisterResponse { released: 1 })
        }
        fn statfs(&self, _req: StatfsRequest) -> Result<StatfsResponse, VfsRegistryError> {
            Ok(StatfsResponse {
                block_size: 1,
                blocks_total: 2,
                blocks_free: 3,
                fs_flags: 4,
            })
        }
        fn events(&self, _req: EventsRequest) -> Result<EventsResponse, VfsRegistryError> {
            Err(VfsRegistryError::NotRegistered)
        }
    }

    #[test]
    fn family_version_frozen() {
        assert_eq!(FAMILY_VERSION, 1);
    }

    #[test]
    fn message_table_matches_constants() {
        assert_eq!(MESSAGES.len(), 4);
        assert_eq!(MESSAGES[0].number, MSG_REGISTER);
        assert_eq!(MESSAGES[0].name, "Register");
        assert_eq!(MESSAGES[1].number, MSG_UNREGISTER);
        assert_eq!(MESSAGES[1].name, "Unregister");
        assert_eq!(MESSAGES[2].number, MSG_STATFS);
        assert_eq!(MESSAGES[2].name, "Statfs");
        assert_eq!(MESSAGES[3].number, MSG_EVENTS);
        assert_eq!(MESSAGES[3].name, "Events");
        assert!(
            MESSAGES.windows(2).all(|w| w[0].number < w[1].number),
            "自省表升序"
        );
    }

    #[test]
    fn register_roundtrip() {
        let req = RegisterRequest {
            path_ptr: 1,
            path_len: 2,
            fs_kind: 3,
            flags: 4,
        };
        assert_eq!(RegisterRequest::decode(&req.encode()), Ok(req));
        let resp = RegisterResponse { token: 1 };
        assert_eq!(RegisterResponse::decode(&resp.encode()), Ok(resp));
    }

    #[test]
    fn unregister_roundtrip() {
        let req = UnregisterRequest { token: 1, flags: 2 };
        assert_eq!(UnregisterRequest::decode(&req.encode()), Ok(req));
        let resp = UnregisterResponse { released: 1 };
        assert_eq!(UnregisterResponse::decode(&resp.encode()), Ok(resp));
    }

    #[test]
    fn statfs_roundtrip() {
        let req = StatfsRequest {
            path_ptr: 1,
            path_len: 2,
        };
        assert_eq!(StatfsRequest::decode(&req.encode()), Ok(req));
        let resp = StatfsResponse {
            block_size: 1,
            blocks_total: 2,
            blocks_free: 3,
            fs_flags: 4,
        };
        assert_eq!(StatfsResponse::decode(&resp.encode()), Ok(resp));
    }

    #[test]
    fn events_roundtrip() {
        let req = EventsRequest {
            mask: 1,
            queue_depth: 2,
        };
        assert_eq!(EventsRequest::decode(&req.encode()), Ok(req));
        let resp = EventsResponse { queue_id: 1 };
        assert_eq!(EventsResponse::decode(&resp.encode()), Ok(resp));
    }

    #[test]
    fn strict_decode_rejects_nonzero_reserved() {
        let mut p = RegisterResponse { token: 1 }.encode();
        p[1] = 9;
        assert_eq!(
            RegisterResponse::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 1 })
        );
        let mut p = UnregisterRequest { token: 1, flags: 2 }.encode();
        p[2] = 9;
        assert_eq!(
            UnregisterRequest::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 2 })
        );
        let mut p = UnregisterResponse { released: 1 }.encode();
        p[1] = 9;
        assert_eq!(
            UnregisterResponse::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 1 })
        );
        let mut p = StatfsRequest {
            path_ptr: 1,
            path_len: 2,
        }
        .encode();
        p[2] = 9;
        assert_eq!(
            StatfsRequest::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 2 })
        );
        let mut p = EventsRequest {
            mask: 1,
            queue_depth: 2,
        }
        .encode();
        p[2] = 9;
        assert_eq!(
            EventsRequest::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 2 })
        );
        let mut p = EventsResponse { queue_id: 1 }.encode();
        p[1] = 9;
        assert_eq!(
            EventsResponse::decode(&p),
            Err(DecodeError::ReservedNonZero { reg: 1 })
        );
    }

    #[test]
    fn error_table_matches_contract() {
        let table: [(VfsRegistryError, &'static str, i32, bool, Option<u64>); 5] = [
            (
                VfsRegistryError::AlreadyRegistered,
                "M-VFS-ALREADY-REGISTERED",
                17,
                false,
                None,
            ),
            (
                VfsRegistryError::NotRegistered,
                "M-VFS-NOT-REGISTERED",
                2,
                false,
                None,
            ),
            (
                VfsRegistryError::PathInvalid,
                "M-VFS-PATH-INVALID",
                22,
                false,
                None,
            ),
            (
                VfsRegistryError::FsKindUnsupported,
                "M-VFS-FS-UNSUPPORTED",
                19,
                false,
                None,
            ),
            (
                VfsRegistryError::RegistryBusy,
                "M-VFS-REGISTRY-BUSY",
                11,
                true,
                Some(50),
            ),
        ];
        for (e, code, errno, retryable, interval) in table {
            assert_eq!(e.code(), code);
            assert_eq!(e.errno(), errno);
            assert_eq!(e.is_retryable(), retryable);
            assert_eq!(e.retry_interval_ms(), interval);
        }
    }

    #[test]
    fn errno_bindings_unique_in_group() {
        let all = [
            VfsRegistryError::AlreadyRegistered,
            VfsRegistryError::NotRegistered,
            VfsRegistryError::PathInvalid,
            VfsRegistryError::FsKindUnsupported,
            VfsRegistryError::RegistryBusy,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i < j {
                    assert_ne!(a.errno(), b.errno(), "组内 errno 单射");
                }
            }
        }
    }

    #[test]
    fn into_dispatch_maps_compat_layer() {
        let all = [
            VfsRegistryError::AlreadyRegistered,
            VfsRegistryError::NotRegistered,
            VfsRegistryError::PathInvalid,
            VfsRegistryError::FsKindUnsupported,
            VfsRegistryError::RegistryBusy,
        ];
        for e in all {
            match e.into_dispatch_error() {
                DispatchError::Compat(c) => {
                    assert_eq!(c.errno, e.errno());
                    assert_eq!(c.retryable, e.is_retryable());
                }
                other => panic!("期望 Compat 载体，实得 {other:?}"),
            }
        }
    }

    #[test]
    fn attach_demuxes_typed_roundtrip() {
        let mut d = Dispatcher::new(FAMILY_VERSION, Box::new(AllowGate));
        attach(&mut d, std::sync::Arc::new(FakeService));
        assert_eq!(d.route_count(), 4);

        // Register 全链：类型化请求 → dispatch → 类型化应答。
        let req = RegisterRequest {
            path_ptr: 1,
            path_len: 2,
            fs_kind: 3,
            flags: 4,
        };
        let word = MsgHeader::encode(FAMILY_VERSION, MSG_REGISTER);
        let out = d.dispatch(word, 0, &req.encode()).expect("register 应成功");
        assert_eq!(
            RegisterResponse::decode(&out),
            Ok(RegisterResponse { token: 1 })
        );

        // Unregister 全链：类型化请求 → dispatch → 类型化应答。
        let req = UnregisterRequest { token: 1, flags: 2 };
        let word = MsgHeader::encode(FAMILY_VERSION, MSG_UNREGISTER);
        let out = d
            .dispatch(word, 0, &req.encode())
            .expect("unregister 应成功");
        assert_eq!(
            UnregisterResponse::decode(&out),
            Ok(UnregisterResponse { released: 1 })
        );

        // Statfs 全链：类型化请求 → dispatch → 类型化应答。
        let req = StatfsRequest {
            path_ptr: 1,
            path_len: 2,
        };
        let word = MsgHeader::encode(FAMILY_VERSION, MSG_STATFS);
        let out = d.dispatch(word, 0, &req.encode()).expect("statfs 应成功");
        assert_eq!(
            StatfsResponse::decode(&out),
            Ok(StatfsResponse {
                block_size: 1,
                blocks_total: 2,
                blocks_free: 3,
                fs_flags: 4
            })
        );

        // Events 错误路径：NotRegistered → Compat ENOENT(2)。
        let req = EventsRequest {
            mask: 1,
            queue_depth: 2,
        };
        let word = MsgHeader::encode(FAMILY_VERSION, MSG_EVENTS);
        let err = d
            .dispatch(word, 0, &req.encode())
            .expect_err("FakeService 对末位消息恒返 NotRegistered");
        assert_eq!(err.as_errno(), Some(2));
    }
}
