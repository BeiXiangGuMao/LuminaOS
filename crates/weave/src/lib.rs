//! Weave 织流 —— 包管理核心类型。
//!
//! 依据《指标与规范手册》第 15 章：Weave 的安装/卸载一律走「代际事务」——事务
//! 具备 Prepare/Commit/Rollback 三相，提交不可重复，回滚不残留。本 crate 提供
//! 清单（manifest）解析与事务状态机的策略面；内容寻址存储与签名校验在服务侧。
//!
//! **no_std（M16-② 起）**：包容器格式（[`pkg`]）需随内核 EXEC 装载链运行，
//! 本 crate 自 v0.17.0 起转为 `no_std + alloc`（宿主测试不受影响；原 std 面
//! 仅用 `fmt`/`String`/`Vec`，均由 core/alloc 等价替代，如实记档）。
//!
//! **M29-W1 扩容**：[`store`] 内容寻址对象库（FNV-1a 64 身份、定容槽位、
//! 重哈希校验）与 [`journal`] WE-P02 断电注入框架（双代际根槽、提交路径
//! 四相注入、恢复不变式宿主矩阵）落位；事务策略面（本文件
//! `Transaction`）的机制承载即 [`journal::GenRoot`]。
//!
//! **M31-W1 扩容**：[`boot`] 自举装载面——boot 后 recover 库态语义挂接
//! （三不变式四相复演 + store 根装载同源对账，结构化 [`boot::BootReport`]
//! 供内核启动序列 fail-visible 消费；介质落盘随 crystal 块域挂账不动）。
#![no_std]
extern crate alloc;

pub mod boot;
pub mod journal;
pub mod pkg;
pub mod store;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// 语义化版本（仅核心三段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// 主版本。
    pub major: u16,
    /// 次版本。
    pub minor: u16,
    /// 修订号。
    pub patch: u16,
}

/// 版本解析错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// 段数不为三。
    BadShape,
    /// 某段不是合法数字。
    BadNumber,
}

impl Version {
    /// 解析 "MAJOR.MINOR.PATCH"。
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let parts: [&str; 3] = s
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ParseError::BadShape)?;
        let num = |x: &str| x.parse::<u16>().map_err(|_| ParseError::BadNumber);
        Ok(Version {
            major: num(parts[0])?,
            minor: num(parts[1])?,
            patch: num(parts[2])?,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// 依赖声明；`req` 支持 `^MAJOR.MINOR`（兼容语义）与 `=MAJOR.MINOR.PATCH`（锁定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    /// 依赖包名。
    pub name: String,
    /// 版本要求。
    pub req: VersionReq,
}

/// 版本要求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionReq {
    /// `^X.Y`：同主版本内的最小次版本。
    Caret(u16, u16),
    /// `=X.Y.Z`：精确锁定。
    Exact(Version),
}

impl VersionReq {
    /// 解析版本要求。
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        if let Some(rest) = s.strip_prefix('^') {
            let parts: [&str; 2] = rest
                .split('.')
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| ParseError::BadShape)?;
            let major = parts[0].parse::<u16>().map_err(|_| ParseError::BadNumber)?;
            let minor = parts[1].parse::<u16>().map_err(|_| ParseError::BadNumber)?;
            return Ok(VersionReq::Caret(major, minor));
        }
        if let Some(rest) = s.strip_prefix('=') {
            return Ok(VersionReq::Exact(Version::parse(rest)?));
        }
        Err(ParseError::BadShape)
    }

    /// 版本是否满足要求。
    pub fn matches(&self, v: &Version) -> bool {
        match *self {
            VersionReq::Exact(e) => *v == e,
            VersionReq::Caret(major, minor) => v.major == major && v.minor >= minor,
        }
    }
}

/// 包清单。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// 包名（反向域名）。
    pub name: String,
    /// 包版本。
    pub version: Version,
    /// 依赖列表。
    pub deps: Vec<Dep>,
}

/// 事务状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    /// 已准备，未提交。
    Prepared,
    /// 提交进行中。
    Committing,
    /// 已提交（终态）。
    Committed,
    /// 已回滚（终态）。
    RolledBack,
}

/// 代际事务：三相状态机，提交一次性。
#[derive(Debug)]
pub struct Transaction {
    gen: u64,
    state: TxState,
}

impl Transaction {
    /// 开启第 `gen` 代事务并完成准备相。
    pub fn prepare(gen: u64) -> Self {
        Self {
            gen,
            state: TxState::Prepared,
        }
    }

    /// 事务代龄。
    pub fn generation(&self) -> u64 {
        self.gen
    }

    /// 当前状态。
    pub fn state(&self) -> TxState {
        self.state
    }

    /// 提交：仅 Prepared 可提交；Committing 重复提交被拒绝（一次性语义）。
    pub fn commit(&mut self) -> Result<(), String> {
        match self.state {
            TxState::Prepared => {
                self.state = TxState::Committing;
                // 真实实现在此落盘双代际根槽；策略面视该步为原子成功。
                self.state = TxState::Committed;
                Ok(())
            }
            TxState::Committed => Err("double commit rejected".into()),
            TxState::RolledBack => Err("commit after rollback".into()),
            TxState::Committing => Err("concurrent commit".into()),
        }
    }

    /// 回滚：Prepared/Committing 可回滚，终态不可。
    pub fn rollback(&mut self) -> Result<(), String> {
        match self.state {
            TxState::Prepared | TxState::Committing => {
                self.state = TxState::RolledBack;
                Ok(())
            }
            TxState::Committed => Err("cannot rollback committed".into()),
            TxState::RolledBack => Err("already rolled back".into()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Dep, Manifest, Transaction, TxState, Version, VersionReq};
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn version_parse_order_and_display() {
        let a = Version::parse("1.2.3").expect("a");
        let b = Version::parse("1.10.0").expect("b");
        assert!(a < b);
        assert_eq!(a.to_string(), "1.2.3");
        assert_eq!(Version::parse("1.2"), Err(super::ParseError::BadShape));
    }

    #[test]
    fn req_matches() {
        let caret = VersionReq::parse("^1.4").expect("caret");
        assert!(caret.matches(&Version::parse("1.4.0").expect("v")));
        assert!(caret.matches(&Version::parse("1.9.9").expect("v")));
        assert!(!caret.matches(&Version::parse("2.0.0").expect("v")));
        let exact = VersionReq::parse("=1.4.2").expect("exact");
        assert!(exact.matches(&Version::parse("1.4.2").expect("v")));
        assert!(!exact.matches(&Version::parse("1.4.3").expect("v")));
    }

    #[test]
    fn manifest_with_deps() {
        let m = Manifest {
            name: "org.lumina.notes".into(),
            version: Version::parse("0.3.1").expect("v"),
            deps: vec![Dep {
                name: "org.lumina.loom".into(),
                req: VersionReq::parse("^0.1").expect("req"),
            }],
        };
        assert_eq!(m.deps.len(), 1);
        assert_eq!(m.name, "org.lumina.notes");
    }

    #[test]
    fn transaction_is_one_shot() {
        let mut t = Transaction::prepare(7);
        assert_eq!(t.generation(), 7);
        assert_eq!(t.state(), TxState::Prepared);
        t.commit().expect("commit");
        assert_eq!(t.state(), TxState::Committed);
        assert!(t.commit().is_err(), "double commit");
        assert!(t.rollback().is_err());

        let mut t2 = Transaction::prepare(8);
        t2.rollback().expect("rollback");
        assert!(t2.commit().is_err());
    }
}
