//! 内核路径：绝对路径的词法规范化与组件切分。
//!
//! 骨架约定（M13-①）：VFS 面只接受**绝对且已词法规范化**的路径——以 `/` 起始、
//! 无空组件、无 `.` / `..` 残留。`..` 在进入挂载语义之前先行词法消解，因此「跨
//! 挂载点的 `..`」不产生回溯到挂载前文件系统的效果；该语义差异留待文件面块引入
//! 逐段解析时再评估（届时以本模块为唯一入口改造，调用方不变）。

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use super::FsError;

/// 已规范化的绝对路径（拥有所有权）。
///
/// 不变式：内部字符串要么为 `"/"`，要么以单个 `/` 起始、不以 `/` 结尾、
/// 不含空组件与 `.` / `..` 段。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathBuf(String);

impl PathBuf {
    /// 根路径 `"/"`。
    pub fn root() -> Self {
        Self(String::from("/"))
    }

    /// 词法规范化：折叠重复 `/`、消解 `.` 与 `..`；拒绝相对路径与越过根的 `..`。
    pub fn normalize(input: &str) -> Result<Self, FsError> {
        if !input.starts_with('/') {
            return Err(FsError::InvalidPath);
        }
        let mut stack: Vec<&str> = Vec::new();
        for comp in input.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    stack.pop().ok_or(FsError::InvalidPath)?;
                }
                other => stack.push(other),
            }
        }
        if stack.is_empty() {
            return Ok(Self::root());
        }
        let mut out = String::new();
        for comp in stack {
            out.push('/');
            out.push_str(comp);
        }
        Ok(Self(out))
    }

    /// 内部字符串视图（已规范化，可直接用于日志与比较）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 路径组件迭代器（不含分隔符；根路径为空迭代）。
    pub fn components(&self) -> impl Iterator<Item = &str> + '_ {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// 组件数（根路径为 0）。
    pub fn depth(&self) -> usize {
        self.components().count()
    }

    /// 追加单个组件。要求 `comp` 为合法单段名（非空、不含 `/`、非 `.` / `..`）。
    pub fn join(&self, comp: &str) -> Result<Self, FsError> {
        validate_component(comp)?;
        if self.0 == "/" {
            return Ok(Self(String::from("/") + comp));
        }
        Ok(Self(self.0.clone() + "/" + comp))
    }

    /// 父路径；根路径无父。
    pub fn parent(&self) -> Option<Self> {
        if self.0 == "/" {
            return None;
        }
        match self.0.rfind('/') {
            // "/a" 的父即根。
            Some(0) => Some(Self::root()),
            Some(idx) => Some(Self(self.0[..idx].to_string())),
            None => None,
        }
    }

    /// 末段名；根路径返回空串。
    pub fn name(&self) -> &str {
        match self.0.rfind('/') {
            Some(idx) => &self.0[idx + 1..],
            None => "",
        }
    }

    /// 组件意义下的前缀判断：`prefix` 的组件序列是自身的逐段前缀。
    /// 逐段比较（而非字符串前缀）保证 `/a/b` 不是 `/a/bc` 的前缀。
    pub fn starts_with_components(&self, prefix: &PathBuf) -> bool {
        if prefix.0 == "/" {
            return true;
        }
        let mut mine = self.components();
        for p in prefix.components() {
            match mine.next() {
                Some(c) if c == p => {}
                _ => return false,
            }
        }
        true
    }
}

/// 校验单段路径名。
pub(crate) fn validate_component(comp: &str) -> Result<(), FsError> {
    if comp.is_empty() || comp.contains('/') || comp == "." || comp == ".." {
        return Err(FsError::InvalidPath);
    }
    Ok(())
}

impl fmt::Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::PathBuf;
    use crate::vfs::FsError;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;

    fn norm(s: &str) -> String {
        PathBuf::normalize(s)
            .expect("normalize")
            .as_str()
            .to_string()
    }

    #[test]
    fn normalize_folds_dot_and_redundant_slashes() {
        assert_eq!(norm("/a/./b//c/"), "/a/b/c");
        assert_eq!(norm("/"), "/");
        assert_eq!(norm("//"), "/");
        assert_eq!(norm("/a/../b/./../c"), "/c");
    }

    #[test]
    fn normalize_rejects_relative_and_root_escape() {
        assert_eq!(PathBuf::normalize("a/b"), Err(FsError::InvalidPath));
        assert_eq!(PathBuf::normalize("/.."), Err(FsError::InvalidPath));
        assert_eq!(PathBuf::normalize("/a/../../b"), Err(FsError::InvalidPath));
    }

    #[test]
    fn components_depth_and_name() {
        let p = PathBuf::normalize("/a/b/c").expect("normalize");
        let comps: Vec<_> = p.components().collect();
        assert_eq!(comps, vec!["a", "b", "c"]);
        assert_eq!(p.depth(), 3);
        assert_eq!(p.name(), "c");
        let root = PathBuf::root();
        assert_eq!(root.depth(), 0);
        assert_eq!(root.name(), "");
    }

    #[test]
    fn join_validates_single_component() {
        let p = PathBuf::normalize("/a").expect("normalize");
        assert_eq!(
            p.join("b").and_then(|x| x.join("c")).unwrap().as_str(),
            "/a/b/c"
        );
        assert_eq!(PathBuf::root().join("etc").unwrap().as_str(), "/etc");
        assert_eq!(p.join(""), Err(FsError::InvalidPath));
        assert_eq!(p.join("x/y"), Err(FsError::InvalidPath));
        assert_eq!(p.join(".."), Err(FsError::InvalidPath));
    }

    #[test]
    fn parent_chain_ends_at_root() {
        let p = PathBuf::normalize("/a/b").expect("normalize");
        let parent = p.parent().expect("parent of /a/b");
        assert_eq!(parent.as_str(), "/a");
        let grand = parent.parent().expect("parent of /a");
        assert_eq!(grand.as_str(), "/");
        assert!(grand.parent().is_none(), "root has no parent");
    }

    #[test]
    fn prefix_is_component_wise_not_string_wise() {
        let base = PathBuf::normalize("/a/b").expect("normalize");
        let child = PathBuf::normalize("/a/b/c").expect("normalize");
        let sibling = PathBuf::normalize("/a/bc").expect("normalize");
        let root = PathBuf::root();
        assert!(child.starts_with_components(&base));
        assert!(!sibling.starts_with_components(&base));
        assert!(child.starts_with_components(&root));
        assert!(base.starts_with_components(&base), "self is a prefix");
    }
}
