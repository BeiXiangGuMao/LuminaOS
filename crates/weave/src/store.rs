//! 内容寻址对象库。
//!
//! 承接 Weave 细则第 15 章「内容寻址存储」面（M29-W1）：对象以其内容
//! 摘要为身份（`ObjectId` = FNV-1a 64）——同内容自动去重，异内容身份
//! 必异（64 位域内）。v0 决策：
//!
//! - **摘要算法**：FNV-1a 64（决定论、零依赖、无堆）——**非密码学面**，
//!   签名校验属服务侧（细则定位），完整性防线以 [`ObjectStore::verify`]
//!   重哈希比对承载（64 位碰撞域 v0 如实登记）；
//! - **定容槽位**：`CAP` 槽预分配（构造期一次性 `with_capacity`），存满
//!   `put` 拒收返回 `None`（fail-visible，静默截断禁令纪律）；
//! - **零删除语义**：v0 无 GC/淘汰（内容寻址不可变对象，删除面随包管理
//!   引用计数批挂账）。

use alloc::vec::Vec;

use core::fmt;

/// 对象身份：内容的 FNV-1a 64 摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// FNV-1a 64 位摘要（v0 内容寻址算法，见模块文档）。
#[must_use]
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// 校验失败：存储内容重哈希与身份不符（位翻转/撕裂残留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyError {
    /// 请求的对象身份。
    pub id: ObjectId,
    /// 存储内容的实际重哈希。
    pub actual: ObjectId,
}

/// 定容内容寻址对象库（`CAP` 槽，构造期一次性预分配）。
pub struct ObjectStore<const CAP: usize> {
    slots: Vec<Option<Slot>>,
    bytes: usize,
}

struct Slot {
    id: ObjectId,
    data: Vec<u8>,
}

impl<const CAP: usize> ObjectStore<CAP> {
    /// 构造空库（`CAP` 槽预分配）。
    pub fn new() -> Self {
        Self {
            slots: Vec::with_capacity(CAP),
            bytes: 0,
        }
    }

    /// 存入对象：返回内容身份；同内容去重（身份已存在则不入新槽）。
    ///
    /// 库满（去重后仍需新槽且槽位耗尽）→ `None`（fail-visible）。
    pub fn put(&mut self, data: &[u8]) -> Option<ObjectId> {
        let id = ObjectId(fnv1a64(data));
        if self
            .slots
            .iter()
            .any(|s| matches!(s, Some(sl) if sl.id == id))
        {
            return Some(id); // 去重：内容寻址同体必同 id
        }
        if self.slots.len() >= CAP {
            return None; // 库满拒收
        }
        self.bytes += data.len();
        self.slots.push(Some(Slot {
            id,
            data: data.to_vec(),
        }));
        Some(id)
    }

    /// 按 身份 取对象内容。
    #[must_use]
    pub fn get(&self, id: ObjectId) -> Option<&[u8]> {
        self.slots
            .iter()
            .flatten()
            .find(|sl| sl.id == id)
            .map(|sl| sl.data.as_slice())
    }

    /// 身份是否在库。
    #[must_use]
    pub fn has(&self, id: ObjectId) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, Some(sl) if sl.id == id))
    }

    /// 完整性校验：存储内容重哈希与身份比对。
    ///
    /// 对象不在库 → `None`（与「在库但损坏」区分）；在库失配 →
    /// `Some(Err)`（位翻转/撕裂残留显形）。
    pub fn verify(&self, id: ObjectId) -> Option<Result<(), VerifyError>> {
        let sl = self.slots.iter().flatten().find(|sl| sl.id == id)?;
        let actual = ObjectId(fnv1a64(&sl.data));
        if actual == id {
            Some(Ok(()))
        } else {
            Some(Err(VerifyError { id, actual }))
        }
    }

    /// 统计：(对象数, 内容字节总量)。
    #[must_use]
    pub fn stats(&self) -> (usize, usize) {
        (self.slots.iter().flatten().count(), self.bytes)
    }
}

impl<const CAP: usize> Default for ObjectStore<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip_and_dedup() {
        let mut st = ObjectStore::<8>::new();
        let a = st.put(b"alpha").expect("put a");
        let b = st.put(b"beta").expect("put b");
        assert_eq!(st.get(a), Some(&b"alpha"[..]));
        assert_eq!(st.get(b), Some(&b"beta"[..]));
        // 去重：同内容同身份，槽位不增
        let a2 = st.put(b"alpha").expect("put a2");
        assert_eq!(a2, a);
        let (n, bytes) = st.stats();
        assert_eq!(n, 2);
        assert_eq!(bytes, 9);
        // 异内容身份必异（域内）
        assert_ne!(a, b);
    }

    #[test]
    fn capacity_fail_visible() {
        let mut st = ObjectStore::<2>::new();
        assert!(st.put(b"one").is_some());
        assert!(st.put(b"two").is_some());
        assert_eq!(st.put(b"three"), None, "full store must reject");
        // 去重不受容量影响（身份已在库）
        assert!(st.put(b"one").is_some());
        assert!(st.has(ObjectId(fnv1a64(b"two"))));
        assert!(!st.has(ObjectId(fnv1a64(b"three"))));
    }

    #[test]
    fn verify_detects_corruption() {
        let mut st = ObjectStore::<4>::new();
        let id = st.put(b"integrity").expect("put");
        assert_eq!(st.verify(id), Some(Ok(())));
        // 不在库 → None（与在库损坏区分）
        assert_eq!(st.verify(ObjectId(0xDEAD)), None);
        // 模拟位翻转（测试专用后门：绕过 put 的单一事实源写入）
        st.corrupt_for_test(id, 0, 0xFF ^ b'i');
        match st.verify(id) {
            Some(Err(e)) => {
                assert_eq!(e.id, id);
                assert_ne!(e.actual, id, "re-hash must diverge after flip");
            }
            other => panic!("corruption must be detected, got {other:?}"),
        }
    }

    #[test]
    fn fnv1a64_known_vectors() {
        // 手工核算锚点：FNV-1a 64 空串与经典向量
        assert_eq!(fnv1a64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171F73967E8);
    }

    #[test]
    fn display_format() {
        let id = ObjectId(0x0000_0100_0000_01B3);
        assert_eq!(alloc::string::ToString::to_string(&id), "00000100000001b3");
    }

    /// 测试专用后门：对在库对象指定位翻转（模拟介质损伤）。
    #[cfg(test)]
    impl<const CAP: usize> ObjectStore<CAP> {
        /// 指定对象第 `at` 字节改写为 `val`（越界静默忽略）。
        pub fn corrupt_for_test(&mut self, id: ObjectId, at: usize, val: u8) {
            if let Some(Some(sl)) = self
                .slots
                .iter_mut()
                .find(|s| matches!(s.as_ref(), Some(sl) if sl.id == id))
            {
                if at < sl.data.len() {
                    sl.data[at] = val;
                }
            }
        }
    }
}
