//! Crystal 晶簇 —— 代际槽位容器。
//!
//! 依据《指标与规范手册》第 6 章：Crystal 以「双代际根槽 + 写放大模型」组织存储
//! 元数据。本 crate 把同一思想实现为通用数据结构：代际槽表（generational slab）。
//! 每个槽位携带独立代龄，句柄（索引 + 代龄）在元素删除后立即失效，从根上杜绝
//! ABA 问题——这正是「双代际根槽」在内存元数据面的镜像实现。
//!
//! 用途：Mirror 的 Surface 表、Aurora 的应用实例表、Pulse 的连接表等一切
//! 「长生命周期、句柄外泄」场景；v0.13.0 起 Bedrock 的文件描述符表亦以本容器为基座。
#![no_std]
extern crate alloc;

pub mod checksum;
pub mod format;
pub mod layout;
pub mod vfs;
pub mod wal;

use alloc::vec::Vec;

/// 代际槽表中的句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    /// 槽位索引。
    pub index: usize,
    /// 创建该句柄时的代龄。
    pub generation: u64,
}

/// 槽表错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// 句柄不存在或已失效（代龄不匹配）。
    StaleKey,
    /// 容量已满且无空闲槽位。
    Full,
}

/// 单个槽位：代龄 + 可选值（私有结构，随容器 Debug 输出）。
struct Slot<T> {
    generation: u64,
    value: Option<T>,
}

/// 代际槽表。
pub struct GenerationalSlab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<usize>,
    live: usize,
}

impl<T> core::fmt::Debug for GenerationalSlab<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GenerationalSlab")
            .field("live", &self.live)
            .field("slot_capacity", &self.slots.len())
            .field("free", &self.free.len())
            .finish()
    }
}

impl<T> GenerationalSlab<T> {
    /// 创建空槽表。
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    /// 插入元素，返回句柄。
    pub fn insert(&mut self, value: T) -> Result<Key, SlotError> {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index];
            slot.generation += 1; // 复用即升代：旧句柄全部失效
            slot.value = Some(value);
            self.live += 1;
            return Ok(Key {
                index,
                generation: slot.generation,
            });
        }
        let generation = 0;
        self.slots.push(Slot {
            generation,
            value: Some(value),
        });
        self.live += 1;
        Ok(Key {
            index: self.slots.len() - 1,
            generation,
        })
    }

    /// 代龄匹配时返回共享引用。
    pub fn get(&self, key: Key) -> Result<&T, SlotError> {
        let slot = self.slots.get(key.index).ok_or(SlotError::StaleKey)?;
        if slot.generation != key.generation {
            return Err(SlotError::StaleKey);
        }
        slot.value.as_ref().ok_or(SlotError::StaleKey)
    }

    /// 代龄匹配时返回可变引用。
    pub fn get_mut(&mut self, key: Key) -> Result<&mut T, SlotError> {
        let slot = self.slots.get_mut(key.index).ok_or(SlotError::StaleKey)?;
        if slot.generation != key.generation {
            return Err(SlotError::StaleKey);
        }
        slot.value.as_mut().ok_or(SlotError::StaleKey)
    }

    /// 删除元素并使句柄失效；槽位进入空闲表待复用。
    pub fn remove(&mut self, key: Key) -> Result<T, SlotError> {
        let slot = self.slots.get_mut(key.index).ok_or(SlotError::StaleKey)?;
        if slot.generation != key.generation {
            return Err(SlotError::StaleKey);
        }
        let value = slot.value.take().ok_or(SlotError::StaleKey)?;
        self.free.push(key.index);
        self.live -= 1;
        Ok(value)
    }

    /// 存活元素数。
    pub fn len(&self) -> usize {
        self.live
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }
}

impl<T> Default for GenerationalSlab<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::{GenerationalSlab, SlotError};

    #[test]
    fn insert_get_remove_roundtrip() {
        let mut s = GenerationalSlab::new();
        let k = s.insert(41u32).expect("insert");
        assert_eq!(s.get(k), Ok(&41));
        assert_eq!(s.remove(k), Ok(41));
        assert_eq!(s.get(k), Err(SlotError::StaleKey));
        assert!(s.is_empty());
    }

    #[test]
    fn stale_handle_never_sees_reused_slot() {
        let mut s = GenerationalSlab::new();
        let k1 = s.insert("first").expect("insert");
        s.remove(k1).expect("remove");
        let k2 = s.insert("second").expect("reinsert same index");
        assert_eq!(k1.index, k2.index, "slot reused");
        assert_ne!(k1.generation, k2.generation, "generation bumped");
        assert_eq!(s.get(k1), Err(SlotError::StaleKey));
        assert_eq!(s.get(k2), Ok(&"second"));
    }

    #[test]
    fn key_hashable_for_handle_tables() {
        use std::collections::HashSet;
        let mut s = GenerationalSlab::new();
        let k = s.insert(1).expect("insert");
        let mut set = HashSet::new();
        set.insert(k);
        s.remove(k).expect("remove");
        // 旧句柄仍在集合里，但查询槽表必然 StaleKey——外泄句柄安全。
        let stale = *set.iter().next().expect("non-empty");
        assert_eq!(stale.index, k.index);
        assert_eq!(stale.generation, k.generation);
        assert_eq!(s.get(stale), Err(SlotError::StaleKey));
    }
}
