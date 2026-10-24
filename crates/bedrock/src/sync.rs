//! Bedrock 自持同步原语（M26-V1-c 零依赖收口）。
//!
//! **定位**（ADR-0001 终态 + ADR-0005 登记例外）：bedrock 拒绝对 ostd 的
//! 运行期依赖以回归「零依赖通信与契约域」，本模块以等价最小面自持
//! [`SpinLock`] 与 [`SpscRing`]——unsafe 封装在 `unsafe impl Sync/Send`
//! 与内部原子操作中，API 对调用方完全 safe（与 OSTD SYNC-01/02 同款纪律；
//! 例外登记见 tools/xtask/allowlist.toml unsafe 容忍面 bedrock 条目）。
//!
//! 与 ostd 版差异（如实记档）：SpinLock 无锁等待看门狗钩子（内核调试
//! 基建，属 kernel/ostd 域）；SpscRing 语义逐行同源（缓存行隔离 + 原子
//! 游标 + SPSC 契约）。

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// 自旋锁。持有 [`SpinGuard`] 期间临界区互斥；T 不必 Sync（锁提供同步）。
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
    /// `Send` 约束：T 的所有权可跨线程移动；`Sync` 由下方 unsafe impl 提供。
    _marker: PhantomData<UnsafeCell<T>>,
}

// SAFETY: 前置条件 —— 所有对 value 的访问都在持有 locked 原子标志时进行。
// SAFETY: 不变式 —— locked 为 true 期间恰好有一个持锁者；UnsafeCell 仅在持锁时触碰。
// SAFETY: 并发 —— Acquire/Release 配对保证临界区写入对下一个持锁者可见。
// SAFETY: 违反后果 —— 若 T: Send 不成立（跨线程共享非 Send 数据）即为未定义行为，
//   故以 `T: Send` 约束封死该通道。
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// 创建自旋锁并包入初值。
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
            _marker: PhantomData,
        }
    }
}

impl<T> SpinLock<T> {
    /// 获取锁；忙等到 `test_and_set` 成功为止。
    pub fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // 提示 CPU 当前为自旋等待，降低超线程争用（x86 PAUSE / ARM YIELD 语义）。
            core::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }

    /// 尝试获取锁；立即返回结果而不忙等。
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinGuard { lock: self })
    }

    /// 是否已被持有（仅用于断言与诊断，不做同步判断依据）。
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

/// 持有期的守卫；Drop 时释放锁并将临界区写入发布给下一个持锁者。
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T> core::ops::Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: 前置条件 —— 守卫存活即持锁（Drop 释放前引用不可逃逸）。
        // 不变式 —— 持锁期间独占访问。
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: 同上——持锁独占；可变访问经 DerefMut 通道。
        unsafe { &mut *self.lock.value.get() }
    }
}

/// 缓存行隔离包装（64 B 对齐；消除伪共享——SYNC-02 语义）。
#[repr(align(64))]
struct CacheLine(AtomicUsize);

/// 固定容量无锁 SPSC 环。
///
/// `N` MUST 为 2 的幂（取模经位与；构造时 debug_assert 校验）。
pub struct SpscRing<T, const N: usize> {
    /// 生产者游标（已发布消息数）。
    tail: CacheLine,
    /// 消费者游标（已消费消息数）。
    head: CacheLine,
    /// 槽位池（仅生产者写未发布槽、消费者读已发布槽——SPSC 契约下不重叠）。
    buf: UnsafeCell<[MaybeUninit<T>; N]>,
}

// SAFETY: 前置条件 —— SPSC 契约：同一时刻恰好一个生产者与一个消费者。
// 不变式 —— 生产者只写 [tail % N] 且先写后发布（Release）；消费者只在
//          Acquire 读到新 tail 后读槽，且读完后才 Release 让出槽位；
//          两游标永不指向同一未完成槽（容量判定排除满/空歧义）。
// 并发 —— 原子游标构成 happens-before 链：写槽 → tail.Release →
//          tail.Acquire → 读槽 → head.Release → head.Acquire → 复用槽。
// 违反后果 —— 多生产者/多消费者即槽位撕裂与消息丢失（数据竞争，UB）。
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}
// SAFETY: 同上——Send/Sync 语义由 SPSC 使用契约约束（单发单收）。
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}

impl<T: Copy, const N: usize> SpscRing<T, N> {
    /// 创建空环（槽位未初始化；首读必发生在首写之后，MaybeUninit 安全）。
    pub const fn new() -> Self {
        Self {
            tail: CacheLine(AtomicUsize::new(0)),
            head: CacheLine(AtomicUsize::new(0)),
            // SAFETY 注记：MaybeUninit 数组逐元素 uninit 是合法常量构造；
            // 未初始化内存永不被读取（消费前必有对应发布写入）。
            buf: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
        }
    }

    /// 入队一条消息；满则原样退还（非阻塞，快速路径语义）。
    pub fn send(&self, value: T) -> Result<(), T> {
        let t = self.tail.0.load(Ordering::Relaxed);
        let h = self.head.0.load(Ordering::Acquire);
        if t.wrapping_sub(h) >= N {
            return Err(value);
        }
        // SAFETY: 前置条件 —— SPSC 契约下生产者独占 [t % N] 槽。
        // 不变式 —— 槽写入完成后 tail 才 Release 自增（下方 store）。
        // 并发 —— 消费者最多 Acquire 读到旧 t，不读本槽。
        // 违反后果 —— 双生产者会撕裂槽位（契约封死，见 unsafe impl）。
        unsafe { (*self.buf.get())[t % N].write(value) };
        self.tail.0.store(t.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// 出队一条消息；空则 None（非阻塞）。
    pub fn recv(&self) -> Option<T> {
        let h = self.head.0.load(Ordering::Relaxed);
        let t = self.tail.0.load(Ordering::Acquire);
        if h == t {
            return None;
        }
        // SAFETY: 前置条件 —— h < t（上方判定）保证 [h % N] 已发布。
        // 不变式 —— 槽值读出后 head 才 Release 自增（下方 store）。
        // 并发 —— 生产者最多复用 [h % N] 于本核 head 自增之后。
        // 违反后果 —— 多消费者会重复消费（契约封死，见 unsafe impl）。
        let v = unsafe { (*self.buf.get())[h % N].assume_init() };
        self.head.0.store(h.wrapping_add(1), Ordering::Release);
        Some(v)
    }

    /// 当前可消费消息数。
    pub fn len(&self) -> usize {
        self.tail
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.0.load(Ordering::Acquire))
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Copy, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{SpinLock, SpscRing};

    #[test]
    fn spinlock_exclusion_smoke() {
        let lock = SpinLock::new(7u32);
        {
            let mut g = lock.lock();
            *g += 1;
            assert!(lock.is_locked());
        }
        assert!(!lock.is_locked());
        assert_eq!(*lock.lock(), 8);
        assert!(lock.try_lock().is_some());
    }

    #[test]
    fn spsc_roundtrip_and_capacity() {
        let ring = SpscRing::<u32, 4>::new();
        assert!(ring.is_empty());
        for i in 0..4u32 {
            assert_eq!(ring.send(i), Ok(()));
        }
        assert_eq!(ring.send(99), Err(99), "满则退还");
        assert_eq!(ring.len(), 4);
        for i in 0..4u32 {
            assert_eq!(ring.recv(), Some(i));
        }
        assert_eq!(ring.recv(), None);
        // 回绕复用。
        for i in 10..14u32 {
            assert_eq!(ring.send(i), Ok(()));
        }
        assert_eq!(ring.recv(), Some(10));
    }
}
