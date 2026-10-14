//! 自旋锁：内核态互斥的最基本原语。
//!
//! 设计约束：不依赖堆分配、不依赖线程库；临界区必须极短（中断上下文亦可能获取）。
//! API 对调用方完全 safe——unsafe 被封装在 `unsafe impl Sync` 与内部原子操作中，
//! 这是 OSTD「unsafe 收口」原则的示范实现。

pub mod spsc;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// 锁等待看门狗钩子（M19-① 取证面第二级）：`lock()` 自旋超过
/// [`STALL_SPINS`] 阈值时以锁对象地址调用；`0` = 未注册（零成本路径，
/// 分支极可预测，正常路径仅多一次自增）。注册方（kernel）保证指针
/// 生命周期与函数体安全（ISR 语境可达：免分配、免再入锁）。
static STALL_HOOK: AtomicUsize = AtomicUsize::new(0);
/// 自旋阈值：2^22 次 PAUSE ≈ 数十 ms 量级（TCG 参考基线）——远超正常
/// 临界区 μs 级持锁时长；命中即「等锁者饥饿」实锤（同核持锁被本核
/// ISR 打断的死锁模式中，等锁者恰为本核 ISR，永不推进）。
const STALL_SPINS: u64 = 1 << 22;

/// 注册看门狗钩子（幂等覆盖；kernel 初始化早期调用一次）。
pub fn set_lock_stall_hook(f: fn(usize)) {
    STALL_HOOK.store(f as usize, Ordering::Release);
}

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
        let mut spins: u64 = 0;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // 锁等待看门狗（M19-①）：自旋计数超阈值即以锁地址回调注册方
            // 钩子（幂等节流：同锁每 STALL_SPINS 次至多一报）。ISR 等锁
            // 命中阈值 = 「持锁者被本核中断打断」死锁模式的直接证据。
            spins = spins.wrapping_add(1);
            if spins >= STALL_SPINS && spins & (STALL_SPINS - 1) == 0 {
                let h = STALL_HOOK.load(Ordering::Acquire);
                if h != 0 {
                    // SAFETY: 前置条件 —— set_lock_stall_hook 注册方保证
                    //          指针为 fn(usize) 且永不过期（kernel static）。
                    // 不变式 —— 钩子体内免分配、免取锁（ISR 语境可达纪律）。
                    // 并发 —— 原子读取；多核同时命中时各自回调（可接受）。
                    // 违反后果 —— 钩子内取锁即递归死锁（注册纪律封死）。
                    let f: fn(usize) = unsafe { core::mem::transmute(h) };
                    f(self as *const Self as usize);
                }
            }
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
        // SAFETY: 前置条件 —— 守卫存在期间锁必然处于持有状态。
        // SAFETY: 不变式 —— 持锁期间无其他执行流可触碰 value。
        // SAFETY: 并发 —— Acquire 已完成，可见性有保障。
        // SAFETY: 违反后果 —— 若锁实现破坏互斥，将产生数据竞争（由测试门禁拦截）。
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: 同 `Deref::deref`；可变访问同样被锁互斥保护。
        unsafe { &mut *self.lock.value.get() }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::SpinLock;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn lock_excludes_concurrent_writers() {
        let lock = Arc::new(SpinLock::new(0u64));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let l = Arc::clone(&lock);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    *l.lock() += 1;
                }
            }));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
        assert_eq!(*lock.lock(), 8000);
    }

    #[test]
    fn try_lock_and_unlock_roundtrip() {
        let lock = SpinLock::new(7);
        assert!(!lock.is_locked());
        {
            let mut g = lock.try_lock().expect("free lock should acquire");
            *g += 3;
            assert!(lock.try_lock().is_none(), "locked while guard alive");
        }
        assert!(!lock.is_locked());
        assert_eq!(*lock.lock(), 10);
    }
}
