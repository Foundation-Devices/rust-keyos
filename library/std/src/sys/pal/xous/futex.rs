use core::sync::atomic::Atomic;
use core::time::Duration;

pub type Futex = Atomic<Primitive>;
pub type Primitive = usize;

pub type SmallFutex = Atomic<SmallPrimitive>;
pub type SmallPrimitive = usize;

pub fn futex_wait(futex: &Futex, expected: Primitive, timeout: Option<Duration>) -> bool {
    assert!(timeout.is_none(), "Timeouts on xous futexes is not supported");
    xous::futex_wait(futex, expected).ok();
    // "false" means we didn't time out, but got woken, which is always the case as
    // we don't support timeouts here.
    false
}

pub fn futex_wake(futex: &Futex) -> bool {
    xous::futex_wake(futex, 1).ok();
    // We don't know if we woke anyone, and apparently some other implementations do this too
    false
}

pub fn futex_wake_all(futex: &Futex) {
    xous::futex_wake(futex, usize::MAX).ok();
}
