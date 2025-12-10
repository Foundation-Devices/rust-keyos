use core::{sync::atomic::{Atomic}, time::Duration};

pub type Futex = Atomic<Primitive>;
pub type Primitive = usize;

pub type SmallFutex = Atomic<SmallPrimitive>;
pub type SmallPrimitive = usize;

pub fn futex_wait(futex: &Futex, expected: Primitive, timeout: Option<Duration>) -> bool {
    assert!(timeout.is_none(), "Timeouts on xous futexes is not supported");
    xous::futex_wait(futex, expected).ok();
    // Never time out, because it is always none.
    false
}

pub fn futex_wake(futex: &Futex) -> bool {
    xous::futex_wake(futex,1).ok();
    // We don't know if we woke anyone
    false
}

pub fn futex_wake_all(futex: &Futex) {
    xous::futex_wake(futex, usize::MAX).ok();
}
