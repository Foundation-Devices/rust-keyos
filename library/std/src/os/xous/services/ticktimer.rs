use core::sync::atomic::{Atomic, AtomicU32, Ordering};

use crate::os::xous::ffi::Connection;

pub(crate) enum TicktimerScalar {
    ElapsedNs,
    Sleep { nanoseconds: u64 },
    WaitForCondition { cookie: usize, timeout_ns: u64 },
    NotifyCondition { cookie: usize, count: usize },
    GetSystemTime,
}

impl Into<[usize; 5]> for TicktimerScalar {
    fn into(self) -> [usize; 5] {
        match self {
            TicktimerScalar::ElapsedNs => [0, 0, 0, 0, 0],
            TicktimerScalar::Sleep { nanoseconds } => {
                [1, (nanoseconds & 0xffffffff) as usize, (nanoseconds >> 32) as usize, 0, 0]
            }
            TicktimerScalar::WaitForCondition { cookie, timeout_ns } => {
                [8, cookie, (timeout_ns & 0xffffffff) as usize, (timeout_ns >> 32) as usize, 0]
            }
            TicktimerScalar::NotifyCondition { cookie, count } => [9, cookie, count, 0, 0],
            TicktimerScalar::GetSystemTime => [12, 0, 0, 0, 0],
        }
    }
}

/// Returns a `Connection` to the ticktimer server. This server is used for synchronization
/// primitives such as sleep, Mutex, and Condvar.
pub(crate) fn ticktimer_server() -> Connection {
    static TICKTIMER_SERVER_CONNECTION: Atomic<u32> = AtomicU32::new(0);
    let cid = TICKTIMER_SERVER_CONNECTION.load(Ordering::Relaxed);
    if cid != 0 {
        return cid.into();
    }

    let cid = crate::os::xous::ffi::connect("ticktimer-server".try_into().unwrap()).unwrap();
    TICKTIMER_SERVER_CONNECTION.store(cid.into(), Ordering::Relaxed);
    cid
}
