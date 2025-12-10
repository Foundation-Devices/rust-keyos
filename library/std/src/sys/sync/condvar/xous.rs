use core::sync::atomic::{AtomicUsize, Ordering};

use crate::os::xous::ffi::blocking_scalar;
use crate::os::xous::services::{TicktimerScalar, ticktimer_server};
use crate::sys::sync::Mutex;
use crate::time::Duration;

pub struct Condvar {
    waiting_on_futex: AtomicUsize,
    waiting_on_ticktimer: AtomicUsize,
}

unsafe impl Send for Condvar {}
unsafe impl Sync for Condvar {}

impl Condvar {
    #[inline]
    pub const fn new() -> Condvar {
        Condvar { waiting_on_futex: AtomicUsize::new(0), waiting_on_ticktimer: AtomicUsize::new(0) }
    }

    fn notify_some(&self, mut count: usize) {
        if self.waiting_on_ticktimer.load(Ordering::SeqCst) > 0 {
            let notified = blocking_scalar(
                ticktimer_server(),
                TicktimerScalar::NotifyCondition { cookie: self.index(), count }.into(),
            )
            .expect("failure to send NotifyCondition command")[0];
            count -= notified;
        }

        if count > 0 {
            if self.waiting_on_futex.load(Ordering::SeqCst) > 0 {
                xous::futex_wake(&self.waiting_on_futex, count).ok();
            }
        }
    }

    pub fn notify_one(&self) {
        self.notify_some(1)
    }

    pub fn notify_all(&self) {
        self.notify_some(usize::MAX)
    }

    fn index(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    pub unsafe fn wait(&self, mutex: &Mutex) {
        let prev_futex_waiters = self.waiting_on_futex.fetch_add(1, Ordering::SeqCst);
        unsafe { mutex.unlock() };
        // If we got preempted and self.waiting_on_futex changed, this will return immediately.
        // Then again, spurious returns from `wait` are documented and should be accounted for,
        // so let the caller handle this case.
        xous::futex_wait(&self.waiting_on_futex, prev_futex_waiters + 1).ok();
        mutex.lock();
        self.waiting_on_futex.fetch_sub(1, Ordering::SeqCst);
    }

    // Returns false on timeout
    pub unsafe fn wait_timeout(&self, mutex: &Mutex, dur: Duration) -> bool {
        let mut nanos = dur.as_nanos() as u64;
        // Ensure we don't wait for 0 ms, which would cause us to wait forever
        if nanos == 0 {
            nanos = 1;
        }
        self.waiting_on_ticktimer.fetch_add(1, Ordering::SeqCst);
        unsafe { mutex.unlock() };
        // Threading concern: There is a chance that the `notify` thread wakes up here before
        // we have a chance to wait for the condition. This is fine because we've recorded
        // the fact that we're waiting by incrementing the counter.
        let result = blocking_scalar(
            ticktimer_server(),
            TicktimerScalar::WaitForCondition { cookie: self.index(), timeout_ns: nanos }.into(),
        )
        .expect("Ticktimer: failure to send WaitForCondition command");
        mutex.lock();
        self.waiting_on_ticktimer.fetch_sub(1, Ordering::SeqCst);

        result[0] == 0
    }
}
