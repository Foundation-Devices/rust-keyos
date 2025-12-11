use core::sync::atomic::{AtomicBool, Ordering};

use crate::pin::Pin;
use crate::sys::sync::{Condvar, Mutex};
use crate::time::Duration;

pub struct Parker {
    token: AtomicBool,
    mtx: Mutex,
    condvar: Condvar,
}

impl Parker {
    pub unsafe fn new_in_place(parker: *mut Parker) {
        unsafe {
            parker.write(Parker {
                token: AtomicBool::new(false),
                mtx: Mutex::new(),
                condvar: Condvar::new(),
            })
        }
    }

    pub unsafe fn park(self: Pin<&Self>) {
        self.mtx.lock();
        while !self.token.load(Ordering::SeqCst) {
            self.condvar.wait(&self.mtx);
        }
        self.token.store(false, Ordering::SeqCst);
        self.mtx.unlock();
    }

    pub unsafe fn park_timeout(self: Pin<&Self>, mut timeout: Duration) {
        self.mtx.lock();
        while timeout > Duration::ZERO && !self.token.load(Ordering::SeqCst) {
            let start = crate::time::Instant::now();
            self.condvar.wait_timeout(&self.mtx, timeout);
            timeout = timeout.saturating_sub(start.elapsed());
        }
        self.token.store(false, Ordering::SeqCst);
        self.mtx.unlock();
    }

    pub fn unpark(self: Pin<&Self>) {
        self.mtx.lock();
        self.token.store(true, Ordering::SeqCst);
        self.condvar.notify_one();
        unsafe { self.mtx.unlock() };
    }
}
