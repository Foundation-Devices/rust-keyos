use crate::io;
use crate::num::NonZero;
use crate::os::xous::ffi::{
    MemoryFlags, blocking_scalar, create_thread, do_yield, join_thread, map_memory,
};
use crate::os::xous::services::{TicktimerScalar, ticktimer_server};
use crate::thread::ThreadInit;
use crate::time::Duration;

pub struct Thread {
    tid: xous::TID,
}

pub const DEFAULT_MIN_STACK_SIZE: usize = 131072;

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        let data = Box::into_raw(init);
        let stack: &mut [u8] =
            unsafe { map_memory(None, None, stack.next_multiple_of(0x1000), MemoryFlags::W) }
                .map_err(|code| io::Error::from_raw_os_error(code as i32))?;
        let tid = create_thread(thread_start as *mut usize, stack, data as usize, 0, 0, 0)
            .map_err(|code| io::Error::from_raw_os_error(code as i32))?;

        #[inline(never)]
        fn rust_main_thread_not_inlined(init: Box<ThreadInit>) {
            let rust_start = init.init();
            rust_start();
        }

        extern "C" fn thread_start(data: *mut usize) -> () {
            // SAFETY: we are simply recreating the box that was leaked earlier.
            let init = unsafe { Box::from_raw(data as *mut ThreadInit) };

            // Run the main thread with an inline(never) barrier to prevent
            // dealloc calls from being reordered to after the TLS has been destroyed.
            // See https://github.com/rust-lang/rust/pull/144465#pullrequestreview-3289729950
            // for more context.
            rust_main_thread_not_inlined(init);

            // Destroy TLS, which will free the TLS page and call the destructor for
            // any thread local storage (if any).
            unsafe {
                crate::sys::thread_local::key::destroy_tls();
            }
        }

        Ok(Thread { tid })
    }

    pub fn join(self) {
        join_thread(self.tid).unwrap();
    }
}

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    // We're unicore right now.
    Ok(unsafe { NonZero::new_unchecked(1) })
}

pub fn yield_now() {
    do_yield();
}

pub fn sleep(dur: Duration) {
    // u64::MAX nanoseconds is 500 years.
    let nanoseconds: u64 = dur.as_nanos().try_into().unwrap_or(u64::MAX).max(1);
    blocking_scalar(ticktimer_server(), TicktimerScalar::Sleep { nanoseconds }.into())
        .expect("failed to send message to ticktimer server");
}
