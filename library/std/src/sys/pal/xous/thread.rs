use crate::ffi::CStr;
use crate::io;
use crate::num::NonZero;
use crate::os::xous::ffi::{
    MemoryFlags, blocking_scalar, create_thread, do_yield, join_thread, map_memory,
};
use crate::os::xous::services::{TicktimerScalar, ticktimer_server};
use crate::time::Duration;

pub struct Thread {
    tid: xous::TID,
}

pub const DEFAULT_MIN_STACK_SIZE: usize = 131072;

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack: usize, thread_main: Box<dyn FnOnce()>) -> io::Result<Thread> {
        let (thread_main_p1, thread_main_p2): (usize, usize) =
            unsafe { core::mem::transmute(Box::into_raw(thread_main)) };
        let stack: &mut [u8] =
            unsafe { map_memory(None, None, stack.next_multiple_of(0x1000), MemoryFlags::W) }
                .map_err(|code| io::Error::from_raw_os_error(code as i32))?;
        let tid =
            create_thread(thread_start as *mut usize, stack, thread_main_p1, thread_main_p2, 0, 0)
                .map_err(|code| io::Error::from_raw_os_error(code as i32))?;

        extern "C" fn thread_start(
            thread_main_p1: usize,
            thread_main_p2: usize,
            _arg2: usize,
            _arg3: usize,
        ) {
            unsafe {
                let thread_main: *mut dyn FnOnce() =
                    core::mem::transmute((thread_main_p1, thread_main_p2));
                // Run the contents of the new thread.
                Box::from_raw(thread_main)();

                // Destroy TLS, which will free the TLS page and call the destructor for
                // any thread local storage (if any).
                crate::sys::thread_local::key::destroy_tls();
            }
        }

        Ok(Thread { tid })
    }

    pub fn yield_now() {
        do_yield();
    }

    pub fn set_name(_name: &CStr) {
        // nope
    }

    pub fn sleep(dur: Duration) {
        // Because the sleep server works on units of `usized milliseconds`, split
        // the messages up into these chunks. This means we may run into issues
        // if you try to sleep a thread for more than 49 days on a 32-bit system.
        let mut millis = dur.as_millis();
        while millis > 0 {
            let sleep_duration =
                if millis > (usize::MAX as _) { usize::MAX } else { millis as usize };
            blocking_scalar(ticktimer_server(), TicktimerScalar::SleepMs(sleep_duration).into())
                .expect("failed to send message to ticktimer server");
            millis -= sleep_duration as u128;
        }
    }

    pub fn join(self) {
        join_thread(self.tid).unwrap();
    }
}

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    // We're unicore right now.
    Ok(unsafe { NonZero::new_unchecked(1) })
}
