#![forbid(unsafe_op_in_unsafe_fn)]

pub mod futex;
pub mod params;

#[path = "../unsupported/common.rs"]
#[allow(dead_code)]
mod common;
pub use common::*;

#[cfg(not(test))]
#[cfg(feature = "panic-unwind")]
mod eh_unwinding {
    // TODO
}

#[cfg(not(test))]
mod c_compat {
    use crate::os::xous::ffi::exit;

    unsafe extern "C" {
        fn main() -> u32;
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn abort() {
        exit(1);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _start(_eh_frame: usize, params: *mut u8, rnd_seed: usize) {
        #[cfg(feature = "panic-unwind")]
        {
            // TODO
            // unsafe { super::eh_unwinding::EH_FRAME_ADDRESS = eh_frame };
            // unwind::set_custom_eh_frame_finder(&super::eh_unwinding::EH_FRAME_SETTINGS).ok();
        }

        init_stack_guard(rnd_seed as u32);

        unsafe { super::params::set(params) };

        exit(unsafe { main() });
    }

    pub fn init_stack_guard(rnd_seed: u32) {
        unsafe extern "C" {
            static __stack_chk_guard: crate::sync::atomic::AtomicU32;
        }

        // Ensure at least one 0 byte to reduce certain string-overflow exploits
        let canary = rnd_seed & 0xFFFF_FF00;

        unsafe {
            __stack_chk_guard.store(canary, crate::sync::atomic::Ordering::Relaxed);
        }
    }

}
