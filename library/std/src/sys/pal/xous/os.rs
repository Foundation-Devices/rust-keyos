use super::unsupported;
use crate::ffi::{OsStr, OsString};
use crate::marker::PhantomData;
use crate::path::{self, PathBuf};
use crate::sync::atomic::{Atomic, AtomicPtr, Ordering};
use crate::{fmt, io};

pub(crate) mod params;

static PARAMS_ADDRESS: Atomic<*mut u8> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(not(test))]
#[cfg(feature = "panic_unwind")]
mod eh_unwinding {
    // TODO
}

#[cfg(not(test))]
mod c_compat {
    use crate::os::xous::ffi::exit;
    use crate::sync::atomic::{AtomicU32, Ordering};

    unsafe extern "C" {
        fn main() -> u32;
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn abort() {
        exit(1);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _start(_eh_frame: usize, params_address: usize, rnd_seed: usize) {
        #[cfg(feature = "panic_unwind")]
        {
            // TODO
            // unsafe { super::eh_unwinding::EH_FRAME_ADDRESS = eh_frame };
            // unwind::set_custom_eh_frame_finder(&super::eh_unwinding::EH_FRAME_SETTINGS).ok();
        }

        init_stack_guard(rnd_seed as u32);

        if params_address != 0 {
            let params_address = crate::ptr::with_exposed_provenance_mut::<u8>(params_address);
            if unsafe {
                super::params::ApplicationParameters::new_from_ptr(params_address).is_some()
            } {
                super::PARAMS_ADDRESS.store(params_address, core::sync::atomic::Ordering::Relaxed);
            }
        }
        exit(unsafe { main() });
    }

    /// Stack protection canary
    #[unsafe(no_mangle)]
    pub static __stack_chk_guard: AtomicU32 = AtomicU32::new(0);

    /// Called by compiler-generated epilogues on mismatch.
    #[unsafe(no_mangle)]
    pub extern "C" fn __stack_chk_fail() -> ! {
        exit(1337)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __stack_chk_fail_local() -> ! {
        __stack_chk_fail()
    }

    pub fn init_stack_guard(rnd_seed: u32) {
        // Ensure at least one 0 byte to reduce certain string-overflow exploits
        let canary = rnd_seed & 0xFFFF_FF00;
        __stack_chk_guard.store(canary, Ordering::Relaxed);
    }
}

pub fn errno() -> i32 {
    0
}

pub fn error_string(errno: i32) -> String {
    format!("error #{}", errno)
}

pub fn getcwd() -> io::Result<PathBuf> {
    unsupported()
}

pub fn chdir(_: &path::Path) -> io::Result<()> {
    unsupported()
}

pub struct SplitPaths<'a>(!, PhantomData<&'a ()>);

pub fn split_paths(_unparsed: &OsStr) -> SplitPaths<'_> {
    panic!("unsupported")
}

impl<'a> Iterator for SplitPaths<'a> {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> {
        self.0
    }
}

#[derive(Debug)]
pub struct JoinPathsError;

pub fn join_paths<I, T>(_paths: I) -> Result<OsString, JoinPathsError>
where
    I: Iterator<Item = T>,
    T: AsRef<OsStr>,
{
    Err(JoinPathsError)
}

impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "not supported on this platform yet".fmt(f)
    }
}

impl crate::error::Error for JoinPathsError {}

pub fn current_exe() -> io::Result<PathBuf> {
    unsupported()
}

pub(crate) fn get_application_parameters() -> Option<params::ApplicationParameters> {
    let params_address = PARAMS_ADDRESS.load(Ordering::Relaxed);
    unsafe { params::ApplicationParameters::new_from_ptr(params_address) }
}

pub fn temp_dir() -> PathBuf {
    panic!("no filesystem on this platform")
}

pub fn home_dir() -> Option<PathBuf> {
    None
}

pub fn exit(code: i32) -> ! {
    crate::os::xous::ffi::exit(code as u32);
}

pub fn getpid() -> u32 {
    panic!("no pids on this platform")
}
