#![allow(dead_code)]
#![allow(unused_variables)]
#![stable(feature = "rust1", since = "1.0.0")]

#[path = "../unix/ffi/os_str.rs"]
mod os_str;

#[stable(feature = "rust1", since = "1.0.0")]
pub use self::os_str::{OsStrExt, OsStringExt};

#[stable(feature = "rust1", since = "1.0.0")]
pub use xous::{
    keyos::STACK_PAGE_COUNT,
};
use xous::{MemoryRange, SID, TID, CID, MemoryFlags as MemoryFlags2, Limits as Limits2, Error as Error2};
use crate::num::NonZeroUsize;

#[stable(feature = "rust1", since = "1.0.0")]
pub type Error = Error2;

#[stable(feature = "rust1", since = "1.0.0")]
pub type Limits = Limits2;

#[stable(feature = "rust1", since = "1.0.0")]
pub type MemoryFlags = MemoryFlags2;

#[stable(feature = "rust1", since = "1.0.0")]
#[repr(transparent)]
pub struct ServerAddress(SID);

#[stable(feature = "rust1", since = "1.0.0")]
pub type Connection = CID;

#[stable(feature = "rust1", since = "1.0.0")]
pub type ThreadId = TID;

#[stable(feature = "rust1", since = "1.0.0")]
impl TryFrom<&str> for ServerAddress {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let b = value.as_bytes();
        if b.len() == 0 || b.len() > 16 {
            return Err(());
        }

        let mut this_temp = [0u8; 16];
        for (dest, src) in this_temp.iter_mut().zip(b.iter()) {
            *dest = *src;
        }

        let mut this = [0u32; 4];
        for (dest, src) in this.iter_mut().zip(this_temp.chunks_exact(4)) {
            *dest = u32::from_le_bytes(src.try_into().unwrap());
        }
        Ok(ServerAddress(SID::from_array(this)))
    }
}

fn lend_mut_impl(
    connection: Connection,
    opcode: usize,
    data: &mut [u8],
    arg1: usize,
    arg2: usize,
    blocking: bool,
) -> Result<(usize, usize), Error> {
    let range = unsafe { MemoryRange::new(data.as_mut_ptr() as usize, data.len())? };
    let offset = if arg1 != 0 { Some(arg1.try_into().unwrap()) } else { None };
    let valid = if arg2 != 0 { Some(arg2.try_into().unwrap()) } else { None };
    let msg = xous::Message::new_lend_mut(opcode, range, offset, valid);

    let result = if blocking {
        xous::send_message(connection, msg)?
    } else {
        xous::try_send_message(connection, msg)?
    };

    match result {
        xous::Result::MemoryReturned(arg1, arg2) => Ok(
            (arg1.map(|v| v.get()).unwrap_or_default(), arg2.map(|v| v.get()).unwrap_or_default())
        ),
        xous::Result::Error(e) => Err(e.into()),
        _ => Err(Error::InternalError),
    }
}

pub(crate) fn lend_mut(
    connection: Connection,
    opcode: usize,
    data: &mut [u8],
    arg1: usize,
    arg2: usize,
) -> Result<(usize, usize), Error> {
    lend_mut_impl(connection, opcode, data, arg1, arg2, true)
}

pub(crate) fn try_lend_mut(
    connection: Connection,
    opcode: usize,
    data: &mut [u8],
    arg1: usize,
    arg2: usize,
) -> Result<(usize, usize), Error> {
    lend_mut_impl(connection, opcode, data, arg1, arg2, false)
}

fn lend_impl(
    connection: Connection,
    opcode: usize,
    data: &[u8],
    arg1: usize,
    arg2: usize,
    blocking: bool,
) -> Result<(usize, usize), Error> {
    let range = unsafe { MemoryRange::new(data.as_ptr() as usize, data.len())? };
    let offset = if arg1 != 0 { Some(arg1.try_into().unwrap()) } else { None };
    let valid = if arg2 != 0 { Some(arg2.try_into().unwrap()) } else { None };

    let msg = xous::Message::new_lend(opcode, range, offset, valid);

    let result = if blocking {
        xous::send_message(connection, msg)?
    } else {
        xous::try_send_message(connection, msg)?
    };

    match result {
        xous::Result::MemoryReturned(arg1, arg2) => Ok(
            (arg1.map(|v| v.get()).unwrap_or_default(), arg2.map(|v| v.get()).unwrap_or_default())
        ),
        xous::Result::Error(e) => Err(e.into()),
        _ => Err(Error::InternalError),
    }
}

pub(crate) fn lend(
    connection: Connection,
    opcode: usize,
    data: &[u8],
    arg1: usize,
    arg2: usize,
) -> Result<(usize, usize), Error> {
    lend_impl(connection, opcode, data, arg1, arg2, true)
}

pub(crate) fn try_lend(
    connection: Connection,
    opcode: usize,
    data: &[u8],
    arg1: usize,
    arg2: usize,
) -> Result<(usize, usize), Error> {
    lend_impl(connection, opcode, data, arg1, arg2, false)
}

fn scalar_impl(connection: Connection, args: [usize; 5], blocking: bool) -> Result<(), Error> {
    let [opcode, arg1, arg2, arg3, arg4] = args;
    let msg = xous::Message::new_scalar(opcode, arg1, arg2, arg3, arg4);

    let result = if blocking {
        xous::send_message(connection, msg)?
    } else {
        xous::try_send_message(connection, msg)?
    };

    match result {
        xous::Result::Ok => Ok(()),
        xous::Result::Error(e) => Err(e.into()),
        _ => Err(Error::InternalError),
    }
}

pub(crate) fn scalar(connection: Connection, args: [usize; 5]) -> Result<(), Error> {
    scalar_impl(connection, args, true)
}

pub(crate) fn try_scalar(connection: Connection, args: [usize; 5]) -> Result<(), Error> {
    scalar_impl(connection, args, false)
}

fn blocking_scalar_impl(
    connection: Connection,
    args: [usize; 5],
    blocking: bool,
) -> Result<[usize; 5], xous::Error> {
    let [opcode, arg1, arg2, arg3, arg4] = args;
    let msg = xous::Message::new_blocking_scalar(opcode, arg1, arg2, arg3, arg4);

    let result = if blocking {
        xous::send_message(connection, msg)?
    } else {
        xous::try_send_message(connection, msg)?
    };

    match result {
        xous::Result::Scalar1(a1) => Ok([a1, 0, 0, 0, 0]),
        xous::Result::Scalar2(a1, a2) => Ok([a1, a2, 0, 0, 0]),
        xous::Result::Scalar5(a1, a2, a3, a4, a5) => Ok([a1, a2, a3, a4, a5]),
        xous::Result::Error(e) => Err(e),
        _ => Err(Error::InternalError),
    }
}

pub(crate) fn blocking_scalar(
    connection: Connection,
    args: [usize; 5],
) -> Result<[usize; 5], Error> {
    blocking_scalar_impl(connection, args, true)
}

pub(crate) fn try_blocking_scalar(
    connection: Connection,
    args: [usize; 5],
) -> Result<[usize; 5], Error> {
    blocking_scalar_impl(connection, args, false)
}

fn connect_impl(address: ServerAddress, blocking: bool) -> Result<Connection, Error> {
    Ok(if blocking {
        xous::connect(address.0)?
    } else {
        xous::try_connect(address.0)?
    })
}

/// Connect to a Xous server represented by the specified `address`.
///
/// The current thread will block until the server is available. Returns
/// an error if the server cannot accept any more connections.
pub(crate) fn connect(address: ServerAddress) -> Result<Connection, Error> {
    connect_impl(address, true)
}

/// Attempt to connect to a Xous server represented by the specified `address`.
///
/// If the server does not exist then None is returned.
pub(crate) fn try_connect(address: ServerAddress) -> Result<Option<Connection>, Error> {
    match connect_impl(address, false) {
        Ok(conn) => Ok(Some(conn)),
        Err(Error::ServerNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Terminate the current process and return the specified code to the parent process.
pub(crate) fn exit(return_code: u32) -> ! {
    xous::terminate_process(return_code)
}

/// Suspend the current thread and allow another thread to run. This thread may
/// continue executing again immediately if there are no other threads available
/// to run on the system.
pub(crate) fn do_yield() {
    xous::yield_slice();
}

/// Allocate memory from the system. An optional physical and/or virtual address
/// may be specified in order to ensure memory is allocated at specific offsets,
/// otherwise the kernel will select an address.
///
/// # Safety
///
/// This function is safe unless a virtual address is specified. In that case,
/// the kernel will return an alias to the existing range. This violates Rust's
/// pointer uniqueness guarantee.
pub(crate) unsafe fn map_memory<T>(
    phys: Option<core::ptr::NonNull<T>>,
    virt: Option<core::ptr::NonNull<T>>,
    count: usize,
    flags: MemoryFlags,
) -> Result<&'static mut [T], Error> {
    let size = count * core::mem::size_of::<T>();
    let phys_addr = phys.map(|p| NonZeroUsize::try_from(p.as_ptr() as usize).unwrap());
    let virt_addr = virt.map(|p| NonZeroUsize::try_from(p.as_ptr() as usize).unwrap());

    let range = xous::map_memory(phys_addr, virt_addr, size, flags)?;
    let slice = core::slice::from_raw_parts_mut(range.as_mut_ptr() as *mut T, count);
    Ok(slice)
}

/// Destroy the given memory, returning it to the compiler.
///
/// Safety: The memory pointed to by `range` should not be used after this
/// function returns, even if this function returns Err().
pub(crate) unsafe fn unmap_memory<T>(range: *mut [T]) -> Result<(), Error> {
    let addr = range.as_mut_ptr() as usize;
    let len = range.len() * core::mem::size_of::<T>();

    let range = xous::MemoryRange::new(addr, len)?;
    xous::unmap_memory(range)
}

/// Adjust the memory flags for the given range. This can be used to remove flags
/// from a given region in order to harden memory access. Note that flags may
/// only be removed and may never be added.
///
/// Safety: The memory pointed to by `range` may become inaccessible or have its
/// mutability removed. It is up to the caller to ensure that the flags specified
/// by `new_flags` are upheld, otherwise the program will crash.
pub(crate) unsafe fn update_memory_flags<T>(
    range: *mut [T],
    new_flags: MemoryFlags,
) -> Result<(), Error> {
    let addr = range.as_mut_ptr() as usize;
    let len = range.len() * core::mem::size_of::<T>();

    let range = xous::MemoryRange::new(addr, len)?;
    let result = xous::update_memory_flags(range, new_flags)?;

    match result {
        xous::Result::Ok => Ok(()),
        xous::Result::Error(e) => Err(e),
        _ => Err(Error::InternalError),
    }
}

/// Create a thread with a given stack and up to four arguments
pub(crate) fn create_thread(
    start: *mut usize,
    stack: *mut [u8],
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> Result<ThreadId, Error> {
    let a1 = start as usize;
    let stack_addr = stack.as_mut_ptr() as usize;
    let stack_size = stack.len();
    let thread_init = xous::arch::args_to_thread(start as usize, stack_addr, stack_size, arg0, arg1, arg2, arg3)?;

    let result = xous::rsyscall(xous::SysCall::CreateThread(thread_init))?;

    match result {
        xous::Result::ThreadID(tid) => Ok(tid),
        xous::Result::Error(e) => Err(e),
        _ => Err(Error::InternalError),
    }
}

/// Wait for the given thread to terminate and return the exit code from that thread.
pub(crate) fn join_thread(thread_id: ThreadId) -> Result<usize, Error> {
    xous::join_thread(thread_id)
}

/// Get the current thread's ID
pub(crate) fn thread_id() -> Result<ThreadId, Error> {
    xous::current_tid()
}

/// Adjust the given `knob` limit to match the new value `new`. The current value must
/// match the `current` in order for this to take effect.
///
/// The new value is returned as a result of this call. If the call fails, then the old
/// value is returned. In either case, this function returns successfully.
///
/// An error is generated if the `knob` is not a valid limit, or if the call
/// would not succeed.
pub(crate) fn adjust_limit(knob: Limits, current: usize, new: usize) -> Result<usize, Error> {
    let knob = knob as usize;
    let a2 = current;
    let a3 = new;

    let syscall = xous::SysCall::AdjustProcessLimit(knob, a2, a3);
    let result = xous::rsyscall(syscall)?;

    match result {
        xous::Result::Scalar2(a1, a2) if a1 == knob as usize => Ok(a2),
        xous::Result::Scalar5(a1, a2, ..) if a1 == knob as usize => Ok(a1),
        xous::Result::Error(e) => Err(e),
        _ => Err(Error::InternalError),
    }
}
