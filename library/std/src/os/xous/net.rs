//! Xous-specific extensions to socket types.

use crate::io;
use crate::net::{TcpListener, TcpStream, UdpSocket};
use crate::os::xous::ffi::{blocking_scalar, lend_mut};
use crate::os::xous::services::net_server;
use crate::sys::AsInner;

const WAIT_READINESS: usize = 101;
const WAKE: usize = 102;

/// Header plus one four-byte slot per entry, in a page-sized bounce buffer.
const WAIT_HEADER: usize = 4;
const WAIT_BUF_LEN: usize = 4096;
const MAX_WAIT_ENTRIES: usize = (WAIT_BUF_LEN - WAIT_HEADER) / 4;

/// One socket in a readiness wait: the state bits are the READY_* values the
/// network server speaks, and `known` is what the caller saw last, so only a
/// change can end the wait.
#[derive(Clone, Copy, Debug)]
pub struct WaitEntry {
    pub descriptor: u16,
    pub interest: u8,
    pub known: u8,
}

/// Block until one of `entries` gains a state bit its caller has not seen, a
/// wake arrives for `selector`, or the timeout passes. `None` waits forever;
/// `Some(0)` reports the current states without waiting.
///
/// Returns whether the wait ended by wake, and the current state of every
/// entry; the caller owns turning states into edges.
pub fn readiness_wait(
    entries: &[WaitEntry],
    selector: u16,
    timeout: Option<crate::time::Duration>,
) -> io::Result<(bool, crate::vec::Vec<(u16, u8)>)> {
    // The wire cannot carry a zero, so the timeout travels one high.
    let timeout_ms = match timeout {
        None => 0,
        Some(t) => (t.as_millis() as usize).saturating_add(1),
    };
    if entries.len() > MAX_WAIT_ENTRIES {
        return Err(io::const_error!(io::ErrorKind::InvalidInput, "too many sockets in one wait"));
    }

    #[repr(C, align(4096))]
    struct WaitBuf {
        raw: [u8; WAIT_BUF_LEN],
    }
    let mut buf = WaitBuf { raw: [0u8; WAIT_BUF_LEN] };

    buf.raw[0] = entries.len() as u8;
    buf.raw[1..3].copy_from_slice(&selector.to_le_bytes());
    for (index, entry) in entries.iter().enumerate() {
        let at = WAIT_HEADER + index * 4;
        buf.raw[at..at + 2].copy_from_slice(&entry.descriptor.to_le_bytes());
        buf.raw[at + 2] = entry.interest;
        buf.raw[at + 3] = entry.known;
    }

    lend_mut(net_server(), WAIT_READINESS, &mut buf.raw, timeout_ms, 0)
        .map_err(|_| io::const_error!(io::ErrorKind::Other, "the network server did not answer"))?;

    let count = buf.raw[0] as usize;
    let woken = buf.raw[1] != 0;
    let states = (0..count)
        .map(|index| {
            let at = WAIT_HEADER + index * 4;
            (u16::from_le_bytes([buf.raw[at], buf.raw[at + 1]]), buf.raw[at + 2])
        })
        .collect();
    Ok((woken, states))
}

/// End `selector`'s readiness wait early, or its next one if none is parked.
pub fn wake(selector: u16) -> io::Result<()> {
    blocking_scalar(net_server(), [WAKE, selector as usize, 0, 0, 0])
        .map_err(|_| io::const_error!(io::ErrorKind::Other, "the network server did not answer"))?;
    Ok(())
}

/// What a socket would do right now if it were used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readiness {
    /// A read would return without blocking. End of stream counts, because the
    /// read that follows returns zero rather than waiting.
    pub readable: bool,
    /// A write would accept at least one byte.
    pub writable: bool,
    /// The connection is gone.
    pub closed: bool,
}

/// Ask about a socket by name rather than by value.
///
/// A readiness-driven poll keeps a set of sockets it does not own, and has to
/// ask about all of them without holding any.
pub fn readiness(descriptor: u16) -> io::Result<Readiness> {
    const READINESS: usize = 100;
    const READABLE: usize = 1;
    const WRITABLE: usize = 2;
    const CLOSED: usize = 4;
    const UNKNOWN: usize = 8;

    let reply = blocking_scalar(net_server(), [READINESS | ((descriptor as usize) << 16), 0, 0, 0, 0])
        .map_err(|_| io::const_error!(io::ErrorKind::Other, "the network server did not answer"))?;

    // A caller polling a descriptor nobody owns has to be told so, not handed a
    // readiness it would act on forever.
    if reply[0] & UNKNOWN != 0 {
        return Err(io::const_error!(io::ErrorKind::NotFound, "no such socket"));
    }

    Ok(Readiness {
        readable: reply[0] & READABLE != 0,
        writable: reply[0] & WRITABLE != 0,
        closed: reply[0] & CLOSED != 0,
    })
}

/// Names a socket the way the network server does.
///
/// A readiness poll runs beside the socket rather than owning it, so it needs
/// a name for something it never opened. This is the closest thing Xous has to
/// a file descriptor: there is no kernel handle table behind it.
pub trait AsRawDescriptor {
    fn as_raw_descriptor(&self) -> u16;
}

impl AsRawDescriptor for TcpStream {
    fn as_raw_descriptor(&self) -> u16 {
        self.as_inner().descriptor()
    }
}

impl AsRawDescriptor for TcpListener {
    fn as_raw_descriptor(&self) -> u16 {
        self.as_inner().descriptor()
    }
}

impl AsRawDescriptor for UdpSocket {
    fn as_raw_descriptor(&self) -> u16 {
        self.as_inner().descriptor()
    }
}
