//! Xous-specific extensions to socket types.

use crate::io;
use crate::net::{TcpListener, TcpStream, UdpSocket};
use crate::os::xous::ffi::blocking_scalar;
use crate::os::xous::services::net_server;
use crate::sys::AsInner;

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
