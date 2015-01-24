extern crate libc;
extern crate alloc;

use std::intrinsics;
use std::mem;
use std::ffi::CString;
use alloc::arc::Arc;
use std::os;
use std::io;
use std::sync::Mutex;
use std::io::{IoResult, IoError};
use std::os::unix::Fd;
use std::slice::SliceExt;
use std::iter::IteratorExt;

struct Inner {
    fd: Fd
}

impl Inner {
    fn new(fd: Fd) -> Inner {
        Inner { fd: fd }
    }
}

impl Drop for Inner {
    fn drop(&mut self) { unsafe { let _ = libc::close(self.fd); } }
}

fn sockaddr_to_unix(storage: &libc::sockaddr_storage,
                  len: usize) -> IoResult<CString> {
  match storage.ss_family as libc::c_int {
    libc::AF_UNIX => {
      assert!(len as usize <= mem::size_of::<libc::sockaddr_un>());
      let storage: &libc::sockaddr_un = unsafe {
        mem::transmute(storage)
      };
      unsafe {
        //FIXME: the array size depends on the platform
        let tmp:&[u8; 104] = mem::transmute(&storage.sun_path);
        Ok(CString::from_slice(tmp))
      }
    }
  _ => Err(io::standard_error(io::InvalidInput))
}
}

#[inline]
fn retry<F>(mut f: F) -> libc::c_int where F: FnMut() -> libc::c_int {
  loop {
      match f() {
          -1 if os::errno() as isize == libc::EINTR as isize => {}
          n => return n,
      }
  }
}

fn last_error() -> IoError {
  IoError::last_error()
}

fn addr_to_sockaddr_un(addr: &CString) -> IoResult<(libc::sockaddr_storage, usize)> {
  // the sun_path length is limited to SUN_LEN (with null)
  assert!(mem::size_of::<libc::sockaddr_storage>() >=
          mem::size_of::<libc::sockaddr_un>());
  let mut storage: libc::sockaddr_storage = unsafe { intrinsics::init() };
  let s: &mut libc::sockaddr_un = unsafe { mem::transmute(&mut storage) };

    let len = addr.len();
    if len > s.sun_path.len() - 1 {
        return Err(io::IoError {
            kind: io::InvalidInput,
            desc: "path must be smaller than SUN_LEN",
            detail: None,
        })
    }
    s.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, value) in s.sun_path.iter_mut().zip(addr.iter()) {
        *slot = *value;
    }

    // count the null terminator
    let len = mem::size_of::<libc::sa_family_t>() + len + 1;
    return Ok((storage, len));
}

fn unix_socket(ty: libc::c_int) -> IoResult<Fd> {
    match unsafe { libc::socket(libc::AF_UNIX, ty, 0) } {
        -1 => Err(last_error()),
        fd => Ok(fd)
    }
}

fn connect(addr: &CString, ty: libc::c_int) -> IoResult<Inner> {
    let (addr, len) = try!(addr_to_sockaddr_un(addr));
    let inner = Inner { fd: try!(unix_socket(ty))};
    let addrp = &addr as *const libc::sockaddr_storage;
    match retry(|| unsafe {
        libc::connect(inner.fd, addrp as *const libc::sockaddr,
                     len as libc::socklen_t)
    }) {
        -1 => Err(last_error()),
        _  => Ok(inner)
    }
}

fn bind(addr: &CString, ty: libc::c_int) -> IoResult<Inner> {
    let (addr, len) = try!(addr_to_sockaddr_un(addr));
    let inner = Inner::new(try!(unix_socket(ty)));
    let addrp = &addr as *const libc::sockaddr_storage;
    match unsafe {
        libc::bind(inner.fd, addrp as *const libc::sockaddr, len as libc::socklen_t)
    } {
        -1 => Err(last_error()),
        _  => Ok(inner)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Unix Datagram
////////////////////////////////////////////////////////////////////////////////

pub struct UnixDatagram {
    inner: Arc<Inner>,
}

impl UnixDatagram {
    pub fn connect(addr: &CString) -> IoResult<UnixDatagram> {
        connect(addr, libc::SOCK_DGRAM).map(|inner| {
            UnixDatagram { inner: Arc::new(inner) }
        })
    }
    pub fn bind(addr: &CString) -> IoResult<UnixDatagram> {
        bind(addr, libc::SOCK_DGRAM).map(|inner| {
            UnixDatagram { inner: Arc::new(inner) }
        })
    }

    fn fd(&self) -> Fd { (*self.inner).fd }

    pub fn recvfrom(&mut self, buf: &mut [u8]) -> IoResult<(usize, CString)> {
        let mut storage: libc::sockaddr_storage = unsafe { intrinsics::init() };
        let storagep = &mut storage as *mut libc::sockaddr_storage;
        let mut addrlen: libc::socklen_t =
                mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let ret = retry(|| unsafe {
            libc::recvfrom(self.fd(),
                           buf.as_ptr() as *mut libc::c_void,
                           buf.len() as libc::size_t,
                           0,
                           storagep as *mut libc::sockaddr,
                           &mut addrlen) as libc::c_int
        });

        if ret < 0 { return Err(last_error()) }
        sockaddr_to_unix(&storage, addrlen as usize).and_then(|addr| {
            Ok((ret as usize, addr))
        })
    }

    pub fn sendto(&mut self, buf: &[u8], dst: &CString) -> IoResult<()> {
        let (dst, len) = try!(addr_to_sockaddr_un(dst));
        let dstp = &dst as *const libc::sockaddr_storage;
        let ret = retry(|| unsafe {
            libc::sendto(self.fd(),
                         buf.as_ptr() as *const libc::c_void,
                         buf.len() as libc::size_t,
                         0,
                         dstp as *const libc::sockaddr,
                         len as libc::socklen_t) as libc::c_int
        });

        match ret {
            -1 => Err(last_error()),
            n if n as usize != buf.len() => {

                Err(io::IoError {
                    kind: io::OtherIoError,
                    desc: "couldn't send entire packet at once",
                    detail: None,
                })
            }
            _ => Ok(())
        }
    }

    pub fn clone(&mut self) -> UnixDatagram {
        UnixDatagram { inner: self.inner.clone() }
    }
}

