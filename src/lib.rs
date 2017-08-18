//! Syslog
//!
//! This crate provides facilities to send log messages via syslog.
//! It supports Unix sockets for local syslog, UDP and TCP for remote servers.
//!
//! Messages can be passed directly without modification, or in RFC 3164 or RFC 5424 format
//!
//! The code is available on [Github](https://github.com/Geal/rust-syslog)
//!
//! # Example
//!
//! ```
//! extern crate syslog;
//!
//! use syslog::{Facility,Severity};
//!
//! fn main() {
//!   match syslog::unix(Facility::LOG_USER) {
//!     Err(e)         => println!("impossible to connect to syslog: {:?}", e),
//!     Ok(writer) => {
//!       let r = writer.send(Severity::LOG_ALERT, "hello world");
//!       if r.is_err() {
//!         println!("error sending the log {}", r.err().expect("got error"));
//!       }
//!     }
//!   }
//! }
//! ```
#![crate_type = "lib"]

#[macro_use] extern crate error_chain;
extern crate unix_socket;
extern crate libc;
extern crate time;
extern crate log;

use std::io::{self, Write};
use std::env;
use std::marker::PhantomData;
use std::collections::HashMap;
use std::net::{SocketAddr,ToSocketAddrs,UdpSocket,TcpStream};
use std::path::Path;
use std::error::Error;

use libc::getpid;
use unix_socket::{UnixDatagram, UnixStream};
use log::{Log,LogRecord,LogMetadata,LogLevel,SetLoggerError};

mod errors {
 error_chain! {
   errors { Initialization Format Write }

   foreign_links {
     Io(::std::io::Error) #[doc = "Link to a `std::error::Error` type."];
   }
 }
}

mod facility;
mod format;
pub use facility::Facility;
pub use format::Severity;
pub use errors::*;

use format::{LogFormat,Formatter3164};

pub type Priority = u8;

/// RFC 5424 structured data
pub type StructuredData = HashMap<String, HashMap<String, String>>;

pub enum LoggerBackend {
  /// Unix socket, temp file path, log file path
  Unix(UnixDatagram),
  UnixStream(UnixStream),
  Udp(UdpSocket, SocketAddr),
  Tcp(TcpStream)
}

/// Main logging structure
pub struct Logger<Backend: Write, T, Formatter: LogFormat<T>> {
  formatter: Formatter,
  backend:   Backend,
  phantom:   PhantomData<T>,
}

/// Returns a Logger using unix socket to target local syslog ( using /dev/log or /var/run/syslog)
pub fn unix<'a>(facility: Facility) -> Result<Logger<LoggerBackend, &'a str, Formatter3164>> {
    unix_custom(facility, "/dev/log").or_else(|e| {
      if let &ErrorKind::Io(ref io_err) = e.kind() {
        if io_err.kind() == io::ErrorKind::NotFound {
          return unix_custom(facility, "/var/run/syslog");
        }
      }
      Err(e)
    })
}

/// Returns a Logger using unix socket to target local syslog at user provided path
pub fn unix_custom<'a, P: AsRef<Path>>(facility: Facility, path: P) -> Result<Logger<LoggerBackend, &'a str, Formatter3164>> {
    let (process_name, pid) = get_process_info()?;
    let sock = UnixDatagram::unbound().chain_err(|| ErrorKind::Initialization)?;
    match sock.connect(&path) {
        Ok(()) => {
            Ok(Logger {
              formatter: Formatter3164 {
                             facility: facility.clone(),
                             hostname: None,
                             process:  process_name,
                             pid:      pid,
                },
                backend:   LoggerBackend::Unix(sock),
                phantom:   PhantomData,
            })
        },
        Err(ref e) if e.raw_os_error() == Some(libc::EPROTOTYPE) => {
            let sock = UnixStream::connect(path).chain_err(|| ErrorKind::Initialization)?;
            Ok(Logger {
                formatter: Formatter3164 {
                             facility: facility.clone(),
                             hostname: None,
                             process:  process_name,
                             pid:      pid,
                },
                backend:   LoggerBackend::UnixStream(sock),
                phantom:   PhantomData,
            })
        },
        Err(e) => Err(e).chain_err(|| ErrorKind::Initialization),
    }
}
/// returns a UDP logger connecting `local` and `server`
pub fn udp<'a, T: ToSocketAddrs>(local: T, server: T, hostname:String, facility: Facility) -> Result<Logger<LoggerBackend, &'a str, Formatter3164>> {
  server.to_socket_addrs().chain_err(|| ErrorKind::Initialization).and_then(|mut server_addr_opt| {
    server_addr_opt.next().chain_err(|| ErrorKind::Initialization)
  }).and_then(|server_addr| {
    UdpSocket::bind(local).chain_err(|| ErrorKind::Initialization).and_then(|socket| {
      let (process_name, pid) = get_process_info()?;
      Ok(Logger {
        formatter: Formatter3164 {
                     facility: facility.clone(),
                     hostname: Some(hostname),
                     process:  process_name,
                     pid:      pid,
                   },
        backend:   LoggerBackend::Udp(socket, server_addr),
        phantom:   PhantomData,
      })
    })
  })
}

/// returns a TCP logger connecting `local` and `server`
pub fn tcp<'a, T: ToSocketAddrs>(server: T, hostname: String, facility: Facility) -> Result<Logger<TcpStream, &'a str, Formatter3164>> {
  TcpStream::connect(server).chain_err(|| ErrorKind::Initialization).and_then(|socket| {
    let (process_name, pid) = get_process_info()?;
    Ok(Logger {
      formatter: Formatter3164 {
                     facility: facility.clone(),
                     hostname: Some(hostname),
                     process:  process_name,
                     pid:      pid,
                   },
      backend:        socket,
      phantom:   PhantomData,
    })
  })
}

/*
/// Unix socket Logger init function compatible with log crate
pub fn init_unix(facility: Facility, log_level: log::LogLevelFilter) -> Result<()> {
  log::set_logger(|max_level| {
    max_level.set(log_level);
    Box::new(unix(facility).unwrap())
  }).chain_err(|| "could not create logger")
}

/// Unix socket Logger init function compatible with log crate and user provided socket path
pub fn init_unix_custom<P: AsRef<Path>>(facility: Facility, log_level: log::LogLevelFilter, path: P) -> Result<(), SetLoggerError> {
    log::set_logger(|max_level| {
      max_level.set(log_level);
      unix_custom(facility, path).unwrap()
    })
}

/// UDP Logger init function compatible with log crate
pub fn init_udp<T: ToSocketAddrs>(local: T, server: T, hostname:String, facility: Facility, log_level: log::LogLevelFilter) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    max_level.set(log_level);
    udp(local, server, hostname, facility).unwrap()
  })
}

/// TCP Logger init function compatible with log crate
pub fn init_tcp<T: ToSocketAddrs>(server: T, hostname: String, facility: Facility, log_level: log::LogLevelFilter) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    max_level.set(log_level);
    tcp(server, hostname, facility).unwrap()
  })
}

/// Initializes logging subsystem for log crate
///
/// This tries to connect to syslog by following ways:
///
/// 1. Unix sockets /dev/log and /var/run/syslog (in this order)
/// 2. Tcp connection to 127.0.0.1:601
/// 3. Udp connection to 127.0.0.1:514
///
/// Note the last option usually (almost) never fails in this method. So
/// this method doesn't return error even if there is no syslog.
///
/// If `application_name` is `None` name is derived from executable name
pub fn init(facility: Facility, log_level: log::LogLevelFilter,
    application_name: Option<&str>)
    -> Result<(), SyslogError>
{
  let backend = unix(facility).map(|logger| logger.s)
    .or_else(|_| {
        TcpStream::connect(("127.0.0.1", 601))
        .map(|s| LoggerBackend::Tcp(s))
    })
    .or_else(|_| {
        let udp_addr = "127.0.0.1:514".parse().unwrap();
        UdpSocket::bind(("127.0.0.1", 0))
        .map(|s| LoggerBackend::Udp(s, udp_addr))
    }).map_err(|e| SyslogError{ description: e.description().to_owned() })?;
  let (process_name, pid) = get_process_info().unwrap();
  log::set_logger(|max_level| {
    max_level.set(log_level);
    Logger {
        facility: facility.clone(),
        hostname: None,
        process:  application_name
            .map(|v| v.to_string())
            .unwrap_or(process_name),
        pid:      pid,
        s:        backend,
    }
  }).map_err(|e| SyslogError{ description: e.description().to_owned() })
}
*/

impl<W:Write, T, F:LogFormat<T>> Logger<W, T, F> {
  pub fn emerg(&mut self, message: T) -> Result<()> {
    self.formatter.emerg(&mut self.backend, message)
  }

  pub fn alert(&mut self, message: T) -> Result<()> {
    self.formatter.alert(&mut self.backend, message)
  }

  pub fn crit(&mut self, message: T) -> Result<()> {
    self.formatter.crit(&mut self.backend, message)
  }

  pub fn err(&mut self, message: T) -> Result<()> {
    self.formatter.err(&mut self.backend, message)
  }

  pub fn warning(&mut self, message: T) -> Result<()> {
    self.formatter.warning(&mut self.backend, message)
  }

  pub fn notice(&mut self, message: T) -> Result<()> {
    self.formatter.notice(&mut self.backend, message)
  }

  pub fn info(&mut self, message: T) -> Result<()> {
    self.formatter.info(&mut self.backend, message)
  }

  pub fn debug(&mut self, message: T) -> Result<()> {
    self.formatter.debug(&mut self.backend, message)
  }
}

impl Write for LoggerBackend {
  /// Sends a message directly, without any formatting
  fn write(&mut self, message: &[u8]) -> io::Result<usize> {
    match self {
      &mut LoggerBackend::Unix(ref dgram) => {
        dgram.send(&message[..])
      },
      &mut LoggerBackend::UnixStream(ref mut socket) => {
        let null = [0 ; 1];
        socket.write(&message[..]).and_then(|_| socket.write(&null))
      },
      &mut LoggerBackend::Udp(ref socket, ref addr)    => {
        socket.send_to(&message[..], addr)
      },
      &mut LoggerBackend::Tcp(ref mut socket)         => {
        socket.write(&message[..])
      }
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    match self {
      &mut LoggerBackend::Unix(_) => {
        Ok(())
      },
      &mut LoggerBackend::UnixStream(ref mut socket) => {
        socket.flush()
      },
      &mut LoggerBackend::Udp(_, _)  => {
        Ok(())
      },
      &mut LoggerBackend::Tcp(ref mut socket)        => {
        socket.flush()
      }
    }
  }
}

/*
#[allow(unused_variables,unused_must_use)]
impl Log for Logger {
  fn enabled(&self, metadata: &LogMetadata) -> bool {
    true
  }

  fn log(&self, record: &LogRecord) {
    let message = &(format!("{}", record.args()));
    match record.level() {
      LogLevel::Error => self.err(message),
      LogLevel::Warn  => self.warning(message),
      LogLevel::Info  => self.info(message),
      LogLevel::Debug => self.debug(message),
      LogLevel::Trace => self.debug(message)
    };
  }
}
*/

fn get_process_info() -> Result<(String,i32)> {
  env::current_exe().chain_err(|| ErrorKind::Initialization).and_then(|path| {
    path.file_name().and_then(|os_name| os_name.to_str()).map(|name| name.to_string())
      .chain_err(|| ErrorKind::Initialization)
  }).map(|name| {
    let pid = unsafe { getpid() };
    (name, pid)
  })
}

#[test]
#[allow(unused_must_use)]
fn message() {
  use std::thread;
  use std::sync::mpsc::channel;

  let r = unix(Facility::LOG_USER);
  //let r = tcp("127.0.0.1:4242", "localhost".to_string(), Facility::LOG_USER);
  if r.is_ok() {
    let w = r.unwrap();
    let m:String = w.format_3164(Severity::LOG_ALERT, "hello");
    println!("test: {}", m);
    let r = w.send_3164(Severity::LOG_ALERT, "pouet");
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    //assert_eq!(m, "<9> test hello".to_string());

    let data = Arc::new(w);
    let (tx, rx) = channel();
    for i in 0..3 {
      let shared = data.clone();
      let tx = tx.clone();
      thread::spawn(move || {
        //let mut logger = *shared;
        let message = &format!("sent from {}", i);
        shared.send_3164(Severity::LOG_DEBUG, message);
        tx.send(());
      });
    }

    for _ in 0..3 {
      rx.recv();
    }
  }
}

