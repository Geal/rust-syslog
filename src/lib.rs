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

extern crate unix_socket;
extern crate libc;
extern crate time;
extern crate log;
extern crate regex;

use std::result::Result;
use std::io::{self, Write};
use std::env;
use std::collections::HashMap;
use std::net::{SocketAddr,ToSocketAddrs,UdpSocket,TcpStream};
use std::sync::{Arc, Mutex};

use libc::funcs::posix88::unistd::getpid;
use unix_socket::UnixDatagram;
use log::{Log, LogRecord, LogMetadata,LogLevel, LogLevelFilter, SetLoggerError};
use regex::Regex;

mod facility;
pub use facility::Facility;

pub type Priority = u8;

/// RFC 5424 structured data
pub type StructuredData = HashMap<String, HashMap<String, String>>;


#[allow(non_camel_case_types)]
#[derive(Copy,Clone)]
pub enum Severity {
  LOG_EMERG,
  LOG_ALERT,
  LOG_CRIT,
  LOG_ERR,
  LOG_WARNING,
  LOG_NOTICE,
  LOG_INFO,
  LOG_DEBUG
}

enum LoggerBackend {
  /// Unix socket, temp file path, log file path
  Unix(UnixDatagram),
  Udp(Box<UdpSocket>, SocketAddr),
  Tcp(Arc<Mutex<TcpStream>>)
}

/// Main logging structure
pub struct Logger {
  facility: Facility,
  hostname: Option<String>,
  process:  String,
  pid:      i32,
  s:        LoggerBackend,
  directives: Vec<LogDirective>,
  filter:     Option<Regex>
}

struct LogDirective {
    name:       Option<String>,
    level:      LogLevelFilter,
}

fn detect_unix_socket() -> Result<UnixDatagram, io::Error> {
  let sock = try!(UnixDatagram::unbound());
  try!(sock.connect("/dev/log")
    .or_else(|e| if e.kind() == io::ErrorKind::NotFound {
      sock.connect("/var/run/syslog")
    } else {
      Err(e)
    }));
  Ok(sock)
}

/// Returns a Logger using unix socket to target local syslog ( using /dev/log or /var/run/syslog)
pub fn unix(facility: Facility) -> Result<Box<Logger>, io::Error> {
  let (process_name, pid) = get_process_info().unwrap();
  let (directives, filter) = parse_env();
  Ok(Box::new(Logger {
    facility: facility.clone(),
    hostname: None,
    process:  process_name,
    pid:      pid,
    s:        LoggerBackend::Unix(try!(detect_unix_socket())),
    directives: directives,
    filter: filter
  }))
}

/// returns a UDP logger connecting `local` and `server`
pub fn udp<T: ToSocketAddrs>(local: T, server: T, hostname:String, facility: Facility) -> Result<Box<Logger>, io::Error> {
  server.to_socket_addrs().and_then(|mut server_addr_opt| {
    server_addr_opt.next().ok_or(
      io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid server address"
      )
    )
  }).and_then(|server_addr| {
    UdpSocket::bind(local).map(|socket| {
      let (process_name, pid) = get_process_info().unwrap();
      let (directives, filter) = parse_env();
      Box::new(Logger {
        facility: facility.clone(),
        hostname: Some(hostname),
        process:  process_name,
        pid:      pid,
        s:        LoggerBackend::Udp(Box::new(socket), server_addr),
        directives: directives,
        filter: filter
      })
    })
  })
}

/// returns a TCP logger connecting `local` and `server`
pub fn tcp<T: ToSocketAddrs>(server: T, hostname: String, facility: Facility) -> Result<Box<Logger>, io::Error> {
  TcpStream::connect(server).map(|socket| {
      let (process_name, pid) = get_process_info().unwrap();
      let (directives, filter) = parse_env();
      Box::new(Logger {
        facility: facility.clone(),
        hostname: Some(hostname),
        process:  process_name,
        pid:      pid,
        s:        LoggerBackend::Tcp(Arc::new(Mutex::new(socket))),
        directives: directives,
        filter:   filter
      })
  })
}

/// Unix socket Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_unix(facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    let logger = unix(facility).unwrap();
    max_level.set(logger.filter());
    logger
  })
}

/// UDP Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_udp<T: ToSocketAddrs>(local: T, server: T, hostname:String, facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    let logger = udp(local, server, hostname, facility).unwrap();
    max_level.set(logger.filter());
    logger
  })
}

/// TCP Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_tcp<T: ToSocketAddrs>(server: T, hostname: String, facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    let logger = tcp(server, hostname, facility).unwrap();
    max_level.set(logger.filter());
    logger
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
    -> Result<(), SetLoggerError>
{
  let (directives, filter) = parse_env();
  let backend = detect_unix_socket().map(LoggerBackend::Unix)
    .or_else(|_| {
        TcpStream::connect(("127.0.0.1", 601))
        .map(|s| LoggerBackend::Tcp(Arc::new(Mutex::new(s))))
    })
    .or_else(|_| {
        let udp_addr = "127.0.0.1:514".parse().unwrap();
        UdpSocket::bind(("127.0.0.1", 0))
        .map(|s| LoggerBackend::Udp(Box::new(s), udp_addr))
    }).unwrap_or_else(|e| panic!("Syslog UDP socket creating failed: {}", e));
  let (process_name, pid) = get_process_info().unwrap();
  log::set_logger(|max_level| {
    let logger = Box::new(Logger {
        facility: facility.clone(),
        hostname: None,
        process:  application_name
            .map(|v| v.to_string())
            .unwrap_or(process_name),
        pid:      pid,
        s:        backend,
        directives: directives,
        filter:   filter
    });
    if logger.directives.is_empty() {
        max_level.set(log_level);
    }else{
        max_level.set(logger.filter());
    }
    logger
  })
}

fn parse_env() -> (Vec<LogDirective>, Option<Regex>){
    if let Ok(s) = env::var("RUST_LOG") {
         parse_logging_spec(&s)
    } else {
        (Vec::new(), None)
    }
}

/// Parse a logging specification string (e.g: "crate1,crate2::mod3,crate3::x=error/foo")
/// and return a vector with log directives.
fn parse_logging_spec(spec: &str) -> (Vec<LogDirective>, Option<Regex>) {
    let mut dirs = Vec::new();

    let mut parts = spec.split('/');
    let mods = parts.next();
    let filter = parts.next();
    if parts.next().is_some() {
        println!("warning: invalid logging spec '{}', \
                 ignoring it (too many '/'s)", spec);
        return (dirs, None);
    }
    mods.map(|m| { for s in m.split(',') {
        if s.len() == 0 { continue }
        let mut parts = s.split('=');
        let (log_level, name) = match (parts.next(), parts.next().map(|s| s.trim()), parts.next()) {
            (Some(part0), None, None) => {
                // if the single argument is a log-level string or number,
                // treat that as a global fallback
                match part0.parse() {
                    Ok(num) => (num, None),
                    Err(_) => (LogLevelFilter::max(), Some(part0)),
                }
            }
            (Some(part0), Some(""), None) => (LogLevelFilter::max(), Some(part0)),
            (Some(part0), Some(part1), None) => {
                match part1.parse() {
                    Ok(num) => (num, Some(part0)),
                    _ => {
                        println!("warning: invalid logging spec '{}', \
                                 ignoring it", part1);
                        continue
                    }
                }
            },
            _ => {
                println!("warning: invalid logging spec '{}', \
                         ignoring it", s);
                continue
            }
        };
        dirs.push(LogDirective {
            name: name.map(|s| s.to_string()),
            level: log_level,
        });
    }});

    let filter = filter.map_or(None, |filter| {
        match Regex::new(filter) {
            Ok(re) => Some(re),
            Err(e) => {
                println!("warning: invalid regex filter - {}", e);
                None
            }
        }
    });

    return (dirs, filter);
}

impl Logger {
  /// format a message as a RFC 3164 log message
  pub fn format_3164(&self, severity:Severity, message: &str) -> String {
    if let Some(ref hostname) = self.hostname {
        format!("<{}>{} {} {}[{}]: {}",
          self.encode_priority(severity, self.facility),
          time::now().strftime("%b %d %T").unwrap(),
          hostname, self.process, self.pid, message)
    } else {
        format!("<{}>{} {}[{}]: {}",
          self.encode_priority(severity, self.facility),
          time::now().strftime("%b %d %T").unwrap(),
          self.process, self.pid, message)
    }
  }

  /// format RFC 5424 structured data as `([id (name="value")*])*`
  pub fn format_5424_structured_data(&self, data: StructuredData) -> String {
    if data.is_empty() {
      "-".to_string()
    } else {
      let mut res = String::new();
      for (id, params) in data.iter() {
        res = res + "["+id;
        for (name,value) in params.iter() {
          res = res + " " + name + "=\"" + value + "\"";
        }
        res = res + "]";
      }

      res
    }
  }

  /// format a message as a RFC 5424 log message
  pub fn format_5424(&self, severity:Severity, message_id: i32, data: StructuredData, message: &str) -> String {
    let f =  format!("<{}> {} {} {} {} {} {} {} {}",
      self.encode_priority(severity, self.facility),
      1, // version
      time::now_utc().rfc3339(),
      self.hostname.as_ref().map(|x| &x[..]).unwrap_or("localhost"),
      self.process, self.pid, message_id,
      self.format_5424_structured_data(data), message);
    return f;
  }

  fn encode_priority(&self, severity: Severity, facility: Facility) -> Priority {
    return facility as u8 | severity as u8
  }

  /// Sends a basic log message of the format `<priority> message`
  pub fn send(&self, severity: Severity, message: &str) -> Result<usize, io::Error> {
    let formatted =  format!("<{}> {}",
      self.encode_priority(severity, self.facility.clone()),
      message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a RFC 3164 log message
  pub fn send_3164(&self, severity: Severity, message: &str) -> Result<usize, io::Error> {
    let formatted = self.format_3164(severity, message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a RFC 5424 log message
  pub fn send_5424(&self, severity: Severity, message_id: i32, data: StructuredData, message: &str) -> Result<usize, io::Error> {
    let formatted = self.format_5424(severity, message_id, data, message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a message directly, without any formatting
  pub fn send_raw(&self, message: &[u8]) -> Result<usize, io::Error> {
    match self.s {
      LoggerBackend::Unix(ref dgram) => dgram.send(&message[..]),
      LoggerBackend::Udp(ref socket, ref addr)    => socket.send_to(&message[..], addr),
      LoggerBackend::Tcp(ref socket_wrap)         => {
        let mut socket = socket_wrap.lock().unwrap();
        socket.write(&message[..])
      }
    }
  }

  pub fn emerg(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_EMERG, message)
  }

  pub fn alert(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_ALERT, message)
  }

  pub fn crit(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_CRIT, message)
  }

  pub fn err(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_ERR, message)
  }

  pub fn warning(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_WARNING, message)
  }

  pub fn notice(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_NOTICE, message)
  }

  pub fn info(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_INFO, message)
  }

  pub fn debug(&self, message: &str) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_DEBUG, message)
  }

  pub fn process_name(&self) -> &String {
    &self.process
  }

  pub fn process_id(&self) -> i32 {
    self.pid
  }

  pub fn set_process_name(&mut self, name: String) {
    self.process = name
  }

  pub fn set_process_id(&mut self, id: i32) {
    self.pid = id
  }

  pub fn filter(&self) -> LogLevelFilter {
      self.directives.iter()
          .map(|d| d.level).max()
          .unwrap_or(LogLevelFilter::Trace)
  }

  fn enabled(&self, level: LogLevel, target: &str) -> bool {
      // Search for the longest match, the vector is assumed to be pre-sorted.
      if self.directives.is_empty() {
          return true;
      }
      for directive in self.directives.iter().rev() {
          match directive.name {
              Some(ref name) if !target.starts_with(&**name) => {},
              Some(..) | None => {
                  return level <= directive.level
              }
          }
      }
      false
  }
}

#[allow(unused_variables,unused_must_use)]
impl Log for Logger {
  fn enabled(&self, metadata: &LogMetadata) -> bool {
    self.enabled(metadata.level(), metadata.target())
  }

  fn log(&self, record: &LogRecord) {
    if let Some(filter) = self.filter.as_ref() {
        if !filter.is_match(&*record.args().to_string()) {
            return;
        }
    }
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

fn get_process_info() -> Option<(String,i32)> {
  env::current_exe().ok().and_then(|path| {
    path.file_name().and_then(|os_name| os_name.to_str()).map(|name| name.to_string())
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

#[test]
fn parse_logging_spec_valid() {
    let (dirs, filter) = parse_logging_spec("crate1::mod1=error,crate1::mod2,crate2=debug");
    assert_eq!(dirs.len(), 3);
    assert_eq!(dirs[0].name, Some("crate1::mod1".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Error);

    assert_eq!(dirs[1].name, Some("crate1::mod2".to_string()));
    assert_eq!(dirs[1].level, LogLevelFilter::max());

    assert_eq!(dirs[2].name, Some("crate2".to_string()));
    assert_eq!(dirs[2].level, LogLevelFilter::Debug);
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_invalid_crate() {
    // test parse_logging_spec with multiple = in specification
    let (dirs, filter) = parse_logging_spec("crate1::mod1=warn=info,crate2=debug");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate2".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Debug);
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_invalid_log_level() {
    // test parse_logging_spec with 'noNumber' as log level
    let (dirs, filter) = parse_logging_spec("crate1::mod1=noNumber,crate2=debug");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate2".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Debug);
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_string_log_level() {
    // test parse_logging_spec with 'warn' as log level
    let (dirs, filter) = parse_logging_spec("crate1::mod1=wrong,crate2=warn");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate2".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Warn);
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_empty_log_level() {
    // test parse_logging_spec with '' as log level
    let (dirs, filter) = parse_logging_spec("crate1::mod1=wrong,crate2=");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate2".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::max());
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_global() {
    // test parse_logging_spec with no crate
    let (dirs, filter) = parse_logging_spec("warn,crate2=debug");
    assert_eq!(dirs.len(), 2);
    assert_eq!(dirs[0].name, None);
    assert_eq!(dirs[0].level, LogLevelFilter::Warn);
    assert_eq!(dirs[1].name, Some("crate2".to_string()));
    assert_eq!(dirs[1].level, LogLevelFilter::Debug);
    assert!(filter.is_none());
}

#[test]
fn parse_logging_spec_valid_filter() {
    let (dirs, filter) = parse_logging_spec("crate1::mod1=error,crate1::mod2,crate2=debug/abc");
    assert_eq!(dirs.len(), 3);
    assert_eq!(dirs[0].name, Some("crate1::mod1".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Error);

    assert_eq!(dirs[1].name, Some("crate1::mod2".to_string()));
    assert_eq!(dirs[1].level, LogLevelFilter::max());

    assert_eq!(dirs[2].name, Some("crate2".to_string()));
    assert_eq!(dirs[2].level, LogLevelFilter::Debug);
    assert!(filter.is_some() && filter.unwrap().to_string() == "abc");
}

#[test]
fn parse_logging_spec_invalid_crate_filter() {
    let (dirs, filter) = parse_logging_spec("crate1::mod1=error=warn,crate2=debug/a.c");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate2".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::Debug);
    assert!(filter.is_some() && filter.unwrap().to_string() == "a.c");
}

#[test]
fn parse_logging_spec_empty_with_filter() {
    let (dirs, filter) = parse_logging_spec("crate1/a*c");
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0].name, Some("crate1".to_string()));
    assert_eq!(dirs[0].level, LogLevelFilter::max());
    assert!(filter.is_some() && filter.unwrap().to_string() == "a*c");
}
