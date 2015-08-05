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
//!     Ok(mut writer) => {
//!       let r = writer.send(Severity::LOG_ALERT, String::from("hello world"));
//!       if r.is_err() {
//!         println!("error sending the log {}", r.err().expect("got error"));
//!       }
//!     }
//!   }
//! }
//! ```
#![crate_type = "lib"]

extern crate unix_socket;
extern crate rand;
extern crate libc;
extern crate time;
extern crate log;

use std::result::Result;
use std::io::{self, Write};
use std::path::Path;
use std::env;
use std::collections::HashMap;
use std::net::{SocketAddr,ToSocketAddrs,UdpSocket,TcpStream};
use std::sync::{Arc, Mutex};

use rand::{thread_rng, Rng};
use libc::funcs::posix88::unistd::getpid;
use unix_socket::UnixDatagram;
use log::{Log,LogRecord,LogMetadata,LogLevel,SetLoggerError};

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

#[allow(non_camel_case_types)]
#[derive(Copy,Clone)]
pub enum Facility {
  LOG_KERN     = 0  << 3,
  LOG_USER     = 1  << 3,
  LOG_MAIL     = 2  << 3,
  LOG_DAEMON   = 3  << 3,
  LOG_AUTH     = 4  << 3,
  LOG_SYSLOG   = 5  << 3,
  LOG_LPR      = 6  << 3,
  LOG_NEWS     = 7  << 3,
  LOG_UUCP     = 8  << 3,
  LOG_CRON     = 9  << 3,
  LOG_AUTHPRIV = 10 << 3,
  LOG_FTP      = 11 << 3,
  LOG_LOCAL0   = 16 << 3,
  LOG_LOCAL1   = 17 << 3,
  LOG_LOCAL2   = 18 << 3,
  LOG_LOCAL3   = 19 << 3,
  LOG_LOCAL4   = 20 << 3,
  LOG_LOCAL5   = 21 << 3,
  LOG_LOCAL6   = 22 << 3,
  LOG_LOCAL7   = 23 << 3
}

enum LoggerBackend {
  /// Unix socket, temp file path, log file path
  Unix(Box<UnixDatagram>,String,String),
  Udp(Box<UdpSocket>, SocketAddr),
  Tcp(Arc<Mutex<TcpStream>>)
}

/// Main logging structure
pub struct Logger {
  facility: Facility,
  hostname: String,
  process:  String,
  pid:      i32,
  s:        LoggerBackend
}

/// Returns a Logger using unix socket to target local syslog ( using /dev/log or /var/run/syslog)
pub fn unix(facility: Facility) -> Result<Box<Logger>, io::Error> {
  let mut path = "/dev/log".to_string();
  if ! std::fs::metadata(Path::new(&path)).is_ok() {
    path = "/var/run/syslog".to_string();
    if ! std::fs::metadata(Path::new(&path)).is_ok() {
      return Err(
        io::Error::new(
          io::ErrorKind::NotFound,
          "could not find /dev/log nor /var/run/syslog"
        )
      );
    }
  }
  match tempfile() {
    None => {
      println!("could not generate a tempfile");
      Err(
        io::Error::new(
          io::ErrorKind::AlreadyExists,
          "could not generate a temporary file"
        )
      )
    },
    Some(p) => {
      UnixDatagram::bind(&p) .map( |s| {
        let (process_name, pid) = get_process_info().unwrap();
        Box::new(Logger {
          facility: facility.clone(),
          hostname: "localhost".to_string(),
          process:  process_name,
          pid:      pid,
          s:        LoggerBackend::Unix(Box::new(s), p.clone(), path.clone())
        })
      })
    }
  }
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
      Box::new(Logger {
        facility: facility.clone(),
        hostname: hostname,
        process:  process_name,
        pid:      pid,
        s:        LoggerBackend::Udp(Box::new(socket), server_addr)
      })
    })
  })
}

/// returns a TCP logger connecting `local` and `server`
pub fn tcp<T: ToSocketAddrs>(server: T, hostname: String, facility: Facility) -> Result<Box<Logger>, io::Error> {
  TcpStream::connect(server).map(|socket| {
      let (process_name, pid) = get_process_info().unwrap();
      Box::new(Logger {
        facility: facility.clone(),
        hostname: hostname,
        process:  process_name,
        pid:      pid,
        s:        LoggerBackend::Tcp(Arc::new(Mutex::new(socket)))
      })
  })
}

/// Unix socket Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_unix(facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    unix(facility).unwrap()
  })
}

/// UDP Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_udp<T: ToSocketAddrs>(local: T, server: T, hostname:String, facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    udp(local, server, hostname, facility).unwrap()
  })
}

/// TCP Logger init function compatible with log crate
#[allow(unused_variables)]
pub fn init_tcp<T: ToSocketAddrs>(server: T, hostname: String, facility: Facility) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    tcp(server, hostname, facility).unwrap()
  })
}

impl Logger {
  /// format a message as a RFC 3164 log message
  pub fn format_3164(&self, severity:Severity, message: String) -> String {
    let f =  format!("<{}>{} {} {}[{}]: {}",
      self.encode_priority(severity, self.facility),
      time::now_utc().rfc3339(),
      self.hostname, self.process, self.pid, message);
    return f;
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
  pub fn format_5424(&self, severity:Severity, message_id: i32, data: StructuredData, message: String) -> String {
    let f =  format!("<{}> {} {} {} {} {} {} {} {}",
      self.encode_priority(severity, self.facility),
      1, // version
      time::now_utc().rfc3339(),
      self.hostname, self.process, self.pid, message_id,
      self.format_5424_structured_data(data), message);
    return f;
  }

  fn encode_priority(&self, severity: Severity, facility: Facility) -> Priority {
    return facility as u8 | severity as u8
  }

  /// Sends a basic log message of the format `<priority> message`
  pub fn send(&self, severity: Severity, message: String) -> Result<usize, io::Error> {
    let formatted =  format!("<{:?}> {:?}",
      self.encode_priority(severity, self.facility.clone()),
      message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a RFC 3164 log message
  pub fn send_3164(&self, severity: Severity, message: String) -> Result<usize, io::Error> {
    let formatted = self.format_3164(severity, message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a RFC 5424 log message
  pub fn send_5424(&self, severity: Severity, message_id: i32, data: StructuredData, message: String) -> Result<usize, io::Error> {
    let formatted = self.format_5424(severity, message_id, data, message).into_bytes();
    self.send_raw(&formatted[..])
  }

  /// Sends a message directly, without any formatting
  pub fn send_raw(&self, message: &[u8]) -> Result<usize, io::Error> {
    match self.s {
      LoggerBackend::Unix(ref dgram, _, ref path) => dgram.send_to(&message[..], Path::new(&path)),
      LoggerBackend::Udp(ref socket, ref addr)    => socket.send_to(&message[..], addr),
      LoggerBackend::Tcp(ref socket_wrap)         => {
        let mut socket = socket_wrap.lock().unwrap();
        socket.write(&message[..])
      }
    }
  }

  pub fn emerg(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_EMERG, message)
  }

  pub fn alert(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_ALERT, message)
  }

  pub fn crit(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_CRIT, message)
  }

  pub fn err(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_ERR, message)
  }

  pub fn warning(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_WARNING, message)
  }

  pub fn notice(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_NOTICE, message)
  }

  pub fn info(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_INFO, message)
  }

  pub fn debug(&self, message: String) -> Result<usize, io::Error> {
    self.send_3164(Severity::LOG_DEBUG, message)
  }
}

impl Drop for Logger {
  fn drop(&mut self) {
    if let LoggerBackend::Unix(_, ref client, _) = self.s {
      let r = std::fs::remove_file(&Path::new(&client.clone()));
      if r.is_err() {
        println!("could not delete the client socket: {}", client);
      }
    }
  }
}

#[allow(unused_variables,unused_must_use)]
impl Log for Logger {
  fn enabled(&self, metadata: &LogMetadata) -> bool {
    true
  }

  fn log(&self, record: &LogRecord) {
    let message = (format!("{}", record.args())).to_string();
    match record.level() {
      LogLevel::Error => self.err(message),
      LogLevel::Warn  => self.warning(message),
      LogLevel::Info  => self.info(message),
      LogLevel::Debug => self.debug(message),
      LogLevel::Trace => self.debug(message)
    };
  }
}

fn tempfile() -> Option<String> {
  let tmpdir = Path::new("/tmp");
  let mut r = thread_rng();
  for _ in 0..1000 {
    let filename: String = r.gen_ascii_chars().take(16).collect();
    let p = tmpdir.join(filename);
    if ! std::fs::metadata(&p).is_ok() {
      //return p.as_str().map(|s| s.to_string());
      return p.to_str().map(|s| String::from(s));
    }
  }
  None
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
    let m:String = w.format_3164(Severity::LOG_ALERT, "hello".to_string());
    println!("test: {}", m);
    let r = w.send_3164(Severity::LOG_ALERT, "pouet".to_string());
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
        let message = format!("sent from {}", i);
        shared.send_3164(Severity::LOG_DEBUG, message.to_string());
        tx.send(());
      });
    }

    for _ in 0..3 {
      rx.recv();
    }
  }
}

