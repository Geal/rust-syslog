#![crate_type = "lib"]

extern crate unix_socket;
extern crate rand;
extern crate libc;
extern crate time;

use std::result::Result;
use std::io::{self, Write};
use std::path::Path;
use std::net::{SocketAddr,ToSocketAddrs,UdpSocket,TcpStream};
use rand::{thread_rng, Rng};
use libc::funcs::posix88::unistd::getpid;

use unix_socket::UnixDatagram;

pub type Priority = u8;

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

pub enum LoggerBackend {
  /// Unix socket, temp file path, log file path
  Unix(Box<UnixDatagram>,String,String),
  Udp(Box<UdpSocket>, SocketAddr),
  Tcp(Box<TcpStream>)
}

pub struct Writer {
  facility: Facility,
  tag:      String,
  hostname: String,
  network:  String,
  s:        LoggerBackend
}

pub fn init(facility: Facility, tag: String) -> Result<Box<Writer>, io::Error> {
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
        Box::new(Writer {
          facility: facility.clone(),
          tag:      tag.clone(),
          hostname: "".to_string(),
          network:  "".to_string(),
          s:        LoggerBackend::Unix(Box::new(s), p.clone(), path.clone())
        })
      })
    }
  }
}

pub fn init_UDP<T: ToSocketAddrs>(local: T, server: T, facility: Facility, tag: String) -> Result<Box<Writer>, io::Error> {
  server.to_socket_addrs().and_then(|mut server_addr_opt| {
    server_addr_opt.next().ok_or(
      io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid server address"
      )
    )
  }).and_then(|server_addr| {
    UdpSocket::bind(local).map(|socket| {
      Box::new(Writer {
        facility: facility.clone(),
        tag:      tag.clone(),
        hostname: "".to_string(),
        network:  "".to_string(),
        s:        LoggerBackend::Udp(Box::new(socket), server_addr)
      })
    })
  })
}

pub fn init_TCP<T: ToSocketAddrs>(server: T, facility: Facility, tag: String) -> Result<Box<Writer>, io::Error> {
  TcpStream::connect(server).map(|socket| {
      Box::new(Writer {
        facility: facility.clone(),
        tag:      tag.clone(),
        hostname: "".to_string(),
        network:  "".to_string(),
        s:        LoggerBackend::Tcp(Box::new(socket))
      })
  })
}

impl Writer {
  pub fn format_extended(&self, severity:Severity, message: String) -> String {
    let pid = unsafe { getpid() };
    let f =  format!("<{}> {} {} {} {} {} {}",
      self.encode_priority(severity, self.facility),
      1,// version
      time::now_utc().rfc3339(),
      self.hostname, self.tag, pid, message);
    return f;
  }

  pub fn format(&self, severity:Severity, message: String) -> String {
    let f =  format!("<{:?}> {:?} {:?}",
      self.encode_priority(severity, self.facility.clone()),
      self.tag, message);
    return f;
  }

  fn encode_priority(&self, severity: Severity, facility: Facility) -> Priority {
    return facility as u8 | severity as u8
  }

  pub fn send(&mut self, severity: Severity, message: String) -> Result<usize, io::Error> {
    let formatted = self.format(severity, message).into_bytes();
    match self.s {
      LoggerBackend::Unix(ref dgram, _, ref path) => dgram.send_to(&formatted[..], Path::new(&path)),
      LoggerBackend::Udp(ref socket, ref addr)    => socket.send_to(&formatted[..], addr),
      LoggerBackend::Tcp(ref mut socket)          => socket.write(&formatted[..])
    }
  }

  pub fn emerg(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_EMERG, message)
  }

  pub fn alert(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_ALERT, message)
  }

  pub fn crit(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_CRIT, message)
  }

  pub fn err(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_ERR, message)
  }

  pub fn warning(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_WARNING, message)
  }

  pub fn notice(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_NOTICE, message)
  }

  pub fn info(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_INFO, message)
  }

  pub fn debug(&mut self, message: String) -> Result<usize, io::Error> {
    self.send(Severity::LOG_DEBUG, message)
  }
}

impl Drop for Writer {
  fn drop(&mut self) {
    if let LoggerBackend::Unix(_, ref client, _) = self.s {
      let r = std::fs::remove_file(&Path::new(&client.clone()));
      if r.is_err() {
        println!("could not delete the client socket: {}", client);
      }
    }
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

