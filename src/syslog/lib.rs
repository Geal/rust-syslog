#[crate_type = "lib"];
#[desc = "Syslog client"];
#[license = "MIT"];

extern crate extra = "extra";
extern crate native = "native";

use std::io;
use std::result::Result;
use std::path::posix::Path;
use std::rand;
use std::rand::Rng;
use std::libc::getpid;
use extra::time;
use native::io::pipe::UnixDatagram;

pub type Priority = uint;

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

pub struct Writer {
  severity: Severity,
  facility: Facility,
  tag:      ~str,
  hostname: ~str,
  network:  ~str,
  raddr:    ~str,
  client:   ~str,
  server:   ~str,
  s:        ~UnixDatagram
}

pub fn init(address: ~str, severity: Severity, facility: Facility, tag: ~str) -> Result<~Writer, io::IoError> {
  match tempfile() {
    None => {
      println!("could not generate a tempfile");
      Err(io::IoError {
        kind: io::PathAlreadyExists,
        desc: "could not generate a temporary file",
        detail: None
      })
    },
    Some(p) => {
      println!("temp file: {}", p);
      UnixDatagram::bind(&p.to_c_str()) .map( |s| {
        ~Writer {
          severity: severity,
          facility: facility,
          tag:      tag.clone(),
          hostname: ~"",
          network:  ~"",
          raddr:    address.clone(),
          client:   p.clone(),
          server:   ~"/var/run/syslog",
          s:        ~s
        }
      })
    }
  }
}

impl Writer {
  pub fn format(&self, message: ~str) -> ~str {
    let pid = unsafe { getpid() };
    let f =  format!("<{:u}> {:d} {:s} {:s} {:s} {:d} {:s}",
      self.encode_priority(), 1/*version*/, time::now_utc().rfc3339(),
      self.hostname, self.tag, pid, message);
    println!("formatted: {}", f);
    return f;
  }

  fn encode_priority(&self) -> Priority {
    return self.facility as uint | self.severity as uint
  }

  pub fn send(&mut self, message: ~str) -> Result<(), io::IoError> {
    let formatted = self.format(message).into_bytes();
    self.s.sendto(formatted, &self.server.to_c_str())
  }
}

impl Drop for Writer {
  fn drop(&mut self) {
    let r = io::fs::unlink(&Path::new(self.client.clone()));
    if r.is_err() {
      println!("could not delete the client socket: {}", self.client);
    }
  }
}

fn tempfile() -> Option<~str> {
  let tmpdir = Path::new("/tmp");
  let mut r = rand::rng();
  for _ in range(0u, 1000) {
    let p = tmpdir.join(r.gen_ascii_str(16));
    if ! p.stat().is_ok() {
      return p.as_str().map(|s| s.to_owned());
    }
  }
  None
}
