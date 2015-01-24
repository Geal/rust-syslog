extern crate syslog;

use syslog::{Facility,Severity};

fn main() {
  match syslog::init(String::from_str("add"), Facility::LOG_USER, String::from_str("example")) {
    Err(e)         => println!("impossible to connect to syslog: {}", e.desc),
    Ok(mut writer) => {
      let r = writer.send(Severity::LOG_ALERT, String::from_str("hello world"));
      if r.is_err() {
        println!("error sending the log {}", r.err().expect("got error"));
      }
    }
  }
}
