extern crate syslog;

use syslog::{Facility,Severity};

fn main() {
  match syslog::init(Facility::LOG_USER, String::from("example")) {
    Err(e)         => println!("impossible to connect to syslog: {:?}", e),
    Ok(mut writer) => {
      let r = writer.send(Severity::LOG_ALERT, String::from("hello world"));
      if r.is_err() {
        println!("error sending the log {}", r.err().expect("got error"));
      }
    }
  }
}
