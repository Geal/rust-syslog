extern crate syslog;

use syslog::{Facility,Formatter3164};

fn main() {

 let formatter = Formatter3164 {
   facility: Facility::LOG_USER,
   hostname: None,
   process:  "process".to_string(),
   pid:      1234,
 };

  match syslog::unix(formatter) {
    Err(e)         => println!("impossible to connect to syslog: {:?}", e),
    Ok(mut logger) => {
      let r = logger.alert("hello world");
      if r.is_err() {
        println!("error sending the log {}", r.err().expect("got error"));
      }
    }
  }
}
