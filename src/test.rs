extern crate native;
extern crate rand;
extern crate test;
extern crate syslog;

use syslog::{init, LOG_USER, LOG_ALERT};

#[test]
fn message() {
  let r = init("add".to_string(), LOG_USER, "test".to_string());
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:String = w.format(LOG_ALERT, "hello".to_string());
    println!("test: {}", m);
    let r = w.send(LOG_ALERT, "pouet".to_string());
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    assert_eq!(m, "<9> test hello".to_string());
  }
}

