extern crate native;
extern crate rand;

use syslog = lib;

mod lib;

#[test]
fn message() {
  let r = syslog::init("add".to_string(), syslog::LOG_USER, "test".to_string());
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:String = w.format(syslog::LOG_ALERT, "hello".to_string());
    println!("test: {}", m);
    let r = w.send(syslog::LOG_ALERT, "pouet".to_string());
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    assert_eq!(m, "<9> test hello".to_string());
  }
}
