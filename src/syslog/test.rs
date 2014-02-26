extern crate extra;
extern crate native;

use syslog = lib;

mod lib;

#[test]
fn message() {
  let r = syslog::init(~"add", syslog::LOG_USER, ~"test");
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:~str = w.format(syslog::LOG_ALERT, ~"hello");
    println!("test: {}", m);
    let r = w.send(syslog::LOG_ALERT, ~"pouet");
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    assert_eq!(m, ~"hello");
  }
}
