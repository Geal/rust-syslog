extern crate extra;
extern crate native;

use syslog = lib;

mod lib;

#[test]
fn message() {
  println!("{}", ~"aaa");
  let r = syslog::init(~"add", syslog::LOG_ALERT, syslog::LOG_USER, ~"test");
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:~str = w.format(~"hello");
    println!("test: {}", m);
    let r = w.send(~"pouet");
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    assert_eq!(m, ~"hello");
  }
}
