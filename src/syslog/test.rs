extern crate extra;
extern crate native;

use syslog = lib;

use std::io;

mod lib;

#[test]
fn message() {
  println!("{}", ~"aaa");
  let r = syslog::init(~"add", syslog::LOG_ALERT, syslog::LOG_USER, ~"test");
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:~str = w.format(~"hello");
    println!("test: {}", m);
    w.send(~"pouet");
    assert_eq!(m, ~"hello");
  }
}
