extern crate extra;
use syslog = lib;

use std::io;

mod lib;

#[test]
fn message() {
  println!("{}", ~"aaa");
  let w = syslog::init(~"add", syslog::LOG_ALERT, syslog::LOG_USER, ~"test");
  let m:~str = w.format(~"hello");
  println!("test: {}", m);
  assert_eq!(m, ~"hello");
}
