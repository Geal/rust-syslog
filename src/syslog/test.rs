extern crate extra;
use syslog = lib;

use std::io;

mod lib;

#[test]
fn message() {
  println!("{}", ~"aaa");
  let w = syslog::init(~"add", 1, ~"test");
  let m:~str = w.format(~"hello");
  println!("test: {}", m);
  assert_eq!(m, ~"hello");
}
