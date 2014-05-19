extern crate native;
extern crate rand;

use syslog = lib;

mod lib;

#[test]
fn message() {
  let r = syslog::init("add".to_owned(), syslog::LOG_USER, "test".to_owned());
  if r.is_ok() {
    let mut w = r.unwrap();
    let m:~str = w.format(syslog::LOG_ALERT, "hello".to_owned());
    println!("test: {}", m);
    let r = w.send(syslog::LOG_ALERT, "pouet".to_owned());
    if r.is_err() {
      println!("error sending: {}", r.unwrap_err());
    }
    assert_eq!(m, "<9> test hello".to_owned());
  }
}
