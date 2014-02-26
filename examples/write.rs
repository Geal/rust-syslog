extern crate extra;
extern crate native;
extern crate syslog;

fn main() {
  match syslog::init(~"add", syslog::LOG_USER, ~"example") {
    Err(e)         => println!("impossible to connect to syslog: {}", e.desc),
    Ok(mut writer) => {
      let r = writer.send(syslog::LOG_ALERT, ~"hello");
      if e.is_err() {
        println!("error sending the log {}", r.unwrap().desc);
      }
    }
  }
}
