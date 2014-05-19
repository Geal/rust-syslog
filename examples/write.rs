extern crate native;
extern crate syslog;

fn main() {
  match syslog::init("add".to_owned(), syslog::LOG_USER, "example".to_owned()) {
    Err(e)         => println!("impossible to connect to syslog: {}", e.desc),
    Ok(mut writer) => {
      let r = writer.send(syslog::LOG_ALERT, "hello world".to_owned());
      if r.is_err() {
        println!("error sending the log {}", r.unwrap_err().desc);
      }
    }
  }
}
