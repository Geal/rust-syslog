extern crate syslog_tls;

use syslog_tls::{Facility, Formatter5424, SyslogMessage};

fn main() {
    let formatter = Formatter5424 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "myprogram".into(),
        pid: 0,
    };

    match syslog_tls::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer
                .err(SyslogMessage {
                    message_level: 1,
                    structured: Vec::new(),
                    message: "hello world".to_string(),
                })
                .expect("could not write error message");
        }
    }
}
