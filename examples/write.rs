extern crate syslog_tls;

use syslog_tls::{Facility, Formatter3164};

fn main() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "myprogram".into(),
        pid: 0,
    };

    match syslog_tls::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer
                .err("hello world")
                .expect("could not write error message");
            writer
                .err("hello all".to_string())
                .expect("could not write error message");
        }
    }
}
