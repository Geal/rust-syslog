//! using syslog with the log crate
extern crate syslog_tls;
#[macro_use]
extern crate log;

use log::LevelFilter;
use syslog_tls::{BasicLogger, Facility, Formatter3164};

fn main() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "myprogram".into(),
        pid: 0,
    };

    let logger = syslog_tls::unix(formatter).expect("could not connect to syslog");
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Info))
        .expect("could not register logger");

    info!("hello world");
}
