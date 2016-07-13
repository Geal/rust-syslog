# Sending to Syslog in Rust

[![Build Status](https://travis-ci.org/Geal/rust-syslog.png?branch=master)](https://travis-ci.org/Geal/rust-syslog)
[![Coverage Status](https://coveralls.io/repos/Geal/rust-syslog/badge.svg?branch=master&service=github)](https://coveralls.io/github/Geal/rust-syslog?branch=master)

A small library to write to local syslog.

## Installation

syslog is available on [crates.io](https://crates.io/crates/syslog) and can be included in your Cargo enabled project like this:

```toml
[dependencies]
syslog = "~3.1.0"
```

## documentation

Reference documentation is available [here](http://rust.unhandledexpression.com/syslog/).

## Example

```rust
extern crate syslog;

use syslog::{Facility,Severity};

fn main() {
  match syslog::unix(Facility::LOG_USER) {
    Err(e)         => println!("impossible to connect to syslog: {:?}", e),
    Ok(writer) => {
      let r = writer.send_3164(Severity::LOG_ALERT, "hello world");
      if r.is_err() {
        println!("error sending the log {}", r.err().expect("got error"));
      }
    }
  }
}
```

The struct `syslog::Logger` implements `Log` from the `log` crate, so it can be used as backend for other logging systems.

There are 3 functions to create loggers:

* the `unix` function sends to the local syslog through a Unix socket: `syslog::unix(Facility::LOG_USER)`
* the `tcp` function takes an address for a remote TCP syslog server and a hostname: `tcp("127.0.0.1:4242", "localhost".to_string(), Facility::LOG_USER)`
* the `udp` function takes an address for a local port, and the address remote UDP syslog server and a hostname: `udp("127.0.0.1:1234", "127.0.0.1:4242", "localhost".to_string(), Facility::LOG_USER)`

This crate supports filtering similar to the [env_logger](https://crates.io/crates/env_logger) crate when using the logging facade provided by [log](https://crates.io/crates/log).  You can use their [documentation](http://burntsushi.net/rustdoc/env_logger/index.html#enabling-logging) for any questions. It should be functionally identical except one small difference.  env_logger defaults to filtering out all log messages when the environmental variable RUST_LOG is not set, where this crate defaults to the log level filter used in the init function.   The environmental variable acts like an override for what you pass in during init.

To use the facade, simply setup up logger:
```rust
syslog::init(Facility::LOG_USER,LogLevelFilter::Trace,Some("yourmodule")).unwrap();
```
And then use the methods provided by the logging crate:
```rust
info!("Log at info");
error!("Log at error");
```
If you run the previous code with RUST_LOG=yourmodule=error then you will only see the error log and the info line will be filtered.
