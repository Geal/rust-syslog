# Sending to Syslog in Rust

[![Build Status](https://travis-ci.org/Geal/rust-syslog.png?branch=master)](https://travis-ci.org/Geal/rust-syslog)
[![Coverage Status](https://coveralls.io/repos/Geal/rust-syslog/badge.svg?branch=master&service=github)](https://coveralls.io/github/Geal/rust-syslog?branch=master)

A small library to write to local syslog.

## Installation

syslog is available on [crates.io](https://crates.io/crates/syslog) and can be included in your Cargo enabled project like this:

```toml
[dependencies]
syslog = "~2.1.0"
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
      let r = writer.send(Severity::LOG_ALERT, String::from("hello world"));
      if r.is_err() {
        println!("error sending the log {}", r.err().expect("got error"));
      }
    }
  }
}
```

The struct `syslog::Logger` implements `Log` from the `log` crate, so it can be used as backend for other logging systems.
