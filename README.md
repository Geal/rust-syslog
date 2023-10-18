# Sending to Syslog in Rust

A small library to write to local syslog.

This crate is forked from [syslog](https://crates.io/crates/syslog), and adds support for TLS among with some other quality-of-life changes.

## Installation

syslog-tls is available on [crates.io](https://crates.io/crates/syslog-tls) and can be included in your Cargo enabled project like this:

```toml
[dependencies]
syslog = "^7.0"
```

## documentation

Reference documentation is available [here](https://docs.rs/syslog-tls).

There are 4 functions to create loggers:

* the `unix` function sends to the local syslog through a Unix socket: `syslog::unix(formatter)`
* the `udp` function takes an address for a local port, and the address remote UDP syslog server: `udp(formatter, "127.0.0.1:1234", "127.0.0.1:4242")`
* the `tcp` function takes an address for a remote TCP syslog server: `tcp(formatter, "127.0.0.1:4242")`
* the `tls` function takes an address for a remote TCP syslog server, a certificate, and a host domain: `tls(formatter, "127.0.0.1:4242", certificate, host)`
