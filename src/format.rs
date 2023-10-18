use std::fmt::Display;
use std::io::Write;
use time::{self, OffsetDateTime};

use crate::errors::*;
use crate::facility::Facility;
use crate::get_hostname;
use crate::get_process_info;
use crate::Priority;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum Severity {
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
}

pub trait LogFormat<T> {
    fn format<W: Write>(&self, w: &mut W, severity: Severity, message: T) -> Result<()> {
        self.format_at(w, severity, now_local().unwrap(), message)
    }

    fn format_at<W: Write>(
        &self,
        w: &mut W,
        severity: Severity,
        time: OffsetDateTime,
        message: T,
    ) -> Result<()>;

    fn emerg<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_EMERG, message)
    }

    fn alert<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_ALERT, message)
    }

    fn crit<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_CRIT, message)
    }

    fn err<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_ERR, message)
    }

    fn warning<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_WARNING, message)
    }

    fn notice<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_NOTICE, message)
    }

    fn info<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_INFO, message)
    }

    fn debug<W: Write>(&mut self, w: &mut W, message: T) -> Result<()> {
        self.format(w, Severity::LOG_DEBUG, message)
    }
}

#[derive(Clone, Debug)]
pub struct Formatter3164 {
    pub facility: Facility,
    pub hostname: Option<String>,
    pub process: String,
    pub pid: u32,
}

impl<T: Display> LogFormat<T> for Formatter3164 {
    fn format_at<W: Write>(
        &self,
        w: &mut W,
        severity: Severity,
        time: OffsetDateTime,
        message: T,
    ) -> Result<()> {
        let format =
            time::format_description::parse("[month repr:short] [day] [hour]:[minute]:[second]")
                .unwrap();

        if let Some(ref hostname) = self.hostname {
            writeln!(
                w,
                "<{}>{} {} {}[{}]: {}",
                encode_priority(severity, self.facility),
                time.format(&format).unwrap(),
                hostname,
                self.process,
                self.pid,
                message
            )
            .chain_err(|| ErrorKind::Format)
        } else {
            writeln!(
                w,
                "<{}>{} {}[{}]: {}",
                encode_priority(severity, self.facility),
                time.format(&format).unwrap(),
                self.process,
                self.pid,
                message
            )
            .chain_err(|| ErrorKind::Format)
        }
    }
}

impl Default for Formatter3164 {
    /// Returns a `Formatter3164` with default settings.
    ///
    /// The default settings are as follows:
    ///
    /// * `facility`: `LOG_USER`, as [specified by POSIX].
    /// * `hostname`: Automatically detected using [the `hostname` crate], if possible.
    /// * `process`: Automatically detected using [`std::env::current_exe`], or if that fails, an empty string.
    /// * `pid`: Automatically detected using [`libc::getpid`].
    ///
    /// [`libc::getpid`]: https://docs.rs/libc/0.2/libc/fn.getpid.html
    /// [specified by POSIX]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/closelog.html
    /// [`std::env::current_exe`]: https://doc.rust-lang.org/std/env/fn.current_exe.html
    /// [the `hostname` crate]: https://crates.io/crates/hostname
    fn default() -> Self {
        let (process, pid) = get_process_info().unwrap_or((String::new(), std::process::id()));
        let hostname = get_hostname().ok();

        Self {
            facility: Default::default(),
            hostname,
            process,
            pid,
        }
    }
}

/// RFC 5424 structured data
pub type StructuredData = Vec<(String, Vec<(String, String)>)>;

pub struct SyslogMessage {
    pub message_level: u32,
    pub structured: StructuredData,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Formatter5424 {
    pub facility: Facility,
    pub hostname: Option<String>,
    pub process: String,
    pub pid: u32,
}

impl Formatter5424 {
    pub fn format_5424_structured_data(&self, data: StructuredData) -> String {
        if data.is_empty() {
            "-".to_string()
        } else {
            let mut res = String::new();
            for (id, params) in &data {
                res = res + "[" + id;
                for (name, value) in params {
                    res = res + " " + name + "=\"" + value + "\"";
                }
                res += "]";
            }

            res
        }
    }
}

impl LogFormat<SyslogMessage> for Formatter5424 {
    fn format_at<W: Write>(
        &self,
        w: &mut W,
        severity: Severity,
        time: OffsetDateTime,
        message: SyslogMessage,
    ) -> Result<()> {
        write!(
            w,
            "<{}>1 {} {} {} {} {} {} {}{}", // v1
            encode_priority(severity, self.facility),
            time.format(&time::format_description::well_known::Rfc3339)
                .expect("Can format time"),
            self.hostname
                .as_ref()
                .map(|x| &x[..])
                .unwrap_or("localhost"),
            self.process,
            self.pid,
            message.message_level,
            self.format_5424_structured_data(message.structured),
            message.message,
            // Append new-line at the end of message if not present, mandatory for RFC5424
            if message.message.ends_with('\n') {
                ""
            } else {
                "\n"
            },
        )
        .chain_err(|| "Failed to write syslog message")
    }
}

impl Default for Formatter5424 {
    /// Returns a `Formatter5424` with default settings.
    ///
    /// The default settings are as follows:
    ///
    /// * `facility`: `LOG_USER`, as [specified by POSIX].
    /// * `hostname`: Automatically detected using [the `hostname` crate], if possible.
    /// * `process`: Automatically detected using [`std::env::current_exe`], or if that fails, an empty string.
    /// * `pid`: Automatically detected using [`libc::getpid`].
    ///
    /// [`libc::getpid`]: https://docs.rs/libc/0.2/libc/fn.getpid.html
    /// [specified by POSIX]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/closelog.html
    /// [`std::env::current_exe`]: https://doc.rust-lang.org/std/env/fn.current_exe.html
    /// [the `hostname` crate]: https://crates.io/crates/hostname
    fn default() -> Self {
        // Get the defaults from `Formatter3164` and move them over.
        let Formatter3164 {
            facility,
            hostname,
            process,
            pid,
        } = Default::default();
        Self {
            facility,
            hostname,
            process,
            pid,
        }
    }
}

fn encode_priority(severity: Severity, facility: Facility) -> Priority {
    facility as u8 | severity as u8
}

#[cfg(unix)]
// On unix platforms, time::OffsetDateTime::now_local always returns an error so use UTC instead
// https://github.com/time-rs/time/issues/380
fn now_local() -> std::result::Result<time::OffsetDateTime, time::error::IndeterminateOffset> {
    Ok(time::OffsetDateTime::now_utc())
}

#[cfg(not(unix))]
fn now_local() -> std::result::Result<time::OffsetDateTime, time::error::IndeterminateOffset> {
    time::OffsetDateTime::now_local()
}

#[test]
fn test_formatter3164_defaults() {
    let d = Formatter3164::default();

    // `Facility` doesn't implement `PartialEq`, so we use a `match` instead.
    assert!(match d.facility {
        Facility::LOG_USER => true,
        _ => false,
    });

    assert!(match &d.hostname {
        Some(hostname) => !hostname.is_empty(),
        None => false,
    });

    assert!(!d.process.is_empty());

    // Can't really make any assertions about the pid.
}

#[test]
fn test_formatter5424_defaults() {
    let d = Formatter5424::default();

    // `Facility` doesn't implement `PartialEq`, so we use a `match` instead.
    assert!(match d.facility {
        Facility::LOG_USER => true,
        _ => false,
    });

    assert!(match &d.hostname {
        Some(hostname) => !hostname.is_empty(),
        None => false,
    });

    assert!(!d.process.is_empty());

    // Can't really make any assertions about the pid.
}
