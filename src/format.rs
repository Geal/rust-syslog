use std::collections::HashMap;
use std::fmt::Display;
use std::io::Write;
use time;

use errors::*;
use facility::Facility;
use Priority;

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
    fn format<W: Write>(&self, w: &mut W, severity: Severity, message: T) -> Result<()>;

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
    pub pid: i32,
}

impl<T: Display> LogFormat<T> for Formatter3164 {
    fn format<W: Write>(&self, w: &mut W, severity: Severity, message: T) -> Result<()> {
        if let Some(ref hostname) = self.hostname {
            write!(
                w,
                "<{}>{} {} {}[{}]: {}",
                encode_priority(severity, self.facility),
                time::now().strftime("%b %d %T").unwrap(),
                hostname,
                self.process,
                self.pid,
                message
            )
            .chain_err(|| ErrorKind::Format)
        } else {
            write!(
                w,
                "<{}>{} {}[{}]: {}",
                encode_priority(severity, self.facility),
                time::now().strftime("%b %d %T").unwrap(),
                self.process,
                self.pid,
                message
            )
            .chain_err(|| ErrorKind::Format)
        }
    }
}

/// RFC 5424 structured data
pub type StructuredData = HashMap<String, HashMap<String, String>>;

#[derive(Clone, Debug)]
pub struct Formatter5424 {
    pub facility: Facility,
    pub hostname: Option<String>,
    pub process: String,
    pub pid: i32,
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

impl<T: Display> LogFormat<(i32, StructuredData, T)> for Formatter5424 {
    fn format<W: Write>(
        &self,
        w: &mut W,
        severity: Severity,
        log_message: (i32, StructuredData, T),
    ) -> Result<()> {
        let (message_id, data, message) = log_message;

        write!(
            w,
            "<{}> {} {} {} {} {} {} {} {}",
            encode_priority(severity, self.facility),
            1, // version
            time::now_utc().rfc3339(),
            self.hostname
                .as_ref()
                .map(|x| &x[..])
                .unwrap_or("localhost"),
            self.process,
            self.pid,
            message_id,
            self.format_5424_structured_data(data),
            message
        )
        .chain_err(|| ErrorKind::Format)
    }
}

fn encode_priority(severity: Severity, facility: Facility) -> Priority {
    facility as u8 | severity as u8
}
