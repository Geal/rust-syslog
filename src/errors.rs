#[derive(Error, Debug)]
pub enum Error {
    #[error("initialization: {0}")]
    Initialization(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("cannot find process file name")]
    ProcessHasNoFilename,
    #[error("not a valid UTF-8 string")]
    NonUtf8OsStr,
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("cannot find a valid unix socket to local syslog")]
    NoValidUnixSocket,
    #[error("not a valid socket address")]
    InvalidSocketAddr,
    #[error("format: {0}")]
    Format(#[source] std::io::Error),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
