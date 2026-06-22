use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Config(String),
    Crypto(String),
    Protocol(String),
    Obfs(String),
    Socks5(String),
    Dns(String),
    Tunnel(String),
    Tls(String),
    Websocket(String),
    Buffer(String),
    ParseInt(std::num::ParseIntError),
    AddrParse(std::net::AddrParseError),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Config(s) => write!(f, "Config error: {}", s),
            Error::Crypto(s) => write!(f, "Crypto error: {}", s),
            Error::Protocol(s) => write!(f, "Protocol error: {}", s),
            Error::Obfs(s) => write!(f, "Obfuscation error: {}", s),
            Error::Socks5(s) => write!(f, "SOCKS5 error: {}", s),
            Error::Dns(s) => write!(f, "DNS error: {}", s),
            Error::Tunnel(s) => write!(f, "Tunnel error: {}", s),
            Error::Tls(s) => write!(f, "TLS error: {}", s),
            Error::Websocket(s) => write!(f, "WebSocket error: {}", s),
            Error::Buffer(s) => write!(f, "Buffer error: {}", s),
            Error::ParseInt(e) => write!(f, "Parse int error: {}", e),
            Error::AddrParse(e) => write!(f, "Addr parse error: {}", e),
            Error::Other(s) => write!(f, "Error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseInt(e)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::AddrParse(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
