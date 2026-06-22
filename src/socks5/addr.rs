use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Addr {
    pub addr_type: u8,
    pub host: String,
    pub port: u16,
}

impl Socks5Addr {
    pub fn new(addr_type: u8, host: String, port: u16) -> Self {
        Socks5Addr { addr_type, host, port }
    }

    pub fn from_host_port(host: &str, port: u16) -> Self {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Socks5Addr { addr_type: 1, host: ip.to_string(), port }
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            Socks5Addr { addr_type: 4, host: ip.to_string(), port }
        } else {
            Socks5Addr { addr_type: 3, host: host.to_string(), port }
        }
    }

    /// Parse SOCKS5 address from wire format: [ATYPE][ADDR][PORT]
    pub fn parse(data: &[u8]) -> Result<(Socks5Addr, usize)> {
        if data.is_empty() {
            return Err(Error::Socks5("empty addr".into()));
        }
        let addr_type = data[0];
        let (host, offset) = match addr_type {
            1 => {
                if data.len() < 5 { return Err(Error::Socks5("short IPv4".into())); }
                let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]).to_string();
                (ip, 5)
            }
            3 => {
                if data.len() < 2 { return Err(Error::Socks5("short domain".into())); }
                let len = data[1] as usize;
                if data.len() < 2 + len { return Err(Error::Socks5("short domain body".into())); }
                let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
                (domain, 2 + len)
            }
            4 => {
                if data.len() < 17 { return Err(Error::Socks5("short IPv6".into())); }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = std::net::Ipv6Addr::from(octets).to_string();
                (ip, 17)
            }
            _ => return Err(Error::Socks5(format!("unknown atyp {}", addr_type))),
        };
        if data.len() < offset + 2 {
            return Err(Error::Socks5("short port".into()));
        }
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        Ok((Socks5Addr { addr_type, host, port }, offset + 2))
    }

    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.addr_type);
        match self.addr_type {
            1 => {
                let ip: std::net::Ipv4Addr = self.host.parse().unwrap_or_else(|_| std::net::Ipv4Addr::new(0, 0, 0, 0));
                buf.extend_from_slice(&ip.octets());
            }
            3 => {
                buf.push(self.host.len() as u8);
                buf.extend_from_slice(self.host.as_bytes());
            }
            4 => {
                let ip: std::net::Ipv6Addr = self.host.parse().unwrap_or_else(|_| std::net::Ipv6Addr::UNSPECIFIED);
                buf.extend_from_slice(&ip.octets());
            }
            _ => {}
        }
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    /// Wire size of this address (including ATYP byte)
    pub fn encoded_size(&self) -> usize {
        1 + match self.addr_type {
            1 => 4,
            3 => 1 + self.host.len(),
            4 => 16,
            _ => 0,
        } + 2
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn is_ipv4(&self) -> bool { self.addr_type == 1 }
    pub fn is_domain(&self) -> bool { self.addr_type == 3 }
    pub fn is_ipv6(&self) -> bool { self.addr_type == 4 }
}
