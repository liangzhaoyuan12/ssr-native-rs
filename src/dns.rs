use std::net::IpAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct DnsCache {
    cache: HashMap<String, (IpAddr, Instant)>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl_secs: u64) -> Self {
        DnsCache {
            cache: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn get(&self, host: &str) -> Option<IpAddr> {
        self.cache.get(host).and_then(|(addr, time)| {
            if time.elapsed() < self.ttl {
                Some(*addr)
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, host: String, addr: IpAddr) {
        self.cache.insert(host, (addr, Instant::now()));
    }

    pub async fn resolve(&mut self, host: &str) -> crate::error::Result<IpAddr> {
        if let Some(addr) = self.get(host) {
            return Ok(addr);
        }
        let addr = tokio::net::lookup_host((host, 0)).await?
            .next()
            .ok_or_else(|| crate::error::Error::Dns(format!("resolve {} failed", host)))?;
        let ip = addr.ip();
        self.insert(host.to_string(), ip);
        Ok(ip)
    }
}
