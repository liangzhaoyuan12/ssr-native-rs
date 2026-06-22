use crate::error::Result;
use super::obfs::{Obfs, ServerInfo};
use super::obfsutil::rand_bytes;

fn generate_http_header(host: &str, data_len: usize, is_post: bool, is_server: bool) -> Vec<u8> {
    let host = if host.is_empty() { "www.baidu.com" } else { host };
    let method = if is_post { "POST" } else { "GET" };

    let path = if is_server {
        // Server sends response-like headers
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Content-Type: application/octet-stream\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            data_len
        )
    } else {
        // Client sends request-like headers
        let user_agent = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/537.36",
        ][rand_bytes(1)[0] as usize % 4];

        format!(
            "{} /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Language: en-US,en;q=0.8\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: keep-alive\r\n\
             Content-Length: {}\r\n\
             \r\n",
            method, "udp151df/", host, user_agent, data_len
        )
    };

    path.into_bytes()
}

pub struct HttpSimple {
    server_info: ServerInfo,
    buffer: Vec<u8>,
}

impl HttpSimple {
    pub fn new() -> Self {
        HttpSimple { server_info: ServerInfo::default(), buffer: Vec::new() }
    }
}

impl Obfs for HttpSimple {
    fn name(&self) -> &str { "http_simple" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }

    fn client_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let host = &self.server_info.host;
        let header = generate_http_header(host, data.len(), false, false);
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn client_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        // Find end of HTTP headers (\r\n\r\n)
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            // Need more data
            Ok(Vec::new())
        }
    }

    fn server_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let header = generate_http_header("", data.len(), false, true);
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn server_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            Ok(Vec::new())
        }
    }

    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) { self.buffer.clear(); }
}

pub struct HttpPost {
    server_info: ServerInfo,
    buffer: Vec<u8>,
}

impl HttpPost {
    pub fn new() -> Self {
        HttpPost { server_info: ServerInfo::default(), buffer: Vec::new() }
    }
}

impl Obfs for HttpPost {
    fn name(&self) -> &str { "http_post" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }

    fn client_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let host = &self.server_info.host;
        let header = generate_http_header(host, data.len(), true, false);
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn client_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            Ok(Vec::new())
        }
    }

    fn server_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let header = generate_http_header("", data.len(), false, true);
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn server_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            Ok(Vec::new())
        }
    }

    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) { self.buffer.clear(); }
}

pub struct HttpMix {
    server_info: ServerInfo,
    buffer: Vec<u8>,
    is_first: bool,
}

impl HttpMix {
    pub fn new() -> Self {
        HttpMix { server_info: ServerInfo::default(), buffer: Vec::new(), is_first: true }
    }
}

impl Obfs for HttpMix {
    fn name(&self) -> &str { "http_mix" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }

    fn client_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let host = &self.server_info.host;
        let is_post = !self.is_first;
        let header = generate_http_header(host, data.len(), is_post, false);
        self.is_first = false;
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn client_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            Ok(Vec::new())
        }
    }

    fn server_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let header = generate_http_header("", data.len(), false, true);
        let mut out = Vec::with_capacity(header.len() + data.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn server_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        if let Some(pos) = find_http_header_end(&self.buffer) {
            let body = self.buffer[pos..].to_vec();
            self.buffer.clear();
            Ok(body)
        } else {
            Ok(Vec::new())
        }
    }

    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) { self.buffer.clear(); }
}

pub struct Plain {
    server_info: ServerInfo,
}

impl Plain {
    pub fn new() -> Self { Plain { server_info: ServerInfo::default() } }
}

impl Obfs for Plain {
    fn name(&self) -> &str { "plain" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_decode(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

/// Find end of HTTP headers (\r\n\r\n), return position after it
fn find_http_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}
