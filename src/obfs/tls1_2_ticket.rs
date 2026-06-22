use crate::error::Result;
use super::obfs::{Obfs, ServerInfo};

pub struct Tls12TicketAuth {
    server_info: ServerInfo,
}

impl Tls12TicketAuth {
    pub fn new() -> Self {
        Tls12TicketAuth { server_info: ServerInfo::default() }
    }
}

impl Obfs for Tls12TicketAuth {
    fn name(&self) -> &str { "tls1.2_ticket_auth" }
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

pub struct Tls12TicketFastAuth {
    server_info: ServerInfo,
}

impl Tls12TicketFastAuth {
    pub fn new() -> Self {
        Tls12TicketFastAuth { server_info: ServerInfo::default() }
    }
}

impl Obfs for Tls12TicketFastAuth {
    fn name(&self) -> &str { "tls1.2_ticket_fastauth" }
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
