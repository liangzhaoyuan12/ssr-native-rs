use crate::error::Result;
use super::obfs::{Protocol, ServerInfo};

pub struct VerifySimple {
    server_info: ServerInfo,
}

impl VerifySimple {
    pub fn new() -> Self {
        VerifySimple { server_info: ServerInfo::default() }
    }
}

impl Protocol for VerifySimple {
    fn name(&self) -> &str { "verify_simple" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}
