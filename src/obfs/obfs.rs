use crate::error::Result;

pub trait Obfs: Send {
    fn name(&self) -> &str;
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn client_encode(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn client_decode(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_encode(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_decode(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn set_server_info(&mut self, info: ServerInfo);
    fn get_server_info(&self) -> &ServerInfo;
    fn dispose(&mut self);
}

pub trait Protocol: Send {
    fn name(&self) -> &str;
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn set_server_info(&mut self, info: ServerInfo);
    fn get_server_info(&self) -> &ServerInfo;
    fn dispose(&mut self);
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub host: String,
    pub port: u16,
    pub param: String,
    pub key: Vec<u8>,
    pub recv_iv: Vec<u8>,
    pub send_iv: Vec<u8>,
    pub udp: bool,
}

impl Default for ServerInfo {
    fn default() -> Self {
        ServerInfo {
            host: String::new(),
            port: 0,
            param: String::new(),
            key: Vec::new(),
            recv_iv: Vec::new(),
            send_iv: Vec::new(),
            udp: false,
        }
    }
}
