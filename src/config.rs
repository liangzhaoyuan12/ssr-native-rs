use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrConfig {
    pub password: String,
    pub method: String,
    pub protocol: String,
    #[serde(rename = "protocol_param")]
    pub protocol_param: String,
    pub obfs: String,
    #[serde(rename = "obfs_param")]
    pub obfs_param: String,
    #[serde(default)]
    pub udp: bool,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: u64,
    #[serde(rename = "server_settings")]
    pub server_settings: Option<ServerSettings>,
    #[serde(rename = "client_settings")]
    pub client_settings: Option<ClientSettings>,
    #[serde(rename = "over_tls_settings")]
    pub over_tls_settings: Option<OverTlsSettings>,
}

fn default_idle_timeout() -> u64 { 300 }
fn default_connect_timeout() -> u64 { 6 }
fn default_udp_timeout() -> u64 { 6 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub listen_address: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    pub server: String,
    pub server_port: u16,
    pub listen_address: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverTlsSettings {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_server_domain")]
    pub server_domain: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub root_cert_file: String,
}

fn default_server_domain() -> String { "goodsitesample.com".into() }

impl SsrConfig {
    pub fn from_file(path: &str) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::Error::Config(format!("read config file: {}", e)))?;
        let config: SsrConfig = serde_json::from_str(&content)
            .map_err(|e| crate::error::Error::Config(format!("parse config: {}", e)))?;
        Ok(config)
    }
}
