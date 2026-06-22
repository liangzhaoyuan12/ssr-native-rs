use crate::base64;
use percent_encoding::percent_decode;

pub fn decode_ssr_link(link: &str) -> crate::error::Result<super::config::SsrConfig> {
    let link = link.trim();
    if !link.starts_with("ssr://") {
        return Err(crate::error::Error::Other("not an ssr link".into()));
    }
    let b64 = &link[6..];
    let decoded = base64::decode_urlsafe(b64)?;
    let decoded_str = String::from_utf8_lossy(&decoded);
    let parts: Vec<&str> = decoded_str.splitn(2, '/').collect();
    if parts.len() < 2 {
        return Err(crate::error::Error::Other("invalid ssr link".into()));
    }
    let base_info = parts[0];
    let param_part = parts[1].strip_prefix('?').unwrap_or(parts[1]);
    let base_parts: Vec<&str> = base_info.splitn(6, ':').collect();
    if base_parts.len() < 6 {
        return Err(crate::error::Error::Other("invalid ssr link base".into()));
    }
    let host = percent_decode(base_parts[0].as_bytes()).decode_utf8_lossy().to_string();
    let port: u16 = base_parts[1].parse().map_err(|_| crate::error::Error::Other("invalid port".into()))?;
    let protocol = base_parts[2].to_string();
    let method = base_parts[3].to_string();
    let obfs = base_parts[4].to_string();
    let password_b64 = base_parts[5];
    let password_bytes = base64::decode_urlsafe(password_b64).unwrap_or_default();
    let password = String::from_utf8_lossy(&password_bytes).to_string();
    let mut config = super::config::SsrConfig {
        password,
        method,
        protocol,
        protocol_param: String::new(),
        obfs,
        obfs_param: String::new(),
        udp: false,
        idle_timeout: 300,
        connect_timeout: 6,
        udp_timeout: 6,
        server_settings: None,
        client_settings: Some(super::config::ClientSettings {
            server: host,
            server_port: port,
            listen_address: "127.0.0.1".into(),
            listen_port: 1080,
        }),
        over_tls_settings: None,
    };
    for param in param_part.split('&') {
        let kv: Vec<&str> = param.splitn(2, '=').collect();
        if kv.len() != 2 { continue; }
        match kv[0] {
            "obfsparam" => {
                if let Ok(b) = base64::decode_urlsafe(kv[1]) {
                    config.obfs_param = String::from_utf8_lossy(&b).to_string();
                }
            }
            "protoparam" => {
                if let Ok(b) = base64::decode_urlsafe(kv[1]) {
                    config.protocol_param = String::from_utf8_lossy(&b).to_string();
                }
            }
            _ => {}
        }
    }
    Ok(config)
}
