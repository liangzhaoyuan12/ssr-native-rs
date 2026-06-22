use crate::error::{Error, Result};
use crate::crypto::stream::{CipherMethod, StreamCipher};
use crate::crypto::aead::{AeadMethod, AeadTcpCipher};
use crate::crypto::key_derive;
use crate::obfs::obfs::{Obfs, Protocol, ServerInfo};
use crate::obfs::auth::*;
use crate::obfs::auth_chain::*;
use crate::obfs::http_simple::*;
use crate::obfs::tls1_2_ticket::*;
use crate::config::SsrConfig;

pub fn create_protocol(name: &str) -> Option<Box<dyn Protocol>> {
    Some(match name {
        "origin" => Box::new(Origin::new()),
        "verify_simple" => Box::new(VerifySimple::new()),
        "auth_simple" => Box::new(AuthSimple::new()),
        "auth_sha1" => Box::new(AuthSha1::new()),
        "auth_sha1_v2" => Box::new(AuthSha1V2::new()),
        "auth_sha1_v4" => Box::new(AuthSha1V4::new()),
        "auth_aes128_md5" => Box::new(AuthAes128Md5::new()),
        "auth_aes128_sha1" => Box::new(AuthAes128Sha1::new()),
        "auth_chain_a" => Box::new(AuthChainA::new()),
        "auth_chain_b" => Box::new(AuthChainB::new()),
        "auth_chain_c" => Box::new(AuthChainC::new()),
        "auth_chain_d" => Box::new(AuthChainD::new()),
        "auth_chain_e" => Box::new(AuthChainE::new()),
        "auth_chain_f" => Box::new(AuthChainF::new()),
        _ => return None,
    })
}

pub fn create_obfs(name: &str) -> Option<Box<dyn Obfs>> {
    Some(match name {
        "plain" => Box::new(Plain::new()),
        "http_simple" => Box::new(HttpSimple::new()),
        "http_post" => Box::new(HttpPost::new()),
        "http_mix" => Box::new(HttpMix::new()),
        "tls1.2_ticket_auth" => Box::new(Tls12TicketAuth::new()),
        "tls1.2_ticket_fastauth" => Box::new(Tls12TicketFastAuth::new()),
        _ => return None,
    })
}

/// Combined cipher pipeline: protocol -> cipher -> obfs
pub enum CipherKind {
    Stream(StreamCipher),
    AeadTcp(AeadTcpCipher),
}

pub struct TunnelCipherCtx {
    pub server_info: ServerInfo,
    pub protocol: Option<Box<dyn Protocol>>,
    pub obfs: Option<Box<dyn Obfs>>,
    pub cipher: CipherKind,
}

impl TunnelCipherCtx {
    pub fn new(config: &SsrConfig, _is_server: bool) -> Result<Self> {
        let method_name = &config.method;

        // Check if it's AEAD
        if let Some(method) = AeadMethod::from_name(method_name) {
            let key = key_derive::crypto_derive_key(config.password.as_bytes(), method.key_len());
            let cipher = CipherKind::AeadTcp(AeadTcpCipher::new(method, key.clone()));
            // AEAD ciphers don't use protocol/obfs in SSR
            let server_info = ServerInfo {
                host: config.client_settings.as_ref().map(|s| s.server.clone()).unwrap_or_default(),
                port: config.client_settings.as_ref().map(|s| s.server_port).unwrap_or(0),
                param: String::new(),
                key,
                recv_iv: Vec::new(),
                send_iv: Vec::new(),
                udp: config.udp,
            };
            return Ok(TunnelCipherCtx {
                server_info,
                protocol: None,
                obfs: None,
                cipher,
            });
        }

        // Stream cipher
        let method = CipherMethod::from_name(method_name)
            .ok_or_else(|| Error::Config(format!("unknown cipher: {}", method_name)))?;
        let der_key = if method == CipherMethod::Table {
            config.password.as_bytes().to_vec()
        } else {
            key_derive::bytes_to_key(
                config.password.as_bytes(),
                method.key_len(),
                method.iv_len(),
            ).0
        };

        let cipher = CipherKind::Stream(StreamCipher::new(method, der_key.clone()));

        let mut protocol = if config.protocol.is_empty() || config.protocol == "origin" {
            None
        } else {
            create_protocol(&config.protocol)
        };

        let mut obfs = if config.obfs.is_empty() || config.obfs == "plain" {
            None
        } else {
            create_obfs(&config.obfs)
        };

        let server_info = ServerInfo {
            host: config.client_settings.as_ref().map(|s| s.server.clone()).unwrap_or_default(),
            port: config.client_settings.as_ref().map(|s| s.server_port).unwrap_or(0),
            param: config.protocol_param.clone(),
            key: der_key.clone(),
            recv_iv: Vec::new(),
            send_iv: Vec::new(),
            udp: config.udp,
        };

        if let Some(ref mut p) = protocol {
            p.set_server_info(server_info.clone());
        }
        if let Some(ref mut o) = obfs {
            o.set_server_info(server_info.clone());
        }

        Ok(TunnelCipherCtx {
            server_info,
            protocol,
            obfs,
            cipher,
        })
    }

    pub fn client_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = if let Some(ref mut p) = self.protocol {
            p.client_pre_encrypt(data)?
        } else {
            data.to_vec()
        };

        let data = match &mut self.cipher {
            CipherKind::Stream(c) => c.encrypt(&data)?,
            CipherKind::AeadTcp(c) => c.encrypt(&data)?,
        };

        let data = if let Some(ref mut o) = self.obfs {
            o.client_encode(&data)?
        } else {
            data
        };

        Ok(data)
    }

    pub fn client_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = if let Some(ref mut o) = self.obfs {
            o.client_decode(data)?
        } else {
            data.to_vec()
        };

        let data = match &mut self.cipher {
            CipherKind::Stream(c) => c.decrypt(&data)?,
            CipherKind::AeadTcp(c) => c.decrypt(&data)?,
        };

        let data = if let Some(ref mut p) = self.protocol {
            p.client_post_decrypt(&data)?
        } else {
            data
        };

        Ok(data)
    }

    pub fn server_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = if let Some(ref mut p) = self.protocol {
            p.server_pre_encrypt(data)?
        } else {
            data.to_vec()
        };

        let data = match &mut self.cipher {
            CipherKind::Stream(c) => c.encrypt(&data)?,
            CipherKind::AeadTcp(c) => c.encrypt(&data)?,
        };

        let data = if let Some(ref mut o) = self.obfs {
            o.server_encode(&data)?
        } else {
            data
        };

        Ok(data)
    }

    pub fn server_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = if let Some(ref mut o) = self.obfs {
            o.server_decode(data)?
        } else {
            data.to_vec()
        };

        let data = match &mut self.cipher {
            CipherKind::Stream(c) => c.decrypt(&data)?,
            CipherKind::AeadTcp(c) => c.decrypt(&data)?,
        };

        let data = if let Some(ref mut p) = self.protocol {
            p.server_post_decrypt(&data)?
        } else {
            data
        };

        Ok(data)
    }

    pub fn method_name(&self) -> &'static str {
        match &self.cipher {
            CipherKind::Stream(c) => c.method().name(),
            CipherKind::AeadTcp(c) => c.method().name(),
        }
    }
}
