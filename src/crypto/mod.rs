pub mod stream;
pub mod aead;
pub mod key_derive;
pub mod cipher_names;

use crate::error::{Error, Result};
use stream::{CipherMethod, StreamCipher};
use aead::{AeadMethod, AeadTcpCipher, AeadUdpCipher};

/// Top-level cipher that handles both stream and AEAD ciphers
/// Matching the C `cipher_env_t` + `enc_ctx` combined pattern
pub enum SsrCipher {
    Stream(StreamCipher),
    AeadTcp(AeadTcpCipher),
}

impl SsrCipher {
    /// Create a new cipher from method name and password
    pub fn new(method_name: &str, password: &str) -> Result<Self> {
        if let Some(method) = AeadMethod::from_name(method_name) {
            let key = key_derive::crypto_derive_key(password.as_bytes(), method.key_len());
            Ok(SsrCipher::AeadTcp(AeadTcpCipher::new(method, key)))
        } else if let Some(method) = CipherMethod::from_name(method_name) {
            let key = key_derive::bytes_to_key(
                password.as_bytes(),
                method.key_len(),
                method.iv_len(),
            ).0;
            if method == CipherMethod::Table {
                // Table cipher uses raw password as key (passed to TableCipher::new)
                Ok(SsrCipher::Stream(StreamCipher::new(method, password.as_bytes().to_vec())))
            } else {
                Ok(SsrCipher::Stream(StreamCipher::new(method, key)))
            }
        } else {
            Err(Error::Crypto(format!("unknown cipher method: {}", method_name)))
        }
    }

    /// Encrypt data (TCP mode, handles IV prepending automatically)
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SsrCipher::Stream(c) => c.encrypt(data),
            SsrCipher::AeadTcp(c) => c.encrypt(data),
        }
    }

    /// Decrypt data (TCP mode, handles IV stripping automatically)
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SsrCipher::Stream(c) => c.decrypt(data),
            SsrCipher::AeadTcp(c) => c.decrypt(data),
        }
    }

    /// Create UDP cipher for AEAD (separate instance for each packet)
    pub fn new_udp(method_name: &str, password: &str) -> Result<AeadUdpCipher> {
        let method = AeadMethod::from_name(method_name)
            .ok_or_else(|| Error::Crypto(format!("unknown AEAD method: {}", method_name)))?;
        let key = key_derive::crypto_derive_key(password.as_bytes(), method.key_len());
        Ok(AeadUdpCipher::new(method, key))
    }

    pub fn is_initialized(&self) -> bool {
        match self {
            SsrCipher::Stream(c) => c.initialized(),
            SsrCipher::AeadTcp(c) => c.is_initialized(),
        }
    }

    pub fn method_name(&self) -> &'static str {
        match self {
            SsrCipher::Stream(c) => c.method().name(),
            SsrCipher::AeadTcp(c) => c.method().name(),
        }
    }

    pub fn is_aead(&self) -> bool {
        matches!(self, SsrCipher::AeadTcp(_))
    }
}
