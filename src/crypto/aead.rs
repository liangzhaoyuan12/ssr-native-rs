use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use cipher::generic_array::GenericArray;
use typenum::{U12, U24};
use crate::error::{Error, Result};

type AesNonce = GenericArray<u8, U12>;
type ChaChaNonce = GenericArray<u8, U12>;
type _XChaChaNonce = GenericArray<u8, U24>;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadMethod {
    Aes128Gcm, Aes192Gcm, Aes256Gcm,
    ChaCha20Poly1305, XChaCha20Poly1305,
}

impl AeadMethod {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-192-gcm" => Self::Aes192Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" => Self::ChaCha20Poly1305,
            "xchacha20-ietf-poly1305" => Self::XChaCha20Poly1305,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes192Gcm => "aes-192-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
            Self::XChaCha20Poly1305 => "xchacha20-ietf-poly1305",
        }
    }

    pub fn key_len(&self) -> usize {
        match self { Self::Aes128Gcm => 16, Self::Aes192Gcm => 24, _ => 32 }
    }
    pub fn nonce_len(&self) -> usize {
        match self { Self::XChaCha20Poly1305 => 24, _ => 12 }
    }
    pub fn tag_len(&self) -> usize { 16 }
    pub fn salt_len(&self) -> usize { 32 }
}

// Concrete AEAD helpers using explicit nonce types

fn enc_aes128(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = AesNonce::from_slice(nonce);
    c.encrypt(n, Payload { msg: pt, aad }).map_err(|_| Error::Crypto("aes-128-gcm enc".into()))
}

fn enc_aes256(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = AesNonce::from_slice(nonce);
    c.encrypt(n, Payload { msg: pt, aad }).map_err(|_| Error::Crypto("aes-256-gcm enc".into()))
}

fn enc_chacha(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = ChaChaNonce::from_slice(nonce);
    c.encrypt(n, Payload { msg: pt, aad }).map_err(|_| Error::Crypto("chacha20-poly1305 enc".into()))
}

fn enc_xchacha(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = XNonce::from_slice(nonce);
    c.encrypt(n, Payload { msg: pt, aad }).map_err(|_| Error::Crypto("xchacha20-poly1305 enc".into()))
}

fn dec_aes128(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = AesNonce::from_slice(nonce);
    c.decrypt(n, Payload { msg: ct, aad }).map_err(|_| Error::Crypto("aes-128-gcm dec".into()))
}

fn dec_aes256(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = AesNonce::from_slice(nonce);
    c.decrypt(n, Payload { msg: ct, aad }).map_err(|_| Error::Crypto("aes-256-gcm dec".into()))
}

fn dec_chacha(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = ChaChaNonce::from_slice(nonce);
    c.decrypt(n, Payload { msg: ct, aad }).map_err(|_| Error::Crypto("chacha20-poly1305 dec".into()))
}

fn dec_xchacha(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Crypto(format!("{}", e)))?;
    let n = XNonce::from_slice(nonce);
    c.decrypt(n, Payload { msg: ct, aad }).map_err(|_| Error::Crypto("xchacha20-poly1305 dec".into()))
}

fn aead_encrypt(method: AeadMethod, key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    match method {
        AeadMethod::Aes128Gcm => enc_aes128(key, nonce, pt, aad),
        AeadMethod::Aes192Gcm | AeadMethod::Aes256Gcm => enc_aes256(key, nonce, pt, aad),
        AeadMethod::ChaCha20Poly1305 => enc_chacha(key, nonce, pt, aad),
        AeadMethod::XChaCha20Poly1305 => enc_xchacha(key, nonce, pt, aad),
    }
}

fn aead_decrypt(method: AeadMethod, key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    match method {
        AeadMethod::Aes128Gcm => dec_aes128(key, nonce, ct, aad),
        AeadMethod::Aes192Gcm | AeadMethod::Aes256Gcm => dec_aes256(key, nonce, ct, aad),
        AeadMethod::ChaCha20Poly1305 => dec_chacha(key, nonce, ct, aad),
        AeadMethod::XChaCha20Poly1305 => dec_xchacha(key, nonce, ct, aad),
    }
}

fn derive_subkey(key: &[u8], salt: &[u8], out_len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), key);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm).expect("HKDF expand");
    okm
}

fn build_nonce(nonce_len: usize, counter: u64) -> Vec<u8> {
    let mut nonce = vec![0u8; nonce_len];
    let cb = counter.to_be_bytes();
    let start = nonce_len.saturating_sub(8);
    nonce[start..].copy_from_slice(&cb[..nonce_len - start]);
    nonce
}

// --- TCP mode ---

pub struct AeadTcpCipher {
    method: AeadMethod,
    key: Vec<u8>,
    salt: Vec<u8>,
    nonce: u64,
    subkey: Vec<u8>,
    initialized: bool,
}

impl AeadTcpCipher {
    pub fn new(method: AeadMethod, key: Vec<u8>) -> Self {
        AeadTcpCipher {
            method, key,
            salt: vec![0u8; method.salt_len()],
            nonce: 0, subkey: Vec::new(), initialized: false,
        }
    }

    pub fn method(&self) -> AeadMethod { self.method }
    pub fn is_initialized(&self) -> bool { self.initialized }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let tag = self.method.tag_len();
        let chunk_size = 0x3FFF;

        if !self.initialized {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut self.salt);
            self.subkey = derive_subkey(&self.key, &self.salt, self.method.key_len());
            self.nonce = 0;
            self.initialized = true;
            let mut out = Vec::new();
            out.extend_from_slice(&self.salt);
            encrypt_chunks(&mut out, &mut self.nonce, &self.subkey, self.method, tag, chunk_size, plaintext)?;
            return Ok(out);
        }
        let mut out = Vec::new();
        encrypt_chunks(&mut out, &mut self.nonce, &self.subkey, self.method, tag, chunk_size, plaintext)?;
        Ok(out)
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let tag = self.method.tag_len();
        let sl = self.method.salt_len();

        if !self.initialized {
            if data.len() < sl { return Err(Error::Crypto("aead: short".into())); }
            self.salt.copy_from_slice(&data[..sl]);
            self.subkey = derive_subkey(&self.key, &self.salt, self.method.key_len());
            self.nonce = 0;
            self.initialized = true;
            return decrypt_chunks(&data[sl..], &mut self.nonce, &self.subkey, self.method, tag);
        }
        decrypt_chunks(data, &mut self.nonce, &self.subkey, self.method, tag)
    }
}

fn encrypt_chunks(out: &mut Vec<u8>, nonce: &mut u64, subkey: &[u8], method: AeadMethod, _tag: usize, chunk_size: usize, pt: &[u8]) -> Result<()> {
    let mut remaining = pt;
    while !remaining.is_empty() {
        let chunk = &remaining[..remaining.len().min(chunk_size)];
        remaining = &remaining[chunk.len()..];
        let len_be = (chunk.len() as u16).to_be_bytes();
        let n = build_nonce(method.nonce_len(), *nonce); *nonce += 1;
        let enc_len = aead_encrypt(method, subkey, &n, &len_be, &[])?;
        let n = build_nonce(method.nonce_len(), *nonce); *nonce += 1;
        let enc_payload = aead_encrypt(method, subkey, &n, chunk, &[])?;
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&enc_payload);
    }
    Ok(())
}

fn decrypt_chunks(data: &[u8], nonce: &mut u64, subkey: &[u8], method: AeadMethod, tag: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let ls = 2 + tag;
        if offset + ls > data.len() { return Err(Error::Crypto("aead chunk".into())); }
        let n = build_nonce(method.nonce_len(), *nonce); *nonce += 1;
        let len_plain = aead_decrypt(method, subkey, &n, &data[offset..offset + ls], &[])?;
        offset += ls;
        let plen = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let ps = plen + tag;
        if offset + ps > data.len() { return Err(Error::Crypto("aead payload".into())); }
        let n = build_nonce(method.nonce_len(), *nonce); *nonce += 1;
        let plain = aead_decrypt(method, subkey, &n, &data[offset..offset + ps], &[])?;
        offset += ps;
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

// --- UDP mode ---

pub struct AeadUdpCipher {
    method: AeadMethod,
    key: Vec<u8>,
}

impl AeadUdpCipher {
    pub fn new(method: AeadMethod, key: Vec<u8>) -> Self { AeadUdpCipher { method, key } }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; self.method.salt_len()];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let subkey = derive_subkey(&self.key, &salt, self.method.key_len());
        let nonce = vec![0u8; self.method.nonce_len()];
        let ct = aead_encrypt(self.method, &subkey, &nonce, plaintext, &[])?;
        let mut out = Vec::with_capacity(salt.len() + ct.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sl = self.method.salt_len();
        if data.len() < sl + self.method.tag_len() {
            return Err(Error::Crypto("aead udp: short".into()));
        }
        let subkey = derive_subkey(&self.key, &data[..sl], self.method.key_len());
        let nonce = vec![0u8; self.method.nonce_len()];
        aead_decrypt(self.method, &subkey, &nonce, &data[sl..], &[])
    }
}
