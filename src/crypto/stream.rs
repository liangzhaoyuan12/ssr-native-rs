use md5::Digest;
use cipher::{BlockEncrypt, KeyInit, StreamCipher as CipherStreamCipher, BlockSizeUser};
use cipher::generic_array::GenericArray;
use crate::error::{Error, Result};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    None, Table,
    Rc4, Rc4Md5, Rc4Md5_6,
    Aes128Cfb, Aes192Cfb, Aes256Cfb,
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
    Camellia128Cfb, Camellia192Cfb, Camellia256Cfb,
    BfCfb, Cast5Cfb, DesCfb, IdeaCfb, Rc2Cfb, SeedCfb,
    Salsa20, ChaCha20, ChaCha20Ietf,
}

impl CipherMethod {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_lowercase().as_str() {
            "none" => Self::None, "table" => Self::Table,
            "rc4" => Self::Rc4, "rc4-md5" => Self::Rc4Md5, "rc4-md5-6" => Self::Rc4Md5_6,
            "aes-128-cfb" => Self::Aes128Cfb, "aes-192-cfb" => Self::Aes192Cfb, "aes-256-cfb" => Self::Aes256Cfb,
            "aes-128-ctr" => Self::Aes128Ctr, "aes-192-ctr" => Self::Aes192Ctr, "aes-256-ctr" => Self::Aes256Ctr,
            "camellia-128-cfb" => Self::Camellia128Cfb, "camellia-192-cfb" => Self::Camellia192Cfb, "camellia-256-cfb" => Self::Camellia256Cfb,
            "bf-cfb" => Self::BfCfb, "cast5-cfb" => Self::Cast5Cfb, "des-cfb" => Self::DesCfb,
            "idea-cfb" => Self::IdeaCfb, "rc2-cfb" => Self::Rc2Cfb, "seed-cfb" => Self::SeedCfb,
            "salsa20" => Self::Salsa20, "chacha20" => Self::ChaCha20, "chacha20-ietf" => Self::ChaCha20Ietf,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none", Self::Table => "table",
            Self::Rc4 => "rc4", Self::Rc4Md5 => "rc4-md5", Self::Rc4Md5_6 => "rc4-md5-6",
            Self::Aes128Cfb => "aes-128-cfb", Self::Aes192Cfb => "aes-192-cfb", Self::Aes256Cfb => "aes-256-cfb",
            Self::Aes128Ctr => "aes-128-ctr", Self::Aes192Ctr => "aes-192-ctr", Self::Aes256Ctr => "aes-256-ctr",
            Self::Camellia128Cfb => "camellia-128-cfb", Self::Camellia192Cfb => "camellia-192-cfb", Self::Camellia256Cfb => "camellia-256-cfb",
            Self::BfCfb => "bf-cfb", Self::Cast5Cfb => "cast5-cfb", Self::DesCfb => "des-cfb",
            Self::IdeaCfb => "idea-cfb", Self::Rc2Cfb => "rc2-cfb", Self::SeedCfb => "seed-cfb",
            Self::Salsa20 => "salsa20", Self::ChaCha20 => "chacha20", Self::ChaCha20Ietf => "chacha20-ietf",
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::None | Self::Table | Self::Rc4 | Self::Rc4Md5 | Self::Rc4Md5_6 => 16,
            Self::Aes128Cfb | Self::Aes128Ctr => 16,
            Self::Aes192Cfb | Self::Aes192Ctr => 24,
            Self::Aes256Cfb | Self::Aes256Ctr => 32,
            Self::Camellia128Cfb => 16, Self::Camellia192Cfb => 24, Self::Camellia256Cfb => 32,
            Self::BfCfb | Self::Cast5Cfb | Self::IdeaCfb | Self::Rc2Cfb | Self::SeedCfb => 16,
            Self::DesCfb => 8,
            Self::Salsa20 | Self::ChaCha20 | Self::ChaCha20Ietf => 32,
        }
    }

    pub fn iv_len(&self) -> usize {
        match self {
            Self::None | Self::Table | Self::Rc4 => 0,
            Self::Rc4Md5 => 16, Self::Rc4Md5_6 => 6,
            Self::Aes128Cfb | Self::Aes192Cfb | Self::Aes256Cfb => 16,
            Self::Aes128Ctr | Self::Aes192Ctr | Self::Aes256Ctr => 16,
            Self::Camellia128Cfb | Self::Camellia192Cfb | Self::Camellia256Cfb => 16,
            Self::BfCfb | Self::Cast5Cfb | Self::DesCfb | Self::IdeaCfb | Self::Rc2Cfb => 8,
            Self::SeedCfb => 16,
            Self::Salsa20 | Self::ChaCha20 => 8,
            Self::ChaCha20Ietf => 12,
        }
    }

    pub fn need_iv_prepend(&self) -> bool {
        self.iv_len() > 0 && !matches!(self, Self::Rc4Md5 | Self::Rc4Md5_6)
    }
}

// --- Table cipher ---

pub struct TableCipher {
    enc_table: [u8; 256],
    dec_table: [u8; 256],
}

impl TableCipher {
    pub fn new(password: &[u8]) -> Self {
        let mut enc_table: [u8; 256] = std::array::from_fn(|i| i as u8);
        let digest = md5::Md5::digest(password);
        let seed = u64::from_le_bytes([digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]]);
        let mut rng = XorShift64::new(seed);
        for _ in 0..1024 {
            for i in 1..256 {
                let j = (rng.next() as usize) % (i + 1);
                enc_table.swap(i, j);
            }
        }
        let mut dec_table = [0u8; 256];
        for i in 0..256 { dec_table[enc_table[i] as usize] = i as u8; }
        TableCipher { enc_table, dec_table }
    }

    pub fn encrypt(&self, data: &mut [u8]) {
        for b in data.iter_mut() { *b = self.enc_table[*b as usize]; }
    }

    pub fn decrypt(&self, data: &mut [u8]) {
        for b in data.iter_mut() { *b = self.dec_table[*b as usize]; }
    }
}

struct XorShift64 { state: u64 }

impl XorShift64 {
    fn new(seed: u64) -> Self { XorShift64 { state: seed } }
    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.state = x; x
    }
}

// --- Generic CFB mode for any block cipher with BlockSizeUser ---

macro_rules! make_cfb {
    ($name:ident, $cipher:ty, $key_size:expr) => {
        struct $name {
            cipher: $cipher,
            iv: Vec<u8>,
        }
        impl $name {
            fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
                let mut k = [0u8; $key_size];
                let len = key.len().min($key_size);
                k[..len].copy_from_slice(&key[..len]);
                let cipher = <$cipher>::new_from_slice(&k[..len])
                    .map_err(|e| Error::Crypto(format!("{}: {}", stringify!($name), e)))?;
                Ok($name { cipher, iv: iv.to_vec() })
            }
            fn process(&mut self, data: &mut [u8]) {
                let bs = self.iv.len();
                for chunk in data.chunks_mut(bs) {
                    let mut fb = self.iv.clone();
                    let block: &mut GenericArray<u8, <$cipher as BlockSizeUser>::BlockSize> =
                        GenericArray::from_mut_slice(&mut fb);
                    self.cipher.encrypt_block(block);
                    for (d, e) in chunk.iter_mut().zip(fb.iter()) {
                        *d ^= *e;
                    }
                    self.iv.copy_from_slice(chunk);
                }
            }
        }
    };
}

// 16-byte block ciphers
make_cfb!(Aes128CfbImpl, aes::Aes128, 16);
make_cfb!(Aes192CfbImpl, aes::Aes192, 24);
make_cfb!(Aes256CfbImpl, aes::Aes256, 32);
make_cfb!(Camellia128CfbImpl, camellia::Camellia128, 16);
make_cfb!(Camellia192CfbImpl, camellia::Camellia192, 24);
make_cfb!(Camellia256CfbImpl, camellia::Camellia256, 32);
// seed-cfb: no pure Rust SEED cipher crate available

// 8-byte block ciphers
make_cfb!(BfCfbImpl, blowfish::Blowfish, 16);
make_cfb!(Cast5CfbImpl, cast5::Cast5, 16);
make_cfb!(DesCfbImpl, des::Des, 8);

// --- CTR mode ---

macro_rules! make_ctr {
    ($name:ident, $cipher:ty) => {
        struct $name { inner: ctr::Ctr128BE<$cipher> }
        impl $name {
            fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
                use cipher::KeyIvInit;
                let c = ctr::Ctr128BE::<$cipher>::new_from_slices(key, iv)
                    .map_err(|e| Error::Crypto(format!("{}: {}", stringify!($name), e)))?;
                Ok($name { inner: c })
            }
            fn apply_keystream(&mut self, data: &mut [u8]) {
                self.inner.apply_keystream(data);
            }
        }
    };
}

make_ctr!(Aes128CtrImpl, aes::Aes128);
make_ctr!(Aes192CtrImpl, aes::Aes192);
make_ctr!(Aes256CtrImpl, aes::Aes256);

// --- Stream cipher wrappers for salsa20, chacha20 ---

struct Salsa20Impl { inner: salsa20::Salsa20 }
impl Salsa20Impl {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        use cipher::KeyIvInit;
        let c = salsa20::Salsa20::new_from_slices(key, iv)
            .map_err(|e| Error::Crypto(format!("salsa20: {}", e)))?;
        Ok(Salsa20Impl { inner: c })
    }
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

// In chacha20 v0.9:
// ChaCha20     = IETF variant (12-byte nonce)
// ChaCha20Legacy = original variant (8-byte nonce)
struct ChaCha20Impl { inner: chacha20::ChaCha20Legacy }
impl ChaCha20Impl {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        use cipher::KeyIvInit;
        let c = chacha20::ChaCha20Legacy::new_from_slices(key, iv)
            .map_err(|e| Error::Crypto(format!("chacha20: {}", e)))?;
        Ok(ChaCha20Impl { inner: c })
    }
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

struct ChaCha20IetfImpl { inner: chacha20::ChaCha20 }
impl ChaCha20IetfImpl {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        use cipher::KeyIvInit;
        let c = chacha20::ChaCha20::new_from_slices(key, iv)
            .map_err(|e| Error::Crypto(format!("chacha20-ietf: {}", e)))?;
        Ok(ChaCha20IetfImpl { inner: c })
    }
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

// --- RC4-MD5 ---

fn rc4_md5_key(derived_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(derived_key.len() + iv.len());
    data.extend_from_slice(derived_key);
    data.extend_from_slice(iv);
    md5::Md5::digest(data).to_vec()
}

// --- StreamCipher (state machine) ---

pub struct StreamCipher {
    method: CipherMethod,
    enc_key: Vec<u8>,
    iv: Vec<u8>,
    initialized: bool,
    enc_table: Option<TableCipher>,
    rc4_cipher: Option<rc4::Rc4<typenum::U16>>,
    aes128_cfb: Option<Aes128CfbImpl>, aes192_cfb: Option<Aes192CfbImpl>, aes256_cfb: Option<Aes256CfbImpl>,
    camellia128_cfb: Option<Camellia128CfbImpl>, camellia192_cfb: Option<Camellia192CfbImpl>, camellia256_cfb: Option<Camellia256CfbImpl>,
    bf_cfb: Option<BfCfbImpl>, cast5_cfb: Option<Cast5CfbImpl>, des_cfb: Option<DesCfbImpl>,
    aes128_ctr: Option<Aes128CtrImpl>, aes192_ctr: Option<Aes192CtrImpl>, aes256_ctr: Option<Aes256CtrImpl>,
    salsa20: Option<Salsa20Impl>,
    chacha20: Option<ChaCha20Impl>,
    chacha20_ietf: Option<ChaCha20IetfImpl>,
}

impl StreamCipher {
    pub fn new(method: CipherMethod, key: Vec<u8>) -> Self {
        let iv_len = method.iv_len();
        StreamCipher {
            method, enc_key: key, iv: vec![0u8; iv_len],
            initialized: false, enc_table: None, rc4_cipher: None,
            aes128_cfb: None, aes192_cfb: None, aes256_cfb: None,
            camellia128_cfb: None, camellia192_cfb: None, camellia256_cfb: None,
            bf_cfb: None, cast5_cfb: None, des_cfb: None,
            aes128_ctr: None, aes192_ctr: None, aes256_ctr: None,
            salsa20: None, chacha20: None, chacha20_ietf: None,
        }
    }

    pub fn method(&self) -> CipherMethod { self.method }
    pub fn initialized(&self) -> bool { self.initialized }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self.method {
            CipherMethod::None => return Ok(data.to_vec()),
            CipherMethod::Table => {
                let mut out = data.to_vec();
                self.enc_table.get_or_insert_with(|| TableCipher::new(&self.enc_key));
                self.enc_table.as_ref().unwrap().encrypt(&mut out);
                return Ok(out);
            }
            _ => {}
        }
        if !self.initialized {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut self.iv);
            self.init()?;
            self.initialized = true;
            if self.method.need_iv_prepend() {
                let mut out = Vec::with_capacity(self.iv.len() + data.len());
                out.extend_from_slice(&self.iv);
                let mut enc = data.to_vec();
                self.apply(&mut enc)?;
                out.extend_from_slice(&enc);
                return Ok(out);
            }
        }
        let mut out = data.to_vec();
        self.apply(&mut out)?;
        Ok(out)
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self.method {
            CipherMethod::None => return Ok(data.to_vec()),
            CipherMethod::Table => {
                let mut out = data.to_vec();
                self.enc_table.get_or_insert_with(|| TableCipher::new(&self.enc_key));
                self.enc_table.as_ref().unwrap().decrypt(&mut out);
                return Ok(out);
            }
            _ => {}
        }
        if !self.initialized {
            let iv_len = self.iv.len();
            if self.method.need_iv_prepend() {
                if data.len() < iv_len { return Err(Error::Crypto("short iv".into())); }
                self.iv.copy_from_slice(&data[..iv_len]);
                self.init()?;
                self.initialized = true;
                let mut out = data[iv_len..].to_vec();
                self.apply(&mut out)?;
                return Ok(out);
            } else if self.method == CipherMethod::Rc4Md5 || self.method == CipherMethod::Rc4Md5_6 {
                if data.len() < iv_len { return Err(Error::Crypto("short iv".into())); }
                self.iv.copy_from_slice(&data[..iv_len]);
                let actual_key = rc4_md5_key(&self.enc_key, &self.iv);
                self.rc4_cipher = Some(
                    rc4::Rc4::<typenum::U16>::new_from_slice(&actual_key)
                        .map_err(|e| Error::Crypto(format!("rc4-md5: {}", e)))?,
                );
                self.initialized = true;
                let mut out = data[iv_len..].to_vec();
                self.rc4_cipher.as_mut().unwrap().apply_keystream(&mut out);
                return Ok(out);
            }
            self.init()?;
            self.initialized = true;
        }
        let mut out = data.to_vec();
        self.apply(&mut out)?;
        Ok(out)
    }

    fn init(&mut self) -> Result<()> {
        match self.method {
            CipherMethod::None | CipherMethod::Table => {}
            CipherMethod::Rc4 => {
                self.rc4_cipher = Some(
                    rc4::Rc4::<typenum::U16>::new_from_slice(&self.enc_key)
                        .map_err(|e| Error::Crypto(format!("rc4: {}", e)))?,
                );
            }
            CipherMethod::Rc4Md5 | CipherMethod::Rc4Md5_6 => {
                let actual_key = rc4_md5_key(&self.enc_key, &self.iv);
                self.rc4_cipher = Some(
                    rc4::Rc4::<typenum::U16>::new_from_slice(&actual_key)
                        .map_err(|e| Error::Crypto(format!("rc4-md5: {}", e)))?,
                );
            }
            CipherMethod::Aes128Cfb => self.aes128_cfb = Some(Aes128CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Aes192Cfb => self.aes192_cfb = Some(Aes192CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Aes256Cfb => self.aes256_cfb = Some(Aes256CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Camellia128Cfb => self.camellia128_cfb = Some(Camellia128CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Camellia192Cfb => self.camellia192_cfb = Some(Camellia192CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Camellia256Cfb => self.camellia256_cfb = Some(Camellia256CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::BfCfb => self.bf_cfb = Some(BfCfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Cast5Cfb => self.cast5_cfb = Some(Cast5CfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::DesCfb => self.des_cfb = Some(DesCfbImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Aes128Ctr => self.aes128_ctr = Some(Aes128CtrImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Aes192Ctr => self.aes192_ctr = Some(Aes192CtrImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Aes256Ctr => self.aes256_ctr = Some(Aes256CtrImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::Salsa20 => self.salsa20 = Some(Salsa20Impl::new(&self.enc_key, &self.iv)?),
            CipherMethod::ChaCha20 => self.chacha20 = Some(ChaCha20Impl::new(&self.enc_key, &self.iv)?),
            CipherMethod::ChaCha20Ietf => self.chacha20_ietf = Some(ChaCha20IetfImpl::new(&self.enc_key, &self.iv)?),
            CipherMethod::IdeaCfb | CipherMethod::Rc2Cfb | CipherMethod::SeedCfb => {
                return Err(Error::Crypto(format!("not impl: {}", self.method.name())));
            }
        }
        Ok(())
    }

    fn apply(&mut self, data: &mut [u8]) -> Result<()> {
        match self.method {
            CipherMethod::None | CipherMethod::Table => Ok(()),
            CipherMethod::IdeaCfb | CipherMethod::Rc2Cfb | CipherMethod::SeedCfb => {
                Err(Error::Crypto(format!("not impl: {}", self.method.name())))
            }
            CipherMethod::Rc4 | CipherMethod::Rc4Md5 | CipherMethod::Rc4Md5_6 => {
                self.rc4_cipher.as_mut().ok_or(Error::Crypto("rc4 uninit".into()))?.apply_keystream(data);
                Ok(())
            }
            CipherMethod::Aes128Cfb => { self.aes128_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Aes192Cfb => { self.aes192_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Aes256Cfb => { self.aes256_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Camellia128Cfb => { self.camellia128_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Camellia192Cfb => { self.camellia192_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Camellia256Cfb => { self.camellia256_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::BfCfb => { self.bf_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Cast5Cfb => { self.cast5_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::DesCfb => { self.des_cfb.as_mut().unwrap().process(data); Ok(()) }
            CipherMethod::Aes128Ctr => { self.aes128_ctr.as_mut().unwrap().apply_keystream(data); Ok(()) }
            CipherMethod::Aes192Ctr => { self.aes192_ctr.as_mut().unwrap().apply_keystream(data); Ok(()) }
            CipherMethod::Aes256Ctr => { self.aes256_ctr.as_mut().unwrap().apply_keystream(data); Ok(()) }
            CipherMethod::Salsa20 => { self.salsa20.as_mut().unwrap().apply_keystream(data); Ok(()) }
            CipherMethod::ChaCha20 => { self.chacha20.as_mut().unwrap().apply_keystream(data); Ok(()) }
            CipherMethod::ChaCha20Ietf => { self.chacha20_ietf.as_mut().unwrap().apply_keystream(data); Ok(()) }
        }
    }
}
