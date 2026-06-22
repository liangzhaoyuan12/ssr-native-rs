use hmac::{Hmac, Mac};
use sha1::Sha1 as Sha1Hash;
use sha1::Digest;
use crate::crc32::{crc32, adler32};

type HmacSha1 = Hmac<Sha1Hash>;

/// HMAC-SHA1 with key only
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SSR HMAC: HMAC-SHA1 with IV and key
pub fn ss_sha1_hmac(plain: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(plain);
    if !iv.is_empty() {
        mac.update(iv);
    }
    mac.finalize().into_bytes().to_vec()
}

/// SS HMAC with separate iv and key
pub fn ss_sha1_hmac_full(plain: &[u8], plen: usize, iv: &[u8], iv_len: usize, key: &[u8], key_len: usize) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(&key[..key_len]).expect("HMAC key");
    mac.update(&plain[..plen]);
    if iv_len > 0 {
        mac.update(&iv[..iv_len]);
    }
    mac.finalize().into_bytes().to_vec()
}

pub fn ss_md5_hmac_with_key(msg: &[u8], key: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac = Hmac::<md5::Md5>::new_from_slice(key).expect("HMAC-MD5");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn ss_sha1_hmac_with_key(msg: &[u8], key: &[u8]) -> Vec<u8> {
    hmac_sha1(key, msg)
}

pub fn ss_md5_hash_func(data: &[u8]) -> Vec<u8> {
    md5::Md5::digest(data).to_vec()
}

pub fn ss_sha1_hash_func(data: &[u8]) -> Vec<u8> {
    Sha1Hash::digest(data).to_vec()
}

pub fn xorshift128plus(seed: &mut u64) -> u64 {
    let mut x = *seed;
    let y = x;
    x ^= x << 23;
    let t = x ^ y ^ (x >> 17) ^ (y >> 26);
    *seed = t;
    t.wrapping_add(y)
}

pub fn get_s5_head_size(data: &[u8]) -> usize {
    if data.len() < 2 {
        return 0;
    }
    let addr_type = data[0];
    match addr_type {
        1 => 7,      // IPv4: type(1) + ip(4) + port(2)
        3 => {       // Domain
            if data.len() < 2 {
                return 0;
            }
            4 + data[1] as usize
        }
        4 => 19,     // IPv6: type(1) + ip(16) + port(2)
        _ => 0,
    }
}

pub fn rand_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn memintcopy_lt(data: &mut [u8], val: u32) {
    data[0] = (val & 0xFF) as u8;
    data[1] = ((val >> 8) & 0xFF) as u8;
    data[2] = ((val >> 16) & 0xFF) as u8;
    data[3] = ((val >> 24) & 0xFF) as u8;
}

pub fn fillcrc32(data: &mut [u8], len: usize) {
    let crc = crc32(&data[..len - 4]);
    data[len - 4] = (crc & 0xFF) as u8;
    data[len - 3] = ((crc >> 8) & 0xFF) as u8;
    data[len - 2] = ((crc >> 16) & 0xFF) as u8;
    data[len - 1] = ((crc >> 24) & 0xFF) as u8;
}

pub fn fillcrc32to(data: &[u8], data_len: usize, output: &mut [u8]) {
    let crc = crc32(&data[..data_len]);
    output[0] = (crc & 0xFF) as u8;
    output[1] = ((crc >> 8) & 0xFF) as u8;
}

pub fn checkcrc32(data: &[u8], len: usize) -> bool {
    if len < 4 { return false; }
    let crc = crc32(&data[..len - 4]);
    let expected = u32::from_le_bytes([data[len-4], data[len-3], data[len-2], data[len-1]]);
    crc == expected
}

pub fn filladler32(data: &mut [u8], len: usize) {
    let a = adler32(&data[..len - 4]);
    data[len - 4] = (a & 0xFF) as u8;
    data[len - 3] = ((a >> 8) & 0xFF) as u8;
    data[len - 2] = ((a >> 16) & 0xFF) as u8;
    data[len - 1] = ((a >> 24) & 0xFF) as u8;
}

pub fn checkadler32(data: &[u8], len: usize) -> bool {
    if len < 4 { return false; }
    let a = adler32(&data[..len - 4]);
    let expected = u32::from_le_bytes([data[len-4], data[len-3], data[len-2], data[len-1]]);
    a == expected
}
