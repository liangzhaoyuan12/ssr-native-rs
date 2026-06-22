use crate::error::{Error, Result};
use crate::crc32::crc32;
use super::obfs::{Protocol, ServerInfo};
use super::obfsutil::*;

const OBFS_HMAC_SHA1_LEN: usize = 10;

// --- Global data for auth protocols ---
pub struct AuthGlobalData {
    pub local_client_id: [u8; 8],
    pub connection_id: u32,
}

impl AuthGlobalData {
    pub fn new() -> Self {
        let mut id = [0u8; 8];
        let mut conn = [0u8; 4];
        let r = rand_bytes(8);
        id.copy_from_slice(&r);
        let r2 = rand_bytes(4);
        conn.copy_from_slice(&r2);
        AuthGlobalData {
            local_client_id: id,
            connection_id: u32::from_le_bytes(conn) & 0xFFFFFF,
        }
    }
}

fn random_padding_len(data_len: usize) -> usize {
    let r = if data_len > 1300 {
        0usize
    } else if data_len > 400 {
        ((xorshift128plus(&mut 0)) & 0x7F) as usize
    } else {
        ((xorshift128plus(&mut 0)) & 0x3FF) as usize
    };
    r + 1
}

#[allow(unused)]
fn random_padding_len_aes(_data_len: usize) -> usize {
    ((xorshift128plus(&mut 0)) & 0xF) as usize + 1
}

// ============================================================
//  AuthSHA1v4 Protocol
// ============================================================

pub struct AuthSha1V4 {
    server_info: ServerInfo,
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buffer: Vec<u8>,
    pack_unit_size: usize,
    extra_wait_size: usize,
    max_time_diff: i32,
}

impl AuthSha1V4 {
    pub fn new() -> Self {
        let extra = rand_bytes(2);
        let extra_size = (u16::from_le_bytes([extra[0], extra[1]]) % 1024) as usize;
        AuthSha1V4 {
            server_info: ServerInfo::default(),
            has_sent_header: false,
            has_recv_header: false,
            recv_buffer: Vec::new(),
            pack_unit_size: 2000,
            extra_wait_size: extra_size,
            max_time_diff: 86400,
        }
    }

}

impl Protocol for AuthSha1V4 {
    fn name(&self) -> &str { "auth_sha1_v4" }

    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() * 2 + 4096);
        let mut remaining = data;
        let first = !self.has_sent_header;

        if first && !remaining.is_empty() {
            let head_size = get_s5_head_size(remaining);
            let hs = head_size.min(remaining.len());
            let auth_pkt = auth_sha1_v4_pack_auth_data(&remaining[..hs], &self.server_info);
            out.extend_from_slice(&auth_pkt);
            remaining = &remaining[hs..];
            self.has_sent_header = true;
        }

        while !remaining.is_empty() {
            let chunk = &remaining[..remaining.len().min(self.pack_unit_size)];
            remaining = &remaining[chunk.len()..];
            let pkt = auth_sha1_v4_pack_data(chunk);
            out.extend_from_slice(&pkt);
        }

        Ok(out)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.recv_buffer.extend_from_slice(data);
        let mut out = Vec::new();

        loop {
            if self.recv_buffer.len() <= 4 {
                break;
            }

            // Check CRC of first 2 bytes
            let crc_calc = crc32(&self.recv_buffer[..2]);
            let crc_pkt = u16::from_le_bytes([self.recv_buffer[2], self.recv_buffer[3]]);
            if (crc_calc as u16) != crc_pkt {
                self.recv_buffer.clear();
                return Err(Error::Obfs("auth_sha1_v4 crc mismatch".into()));
            }

            let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if length >= 8192 || length < 7 {
                self.recv_buffer.clear();
                return Err(Error::Obfs("auth_sha1_v4 bad length".into()));
            }

            if length > self.recv_buffer.len() {
                break; // need more data
            }

            if !checkadler32(&self.recv_buffer[..length], length) {
                self.recv_buffer.clear();
                return Err(Error::Obfs("auth_sha1_v4 adler32 mismatch".into()));
            }

            let pos = self.recv_buffer[4] as usize;
            if pos < 255 {
                let data_start = pos + 4;
                let data_size = length - data_start - 4;
                if data_start + data_size <= length {
                    out.extend_from_slice(&self.recv_buffer[data_start..data_start + data_size]);
                }
            } else {
                let pos2 = u16::from_be_bytes([self.recv_buffer[5], self.recv_buffer[6]]) as usize;
                let data_start = pos2 + 4;
                let data_size = length - data_start - 4;
                if data_start + data_size <= length {
                    out.extend_from_slice(&self.recv_buffer[data_start..data_start + data_size]);
                }
            }

            self.recv_buffer.drain(..length);
        }

        Ok(out)
    }

    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut remaining = data;

        while remaining.len() > self.pack_unit_size {
            let pkt = auth_sha1_v4_pack_data(&remaining[..self.pack_unit_size]);
            out.extend_from_slice(&pkt);
            remaining = &remaining[self.pack_unit_size..];
        }
        if !remaining.is_empty() {
            let pkt = auth_sha1_v4_pack_data(remaining);
            out.extend_from_slice(&pkt);
        }

        Ok(out)
    }

    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let need_wait = self.extra_wait_size;
        if !self.has_recv_header {
            self.recv_buffer.extend_from_slice(data);
            if self.recv_buffer.len() < 12 && self.recv_buffer.len() < need_wait {
                return Ok(Vec::new());
            }

            // Verify auth header
            let header_len = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if header_len > self.recv_buffer.len() {
                return Ok(Vec::new());
            }

            // Verify HMAC
            let hmac = ss_sha1_hmac_full(
                &self.recv_buffer,
                header_len - OBFS_HMAC_SHA1_LEN,
                &self.server_info.recv_iv,
                self.server_info.recv_iv.len(),
                &self.server_info.key,
                self.server_info.key.len(),
            );

            if hmac.len() < OBFS_HMAC_SHA1_LEN || &hmac[..OBFS_HMAC_SHA1_LEN] != &self.recv_buffer[header_len - OBFS_HMAC_SHA1_LEN..header_len] {
                return Err(Error::Obfs("auth_sha1_v4 hmac mismatch".into()));
            }

            // Extract position
            let pos = self.recv_buffer[6] as usize;
            let data_start = if pos < 255 {
                pos + 6
            } else {
                (u16::from_be_bytes([self.recv_buffer[7], self.recv_buffer[8]]) as usize) + 6
            };

            let data_size = header_len - OBFS_HMAC_SHA1_LEN - data_start;
            if data_start + data_size > header_len {
                return Err(Error::Obfs("auth_sha1_v4 bad auth packet".into()));
            }

            let mut out = self.recv_buffer[data_start..data_start + data_size].to_vec();
            if out.len() < 12 {
                return Err(Error::Obfs("auth_sha1_v4 short auth data".into()));
            }

            // Verify timestamp
            let utc_time = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            let time_diff = (now as i32 - utc_time as i32).abs();
            if time_diff > self.max_time_diff {
                return Err(Error::Obfs("auth_sha1_v4 wrong timestamp".into()));
            }

            // Remove timestamp / client_id / connection_id from output
            out.drain(..12);
            self.has_recv_header = true;

            // Process remaining data in buffer
            self.recv_buffer.drain(..header_len);

            // Continue processing remaining chunks
            let mut remaining_out = Vec::new();
            loop {
                if self.recv_buffer.len() <= 4 {
                    break;
                }
                let crc_calc = crc32(&self.recv_buffer[..2]);
                let crc_pkt = u16::from_le_bytes([self.recv_buffer[2], self.recv_buffer[3]]);
                if (crc_calc as u16) != crc_pkt {
                    self.recv_buffer.clear();
                    break;
                }
                let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
                if length >= 8192 || length < 7 || length > self.recv_buffer.len() {
                    break;
                }
                if !checkadler32(&self.recv_buffer[..length], length) {
                    self.recv_buffer.clear();
                    break;
                }
                let pos = self.recv_buffer[4] as usize;
                let data_start = if pos < 255 { pos + 4 } else { (u16::from_be_bytes([self.recv_buffer[5], self.recv_buffer[6]]) as usize) + 4 };
                let data_size = length - data_start - 4;
                if data_start + data_size <= length {
                    remaining_out.extend_from_slice(&self.recv_buffer[data_start..data_start + data_size]);
                }
                self.recv_buffer.drain(..length);
            }

            out.extend_from_slice(&remaining_out);
            Ok(out)
        } else {
            // Already have header, just process data packets
            self.recv_buffer.extend_from_slice(data);
            let mut out = Vec::new();
            loop {
                if self.recv_buffer.len() <= 4 {
                    break;
                }
                let crc_calc = crc32(&self.recv_buffer[..2]);
                let crc_pkt = u16::from_le_bytes([self.recv_buffer[2], self.recv_buffer[3]]);
                if (crc_calc as u16) != crc_pkt {
                    self.recv_buffer.clear();
                    return Err(Error::Obfs("auth_sha1_v4 crc mismatch".into()));
                }
                let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
                if length >= 8192 || length < 7 || length > self.recv_buffer.len() {
                    break;
                }
                if !checkadler32(&self.recv_buffer[..length], length) {
                    self.recv_buffer.clear();
                    return Err(Error::Obfs("auth_sha1_v4 adler32 mismatch".into()));
                }
                let pos = self.recv_buffer[4] as usize;
                let data_start = if pos < 255 { pos + 4 } else { (u16::from_be_bytes([self.recv_buffer[5], self.recv_buffer[6]]) as usize) + 4 };
                let data_size = length - data_start - 4;
                if data_start + data_size <= length {
                    out.extend_from_slice(&self.recv_buffer[data_start..data_start + data_size]);
                }
                self.recv_buffer.drain(..length);
            }
            Ok(out)
        }
    }

    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) { self.recv_buffer.clear(); }
}

// ---- Packet functions ----

fn auth_sha1_v4_pack_data(data: &[u8]) -> Vec<u8> {
    let rlen = random_padding_len(data.len());
    let out_size = rlen + data.len() + 8;
    let mut out = vec![0u8; out_size];

    out[0] = (out_size >> 8) as u8;
    out[1] = (out_size & 0xFF) as u8;

    let crc_val = crc32(&out[..2]);
    out[2] = (crc_val & 0xFF) as u8;
    out[3] = ((crc_val >> 8) & 0xFF) as u8;

    if rlen < 128 {
        out[4] = rlen as u8;
        out[5..5 + data.len()].copy_from_slice(data);
    } else {
        out[4] = 0xFF;
        out[5] = ((rlen >> 8) & 0xFF) as u8;
        out[6] = (rlen & 0xFF) as u8;
        out[7..7 + data.len()].copy_from_slice(data);
    }

    let olen = out.len();
    filladler32(&mut out, olen);
    out
}

fn auth_sha1_v4_pack_auth_data(data: &[u8], server: &ServerInfo) -> Vec<u8> {
    let rlen = random_padding_len(data.len());
    let data_offset = rlen + 4 + 2;
    let out_size = data_offset + data.len() + 12 + OBFS_HMAC_SHA1_LEN;
    let mut out = vec![0u8; out_size];

    out[0] = (out_size >> 8) as u8;
    out[1] = (out_size & 0xFF) as u8;

    // CRC = CRC32(out[0:2] + "auth_sha1_v4" + key)
    let salt = b"auth_sha1_v4";
    let mut crc_data = Vec::with_capacity(2 + salt.len() + server.key.len());
    crc_data.extend_from_slice(&out[..2]);
    crc_data.extend_from_slice(salt);
    crc_data.extend_from_slice(&server.key);
    fillcrc32to(&crc_data, crc_data.len(), &mut out[2..]);

    if rlen < 128 {
        out[6] = rlen as u8;
    } else {
        out[6] = 0xFF;
        out[7] = ((rlen >> 8) & 0xFF) as u8;
        out[8] = (rlen & 0xFF) as u8;
    }

    // Timestamp (4 bytes LE)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    memintcopy_lt(&mut out[data_offset..], now);

    // local_client_id (4 bytes)
    let rnd = rand_bytes(4);
    out[data_offset + 4..data_offset + 8].copy_from_slice(&rnd);

    // connection_id (4 bytes LE)
    let conn_id = rand::random::<u32>() & 0xFFFFFF;
    memintcopy_lt(&mut out[data_offset + 8..], conn_id);

    // Data
    out[data_offset + 12..data_offset + 12 + data.len()].copy_from_slice(data);

    // HMAC-SHA1
    let hmac = ss_sha1_hmac_full(
        &out, out_size - OBFS_HMAC_SHA1_LEN,
        &server.recv_iv, server.recv_iv.len(),
        &server.key, server.key.len(),
    );
    let hmac_start = out_size - OBFS_HMAC_SHA1_LEN;
    out[hmac_start..hmac_start + OBFS_HMAC_SHA1_LEN.min(hmac.len())]
        .copy_from_slice(&hmac[..OBFS_HMAC_SHA1_LEN.min(hmac.len())]);

    out
}

// ---- Other protocol stubs (unchanged from pass-through) ----

pub struct Origin {
    server_info: ServerInfo,
}

impl Origin {
    pub fn new() -> Self { Origin { server_info: ServerInfo::default() } }
}

impl Protocol for Origin {
    fn name(&self) -> &str { "origin" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

pub struct AuthAes128Md5 {
    server_info: ServerInfo,
}

impl AuthAes128Md5 {
    pub fn new() -> Self { AuthAes128Md5 { server_info: ServerInfo::default() } }
}

impl Protocol for AuthAes128Md5 {
    fn name(&self) -> &str { "auth_aes128_md5" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

pub struct AuthAes128Sha1 {
    server_info: ServerInfo,
}

impl AuthAes128Sha1 {
    pub fn new() -> Self { AuthAes128Sha1 { server_info: ServerInfo::default() } }
}

impl Protocol for AuthAes128Sha1 {
    fn name(&self) -> &str { "auth_aes128_sha1" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

pub struct VerifySimple {
    server_info: ServerInfo,
}

impl VerifySimple {
    pub fn new() -> Self { VerifySimple { server_info: ServerInfo::default() } }
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

pub struct AuthSimple {
    server_info: ServerInfo,
}

impl AuthSimple {
    pub fn new() -> Self { AuthSimple { server_info: ServerInfo::default() } }
}

impl Protocol for AuthSimple {
    fn name(&self) -> &str { "auth_simple" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

pub struct AuthSha1 {
    server_info: ServerInfo,
}

impl AuthSha1 {
    pub fn new() -> Self { AuthSha1 { server_info: ServerInfo::default() } }
}

impl Protocol for AuthSha1 {
    fn name(&self) -> &str { "auth_sha1" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}

pub struct AuthSha1V2 {
    server_info: ServerInfo,
}

impl AuthSha1V2 {
    pub fn new() -> Self { AuthSha1V2 { server_info: ServerInfo::default() } }
}

impl Protocol for AuthSha1V2 {
    fn name(&self) -> &str { "auth_sha1_v2" }
    fn client_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn client_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_pre_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn server_post_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    fn set_server_info(&mut self, info: ServerInfo) { self.server_info = info; }
    fn get_server_info(&self) -> &ServerInfo { &self.server_info }
    fn dispose(&mut self) {}
}
