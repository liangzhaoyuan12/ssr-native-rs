use hkdf::Hkdf;
use sha2::Sha256;

pub fn sha256_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}
