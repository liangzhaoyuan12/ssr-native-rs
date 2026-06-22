use sha1::Digest;

/// OpenSSL's EVP_BytesToKey with MD5, count=1
pub fn bytes_to_key(password: &[u8], key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut key = vec![0u8; key_len];
    let mut iv = vec![0u8; iv_len];
    let mut hash = Vec::new();
    let total = key_len + iv_len;
    let mut produced = 0;

    while produced < total {
        let mut hasher = md5::Md5::new();
        if !hash.is_empty() {
            hasher.update(&hash);
        }
        hasher.update(password);
        hash = hasher.finalize().to_vec();

        let copy_len = hash.len().min(total - produced);
        let dest = if produced < key_len {
            &mut key[produced..produced + copy_len]
        } else {
            &mut iv[produced - key_len..produced - key_len + copy_len]
        };
        dest.copy_from_slice(&hash[..copy_len]);
        produced += copy_len;
    }

    (key, iv)
}

/// AEAD key derivation (same iterative MD5 approach)
pub fn crypto_derive_key(password: &[u8], key_len: usize) -> Vec<u8> {
    bytes_to_key(password, key_len, 0).0
}
