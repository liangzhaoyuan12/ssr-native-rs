pub fn encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn decode(data: &str) -> Result<Vec<u8>, crate::error::Error> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| crate::error::Error::Other(format!("base64 decode: {}", e)))
}

pub fn encode_urlsafe(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn decode_urlsafe(data: &str) -> Result<Vec<u8>, crate::error::Error> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| crate::error::Error::Other(format!("base64 urlsafe decode: {}", e)))
}
