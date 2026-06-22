pub const CIPHER_NAMES: &[&str] = &[
    "none", "table", "rc4", "rc4-md5", "rc4-md5-6",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
    "salsa20", "chacha20", "chacha20-ietf",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
];

pub const PROTOCOL_NAMES: &[&str] = &[
    "origin", "verify_simple", "auth_simple",
    "auth_sha1", "auth_sha1_v2", "auth_sha1_v4",
    "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b", "auth_chain_c",
    "auth_chain_d", "auth_chain_e", "auth_chain_f",
];

pub const OBFS_NAMES: &[&str] = &[
    "plain", "http_simple", "http_post", "http_mix",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth",
];
