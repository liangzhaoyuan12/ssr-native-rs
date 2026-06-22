# ssr-native-rs

A pure Rust port of [ssr-n (ShadowsocksR-native)](https://github.com/ShadowsocksR-Live/shadowsocksr-native).  
Provides a SOCKS5 proxy client and SSR server with full feature parity.

## Features

- **SOCKS5 Proxy** — Full SOCKS5 protocol (CONNECT, UDP ASSOCIATE)
- **SSR Protocols** — 14 protocol plugins (origin, auth_sha1_v4, auth_aes128_md5, auth_chain_a~f, etc.)
- **SSR Obfuscators** — 6 obfuscation plugins (plain, http_simple, http_post, http_mix, tls1.2_ticket_auth, tls1.2_ticket_fastauth)
- **Encryption** — 28 ciphers including stream ciphers and AEAD ciphers
- **UDP Relay** — Full UDP over TCP relay support
- **SSRoT** — ShadowsocksR over TLS (WebSocket tunneling over HTTPS)
- **Configuration** — JSON config file, same format as original ssr-n
- **Pure Rust** — No C dependencies, no libuv/libsodium/mbedTLS bindings. Fully cross-compilable

## Build

```bash
# Build everything (lib + client + server)
cargo build --release

# Build library only
cargo build --release -p ssr-native-rs --lib

# Build binary only
cargo build --release --bin ssr-client
cargo build --release --bin ssr-server
```

## Usage

### Client (SOCKS5 proxy)

```bash
ssr-client -c config.json
```

### Server

```bash
ssr-server -c config.json
```

### Options

| Flag | Description |
|------|-------------|
| `-c <path>` | Config file path (default: `config.json`) |
| `-d` | Run as daemon |
| `-h` | Show help |

## Configuration

```json
{
    "password": "your-password",
    "method": "aes-256-cfb",
    "protocol": "auth_aes128_md5",
    "protocol_param": "",
    "obfs": "tls1.2_ticket_auth",
    "obfs_param": "",
    "udp": false,
    "idle_timeout": 300,
    "connect_timeout": 6,
    "udp_timeout": 6,

    "server_settings": {
        "listen_address": "0.0.0.0",
        "listen_port": 12475
    },

    "client_settings": {
        "server": "your-server.com",
        "server_port": 12475,
        "listen_address": "127.0.0.1",
        "listen_port": 1080
    },

    "over_tls_settings": {
        "enable": false,
        "server_domain": "goodsitesample.com",
        "path": "/udg151df/",
        "root_cert_file": ""
    }
}
```

### Supported Ciphers

| Category | Ciphers |
|----------|---------|
| None/Table | `none`, `table` |
| RC4 | `rc4`, `rc4-md5`, `rc4-md5-6` |
| AES | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr` |
| Camellia | `camellia-128-cfb`, `camellia-192-cfb`, `camellia-256-cfb` |
| Block ciphers | `bf-cfb`, `cast5-cfb`, `des-cfb` |
| Stream | `salsa20`, `chacha20`, `chacha20-ietf` |
| AEAD | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` |

### Supported Protocols

`origin`, `verify_simple`, `auth_simple`, `auth_sha1`, `auth_sha1_v2`, `auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a`, `auth_chain_b`, `auth_chain_c`, `auth_chain_d`, `auth_chain_e`, `auth_chain_f`

### Supported Obfuscations

`plain`, `http_simple`, `http_post`, `http_mix`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth`

## Use as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
ssr-native-rs = { git = "https://github.com/liangzhaoyuan12/ssr-native-rs" }
```

### Quick Start

```rust
use ssr_native_rs::config::SsrConfig;
use ssr_native_rs::protocol::TunnelCipherCtx;

// Load config from file
let config = SsrConfig::from_file("config.json")?;

// Create cipher pipeline (client_side = false, server_side = true)
let mut ctx = TunnelCipherCtx::new(&config, false)?;

// Encrypt data (protocol -> cipher -> obfs)
let encrypted = ctx.client_encrypt(b"socks5 address data")?;

// Decrypt data (obfs -> cipher -> protocol)
let decrypted = ctx.client_decrypt(&encrypted)?;
```

### API Overview

All 20 public modules are exposed through `lib.rs`. Key modules:

| Module | Description |
|--------|-------------|
| `crypto` | Cipher types, key derivation, cipher name lookup |
| `socks5` | SOCKS5 state machine (`S5Parser`), address codec (`Socks5Addr`), packet builders |
| `obfs` | Protocol/obfuscation traits and all plugin implementations |
| `protocol` | `TunnelCipherCtx` — the SSR encrypt/decrypt pipeline |
| `config` | `SsrConfig` — JSON config parser |
| `tunnel` | TCP proxy helpers (`proxy_streams`, `write_all`, `read_exact`) |
| `dns` | DNS resolver cache |
| `websocket` | WebSocket frame encode/decode |
| `tls` | `rustls`-based TLS connector |
| `qr_code` | SSR URI scheme encode/decode (ssr:// links) |

### TunnelCipherCtx — The SSR Pipeline

`TunnelCipherCtx` is the core pipeline that chains **protocol → cipher → obfs**:

```rust
// Create context (client side)
let mut ctx = TunnelCipherCtx::new(&config, false)?;

// Client encrypt: protocol.client_pre_encrypt() → cipher.encrypt() → obfs.client_encode()
let encrypted = ctx.client_encrypt(&plain_data)?;

// Client decrypt: obfs.client_decode() → cipher.decrypt() → protocol.client_post_decrypt()
let decrypted = ctx.client_decrypt(&encrypted)?;

// Server encrypt: protocol.server_pre_encrypt() → cipher.encrypt() → obfs.server_encode()
let server_encrypted = ctx.server_encrypt(&plain_data)?;

// Server decrypt: obfs.server_decode() → cipher.decrypt() → protocol.server_post_decrypt()
let server_decrypted = ctx.server_decrypt(&encrypted)?;
```

### Low-level Crypto API

```rust
use ssr_native_rs::crypto::SsrCipher;

// Create a cipher from method name and password
let mut cipher = SsrCipher::new("aes-256-cfb", "my_password")?;

// Encrypt/decrypt (auto-handles IV prepend/strip on first call)
let ct = cipher.encrypt(b"hello world")?;
let pt = cipher.decrypt(&ct)?;

// AEAD UDP mode (separate instance per packet)
let udp_cipher = SsrCipher::new_udp("aes-128-gcm", "my_password")?;
let packet = udp_cipher.encrypt(b"udp data")?;
let data = udp_cipher.decrypt(&packet)?;
```

### SOCKS5 State Machine

```rust
use ssr_native_rs::socks5::{S5Parser, S5Result, S5AuthMethod, build_method_response, build_response, REP_SUCCESS};

let mut parser = S5Parser::new();
let (result, consumed) = parser.parse(&client_data);

match result {
    S5Result::AuthSelect => {
        if parser.has_method(S5AuthMethod::None) {
            parser.select_auth(S5AuthMethod::None);
            // Send response: [0x05, 0x00]
        }
    }
    S5Result::ExecCmd => {
        let target = parser.addr_str();  // "example.com" or "1.2.3.4"
        let port = parser.dport;          // 80
        // Forward connection...
    }
    _ => {}
}
```

### SOCKS5 Address Codec

```rust
use ssr_native_rs::socks5::Socks5Addr;

// Parse from wire format
let (addr, used) = Socks5Addr::parse(&bytes)?;

// Encode to wire format
let addr = Socks5Addr::from_host_port("example.com", 80);
let wire = addr.encode();  // [0x03, 11, 'e','x','a','m','p','l','e',...]

// Inspect
println!("{}", addr.to_string());           // "example.com:80"
println!("is_domain: {}", addr.is_domain());  // true
```

### Config Builder

```rust
use ssr_native_rs::config::{SsrConfig, ClientSettings};

let config = SsrConfig {
    password: "my_pass".into(),
    method: "aes-256-cfb".into(),
    protocol: "auth_aes128_md5".into(),
    protocol_param: String::new(),
    obfs: "tls1.2_ticket_auth".into(),
    obfs_param: String::new(),
    udp: false,
    idle_timeout: 300,
    connect_timeout: 6,
    udp_timeout: 6,
    server_settings: None,
    client_settings: Some(ClientSettings {
        server: "your-server.com".into(),
        server_port: 12475,
        listen_address: "127.0.0.1".into(),
        listen_port: 1080,
    }),
    over_tls_settings: None,
};
```

## Architecture

```
src/
├── lib.rs              # Public API (20 pub mods)
├── bin/
│   ├── ssr-client.rs   # SOCKS5 proxy client
│   └── ssr-server.rs   # SSR server
├── crypto/             # 28 cipher implementations
├── socks5/             # SOCKS5 state machine + address codec + packet builder
├── obfs/               # Obfuscation framework: 14 protocols + 6 obfuscators
├── protocol/           # SSR Executive pipeline
├── config.rs           # JSON config parser
├── tunnel.rs           # TCP bidirectional proxy
└── ...                 # dns, cache, ppbloom, websocket, tls, qr_code, utils
```

## Dependencies (all pure Rust)

- **Runtime**: `tokio`
- **TLS**: `rustls` + `tokio-rustls`
- **Config**: `serde` + `serde_json`
- **Crypto**: `aes`, `aes-gcm`, `chacha20`, `chacha20poly1305`, `salsa20`, `rc4`, `camellia`, `blowfish`, `cast5`, `des`, `md-5`, `sha-1`, `sha2`, `hmac`, `hkdf`
- **Other**: `clap`, `log`/`env_logger`, `httparse`, `bloomfilter`, `percent-encoding`

## License

GPL-3.0-only
