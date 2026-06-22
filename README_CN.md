# ssr-native-rs

[ssr-n (ShadowsocksR-native)](https://github.com/ShadowsocksR-Live/shadowsocksr-native) 的纯 Rust 移植版。  
提供完整的 SOCKS5 代理客户端和 SSR 服务端。

## 特性

- **SOCKS5 代理** — 完整的 SOCKS5 协议支持 (CONNECT, UDP ASSOCIATE)
- **SSR 协议** — 14 种协议插件 (origin, auth_sha1_v4, auth_aes128_md5, auth_chain_a~f 等)
- **SSR 混淆** — 6 种混淆插件 (plain, http_simple, http_post, http_mix, tls1.2_ticket_auth, tls1.2_ticket_fastauth)
- **加密算法** — 28 种加密算法，包括流加密和 AEAD 加密
- **UDP 中继** — 完整的 UDP over TCP 中继支持
- **SSRoT** — ShadowsocksR over TLS (基于 WebSocket 的 HTTPS 隧道)
- **配置文件** — JSON 格式，与原始 ssr-n 完全兼容
- **纯 Rust 实现** — 无 C 语言依赖，无需 libuv/libsodium/mbedTLS 绑定，支持全平台交叉编译

## 编译

```bash
# 编译全部 (库 + 客户端 + 服务端)
cargo build --release

# 仅编译库
cargo build --release -p ssr-native-rs --lib

# 仅编译二进制
cargo build --release --bin ssr-client
cargo build --release --bin ssr-server
```

## 使用方法

### 客户端 (SOCKS5 代理)

```bash
ssr-client -c config.json
```

### 服务端

```bash
ssr-server -c config.json
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `-c <路径>` | 配置文件路径 (默认: `config.json`) |
| `-d` | 后台守护进程模式运行 |
| `-h` | 显示帮助信息 |

## 配置

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

### 支持的加密算法

| 类别 | 算法 |
|------|------|
| 无/表 | `none`, `table` |
| RC4 | `rc4`, `rc4-md5`, `rc4-md5-6` |
| AES | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr` |
| Camellia | `camellia-128-cfb`, `camellia-192-cfb`, `camellia-256-cfb` |
| 块加密 | `bf-cfb`, `cast5-cfb`, `des-cfb` |
| 流加密 | `salsa20`, `chacha20`, `chacha20-ietf` |
| AEAD | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` |

### 支持的协议

`origin`, `verify_simple`, `auth_simple`, `auth_sha1`, `auth_sha1_v2`, `auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a`, `auth_chain_b`, `auth_chain_c`, `auth_chain_d`, `auth_chain_e`, `auth_chain_f`

### 支持的混淆

`plain`, `http_simple`, `http_post`, `http_mix`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth`

## 作为库使用

在 `Cargo.toml` 中添加:

```toml
[dependencies]
ssr-native-rs = { git = "https://github.com/liangzhaoyuan12/ssr-native-rs" }
```

### 快速入门

```rust
use ssr_native_rs::config::SsrConfig;
use ssr_native_rs::protocol::TunnelCipherCtx;

// 从文件加载配置
let config = SsrConfig::from_file("config.json")?;

// 创建加密管线 (client_side = false, server_side = true)
let mut ctx = TunnelCipherCtx::new(&config, false)?;

// 加密数据 (protocol -> cipher -> obfs)
let encrypted = ctx.client_encrypt(b"socks5 address data")?;

// 解密数据 (obfs -> cipher -> protocol)
let decrypted = ctx.client_decrypt(&encrypted)?;
```

### API 概览

所有 20 个公共模块都通过 `lib.rs` 暴露。核心模块:

| 模块 | 说明 |
|------|------|
| `crypto` | 加密算法类型、密钥派生、算法名称查找 |
| `socks5` | SOCKS5 状态机 (`S5Parser`)、地址编解码 (`Socks5Addr`)、数据包构建函数 |
| `obfs` | 协议/混淆 trait 以及所有插件的实现 |
| `protocol` | `TunnelCipherCtx` — SSR 加密/解密管线 |
| `config` | `SsrConfig` — JSON 配置解析 |
| `tunnel` | TCP 代理辅助函数 (`proxy_streams`, `write_all`, `read_exact`) |
| `dns` | DNS 解析缓存 |
| `websocket` | WebSocket 帧编解码 |
| `tls` | 基于 `rustls` 的 TLS 连接器 |
| `qr_code` | SSR URI 链接编解码 (ssr:// 格式) |

### TunnelCipherCtx — SSR 加密管线

`TunnelCipherCtx` 是核心管线，串联了 **protocol → cipher → obfs** 三个阶段:

```rust
// 创建上下文 (客户端)
let mut ctx = TunnelCipherCtx::new(&config, false)?;

// 客户端加密: protocol.client_pre_encrypt() → cipher.encrypt() → obfs.client_encode()
let encrypted = ctx.client_encrypt(&plain_data)?;

// 客户端解密: obfs.client_decode() → cipher.decrypt() → protocol.client_post_decrypt()
let decrypted = ctx.client_decrypt(&encrypted)?;

// 服务端加密: protocol.server_pre_encrypt() → cipher.encrypt() → obfs.server_encode()
let server_encrypted = ctx.server_encrypt(&plain_data)?;

// 服务端解密: obfs.server_decode() → cipher.decrypt() → protocol.server_post_decrypt()
let server_decrypted = ctx.server_decrypt(&encrypted)?;
```

### 底层 Crypto API

```rust
use ssr_native_rs::crypto::SsrCipher;

// 从方法名和密码创建密码器
let mut cipher = SsrCipher::new("aes-256-cfb", "my_password")?;

// 加密/解密 (首次调用自动处理 IV 前置/剥离)
let ct = cipher.encrypt(b"hello world")?;
let pt = cipher.decrypt(&ct)?;

// AEAD UDP 模式 (每个数据包独立实例)
let udp_cipher = SsrCipher::new_udp("aes-128-gcm", "my_password")?;
let packet = udp_cipher.encrypt(b"udp data")?;
let data = udp_cipher.decrypt(&packet)?;
```

### SOCKS5 状态机

```rust
use ssr_native_rs::socks5::{S5Parser, S5Result, S5AuthMethod, build_method_response, build_response, REP_SUCCESS};

let mut parser = S5Parser::new();
let (result, consumed) = parser.parse(&client_data);

match result {
    S5Result::AuthSelect => {
        if parser.has_method(S5AuthMethod::None) {
            parser.select_auth(S5AuthMethod::None);
            // 发送响应: [0x05, 0x00]
        }
    }
    S5Result::ExecCmd => {
        let target = parser.addr_str();  // "example.com" 或 "1.2.3.4"
        let port = parser.dport;          // 80
        // 转发连接...
    }
    _ => {}
}
```

### SOCKS5 地址编解码

```rust
use ssr_native_rs::socks5::Socks5Addr;

// 从线格式解析
let (addr, used) = Socks5Addr::parse(&bytes)?;

// 编码为线格式
let addr = Socks5Addr::from_host_port("example.com", 80);
let wire = addr.encode();  // [0x03, 11, 'e','x','a','m','p','l','e',...]

// 属性
println!("{}", addr.to_string());            // "example.com:80"
println!("is_domain: {}", addr.is_domain());  // true
```

### 配置构建器

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

## 项目结构

```
src/
├── lib.rs              # 公共 API (20 个 pub mod)
├── bin/
│   ├── ssr-client.rs   # SOCKS5 代理客户端
│   └── ssr-server.rs   # SSR 服务端
├── crypto/             # 28 种加密算法实现
├── socks5/             # SOCKS5 状态机 + 地址编解码 + 数据包构建
├── obfs/               # 混淆框架: 14 种协议 + 6 种混淆
├── protocol/           # SSR Executive 管线
├── config.rs           # JSON 配置解析器
├── tunnel.rs           # TCP 双向代理
└── ...                 # dns, cache, ppbloom, websocket, tls, qr_code, utils 等
```

## 依赖 (全部纯 Rust)

- **运行时**: `tokio`
- **TLS**: `rustls` + `tokio-rustls`
- **配置**: `serde` + `serde_json`
- **加密**: `aes`, `aes-gcm`, `chacha20`, `chacha20poly1305`, `salsa20`, `rc4`, `camellia`, `blowfish`, `cast5`, `des`, `md-5`, `sha-1`, `sha2`, `hmac`, `hkdf`
- **其它**: `clap`, `log`/`env_logger`, `httparse`, `bloomfilter`, `percent-encoding`

## 与原始 ssr-n (C 版) 的差异

- **纯 Rust 实现**: 无 C 依赖，无外部库绑定，可交叉编译到任何 rustc 支持的架构
- **异步运行时**: 使用 `tokio` 替代 `libuv`
- **TLS**: 使用 `rustls` (纯 Rust) 替代 `mbedTLS`
- **加密**: 使用 RustCrypto 系列 crate 替代 `libsodium` + `mbedTLS`
- **API**: 提供 `lib.rs` 公共接口，可作为 crate 依赖使用

## 许可协议

GPL-3.0-only
