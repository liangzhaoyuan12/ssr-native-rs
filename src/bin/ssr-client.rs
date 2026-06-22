use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use clap::Parser;

use ssr_native_rs::config::SsrConfig;
use ssr_native_rs::protocol::TunnelCipherCtx;
use ssr_native_rs::socks5::{S5Parser, S5Result, S5AuthMethod, build_method_response, build_response, REP_SUCCESS};
use ssr_native_rs::tunnel::proxy_streams;

#[derive(Parser)]
#[command(name = "ssr-client", about = "ShadowsocksR-native client", disable_help_flag = true)]
struct Cli {
    #[arg(short = 'c', default_value = "config.json")]
    config: String,
    #[arg(short = 'd')]
    daemon: bool,
    #[arg(short = 'h', long = "help")]
    help: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    let config = SsrConfig::from_file(&cli.config)?;
    let client_cfg = config.client_settings.as_ref()
        .ok_or("client_settings required")?;

    let listen_addr = format!("{}:{}", client_cfg.listen_address, client_cfg.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    log::info!("SSR client listening on {}", listen_addr);

    let config = Arc::new(config);

    loop {
        let (incoming, peer_addr) = listener.accept().await?;
        log::info!("New connection from {}", peer_addr);
        let cfg = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(incoming, &cfg).await {
                log::error!("Client error: {}", e);
            }
        });
    }
}

async fn handle_client(mut incoming: TcpStream, config: &SsrConfig) -> Result<(), Box<dyn std::error::Error>> {
    let client_cfg = config.client_settings.as_ref().unwrap();

    // SOCKS5 handshake
    let mut parser = S5Parser::new();
    let mut buf = [0u8; 4096];
    let n = incoming.read(&mut buf).await?;
    let (result, _consumed) = parser.parse(&buf[..n]);

    match result {
        S5Result::AuthSelect => {
            if parser.has_method(S5AuthMethod::None) {
                parser.select_auth(S5AuthMethod::None);
                incoming.write_all(&build_method_response(0x00)).await?; // No auth
            } else {
                incoming.write_all(&build_method_response(0xFF)).await?; // No acceptable
                return Ok(());
            }
        }
        _ => {
            log::error!("SOCKS5 handshake failed: {:?}", result);
            return Ok(());
        }
    }

    // Read SOCKS5 request (CONNECT)
    let n = incoming.read(&mut buf).await?;
    let (result, _consumed) = parser.parse(&buf[..n]);

    match result {
        S5Result::ExecCmd => {
            if parser.cmd != 1 { // TCP CONNECT only
                incoming.write_all(&build_response(0x07)).await?; // Cmd not supported
                return Ok(());
            }
            let target_addr = parser.addr_str();
            let target_port = parser.dport;
            log::info!("Request: {}:{}", target_addr, target_port);

            // Send SOCKS5 success response
            incoming.write_all(&build_response(REP_SUCCESS)).await?;

            // Connect to SSR server
            let server_addr = format!("{}:{}", client_cfg.server, client_cfg.server_port);
            let mut remote = TcpStream::connect(&server_addr).await?;

            // Create SSR cipher pipeline
            let mut cipher_ctx = TunnelCipherCtx::new(config, false)?;

            // Build SSR payload: target address + port
            let mut payload = Vec::new();
            // ATYP + ADDR + PORT (SOCKS5 style)
            if target_addr.contains(':') {
                // IPv6
                let ip: std::net::Ipv6Addr = target_addr.parse()?;
                payload.push(0x04);
                payload.extend_from_slice(&ip.octets());
            } else if target_addr.parse::<std::net::Ipv4Addr>().is_ok() {
                let ip: std::net::Ipv4Addr = target_addr.parse()?;
                payload.push(0x01);
                payload.extend_from_slice(&ip.octets());
            } else {
                payload.push(0x03);
                payload.push(target_addr.len() as u8);
                payload.extend_from_slice(target_addr.as_bytes());
            }
            payload.extend_from_slice(&target_port.to_be_bytes());

            // Encrypt and send
            let encrypted = cipher_ctx.client_encrypt(&payload)?;
            remote.write_all(&encrypted).await?;

            // If there's more client data (first packet), send it too
            // Then proxy bidirectionally
            proxy_streams(incoming, remote).await?;
        }
        _ => {
            log::error!("SOCKS5 request failed: {:?}", result);
        }
    }

    Ok(())
}
