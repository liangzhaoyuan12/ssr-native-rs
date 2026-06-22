use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use clap::Parser;

use ssr_native_rs::config::SsrConfig;
use ssr_native_rs::protocol::TunnelCipherCtx;
use ssr_native_rs::socks5::Socks5Addr;
use ssr_native_rs::tunnel::proxy_streams;

#[derive(Parser)]
#[command(name = "ssr-server", about = "ShadowsocksR-native server", disable_help_flag = true)]
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
    let server_cfg = config.server_settings.as_ref()
        .ok_or("server_settings required")?;

    let listen_addr = format!("{}:{}", server_cfg.listen_address, server_cfg.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    log::info!("SSR server listening on {}", listen_addr);

    let config = Arc::new(config);

    loop {
        let (incoming, peer_addr) = listener.accept().await?;
        log::info!("New SSR connection from {}", peer_addr);
        let cfg = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_server(incoming, &cfg).await {
                log::error!("Server error: {}", e);
            }
        });
    }
}

async fn handle_server(mut incoming: TcpStream, config: &SsrConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Create SSR cipher pipeline (server side)
    let mut cipher_ctx = TunnelCipherCtx::new(config, true)?;

    // Read encrypted data from client
    let mut buf = [0u8; 4096];
    let n = incoming.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // Decrypt
    let decrypted = cipher_ctx.server_decrypt(&buf[..n])?;

    // Parse target address from decrypted data
    let (target_addr, used) = Socks5Addr::parse(&decrypted)?;
    let target_str = target_addr.to_string();
    log::info!("Target: {}", target_str);

    // Connect to target
    let mut target = TcpStream::connect(&target_str).await?;

    // If there's remaining data after the address, send it first
    if used < decrypted.len() {
        target.write_all(&decrypted[used..]).await?;
    }

    // Proxy bidirectionally
    proxy_streams(incoming, target).await?;

    Ok(())
}
