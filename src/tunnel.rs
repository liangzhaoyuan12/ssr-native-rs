use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::error::{Error, Result};

/// Bidirectional TCP proxy between two sockets
pub async fn proxy_streams(mut local: TcpStream, mut remote: TcpStream) -> Result<()> {
    let (mut lr, mut lw) = local.split();
    let (mut rr, mut rw) = remote.split();

    let c1 = tokio::io::copy(&mut lr, &mut rw);
    let c2 = tokio::io::copy(&mut rr, &mut lw);

    tokio::select! {
        r = c1 => { if let Err(e) = r { return Err(Error::Tunnel(format!("local->remote: {}", e))); } }
        r = c2 => { if let Err(e) = r { return Err(Error::Tunnel(format!("remote->local: {}", e))); } }
    }
    Ok(())
}

/// Write all data to a socket
pub async fn write_all(socket: &mut TcpStream, data: &[u8]) -> Result<()> {
    socket.write_all(data).await.map_err(|e| Error::Tunnel(format!("write: {}", e)))
}

/// Read exact number of bytes from a socket
pub async fn read_exact(socket: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
    socket.read_exact(buf).await.map_err(|e| Error::Tunnel(format!("read: {}", e)))
}

#[allow(unused)]
pub async fn read_some(socket: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
    socket.read(buf).await.map_err(|e| Error::Tunnel(format!("read: {}", e)))
}
