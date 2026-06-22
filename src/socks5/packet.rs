use super::addr::Socks5Addr;

#[allow(dead_code)]
pub const SOCKS5_VER: u8 = 0x05;
pub const METHOD_NOAUTH: u8 = 0x00;
pub const METHOD_GSSAPI: u8 = 0x01;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_NONE: u8 = 0xFF;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOC: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_FAILURE: u8 = 0x01;
pub const REP_DENIED: u8 = 0x02;
pub const REP_NETUNREACH: u8 = 0x03;
pub const REP_HOSTUNREACH: u8 = 0x04;
pub const REP_REFUSED: u8 = 0x05;
pub const REP_TTLEXPIRED: u8 = 0x06;
pub const REP_CMDUNSUPP: u8 = 0x07;
pub const REP_ADDRUNSUPP: u8 = 0x08;

/// Build method selection response: [VER, METHOD]
pub fn build_method_response(method: u8) -> Vec<u8> {
    vec![SOCKS5_VER, method]
}

/// Build SOCKS5 CONNECT request with domain name: [VER, CMD, RSV, ATYP, ADDR, PORT]
pub fn build_connect_request(host: &str, port: u16) -> Vec<u8> {
    let addr = Socks5Addr::from_host_port(host, port);
    let mut buf = vec![SOCKS5_VER, CMD_CONNECT, 0x00];
    buf.extend_from_slice(&addr.encode());
    buf
}

/// Build SOCKS5 response: [VER, REP, RSV, ATYP, ADDR, PORT]
/// Uses IPv4 0.0.0.0:0 as bind address (common for client)
pub fn build_response(rep: u8) -> Vec<u8> {
    let buf = vec![SOCKS5_VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    buf
}

/// Build SOCKS5 response with specific bind address
pub fn build_response_with_bind(rep: u8, bind_addr: &Socks5Addr) -> Vec<u8> {
    let mut buf = vec![SOCKS5_VER, rep, 0x00];
    buf.extend_from_slice(&bind_addr.encode());
    buf
}

/// Build UDP ASSOCIATE response: [VER, REP, RSV, ATYP, BIND_ADDR, BIND_PORT]
pub fn build_udp_assoc_response(rep: u8, bind_addr: &Socks5Addr) -> Vec<u8> {
    let mut buf = vec![SOCKS5_VER, rep, 0x00];
    buf.extend_from_slice(&bind_addr.encode());
    buf
}

/// Parse SOCKS5 UDP datagram: [RSV=2][FRAG=1][ATYP+ADDR+PORT][PAYLOAD]
pub fn parse_udp_datagram(data: &[u8]) -> Option<(Socks5Addr, Vec<u8>)> {
    if data.len() < 3 {
        return None;
    }
    let frag = data[2];
    if frag != 0 {
        return None; // fragmentation not supported
    }
    let (addr, used) = Socks5Addr::parse(&data[3..]).ok()?;
    let payload = data[3 + used..].to_vec();
    Some((addr, payload))
}

/// Build SOCKS5 UDP datagram: [RSV=0x0000][FRAG=0][ATYP+ADDR+PORT][PAYLOAD]
pub fn build_udp_datagram(dst: &Socks5Addr, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00, 0x00]; // RSV + FRAG
    buf.extend_from_slice(&dst.encode());
    buf.extend_from_slice(payload);
    buf
}

/// Build username/password auth response (RFC 1929): [VER=1][STATUS]
pub fn build_userpass_response(status: u8) -> Vec<u8> {
    vec![0x01, status]
}
