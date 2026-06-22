// Result codes matching C s5_result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S5Result {
    NeedMore,      // 0: need more data
    AuthSelect,    // 1: client methods read, server must select
    AuthVerify,    // 2: username/password read, caller must verify
    ExecCmd,       // 3: full request parsed, caller must execute
    BadVersion,    // -1
    BadCmd,        // -2
    BadAtyp,       // -3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S5Atyp {
    Ipv4 = 1,
    Domain = 3,
    Ipv6 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S5Cmd {
    TcpConnect = 1,
    TcpBind = 2,
    UdpAssoc = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S5AuthMethod {
    None = 0,
    Gssapi = 1,
    Passwd = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Version,
    Nmethods,
    Methods,
    AuthPwVersion,
    AuthPwUserLen,
    AuthPwUsername,
    AuthPwPassLen,
    AuthPwPassword,
    ReqVersion,
    ReqCmd,
    ReqRsv,
    ReqAtyp,
    ReqAtypHost,
    ReqDaddr,
    ReqDport0,
    ReqDport1,
    Dead,
}

/// SOCKS5 parser state machine (replicates s5.c's s5_parse)
pub struct S5Parser {
    stage: Stage,
    arg0: usize,    // byte counter within current field
    arg1: usize,    // expected length of current field
    methods: u8,    // bitmask of supported methods
    pub cmd: u8,
    pub atyp: u8,
    pub daddr: Vec<u8>,
    pub dport: u16,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl S5Parser {
    pub fn new() -> Self {
        S5Parser {
            stage: Stage::Version,
            arg0: 0, arg1: 0,
            methods: 0, cmd: 0, atyp: 0,
            daddr: Vec::new(), dport: 0,
            username: Vec::new(), password: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        *self = S5Parser::new();
    }

    /// Feed data into the state machine. Returns when a decision point is reached
    /// or when more data is needed.
    /// On return, `consumed` indicates how many bytes were processed.
    pub fn parse(&mut self, data: &[u8]) -> (S5Result, usize) {
        let mut i = 0;
        let n = data.len();

        while i < n {
            let c = data[i];
            i += 1;

            match self.stage {
                Stage::Version => {
                    if c != 0x05 { return (S5Result::BadVersion, i); }
                    self.stage = Stage::Nmethods;
                }
                Stage::Nmethods => {
                    self.arg0 = 0;
                    self.arg1 = c as usize;
                    self.methods = 0;
                    self.stage = Stage::Methods;
                }
                Stage::Methods => {
                    if self.arg0 < self.arg1 {
                        match c {
                            0 => self.methods |= 1 << 0,
                            1 => self.methods |= 1 << 1,
                            2 => self.methods |= 1 << 2,
                            _ => {}
                        }
                        self.arg0 += 1;
                    }
                    if self.arg0 == self.arg1 {
                        return (S5Result::AuthSelect, i);
                    }
                }
                Stage::AuthPwVersion => {
                    if c != 0x01 { return (S5Result::BadVersion, i); }
                    self.stage = Stage::AuthPwUserLen;
                }
                Stage::AuthPwUserLen => {
                    self.arg0 = 0;
                    let ulen = c as usize;
                    self.username = vec![0u8; ulen];
                    self.stage = Stage::AuthPwUsername;
                }
                Stage::AuthPwUsername => {
                    let ulen = self.username.len();
                    if self.arg0 < ulen {
                        self.username[self.arg0] = c;
                        self.arg0 += 1;
                    }
                    if self.arg0 == ulen {
                        self.stage = Stage::AuthPwPassLen;
                    }
                }
                Stage::AuthPwPassLen => {
                    self.arg0 = 0;
                    let plen = c as usize;
                    self.password = vec![0u8; plen];
                    self.stage = Stage::AuthPwPassword;
                }
                Stage::AuthPwPassword => {
                    let plen = self.password.len();
                    if self.arg0 < plen {
                        self.password[self.arg0] = c;
                        self.arg0 += 1;
                    }
                    if self.arg0 == plen {
                        self.stage = Stage::ReqVersion;
                        return (S5Result::AuthVerify, i);
                    }
                }
                Stage::ReqVersion => {
                    if c != 0x05 { return (S5Result::BadVersion, i); }
                    self.stage = Stage::ReqCmd;
                }
                Stage::ReqCmd => {
                    match c {
                        1 => self.cmd = 1,
                        2 => self.cmd = 2,
                        3 => self.cmd = 3,
                        _ => return (S5Result::BadCmd, i),
                    }
                    self.stage = Stage::ReqRsv;
                }
                Stage::ReqRsv => {
                    self.stage = Stage::ReqAtyp;
                }
                Stage::ReqAtyp => {
                    self.arg0 = 0;
                    match c {
                        1 => { self.atyp = 1; self.arg1 = 4; self.stage = Stage::ReqDaddr; }
                        3 => { self.atyp = 3; self.arg1 = 0; self.stage = Stage::ReqAtypHost; }
                        4 => { self.atyp = 4; self.arg1 = 16; self.stage = Stage::ReqDaddr; }
                        _ => return (S5Result::BadAtyp, i),
                    }
                }
                Stage::ReqAtypHost => {
                    self.arg1 = c as usize;
                    self.stage = Stage::ReqDaddr;
                }
                Stage::ReqDaddr => {
                    if self.arg0 == 0 {
                        self.daddr = vec![0u8; self.arg1];
                    }
                    if self.arg0 < self.arg1 {
                        self.daddr[self.arg0] = c;
                        self.arg0 += 1;
                    }
                    if self.arg0 == self.arg1 {
                        self.stage = Stage::ReqDport0;
                    }
                }
                Stage::ReqDport0 => {
                    self.dport = (c as u16) << 8;
                    self.stage = Stage::ReqDport1;
                }
                Stage::ReqDport1 => {
                    self.dport |= c as u16;
                    self.stage = Stage::Dead;
                    return (S5Result::ExecCmd, i);
                }
                Stage::Dead => {
                    break;
                }
            }
        }

        (S5Result::NeedMore, i)
    }

    pub fn select_auth(&mut self, method: S5AuthMethod) {
        match method {
            S5AuthMethod::None => self.stage = Stage::ReqVersion,
            S5AuthMethod::Passwd => self.stage = Stage::AuthPwVersion,
            _ => {}
        }
    }

    pub fn has_method(&self, method: S5AuthMethod) -> bool {
        let bit = 1 << (method as u8);
        (self.methods & bit) != 0
    }

    pub fn supported_methods(&self) -> Vec<S5AuthMethod> {
        let mut v = Vec::new();
        if self.methods & (1 << 0) != 0 { v.push(S5AuthMethod::None); }
        if self.methods & (1 << 1) != 0 { v.push(S5AuthMethod::Gssapi); }
        if self.methods & (1 << 2) != 0 { v.push(S5AuthMethod::Passwd); }
        v
    }

    /// Get the target address string (IP or domain)
    pub fn addr_str(&self) -> String {
        match self.atyp {
            1 => {
                if self.daddr.len() >= 4 {
                    std::net::Ipv4Addr::new(self.daddr[0], self.daddr[1], self.daddr[2], self.daddr[3]).to_string()
                } else { String::new() }
            }
            3 => String::from_utf8_lossy(&self.daddr).to_string(),
            4 => {
                if self.daddr.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&self.daddr[..16]);
                    std::net::Ipv6Addr::from(octets).to_string()
                } else { String::new() }
            }
            _ => String::new(),
        }
    }

    pub fn is_dead(&self) -> bool {
        self.stage == Stage::Dead
    }
}
