#[derive(Clone, Debug)]
pub struct SocketTarget {
    pub host: String,
    pub port: u16,
    pub has_explicit_port: bool,
}

#[derive(Clone, Debug)]
pub struct InitialRequest {
    pub hostname: String,
    pub port: u16,
    pub is_udp: bool,
    pub payload: Vec<u8>,
    pub response_header: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ProxyPlan {
    pub entries: Vec<ProxyEntry>,
}

#[derive(Clone, Debug)]
pub enum ProxyEntry {
    ProxyIp(SocketTarget),
    Socks5(ProxyCredential),
    Http(ProxyCredential),
}

#[derive(Clone, Debug)]
pub enum ProxyKind {
    Socks5,
    Http,
}

#[derive(Clone, Debug)]
pub struct ProxyCredential {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}
