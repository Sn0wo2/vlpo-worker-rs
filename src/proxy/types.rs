#[derive(Clone, Debug)]
pub enum DnsTransport {
    Tcp,
    Tls,
    Https,
}

#[derive(Clone, Debug)]
pub struct DnsUpstream {
    pub transport: DnsTransport,
    pub host: String,
    pub port: u16,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct DnsResolver {
    pub upstreams: Vec<DnsUpstream>,
}

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

impl InitialRequest {
    pub fn is_dns_request(&self) -> bool {
        self.is_udp && self.port == 53
    }

    pub fn is_udp_only(&self) -> bool {
        self.is_udp && !self.is_dns_request()
    }
}

#[derive(Clone, Debug)]
pub struct ProxyPlan {
    pub entries: Vec<ProxyEntry>,
}

impl ProxyPlan {
    pub fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }
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

pub struct ProxyConfig {
    pub user_id: String,
    pub ws_path: String,
    pub plan: ProxyPlan,
    pub dns_resolver: DnsResolver,
}
