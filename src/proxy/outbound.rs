use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Env, Error, Request, Result, Socket};

use crate::trace_log;

use super::types::{InitialRequest, ProxyCredential, ProxyEntry, ProxyKind, ProxyPlan};
use super::util::{build_socks5_connect_request, first_non_empty, parse_host_port, split_multi_value};

impl ProxyPlan {
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(Self {
            entries: Self::collect_entries(
                first_non_empty(&[env.var("PROXYIP").ok().map(|v| v.to_string())]),
                first_non_empty(&[env.var("SOCKS5").ok().map(|v| v.to_string())]),
                first_non_empty(&[env.var("HTTP_PROXY").ok().map(|v| v.to_string())]),
                false,
            )?,
        })
    }

    pub fn extend_from_request(&self, req: &Request) -> Result<Self> {
        let url = req.url()?;
        let mut entries = self.entries.clone();
        entries.extend(Self::collect_entries(
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("proxyip"))
                .map(|(_, value)| value.into_owned()),
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("socks5"))
                .map(|(_, value)| value.into_owned()),
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("http"))
                .map(|(_, value)| value.into_owned()),
            true,
        )?);
        Ok(Self { entries })
    }

    pub async fn connect_target(&self, target: &InitialRequest) -> Result<Socket> {
        let mut last_error = None;

        for entry in &self.entries {
            trace_log!("alternate route attempt: {} -> {}:{}", entry.kind_name(), target.hostname, target.port);
            match entry.connect(target).await {
                Ok(socket) => {
                    trace_log!("alternate route success: {}", entry.kind_name());
                    return Ok(socket);
                }
                Err(err) => {
                    trace_log!("alternate route failed: {} => {:?}", entry.kind_name(), err);
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::RustError("no proxy target available".into())))
    }

    fn collect_entries(
        proxy_ip: Option<String>,
        socks5: Option<String>,
        http_proxy: Option<String>,
        _from_request: bool,
    ) -> Result<Vec<ProxyEntry>> {
        let mut entries = Vec::new();

        if let Some(proxy_ip) = proxy_ip {
            trace_log!(
                "{} route override: hop list={}",
                if _from_request { "request" } else { "config" },
                proxy_ip
            );
            for item in split_multi_value(&proxy_ip) {
                if let Some(entry) = ProxyEntry::parse(&item)? {
                    entries.push(entry);
                }
            }
        }

        if let Some(socks5) = socks5 {
            trace_log!(
                "{} route override: socks relay={}",
                if _from_request { "request" } else { "config" },
                socks5
            );
            entries.push(ProxyEntry::Socks5(ProxyCredential::parse(&socks5, ProxyKind::Socks5)?));
        }

        if let Some(http_proxy) = http_proxy {
            trace_log!(
                "{} route override: http relay={}",
                if _from_request { "request" } else { "config" },
                http_proxy
            );
            entries.push(ProxyEntry::Http(ProxyCredential::parse(&http_proxy, ProxyKind::Http)?));
        }

        Ok(entries)
    }
}

impl ProxyEntry {
    async fn connect(&self, target: &InitialRequest) -> Result<Socket> {
        match self {
            Self::ProxyIp(proxy) => Self::connect_proxy_ip(proxy, target).await,
            Self::Socks5(proxy) => proxy.connect_socks5(target).await,
            Self::Http(proxy) => proxy.connect_http(target).await,
        }
    }

    #[cfg(debug_assertions)]
    fn kind_name(&self) -> &'static str {
        match self {
            Self::ProxyIp(_) => "proxyip",
            Self::Socks5(_) => "socks5",
            Self::Http(_) => "http-connect",
        }
    }

    fn parse(value: &str) -> Result<Option<Self>> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        if trimmed.starts_with("socks5://") {
            return Ok(Some(Self::Socks5(ProxyCredential::parse(trimmed, ProxyKind::Socks5)?)));
        }

        if trimmed.starts_with("http://") {
            return Ok(Some(Self::Http(ProxyCredential::parse(trimmed, ProxyKind::Http)?)));
        }

        Ok(Some(Self::ProxyIp(parse_host_port(trimmed)?)))
    }

    async fn connect_proxy_ip(proxy: &super::types::SocketTarget, target: &InitialRequest) -> Result<Socket> {
        let port = if proxy.has_explicit_port { proxy.port } else { target.port };
        let mut socket = connect_tcp(&proxy.host, port)?;
        socket.opened().await?;
        write_payload(&mut socket, &target.payload).await?;
        Ok(socket)
    }
}

impl ProxyCredential {
    fn parse(value: &str, default_kind: ProxyKind) -> Result<Self> {
        let authority = value
            .trim()
            .strip_prefix(match default_kind {
                ProxyKind::Socks5 => "socks5://",
                ProxyKind::Http => "http://",
            })
            .unwrap_or(value.trim());

        let (auth_part, host_part) = authority
            .rsplit_once('@')
            .map(|(auth, host)| (Some(auth), host))
            .unwrap_or((None, authority));
        let target = parse_host_port(host_part)?;
        let (username, password) = auth_part
            .map(|auth| {
                let (username, password) = auth.split_once(':').unwrap_or((auth, ""));
                (Some(username.to_string()), Some(password.to_string()))
            })
            .unwrap_or((None, None));

        Ok(Self {
            host: target.host,
            port: target.port,
            username,
            password,
        })
    }

    async fn connect_socks5(&self, target: &InitialRequest) -> Result<Socket> {
        let mut socket = connect_tcp(&self.host, self.port)?;
        socket.opened().await?;

        let methods = if self.username.is_some() && self.password.is_some() {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };
        socket.write_all(&methods).await?;

        let mut response = [0_u8; 2];
        socket.read_exact(&mut response).await?;
        if response[0] != 0x05 {
            return Err(Error::RustError("invalid tunnel version".into()));
        }
        if response[1] == 0x02 {
            self.authorize_socks5(&mut socket).await?;
        } else if response[1] != 0x00 {
            return Err(Error::RustError("unsupported credential mode".into()));
        }

        socket.write_all(&build_socks5_connect_request(&target.hostname, target.port)?).await?;

        let mut header = [0_u8; 4];
        socket.read_exact(&mut header).await?;
        if header[1] != 0x00 {
            return Err(Error::RustError(format!("route setup failed: {}", header[1])));
        }

        let address_len = match header[3] {
            0x01 => 4,
            0x03 => {
                let mut len = [0_u8; 1];
                socket.read_exact(&mut len).await?;
                len[0] as usize
            }
            0x04 => 16,
            _ => return Err(Error::RustError("invalid bind address".into())),
        };

        let mut discard = vec![0_u8; address_len + 2];
        socket.read_exact(&mut discard).await?;
        write_payload(&mut socket, &target.payload).await?;
        Ok(socket)
    }

    async fn connect_http(&self, target: &InitialRequest) -> Result<Socket> {
        let mut socket = connect_tcp(&self.host, self.port)?;
        socket.opened().await?;

        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: vlpo-worker-rs\r\nProxy-Connection: Keep-Alive\r\n",
            target.hostname, target.port, target.hostname, target.port
        );

        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        request.push_str("\r\n");
        socket.write_all(request.as_bytes()).await?;

        let first_line = read_connect_response(&mut socket).await?;
        if !first_line.contains(" 200 ") && !first_line.ends_with(" 200") {
            return Err(Error::RustError(format!("relay handshake failed: {}", first_line)));
        }

        write_payload(&mut socket, &target.payload).await?;
        Ok(socket)
    }

    async fn authorize_socks5(&self, socket: &mut Socket) -> Result<()> {
        let username = self.username.clone().unwrap_or_default();
        let password = self.password.clone().unwrap_or_default();
        let username = username.as_bytes();
        let password = password.as_bytes();
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(Error::RustError("credential payload too long".into()));
        }

        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.push(0x01);
        auth.push(username.len() as u8);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        socket.write_all(&auth).await?;

        let mut response = [0_u8; 2];
        socket.read_exact(&mut response).await?;
        if response[1] != 0x00 {
            return Err(Error::RustError("credential check failed".into()));
        }
        Ok(())
    }
}

pub fn connect_tcp(hostname: &str, port: u16) -> Result<Socket> {
    Socket::builder().connect(hostname.to_string(), port)
}

async fn write_payload(socket: &mut Socket, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    socket.write_all(payload).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_connect_response(socket: &mut Socket) -> Result<String> {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < 8192 {
        let read = socket.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string())
}
