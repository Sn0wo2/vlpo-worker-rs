use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Env, Error, Request, Result, Socket};

use crate::trace_log;

use super::types::{InitialRequest, ProxyCredential, ProxyEntry, ProxyKind, ProxyPlan};
use super::util::{build_socks5_connect_request, first_non_empty, parse_host_port, split_multi_value};

impl ProxyPlan {
    pub fn from_request(req: &Request, env: &Env) -> Result<Self> {
        let url = req.url()?;
        let mut entries = Vec::new();

        if let Some(proxy_ip) = first_non_empty(&[
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("proxyip"))
                .map(|(_, value)| value.into_owned()),
            env.var("PROXYIP").ok().map(|v| v.to_string()),
        ]) {
            trace_log!("route config: hop list={}", proxy_ip);
            for item in split_multi_value(&proxy_ip) {
                if let Some(proxy) = parse_proxy_entry(&item)? {
                    entries.push(proxy);
                }
            }
        }

        if let Some(socks5) = first_non_empty(&[
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("socks5"))
                .map(|(_, value)| value.into_owned()),
            env.var("SOCKS5").ok().map(|v| v.to_string()),
        ]) {
            trace_log!("route config: socks relay={}", socks5);
            entries.push(ProxyEntry::Socks5(ProxyCredential::parse(&socks5, ProxyKind::Socks5)?));
        }

        if let Some(http_proxy) = first_non_empty(&[
            url.query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("http"))
                .map(|(_, value)| value.into_owned()),
            env.var("HTTP_PROXY").ok().map(|v| v.to_string()),
        ]) {
            trace_log!("route config: http relay={}", http_proxy);
            entries.push(ProxyEntry::Http(ProxyCredential::parse(&http_proxy, ProxyKind::Http)?));
        }

        trace_log!("route entries: {}", entries.len());
        Ok(Self { entries })
    }

    pub async fn connect_target(&self, target: &InitialRequest) -> Result<Socket> {
        let mut last_error: Option<Error> = None;

        for entry in &self.entries {
            trace_log!(
                "alternate route attempt: {} -> {}:{}",
                entry.kind_name(),
                target.hostname,
                target.port
            );
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
}

impl ProxyEntry {
    pub async fn connect(&self, target: &InitialRequest) -> Result<Socket> {
        match self {
            Self::ProxyIp(proxy) => {
                let port = if proxy.has_explicit_port {
                    proxy.port
                } else {
                    target.port
                };
                trace_log!(
                    "hop connect start: relay={}:{} target={}:{} payload={}B",
                    proxy.host,
                    port,
                    target.hostname,
                    target.port,
                    target.payload.len()
                );
                let mut socket = connect_tcp(&proxy.host, port)?;
                socket.opened().await?;
                if !target.payload.is_empty() {
                    socket.write_all(&target.payload).await?;
                    socket.flush().await?;
                }
                trace_log!("hop connect ok: {}:{}", proxy.host, port);
                Ok(socket)
            }
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
}

impl ProxyCredential {
    pub fn parse(value: &str, default_kind: ProxyKind) -> Result<Self> {
        let trimmed = value.trim();
        let authority = if let Some(rest) = trimmed.strip_prefix("socks5://") {
            let _ = ProxyKind::Socks5;
            rest
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            let _ = ProxyKind::Http;
            rest
        } else {
            let _ = default_kind;
            trimmed
        };

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

        trace_log!(
            "route credential parsed: kind={} host={} port={} auth={}",
            match default_kind {
                ProxyKind::Socks5 => "socks5",
                ProxyKind::Http => "http",
            },
            target.host,
            target.port,
            username.is_some() && password.is_some()
        );

        Ok(Self {
            host: target.host,
            port: target.port,
            username,
            password,
        })
    }

    async fn connect_socks5(&self, target: &InitialRequest) -> Result<Socket> {
        trace_log!(
            "socks relay start: relay={}:{} target={}:{} payload={}B auth={}",
            self.host,
            self.port,
            target.hostname,
            target.port,
            target.payload.len(),
            self.username.is_some() && self.password.is_some()
        );
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

        match response[1] {
            0x00 => {}
            0x02 => {
                trace_log!("socks relay selected credential auth");
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

                let mut auth_resp = [0_u8; 2];
                socket.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(Error::RustError("credential check failed".into()));
                }
            }
            _ => return Err(Error::RustError("unsupported credential mode".into())),
        }

        let request = build_socks5_connect_request(&target.hostname, target.port)?;
        trace_log!("socks relay sending route request");
        socket.write_all(&request).await?;

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
        if !target.payload.is_empty() {
            socket.write_all(&target.payload).await?;
            socket.flush().await?;
        }
        trace_log!("socks relay connected");
        Ok(socket)
    }

    async fn connect_http(&self, target: &InitialRequest) -> Result<Socket> {
        trace_log!(
            "http relay start: relay={}:{} target={}:{} payload={}B auth={}",
            self.host,
            self.port,
            target.hostname,
            target.port,
            target.payload.len(),
            self.username.is_some() && self.password.is_some()
        );
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

        let mut buf = Vec::new();
        let mut byte = [0_u8; 1];
        while buf.len() < 8192 {
            let read = socket.read(&mut byte).await?;
            if read == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let text = String::from_utf8_lossy(&buf);
        let first_line = text.lines().next().unwrap_or_default();
        trace_log!("http relay response: {}", first_line);
        if !first_line.contains(" 200 ") && !first_line.ends_with(" 200") {
            return Err(Error::RustError(format!("relay handshake failed: {}", first_line)));
        }

        if !target.payload.is_empty() {
            socket.write_all(&target.payload).await?;
            socket.flush().await?;
        }

        trace_log!("http relay connected");
        Ok(socket)
    }
}

pub fn connect_tcp(hostname: &str, port: u16) -> Result<Socket> {
    trace_log!("tcp dial: {}:{}", hostname, port);
    Socket::builder().connect(hostname.to_string(), port)
}

fn parse_proxy_entry(value: &str) -> Result<Option<ProxyEntry>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.starts_with("socks5://") {
        return Ok(Some(ProxyEntry::Socks5(ProxyCredential::parse(
            trimmed,
            ProxyKind::Socks5,
        )?)));
    }

    if trimmed.starts_with("http://") {
        return Ok(Some(ProxyEntry::Http(ProxyCredential::parse(
            trimmed,
            ProxyKind::Http,
        )?)));
    }

    Ok(Some(ProxyEntry::ProxyIp(parse_host_port(trimmed)?)))
}
