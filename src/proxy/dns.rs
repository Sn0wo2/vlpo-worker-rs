use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Headers, Method, Request, RequestInit, Result, Socket};
use worker::wasm_bindgen::JsValue;

use crate::trace_log;

use super::outbound::connect_tcp;
use super::types::{DnsResolver, DnsTransport, DnsUpstream};
use super::util::{parse_host_port, split_multi_value};

impl DnsResolver {
    pub fn from_env(env: &worker::Env) -> Self {
        env.var("DNS_UPSTREAM")
            .ok()
            .map(|value| value.to_string())
            .map(|value| Self::parse(&value))
            .unwrap_or_else(Self::default)
    }

    pub fn default() -> Self {
        Self {
            upstreams: vec![DnsUpstream::default()],
        }
    }

    pub fn parse(value: &str) -> Self {
        let upstreams = split_multi_value(value)
            .into_iter()
            .filter_map(|item| DnsUpstream::parse(&item))
            .collect::<Vec<_>>();

        if upstreams.is_empty() {
            return Self::default();
        }

        Self { upstreams }
    }
}

impl DnsResolver {
    pub async fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut last_error = None;

        for upstream in &self.upstreams {
            trace_log!("dns upstream try: {}", upstream.label());
            match upstream.exchange(payload).await {
                Ok(response) => return Ok(response),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| worker::Error::RustError("dns upstream unavailable".into())))
    }
}

impl DnsUpstream {
    pub fn default() -> Self {
        Self {
            transport: DnsTransport::Https,
            host: "dns.google".to_string(),
            port: 443,
            path: "/dns-query".to_string(),
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        if let Some(rest) = trimmed.strip_prefix("https://") {
            return Self::parse_https(rest);
        }

        if let Some(rest) = trimmed.strip_prefix("tls://") {
            return Self::parse_tls(rest);
        }

        Self::parse_tcp(trimmed)
    }

    pub async fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>> {
        match self.transport {
            DnsTransport::Tcp => self.exchange_over_tcp(payload).await,
            DnsTransport::Tls => self.exchange_over_tls(payload).await,
            DnsTransport::Https => self.exchange_over_https(payload).await,
        }
    }

    async fn exchange_over_tcp(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut socket = connect_tcp(&self.host, self.port)?;
        socket.opened().await?;
        self.exchange_with_socket(&mut socket, payload).await
    }

    async fn exchange_over_tls(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut socket = Socket::builder()
            .secure_transport(worker::SecureTransport::On)
            .connect(self.host.clone(), self.port)?;
        socket.opened().await?;
        self.exchange_with_socket(&mut socket, payload).await
    }

    async fn exchange_over_https(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let headers = Headers::new();
        headers.set("content-type", "application/dns-message")?;

        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from(js_sys::Uint8Array::from(payload))));

        let request = Request::new_with_init(&self.url(), &init)?;
        let mut response = worker::Fetch::Request(request).send().await?;
        response.bytes().await
    }

    async fn exchange_with_socket(&self, socket: &mut Socket, payload: &[u8]) -> Result<Vec<u8>> {
        let length = (payload.len() as u16).to_be_bytes();
        socket.write_all(&length).await?;
        socket.write_all(payload).await?;
        socket.flush().await?;

        let response_size = socket.read_u16().await? as usize;
        let mut response = vec![0_u8; response_size];
        socket.read_exact(&mut response).await?;
        Ok(response)
    }

    fn url(&self) -> String {
        format!("https://{}:{}{}", self.host, self.port, self.path)
    }

    fn parse_https(value: &str) -> Option<Self> {
        let (host_port, path) = value.split_once('/').unwrap_or((value, "dns-query"));
        let target = parse_host_port(host_port).ok()?;
        Some(Self {
            transport: DnsTransport::Https,
            host: target.host,
            port: if target.has_explicit_port { target.port } else { 443 },
            path: format!("/{}", path.trim_start_matches('/')),
        })
    }

    fn parse_tls(value: &str) -> Option<Self> {
        let target = parse_host_port(value).ok()?;
        Some(Self {
            transport: DnsTransport::Tls,
            host: target.host,
            port: if target.has_explicit_port { target.port } else { 853 },
            path: "/dns-query".to_string(),
        })
    }

    fn parse_tcp(value: &str) -> Option<Self> {
        let target = parse_host_port(value).ok()?;
        Some(Self {
            transport: DnsTransport::Tcp,
            host: target.host,
            port: if target.has_explicit_port { target.port } else { 53 },
            path: "/dns-query".to_string(),
        })
    }

    #[cfg(debug_assertions)]
    fn label(&self) -> String {
        match self.transport {
            DnsTransport::Tcp => format!("tcp://{}:{}", self.host, self.port),
            DnsTransport::Tls => format!("tls://{}:{}", self.host, self.port),
            DnsTransport::Https => self.url(),
        }
    }
}
