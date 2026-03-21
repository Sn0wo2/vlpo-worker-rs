use futures_util::StreamExt;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWriteExt};
use worker::{Context, Env, Request, Response, Result, Socket, WebSocket, WebSocketPair, WebsocketEvent};

use crate::trace_error;

use super::outbound::connect_tcp;
use super::types::{DnsResolver, InitialRequest, ProxyConfig, ProxyPlan};
use super::util::{decode_early_data, is_speedtest_host};

pub struct ProxyService {
    config: ProxyConfig,
}

pub struct InboundSession {
    websocket: WebSocket,
    user_id: String,
    plan: ProxyPlan,
    dns_resolver: DnsResolver,
    early_data: String,
}

impl ProxyService {
    pub fn new(env: Env) -> Result<Self> {
        Ok(Self {
            config: ProxyConfig::from_env(env)?,
        })
    }

    pub fn is_websocket_request(req: &Request) -> bool {
        req.headers()
            .get("Upgrade")
            .ok()
            .flatten()
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }

    pub async fn handle(&self, req: Request, ctx: Context) -> Result<Response> {
        let request_path = req.url()?.path().to_string();
        if request_path != self.config.ws_path {
            return Response::error("Not Found", 404);
        }

        let pair = WebSocketPair::new()?;
        pair.server
            .as_ref()
            .set_binary_type(web_sys::BinaryType::Arraybuffer);
        pair.server.accept()?;

        let session = InboundSession::new(
            pair.server,
            self.config.user_id.clone(),
            self.config.plan_for(&req)?,
            self.config.dns_resolver.clone(),
            self.config.early_data_header(&req),
        );

        ctx.wait_until(async move {
            if let Err(_err) = session.run().await {
                trace_error!("channel task failed: {:?}", _err);
            }
        });

        Response::from_websocket(pair.client)
    }
}

impl InboundSession {
    pub fn new(
        websocket: WebSocket,
        user_id: String,
        plan: ProxyPlan,
        dns_resolver: DnsResolver,
        early_data: String,
    ) -> Self {
        Self {
            websocket,
            user_id,
            plan,
            dns_resolver,
            early_data,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut events = self.websocket.events()?;
        let payload = self.read_initial_payload(&mut events).await?;
        if payload.is_empty() {
            self.websocket.close(None, None::<String>)?;
            return Ok(());
        }

        let request = match InitialRequest::parse(&payload, &self.user_id) {
            Ok(request) => request,
            Err(err) => {
                let _ = self.websocket.close(Some(1008), Some("invalid request"));
                return Err(err);
            }
        };

        if is_speedtest_host(&request.hostname) {
            self.websocket.close(Some(1008), Some("blocked"))?;
            return Ok(());
        }

        if request.is_udp_only() {
            self.websocket.close(Some(1003), Some("udp unsupported"))?;
            return Ok(());
        }

        if request.is_dns_request() {
            return self.forward_dns(&request).await;
        }

        self.forward_stream(events, request).await
    }

    async fn forward_dns(&self, request: &InitialRequest) -> Result<()> {
        let response = self.dns_resolver.exchange(&request.payload).await?;
        let mut packet = request.response_header.clone().unwrap_or_default();
        packet.extend_from_slice(&response);
        self.websocket.send_with_bytes(packet)?;
        self.close()
    }

    async fn forward_stream(
        &self,
        mut events: worker::EventStream<'_>,
        request: InitialRequest,
    ) -> Result<()> {
        match self.connect_primary(&request).await {
            Ok(mut socket) => {
                let has_data = self.pipe_streams(&mut events, &mut socket, request.response_header.clone()).await?;
                if has_data || !self.plan.has_entries() {
                    return self.close();
                }

                let mut fallback = self.plan.connect_target(&request).await?;
                let _ = self.pipe_streams(&mut events, &mut fallback, request.response_header.clone()).await?;
                self.close()
            }
            Err(err) => {
                if !self.plan.has_entries() {
                    let _ = self.websocket.close(Some(1011), Some("connect failed"));
                    return Err(err);
                }

                let mut fallback = self.plan.connect_target(&request).await?;
                let _ = self.pipe_streams(&mut events, &mut fallback, request.response_header.clone()).await?;
                self.close()
            }
        }
    }

    async fn connect_primary(&self, request: &InitialRequest) -> Result<Socket> {
        let mut socket = connect_tcp(&request.hostname, request.port)?;
        socket.opened().await?;
        if !request.payload.is_empty() {
            socket.write_all(&request.payload).await?;
            socket.flush().await?;
        }
        Ok(socket)
    }

    async fn read_initial_payload(&self, events: &mut worker::EventStream<'_>) -> Result<Vec<u8>> {
        let early = decode_early_data(&self.early_data)?;
        if !early.is_empty() {
            return Ok(early);
        }

        while let Some(event) = events.next().await {
            match event? {
                WebsocketEvent::Message(message) => {
                    if let Some(payload) = Self::decode_message(message) {
                        return Ok(payload);
                    }
                }
                WebsocketEvent::Close(_) => return Ok(Vec::new()),
            }
        }

        Ok(Vec::new())
    }

    async fn pipe_streams(
        &self,
        events: &mut worker::EventStream<'_>,
        socket: &mut Socket,
        response_header: Option<Vec<u8>>,
    ) -> Result<bool> {
        let (mut reader_socket, mut writer_socket) = split(socket);
        let websocket = self.websocket.clone();
        let reader = async move { Self::pipe_remote_to_ws(&websocket, &mut reader_socket, response_header).await };
        let writer = async move {
            while let Some(event) = events.next().await {
                match event? {
                    WebsocketEvent::Message(message) => {
                        if let Some(payload) = Self::decode_message(message) {
                            writer_socket.write_all(&payload).await?;
                            writer_socket.flush().await?;
                        }
                    }
                    WebsocketEvent::Close(_) => break,
                }
            }

            writer_socket.shutdown().await?;
            Ok::<(), worker::Error>(())
        };

        match futures_util::future::select(Box::pin(reader), Box::pin(writer)).await {
            futures_util::future::Either::Left((result, _)) => result,
            futures_util::future::Either::Right((result, _)) => {
                result?;
                Ok(true)
            }
        }
    }

    async fn pipe_remote_to_ws(
        websocket: &WebSocket,
        socket: &mut (impl AsyncRead + Unpin),
        mut response_header: Option<Vec<u8>>,
    ) -> Result<bool> {
        let mut buf = vec![0_u8; 16 * 1024];
        let mut has_data = false;

        loop {
            let read = socket.read(&mut buf).await?;
            if read == 0 {
                break;
            }

            has_data = true;
            if let Some(header) = response_header.take() {
                let mut merged = Vec::with_capacity(header.len() + read);
                merged.extend_from_slice(&header);
                merged.extend_from_slice(&buf[..read]);
                websocket.send_with_bytes(merged)?;
            } else {
                websocket.send_with_bytes(&buf[..read])?;
            }
        }

        Ok(has_data)
    }

    fn decode_message(message: worker::MessageEvent) -> Option<Vec<u8>> {
        message
            .bytes()
            .filter(|bytes| !bytes.is_empty())
            .or_else(|| message.text().and_then(|text| (!text.is_empty()).then_some(text.into_bytes())))
    }

    fn close(&self) -> Result<()> {
        let _ = self.websocket.close(None, None::<String>);
        Ok(())
    }
}
