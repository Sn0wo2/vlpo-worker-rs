use futures_util::StreamExt;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWriteExt};
use worker::{Result, Socket, WebSocket, WebsocketEvent};

use crate::trace_log;

use super::connect::connect_tcp;
use super::types::{InitialRequest, ProxyPlan};
use super::util::{decode_early_data, is_speedtest_host, DNS_FALLBACK_HOST, DNS_FALLBACK_PORT};

pub struct ProxySession {
    websocket: WebSocket,
    user_id: String,
    plan: ProxyPlan,
    early_data: String,
}

impl ProxySession {
    pub fn new(websocket: WebSocket, user_id: String, plan: ProxyPlan, early_data: String) -> Self {
        Self {
            websocket,
            user_id,
            plan,
            early_data,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut events = self.websocket.events()?;
        let mut initial_payload = decode_early_data(&self.early_data)?;
        trace_log!("session started");
        trace_log!("resume bytes: {}", initial_payload.len());

        if initial_payload.is_empty() {
            trace_log!("waiting for first frame");
            loop {
                let Some(event) = events.next().await else {
                    trace_log!("event stream ended before first frame");
                    return Ok(());
                };
                match event? {
                    WebsocketEvent::Message(message) => {
                        if let Some(bytes) = message.bytes() {
                            trace_log!("first binary frame: {}B", bytes.len());
                            if bytes.is_empty() {
                                trace_log!("ignored empty binary frame");
                                continue;
                            }
                            initial_payload = bytes;
                            break;
                        } else if let Some(text) = message.text() {
                            trace_log!("first text frame: {}B", text.len());
                            if text.is_empty() {
                                trace_log!("ignored empty text frame");
                                continue;
                            }
                            initial_payload = text.into_bytes();
                            break;
                        }
                    }
                    WebsocketEvent::Close(_event) => {
                        trace_log!("channel closed before first frame: code={:?}", _event.code());
                        return Ok(());
                    }
                }
            }
        }

        if initial_payload.is_empty() {
            self.websocket.close(None, None::<String>)?;
            return Ok(());
        }

        let parsed = match InitialRequest::parse(&initial_payload, &self.user_id) {
            Ok(parsed) => parsed,
            Err(err) => {
                let _ = self.websocket.close(Some(1008), Some("invalid request"));
                return Err(err);
            }
        };
        trace_log!(
            "route parsed: {}:{} datagram={} payload={}B",
            parsed.hostname,
            parsed.port,
            parsed.is_udp,
            parsed.payload.len()
        );
        if is_speedtest_host(&parsed.hostname) {
            self.websocket.close(Some(1008), Some("blocked"))?;
            return Ok(());
        }

        if parsed.is_udp && parsed.port != DNS_FALLBACK_PORT {
            self.websocket.close(Some(1003), Some("udp unsupported"))?;
            return Ok(());
        }

        if parsed.is_udp {
            let mut socket = connect_tcp(DNS_FALLBACK_HOST, DNS_FALLBACK_PORT)?;
            socket.opened().await?;
            socket.write_all(&parsed.payload).await?;
            socket.flush().await?;
            self.pipe_remote_to_ws(socket, parsed.response_header.clone()).await?;
            return Ok(());
        }

        self.handle_tcp(&mut events, parsed).await?;
        Ok(())
    }

    async fn handle_tcp(&self, events: &mut worker::EventStream<'_>, parsed: InitialRequest) -> Result<()> {
        let direct_socket = self.try_connect_and_send(&parsed.hostname, parsed.port, &parsed.payload).await;

        match direct_socket {
            Ok(mut socket) => {
                trace_log!("primary link ok: {}:{}", parsed.hostname, parsed.port);
                let has_data = self
                    .pipe_bidirectional(events, &mut socket, parsed.response_header.clone())
                    .await?;

                if !has_data && !self.plan.entries.is_empty() {
                    trace_log!("primary link returned no data, trying alternate route");
                    let mut fallback_socket = self.plan.connect_target(&parsed).await?;
                    let _ = self
                        .pipe_bidirectional(events, &mut fallback_socket, parsed.response_header)
                        .await?;
                } else {
                    let _ = self.websocket.close(None, None::<String>);
                }

                Ok(())
            }
            Err(direct_err) => {
                trace_log!(
                    "primary link failed: {}:{} => {:?}",
                    parsed.hostname,
                    parsed.port,
                    direct_err
                );

                if self.plan.entries.is_empty() {
                    let _ = self.websocket.close(Some(1011), Some("connect failed"));
                    return Err(direct_err);
                }

                trace_log!("trying alternate route");
                let mut socket = match self.plan.connect_target(&parsed).await {
                    Ok(socket) => socket,
                    Err(err) => {
                        let _ = self.websocket.close(Some(1011), Some("connect failed"));
                        return Err(err);
                    }
                };
                let _ = self
                    .pipe_bidirectional(events, &mut socket, parsed.response_header)
                    .await?;
                let _ = self.websocket.close(None, None::<String>);
                Ok(())
            }
        }
    }

    async fn try_connect_and_send(&self, host: &str, port: u16, initial_payload: &[u8]) -> Result<Socket> {
        let mut socket = connect_tcp(host, port)?;
        socket.opened().await?;
        if !initial_payload.is_empty() {
            socket.write_all(initial_payload).await?;
            socket.flush().await?;
        }
        Ok(socket)
    }

    async fn pipe_bidirectional(
        &self,
        events: &mut worker::EventStream<'_>,
        socket: &mut Socket,
        response_header: Option<Vec<u8>>,
    ) -> Result<bool> {
        let (mut read_socket, mut write_socket) = split(socket);
        let ws = self.websocket.clone();
        let reader = async move {
            ProxySession::pipe_remote_to_ws_inner(&ws, &mut read_socket, response_header).await
        };

        let writer = async {
            while let Some(event) = events.next().await {
                match event? {
                    WebsocketEvent::Message(message) => {
                        if let Some(bytes) = message.bytes() {
                            if bytes.is_empty() {
                                continue;
                            }
                            write_socket.write_all(&bytes).await?;
                            write_socket.flush().await?;
                        } else if let Some(text) = message.text() {
                            let bytes = text.into_bytes();
                            if !bytes.is_empty() {
                                write_socket.write_all(&bytes).await?;
                                write_socket.flush().await?;
                            }
                        }
                    }
                    WebsocketEvent::Close(_event) => {
                        trace_log!("channel closed: code={:?}", _event.code());
                        break;
                    }
                }
            }

            write_socket.shutdown().await?;
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

    async fn pipe_remote_to_ws(&self, mut socket: Socket, response_header: Option<Vec<u8>>) -> Result<()> {
        let _ = Self::pipe_remote_to_ws_inner(&self.websocket, &mut socket, response_header).await?;
        let _ = self.websocket.close(None, None::<String>);
        Ok(())
    }

    async fn pipe_remote_to_ws_inner(
        websocket: &WebSocket,
        socket: &mut (impl AsyncRead + Unpin),
        mut response_header: Option<Vec<u8>>,
    ) -> Result<bool> {
        let mut buf = vec![0_u8; 16 * 1024];
        let mut has_data = false;

        loop {
            let read = socket.read(&mut buf).await?;
            if read == 0 {
                trace_log!("upstream closed");
                break;
            }

            has_data = true;
            trace_log!("upstream -> channel {}B", read);

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
}
