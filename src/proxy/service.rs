use worker::{Context, Env, Request, Response, Result, WebSocketPair};

use crate::{trace_error, trace_log};
use super::types::ProxyPlan;
use super::util::{derive_uuid_v4, is_uuid_v4};
use super::ws::ProxySession;

pub struct ProxyService {
    env: Env,
}

impl ProxyService {
    pub fn new(env: Env) -> Self {
        Self { env }
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
        let _method = req.method().to_string();
        let url = req.url()?;
        let request_path = url.path().to_string();
        let _upgrade = req
            .headers()
            .get("Upgrade")
            .ok()
            .flatten()
            .unwrap_or_default();
        let ws_path = self.resolve_ws_path();
        trace_log!(
            "incoming request: method={} path={} upgrade={} expected_path={}",
            _method,
            request_path,
            _upgrade,
            ws_path
        );

        if request_path != ws_path {
            trace_log!(
                "request path mismatch: got={}, expected={}",
                request_path,
                ws_path
            );
            return Response::error("Not Found", 404);
        }

        let user_id = self.resolve_user_id()?;
        trace_log!("session key: {}", user_id);
        let proxy_plan = ProxyPlan::from_request(&req, &self.env)?;
        let early_data = req
            .headers()
            .get("sec-websocket-protocol")
            .ok()
            .flatten()
            .unwrap_or_default();
        trace_log!("resume header length: {}", early_data.len());

        let pair = WebSocketPair::new()?;
        pair.server
            .as_ref()
            .set_binary_type(web_sys::BinaryType::Arraybuffer);
        pair.server.accept()?;
        trace_log!("channel accepted");

        let session = ProxySession::new(pair.server, user_id, proxy_plan, early_data);
        ctx.wait_until(async move {
            if let Err(_err) = session.run().await {
                trace_error!("channel task failed: {:?}", _err);
            }
        });

        Response::from_websocket(pair.client)
    }

    fn resolve_user_id(&self) -> Result<String> {
        let admin = self.read_secret(&["UUID", "uuid", "ADMIN", "admin", "PASSWORD", "password"]);
        let Some(value) = admin else {
            return Ok("00000000-0000-4000-8000-000000000000".to_string());
        };

        if is_uuid_v4(&value) {
            return Ok(value.to_ascii_lowercase());
        }

        let key = self
            .read_secret(&["KEY"])
            .unwrap_or_else(|| "vlpo-worker-rs".to_string());
        Ok(derive_uuid_v4(&(value + &key)))
    }

    fn read_secret(&self, keys: &[&str]) -> Option<String> {
        for key in keys {
            if let Ok(var) = self.env.var(key) {
                let text = var.to_string();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn resolve_ws_path(&self) -> String {
        let raw = self
            .env
            .var("WS_PATH")
            .ok()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "/".to_string());

        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "/" {
            "/".to_string()
        } else if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{}", trimmed)
        }
    }
}
