use worker::{Env, Result};

use super::types::{DnsResolver, ProxyConfig, ProxyPlan};
use super::util::{derive_uuid_v4, first_non_empty, is_uuid_v4, normalize_path};

impl ProxyConfig {
    pub fn from_env(env: Env) -> Result<Self> {
        Ok(Self {
            user_id: Self::resolve_user_id(&env)?,
            ws_path: Self::resolve_ws_path(&env),
            plan: ProxyPlan::from_env(&env)?,
            dns_resolver: DnsResolver::from_env(&env),
        })
    }

    pub fn early_data_header(&self, req: &worker::Request) -> String {
        req.headers()
            .get("sec-websocket-protocol")
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn plan_for(&self, req: &worker::Request) -> Result<ProxyPlan> {
        self.plan.extend_from_request(req)
    }

    fn resolve_user_id(env: &Env) -> Result<String> {
        let Some(value) = Self::read_secret(
            env,
            &["UUID", "uuid", "ADMIN", "admin", "PASSWORD", "password"],
        ) else {
            return Ok("00000000-0000-4000-8000-000000000000".to_string());
        };

        if is_uuid_v4(&value) {
            return Ok(value.to_ascii_lowercase());
        }

        let key = Self::read_secret(env, &["KEY"]).unwrap_or_else(|| "vlpo-worker-rs".to_string());
        Ok(derive_uuid_v4(&(value + &key)))
    }

    fn resolve_ws_path(env: &Env) -> String {
        normalize_path(&Self::read_secret(env, &["WS_PATH"]).unwrap_or_else(|| "/".to_string()))
    }

    fn read_secret(env: &Env, keys: &[&str]) -> Option<String> {
        first_non_empty(
            &keys
                .iter()
                .map(|key| env.var(key).ok().map(|value| value.to_string()))
                .collect::<Vec<_>>(),
        )
    }
}
