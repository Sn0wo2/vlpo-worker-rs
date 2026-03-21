mod a;
mod b;

use worker::Result;

use crate::trace_log;

use super::types::InitialRequest;
use super::util::looks_like_trojan;

impl InitialRequest {
    pub fn parse(chunk: &[u8], user_id: &str) -> Result<Self> {
        trace_log!("framing parse start: frame={}B", chunk.len());
        if looks_like_trojan(chunk) {
            return Self::parse_trojan(chunk, user_id);
        }

        Self::parse_vless(chunk, user_id)
    }
}
