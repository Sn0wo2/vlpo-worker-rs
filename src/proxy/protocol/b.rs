use worker::{Error, Result};

use crate::trace_log;

use super::super::types::InitialRequest;
use super::super::util::{format_uuid, parse_vless_addr};

impl InitialRequest {
    pub(super) fn parse_vless(chunk: &[u8], user_id: &str) -> Result<Self> {
        if chunk.len() < 24 {
            return Err(Error::RustError("invalid frame b".into()));
        }

        let version = chunk[0];
        let uuid = format_uuid(&chunk[1..17]);
        if !uuid.eq_ignore_ascii_case(user_id) {
            return Err(Error::RustError("invalid access token".into()));
        }

        let opt_len = chunk[17] as usize;
        let cmd_index = 18 + opt_len;
        if chunk.len() <= cmd_index {
            return Err(Error::RustError("missing route mode".into()));
        }

        let command = chunk[cmd_index];
        let is_udp = match command {
            0x01 => false,
            0x02 => true,
            _ => return Err(Error::RustError("unsupported route mode".into())),
        };

        if chunk.len() < cmd_index + 4 {
            return Err(Error::RustError("invalid route target".into()));
        }

        let port_index = cmd_index + 1;
        let port = u16::from_be_bytes([chunk[port_index], chunk[port_index + 1]]);
        let mut addr_index = port_index + 2;
        let hostname = parse_vless_addr(chunk, &mut addr_index)?;
        let payload = chunk[addr_index..].to_vec();

        trace_log!(
            "identity-header parsed: rev={} opt={} mode={} route={}:{} datagram={} payload={}B",
            version,
            opt_len,
            command,
            hostname,
            port,
            is_udp,
            payload.len()
        );

        Ok(Self {
            hostname,
            port,
            is_udp,
            payload,
            response_header: Some(vec![version, 0]),
        })
    }
}
