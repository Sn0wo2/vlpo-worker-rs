use worker::{Error, Result};

use crate::trace_log;

use super::types::InitialRequest;
use super::util::{
    format_uuid, looks_like_hash_auth, parse_route_addr, parse_socks_addr, sha224_hex,
};

impl InitialRequest {
    pub fn parse(chunk: &[u8], user_id: &str) -> Result<Self> {
        trace_log!("framing parse start: frame={}B", chunk.len());
        if looks_like_hash_auth(chunk) {
            trace_log!("framing profile: hashed-auth");
            Self::parse_hash_auth(chunk, user_id)
        } else {
            trace_log!("framing profile: identity-header");
            Self::parse_identity_header(chunk, user_id)
        }
    }

    fn parse_hash_auth(chunk: &[u8], user_id: &str) -> Result<Self> {
        if chunk.len() < 58 {
            return Err(Error::RustError("invalid frame a".into()));
        }

        if &chunk[56..58] != b"\r\n" {
            return Err(Error::RustError("invalid frame a header".into()));
        }

        let expected = sha224_hex(user_id);
        let provided = std::str::from_utf8(&chunk[..56])
            .map_err(|_| Error::RustError("invalid frame a token".into()))?;
        if provided != expected {
            return Err(Error::RustError("invalid access token".into()));
        }

        let socks = &chunk[58..];
        if socks.len() < 6 {
            return Err(Error::RustError("invalid frame a payload".into()));
        }
        if socks[0] != 0x01 {
            return Err(Error::RustError("unsupported stream mode".into()));
        }

        let mut index = 1;
        let hostname = parse_socks_addr(socks, &mut index)?;
        if socks.len() < index + 2 {
            return Err(Error::RustError("missing route port".into()));
        }

        let port = u16::from_be_bytes([socks[index], socks[index + 1]]);
        index += 2;
        if socks.len() < index + 2 {
            return Err(Error::RustError("invalid frame delimiter".into()));
        }

        let payload = socks[index + 2..].to_vec();
        trace_log!(
            "hashed-auth parsed: route={}:{} payload={}B",
            hostname,
            port,
            payload.len()
        );
        Ok(Self {
            hostname,
            port,
            is_udp: false,
            payload,
            response_header: None,
        })
    }

    fn parse_identity_header(chunk: &[u8], user_id: &str) -> Result<Self> {
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
        let hostname = parse_route_addr(chunk, &mut addr_index)?;
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
