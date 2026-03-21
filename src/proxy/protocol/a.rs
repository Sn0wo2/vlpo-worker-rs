use worker::{Error, Result};

use crate::trace_log;

use super::super::types::InitialRequest;
use super::super::util::{parse_socks_addr, sha224_hex};

impl InitialRequest {
    pub(super) fn parse_trojan(chunk: &[u8], user_id: &str) -> Result<Self> {
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
}
