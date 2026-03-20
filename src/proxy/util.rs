use std::net::{Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha224};
use worker::{Error, Result};

use super::types::SocketTarget;

pub const DNS_FALLBACK_HOST: &str = "8.8.4.4";
pub const DNS_FALLBACK_PORT: u16 = 53;
pub const SPEEDTEST_HOST: &str = "speed.cloudflare.com";

pub fn decode_early_data(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| Error::RustError(format!("invalid early data: {err}")))
}

pub fn parse_host_port(value: &str) -> Result<SocketTarget> {
    let trimmed = value.trim().trim_matches('/');

    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port) = rest
            .split_once(']')
            .ok_or_else(|| Error::RustError("invalid ipv6 host".into()))?;
        let has_explicit_port = port.starts_with(':');
        let port = port
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(443);
        return Ok(SocketTarget {
            host: host.to_string(),
            port,
            has_explicit_port,
        });
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok(SocketTarget {
                host: host.to_string(),
                port,
                has_explicit_port: true,
            });
        }
    }

    Ok(SocketTarget {
        host: trimmed.to_string(),
        port: 443,
        has_explicit_port: false,
    })
}

pub fn split_multi_value(value: &str) -> Vec<String> {
    value
        .replace('\n', ",")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub fn first_non_empty(values: &[Option<String>]) -> Option<String> {
    values
        .iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .cloned()
}

pub fn is_speedtest_host(host: &str) -> bool {
    host == SPEEDTEST_HOST || host.ends_with(&format!(".{SPEEDTEST_HOST}"))
}

pub fn looks_like_hash_auth(chunk: &[u8]) -> bool {
    chunk.len() >= 58 && chunk[56] == b'\r' && chunk[57] == b'\n'
}

pub fn sha224_hex(input: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(input.as_bytes());
    hex_encode(&hasher.finalize())
}

pub fn format_uuid(bytes: &[u8]) -> String {
    let hex = hex_encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub fn derive_uuid_v4(seed: &str) -> String {
    let first = md5::compute(seed.as_bytes());
    let first_hex = format!("{:x}", first);
    let second = md5::compute(first_hex[7..27].as_bytes());
    let mut bytes = second.0;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_uuid(&bytes)
}

pub fn is_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            14 => {
                if *byte != b'4' {
                    return false;
                }
            }
            19 => {
                if !matches!(*byte, b'8' | b'9' | b'a' | b'A' | b'b' | b'B') {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }

    true
}

pub fn parse_socks_addr(buf: &[u8], index: &mut usize) -> Result<String> {
    if buf.len() <= *index {
        return Err(Error::RustError("invalid socks addr type".into()));
    }

    let addr_type = buf[*index];
    *index += 1;

    match addr_type {
        0x01 => {
            if buf.len() < *index + 4 {
                return Err(Error::RustError("invalid ipv4 length".into()));
            }
            let addr = Ipv4Addr::new(
                buf[*index],
                buf[*index + 1],
                buf[*index + 2],
                buf[*index + 3],
            );
            *index += 4;
            Ok(addr.to_string())
        }
        0x03 => {
            if buf.len() <= *index {
                return Err(Error::RustError("invalid domain length".into()));
            }
            let len = buf[*index] as usize;
            *index += 1;
            if buf.len() < *index + len {
                return Err(Error::RustError("invalid domain bytes".into()));
            }
            let domain = std::str::from_utf8(&buf[*index..*index + len])
                .map_err(|_| Error::RustError("invalid domain utf8".into()))?;
            *index += len;
            Ok(domain.to_string())
        }
        0x04 => {
            if buf.len() < *index + 16 {
                return Err(Error::RustError("invalid ipv6 length".into()));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[*index..*index + 16]);
            *index += 16;
            Ok(Ipv6Addr::from(octets).to_string())
        }
        _ => Err(Error::RustError("unsupported socks address type".into())),
    }
}

pub fn parse_route_addr(buf: &[u8], index: &mut usize) -> Result<String> {
    if buf.len() <= *index {
        return Err(Error::RustError("invalid route address type".into()));
    }

    match buf[*index] {
        0x01 => {
            *index += 1;
            parse_socks_addr(&[&[0x01], &buf[*index..]].concat(), &mut 1_usize)
        }
        0x02 => {
            *index += 1;
            if buf.len() <= *index {
                return Err(Error::RustError("invalid route host length".into()));
            }
            let len = buf[*index] as usize;
            *index += 1;
            if buf.len() < *index + len {
                return Err(Error::RustError("invalid route host data".into()));
            }
            let value = std::str::from_utf8(&buf[*index..*index + len])
                .map_err(|_| Error::RustError("invalid route host text".into()))?;
            *index += len;
            Ok(value.to_string())
        }
        0x03 => {
            *index += 1;
            if buf.len() < *index + 16 {
                return Err(Error::RustError("invalid route ip data".into()));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[*index..*index + 16]);
            *index += 16;
            Ok(Ipv6Addr::from(octets).to_string())
        }
        _ => Err(Error::RustError("unsupported route address type".into())),
    }
}

pub fn build_socks5_connect_request(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];

    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ipv6.octets());
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > u8::MAX as usize {
            return Err(Error::RustError("hostname too long for tunnel".into()));
        }
        request.push(0x03);
        request.push(host_bytes.len() as u8);
        request.extend_from_slice(host_bytes);
    }

    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_uuid_produces_v4() {
        let uuid = derive_uuid_v4("example-seed");
        assert!(is_uuid_v4(&uuid));
    }

    #[test]
    fn parse_host_port_supports_basic_cases() {
        let direct = parse_host_port("example.com:8443").unwrap();
        assert_eq!(direct.host, "example.com");
        assert_eq!(direct.port, 8443);
        assert!(direct.has_explicit_port);

        let ipv6 = parse_host_port("[2606:4700::1]:2053").unwrap();
        assert_eq!(ipv6.host, "2606:4700::1");
        assert_eq!(ipv6.port, 2053);
        assert!(ipv6.has_explicit_port);

        let defaulted = parse_host_port("example.com").unwrap();
        assert_eq!(defaulted.host, "example.com");
        assert_eq!(defaulted.port, 443);
        assert!(!defaulted.has_explicit_port);
    }
}
