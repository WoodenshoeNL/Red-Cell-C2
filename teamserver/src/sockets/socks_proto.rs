//! SOCKS5 protocol codec functions for the socket relay subsystem.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tracing::warn;

use crate::TeamserverError;

use super::types::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, SOCKS_COMMAND_CONNECT,
    SOCKS_METHOD_NO_AUTH, SOCKS_METHOD_NOT_ACCEPTABLE, SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED, SOCKS_VERSION, SocksConnectRequest,
};

pub(super) async fn negotiate_socks5(stream: &mut TcpStream) -> Result<(), io::Error> {
    let version = read_u8(stream).await?;
    if version != SOCKS_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS version"));
    }

    let method_count = usize::from(read_u8(stream).await?);
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&SOCKS_METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, SOCKS_METHOD_NOT_ACCEPTABLE]).await?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS no-auth unavailable"));
    }

    stream.write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]).await
}

pub(super) async fn read_socks_connect_request(
    stream: &mut TcpStream,
) -> Result<SocksConnectRequest, io::Error> {
    let version = read_u8(stream).await?;
    let command = read_u8(stream).await?;
    let _reserved = read_u8(stream).await?;
    let atyp = read_u8(stream).await?;

    if version != SOCKS_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS request version"));
    }

    if command != SOCKS_COMMAND_CONNECT {
        stream
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                0,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "SOCKS command not supported"));
    }

    let address = match atyp {
        SOCKS_ATYP_IPV4 => read_exact_vec(stream, 4).await?,
        SOCKS_ATYP_IPV6 => read_exact_vec(stream, 16).await?,
        SOCKS_ATYP_DOMAIN => {
            let len = usize::from(read_u8(stream).await?);
            read_exact_vec(stream, len).await?
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS address type")),
    };

    let mut port_bytes = [0_u8; 2];
    stream.read_exact(&mut port_bytes).await?;

    Ok(SocksConnectRequest { atyp, address, port: u16::from_be_bytes(port_bytes) })
}

pub(super) async fn send_socks_connect_reply(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    reply: u8,
    atyp: u8,
    address: &[u8],
    port: u16,
) {
    if atyp == SOCKS_ATYP_DOMAIN && address.len() > usize::from(u8::MAX) {
        warn!(
            address_len = address.len(),
            "refusing to send invalid SOCKS5 domain reply with oversized address"
        );
        let failure_response =
            [SOCKS_VERSION, SOCKS_REPLY_GENERAL_FAILURE, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        let mut writer = writer.lock().await;
        let _ = writer.write_all(&failure_response).await;
        return;
    }

    let mut response = vec![SOCKS_VERSION, reply, 0, atyp];
    match atyp {
        SOCKS_ATYP_DOMAIN => {
            response.push(address.len() as u8);
            response.extend_from_slice(address);
        }
        _ => response.extend_from_slice(address),
    }
    response.extend_from_slice(&port.to_be_bytes());

    let mut writer = writer.lock().await;
    let _ = writer.write_all(&response).await;
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8, io::Error> {
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

async fn read_exact_vec(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, io::Error> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(super) fn write_len_prefixed_bytes(
    buf: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: value.len() })?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::super::types::SocketRelayError;

    async fn connected_write_half_and_reader() -> io::Result<(
        Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>,
        tokio::net::tcp::OwnedReadHalf,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server_stream, _) = listener.accept().await?;
        let client_stream = client.await.map_err(|error| io::Error::other(error.to_string()))??;
        let (_client_read, client_write) = client_stream.into_split();
        let (server_read, _server_write) = server_stream.into_split();
        Ok((Arc::new(tokio::sync::Mutex::new(client_write)), server_read))
    }

    /// Returns a connected pair of `TcpStream`s: `(client, server)`.
    async fn connected_stream_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client_task = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, _) = listener.accept().await?;
        let client = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        Ok((client, server))
    }

    #[tokio::test]
    async fn send_socks_connect_reply_rejects_oversized_domain_addresses() -> io::Result<()> {
        let (writer, mut reader) = connected_write_half_and_reader().await?;
        let oversized_domain = vec![b'a'; usize::from(u8::MAX) + 1];

        super::send_socks_connect_reply(
            &writer,
            super::SOCKS_REPLY_SUCCEEDED,
            super::SOCKS_ATYP_DOMAIN,
            &oversized_domain,
            8080,
        )
        .await;

        let mut response = [0_u8; 10];
        reader.read_exact(&mut response).await?;

        assert_eq!(
            response,
            [
                super::SOCKS_VERSION,
                super::SOCKS_REPLY_GENERAL_FAILURE,
                0,
                super::SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn send_socks_connect_reply_domain_success_path() -> io::Result<()> {
        let (writer, mut reader) = connected_write_half_and_reader().await?;
        let domain = b"example.com";

        super::send_socks_connect_reply(
            &writer,
            super::SOCKS_REPLY_SUCCEEDED,
            super::SOCKS_ATYP_DOMAIN,
            domain,
            443,
        )
        .await;

        // Expected: [VER=5, REP=0, RSV=0, ATYP=3, LEN=11, "example.com", PORT_HI=1, PORT_LO=187]
        let mut response = vec![0_u8; 4 + 1 + domain.len() + 2];
        reader.read_exact(&mut response).await?;

        assert_eq!(response[0], super::SOCKS_VERSION);
        assert_eq!(response[1], super::SOCKS_REPLY_SUCCEEDED);
        assert_eq!(response[2], 0); // reserved
        assert_eq!(response[3], super::SOCKS_ATYP_DOMAIN);
        assert_eq!(response[4], 11); // length prefix for "example.com"
        assert_eq!(&response[5..16], b"example.com");
        assert_eq!(&response[16..18], &443_u16.to_be_bytes());

        Ok(())
    }

    #[test]
    fn write_len_prefixed_bytes_normal_input() -> Result<(), SocketRelayError> {
        let mut buf = Vec::new();
        super::write_len_prefixed_bytes(&mut buf, b"data")?;
        assert_eq!(buf[..4], 4_u32.to_le_bytes());
        assert_eq!(&buf[4..], b"data");
        Ok(())
    }

    #[test]
    fn write_len_prefixed_bytes_empty_input() -> Result<(), SocketRelayError> {
        let mut buf = Vec::new();
        super::write_len_prefixed_bytes(&mut buf, &[])?;
        assert_eq!(buf, 0_u32.to_le_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_wrong_version() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=4 with one method (no-auth) — wrong SOCKS version.
        let client_task =
            tokio::spawn(
                async move { client.write_all(&[4, 1, super::SOCKS_METHOD_NO_AUTH]).await },
            );

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_err(), "negotiate_socks5 should return an error for version=4");
        assert_eq!(
            result.expect_err("expected Err").kind(),
            io::ErrorKind::InvalidData,
            "error kind should be InvalidData for wrong SOCKS version"
        );

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_happy_path() -> io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send a valid SOCKS5 greeting: version=5, 1 method, NO_AUTH (0x00).
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 1, super::SOCKS_METHOD_NO_AUTH]).await?;
            // Read the server's method-selection response.
            let mut response = [0_u8; 2];
            client.read_exact(&mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_ok(), "negotiate_socks5 should succeed for a valid NO_AUTH greeting");

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, super::SOCKS_METHOD_NO_AUTH],
            "server should reply [0x05, 0x00] selecting NO_AUTH"
        );

        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_auth_only_methods() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=5 with only method 0x02 (username/password) — no no-auth offered.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 1, 0x02]).await?;
            // Read the rejection response sent by negotiate_socks5.
            let mut response = [0_u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(
            result.is_err(),
            "negotiate_socks5 should return an error when no-auth is not offered"
        );
        assert_eq!(
            result.expect_err("expected Err").kind(),
            io::ErrorKind::PermissionDenied,
            "error kind should be PermissionDenied when only auth methods are offered"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, super::SOCKS_METHOD_NOT_ACCEPTABLE],
            "server should send [5, 0xFF] rejection to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_rejects_zero_methods() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send version=5, n_methods=0, no method bytes — adversarial/malformed greeting.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 0]).await?;
            // Read the rejection response sent by negotiate_socks5.
            let mut response = [0_u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(
            result.is_err(),
            "negotiate_socks5 should return an error when zero methods are advertised"
        );
        assert_eq!(
            result.expect_err("expected Err").kind(),
            io::ErrorKind::PermissionDenied,
            "error kind should be PermissionDenied when no methods are advertised"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [super::SOCKS_VERSION, super::SOCKS_METHOD_NOT_ACCEPTABLE],
            "server should send [5, 0xFF] rejection to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_rejects_non_connect_command() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send a BIND command (0x02) — not CONNECT.
        let client_task = tokio::spawn(async move {
            // version=5, command=BIND, reserved=0, atyp=IPv4, addr=0.0.0.0, port=0
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    2, // BIND
                    0,
                    super::SOCKS_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            // Read the COMMAND_NOT_SUPPORTED reply sent by read_socks_connect_request.
            let mut response = [0_u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response).await?;
            io::Result::Ok(response)
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "BIND command should be rejected");
        assert_eq!(
            result.expect_err("expected Err").kind(),
            io::ErrorKind::Unsupported,
            "error kind should be Unsupported for non-CONNECT command"
        );

        let response = client_task.await.map_err(|e| io::Error::other(e.to_string()))??;
        assert_eq!(
            response,
            [
                super::SOCKS_VERSION,
                super::SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                0,
                super::SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            "server should send COMMAND_NOT_SUPPORTED reply to client"
        );

        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_rejects_unknown_atyp() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send a CONNECT request with an unknown address type (0xFF).
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    0xFF, // unknown atyp
                ])
                .await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "unknown atyp should be rejected");
        assert_eq!(
            result.expect_err("expected Err").kind(),
            io::ErrorKind::InvalidData,
            "error kind should be InvalidData for unknown address type"
        );

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_ipv6_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let ipv6_addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let port: u16 = 443;

        let client_task = tokio::spawn(async move {
            let mut request =
                vec![super::SOCKS_VERSION, super::SOCKS_COMMAND_CONNECT, 0, super::SOCKS_ATYP_IPV6];
            request.extend_from_slice(&ipv6_addr);
            request.extend_from_slice(&port.to_be_bytes());
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "IPv6 CONNECT request should succeed: {:?}", result.err());
        let req = result.expect("unwrap");
        assert_eq!(req.atyp, super::SOCKS_ATYP_IPV6, "atyp should be IPv6");
        assert_eq!(req.address, ipv6_addr, "address should be the full 16-byte IPv6 address");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_domain_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let domain = b"example.com";
        let port: u16 = 443;

        let client_task = tokio::spawn(async move {
            let mut request = vec![
                super::SOCKS_VERSION,
                super::SOCKS_COMMAND_CONNECT,
                0,
                super::SOCKS_ATYP_DOMAIN,
                u8::try_from(domain.len()).expect("unwrap"),
            ];
            request.extend_from_slice(domain);
            request.extend_from_slice(&port.to_be_bytes());
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "DOMAIN CONNECT request should succeed: {:?}", result.err());
        let req = result.expect("unwrap");
        assert_eq!(req.atyp, super::SOCKS_ATYP_DOMAIN, "atyp should be DOMAIN");
        assert_eq!(req.address, domain.to_vec(), "address should be the domain bytes");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_accepts_zero_length_domain() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        let port: u16 = 80;

        let client_task = tokio::spawn(async move {
            let request = vec![
                super::SOCKS_VERSION,
                super::SOCKS_COMMAND_CONNECT,
                0,
                super::SOCKS_ATYP_DOMAIN,
                0, // zero-length domain
                0,
                80, // port 80 in big-endian
            ];
            client.write_all(&request).await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_ok(), "zero-length DOMAIN request should not panic: {:?}", result.err());
        let req = result.expect("unwrap");
        assert_eq!(req.atyp, super::SOCKS_ATYP_DOMAIN, "atyp should be DOMAIN");
        assert!(req.address.is_empty(), "address should be empty for zero-length domain");
        assert_eq!(req.port, port, "port should match");

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_truncated_version_only() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send only the version byte, then close — no method count.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION]).await?;
            client.shutdown().await
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_err(), "should error on truncated handshake (version only)");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_truncated_method_list() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Advertise 3 methods but send only 1 byte of method data, then close.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, 3, super::SOCKS_METHOD_NO_AUTH]).await?;
            client.shutdown().await
        });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_err(), "should error when method list is shorter than method_count");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_truncated_header() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send only 2 of the required 4 header bytes (version, command), then close.
        let client_task = tokio::spawn(async move {
            client.write_all(&[super::SOCKS_VERSION, super::SOCKS_COMMAND_CONNECT]).await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error on truncated request header");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_truncated_ipv4_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Full header but only 2 of 4 IPv4 address bytes, then close.
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    super::SOCKS_ATYP_IPV4,
                    127,
                    0, // only 2 of 4 address bytes
                ])
                .await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error on truncated IPv4 address");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_truncated_ipv6_address() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Full header but only 4 of 16 IPv6 address bytes, then close.
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    super::SOCKS_ATYP_IPV6,
                    0,
                    0,
                    0,
                    1, // only 4 of 16 bytes
                ])
                .await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error on truncated IPv6 address");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_truncated_domain_body() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Domain length says 11 but only 3 bytes follow, then close.
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    super::SOCKS_ATYP_DOMAIN,
                    11, // domain length = 11
                    b'f',
                    b'o',
                    b'o', // only 3 bytes
                ])
                .await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error on truncated domain body");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_missing_port_bytes() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Complete IPv4 address but no port bytes, then close.
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    super::SOCKS_ATYP_IPV4,
                    10,
                    0,
                    0,
                    1, // 4 address bytes — complete
                       // no port bytes
                ])
                .await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error when port bytes are missing");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn negotiate_socks5_empty_stream() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Send nothing and immediately close the connection.
        let client_task = tokio::spawn(async move { client.shutdown().await });

        let result = super::negotiate_socks5(&mut server).await;

        assert!(result.is_err(), "should error on empty stream");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn read_socks_connect_request_partial_port() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected_stream_pair().await?;

        // Complete IPv4 address but only 1 of 2 port bytes, then close.
        let client_task = tokio::spawn(async move {
            client
                .write_all(&[
                    super::SOCKS_VERSION,
                    super::SOCKS_COMMAND_CONNECT,
                    0,
                    super::SOCKS_ATYP_IPV4,
                    10,
                    0,
                    0,
                    1,    // 4 address bytes — complete
                    0x1F, // only 1 of 2 port bytes
                ])
                .await?;
            client.shutdown().await
        });

        let result = super::read_socks_connect_request(&mut server).await;

        assert!(result.is_err(), "should error when only 1 of 2 port bytes are sent");
        assert_eq!(result.expect_err("expected Err").kind(), io::ErrorKind::UnexpectedEof);

        let _ = client_task.await;
        Ok(())
    }
}
