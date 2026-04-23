use tokio::net::TcpStream;

use super::super::{sample_agent, test_manager};

/// The SOCKS5 server must bind exclusively to the loopback interface (`127.0.0.1`) and must
/// not advertise itself on any external or wildcard address (`0.0.0.0`).
///
/// The SOCKS5 relay uses `NO_AUTH` by design, so loopback-only binding is the sole access
/// control layer for this tunnel.
#[tokio::test]
async fn socks5_server_binds_to_localhost_only() -> std::io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| std::io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let start_msg = manager
        .add_socks_server(0xDEAD_BEEF, "0")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    assert!(
        start_msg.contains("127.0.0.1:"),
        "SOCKS5 server must report a 127.0.0.1 bind address, got: {start_msg}"
    );
    assert!(
        !start_msg.contains("0.0.0.0:"),
        "SOCKS5 server must not bind to the wildcard address, got: {start_msg}"
    );

    let bound_port: u16 = start_msg
        .trim_start_matches("Started SOCKS5 server on 127.0.0.1:")
        .trim()
        .parse()
        .map_err(|e| {
            std::io::Error::other(format!("could not parse port from '{start_msg}': {e}"))
        })?;

    let non_loopback_ip: Option<std::net::IpAddr> = (|| {
        use std::net::UdpSocket;
        let udp = UdpSocket::bind("0.0.0.0:0").ok()?;
        udp.connect("192.0.2.1:80").ok()?;
        let ip = udp.local_addr().ok()?.ip();
        if ip.is_loopback() { None } else { Some(ip) }
    })();

    if let Some(ext_ip) = non_loopback_ip {
        let external_connect = TcpStream::connect(format!("{ext_ip}:{bound_port}")).await;
        assert!(
            external_connect.is_err(),
            "connection to {ext_ip}:{bound_port} must be refused because SOCKS5 binds only to \
             loopback"
        );
    }

    TcpStream::connect(format!("127.0.0.1:{bound_port}")).await.map_err(|e| {
        std::io::Error::other(format!("loopback connection to 127.0.0.1:{bound_port} failed: {e}"))
    })?;

    Ok(())
}
