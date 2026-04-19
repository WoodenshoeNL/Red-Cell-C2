use std::collections::HashSet;

use super::super::*;
use super::helpers::{
    build_dns_cname_query, build_dns_query, build_dns_txt_query, dns_answer_rdata,
    dns_answer_rr_type, dns_upload_qname, parse_dns_txt_answer, spawn_test_dns_listener,
};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::timeout;

use super::super::super::MAX_DEMON_INIT_ATTEMPTS_PER_IP;
use super::super::super::dns::{
    DNS_HEADER_LEN, DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT, dns_wire_domain_from_ascii_payload,
    parse_dns_query, spawn_dns_listener_runtime,
};

#[tokio::test]
async fn dns_listener_starts_and_responds_to_unknown_queries_with_refused() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-test".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    // Brief delay for the listener to bind
    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Send a query for an unrecognised C2 domain — expect REFUSED
    let packet = build_dns_txt_query(0x1111, "something.other.domain.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    // RCODE should be 5 (REFUSED)
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_runtime_exits_when_shutdown_started_before_first_poll() {
    let shutdown = ShutdownController::new();
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-shutdown-prepoll".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        shutdown.clone(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
    .expect("dns runtime should start");

    shutdown.initiate();

    let result = timeout(Duration::from_millis(200), runtime)
        .await
        .expect("dns runtime should observe pre-existing shutdown");
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn dns_listener_a_query_returns_ipv4_rdata_when_payload_fits() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-a-rdata".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["A".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Download poll via A query — payload is "wait" encoded into 4 bytes.
    let qname = "0-deadbeef.dn.c2.example.com";
    let packet = build_dns_query(0xA001, qname, DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 0, "expected NOERROR");

    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);

    let parsed = parse_dns_query(&packet).expect("query should parse");
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_A),
        "answer RR must be A for an A query"
    );
    let rdata = dns_answer_rdata(&buf, parsed.qname_raw.len()).expect("rdata present");
    assert_eq!(rdata.len(), 4, "A record rdata must be 4 bytes");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_rate_limits_demon_init_per_source_ip() {
    let port = free_udp_port();
    let domain = "c2.example.com".to_owned();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-init-limit".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.clone(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, registry) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for attempt in 0..=MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x3000_0000 + attempt;
        let payload = valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24));
        let chunks: Vec<&[u8]> = payload.chunks(39).collect();
        let total = u16::try_from(chunks.len()).expect("chunk count should fit in u16");
        let expected_txt = if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP { "ack" } else { "err" };

        for (seq, chunk) in chunks.iter().enumerate() {
            let qname = dns_upload_qname(
                agent_id,
                u16::try_from(seq).expect("chunk index should fit in u16"),
                total,
                chunk,
                &domain,
            );
            let packet = build_dns_txt_query(0x4000 + seq as u16, &qname);
            client.send(&packet).await.expect("send failed");

            let mut buf = vec![0u8; 1024];
            tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                .await
                .expect("no response received")
                .expect("recv failed");

            let txt = parse_dns_txt_answer(&buf).expect("TXT answer should parse");
            let is_last = seq + 1 == chunks.len();
            if is_last {
                assert_eq!(txt, expected_txt);
            } else {
                assert_eq!(txt, "ok");
            }
        }

        if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            assert!(registry.get(agent_id).await.is_some());
        } else {
            assert!(registry.get(agent_id).await.is_none());
        }
    }
    handle.abort();
}

#[tokio::test]
async fn dns_listener_refuses_query_types_not_enabled_by_config() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-txt-only".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_query(0x3333, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_responds_to_a_burst_of_udp_queries() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-burst".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for id in 0x5000..0x5010 {
        let packet = build_dns_txt_query(id, "burst.other.domain.com");
        client.send(&packet).await.expect("send failed");
    }

    let mut buf = vec![0u8; 512];
    let mut seen_ids = HashSet::new();
    for _ in 0x5000..0x5010 {
        let received = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");
        assert!(received >= DNS_HEADER_LEN, "response too short");
        seen_ids.insert(u16::from_be_bytes([buf[0], buf[1]]));
        assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    }
    assert_eq!(seen_ids.len(), 16, "every burst query should receive a response");

    handle.abort();
}

#[tokio::test]
async fn dns_listener_accepts_cname_queries_when_enabled() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-cname".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_cname_query(0x4444, "0-deadbeef.dn.c2.example.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);
    let parsed = parse_dns_query(&packet).expect("query should parse");
    let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
    let echoed_qtype =
        u16::from_be_bytes([buf[question_qtype_offset], buf[question_qtype_offset + 1]]);
    assert_eq!(echoed_qtype, DNS_TYPE_CNAME);
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_CNAME),
        "answer RR must be CNAME when the query is CNAME"
    );
    let expected_rdata =
        dns_wire_domain_from_ascii_payload("wait").expect("wait encodes as CNAME RDATA");
    assert_eq!(dns_answer_rdata(&buf, parsed.qname_raw.len()), Some(expected_rdata));
    handle.abort();
}

/// When multiple record types are enabled, each successful C2 poll must answer with an RR
/// whose TYPE matches the question QTYPE (not always TXT).
#[tokio::test]
async fn dns_listener_multi_record_types_each_answer_rr_matches_query_qtype() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-multi-qtype".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned(), "A".to_owned(), "CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let qname = "0-deadbeef.dn.c2.example.com";
    for (id, qtype) in [(0x6001u16, DNS_TYPE_TXT), (0x6002, DNS_TYPE_A), (0x6003, DNS_TYPE_CNAME)] {
        let packet = build_dns_query(id, qname, qtype);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR for qtype {qtype}");
        let parsed = parse_dns_query(&packet).expect("query should parse");
        assert_eq!(
            dns_answer_rr_type(&buf, parsed.qname_raw.len()),
            Some(qtype),
            "answer RR TYPE must match QTYPE {qtype}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn dns_listener_start_rejects_unsupported_record_types() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-invalid-type".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["MX".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    };

    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let error = match spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    )
    .await
    {
        Ok(_) => panic!("start should fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("unsupported DNS record type configuration"),
        "unexpected error: {error}"
    );
}
