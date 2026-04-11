//! Protocol compatibility: Specter `DEMON_INIT` with versioned listener `InitSecrets`.

use red_cell::{AgentRegistry, Database, DemonPacketParser, ParsedDemonPacket};
use red_cell_common::crypto::{derive_session_keys_for_version, generate_agent_crypto_material};
use specter::protocol::{AgentMetadata, build_init_packet};

fn sample_metadata() -> AgentMetadata {
    AgentMetadata {
        hostname: String::from("win-host"),
        username: String::from("operator"),
        domain_name: String::from("WORKGROUP"),
        internal_ip: String::from("127.0.0.1"),
        process_path: String::from("C:\\specter.exe"),
        process_pid: 123,
        process_tid: 0,
        process_ppid: 1,
        process_arch: 2,
        elevated: false,
        base_address: 0,
        os_major: 10,
        os_minor: 0,
        os_product_type: 1,
        os_service_pack: 0,
        os_build: 19045,
        os_arch: 9,
        sleep_delay: 5_000,
        sleep_jitter: 0,
        kill_date: 0,
        working_hours: 0,
    }
}

#[tokio::test]
async fn versioned_demon_init_parses_and_derives_matching_session_keys() {
    let database = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(database);
    let secret = b"versioned-secret-v1".to_vec();
    let secrets = vec![(1_u8, secret.clone())];
    let parser = DemonPacketParser::with_init_secrets(registry, secrets);

    let raw = generate_agent_crypto_material().expect("raw keys");
    let agent_id = 0xAABB_CCDD_u32;
    let version = 1_u8;
    let packet =
        build_init_packet(agent_id, &raw, &sample_metadata(), Some(version)).expect("build init");

    let expected = derive_session_keys_for_version(
        &raw.key,
        &raw.iv,
        version,
        &[(version, secret.as_slice())],
    )
    .expect("derive expected session keys");

    let parsed = parser
        .parse(&packet, "10.0.0.1")
        .await
        .expect("teamserver parser accepts versioned Specter init");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected Init, got {parsed:?}");
    };

    assert_eq!(init.agent.encryption.aes_key.as_slice(), &expected.key);
    assert_eq!(init.agent.encryption.aes_iv.as_slice(), &expected.iv);
}
