use super::super::download;
use super::super::types::DownloadResult;
use crate::output::TextRender;

// ── DownloadResult ────────────────────────────────────────────────────────────

#[test]
fn download_result_render_contains_all_fields() {
    let r = DownloadResult { id: "p2".to_owned(), dst: "./out.exe".to_owned(), size_bytes: 65536 };
    let rendered = r.render_text();
    assert!(rendered.contains("p2"));
    assert!(rendered.contains("./out.exe"));
    assert!(rendered.contains("65536"));
}

#[test]
fn download_result_serialises_correctly() {
    let r = DownloadResult { id: "p3".to_owned(), dst: "/tmp/x.bin".to_owned(), size_bytes: 1 };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["id"], "p3");
    assert_eq!(v["dst"], "/tmp/x.bin");
    assert_eq!(v["size_bytes"], 1);
}

// ── download writes file to disk ──────────────────────────────────────────────

#[tokio::test]
async fn download_writes_bytes_to_path() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let payload_bytes = b"HELLO WORLD PAYLOAD";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/test-id/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload_bytes.as_ref()))
        .mount(&server)
        .await;

    let cfg = crate::config::ResolvedConfig {
        server: server.uri(),
        token: "tok".to_owned(),
        timeout: 5,
        tls_mode: crate::config::TlsMode::SystemRoots,
    };
    let client = crate::client::ApiClient::new(&cfg).expect("client");

    let tmp = tempfile::tempdir().expect("tempdir");
    let dst = tmp.path().join("payload.bin");
    let dst_str = dst.to_str().expect("valid path");

    let result = download::download(&client, "test-id", dst_str).await.expect("download");

    assert_eq!(result.id, "test-id");
    assert_eq!(result.dst, dst_str);
    assert_eq!(result.size_bytes, payload_bytes.len() as u64);
    assert_eq!(std::fs::read(&dst).expect("read file"), payload_bytes);
}

#[tokio::test]
async fn download_creates_parent_directory() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/nested-id/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"DATA".as_ref()))
        .mount(&server)
        .await;

    let cfg = crate::config::ResolvedConfig {
        server: server.uri(),
        token: "tok".to_owned(),
        timeout: 5,
        tls_mode: crate::config::TlsMode::SystemRoots,
    };
    let client = crate::client::ApiClient::new(&cfg).expect("client");

    let tmp = tempfile::tempdir().expect("tempdir");
    let nested = tmp.path().join("a").join("b").join("payload.exe");
    let dst_str = nested.to_str().expect("valid path");

    let result = download::download(&client, "nested-id", dst_str).await.expect("download");

    assert!(nested.exists(), "download must create parent directories");
    assert_eq!(result.size_bytes, 4);
}
