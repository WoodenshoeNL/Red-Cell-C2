//! Tests for listener configuration parsing and validation:
//! HTTP, SMB, DNS, External, webhook, service, and REST API config.

use super::super::*;

use super::{HTTP_SMB_PROFILE, WEBHOOK_PROFILE};

#[test]
fn parses_listener_profile() {
    let profile = Profile::parse(HTTP_SMB_PROFILE).expect("listener profile should parse");

    assert_eq!(profile.listeners.http.len(), 1);
    assert_eq!(profile.listeners.smb.len(), 1);

    let http_listener = &profile.listeners.http[0];
    assert_eq!(http_listener.name, "teams profile - http");
    assert_eq!(http_listener.hosts, vec!["5pider.net"]);
    assert_eq!(http_listener.host_bind, "0.0.0.0");
    assert_eq!(http_listener.host_rotation, "round-robin");
    assert_eq!(http_listener.port_bind, 443);
    assert_eq!(http_listener.port_conn, Some(443));
    assert!(!http_listener.secure);
    assert_eq!(http_listener.uris, vec!["/Collector/2.0/settings/"]);
    assert_eq!(http_listener.headers.len(), 7);
    assert_eq!(http_listener.host_header, None);
    assert_eq!(http_listener.response.as_ref().map(|response| response.headers.len()), Some(8));
    assert_eq!(http_listener.response.as_ref().and_then(|response| response.body.as_deref()), None);

    let smb_listener = &profile.listeners.smb[0];
    assert_eq!(smb_listener.name, "Pivot - Smb");
    assert_eq!(smb_listener.pipe_name, "demon_pipe");
}

#[test]
fn parses_webhook_profile() {
    let profile = Profile::parse(WEBHOOK_PROFILE).expect("webhook profile should parse");

    let webhook = profile.webhook.and_then(|config| config.discord);
    assert_eq!(
        webhook.as_ref().map(|discord| discord.url.as_str()),
        Some("https://discord.com/api/webhooks/000000000000000000/test-token")
    );
    assert_eq!(webhook.as_ref().and_then(|discord| discord.user.as_deref()), Some("Havoc"));
}

#[test]
fn webhook_retry_defaults_when_omitted() {
    let profile = Profile::parse(WEBHOOK_PROFILE).expect("profile should parse");
    let discord =
        profile.webhook.and_then(|w| w.discord).expect("discord config should be present");
    assert_eq!(discord.max_retries, 3, "default MaxRetries should be 3");
    assert_eq!(discord.retry_base_delay_secs, 1, "default RetryBaseDelaySecs should be 1");
}

#[test]
fn webhook_retry_parses_explicit_values() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
              }
            }

            WebHook {
              Discord {
                Url = "https://discord.com/api/webhooks/123/token"
                MaxRetries = 5
                RetryBaseDelaySecs = 2
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with explicit retry settings should parse");

    let discord =
        profile.webhook.and_then(|w| w.discord).expect("discord config should be present");
    assert_eq!(discord.max_retries, 5);
    assert_eq!(discord.retry_base_delay_secs, 2);
}

#[test]
fn webhook_retry_zero_disables_retries() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
              }
            }

            WebHook {
              Discord {
                Url = "https://discord.com/api/webhooks/123/token"
                MaxRetries = 0
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with MaxRetries=0 should parse");

    let discord =
        profile.webhook.and_then(|w| w.discord).expect("discord config should be present");
    assert_eq!(discord.max_retries, 0, "MaxRetries=0 should be preserved");
}

#[test]
fn parses_trusted_proxy_peers_from_single_value_or_list() {
    let single = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = "127.0.0.1/32"
            }
            "#,
    )
    .expect("profile with single trusted proxy peer should parse");
    assert_eq!(single.demon.trusted_proxy_peers, vec!["127.0.0.1/32"]);

    let list = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["127.0.0.1", "10.0.0.0/8"]
            }
            "#,
    )
    .expect("profile with trusted proxy peer list should parse");
    assert_eq!(list.demon.trusted_proxy_peers, vec!["127.0.0.1", "10.0.0.0/8"]);
}

#[test]
fn parses_listener_tls_certificate_paths() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "https listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "/tmp/server.crt"
                  Key = "/tmp/server.key"
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("inline HTTPS listener profile should parse");

    let listener = &profile.listeners.http[0];
    let cert = listener.cert.as_ref().expect("certificate block should be present");

    assert!(listener.secure);
    assert_eq!(cert.cert, "/tmp/server.crt");
    assert_eq!(cert.key, "/tmp/server.key");
}

#[test]
fn parses_listener_response_body() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "body listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080

                Response {
                  Headers = ["Server: nginx"]
                  Body = "{\"status\":\"ok\"}"
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("inline listener profile should parse");

    let response =
        profile.listeners.http[0].response.as_ref().expect("response block should be present");

    assert_eq!(response.body.as_deref(), Some("{\"status\":\"ok\"}"));
}

#[test]
fn parses_http_listener_host_header() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "redirected listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
                HostHeader = "front.example"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.listeners.http[0].host_header.as_deref(), Some("front.example"));
}

#[test]
fn parses_http_listener_with_proxy_block() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "proxied listener"
                Hosts = ["proxy.local"]
                HostBind = "0.0.0.0"
                HostRotation = "round-robin"
                PortBind = 8443

                Proxy {
                  Host = "squid.internal"
                  Port = 3128
                  Username = "proxyuser"
                  Password = "proxysecret"
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with proxy block should parse");

    assert_eq!(profile.listeners.http.len(), 1);
    let listener = &profile.listeners.http[0];
    assert_eq!(listener.name, "proxied listener");

    let proxy = listener.proxy.as_ref().expect("proxy block should be present");
    assert_eq!(proxy.host, "squid.internal");
    assert_eq!(proxy.port, 3128);
    assert_eq!(proxy.username.as_deref(), Some("proxyuser"));
    assert_eq!(proxy.password.as_deref().map(String::as_str), Some("proxysecret"));

    // Verify the From conversion to the domain type sets expected defaults.
    let domain_proxy: crate::HttpListenerProxyConfig = proxy.clone().into();
    assert!(domain_proxy.enabled);
    assert_eq!(domain_proxy.proxy_type.as_deref(), Some("http"));
    assert_eq!(domain_proxy.host, "squid.internal");
    assert_eq!(domain_proxy.port, 3128);
    assert_eq!(domain_proxy.username.as_deref(), Some("proxyuser"));
    assert_eq!(domain_proxy.password.as_deref().map(String::as_str), Some("proxysecret"));
}

#[test]
fn parses_http_listener_with_proxy_block_no_credentials() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "anon proxy listener"
                Hosts = ["proxy.local"]
                HostBind = "0.0.0.0"
                HostRotation = "round-robin"
                PortBind = 9090

                Proxy {
                  Host = "transparent.internal"
                  Port = 8080
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with credential-less proxy block should parse");

    let proxy = profile.listeners.http[0].proxy.as_ref().expect("proxy block should be present");
    assert_eq!(proxy.host, "transparent.internal");
    assert_eq!(proxy.port, 8080);
    assert_eq!(proxy.username, None);
    assert_eq!(proxy.password, None);
}

#[test]
fn rejects_empty_http_listener_host_header() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
                HostHeader = "   "
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("HostHeader")));
}

#[test]
fn rejects_http_listener_with_blank_certificate_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "   "
                  Key = "/tmp/server.key"
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| {
        message.contains("Listeners.Http \"edge\"")
            && message.contains("non-empty Cert and Key paths")
    }));
}

#[test]
fn rejects_http_listener_with_blank_certificate_key_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "/tmp/server.crt"
                  Key = "   "
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| {
        message.contains("Listeners.Http \"edge\"")
            && message.contains("non-empty Cert and Key paths")
    }));
}

#[test]
fn rejects_invalid_trusted_proxy_peer_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              TrustedProxyPeers = ["bad-value", "10.0.0.0/33", "   "]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("TrustedProxyPeers")));
}

#[test]
fn accepts_ipv6_trusted_proxy_peers() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["::1", "2001:db8::/128"]
            }
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("IPv6 trusted proxy peers should validate");
}

#[test]
fn rejects_ipv6_trusted_proxy_peer_with_invalid_prefix_length() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["2001:db8::/129"]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| {
        message.contains("TrustedProxyPeers")
            && message.contains("2001:db8::/129")
            && message.contains("invalid prefix length")
    }));
}

#[test]
fn accepts_service_block_with_warning() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Service {
              Endpoint = "service-endpoint"
              Password = "service-password"
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("profile with Service block should validate successfully");
    assert!(profile.service.is_some());
}

#[test]
fn accepts_valid_external_listener_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              External {
                Name = "bridge"
                Endpoint = "/svc"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("profile with External listener should validate successfully");
    assert_eq!(profile.listeners.external.len(), 1);
    assert_eq!(profile.listeners.external[0].name, "bridge");
    assert_eq!(profile.listeners.external[0].endpoint, "/svc");
}

#[test]
fn rejects_external_listener_missing_endpoint_slash() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              External {
                Name = "bridge"
                Endpoint = "svc"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("endpoint without leading / should fail");
    assert!(error.to_string().contains("must start with '/'"), "unexpected error: {error}");
}

#[test]
fn rejects_invalid_dns_listener_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Dns {
                Name = ""
                Domain = ""
                PortBind = 0
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Listeners.Dns.Name must not be empty")),
        "expected name-empty error; got: {:?}",
        error.errors
    );
    assert!(
        error.errors.iter().any(|m| m.contains("must define Domain")),
        "expected domain-empty error; got: {:?}",
        error.errors
    );
    assert!(
        error.errors.iter().any(|m| m.contains("must define a PortBind greater than zero")),
        "expected port-bind-zero error; got: {:?}",
        error.errors
    );
}

#[test]
fn parses_rest_api_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 120
              key "automation" {
                Value = "secret-admin"
              }
              key "reporting" {
                Value = "secret-analyst"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let api = profile.api.expect("api config should exist");
    assert_eq!(api.rate_limit_per_minute, 120);
    assert_eq!(api.keys["automation"].value, "secret-admin");
    assert_eq!(api.keys["automation"].role, OperatorRole::Admin);
    assert_eq!(api.keys["reporting"].role, OperatorRole::Analyst);
}

#[test]
fn validates_rest_api_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 0
              key "automation" {
                Value = ""
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("RateLimitPerMinute")));
    assert!(error.errors.iter().any(|message| message.contains("non-empty Value")));
}

#[test]
fn rejects_rest_api_configuration_without_keys() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 120
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Api must define at least one key"))
    );
}

/// Build a minimal valid profile with the given Discord webhook URL for validation tests.
fn profile_with_discord_url(url: &str) -> Profile {
    Profile::parse(&format!(
        r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}
            Operators {{
              user "neo" {{
                Password = "pw"
              }}
            }}
            Demon {{}}
            WebHook {{
              Discord {{
                Url = "{url}"
              }}
            }}
            "#
    ))
    .expect("profile should parse")
}

#[test]
fn accepts_valid_discord_webhook_urls() {
    let valid = [
        "https://discord.com/api/webhooks/123/token",
        "https://discordapp.com/api/webhooks/123/token",
        "https://hooks.discord.com/services/T/B/x",
        "https://hooks.discordapp.com/services/T/B/x",
    ];
    for url in valid {
        let profile = profile_with_discord_url(url);
        assert!(
            profile.validate().is_ok(),
            "expected valid for {url}: {:?}",
            profile.validate().expect_err("expected Err")
        );
    }
}

#[test]
fn accepts_discord_webhook_url_with_port() {
    let profile = profile_with_discord_url("https://discord.com:443/api/webhooks/123/token");
    assert!(
        profile.validate().is_ok(),
        "discord.com with explicit port 443 should be accepted: {:?}",
        profile.validate().expect_err("expected Err")
    );
}

#[test]
fn rejects_discord_webhook_url_with_host_in_port() {
    // An attacker might try `evil.com:discord.com` hoping the validator
    // sees "discord.com" as the host. The colon-split must yield "evil.com".
    let profile = profile_with_discord_url("https://evil.com:discord.com/hook");
    let err = profile.validate().expect_err("evil.com disguised via port field must be rejected");
    assert!(
        err.errors.iter().any(|m| m.contains("permitted Discord hostname")),
        "error should mention hostname restriction: {err}"
    );
}

#[test]
fn rejects_http_discord_webhook_url() {
    let profile = profile_with_discord_url("http://discord.com/api/webhooks/123/token");
    let err = profile.validate().expect_err("http webhook URL must be rejected");
    assert!(
        err.errors.iter().any(|m| m.contains("https://")),
        "error should mention https requirement: {err}"
    );
}

#[test]
fn rejects_non_discord_webhook_url() {
    for url in [
        "https://evil.example.com/hook",
        "https://169.254.169.254/latest/meta-data/",
        "https://localhost/hook",
    ] {
        let profile = profile_with_discord_url(url);
        let err = profile.validate().expect_err(&format!("SSRF URL {url} must be rejected"));
        assert!(
            err.errors.iter().any(|m| m.contains("permitted Discord hostname")),
            "error should mention hostname restriction for {url}: {err}"
        );
    }
}

#[test]
fn rejects_empty_discord_webhook_url() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }
            Operators {
              user "neo" {
                Password = "pw"
              }
            }
            Demon {}
            WebHook {
              Discord {
                Url = ""
              }
            }
            "#,
    )
    .expect("profile should parse");
    let err = profile.validate().expect_err("empty webhook URL must be rejected");
    assert!(err.errors.iter().any(|m| m.contains("must not be empty")));
}

#[test]
fn rejects_smb_listener_with_empty_pipe_name() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Smb {
                Name = "pivot"
                PipeName = "   "
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error
            .errors
            .iter()
            .any(|m| m.contains("Listeners.Smb \"pivot\"") && m.contains("PipeName")),
        "expected PipeName error; got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_smb_listener_with_empty_name() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Smb {
                Name = ""
                PipeName = "demo_pipe"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Listeners.Smb.Name must not be empty")),
        "expected name-empty error; got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_service_block_with_empty_endpoint() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Service {
              Endpoint = ""
              Password = "service-password"
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Service.Endpoint must not be empty")),
        "expected endpoint error; got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_service_block_with_empty_password() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Service {
              Endpoint = "service-endpoint"
              Password = ""
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Service.Password must not be empty")),
        "expected password error; got: {:?}",
        error.errors
    );
}

#[test]
fn accepts_valid_dns_listener_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Dns {
                Name = "dns-c2"
                Domain = "c2.example.com"
                PortBind = 53
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("valid DNS listener should pass validation");
    assert_eq!(profile.listeners.dns.len(), 1);
    assert_eq!(profile.listeners.dns[0].name, "dns-c2");
    assert_eq!(profile.listeners.dns[0].domain, "c2.example.com");
    assert_eq!(profile.listeners.dns[0].port_bind, 53);
}

#[test]
fn service_config_debug_redacts_password() {
    let config = ServiceConfig {
        endpoint: "https://bridge.example.com".to_owned(),
        password: "super-secret-password".to_owned(),
    };

    let debug = format!("{config:?}");

    assert!(debug.contains("ServiceConfig"));
    assert!(debug.contains("endpoint: \"https://bridge.example.com\""));
    assert!(debug.contains("password: \"[redacted]\""));
    assert!(!debug.contains("super-secret-password"));
}

#[test]
fn api_key_config_debug_redacts_value() {
    let config = ApiKeyConfig { value: "rc2-api-key-secret".to_owned(), role: OperatorRole::Admin };

    let debug = format!("{config:?}");

    assert!(debug.contains("ApiKeyConfig"));
    assert!(debug.contains("value: \"[redacted]\""));
    assert!(debug.contains("role: Admin"));
    assert!(!debug.contains("rc2-api-key-secret"));
}

#[test]
fn rejects_smb_listener_with_empty_name_and_pipe_name() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Smb {
                Name = ""
                PipeName = ""
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Smb.Name")),
        "expected Smb.Name error, got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|message| message.contains("PipeName")),
        "expected PipeName error, got: {error:?}"
    );
}

#[test]
fn rejects_http_listener_cert_file_not_found() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "/nonexistent/cert.pem"
                  Key = "/nonexistent/key.pem"
                }
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Listeners.Http \"edge\" cert file not found")),
        "expected listener cert not found error; got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|m| m.contains("Listeners.Http \"edge\" key file not found")),
        "expected listener key not found error; got: {error:?}"
    );
}

#[test]
fn rejects_invalid_doh_domain() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                DoHDomain = "not a domain!"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("DoHDomain") && m.contains("not a valid FQDN")),
        "expected DoHDomain FQDN error; got: {error:?}"
    );
}

#[test]
fn accepts_valid_doh_domain() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                DoHDomain = "c2.example.com"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("profile with valid DoHDomain should pass");
}

#[test]
fn rejects_duplicate_listener_ports() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "first"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
              }

              Http {
                Name = "second"
                Hosts = ["listener2.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("port 443 conflicts")),
        "expected port conflict error; got: {error:?}"
    );
}

#[test]
fn rejects_dns_listener_port_conflict_with_http() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "web"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
              }

              Dns {
                Name = "dns-c2"
                Domain = "c2.example.com"
                PortBind = 8080
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Dns") && m.contains("port 8080 conflicts")),
        "expected DNS/HTTP port conflict error; got: {error:?}"
    );
}

#[test]
fn accepts_listeners_on_different_ports() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "web"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
              }

              Http {
                Name = "alt"
                Hosts = ["listener2.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8443
              }

              Dns {
                Name = "dns-c2"
                Domain = "c2.example.com"
                PortBind = 53
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("listeners on different ports should pass");
}
