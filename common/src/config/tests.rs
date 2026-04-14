use super::*;

use super::profile::is_valid_fqdn;
use zeroize::Zeroizing;

const HAVOC_PROFILE: &str = r#"
        Teamserver {
          Host = "0.0.0.0"
          Port = 40056

          Build {
            Nasm = "/usr/bin/nasm"
          }
        }

        Operators {
          user "Neo" {
            Password = "password1234"
            Role = "Admin"
          }

          user "Trinity" {
            Password = "followthewhiterabbit"
            Role = "Operator"
          }
        }

        Demon {
          Sleep = 2
          Jitter = 15
          TrustXForwardedFor = false
          TrustedProxyPeers = ["127.0.0.1/32"]

          Injection {
            Spawn64 = "C:\\Windows\\System32\\notepad.exe"
          }
        }

    "#;

const HTTP_SMB_PROFILE: &str = r#"
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
            Name = "teams profile - http"
            Hosts = ["5pider.net"]
            HostBind = "0.0.0.0"
            HostRotation = "round-robin"
            PortBind = 443
            PortConn = 443
            Headers = [
              "A: 1", "B: 2", "C: 3", "D: 4", "E: 5", "F: 6", "G: 7"
            ]
            Uris = ["/Collector/2.0/settings/"]
            Secure = false

            Response {
              Headers = [
                "H1: 1", "H2: 2", "H3: 3", "H4: 4",
                "H5: 5", "H6: 6", "H7: 7", "H8: 8"
              ]
            }
          }

          Smb {
            Name = "Pivot - Smb"
            PipeName = "demon_pipe"
          }
        }

        Demon {}
    "#;

const WEBHOOK_PROFILE: &str = r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "Neo" {
            Password = "password1234"
          }
        }

        Demon {}

        WebHook {
          Discord {
            Url = "https://discord.com/api/webhooks/000000000000000000/test-token"
            User = "Havoc"
          }
        }
    "#;

const HAVOC_DATA_PROFILE: &str = r#"
        Teamserver {
          Host = "0.0.0.0"
          Port = 40056
        }

        Operators {
          user "Neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 2
        }
    "#;

#[test]
fn parses_base_havoc_profile() {
    let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

    assert_eq!(profile.teamserver.host, "0.0.0.0");
    assert_eq!(profile.teamserver.port, 40056);
    assert_eq!(
        profile.teamserver.build.as_ref().and_then(|build| build.nasm.as_deref()),
        Some("/usr/bin/nasm")
    );
    assert_eq!(profile.operators.users.len(), 2);
    assert_eq!(
        profile.operators.users.get("Neo").map(|operator| operator.password.as_str()),
        Some("password1234")
    );
    assert_eq!(
        profile.operators.users.get("Neo").map(|operator| operator.role),
        Some(OperatorRole::Admin)
    );
    assert_eq!(profile.demon.sleep, Some(2));
    assert_eq!(profile.demon.jitter, Some(15));
    assert!(!profile.demon.trust_x_forwarded_for);
    assert_eq!(profile.demon.trusted_proxy_peers, vec!["127.0.0.1/32"]);
    assert_eq!(
        profile.demon.injection.as_ref().and_then(|injection| injection.spawn64.as_deref()),
        Some("C:\\Windows\\System32\\notepad.exe")
    );
    assert!(profile.listeners.http.is_empty());
    assert!(profile.listeners.smb.is_empty());
    assert!(profile.listeners.external.is_empty());
    assert!(profile.service.is_none());
    assert!(profile.webhook.is_none());
}

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
fn parses_operator_roles_and_defaults_missing_roles_to_admin() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "admin" {
                Password = "adminpw"
              }

              user "operator" {
                Password = "operatorpw"
                Role = "Operator"
              }

              user "analyst" {
                Password = "analystpw"
                Role = "analyst"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with roles should parse");

    assert_eq!(profile.operators.users["admin"].role, OperatorRole::Admin);
    assert_eq!(profile.operators.users["operator"].role, OperatorRole::Operator);
    assert_eq!(profile.operators.users["analyst"].role, OperatorRole::Analyst);
}

#[test]
fn parses_from_reader() {
    let profile = Profile::from_reader(HAVOC_DATA_PROFILE.as_bytes())
        .expect("embedded data profile should parse");

    assert_eq!(profile.teamserver.port, 40056);
    assert_eq!(profile.demon.sleep, Some(2));
    assert!(profile.teamserver.build.is_none());
}

#[test]
fn from_reader_rejects_malformed_hcl() {
    let result = Profile::from_reader("{{invalid hcl".as_bytes());
    assert!(result.is_err(), "malformed HCL must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn loads_profile_from_file() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("profile.yaotl");

    std::fs::write(&profile_path, HAVOC_PROFILE).expect("profile fixture should be written");

    let profile = Profile::from_file(&profile_path).expect("profile should load from disk");

    assert_eq!(profile.teamserver.host, "0.0.0.0");
    assert_eq!(profile.teamserver.port, 40056);
}

#[test]
fn loads_all_embedded_profile_fixtures_from_disk() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let fixtures = [
        ("havoc.yaotl", HAVOC_PROFILE),
        ("http-smb.yaotl", HTTP_SMB_PROFILE),
        ("webhook.yaotl", WEBHOOK_PROFILE),
    ];

    for (name, fixture) in fixtures {
        let path = temp_dir.path().join(name);
        std::fs::write(&path, fixture).expect("profile fixture should be written");

        let profile = Profile::from_file(&path).expect("profile fixture should load");
        assert!(profile.validate().is_ok(), "fixture {name} should validate");
    }
}

#[test]
fn validates_sample_profile() {
    let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

    assert!(profile.validate().is_ok());
}

#[test]
fn rejects_invalid_profile_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = ""
              Port = 0
            }

            Operators {}

            Listeners {
              Http {
                Name = ""
                Hosts = []
                HostBind = ""
                HostRotation = ""
                PortBind = 0
              }
            }

            Demon {}
            "#,
    )
    .expect("invalid profile should still parse");

    let error = profile.validate().expect_err("validation should fail");

    assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Host")));
    assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Port")));
    assert!(error.errors.iter().any(|entry| entry.contains("Operators must define")));
    assert!(error.errors.iter().any(|entry| entry.contains("PortBind")));
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
fn rejects_empty_init_secret() {
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
              InitSecret = ""
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("empty InitSecret should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecret") && msg.contains("empty")),
        "expected an InitSecret error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secret_shorter_than_minimum() {
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
              InitSecret = "tooshort"
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("short InitSecret should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecret") && msg.contains("minimum")),
        "expected a minimum-length InitSecret error, got: {:?}",
        error.errors
    );
}

#[test]
fn accepts_init_secret_at_minimum_length() {
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
              InitSecret = "exactly16bytesok"
            }
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("16-byte InitSecret should be accepted");
}

#[test]
fn accepts_absent_init_secret() {
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

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("absent InitSecret should be accepted");
}

#[test]
fn rejects_both_init_secret_and_init_secrets() {
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
              InitSecret = "exactly16bytesok"
              InitSecrets = [
                { Version = 1, Secret = "exactly16bytesok" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("both fields set should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("mutually exclusive")),
        "expected a mutually-exclusive error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secrets_with_duplicate_version() {
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
              InitSecrets = [
                { Version = 1, Secret = "exactly16bytesok" },
                { Version = 1, Secret = "another16bytes!!" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("duplicate version should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("duplicate version")),
        "expected a duplicate-version error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secrets_with_short_secret() {
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
              InitSecrets = [
                { Version = 1, Secret = "tooshort" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("short secret in InitSecrets should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecrets") && msg.contains("minimum")),
        "expected a minimum-length error in InitSecrets, got: {:?}",
        error.errors
    );
}

#[test]
fn accepts_valid_init_secrets() {
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
              InitSecrets = [
                { Version = 1, Secret = "old-secret-exactly16" },
                { Version = 2, Secret = "new-secret-exactly16" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("valid InitSecrets list should be accepted");
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

#[test]
fn parses_teamserver_plugins_dir() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "plugins"
              MaxDownloadBytes = 1048576
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.plugins_dir.as_deref(), Some("plugins"));
    assert_eq!(profile.teamserver.max_download_bytes, Some(1_048_576));
    assert_eq!(profile.teamserver.max_registered_agents, None);
    assert_eq!(profile.teamserver.drain_timeout_secs, None);
}

#[test]
fn parses_teamserver_download_and_pivot_limits() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxConcurrentDownloadsPerAgent = 8
              MaxAggregateDownloadBytes = 268435456
              MaxPivotChainDepth = 5
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_concurrent_downloads_per_agent, Some(8));
    assert_eq!(profile.teamserver.max_aggregate_download_bytes, Some(268_435_456));
    assert_eq!(profile.teamserver.max_pivot_chain_depth, Some(5));
}

#[test]
fn parses_teamserver_download_and_pivot_limits_defaults_to_none_when_absent() {
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

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_concurrent_downloads_per_agent, None);
    assert_eq!(profile.teamserver.max_aggregate_download_bytes, None);
    assert_eq!(profile.teamserver.max_pivot_chain_depth, None);
}

#[test]
fn parses_teamserver_max_registered_agents() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 2048
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_registered_agents, Some(2_048));
}

#[test]
fn parses_teamserver_drain_timeout() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 45
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.drain_timeout_secs, Some(45));
}

#[test]
fn parses_teamserver_logging_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "red_cell=debug,tower_http=info"
                Format = "Json"

                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
                  Rotation = "Hourly"
                }
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let logging = profile.teamserver.logging.expect("logging config should exist");
    assert_eq!(logging.level.as_deref(), Some("red_cell=debug,tower_http=info"));
    assert_eq!(logging.format, Some(LogFormat::Json));
    let file = logging.file.expect("file logging config should exist");
    assert_eq!(file.directory, "logs");
    assert_eq!(file.prefix, "teamserver.log");
    assert_eq!(file.rotation, Some(LogRotation::Hourly));
}

#[test]
fn rejects_empty_teamserver_plugins_dir() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "   "
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("PluginsDir")));
}

#[test]
fn rejects_zero_max_registered_agents() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("MaxRegisteredAgents")));
}

#[test]
fn rejects_zero_drain_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("DrainTimeoutSecs")));
}

#[test]
fn parses_agent_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 90
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              Sleep = 5
            }
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.agent_timeout_secs, Some(90));
}

#[test]
fn rejects_zero_agent_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("AgentTimeoutSecs")));
}

#[test]
fn rejects_invalid_teamserver_logging_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "   "

                File {
                  Directory = " "
                  Prefix = ""
                }
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("Logging.Level")));
    assert!(error.errors.iter().any(|message| message.contains("Logging.File.Directory")));
    assert!(error.errors.iter().any(|message| message.contains("Logging.File.Prefix")));
}

#[test]
fn rejects_zero_max_download_bytes() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxDownloadBytes = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("MaxDownloadBytes")));
}

#[test]
fn parse_rejects_malformed_hcl() {
    let result = Profile::parse("{completely invalid hcl]");
    assert!(result.is_err(), "malformed HCL must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn from_file_returns_error_for_nonexistent_path() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let missing_path = temp_dir.path().join("does_not_exist.yaotl");

    let result = Profile::from_file(&missing_path);
    assert!(result.is_err(), "missing file must return an error");

    match result.expect_err("expected Err") {
        ProfileError::Read { path, .. } => {
            assert_eq!(
                path,
                missing_path.display().to_string(),
                "error must carry the path that failed to open"
            );
        }
        other => panic!("expected ProfileError::Read, got {other:?}"),
    }
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
fn parse_rejects_hcl_missing_teamserver_block() {
    // Valid HCL syntax but missing the required `Teamserver` block.
    let result = Profile::parse(
        r#"
            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    );
    assert!(result.is_err(), "HCL missing Teamserver block must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn profile_error_parse_display_format() {
    // Trigger a parse error by passing garbage HCL.
    let err = Profile::parse("{{{{not valid hcl@@@@").expect_err("expected Err");
    let msg = err.to_string();
    assert!(msg.starts_with("failed to parse YAOTL profile:"), "unexpected Display output: {msg}");
}

#[test]
fn profile_error_read_display_contains_path() {
    let missing = "/tmp/red_cell_c2_nonexistent_profile_12345.hcl";
    let err = Profile::from_file(missing).expect_err("expected Err");
    let msg = err.to_string();
    assert!(
        msg.starts_with("failed to read YAOTL profile from"),
        "unexpected Display prefix: {msg}"
    );
    assert!(msg.contains(missing), "Display output must contain the path; got: {msg}");
}

#[test]
fn profile_validation_error_display_join_format() {
    let err = ProfileValidationError {
        errors: vec!["error one".to_owned(), "error two".to_owned(), "error three".to_owned()],
    };
    let msg = err.to_string();
    assert!(msg.starts_with("profile validation failed:"), "unexpected Display prefix: {msg}");
    assert!(
        msg.contains("error one; error two; error three"),
        "errors must be joined with \"; \"; got: {msg}"
    );
}

#[test]
fn profile_validation_error_display_single_error_format() {
    let err = ProfileValidationError { errors: vec!["single error".to_owned()] };

    assert_eq!(err.to_string(), "profile validation failed: single error");
}

#[test]
fn profile_validation_error_display_two_error_separator_format() {
    let err = ProfileValidationError {
        errors: vec!["first error".to_owned(), "second error".to_owned()],
    };

    assert_eq!(err.to_string(), "profile validation failed: first error; second error");
}

#[test]
fn profile_validation_error_display_empty_error_format() {
    let err = ProfileValidationError { errors: Vec::new() };

    assert_eq!(err.to_string(), "profile validation failed: ");
}

#[test]
fn parses_teamserver_tls_certificate_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, b"fake-cert").expect("write cert");
    std::fs::write(&key_path, b"fake-key").expect("write key");

    let hcl = format!(
        r#"
            Teamserver {{
              Host = "0.0.0.0"
              Port = 40056

              Cert {{
                Cert = "{}"
                Key = "{}"
              }}
            }}

            Operators {{
              user "Neo" {{
                Password = "password1234"
              }}
            }}

            Listeners {{}}

            Demon {{}}
            "#,
        cert_path.display(),
        key_path.display()
    );

    let profile = Profile::parse(&hcl).expect("profile with teamserver cert block should parse");

    let cert = profile.teamserver.cert.as_ref().expect("teamserver cert block should be present");

    assert_eq!(cert.cert, cert_path.display().to_string());
    assert_eq!(cert.key, key_path.display().to_string());

    profile.validate().expect("profile with valid cert paths should pass validation");
}

#[test]
fn rejects_teamserver_with_blank_certificate_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "   "
                Key = "/tmp/server.key"
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
        "expected error about blank Teamserver.Cert.Cert path, got: {error:?}"
    );
}

#[test]
fn rejects_teamserver_with_blank_certificate_key_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "/tmp/server.crt"
                Key = "   "
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
        "expected error about blank Teamserver.Cert.Key path, got: {error:?}"
    );
}

#[test]
fn rejects_teamserver_with_both_blank_certificate_paths() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = ""
                Key = ""
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
        "expected Cert path error, got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
        "expected Key path error, got: {error:?}"
    );
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

fn demon_config_with_secret(secret: Option<&str>) -> DemonConfig {
    DemonConfig {
        sleep: None,
        jitter: None,
        indirect_syscall: false,
        stack_duplication: false,
        sleep_technique: None,
        proxy_loading: None,
        amsi_etw_patching: None,
        injection: None,
        dotnet_name_pipe: None,
        binary: None,
        init_secret: secret.map(|s| Zeroizing::new(s.to_owned())),
        init_secrets: Vec::new(),
        trust_x_forwarded_for: false,
        trusted_proxy_peers: vec![],
        heap_enc: true,
        allow_legacy_ctr: false,
    }
}

#[test]
fn demon_config_debug_redacts_init_secret() {
    let config = demon_config_with_secret(Some("hkdf-super-secret"));

    let debug = format!("{config:?}");

    assert!(debug.contains("DemonConfig"));
    assert!(debug.contains("init_secret: Some(\"[redacted]\")"));
    assert!(!debug.contains("hkdf-super-secret"));
}

#[test]
fn demon_config_debug_none_init_secret() {
    let config = demon_config_with_secret(None);

    let debug = format!("{config:?}");

    assert!(debug.contains("init_secret: None"));
}

#[test]
fn demon_config_amsi_etw_canonical_alias_deserialises() {
    // ARC-01: the profile may use `AmsiEtw` (canonical) or `AmsiEtwPatching` (legacy).
    // Both must deserialise to the same `amsi_etw_patching` field.
    const PROFILE_CANONICAL: &str = r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }
            Operators {
              user "test" { Password = "test" }
            }
            Demon {
              AmsiEtw = "patch"
            }
        "#;
    const PROFILE_LEGACY: &str = r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }
            Operators {
              user "test" { Password = "test" }
            }
            Demon {
              AmsiEtwPatching = "hwbp"
            }
        "#;

    let canonical =
        Profile::parse(PROFILE_CANONICAL).expect("canonical AmsiEtw key should deserialise");
    let legacy =
        Profile::parse(PROFILE_LEGACY).expect("legacy AmsiEtwPatching key should deserialise");

    assert_eq!(canonical.demon.amsi_etw_patching.as_deref(), Some("patch"));
    assert_eq!(legacy.demon.amsi_etw_patching.as_deref(), Some("hwbp"));
}

// --- Semantic validation tests ---

#[test]
fn rejects_teamserver_cert_file_not_found() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Cert {
                Cert = "/nonexistent/path/cert.pem"
                Key = "/nonexistent/path/key.pem"
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Teamserver.Cert.Cert file not found")),
        "expected cert file not found error; got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|m| m.contains("Teamserver.Cert.Key file not found")),
        "expected key file not found error; got: {error:?}"
    );
}

#[test]
fn accepts_teamserver_cert_paths_that_exist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, b"fake-cert").expect("write cert");
    std::fs::write(&key_path, b"fake-key").expect("write key");

    let hcl = format!(
        r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
              Cert {{
                Cert = "{}"
                Key = "{}"
              }}
            }}

            Operators {{
              user "neo" {{
                Password = "password1234"
              }}
            }}

            Demon {{}}
            "#,
        cert_path.display(),
        key_path.display()
    );

    let profile = Profile::parse(&hcl).expect("profile should parse");
    profile.validate().expect("profile with existing cert paths should pass validation");
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

#[test]
fn is_valid_fqdn_accepts_valid_domains() {
    assert!(is_valid_fqdn("example.com"));
    assert!(is_valid_fqdn("c2.example.com"));
    assert!(is_valid_fqdn("sub.domain.example.com"));
    assert!(is_valid_fqdn("example.com."));
    assert!(is_valid_fqdn("my-domain.example.com"));
}

#[test]
fn is_valid_fqdn_rejects_invalid_domains() {
    assert!(!is_valid_fqdn(""));
    assert!(!is_valid_fqdn("localhost"));
    assert!(!is_valid_fqdn(".example.com"));
    assert!(!is_valid_fqdn("example..com"));
    assert!(!is_valid_fqdn("-example.com"));
    assert!(!is_valid_fqdn("example-.com"));
    assert!(!is_valid_fqdn("exam ple.com"));
    assert!(!is_valid_fqdn("example.com/path"));
}
