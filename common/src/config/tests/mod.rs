mod listeners;
mod operators;
mod profile;
mod teamserver;

// Shared profile fixture strings used across multiple test submodules.
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
