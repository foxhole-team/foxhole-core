use super::*;

/// The exact shape the Android app produces: every node of the profile
/// wrapped in one group, with the group as the primary outbound.
fn selector_json(members: &str, extra: &str) -> String {
    format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"selector",
                    "members":{members}
                    {extra}
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
            }}"#
    )
}

const SS_MEMBER_A: &str = r#"{"id":"node-a","outbound":{"type":"shadowsocks","server":"198.51.100.7","port":8388,"method":"aes-128-gcm","password":"pw"}}"#;
const SS_MEMBER_B: &str = r#"{"id":"node-b","outbound":{"type":"shadowsocks","server":"198.51.100.8","port":8388,"method":"aes-128-gcm","password":"pw"}}"#;

/// A Shadowsocks outbound with `extra` spliced into it.
fn shadowsocks_json(extra: &str) -> String {
    format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"shadowsocks",
                    "server":"198.51.100.7","port":8388,
                    "method":"chacha20-ietf-poly1305","password":"pw"
                    {extra}
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
            }}"#
    )
}

fn shadowsocks(extra: &str) -> Result<ShadowsocksConfig, ConfigError> {
    EngineConfig::parse(&shadowsocks_json(extra)).map(|config| {
        let OutboundConfig::Shadowsocks(shadowsocks) = config.outbound else {
            panic!("expected a shadowsocks outbound");
        };
        shadowsocks
    })
}

const WG_PRIVATE_KEY: &str = "l40T7xeXzdV13X8f/1IjcRR0wbrACb0bebRqcN01mbQ=";
const WG_PEER_PUBLIC_KEY: &str = "/94rCPHnchHT/rfGYWR3oBaNKtGcelLi4ainYamMiTc=";

fn wireguard_json(private_key: &str, address: &str, allowed_ips: &str) -> String {
    format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"wireguard",
                    "server":"edge.example","port":51820,
                    "private_key":"{private_key}",
                    "peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                    "address":{address},
                    "allowed_ips":{allowed_ips}
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
            }}"#
    )
}

fn amnezia_json_with_mtu(mtu: u16, amnezia: &str) -> String {
    format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"wireguard",
                    "server":"example.com","port":51820,
                    "private_key":"{WG_PRIVATE_KEY}",
                    "peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                    "address":["10.8.0.2/32"],
                    "allowed_ips":["0.0.0.0/0"],
                    "mtu":{mtu},
                    "amnezia":{amnezia}
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
            }}"#
    )
}

fn amnezia_json(amnezia: &str) -> String {
    format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"wireguard",
                    "server":"edge.example","port":51820,
                    "private_key":"{WG_PRIVATE_KEY}",
                    "peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                    "address":["10.8.0.2/32"],
                    "allowed_ips":["0.0.0.0/0"],
                    "amnezia":{amnezia}
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
            }}"#
    )
}

/// A base64 `ECHConfigList` holding one draft-18 config: X25519 KEM,
/// HKDF-SHA256 / AES-128-GCM, public name `public.example`.
const ECH_CONFIG_LIST: &str =
    "AEH+DQA9AQAgACAgISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";

fn trojan_with_tls(tls: &str) -> String {
    format!(
        r#"{{
            "schema_version":1,
            "outbound":{{
                "type":"trojan",
                "server":"trojan.example",
                "port":443,
                "password":"trojan-password-secret",
                "tls":{tls}
            }},
            "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
        }}"#
    )
}

mod parse;
mod policy_tls;
mod protocols;
