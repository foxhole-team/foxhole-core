use super::*;

fn config(dns: &str, routes: &str, traffic: &str) -> EngineConfig {
    EngineConfig::parse(&format!(
        r#"{{"schema_version":1,"outbound":{{"type":"direct"}},"tun":{{"mtu":1400,"ipv4":"10.77.0.1"}},"runtime":{{"local_guard":true}},"dns":{dns},"routes":{routes},"traffic":{traffic}}}"#
    )).unwrap()
}

const DOMAIN: &str = r#"[{"domain_suffixes":["test"],"action":{"type":"direct"}}]"#;
const FAKE_DNS: &str = r#"{"mode":"fake_ip","advertise":"10.77.0.1"}"#;
const PACKAGE_DNS: &str = r#"{"mode":"fake_ip","advertise":"10.77.0.1","blocklist":{"suffixes":["test"],"bypass_packages":["com.example.allowed"]}}"#;

fn no_identity_start(configuration: EngineConfig) -> io::Result<(CoreRuntime, UnixStream)> {
    let (tun, peer) = UnixStream::pair().unwrap();
    CoreRuntime::start(
        701,
        configuration,
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .map(|runtime| (runtime, peer))
}

fn must_refuse(configuration: EngineConfig) -> io::Error {
    match no_identity_start(configuration) {
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            error
        }
        Ok((runtime, _peer)) => {
            let _ = runtime.stop();
            panic!("identity-dependent policy started without a platform attributor");
        }
    }
}

#[test]
fn dns_package_bypass_is_refused_at_start_without_platform_identity() {
    let error = must_refuse(config(PACKAGE_DNS, "[]", "{}"));
    assert!(error.to_string().contains("flow attribution"));
}

#[test]
fn real_ip_domain_routing_is_refused_at_start_without_platform_identity() {
    let error = must_refuse(config(
        r#"{"mode":"real_ip","advertise":"10.77.0.1"}"#,
        DOMAIN,
        "{}",
    ));
    assert!(error.to_string().contains("flow attribution"));
}

#[test]
fn ordinary_full_device_and_fake_domain_policies_do_not_require_uid_apis() {
    for configuration in [config("{}", "[]", "{}"), config(FAKE_DNS, DOMAIN, "{}")] {
        let (runtime, _peer) = no_identity_start(configuration).unwrap();
        assert_eq!(runtime.stop(), StopResult::Stopped);
    }
}

#[test]
fn uid_and_quarantine_policies_are_still_refused_before_start_without_identity() {
    must_refuse(config(
        FAKE_DNS,
        r#"[{"uid":10123,"action":{"type":"direct"}}]"#,
        "{}",
    ));
    must_refuse(config(FAKE_DNS, "[]", r#"{"quarantine_new_apps":true}"#));
}

#[test]
fn reload_cannot_add_package_bypass_or_real_ip_domain_routing_without_identity() {
    let (runtime, _peer) = no_identity_start(config(FAKE_DNS, "[]", "{}")).unwrap();
    for unsupported in [
        config(PACKAGE_DNS, "[]", "{}"),
        config(r#"{"mode":"real_ip"}"#, DOMAIN, "{}"),
        config(r#"{"mode":"fake_ip"}"#, DOMAIN, "{}"),
    ] {
        let refusal = runtime
            .reload_policy(PolicyConfig {
                expected_revision: Some(1),
                routes: unsupported.routes,
                dns: unsupported.dns,
                traffic: unsupported.traffic,
            })
            .unwrap_err();
        assert_eq!(refusal.refusal, PolicyRefusal::IdentityUnavailable);
        assert_eq!(runtime.policy_revision(), 1);
    }
    assert_eq!(runtime.stop(), StopResult::Stopped);
}

#[test]
fn an_ordinary_vless_profile_with_no_app_or_domain_routes_starts_without_uid_apis() {
    let configuration = EngineConfig::parse(
        r#"{"schema_version":1,"outbound":{"type":"vless","server":"127.0.0.1","port":9,"uuid":"00000000-0000-0000-0000-000000000001"},"tun":{"mtu":1400,"ipv4":"10.77.0.1"},"dns":{"mode":"real_ip"}}"#,
    ).unwrap();
    let (runtime, _peer) = no_identity_start(configuration).unwrap();
    assert_eq!(runtime.stop(), StopResult::Stopped);
}

#[test]
fn advertise_less_fake_domain_routing_is_refused_without_platform_identity() {
    let error = must_refuse(config(r#"{"mode":"fake_ip"}"#, DOMAIN, "{}"));
    assert!(error.to_string().contains("flow attribution"));
}
