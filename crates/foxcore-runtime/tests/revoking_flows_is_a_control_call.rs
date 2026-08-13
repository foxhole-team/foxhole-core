//! `revoke_flows` as the control plane exposes it, which is the surface the
//! JNI layer wraps and the app codes against.
//!
//! What the flows themselves do when they are revoked — a TCP reset the peer
//! can see, a UDP session released — is measured against real packets in
//! `foxcore-tun`'s `blocking_an_app_reaches_its_open_connections`. This is the
//! other half: the call's own contract, which the app depends on before any
//! flow exists. It has to be safe to make unconditionally, it has to say how
//! much it did, and it has to leave a record whether or not it did anything.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use foxcore_api::EngineConfig;
use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::{CoreRuntime, FlowLane, RevokeTarget};

/// Starts without touching the network: `server_ip` is present so nothing
/// resolves, and the outbound is built against an address that refuses. The
/// control call is what is under test, not the dial.
fn offline_profile() -> EngineConfig {
    EngineConfig::parse(
        r#"{
            "schema_version": 1,
            "outbound": {
                "type": "vless",
                "server": "bootstrap.invalid",
                "port": 443,
                "server_ip": "203.0.113.7",
                "uuid": "d0cf0001-0000-4000-8000-000000000000"
            },
            "tun": { "mtu": 1400, "ipv4": "10.75.0.1" }
        }"#,
    )
    .expect("a fixed, valid offline profile")
}

/// The peer end must outlive the engine: closing it early hands the relay an
/// EOF and turns every assertion below into a test of teardown.
fn start() -> (CoreRuntime, UnixStream) {
    let (tun, peer) = UnixStream::pair().expect("a socket pair stands in for the TUN");
    let runtime = CoreRuntime::start(
        1,
        offline_profile(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .expect("an offline profile starts");
    (runtime, peer)
}

/// Every target shape the app can send is accepted, answers with a count, and
/// is recorded — on an engine with nothing open, which is the state the call
/// most often arrives in.
///
/// Zero is the answer here and it is a success. An app that blocks a package
/// does not first check whether that package happens to be talking, so a
/// refusal for "nothing matched" would make the caller invent a check it
/// cannot do correctly anyway: between its check and its call the app could
/// have opened a connection.
#[test]
fn revoking_on_a_quiet_engine_is_a_counted_no_op_that_is_still_recorded() {
    let (runtime, _peer) = start();
    let _ = runtime.drain_events(usize::MAX);

    for target in [
        RevokeTarget::All {},
        RevokeTarget::Lane {
            lane: FlowLane::Vpn,
        },
        RevokeTarget::Uid { uid: 10_123 },
        RevokeTarget::Package {
            package: "com.example.app".to_owned(),
        },
        RevokeTarget::Outbound {
            outbound: "default".to_owned(),
        },
        RevokeTarget::Flow { flow: 7 },
    ] {
        assert_eq!(
            runtime.revoke_flows(&target),
            0,
            "{target:?} matches nothing on a quiet engine, which is not an error"
        );
    }

    let journal = runtime.drain_events_json(usize::MAX);
    assert_eq!(
        journal.matches(r#""type":"flows_revoked""#).count(),
        6,
        "every request is recorded, including the ones that found nothing: \
         'the user blocked this app and it had nothing open' and 'the user \
         never blocked this app' are different facts. Got: {journal}"
    );
    assert!(
        journal.contains(r#""target":"package""#)
            && journal.contains(r#""scope":"com.example.app""#),
        "and the record names which app, or a journal entry cannot be read \
         back: {journal}"
    );
    assert!(
        journal.contains(r#""target":"all""#) && journal.contains(r#""count":0"#),
        "{journal}"
    );

    assert_eq!(runtime.stop(), foxcore_runtime::StopResult::Stopped);
}

/// The call does not disturb the engine it is made on.
///
/// Revocation is not a lifecycle operation: the tunnel stays up, the policy is
/// untouched and its revision does not move. An app that revoked flows and
/// found its policy version had changed underneath would have no safe way to
/// use `expected_revision` afterwards.
#[test]
fn revoking_changes_neither_the_policy_nor_the_engine() {
    let (runtime, _peer) = start();
    let revision = runtime.policy_revision();
    let generation = runtime.generation();

    for _ in 0..3 {
        runtime.revoke_flows(&RevokeTarget::All {});
    }

    assert_eq!(
        runtime.policy_revision(),
        revision,
        "revoking live flows is not a policy change: reload decides what the \
         next flow may do, this decides which current ones stop"
    );
    assert_eq!(runtime.generation(), generation);
    assert!(
        runtime.last_policy_error().is_none(),
        "and it is not a policy refusal either"
    );
    assert_eq!(runtime.stop(), foxcore_runtime::StopResult::Stopped);
}

/// The target document, parsed exactly as the JNI boundary parses it.
///
/// The app builds this JSON, so the shapes it may send and the shapes it may
/// not are part of the contract rather than an implementation detail.
#[test]
fn the_target_document_is_the_contract() {
    assert_eq!(
        RevokeTarget::parse(r#"{"kind":"package","package":"com.example.app"}"#),
        Ok(RevokeTarget::Package {
            package: "com.example.app".to_owned()
        })
    );
    assert_eq!(
        RevokeTarget::parse(r#"{"kind":"lane","lane":"direct"}"#),
        Ok(RevokeTarget::Lane {
            lane: FlowLane::Direct
        })
    );

    // The two ways to misread a malformed target are to cut nothing and to cut
    // everything. Neither is guessed for the user, so all of these are refused
    // and reach the app as `-3` rather than as an action.
    for refused in [
        r#"{"kind":"all","package":"com.example.app"}"#,
        r#"{"kind":"packages","package":"com.example.app"}"#,
        r#"{"kind":"package"}"#,
        r#"{"kind":"lane","lane":"clearnet"}"#,
        r#"{"package":"com.example.app"}"#,
        "not json at all",
        "",
    ] {
        assert!(
            RevokeTarget::parse(refused).is_err(),
            "{refused} must be refused rather than interpreted"
        );
    }
}
