//! Configs an app built against ABI v1 sends, replayed against this build.
//!
//! `fixtures/abi/v1/{engine,policy}-config/*.json` are frozen bytes, not
//! generated ones. That is the whole point: every other check of the config
//! surface in this workspace builds the value with the current types and then
//! asserts something about it, so a field that stopped being accepted also
//! stopped being constructed and no test noticed. These files were written once
//! and are read verbatim. If one of them stops parsing, an installed app that
//! saved that config has stopped being able to start the tunnel.
//!
//! Adding a fixture is normal — it widens the corpus. Editing one to make it
//! pass is a schema break wearing a fixture change and requires an explicit
//! migration and rollback decision, not merely a green test.
//!
//! Run on its own: `cargo test -p foxcore-api --test abi_v1_fixtures`

use std::fs;
use std::path::{Path, PathBuf};

use foxcore_api::{
    CAPABILITIES_SCHEMA_VERSION, CORE_ABI_VERSION, EngineConfig, PolicyConfig, SCHEMA_VERSION,
};

fn fixture_dir(leaf: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/foxcore-api.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above the crate")
        .join("fixtures/abi/v1")
        .join(leaf)
}

/// Sorted so a failure names the same file on every machine.
fn fixtures(leaf: &str) -> Vec<PathBuf> {
    let directory = fixture_dir(leaf);
    let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no fixtures under {} — an empty corpus passes every check it is asked",
        directory.display()
    );
    paths
}

#[test]
fn every_frozen_v1_engine_config_still_parses() {
    for path in fixtures("engine-config") {
        let json = fs::read_to_string(&path).expect("a readable fixture");
        let config = EngineConfig::parse(&json).unwrap_or_else(|error| {
            panic!(
                "{} no longer parses: {error}\n\
                 An app that saved this config cannot start this build.",
                path.display()
            )
        });
        assert_eq!(
            config.schema_version,
            SCHEMA_VERSION,
            "{} declares a schema this build does not call v1",
            path.display()
        );
    }
}

#[test]
fn every_frozen_v1_policy_config_still_parses() {
    for path in fixtures("policy-config") {
        let json = fs::read_to_string(&path).expect("a readable fixture");
        PolicyConfig::parse(&json).unwrap_or_else(|error| {
            panic!(
                "{} no longer parses: {error}\n\
                 nativeReloadPolicy would refuse this app's saved policy.",
                path.display()
            )
        });
    }
}

/// The three numbers the app compares before it does anything else. They are
/// checked here as well as in the capabilities
/// document because this test runs in the ordinary workspace gate, while
/// `scripts/abi-gate.sh` needs a linker and a C compiler.
#[test]
fn the_declared_versions_are_still_v1() {
    assert_eq!(CORE_ABI_VERSION, 1, "changing the ABI version is an ABI v2");
    assert_eq!(SCHEMA_VERSION, 1, "changing the config schema is an ABI v2");
    assert_eq!(
        CAPABILITIES_SCHEMA_VERSION, 1,
        "changing the capabilities schema is an ABI v2"
    );
}

/// A config from a schema the build does not know must be refused by version,
/// not parsed for the fields it happens to recognise. This is the negative half
/// of the contract: it is what makes a *future* app's config fail loudly on an
/// older library instead of starting a tunnel with half a policy.
#[test]
fn a_newer_schema_is_refused_rather_than_partially_applied() {
    let json = fs::read_to_string(fixture_dir("engine-config").join("01-minimal-vless.json"))
        .expect("a readable fixture");
    let bumped = json.replace("\"schema_version\": 1", "\"schema_version\": 2");
    assert_ne!(json, bumped, "the fixture no longer declares schema 1");
    let error = EngineConfig::parse(&bumped).expect_err("schema 2 must not parse as schema 1");
    assert!(
        error.to_string().contains('2'),
        "the refusal must name the schema it saw, got: {error}"
    );
}
