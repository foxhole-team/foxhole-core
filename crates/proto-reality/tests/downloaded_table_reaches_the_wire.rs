mod fingerprint_table_support;

use fingerprint_table_support as support;
use proto_reality::{RealityHelloProfile, install_fingerprint_tables};

#[tokio::test]
async fn an_installed_table_changes_what_the_socket_carries() {
    let mut before = Vec::new();
    for profile in RealityHelloProfile::ALL {
        let hello = support::client_hello_on_the_wire(*profile).await;
        support::assert_is_a_complete_client_hello(&format!("{profile:?}"), &hello);
        assert_eq!(
            support::extension_body(&hello, support::RENEGOTIATION_INFO),
            Some(vec![0x00]),
            "{profile:?}: the built-in table's renegotiation_info is one zero byte"
        );
        before.push(hello);
    }

    let document = support::rehash(support::with_marked_renegotiation_info(
        support::committed_document(),
        "0000",
    ));
    let replaced = install_fingerprint_tables(document.to_string().as_bytes())
        .expect("a self-consistent document must install");
    assert!(replaced > 0, "the document must replace at least one table");

    let mut changed = 0_usize;
    for profile in RealityHelloProfile::ALL {
        let hello = support::client_hello_on_the_wire(*profile).await;
        support::assert_is_a_complete_client_hello(&format!("{profile:?}"), &hello);
        match support::extension_body(&hello, support::RENEGOTIATION_INFO) {
            Some(body) if body == [0x00, 0x00] => changed += 1,
            Some(body) => assert_eq!(
                body,
                vec![0x00],
                "{profile:?}: a profile the document does not cover must keep its built-in table"
            ),
            None => panic!("{profile:?}: the hello lost an extension the table names"),
        }
    }
    assert_eq!(
        changed, replaced,
        "every table the document replaced must be the one writing the bytes"
    );

    for (profile, built_in) in RealityHelloProfile::ALL.iter().zip(before) {
        let after = support::client_hello_on_the_wire(*profile).await;
        assert_eq!(
            support::stable_extension_types(&after),
            support::stable_extension_types(&built_in),
            "{profile:?}: the downloaded table must not add or drop an extension"
        );
    }
}
