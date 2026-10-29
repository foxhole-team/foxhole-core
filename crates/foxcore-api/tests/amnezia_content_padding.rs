use foxcore_api::AmneziaConfig;
use serde_json::json;

#[test]
fn content_padding_preserves_the_entire_uint32_range() {
    for expected in [
        json!(0),
        json!(13),
        json!(65536),
        json!(u32::MAX),
        json!("0-1"),
        json!("65536-4294967295"),
    ] {
        let parsed: AmneziaConfig =
            serde_json::from_value(json!({"content_padding_addition": expected.clone()}))
                .expect("a valid content padding addition must be retained");
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["content_padding_addition"],
            expected
        );
    }
}

#[test]
fn malformed_content_padding_does_not_become_a_disabled_default() {
    for malformed in [
        json!(null),
        json!(-1),
        json!(4294967296_u64),
        json!("9-8"),
        json!("1-4294967296"),
        json!("-1-3"),
        json!("1-2-3"),
        json!("13"),
        json!(" 1-2 "),
        json!(""),
        json!(true),
        json!(1.25),
        json!({"start": 1, "end": 2}),
    ] {
        assert!(
            serde_json::from_value::<AmneziaConfig>(
                json!({"content_padding_addition": malformed.clone()})
            )
            .is_err(),
            "malformed CPA accepted: {malformed}"
        );
    }
}

#[test]
fn absent_content_padding_adds_no_serialized_field() {
    assert!(
        serde_json::to_value(AmneziaConfig::default())
            .unwrap()
            .get("content_padding_addition")
            .is_none()
    );
}
