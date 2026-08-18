//! Core-owned link parsing across JNI; successful JSON contains credentials,
//! while rejection reports deliberately omit input values.

use std::panic::{AssertUnwindSafe, catch_unwind};

use foxcore_link::{
    DroppedOption, ImportedProfile, RejectedLine, import_link, import_subscription_partial,
};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use serde::Serialize;

const PANIC: &str = "panic inside FoxCore JNI boundary";

fn finish_string(
    env: &mut JNIEnv<'_>,
    result: std::thread::Result<Result<String, String>>,
) -> jstring {
    match result {
        Ok(Ok(json)) => env
            .new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Ok(Err(message)) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            std::ptr::null_mut()
        }
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalStateException", PANIC);
            std::ptr::null_mut()
        }
    }
}

#[derive(Serialize)]
struct ProfileJson<'a> {
    name: Option<&'a str>,
    outbound: &'a foxcore_api::OutboundConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dropped: Vec<DroppedJson<'a>>,
}

#[derive(Serialize)]
struct DroppedJson<'a> {
    option: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct SubscriptionJson<'a> {
    profiles: Vec<ProfileJson<'a>>,
    rejected: Vec<RejectedJson<'a>>,
}

#[derive(Serialize)]
struct RejectedJson<'a> {
    index: usize,
    scheme: Option<&'a str>,
    reason: &'a str,
}

fn profile_json(profile: &ImportedProfile) -> ProfileJson<'_> {
    ProfileJson {
        name: profile.name.as_deref(),
        outbound: &profile.outbound,
        dropped: profile.dropped.iter().map(dropped_json).collect(),
    }
}

fn dropped_json(dropped: &DroppedOption) -> DroppedJson<'_> {
    DroppedJson {
        option: &dropped.option,
        reason: &dropped.reason,
    }
}

fn rejected_json(line: &RejectedLine) -> RejectedJson<'_> {
    RejectedJson {
        index: line.index,
        scheme: line.scheme.as_deref(),
        reason: &line.reason,
    }
}

/// Parse one share link into the outbound config the core would run.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeImportLink(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    link: JString<'_>,
) -> jstring {
    let mut env = env;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let link: String = env
            .get_string(&link)
            .map_err(|_| "the link is not a string".to_string())?
            .into();
        let profile = import_link(&link).map_err(|error| error.to_string())?;
        serde_json::to_string(&profile_json(&profile))
            .map_err(|_| "the profile could not be rendered".to_string())
    }));
    finish_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeImportSubscription(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    body: JString<'_>,
) -> jstring {
    let mut env = env;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let body: String = env
            .get_string(&body)
            .map_err(|_| "the subscription body is not a string".to_string())?
            .into();
        let imported = import_subscription_partial(&body).map_err(|error| error.to_string())?;
        serde_json::to_string(&SubscriptionJson {
            profiles: imported.profiles.iter().map(profile_json).collect(),
            rejected: imported.rejected.iter().map(rejected_json).collect(),
        })
        .map_err(|_| "the subscription could not be rendered".to_string())
    }));
    finish_string(&mut env, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Provider-shaped percent-encoded base64 keys.
    const WG_PRIVATE: &str = "l40T7xeXzdV13X8f%2F1IjcRR0wbrACb0bebRqcN01mbQ%3D";
    const WG_PUBLIC: &str = "%2F94rCPHnchHT%2FrfGYWR3oBaNKtGcelLi4ainYamMiTc%3D";

    /// A dropped option is reported without leaking its value.
    #[test]
    fn an_imported_profile_carries_the_options_the_core_did_not_apply() {
        let link = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51820?publickey={WG_PUBLIC}&address=10.8.0.2%2F32&dns=1.1.1.1"
        );
        let profile =
            import_link(&link).expect("a dns= parameter must cost a note, not the server");

        let json = serde_json::to_string(&profile_json(&profile)).unwrap();
        let document: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(document["dropped"][0]["option"], "dns");
        assert!(
            document["dropped"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("dns configuration")
        );
        assert!(
            !json.contains("1.1.1.1"),
            "the value is untrusted input and must never cross this boundary: {json}"
        );
    }

    /// Profiles imported whole omit the optional field.
    #[test]
    fn a_profile_with_nothing_dropped_omits_the_field() {
        let link = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51820?publickey={WG_PUBLIC}&address=10.8.0.2%2F32"
        );
        let profile = import_link(&link).expect("a plain WireGuard link imports whole");

        let json = serde_json::to_string(&profile_json(&profile)).unwrap();
        assert!(!json.contains("dropped"), "{json}");
    }
}
