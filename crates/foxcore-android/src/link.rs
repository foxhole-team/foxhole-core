//! Share links and subscriptions across the ABI.
//!
//! Without this the app cannot import a profile through the core at all: 2267
//! lines of parsers were reachable only from host-side dev binaries, so every
//! link the user pasted had to be parsed a second time in Kotlin — two parsers
//! for one format, disagreeing at exactly the edge cases that matter.
//!
//! Everything here returns secrets. An imported profile *is* a credential, and
//! the JSON these functions hand back must be treated the way the app treats a
//! password: never logged, never in a bug report, never in an analytics event.
//! The one place that rule is enforced rather than requested is the rejection
//! report, which is built in `foxcore-link` specifically so it can be shown and
//! logged safely.

use std::panic::{AssertUnwindSafe, catch_unwind};

use foxcore_link::{
    DroppedOption, ImportedProfile, RejectedLine, import_link, import_subscription_partial,
};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use serde::Serialize;

/// The same wording every entry point in this library uses, so a caller
/// matching on it does not have to know which module threw.
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
    /// The tag the core routes by, so the app never has to invent one and then
    /// disagree with the config it just built.
    outbound: &'a foxcore_api::OutboundConfig,
    /// Parameters the core understood and deliberately did not carry out.
    ///
    /// Absent for a profile imported whole, so a caller can ignore the field
    /// until there is something to say. Non-empty means the server works but
    /// not in every respect the provider wrote down — a WireGuard profile's own
    /// `dns=`, for instance, which the engine's resolver configuration
    /// overrides. Losing the server over that would be worse; losing the *fact*
    /// silently is what this field exists to prevent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dropped: Vec<DroppedJson<'a>>,
}

/// The name of a dropped option and what the core does instead — **never its
/// value**. A subscription's parameter values are untrusted input, and this
/// struct is meant to be safe to show and to log.
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

/// Parses one share link into the outbound config the core would run.
///
/// The same parser the core itself uses, which is the point: a link that
/// imports here is a link that connects, and one that does not is refused with
/// the reason rather than half-accepted with a silently dropped option.
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
        // The error is rendered, not the link. `LinkError` is written not to
        // echo its input, and this is the boundary where that stops being a
        // convention and starts being visible to the user.
        let profile = import_link(&link).map_err(|error| error.to_string())?;
        serde_json::to_string(&profile_json(&profile))
            .map_err(|_| "the profile could not be rendered".to_string())
    }));
    finish_string(&mut env, result)
}

/// Imports every profile in a subscription body, reporting the lines that did
/// not parse instead of refusing the whole body over one of them.
///
/// Real subscriptions carry support links, notices and protocols this build
/// does not have. The strict all-or-nothing import stays available in the
/// crate; it is not what an app should call, because one advertising line
/// costing the user ten servers is not a defensible failure mode.
///
/// The body may be plain lines or base64; the crate decides.
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

    // Percent-encoded exactly as a provider writes them: base64 keys carry `/`
    // and `=`, which a URL parser will not accept raw in userinfo or a query.
    const WG_PRIVATE: &str = "l40T7xeXzdV13X8f%2F1IjcRR0wbrACb0bebRqcN01mbQ%3D";
    const WG_PUBLIC: &str = "%2F94rCPHnchHT%2FrfGYWR3oBaNKtGcelLi4ainYamMiTc%3D";

    /// D8: the app imports the owner's WireGuard server and is never told that
    /// the profile's own resolver was not applied. The parser reports it; this
    /// boundary used to drop the report on the floor.
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

    /// A profile imported whole says nothing, so a caller can ignore the field
    /// until there is something in it.
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
