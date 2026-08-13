//! Report *why* each profile in a subscription cannot be imported.
//!
//! Reads the subscription body on stdin and prints one line per scheme with the
//! parser's own error text. `LinkError` is written to never carry endpoints,
//! credentials, UUIDs, SNI or paths, so this output stays safe to paste into an
//! issue — it names the missing capability, not the profile.

use std::io::Read;

use foxcore_link::{ProfileScheme, import_first_profile_by_scheme, inspect_subscription};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body)?;
    let body = body.trim().to_string();

    match inspect_subscription(&body) {
        Ok(shapes) => {
            println!("shapes ({}):", shapes.len());
            for shape in &shapes {
                println!("  {}", shape.label());
            }
        }
        Err(error) => println!("inspect failed: {error}"),
    }

    println!("import per scheme:");
    for (name, scheme) in [
        ("vless", ProfileScheme::Vless),
        ("vmess", ProfileScheme::Vmess),
        ("trojan", ProfileScheme::Trojan),
        ("shadowsocks", ProfileScheme::Shadowsocks),
        ("hysteria2", ProfileScheme::Hysteria2),
    ] {
        match import_first_profile_by_scheme(&body, scheme) {
            Ok(_) => println!("  {name:<12} ok"),
            Err(error) => println!("  {name:<12} {error}"),
        }
    }
    Ok(())
}
