use crate::{LinkError, MAX_LINK_BYTES, SecretString};
use std::net::IpAddr;
use url::{Host, Url};

/// Normalize an Outline dynamic key; callers still own DNS/redirect/TLS download admission.
pub fn outline_access_key_source(value: &str) -> Result<SecretString, LinkError> {
    let invalid = || LinkError::Invalid("invalid Outline source".into());
    if value.is_empty()
        || value.len() > MAX_LINK_BYTES
        || value.chars().any(|v| v.is_control() || v.is_whitespace())
    {
        return Err(invalid());
    }
    let (scheme, authority) = value.split_once("://").ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("ssconf")
        || authority.is_empty()
        || authority.starts_with(['/', '\\'])
    {
        return Err(invalid());
    }
    let url = Url::parse(&format!("https://{authority}")).map_err(|_| invalid())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid());
    }
    let public = match url.host().ok_or_else(invalid)? {
        Host::Domain(host) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            host.contains('.')
                && ![
                    "localhost",
                    "local",
                    "localdomain",
                    "lan",
                    "internal",
                    "home.arpa",
                ]
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        }
        Host::Ipv4(ip) => public_ip(IpAddr::V4(ip)),
        Host::Ipv6(ip) => public_ip(IpAddr::V6(ip)),
    };
    if !public {
        return Err(invalid());
    }
    Ok(SecretString::new(url.as_str()))
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
                && !(ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                && !(ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1]))
                && !(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| public_ip(IpAddr::V4(ip)))
            .unwrap_or_else(|| {
                let words = ip.segments();
                words[0] & 0xe000 == 0x2000
                    && !(words[0] == 0x2001 && (words[1] < 0x0200 || words[1] == 0x0db8))
                    && words[0] != 0x2002
                    && !(words[0] & 0xfff0 == 0x3ff0)
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_key_uses_https_and_retains_opaque_access_material() {
        let source =
            outline_access_key_source("SSCONF://example.com/opaque%2Fkey?token=value#My%20VPN")
                .unwrap();
        assert_eq!(
            source.expose(),
            "https://example.com/opaque%2Fkey?token=value#My%20VPN"
        );
        assert!(!format!("{source:?}").contains("opaque"));
    }

    #[test]
    fn dynamic_key_refuses_credentials_private_literals_and_local_names() {
        for source in [
            "ssconf://localhost/key",
            "ssconf://router.lan/key",
            "ssconf://192.168.1.1/key",
            "ssconf://[::1]/key",
            "ssconf://[::ffff:127.0.0.1]/key",
            "ssconf://user:password@1.1.1.1/key",
            "ssconf:///example.com/key",
            "ssconf://1.1.1.1/key\n",
        ] {
            let error = outline_access_key_source(source).unwrap_err().to_string();
            assert!(!error.contains("password"));
        }
    }
}
