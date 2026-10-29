use foxcore_api::OutboundConfig;

pub(crate) fn compiled() -> Vec<&'static str> {
    [
        ("vless", cfg!(feature = "vless")),
        ("vmess", cfg!(feature = "vmess")),
        ("hysteria2", cfg!(feature = "hysteria2")),
        ("tuic", cfg!(feature = "tuic")),
        ("trojan", cfg!(feature = "trojan")),
        ("shadowsocks", cfg!(feature = "shadowsocks")),
        ("wireguard", cfg!(feature = "wireguard")),
        ("naive", cfg!(feature = "naive")),
        ("anytls", cfg!(feature = "anytls")),
        ("shadowtls", cfg!(feature = "shadowtls")),
        ("socks", cfg!(feature = "socks")),
        ("http", cfg!(feature = "http")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect()
}

pub(crate) fn name(outbound: &OutboundConfig) -> &'static str {
    match outbound {
        OutboundConfig::Vless(_) => "vless",
        OutboundConfig::Vmess(_) => "vmess",
        OutboundConfig::Hysteria2(_) => "hysteria2",
        OutboundConfig::Tuic(_) => "tuic",
        OutboundConfig::Trojan(_) => "trojan",
        OutboundConfig::Shadowsocks(_) => "shadowsocks",
        OutboundConfig::Wireguard(_) => "wireguard",
        OutboundConfig::Naive(_) => "naive",
        OutboundConfig::AnyTls(_) => "anytls",
        OutboundConfig::ShadowTls(_) => "shadowtls",
        OutboundConfig::Socks(_) => "socks",
        OutboundConfig::Http(_) => "http",
        OutboundConfig::Selector(_) => "selector",
        OutboundConfig::Direct(_) => "direct",
        OutboundConfig::Tor(_) => "tor",
        OutboundConfig::I2p(_) => "i2p",
    }
}

pub(crate) fn require_available(outbound: &OutboundConfig) -> Result<(), &'static str> {
    if let OutboundConfig::Selector(group) = outbound {
        for member in &group.members {
            require_available(&member.outbound)?;
        }
        Ok(())
    } else if compiled().contains(&name(outbound)) {
        Ok(())
    } else {
        Err("PROTOCOL_UNAVAILABLE")
    }
}
