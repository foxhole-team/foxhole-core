use super::*;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};

use foxcore_api::{
    ContinuityInterruption, ControlProxyConfig, CoreEvent, DnsMode, DnsRoute,
    LoopbackInboundConfig, LoopbackUpstream, MAX_LOOPBACK_INBOUNDS, OutboundId,
    OutboundUnavailable, PolicyConfig, RouteAction,
};
use foxcore_route::RouteTable;
use foxcore_tun::ContinuityConfirm;

/// Bounded: these cross the JNI boundary into a log line and onto a screen, and
/// a serde error on a large document carries a tail nobody reads.
fn bounded_message(message: &str) -> String {
    if message.chars().count() <= MAX_POLICY_ERROR_CHARS {
        return message.to_owned();
    }
    message
        .chars()
        .take(MAX_POLICY_ERROR_CHARS)
        .collect::<String>()
        + "…"
}

impl CoreRuntime {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy.revision()
    }

    /// Isolated web-app control plane bound to this exact runtime generation.
    ///
    /// Clones may outlive `CoreRuntime`, but every VPN/Tor authorization then
    /// fails closed because its runtime lease observes generation liveness.
    pub fn component_manager(&self) -> ComponentManager {
        self.components.clone()
    }

    /// Bind an unlocked share vault to this generation. Replaces any previous
    /// one, whose handle then stops resolving.
    pub fn attach_share_manager(&self, manager: Arc<ShareManager>) {
        *lock(&self.share) = Some(manager);
    }

    /// The share vault, if one is attached and this generation is still alive.
    ///
    /// Fails closed after a stop for the same reason a component lease does: a
    /// vault that outlived its root would be a second lifecycle owner.
    pub fn share_manager(&self) -> Option<Arc<ShareManager>> {
        self.availability
            .load(Ordering::Acquire)
            .then(|| lock(&self.share).clone())
            .flatten()
    }

    /// Bind the LAN ingress on a network the user confirmed.
    ///
    /// The upstream is built here and nowhere else: it is the only object that
    /// can produce a tunnel, and it re-reads the live kill switch, overlay gate
    /// and continuity hold on every session rather than caching them. A LAN
    /// listener that kept serving after the device's own flows stopped would be
    /// the worst possible version of this feature.
    pub fn start_lan_proxy(
        &self,
        config: LanProxyConfig,
        binding: NetworkBinding,
    ) -> Result<LanProxyHandle, ComponentError> {
        if !self.availability.load(Ordering::Acquire) {
            return Err(ComponentError::RuntimeUnavailable);
        }
        self.components.start_lan_proxy(
            self.tokio_handle.clone(),
            config,
            binding,
            self.lan_upstream(),
        )
    }

    /// Bind the LAN ingress and keep the handle for the life of this
    /// generation.
    ///
    /// [`Self::start_lan_proxy`] hands the handle back to its caller, which is
    /// right for an in-process user and wrong for the JNI boundary: Java gets an
    /// opaque engine `long` and has nowhere to put a second one, so a handle
    /// returned across it would be dropped immediately — closing the listeners
    /// it had just opened. This is the owning form.
    ///
    /// Starting while one is already up **replaces** it: the previous listeners
    /// close and their credentials are invalidated before the new ones bind.
    /// Replacing rather than refusing is what makes the call safe to repeat —
    /// the component refuses a duplicate identity, and a proxy the network took
    /// away still holds its name until its handle is dropped, so "refuse if
    /// present" would wedge the feature until the tunnel was restarted. If the
    /// new binding then fails, nothing is listening: that is the fail-closed
    /// direction and is deliberate.
    pub fn install_lan_proxy(
        &self,
        config: LanProxyConfig,
        binding: NetworkBinding,
    ) -> Result<(), ComponentError> {
        let preset = config.preset;
        self.shutdown_lan_proxy();
        match self.start_lan_proxy(config, binding) {
            Ok(handle) => {
                *lock(&self.lan_proxy) = Some(LanProxySession { preset, handle });
                *lock(&self.last_lan_error) = None;
                Ok(())
            }
            Err(error) => {
                self.record_lan_error(&error.to_string());
                Err(error)
            }
        }
    }

    /// Close the LAN listeners. Idempotent; returns whether one was running.
    ///
    /// Clears the recorded reason as well, because this is the user putting the
    /// feature away: a refusal left on screen after that is about an attempt
    /// they have already abandoned.
    pub fn stop_lan_proxy(&self) -> bool {
        let stopped = self.shutdown_lan_proxy();
        *lock(&self.last_lan_error) = None;
        stopped
    }

    /// Stop and forget the session without touching the recorded reason.
    ///
    /// Used by the engine stop paths, which must not erase why a start failed
    /// on the way down.
    fn shutdown_lan_proxy(&self) -> bool {
        let previous = lock(&self.lan_proxy).take();
        match previous {
            Some(session) => {
                session.handle.stop();
                true
            }
            None => false,
        }
    }

    /// The network moved: close the listeners and invalidate the credentials.
    ///
    /// The handle is kept rather than dropped, so the status document can say
    /// `network_lost` instead of falling back to `stopped` — "the proxy you
    /// started is gone because the Wi-Fi changed" and "you never started one"
    /// are different sentences and the app has to be able to tell them apart.
    /// Rebinding is not attempted: the same credentials on a different network
    /// are the definition of a proxy following the user somewhere they did not
    /// intend, so the new network has to be confirmed and started again.
    fn lan_network_changed(&self) {
        if let Some(session) = lock(&self.lan_proxy).as_ref() {
            session.handle.network_changed();
        }
    }

    /// Record why a LAN start or stop was refused, for the status document.
    ///
    /// Public because the refusals that matter most to a user happen before the
    /// runtime is reached at all — a malformed request, both ports zero, a
    /// password nobody typed — and a status document that said only "stopped"
    /// after those is the state this whole call exists to replace.
    pub fn record_lan_error(&self, message: &str) {
        *lock(&self.last_lan_error) = Some(bounded_message(message));
    }

    /// Everything the LAN screen draws, in one document. See
    /// [`crate::lan_proxy_stopped_status_json`] for the shape when nothing has
    /// been started.
    pub fn lan_proxy_status_json(&self) -> String {
        let session = lock(&self.lan_proxy);
        let last_error = lock(&self.last_lan_error).clone();
        let status = match session.as_ref() {
            Some(session) => {
                let binding = session.handle.binding();
                LanProxyStatus {
                    state: lan_state_name(session.handle.state()),
                    socks_address: session
                        .handle
                        .socks_address()
                        .map(|address| address.to_string()),
                    http_address: session
                        .handle
                        .http_address()
                        .map(|address| address.to_string()),
                    preset: Some(lan_preset_name(session.preset)),
                    network_handle: Some(binding.network_handle),
                    local_address: Some(binding.local_address.to_string()),
                    interface_name: Some(binding.interface_name.as_str()),
                    transport: Some(lan_transport_name(binding.transport)),
                    last_error,
                }
            }
            None => LanProxyStatus {
                state: lan_state_name(LanProxyState::Stopped),
                socks_address: None,
                http_address: None,
                preset: None,
                network_handle: None,
                local_address: None,
                interface_name: None,
                transport: None,
                last_error,
            },
        };
        serde_json::to_string(&status).unwrap_or_else(|_| LAN_PROXY_STOPPED.to_owned())
    }

    pub(crate) fn start_control_proxy(
        &self,
        config: Option<ControlProxyConfig>,
    ) -> Result<(), ComponentError> {
        let Some(config) = config else {
            return Ok(());
        };
        if lock(&self.control_proxy).is_some() {
            return Err(ComponentError::AlreadyExists);
        }
        let fingerprint = CredentialFingerprint::new(&config.username, config.password.expose());
        let credentials = LanCredentials::new(
            config.username,
            config.password.expose().as_bytes().to_vec(),
        )
        .ok_or(ComponentError::LanBindingRefused)?;
        let handle = self.components.start_loopback_proxy(
            self.tokio_handle.clone(),
            LanProxyConfig {
                id: ComponentId::new("runtime:control-proxy")?,
                preset: LanProxyPreset::Vpn,
                socks_port: 0,
                http_port: config.http_port,
                credentials,
            },
            self.generation,
            self.lan_upstream(),
        )?;
        *lock(&self.control_proxy) = Some(handle);
        *lock(&self.control_proxy_credentials) = Some(fingerprint);
        Ok(())
    }

    fn stop_control_proxy(&self) {
        *lock(&self.control_proxy_credentials) = None;
        if let Some(handle) = lock(&self.control_proxy).take() {
            handle.stop();
        }
    }

    /// The one upstream every loopback and LAN ingress in this generation uses.
    ///
    /// Built per call rather than held: it borrows the live policy store and
    /// continuity gate, so every session it serves reads the gates as they are
    /// now. A cached decision is what would leave a listener carrying traffic
    /// after the kill switch stopped the device's own flows.
    fn lan_upstream(&self) -> Arc<lan::RegistryUpstream> {
        Arc::new(lan::RegistryUpstream::new(
            self.generation,
            self.outbounds.clone(),
            self.policy.clone(),
            self.continuity.clone(),
            self.connections.clone(),
            Arc::new(foxcore_outbound::Outbound::direct(self.dialer.clone())),
        ))
    }

    /// Bind every named loopback inbound the engine config declared.
    ///
    /// All or nothing. A partial set is the worst outcome available here: the
    /// app would hand out proxy settings for the inbounds that came up and the
    /// applications behind the ones that did not would be pointed at a closed
    /// port — which on Android is not an error the user sees, it is a web app
    /// that silently uses the system network instead.
    pub(crate) fn start_loopback_inbounds(
        &self,
        configs: &[LoopbackInboundConfig],
    ) -> Result<(), ComponentError> {
        for config in configs {
            if let Err(error) = self.install_loopback_inbound(config) {
                self.shutdown_loopback_inbounds();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Bind one named loopback inbound, or refuse and leave nothing listening.
    ///
    /// Public because web apps are created and destroyed while the tunnel is up,
    /// and tearing the engine down to add one would drop every other app's
    /// connections. Refusals are the component's own: an upstream this
    /// generation does not have (`RuntimeUnavailable`), a name already taken
    /// (`AlreadyExists`), a port that will not bind (`LanBindFailed`).
    pub fn install_loopback_inbound(
        &self,
        config: &LoopbackInboundConfig,
    ) -> Result<(), ComponentError> {
        config
            .validate()
            .map_err(|_| ComponentError::InvalidIdentity)?;
        let route = match config.upstream {
            LoopbackUpstream::Profile => LanRoute::Vpn,
            LoopbackUpstream::Tor => LanRoute::Tor,
            LoopbackUpstream::Direct => LanRoute::Direct,
        };
        // Absent together — validated above — is the anonymous listener the app
        // asked for; present together must still form usable credentials.
        let credentials = match (&config.username, &config.password) {
            (Some(username), Some(password)) => Some(
                LanCredentials::new(username.clone(), password.expose().as_bytes().to_vec())
                    .ok_or(ComponentError::LanBindingRefused)?,
            ),
            _ => None,
        };

        // Checked here as well as in `EngineConfig::validate`, because the two
        // see different things: the validator sees a whole list at once and this
        // sees one inbound arriving on a running engine, which is the path a web
        // app being created actually takes. Without it the JNI call is a way
        // around the one rule that makes these listeners separate at all — every
        // one of them is on `127.0.0.1`, where any app on the device can reach
        // any port, so a repeated credential is a repeated upstream.
        // An anonymous listener has no credential to repeat, so it has nothing to
        // collide with: what separates it from the others is its port alone.
        let fingerprint = config
            .username
            .as_deref()
            .zip(config.password.as_ref())
            .map(|(username, password)| CredentialFingerprint::new(username, password.expose()));
        {
            let existing = lock(&self.loopback_inbounds);
            // The name check comes first, and the order is the difference
            // between two answers the app acts on differently. At the cap, a
            // repeated name reported as `Capacity` sends the app looking for
            // something to delete when what it actually has is a stale entry it
            // should replace.
            if existing.iter().any(|session| session.name == config.name) {
                return Err(ComponentError::AlreadyExists);
            }
            if let Some(fingerprint) = fingerprint.as_ref()
                && existing
                    .iter()
                    .filter_map(|session| session.credentials.as_ref())
                    .chain(lock(&self.control_proxy_credentials).as_ref())
                    .any(|other| fingerprint.overlaps(other))
            {
                return Err(ComponentError::AlreadyExists);
            }
            if existing.len() >= MAX_LOOPBACK_INBOUNDS {
                return Err(ComponentError::Capacity);
            }
        }

        let handle = self.components.start_loopback_inbound(
            self.tokio_handle.clone(),
            LoopbackInbound {
                id: loopback_inbound_id(&config.name)?,
                http_port: config.http_port,
                credentials,
                route,
                max_sessions: usize::from(config.max_sessions),
            },
            self.generation,
            self.lan_upstream(),
        )?;
        lock(&self.loopback_inbounds).push(LoopbackInboundSession {
            name: config.name.clone(),
            upstream: config.upstream,
            credentials: fingerprint,
            handle,
        });
        Ok(())
    }

    /// Close one named loopback inbound. Returns whether one was running.
    pub fn remove_loopback_inbound(&self, name: &str) -> bool {
        let mut inbounds = lock(&self.loopback_inbounds);
        let Some(position) = inbounds.iter().position(|session| session.name == name) else {
            return false;
        };
        // Removed before `stop`, because `Drop` calls `stop` too and the
        // component only frees the identity once. Taking it out of the list
        // first is what lets the same name be started again immediately.
        let session = inbounds.remove(position);
        drop(inbounds);
        session.handle.stop();
        true
    }

    fn shutdown_loopback_inbounds(&self) {
        for session in lock(&self.loopback_inbounds).drain(..) {
            session.handle.stop();
        }
    }

    /// Everything the app needs to point an application at one of these, as one
    /// JSON document. See [`crate::loopback_inbounds_empty_json`] for the shape
    /// when none is running.
    pub fn loopback_inbounds_json(&self) -> String {
        let inbounds = lock(&self.loopback_inbounds);
        let rows = inbounds
            .iter()
            .map(|session| LoopbackInboundStatus {
                name: session.name.as_str(),
                upstream: session.upstream.name(),
                state: lan_state_name(session.handle.state()),
                // Always `127.0.0.1:port`. Reported rather than assumed because
                // the port may have been ephemeral, and because an app that
                // hardcodes the address would keep working if this ever moved.
                http_address: session
                    .handle
                    .http_address()
                    .map(|address| address.to_string()),
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&LoopbackInbounds { inbounds: rows })
            .unwrap_or_else(|_| loopback_inbounds_empty_json().to_owned())
    }

    /// Publish the attached share vault as an onion service.
    ///
    /// Takes a Tor lease from the same provider every component uses, starts
    /// the loopback-only server and hands its port to `publisher`. There is no
    /// argument that could select another transport and no error path that
    /// falls back to one: a build without Tor, or a Tor that will not publish,
    /// leaves nothing listening. `share→clearnet` is not representable here.
    pub fn publish_share(
        &self,
        publisher: Arc<dyn OnionPublisher>,
    ) -> Result<PublishedShare, PublishError> {
        let manager = self
            .share_manager()
            .ok_or(PublishError::ServerUnavailable)?;
        publish_share(
            &self.lease_provider,
            manager,
            &self.tokio_handle,
            publisher,
            Arc::new(wall_clock_ms),
        )
    }

    /// Publish the attached vault as an onion service on the profile's Tor
    /// outbound.
    ///
    /// `nickname` identifies the service inside this Tor runtime. The Android
    /// caller uses a random session nickname and the Tor primary keystore is
    /// ephemeral, so an engine restart invalidates both address and invitation.
    #[cfg(feature = "onion-service")]
    pub fn publish_share_over_tor(
        &self,
        nickname: &str,
        virtual_port: u16,
    ) -> Result<PublishedShare, PublishError> {
        self.publish_share(Arc::new(publish::TorOnionPublisher::new(
            self.outbounds.clone(),
            self.tokio_handle.clone(),
            nickname,
            virtual_port,
        )))
    }

    /// Replace route and DNS policy, remembering *why* if it is refused.
    ///
    /// The message is kept rather than only returned because the caller across
    /// the JNI boundary receives a `jlong` and cannot carry one back. See
    /// [`Self::last_policy_error`].
    pub fn reload_policy(&self, config: PolicyConfig) -> Result<u64, PolicyError> {
        let outcome = self.reload_policy_inner(config);
        match &outcome {
            // Cleared on success, so a reading taken later cannot be a stale
            // reason for a reload that then worked.
            Ok(_) => *lock(&self.last_policy_error) = None,
            Err(error) => self.record_policy_error(&error.message),
        }
        outcome
    }

    /// Why the most recent reload on this generation was refused, if it was.
    ///
    /// A separate read rather than a wider return type: `nativeReloadPolicy`
    /// answers with a code the app switches on, and D11 is the record of what
    /// happens when that answer is prose instead — every refusal arrived as the
    /// same `IllegalStateException` and the app could only ever shrug. The code
    /// stays the answer; this is the detail beside it, for the one refusal that
    /// cannot be acted on without it.
    pub fn last_policy_error(&self) -> Option<String> {
        lock(&self.last_policy_error).clone()
    }

    /// Record a refusal raised before [`Self::reload_policy`] could be reached.
    ///
    /// The document has to parse before there is a `PolicyConfig` to refuse,
    /// and a parse failure is the commonest `-1` there is — a field spelled
    /// wrong, a field removed two releases ago, a truncated write. Without this
    /// the one refusal that most needs words would be the one that has none.
    pub fn record_policy_error(&self, message: &str) {
        *lock(&self.last_policy_error) = Some(bounded_message(message));
    }

    fn reload_policy_inner(&self, config: PolicyConfig) -> Result<u64, PolicyError> {
        config
            .validate()
            .map_err(|error| PolicyError::new(PolicyRefusal::Invalid, error.to_string()))?;
        if !self.attribution_available
            && (config
                .routes
                .iter()
                .any(|rule| rule.uid.is_some() || rule.package.is_some())
                || config.traffic.requires_identity())
        {
            return Err(PolicyError::new(
                PolicyRefusal::IdentityUnavailable,
                "UID/package routes require a platform flow attributor",
            ));
        }
        for rule in &config.routes {
            match &rule.action {
                RouteAction::Outbound(id) if self.outbounds.get(&id.0).is_none() => {
                    return Err(PolicyError::new(
                        PolicyRefusal::UnknownOutbound,
                        format!("route references unknown outbound id '{}'", id.0),
                    ));
                }
                RouteAction::Tor if self.outbounds.tor().is_none() => {
                    return Err(PolicyError::new(
                        PolicyRefusal::TorUnavailable,
                        "route action 'tor' requires a registered Tor outbound",
                    ));
                }
                RouteAction::I2p if self.outbounds.i2p().is_none() => {
                    return Err(PolicyError::new(
                        PolicyRefusal::I2pUnavailable,
                        "route action 'i2p' requires a registered I2P outbound",
                    ));
                }
                _ => {}
            }
        }
        if config.dns.route == DnsRoute::Tor && self.outbounds.tor().is_none() {
            return Err(PolicyError::new(
                PolicyRefusal::TorUnavailable,
                "dns.route='tor' requires a registered Tor outbound",
            ));
        }
        if config.traffic.uses_tor() && self.outbounds.tor().is_none() {
            return Err(PolicyError::new(
                PolicyRefusal::TorUnavailable,
                "traffic Tor actions require a registered Tor outbound",
            ));
        }
        if config.traffic.tor_enabled == Some(true) && self.outbounds.tor().is_none() {
            return Err(PolicyError::new(
                PolicyRefusal::TorUnavailable,
                "traffic.tor_enabled=true requires a registered Tor outbound",
            ));
        }
        if config.traffic.i2p_enabled == Some(true) && self.outbounds.i2p().is_none() {
            return Err(PolicyError::new(
                PolicyRefusal::I2pUnavailable,
                "traffic.i2p_enabled=true requires a registered I2P outbound",
            ));
        }
        // The start-time refusal in `EngineConfig::validate` cannot cover this:
        // a reload replaces the DNS policy of a generation whose outbound is
        // already fixed, so fake-IP can be switched on under a running packet
        // tunnel unless this boundary rejects it.
        if self.packet_tunnel && config.dns.mode == DnsMode::FakeIp {
            return Err(PolicyError::new(
                PolicyRefusal::PacketTunnelRejectsFakeIp,
                "dns.mode='fake_ip' cannot be reloaded onto an L3 packet tunnel: this \
                 generation seals clearnet flows as IP packets, so a fake destination \
                 would leave for a peer that cannot route it",
            ));
        }
        // Same reason the start-time refusal cannot cover it: the outbound of a
        // running generation is fixed, and a reload can switch on an interceptor
        // routed through a primary that is a clearnet placeholder. `primary` is
        // the default route, so this arrives without anyone naming it.
        if self.packet_tunnel && config.dns.intercepts() && config.dns.route == DnsRoute::Primary {
            return Err(PolicyError::new(
                PolicyRefusal::PacketTunnelRejectsPrimaryDns,
                "dns.route='primary' cannot be reloaded onto an L3 packet tunnel: the \
                 generation's default outbound is the clearnet placeholder standing in for \
                 the tunnel, so every intercepted lookup would leave beside it",
            ));
        }
        let (tor_enabled, i2p_enabled) = resolve_network_gates(&config.traffic, &self.outbounds);
        let continuity = config.traffic.continuity;
        // Without fake-IP a `.onion` lookup can leave as ordinary port-53 traffic to a
        // clearnet resolver, so a hot reload must not be able to relax it either.
        if tor_enabled && self.outbounds.tor().is_some() && config.dns.mode != DnsMode::FakeIp {
            return Err(PolicyError::new(
                PolicyRefusal::OverlayRequiresFakeIp,
                "Tor routing requires dns.mode='fake_ip'",
            ));
        }
        if i2p_enabled && self.outbounds.i2p().is_some() && config.dns.mode != DnsMode::FakeIp {
            return Err(PolicyError::new(
                PolicyRefusal::OverlayRequiresFakeIp,
                "I2P routing requires dns.mode='fake_ip'",
            ));
        }
        let routes = RouteTable::compile_with_traffic(
            config.routes,
            RouteAction::Outbound(OutboundId("default".into())),
            config.traffic,
            tor_enabled,
            i2p_enabled,
        );
        let previous_revision = self.policy.revision();
        let revision = self
            .policy
            .reload(config.expected_revision, routes, config.dns)
            .map_err(|error| {
                PolicyError::new(PolicyRefusal::RevisionConflict, error.to_string())
            })?;
        // Applied only after the swap succeeded, and never retroactively: a
        // hold already up survives, because the flag decides what happens at
        // the *next* interruption, not whether the last one was real.
        self.continuity.set_config(continuity);
        self.attributor.invalidate();
        // Emitted only after the swap succeeded: a rejected reload must not
        // appear in the audit trail as an applied one.
        self.events.publish(CoreEvent::ConfigApplied {
            revision,
            previous_revision,
        });
        // A reload is the second event that can plausibly have changed the
        // answer for a lane that was not there at start — the first being a
        // network change. Spawned, never awaited: the caller is on the app's
        // thread, and a bootstrap takes seconds. A profile whose failure a
        // rebuild cannot fix starts nothing at all.
        self.spawn_outbound_retry();
        Ok(revision)
    }

    /// Stop the live flows `target` names. Returns how many were reached.
    ///
    /// # Why this is not part of `reload_policy`
    ///
    /// A reload preserves flows that are already open, and that is correct for
    /// what a reload usually is: nobody wants a download killed because a
    /// routing rule was reordered. It is wrong for exactly one class of change
    /// — `Block`, and quarantine — where the user's intent is that the app
    /// *stops talking*, and where the old behaviour let it keep talking over
    /// the TCP connections it already had until they closed on their own. For a
    /// security product that is a promise that is not kept.
    ///
    /// The policy layer cannot tell the two cases apart, because the difference
    /// is not in the document: the same edited rule list arrives either way,
    /// and a reload that guessed would either kill downloads on a reorder or go
    /// on letting a blocked app talk. So the caller says which it meant. The
    /// intended pairings, none of which this call decides for itself:
    ///
    /// * a route change — reload only, nothing revoked;
    /// * an ordinary rule addition — the caller's choice;
    /// * quarantine of a newly installed app, and the user's "block now" —
    ///   reload, then `revoke_flows(Package | Uid)`;
    /// * the kill switch — reload, then `revoke_flows(All)`. Arming the switch
    ///   through a reload already revokes the snapshot, so this is the
    ///   belt-and-braces form for a caller that wants one code path.
    ///
    /// Reload **first** in each pairing: the new policy is then already
    /// refusing new flows by the time the old ones are cut, so nothing can be
    /// opened in between by the app that is being stopped.
    ///
    /// # What the flows see
    ///
    /// A revoked TCP flow is reset towards the application, so the app fails
    /// immediately instead of waiting out a timeout on a connection that will
    /// never answer again. A revoked UDP flow stops carrying traffic and its
    /// session is released. Both are counted as `flows_revoked`.
    ///
    /// Idempotent, safe while traffic is moving, and a target that matches
    /// nothing returns zero rather than failing — the caller asked for a state,
    /// and an app with no open connections is already in it.
    pub fn revoke_flows(&self, target: &RevokeTarget) -> usize {
        let count = self.connections.revoke(target);
        // Published whatever the count, because the request is the auditable
        // thing rather than its yield. A journal that only recorded revocations
        // that happened to catch something could not answer "did the block I
        // pressed actually reach the core".
        self.events.publish(CoreEvent::FlowsRevoked {
            target: target.kind().to_owned(),
            scope: target.scope(),
            count: count as u64,
        });
        count
    }

    /// Verifies and atomically activates a signed DNS rule-set update. The
    /// previous verified policy remains live on every error.
    pub fn install_dns_rule_set(&self, bundle: RuleSetBundle) -> io::Result<u64> {
        let previous_revision = self.policy.revision();
        let revision = self.policy.install_dns_rule_set(bundle)?;
        if revision != previous_revision {
            self.events.publish(CoreEvent::ConfigApplied {
                revision,
                previous_revision,
            });
        }
        Ok(revision)
    }

    /// Takes the audit events this generation produced since the last call.
    ///
    /// Polled rather than pushed: an upcall into the JVM from the flow path
    /// would put a GC pause on the data plane, which is exactly what
    /// [`foxcore_api::EventSink`] forbids.
    pub fn drain_events(&self, max: usize) -> EventDrain {
        self.events.drain(max)
    }

    /// Sends every event to a second consumer as well as to the drain queue.
    ///
    /// For an in-process consumer, and deliberately not the same mechanism as
    /// [`Self::drain_events`]: anything across the JNI boundary must poll,
    /// because an upcall into the JVM from the flow path would put a GC pause on
    /// the data plane. A recorder in this process only queues, so it can be told
    /// directly and does not depend on anyone remembering to poll.
    ///
    /// Nothing in the shipped JNI layer attaches one today — the app's security
    /// journal is Kotlin and reads `nativeDrainEvents`. This stays
    /// because it is the only path that does not lose events while no screen is
    /// open, and it is what a native consumer would use.
    pub fn attach_event_recorder(&self, recorder: EventRecorder) {
        self.events.attach_recorder(recorder);
    }

    /// Stops sending events to the recorder. Idempotent.
    pub fn detach_event_recorder(&self) {
        self.events.detach_recorder();
    }

    /// The traffic map: live flows with the route each one took, per-app and
    /// per-lane totals, DNS verdict counts and the active selector members.
    ///
    /// Separate from `snapshot_json` on purpose: this one is proportional to
    /// the number of open flows, and a UI polling the cheap counters every
    /// second should not pay for it.
    ///
    /// One document rather than four calls, because the parts have to agree:
    /// a screen that drew rows from one poll and lane totals from the next
    /// would show sums that do not add up while traffic is moving.
    pub fn traffic_map_json(&self) -> String {
        let flow = self.metrics.snapshot();
        let selectors = self.outbounds.selector_state();
        let document = TrafficMapDocument {
            generation: self.generation,
            map: self.connections.snapshot(),
            selectors: selectors
                .iter()
                .map(|(tag, active)| SelectorState { tag, active })
                .collect(),
            dns: DnsVerdicts {
                queries: flow.dns_queries,
                blocked: flow.dns_blocked,
                allowed: flow.dns_allowed,
            },
        };
        serde_json::to_string(&document).unwrap_or_else(|_| EMPTY_TRAFFIC_MAP.to_owned())
    }

    /// The name the traffic map had when it was only a connection list. Same
    /// document; the old fields are still there.
    pub fn connections_json(&self) -> String {
        self.traffic_map_json()
    }

    /// Take the map updates produced since the previous call.
    ///
    /// Polled for the same reason the audit stream is: an upcall into the JVM
    /// from the flow path would put a GC pause on the data plane.
    pub fn drain_traffic_events_json(&self, max: usize) -> String {
        serde_json::to_string(&self.connections.drain_events(max))
            .unwrap_or_else(|_| r#"{"events":[],"dropped":0}"#.to_owned())
    }

    pub fn drain_events_json(&self, max: usize) -> String {
        serde_json::to_string(&self.drain_events(max))
            .unwrap_or_else(|_| r#"{"events":[],"dropped":0}"#.to_owned())
    }

    pub fn network_changed(&self) {
        // Before the hold check, and unconditionally. A continuity hold defers
        // *this device's* reconnect, which is a choice about the user's own
        // flows; the LAN listener is bound to an address on a network that has
        // already gone, and leaving it up would keep another device's traffic
        // pointed at a dead socket with the old network's credentials still
        // valid. Rule 4 of the component has no exception for a held switch.
        self.lan_network_changed();
        if self.hold_network_switch(None) {
            return;
        }
        self.rebind_network();
    }

    pub fn network_changed_with_handle(&self, network_handle: u64) {
        self.lan_network_changed();
        if self.hold_network_switch(Some(network_handle)) {
            return;
        }
        self.dialer.set_network_handle(network_handle);
        self.rebind_network();
    }

    /// Everything a network change moves, in the order it has to move.
    ///
    /// The handle is already set by the caller, because everything below reads
    /// it: the outbounds redial through the dialer, and the packet tunnel binds
    /// its replacement socket to whatever the dialer now names.
    ///
    /// The three are one event and are done together deliberately. Moving the
    /// sockets without flushing the resolver leaves the previous network's
    /// answers alive until their TTL — on a split-horizon or captive network
    /// that is the wrong addresses handed out over the new link, with every
    /// counter clean, which is the D1 shape. Flushing the resolver without
    /// moving the sockets resolves names correctly onto an interface that
    /// cannot carry them.
    fn rebind_network(&self) {
        self.outbounds.network_changed();
        // The commonest reason a lane that could not be built now can be. The
        // pass is spawned, not awaited: this call arrives on the app's thread
        // and a Tor bootstrap takes seconds. Nothing waits on the result —
        // flows on lanes that are up keep moving, flows on this one keep being
        // refused, and the snapshot and the event say when that changes.
        self.spawn_outbound_retry();
        // Cached answers and idle upstream connections, both of which belong to
        // the network that went away. Not the fake-IP pool: applications are
        // holding those addresses.
        self.policy.network_changed();
        // Only the L3 relay reads this, and only to build itself a socket on
        // the network the dialer now names. Last, so the tunnel looks for its
        // new socket after the resolver it may need is ready to answer on the
        // new network.
        self.network_epoch.send_modify(|epoch| *epoch += 1);
    }

    /// Returns whether the switch was held rather than performed.
    ///
    /// With `seamless_network_switch` off every network change is an explicit
    /// reconnect: nothing is rebound and no outbound is redialled until the app
    /// confirms. The new handle is remembered so the confirmation can apply it.
    fn hold_network_switch(&self, network_handle: Option<u64>) -> bool {
        if self.continuity.config().seamless_network_switch {
            return false;
        }
        if let Some(handle) = network_handle {
            *lock(&self.deferred_network) = Some(handle);
        }
        self.continuity
            .interrupt(ContinuityInterruption::NetworkSwitch);
        // The lanes are already held. Invalidate sockets from the old network
        // now so an in-flight reconnect cannot become ready behind the hold;
        // their replacement still waits on the confirmation above.
        self.outbounds.network_changed();
        true
    }

    /// The lanes that are configured but not carrying traffic, and why.
    ///
    /// Empty is the ordinary answer. A non-empty one means the engine started
    /// without part of the profile: those flows are refused with
    /// `BlockReason::LaneUnavailable` and every other lane is running.
    pub fn unavailable_outbounds(&self) -> Vec<OutboundUnavailable> {
        self.outbounds.unavailable()
    }

    /// Ask the core to try building the outbounds that were not there at start.
    ///
    /// Returns immediately with the number of attempts it started; the result
    /// of each arrives as [`CoreEvent::OutboundRestored`] or
    /// [`CoreEvent::OutboundUnavailable`], and is visible in the snapshot
    /// either way. Nothing is restarted: an outbound that comes up is put into
    /// the registry entry that was refusing for it, so the tun stays open and
    /// live flows on the other lanes are not disturbed.
    ///
    /// Zero means there was nothing worth attempting — every lane is up, an
    /// attempt is already running, the failure is permanent, or policy gates
    /// the lane off.
    pub fn retry_unavailable_outbounds(&self) -> usize {
        self.spawn_outbound_retry()
    }

    /// Start a retry pass on the worker's executor. Returns how many entries it
    /// claimed — never blocks, and never runs on a flow path.
    fn spawn_outbound_retry(&self) -> usize {
        let policy_gates = self.policy.gates();
        let gates = OverlayGates::new(policy_gates.tor_enabled(), policy_gates.i2p_enabled());
        let pending: Vec<_> = self
            .outbounds
            .deferred()
            .into_iter()
            .filter(|deferred| gates.may_build(deferred))
            .collect();
        if pending.is_empty() {
            return 0;
        }
        let outbounds = self.outbounds.clone();
        let dialer = self.dialer.clone();
        let handshake_timeout_ms = self.handshake_timeout_ms;
        let events = self.events.sink();
        drop(self.tokio_handle.spawn(async move {
            retry_deferred_outbounds(outbounds, dialer, handshake_timeout_ms, gates, events).await
        }));
        pending.len()
    }

    pub fn snapshot_json(&self) -> String {
        let selectors = self.outbounds.selector_state();
        let snapshot = RuntimeSnapshot {
            generation: self.generation,
            policy_revision: self.policy.revision(),
            reconnects: self.outbounds.reconnects(),
            selectors: selectors
                .iter()
                .map(|(tag, active)| SelectorState { tag, active })
                .collect(),
            flow: self.metrics.snapshot(),
            unavailable: self.outbounds.unavailable(),
            continuity: {
                let state = self.continuity_state();
                (!state.held_lanes.is_empty() || state.pending_token.is_some()).then_some(state)
            },
            last_error: lock(&self.last_error).clone(),
        };
        serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into())
    }

    /// Stop the engine and say what happened.
    ///
    /// Every wait on this path has a ceiling. `TimedOut` means the worker is
    /// still alive and this handle still owns it: the app can retry, or call
    /// [`Self::force_kill`] and stop caring.
    /// Retry a stop without touching the process-global stop diagnostics.
    ///
    /// For the reaper thread only. `stop` republishes `stop_requested`, which
    /// clears the phase counters — and the reaper runs *after* a force kill has
    /// deliberately recorded `force_killed` to preserve them. Letting it call
    /// `stop` meant the one window `nativeLastStopDiagnostics` exists for was
    /// erased by the reaper's next lap, three seconds later.
    pub fn stop_quiet(&self) -> StopResult {
        self.stop_control_proxy();
        self.shutdown_loopback_inbounds();
        self.shutdown_lan_proxy();
        self.availability.store(false, Ordering::Release);
        let result = self.worker.stop(STOP_TIMEOUT, || {
            self.cancel.cancel();
            self.metrics.set_connected(false);
        });
        self.stop_continuity_watch();
        result
    }

    pub fn stop(&self) -> StopResult {
        self.stop_control_proxy();
        self.shutdown_loopback_inbounds();
        self.shutdown_lan_proxy();
        self.availability.store(false, Ordering::Release);
        stop_diagnostics::stop_requested(self.generation);
        let result = self.worker.stop(STOP_TIMEOUT, || {
            self.cancel.cancel();
            self.metrics.set_connected(false);
        });
        stop_diagnostics::record(result);
        self.stop_continuity_watch();
        result
    }

    /// Cancel everything and stop waiting, whatever state the worker is in.
    ///
    /// Returns without blocking on the data plane at all. A wedged worker is
    /// handed to the process-wide quarantine list, which keeps ownership until
    /// it really exits; Android's worker lease still refuses a replacement
    /// generation until then, so this buys the app a return from the call, not
    /// a free descriptor. That is the honest trade, and it is the one the app
    /// currently builds four hundred lines of its own scaffolding to get.
    pub fn force_kill(&self) -> StopResult {
        self.stop_control_proxy();
        self.shutdown_loopback_inbounds();
        // The listeners are this process's sockets and closing them costs a
        // cancellation token and a drop; a force kill abandons the *worker*, not
        // the things a dead generation must not leave bound.
        self.shutdown_lan_proxy();
        self.availability.store(false, Ordering::Release);
        self.cancel.cancel();
        self.metrics.set_connected(false);
        let result = self.worker.abandon();
        // Deliberately not `record`: the worker was abandoned, so whatever the
        // phase counters hold is the last thing anyone observed about it, and
        // overwriting the phase with this call's own answer would erase the
        // evidence the force kill exists to preserve.
        stop_diagnostics::force_killed();
        self.stop_continuity_watch();
        result
    }

    /// Which lanes are suspended and what the app has to answer.
    pub fn continuity_state(&self) -> ContinuityState {
        ContinuityState {
            held_lanes: self
                .continuity
                .held_lanes()
                .into_iter()
                .map(FlowLane::name)
                .collect(),
            pending_token: self.continuity.pending_token(),
            interruption: self.continuity.pending_interruption(),
            expired: self.continuity.is_expired(),
        }
    }

    /// Release the held lanes and reconnect.
    ///
    /// Confirmation costs a full reconnect by design: every stateful outbound
    /// is torn down and re-established, and a network handle the app reported
    /// while the hold was up is applied now rather than earlier. Resuming the
    /// old sessions instead would be the seamless repair the user switched off.
    ///
    /// A token that names an interruption which is no longer the current one is
    /// refused, so a dialog answered late cannot resume a lane that has since
    /// failed again for a different reason.
    pub fn confirm_continuity(&self, token: u64) -> ConfirmResult {
        match self.continuity.claim_confirmation(token) {
            ContinuityConfirm::Confirmed => {
                if let Some(handle) = lock(&self.deferred_network).take() {
                    self.dialer.set_network_handle(handle);
                }
                self.rebind_network();
                self.attributor.invalidate();
                match self.continuity.complete_confirmation(token) {
                    ContinuityConfirm::Confirmed => ConfirmResult::Confirmed,
                    ContinuityConfirm::NothingPending => ConfirmResult::NothingPending,
                    ContinuityConfirm::StaleToken => ConfirmResult::StaleToken,
                }
            }
            ContinuityConfirm::NothingPending => ConfirmResult::NothingPending,
            ContinuityConfirm::StaleToken => ConfirmResult::StaleToken,
        }
    }

    /// Start the deadline watch. Called once, at start.
    ///
    /// The thread parks on a channel and is woken only when a hold is raised or
    /// released, so an engine whose user never switched anything off costs one
    /// blocked thread and zero wakeups. It used to sample two counters every
    /// second to notice a repair it could not be told about; the outbound
    /// registry now pushes those instead.
    pub(crate) fn start_continuity_watch(&self) {
        let mut watch = lock(&self.continuity_watch);
        if watch.is_some() {
            return;
        }
        // Capacity one: a second wakeup while the first is unread says nothing
        // the watch will not already see when it looks at the gate.
        let (wake_tx, wake_rx) = mpsc::sync_channel(1);
        self.continuity.set_wakeup(wake_tx);
        let gate = self.continuity.clone();
        // The gate and the wakeup channel, and nothing else. This thread used
        // to be handed `availability`, `metrics` and the cancellation token so
        // it could stop the engine on a deadline; it cannot do that any more,
        // and a thread holding the engine's kill switch "just in case" is how
        // the ability comes back by accident.
        let Ok(thread) = std::thread::Builder::new()
            .name(format!("foxcore-continuity-{}", self.generation))
            .spawn(move || continuity_watch(gate, wake_rx))
        else {
            return;
        };
        *watch = Some(ContinuityWatch { thread });
    }

    fn stop_continuity_watch(&self) {
        // Dropping the gate's sender disconnects the channel, which is how the
        // parked thread learns the engine is going away.
        self.continuity.clear_wakeup();
        let watch = lock(&self.continuity_watch).take();
        if let Some(watch) = watch {
            // Bounded like every other wait on this path. This thread only ever
            // touches a channel and two atomics, so the budget should never be
            // spent — but "should never" is what the last unbounded join said.
            if let Err(thread) = join_within(watch.thread, JOIN_GRACE) {
                quarantine_worker(thread);
            }
        }
    }
}
