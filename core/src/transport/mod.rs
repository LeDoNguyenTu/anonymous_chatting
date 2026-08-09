//! Talking to the relay.
//!
//! The relay is assumed hostile (`docs/THREAT_MODEL.md` §3). This module
//! therefore treats every response as untrusted input and never lets the relay
//! influence anything except *which bytes arrive* — the bytes themselves mean
//! nothing until MLS has authenticated them.
//!
//! Phase 1 is direct TLS with the relay certificate pinned by SPKI hash
//! (D-017). Phase 4 adds Tor (`tor` submodule) as a second, additive backend
//! — `RelayClient` picks between them at construction time and reports which
//! one it is actually using via [`RelayClient::route`], which the manifest
//! and the Custody Strip both read rather than assuming.

pub mod tor;

use serde::{Deserialize, Serialize};

pub use tor::TorRelayConfig;

/// How a message reached, or will reach, the relay.
///
/// Reported by the manifest at stage 7 and by the Custody Strip. It must always
/// describe what actually happened — a manifest that claims Tor for a message
/// that went direct is worse than no manifest (SPEC §8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    /// Straight to the relay over TLS 1.3. The relay sees the client's IP.
    Direct,
    /// Through a Tor onion circuit. The relay never learns the client's IP.
    Tor,
    /// No connection. Messages are queued locally.
    Offline,
}

impl Route {
    /// The label shown in the Custody Strip.
    pub fn label(&self) -> &'static str {
        match self {
            Route::Direct => "DIRECT",
            Route::Tor => "TOR",
            Route::Offline => "OFFLINE",
        }
    }

    /// The same route written as a title rather than a status token.
    ///
    /// [`Route::label`] is deliberately shouted: in the Custody Strip it is a
    /// state readout sitting beside `VERIFIED` and `KEY CHANGED`, and it
    /// should read like one. A settings screen offering a choice is not a
    /// status readout, and setting it in the same capitals would make picking
    /// a transport look like an alarm.
    ///
    /// Both spellings live here rather than in each client so a screen cannot
    /// invent its own name for a route the manifest calls something else.
    pub fn name(&self) -> &'static str {
        match self {
            Route::Direct => "Direct",
            Route::Tor => "Tor",
            Route::Offline => "Offline",
        }
    }

    /// The honest one-line description shown when the field is opened.
    ///
    /// Neither option is labelled "the secure one". The trade is stated and the
    /// user chooses (SPEC §6.7.9).
    pub fn explanation(&self) -> &'static str {
        match self {
            Route::Direct => {
                "Messages go straight to the relay over TLS 1.3. The relay sees the IP address \
                 you connect from. Message content stays encrypted either way."
            }
            Route::Tor => {
                "Messages route through a Tor onion circuit. The relay never learns your IP \
                 address. Your internet provider can still see that you are using Tor."
            }
            Route::Offline => {
                "No connection to the relay. Messages you write are queued on this device and \
                 send when you reconnect."
            }
        }
    }
}

/// Anything that can go wrong talking to the relay.
///
/// Every variant carries enough for the UI to say what happened and what to do
/// (SPEC §6.9). None of them is "something went wrong".
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// No connection could be made.
    #[error("no connection to the relay at {0}; the message will send when you reconnect")]
    Unreachable(String),
    /// The relay's certificate did not match the pinned key, or a remote relay
    /// was configured without a pin at all.
    ///
    /// This is the loud one. It means the connection is not demonstrably to the
    /// relay the user configured, and the correct response is to stop.
    #[error("the relay at {0} could not be verified against a pinned key; Pouch will not connect")]
    PinMismatch(String),
    /// The relay rejected the request.
    #[error("the relay rejected the request (status {0})")]
    Rejected(u16),
    /// The relay returned something unreadable.
    #[error("the relay returned a response Pouch could not read")]
    MalformedResponse,
    /// The blob exceeded what the relay accepts.
    #[error("this message is too large for the relay to accept")]
    TooLarge,
    /// Bootstrapping a Tor connection failed — no consensus reachable, no
    /// circuit could be built, or the onion address could not be resolved.
    /// Distinct from `Unreachable`, which means a specific relay did not
    /// answer; this means Tor itself never got going.
    #[error("could not establish a Tor connection: {0}")]
    TorBootstrapFailed(String),
}

/// A blob waiting in an inbox.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The relay's random identifier for this blob.
    pub message_id: String,
    /// Ciphertext, exactly as stored. Not yet authenticated — it came from a
    /// hostile source and means nothing until MLS says otherwise.
    pub blob: Vec<u8>,
}

/// Where the relay lives and how its certificate is pinned.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Base URL, e.g. `https://relay.example:8443`.
    pub base_url: String,
    /// SHA-256 of the relay certificate's SubjectPublicKeyInfo, hex encoded.
    ///
    /// `None` disables pinning and is only accepted for a loopback address
    /// during development. [`RelayClient::new`] enforces that.
    pub spki_pin: Option<String>,
}

impl RelayConfig {
    /// A local development relay with no TLS and no pinning.
    ///
    /// Named `insecure_local` rather than `local` so a call site reads as what
    /// it is. No user should ever be running this configuration.
    pub fn insecure_local(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            spki_pin: None,
        }
    }

    /// A relay reached over TLS with its public key pinned.
    pub fn pinned(base_url: impl Into<String>, spki_pin: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            spki_pin: Some(spki_pin.into()),
        }
    }

    /// The direct relay this deployment talks to, from the environment.
    ///
    /// `POUCH_RELAY` names it and `POUCH_RELAY_PIN` pins it. Nothing set means
    /// the caller's own default — for both shipped clients that is loopback, so
    /// a fresh install keeps talking to a relay on the same machine.
    ///
    /// These are the names the CLI has used since Phase 1. This function exists
    /// because the desktop client had its address *compiled in*, so every copy
    /// of a distributed build could only reach a relay on the machine it ran
    /// on — which made "self-hostable relay" true of the architecture and false
    /// of the artifact. Lifting the CLI's own logic here rather than writing a
    /// second copy in the desktop client is D-046's rule applied to
    /// configuration: two hand-maintained readers of one variable drift, and
    /// the failure mode is a user who sets the documented variable and watches
    /// one of the two clients ignore it.
    ///
    /// Deliberately **not** a user preference, and deliberately not read from
    /// anywhere the UI can write. It is the same boundary
    /// [`TorRelayConfig::from_env`] already draws, for the same reason: a client
    /// that can be pointed at an arbitrary relay from its own interface is a
    /// client that can be talked into it. Pointing at the wrong relay does not
    /// expose message content — the relay never holds a key — but it does hand
    /// that operator the inbox identifiers and connection timing that
    /// `THREAT_MODEL.md` §5 lists as visible, and it silently breaks delivery.
    ///
    /// No pin plus a non-loopback address is still refused by
    /// [`RelayClient::new`] rather than warned about (D-017). Setting the URL
    /// alone therefore fails closed, which is the intended behaviour: the
    /// missing pin is a configuration error, not a downgrade to accept.
    pub fn from_env(default_url: &str) -> Self {
        let base_url = std::env::var("POUCH_RELAY").unwrap_or_else(|_| default_url.to_string());
        let spki_pin = std::env::var("POUCH_RELAY_PIN")
            .ok()
            .filter(|pin| !pin.trim().is_empty());

        Self { base_url, spki_pin }
    }

    /// Whether the configured host is genuinely a loopback address.
    ///
    /// Compared against the host component after an exact prefix match, so a
    /// registered domain like `127.0.0.1.example.com` — which a `starts_with`
    /// check on the whole URL would happily accept — is not treated as local.
    pub fn is_loopback(&self) -> bool {
        let Some(rest) = self.base_url.strip_prefix("http://") else {
            return false;
        };
        // Strip anything after the authority.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

        // An IPv6 literal is bracketed; anything else splits on the port colon.
        let host = if let Some(end) = authority.strip_prefix('[') {
            match end.split_once(']') {
                // Whatever follows the closing bracket must be a port and
                // nothing else. `[::1].evil.com` parses to a loopback host with
                // a trailing domain otherwise, which is a host someone else
                // controls being treated as local.
                Some((inner, after)) if after.is_empty() || after.starts_with(':') => inner,
                _ => return false,
            }
        } else {
            authority.split(':').next().unwrap_or_default()
        };

        matches!(host, "127.0.0.1" | "localhost" | "::1")
    }
}

/// The two ways `RelayClient` can actually reach a relay.
///
/// The Tor variant is boxed because it is substantially larger than the
/// `reqwest` client — an unboxed enum would make every direct-transport
/// `RelayClient` pay for the Tor backend's size.
enum Backend {
    Direct(reqwest::Client),
    Tor(Box<tor::TorBackend>),
}

/// A client for one relay.
pub struct RelayClient {
    /// Human-readable address for display in the manifest, Custody Strip,
    /// and Security details — an `https://` URL for Direct, `onion:port` for
    /// Tor.
    address: String,
    route: Route,
    backend: Backend,
}

impl RelayClient {
    /// Builds a direct-transport client.
    ///
    /// **Refuses to build an unpinned client for a non-loopback address.** An
    /// unpinned TLS connection to a remote relay relies on the public CA
    /// system, which is exactly the trusted third party pinning exists to
    /// remove (D-017). A hard error rather than a warning means the insecure
    /// configuration cannot be reached by forgetting to set something.
    pub fn new(config: RelayConfig) -> Result<Self, TransportError> {
        if config.spki_pin.is_none() && !config.is_loopback() {
            return Err(TransportError::PinMismatch(config.base_url.clone()));
        }

        let http = reqwest::Client::builder()
            // A hostile relay must not be able to hold a client open forever.
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| TransportError::Unreachable(config.base_url.clone()))?;

        Ok(Self {
            address: config.base_url,
            route: Route::Direct,
            backend: Backend::Direct(http),
        })
    }

    /// Builds a Tor-transport client, bootstrapping a Tor connection.
    ///
    /// This is async and can take real time — Tor bootstrap means fetching a
    /// consensus and building a first circuit, not a local operation. See
    /// [`tor::TorBackend::connect`] for the implementation.
    pub async fn connect_tor(config: TorRelayConfig) -> Result<Self, TransportError> {
        let address = format!("{}:{}", config.onion_host, config.onion_port);
        let backend = tor::TorBackend::connect(config).await?;
        Ok(Self {
            address,
            route: Route::Tor,
            backend: Backend::Tor(Box::new(backend)),
        })
    }

    /// The relay address, for display in the manifest and Custody Strip.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Which route this client actually uses. Read by the manifest and the
    /// Custody Strip instead of either assuming Direct or reconstructing it
    /// from the address string.
    pub fn route(&self) -> Route {
        self.route
    }

    /// Posts a blob to an inbox. Returns the relay's identifier for it.
    pub async fn send(&self, inbox_id: &str, blob: &[u8]) -> Result<String, TransportError> {
        match &self.backend {
            Backend::Direct(http) => self.send_direct(http, inbox_id, blob).await,
            Backend::Tor(tor_backend) => tor_backend.send(inbox_id, blob).await,
        }
    }

    async fn send_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
        blob: &[u8],
    ) -> Result<String, TransportError> {
        let url = format!("{}/inbox/{inbox_id}", self.address);

        let response = http
            .post(&url)
            .body(blob.to_vec())
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        let status = response.status();
        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(TransportError::TooLarge);
        }
        if !status.is_success() {
            return Err(TransportError::Rejected(status.as_u16()));
        }

        #[derive(Deserialize)]
        struct Accepted {
            message_id: String,
        }

        let accepted: Accepted = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        Ok(accepted.message_id)
    }

    /// Collects what is waiting for an inbox, without erasing it.
    pub async fn collect(&self, inbox_id: &str) -> Result<Vec<Envelope>, TransportError> {
        match &self.backend {
            Backend::Direct(http) => self.collect_direct(http, inbox_id).await,
            Backend::Tor(tor_backend) => tor_backend.collect(inbox_id).await,
        }
    }

    async fn collect_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
    ) -> Result<Vec<Envelope>, TransportError> {
        use base64::Engine as _;

        let url = format!("{}/inbox/{inbox_id}", self.address);

        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        #[derive(Deserialize)]
        struct Waiting {
            message_id: String,
            blob: String,
        }
        #[derive(Deserialize)]
        struct Collected {
            messages: Vec<Waiting>,
        }

        let collected: Collected = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        collected
            .messages
            .into_iter()
            .map(|m| {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(m.blob.as_bytes())
                    .map_err(|_| TransportError::MalformedResponse)?;
                Ok(Envelope {
                    message_id: m.message_id,
                    blob,
                })
            })
            .collect()
    }

    /// Tells the relay a set of blobs has been stored and may be erased.
    ///
    /// Called only after the messages are safely in the local database. Doing
    /// it earlier would lose messages on a crash between the two steps.
    pub async fn acknowledge(
        &self,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        if message_ids.is_empty() {
            return Ok(0);
        }
        match &self.backend {
            Backend::Direct(http) => self.acknowledge_direct(http, inbox_id, message_ids).await,
            Backend::Tor(tor_backend) => tor_backend.acknowledge(inbox_id, message_ids).await,
        }
    }

    async fn acknowledge_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        let url = format!("{}/inbox/{inbox_id}/ack", self.address);

        #[derive(Serialize)]
        struct Ack<'a> {
            message_ids: &'a [String],
        }
        #[derive(Deserialize)]
        struct Erased {
            erased: usize,
        }

        let response = http
            .post(&url)
            .json(&Ack { message_ids })
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let erased: Erased = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        Ok(erased.erased)
    }

    /// Whether the relay answers at all. Drives the Custody Strip's transport
    /// field between the configured route and `OFFLINE`.
    pub async fn reachable(&self) -> bool {
        match &self.backend {
            Backend::Direct(http) => {
                let url = format!("{}/health", self.address);
                matches!(http.get(&url).send().await, Ok(r) if r.status().is_success())
            }
            Backend::Tor(tor_backend) => tor_backend.reachable().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unpinned_remote_relay_is_refused() {
        // The configuration that would quietly fall back to the public CA
        // system must be unreachable by omission, not merely discouraged.
        let config = RelayConfig::insecure_local("https://relay.example.com");
        assert!(matches!(
            RelayClient::new(config),
            Err(TransportError::PinMismatch(_))
        ));
    }

    #[test]
    fn an_unpinned_loopback_relay_is_allowed_for_development() {
        for url in [
            "http://127.0.0.1:8443",
            "http://localhost:8443",
            "http://[::1]:8443",
            "http://127.0.0.1",
        ] {
            assert!(
                RelayClient::new(RelayConfig::insecure_local(url)).is_ok(),
                "{url} should be usable for local development"
            );
        }
    }

    #[test]
    fn a_pinned_remote_relay_is_allowed() {
        let config = RelayConfig::pinned("https://relay.example.com", "a".repeat(64));
        assert!(RelayClient::new(config).is_ok());
    }

    #[test]
    fn a_hostname_that_merely_begins_with_a_loopback_address_is_not_loopback() {
        // `127.0.0.1.evil.com` is a registrable domain someone else controls. A
        // naive starts_with check on the URL accepts it and disables pinning
        // against an attacker-controlled host.
        for url in [
            "http://127.0.0.1.evil.com",
            "http://127.0.0.1.evil.com:8443/inbox",
            "http://localhost.evil.com",
            "http://[::1].evil.com",
        ] {
            assert!(
                RelayClient::new(RelayConfig::insecure_local(url)).is_err(),
                "{url} must not be treated as loopback"
            );
        }
    }

    /// One test rather than four, because environment variables are process
    /// global and `cargo test` runs test functions on parallel threads. Four
    /// tests each setting and clearing the same two variables would pass alone
    /// and interfere with one another under load — a flake that appears to be
    /// about transport configuration and is really about test isolation. The
    /// Tor equivalent above is a single test for the same reason.
    #[test]
    fn from_env_reads_the_deployment_relay_and_still_fails_closed() {
        // Nothing set: the caller's default, unpinned, which is loopback for a
        // fresh install and must stay usable.
        std::env::remove_var("POUCH_RELAY");
        std::env::remove_var("POUCH_RELAY_PIN");
        let config = RelayConfig::from_env("http://127.0.0.1:8443");
        assert_eq!(config.base_url, "http://127.0.0.1:8443");
        assert_eq!(config.spki_pin, None);
        assert!(
            RelayClient::new(config).is_ok(),
            "the default must remain a working local relay"
        );

        // Both set: the deployment's relay, pinned.
        std::env::set_var("POUCH_RELAY", "https://relay.example.com:8443");
        std::env::set_var("POUCH_RELAY_PIN", "a".repeat(64));
        let config = RelayConfig::from_env("http://127.0.0.1:1");
        assert_eq!(config.base_url, "https://relay.example.com:8443");
        assert_eq!(config.spki_pin, Some("a".repeat(64)));
        assert!(RelayClient::new(config).is_ok());

        // An empty variable is what `set VAR=` leaves behind. Reading it as a
        // pin would fail later with a certificate error rather than now with
        // the honest "you have not set a pin".
        std::env::set_var("POUCH_RELAY_PIN", "   ");
        assert_eq!(
            RelayConfig::from_env("ignored").spki_pin,
            None,
            "a whitespace-only pin is not a pin"
        );

        // URL without a pin: D-017's refusal still applies. Setting the address
        // alone must fail closed rather than fall back to the public CA system.
        std::env::remove_var("POUCH_RELAY_PIN");
        let config = RelayConfig::from_env("http://127.0.0.1:1");
        assert!(
            matches!(
                RelayClient::new(config),
                Err(TransportError::PinMismatch(_))
            ),
            "an unpinned remote relay must be refused however it was configured"
        );

        std::env::remove_var("POUCH_RELAY");
    }

    #[test]
    fn https_is_never_treated_as_loopback_and_so_always_needs_a_pin() {
        assert!(!RelayConfig::insecure_local("https://127.0.0.1:8443").is_loopback());
    }

    #[test]
    fn every_route_names_what_it_actually_does() {
        assert_eq!(Route::Direct.label(), "DIRECT");
        assert_eq!(Route::Tor.label(), "TOR");
        assert_eq!(Route::Offline.label(), "OFFLINE");

        // Direct transport must admit the IP exposure rather than gloss it.
        assert!(Route::Direct.explanation().contains("IP address"));
        // Tor must admit what it does not hide.
        assert!(Route::Tor.explanation().contains("internet provider"));
    }

    #[test]
    fn no_route_claims_to_be_the_secure_one() {
        for route in [Route::Direct, Route::Tor, Route::Offline] {
            let text = route.explanation().to_lowercase();
            for banned in [
                "unbreakable",    // guardrail-allow: asserted absent
                "military grade", // guardrail-allow: asserted absent
                "100% secure",    // guardrail-allow: asserted absent
                "totally safe",   // guardrail-allow: asserted absent
            ] {
                assert!(
                    !text.contains(banned),
                    "{banned:?} appears in {} copy",
                    route.label()
                );
            }
        }
    }

    #[test]
    fn a_freshly_built_direct_client_reports_the_direct_route() {
        let client =
            RelayClient::new(RelayConfig::insecure_local("http://127.0.0.1:8443")).expect("builds");
        assert_eq!(client.route(), Route::Direct);
    }
}
