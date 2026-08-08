//! Tor-routed transport (Phase 4, D-039).
//!
//! `reqwest` has no hook for a custom low-level connector, and arti-client
//! has no in-process SOCKS listener (only the separate `arti` CLI binary
//! does, which would mean shelling out to a subprocess rather than using an
//! audited library through its intended interface). This backend is
//! therefore built directly on `hyper`/`hyper-util`: a small
//! [`TorConnector`] implements `tower::Service<http::Uri>` by dialing the
//! request's own host:port through an already-bootstrapped
//! [`arti_client::TorClient`], and `hyper_util::client::legacy::Client`
//! drives ordinary HTTP requests over that.
//!
//! Plain HTTP over the circuit is deliberate, not an oversight. A v3 onion
//! service is already authenticated and encrypted end to end by the Tor
//! protocol itself — the address *is* the public key — so layering TLS on
//! top would add a certificate to verify without adding a property the
//! circuit does not already have. The message bytes are MLS ciphertext
//! before they reach this module regardless.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tor_rtcompat::PreferredRuntime;

use super::{Envelope, TransportError};

/// Where the Tor-routed relay lives, and where this client's Tor state
/// (guard relays, consensus cache, onion service keys — none of it a
/// message secret) persists across runs.
#[derive(Debug, Clone)]
pub struct TorRelayConfig {
    /// The relay's onion address, without scheme or port — e.g.
    /// `"abcdefg...onion"`.
    pub onion_host: String,
    /// The port the relay's onion service listens on.
    pub onion_port: u16,
    /// Directory for Tor's own state and cache. Never inside the encrypted
    /// database: this is bootstrap/circuit data, not a key or message.
    pub state_dir: String,
}

/// A Tor circuit, dressed as something `hyper_util`'s pooling client accepts.
///
/// `hyper_util` requires a connector's output to implement its `Connection`
/// trait, which reports connection metadata back to the pool. `DataStream`
/// cannot implement it directly — both types are foreign to this crate, so
/// the orphan rule forbids it — hence this newtype, whose entire job is to
/// carry that one trait plus pass-through I/O.
///
/// [`Connected::new()`] with nothing added is the honest answer here: the
/// extras it can carry describe proxy and ALPN state that a Tor circuit to an
/// onion service does not have. Claiming otherwise would put a fiction into
/// hyper's connection pool.
struct TorStream(TokioIo<arti_client::DataStream>);

impl Connection for TorStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl HyperRead for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl HyperWrite for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// A single-target Tor connector: every call dials whatever host:port the
/// request's own URI names, through the already-bootstrapped `TorClient`.
#[derive(Clone)]
struct TorConnector {
    tor_client: Arc<TorClient<PreferredRuntime>>,
}

impl tower_service::Service<http::Uri> for TorConnector {
    type Response = TorStream;
    type Error = TransportError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let tor_client = self.tor_client.clone();
        let host = uri.host().unwrap_or_default().to_string();
        let port = uri.port_u16().unwrap_or(80);
        Box::pin(async move {
            let stream = tor_client
                .connect((host.as_str(), port))
                .await
                .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;
            Ok(TorStream(TokioIo::new(stream)))
        })
    }
}

/// The Tor-routed half of `RelayClient`.
pub(super) struct TorBackend {
    hyper_client: HyperClient<TorConnector, Full<Bytes>>,
    onion_host: String,
    onion_port: u16,
}

impl TorBackend {
    /// Bootstraps a Tor connection and readies a client for one onion
    /// target. Slow by nature — fetching a consensus and building a first
    /// circuit is real network I/O, not a local operation — so this must
    /// never be called from a fast path.
    pub(super) async fn connect(config: TorRelayConfig) -> Result<Self, TransportError> {
        if config.onion_host.trim().is_empty()
            || config.onion_host.contains('\0')
            || config.onion_host.chars().any(|c| c.is_control())
        {
            return Err(TransportError::TorBootstrapFailed(
                "the configured onion address is not a valid hostname".to_string(),
            ));
        }

        let mut tor_config_builder = TorClientConfig::builder();
        // `CfgPath::new_literal` rather than `CfgPath::new`: the latter treats
        // `$VAR` and `~` in the string as expansions to perform. This path
        // comes from the host application (an OS app-data directory, or an env
        // var on the CLI), so a literal `$` in it is part of the path, not a
        // variable reference.
        let state_dir = CfgPath::new_literal(PathBuf::from(&config.state_dir));
        tor_config_builder
            .storage()
            .state_dir(state_dir.clone())
            .cache_dir(state_dir);
        let tor_config = tor_config_builder
            .build()
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        // `create_bootstrapped` hands back an `Arc` already — wrapping it in
        // another would just add an indirection.
        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        let connector = TorConnector { tor_client };
        let hyper_client = HyperClient::builder(TokioExecutor::new()).build(connector);

        Ok(Self {
            hyper_client,
            onion_host: config.onion_host,
            onion_port: config.onion_port,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", self.onion_host, self.onion_port)
    }

    pub(super) async fn send(&self, inbox_id: &str, blob: &[u8]) -> Result<String, TransportError> {
        let uri = self
            .url(&format!("/inbox/{inbox_id}"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .body(Full::new(Bytes::copy_from_slice(blob)))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        let status = response.status();
        if status == http::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(TransportError::TooLarge);
        }
        if !status.is_success() {
            return Err(TransportError::Rejected(status.as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();

        #[derive(Deserialize)]
        struct Accepted {
            message_id: String,
        }
        let accepted: Accepted =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;
        Ok(accepted.message_id)
    }

    pub(super) async fn collect(&self, inbox_id: &str) -> Result<Vec<Envelope>, TransportError> {
        use base64::Engine as _;

        let uri = self
            .url(&format!("/inbox/{inbox_id}"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();

        #[derive(Deserialize)]
        struct Waiting {
            message_id: String,
            blob: String,
        }
        #[derive(Deserialize)]
        struct Collected {
            messages: Vec<Waiting>,
        }
        let collected: Collected =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;

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

    pub(super) async fn acknowledge(
        &self,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        #[derive(Serialize)]
        struct Ack<'a> {
            message_ids: &'a [String],
        }
        #[derive(Deserialize)]
        struct Erased {
            erased: usize,
        }

        let body_bytes = serde_json::to_vec(&Ack { message_ids })
            .map_err(|_| TransportError::MalformedResponse)?;

        let uri = self
            .url(&format!("/inbox/{inbox_id}/ack"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();
        let erased: Erased =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;
        Ok(erased.erased)
    }

    pub(super) async fn reachable(&self) -> bool {
        let Ok(uri) = self.url("/health").parse::<http::Uri>() else {
            return false;
        };
        let Ok(request) = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
        else {
            return false;
        };
        matches!(self.hyper_client.request(request).await, Ok(r) if r.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_onion_host_that_is_not_a_valid_hostname_is_rejected_before_bootstrapping() {
        let config = TorRelayConfig {
            onion_host: "not a valid host\0".to_string(),
            onion_port: 8443,
            state_dir: std::env::temp_dir()
                .join("pouch-tor-test-invalid-host")
                .to_string_lossy()
                .to_string(),
        };
        let result = TorBackend::connect(config).await;
        assert!(
            result.is_err(),
            "a malformed onion host must not silently proceed"
        );
    }

    /// Ignored by default: this bootstraps a real Tor connection to the live
    /// Tor network, which needs network access and takes real time (seconds
    /// to tens of seconds). Run explicitly with `cargo test -- --ignored`
    /// when verifying this against the real network — see
    /// `docs/PROGRESS.md`'s Phase 4 manual verification checklist.
    ///
    /// **What this proves:** that `TorBackend::connect` really does fetch a
    /// consensus and build a circuit against the live Tor network, with the
    /// state directory and config this module constructs.
    ///
    /// **What it does not prove:** that the `TorConnector`/`TorStream` path
    /// carries an HTTP exchange. That needs a reachable onion service, and
    /// this test deliberately does not hard-code a third party's onion
    /// address — one was tried and turned out not to be a valid v3 address at
    /// all, which is exactly the brittleness worth avoiding. Set
    /// `POUCH_TEST_ONION=<host>:<port>` to extend this test to a real
    /// request; the project's own relay-as-onion-service covers the same
    /// ground end to end once that exists.
    #[tokio::test]
    #[ignore]
    async fn a_real_tor_bootstrap_succeeds_against_the_live_network() {
        let (onion_host, onion_port) = match std::env::var("POUCH_TEST_ONION") {
            Ok(target) => {
                let (host, port) = target
                    .rsplit_once(':')
                    .expect("POUCH_TEST_ONION is host:port");
                (host.to_string(), port.parse::<u16>().expect("a port"))
            }
            // No target configured: bootstrap is still exercised for real, and
            // the address below is never dialled.
            Err(_) => ("unused.invalid".to_string(), 80),
        };

        let config = TorRelayConfig {
            onion_host,
            onion_port,
            state_dir: std::env::temp_dir()
                .join("pouch-tor-test-real-bootstrap")
                .to_string_lossy()
                .to_string(),
        };
        let backend = TorBackend::connect(config).await.expect("bootstraps");

        if std::env::var("POUCH_TEST_ONION").is_err() {
            println!("bootstrap succeeded; set POUCH_TEST_ONION=host:port to also dial one");
            return;
        }

        let uri = backend.url("/").parse::<http::Uri>().expect("uri");
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .expect("request");

        let response = backend
            .hyper_client
            .request(request)
            .await
            .expect("the circuit carried an HTTP exchange");
        println!(
            "onion service answered over Tor with status {}",
            response.status()
        );
    }
}
