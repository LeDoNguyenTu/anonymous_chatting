//! The relay as a Tor v3 onion service (Phase 4, D-039).
//!
//! `axum::serve` in the pinned axum 0.7.9 only accepts a concrete
//! `tokio::net::TcpListener`, not an arbitrary stream source, so an onion
//! service's incoming connections cannot go through it directly. Instead,
//! each accepted Tor stream is served individually with
//! `hyper_util::server::conn::auto`, using the same `axum::Router` (via its
//! `tower::Service` implementation) the direct TCP listener already uses —
//! one set of routes, two ways in.
//!
//! What this changes about what the relay learns: nothing it stores, and one
//! thing it does not. A blob arriving over a rendezvous circuit carries no
//! source IP for the relay to see, because there is no TCP connection from
//! the client to see one from. That is the whole point of Phase 4 — the wire
//! protocol already had no sender field (D-026), and this closes the network
//! layer that remained.

use std::sync::Arc;

use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use futures_util::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::RunningOnionService;
use tor_rtcompat::PreferredRuntime;

/// Bootstraps Tor, launches the onion service, and spawns a background task
/// that serves `router` over every incoming Tor stream.
///
/// Returns the onion address and the running service handle. **The caller must
/// keep the handle alive for as long as the service should run** — dropping it
/// tears the onion service down, and the serving loop would then sit on a
/// stream that never yields again.
///
/// Bootstrapping (fetching a consensus, building the first circuits) is real
/// network I/O and can take real time — this is why nothing here has a fixed
/// short timeout; the caller decides how long to wait, if at all.
pub async fn run_onion_service(
    router: axum::Router,
    tor_state_dir: &str,
    nickname: &str,
) -> anyhow::Result<(String, Arc<RunningOnionService>)> {
    let mut tor_config_builder = TorClientConfig::builder();
    // `new_literal`, not `new`: `new` would treat `$` and `~` in an operator's
    // path as variables to expand. Matches `core/src/transport/tor.rs`.
    let state_dir = CfgPath::new_literal(std::path::PathBuf::from(tor_state_dir));
    tor_config_builder
        .storage()
        .state_dir(state_dir.clone())
        .cache_dir(state_dir);
    let tor_config = tor_config_builder.build()?;

    let tor_client: Arc<TorClient<PreferredRuntime>> =
        TorClient::create_bootstrapped(tor_config).await?;

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse()?)
        .build()?;

    let Some((onion_service, rend_requests)) = tor_client.launch_onion_service(svc_config)? else {
        anyhow::bail!("onion service hosting is disabled in this Tor client configuration");
    };

    let onion_address = onion_service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("onion service has no address yet"))?
        // arti redacts onion addresses in `Display` on purpose, so one cannot
        // reach a log by accident. This one is going to the operator who
        // configured the service and needs it to connect a client, which is
        // the case the unredacted accessor exists for.
        .display_unredacted()
        .to_string();

    tokio::spawn(async move {
        // `tor_client` is moved in here deliberately: the client owns the
        // circuits the service runs over, so it has to outlive the loop.
        let _tor_client = tor_client;
        let mut stream_requests =
            std::pin::pin!(tor_hsservice::handle_rend_requests(rend_requests));
        while let Some(stream_request) = stream_requests.next().await {
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(data_stream) = stream_request.accept(Connected::new_empty()).await else {
                    return;
                };
                let io = TokioIo::new(data_stream);
                let service = TowerToHyperService::new(router);
                // A failed connection is dropped rather than reported. There
                // is nowhere to report it to — this process writes no logs
                // (SPEC §2.3) — and a per-connection error is exactly the kind
                // of record that would turn into a request log.
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    Ok((onion_address, onion_service))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_nickname_builds_a_config() {
        let config = OnionServiceConfigBuilder::default()
            .nickname("pouch-relay".parse().expect("valid nickname"))
            .build();
        assert!(config.is_ok());
    }

    #[test]
    fn an_empty_nickname_is_rejected() {
        let parsed: Result<tor_hsservice::HsNickname, _> = "".parse();
        assert!(
            parsed.is_err(),
            "an empty nickname must not silently become valid"
        );
    }
}
