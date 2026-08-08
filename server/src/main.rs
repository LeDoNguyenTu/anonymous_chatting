//! Pouch relay binary.
//!
//! Binds the queue to an address and sweeps expired blobs. Everything
//! interesting is in the library — see `lib.rs` for the design constraint this
//! server exists to satisfy.

use std::time::Duration;

use pouch_relay::http::{router, RelayState, MAX_BLOB_BYTES};
use pouch_relay::store::Store;

/// How often expired blobs are swept. Expiry is also enforced on read, so a
/// stopped sweeper delays erasure but cannot cause a blob to be served past its
/// TTL.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("POUCH_RELAY_DB").unwrap_or_else(|_| "pouch-relay.db".to_string());
    let bind = std::env::var("POUCH_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());

    let store = Store::open(&db_path, MAX_BLOB_BYTES)?;
    let state = RelayState::new(store);

    // Sweeper. Deliberately holds the lock only for the duration of one delete.
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            if let Ok(store) = sweeper.store().lock() {
                // A failed sweep is not reported anywhere. There is nowhere to
                // report it to: the relay writes no logs (SPEC §2.3), and
                // expiry is enforced on read regardless.
                let _ = store.sweep_expired();
            }
        }
    });

    let app = router(state);

    // Held for the process lifetime — dropping this handle tears the onion
    // service down. Opt-in: no `POUCH_RELAY_TOR_STATE`, no onion service, and
    // the direct listener below is unaffected either way.
    let _onion_service_guard = if let Ok(tor_state_dir) = std::env::var("POUCH_RELAY_TOR_STATE") {
        // rustls refuses to guess a crypto provider when its feature flags do
        // not name exactly one, and arti's `rustls` feature deliberately names
        // none — it leaves the choice to the application. Installing it here,
        // explicitly, means a future dependency change cannot quietly swap the
        // provider out from under the relay, and the failure (if any) happens
        // on this line rather than as a panic deep inside the first TLS
        // handshake. Ignoring the error is correct: it only fails if a
        // provider is already installed, which is the desired end state.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let nickname = std::env::var("POUCH_RELAY_ONION_NICKNAME")
            .unwrap_or_else(|_| "pouch-relay".to_string());
        match pouch_relay::onion::run_onion_service(app.clone(), &tor_state_dir, &nickname).await {
            Ok((address, service)) => {
                // Names an operational address the operator configured, and
                // nothing about any request — same class of information as the
                // bind address printed below.
                println!("pouch-relay onion service listening at {address}");
                Some(service)
            }
            Err(e) => {
                // Printed, not swallowed: an operator who asked for an onion
                // service and silently got only the direct listener would
                // believe they had a protection they do not have.
                println!("pouch-relay: onion service failed to start: {e}");
                None
            }
        }
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(&bind).await?;

    // The only line this process ever prints in the default configuration. It
    // names the bind address, which the operator already knows, and nothing
    // about any request.
    println!("pouch-relay listening on {bind} (access logging disabled)");

    axum::serve(listener, app).await?;
    Ok(())
}
