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

    let listener = tokio::net::TcpListener::bind(&bind).await?;

    // The only line this process ever prints. It names the bind address, which
    // the operator already knows, and nothing about any request.
    println!("pouch-relay listening on {bind} (access logging disabled)");

    axum::serve(listener, router(state)).await?;
    Ok(())
}
