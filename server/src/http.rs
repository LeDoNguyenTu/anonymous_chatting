//! The relay's HTTP surface.
//!
//! Three operations, and deliberately nothing else:
//!
//! | | |
//! |---|---|
//! | `POST /inbox/{id}` | hand the relay a blob |
//! | `GET /inbox/{id}` | see what is waiting |
//! | `POST /inbox/{id}/ack` | confirm storage, so the relay can erase |
//!
//! There is no account creation, no directory lookup, no presence, no read
//! receipt, and no queue-depth endpoint. Every one of those is absent because
//! it would let the relay — or anyone reading its responses — learn something
//! about a person. Adding one is a stop-and-ask under SPEC §2.6.

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::store::{Store, StoreError};

/// Largest blob the relay will accept, in bytes.
///
/// Padding buckets top out at 16 MB plus increments (SPEC §7.1); this leaves
/// room for one bucket plus protocol overhead.
pub const MAX_BLOB_BYTES: usize = 20 * 1024 * 1024;

/// Shared relay state.
#[derive(Clone)]
pub struct RelayState {
    store: Arc<Mutex<Store>>,
}

impl RelayState {
    /// Wraps an opened store for use by the HTTP layer.
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Access to the underlying queue, for the sweeper and for tests.
    pub fn store(&self) -> &Arc<Mutex<Store>> {
        &self.store
    }
}

/// Response to a successful submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct Accepted {
    /// The random identifier the blob was filed under.
    pub message_id: String,
}

/// One waiting blob, base64 encoded for JSON transport.
#[derive(Debug, Serialize, Deserialize)]
pub struct Waiting {
    /// The blob's random identifier.
    pub message_id: String,
    /// Standard base64 ciphertext.
    pub blob: String,
}

/// Everything currently waiting for an inbox.
#[derive(Debug, Serialize, Deserialize)]
pub struct Collected {
    /// Waiting blobs, oldest identifier first.
    pub messages: Vec<Waiting>,
}

/// Identifiers a client has confirmed it stored.
#[derive(Debug, Serialize, Deserialize)]
pub struct Ack {
    /// Message identifiers to erase.
    pub message_ids: Vec<String>,
}

/// How many blobs an acknowledgement erased.
#[derive(Debug, Serialize, Deserialize)]
pub struct Erased {
    /// Count of blobs removed.
    pub erased: usize,
}

/// Errors as seen by a client.
///
/// Deliberately uninformative. A relay that distinguishes "no such inbox" from
/// "inbox is empty" has just built an account-existence oracle, which is a
/// metadata leak the rest of the design works to avoid.
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::MalformedInboxId => {
                ApiError(StatusCode::BAD_REQUEST, "malformed inbox identifier")
            }
            StoreError::BlobTooLarge => ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "blob exceeds the maximum accepted size",
            ),
            // The underlying database error is not surfaced. It could name a
            // column, and columns are the thing being kept quiet about.
            StoreError::Database(_) => {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "relay storage failure")
            }
        }
    }
}

/// Builds the relay router.
///
/// No `TraceLayer`, no request logger, no metrics middleware. That absence is
/// the feature; `scripts/check-guardrails.sh` fails the build if one appears.
pub fn router(state: RelayState) -> Router {
    Router::new()
        .route("/inbox/:inbox_id", post(submit).get(collect))
        .route("/inbox/:inbox_id/ack", post(acknowledge))
        .route("/health", get(health))
        .with_state(state)
}

/// Liveness only. Returns a fixed string and nothing about the queue.
async fn health() -> &'static str {
    "ok"
}

/// Accepts a blob for an inbox.
///
/// The body is raw bytes, not JSON: the relay has no reason to parse the
/// ciphertext, and refusing to parse it is the simplest way to guarantee it
/// never accidentally inspects it.
async fn submit(
    State(state): State<RelayState>,
    Path(inbox_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Accepted>), ApiError> {
    let store = state.store.lock().map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relay storage unavailable",
        )
    })?;

    let message_id = store.enqueue(&inbox_id, &body)?;
    Ok((StatusCode::CREATED, Json(Accepted { message_id })))
}

/// Returns what is waiting for an inbox, without erasing it.
async fn collect(
    State(state): State<RelayState>,
    Path(inbox_id): Path<String>,
) -> Result<Json<Collected>, ApiError> {
    use base64::Engine as _;

    let store = state.store.lock().map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relay storage unavailable",
        )
    })?;

    let messages = store
        .collect(&inbox_id)?
        .into_iter()
        .map(|m| Waiting {
            message_id: m.message_id,
            blob: base64::engine::general_purpose::STANDARD.encode(m.blob),
        })
        .collect();

    Ok(Json(Collected { messages }))
}

/// Erases blobs the client has confirmed it stored.
async fn acknowledge(
    State(state): State<RelayState>,
    Path(inbox_id): Path<String>,
    Json(ack): Json<Ack>,
) -> Result<Json<Erased>, ApiError> {
    let store = state.store.lock().map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relay storage unavailable",
        )
    })?;

    let erased = store.acknowledge(&inbox_id, &ack.message_ids)?;
    Ok(Json(Erased { erased }))
}
