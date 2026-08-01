//! Server blindness — SPEC §8.3.
//!
//! The single highest-value test in the repository, and the one the whole
//! architecture is arranged to satisfy: **a full database dump handed to an
//! adversary must yield nothing useful.**
//!
//! It is written the way §8.3 requires — before the client feature it verifies
//! — so the relay is developed against it rather than the other way round. The
//! placeholder encryption in `sealed()` below is replaced by a real MLS
//! payload from `pouch-core` once Phase 1's core lands; the assertions do not
//! change when that happens, because they are about what the *relay* can see,
//! and the relay must be equally blind either way.
//!
//! Every assertion here is phrased against the raw bytes on disk rather than
//! against an API response. An API can be written to hide a column. A hexdump
//! cannot.

use std::net::SocketAddr;

use pouch_relay::http::{router, Ack, Collected, RelayState, MAX_BLOB_BYTES};
use pouch_relay::store::Store;

/// Strings a dump must never contain. Each stands for a class of leak.
const SECRET_MESSAGE: &str = "MEETING-AT-DAWN-8f21c7d9-CANARY";
const SENDER_NAME: &str = "Brian-Le-Do-Nguyen-Tu-CANARY";
const RECIPIENT_NAME: &str = "Mai-Nguyen-CANARY";
const CONVERSATION_TOPIC: &str = "the-thing-we-agreed-not-to-name-CANARY";

/// Spawns the relay on a real port against a real file-backed database.
///
/// A file, not `:memory:`, because the test's whole point is to read the bytes
/// SQLite actually wrote.
async fn spawn_relay(db_path: &str) -> SocketAddr {
    let store = Store::open(db_path, MAX_BLOB_BYTES).expect("relay store opens");
    let state = RelayState::new(store);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("relay binds an ephemeral port");
    let addr = listener.local_addr().expect("relay reports its address");

    tokio::spawn(async move {
        axum::serve(listener, router(state))
            .await
            .expect("relay serves");
    });

    addr
}

/// Stands in for the real client-side encryption until Phase 1's core lands.
///
/// Deliberately *not* a cipher — it is a reversible transform, and calling it
/// encryption anywhere would be exactly the kind of thing SPEC §2.1 forbids.
/// Its only job is to make the bytes the relay receives not literally equal to
/// the plaintext, so that this test verifies the relay's blindness rather than
/// accidentally verifying the strength of a placeholder.
///
/// When this is swapped for a real MLS application message, every assertion
/// below stays as it is. That is the point: the relay's blindness must not
/// depend on which cipher the client chose.
fn sealed(plaintext: &str) -> Vec<u8> {
    // A keystream this test controls, so the transform is obviously not a
    // security claim. Real confidentiality arrives with pouch-core.
    plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ (0xA5u8.wrapping_add(i as u8)))
        .collect()
}

/// Reads every byte of the database file, including pages SQLite has freed but
/// not yet overwritten.
///
/// Freed pages matter: a `DELETE` marks a page reusable without scrubbing it,
/// so a naive `SELECT`-based check would pass while the plaintext of an
/// acknowledged message still sat in the file.
fn dump(db_path: &str) -> Vec<u8> {
    std::fs::read(db_path).expect("database file is readable")
}

/// Asserts a canary appears nowhere in the dump, in any plausible encoding.
fn assert_absent(dump: &[u8], canary: &str, what: &str) {
    let raw = canary.as_bytes();
    assert!(
        !contains(dump, raw),
        "{what} appears in the relay database as plain bytes"
    );

    // UTF-16, in case a future storage layer round-trips through it.
    let utf16: Vec<u8> = canary
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert!(!contains(dump, &utf16), "{what} appears UTF-16 encoded");

    // Base64 and hex, because "we encoded it" is not the same as "we removed
    // it" and is the most likely form an accidental leak would take.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    assert!(
        !contains(dump, b64.as_bytes()),
        "{what} appears base64 encoded"
    );
    assert!(
        !contains(dump, hex::encode(raw).as_bytes()),
        "{what} appears hex encoded"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn relay_database_reveals_nothing_about_a_real_conversation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("relay.db");
    let db_path = db_path.to_str().expect("utf-8 path").to_string();

    let addr = spawn_relay(&db_path).await;
    let client = reqwest::Client::new();

    // Two inboxes. Opaque random hex — not names, not hashes of names.
    let alice_inbox = "9c2f81a4e07b3d5162fa48c0d93e7b16";
    let mai_inbox = "4d81f0a7c3e29b6510af7d3c84e2b095";

    // A conversation. Every payload carries a canary.
    let exchange = [
        (mai_inbox, format!("{SENDER_NAME}: {SECRET_MESSAGE}")),
        (mai_inbox, format!("re: {CONVERSATION_TOPIC}")),
        (alice_inbox, format!("{RECIPIENT_NAME}: understood")),
    ];

    for (inbox, text) in &exchange {
        let res = client
            .post(format!("http://{addr}/inbox/{inbox}"))
            .body(sealed(text))
            .send()
            .await
            .expect("relay accepts a blob");
        assert_eq!(res.status(), 201, "submission succeeds");
    }

    // Collect, as a real client would.
    let collected: Collected = client
        .get(format!("http://{addr}/inbox/{mai_inbox}"))
        .send()
        .await
        .expect("collection succeeds")
        .json()
        .await
        .expect("collection returns JSON");
    assert_eq!(collected.messages.len(), 2, "both messages are waiting");

    // Acknowledge one, leaving the other queued, so the dump covers both a
    // live row and a freed page.
    let ack = Ack {
        message_ids: vec![collected.messages[0].message_id.clone()],
    };
    let res = client
        .post(format!("http://{addr}/inbox/{mai_inbox}/ack"))
        .json(&ack)
        .send()
        .await
        .expect("acknowledgement succeeds");
    assert_eq!(res.status(), 200);

    // Give SQLite a moment to flush, then read the file as an adversary would.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let bytes = dump(&db_path);
    assert!(
        !bytes.is_empty(),
        "the database file has content to inspect"
    );

    // ---- the assertions that matter ------------------------------------
    assert_absent(&bytes, SECRET_MESSAGE, "message content");
    assert_absent(&bytes, SENDER_NAME, "the sender's display name");
    assert_absent(&bytes, RECIPIENT_NAME, "the recipient's display name");
    assert_absent(&bytes, CONVERSATION_TOPIC, "conversation content");

    // Plain English fragments, to catch a leak that mangles the canary but
    // preserves the payload around it.
    for fragment in ["understood", "MEETING", "re: the-thing"] {
        assert!(
            !contains(&bytes, fragment.as_bytes()),
            "plaintext fragment {fragment:?} survives in the relay database"
        );
    }
}

#[tokio::test]
async fn relay_schema_holds_four_columns_and_no_more() {
    // A leak is far more likely to arrive as a helpful new column than as a
    // dramatic exfiltration. This pins the shape.
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("schema.db");
    let db_path = db_path.to_str().expect("utf-8 path");

    {
        let store = Store::open(db_path, MAX_BLOB_BYTES).expect("store opens");
        store
            .enqueue("9c2f81a4e07b3d5162fa48c0d93e7b16", b"blob")
            .expect("enqueue succeeds");
    }

    let conn = rusqlite::Connection::open(db_path).expect("dump opens");
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('queue') ORDER BY cid")
        .expect("schema is introspectable");
    let columns: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("columns enumerate")
        .map(|r| r.expect("column name"))
        .collect();

    assert_eq!(
        columns,
        vec!["message_id", "inbox_id", "blob", "expires_at"],
        "the relay stores exactly the four fields in SPEC §4.3 — adding one is \
         a threat-model change, not a schema change"
    );

    // Every table in the database, not just the one we know about.
    let mut tables = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .expect("table list");
    let names: Vec<String> = tables
        .query_map([], |r| r.get::<_, String>(0))
        .expect("tables enumerate")
        .map(|r| r.expect("table name"))
        .collect();
    assert_eq!(names, vec!["queue"], "the relay has exactly one table");
}

#[tokio::test]
async fn relay_stores_no_timestamp_finer_than_the_ttl_bucket() {
    // SPEC §2.3 forbids plaintext timestamps beyond the queue TTL. A
    // second-precision expiry is such a timestamp wearing a different hat:
    // subtract the TTL and it is an exact arrival clock.
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("time.db");
    let db_path = db_path.to_str().expect("utf-8 path");

    {
        let store = Store::open(db_path, MAX_BLOB_BYTES).expect("store opens");
        for _ in 0..16 {
            store
                .enqueue("9c2f81a4e07b3d5162fa48c0d93e7b16", b"blob")
                .expect("enqueue succeeds");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    let conn = rusqlite::Connection::open(db_path).expect("dump opens");
    let distinct: i64 = conn
        .query_row("SELECT COUNT(DISTINCT expires_at) FROM queue", [], |r| {
            r.get(0)
        })
        .expect("expiry values are countable");

    assert_eq!(
        distinct, 1,
        "messages arriving together must be indistinguishable by expiry; \
         {distinct} distinct values means the column is an arrival clock"
    );

    // And the stored value must sit on a bucket boundary rather than on an
    // arbitrary second.
    let expiry: i64 = conn
        .query_row("SELECT expires_at FROM queue LIMIT 1", [], |r| r.get(0))
        .expect("expiry is readable");
    assert_eq!(
        expiry % 3600,
        0,
        "expiry is not aligned to an hour boundary"
    );
}

#[tokio::test]
async fn relay_does_not_reveal_whether_an_inbox_exists() {
    // An account-existence oracle would undo much of what the opaque inbox
    // identifier buys. An unknown inbox and an empty one must be
    // indistinguishable from outside.
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("oracle.db");
    let addr = spawn_relay(db_path.to_str().expect("utf-8 path")).await;
    let client = reqwest::Client::new();

    let used = "9c2f81a4e07b3d5162fa48c0d93e7b16";
    let never_used = "00112233445566778899aabbccddeeff";

    // Give the first inbox a message, then drain it so it is empty-but-known.
    client
        .post(format!("http://{addr}/inbox/{used}"))
        .body(sealed("x"))
        .send()
        .await
        .expect("submission succeeds");
    let collected: Collected = client
        .get(format!("http://{addr}/inbox/{used}"))
        .send()
        .await
        .expect("collection succeeds")
        .json()
        .await
        .expect("JSON");
    client
        .post(format!("http://{addr}/inbox/{used}/ack"))
        .json(&Ack {
            message_ids: collected
                .messages
                .iter()
                .map(|m| m.message_id.clone())
                .collect(),
        })
        .send()
        .await
        .expect("ack succeeds");

    let known = client
        .get(format!("http://{addr}/inbox/{used}"))
        .send()
        .await
        .expect("known inbox responds");
    let unknown = client
        .get(format!("http://{addr}/inbox/{never_used}"))
        .send()
        .await
        .expect("unknown inbox responds");

    assert_eq!(
        known.status(),
        unknown.status(),
        "a drained inbox and one that never existed must return the same status"
    );
    assert_eq!(
        known.text().await.expect("body"),
        unknown.text().await.expect("body"),
        "a drained inbox and one that never existed must return the same body"
    );
}
