//! The Phase 1 exit criterion, as an automated test.
//!
//! SPEC §9 requires two clients on different machines to exchange text
//! reliably. Two clients in one process against a real relay is the part that
//! can be automated; the cross-machine half stays on the manual checklist in
//! `docs/PROGRESS.md`.
//!
//! Everything here goes through `pouch_core::Pouch` — the same surface the
//! desktop and CLI clients use. Nothing reaches past it, so a regression that
//! breaks a client breaks this test too.
//!
//! It runs against the real relay binary's router, not a mock. A mock cannot
//! disagree with the server, which is exactly the class of bug that only
//! appeared when the two were first run together.

// The crate warns on `expect` because a panic in the crypto path is a denial of
// service. clippy.toml exempts `#[cfg(test)]` modules but not integration
// tests, which live in their own crate. In a test `expect` is the correct way
// to say "this must have worked" — a test that handles its own setup failure
// gracefully is a test that can pass without testing anything.
#![allow(clippy::expect_used)]

use std::net::SocketAddr;

use pouch_core::transport::RelayConfig;
use pouch_core::Pouch;
use pouch_relay::http::{router, RelayState, MAX_BLOB_BYTES};
use pouch_relay::store::Store;

/// Starts a relay on an ephemeral port. Returns its address and database path.
async fn spawn_relay(dir: &std::path::Path) -> (SocketAddr, String) {
    let db_path = dir.join("relay.db").to_string_lossy().into_owned();
    let store = Store::open(&db_path, MAX_BLOB_BYTES).expect("relay store opens");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("relay binds");
    let addr = listener.local_addr().expect("relay address");

    tokio::spawn(async move {
        axum::serve(listener, router(RelayState::new(store)))
            .await
            .expect("relay serves");
    });

    (addr, db_path)
}

fn key(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_message_written_offline_is_delivered_after_reconnecting() {
    // SPEC §8.2: offline queue and retry on reconnect. Phase 1 returned an
    // error whose copy already promised "will send when you reconnect", and
    // nothing kept that promise.
    //
    // Only an end-to-end run proves this. The interesting part is that the
    // ratchet advanced when the message was encrypted for the failed send, so
    // a retry has to post *that* blob rather than encrypt a second one — and
    // whether the peer can still decrypt it is a question a unit test with a
    // stubbed relay cannot ask.
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, _) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x11), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x22), relay()).expect("mai");
    let code = mai.invite_code().expect("code");
    let conversation = brian.add_contact("Mai", &code).await.expect("adds");
    mai.receive_messages().await.expect("mai joins");

    // --- the relay goes away -------------------------------------------------
    let dead = RelayConfig::insecure_local("http://127.0.0.1:1");
    let mut offline = Pouch::open(&brian_db, &mut key(0x11), dead).expect("reopens offline");

    assert_eq!(offline.queued_count().expect("counts"), 0);
    let failed = offline
        .send_message(&conversation, "written on a train")
        .await;
    assert!(failed.is_err(), "a send with no relay reported success");

    assert_eq!(
        offline.queued_count().expect("counts"),
        1,
        "a message that could not be sent was not queued"
    );

    // It is in the thread already, so the user can see what they wrote rather
    // than losing it to a failed send.
    let thread = offline.messages(&conversation).expect("reads");
    assert!(
        thread.iter().any(|m| m.body == "written on a train"),
        "the queued message is missing from the conversation"
    );
    drop(offline);

    // --- the relay comes back ------------------------------------------------
    let mut brian = Pouch::open(&brian_db, &mut key(0x11), relay()).expect("reopens online");
    assert_eq!(
        brian.queued_count().expect("counts"),
        1,
        "the queue did not survive a restart"
    );

    let delivered = brian.flush_outbox().await.expect("flushes");
    assert_eq!(delivered, 1);
    assert_eq!(brian.queued_count().expect("counts"), 0);

    // --- and the other side can actually read it -----------------------------
    let received = mai.receive_messages().await.expect("mai receives");
    assert_eq!(
        received.messages.len(),
        1,
        "the delivered blob did not decrypt on the other side"
    );
    assert_eq!(received.messages[0].body, "written on a train");
}

#[tokio::test]
async fn a_queue_flushes_in_the_order_it_was_written() {
    // The ratchet generations are in order and MLS tolerates little
    // reordering, so a queue that flushed out of order would lose messages
    // the same way D-028 did.
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, _) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x11), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x22), relay()).expect("mai");
    let code = mai.invite_code().expect("code");
    let conversation = brian.add_contact("Mai", &code).await.expect("adds");
    mai.receive_messages().await.expect("mai joins");

    let dead = RelayConfig::insecure_local("http://127.0.0.1:1");
    let mut offline = Pouch::open(&brian_db, &mut key(0x11), dead).expect("reopens offline");
    for body in ["first", "second", "third", "fourth", "fifth"] {
        let _ = offline.send_message(&conversation, body).await;
    }
    assert_eq!(offline.queued_count().expect("counts"), 5);
    drop(offline);

    let mut brian = Pouch::open(&brian_db, &mut key(0x11), relay()).expect("reopens online");
    assert_eq!(brian.flush_outbox().await.expect("flushes"), 5);

    let received = mai.receive_messages().await.expect("mai receives");

    // Arrival order is deliberately not asserted. The relay returns blobs in
    // random-identifier order on purpose, so a batch always arrives shuffled —
    // that is the privacy property D-028 was resolved in favour of.
    //
    // That all five decrypt is the assertion that matters. The blobs are
    // consecutive ratchet generations; if the queue had flushed them out of
    // order, the ones beyond the out-of-order tolerance would have failed to
    // decrypt and would be missing here.
    let mut bodies: Vec<&str> = received.messages.iter().map(|m| m.body.as_str()).collect();
    bodies.sort_unstable();
    assert_eq!(
        bodies,
        vec!["fifth", "first", "fourth", "second", "third"],
        "a queued message did not survive the flush"
    );
}

#[tokio::test]
async fn retention_deletes_what_has_outlived_it_and_keeps_the_rest() {
    // SPEC §8.1 requires the retention expiry logic be tested. Done through the
    // public surface rather than the store, because the setting is only useful
    // if changing it through the API actually deletes something.
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, _) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x11), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x22), relay()).expect("mai");
    let code = mai.invite_code().expect("code");
    let conversation = brian.add_contact("Mai", &code).await.expect("adds");
    mai.receive_messages().await.expect("mai joins");

    brian
        .send_message(&conversation, "recent enough to survive")
        .await
        .expect("sends");

    // Default keeps everything.
    assert_eq!(
        brian.retention_policy().expect("reads"),
        pouch_core::RetentionPolicy::Forever
    );
    assert_eq!(brian.purge_expired().expect("purges"), 0);
    assert_eq!(brian.messages(&conversation).expect("reads").len(), 1);

    // A one-second window deletes it, because it is already older than that.
    // Uses the per-conversation control, which is the finer of the two.
    //
    // Sleeps past two seconds rather than just past one. Timestamps are whole
    // seconds and the comparison is `at < now - interval`, so at 1.1s elapsed
    // both sides land in the same second and nothing is expired yet. The
    // boundary is exclusive by design — a message is deleted once it has
    // outlived the interval, not once it has reached it.
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let deleted = brian
        .set_disappearing_messages(&conversation, Some(1))
        .expect("sets");
    assert_eq!(deleted, 1, "the disappearing interval deleted nothing");
    assert!(brian.messages(&conversation).expect("reads").is_empty());

    // Clearing it returns the conversation to the device-wide policy, which is
    // still forever, so nothing further goes.
    brian
        .set_disappearing_messages(&conversation, None)
        .expect("clears");
    assert_eq!(
        brian.disappearing_messages(&conversation).expect("reads"),
        None
    );
}

#[tokio::test]
async fn two_clients_exchange_text_and_the_relay_learns_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, relay_db) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    // --- first run: two identities, created locally, registering nothing ----
    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x11), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x22), relay()).expect("mai");

    // --- add contact: Mai publishes a code, Brian starts the conversation ---
    let mai_code = mai.invite_code().expect("mai invite code");
    let conversation = brian
        .add_contact("Mai", &mai_code)
        .await
        .expect("brian adds mai");

    // --- Mai collects the Welcome and the introduction ----------------------
    let opened = mai.receive_messages().await.expect("mai polls");
    assert_eq!(
        opened.conversations_opened.len(),
        1,
        "the Welcome did not open a conversation"
    );
    assert!(
        opened.messages.is_empty(),
        "the introduction was rendered as a message"
    );

    // Mai learned Brian's name over the encrypted channel, not from the relay.
    let mai_conversations = mai.conversations().expect("mai conversations");
    assert_eq!(mai_conversations.len(), 1);
    assert_eq!(mai_conversations[0].contact_name, "Brian");

    // --- and neither party is verified, because nobody compared anything ----
    for summary in mai.conversations().expect("mai") {
        assert_eq!(
            summary.identity,
            pouch_core::IdentityState::Unverified,
            "a contact was verified without the user comparing a safety number"
        );
    }

    // --- messages, both directions ------------------------------------------
    let manifest = brian
        .send_message(&conversation, "the meeting is at dawn")
        .await
        .expect("brian sends");
    assert!(manifest.failure().is_none(), "{}", manifest.summary());

    let received = mai.receive_messages().await.expect("mai polls");
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].body, "the meeting is at dawn");

    mai.send_message(&conversation, "understood")
        .await
        .expect("mai replies");

    let back = brian.receive_messages().await.expect("brian polls");
    assert_eq!(back.messages.len(), 1);
    assert_eq!(back.messages[0].body, "understood");

    // --- a run of messages arrives intact and in order ----------------------
    for i in 0..12 {
        brian
            .send_message(&conversation, &format!("message {i}"))
            .await
            .expect("brian sends");
    }
    let run = mai.receive_messages().await.expect("mai polls");
    assert_eq!(run.messages.len(), 12, "messages were lost");

    let stored = mai.messages(&conversation).expect("mai reads");
    let bodies: Vec<&str> = stored.iter().map(|m| m.body.as_str()).collect();
    for i in 0..12 {
        assert!(
            bodies.contains(&format!("message {i}").as_str()),
            "message {i} is missing from the stored conversation"
        );
    }

    // --- safety numbers agree on both devices -------------------------------
    let brian_contact = brian.conversations().expect("brian")[0].contact_id.clone();
    let mai_contact = mai.conversations().expect("mai")[0].contact_id.clone();
    assert_eq!(
        brian.safety_number(&brian_contact).expect("brian number"),
        mai.safety_number(&mai_contact).expect("mai number"),
        "the two devices show different safety numbers; every verification would fail"
    );

    // --- server blindness, against this real conversation (SPEC §8.3) -------
    let dump = std::fs::read(&relay_db).expect("relay database is readable");
    for canary in [
        &b"the meeting is at dawn"[..],
        &b"understood"[..],
        &b"Brian"[..],
        &b"Mai"[..],
        &b"message 7"[..],
    ] {
        assert!(
            !contains(&dump, canary),
            "{:?} survives in the relay database",
            String::from_utf8_lossy(canary)
        );
    }

    // --- and the local databases are encrypted at rest ----------------------
    for path in [&brian_db, &mai_db] {
        let local = std::fs::read(path).expect("local database is readable");
        assert!(
            !contains(&local, b"the meeting is at dawn"),
            "message plaintext is unencrypted in {path}"
        );
    }
}

#[tokio::test]
async fn a_conversation_survives_a_restart() {
    // The bug that only an end-to-end run finds: MLS state persists, but the
    // in-memory group is not rebuilt, so every restart loses every
    // conversation while its keys sit intact on disk (D-027).
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, _relay_db) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    let conversation = {
        let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x33), relay()).expect("brian");
        let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x44), relay()).expect("mai");
        let code = mai.invite_code().expect("code");
        let conversation = brian.add_contact("Mai", &code).await.expect("adds");
        mai.receive_messages().await.expect("mai joins");
        brian
            .send_message(&conversation, "before restart")
            .await
            .expect("sends");
        mai.receive_messages().await.expect("mai receives");
        conversation
    };
    // Both clients dropped here — as if the applications had exited.

    let mut brian = Pouch::open(&brian_db, &mut key(0x33), relay()).expect("brian reopens");
    let mut mai = Pouch::open(&mai_db, &mut key(0x44), relay()).expect("mai reopens");

    // The history is still there.
    assert_eq!(
        mai.messages(&conversation).expect("mai reads").len(),
        1,
        "message history did not survive the restart"
    );

    // And the conversation still works, which is the harder half — it means
    // the ratchet state was rehydrated, not merely the message rows.
    brian
        .send_message(&conversation, "after restart")
        .await
        .expect("sends after restart");

    let received = mai.receive_messages().await.expect("mai polls");
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].body, "after restart");
}

#[tokio::test]
async fn a_failed_send_reports_the_stage_it_stopped_at() {
    // SPEC §6.5.5: on failure the manifest stops at the failed stage and names
    // it, turning error reporting into diagnosis.
    let dir = tempfile::tempdir().expect("temp dir");
    let (addr, _) = spawn_relay(dir.path()).await;
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));

    let brian_db = dir.path().join("brian.db").to_string_lossy().into_owned();
    let mai_db = dir.path().join("mai.db").to_string_lossy().into_owned();

    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x55), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x66), relay()).expect("mai");
    let code = mai.invite_code().expect("code");
    let conversation = brian.add_contact("Mai", &code).await.expect("adds");

    // Point the client at a port nothing is listening on.
    let dead = RelayConfig::insecure_local("http://127.0.0.1:1");
    let mut offline = Pouch::open(&brian_db, &mut key(0x55), dead).expect("reopens");

    let result = offline.send_message(&conversation, "never arrives").await;
    assert!(result.is_err(), "a send with no relay reported success");

    let error = result.expect_err("an error").to_string();
    assert!(
        error.contains("no connection to the relay"),
        "the error does not say what happened: {error}"
    );
    assert!(
        error.contains("will send when you reconnect"),
        "the error does not say what to do: {error}"
    );
}
