//! The Manifest — a record of every stage a message actually passed through.
//!
//! SPEC §6.5. The rule that governs this entire module:
//!
//! > A manifest that lies is worse than no manifest.
//!
//! So a stage is only ever marked `Ran` by the code that actually performed it.
//! There is no constructor that produces a complete manifest, no default that
//! fills stages in optimistically, and no way to mark a stage complete without
//! supplying the detail it recorded. A stage that did not happen reports
//! `NotApplicable` or `NotYetImplemented`, and both are shown to the user —
//! an absent stage is itself information (SPEC §6.5.1).

use serde::{Deserialize, Serialize};

use crate::transport::Route;

/// The nine stages, in the order a message passes through them.
///
/// The order carries meaning the reader needs: stage 4 padding after stage 3
/// compression is a security-relevant ordering, not a presentational choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    /// 1 — the message was composed.
    Compose,
    /// 2 — metadata was removed. Attachments only.
    Strip,
    /// 3 — the payload was compressed.
    Compress,
    /// 4 — the payload was padded to a fixed bucket.
    Pad,
    /// 5 — the payload was encrypted.
    Encrypt,
    /// 6 — the sender was sealed from the relay.
    Seal,
    /// 7 — the blob was routed to the relay.
    Route,
    /// 8 — the relay held the blob.
    Queue,
    /// 9 — the blob was delivered.
    Deliver,
}

impl Stage {
    /// The stage number shown in the manifest.
    pub fn number(&self) -> u8 {
        match self {
            Stage::Compose => 1,
            Stage::Strip => 2,
            Stage::Compress => 3,
            Stage::Pad => 4,
            Stage::Encrypt => 5,
            Stage::Seal => 6,
            Stage::Route => 7,
            Stage::Queue => 8,
            Stage::Deliver => 9,
        }
    }

    /// The label shown to the user.
    pub fn label(&self) -> &'static str {
        match self {
            Stage::Compose => "COMPOSED",
            Stage::Strip => "METADATA REMOVED",
            Stage::Compress => "COMPRESSED",
            Stage::Pad => "PADDED",
            Stage::Encrypt => "ENCRYPTED",
            Stage::Seal => "SENDER SEALED",
            Stage::Route => "ROUTED",
            Stage::Queue => "HELD AT RELAY",
            Stage::Deliver => "DELIVERED",
        }
    }

    /// All nine, in order.
    pub fn all() -> [Stage; 9] {
        [
            Stage::Compose,
            Stage::Strip,
            Stage::Compress,
            Stage::Pad,
            Stage::Encrypt,
            Stage::Seal,
            Stage::Route,
            Stage::Queue,
            Stage::Deliver,
        ]
    }
}

/// What happened at one stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageOutcome {
    /// It ran, and this is what it recorded.
    Ran(String),
    /// It does not apply to this message — a text message has no metadata to
    /// strip. Shown, never hidden.
    NotApplicable(String),
    /// The feature is not built yet. Shown as such, never as complete.
    NotYetImplemented,
    /// It failed, and this is why.
    Failed(String),
    /// It has not been reached yet. Used while a message is in flight.
    Pending,
}

impl StageOutcome {
    /// The text shown beside the stage.
    pub fn detail(&self) -> String {
        match self {
            StageOutcome::Ran(d) => d.clone(),
            StageOutcome::NotApplicable(why) => format!("n/a — {why}"),
            StageOutcome::NotYetImplemented => "not yet implemented".to_string(),
            StageOutcome::Failed(why) => format!("failed — {why}"),
            StageOutcome::Pending => "pending".to_string(),
        }
    }

    /// Whether this stage actually did something.
    pub fn ran(&self) -> bool {
        matches!(self, StageOutcome::Ran(_))
    }
}

/// The record for one message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    stages: Vec<(Stage, StageOutcome)>,
}

impl Manifest {
    /// Begins a manifest for a plain text message.
    ///
    /// Only stage 1 is marked as having run, because at this point only stage 1
    /// has. Stage 2 is marked not applicable — there is no attachment metadata
    /// on a text message. Stage 3 (compression) landed in Phase 3 and starts
    /// `Pending` like every other stage still to run. Padding and sealed
    /// sender remain not yet implemented; see `docs/DECISIONS.md` D-006's note
    /// on why neither has an authorizing decision yet.
    pub fn new(plaintext_len: usize) -> Self {
        Self {
            stages: vec![
                (
                    Stage::Compose,
                    StageOutcome::Ran(format!("{plaintext_len} bytes")),
                ),
                (
                    Stage::Strip,
                    StageOutcome::NotApplicable("text message".to_string()),
                ),
                (Stage::Compress, StageOutcome::Pending),
                (Stage::Pad, StageOutcome::NotYetImplemented),
                (Stage::Encrypt, StageOutcome::Pending),
                (Stage::Seal, StageOutcome::NotYetImplemented),
                (Stage::Route, StageOutcome::Pending),
                (Stage::Queue, StageOutcome::Pending),
                (Stage::Deliver, StageOutcome::Pending),
            ],
        }
    }

    fn set(&mut self, stage: Stage, outcome: StageOutcome) {
        if let Some(slot) = self.stages.iter_mut().find(|(s, _)| *s == stage) {
            slot.1 = outcome;
        }
    }

    /// Records that compression ran, naming the algorithm and the size change.
    ///
    /// The isolation guarantee (D-009, SPEC §6.5.2) is a property of *how*
    /// `api::compression` calls the library, not something this line can show
    /// — but the byte counts are still worth reporting, because they are the
    /// visible evidence that something real happened rather than a stage
    /// quietly rubber-stamping itself.
    pub fn compressed(&mut self, algorithm: &str, before: usize, after: usize) {
        self.set(
            Stage::Compress,
            StageOutcome::Ran(format!("{algorithm} · {before} → {after} bytes")),
        );
    }

    /// Records that encryption ran, naming the actual mechanisms.
    ///
    /// SPEC §2.5: "Encrypted" alone is insufficient; the mechanism is the
    /// standard.
    pub fn encrypted(
        &mut self,
        ciphersuite: &str,
        aead: &str,
        key_agreement: &str,
        signature: &str,
    ) {
        self.set(
            Stage::Encrypt,
            StageOutcome::Ran(format!(
                "{aead} · key agreement {key_agreement} · signature {signature} · {ciphersuite}"
            )),
        );
    }

    /// Records how the blob reached the relay.
    pub fn routed(&mut self, route: Route, relay_address: &str) {
        self.set(
            Stage::Route,
            StageOutcome::Ran(format!("{} · {relay_address}", route.label())),
        );
    }

    /// Records that the relay accepted the blob.
    pub fn queued(&mut self, message_id: &str) {
        self.set(
            Stage::Queue,
            StageOutcome::Ran(format!("blob {message_id} · TTL 30d")),
        );
    }

    /// Records delivery.
    pub fn delivered(&mut self) {
        self.set(Stage::Deliver, StageOutcome::Ran("accepted".to_string()));
    }

    /// Records a routing failure, naming the stage it stopped at.
    ///
    /// This is what turns error reporting into diagnosis: the collapsed line
    /// reads `failed at stage 07 · routing · no relay connection`.
    pub fn failed_at_routing(&mut self, reason: &str) {
        self.set(Stage::Route, StageOutcome::Failed(reason.to_string()));
        self.set(Stage::Queue, StageOutcome::Pending);
        self.set(Stage::Deliver, StageOutcome::Pending);
    }

    /// Every stage and its outcome, in order.
    pub fn stages(&self) -> &[(Stage, StageOutcome)] {
        &self.stages
    }

    /// How many stages actually ran.
    pub fn ran_count(&self) -> usize {
        self.stages.iter().filter(|(_, o)| o.ran()).count()
    }

    /// The first failure, if there was one.
    pub fn failure(&self) -> Option<(Stage, String)> {
        self.stages.iter().find_map(|(s, o)| match o {
            StageOutcome::Failed(why) => Some((*s, why.clone())),
            _ => None,
        })
    }

    /// The collapsed single line shown beneath a message.
    pub fn summary(&self) -> String {
        if let Some((stage, why)) = self.failure() {
            return format!(
                "failed at stage {:02} · {} · {why}",
                stage.number(),
                stage.label().to_lowercase()
            );
        }
        format!("{} of 9 stages ran", self.ran_count())
    }

    /// The expanded manifest, as monospace lines.
    pub fn lines(&self) -> Vec<String> {
        self.stages
            .iter()
            .map(|(stage, outcome)| {
                format!(
                    "{:02}  {:<18} {}",
                    stage.number(),
                    stage.label(),
                    outcome.detail()
                )
            })
            .collect()
    }
}

/// What the relay could see about one message (SPEC §6.5.4).
///
/// Three blocks, and the third is required. Showing what is protected while
/// omitting what leaks is the reassuring half-truth Prime Directive 3 forbids.
#[derive(Debug, Clone)]
pub struct RelayVisibility {
    /// The inbox the blob was filed under.
    pub inbox_id: String,
    /// The blob's size in bytes.
    pub blob_size: usize,
    /// What the relay can see.
    pub visible: Vec<&'static str>,
    /// What it cannot.
    pub not_visible: Vec<&'static str>,
    /// What a network observer can still infer regardless.
    pub still_inferable: Vec<&'static str>,
}

impl RelayVisibility {
    /// Builds the honest description for a message of this size.
    ///
    /// Phase-accurate: until sealed sender lands in Phase 3, the relay *can*
    /// see which inbox submitted a blob, so that fact appears under `visible`
    /// rather than under `not_visible`.
    pub fn for_message(inbox_id: &str, blob_size: usize) -> Self {
        Self {
            inbox_id: inbox_id.to_string(),
            blob_size,
            visible: vec![
                "the inbox this was filed under (random, not you)",
                "the size of this blob",
                "the hour it arrived, within a 30-day TTL window",
                "the IP address you connected from",
                "which inbox submitted it — sealed sender is not built yet",
            ],
            not_visible: vec![
                "message content",
                "your name or your contact's name",
                "the exact second you sent it",
                "whether this is a first message or a reply",
            ],
            still_inferable: vec!["that you connected", "roughly when", "how often"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_manifest_claims_only_what_has_happened() {
        // The failure this guards: a manifest constructed pre-filled with
        // successes, so a message that never sent still shows nine green
        // stages.
        let m = Manifest::new(412);
        assert_eq!(m.ran_count(), 1, "only compose has run");
        assert!(matches!(
            m.stages()[Stage::Encrypt.number() as usize - 1].1,
            StageOutcome::Pending
        ));
    }

    #[test]
    fn unbuilt_stages_report_as_unimplemented_never_as_complete() {
        // Padding and sealed sender remain unbuilt as of Phase 3 — see
        // DECISIONS.md D-006's note on why neither has an authorizing
        // decision yet. They must say so rather than silently disappearing or
        // claiming success. Compression is no longer in this list: it landed
        // this phase and is covered separately below.
        let m = Manifest::new(100);
        for stage in [Stage::Pad, Stage::Seal] {
            let (_, outcome) = m
                .stages()
                .iter()
                .find(|(s, _)| *s == stage)
                .expect("stage present");
            assert_eq!(
                *outcome,
                StageOutcome::NotYetImplemented,
                "{} must report as not yet implemented",
                stage.label()
            );
            assert!(!outcome.ran());
        }
    }

    #[test]
    fn compression_reports_the_algorithm_and_the_size_change() {
        let mut m = Manifest::new(100);
        m.compressed("zstd", 100, 40);

        let (_, outcome) = m
            .stages()
            .iter()
            .find(|(s, _)| *s == Stage::Compress)
            .expect("stage present");
        assert!(outcome.ran());
        assert_eq!(outcome.detail(), "zstd · 100 → 40 bytes");
    }

    #[test]
    fn every_stage_is_present_even_when_it_did_not_run() {
        // An absent stage is itself information, so nothing is hidden.
        let m = Manifest::new(10);
        assert_eq!(m.stages().len(), 9);
        for stage in Stage::all() {
            assert!(m.stages().iter().any(|(s, _)| *s == stage));
        }
    }

    #[test]
    fn a_text_message_reports_stripping_as_not_applicable_with_a_reason() {
        let m = Manifest::new(10);
        let (_, outcome) = m
            .stages()
            .iter()
            .find(|(s, _)| *s == Stage::Strip)
            .expect("strip present");
        assert!(matches!(outcome, StageOutcome::NotApplicable(_)));
        assert!(outcome.detail().contains("text message"));
    }

    #[test]
    fn the_encryption_stage_names_the_actual_mechanisms() {
        // SPEC §2.5: "Encrypted" alone is insufficient.
        let mut m = Manifest::new(10);
        m.encrypted(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "AES-128-GCM",
            "X25519",
            "Ed25519",
        );

        let detail = m
            .stages()
            .iter()
            .find(|(s, _)| *s == Stage::Encrypt)
            .expect("encrypt present")
            .1
            .detail();

        for mechanism in ["AES-128-GCM", "X25519", "Ed25519", "MLS_128_DHKEMX25519"] {
            assert!(detail.contains(mechanism), "{mechanism} not named");
        }
    }

    #[test]
    fn a_direct_message_never_reports_tor() {
        // SPEC §8.6, stated explicitly: a message sent over direct transport
        // must report direct at stage 7.
        let mut m = Manifest::new(10);
        m.routed(Route::Direct, "http://127.0.0.1:8443");

        let detail = m
            .stages()
            .iter()
            .find(|(s, _)| *s == Stage::Route)
            .expect("route present")
            .1
            .detail();

        assert!(detail.contains("DIRECT"));
        assert!(!detail.contains("TOR"), "a direct message claimed Tor");
    }

    #[test]
    fn a_failure_names_the_stage_it_stopped_at() {
        let mut m = Manifest::new(10);
        m.encrypted("suite", "AES-128-GCM", "X25519", "Ed25519");
        m.failed_at_routing("no relay connection");

        let summary = m.summary();
        assert!(summary.contains("stage 07"), "{summary}");
        assert!(summary.contains("no relay connection"), "{summary}");

        let (stage, _) = m.failure().expect("a failure is recorded");
        assert_eq!(stage, Stage::Route);
    }

    #[test]
    fn a_failed_send_does_not_claim_delivery() {
        // The worst possible manifest lie: reporting delivered for a message
        // that never left.
        let mut m = Manifest::new(10);
        m.encrypted("suite", "AES-128-GCM", "X25519", "Ed25519");
        m.failed_at_routing("no relay connection");

        for stage in [Stage::Queue, Stage::Deliver] {
            let (_, outcome) = m
                .stages()
                .iter()
                .find(|(s, _)| *s == stage)
                .expect("stage present");
            assert!(
                !outcome.ran(),
                "{} claimed success after a failure",
                stage.label()
            );
        }
    }

    #[test]
    fn a_completed_send_reports_the_stages_that_actually_ran() {
        let mut m = Manifest::new(412);
        m.encrypted("suite", "AES-128-GCM", "X25519", "Ed25519");
        m.routed(Route::Direct, "http://127.0.0.1:8443");
        m.queued("7f3ac219");
        m.delivered();

        // Compose, encrypt, route, queue, deliver. Five, not nine — the other
        // four are genuinely not built in Phase 1.
        assert_eq!(m.ran_count(), 5, "{:?}", m.summary());
        assert!(m.failure().is_none());
    }

    #[test]
    fn relay_visibility_admits_what_leaks() {
        // The third block is required. A screen that lists only what is
        // protected is the half-truth Prime Directive 3 forbids.
        let v = RelayVisibility::for_message("7f3ac219", 1024);
        assert!(!v.still_inferable.is_empty(), "the leak block is missing");

        // Phase-accurate: sealed sender is not built, so the relay *can* see
        // which inbox submitted a blob and the screen must say so.
        assert!(
            v.visible
                .iter()
                .any(|s| s.contains("sealed sender is not built")),
            "the screen claims sender privacy the build does not provide"
        );
        assert!(
            v.visible.iter().any(|s| s.contains("IP address")),
            "the screen omits the IP exposure that direct transport has"
        );
    }
}
