//! Engine-internal state machines modeled as explicit enums.
//!
//! Per `docs/marmot-architecture/further-context/cgka-engine-design.md:135-166`
//! and spike-findings §2.1, the "rustls-style state-machine-as-enum" discipline
//! makes illegal transitions a compile-time concern rather than a scattered
//! runtime `if/match`. This module defines the two state machines this
//! refactor lands:
//!
//! - [`EpochState`] — per-group commit lifecycle. The core correctness
//!   invariant of the engine.
//! - [`WelcomeState`] — minimal; welcomes auto-accept today.
//!
//! `MemberState` is **deliberately omitted** (decision per the production
//! refactor plan's clarifying round): OpenMLS's own member tracking is
//! authoritative; a parallel enum would drift.
//!
//! ## Opacity discipline
//!
//! Non-trivial variants wrap newtype structs with private fields. External
//! code can match on the variant discriminant and query state via accessors
//! but cannot fabricate a `PendingPublish` or `Recovering` without going
//! through constructors + transition methods. This gives the invariant
//! "only the engine can advance the state machine" type-system teeth.

use crate::ingest::PeeledMessage;
use crate::types::EpochId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Opaque handle to a staged MLS commit. The engine serializes its
/// backend-specific staged-commit representation into this; cgka-traits stays
/// decoupled from openmls's heavy types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedCommitHandle(Vec<u8>);

impl StagedCommitHandle {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Opaque handle referencing a pending outbound send. Passed back to
/// `CgkaEngine::confirm_published` after the transport confirms publish.
///
/// Intentionally a `u64` newtype: the engine generates and owns these; no
/// cross-process stability required.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PendingStateRef(u64);

impl PendingStateRef {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PendingStateRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pending#{}", self.0)
    }
}

// ── PendingPublish inner ────────────────────────────────────────────────────

/// Data carried by [`EpochState::PendingPublish`]. Private fields enforce that
/// construction only happens via transition methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPublish {
    epoch: EpochId,
    pending: StagedCommitHandle,
    pending_ref: PendingStateRef,
}

impl PendingPublish {
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    pub fn pending_ref(&self) -> PendingStateRef {
        self.pending_ref
    }

    pub fn staged_commit(&self) -> &StagedCommitHandle {
        &self.pending
    }
}

// ── Merging inner ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Merging {
    epoch: EpochId,
}

impl Merging {
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }
}

// ── Recovering inner ────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovering {
    last_stable_epoch: EpochId,
    buffered: Vec<PeeledMessage>,
}

impl Recovering {
    pub fn last_stable_epoch(&self) -> EpochId {
        self.last_stable_epoch
    }

    pub fn buffered(&self) -> &[PeeledMessage] {
        &self.buffered
    }

    pub fn into_buffered(self) -> Vec<PeeledMessage> {
        self.buffered
    }
}

// ── EpochState ──────────────────────────────────────────────────────────────

/// Per-group commit lifecycle.
///
/// Legal transitions:
///
/// ```text
///                    ┌──────────────┐
///                    │    Stable    │◄─────────────┐
///                    └──────┬───────┘              │
///                           │ begin_pending         │ merge_to_stable
///                           ▼                       │
///                    ┌──────────────┐               │
///                    │ PendingPubli │               │
///                    │      sh      │               │
///                    └──┬─────────┬─┘               │
///          rollback_    │         │ confirm_publish │
///          pending      │         ▼                 │
///                       │   ┌──────────┐            │
///                       └──►│ Merging  │────────────┘
///                           └──────────┘
///                                ▲
///                                │
///                                ▼
///                         ┌─────────────┐
///                         │ Recovering  │   (unrecoverable fork fallback;
///                         └─────────────┘    same-epoch races recover
///                                            before entering this state)
/// ```
///
/// Every transition below returns `Result<Self, InvalidTransition>`. Illegal
/// transitions do NOT panic — they return a typed error the engine logs and
/// upgrades to an `EngineError::Backend` in practice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochState {
    Stable { epoch: EpochId },
    PendingPublish(PendingPublish),
    Merging(Merging),
    Recovering(Recovering),
}

impl EpochState {
    pub fn stable(epoch: EpochId) -> Self {
        EpochState::Stable { epoch }
    }

    /// Current epoch this state reflects. For `Recovering`, returns the last
    /// stable epoch — the current (forked) epoch is ambiguous by definition.
    pub fn epoch(&self) -> EpochId {
        match self {
            EpochState::Stable { epoch } => *epoch,
            EpochState::PendingPublish(p) => p.epoch(),
            EpochState::Merging(m) => m.epoch(),
            EpochState::Recovering(r) => r.last_stable_epoch(),
        }
    }

    /// Whether the engine may ingest new inbound messages while in this state.
    /// `PendingPublish` and `Merging` buffer; `Stable` and `Recovering` accept.
    pub fn can_ingest(&self) -> bool {
        matches!(self, EpochState::Stable { .. } | EpochState::Recovering(_))
    }

    /// Short name for logs / tests.
    pub fn name(&self) -> &'static str {
        match self {
            EpochState::Stable { .. } => "Stable",
            EpochState::PendingPublish(_) => "PendingPublish",
            EpochState::Merging(_) => "Merging",
            EpochState::Recovering(_) => "Recovering",
        }
    }

    // ── Transitions ─────────────────────────────────────────────────────────

    /// `Stable → PendingPublish`. Only legal from `Stable`.
    ///
    /// `new_epoch` is the epoch the group WILL be at once the commit is
    /// confirmed. For the 0.1.0 spike-shortcut (merge-before-confirm), this
    /// equals the MLS group's current epoch post-`merge_pending_commit`.
    /// Once Task 4.13 lifts into real publish-before-apply, `new_epoch`
    /// becomes the projected-future epoch and rollback restores the
    /// caller's prior Stable epoch.
    pub fn begin_pending(
        self,
        new_epoch: EpochId,
        pending: StagedCommitHandle,
        pending_ref: PendingStateRef,
    ) -> Result<Self, InvalidTransition> {
        match self {
            EpochState::Stable { epoch: _ } => Ok(EpochState::PendingPublish(PendingPublish {
                epoch: new_epoch,
                pending,
                pending_ref,
            })),
            other => Err(InvalidTransition {
                from: other.name(),
                to: "PendingPublish",
                reason: "begin_pending requires Stable",
            }),
        }
    }

    /// `PendingPublish → Merging`. Triggered by a successful transport publish
    /// confirmation.
    pub fn confirm_publish(self) -> Result<Self, InvalidTransition> {
        match self {
            EpochState::PendingPublish(p) => Ok(EpochState::Merging(Merging { epoch: p.epoch })),
            other => Err(InvalidTransition {
                from: other.name(),
                to: "Merging",
                reason: "confirm_publish requires PendingPublish",
            }),
        }
    }

    /// `PendingPublish → Stable` at the CALLER-supplied prior epoch. Used
    /// when transport publish fails and the engine must discard the staged
    /// commit. The caller owns the "what was the previous Stable epoch"
    /// memory for now — Task 4.13 centralizes this in `EpochManager` with
    /// real staged-commit state.
    pub fn rollback_pending(self, prior_epoch: EpochId) -> Result<Self, InvalidTransition> {
        match self {
            EpochState::PendingPublish(_) => Ok(EpochState::Stable { epoch: prior_epoch }),
            other => Err(InvalidTransition {
                from: other.name(),
                to: "Stable",
                reason: "rollback_pending requires PendingPublish",
            }),
        }
    }

    /// `Merging → Stable { epoch: next }`. The engine advances the epoch
    /// counter when the commit has been applied to the local MLS state.
    pub fn merge_to_stable(self, next_epoch: EpochId) -> Result<Self, InvalidTransition> {
        match self {
            EpochState::Merging(_) => Ok(EpochState::Stable { epoch: next_epoch }),
            other => Err(InvalidTransition {
                from: other.name(),
                to: "Stable",
                reason: "merge_to_stable requires Merging",
            }),
        }
    }

    /// `Stable | * → Recovering`. Always legal. Called when the engine detects
    /// an epoch fork it cannot recover with the available snapshots.
    pub fn detect_fork(self, buffered: Vec<PeeledMessage>) -> Self {
        let last_stable_epoch = self.epoch();
        EpochState::Recovering(Recovering {
            last_stable_epoch,
            buffered,
        })
    }
}

/// Error returned when a state-machine transition is attempted from a state
/// that does not allow it. All fields are `'static str` so this is cheap to
/// construct and always Send + Sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("illegal {to} transition from {from}: {reason}")]
pub struct InvalidTransition {
    pub from: &'static str,
    pub to: &'static str,
    pub reason: &'static str,
}

// ── WelcomeState ────────────────────────────────────────────────────────────

/// Pending-welcome state. Minimal per the production-refactor plan's decision
/// to skip a user-driven decline variant for 0.1.0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WelcomeState {
    None,
    Pending(PendingWelcomeState),
    Active,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWelcomeState {
    welcome_bytes: Vec<u8>,
    group_id: crate::types::GroupId,
}

impl PendingWelcomeState {
    pub fn welcome_bytes(&self) -> &[u8] {
        &self.welcome_bytes
    }

    pub fn group_id(&self) -> &crate::types::GroupId {
        &self.group_id
    }
}

impl WelcomeState {
    pub fn pending(welcome_bytes: Vec<u8>, group_id: crate::types::GroupId) -> Self {
        WelcomeState::Pending(PendingWelcomeState {
            welcome_bytes,
            group_id,
        })
    }

    pub fn activate(self) -> Result<Self, InvalidTransition> {
        match self {
            WelcomeState::Pending(_) => Ok(WelcomeState::Active),
            other => {
                let from = match other {
                    WelcomeState::None => "None",
                    WelcomeState::Pending(_) => unreachable!(),
                    WelcomeState::Active => "Active",
                };
                Err(InvalidTransition {
                    from,
                    to: "Active",
                    reason: "activate requires Pending",
                })
            }
        }
    }
}

// ── Transition tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> StagedCommitHandle {
        StagedCommitHandle::from_bytes(vec![0xAB; 4])
    }

    fn pref() -> PendingStateRef {
        PendingStateRef::new(42)
    }

    #[test]
    fn stable_begin_pending_confirm_merge() {
        let s = EpochState::stable(EpochId(0));
        assert!(s.can_ingest());
        let s = s.begin_pending(EpochId(1), handle(), pref()).unwrap();
        assert_eq!(s.name(), "PendingPublish");
        assert_eq!(s.epoch(), EpochId(1));
        assert!(!s.can_ingest());
        let s = s.confirm_publish().unwrap();
        assert_eq!(s.name(), "Merging");
        let s = s.merge_to_stable(EpochId(1)).unwrap();
        assert_eq!(s, EpochState::stable(EpochId(1)));
    }

    #[test]
    fn rollback_returns_to_prior_stable_epoch() {
        let s = EpochState::stable(EpochId(5));
        let s = s.begin_pending(EpochId(6), handle(), pref()).unwrap();
        let s = s.rollback_pending(EpochId(5)).unwrap();
        assert_eq!(s, EpochState::stable(EpochId(5)));
    }

    #[test]
    fn begin_pending_from_non_stable_errors() {
        let s = EpochState::stable(EpochId(0))
            .begin_pending(EpochId(1), handle(), pref())
            .unwrap();
        assert!(
            s.clone()
                .begin_pending(EpochId(2), handle(), pref())
                .is_err()
        );
        let s = s.confirm_publish().unwrap();
        assert!(s.begin_pending(EpochId(2), handle(), pref()).is_err());
    }

    #[test]
    fn confirm_publish_requires_pending() {
        assert!(EpochState::stable(EpochId(0)).confirm_publish().is_err());
        let merging = EpochState::stable(EpochId(0))
            .begin_pending(EpochId(1), handle(), pref())
            .unwrap()
            .confirm_publish()
            .unwrap();
        assert!(merging.confirm_publish().is_err());
    }

    #[test]
    fn rollback_requires_pending() {
        assert!(
            EpochState::stable(EpochId(0))
                .rollback_pending(EpochId(0))
                .is_err()
        );
    }

    #[test]
    fn merge_to_stable_requires_merging() {
        assert!(
            EpochState::stable(EpochId(0))
                .merge_to_stable(EpochId(1))
                .is_err()
        );
        let pending = EpochState::stable(EpochId(0))
            .begin_pending(EpochId(1), handle(), pref())
            .unwrap();
        assert!(pending.merge_to_stable(EpochId(1)).is_err());
    }

    #[test]
    fn detect_fork_always_legal_and_preserves_last_stable() {
        let s = EpochState::stable(EpochId(7));
        let s = s.detect_fork(vec![]);
        match &s {
            EpochState::Recovering(r) => assert_eq!(r.last_stable_epoch(), EpochId(7)),
            _ => panic!("expected Recovering"),
        }
        assert!(s.can_ingest());

        // From PendingPublish, fork preserves the new pending epoch as
        // "last known"; same-epoch recovery normally happens before this
        // fallback state is entered.
        let s = EpochState::stable(EpochId(3))
            .begin_pending(EpochId(4), handle(), pref())
            .unwrap()
            .detect_fork(vec![]);
        match &s {
            EpochState::Recovering(r) => assert_eq!(r.last_stable_epoch(), EpochId(4)),
            _ => panic!("expected Recovering"),
        }
    }

    #[test]
    fn invalid_transition_message_names_both_states() {
        let err = EpochState::stable(EpochId(0))
            .confirm_publish()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Stable"));
        assert!(msg.contains("Merging"));
    }

    #[test]
    fn welcome_state_activate_flow() {
        let w = WelcomeState::pending(vec![1, 2, 3], crate::types::GroupId::new(vec![0xAA; 4]));
        let w = w.activate().unwrap();
        assert_eq!(w, WelcomeState::Active);
    }

    #[test]
    fn welcome_state_activate_from_none_or_active_errors() {
        assert!(WelcomeState::None.activate().is_err());
        assert!(WelcomeState::Active.activate().is_err());
    }
}
