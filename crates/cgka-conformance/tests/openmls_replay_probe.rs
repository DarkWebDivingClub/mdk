use std::collections::BTreeSet;

use cgka_conformance::canonicalization::{
    CanonicalizationInput, CanonicalizationPolicy, CanonicalizationState, DroppedMessageReason,
    MessageKind, SyncState, canonicalize_with_materialized_candidates,
};
use cgka_conformance::convergence::ConvergencePolicy;
use cgka_conformance::openmls_projection::{
    OpenMlsCandidatePath, OpenMlsCanonicalizationBatch, OpenMlsContentKind,
    OpenMlsReplayObservation, canonicalize_openmls_batch, canonicalize_stored_openmls_messages,
    materialize_openmls_candidate_paths, project_mls_message, replay_openmls_messages,
};
use cgka_conformance::{ClientBuilder, TransportBus};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::MessageStorage;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId};

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

#[tokio::test]
async fn openmls_probe_replays_consumed_proposal_without_mutating_live_state() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-probe", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let proposal_msg = bob.leave_capture().await;
    assert_projected_kind(&proposal_msg, OpenMlsContentKind::Proposal, 1);

    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice should process bob's proposal and auto-commit: {alice_outcomes:?}"
    );

    let commit_msg = bus
        .queued_messages()
        .into_iter()
        .find(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .expect("alice auto-published a commit");
    assert_projected_kind(&commit_msg, OpenMlsContentKind::Commit, 1);

    let observations = replay_openmls_messages(
        carol.storage(),
        &group_id,
        &[proposal_msg, commit_msg.clone()],
    )
    .expect("probe replay succeeds");
    let proposal_ref = observations
        .iter()
        .find_map(|observation| match observation {
            OpenMlsReplayObservation::ProposalStored { proposal_ref, .. } => {
                Some(proposal_ref.clone())
            }
            _ => None,
        })
        .expect("proposal stored during probe replay");
    let consumed_refs = observations
        .iter()
        .find_map(|observation| match observation {
            OpenMlsReplayObservation::CommitStaged {
                consumed_proposal_refs,
                ..
            } => Some(consumed_proposal_refs.clone()),
            _ => None,
        })
        .expect("commit staged during probe replay");
    assert_eq!(consumed_refs, vec![proposal_ref]);
    assert_eq!(carol.epoch().0, 1, "probe replay rolls back live storage");

    bus.deliver_all();
    let carol_outcomes = carol.tick().await;
    assert!(
        carol_outcomes.iter().all(Result::is_ok),
        "carol should still process the real proposal and commit after probe: {carol_outcomes:?}"
    );
    assert_eq!(carol.epoch().0, 2);
}

#[tokio::test]
async fn openmls_materializes_competing_commit_paths_from_same_anchor() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-branches", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let _alice_pending = alice.invite(vec![david_kp]).await;
    let _bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages: Vec<_> = bus
        .queued_messages()
        .into_iter()
        .filter(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .collect();
    assert_eq!(
        commit_messages.len(),
        2,
        "expected two competing commit candidates"
    );

    let candidates = materialize_openmls_candidate_paths(
        carol.storage(),
        &group_id,
        &[
            OpenMlsCandidatePath {
                branch_id: "alice-adds-david".into(),
                messages: vec![commit_messages[0].clone()],
            },
            OpenMlsCandidatePath {
                branch_id: "bob-adds-eve".into(),
                messages: vec![commit_messages[1].clone()],
            },
        ],
    )
    .expect("candidate paths materialize");

    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| candidate.fork_epoch == 1));
    assert!(candidates.iter().all(|candidate| candidate.tip_epoch == 2));
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.commit_message_ids.len() == 1)
    );
    assert_ne!(candidates[0].tip_digest, candidates[1].tip_digest);
    let canonicalized = canonicalize_with_materialized_candidates(
        CanonicalizationInput {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                sync_state: SyncState::Stable,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            pending_messages: vec![],
            outbound_intents: vec![],
            candidate_branches: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                stable_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
        candidates
            .iter()
            .map(|candidate| candidate.canonical_materialized_candidate())
            .collect(),
    );
    let lower_digest_candidate = candidates
        .iter()
        .min_by_key(|candidate| candidate.tip_digest)
        .expect("candidate set is not empty");
    assert_eq!(
        canonicalized.selected_branch_id.as_deref(),
        Some(lower_digest_candidate.branch_id.as_str())
    );
    assert_eq!(
        canonicalized.accepted_commits,
        lower_digest_candidate.commit_message_ids
    );
    let losing_commit_id = candidates
        .iter()
        .find(|candidate| candidate.branch_id != lower_digest_candidate.branch_id)
        .and_then(|candidate| candidate.commit_message_ids.first())
        .expect("losing commit exists");
    assert!(canonicalized.dropped_messages.iter().any(|dropped| {
        dropped.message_id == *losing_commit_id
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
    }));
    assert_eq!(
        carol.epoch().0,
        1,
        "candidate materialization must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn openmls_canonicalization_maps_consumed_proposal_refs_to_pending_proposals() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-canonical-proposal", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let proposal_msg = bob.leave_capture().await;
    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice should process bob's proposal and auto-commit: {alice_outcomes:?}"
    );
    let commit_msg = bus
        .queued_messages()
        .into_iter()
        .find(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .expect("alice auto-published a commit");

    let result = canonicalize_openmls_batch(
        carol.storage(),
        &group_id,
        OpenMlsCanonicalizationBatch {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                sync_state: SyncState::Stable,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            candidate_paths: vec![OpenMlsCandidatePath {
                branch_id: "bob-leaves".into(),
                messages: vec![commit_msg.clone()],
            }],
            pending_messages: vec![proposal_msg.clone()],
            outbound_intents: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                stable_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
    )
    .expect("OpenMLS canonicalization adapter succeeds");

    let proposal_id = hex::encode(proposal_msg.id.as_slice());
    let commit_id = hex::encode(commit_msg.id.as_slice());
    assert_eq!(result.selected_branch_id.as_deref(), Some("bob-leaves"));
    assert_eq!(result.accepted_commits, vec![commit_id]);
    assert_eq!(result.accepted_proposals, vec![proposal_id]);
    assert!(result.dropped_messages.is_empty());
    assert_eq!(
        carol.epoch().0,
        1,
        "canonicalization probes must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn openmls_canonicalization_uses_app_messages_as_branch_witnesses() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-canonical-app", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages: Vec<_> = bus
        .queued_messages()
        .into_iter()
        .filter(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .collect();
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        alice
            .send_app_capture(b"witness from higher digest branch".to_vec())
            .await
    } else {
        bob.confirm(bob_pending).await;
        bob.send_app_capture(b"witness from higher digest branch".to_vec())
            .await
    };

    let result = canonicalize_openmls_batch(
        carol.storage(),
        &group_id,
        OpenMlsCanonicalizationBatch {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                sync_state: SyncState::Stable,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            candidate_paths: vec![
                OpenMlsCandidatePath {
                    branch_id: "app-branch".into(),
                    messages: vec![commit_messages[app_branch_index].clone()],
                },
                OpenMlsCandidatePath {
                    branch_id: "quiet-branch".into(),
                    messages: vec![commit_messages[quiet_branch_index].clone()],
                },
            ],
            pending_messages: vec![app_msg.clone()],
            outbound_intents: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                stable_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
    )
    .expect("OpenMLS canonicalization adapter succeeds");

    assert_eq!(result.selected_branch_id.as_deref(), Some("app-branch"));
    assert_eq!(
        result.accepted_app_messages,
        vec![hex::encode(app_msg.id.as_slice())]
    );
    assert!(
        result.invalidated_app_messages.is_empty(),
        "app branch witness should be accepted, not invalidated"
    );
    assert_eq!(
        carol.epoch().0,
        1,
        "canonicalization probes must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn stored_openmls_messages_reconstruct_canonicalization_batch() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("stored-openmls-canonical", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages: Vec<_> = bus
        .queued_messages()
        .into_iter()
        .filter(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .collect();
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        alice
            .send_app_capture(b"stored witness from higher digest branch".to_vec())
            .await
    } else {
        bob.confirm(bob_pending).await;
        bob.send_app_capture(b"stored witness from higher digest branch".to_vec())
            .await
    };

    store_created_message(carol.storage(), &group_id, &commit_messages[0]);
    store_created_message(carol.storage(), &group_id, &commit_messages[1]);
    store_created_message(carol.storage(), &group_id, &app_msg);

    let result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            sync_state: SyncState::Stable,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 5,
                witness_quorum_senders_per_epoch: 2,
                witness_quorum_epochs: 1,
                max_witness_override_depth: 1,
            },
            app_message_past_epoch_limit: 5,
            stable_quiescence_ms: 1_000,
        },
        2_000,
    )
    .expect("stored OpenMLS canonicalization succeeds");

    let app_commit_id = hex::encode(commit_messages[app_branch_index].id.as_slice());
    assert_eq!(result.accepted_commits, vec![app_commit_id]);
    assert_eq!(
        result.accepted_app_messages,
        vec![hex::encode(app_msg.id.as_slice())]
    );
    assert_eq!(
        carol.epoch().0,
        1,
        "stored canonicalization must not mutate the retained anchor"
    );
}

fn assert_projected_kind(msg: &TransportMessage, expected_kind: OpenMlsContentKind, source: u64) {
    let projection = project_mls_message(&msg.payload).expect("MLS message projects");
    assert_eq!(projection.kind, expected_kind);
    assert_eq!(projection.source_epoch, Some(source));
}

fn store_created_message(
    storage: &storage_memory::MemoryStorage,
    group_id: &GroupId,
    msg: &TransportMessage,
) {
    let projection = project_mls_message(&msg.payload).expect("message projects");
    let epoch = projection
        .source_epoch
        .expect("group message has source epoch");
    storage
        .put_message(&MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(epoch),
            state: MessageState::Created,
            payload: serde_json::to_vec(msg).expect("transport serializes"),
        })
        .expect("message stored");
}
