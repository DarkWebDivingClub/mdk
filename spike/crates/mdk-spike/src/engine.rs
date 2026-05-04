use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use rand::RngCore;

use cgka_engine::{
    CgkaEngine, Capability, EncryptedPayload, EngineError, EpochId, Feature, FeatureRegistry,
    FeatureStatus, GroupCapabilities, GroupContext, GroupContextSnapshot, GroupEvent, GroupId,
    IngestOutcome, MemberId, MessageId, MessageType, PendingStateRef, SendIntent, SendResult,
    StaleReason, TransportEnvelope, TransportKind, TransportMessage,
};
use transport::TransportPeeler;

use crate::context::MlsGroupContextSpike;
use crate::extensions::{
    BasicGroupData, NostrTransportData, BASIC_GROUP_DATA_EXT_TYPE, NOSTR_TRANSPORT_DATA_EXT_TYPE,
};
use crate::registry::default_registry;

const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

const EXPORTER_LABEL: &str = "nostr";

pub struct Mdk {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    identity: [u8; 32],
    registry: FeatureRegistry,
    peeler: Box<dyn TransportPeeler>,
    groups: HashMap<GroupId, GroupState>,
    transport_to_mls: HashMap<Vec<u8>, GroupId>,
    pending: HashMap<PendingStateRef, PendingOp>,
    pending_counter: u64,
    seen: HashSet<MessageId>,
    events: Vec<GroupEvent>,
    /// Capabilities NOT to advertise in this client's KeyPackage. Used by the
    /// negative capability-negotiation test. Set via `DM_DROP_CAPS` env at startup.
    dropped_caps: Vec<Capability>,
    /// Auto-commit side effects (TransportMessages the engine produced in
    /// response to inbound events — e.g. auto-committing a SelfRemove proposal).
    /// The wiring layer drains these after `ingest` and publishes them.
    auto_publish_queue: Vec<TransportMessage>,
}

struct GroupState {
    mls_group: MlsGroup,
    nostr_group_id: [u8; 32],
    name: String,
    description: String,
}

#[derive(Clone, Debug)]
enum PendingOp {
    GroupCreation { group_id: GroupId },
    Invite { group_id: GroupId, added: Vec<MemberId> },
    Leave { group_id: GroupId },
}

impl Mdk {
    /// `identity` must be the 32-byte Nostr x-only pubkey of the local user. That way
    /// MemberId identifiers match Nostr pubkeys 1:1.
    pub fn new(identity: [u8; 32], peeler: Box<dyn TransportPeeler>) -> Result<Self, EngineError> {
        Self::with_dropped_caps(identity, peeler, Vec::new())
    }

    /// Same as `new` but drops selected capabilities from the advertised KeyPackage.
    /// Used by the negative capability-negotiation test — a client that doesn't
    /// advertise `SelfRemove` cannot be added to a group that requires it.
    pub fn with_dropped_caps(
        identity: [u8; 32],
        peeler: Box<dyn TransportPeeler>,
        dropped_caps: Vec<Capability>,
    ) -> Result<Self, EngineError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| EngineError::Backend(format!("sig keypair: {e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| EngineError::Backend(format!("store signer: {e:?}")))?;

        let basic = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: basic.into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential_with_key,
            identity,
            registry: default_registry(),
            peeler,
            groups: HashMap::new(),
            transport_to_mls: HashMap::new(),
            pending: HashMap::new(),
            pending_counter: 0,
            seen: HashSet::new(),
            events: Vec::new(),
            dropped_caps,
            auto_publish_queue: Vec::new(),
        })
    }

    fn next_pending(&mut self) -> PendingStateRef {
        self.pending_counter += 1;
        PendingStateRef(self.pending_counter)
    }

    /// Capabilities the local KeyPackage advertises — walks the feature registry
    /// and collects every capability except those listed in `dropped_caps`.
    fn leaf_capabilities(&self) -> Capabilities {
        let mut ext_types: Vec<ExtensionType> = vec![ExtensionType::RequiredCapabilities];
        let mut proposal_types: Vec<ProposalType> = Vec::new();

        for (_feature, spec) in self.registry.all() {
            if self.dropped_caps.contains(&spec.requires) {
                continue;
            }
            match &spec.requires {
                Capability::Extension(t) => ext_types.push(ExtensionType::Unknown(*t)),
                Capability::Proposal(t) => {
                    proposal_types.push(ProposalType::from(*t));
                }
            }
        }

        Capabilities::new(
            None,
            Some(&[CIPHERSUITE]),
            Some(&ext_types),
            Some(&proposal_types),
            None,
        )
    }

    fn build_group_context(&self, group_id: &GroupId) -> Result<MlsGroupContextSpike, EngineError> {
        let state = self
            .groups
            .get(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let exporter = state
            .mls_group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&exporter);
        Ok(MlsGroupContextSpike {
            exporter_secret_nostr: secret,
            epoch_num: state.mls_group.epoch().as_u64(),
            nostr_group_id: Some(state.nostr_group_id.to_vec()),
        })
    }

    fn member_ids(group: &MlsGroup) -> Vec<MemberId> {
        group
            .members()
            .filter_map(|m| {
                let basic = BasicCredential::try_from(m.credential).ok()?;
                let id = basic.identity();
                if id.len() == 32 {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(id);
                    Some(MemberId(out))
                } else {
                    None
                }
            })
            .collect()
    }

    fn capabilities_from_key_package(kp: &KeyPackage) -> GroupCapabilities {
        let mut caps = GroupCapabilities::default();
        let leaf_caps = kp.leaf_node().capabilities();
        for ext_type in leaf_caps.extensions() {
            if let ExtensionType::Unknown(t) = ext_type {
                caps.add(Capability::Extension(*t));
            }
        }
        for proposal_type in leaf_caps.proposals() {
            let wire: u16 = (*proposal_type).into();
            caps.add(Capability::Proposal(wire));
        }
        caps
    }

    fn parse_key_package(&self, bytes: &[u8]) -> Result<KeyPackage, EngineError> {
        let mls_in = MlsMessageIn::tls_deserialize(&mut &bytes[..])
            .map_err(|e| EngineError::Serialize(format!("keypackage deserialize: {e:?}")))?;
        match mls_in.extract() {
            MlsMessageBodyIn::KeyPackage(kp_in) => kp_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| EngineError::Backend(format!("kp validate: {e:?}"))),
            _ => Err(EngineError::Serialize("not a keypackage".into())),
        }
    }
}

#[async_trait]
impl CgkaEngine for Mdk {
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError> {
        if !self.seen.insert(msg.id) {
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen,
            });
        }

        match msg.envelope.clone() {
            TransportEnvelope::Welcome { recipient } => {
                if recipient.0 != self.identity {
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::NotForThisClient,
                    });
                }
                let peeled = self
                    .peeler
                    .peel_welcome(&msg)
                    .await
                    .map_err(|e| EngineError::Peeler(format!("{e}")))?;
                // peeled.payload = serialised MlsMessageIn whose body is a Welcome
                let mls_in = MlsMessageIn::tls_deserialize(&mut &peeled.payload[..])
                    .map_err(|e| EngineError::Serialize(format!("welcome deserialize: {e:?}")))?;
                let welcome = match mls_in.extract() {
                    MlsMessageBodyIn::Welcome(w) => w,
                    _ => return Err(EngineError::Serialize("expected welcome body".into())),
                };
                let join_cfg = MlsGroupJoinConfig::builder()
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .build();
                let staged = StagedWelcome::new_from_welcome(
                    &self.provider,
                    &join_cfg,
                    welcome,
                    None, // ratchet tree embedded in welcome
                )
                .map_err(|e| EngineError::Backend(format!("staged welcome: {e:?}")))?;
                let mls_group = staged
                    .into_group(&self.provider)
                    .map_err(|e| EngineError::Backend(format!("into_group: {e:?}")))?;

                let mls_group_id = GroupId(mls_group.group_id().as_slice().to_vec());

                // Extract our two extensions from the group context.
                let (mut name, mut description, mut nostr_group_id) =
                    ("".to_string(), "".to_string(), [0u8; 32]);
                let gc_exts = mls_group.extensions();
                for ext in gc_exts.iter() {
                    if let Extension::Unknown(t, data) = ext {
                        if *t == BASIC_GROUP_DATA_EXT_TYPE {
                            if let Some(bgd) = BasicGroupData::decode(&data.0) {
                                name = bgd.name;
                                description = bgd.description;
                            }
                        } else if *t == NOSTR_TRANSPORT_DATA_EXT_TYPE {
                            if let Some(ntd) = NostrTransportData::decode(&data.0) {
                                nostr_group_id = ntd.nostr_group_id;
                            }
                        }
                    }
                }

                let epoch = mls_group.epoch().as_u64();
                self.transport_to_mls
                    .insert(nostr_group_id.to_vec(), mls_group_id.clone());
                self.groups.insert(
                    mls_group_id.clone(),
                    GroupState {
                        mls_group,
                        nostr_group_id,
                        name,
                        description,
                    },
                );
                self.events.push(GroupEvent::Joined {
                    group_id: mls_group_id,
                    epoch: EpochId(epoch),
                });
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                let Some(mls_group_id) = self.transport_to_mls.get(&transport_group_id).cloned()
                else {
                    return Ok(IngestOutcome::Stale {
                        reason: StaleReason::UnknownGroup,
                    });
                };
                let ctx = self.build_group_context(&mls_group_id)?;
                let snapshot = GroupContextSnapshot::from_context(&ctx, &["nostr"]);
                let peeled = match self
                    .peeler
                    .peel_group_message(&msg, &snapshot)
                    .await
                {
                    Ok(p) => p,
                    Err(err) => {
                        // Peel failure on an inbound group message almost always
                        // means the blob was encrypted with a different epoch's
                        // exporter secret — either backlog from before we joined,
                        // or a race after a forked commit. Treat as stale, not
                        // error.
                        tracing::debug!("peel_group_message (stale): {err}");
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::AlreadyAtEpoch {
                                current: EpochId(0),
                                msg_epoch: EpochId(0),
                            },
                        });
                    }
                };

                // Decode inner MLS message
                let mls_in = MlsMessageIn::tls_deserialize(&mut &peeled.payload[..])
                    .map_err(|e| EngineError::Serialize(format!("mls deserialize: {e:?}")))?;
                let protocol_msg: ProtocolMessage = match mls_in.extract() {
                    MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
                    MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
                    _ => return Err(EngineError::Serialize("not a group message".into())),
                };

                let state = self
                    .groups
                    .get_mut(&mls_group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(mls_group_id.clone()))?;

                tracing::debug!("ingest: processing group message, id={}", msg.id.as_hex());
                let processed = match state.mls_group.process_message(&self.provider, protocol_msg)
                {
                    Ok(p) => p,
                    Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::OwnEcho,
                        });
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                        // Typical cause: we just joined via a welcome which advanced us
                        // to the post-commit epoch, then the commit itself arrives.
                        let current = EpochId(state.mls_group.epoch().as_u64());
                        return Ok(IngestOutcome::Stale {
                            reason: StaleReason::AlreadyAtEpoch {
                                current,
                                msg_epoch: EpochId(0),
                            },
                        });
                    }
                    Err(e) => return Err(EngineError::Backend(format!("process_message: {e:?}"))),
                };

                let sender_identity = processed.credential().clone();
                let sender = match BasicCredential::try_from(sender_identity) {
                    Ok(b) if b.identity().len() == 32 => {
                        let mut m = [0u8; 32];
                        m.copy_from_slice(b.identity());
                        MemberId(m)
                    }
                    _ => MemberId([0u8; 32]),
                };

                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(app) => {
                        let rumor = app.into_bytes();
                        let epoch = state.mls_group.epoch().as_u64();
                        self.events.push(GroupEvent::ApplicationMessage {
                            group_id: mls_group_id,
                            sender,
                            rumor_bytes: rumor,
                            epoch: EpochId(epoch),
                        });
                    }
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        // Before merging, extract the add/remove proposal info so we
                        // can emit semantically meaningful events.
                        let added: Vec<MemberId> = staged
                            .add_proposals()
                            .filter_map(|qp| {
                                let kp = qp.add_proposal().key_package();
                                BasicCredential::try_from(kp.leaf_node().credential().clone())
                                    .ok()
                                    .and_then(|b| {
                                        let id = b.identity();
                                        if id.len() == 32 {
                                            let mut m = [0u8; 32];
                                            m.copy_from_slice(id);
                                            Some(MemberId(m))
                                        } else {
                                            None
                                        }
                                    })
                            })
                            .collect();
                        let removed_indices: Vec<u32> = staged
                            .remove_proposals()
                            .map(|qp| qp.remove_proposal().removed().u32())
                            .collect();
                        let removed: Vec<MemberId> = removed_indices
                            .iter()
                            .filter_map(|idx| {
                                state.mls_group.members().find_map(|m| {
                                    if m.index.u32() != *idx {
                                        return None;
                                    }
                                    BasicCredential::try_from(m.credential).ok().and_then(|b| {
                                        let id = b.identity();
                                        if id.len() == 32 {
                                            let mut out = [0u8; 32];
                                            out.copy_from_slice(id);
                                            Some(MemberId(out))
                                        } else {
                                            None
                                        }
                                    })
                                })
                            })
                            .collect();

                        state
                            .mls_group
                            .merge_staged_commit(&self.provider, *staged)
                            .map_err(|e| {
                                EngineError::Backend(format!("merge_staged_commit: {e:?}"))
                            })?;
                        let new_epoch = state.mls_group.epoch().as_u64();
                        for m in &added {
                            self.events.push(GroupEvent::MemberAdded {
                                group_id: mls_group_id.clone(),
                                member: m.clone(),
                                epoch: EpochId(new_epoch),
                            });
                        }
                        for m in &removed {
                            self.events.push(GroupEvent::MemberRemoved {
                                group_id: mls_group_id.clone(),
                                member: m.clone(),
                                epoch: EpochId(new_epoch),
                            });
                        }
                        self.events.push(GroupEvent::EpochAdvanced {
                            group_id: mls_group_id,
                            new_epoch: EpochId(new_epoch),
                        });
                    }
                    ProcessedMessageContent::ProposalMessage(qp) => {
                        tracing::debug!("ingest: proposal received, variant={:?}", qp.proposal());
                        // Per MIP-03: a SelfRemove proposal is automatically
                        // committed by a different member. The committer MUST NOT
                        // be the member being removed. OpenMLS has already queued
                        // the proposal via process_message — we issue a commit to
                        // pending proposals. The resulting commit is wrapped and
                        // flagged on the pending store so the caller can publish.
                        let is_self_remove = matches!(
                            qp.proposal(),
                            Proposal::SelfRemove
                        );
                        if is_self_remove {
                            // Per MIP-03 §147 the removed member is identified by
                            // `sender.leaf_index`. Per RFC 9420 §12.2 the
                            // committer MUST NOT be the removed member.
                            //
                            // Race avoidance: if multiple remaining members each
                            // auto-commit independently they fork the epoch.
                            // Deterministic rule: the lowest-index remaining
                            // member is the committer. Others wait for that
                            // commit to arrive as normal inbound.
                            let leaver_leaf = match qp.sender() {
                                Sender::Member(idx) => Some(*idx),
                                _ => None,
                            };
                            let own = state.mls_group.own_leaf_index();
                            let lowest_remaining = state
                                .mls_group
                                .members()
                                .map(|m| m.index)
                                .filter(|idx| Some(*idx) != leaver_leaf)
                                .min();
                            let auto_commit = leaver_leaf
                                .map(|l| l != own)
                                .unwrap_or(false)
                                && lowest_remaining == Some(own);
                            if auto_commit {
                                // Create commit-to-pending-proposals — a
                                // SelfRemove-only commit per spec §144/146.
                                match state.mls_group.commit_to_pending_proposals(
                                    &self.provider,
                                    &self.signer,
                                ) {
                                    Ok((commit_out, _welcome_opt, _gi)) => {
                                        match commit_out.tls_serialize_detached() {
                                            Ok(commit_bytes) => {
                                                // Wrap + enqueue for publication
                                                // via a queued auto-commit side
                                                // effect. For the spike we wrap
                                                // inline and stash the bytes on a
                                                // queue that the wiring layer can
                                                // drain.
                                                let ctx_snap = {
                                                    let ctx = self.build_group_context(&mls_group_id)?;
                                                    GroupContextSnapshot::from_context(
                                                        &ctx,
                                                        &["nostr"],
                                                    )
                                                };
                                                let payload = EncryptedPayload {
                                                    message_type: MessageType::Commit,
                                                    bytes: commit_bytes,
                                                };
                                                let wrapped = self
                                                    .peeler
                                                    .wrap_group_message(&payload, &ctx_snap)
                                                    .await
                                                    .map_err(|e| {
                                                        EngineError::Peeler(format!("{e}"))
                                                    })?;
                                                self.auto_publish_queue.push(wrapped);
                                                // Merge locally; remaining members
                                                // will merge when they receive it.
                                                let state = self
                                                    .groups
                                                    .get_mut(&mls_group_id)
                                                    .ok_or_else(|| {
                                                        EngineError::UnknownGroup(
                                                            mls_group_id.clone(),
                                                        )
                                                    })?;
                                                state
                                                    .mls_group
                                                    .merge_pending_commit(&self.provider)
                                                    .map_err(|e| {
                                                        EngineError::Backend(format!(
                                                            "merge auto-commit: {e:?}"
                                                        ))
                                                    })?;
                                                let new_epoch =
                                                    state.mls_group.epoch().as_u64();
                                                self.events.push(GroupEvent::EpochAdvanced {
                                                    group_id: mls_group_id.clone(),
                                                    new_epoch: EpochId(new_epoch),
                                                });
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "auto-commit serialize failed: {e:?}"
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("auto-commit self-remove: {e:?}");
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        // external join proposals — ignored in spike
                    }
                }
            }
        }
        Ok(IngestOutcome::Processed)
    }

    fn drain_events(&mut self) -> Vec<GroupEvent> {
        std::mem::take(&mut self.events)
    }

    fn drain_auto_publish(&mut self) -> Vec<TransportMessage> {
        std::mem::take(&mut self.auto_publish_queue)
    }

    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        match intent {
            SendIntent::ApplicationMessage {
                group_id,
                rumor_bytes,
            } => {
                let state = self
                    .groups
                    .get_mut(&group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

                let msg_out = state
                    .mls_group
                    .create_message(&self.provider, &self.signer, &rumor_bytes)
                    .map_err(|e| EngineError::Backend(format!("create_message: {e:?}")))?;

                let serialised = msg_out
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

                let payload = EncryptedPayload {
                    message_type: MessageType::Application,
                    bytes: serialised,
                };
                let ctx = self.build_group_context(&group_id)?;
                let snapshot = GroupContextSnapshot::from_context(&ctx, &["nostr"]);
                let wrapped = self
                    .peeler
                    .wrap_group_message(&payload, &snapshot)
                    .await
                    .map_err(|e| EngineError::Peeler(format!("{e}")))?;

                Ok(SendResult::ApplicationMessage { msg: wrapped })
            }
            SendIntent::Invite {
                group_id,
                key_packages,
            } => {
                let mut parsed_kps = Vec::with_capacity(key_packages.len());
                for bytes in &key_packages {
                    parsed_kps.push(self.parse_key_package(bytes)?);
                }

                // Capability check: each new member's KeyPackage must cover the
                // group's existing RequiredCapabilities.
                let required = {
                    let state = self
                        .groups
                        .get(&group_id)
                        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
                    let mut req = GroupCapabilities::default();
                    for ext in state.mls_group.extensions().iter() {
                        if let Extension::RequiredCapabilities(rc) = ext {
                            for t in rc.extension_types() {
                                if let ExtensionType::Unknown(u) = t {
                                    req.add(Capability::Extension(*u));
                                }
                            }
                            for p in rc.proposal_types() {
                                let wire: u16 = (*p).into();
                                req.add(Capability::Proposal(wire));
                            }
                        }
                    }
                    req
                };
                for kp in &parsed_kps {
                    let caps = Self::capabilities_from_key_package(kp);
                    if !caps.covers(&required) {
                        return Err(EngineError::Other(format!(
                            "invitee KeyPackage missing required capabilities: required={:?} had={:?}",
                            required, caps
                        )));
                    }
                }

                let state = self
                    .groups
                    .get_mut(&group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

                let (commit_out, welcome_out, _gi) = state
                    .mls_group
                    .add_members(&self.provider, &self.signer, &parsed_kps)
                    .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;

                let commit_bytes = commit_out
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
                let welcome_bytes = welcome_out
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

                // Wrap commit using the CURRENT (pre-merge) exporter secret so
                // current members can decrypt before advancing. OpenMLS internally
                // uses the sender-side epoch here.
                let ctx = self.build_group_context(&group_id)?;
                let snapshot = GroupContextSnapshot::from_context(&ctx, &["nostr"]);
                let commit_payload = EncryptedPayload {
                    message_type: MessageType::Commit,
                    bytes: commit_bytes,
                };
                let wrapped_commit = self
                    .peeler
                    .wrap_group_message(&commit_payload, &snapshot)
                    .await
                    .map_err(|e| EngineError::Peeler(format!("{e}")))?;

                let mut added: Vec<MemberId> = Vec::with_capacity(parsed_kps.len());
                let mut welcomes = Vec::with_capacity(parsed_kps.len());
                for kp in &parsed_kps {
                    let basic = BasicCredential::try_from(kp.leaf_node().credential().clone())
                        .map_err(|e| EngineError::Backend(format!("basic cred: {e:?}")))?;
                    let id = basic.identity();
                    if id.len() != 32 {
                        return Err(EngineError::Other("identity must be 32 bytes".into()));
                    }
                    let mut m = [0u8; 32];
                    m.copy_from_slice(id);
                    let recipient = MemberId(m);
                    added.push(recipient.clone());

                    let payload = EncryptedPayload {
                        message_type: MessageType::Welcome,
                        bytes: welcome_bytes.clone(),
                    };
                    let wrapped = self
                        .peeler
                        .wrap_welcome(&payload, &recipient)
                        .await
                        .map_err(|e| EngineError::Peeler(format!("{e}")))?;
                    welcomes.push(wrapped);
                }

                let pending_ref = self.next_pending();
                self.pending.insert(
                    pending_ref.clone(),
                    PendingOp::Invite {
                        group_id: group_id.clone(),
                        added,
                    },
                );

                Ok(SendResult::GroupEvolution {
                    msg: wrapped_commit,
                    welcomes,
                    pending: pending_ref,
                })
            }
            SendIntent::Leave { group_id } => {
                // Uses the SelfRemove proposal path — the reason the feature
                // exists. OpenMLS 0.8 explicitly rejects remove_members([self])
                // with CannotRemoveSelf. `leave_group()` produces a SelfRemove
                // proposal that remaining members can commit.
                //
                // Spike behaviour:
                //   * leaver publishes the proposal via the adapter
                //   * leaver forgets the group locally (one-shot exit)
                //   * remaining members receive & stage the proposal; a full
                //     demo would auto-commit it from another member. Not wired.
                let state = self
                    .groups
                    .get_mut(&group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

                let proposal_out = state
                    .mls_group
                    .leave_group_via_self_remove(&self.provider, &self.signer)
                    .map_err(|e| EngineError::Backend(format!("leave_group_via_self_remove: {e:?}")))?;

                let proposal_bytes = proposal_out
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

                let ctx = self.build_group_context(&group_id)?;
                let snapshot = GroupContextSnapshot::from_context(&ctx, &["nostr"]);
                let payload = EncryptedPayload {
                    message_type: MessageType::Proposal,
                    bytes: proposal_bytes,
                };
                let wrapped = self
                    .peeler
                    .wrap_group_message(&payload, &snapshot)
                    .await
                    .map_err(|e| EngineError::Peeler(format!("{e}")))?;

                let pending_ref = self.next_pending();
                self.pending.insert(
                    pending_ref.clone(),
                    PendingOp::Leave {
                        group_id: group_id.clone(),
                    },
                );

                Ok(SendResult::GroupEvolution {
                    msg: wrapped,
                    welcomes: Vec::new(),
                    pending: pending_ref,
                })
            }
        }
    }

    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        let op = self
            .pending
            .remove(&pending)
            .ok_or(EngineError::UnknownPending(pending))?;
        match op {
            PendingOp::GroupCreation { group_id } => {
                // The create_group path merged eagerly so the exporter secret would
                // be available for wrap; nothing to do here beyond emitting.
                let state = self
                    .groups
                    .get(&group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
                let epoch = state.mls_group.epoch().as_u64();
                Ok(GroupEvent::GroupCreated {
                    group_id,
                    epoch: EpochId(epoch),
                })
            }
            PendingOp::Invite { group_id, added } => {
                let state = self
                    .groups
                    .get_mut(&group_id)
                    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
                state
                    .mls_group
                    .merge_pending_commit(&self.provider)
                    .map_err(|e| EngineError::Backend(format!("merge_pending(invite): {e:?}")))?;
                let epoch = state.mls_group.epoch().as_u64();
                // Emit MemberAdded for each + also a composite EpochAdvanced. The
                // MemberAdded events are surfaced from the engine's queue rather
                // than returned directly so the CLI sees the same shape as inbound
                // commits processed by other members.
                for m in &added {
                    self.events.push(GroupEvent::MemberAdded {
                        group_id: group_id.clone(),
                        member: m.clone(),
                        epoch: EpochId(epoch),
                    });
                }
                Ok(GroupEvent::EpochAdvanced {
                    group_id,
                    new_epoch: EpochId(epoch),
                })
            }
            PendingOp::Leave { group_id } => {
                // SelfRemove is a proposal, not a commit — there's no pending
                // commit to merge. Remaining members stage this proposal and a
                // follow-up commit will apply it; for the spike the leaver
                // simply forgets the group.
                let epoch = self
                    .groups
                    .get(&group_id)
                    .map(|s| s.mls_group.epoch().as_u64())
                    .unwrap_or(0);
                self.transport_to_mls.retain(|_k, v| v != &group_id);
                self.groups.remove(&group_id);
                Ok(GroupEvent::MemberRemoved {
                    group_id,
                    member: MemberId(self.identity),
                    epoch: EpochId(epoch),
                })
            }
        }
    }

    async fn create_group(
        &mut self,
        name: &str,
        description: &str,
        member_key_packages: &[Vec<u8>],
        transports: &[TransportKind],
    ) -> Result<(GroupId, SendResult), EngineError> {
        // Parse member key packages + extract their capabilities for verification.
        let mut parsed_kps = Vec::with_capacity(member_key_packages.len());
        for bytes in member_key_packages {
            parsed_kps.push(self.parse_key_package(bytes)?);
        }

        // Build the required capabilities for this group given active transports + my registry.
        let required = self.registry.required_for_transports(transports);
        // Sanity: every member's KeyPackage must cover `required`.
        for kp in &parsed_kps {
            let caps = Self::capabilities_from_key_package(kp);
            if !caps.covers(&required) {
                return Err(EngineError::Other(format!(
                    "member key package missing required capabilities ({:?})",
                    required
                )));
            }
        }

        // Build the extension payload for the new group.
        let mut nostr_group_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nostr_group_id);

        let basic = BasicGroupData {
            name: name.to_string(),
            description: description.to_string(),
            image_url: None,
        };
        let mut gc_ext_vec: Vec<Extension> = Vec::new();
        gc_ext_vec.push(Extension::Unknown(
            BASIC_GROUP_DATA_EXT_TYPE,
            UnknownExtension(basic.encode()),
        ));

        if transports.contains(&TransportKind::Nostr) {
            let ntd = NostrTransportData {
                nostr_group_id,
                relays: vec!["wss://relay.primal.net".to_string()],
            };
            gc_ext_vec.push(Extension::Unknown(
                NOSTR_TRANSPORT_DATA_EXT_TYPE,
                UnknownExtension(ntd.encode()),
            ));
        }

        // RequiredCapabilities: union of extensions + proposals pulled from the
        // registry for the active transports + Required-level features.
        let required_ext_types: Vec<ExtensionType> = required
            .extensions()
            .map(|t| ExtensionType::Unknown(*t))
            .collect();
        let required_proposal_types: Vec<ProposalType> = required
            .proposals()
            .map(|t| ProposalType::from(*t))
            .collect();
        let required_caps_ext = RequiredCapabilitiesExtension::new(
            &required_ext_types,
            &required_proposal_types,
            &[],
        );
        gc_ext_vec.push(Extension::RequiredCapabilities(required_caps_ext));

        let gc_exts = Extensions::from_vec(gc_ext_vec)
            .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?;

        let leaf_caps = self.leaf_capabilities();
        // SelfRemove proposals MUST be sent as PublicMessage per MIP-03 / MLS
        // Extensions draft — OpenMLS 0.8 forbids leave_group_via_self_remove on
        // pure-ciphertext groups. Use pure-plaintext at the MLS layer; the
        // transport layer (kind 445 + exporter-secret ChaCha20Poly1305) still
        // provides the network-visible encryption.
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(leaf_caps)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_group_context_extensions(gc_exts)
            .use_ratchet_tree_extension(true)
            .build();

        let mut mls_group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &group_config,
            self.credential_with_key.clone(),
        )
        .map_err(|e| EngineError::Backend(format!("group new: {e:?}")))?;

        // Add members
        let (commit_out, welcome_out, _group_info) = mls_group
            .add_members(&self.provider, &self.signer, &parsed_kps)
            .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;

        // Serialise commit + welcome
        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let welcome_bytes = welcome_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        // Build GroupContext snapshot BEFORE storing the group in self.groups, using
        // the not-yet-merged epoch so recipients can peel.
        // Actually: exporter secret depends on the NEW epoch (post-commit). We need to
        // export the secret for the epoch the welcome brings recipients into. For the
        // spike we'll merge_pending_commit to get the post-commit secret, then export.
        // But target-arch says "publish first, then merge". To honor both: we pre-compute
        // by temporarily merging, exporting, then... actually OpenMLS can export from the
        // staged commit's group_context if we look at GroupInfo. Simpler: merge here and
        // remember that's a spike shortcut — publish-before-apply still honored because
        // we do NOT emit GroupCreated event until confirm_published.
        mls_group
            .merge_pending_commit(&self.provider)
            .map_err(|e| EngineError::Backend(format!("merge_pending: {e:?}")))?;

        let exporter = mls_group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
        let mut exporter_arr = [0u8; 32];
        exporter_arr.copy_from_slice(&exporter);

        let group_id = GroupId(mls_group.group_id().as_slice().to_vec());

        // Store so build_group_context works for subsequent sends
        self.groups.insert(
            group_id.clone(),
            GroupState {
                mls_group,
                nostr_group_id,
                name: name.to_string(),
                description: description.to_string(),
            },
        );
        self.transport_to_mls
            .insert(nostr_group_id.to_vec(), group_id.clone());

        let ctx = MlsGroupContextSpike {
            exporter_secret_nostr: exporter_arr,
            epoch_num: self
                .groups
                .get(&group_id)
                .unwrap()
                .mls_group
                .epoch()
                .as_u64(),
            nostr_group_id: Some(nostr_group_id.to_vec()),
        };
        let snapshot = GroupContextSnapshot::from_context(&ctx, &["nostr"]);

        let commit_payload = EncryptedPayload {
            message_type: MessageType::Commit,
            bytes: commit_bytes,
        };
        let wrapped_commit = self
            .peeler
            .wrap_group_message(&commit_payload, &snapshot)
            .await
            .map_err(|e| EngineError::Peeler(format!("{e}")))?;

        // Wrap a welcome per recipient
        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        for kp in &parsed_kps {
            let basic = BasicCredential::try_from(kp.leaf_node().credential().clone())
                .map_err(|e| EngineError::Backend(format!("basic cred: {e:?}")))?;
            let id = basic.identity();
            if id.len() != 32 {
                return Err(EngineError::Other("member identity must be 32 bytes".into()));
            }
            let mut recip = [0u8; 32];
            recip.copy_from_slice(id);
            let recipient = MemberId(recip);

            let payload = EncryptedPayload {
                message_type: MessageType::Welcome,
                bytes: welcome_bytes.clone(),
            };
            let wrapped = self
                .peeler
                .wrap_welcome(&payload, &recipient)
                .await
                .map_err(|e| EngineError::Peeler(format!("{e}")))?;
            welcomes.push(wrapped);
        }

        let pending_ref = self.next_pending();
        // For the spike we've already merged above — so confirm_published is a no-op
        // that just emits the GroupCreated event. We still return GroupEvolution so the
        // application layer exercises the publish-before-apply seam.
        self.pending.insert(
            pending_ref.clone(),
            PendingOp::GroupCreation {
                group_id: group_id.clone(),
            },
        );

        Ok((
            group_id,
            SendResult::GroupEvolution {
                msg: wrapped_commit,
                welcomes,
                pending: pending_ref,
            },
        ))
    }

    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: Feature,
    ) -> Result<FeatureStatus, EngineError> {
        let state = self
            .groups
            .get(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let Some(spec) = self.registry.spec(feature) else {
            return Ok(FeatureStatus::Unavailable {
                missing: GroupCapabilities::default(),
            });
        };

        // 1. Check whether the group's RequiredCapabilities covers the feature's
        //    capability (MLS enforces this on adds, so if it's in required, every
        //    current leaf MUST support it).
        let mut required = GroupCapabilities::default();
        for ext in state.mls_group.extensions().iter() {
            if let Extension::RequiredCapabilities(rc) = ext {
                for ext_type in rc.extension_types() {
                    if let ExtensionType::Unknown(u) = ext_type {
                        required.add(Capability::Extension(*u));
                    }
                }
                for p in rc.proposal_types() {
                    let wire: u16 = (*p).into();
                    required.add(Capability::Proposal(wire));
                }
            }
        }
        let in_required = required.contains(&spec.requires);
        if in_required {
            return Ok(FeatureStatus::Available);
        }

        // 2. Not in RequiredCapabilities. OpenMLS 0.8 doesn't publicly expose
        //    per-leaf `LeafNode` access from `MlsGroup`, so in the spike we can't
        //    walk every member's advertised Capabilities to decide between
        //    Upgradeable vs Unavailable. We return Upgradeable as a best-effort —
        //    the real target (with tree access) would compute this precisely.
        Ok(FeatureStatus::Upgradeable)
    }

    fn constructable_capabilities(
        &self,
        member_key_packages: &[Vec<u8>],
    ) -> Result<GroupCapabilities, EngineError> {
        if member_key_packages.is_empty() {
            return Ok(GroupCapabilities::default());
        }
        let mut iter = member_key_packages.iter();
        let first = self.parse_key_package(iter.next().unwrap())?;
        let mut intersection = Self::capabilities_from_key_package(&first);
        // Include local client too
        intersection = intersection.intersect(&self.registry.all_advertisable());
        for bytes in iter {
            let kp = self.parse_key_package(bytes)?;
            intersection = intersection.intersect(&Self::capabilities_from_key_package(&kp));
        }
        Ok(intersection)
    }

    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext>, EngineError> {
        let ctx = self.build_group_context(group_id)?;
        Ok(Box::new(ctx))
    }

    fn members(&self, group_id: &GroupId) -> Result<Vec<MemberId>, EngineError> {
        let state = self
            .groups
            .get(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        Ok(Self::member_ids(&state.mls_group))
    }

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError> {
        let state = self
            .groups
            .get(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        Ok(EpochId(state.mls_group.epoch().as_u64()))
    }

    fn self_id(&self) -> MemberId {
        MemberId(self.identity)
    }

    fn fresh_key_package(&mut self) -> Result<Vec<u8>, EngineError> {
        let caps = self.leaf_capabilities();
        let kp_bundle = KeyPackage::builder()
            .leaf_node_capabilities(caps)
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(|e| EngineError::Backend(format!("kp build: {e:?}")))?;
        let kp: KeyPackage = kp_bundle.key_package().clone();
        let mls_msg: MlsMessage = kp.into();
        // MlsMessage is the unified container that serializes with its wire format;
        // in openmls 0.8 the type is called MlsMessageOut/MlsMessage depending on
        // version. The KeyPackage → MlsMessageOut convention is standard.
        let bytes = mls_msg
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        Ok(bytes)
    }
}

// The OpenMLS outbound message alias. Name varies across 0.8 minor versions; alias
// locally so the above compiles against whichever.
type MlsMessage = MlsMessageOut;
