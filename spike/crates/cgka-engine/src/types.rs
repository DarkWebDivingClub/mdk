use serde::{Deserialize, Serialize};

/// Content-addressed message identifier. For Nostr transport this is the event id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

impl MessageId {
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MessageId({})", self.as_hex())
    }
}

/// Opaque MLS group identifier.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub Vec<u8>);

impl GroupId {
    pub fn as_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Debug for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId({})", self.as_hex())
    }
}

/// Opaque member identifier (for spike = nostr pubkey bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub [u8; 32]);

impl MemberId {
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for MemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemberId({})", self.as_hex())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize)]
pub struct EpochId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Timestamp(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum TransportSource {
    Nostr,
    Fips,
    Other,
}

/// The coordinator's input/output blob type. Opaque bytes + minimal metadata.
/// Per target-architecture.md §"The TransportMessage Type".
#[derive(Clone, Debug)]
pub struct TransportMessage {
    pub id: MessageId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
    pub causal_deps: Vec<MessageId>,
    pub source: TransportSource,
    /// Destination type discriminator the adapter needs — in Nostr terms, which
    /// outer event kind (445 group msg vs 1059 welcome gift-wrap). Kept minimal.
    pub envelope: TransportEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEnvelope {
    /// Group message. The `transport_group_id` is the transport-visible routing tag
    /// (Nostr `h`-tag value = nostr_group_id from NostrTransportData extension).
    GroupMessage { transport_group_id: Vec<u8> },
    /// Welcome — addressed to a specific member (giftwrap on Nostr).
    Welcome { recipient: MemberId },
}

/// Output of TransportPeeler::peel — classified inner payload ready for CGKA backend.
#[derive(Clone, Debug)]
pub struct PeeledMessage {
    pub id: MessageId,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub ordering_metadata: OrderingMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    Commit,
    Proposal,
    Application,
    Welcome,
}

#[derive(Clone, Debug, Default)]
pub struct OrderingMetadata {
    pub epoch_hint: Option<EpochId>,
}

/// Wrapped-for-transport-but-not-yet-sent: the CGKA backend's output before the peeler
/// adds the outer envelope.
#[derive(Clone, Debug)]
pub struct EncryptedPayload {
    pub message_type: MessageType,
    pub bytes: Vec<u8>,
}

/// Application-layer intent. Fed into `CgkaEngine::send`.
#[derive(Clone, Debug)]
pub enum SendIntent {
    /// Send a plaintext application message (an unsigned Nostr rumor is serialised by
    /// the engine before encryption).
    ApplicationMessage {
        group_id: GroupId,
        /// Serialised unsigned Nostr rumor. The engine does not interpret this.
        rumor_bytes: Vec<u8>,
    },
    /// Invite new members to an existing group. Their KeyPackages must have been
    /// fetched by the caller.
    Invite {
        group_id: GroupId,
        key_packages: Vec<Vec<u8>>, // serialised MLS KeyPackages
    },
    /// Leave the group (self-remove). Translates to a Remove(self_leaf) commit in
    /// the spike; the real target uses the dedicated SelfRemove proposal.
    Leave { group_id: GroupId },
}

/// Outcome of `CgkaEngine::ingest`. Lets the coordinator distinguish
/// "silently-dedupe-worthy" conditions from genuine processing errors, per the
/// spike learning that `Backend(String)` was hiding structure.
#[derive(Clone, Debug)]
pub enum IngestOutcome {
    /// Successfully processed; any resulting events are in `drain_events()`.
    Processed,
    /// Silently-ignore condition. Log at trace/debug, not warn.
    Stale { reason: StaleReason },
}

#[derive(Clone, Debug)]
pub enum StaleReason {
    /// Same MessageId already ingested.
    AlreadySeen,
    /// A commit whose source epoch is behind our current epoch (e.g. commit-echo
    /// after we already advanced via a welcome).
    AlreadyAtEpoch { current: EpochId, msg_epoch: EpochId },
    /// Welcome not addressed to our identity.
    NotForThisClient,
    /// Group message for a group we don't track (not yet joined, or left).
    UnknownGroup,
    /// Our own outbound message echoing back.
    OwnEcho,
}

/// Opaque pending-state handle. Returned with a `GroupEvolution` SendResult; must be
/// passed back to `confirm_published` after the transport confirms delivery.
/// Per target-architecture §"The `SendResult`/`PendingStateRef` outbound contract".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingStateRef(pub u64);

#[derive(Debug)]
pub enum SendResult {
    /// Fire-and-forget application message. No state change on publish.
    ApplicationMessage { msg: TransportMessage },
    /// Commit / add / remove / rotation. Two-step: publish THEN `confirm_published`.
    /// The `welcomes` vec carries any gift-wrapped welcomes that must also be published.
    GroupEvolution {
        msg: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
    },
}

/// Output of `CgkaEngine::events`. Ordered, decrypted, application-visible.
#[derive(Clone, Debug)]
pub enum GroupEvent {
    ApplicationMessage {
        group_id: GroupId,
        sender: MemberId,
        rumor_bytes: Vec<u8>,
        epoch: EpochId,
    },
    MemberAdded {
        group_id: GroupId,
        member: MemberId,
        epoch: EpochId,
    },
    MemberRemoved {
        group_id: GroupId,
        member: MemberId,
        epoch: EpochId,
    },
    EpochAdvanced {
        group_id: GroupId,
        new_epoch: EpochId,
    },
    GroupCreated {
        group_id: GroupId,
        epoch: EpochId,
    },
    Joined {
        group_id: GroupId,
        epoch: EpochId,
    },
}
