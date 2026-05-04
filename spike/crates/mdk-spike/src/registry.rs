use cgka_engine::{
    Capability, Feature, FeatureRegistry, FeatureSpec, RequirementLevel, TransportKind,
};

use crate::extensions::{BASIC_GROUP_DATA_EXT_TYPE, NOSTR_TRANSPORT_DATA_EXT_TYPE};

/// The spike's feature registry. Deliberately small — enough to prove the three
/// `RequirementLevel` shapes (Required / TransportRequired / Optional) all work.
pub fn default_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();

    r.register(
        Feature::BasicGroupData,
        FeatureSpec {
            requires: Capability::Extension(BASIC_GROUP_DATA_EXT_TYPE),
            requirement_level: RequirementLevel::Required,
            description: "Basic group metadata (name, description, image)",
        },
    );

    r.register(
        Feature::NostrTransportData,
        FeatureSpec {
            requires: Capability::Extension(NOSTR_TRANSPORT_DATA_EXT_TYPE),
            requirement_level: RequirementLevel::TransportRequired {
                transport: TransportKind::Nostr,
            },
            description: "Nostr relay transport metadata (nostr_group_id, relays)",
        },
    );

    r.register(
        Feature::Reactions,
        FeatureSpec {
            requires: Capability::Proposal(0xFF01),
            requirement_level: RequirementLevel::Optional,
            description: "Message reactions (declared only; not wired in spike)",
        },
    );

    // RFC 9420 self_remove proposal = wire value 0x000a. Required so every member
    // can leave the group unilaterally.
    r.register(
        Feature::SelfRemove,
        FeatureSpec {
            requires: Capability::Proposal(0x000a),
            requirement_level: RequirementLevel::Required,
            description: "Self-remove proposal (RFC 9420 draft-ietf-mls-extensions-07)",
        },
    );

    r
}
