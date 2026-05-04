//! Capability negotiation — simplified to prove the model works across
//! transport-pluggable extensions. See capability-negotiation.md + cgka-engine-design.md.

use std::collections::{BTreeSet, HashMap};

/// Which transport a feature is tied to. Used by `RequirementLevel::TransportRequired`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TransportKind {
    Nostr,
    Fips,
}

/// One MLS primitive that a feature requires. Flat — no dependency graph.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Capability {
    /// An MLS extension type number (u16 in MLS).
    Extension(u16),
    /// An MLS proposal type number.
    Proposal(u16),
}

/// Enum-y feature registry keys. One feature ↔ one `FeatureSpec` ↔ one `Capability`.
/// The split of `NostrGroupData` into `BasicGroupData` + `NostrTransportData` is the
/// core architectural shift this spike tests.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Feature {
    // ── Basic features (transport-agnostic) ──────────────
    /// Name, description, image. Required in every group regardless of transport.
    BasicGroupData,

    // ── Transport features ───────────────────────────────
    /// Nostr relay transport. Carries nostr_group_id + relay hints.
    NostrTransportData,
    /// FIPS mesh transport (placeholder — not wired in the spike).
    FipsTransportData,

    // ── Protocol features (declared; not all implemented in spike) ──
    /// Declared to prove the `Optional` requirement level — not actually wired.
    Reactions,
    /// RFC 9420 self_remove proposal (draft-ietf-mls-extensions-07). Required —
    /// every member must be able to leave gracefully without coordinator help.
    SelfRemove,
}

#[derive(Clone, Debug)]
pub struct FeatureSpec {
    pub requires: Capability,
    pub requirement_level: RequirementLevel,
    pub description: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequirementLevel {
    /// Must be in RequiredCapabilities. New members cannot join without it.
    Required,
    /// Group uses it if universally supported by current members.
    Optional,
    /// Required if and only if a specific transport is active.
    TransportRequired { transport: TransportKind },
}

#[derive(Default, Debug, Clone)]
pub struct FeatureRegistry {
    features: HashMap<Feature, FeatureSpec>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, feature: Feature, spec: FeatureSpec) {
        self.features.insert(feature, spec);
    }

    pub fn spec(&self, feature: Feature) -> Option<&FeatureSpec> {
        self.features.get(&feature)
    }

    pub fn all(&self) -> impl Iterator<Item = (&Feature, &FeatureSpec)> {
        self.features.iter()
    }

    /// The capabilities the group MUST require given a set of active transports.
    /// (Everything `Required` + every `TransportRequired` whose transport is active.)
    pub fn required_for_transports(&self, transports: &[TransportKind]) -> GroupCapabilities {
        let mut caps = GroupCapabilities::default();
        for (_feature, spec) in self.features.iter() {
            let include = match spec.requirement_level {
                RequirementLevel::Required => true,
                RequirementLevel::TransportRequired { transport } => transports.contains(&transport),
                RequirementLevel::Optional => false,
            };
            if include {
                caps.add(spec.requires.clone());
            }
        }
        caps
    }

    /// Every capability advertised by at least one feature — used to populate the
    /// local client's KeyPackage capabilities (so we can join groups that require them).
    pub fn all_advertisable(&self) -> GroupCapabilities {
        let mut caps = GroupCapabilities::default();
        for (_, spec) in self.features.iter() {
            caps.add(spec.requires.clone());
        }
        caps
    }
}

/// The flat set of capabilities for a group or a member. Membership test only —
/// no order, no dependency graph.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct GroupCapabilities {
    extensions: BTreeSet<u16>,
    proposals: BTreeSet<u16>,
}

impl GroupCapabilities {
    pub fn add(&mut self, cap: Capability) {
        match cap {
            Capability::Extension(t) => {
                self.extensions.insert(t);
            }
            Capability::Proposal(t) => {
                self.proposals.insert(t);
            }
        }
    }

    pub fn contains(&self, cap: &Capability) -> bool {
        match cap {
            Capability::Extension(t) => self.extensions.contains(t),
            Capability::Proposal(t) => self.proposals.contains(t),
        }
    }

    pub fn extensions(&self) -> impl Iterator<Item = &u16> {
        self.extensions.iter()
    }

    pub fn proposals(&self) -> impl Iterator<Item = &u16> {
        self.proposals.iter()
    }

    /// Capabilities present in BOTH sets.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            extensions: self.extensions.intersection(&other.extensions).copied().collect(),
            proposals: self.proposals.intersection(&other.proposals).copied().collect(),
        }
    }

    /// Capabilities present in either self or other (union).
    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.extensions.extend(other.extensions.iter().copied());
        out.proposals.extend(other.proposals.iter().copied());
        out
    }

    /// Does this set cover every capability in `required`?
    pub fn covers(&self, required: &Self) -> bool {
        required.extensions.is_subset(&self.extensions)
            && required.proposals.is_subset(&self.proposals)
    }
}

/// The answer to "does this feature work in this group right now?"
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeatureStatus {
    /// Every member supports it AND it's in RequiredCapabilities.
    Available,
    /// Every member supports it but the group hasn't been upgraded to require it.
    Upgradeable,
    /// At least one member's KeyPackage doesn't advertise it.
    Unavailable {
        /// Which caps are missing from some member.
        missing: GroupCapabilities,
    },
}
