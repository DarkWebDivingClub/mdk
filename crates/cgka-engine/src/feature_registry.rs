//! Runtime feature registry — replaces the static `SUPPORTED_PROPOSALS` /
//! `GROUP_CONTEXT_REQUIRED_PROPOSALS` constants MDK today hard-codes.
//!
//! One capability per feature, as the design doc insists
//! (`docs/marmot-architecture/further-context/cgka-engine-design.md:362-374`).

use cgka_traits::capabilities::{
    CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel, TransportKind,
};
use std::collections::HashMap;

/// Runtime-queryable feature registry. Populated at engine construction;
/// immutable thereafter.
#[derive(Default, Clone)]
pub struct FeatureRegistry {
    features: HashMap<Feature, CapabilityRequirement>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, feature: Feature, req: CapabilityRequirement) {
        self.features.insert(feature, req);
    }

    pub fn get(&self, feature: &Feature) -> Option<&CapabilityRequirement> {
        self.features.get(feature)
    }

    /// The capabilities a group needs when built with the given active
    /// transports. Equals the union of every feature's required capability
    /// whose `level` is `Required` or `TransportRequired { transport: T }`
    /// for some T in `active_transports`.
    pub fn required_for_transports(
        &self,
        active_transports: &[TransportKind],
    ) -> GroupCapabilities {
        let mut out = GroupCapabilities::default();
        for req in self.features.values() {
            match &req.level {
                RequirementLevel::Required => out.insert(req.requires),
                RequirementLevel::TransportRequired { transport }
                    if active_transports.contains(transport) =>
                {
                    out.insert(req.requires);
                }
                _ => {}
            }
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Feature, &CapabilityRequirement)> {
        self.features.iter()
    }
}
