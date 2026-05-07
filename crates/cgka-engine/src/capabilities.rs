//! Capability derivation from the [`FeatureRegistry`] into OpenMLS
//! [`Capabilities`] / [`RequiredCapabilitiesExtension`] shapes.
//!
//! The engine is the one place that speaks both Marmot-capability vocabulary
//! (Feature / Capability / RequirementLevel) AND OpenMLS vocabulary
//! (ExtensionType / ProposalType). This module is the translator.

use crate::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{
    Capability as CTCapability, Feature, GroupCapabilities, RequirementLevel, TransportKind,
};
use cgka_traits::error::EngineError;
use openmls::extensions::RequiredCapabilitiesExtension;
use openmls::prelude::{Capabilities, ExtensionType, ProposalType};
use openmls_traits::types::Ciphersuite;

/// Derive the per-leaf `Capabilities` this client advertises. Includes every
/// feature in the registry regardless of level — that's what "I support this"
/// means at the leaf.
pub(crate) fn leaf_capabilities(
    registry: &FeatureRegistry,
    ciphersuite: Ciphersuite,
) -> Capabilities {
    let mut ext_types: Vec<ExtensionType> = vec![
        ExtensionType::RequiredCapabilities,
        // MIP-01 requires every member to advertise marmot_group_data
        // (0xF2EE) in their leaf capabilities. The engine ALWAYS includes
        // this regardless of feature registry — it's a structural
        // requirement of the Marmot protocol, not a feature.
        crate::group_data::extension_type(),
    ];
    let mut proposal_types: Vec<ProposalType> = Vec::new();

    for (_feat, req) in registry.iter() {
        match req.requires {
            CTCapability::Extension(t) => ext_types.push(ExtensionType::Unknown(t)),
            CTCapability::Proposal(t) => proposal_types.push(ProposalType::from(t)),
        }
    }

    Capabilities::new(
        None,
        Some(&[ciphersuite]),
        Some(&ext_types),
        Some(&proposal_types),
        None,
    )
}

/// Derive the `RequiredCapabilities` extension for a new group. Includes
/// every `Required` feature + every `TransportRequired` feature whose
/// transport is listed in `active_transports`.
pub(crate) fn required_capabilities_extension(
    registry: &FeatureRegistry,
    active_transports: &[TransportKind],
) -> (GroupCapabilities, RequiredCapabilitiesExtension) {
    let mut caps = GroupCapabilities::default();
    // MIP-01 mandates marmot_group_data (0xF2EE) be in the group's
    // RequiredCapabilities. Always added.
    caps.insert(CTCapability::Extension(
        crate::group_data::MARMOT_GROUP_DATA_EXT_TYPE,
    ));
    for (_f, req) in registry.iter() {
        match &req.level {
            RequirementLevel::Required => caps.insert(req.requires),
            RequirementLevel::TransportRequired { transport }
                if active_transports.contains(transport) =>
            {
                caps.insert(req.requires);
            }
            _ => {}
        }
    }

    let ext_types: Vec<ExtensionType> = caps
        .extensions
        .iter()
        .map(|t| ExtensionType::Unknown(*t))
        .collect();
    let proposal_types: Vec<ProposalType> = caps
        .proposals
        .iter()
        .map(|t| ProposalType::from(*t))
        .collect();

    let ext = RequiredCapabilitiesExtension::new(&ext_types, &proposal_types, &[]);
    (caps, ext)
}

/// Derive RequiredCapabilities and additionally force specific caller-
/// requested features to be required for this group, even when their registry
/// level is `Optional`.
pub(crate) fn required_capabilities_extension_for_features(
    registry: &FeatureRegistry,
    active_transports: &[TransportKind],
    requested: &[Feature],
) -> Result<(GroupCapabilities, RequiredCapabilitiesExtension), EngineError> {
    let (mut caps, _) = required_capabilities_extension(registry, active_transports);
    for feature in requested {
        let req = registry
            .get(feature)
            .ok_or_else(|| EngineError::Other(format!("unknown feature {feature}")))?;
        caps.insert(req.requires);
    }
    Ok((caps.clone(), extension_from_group_capabilities(&caps)))
}

pub(crate) fn extension_from_group_capabilities(
    caps: &GroupCapabilities,
) -> RequiredCapabilitiesExtension {
    let ext_types: Vec<ExtensionType> = caps
        .extensions
        .iter()
        .map(|t| ExtensionType::Unknown(*t))
        .collect();
    let proposal_types: Vec<ProposalType> = caps
        .proposals
        .iter()
        .map(|t| ProposalType::from(*t))
        .collect();
    RequiredCapabilitiesExtension::new(&ext_types, &proposal_types, &[])
}

/// Read a KeyPackage's advertised capabilities into a Marmot
/// [`GroupCapabilities`]. Used by `constructable_capabilities` and by the
/// invite-validation path.
pub(crate) fn capabilities_of_key_package(kp: &openmls::prelude::KeyPackage) -> GroupCapabilities {
    capabilities_of_leaf(kp.leaf_node())
}

/// Read a LeafNode's advertised capabilities for constructability checks and
/// cache-on-ingest updates.
pub(crate) fn capabilities_of_leaf(leaf: &openmls::prelude::LeafNode) -> GroupCapabilities {
    let caps = leaf.capabilities();
    let mut out = GroupCapabilities::default();
    for ext in caps.extensions() {
        if let ExtensionType::Unknown(t) = ext {
            out.extensions.insert(*t);
        }
    }
    for prop in caps.proposals() {
        out.proposals.insert(u16::from(*prop));
    }
    out
}
