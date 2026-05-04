//! Local client identity — signer + credential bundle carried by the engine.
//!
//! Generated once per engine instance. Not persisted across restarts in
//! `storage-memory`; a SQLite backend will change that.

use cgka_traits::types::MemberId;
use openmls::prelude::{BasicCredential, CredentialWithKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;

/// Bundle of everything needed to sign + identify the local client.
pub struct Identity {
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) self_id: MemberId,
}

impl Identity {
    /// Produce a fresh identity with a basic credential whose `identity`
    /// field carries `identity_bytes` (opaque — typically a stable pubkey).
    pub fn generate(ciphersuite: Ciphersuite, identity_bytes: Vec<u8>) -> Result<Self, String> {
        let scheme: SignatureScheme = ciphersuite.signature_algorithm();
        let signer = SignatureKeyPair::new(scheme).map_err(|e| format!("signer: {e}"))?;
        let credential = BasicCredential::new(identity_bytes.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            signer,
            credential_with_key,
            self_id: MemberId::new(identity_bytes),
        })
    }

    pub fn self_id(&self) -> &MemberId {
        &self.self_id
    }
}
