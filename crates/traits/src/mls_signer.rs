//! Abstraction over the MLS signing key used by `Identity`.
//!
//! Extends [`openmls_traits::signatures::Signer`] with access to the public
//! key bytes — the one thing `Identity` needs that `Signer` alone does not
//! provide.

use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

/// An MLS-compatible signer that can also expose its public key bytes.
pub trait MlsSigner: Signer + Send + Sync {
    fn public_key(&self) -> &[u8];
}

/// Blanket `Signer` impl for `Box<dyn MlsSigner>` so that a
/// `&Box<dyn MlsSigner>` satisfies `&impl Signer` (which requires `Sized`).
impl Signer for Box<dyn MlsSigner> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        (**self).sign(payload)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        (**self).signature_scheme()
    }
}
