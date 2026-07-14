//! Vault-backed HPKE key operations.
//!
//! The [`HpkeVaultBackend`] trait abstracts X25519 key derivation and
//! Diffie-Hellman inside a secure boundary (hardware vault, software vault,
//! etc.). Private keys never leave the vault — only public keys and raw DH
//! results cross this interface.

use openmls_traits::types::CryptoError;

/// Backend trait for vault-backed HPKE key operations.
///
/// Implementors perform X25519 key derivation and DH inside a secure
/// element (hardware vault, software vault, etc.). Private keys never
/// leave the vault boundary.
pub trait HpkeVaultBackend: Send + Sync {
    /// Return the X25519 public key at the given derivation path.
    ///
    /// `key_type` is `"init"` or `"enc"`, and `index` is the monotonic
    /// counter value.
    fn pubkey_at(&self, key_type: &str, index: u32) -> Result<Vec<u8>, CryptoError>;

    /// Perform X25519 Diffie-Hellman at the given derivation path,
    /// returning the raw 32-byte DH output.
    ///
    /// `key_type` and `index` identify the private key.
    /// `peer_public` is the peer's X25519 public key (32 bytes).
    fn dh(&self, key_type: &str, index: u32, peer_public: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
