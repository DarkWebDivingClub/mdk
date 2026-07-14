//! Vault-backed HPKE crypto provider.
//!
//! [`VaultCryptoProvider`] wraps [`RustCrypto`] and intercepts two methods:
//!
//! - **`derive_hpke_keypair`** — for `InitKey` and `EncryptionKey` purposes,
//!   routes to a [`HpkeVaultBackend`] to derive keys from the vault's
//!   deterministic key tree instead of random IKM.
//!
//! - **`hpke_open`** — recognizes vault-path markers in the `sk_r` field
//!   (e.g. `b"vault:init/3"`), performs X25519 DH via the vault, and completes
//!   HPKE decapsulation using `hpke-rs::key_schedule`.
//!
//! All other methods delegate to `RustCrypto` unchanged.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use hkdf::Hkdf;
use hpke_rs_crypto::types as hpke_types;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, HpkeKeyPurpose, KemOutput, SignatureScheme,
};
use sha2::Sha256;
use tls_codec::SecretVLBytes;

pub use cgka_traits::hpke_vault::HpkeVaultBackend;

/// Vault path prefix for recognizing vault-backed private keys.
const VAULT_PREFIX: &[u8] = b"vault:";

/// HPKE crypto provider that optionally routes key operations to a vault.
///
/// When `vault` is `None`, all operations delegate to `RustCrypto`.
/// When `vault` is `Some`, `derive_hpke_keypair` for `InitKey` and
/// `EncryptionKey` purposes uses vault-derived keys, and `hpke_open`
/// recognizes vault-path markers to perform DH through the vault.
pub struct VaultCryptoProvider {
    inner: RustCrypto,
    vault: Option<Arc<dyn HpkeVaultBackend>>,
    init_counter: AtomicU32,
    enc_counter: AtomicU32,
}

impl VaultCryptoProvider {
    /// Create a provider with no vault backend (pure delegation to RustCrypto).
    pub fn new() -> Self {
        Self {
            inner: RustCrypto::default(),
            vault: None,
            init_counter: AtomicU32::new(0),
            enc_counter: AtomicU32::new(0),
        }
    }

    /// Create a provider backed by a vault.
    ///
    /// `init_index` and `enc_index` are the starting counter values for
    /// init-key and encryption-key derivation respectively.
    pub fn with_vault(
        vault: Arc<dyn HpkeVaultBackend>,
        init_index: u32,
        enc_index: u32,
    ) -> Self {
        Self {
            inner: RustCrypto::default(),
            vault: Some(vault),
            init_counter: AtomicU32::new(init_index),
            enc_counter: AtomicU32::new(enc_index),
        }
    }

    /// Access the inner `RustCrypto` provider (for `OpenMlsRand` delegation).
    pub fn rand_provider(&self) -> &RustCrypto {
        &self.inner
    }

    /// Encode a vault derivation path as opaque "private key" bytes.
    fn encode_vault_path(key_type: &str, index: u32) -> Vec<u8> {
        format!("vault:{key_type}/{index}").into_bytes()
    }

    /// Parse a vault path from opaque "private key" bytes.
    ///
    /// Returns `Some((key_type, index))` if the bytes encode a vault path,
    /// `None` otherwise.
    fn parse_vault_path(sk_r: &[u8]) -> Option<(&str, u32)> {
        if !sk_r.starts_with(VAULT_PREFIX) {
            return None;
        }
        let path = std::str::from_utf8(&sk_r[VAULT_PREFIX.len()..]).ok()?;
        let (key_type, index_str) = path.split_once('/')?;
        let index = index_str.parse::<u32>().ok()?;
        Some((key_type, index))
    }

    /// HPKE decapsulation using a vault-backed private key.
    ///
    /// Performs X25519 DH via the vault, then extract-and-expand (RFC 9180 §4.1),
    /// then hpke-rs key_schedule + AEAD decrypt.
    fn vault_hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        key_type: &str,
        index: u32,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let vault = self.vault.as_ref().ok_or(CryptoError::CryptoLibraryError)?;

        let enc = input.kem_output.as_slice();
        let ct = input.ciphertext.as_slice();

        // Step 1: DH via vault — raw X25519 output (32 bytes).
        let dh_result = vault.dh(key_type, index, enc)?;

        // Step 2: Get receiver's public key for kem_context.
        let pk_r = vault.pubkey_at(key_type, index)?;

        // Step 3: Compute kem_context = enc || pk_r (base mode, no auth).
        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);

        // Step 4: extract_and_expand(dh_result, kem_context) → shared_secret.
        let shared_secret =
            extract_and_expand(&dh_result, &kem_context, kem_suite_id(config.0));

        // Step 5: hpke-rs key_schedule → Context.
        let hpke = hpke_rs::Hpke::<HpkeRustCrypto>::new(
            hpke_rs::Mode::Base,
            kem_algorithm(config.0),
            kdf_algorithm(config.1),
            aead_algorithm(config.2),
        );
        let mut ctx = hpke
            .key_schedule(&shared_secret, info, &[], &[])
            .map_err(|_| CryptoError::HpkeDecryptionError)?;

        // Step 6: AEAD decrypt.
        ctx.open(aad, ct).map_err(|_| CryptoError::HpkeDecryptionError)
    }
}

impl Default for VaultCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ── OpenMlsCrypto delegation ──────────────────────────────────────────────

impl OpenMlsCrypto for VaultCryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.inner.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.inner.supported_ciphersuites()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(
        &self,
        alg: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner.verify_signature(alg, data, pk, signature)
    }

    fn sign(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if let Some((key_type, index)) = Self::parse_vault_path(sk_r) {
            tracing::debug!(
                target: "cgka_engine::vault_crypto",
                method = "hpke_open",
                vault_backed = true,
                key_type,
                index,
                "routing to vault"
            );
            self.vault_hpke_open(config, input, key_type, index, info, aad)
        } else {
            self.inner.hpke_open(config, input, sk_r, info, aad)
        }
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.inner
            .hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner
            .hpke_setup_receiver_and_export(config, enc, sk_r, info, exporter_context, exporter_length)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
        purpose: HpkeKeyPurpose,
    ) -> Result<HpkeKeyPair, CryptoError> {
        match (&self.vault, purpose) {
            (Some(vault), HpkeKeyPurpose::InitKey) => {
                let index = self.init_counter.fetch_add(1, Ordering::Relaxed);
                let public = vault.pubkey_at("init", index)?;
                let private = Self::encode_vault_path("init", index);
                tracing::debug!(
                    target: "cgka_engine::vault_crypto",
                    method = "derive_hpke_keypair",
                    purpose = "init_key",
                    index,
                    "vault-backed key derived"
                );
                Ok(HpkeKeyPair {
                    private: private.into(),
                    public,
                })
            }
            (Some(vault), HpkeKeyPurpose::EncryptionKey) => {
                let index = self.enc_counter.fetch_add(1, Ordering::Relaxed);
                let public = vault.pubkey_at("enc", index)?;
                let private = Self::encode_vault_path("enc", index);
                tracing::debug!(
                    target: "cgka_engine::vault_crypto",
                    method = "derive_hpke_keypair",
                    purpose = "encryption_key",
                    index,
                    "vault-backed key derived"
                );
                Ok(HpkeKeyPair {
                    private: private.into(),
                    public,
                })
            }
            _ => {
                // PathSecret, ExternalPub, or no vault — delegate.
                self.inner.derive_hpke_keypair(config, ikm, purpose)
            }
        }
    }
}

// ── OpenMlsRand delegation ───────────────────────────────────────────────

impl OpenMlsRand for VaultCryptoProvider {
    type Error = <RustCrypto as OpenMlsRand>::Error;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.inner.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.inner.random_vec(len)
    }
}

// ── HPKE helper functions ────────────────────────────────────────────────

/// RFC 9180 §4.1 ExtractAndExpand — converts a raw DH output into
/// the KEM shared secret.
///
/// ```text
/// def ExtractAndExpand(dh, kem_context):
///   suite_id = concat("KEM", I2OSP(kem_id, 2))
///   prk = LabeledExtract("", "eae_prk", dh, suite_id)
///   shared_secret = LabeledExpand(prk, "shared_secret", kem_context, Nsecret, suite_id)
///   return shared_secret
/// ```
fn extract_and_expand(dh: &[u8], kem_context: &[u8], suite_id: &[u8]) -> Vec<u8> {
    // LabeledExtract("", "eae_prk", dh)
    //   = Extract("", concat("HPKE-v1", suite_id, "eae_prk", dh))
    let mut labeled_ikm = Vec::new();
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(b"eae_prk");
    labeled_ikm.extend_from_slice(dh);

    let hkdf = Hkdf::<Sha256>::new(Some(&[]), &labeled_ikm);

    // LabeledExpand(prk, "shared_secret", kem_context, Nsecret=32)
    //   = Expand(prk, concat(I2OSP(Nsecret, 2), "HPKE-v1", suite_id, "shared_secret", kem_context), 32)
    let nsecret: u16 = 32;
    let mut labeled_info = Vec::new();
    labeled_info.extend_from_slice(&nsecret.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(b"shared_secret");
    labeled_info.extend_from_slice(kem_context);

    let mut shared_secret = vec![0u8; 32];
    hkdf.expand(&labeled_info, &mut shared_secret)
        .expect("HKDF-Expand for 32 bytes should not fail");
    shared_secret
}

/// KEM suite_id = "KEM" || I2OSP(kem_id, 2)
fn kem_suite_id(kem: HpkeKemType) -> &'static [u8] {
    match kem {
        HpkeKemType::DhKem25519 => b"KEM\x00\x20",
        HpkeKemType::DhKemP256 => b"KEM\x00\x10",
        HpkeKemType::DhKemP384 => b"KEM\x00\x11",
        HpkeKemType::DhKemP521 => b"KEM\x00\x12",
        HpkeKemType::DhKem448 => b"KEM\x00\x21",
        HpkeKemType::XWingKemDraft6 => b"KEM\x00\x4D",
    }
}

/// Map openmls HpkeKemType to hpke-rs KemAlgorithm.
fn kem_algorithm(kem: HpkeKemType) -> hpke_types::KemAlgorithm {
    match kem {
        HpkeKemType::DhKemP256 => hpke_types::KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => hpke_types::KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => hpke_types::KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => hpke_types::KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => hpke_types::KemAlgorithm::DhKem448,
        HpkeKemType::XWingKemDraft6 => {
            unimplemented!("XWingKemDraft6 is not supported for vault-backed HPKE")
        }
    }
}

/// Map openmls HpkeKdfType to hpke-rs KdfAlgorithm.
fn kdf_algorithm(kdf: HpkeKdfType) -> hpke_types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_types::KdfAlgorithm::HkdfSha512,
    }
}

/// Map openmls HpkeAeadType to hpke-rs AeadAlgorithm.
fn aead_algorithm(aead: HpkeAeadType) -> hpke_types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => hpke_types::AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke_types::AeadAlgorithm::HpkeExport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// A test vault backend backed by a single known X25519 static secret.
    /// Stores the secret for key_type="init", index=0.
    struct TestVault {
        secret: StaticSecret,
    }

    impl TestVault {
        fn new(secret_bytes: [u8; 32]) -> Self {
            Self {
                secret: StaticSecret::from(secret_bytes),
            }
        }

        fn public_key(&self) -> PublicKey {
            PublicKey::from(&self.secret)
        }
    }

    impl HpkeVaultBackend for TestVault {
        fn pubkey_at(&self, _key_type: &str, _index: u32) -> Result<Vec<u8>, CryptoError> {
            Ok(self.public_key().as_bytes().to_vec())
        }

        fn dh(
            &self,
            _key_type: &str,
            _index: u32,
            peer_public: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            let peer: [u8; 32] = peer_public
                .try_into()
                .map_err(|_| CryptoError::CryptoLibraryError)?;
            let peer_pk = PublicKey::from(peer);
            let shared = self.secret.diffie_hellman(&peer_pk);
            Ok(shared.as_bytes().to_vec())
        }
    }

    /// End-to-end test: hpke_seal (standard RustCrypto) → vault_hpke_open.
    ///
    /// Simulates Alice encrypting to Bob's vault-backed init key, then
    /// Bob decrypting via the vault. This is the exact Welcome flow.
    #[test]
    fn hpke_seal_then_vault_open_roundtrip() {
        let ciphersuite =
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let config = ciphersuite.hpke_config();

        // Bob's vault with a deterministic secret.
        let bob_secret = [42u8; 32];
        let vault = Arc::new(TestVault::new(bob_secret));
        let bob_pk = vault.public_key().as_bytes().to_vec();

        // Alice seals to Bob's public key (standard RustCrypto path).
        let inner = RustCrypto::default();
        let info = b"test info";
        let aad = b"test aad";
        let plaintext = b"hello from Alice";

        let ct = inner
            .hpke_seal(config, &bob_pk, info, aad, plaintext)
            .expect("seal should succeed");

        // Bob decrypts via vault.
        let config = ciphersuite.hpke_config();
        let provider = VaultCryptoProvider::with_vault(vault, 0, 0);
        let sk_r = VaultCryptoProvider::encode_vault_path("init", 0);

        let recovered = provider
            .hpke_open(config, &ct, &sk_r, info, aad)
            .expect("vault hpke_open should succeed");

        assert_eq!(recovered, plaintext);
    }

    /// Compare our extract_and_expand against hpke-rs's internal decap.
    ///
    /// Uses hpke-rs `open()` with the raw private key to get the expected
    /// plaintext, then compares intermediate values.
    #[test]
    fn extract_and_expand_matches_hpke_rs() {
        let cs = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

        // Generate a keypair via RustCrypto so we have real raw private key bytes.
        let inner = RustCrypto::default();
        let kp = inner
            .derive_hpke_keypair(cs.hpke_config(), &[0u8; 32], HpkeKeyPurpose::InitKey)
            .unwrap();
        let pk_r = &kp.public;
        let sk_r_raw: &[u8] = &kp.private;

        // Seal.
        let info = b"test";
        let aad = b"";
        let ptxt = b"hello";
        let ct = inner
            .hpke_seal(cs.hpke_config(), pk_r, info, aad, ptxt)
            .unwrap();

        // Standard RustCrypto open should work.
        let recovered = inner
            .hpke_open(cs.hpke_config(), &ct, sk_r_raw, info, aad)
            .expect("standard open should work");
        assert_eq!(recovered, ptxt);

        // Now do it manually: DH + extract_and_expand + key_schedule.
        let enc = ct.kem_output.as_slice();

        // DH using x25519-dalek with the raw private key.
        let sk_bytes: [u8; 32] = sk_r_raw.try_into().unwrap();
        let sk = StaticSecret::from(sk_bytes);
        let enc_arr: [u8; 32] = enc.try_into().unwrap();
        let enc_pk = PublicKey::from(enc_arr);
        let dh_result = sk.diffie_hellman(&enc_pk);

        // pk_r for kem_context.
        let pk_r_for_ctx = PublicKey::from(&sk).to_bytes();
        assert_eq!(pk_r_for_ctx.as_slice(), pk_r.as_slice(), "pk_r derivation mismatch");

        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r_for_ctx);

        let hpke_config = cs.hpke_config();
        let shared_secret = extract_and_expand(
            dh_result.as_bytes(),
            &kem_context,
            kem_suite_id(hpke_config.0),
        );

        let hpke_config2 = cs.hpke_config();
        let hpke = hpke_rs::Hpke::<HpkeRustCrypto>::new(
            hpke_rs::Mode::Base,
            kem_algorithm(hpke_config2.0),
            kdf_algorithm(hpke_config2.1),
            aead_algorithm(hpke_config2.2),
        );
        let mut ctx = hpke
            .key_schedule(&shared_secret, info, &[], &[])
            .expect("key_schedule should succeed");
        let manual_recovered = ctx
            .open(aad, ct.ciphertext.as_slice())
            .expect("manual open should succeed");
        assert_eq!(manual_recovered, ptxt);
    }

    /// Verify that vault DH matches x25519-dalek's DH for the same keys.
    #[test]
    fn vault_dh_matches_dalek() {
        let bob_secret_bytes = [42u8; 32];
        let vault = TestVault::new(bob_secret_bytes);
        let bob_sk = StaticSecret::from(bob_secret_bytes);

        // Simulate Alice's ephemeral key.
        let alice_secret = StaticSecret::from([99u8; 32]);
        let alice_pk = PublicKey::from(&alice_secret);

        // DH via vault.
        let vault_dh = vault
            .dh("init", 0, alice_pk.as_bytes())
            .expect("vault dh should succeed");

        // DH via dalek directly.
        let dalek_dh = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(vault_dh, dalek_dh.as_bytes().to_vec());
    }

    #[test]
    fn parse_vault_path_valid() {
        assert_eq!(
            VaultCryptoProvider::parse_vault_path(b"vault:init/3"),
            Some(("init", 3))
        );
        assert_eq!(
            VaultCryptoProvider::parse_vault_path(b"vault:enc/42"),
            Some(("enc", 42))
        );
    }

    #[test]
    fn parse_vault_path_invalid() {
        assert_eq!(VaultCryptoProvider::parse_vault_path(b"notavault"), None);
        assert_eq!(VaultCryptoProvider::parse_vault_path(b"vault:"), None);
        assert_eq!(VaultCryptoProvider::parse_vault_path(b"vault:init"), None);
        assert_eq!(
            VaultCryptoProvider::parse_vault_path(b"vault:init/abc"),
            None
        );
    }

    #[test]
    fn encode_vault_path_roundtrip() {
        let encoded = VaultCryptoProvider::encode_vault_path("init", 7);
        let (key_type, index) = VaultCryptoProvider::parse_vault_path(&encoded).unwrap();
        assert_eq!(key_type, "init");
        assert_eq!(index, 7);
    }

    #[test]
    fn no_vault_delegates_to_rustcrypto() {
        let provider = VaultCryptoProvider::new();
        let ciphersuite =
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let ikm = [0u8; 32];
        // With no vault, all purposes delegate to RustCrypto.
        let kp = provider
            .derive_hpke_keypair(
                ciphersuite.hpke_config(),
                &ikm,
                HpkeKeyPurpose::InitKey,
            )
            .expect("derive should succeed");
        // The private key should be actual key bytes, not a vault path.
        assert!(!kp.private.starts_with(VAULT_PREFIX));
    }
}
