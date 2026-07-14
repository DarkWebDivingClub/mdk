//! End-to-end test for vault-backed HPKE key management.
//!
//! Exercises the full KeyPackage-creation → group-creation → Welcome-decryption
//! path with Bob's HPKE init and encryption keys managed through a
//! [`VaultCryptoProvider`]-backed engine, while Alice uses a standard engine.

use std::sync::Arc;

use async_trait::async_trait;
use cgka_engine::canonicalization::ConvergenceStatus;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::vault_crypto::HpkeVaultBackend;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use openmls_traits::types::CryptoError;
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;
use x25519_dalek::{PublicKey, StaticSecret};

mod support;
use support::proof_signer;

// ── Test vault backend ───────────────────────────────────────────────────

/// A test vault that derives distinct X25519 keys from a seed, key type,
/// and index. Mimics a real BIP-32 vault: each `(key_type, index)` pair
/// produces a unique, deterministic key.
struct TestVault {
    seed: [u8; 32],
}

impl TestVault {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Derive a deterministic X25519 secret for the given path.
    fn secret_at(&self, key_type: &str, index: u32) -> StaticSecret {
        let mut hasher = Sha256::new();
        hasher.update(b"test-vault-v1");
        hasher.update(&self.seed);
        hasher.update(key_type.as_bytes());
        hasher.update(index.to_be_bytes());
        let derived: [u8; 32] = hasher.finalize().into();
        StaticSecret::from(derived)
    }
}

impl HpkeVaultBackend for TestVault {
    fn pubkey_at(&self, key_type: &str, index: u32) -> Result<Vec<u8>, CryptoError> {
        let sk = self.secret_at(key_type, index);
        Ok(PublicKey::from(&sk).as_bytes().to_vec())
    }

    fn dh(
        &self,
        key_type: &str,
        index: u32,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let sk = self.secret_at(key_type, index);
        let peer: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        let shared = sk.diffie_hellman(&PublicKey::from(peer));
        Ok(shared.as_bytes().to_vec())
    }
}

// ── Test helpers (mirrors invite_leave.rs patterns) ──────────────────────

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct MockPeeler;

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_standard_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_vault_client(
    id: &[u8],
    vault: Arc<dyn HpkeVaultBackend>,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .vault_backend(vault, 0, 0)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Alice (standard engine) creates a group with Bob (vault-backed engine).
/// Bob's KeyPackage init key lives in the vault. Alice encrypts the Welcome
/// to that init key. Bob decrypts via vault DH and joins successfully.
#[tokio::test]
async fn vault_backed_bob_joins_via_welcome() {
    let vault = Arc::new(TestVault::new([42u8; 32]));
    let mut alice = build_standard_client(b"vault-alice");
    let mut bob = build_vault_client(b"vault-bob", vault);

    // Bob generates a KeyPackage — init key comes from the vault.
    let bob_kp = bob.fresh_key_package().await.unwrap();

    // Alice creates a group and invites Bob.
    let (_group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "vault-test".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match &create_result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => panic!("expected GroupCreated"),
    };
    alice.confirm_published(pending).await.unwrap();

    let welcome_for_bob = match create_result {
        SendResult::GroupCreated { mut welcomes, .. } => welcomes.remove(0),
        _ => unreachable!(),
    };

    // Bob decrypts the Welcome using vault-backed HPKE — this is the
    // critical path we're testing.
    bob.join_welcome(welcome_for_bob).await.unwrap();

    // Both engines see 2 members.
    let alice_members = alice.members(&_group_id).unwrap();
    let bob_members = bob.members(&_group_id).unwrap();
    assert_eq!(alice_members.len(), 2, "alice should see 2 members");
    assert_eq!(bob_members.len(), 2, "bob should see 2 members");
}

/// Both Alice and Bob are vault-backed. Alice creates a group, Bob joins
/// via Welcome. Then Alice invites Carol (also vault-backed) as a third
/// member. This tests multiple vault-backed engines interacting.
#[tokio::test]
async fn all_vault_backed_three_member_group() {
    let alice_vault = Arc::new(TestVault::new([10u8; 32]));
    let bob_vault = Arc::new(TestVault::new([20u8; 32]));
    let carol_vault = Arc::new(TestVault::new([30u8; 32]));

    let mut alice = build_vault_client(b"v-alice", alice_vault);
    let mut bob = build_vault_client(b"v-bob", bob_vault);
    let mut carol = build_vault_client(b"v-carol", carol_vault);

    // Create alice+bob group.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "all-vault".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match &create_result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => panic!("expected GroupCreated"),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome_for_bob = match create_result {
        SendResult::GroupCreated { mut welcomes, .. } => welcomes.remove(0),
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    assert_eq!(alice.members(&group_id).unwrap().len(), 2);
    assert_eq!(bob.members(&group_id).unwrap().len(), 2);

    // Alice invites Carol.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite_result = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    let (commit_msg, carol_welcome, inv_pending) = match invite_result {
        SendResult::GroupEvolution {
            msg,
            mut welcomes,
            pending,
        } => (msg, welcomes.remove(0), pending),
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(inv_pending).await.unwrap();

    // Carol joins via vault-backed Welcome decryption.
    carol.join_welcome(carol_welcome).await.unwrap();

    // Bob ingests Alice's commit and converges.
    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit_msg
    };
    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "commit should buffer for convergence; got {outcome:?}"
    );
    let conv = bob
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence should succeed");
    assert_eq!(
        conv.convergence_status,
        ConvergenceStatus::Settled,
        "convergence should settle; errors: {:?}",
        conv.errors
    );

    // All three see 3 members.
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
    assert_eq!(
        bob.members(&group_id).unwrap().len(),
        3,
        "bob should see 3 members after convergence; epoch: {:?}, errors: {:?}",
        bob.epoch(&group_id),
        conv.errors
    );
    assert_eq!(carol.members(&group_id).unwrap().len(), 3);
}
