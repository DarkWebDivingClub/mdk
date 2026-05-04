//! Phase 4.1 smoke tests.
//!
//! Proves: the engine can be built, trait-impl'd, and wrapped in
//! `Box<dyn CgkaEngine + Send + Sync>` without hitting the spike's E0195
//! class of lifetime regressions. Real method behaviour is covered in
//! subsequent phases.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::MemberId;
use cgka_traits::{CgkaEngine, EngineError};
use storage_memory::MemoryStorage;

struct StubPeeler;

#[async_trait]
impl TransportPeeler for StubPeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("stub".into()))
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("stub".into()))
    }

    async fn wrap_group_message(
        &self,
        _payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("stub".into()))
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("stub".into()))
    }
}

#[test]
fn engine_can_be_built_and_boxed_as_trait_object() {
    let engine = EngineBuilder::new(MemoryStorage::new())
        .identity(b"self-identity".to_vec())
        .peeler(Box::new(StubPeeler))
        .build()
        .expect("build");

    // self_id is real from the start.
    assert_eq!(engine.self_id().as_slice(), b"self-identity");

    // Witness: Box<dyn CgkaEngine + Send + Sync>. If async-trait regresses
    // the spike's E0195 pattern, this line stops compiling.
    let _boxed: Box<dyn CgkaEngine + Send + Sync> = Box::new(engine);
}

#[test]
fn builder_rejects_missing_identity() {
    let res = EngineBuilder::new(MemoryStorage::new())
        .peeler(Box::new(StubPeeler))
        .build();
    assert!(matches!(res, Err(EngineError::Other(_))));
}

#[test]
fn builder_rejects_missing_peeler() {
    let res = EngineBuilder::new(MemoryStorage::new())
        .identity(b"id".to_vec())
        .build();
    assert!(matches!(res, Err(EngineError::Other(_))));
}

#[tokio::test]
async fn stubbed_methods_return_typed_not_panic() {
    let mut engine = EngineBuilder::new(MemoryStorage::new())
        .identity(b"id".to_vec())
        .peeler(Box::new(StubPeeler))
        .build()
        .unwrap();

    // drain methods return empty (not stubbed) from day one.
    assert!(engine.drain_events().is_empty());
    assert!(engine.drain_auto_publish().is_empty());

    // Stubbed methods return typed errors (no panics).
    let res = engine
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: cgka_traits::GroupId::new(vec![0; 4]),
            payload: vec![],
        })
        .await;
    assert!(res.is_err());
}
