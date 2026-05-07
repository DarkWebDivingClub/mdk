//! Engine construction and trait-object scaffold tests.
//!
//! Proves the engine can be built, implements `CgkaEngine`, and can be wrapped
//! in `Box<dyn CgkaEngine + Send + Sync>` without async-trait lifetime
//! regressions. Behavior-level coverage lives in the focused integration tests.

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
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_group_message(
        &self,
        _payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
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

    // Witness: this line stops compiling if async-trait lifetimes regress.
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
async fn empty_engine_methods_return_typed_results() {
    let mut engine = EngineBuilder::new(MemoryStorage::new())
        .identity(b"id".to_vec())
        .peeler(Box::new(StubPeeler))
        .build()
        .unwrap();

    // Drain methods return empty before any events are emitted.
    assert!(engine.drain_events().is_empty());
    assert!(engine.drain_auto_publish().is_empty());

    // Sending to an unknown group returns a typed error, not a panic.
    let res = engine
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: cgka_traits::GroupId::new(vec![0; 4]),
            payload: vec![],
        })
        .await;
    assert!(res.is_err());
}
