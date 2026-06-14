//! KeyPackage publication: publication payload, publisher trait, and no-op impl.

use async_trait::async_trait;
use cgka_traits::MemberId;
use cgka_traits::TransportEndpoint;
use cgka_traits::engine::KeyPackage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackagePublication {
    pub account_id: MemberId,
    pub key_package: KeyPackage,
    pub endpoints: Vec<TransportEndpoint>,
}

#[derive(Debug, thiserror::Error)]
#[error("key package publication failed: {0}")]
pub struct KeyPackagePublishError(pub String);

#[async_trait]
pub trait KeyPackagePublisher: Send + Sync {
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopKeyPackagePublisher;

#[async_trait]
impl KeyPackagePublisher for NoopKeyPackagePublisher {
    async fn publish_key_package(
        &self,
        _publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        Ok(())
    }
}
