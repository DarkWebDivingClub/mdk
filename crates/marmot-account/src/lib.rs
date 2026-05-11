//! Thin account-device orchestration for Marmot.
//!
//! This crate is intentionally small. It owns the app-level coordination that
//! sits above `AccountDeviceSession`: transport account activation, transport
//! routing, KeyPackage publication, and publish confirmation or rollback.

use std::collections::{HashMap, VecDeque};

use async_trait::async_trait;
use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, QueuedIntentRef,
    SessionEffects, SessionError,
};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, Timestamp, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportDelivery, TransportEndpoint, TransportGroupSubscription,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};

const TRACE_TARGET: &str = "marmot_account::runtime";

pub type AccountResult<T> = Result<T, AccountError>;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Transport(#[from] TransportAdapterError),
    #[error(transparent)]
    TransportRouting(#[from] TransportRoutingError),
    #[error(transparent)]
    KeyPackage(#[from] KeyPackagePublishError),
    #[error("transport delivery was addressed to a different account")]
    WrongAccountDelivery,
}

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

pub trait TransportRoutingPolicy: Send + Sync {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint>;
    fn key_package_endpoints(&self) -> Vec<TransportEndpoint>;
    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription>;
    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError>;
    fn required_acks(&self, target: &TransportPublishTarget) -> usize;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportRoutingError {
    #[error("missing inbox route for recipient")]
    MissingInboxRoute,
    #[error("missing group route for transport group id")]
    MissingGroupRoute,
}

#[derive(Clone, Debug)]
pub struct StaticTransportRouting {
    local_inbox_endpoints: Vec<TransportEndpoint>,
    key_package_endpoints: Vec<TransportEndpoint>,
    inbox_routes: HashMap<MemberId, Vec<TransportEndpoint>>,
    group_routes: Vec<TransportGroupSubscription>,
    required_acks: usize,
}

impl StaticTransportRouting {
    pub fn new(local_inbox_endpoints: Vec<TransportEndpoint>) -> Self {
        Self {
            key_package_endpoints: local_inbox_endpoints.clone(),
            local_inbox_endpoints,
            inbox_routes: HashMap::new(),
            group_routes: Vec::new(),
            required_acks: 1,
        }
    }

    pub fn key_package_endpoints(mut self, endpoints: Vec<TransportEndpoint>) -> Self {
        self.key_package_endpoints = endpoints;
        self
    }

    pub fn required_acks(mut self, required_acks: usize) -> Self {
        self.required_acks = required_acks;
        self
    }

    pub fn with_inbox_route(
        mut self,
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.inbox_routes.insert(account_id, endpoints);
        self
    }

    pub fn with_group_route(
        mut self,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.group_routes.push(TransportGroupSubscription {
            group_id,
            transport_group_id,
            endpoints,
        });
        self
    }
}

impl TransportRoutingPolicy for StaticTransportRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        self.local_inbox_endpoints.clone()
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        self.key_package_endpoints.clone()
    }

    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription> {
        self.group_routes.clone()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        match &message.envelope {
            TransportEnvelope::Welcome { recipient } => {
                let endpoints = self
                    .inbox_routes
                    .get(recipient)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingInboxRoute)?;
                Ok(TransportPublishTarget::Inbox {
                    recipient: recipient.clone(),
                    endpoints,
                })
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                let route = self
                    .group_routes
                    .iter()
                    .find(|route| route.transport_group_id == *transport_group_id)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingGroupRoute)?;
                Ok(TransportPublishTarget::Group {
                    group_id: route.group_id,
                    transport_group_id: route.transport_group_id,
                    endpoints: route.endpoints,
                })
            }
        }
    }

    fn required_acks(&self, _target: &TransportPublishTarget) -> usize {
        self.required_acks
    }
}

pub struct AccountDeviceRuntime<A, R = StaticTransportRouting, K = NoopKeyPackagePublisher> {
    session: AccountDeviceSession,
    adapter: A,
    routing: R,
    key_packages: K,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        Self {
            session,
            adapter,
            routing,
            key_packages,
        }
    }

    pub fn session(&self) -> &AccountDeviceSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut AccountDeviceSession {
        &mut self.session
    }

    pub async fn activate_transport(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "activate_transport",
            inbox_endpoint_count = self.routing.local_inbox_endpoints().len(),
            group_subscription_count = self.routing.group_subscriptions().len(),
            "activating account transport"
        );
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: self.session.self_id(),
                inbox_endpoints: self.routing.local_inbox_endpoints(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn sync_transport_groups(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "sync_transport_groups",
            group_subscription_count = self.routing.group_subscriptions().len(),
            "syncing account group subscriptions"
        );
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: self.session.self_id(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        let key_package = self.session.fresh_key_package().await?;
        self.key_packages
            .publish_key_package(KeyPackagePublication {
                account_id: self.session.self_id(),
                key_package: key_package.clone(),
                endpoints: self.routing.key_package_endpoints(),
            })
            .await?;
        Ok(key_package)
    }

    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok((group_id, effects))
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.send(intent).await?;
        self.publish_session_effects(effects).await
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let IngestEffects { outcome, effects } = self.session.ingest(delivery.message).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok(AccountIngestEffects { outcome, effects })
    }

    pub async fn publish_session_effects(
        &mut self,
        effects: SessionEffects,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(effects, &mut queue);

        while let Some(work) = queue.pop_front() {
            match work {
                PublishWork::ApplicationMessage { msg } | PublishWork::Proposal { msg } => {
                    self.publish_one(msg, &mut output).await?;
                }
                PublishWork::GroupCreated { welcomes, pending } => {
                    self.publish_pending(welcomes, pending, &mut output, &mut queue)
                        .await?;
                }
                PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                } => {
                    let mut messages = Vec::with_capacity(1 + welcomes.len());
                    messages.push(msg);
                    messages.extend(welcomes);
                    self.publish_pending(messages, pending, &mut output, &mut queue)
                        .await?;
                }
                PublishWork::AutoPublish { msg, pending } => {
                    self.publish_pending(vec![msg], pending, &mut output, &mut queue)
                        .await?;
                }
            }
        }

        Ok(output)
    }

    async fn publish_pending(
        &mut self,
        messages: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        let mut all_published = true;
        for message in messages {
            all_published &= self.publish_one(message, output).await?;
        }

        if all_published {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_one(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<bool> {
        let message_id = message.id.clone();
        let target = match self.routing.publish_target(&message) {
            Ok(target) => target,
            Err(e) => {
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(false);
            }
        };
        let required_acks = self.routing.required_acks(&target);
        let report = match self
            .adapter
            .publish(TransportPublishRequest {
                account_id: self.session.self_id(),
                message,
                target,
                required_acks,
            })
            .await
        {
            Ok(report) => report,
            Err(e) => {
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(false);
            }
        };
        let published = report.met_required_acks();
        if !published {
            output.failures.push(PublishFailure {
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        output.reports.push(report);
        Ok(published)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeviceEffects {
    pub events: Vec<GroupEvent>,
    pub queued: Vec<QueuedIntentRef>,
    pub reports: Vec<TransportPublishReport>,
    pub failures: Vec<PublishFailure>,
    pub pending: Vec<PendingResolution>,
}

impl AccountDeviceEffects {
    fn absorb_session_effects(
        &mut self,
        effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
    ) {
        self.events.extend(effects.events);
        self.queued.extend(effects.queued);
        queue.extend(effects.publish);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    pub effects: AccountDeviceEffects,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}
