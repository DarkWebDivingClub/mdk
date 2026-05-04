//! Scenario traces for early cross-implementation test vectors.
//!
//! These records intentionally avoid implementation-local MLS bytes and group
//! ids. They capture the deterministic observable outcome a conforming engine
//! should produce after running the same scripted scenario.

use crate::HarnessClient;
use cgka_traits::engine::GroupEvent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTrace {
    pub name: String,
    pub observations: Vec<ClientObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientObservation {
    pub client: String,
    pub epoch: u64,
    pub member_count: usize,
    pub received_payloads: Vec<String>,
    pub removed_members: Vec<String>,
}

pub fn observe_client(label: impl Into<String>, client: &mut HarnessClient) -> ClientObservation {
    let events = client.drain_events();
    ClientObservation {
        client: label.into(),
        epoch: client.epoch().0,
        member_count: client.members().len(),
        received_payloads: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MessageReceived { payload, .. } => {
                    Some(String::from_utf8_lossy(payload).into_owned())
                }
                _ => None,
            })
            .collect(),
        removed_members: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MemberRemoved { member, .. } => {
                    Some(String::from_utf8_lossy(member.as_slice()).into_owned())
                }
                _ => None,
            })
            .collect(),
    }
}
