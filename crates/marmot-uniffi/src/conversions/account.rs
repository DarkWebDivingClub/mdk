//! Account summary, send summary, key-package, and user-profile FFI conversions.

use marmot_app::{AccountKeyPackageRecord, SendSummary, UserProfileMetadata};

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub running: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SendSummaryFfi {
    pub published: u32,
    pub message_ids: Vec<String>,
}

impl From<SendSummary> for SendSummaryFfi {
    fn from(value: SendSummary) -> Self {
        Self {
            published: value.published as u32,
            message_ids: value.message_ids,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountKeyPackageFfi {
    pub account_ref: Option<String>,
    pub account_id_hex: String,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub event_id_hex: String,
    pub published_at: u64,
    pub key_package_bytes: u64,
    pub source_relays: Vec<String>,
    pub local: bool,
    pub relay: bool,
}

impl From<AccountKeyPackageRecord> for AccountKeyPackageFfi {
    fn from(value: AccountKeyPackageRecord) -> Self {
        Self {
            account_ref: value.account_label,
            account_id_hex: value.account_id_hex,
            key_package_id: value.key_package_id,
            key_package_ref_hex: value.key_package_ref_hex,
            event_id_hex: value.key_package_event_id,
            published_at: value.published_at,
            key_package_bytes: value.key_package_bytes as u64,
            source_relays: value.source_relays,
            local: value.local,
            relay: value.relay,
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct UserProfileMetadataFfi {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub nip05: Option<String>,
    pub lud16: Option<String>,
}

impl From<UserProfileMetadata> for UserProfileMetadataFfi {
    fn from(value: UserProfileMetadata) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
        }
    }
}

impl From<UserProfileMetadataFfi> for UserProfileMetadata {
    fn from(value: UserProfileMetadataFfi) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
            created_at: 0,
            source_relays: vec![],
        }
    }
}
