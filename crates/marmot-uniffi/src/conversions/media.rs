//! Media locator, attachment, upload/download, and media-record FFI conversions.

use std::collections::HashMap;

use marmot_app::{
    AppMessageRecord, MediaAttachmentReference, MediaDownloadResult, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadRequest, MediaUploadResult,
};

use super::account::SendSummaryFfi;

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaLocatorFfi {
    pub kind: String,
    pub value: String,
}

impl From<MediaLocator> for MediaLocatorFfi {
    fn from(value: MediaLocator) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

impl From<MediaLocatorFfi> for MediaLocator {
    fn from(value: MediaLocatorFfi) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaAttachmentReferenceFfi {
    pub locators: Vec<MediaLocatorFfi>,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: String,
    pub source_epoch: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaAttachmentReference> for MediaAttachmentReferenceFfi {
    fn from(value: MediaAttachmentReference) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

impl From<MediaAttachmentReferenceFfi> for MediaAttachmentReference {
    fn from(value: MediaAttachmentReferenceFfi) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentRequestFfi {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaUploadAttachmentRequestFfi> for MediaUploadAttachmentRequest {
    fn from(value: MediaUploadAttachmentRequestFfi) -> Self {
        Self {
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadRequestFfi {
    pub attachments: Vec<MediaUploadAttachmentRequestFfi>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
}

impl From<MediaUploadRequestFfi> for MediaUploadRequest {
    fn from(value: MediaUploadRequestFfi) -> Self {
        Self {
            attachments: value.attachments.into_iter().map(Into::into).collect(),
            caption: value.caption,
            send: value.send,
            blossom_server: value.blossom_server,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentResultFfi {
    pub reference: MediaAttachmentReferenceFfi,
    pub encrypted_size_bytes: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadResultFfi {
    pub attachments: Vec<MediaUploadAttachmentResultFfi>,
    pub sent: Option<SendSummaryFfi>,
}

impl From<MediaUploadResult> for MediaUploadResultFfi {
    fn from(value: MediaUploadResult) -> Self {
        Self {
            attachments: value
                .attachments
                .into_iter()
                .map(|attachment| MediaUploadAttachmentResultFfi {
                    reference: attachment.reference.into(),
                    encrypted_size_bytes: attachment.encrypted_size_bytes,
                })
                .collect(),
            sent: value.sent.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaDownloadResultFfi {
    pub plaintext: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

impl From<MediaDownloadResult> for MediaDownloadResultFfi {
    fn from(value: MediaDownloadResult) -> Self {
        Self {
            plaintext: value.plaintext,
            file_name: value.file_name,
            media_type: value.media_type,
            size_bytes: value.size_bytes,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaRecordFfi {
    pub message_id_hex: String,
    pub attachment_index: u32,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub reference: MediaAttachmentReferenceFfi,
    pub caption: Option<String>,
    pub recorded_at: u64,
    pub received_at: u64,
}

pub(crate) fn media_records_ffi(messages: Vec<AppMessageRecord>) -> Vec<MediaRecordFfi> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then_some(message.plaintext.clone());
        for (attachment_index, reference) in media_attachments_from_message(&message)
            .into_iter()
            .enumerate()
        {
            records.push(MediaRecordFfi {
                message_id_hex: message.message_id_hex.clone(),
                attachment_index: attachment_index.try_into().unwrap_or(u32::MAX),
                direction: message.direction.clone(),
                group_id_hex: message.group_id_hex.clone(),
                sender: message.sender.clone(),
                reference: reference.into(),
                caption: caption.clone(),
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            });
        }
    }
    records
}

fn media_attachments_from_message(message: &AppMessageRecord) -> Vec<MediaAttachmentReference> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| media_attachment_from_imeta_tag(tag, message.source_epoch))
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Option<MediaAttachmentReference> {
    let mut locators = Vec::new();
    let mut fields = HashMap::new();
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return None;
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest.split_once(' ')?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        if let Some((key, value)) = field.split_once(' ') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
    };
    Some(MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256")?,
        plaintext_sha256: required("plaintext_sha256")?,
        nonce_hex: required("nonce")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
        source_epoch: source_epoch.unwrap_or_default(),
        dim: fields.get("dim").cloned(),
        thumbhash: fields.get("thumbhash").cloned(),
    })
}
