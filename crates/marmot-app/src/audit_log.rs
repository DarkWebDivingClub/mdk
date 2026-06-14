//! Forensic audit-log feature: settings, per-account-device JSONL recorders,
//! file enumeration, HTTP upload, and audit-log path validation.
//!
//! The audit log is an opt-in, sensitive-mode forensic measure recorded per
//! account-device at `<account_dir>/audit-<engine_id>.jsonl`. This module owns
//! the audit DTOs, the stable salted-hash identity derivation, the upload
//! client, and the `MarmotApp` methods that drive recording, enumeration,
//! validation, and upload.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cgka_traits::MemberId;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;

use crate::conversions::{audit_log_settings_from_storage, audit_log_settings_to_storage};
use crate::error::AppError;
use crate::{MarmotApp, config};

const AUDIT_LOG_CONTENT_TYPE: &str = "application/x-ndjson";
const AUDIT_DEVICE_ID_FILE: &str = "audit-device-id";
pub(crate) const AUDIT_ID_BYTES: usize = 16;
const AUDIT_LOG_UPLOAD_MAX_BYTES: u64 = 64 * 1024 * 1024;
const AUDIT_LOG_UPLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUDIT_LOG_UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
static AUDIT_LOG_UPLOAD_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(AUDIT_LOG_UPLOAD_CONNECT_TIMEOUT)
        .timeout(AUDIT_LOG_UPLOAD_TIMEOUT)
        .build()
        .expect("audit log upload client configuration should be valid")
});

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogFile {
    pub account_ref: String,
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogUploadResult {
    pub path: String,
    pub status: u16,
    pub bytes_sent: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogTrackerUpdateResult {
    pub enabled: bool,
    pub uploaded: Vec<AuditLogUploadResult>,
    pub skipped_reason: Option<String>,
}

/// Outcome of deleting a single audit log file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogDeleteOutcome {
    /// `true` when a live recorder owned the file and was rotated, so a fresh
    /// file is already being recorded; `false` when the file was simply removed
    /// because no live recorder was writing it (account session closed, or
    /// audit logging off).
    pub still_recording: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditLogSettings {
    pub enabled: bool,
}

fn audit_account_ref_hex(account_id: &MemberId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-account-ref/v1");
    hasher.update(account_id.as_slice());
    let digest = hasher.finalize();
    hex::encode(&digest[..AUDIT_ID_BYTES])
}

fn audit_engine_id_hex(account_id: &MemberId, device_id_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-engine-id/v2");
    hasher.update(account_id.as_slice());
    hasher.update(device_id_hex.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..AUDIT_ID_BYTES])
}

fn parse_audit_device_id_hex(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    let bytes = hex::decode(value).map_err(|_| {
        AppError::InvalidAuditLogFile("audit device id must be hex encoded".to_owned())
    })?;
    if bytes.len() != AUDIT_ID_BYTES {
        return Err(AppError::InvalidAuditLogFile(format!(
            "audit device id must be {AUDIT_ID_BYTES} bytes"
        )));
    }
    Ok(value.to_owned())
}

fn generate_audit_device_id_hex() -> String {
    let mut bytes = [0u8; AUDIT_ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn audit_device_id_hex(account_dir: &Path) -> Result<String, AppError> {
    let path = account_dir.join(AUDIT_DEVICE_ID_FILE);
    match fs::read_to_string(&path) {
        Ok(value) => return parse_audit_device_id_hex(&value),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let device_id = generate_audit_device_id_hex();
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(device_id.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(device_id)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            parse_audit_device_id_hex(&fs::read_to_string(&path)?)
        }
        Err(err) => Err(err.into()),
    }
}

fn audit_log_file_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_string_lossy();
    (file_name.starts_with("audit-") && file_name.ends_with(".jsonl"))
        .then(|| file_name.into_owned())
}

fn system_time_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

fn validate_audit_upload_endpoint(
    endpoint: &str,
    authorization_bearer_token: Option<&str>,
) -> Result<String, AppError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(AppError::AuditLogUpload(
            "forensic upload endpoint is empty".to_owned(),
        ));
    }
    if !config::endpoint_transport_allowed(endpoint) {
        return Err(AppError::AuditLogUpload(
            "forensic upload endpoint must be https, or loopback http for local testing".to_owned(),
        ));
    }
    if !config::endpoint_host_is_loopback(endpoint)
        && authorization_bearer_token.is_none_or(|token| token.trim().is_empty())
    {
        return Err(AppError::AuditLogUpload(
            "forensic upload endpoint requires an authorization bearer token unless it is loopback"
                .to_owned(),
        ));
    }
    Ok(endpoint.to_owned())
}

fn audit_log_reqwest_error(err: reqwest::Error) -> AppError {
    if let Some(status) = err.status() {
        AppError::AuditLogUpload(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AppError::AuditLogUpload("request timed out".into())
    } else if err.is_connect() {
        AppError::AuditLogUpload("connection failed".into())
    } else if err.is_body() {
        AppError::AuditLogUpload("invalid response body".into())
    } else {
        AppError::AuditLogUpload("request failed".into())
    }
}

impl MarmotApp {
    pub fn audit_log_settings(&self) -> Result<AuditLogSettings, AppError> {
        Ok(audit_log_settings_from_storage(
            self.shared_storage()?.audit_log_settings()?,
        ))
    }

    pub fn set_audit_log_settings(
        &self,
        settings: AuditLogSettings,
    ) -> Result<AuditLogSettings, AppError> {
        self.shared_storage()?
            .set_audit_log_settings(&audit_log_settings_to_storage(settings.clone()))?;
        Ok(settings)
    }

    pub fn audit_log_files(&self) -> Result<Vec<AuditLogFile>, AppError> {
        let mut files = Vec::new();
        for account in self.account_home().accounts()? {
            let account_dir = self.account_dir(&account.label);
            if !account_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(account_dir)? {
                let entry = entry?;
                let path = entry.path();
                let Some(file_name) = audit_log_file_name(&path) else {
                    continue;
                };
                let metadata = entry.metadata()?;
                if !metadata.is_file() {
                    continue;
                }
                files.push(AuditLogFile {
                    account_ref: account.label.clone(),
                    path: path.to_string_lossy().into_owned(),
                    file_name,
                    size_bytes: metadata.len(),
                    modified_at_ms: metadata.modified().ok().and_then(system_time_ms),
                });
            }
        }
        files.sort_by(|left, right| {
            left.account_ref
                .cmp(&right.account_ref)
                .then_with(|| left.file_name.cmp(&right.file_name))
        });
        Ok(files)
    }

    pub async fn post_audit_log_file(
        &self,
        path: &str,
        endpoint: &str,
    ) -> Result<AuditLogUploadResult, AppError> {
        let config = config::AuditLogTrackerConfig {
            endpoint: Some(endpoint.to_owned()),
            ..Default::default()
        };
        self.post_audit_log_file_with_tracker_config(path, &config)
            .await
    }

    pub async fn post_audit_log_file_with_tracker_config(
        &self,
        path: &str,
        config: &config::AuditLogTrackerConfig,
    ) -> Result<AuditLogUploadResult, AppError> {
        let path = self.validate_audit_log_path(path)?;
        let config = config
            .clone()
            .normalize()
            .map_err(AppError::AuditLogUpload)?;
        let endpoint = config
            .resolved_endpoint(self.service_endpoints())
            .ok_or_else(|| AppError::AuditLogUpload("forensic upload endpoint is empty".into()))
            .and_then(|endpoint| {
                validate_audit_upload_endpoint(
                    &endpoint,
                    config.authorization_bearer_token.as_deref(),
                )
            })?;
        let file = tokio::fs::File::open(&path).await?;
        let bytes_sent = file.metadata().await?.len();
        if bytes_sent > AUDIT_LOG_UPLOAD_MAX_BYTES {
            return Err(AppError::AuditLogUpload(format!(
                "audit log exceeds {} byte upload limit",
                AUDIT_LOG_UPLOAD_MAX_BYTES
            )));
        }
        let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
        let mut request = AUDIT_LOG_UPLOAD_CLIENT
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, AUDIT_LOG_CONTENT_TYPE)
            .header(reqwest::header::CONTENT_LENGTH, bytes_sent)
            .body(body);
        if let Some(token) = config.authorization_bearer_token.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(value) = config.source.account_label.as_deref() {
            request = request.header("X-Goggles-Account-Label", value);
        }
        if let Some(value) = config.source.device_label.as_deref() {
            request = request.header("X-Goggles-Device-Label", value);
        }
        if let Some(value) = config.source.platform.as_deref() {
            request = request.header("X-Goggles-Platform", value);
        }
        if let Some(value) = config.source.app_version.as_deref() {
            request = request.header("X-Goggles-App-Version", value);
        }
        let response = request.send().await.map_err(audit_log_reqwest_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(AppError::AuditLogUpload(format!(
                "upload returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(AuditLogUploadResult {
            path: path.to_string_lossy().into_owned(),
            status: status.as_u16(),
            bytes_sent,
        })
    }

    /// Open the file-backed forensic recorder for `label`, or `None` if it
    /// could not be prepared.
    ///
    /// Best-effort and privacy-safe: every failure is logged and swallowed so
    /// callers can continue without audit logging, matching how the recorder is
    /// treated everywhere else. Shared by `open_account` (session construction)
    /// and the live audit-toggle path ([`build_audit_recorder`]).
    pub(crate) fn open_audit_recorder(
        &self,
        label: &str,
        account_id: &MemberId,
    ) -> Option<Box<dyn marmot_forensics::ForensicRecorder>> {
        let account_dir = self.account_dir(label);
        let device_id_hex = match audit_device_id_hex(&account_dir) {
            Ok(device_id_hex) => device_id_hex,
            Err(e) => {
                tracing::warn!(
                    target: "marmot_app",
                    method = "open_audit_recorder",
                    error = %e,
                    "failed to prepare forensic audit identity; continuing without it"
                );
                return None;
            }
        };
        let account_ref_hex = audit_account_ref_hex(account_id);
        let engine_id_hex = audit_engine_id_hex(account_id, &device_id_hex);
        // Canonicalize the directory so the recorder stores the same path that
        // `delete_audit_log_file` derives (it canonicalizes its input). A
        // non-canonical app root — relative, or reached through a symlinked
        // prefix like macOS `/var` -> `/private/var` — would otherwise make the
        // live-recorder match fail, so a delete would remove the visible file
        // while the recorder kept appending to the orphaned inode.
        let account_dir = fs::canonicalize(&account_dir).unwrap_or(account_dir);
        let audit_path = account_dir.join(format!("audit-{engine_id_hex}.jsonl"));
        match marmot_forensics::JsonlRecorder::open_with_account_ref(
            &audit_path,
            engine_id_hex,
            Some(account_ref_hex),
        ) {
            Ok(recorder) => Some(Box::new(recorder)),
            Err(e) => {
                tracing::warn!(
                    target: "marmot_app",
                    method = "open_audit_recorder",
                    error = %e,
                    "failed to open forensic audit log; continuing without it"
                );
                None
            }
        }
    }

    /// Build the recorder to install on a live session for the given audit
    /// switch value: a file-backed recorder when `enabled` (and openable), or a
    /// [`marmot_forensics::NoopRecorder`] when off or on failure.
    ///
    /// Used to apply an audit-setting change to an already-running session
    /// in place, without reopening it.
    pub(crate) fn build_audit_recorder(
        &self,
        label: &str,
        enabled: bool,
    ) -> Box<dyn marmot_forensics::ForensicRecorder> {
        if !enabled {
            return Box::new(marmot_forensics::NoopRecorder);
        }
        let account_id = match self.member_id(label) {
            Ok(account_id) => account_id,
            Err(e) => {
                tracing::warn!(
                    target: "marmot_app",
                    method = "build_audit_recorder",
                    error = %e,
                    "failed to resolve account identity for audit logging; continuing without it"
                );
                return Box::new(marmot_forensics::NoopRecorder);
            }
        };
        self.open_audit_recorder(label, &account_id)
            .unwrap_or_else(|| Box::new(marmot_forensics::NoopRecorder))
    }

    fn validate_audit_log_path(&self, path: &str) -> Result<PathBuf, AppError> {
        let path = path.trim();
        if path.is_empty() {
            return Err(AppError::InvalidAuditLogFile(
                "audit log path is empty".to_owned(),
            ));
        }
        let path = PathBuf::from(path);
        if audit_log_file_name(&path).is_none() {
            return Err(AppError::InvalidAuditLogFile(
                "audit log file must be named audit-*.jsonl".to_owned(),
            ));
        }
        // Refuse a symlinked final component. `canonicalize` below resolves it
        // to its target, so without this an `audit-*.jsonl` symlink could make
        // us delete (or upload) an unrelated file that merely sits under the app
        // root — e.g. the shared storage database.
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(AppError::InvalidAuditLogFile(
                "audit log file must not be a symlink".to_owned(),
            ));
        }
        let path = fs::canonicalize(path)?;
        let root = fs::canonicalize(&self.root)?;
        if !path.starts_with(&root) {
            return Err(AppError::InvalidAuditLogFile(
                "audit log file must be inside the app root".to_owned(),
            ));
        }
        // The resolved target must itself be an audit log file: defense in
        // depth against a symlinked parent component redirecting us elsewhere.
        if audit_log_file_name(&path).is_none() {
            return Err(AppError::InvalidAuditLogFile(
                "resolved audit log file must be named audit-*.jsonl".to_owned(),
            ));
        }
        Ok(path)
    }

    /// Validate `path` as an audit log file and resolve which local account
    /// owns it.
    ///
    /// Returns the canonical path plus the owning account's `account_id_hex`
    /// (the audit file lives directly in that account's directory). The owner
    /// is `None` for a valid-but-unclaimed file, e.g. one left behind by a
    /// since-removed account.
    pub(crate) fn resolve_audit_log_path(
        &self,
        path: &str,
    ) -> Result<(PathBuf, Option<String>), AppError> {
        let path = self.validate_audit_log_path(path)?;
        let mut owner_account_id_hex = None;
        for account in self.account_home().accounts()? {
            let Ok(dir) = fs::canonicalize(self.account_dir(&account.label)) else {
                continue;
            };
            if path.parent() == Some(dir.as_path()) {
                owner_account_id_hex = Some(account.account_id_hex);
                break;
            }
        }
        Ok((path, owner_account_id_hex))
    }

    /// Remove an audit log file from disk.
    ///
    /// Safe only when no live recorder holds the file open; a caller with a
    /// running account worker must rotate the live recorder instead (see
    /// `AppClient::rotate_audit_log_if_active`) so the held handle is never
    /// orphaned. A missing file is treated as success.
    pub(crate) fn remove_audit_log_file(&self, path: &Path) -> Result<(), AppError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use marmot_account::AccountHome;

    use crate::MarmotApp;

    #[test]
    fn audit_engine_id_is_stable_hash_not_raw_account_prefix() {
        let account_id = MemberId::new(vec![0xab; 32]);

        let engine_id = audit_engine_id_hex(&account_id, "01".repeat(16).as_str());

        assert_eq!(engine_id.len(), 32);
        assert_eq!(
            engine_id,
            audit_engine_id_hex(&account_id, "01".repeat(16).as_str())
        );
        assert_ne!(engine_id, hex::encode(&account_id.as_slice()[..16]));
    }

    #[test]
    fn audit_identity_hashes_separate_account_and_device_scope() {
        let account_id = MemberId::new(vec![0xab; 32]);
        let first_device = "01".repeat(16);
        let second_device = "02".repeat(16);

        let account_ref = audit_account_ref_hex(&account_id);
        let first_engine = audit_engine_id_hex(&account_id, &first_device);
        let second_engine = audit_engine_id_hex(&account_id, &second_device);

        assert_eq!(account_ref.len(), 32);
        assert_eq!(account_ref, audit_account_ref_hex(&account_id));
        assert_ne!(account_ref, hex::encode(&account_id.as_slice()[..16]));
        assert_ne!(first_engine, second_engine);
    }

    #[test]
    fn audit_device_id_is_generated_once_per_account_dir() {
        let dir = tempfile::tempdir().unwrap();

        let first = audit_device_id_hex(dir.path()).unwrap();
        let second = audit_device_id_hex(dir.path()).unwrap();

        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(AUDIT_DEVICE_ID_FILE))
                .unwrap()
                .trim(),
            first
        );
    }

    #[test]
    fn audit_log_settings_persist_in_shared_storage() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        assert_eq!(
            app.audit_log_settings().unwrap(),
            AuditLogSettings::default()
        );

        let stored = app
            .set_audit_log_settings(AuditLogSettings { enabled: true })
            .unwrap();

        assert_eq!(stored, AuditLogSettings { enabled: true });

        let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        assert_eq!(reopened.audit_log_settings().unwrap(), stored);
    }

    #[test]
    fn resolve_audit_log_path_maps_file_to_owning_account() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        let audit_path = app.account_dir("alice").join("audit-deadbeef.jsonl");
        std::fs::write(&audit_path, b"{}\n").unwrap();

        let (resolved, owner) = app
            .resolve_audit_log_path(&audit_path.to_string_lossy())
            .unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&audit_path).unwrap());
        assert_eq!(owner.as_deref(), Some(account.account_id_hex.as_str()));
    }

    #[test]
    fn resolve_audit_log_path_has_no_owner_outside_account_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        // A valid audit file directly under the app root belongs to no account.
        let orphan = dir.path().join("audit-orphan.jsonl");
        std::fs::write(&orphan, b"{}\n").unwrap();

        let (_, owner) = app
            .resolve_audit_log_path(&orphan.to_string_lossy())
            .unwrap();
        assert_eq!(owner, None);
    }

    #[test]
    fn remove_audit_log_file_deletes_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        let audit_path = app.account_dir("alice").join("audit-deadbeef.jsonl");
        std::fs::write(&audit_path, b"{}\n").unwrap();
        assert!(audit_path.exists());

        app.remove_audit_log_file(&audit_path).unwrap();
        assert!(!audit_path.exists());
        // A missing file is treated as success.
        app.remove_audit_log_file(&audit_path).unwrap();
    }

    #[test]
    fn build_audit_recorder_reflects_enabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        // Off -> no-op recorder with no file backing.
        assert!(
            app.build_audit_recorder("alice", false)
                .audit_log_path()
                .is_none()
        );

        // On -> file-backed recorder; the backing file is created in the
        // account directory so the live session records to it immediately.
        let recorder = app.build_audit_recorder("alice", true);
        let path = recorder
            .audit_log_path()
            .expect("file-backed recorder when enabled");
        assert!(path.exists());
        // The recorder stores the canonical path (see below); compare against
        // the canonical account dir.
        assert_eq!(
            path.parent(),
            Some(
                std::fs::canonicalize(app.account_dir("alice"))
                    .unwrap()
                    .as_path()
            )
        );
    }

    #[test]
    fn live_recorder_path_matches_resolved_delete_path() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        let recorder = app.build_audit_recorder("alice", true);
        let recorder_path = recorder
            .audit_log_path()
            .expect("file-backed recorder when enabled");

        // The live recorder must store the exact path that delete derives from
        // the host-supplied (dir-relative) path it gets back from
        // `audit_log_files`. If these differ — e.g. macOS `/var` vs
        // `/private/var` — the worker would not recognize the live recorder and
        // a delete would orphan its open append handle.
        let listed = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .find(|file| file.account_ref == "alice")
            .expect("audit file is listed");
        let (resolved, owner) = app.resolve_audit_log_path(&listed.path).unwrap();
        assert_eq!(resolved, recorder_path);
        assert_eq!(
            owner.as_deref(),
            Some(
                app.account_home()
                    .account("alice")
                    .unwrap()
                    .account_id_hex
                    .as_str()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_audit_log_path_rejects_symlinked_audit_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        // A sensitive non-audit file under the app root.
        let secret = app.account_dir("alice").join("shared-storage.db");
        std::fs::write(&secret, b"do-not-delete").unwrap();

        // A symlink with an audit-looking name pointing at it.
        let link = app.account_dir("alice").join("audit-evil.jsonl");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        // Resolution (and therefore delete) refuses the symlink outright, so the
        // target is never followed and never removed.
        assert!(matches!(
            app.resolve_audit_log_path(&link.to_string_lossy()),
            Err(AppError::InvalidAuditLogFile(_))
        ));
        assert!(secret.exists(), "symlink target must be untouched");
    }
}
