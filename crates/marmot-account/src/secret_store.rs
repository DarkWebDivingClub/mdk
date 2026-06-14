//! Account secret storage: the `AccountSecretStore` trait and its file- and
//! keychain-backed implementations.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::home::{ACCOUNT_SECRET_FILE, AccountSummary, LOCAL_FILE_SECRET_BACKEND};
use crate::io::{read_json, write_secret_json};
use crate::keyring::{initialize_keyring_store, map_keyring_error};

#[derive(Clone, Serialize, Deserialize)]
struct StoredAccountSecret {
    #[serde(default = "stored_secret_version")]
    version: u32,
    #[serde(default = "stored_secret_backend")]
    backend: String,
    secret_key_hex: String,
}

pub trait AccountSecretStore: Send + Sync {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool>;
    /// Whether the store already holds a credential keyed by account id.
    /// Stores that key one credential per label never share entries across
    /// records, so the default reports `false`.
    fn has_secret_for_account_id(&self, _account_id_hex: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }
    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()>;
    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys>;
    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()>;
}

#[derive(Clone, Debug)]
pub struct LocalFileSecretStore {
    root: PathBuf,
}

impl LocalFileSecretStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn secret_path(&self, label: &str) -> PathBuf {
        self.root
            .join("accounts")
            .join(label)
            .join(ACCOUNT_SECRET_FILE)
    }
}

impl AccountSecretStore for LocalFileSecretStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        Ok(self.secret_path(label).exists())
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        write_secret_json(
            self.secret_path(&account.label),
            &StoredAccountSecret {
                version: stored_secret_version(),
                backend: stored_secret_backend(),
                secret_key_hex: keys.secret_key().to_secret_hex(),
            },
        )
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        let secret: StoredAccountSecret = read_json(self.secret_path(&account.label))?;
        if secret.backend != LOCAL_FILE_SECRET_BACKEND {
            return Err(AccountHomeError::UnsupportedSecretBackend(secret.backend));
        }
        nostr::Keys::parse(&secret.secret_key_hex).map_err(|_| AccountHomeError::InvalidSecretKey)
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        let path = self.secret_path(&account.label);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeychainSecretStore {
    service_name: String,
}

impl KeychainSecretStore {
    pub fn new(service_name: impl Into<String>) -> AccountHomeResult<Self> {
        let service_name = service_name.into().trim().to_owned();
        if service_name.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        initialize_keyring_store()?;
        Ok(Self { service_name })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    fn entry_for_account(&self, account_id_hex: &str) -> AccountHomeResult<keyring_core::Entry> {
        keyring_core::Entry::new(&self.service_name, account_id_hex).map_err(map_keyring_error)
    }
}

impl AccountSecretStore for KeychainSecretStore {
    fn has_secret_for_label(&self, _label: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }

    fn has_secret_for_account_id(&self, account_id_hex: &str) -> AccountHomeResult<bool> {
        match self.entry_for_account(account_id_hex)?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        self.entry_for_account(&account.account_id_hex)?
            .set_password(&keys.secret_key().to_secret_hex())
            .map_err(map_keyring_error)
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .get_password()
        {
            Ok(secret_key) => {
                nostr::Keys::parse(&secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)
            }
            Err(keyring_core::Error::NoEntry) => Err(AccountHomeError::SecretNotFound(
                account.account_id_hex.clone(),
            )),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .delete_credential()
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_keyring_error(err)),
        }
    }
}

pub(crate) fn stored_secret_version() -> u32 {
    1
}

pub(crate) fn stored_secret_backend() -> String {
    LOCAL_FILE_SECRET_BACKEND.to_owned()
}
