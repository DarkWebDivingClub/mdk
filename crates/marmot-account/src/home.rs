//! Persistent account home: local Nostr account records and signing credentials.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use std::fs;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::io::{read_json, validate_account_label, write_json};
use crate::secret_store::{AccountSecretStore, KeychainSecretStore, LocalFileSecretStore};

const ACCOUNT_RECORD_FILE: &str = "account.json";
pub(crate) const ACCOUNT_SECRET_FILE: &str = "secret.json";
pub(crate) const LOCAL_FILE_SECRET_BACKEND: &str = "local-dev-file";
pub const DEFAULT_KEYCHAIN_SERVICE_NAME: &str = "com.marmot.darkmatter";

/// Persistent home for local Nostr account records and their signing
/// credentials.
///
/// `AccountHome` is **not safe for arbitrary concurrent mutation**.
/// Methods such as [`AccountHome::create_account`] and
/// [`AccountHome::import_account`] perform check-then-act sequences over
/// the filesystem and the secret store (e.g. checking
/// [`AccountSecretStore::has_secret_for_label`] /
/// [`AccountSecretStore::has_secret_for_account_id`] before writing a
/// credential). Two callers racing those methods can both observe the
/// pre-state and both proceed, which can produce duplicate writes. The
/// duplicate-key guard in `write_signing_account_for_label` is advisory,
/// not atomic; callers needing concurrent imports must serialize
/// mutations externally.
///
/// [`AccountHome::remove_account`] is the exception: it holds an internal
/// mutation lock across its shared-credential check and the matching
/// `remove_secret` call, so concurrent `remove_account` calls on twin
/// records sharing a credential cannot both skip deletion and orphan it.
#[derive(Clone)]
pub struct AccountHome {
    root: PathBuf,
    secret_store: Arc<dyn AccountSecretStore>,
    /// Serializes mutating operations whose check-then-act sequences would
    /// otherwise race against concurrent callers. Currently held by
    /// [`AccountHome::remove_account`] to make the
    /// `secret_shared_with_other_record` check and the matching
    /// `remove_secret` call atomic, so two concurrent removals on twin
    /// records cannot both observe the other as still present and skip
    /// deleting the shared credential.
    mutation_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
}

impl AccountHome {
    pub fn open(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            secret_store: Arc::new(LocalFileSecretStore::new(&root)),
            root,
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn open_with_keychain(
        root: impl AsRef<Path>,
        service_name: impl Into<String>,
    ) -> AccountHomeResult<Self> {
        let secret_store = Arc::new(KeychainSecretStore::new(service_name)?);
        Ok(Self::open_with_secret_store(root, secret_store))
    }

    pub fn open_with_default_keychain(root: impl AsRef<Path>) -> AccountHomeResult<Self> {
        Self::open_with_keychain(root, DEFAULT_KEYCHAIN_SERVICE_NAME)
    }

    pub fn open_with_secret_store(
        root: impl AsRef<Path>,
        secret_store: Arc<dyn AccountSecretStore>,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            secret_store,
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn account_dir(&self, label: &str) -> PathBuf {
        self.accounts_dir().join(label)
    }

    pub fn create_account(&self, label: &str) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn create_nostr_account(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account(&keys)
    }

    pub fn import_account(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn import_nostr_account(&self, secret_key: &str) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account(&keys)
    }

    pub fn add_public_account(&self, public_key: &str) -> AccountHomeResult<AccountSummary> {
        let account_id_hex = Self::account_id_for_public_key(public_key)?;
        if self.account_record_path(&account_id_hex).exists() {
            return Err(AccountHomeError::AccountExists(account_id_hex));
        }
        let account = AccountSummary {
            label: account_id_hex.clone(),
            account_id_hex,
            local_signing: false,
        };
        self.write_account_record(&account)?;
        Ok(account)
    }

    pub fn account_id_for_secret(secret_key: &str) -> AccountHomeResult<String> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        Ok(keys.public_key().to_hex())
    }

    pub fn account_id_for_public_key(public_key: &str) -> AccountHomeResult<String> {
        nostr::PublicKey::parse(public_key)
            .map(|pubkey| pubkey.to_hex())
            .map_err(|_| AccountHomeError::InvalidPublicKey)
    }

    pub fn account(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        if validate_account_label(account_ref).is_ok() {
            let path = self.account_record_path(account_ref);
            if path.exists() {
                return read_json(path);
            }
        }

        let account_id = Self::account_id_for_public_key(account_ref)
            .map_err(|_| AccountHomeError::UnknownAccount(account_ref.to_owned()))?;
        let path = self.account_record_path(&account_id);
        if !path.exists() {
            return Err(AccountHomeError::UnknownAccount(account_ref.to_owned()));
        }
        read_json(path)
    }

    pub fn accounts(&self) -> AccountHomeResult<Vec<AccountSummary>> {
        let dir = self.accounts_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut accounts = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path().join(ACCOUNT_RECORD_FILE);
            if path.exists() {
                accounts.push(read_json(path)?);
            }
        }
        accounts.sort_by(|a: &AccountSummary, b| a.account_id_hex.cmp(&b.account_id_hex));
        Ok(accounts)
    }

    pub fn remove_account(&self, account_ref: &str) -> AccountHomeResult<()> {
        // Hold the mutation lock across the shared-credential check and
        // the matching `remove_secret` call so two concurrent removals on
        // twin records cannot both observe the other as still present,
        // both skip deletion, and orphan the shared credential.
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let account = self.account(account_ref)?;
        if !self.secret_shared_with_other_record(&account)? {
            self.secret_store.remove_secret(&account)?;
        }
        match fs::remove_dir_all(self.account_dir(&account.label)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Account-id-keyed stores hold one credential per account id, so records
    /// with the same account id share a single credential. The shared
    /// credential must outlive this record while another signing record still
    /// depends on it.
    ///
    /// This helper is only safe when the caller already holds
    /// `AccountHome::mutation_lock`, which serializes the check against
    /// concurrent removals on twin records. See
    /// [`AccountHome::remove_account`].
    fn secret_shared_with_other_record(&self, account: &AccountSummary) -> AccountHomeResult<bool> {
        if !self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?
        {
            return Ok(false);
        }
        Ok(self.accounts()?.iter().any(|other| {
            other.local_signing
                && other.label != account.label
                && other.account_id_hex == account.account_id_hex
        }))
    }

    pub fn load_signing_keys(&self, account_ref: &str) -> AccountHomeResult<nostr::Keys> {
        let account = self.account(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        let keys = self.secret_store.load_secret(&account)?;
        if keys.public_key().to_hex() != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(keys)
    }

    fn write_signing_account(&self, keys: &nostr::Keys) -> AccountHomeResult<AccountSummary> {
        let label = keys.public_key().to_hex();
        self.write_signing_account_for_label(&label, keys)
    }

    fn write_signing_account_for_label(
        &self,
        label: &str,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        let label = label.to_owned();
        validate_account_label(&label)?;
        if self.account_record_path(&label).exists()
            || self.secret_store.has_secret_for_label(&label)?
        {
            return Err(AccountHomeError::AccountExists(label));
        }
        let account_id_hex = keys.public_key().to_hex();
        // NOTE: this check-then-write is advisory. Concurrent callers can
        // both observe an empty store and both proceed. See the `AccountHome`
        // type-level docs; callers needing concurrent imports must serialize
        // externally.
        if self
            .secret_store
            .has_secret_for_account_id(&account_id_hex)?
        {
            return Err(AccountHomeError::AccountIdInUse(account_id_hex));
        }
        let account = AccountSummary {
            label,
            account_id_hex,
            local_signing: true,
        };
        self.secret_store.write_secret(&account, keys)?;
        if let Err(err) = self.write_account_record(&account) {
            let _ = self.secret_store.remove_secret(&account);
            return Err(err);
        }
        Ok(account)
    }

    fn write_account_record(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        validate_account_label(&account.label)?;
        write_json(self.account_record_path(&account.label), account)
    }

    fn accounts_dir(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn account_record_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_RECORD_FILE)
    }
}
