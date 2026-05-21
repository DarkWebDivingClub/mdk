use marmot_app::AppError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MarmotKitError {
    #[error("identity already exists: {account}")]
    DuplicateIdentity { account: String },
    #[error("unknown account: {account_ref}")]
    UnknownAccount { account_ref: String },
    #[error("unknown group: {group_id_hex}")]
    UnknownGroup { group_id_hex: String },
    #[error("invalid hex: {message}")]
    InvalidHex { message: String },
    #[error("invalid nostr identity: {message}")]
    InvalidIdentity { message: String },
    #[error("missing key package for {account}")]
    MissingKeyPackage { account: String },
    #[error("publish failed: {message}")]
    Publish { message: String },
    #[error("transport closed")]
    TransportClosed,
    #[error("marmot runtime error: {message}")]
    Runtime { message: String },
}

impl From<AppError> for MarmotKitError {
    fn from(value: AppError) -> Self {
        match value {
            AppError::UnknownGroup(group_id_hex) => Self::UnknownGroup { group_id_hex },
            AppError::Hex(err) => Self::InvalidHex {
                message: err.to_string(),
            },
            AppError::MissingKeyPackage(account) => Self::MissingKeyPackage { account },
            AppError::InvalidPublicKey => Self::InvalidIdentity {
                message: "invalid nostr public key".into(),
            },
            AppError::InvalidKeyPackageEvent(message) => Self::InvalidIdentity { message },
            AppError::Publish(message) => Self::Publish { message },
            AppError::TransportClosed => Self::TransportClosed,
            other => Self::Runtime {
                message: other.to_string(),
            },
        }
    }
}
