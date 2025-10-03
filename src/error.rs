use chrono::{DateTime, Utc};
use nillion_nucs::{
    builder::NucTokenBuildError,
    envelope::{InvalidSignature, NucEnvelopeParseError},
};
use serde::Deserialize;

use crate::models::TxHash;

/// An error when requesting a token.
#[derive(Debug, thiserror::Error)]
pub enum RequestTokenError {
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when paying for a subscription.
#[derive(Debug, thiserror::Error)]
pub enum PaySubscriptionError {
    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    #[error("fetching subscription cost: {0}")]
    Cost(#[from] SubscriptionCostError),

    #[error("fetching subscription status: {0}")]
    Status(#[from] SubscriptionStatusError),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("making payment: {0}")]
    Payment(String),

    #[error("server could not validate payment: {tx_hash}")]
    PaymentValidation { tx_hash: TxHash, payload: String },

    #[error("cannot renew subscription before {0}")]
    CannotRenewYet(DateTime<Utc>),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when fetching the subscription status.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionStatusError {
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("signing request: {0}")]
    Signing(#[from] SigningError),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when fetching the subscription cost.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionCostError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when revoking a token.
#[derive(Debug, thiserror::Error)]
pub enum RevokeTokenError {
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    #[error("requesting token: {0}")]
    RequestToken(#[from] RequestTokenError),

    #[error("malformed token returned from nilauth: {0}")]
    MalformedAuthToken(#[from] NucEnvelopeParseError),

    #[error("invalid signatures in token returned from nilauth: {0}")]
    InvalidAuthTokenSignatures(#[from] InvalidSignature),

    #[error("authentication token must be a delegation")]
    AuthTokenNotDelegation,

    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when requesting information about a nilauth instance.
#[derive(Debug, thiserror::Error)]
pub enum AboutError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when looking up revoked tokens.
#[derive(Debug, thiserror::Error)]
pub enum LookupRevokedTokensError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when signing a request.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("payload serialization: {0}")]
    PayloadSerde(#[from] serde_json::Error),

    #[error("invalid public key")]
    InvalidPublicKey,
}

/// An error when performing a request.
#[derive(Clone, Debug, Deserialize)]
pub struct RequestError {
    /// The error message.
    pub message: String,

    /// The error code.
    pub error_code: String,
}

// implement `From<RequestError>` for a list of types.
macro_rules! impl_from_request_error {
    ($t:ty) => {
        impl From<RequestError> for $t {
            fn from(e: RequestError) -> Self {
                Self::Request(e)
            }
        }
    };
    ($t:ty, $($rest:ty),+) => {
        impl_from_request_error!($t);
        impl_from_request_error!($($rest),+);
    };
}

impl_from_request_error!(
    RequestTokenError,
    PaySubscriptionError,
    SubscriptionStatusError,
    SubscriptionCostError,
    RevokeTokenError,
    AboutError,
    LookupRevokedTokensError
);
