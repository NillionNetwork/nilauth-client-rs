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
    /// Failed to fetch server information.
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    /// Failed to build the Nuc invocation token.
    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when paying for a subscription.
#[derive(Debug, thiserror::Error)]
pub enum PaySubscriptionError {
    /// Failed to build the Nuc invocation token.
    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    /// Failed to fetch server information.
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    /// Failed to fetch the subscription cost.
    #[error("fetching subscription cost: {0}")]
    Cost(#[from] SubscriptionCostError),

    /// Failed to fetch the subscription status.
    #[error("fetching subscription status: {0}")]
    Status(#[from] SubscriptionStatusError),

    /// Failed to serialize a data structure.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    /// The provided public key was invalid.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The on-chain payment transaction failed.
    #[error("making payment: {0}")]
    Payment(String),

    /// The server failed to validate the payment after multiple retries.
    #[error("server could not validate payment: {tx_hash}")]
    PaymentValidation {
        /// The transaction hash of the failed payment.
        tx_hash: TxHash,
        /// The payload used for the payment.
        payload: String,
    },

    /// The subscription cannot be renewed yet.
    #[error("cannot renew subscription before {0}")]
    CannotRenewYet(DateTime<Utc>),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when fetching the subscription status.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionStatusError {
    /// Failed to fetch server information.
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// Failed to sign the request.
    #[error("signing request: {0}")]
    Signing(#[from] SigningError),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when fetching the subscription cost.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionCostError {
    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when revoking a token.
#[derive(Debug, thiserror::Error)]
pub enum RevokeTokenError {
    /// Failed to fetch server information.
    #[error("fetching server's about: {0}")]
    About(#[from] AboutError),

    /// Failed to request an authentication token.
    #[error("requesting token: {0}")]
    RequestToken(#[from] RequestTokenError),

    /// The authentication token returned from the server was malformed.
    #[error("malformed token returned from nilauth: {0}")]
    MalformedAuthToken(#[from] NucEnvelopeParseError),

    /// The authentication token returned from the server had invalid signatures.
    #[error("invalid signatures in token returned from nilauth: {0}")]
    InvalidAuthTokenSignatures(#[from] InvalidSignature),

    /// The provided authentication token was not a delegation token.
    #[error("authentication token must be a delegation")]
    AuthTokenNotDelegation,

    /// Failed to build the Nuc invocation token.
    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when requesting information about a nilauth instance.
#[derive(Debug, thiserror::Error)]
pub enum AboutError {
    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when looking up revoked tokens.
#[derive(Debug, thiserror::Error)]
pub enum LookupRevokedTokensError {
    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The nilauth service returned an error.
    #[error("request: {0:?}")]
    Request(RequestError),
}

/// An error when signing a request.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Failed to serialize the payload for signing.
    #[error("payload serialization: {0}")]
    PayloadSerde(#[from] serde_json::Error),

    /// The provided public key was invalid.
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
