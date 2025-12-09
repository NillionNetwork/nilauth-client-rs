//! Error types for the nilauth client.

use nillion_nucs::{
    builder::NucTokenBuildError,
    envelope::{InvalidSignature, NucEnvelopeParseError},
};
use serde::Deserialize;

/// An error when requesting a token.
#[derive(Debug, thiserror::Error)]
pub enum RequestTokenError {
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

/// An error when creating a payment resource.
#[derive(Debug, thiserror::Error)]
pub enum PaymentResourceError {
    /// Failed to serialize the payload.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// An error when validating a payment.
#[derive(Debug, thiserror::Error)]
pub enum ValidatePaymentError {
    /// Failed to build the Nuc invocation token.
    #[error("building invocation: {0}")]
    BuildInvocation(#[from] NucTokenBuildError),

    /// An Http request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The server failed to validate the payment after multiple retries.
    #[error("server could not validate payment after retries: tx_hash={tx_hash}")]
    RetriesExhausted {
        /// The transaction hash of the failed payment.
        tx_hash: String,
    },

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
    ValidatePaymentError,
    SubscriptionStatusError,
    SubscriptionCostError,
    RevokeTokenError,
    AboutError,
    LookupRevokedTokensError
);
