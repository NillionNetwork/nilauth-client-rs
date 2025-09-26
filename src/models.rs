use chrono::{DateTime, Utc};
use nillion_nucs::{envelope::NucTokenEnvelope, token::ProofHash};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// A nillion blind module.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlindModule {
    /// The nildb blind module.
    NilDb,

    /// The nilai blind module.
    NilAi,
}

impl Display for BlindModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilDb => write!(f, "nildb"),
            Self::NilAi => write!(f, "nilai"),
        }
    }
}

/// The arguments to a request to revoke a token.
pub struct RevokeTokenArgs {
    /// The authentication token to use as a base to derive the invocation token.
    pub auth_token: NucTokenEnvelope,

    /// The token to be revoked.
    pub revocable_token: NucTokenEnvelope,
}

/// A transaction hash.
#[derive(Clone, Debug, PartialEq)]
pub struct TxHash(pub String);

impl Display for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a nilauth server.
#[derive(Clone, Deserialize)]
pub struct About {
    /// The server's public key.
    #[serde(with = "hex::serde")]
    pub public_key: [u8; 33],
}

/// A revoked token.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RevokedToken {
    /// The token hash.
    pub token_hash: ProofHash,

    /// The timestamp at which the token was revoked.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub revoked_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct Subscription {
    /// Whether the user is actively subscribed.
    pub subscribed: bool,

    /// The details about the subscription.
    pub details: Option<SubscriptionDetails>,
}

/// The subscription information.
#[derive(Deserialize)]
pub struct SubscriptionDetails {
    /// The timestamp at which the subscription expires.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub expires_at: DateTime<Utc>,

    /// The timestamp at which the subscription can be renewed.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub renewable_at: DateTime<Utc>,
}
