//! Client for interacting with the Nilauth service.

use async_trait::async_trait;
use nillion_nucs::{
    NucSigner,
    builder::{InvocationBuilder, NucTokenBuildError},
    did::Did,
    envelope::NucTokenEnvelope,
    k256::sha2::{Digest, Sha256},
    token::{ProofHash, TokenBody},
};
use reqwest::Response;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{iter, time::Duration};
use tokio::time::sleep;
use tracing::{info, warn};

pub use crate::{
    error::{
        AboutError, LookupRevokedTokensError, PaymentResourceError, RequestError, RequestTokenError, RevokeTokenError,
        SubscriptionCostError, SubscriptionStatusError, ValidatePaymentError,
    },
    models::{About, BlindModule, RevokeTokenArgs, RevokedToken, Subscription, SubscriptionDetails, TxHash},
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TX_RETRY_ERROR_CODE: &str = "TRANSACTION_NOT_COMMITTED";
static PAYMENT_TX_RETRIES: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(10),
    Duration::from_secs(10),
];

/// The result of creating a payment resource.
///
/// This contains the digest (hash) to be sent on-chain and the payload
/// to be used for validation after the transaction is confirmed.
#[derive(Debug, Clone)]
pub struct PaymentResource {
    /// The SHA-256 hash of the canonical JSON payload.
    /// This should be sent as the `digest` parameter to the BurnWithDigest contract.
    pub digest: [u8; 32],

    /// The payload that was hashed. This must be sent to `validate_payment`
    /// after the on-chain transaction is confirmed.
    pub payload: OnChainPaymentPayload,
}

/// An interface to interact with nilauth.
#[async_trait]
pub trait NilauthClient {
    /// Get information about the nilauth instance.
    async fn about(&self) -> Result<About, AboutError>;

    /// Get the nilauth service's public key.
    fn public_key(&self) -> [u8; 33];

    /// Get the nilauth service's DID.
    fn did(&self) -> Did;

    /// Get the configured chain ID.
    fn chain_id(&self) -> u64;

    /// Request a root Nuc for a blind module.
    ///
    /// This action must be performed by the **Subscriber**. It will fail if the
    /// subscriber's `Did` does not have an active subscription.
    async fn request_token(
        &self,
        signer: &dyn NucSigner,
        blind_module: BlindModule,
    ) -> Result<String, RequestTokenError>;

    /// Create a payment resource for a subscription.
    ///
    /// This is the first step in the decoupled payment flow. The returned `PaymentResource`
    /// contains the digest to be sent on-chain and the payload to be used for validation.
    ///
    /// # Arguments
    /// * `blind_module` - The blind module to subscribe to
    /// * `payer_did` - The DID of the identity paying for the subscription
    /// * `subscriber_did` - The DID of the identity receiving the subscription
    fn create_payment_resource(
        &self,
        blind_module: BlindModule,
        payer_did: Did,
        subscriber_did: Did,
    ) -> PaymentResource;

    /// Validate a payment transaction with the nilauth service.
    ///
    /// This is the final step in the decoupled payment flow. Call this after the
    /// on-chain BurnWithDigest transaction has been confirmed.
    ///
    /// # Arguments
    /// * `tx_hash` - The transaction hash from the on-chain payment
    /// * `payload` - The payload returned by `create_payment_resource`
    /// * `payer_signer` - The signer of the identity that paid for the subscription
    async fn validate_payment(
        &self,
        tx_hash: &str,
        payload: &OnChainPaymentPayload,
        payer_signer: &dyn NucSigner,
    ) -> Result<(), ValidatePaymentError>;

    /// Get the subscription status for a given `Did`.
    async fn subscription_status(
        &self,
        did: Did,
        blind_module: BlindModule,
    ) -> Result<Subscription, SubscriptionStatusError>;

    /// Get the cost of a subscription in unils.
    async fn subscription_cost(&self, blind_module: BlindModule) -> Result<u64, SubscriptionCostError>;

    /// Revoke a token.
    async fn revoke_token(&self, args: RevokeTokenArgs, signer: &dyn NucSigner) -> Result<(), RevokeTokenError>;

    /// Looks up which tokens in a Nuc token envelope have been revoked.
    async fn lookup_revoked_tokens(
        &self,
        envelope: &NucTokenEnvelope,
    ) -> Result<Vec<RevokedToken>, LookupRevokedTokensError>;
}

/// The default implementation of `NilauthClient` that interacts with a `nilauth` service over HTTP.
pub struct DefaultNilauthClient {
    client: reqwest::Client,
    base_url: String,
    public_key: [u8; 33],
    did: Did,
    chain_id: u64,
}

impl DefaultNilauthClient {
    /// Creates a new `DefaultNilauthClient` by fetching the service's public key.
    ///
    /// This is an async factory method that fetches the `/about` endpoint to get
    /// the service's public key, which is required for building authentication tokens.
    ///
    /// # Arguments
    /// * `base_url` - The base URL of the nilauth service
    /// * `chain_id` - The Ethereum chain ID for payment validation
    pub async fn create(base_url: impl Into<String>, chain_id: u64) -> Result<Self, AboutError> {
        let base_url = base_url.into();
        let client = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build().map_err(AboutError::Http)?;

        // Fetch the service's public key
        let url = format!("{base_url}/about");
        let response = client.get(&url).send().await.map_err(AboutError::Http)?;
        let about: About = Self::parse_response_static::<About, AboutError>(response).await?;

        Ok(Self { client, base_url, public_key: about.public_key, did: Did::key(about.public_key), chain_id })
    }

    fn make_url(&self, path: &str) -> String {
        let base_url = &self.base_url;
        format!("{base_url}{path}")
    }

    async fn parse_response_static<T, E>(response: Response) -> Result<T, E>
    where
        T: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let error: RequestError = response.json().await?;
            Err(error.into())
        }
    }

    async fn parse_response<T, E>(&self, response: Response) -> Result<T, E>
    where
        T: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        Self::parse_response_static(response).await
    }

    async fn post<R, O, E>(&self, url: &str, request: &R) -> Result<O, E>
    where
        R: Serialize,
        O: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        let response = self.client.post(url).json(&request).send().await?;
        self.parse_response(response).await
    }

    async fn get<O, E>(&self, url: &str) -> Result<O, E>
    where
        O: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        let response = self.client.get(url).send().await?;
        self.parse_response(response).await
    }
}

#[async_trait]
impl NilauthClient for DefaultNilauthClient {
    async fn about(&self) -> Result<About, AboutError> {
        let url = self.make_url("/about");
        self.get(&url).await
    }

    fn public_key(&self) -> [u8; 33] {
        self.public_key
    }

    fn did(&self) -> Did {
        self.did
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn request_token(
        &self,
        signer: &dyn NucSigner,
        blind_module: BlindModule,
    ) -> Result<String, RequestTokenError> {
        let invocation = create_identity_nuc(signer, self.did, ["nil", "auth", "nucs", "create"]).await?;

        let header_value = format!("Bearer {invocation}");
        let url = self.make_url("/api/v1/nucs/create");
        let payload = CreateNucRequest { blind_module };

        let response = self.client.post(url).json(&payload).header("Authorization", header_value).send().await?;
        let response: Result<CreateNucResponse, RequestTokenError> = self.parse_response(response).await;
        Ok(response?.token)
    }

    fn create_payment_resource(
        &self,
        blind_module: BlindModule,
        payer_did: Did,
        subscriber_did: Did,
    ) -> PaymentResource {
        let payload = OnChainPaymentPayload {
            service_public_key: self.public_key,
            nonce: rand::random(),
            blind_module,
            payer_did,
            subscriber_did,
            chain_id: self.chain_id,
        };

        // Use RFC 8785 canonical JSON serialization for consistent hashing
        let payload_bytes = serde_jcs::to_vec(&payload).expect("payload serialization should not fail");
        let digest: [u8; 32] = Sha256::digest(&payload_bytes).into();

        info!(
            "Created payment resource: payload={}, digest={}",
            String::from_utf8_lossy(&payload_bytes),
            hex::encode(digest)
        );

        PaymentResource { digest, payload }
    }

    async fn validate_payment(
        &self,
        tx_hash: &str,
        payload: &OnChainPaymentPayload,
        payer_signer: &dyn NucSigner,
    ) -> Result<(), ValidatePaymentError> {
        let url = self.make_url("/api/v1/payments/validate");
        let request = ValidatePaymentRequest { tx_hash: tx_hash.to_string(), payload: payload.clone() };

        // Authenticate the validation request with the Payer's identity Nuc.
        let invocation = create_identity_nuc(payer_signer, self.did, ["nil", "auth", "payments", "validate"]).await?;
        let auth_header = format!("Bearer {invocation}");

        for delay in PAYMENT_TX_RETRIES {
            let response = self.client.post(&url).json(&request).header("Authorization", &auth_header).send().await?;

            if response.status().is_success() {
                info!("Payment validated successfully: tx_hash={}", tx_hash);
                return Ok(());
            }

            let error: RequestError = response.json().await?;
            if error.error_code == TX_RETRY_ERROR_CODE {
                warn!("Server could not validate payment, retrying in {delay:?}: {error:?}");
                sleep(*delay).await;
            } else {
                return Err(ValidatePaymentError::Request(error));
            }
        }

        // If all retries fail, return a specific error.
        Err(ValidatePaymentError::RetriesExhausted { tx_hash: tx_hash.to_string() })
    }

    async fn subscription_status(
        &self,
        did: Did,
        blind_module: BlindModule,
    ) -> Result<Subscription, SubscriptionStatusError> {
        let url = format!("/api/v1/subscriptions/status?blind_module={blind_module}&did={did}");
        let url = self.make_url(&url);
        self.get(&url).await
    }

    async fn subscription_cost(&self, blind_module: BlindModule) -> Result<u64, SubscriptionCostError> {
        let url = format!("/api/v1/payments/cost?blind_module={blind_module}");
        let url = self.make_url(&url);
        let response: Result<GetCostResponse, SubscriptionCostError> = self.get(&url).await;
        Ok(response?.cost_unils)
    }

    async fn revoke_token(&self, args: RevokeTokenArgs, signer: &dyn NucSigner) -> Result<(), RevokeTokenError> {
        let RevokeTokenArgs { auth_token, revocable_token } = args;

        // The auth token's signatures must be validated before use.
        let auth_token = auth_token.validate_signatures()?;

        // Manually check that we are extending a delegation token, as the new
        // `InvocationBuilder` does not perform this check.
        if !matches!(auth_token.token().token().body, TokenBody::Delegation(_)) {
            return Err(RevokeTokenError::AuthTokenNotDelegation);
        }

        let token_to_revoke = revocable_token.encode();

        let invocation = InvocationBuilder::extending(auth_token)
            .subject(*signer.did())
            .audience(self.did)
            .command(["nuc", "revoke"])
            .arguments(json!({ "token": token_to_revoke }))
            .sign_and_serialize(signer)
            .await
            .map_err(|e| {
                warn!("Failed to revoke token from revocable token={:?}", e);
                RevokeTokenError::BuildInvocation(e)
            })?;

        let header_value = format!("Bearer {invocation}");
        let url = self.make_url("/api/v1/revocations/revoke");
        let response = self.client.post(url).header("Authorization", header_value).send().await?;
        self.parse_response(response).await
    }

    async fn lookup_revoked_tokens(
        &self,
        envelope: &NucTokenEnvelope,
    ) -> Result<Vec<RevokedToken>, LookupRevokedTokensError> {
        let hashes = iter::once(envelope.token()).chain(envelope.proofs()).map(|t| t.compute_hash()).collect();
        let request = LookupRevokedTokensRequest { hashes };
        let url = self.make_url("/api/v1/revocations/lookup");
        let response: Result<LookupRevokedTokensResponse, LookupRevokedTokensError> = self.post(&url, &request).await;
        Ok(response?.revoked)
    }
}

/// The request body for creating a Nuc.
#[derive(Serialize)]
struct CreateNucRequest {
    /// The blind module to create a Nuc for.
    blind_module: BlindModule,
}

/// The response body for a Nuc creation request.
#[derive(Debug, Deserialize)]
struct CreateNucResponse {
    /// The serialized root Nuc token.
    token: String,
}

/// The request body for validating a payment.
#[derive(Serialize)]
struct ValidatePaymentRequest {
    /// The on-chain transaction hash for the payment.
    tx_hash: String,
    /// The payload that was hashed and included in the on-chain transaction.
    payload: OnChainPaymentPayload,
}

/// The plaintext payload that is hashed and stored on-chain.
///
/// This payload is serialized using RFC 8785 canonical JSON and then hashed
/// with SHA-256 to produce the digest sent to the BurnWithDigest contract.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OnChainPaymentPayload {
    /// The public key of the nilauth service this payment is for.
    #[serde(with = "hex::serde")]
    pub service_public_key: [u8; 33],

    /// A random value to ensure the hash of this payload is unique.
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 16],

    /// The nillion blind module being subscribed to.
    pub blind_module: BlindModule,

    /// The user paying for the subscription.
    pub payer_did: Did,

    /// The user the subscription is for.
    pub subscriber_did: Did,

    /// The Ethereum chain ID this payment is for.
    pub chain_id: u64,
}

/// The response body for the subscription cost endpoint.
#[derive(Debug, Deserialize)]
struct GetCostResponse {
    /// The cost in unils.
    cost_unils: u64,
}

/// The request body for looking up revoked tokens.
#[derive(Serialize)]
struct LookupRevokedTokensRequest {
    /// The list of token hashes to check.
    hashes: Vec<ProofHash>,
}

/// The response body for a revoked token lookup.
#[derive(Deserialize)]
struct LookupRevokedTokensResponse {
    /// The list of tokens that were found to be revoked.
    revoked: Vec<RevokedToken>,
}

/// Creates a self-signed identity Nuc for authenticating a request.
async fn create_identity_nuc<const N: usize>(
    signer: &dyn NucSigner,
    audience: Did,
    command: [&str; N],
) -> Result<String, NucTokenBuildError> {
    InvocationBuilder::new().subject(*signer.did()).audience(audience).command(command).sign_and_serialize(signer).await
}
