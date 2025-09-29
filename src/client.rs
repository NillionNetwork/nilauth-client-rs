use async_trait::async_trait;
use chrono::Utc;
use nilchain_client::{client::NillionChainClient, transactions::TokenAmount};
use nillion_nucs::{
    DidMethod, Keypair,
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
        AboutError, LookupRevokedTokensError, PaySubscriptionError, RequestError, RequestTokenError, RevokeTokenError,
        SigningError, SubscriptionCostError, SubscriptionStatusError,
    },
    models::{About, BlindModule, RevokeTokenArgs, RevokedToken, Subscription, TxHash},
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

/// An interface to interact with nilauth.
#[async_trait]
pub trait NilauthClient {
    /// Get information about the nilauth instance.
    async fn about(&self) -> Result<About, AboutError>;

    /// Request a token for the given private key.
    async fn request_token(&self, keypair: &Keypair, blind_module: BlindModule) -> Result<String, RequestTokenError>;

    /// Pay for a subscription.
    async fn pay_subscription(
        &self,
        payments_client: &mut NillionChainClient,
        blind_module: BlindModule,
        payer_keypair: &Keypair,
        subscriber_did: Did,
    ) -> Result<TxHash, PaySubscriptionError>;

    /// Get our subscription status.
    async fn subscription_status(
        &self,
        did: Did,
        blind_module: BlindModule,
    ) -> Result<Subscription, SubscriptionStatusError>;

    /// Get the cost of a subscription.
    async fn subscription_cost(&self, blind_module: BlindModule) -> Result<TokenAmount, SubscriptionCostError>;

    /// Revoke a token.
    async fn revoke_token(&self, args: RevokeTokenArgs, keypair: &Keypair) -> Result<(), RevokeTokenError>;

    /// Lookup whether a token is revoked.
    async fn lookup_revoked_tokens(
        &self,
        envelope: &NucTokenEnvelope,
    ) -> Result<Vec<RevokedToken>, LookupRevokedTokensError>;
}

/// The default nilauth client that hits the actual service.
pub struct DefaultNilauthClient {
    client: reqwest::Client,
    base_url: String,
}

impl DefaultNilauthClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build()?;
        Ok(Self { client, base_url: base_url.into() })
    }

    fn make_url(&self, path: &str) -> String {
        let base_url = &self.base_url;
        format!("{base_url}{path}")
    }

    async fn parse_response<T, E>(response: Response) -> Result<T, E>
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

    async fn post<R, O, E>(&self, url: &str, request: &R) -> Result<O, E>
    where
        R: Serialize,
        O: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        let response = self.client.post(url).json(&request).send().await?;
        Self::parse_response(response).await
    }

    async fn get<O, E>(&self, url: &str) -> Result<O, E>
    where
        O: DeserializeOwned,
        E: From<reqwest::Error> + From<RequestError>,
    {
        let response = self.client.get(url).send().await?;
        Self::parse_response(response).await
    }
}

#[async_trait]
impl NilauthClient for DefaultNilauthClient {
    async fn about(&self) -> Result<About, AboutError> {
        let url = self.make_url("/about");
        self.get(&url).await
    }

    async fn request_token(&self, keypair: &Keypair, blind_module: BlindModule) -> Result<String, RequestTokenError> {
        let about = self.about().await?;

        let invocation = create_identity_nuc(keypair, Did::key(about.public_key), ["nuc", "create"]).await?;

        let header_value = format!("Bearer {invocation}");
        let url = self.make_url("/api/v1/nucs/create");
        let payload = CreateNucRequest { blind_module };

        let response = self.client.post(url).json(&payload).header("Authorization", header_value).send().await?;
        let response: Result<CreateNucResponse, RequestTokenError> = Self::parse_response(response).await;
        Ok(response?.token)
    }

    async fn pay_subscription(
        &self,
        payments_client: &mut NillionChainClient,
        blind_module: BlindModule,
        payer_keypair: &Keypair,
        subscriber_did: Did,
    ) -> Result<TxHash, PaySubscriptionError> {
        let subscription = self.subscription_status(subscriber_did, blind_module).await?;
        if let Some(details) = subscription.details
            && details.renewable_at > Utc::now()
        {
            return Err(PaySubscriptionError::CannotRenewYet(details.renewable_at));
        }

        let about = self.about().await?;
        let cost = self.subscription_cost(blind_module).await?;
        let payload = OnChainPaymentPayload {
            service_public_key: about.public_key,
            nonce: rand::random(),
            blind_module,
            payer_did: payer_keypair.to_did(DidMethod::Key),
            subscriber_did,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let hash = Sha256::digest(&payload_bytes);
        info!("Making payment using payload={}, digest={}", String::from_utf8_lossy(&payload_bytes), hex::encode(hash));

        let tx_hash_str = payments_client
            .pay_for_resource(cost, hash.to_vec())
            .await
            .map_err(|e| PaySubscriptionError::Payment(e.to_string()))?;

        let url = self.make_url("/api/v1/payments/validate");
        let request = ValidatePaymentRequest { tx_hash: tx_hash_str.clone(), payload };
        let tx_hash = TxHash(tx_hash_str);

        // Authenticate the validation request with the Payer's identity NUC.
        let invocation =
            create_identity_nuc(payer_keypair, Did::key(about.public_key), ["payments", "validate"]).await?;
        let auth_header = format!("Bearer {invocation}");

        for delay in PAYMENT_TX_RETRIES {
            let response = self.client.post(&url).json(&request).header("Authorization", &auth_header).send().await?;

            if response.status().is_success() {
                return Ok(tx_hash);
            }

            let error: RequestError = response.json().await?;
            if error.error_code == TX_RETRY_ERROR_CODE {
                warn!("Server could not validate payment, retrying in {delay:?}: {error:?}");
                sleep(*delay).await;
            } else {
                return Err(PaySubscriptionError::Request(error));
            }
        }

        // If all retries fail, return a specific error.
        Err(PaySubscriptionError::PaymentValidation {
            tx_hash,
            payload: String::from_utf8_lossy(&payload_bytes).to_string(),
        })
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

    async fn subscription_cost(&self, blind_module: BlindModule) -> Result<TokenAmount, SubscriptionCostError> {
        let url = format!("/api/v1/payments/cost?blind_module={blind_module}");
        let url = self.make_url(&url);
        let response: Result<GetCostResponse, SubscriptionCostError> = self.get(&url).await;
        Ok(TokenAmount::Unil(response?.cost_unils))
    }

    async fn revoke_token(&self, args: RevokeTokenArgs, keypair: &Keypair) -> Result<(), RevokeTokenError> {
        let about = self.about().await?;
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
            .subject(keypair.to_did(DidMethod::Key))
            .audience(Did::key(about.public_key))
            .command(["nuc", "revoke"])
            .arguments(json!({ "token": token_to_revoke }))
            .sign_and_serialize(&keypair.signer(DidMethod::Key))
            .await
            .map_err(|e| {
                warn!("Failed to revoke token from revocable token={:?}", e);
                RevokeTokenError::BuildInvocation(e)
            })?;

        let header_value = format!("Bearer {invocation}");
        let url = self.make_url("/api/v1/revocations/revoke");
        let response = self.client.post(url).header("Authorization", header_value).send().await?;
        Self::parse_response(response).await
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

#[derive(Serialize)]
struct CreateNucRequest {
    blind_module: BlindModule,
}

#[derive(Debug, Deserialize)]
struct CreateNucResponse {
    token: String,
}

#[derive(Serialize)]
struct ValidatePaymentRequest {
    tx_hash: String,
    payload: OnChainPaymentPayload,
}

/// The plaintext payload that is hashed and stored on-chain.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct OnChainPaymentPayload {
    /// The public key of the nilauth service this payment is for.
    #[serde(with = "hex::serde")]
    service_public_key: [u8; 33],
    /// A random value to ensure the hash of this payload is unique
    #[serde(with = "hex::serde")]
    nonce: [u8; 16],
    /// The nillion blind module being subscribe to.
    blind_module: BlindModule,
    /// The user paying for the subscription.
    payer_did: Did,
    /// The user the subscription is for.
    subscriber_did: Did,
}

#[derive(Debug, Deserialize)]
struct GetCostResponse {
    // The cost in unils.
    cost_unils: u64,
}

#[derive(Serialize)]
struct LookupRevokedTokensRequest {
    hashes: Vec<ProofHash>,
}

#[derive(Deserialize)]
struct LookupRevokedTokensResponse {
    revoked: Vec<RevokedToken>,
}

/// Creates a self-signed identity NUC for authenticating a request.
async fn create_identity_nuc<const N: usize>(
    keypair: &Keypair,
    audience: Did,
    command: [&str; N],
) -> Result<String, NucTokenBuildError> {
    InvocationBuilder::new()
        .subject(keypair.to_did(DidMethod::Key))
        .audience(audience)
        .command(command)
        .sign_and_serialize(&keypair.signer(DidMethod::Key))
        .await
}
