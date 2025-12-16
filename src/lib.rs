//! A Rust client for interacting with [nilauth](https://github.com/NillionNetwork/nilauth),
//! a service that manages blind module subscriptions and mints Nuc tokens for
//! the [Nillion Network](https://nillion.com).
//!
//! # Getting Started
//!
//! The primary entry point is the [`NilauthClient`] trait and its default
//! implementation, [`DefaultNilauthClient`].
//!
//! ## Payment Flow
//!
//! This client uses a decoupled payment flow with ERC-20 token burns:
//!
//! 1. **Create Payment Resource**: Call `create_payment_resource()` to get a digest and payload
//! 2. **On-Chain Payment**: Send the digest to the BurnWithDigest contract on Ethereum
//! 3. **Validate Payment**: Call `validate_payment()` with the tx hash and payload
//!
//! ## Example: Paying for a Subscription and Minting a Token
//!
//! ```no_run
//! use nilauth_client::{
//!     client::{BlindModule, DefaultNilauthClient, NilauthClient},
//! };
//! use nillion_nucs::signer::{DidMethod, Signer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Set up client and signers
//!     let nilauth_client = DefaultNilauthClient::create("http://127.0.0.1:30921", 31337).await?;
//!
//!     let payer_signer = Signer::from_private_key(&[1; 32], DidMethod::Key);
//!     let subscriber_signer = Signer::generate(DidMethod::Key);
//!     let subscriber_did = *subscriber_signer.did();
//!     let product = BlindModule::NilDb;
//!
//!     // 2. Create payment resource (get digest for on-chain payment)
//!     let resource = nilauth_client.create_payment_resource(
//!         product,
//!         *payer_signer.did(),
//!         subscriber_did,
//!     );
//!     println!("Send digest to BurnWithDigest contract: 0x{}", hex::encode(resource.digest));
//!
//!     // 3. After on-chain tx confirms, validate with nilauth
//!     let tx_hash = "0x..."; // From on-chain transaction
//!     nilauth_client.validate_payment(tx_hash, &resource.payload, &*payer_signer).await?;
//!     println!("Payment validated!");
//!
//!     // 4. The Subscriber can now request a root Nuc for the product
//!     let token = nilauth_client.request_token(&*subscriber_signer, product).await?;
//!     println!("Received root token: {}", token);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod models;

pub use client::{DefaultNilauthClient, NilauthClient, OnChainPaymentPayload, PaymentResource};
pub use error::{
    AboutError, LookupRevokedTokensError, PaymentResourceError, RequestError, RequestTokenError, RevokeTokenError,
    SubscriptionCostError, SubscriptionStatusError, ValidatePaymentError,
};
pub use models::{About, BlindModule, RevokeTokenArgs, RevokedToken, Subscription, SubscriptionDetails, TxHash};
