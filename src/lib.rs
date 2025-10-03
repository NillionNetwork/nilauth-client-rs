//! A Rust client for interacting with [nilauth](https://github.com/NillionNetwork/nilauth),
//! a service that manages blind module subscriptions and mints Nuc tokens for
//! the [Nillion Network](https://nillion.com).
//!
//! # Getting Started
//!
//! The primary entry point is the [`NilauthClient`] trait and its default
//! implementation, [`DefaultNilauthClient`].
//!
//! ## Example: Paying for a Subscription and Minting a Token
//!
//! ```no_run
//! use nilauth_client::{
//!     client::{BlindModule, DefaultNilauthClient, NilauthClient},
//!     nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey},
//! };
//! use nillion_nucs::{DidMethod, Keypair};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Set up keypairs and clients
//!     let payment_key = NillionChainPrivateKey::from_bytes(&[0; 32])?;
//!     let mut payer_client = NillionChainClient::new("http://localhost:26648".to_string(), payment_key).await?;
//!     let nilauth_client = DefaultNilauthClient::new("http://127.0.0.1:30921")?;
//!
//!     let payer_keypair = Keypair::generate();
//!     let subscriber_keypair = Keypair::generate();
//!     let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
//!     let product = BlindModule::NilDb;
//!
//!     // 2. The Payer pays for the Subscriber's subscription
//!     let tx_hash = nilauth_client.pay_subscription(
//!         &mut payer_client,
//!         product,
//!         &payer_keypair,
//!         subscriber_did,
//!     ).await?;
//!     println!("Successfully paid for subscription in tx: {}", tx_hash);
//!
//!     // 3. The Subscriber can now request a root Nuc for the product
//!     let token = nilauth_client.request_token(&subscriber_keypair, product).await?;
//!     println!("Received root token: {}", token);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod models;

pub use client::{DefaultNilauthClient, NilauthClient};
pub use models::{About, BlindModule, RevokeTokenArgs, RevokedToken, Subscription, SubscriptionDetails, TxHash};
pub use nilchain_client;
