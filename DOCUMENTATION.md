# Usage Documentation

## Installation

Add `nilauth-client` to your `Cargo.toml`. Since this is not yet published to crates.io, you can add it via a git dependency:

```toml
[dependencies]
nilauth-client = { git = "https://github.com/NillionNetwork/nilauth.git" }
```

## Core Concepts

This client interacts with `nilauth` using a Payer/Subscriber model. This model separates the identity paying for a subscription from the identity that uses it.

| Role           | Description                                                                                                                                                               | Key Methods Used                |
|:---------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------|
| **Payer**      | The principal who pays for a subscription using NIL tokens. This identity signs the payment validation request.                                                           | `pay_subscription`              |
| **Subscriber** | The principal who benefits from the subscription. This identity can request root NUCs for the subscribed blind module, which can then be used to access Nillion services. | `request_token`, `revoke_token` |

In many cases, the Payer and the Subscriber may be the same identity, but the API is designed to support them being different.

## Complete Usage Example

This example demonstrates the primary workflow:

1. A `payer` identity pays for a `nildb` subscription for a `subscriber` identity.
2. The `subscriber` uses the active subscription to mint a root NUC token.

```rust
use nilauth_client::{
    client::{BlindModule, DefaultNilauthClient, NilauthClient},
    nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey},
};
use nillion_nucs::{DidMethod, Keypair};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Step 1: Create Keypairs and Clients for all actors ===
    let nilauth_client = DefaultNilauthClient::new("http://127.0.0.1:30921")?;

    // Payer setup
    let payer_secret_bytes = b"\\x97\\xf4\\x98\\x89\\xfc\\xee\\xd8\\x8a\\x9c\\xdd\\xdb\\x16\\xa1a\\xd1?j\\x120|+9\\x16?<<9|<-$4";
    let payer_keypair = Keypair::from_bytes(payer_secret_bytes);
    let payment_key = NillionChainPrivateKey::from_bytes(payer_secret_bytes)?;
    let mut payer_chain_client = NillionChainClient::new("http://localhost:26648".to_string(), payment_key).await?;

    // Subscriber setup
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
    let product = BlindModule::NilDb;

    // === Step 2: Payer pays for the Subscriber's subscription ===
    println!("Payer is paying for Subscriber's ({}) subscription...", subscriber_did);
    let tx_hash = nilauth_client.pay_subscription(
        &mut payer_chain_client,
        product,
        &payer_keypair,
        subscriber_did,
    ).await?;
    println!("✅ Payment successful! Transaction hash: {}", tx_hash);


    // === Step 3: Subscriber requests a root token ===
    println!("\nSubscriber is requesting a token...");
    let token_string = nilauth_client.request_token(&subscriber_keypair, product).await?;
    println!("✅ Received root token for Subscriber.");
    println!("\nToken:\n{}", token_string);

    Ok(())
}
```
