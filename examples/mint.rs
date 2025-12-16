//! Example demonstrating the decoupled payment flow.
//!
//! This example shows how to:
//! 1. Create a payment resource (get digest for on-chain payment)
//! 2. Validate the payment after on-chain transaction confirms
//! 3. Request a root NUC token for a blind module
//!
//! Note: This example requires a running nilauth service and Anvil node.
//! The on-chain payment step is left as a placeholder since it requires
//! interacting with Ethereum directly (e.g., via ethers-rs or alloy).

use nilauth_client::client::{BlindModule, DefaultNilauthClient, NilauthClient};
use nillion_nucs::signer::{DidMethod, Signer};

const ANVIL_CHAIN_ID: u64 = 31337;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_key_bytes = b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4";

    // 1. Create client - this fetches the service's public key automatically
    let client = DefaultNilauthClient::create("http://localhost:30921", ANVIL_CHAIN_ID).await?;

    let signer = Signer::from_private_key(secret_key_bytes, DidMethod::Key);
    let product = BlindModule::NilDb;

    // Check subscription cost
    let cost = client.subscription_cost(product).await?;
    println!("Cost: product={product}, cost={cost} unils");

    // In this example the payer and the subscriber are the same identity
    let payer_did = *signer.did();
    let subscriber_did = *signer.did();

    // 2. Create payment resource (get digest for on-chain payment)
    let resource = client.create_payment_resource(product, payer_did, subscriber_did);
    println!("Payment resource created:");
    println!("  Digest: 0x{}", hex::encode(resource.digest));
    println!("  (Send this digest to the BurnWithDigest contract on Ethereum)");

    // 3. Perform on-chain payment (not shown - use ethers-rs or alloy)
    // Example pseudocode:
    //   let tx = burn_contract.burn_with_digest(amount, resource.digest).send().await?;
    //   let tx_hash = tx.tx_hash();

    // For demonstration, we'll use a placeholder tx hash
    // In production, this would come from the actual on-chain transaction
    let tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
    println!("\n(Placeholder) On-chain tx hash: {tx_hash}");

    // 4. Validate payment with nilauth
    println!("\nValidating payment...");
    match client.validate_payment(tx_hash, &resource.payload, &*signer).await {
        Ok(()) => println!("Payment validated successfully!"),
        Err(e) => {
            println!("Payment validation failed (expected with placeholder tx): {e}");
            return Ok(());
        }
    }

    // 5. Request root token (only works after successful payment validation)
    let token = client.request_token(&*signer, product).await?;
    println!("Root token: {token}");

    Ok(())
}
