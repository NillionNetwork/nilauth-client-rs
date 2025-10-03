use nilauth_client::{
    client::{BlindModule, DefaultNilauthClient, NilauthClient},
    nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey},
};
use nillion_nucs::{DidMethod, Keypair};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_key_bytes = b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4";
    let payment_key = NillionChainPrivateKey::from_bytes(secret_key_bytes)?;
    let mut payer = NillionChainClient::new("http://localhost:26648".to_string(), payment_key).await?;
    let client = DefaultNilauthClient::new("http://127.0.0.1:30921")?;
    let keypair = Keypair::from_bytes(secret_key_bytes);
    let product = BlindModule::NilDb;

    let cost = client.subscription_cost(product).await?;
    println!("Cost: product={product}, cost={cost}");

    // In this example the payer and the subscriber are the same identity
    let tx_hash = client.pay_subscription(&mut payer, product, &keypair, keypair.to_did(DidMethod::Key)).await?;
    println!("Payment: tx_hash={tx_hash}");

    let token = client.request_token(&keypair, product).await?;
    println!("Root token: token={token}");
    Ok(())
}
