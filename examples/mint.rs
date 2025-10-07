use nilauth_client::{
    client::{BlindModule, DefaultNilauthClient, NilauthClient},
    nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey},
};
use nillion_nucs::signer::{DidMethod, Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_key_bytes = b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4";
    let payment_key = NillionChainPrivateKey::from_bytes(secret_key_bytes)?;

    // These services must be started — see docker-compose.yml in nilauth or nuc-ts
    let mut payer = NillionChainClient::new("http://localhost:30648".to_string(), payment_key).await?;
    let client = DefaultNilauthClient::new("http://localhost:30921")?;

    let signer = Signer::from_private_key(secret_key_bytes, DidMethod::Key);
    let product = BlindModule::NilDb;

    let cost = client.subscription_cost(product).await?;
    println!("Cost: product={product}, cost={cost}");

    // In this example the payer and the subscriber are the same identity
    let subscriber_did = *signer.did();
    let tx_hash = client.pay_subscription(&mut payer, product, &*signer, subscriber_did).await?;
    println!("Payment: tx_hash={tx_hash}");

    let token = client.request_token(&*signer, product).await?;
    println!("Root token: {token}");
    Ok(())
}
