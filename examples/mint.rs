use nilauth_client::{
    client::{BlindModule, DefaultNilauthClient, NilauthClient},
    nilchain_client::{client::NillionChainClient, key::NillionChainPrivateKey},
};
use nillion_nucs::k256::SecretKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payment_key = NillionChainPrivateKey::from_bytes(
        b"\x97\xf4\x98\x89\xfc\xee\xd8\x8a\x9c\xdd\xdb\x16\xa1a\xd1?j\x120|+9\x16?<<9|<-$4",
    )?;
    let mut payer = NillionChainClient::new("http://localhost:26648".to_string(), payment_key).await?;
    let client = DefaultNilauthClient::new("http://127.0.0.1:30921")?;
    let key = SecretKey::random(&mut rand::thread_rng());
    let product = BlindModule::NilDb;

    client.pay_subscription(&mut payer, &key.public_key(), product).await?;
    let token = client.request_token(&key, product).await?;
    println!("{token}");
    Ok(())
}
