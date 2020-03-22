use std::error::Error;

use tokio;

mod socks5;
use socks5::Socks5Listener;

mod race;

mod esni;
use esni::ESNIKeys;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let esni = "/wGWybP7ACQAHQAgshFEgoYR57J8t5JR2EC651y6JQPdpZ0V6Z6q8n128mAAAhMBAQQAAAAAXnNewAAAAABee0fAAAA=";
    let esni_keys = ESNIKeys::parse(esni).unwrap();

    println!("start");
    let mut socks5 = Socks5Listener::new().await?;
    socks5.listen().await?;
    Ok(())
}
