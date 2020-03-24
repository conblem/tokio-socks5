use std::error::Error;
use std::future::Future;
use std::sync::Arc;

use tokio;
use tokio::sync::RwLock;

mod socks5;
use socks5::Socks5Listener;

mod race;

mod esni;
use esni::ESNIKeys;

mod filter;
use crate::filter::ESNIFilter;
use filter::ESNIFilterFactory;
use std::collections::HashMap;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let esni = "/wGWybP7ACQAHQAgshFEgoYR57J8t5JR2EC651y6JQPdpZ0V6Z6q8n128mAAAhMBAQQAAAAAXnNewAAAAABee0fAAAA=";
    let esni_keys = ESNIKeys::parse(esni).unwrap();

    let filter_factory = ESNIFilterFactory::new();
    let mut socks5 = Socks5Listener::<ESNIFilterFactory, ESNIFilter>::new(filter_factory).await?;
    socks5.listen().await?;
    Ok(())
}
