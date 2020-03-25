use std::error::Error;

use tokio;

mod race;

mod socks;
use socks::SocksListener;

mod esni;
use esni::filter::ESNIFilterFactory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("started");

    let filter_factory = ESNIFilterFactory::new();
    let mut socks = SocksListener::new(filter_factory).await?;
    socks.listen().await?;
    Ok(())
}
