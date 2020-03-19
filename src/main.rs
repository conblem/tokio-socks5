use std::error::Error;

use tokio;

mod socks5;

use socks5::Socks5Listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("start");
    let mut socks5 = Socks5Listener::new().await?;
    socks5.listen().await?;
    Ok(())
}
